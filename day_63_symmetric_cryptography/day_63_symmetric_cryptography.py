from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class KeyType(Enum):
    RSA = "RSA"
    ECC = "ECC"


class Operation(Enum):
    ENCRYPT = "encrypt"
    SIGN = "sign"
    VERIFY = "verify"


class CryptoError(Exception):
    pass


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return secrets.compare_digest(left, right)


@dataclass(frozen=True)
class PublicKey:
    algorithm: KeyType
    value: tuple[int, ...]


@dataclass(frozen=True)
class PrivateKey:
    algorithm: KeyType
    value: tuple[int, ...]


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = egcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def mod_inverse(a: int, modulus: int) -> int:
    gcd, x, _ = egcd(a, modulus)
    if gcd != 1:
        raise CryptoError("Modular inverse does not exist")
    return x % modulus


def is_probable_prime(n: int, rounds: int = 16) -> bool:
    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    if n % 2 == 0:
        return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int = 256) -> int:
    if bits < 128:
        raise ValueError("Prime size is too small")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 512) -> KeyPair:
    if bits < 512:
        raise ValueError("Educational RSA requires at least 512 total bits")

    half = bits // 2
    e = 65537

    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue

        phi = (p - 1) * (q - 1)
        if phi % e != 0:
            break

    n = p * q
    d = mod_inverse(e, phi)

    return KeyPair(
        public=PublicKey(KeyType.RSA, (n, e)),
        private=PrivateKey(KeyType.RSA, (n, d)),
    )


def rsa_encrypt(public: PublicKey, plaintext: bytes) -> bytes:
    if public.algorithm is not KeyType.RSA:
        raise CryptoError("RSA public key required")

    n, e = public.value
    message = int.from_bytes(plaintext, "big")

    if message >= n:
        raise CryptoError("Plaintext is too large for this RSA modulus")

    ciphertext = pow(message, e, n)
    size = (n.bit_length() + 7) // 8
    return ciphertext.to_bytes(size, "big")


def rsa_decrypt(private: PrivateKey, ciphertext: bytes) -> bytes:
    if private.algorithm is not KeyType.RSA:
        raise CryptoError("RSA private key required")

    n, d = private.value
    c = int.from_bytes(ciphertext, "big")

    if c >= n:
        raise CryptoError("Invalid RSA ciphertext")

    plaintext = pow(c, d, n)
    length = max(1, (plaintext.bit_length() + 7) // 8)
    return plaintext.to_bytes(length, "big").lstrip(b"\x00") or b"\x00"


def rsa_sign(private: PrivateKey, message: bytes) -> bytes:
    n, d = private.value
    digest = int.from_bytes(sha256(message), "big")

    if digest >= n:
        raise CryptoError("RSA modulus is too small for this digest")

    signature = pow(digest, d, n)
    size = (n.bit_length() + 7) // 8
    return signature.to_bytes(size, "big")


def rsa_verify(public: PublicKey, message: bytes, signature: bytes) -> bool:
    n, e = public.value
    sig = int.from_bytes(signature, "big")

    if sig >= n:
        return False

    recovered = pow(sig, e, n)
    expected = int.from_bytes(sha256(message), "big")
    return recovered == expected


@dataclass(frozen=True)
class ECCPoint:
    x: Optional[int]
    y: Optional[int]

    @property
    def infinity(self) -> bool:
        return self.x is None or self.y is None


class ToyECC:
    """
    A small elliptic curve used only to make point arithmetic executable.
    It is not a production cryptographic curve.
    """

    p = 9739
    a = 497
    b = 1768
    g = ECCPoint(1804, 5368)
    order = 9929

    @classmethod
    def add(cls, p1: ECCPoint, p2: ECCPoint) -> ECCPoint:
        if p1.infinity:
            return p2
        if p2.infinity:
            return p1

        if p1.x == p2.x and (p1.y + p2.y) % cls.p == 0:
            return ECCPoint(None, None)

        if p1 == p2:
            numerator = (3 * p1.x * p1.x + cls.a) % cls.p
            denominator = mod_inverse(2 * p1.y % cls.p, cls.p)
        else:
            numerator = (p2.y - p1.y) % cls.p
            denominator = mod_inverse((p2.x - p1.x) % cls.p, cls.p)

        slope = numerator * denominator % cls.p
        x3 = (slope * slope - p1.x - p2.x) % cls.p
        y3 = (slope * (p1.x - x3) - p1.y) % cls.p
        return ECCPoint(x3, y3)

    @classmethod
    def multiply(cls, scalar: int, point: ECCPoint) -> ECCPoint:
        if scalar < 0:
            raise ValueError("Scalar must be non-negative")

        result = ECCPoint(None, None)
        addend = point

        while scalar:
            if scalar & 1:
                result = cls.add(result, addend)
            addend = cls.add(addend, addend)
            scalar >>= 1

        return result


def generate_ecc_keypair() -> KeyPair:
    private_scalar = secrets.randbelow(ToyECC.order - 1) + 1
    public_point = ToyECC.multiply(private_scalar, ToyECC.g)

    return KeyPair(
        public=PublicKey(KeyType.ECC, (public_point.x, public_point.y)),
        private=PrivateKey(KeyType.ECC, (private_scalar,)),
    )


def ecc_sign(private: PrivateKey, message: bytes) -> tuple[int, int]:
    private_scalar = private.value[0]
    z = int.from_bytes(sha256(message), "big") % ToyECC.order

    while True:
        k = secrets.randbelow(ToyECC.order - 1) + 1
        point = ToyECC.multiply(k, ToyECC.g)

        if point.infinity:
            continue

        r = point.x % ToyECC.order
        if r == 0:
            continue

        s = mod_inverse(k, ToyECC.order) * (z + r * private_scalar)
        s %= ToyECC.order

        if s != 0:
            return r, s


def ecc_verify(public: PublicKey, message: bytes, signature: tuple[int, int]) -> bool:
    if public.algorithm is not KeyType.ECC:
        return False

    r, s = signature
    if not (1 <= r < ToyECC.order and 1 <= s < ToyECC.order):
        return False

    z = int.from_bytes(sha256(message), "big") % ToyECC.order
    w = mod_inverse(s, ToyECC.order)
    u1 = z * w % ToyECC.order
    u2 = r * w % ToyECC.order

    public_point = ECCPoint(public.value[0], public.value[1])
    point = ToyECC.add(
        ToyECC.multiply(u1, ToyECC.g),
        ToyECC.multiply(u2, public_point),
    )

    return not point.infinity and point.x % ToyECC.order == r


class SecureDocumentService:
    def __init__(self) -> None:
        self.audit_log: list[dict] = []

    def audit(self, operation: Operation, success: bool, detail: str) -> None:
        self.audit_log.append(
            {
                "operation": operation.value,
                "success": success,
                "detail": detail,
            }
        )

    def encrypt_for_recipient(self, public: PublicKey, document: bytes) -> str:
        # Real systems normally use hybrid encryption: AES-GCM for the document
        # and RSA-OAEP or ECIES-like mechanisms to protect the symmetric key.
        ciphertext = rsa_encrypt(public, document)
        self.audit(Operation.ENCRYPT, True, "RSA demonstration encryption completed")
        return b64(ciphertext)

    def sign_document(self, private: PrivateKey, document: bytes) -> str:
        if private.algorithm is KeyType.RSA:
            signature = rsa_sign(private, document)
            encoded = b64(signature)
        else:
            r, s = ecc_sign(private, document)
            encoded = json.dumps({"r": r, "s": s}, separators=(",", ":"))

        self.audit(Operation.SIGN, True, f"{private.algorithm.value} signature created")
        return encoded

    def verify_document(
        self,
        public: PublicKey,
        document: bytes,
        signature: str,
    ) -> bool:
        try:
            if public.algorithm is KeyType.RSA:
                valid = rsa_verify(public, document, base64.urlsafe_b64decode(signature + "==="))
            else:
                parsed = json.loads(signature)
                valid = ecc_verify(
                    public,
                    document,
                    (int(parsed["r"]), int(parsed["s"])),
                )

            self.audit(Operation.VERIFY, valid, f"{public.algorithm.value} verification")
            return valid
        except (ValueError, KeyError, json.JSONDecodeError, TypeError):
            self.audit(Operation.VERIFY, False, "Malformed signature")
            return False


def run_demo() -> None:
    print("=== Asymmetric Cryptography Case Study ===")

    document = (
        b"Repository release manifest: version=4.2.0; "
        b"artifact=release.tar.gz"
    )

    rsa_keys = generate_rsa_keypair(512)
    ecc_keys = generate_ecc_keypair()

    service = SecureDocumentService()

    rsa_ciphertext = service.encrypt_for_recipient(rsa_keys.public, b"secret")
    print("RSA ciphertext:", rsa_ciphertext)

    rsa_signature = service.sign_document(rsa_keys.private, document)
    print("RSA signature valid:", service.verify_document(
        rsa_keys.public, document, rsa_signature
    ))

    tampered = document.replace(b"4.2.0", b"4.2.1")
    print("Tampered RSA document valid:", service.verify_document(
        rsa_keys.public, tampered, rsa_signature
    ))

    ecc_signature = service.sign_document(ecc_keys.private, document)
    print("ECC signature valid:", service.verify_document(
        ecc_keys.public, document, ecc_signature
    ))

    print("\nPublic-key distinction:")
    print("RSA encryption uses a recipient public key and recipient private key for decryption.")
    print("Digital signatures use a private key to sign and a public key to verify.")
    print("ECC signatures use elliptic-curve point arithmetic rather than RSA exponentiation.")

    assert service.verify_document(rsa_keys.public, document, rsa_signature)
    assert not service.verify_document(rsa_keys.public, tampered, rsa_signature)
    assert service.verify_document(ecc_keys.public, document, ecc_signature)

    output = Path("crypto_audit.json")
    output.write_text(json.dumps(service.audit_log, indent=2), encoding="utf-8")
    print(f"\nAudit log written to {output.resolve()}")

    try:
        rsa_encrypt(rsa_keys.public, b"x" * 100)
    except CryptoError as exc:
        print("Expected encryption failure:", exc)


if __name__ == "__main__":
    run_demo()
