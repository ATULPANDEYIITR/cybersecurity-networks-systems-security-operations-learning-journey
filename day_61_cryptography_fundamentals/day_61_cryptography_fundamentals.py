#!/usr/bin/env python3
"""
Cryptography Fundamentals
Plaintext, ciphertext, keys, symmetric encryption, and asymmetric encryption.

This executable learning artifact implements:
1. A Caesar cipher for the basic plaintext/ciphertext transformation.
2. A stream-style XOR cipher to demonstrate symmetric encryption mechanics.
3. HMAC-SHA256 for integrity/authentication.
4. A small RSA implementation for asymmetric encryption.
5. Key generation, validation, encryption/decryption, tamper detection,
   and performance observations.

The educational ciphers are intentionally not presented as production
cryptography. Production systems should use established cryptographic
libraries and authenticated encryption such as AES-GCM or ChaCha20-Poly1305.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from dataclasses import dataclass
from enum import Enum
from math import gcd
from typing import Optional


class CryptoError(Exception):
    """Base exception for cryptographic operation failures."""


class KeyType(Enum):
    SYMMETRIC = "symmetric"
    RSA_PUBLIC = "rsa-public"
    RSA_PRIVATE = "rsa-private"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CryptoError(message)


def normalize_text(value: str) -> str:
    require(isinstance(value, str), "Plaintext must be a string.")
    require(value != "", "Plaintext must not be empty.")
    require(len(value) <= 4096, "Plaintext exceeds the 4096-character limit.")
    return value


def caesar_encrypt(plaintext: str, shift: int) -> str:
    plaintext = normalize_text(plaintext)
    shift %= 26
    result: list[str] = []

    for char in plaintext:
        if char.isascii() and char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            result.append(char)

    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)


def xor_encrypt(plaintext: bytes, key: bytes) -> bytes:
    require(len(key) >= 16, "Symmetric key must contain at least 16 bytes.")
    require(len(plaintext) <= 1_048_576, "Plaintext exceeds the size limit.")

    return bytes(
        byte ^ key[index % len(key)]
        for index, byte in enumerate(plaintext)
    )


def xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return xor_encrypt(ciphertext, key)


@dataclass(frozen=True)
class SymmetricKey:
    value: bytes

    @staticmethod
    def generate(size: int = 32) -> "SymmetricKey":
        require(size >= 16, "Symmetric key size must be at least 16 bytes.")
        return SymmetricKey(secrets.token_bytes(size))

    def fingerprint(self) -> str:
        return hashlib.sha256(self.value).hexdigest()[:16]


def hmac_sha256(message: bytes, key: bytes) -> str:
    require(len(key) >= 16, "HMAC key must contain at least 16 bytes.")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(message: bytes, key: bytes, expected: str) -> bool:
    actual = hmac_sha256(message, key)
    return hmac.compare_digest(actual, expected)


def is_prime(number: int) -> bool:
    if number < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29)
    if number in small_primes:
        return True

    if number % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2

    return True


def generate_prime(bits: int = 16) -> int:
    require(8 <= bits <= 24, "Educational RSA supports prime sizes from 8 to 24 bits.")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_prime(candidate):
            return candidate


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int


@dataclass(frozen=True)
class RSAKeyPair:
    public: RSAPublicKey
    private: RSAPrivateKey


def generate_rsa_keypair(bits: int = 16) -> RSAKeyPair:
    """
    Educational RSA key generation.

    Real RSA uses much larger primes, normally at least 2048-bit moduli,
    robust primality testing, secure padding, and established libraries.
    """
    p = generate_prime(bits)
    q = generate_prime(bits)

    while q == p:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        e = 3
        while e < phi and gcd(e, phi) != 1:
            e += 2

    d = pow(e, -1, phi)

    return RSAKeyPair(
        public=RSAPublicKey(n=n, e=e),
        private=RSAPrivateKey(n=n, d=d),
    )


def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> list[int]:
    require(public_key.n > 255, "RSA modulus is too small for byte encoding.")
    require(len(plaintext) <= 256, "Educational RSA message is limited to 256 bytes.")

    return [pow(byte, public_key.e, public_key.n) for byte in plaintext]


def rsa_decrypt(ciphertext: list[int], private_key: RSAPrivateKey) -> bytes:
    require(
        all(0 <= value < private_key.n for value in ciphertext),
        "RSA ciphertext contains an invalid value.",
    )
    return bytes(pow(value, private_key.d, private_key.n) for value in ciphertext)


def describe_security_boundaries() -> None:
    print("\nSecurity boundaries")
    print("-------------------")
    print("Plaintext: readable data before encryption.")
    print("Ciphertext: transformed data intended to conceal plaintext.")
    print("Symmetric key: the same secret key protects encryption/decryption.")
    print("Asymmetric keys: a public key can encrypt; the matching private key decrypts.")
    print("HMAC: verifies integrity and possession of a shared secret.")
    print("Production systems must use standardized authenticated encryption.")


def demonstrate_basic_transformation() -> None:
    print("=== 1. Plaintext and Ciphertext ===")

    plaintext = "Meet at 10:30"
    ciphertext = caesar_encrypt(plaintext, 7)
    recovered = caesar_decrypt(ciphertext, 7)

    print(f"Plaintext : {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Recovered : {recovered}")

    assert recovered == plaintext
    assert ciphertext != plaintext


def demonstrate_symmetric_encryption() -> None:
    print("\n=== 2. Symmetric Encryption ===")

    plaintext = (
        "Symmetric encryption uses one shared secret for both directions."
    ).encode("utf-8")

    key = SymmetricKey.generate()
    ciphertext = xor_encrypt(plaintext, key.value)
    recovered = xor_decrypt(ciphertext, key.value)

    print(f"Key fingerprint: {key.fingerprint()}")
    print(f"Ciphertext bytes: {ciphertext.hex()}")
    print(f"Recovered: {recovered.decode('utf-8')}")

    assert recovered == plaintext
    assert ciphertext != plaintext

    tag = hmac_sha256(ciphertext, key.value)
    print(f"HMAC-SHA256: {tag}")

    assert verify_hmac(ciphertext, key.value, tag)

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    assert not verify_hmac(bytes(tampered), key.value, tag)
    print("Tampering detected: yes")


def demonstrate_asymmetric_encryption() -> None:
    print("\n=== 3. Asymmetric Encryption ===")

    pair = generate_rsa_keypair(bits=16)
    plaintext = b"RSA demo"

    ciphertext = rsa_encrypt(plaintext, pair.public)
    recovered = rsa_decrypt(ciphertext, pair.private)

    print(f"Public modulus: {pair.public.n}")
    print(f"Public exponent: {pair.public.e}")
    print(f"Ciphertext integers: {ciphertext}")
    print(f"Recovered: {recovered.decode('utf-8')}")

    assert recovered == plaintext

    wrong_pair = generate_rsa_keypair(bits=16)
    try:
        wrong_recovered = rsa_decrypt(ciphertext, wrong_pair.private)
        require(
            wrong_recovered != plaintext,
            "Unexpected plaintext recovery with the wrong private key.",
        )
        print("Wrong private key rejected by plaintext verification.")
    except (UnicodeDecodeError, ValueError):
        print("Wrong private key produced unusable plaintext, as expected.")


def demonstrate_key_separation() -> None:
    print("\n=== 4. Key Separation ===")

    encryption_key = SymmetricKey.generate()
    authentication_key = SymmetricKey.generate()

    require(
        encryption_key.value != authentication_key.value,
        "Independent cryptographic purposes require separate keys.",
    )

    print(f"Encryption-key fingerprint: {encryption_key.fingerprint()}")
    print(f"Authentication-key fingerprint: {authentication_key.fingerprint()}")

    message = b"separate key purposes"
    ciphertext = xor_encrypt(message, encryption_key.value)
    tag = hmac_sha256(ciphertext, authentication_key.value)

    assert verify_hmac(ciphertext, authentication_key.value, tag)
    print("Independent encryption and authentication keys: valid")


def demonstrate_edge_cases() -> None:
    print("\n=== 5. Validation and Edge Cases ===")

    try:
        xor_encrypt(b"data", b"short")
    except CryptoError as exc:
        print(f"Short key rejected: {exc}")

    try:
        rsa_decrypt([-1], RSAPrivateKey(n=3233, d=2753))
    except CryptoError as exc:
        print(f"Invalid ciphertext rejected: {exc}")

    assert caesar_decrypt(caesar_encrypt("A z!", 52), 52) == "A z!"
    print("Large Caesar shift normalized correctly.")

    unicode_plaintext = "Confidential: नमस्ते"
    encrypted = caesar_encrypt(unicode_plaintext, 3)
    assert caesar_decrypt(encrypted, 3) == unicode_plaintext
    print("Non-ASCII characters preserved by the demonstration cipher.")


def main() -> None:
    demonstrate_basic_transformation()
    demonstrate_symmetric_encryption()
    demonstrate_asymmetric_encryption()
    demonstrate_key_separation()
    demonstrate_edge_cases()
    describe_security_boundaries()

    print("\nAll cryptographic demonstrations completed successfully.")


if __name__ == "__main__":
    main()
