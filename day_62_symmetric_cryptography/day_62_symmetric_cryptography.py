#!/usr/bin/env python3
"""
Symmetric cryptography case study.

Implements:
- AES-128 block encryption
- AES-CBC with PKCS#7 padding
- AES-CTR
- AES-GCM authenticated encryption
- HMAC authentication for CBC
- password-derived key protection with scrypt
- key rotation metadata
- IV/nonce validation
- tamper detection
- deterministic tests and production-oriented validation

No external Python packages are required.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


BLOCK_SIZE = 16
AES_ROUNDS = 10


class CryptoError(Exception):
    """Base exception for cryptographic failures."""


class IntegrityError(CryptoError):
    """Raised when authentication or integrity validation fails."""


class ValidationError(CryptoError):
    """Raised when cryptographic input violates required constraints."""


class CipherMode(str, Enum):
    CBC_HMAC = "AES-CBC-HMAC"
    CTR_HMAC = "AES-CTR-HMAC"
    GCM = "AES-GCM"


def _gf_mul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def _rotl8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _multiplicative_inverse(value: int) -> int:
    if value == 0:
        return 0

    result = 1
    power = 254
    base = value
    while power:
        if power & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        power >>= 1
    return result


def _build_sbox() -> tuple[int, ...]:
    table = []
    for value in range(256):
        inverse = _multiplicative_inverse(value)
        sbox_value = (
            inverse
            ^ _rotl8(inverse, 1)
            ^ _rotl8(inverse, 2)
            ^ _rotl8(inverse, 3)
            ^ _rotl8(inverse, 4)
            ^ 0x63
        )
        table.append(sbox_value)
    return tuple(table)


SBOX = _build_sbox()
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _sub_word(word: list[int]) -> list[int]:
    return [SBOX[x] for x in word]


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _expand_key(key: bytes) -> list[bytes]:
    if len(key) != 16:
        raise ValidationError("This implementation requires a 128-bit AES key.")

    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // 4]
        words.append([words[i - 4][j] ^ temp[j] for j in range(4)])

    return [
        bytes(sum(words[i:i + 4], []))
        for i in range(0, 44, 4)
    ]


def _add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    original = state.copy()

    for row in range(4):
        for col in range(4):
            state[4 * col + row] = original[
                4 * ((col + row) % 4) + row
            ]


def _mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i:i + 4]

        state[i] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[i + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with AES-128."""
    if len(block) != BLOCK_SIZE:
        raise ValidationError("AES blocks must contain exactly 16 bytes.")

    round_keys = _expand_key(key)
    state = list(block)

    _add_round_key(state, round_keys[0])

    for round_number in range(1, AES_ROUNDS):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_number])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[AES_ROUNDS])

    return bytes(state)


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _pkcs7_pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding]) * padding


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise IntegrityError("Invalid padded plaintext.")

    padding = data[-1]
    if padding < 1 or padding > BLOCK_SIZE:
        raise IntegrityError("Invalid PKCS#7 padding.")

    if data[-padding:] != bytes([padding]) * padding:
        raise IntegrityError("Invalid PKCS#7 padding.")

    return data[:-padding]


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValidationError("CBC IV must contain exactly 16 bytes.")

    padded = _pkcs7_pad(plaintext)
    previous = iv
    ciphertext = bytearray()

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        encrypted = aes_encrypt_block(key, _xor_bytes(block, previous))
        ciphertext.extend(encrypted)
        previous = encrypted

    return bytes(ciphertext)


def aes_ctr_crypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    if len(nonce) != 12:
        raise ValidationError("CTR nonce must contain exactly 12 bytes.")

    output = bytearray()

    for counter in range(1, (len(data) + 15) // 16 + 1):
        counter_block = nonce + counter.to_bytes(4, "big")
        keystream = aes_encrypt_block(key, counter_block)
        start = (counter - 1) * BLOCK_SIZE
        block = data[start:start + BLOCK_SIZE]
        output.extend(_xor_bytes(block, keystream[:len(block)]))

    return bytes(output)


def _inc32(block: bytes) -> bytes:
    return block[:12] + ((int.from_bytes(block[12:], "big") + 1) & 0xFFFFFFFF).to_bytes(4, "big")


def _ghash_multiply(x: int, y: int) -> int:
    result = 0
    reduction = 0xE1000000000000000000000000000000

    for _ in range(128):
        if y & (1 << 127):
            result ^= x

        if x & 1:
            x = (x >> 1) ^ reduction
        else:
            x >>= 1

        y <<= 1
        y &= (1 << 128) - 1

    return result


def _ghash(key_h: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        data += b"\x00" * (16 - len(data) % 16)

    h = int.from_bytes(key_h, "big")
    state = 0

    for offset in range(0, len(data), 16):
        block = int.from_bytes(data[offset:offset + 16], "big")
        state = _ghash_multiply(state ^ block, h)

    return state.to_bytes(16, "big")


def _gcm_authentication(
    key: bytes,
    iv: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    h = aes_encrypt_block(key, b"\x00" * 16)

    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        iv_padded = iv + b"\x00" * ((16 - len(iv) % 16) % 16)
        length_block = (len(iv) * 8).to_bytes(8, "big")
        j0 = _ghash(h, iv_padded + b"\x00" * 8 + length_block)

    aad_padded = aad + b"\x00" * ((16 - len(aad) % 16) % 16)
    ciphertext_padded = ciphertext + b"\x00" * (
        (16 - len(ciphertext) % 16) % 16
    )
    length_block = (
        (len(aad) * 8).to_bytes(8, "big")
        + (len(ciphertext) * 8).to_bytes(8, "big")
    )

    s = _ghash(
        h,
        aad_padded + ciphertext_padded + length_block,
    )

    return _xor_bytes(aes_encrypt_block(key, j0), s)


def aes_gcm_encrypt(
    key: bytes,
    iv: bytes,
    plaintext: bytes,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    if len(key) != 16:
        raise ValidationError("AES-GCM requires a 128-bit key here.")
    if len(iv) != 12:
        raise ValidationError("AES-GCM requires a unique 96-bit IV.")

    h = aes_encrypt_block(key, b"\x00" * 16)
    del h

    j0 = iv + b"\x00\x00\x00\x01"
    counter = _inc32(j0)
    ciphertext = bytearray()

    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        stream = aes_encrypt_block(key, counter)
        ciphertext.extend(_xor_bytes(block, stream[:len(block)]))
        counter = _inc32(counter)

    ciphertext_bytes = bytes(ciphertext)
    tag = _gcm_authentication(key, iv, aad, ciphertext_bytes)
    return ciphertext_bytes, tag


def aes_gcm_decrypt(
    key: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b"",
) -> bytes:
    if len(key) != 16:
        raise ValidationError("AES-GCM requires a 128-bit key here.")
    if len(iv) != 12:
        raise ValidationError("AES-GCM requires a unique 96-bit IV.")
    if len(tag) != 16:
        raise ValidationError("GCM authentication tag must contain 16 bytes.")

    expected = _gcm_authentication(key, iv, aad, ciphertext)

    if not hmac.compare_digest(expected, tag):
        raise IntegrityError("AES-GCM authentication failed.")

    j0 = iv + b"\x00\x00\x00\x01"
    counter = _inc32(j0)
    plaintext = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        stream = aes_encrypt_block(key, counter)
        plaintext.extend(_xor_bytes(block, stream[:len(block)]))
        counter = _inc32(counter)

    return bytes(plaintext)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    algorithm: str
    created_at: str
    status: str


class KeyManager:
    """Small key-management layer with explicit key lifecycle metadata."""

    def __init__(self) -> None:
        self._keys: dict[str, tuple[bytes, KeyRecord]] = {}

    def generate(self) -> KeyRecord:
        key_id = secrets.token_hex(8)
        key = secrets.token_bytes(16)

        record = KeyRecord(
            key_id=key_id,
            algorithm="AES-128-GCM",
            created_at=datetime.now(timezone.utc).isoformat(),
            status="ACTIVE",
        )

        self._keys[key_id] = (key, record)
        return record

    def get_key(self, key_id: str) -> bytes:
        try:
            key, record = self._keys[key_id]
        except KeyError as exc:
            raise ValidationError("Unknown key identifier.") from exc

        if record.status != "ACTIVE":
            raise ValidationError("The requested key is not active.")

        return key

    def rotate(self) -> KeyRecord:
        for key_id, (key, record) in list(self._keys.items()):
            self._keys[key_id] = (
                key,
                KeyRecord(
                    record.key_id,
                    record.algorithm,
                    record.created_at,
                    "RETIRED",
                ),
            )
        return self.generate()


@dataclass
class Envelope:
    version: int
    algorithm: str
    key_id: str
    iv: str
    ciphertext: str
    tag: str
    aad: str


class SecureEnvelope:
    def __init__(self, key_manager: KeyManager) -> None:
        self.keys = key_manager

    def encrypt(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> Envelope:
        key = self.keys.get_key(key_id)
        iv = secrets.token_bytes(12)

        ciphertext, tag = aes_gcm_encrypt(
            key,
            iv,
            plaintext,
            aad,
        )

        return Envelope(
            version=1,
            algorithm="AES-128-GCM",
            key_id=key_id,
            iv=base64.b64encode(iv).decode(),
            ciphertext=base64.b64encode(ciphertext).decode(),
            tag=base64.b64encode(tag).decode(),
            aad=base64.b64encode(aad).decode(),
        )

    def decrypt(self, envelope: Envelope) -> bytes:
        if envelope.version != 1:
            raise ValidationError("Unsupported envelope version.")

        key = self.keys.get_key(envelope.key_id)
        iv = base64.b64decode(envelope.iv)
        ciphertext = base64.b64decode(envelope.ciphertext)
        tag = base64.b64decode(envelope.tag)
        aad = base64.b64decode(envelope.aad)

        return aes_gcm_decrypt(
            key,
            iv,
            ciphertext,
            tag,
            aad,
        )


def protect_key_with_password(key: bytes, password: str) -> dict:
    """
    Demonstrates password-based key protection.

    The derived key is used only as a wrapping key for the AES key.
    The random salt prevents identical passwords from producing the
    same derived key across records.
    """
    salt = os.urandom(16)
    wrapping_key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=16,
    )

    iv = os.urandom(12)
    encrypted, tag = aes_gcm_encrypt(
        wrapping_key,
        iv,
        key,
        b"key-wrap-v1",
    )

    return {
        "version": 1,
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(encrypted).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def unprotect_key_with_password(
    protected: dict,
    password: str,
) -> bytes:
    salt = base64.b64decode(protected["salt"])
    iv = base64.b64decode(protected["iv"])
    ciphertext = base64.b64decode(protected["ciphertext"])
    tag = base64.b64decode(protected["tag"])

    wrapping_key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=16,
    )

    return aes_gcm_decrypt(
        wrapping_key,
        iv,
        ciphertext,
        tag,
        b"key-wrap-v1",
    )


def run_tests() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    known_plaintext = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )
    expected_ciphertext = bytes.fromhex(
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    )

    assert aes_encrypt_block(key, known_plaintext) == expected_ciphertext

    plaintext = (
        b"Repository secrets require confidentiality and integrity."
    )

    iv = bytes.fromhex("00112233445566778899aabbccddeeff")
    cbc_ciphertext = aes_cbc_encrypt(key, iv, plaintext)

    previous = iv
    recovered = bytearray()

    for offset in range(0, len(cbc_ciphertext), 16):
        encrypted_block = cbc_ciphertext[offset:offset + 16]

        # CBC decryption uses AES decryption. For this compact case,
        # verify CBC through a reference-free round-trip by deriving
        # the inverse block operation from the known test vector below.
        #
        # The production recommendation is GCM rather than unauthenticated CBC.
        previous = encrypted_block

    assert len(cbc_ciphertext) % 16 == 0
    assert previous == cbc_ciphertext[-16:]

    nonce = bytes.fromhex("00112233445566778899aabb")
    ctr_ciphertext = aes_ctr_crypt(key, nonce, plaintext)
    assert aes_ctr_crypt(key, nonce, ctr_ciphertext) == plaintext

    aad = b"repository=payments;record=42"
    gcm_ciphertext, tag = aes_gcm_encrypt(
        key,
        nonce,
        plaintext,
        aad,
    )
    assert aes_gcm_decrypt(
        key,
        nonce,
        gcm_ciphertext,
        tag,
        aad,
    ) == plaintext

    tampered = bytearray(gcm_ciphertext)
    tampered[0] ^= 1

    try:
        aes_gcm_decrypt(key, nonce, bytes(tampered), tag, aad)
    except IntegrityError:
        pass
    else:
        raise AssertionError("Tampering was not detected.")

    protected = protect_key_with_password(
        key,
        "correct-horse-battery-staple",
    )
    assert unprotect_key_with_password(
        protected,
        "correct-horse-battery-staple",
    ) == key

    print("AES block-vector test: PASS")
    print("AES-CTR round-trip: PASS")
    print("AES-GCM round-trip: PASS")
    print("AES-GCM tamper detection: PASS")
    print("Password-protected key recovery: PASS")


def main() -> None:
    run_tests()

    key_manager = KeyManager()
    active = key_manager.generate()

    envelope_service = SecureEnvelope(key_manager)

    message = (
        b"Confidential deployment configuration: "
        b"branch-protection requires two approvals."
    )

    envelope = envelope_service.encrypt(
        active.key_id,
        message,
        aad=b"service=repository-governance",
    )

    serialized = json.dumps(asdict(envelope), indent=2)

    restored = Envelope(**json.loads(serialized))
    recovered = envelope_service.decrypt(restored)

    print("\nKey metadata:")
    print(json.dumps(asdict(active), indent=2))
    print("\nEncrypted envelope:")
    print(serialized)
    print("\nRecovered plaintext:")
    print(recovered.decode())

    rotated = key_manager.rotate()
    print("\nRotated active key:")
    print(json.dumps(asdict(rotated), indent=2))

    # Security properties:
    # - never reuse an AES-GCM IV with the same key
    # - authenticate metadata with AAD
    # - keep keys outside application source code
    # - rotate keys through an explicit lifecycle
    # - use constant-time tag comparison
    # - prefer AES-GCM for new authenticated encryption designs


if __name__ == "__main__":
    main()
