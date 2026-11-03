#!/usr/bin/env python3
"""
Cryptographic hashing and integrity verification.

Supported algorithms:
- SHA-256 and SHA-512 from SHA-2
- SHA3-256 and SHA3-512 from SHA-3

Examples:
    python hashing.py
    python hashing.py hash document.bin --algorithm sha256
    python hashing.py hash document.bin --algorithm sha3_256
    python hashing.py verify document.bin <expected-hex-digest> --algorithm sha256

A cryptographic digest detects changes only when the expected digest comes
from a trusted source. Use HMAC when integrity verification must also
authenticate the party that created the verification value.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import BinaryIO


CHUNK_SIZE = 1024 * 1024
MIN_HMAC_KEY_BYTES = 32


class HashAlgorithm(str, Enum):
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"

    @property
    def digest_bits(self) -> int:
        return hashlib.new(self.value).digest_size * 8

    @property
    def family(self) -> str:
        return "SHA-2" if self.value.startswith("sha") and not self.value.startswith("sha3") else "SHA-3"


@dataclass(frozen=True)
class HashResult:
    algorithm: str
    digest: str
    byte_count: int
    created_at: str

    def __post_init__(self) -> None:
        if self.byte_count < 0:
            raise ValueError("Byte count cannot be negative.")
        if not re.fullmatch(r"[0-9a-f]+", self.digest):
            raise ValueError("Digest must contain lowercase hexadecimal characters.")


@dataclass(frozen=True)
class IntegrityManifest:
    file_name: str
    algorithm: str
    digest: str
    byte_count: int
    created_at: str

    @classmethod
    def from_result(
        cls,
        file_path: Path,
        result: HashResult,
    ) -> "IntegrityManifest":
        return cls(
            file_name=file_path.name,
            algorithm=result.algorithm,
            digest=result.digest,
            byte_count=result.byte_count,
            created_at=result.created_at,
        )

    def save(self, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")

        try:
            temporary.write_text(
                json.dumps(asdict(self), indent=2) + "\n",
                encoding="utf-8",
            )
            temporary.replace(destination)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise

    @classmethod
    def load(cls, source: Path) -> "IntegrityManifest":
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Cannot read integrity manifest: {exc}") from exc

        required = {
            "file_name",
            "algorithm",
            "digest",
            "byte_count",
            "created_at",
        }

        if not isinstance(data, dict) or set(data) != required:
            raise ValueError("Manifest structure is invalid.")

        try:
            algorithm = HashAlgorithm(data["algorithm"])
            byte_count = int(data["byte_count"])
            digest = validate_digest(data["digest"], algorithm)
        except (ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"Invalid manifest fields: {exc}") from exc

        if byte_count < 0:
            raise ValueError("Manifest byte count cannot be negative.")

        return cls(
            file_name=str(data["file_name"]),
            algorithm=algorithm.value,
            digest=digest,
            byte_count=byte_count,
            created_at=str(data["created_at"]),
        )


def create_hasher(algorithm: HashAlgorithm):
    """Create a standard-library hash object after validating availability."""
    try:
        return hashlib.new(algorithm.value)
    except ValueError as exc:
        raise RuntimeError(
            f"Hash algorithm {algorithm.value!r} is unavailable."
        ) from exc


def validate_digest(
    digest: str,
    algorithm: HashAlgorithm,
) -> str:
    """Validate hexadecimal representation and expected digest length."""
    if not isinstance(digest, str):
        raise TypeError("Expected digest must be a string.")

    normalized = digest.strip().lower()

    if not re.fullmatch(r"[0-9a-f]+", normalized):
        raise ValueError("Digest must contain hexadecimal characters only.")

    expected_length = create_hasher(algorithm).digest_size * 2

    if len(normalized) != expected_length:
        raise ValueError(
            f"{algorithm.value} requires {expected_length} hexadecimal characters."
        )

    return normalized


def hash_bytes(
    data: bytes,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> HashResult:
    if not isinstance(data, bytes):
        raise TypeError("Hash input must be bytes.")

    hasher = create_hasher(algorithm)
    hasher.update(data)

    return HashResult(
        algorithm=algorithm.value,
        digest=hasher.hexdigest(),
        byte_count=len(data),
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def hash_stream(
    stream: BinaryIO,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
    chunk_size: int = CHUNK_SIZE,
) -> HashResult:
    """
    Hash a binary stream without loading the complete input into memory.

    Memory usage is O(chunk_size), independent of file size.
    """
    if chunk_size <= 0:
        raise ValueError("Chunk size must be positive.")

    hasher = create_hasher(algorithm)
    byte_count = 0

    while True:
        chunk = stream.read(chunk_size)

        if not chunk:
            break

        if not isinstance(chunk, bytes):
            raise TypeError("Stream must return binary data.")

        hasher.update(chunk)
        byte_count += len(chunk)

    return HashResult(
        algorithm=algorithm.value,
        digest=hasher.hexdigest(),
        byte_count=byte_count,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def hash_file(
    file_path: Path,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> HashResult:
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {path}")

    if not path.is_file():
        raise ValueError(f"Path is not a regular file: {path}")

    with path.open("rb") as stream:
        return hash_stream(stream, algorithm)


def verify_bytes(
    data: bytes,
    expected_digest: str,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> bool:
    expected = validate_digest(expected_digest, algorithm)
    actual = hash_bytes(data, algorithm).digest

    return hmac.compare_digest(actual, expected)


def verify_file(
    file_path: Path,
    expected_digest: str,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> bool:
    expected = validate_digest(expected_digest, algorithm)
    actual = hash_file(file_path, algorithm).digest

    return hmac.compare_digest(actual, expected)


def create_hmac(
    data: bytes,
    key: bytes,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> str:
    """
    Produce a keyed authentication value.

    HMAC is not interchangeable with an ordinary unkeyed digest.
    The key must remain confidential and must not be stored beside the data.
    """
    if not isinstance(data, bytes) or not isinstance(key, bytes):
        raise TypeError("Data and HMAC key must be bytes.")

    if len(key) < MIN_HMAC_KEY_BYTES:
        raise ValueError(
            f"HMAC keys must contain at least {MIN_HMAC_KEY_BYTES} bytes."
        )

    return hmac.new(
        key,
        data,
        digestmod=algorithm.value,
    ).hexdigest()


def verify_hmac(
    data: bytes,
    key: bytes,
    expected_tag: str,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> bool:
    expected = validate_digest(expected_tag, algorithm)
    actual = create_hmac(data, key, algorithm)

    return hmac.compare_digest(actual, expected)


def create_file_manifest(
    file_path: Path,
    algorithm: HashAlgorithm = HashAlgorithm.SHA256,
) -> IntegrityManifest:
    path = Path(file_path)
    result = hash_file(path, algorithm)

    return IntegrityManifest.from_result(path, result)


def verify_manifest(
    file_path: Path,
    manifest: IntegrityManifest,
) -> bool:
    algorithm = HashAlgorithm(manifest.algorithm)
    result = hash_file(file_path, algorithm)

    if result.byte_count != manifest.byte_count:
        return False

    return hmac.compare_digest(result.digest, manifest.digest)


def run_self_tests() -> None:
    """Check implementations against published empty-input test vectors."""
    empty = b""

    expected = {
        HashAlgorithm.SHA256:
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        HashAlgorithm.SHA3_256:
            "a7ffc6f8bf1ed76651c14756a061d662"
            "f580ff4de43b49fa82d80a4b80f8434a",
    }

    for algorithm, expected_digest in expected.items():
        actual = hash_bytes(empty, algorithm).digest
        assert actual == expected_digest, (
            f"Known-answer test failed for {algorithm.value}"
        )

    abc_vectors = {
        HashAlgorithm.SHA256:
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        HashAlgorithm.SHA3_256:
            "3a985da74fe225b2045c172d6bd390bd"
            "855f086e3e9d525b46bfe24511431532",
    }

    for algorithm, expected_digest in abc_vectors.items():
        actual = hash_bytes(b"abc", algorithm).digest
        assert actual == expected_digest, (
            f"Known-answer test failed for {algorithm.value}"
        )

    key = bytes(range(MIN_HMAC_KEY_BYTES))
    message = b"release artifact integrity"

    tag = create_hmac(message, key)
    assert verify_hmac(message, key, tag)
    assert not verify_hmac(message + b" altered", key, tag)

    assert verify_bytes(b"abc", abc_vectors[HashAlgorithm.SHA256])
    assert not verify_bytes(b"abd", abc_vectors[HashAlgorithm.SHA256])

    try:
        verify_bytes(b"abc", "not-a-digest")
    except ValueError:
        pass
    else:
        raise AssertionError("Malformed digest was not rejected.")


def run_demo() -> None:
    run_self_tests()

    payload = (
        b"Release package: version 2.4.1\n"
        b"Component: payment-service\n"
        b"Environment: production\n"
    )

    print("Cryptographic hashing demonstration")
    print("------------------------------------")

    for algorithm in HashAlgorithm:
        result = hash_bytes(payload, algorithm)
        print(f"{algorithm.value:10} {result.digest}")
        print(f"{'':10} bytes={result.byte_count}")

    original = hash_bytes(payload, HashAlgorithm.SHA256)
    print("\nIntegrity verification")
    print(f"Original payload: {verify_bytes(payload, original.digest)}")
    print(
        "Modified payload:",
        verify_bytes(payload + b"unauthorized change", original.digest),
    )

    key = bytes(range(MIN_HMAC_KEY_BYTES))
    tag = create_hmac(payload, key)

    print("\nKeyed integrity verification")
    print(f"Valid HMAC: {verify_hmac(payload, key, tag)}")
    print(
        "Modified data:",
        verify_hmac(payload + b"unauthorized change", key, tag),
    )

    print("\nKnown-answer tests: PASSED")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SHA-2, SHA-3 and file integrity verification."
    )

    subparsers = parser.add_subparsers(dest="command")

    hash_parser = subparsers.add_parser("hash", help="Calculate a file digest.")
    hash_parser.add_argument("file", type=Path)
    hash_parser.add_argument(
        "--algorithm",
        choices=[item.value for item in HashAlgorithm],
        default=HashAlgorithm.SHA256.value,
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help="Compare a file digest with an expected digest.",
    )
    verify_parser.add_argument("file", type=Path)
    verify_parser.add_argument("expected_digest")
    verify_parser.add_argument(
        "--algorithm",
        choices=[item.value for item in HashAlgorithm],
        default=HashAlgorithm.SHA256.value,
    )

    return parser.parse_args()


def main() -> int:
    try:
        args = parse_arguments()

        if args.command is None:
            run_demo()
            return 0

        algorithm = HashAlgorithm(args.algorithm)

        if args.command == "hash":
            result = hash_file(args.file, algorithm)
            print(f"Algorithm: {result.algorithm}")
            print(f"Bytes:     {result.byte_count}")
            print(f"Digest:    {result.digest}")
            return 0

        if args.command == "verify":
            valid = verify_file(
                args.file,
                args.expected_digest,
                algorithm,
            )
            print("INTEGRITY VERIFIED" if valid else "INTEGRITY MISMATCH")
            return 0 if valid else 1

        raise ValueError("Unsupported command.")

    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
