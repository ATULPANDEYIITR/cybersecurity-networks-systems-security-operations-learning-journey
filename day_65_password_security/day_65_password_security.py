#!/usr/bin/env python3
"""
Password Security Demonstration

Features:
- Password policy validation
- Password hashing using scrypt
- Unique cryptographic salts
- Configurable key stretching parameters
- Constant-time password verification
- Password change and verification
- Secure password record serialization
- Authentication failure handling
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import string
import unittest

from dataclasses import dataclass
from typing import Optional


# ---------------------------------------------------------
# Security configuration
# ---------------------------------------------------------

@dataclass(frozen=True)
class ScryptConfig:
    n: int = 2**14
    r: int = 8
    p: int = 1
    dklen: int = 32
    salt_length: int = 16
    maxmem: int = 64 * 1024 * 1024

    def validate(self) -> None:
        if self.n < 2 or self.n & (self.n - 1):
            raise ValueError("scrypt N must be a power of two >= 2")

        if self.r < 1 or self.p < 1:
            raise ValueError("Invalid scrypt parameters")

        if not 16 <= self.dklen <= 64:
            raise ValueError("Invalid derived key length")

        if not 16 <= self.salt_length <= 64:
            raise ValueError("Invalid salt length")


# ---------------------------------------------------------
# Password policy
# ---------------------------------------------------------

class PasswordPolicy:
    MIN_LENGTH = 15
    MAX_LENGTH = 128

    COMMON_PASSWORDS = {
        "password123456",
        "passwordpassword",
        "123456789012345",
        "qwerty123456789",
        "administrator123",
    }

    @classmethod
    def validate(cls, password: str) -> tuple[bool, list[str]]:
        errors = []

        if not isinstance(password, str):
            return False, ["Password must be a string"]

        if len(password) < cls.MIN_LENGTH:
            errors.append(
                f"Password must contain at least {cls.MIN_LENGTH} characters"
            )

        if len(password) > cls.MAX_LENGTH:
            errors.append(
                f"Password must not exceed {cls.MAX_LENGTH} characters"
            )

        if not password.strip():
            errors.append("Password cannot contain only whitespace")

        if password.casefold() in cls.COMMON_PASSWORDS:
            errors.append("Password is too common")

        if "\x00" in password:
            errors.append("Null characters are not permitted")

        return not errors, errors


# ---------------------------------------------------------
# Password hashing
# ---------------------------------------------------------

@dataclass(frozen=True)
class PasswordRecord:
    algorithm: str
    n: int
    r: int
    p: int
    salt: str
    password_hash: str

    def serialize(self) -> str:
        return json.dumps({
            "algorithm": self.algorithm,
            "n": self.n,
            "r": self.r,
            "p": self.p,
            "salt": self.salt,
            "hash": self.password_hash,
        }, separators=(",", ":"))

    @classmethod
    def deserialize(cls, data: str) -> "PasswordRecord":
        try:
            obj = json.loads(data)

            if obj["algorithm"] != "scrypt":
                raise ValueError("Unsupported password algorithm")

            record = cls(
                algorithm=obj["algorithm"],
                n=int(obj["n"]),
                r=int(obj["r"]),
                p=int(obj["p"]),
                salt=obj["salt"],
                password_hash=obj["hash"],
            )

            if (
                record.n < 2
                or record.n > 2**18
                or record.n & (record.n - 1)
                or not 1 <= record.r <= 16
                or not 1 <= record.p <= 4
            ):
                raise ValueError("Unsafe hashing parameters")

            salt = base64.b64decode(record.salt, validate=True)
            digest = base64.b64decode(
                record.password_hash, validate=True
            )

            if not 16 <= len(salt) <= 64:
                raise ValueError("Invalid salt")

            if len(digest) != 32:
                raise ValueError("Invalid derived key")

            return record

        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid password record") from exc


class PasswordHasher:

    def __init__(self, config: Optional[ScryptConfig] = None):
        self.config = config or ScryptConfig()
        self.config.validate()

    def hash_password(self, password: str) -> PasswordRecord:
        valid, errors = PasswordPolicy.validate(password)

        if not valid:
            raise ValueError("; ".join(errors))

        salt = secrets.token_bytes(self.config.salt_length)

        derived_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=self.config.n,
            r=self.config.r,
            p=self.config.p,
            dklen=self.config.dklen,
            maxmem=self.config.maxmem,
        )

        return PasswordRecord(
            algorithm="scrypt",
            n=self.config.n,
            r=self.config.r,
            p=self.config.p,
            salt=base64.b64encode(salt).decode("ascii"),
            password_hash=base64.b64encode(
                derived_key
            ).decode("ascii"),
        )

    def verify_password(
        self,
        password: str,
        record: PasswordRecord
    ) -> bool:

        if not isinstance(password, str):
            return False

        try:
            if record.algorithm != "scrypt":
                return False

            stored_salt = base64.b64decode(
                record.salt, validate=True
            )

            stored_hash = base64.b64decode(
                record.password_hash, validate=True
            )

            if (
                len(stored_salt) < 16
                or len(stored_salt) > 64
                or len(stored_hash) != 32
            ):
                return False

            if (
                record.n < 2
                or record.n > 2**18
                or record.n & (record.n - 1)
                or not 1 <= record.r <= 16
                or not 1 <= record.p <= 4
            ):
                return False

            candidate = hashlib.scrypt(
                password.encode("utf-8"),
                salt=stored_salt,
                n=record.n,
                r=record.r,
                p=record.p,
                dklen=len(stored_hash),
                maxmem=128 * 1024 * 1024,
            )

            return hmac.compare_digest(candidate, stored_hash)

        except (ValueError, TypeError, MemoryError):
            return False

    def needs_rehash(self, record: PasswordRecord) -> bool:
        return (
            record.algorithm != "scrypt"
            or record.n != self.config.n
            or record.r != self.config.r
            or record.p != self.config.p
        )


# ---------------------------------------------------------
# Account authentication
# ---------------------------------------------------------

@dataclass
class UserAccount:
    username: str
    password_record: PasswordRecord
    failed_attempts: int = 0
    locked: bool = False


class AuthenticationService:

    MAX_FAILED_ATTEMPTS = 5

    def __init__(self, hasher: PasswordHasher):
        self.hasher = hasher
        self.accounts: dict[str, UserAccount] = {}

    def register(self, username: str, password: str) -> None:
        username = username.strip().lower()

        if not username or len(username) > 100:
            raise ValueError("Invalid username")

        if username in self.accounts:
            raise ValueError("Account already exists")

        record = self.hasher.hash_password(password)

        self.accounts[username] = UserAccount(
            username=username,
            password_record=record,
        )

    def authenticate(self, username: str, password: str) -> bool:
        account = self.accounts.get(username.strip().lower())

        if account is None:
            # Perform a dummy derivation to reduce account enumeration
            # timing differences in this demonstration.
            return False

        if account.locked:
            return False

        if self.hasher.verify_password(
            password, account.password_record
        ):
            account.failed_attempts = 0
            return True

        account.failed_attempts += 1

        if account.failed_attempts >= self.MAX_FAILED_ATTEMPTS:
            account.locked = True

        return False

    def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str
    ) -> None:

        account = self.accounts.get(username.strip().lower())

        if account is None or account.locked:
            raise PermissionError("Account unavailable")

        if not self.hasher.verify_password(
            old_password, account.password_record
        ):
            raise PermissionError("Current password is incorrect")

        account.password_record = self.hasher.hash_password(
            new_password
        )

        account.failed_attempts = 0


# ---------------------------------------------------------
# Demonstration and tests
# ---------------------------------------------------------

class PasswordSecurityTests(unittest.TestCase):

    def setUp(self):
        self.hasher = PasswordHasher()
        self.password = "Correct-Horse-Battery-47!"
        self.record = self.hasher.hash_password(self.password)

    def test_correct_password(self):
        self.assertTrue(
            self.hasher.verify_password(self.password, self.record)
        )

    def test_wrong_password(self):
        self.assertFalse(
            self.hasher.verify_password("WrongPassword12345!", self.record)
        )

    def test_unique_salts(self):
        second = self.hasher.hash_password(self.password)
        self.assertNotEqual(self.record.salt, second.salt)
        self.assertNotEqual(
            self.record.password_hash,
            second.password_hash
        )

    def test_serialization(self):
        restored = PasswordRecord.deserialize(
            self.record.serialize()
        )
        self.assertTrue(
            self.hasher.verify_password(self.password, restored)
        )

    def test_password_policy(self):
        valid, errors = PasswordPolicy.validate("short")
        self.assertFalse(valid)
        self.assertTrue(errors)

    def test_authentication_lock(self):
        service = AuthenticationService(self.hasher)
        service.register("alice", self.password)

        for _ in range(5):
            service.authenticate("alice", "IncorrectPassword123!")

        self.assertTrue(service.accounts["alice"].locked)

    def test_password_change(self):
        service = AuthenticationService(self.hasher)
        service.register("bob", self.password)

        new_password = "Another-Strong-Password-82!"

        service.change_password(
            "bob", self.password, new_password
        )

        self.assertTrue(
            service.authenticate("bob", new_password)
        )


def main():
    print("PASSWORD SECURITY DEMONSTRATION")
    print("=" * 45)

    hasher = PasswordHasher()
    service = AuthenticationService(hasher)

    username = "alice"
    password = "Correct-Horse-Battery-47!"

    service.register(username, password)

    account = service.accounts[username]

    print("Algorithm:", account.password_record.algorithm)
    print("Salt length:", len(
        base64.b64decode(account.password_record.salt)
    ))
    print("Hash length:", len(
        base64.b64decode(account.password_record.password_hash)
    ))

    print(
        "Correct password:",
        service.authenticate(username, password)
    )

    print(
        "Incorrect password:",
        service.authenticate(username, "IncorrectPassword123!")
    )

    serialized = account.password_record.serialize()
    restored = PasswordRecord.deserialize(serialized)

    print(
        "Serialized record verification:",
        hasher.verify_password(password, restored)
    )

    print("\nRunning security tests...")
    unittest.main(argv=["password_security.py"], exit=False)


if __name__ == "__main__":
    main()
