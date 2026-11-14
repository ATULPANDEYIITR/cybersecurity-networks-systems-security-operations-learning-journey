#!/usr/bin/env python3
"""
LDAP Directory Management and Security
---------------------------------------
A self-contained LDAP directory simulation covering:
- Directory Information Tree (DIT)
- Distinguished Names (DNs)
- Entries and attributes
- LDAP searches and filter evaluation
- Bind authentication
- Password hashing and account lockout
- Access control and authorization
- Directory queries and pagination
- Audit logging and validation

Uses only the Python standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class LDAPError(Exception):
    pass


class InvalidDN(LDAPError):
    pass


class InvalidFilter(LDAPError):
    pass


class AuthenticationError(LDAPError):
    pass


class AuthorizationError(LDAPError):
    pass


class EntryNotFound(LDAPError):
    pass


class EntryExists(LDAPError):
    pass


class AccountStatus(Enum):
    ACTIVE = "active"
    LOCKED = "locked"
    DISABLED = "disabled"


class Scope(Enum):
    BASE = "base"
    ONE = "one"
    SUBTREE = "subtree"


def normalize_dn(dn: str) -> str:
    """Normalize a basic DN representation for this educational directory."""
    if not isinstance(dn, str) or not dn.strip():
        raise InvalidDN("DN cannot be empty.")

    parts = []
    escaped = False
    current = []

    for char in dn.strip():
        if char == "," and not escaped:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)

        if char == "\\" and not escaped:
            escaped = True
        else:
            escaped = False

    parts.append("".join(current).strip())

    normalized = []

    for part in parts:
        if "=" not in part:
            raise InvalidDN(f"Invalid RDN: {part}")

        attribute, value = part.split("=", 1)
        attribute = attribute.strip().lower()
        value = value.strip()

        if not re.fullmatch(r"[a-z][a-z0-9-]*", attribute):
            raise InvalidDN(f"Invalid attribute name: {attribute}")

        if not value:
            raise InvalidDN("RDN value cannot be empty.")

        normalized.append(f"{attribute}={value.casefold()}")

    return ",".join(normalized)


def dn_within(dn: str, base: str) -> bool:
    """Check DN suffix boundaries instead of unsafe substring matching."""
    return dn == base or dn.endswith("," + base)


def dn_depth(dn: str) -> int:
    return len(dn.split(","))


@dataclass
class DirectoryEntry:
    dn: str
    attributes: dict[str, list[str]]
    password_hash: Optional[bytes] = None
    password_salt: Optional[bytes] = None
    password_iterations: int = 180_000
    status: AccountStatus = AccountStatus.ACTIVE
    failed_attempts: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def __post_init__(self):
        self.dn = normalize_dn(self.dn)

        normalized = {}

        for key, values in self.attributes.items():
            key = key.lower()

            if not re.fullmatch(r"[a-z][a-z0-9-]*", key):
                raise LDAPError(f"Invalid attribute: {key}")

            if isinstance(values, str):
                values = [values]

            normalized[key] = [str(v) for v in values]

        self.attributes = normalized

        if "objectclass" not in self.attributes:
            raise LDAPError("Every entry requires objectClass.")

    def get(self, attribute: str) -> list[str]:
        return self.attributes.get(attribute.lower(), [])


@dataclass(frozen=True)
class SearchResult:
    dn: str
    attributes: dict[str, tuple[str, ...]]


class LDAPFilter:
    """
    Small safe LDAP filter evaluator.

    Supports:
      (&(department=Engineering)(active=true))
      (|(uid=alice)(uid=bob))
      (!(active=false))
      (uid=*)
      (uid=alice)
    """

    def __init__(self, expression: str):
        self.expression = expression
        self.position = 0
        self.ast = self._parse()

        if self.position != len(expression):
            raise InvalidFilter("Unexpected characters in filter.")

    def _parse(self):
        text = self.expression

        if not text.startswith("("):
            raise InvalidFilter("Filter must begin with '('.")

        self.position += 1

        if self.position >= len(text):
            raise InvalidFilter("Incomplete filter.")

        operator = text[self.position]

        if operator in "&|":
            self.position += 1
            children = []

            while self.position < len(text) and text[self.position] == "(":
                children.append(self._parse())

            if not children:
                raise InvalidFilter("Logical filters require operands.")

            if self._consume() != ")":
                raise InvalidFilter("Missing closing parenthesis.")

            return (operator, children)

        if operator == "!":
            self.position += 1
            child = self._parse()

            if self._consume() != ")":
                raise InvalidFilter("Missing closing parenthesis.")

            return ("!", child)

        start = self.position

        while self.position < len(text):
            char = text[self.position]

            if char == ")":
                break

            if char == "(":
                raise InvalidFilter("Unexpected nested attribute expression.")

            self.position += 1

        if self.position >= len(text):
            raise InvalidFilter("Missing closing parenthesis.")

        expression = text[start:self.position]
        self.position += 1

        if "=" not in expression:
            raise InvalidFilter("Equality operator required.")

        attribute, value = expression.split("=", 1)
        attribute = attribute.lower()

        if not re.fullmatch(r"[a-z][a-z0-9-]*", attribute):
            raise InvalidFilter("Invalid attribute name.")

        if any(ord(c) < 32 for c in value):
            raise InvalidFilter("Control characters are not allowed.")

        return ("=", attribute, value)

    def _consume(self):
        if self.position >= len(self.expression):
            return None

        char = self.expression[self.position]
        self.position += 1
        return char

    @staticmethod
    def _equal(value: str, expected: str) -> bool:
        """Case-insensitive matching for this simplified directory."""
        return value.casefold() == expected.casefold()

    def matches(self, entry: DirectoryEntry) -> bool:
        def evaluate(node):
            operator = node[0]

            if operator == "&":
                return all(evaluate(child) for child in node[1])

            if operator == "|":
                return any(evaluate(child) for child in node[1])

            if operator == "!":
                return not evaluate(node[1])

            _, attribute, expected = node
            values = entry.get(attribute)

            if expected == "*":
                return bool(values)

            return any(self._equal(value, expected) for value in values)

        return evaluate(self.ast)


class PasswordManager:
    """PBKDF2 password storage with constant-time verification."""

    ITERATIONS = 180_000

    @classmethod
    def hash_password(cls, password: str):
        if not isinstance(password, str) or len(password) < 12:
            raise LDAPError("Password must contain at least 12 characters.")

        salt = secrets.token_bytes(32)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            cls.ITERATIONS
        )

        return salt, digest

    @staticmethod
    def verify(password: str, salt: bytes, expected: bytes, iterations: int):
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations
        )

        return hmac.compare_digest(actual, expected)


class AccessController:
    """Simple role-based directory authorization."""

    PERMISSIONS = {
        "administrator": {"read", "search", "write", "delete"},
        "directory-manager": {"read", "search", "write"},
        "employee": {"read", "search"},
        "service-account": {"read", "search"},
    }

    @classmethod
    def authorize(cls, role: str, operation: str):
        allowed = cls.PERMISSIONS.get(role, set())

        if operation not in allowed:
            raise AuthorizationError(
                f"Role '{role}' cannot perform '{operation}'."
            )


class LDAPDirectory:
    def __init__(self, max_failures: int = 5):
        self.entries: dict[str, DirectoryEntry] = {}
        self.max_failures = max_failures
        self.audit: list[dict[str, Any]] = {}

        self.audit = []

    def _log(self, operation: str, dn: str, outcome: str):
        self.audit.append({
            "timestamp": time.time(),
            "operation": operation,
            "dn": dn,
            "outcome": outcome
        })

    def add_entry(self, entry: DirectoryEntry, role="administrator"):
        AccessController.authorize(role, "write")

        dn = normalize_dn(entry.dn)

        if dn in self.entries:
            raise EntryExists(dn)

        parent = ",".join(dn.split(",")[1:])

        if parent and parent not in self.entries:
            raise EntryNotFound(f"Parent entry does not exist: {parent}")

        self.entries[dn] = entry
        self._log("ADD", dn, "SUCCESS")

    def delete_entry(self, dn: str, role="administrator"):
        AccessController.authorize(role, "delete")

        dn = normalize_dn(dn)

        if dn not in self.entries:
            raise EntryNotFound(dn)

        descendants = [
            key for key in self.entries
            if key != dn and dn_within(key, dn)
        ]

        if descendants:
            raise LDAPError("Cannot delete an entry with descendants.")

        del self.entries[dn]
        self._log("DELETE", dn, "SUCCESS")

    def bind(self, dn: str, password: str) -> bool:
        dn = normalize_dn(dn)
        entry = self.entries.get(dn)

        if entry is None:
            self._log("BIND", dn, "INVALID_CREDENTIALS")
            raise AuthenticationError("Invalid credentials.")

        if entry.status != AccountStatus.ACTIVE:
            self._log("BIND", dn, "ACCOUNT_UNAVAILABLE")
            raise AuthenticationError("Account unavailable.")

        if not entry.password_hash or not entry.password_salt:
            raise AuthenticationError("Account has no password verifier.")

        valid = PasswordManager.verify(
            password,
            entry.password_salt,
            entry.password_hash,
            entry.password_iterations
        )

        if not valid:
            entry.failed_attempts += 1

            if entry.failed_attempts >= self.max_failures:
                entry.status = AccountStatus.LOCKED

            self._log("BIND", dn, "INVALID_CREDENTIALS")
            raise AuthenticationError("Invalid credentials.")

        entry.failed_attempts = 0
        self._log("BIND", dn, "SUCCESS")
        return True

    def search(
        self,
        base_dn: str,
        expression: str,
        scope: Scope = Scope.SUBTREE,
        attributes: Optional[list[str]] = None,
        role: str = "employee",
        limit: int = 100
    ) -> list[SearchResult]:

        AccessController.authorize(role, "search")

        base = normalize_dn(base_dn)

        if base not in self.entries:
            raise EntryNotFound(base)

        if limit < 1 or limit > 1000:
            raise LDAPError("Search limit must be between 1 and 1000.")

        ldap_filter = LDAPFilter(expression)
        results = []

        for dn, entry in self.entries.items():
            if scope == Scope.BASE and dn != base:
                continue

            if scope == Scope.ONE:
                if dn_depth(dn) != dn_depth(base) + 1:
                    continue

                if not dn_within(dn, base):
                    continue

            if scope == Scope.SUBTREE and not dn_within(dn, base):
                continue

            if not ldap_filter.matches(entry):
                continue

            selected = {}

            requested = (
                attributes
                if attributes is not None
                else list(entry.attributes.keys())
            )

            for attribute in requested:
                key = attribute.lower()

                if key in entry.attributes:
                    selected[key] = tuple(entry.attributes[key])

            results.append(SearchResult(dn, selected))

            if len(results) >= limit:
                break

        self._log("SEARCH", base, f"RESULTS={len(results)}")

        return results

    def update_attribute(
        self,
        dn: str,
        attribute: str,
        values: list[str],
        role: str = "directory-manager"
    ):
        AccessController.authorize(role, "write")

        dn = normalize_dn(dn)
        entry = self.entries.get(dn)

        if entry is None:
            raise EntryNotFound(dn)

        attribute = attribute.lower()

        if attribute in {"objectclass", "userpassword"}:
            raise AuthorizationError(
                "Protected attributes require dedicated operations."
            )

        if not re.fullmatch(r"[a-z][a-z0-9-]*", attribute):
            raise LDAPError("Invalid attribute name.")

        if not values or any(not isinstance(v, str) for v in values):
            raise LDAPError("Attribute values must be nonempty strings.")

        entry.attributes[attribute] = list(dict.fromkeys(values))
        entry.updated_at = time.time()

        self._log("MODIFY", dn, "SUCCESS")

    def change_password(self, dn: str, new_password: str):
        dn = normalize_dn(dn)

        entry = self.entries.get(dn)

        if entry is None:
            raise EntryNotFound(dn)

        salt, digest = PasswordManager.hash_password(new_password)

        entry.password_salt = salt
        entry.password_hash = digest
        entry.password_iterations = PasswordManager.ITERATIONS
        entry.failed_attempts = 0
        entry.status = AccountStatus.ACTIVE
        entry.updated_at = time.time()

        self._log("PASSWORD_CHANGE", dn, "SUCCESS")

    def reset_account(self, dn: str, role="administrator"):
        AccessController.authorize(role, "write")

        dn = normalize_dn(dn)
        entry = self.entries.get(dn)

        if entry is None:
            raise EntryNotFound(dn)

        entry.failed_attempts = 0
        entry.status = AccountStatus.ACTIVE

        self._log("ACCOUNT_RESET", dn, "SUCCESS")


def build_directory() -> LDAPDirectory:
    directory = LDAPDirectory()

    base = DirectoryEntry(
        "dc=example,dc=com",
        {"objectClass": ["top", "domain"], "dc": ["example"]}
    )

    directory.add_entry(base)

    directory.add_entry(DirectoryEntry(
        "ou=people,dc=example,dc=com",
        {"objectClass": ["top", "organizationalUnit"],
         "ou": ["people"]}
    ))

    directory.add_entry(DirectoryEntry(
        "ou=engineering,dc=example,dc=com",
        {"objectClass": ["top", "organizationalUnit"],
         "ou": ["engineering"]}
    ))

    users = [
        {
            "uid": "alice",
            "name": "Alice Sharma",
            "department": "Engineering",
            "role": "employee"
        },
        {
            "uid": "bob",
            "name": "Bob Kumar",
            "department": "Security",
            "role": "directory-manager"
        },
        {
            "uid": "carol",
            "name": "Carol Singh",
            "department": "Engineering",
            "role": "employee"
        }
    ]

    for user in users:
        dn = f"uid={user['uid']},ou=people,dc=example,dc=com"

        entry = DirectoryEntry(
            dn,
            {
                "objectClass": ["top", "person", "inetOrgPerson"],
                "uid": [user["uid"]],
                "cn": [user["name"]],
                "sn": [user["name"].split()[-1]],
                "department": [user["department"]],
                "mail": [f"{user['uid']}@example.com"],
                "active": ["true"],
                "role": [user["role"]]
            }
        )

        directory.add_entry(entry)

    directory.change_password(
        "uid=alice,ou=people,dc=example,dc=com",
        "Alice-Secure-Password-2026"
    )

    directory.change_password(
        "uid=bob,ou=people,dc=example,dc=com",
        "Bob-Secure-Password-2026"
    )

    directory.change_password(
        "uid=carol,ou=people,dc=example,dc=com",
        "Carol-Secure-Password-2026"
    )

    return directory


def main():
    directory = build_directory()

    print("LDAP DIRECTORY DEMONSTRATION")
    print("=" * 60)

    base = "dc=example,dc=com"

    print("\n1. SUBTREE SEARCH: Engineering employees")

    results = directory.search(
        base,
        "(&(department=Engineering)(active=true))",
        Scope.SUBTREE,
        ["uid", "cn", "department", "mail"]
    )

    for result in results:
        print(result.dn, dict(result.attributes))

    print("\n2. ONE-LEVEL SEARCH")

    results = directory.search(
        "ou=people,dc=example,dc=com",
        "(objectclass=inetOrgPerson)",
        Scope.ONE,
        ["uid", "cn"]
    )

    for result in results:
        print(result.dn, dict(result.attributes))

    print("\n3. AUTHENTICATION")

    alice_dn = "uid=alice,ou=people,dc=example,dc=com"

    try:
        directory.bind(alice_dn, "Alice-Secure-Password-2026")
        print("Alice authenticated successfully.")
    except AuthenticationError as exc:
        print("Authentication failed:", exc)

    print("\n4. INVALID AUTHENTICATION")

    try:
        directory.bind(alice_dn, "incorrect-password")
    except AuthenticationError as exc:
        print("Rejected:", exc)

    print("\n5. ATTRIBUTE MODIFICATION")

    directory.update_attribute(
        alice_dn,
        "telephoneNumber",
        ["+91-9876543210"]
    )

    print(directory.entries[alice_dn].get("telephonenumber"))

    print("\n6. ACCESS CONTROL")

    try:
        directory.update_attribute(
            alice_dn,
            "department",
            ["Administration"],
            role="employee"
        )
    except AuthorizationError as exc:
        print("Unauthorized operation:", exc)

    print("\n7. INVALID FILTER")

    try:
        LDAPFilter("department=Engineering")
    except InvalidFilter as exc:
        print("Filter rejected:", exc)

    print("\n8. DIRECTORY AUDIT")

    for event in directory.audit[-10:]:
        print(event)

    print("\n9. ASSERTIONS")

    assert len(directory.search(
        base,
        "(uid=alice)",
        Scope.SUBTREE
    )) == 1

    assert len(directory.search(
        base,
        "(uid=missing)",
        Scope.SUBTREE
    )) == 0

    assert directory.bind(
        alice_dn,
        "Alice-Secure-Password-2026"
    )

    print("All assertions passed.")


if __name__ == "__main__":
    main()
