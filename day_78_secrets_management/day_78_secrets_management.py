#!/usr/bin/env python3
"""
Secrets Management System
========================

Demonstrates:
- API keys, passwords, access tokens and service credentials
- Secure secret storage abstraction
- Secret lifecycle and version management
- Secret rotation and expiration
- Access control and least-privilege policies
- Secret exposure detection
- Audit logging
- Environment-based configuration
- Input validation and error handling

The in-memory vault is an educational implementation.
Production deployments should use an encrypted vault or a
managed secrets service with authenticated access.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import string
import time

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger("secrets_management")


class SecretType(Enum):
    API_KEY = "api_key"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    PASSWORD = "password"
    DATABASE_CREDENTIAL = "database_credential"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"


class SecretStatus(Enum):
    ACTIVE = "active"
    ROTATING = "rotating"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Permission(Enum):
    READ = "read"
    WRITE = "write"
    ROTATE = "rotate"
    REVOKE = "revoke"
    ADMIN = "admin"


class SecretError(Exception):
    """Base exception for secret-management failures."""


class SecretNotFoundError(SecretError):
    pass


class AccessDeniedError(SecretError):
    pass


class SecretExpiredError(SecretError):
    pass


class SecretValidationError(SecretError):
    pass


class RotationError(SecretError):
    pass


@dataclass(frozen=True)
class Principal:
    principal_id: str
    roles: frozenset[str]


@dataclass
class SecretVersion:
    version: int
    value: str = field(repr=False)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime | None = None
    status: SecretStatus = SecretStatus.ACTIVE

    def is_expired(self) -> bool:
        return (
            self.expires_at is not None
            and datetime.now(timezone.utc) >= self.expires_at
        )


@dataclass
class SecretRecord:
    secret_id: str
    name: str
    secret_type: SecretType
    owner: str
    environment: str
    versions: list[SecretVersion] = field(default_factory=list)
    tags: set[str] = field(default_factory=set)

    @property
    def current_version(self) -> SecretVersion:
        if not self.versions:
            raise SecretNotFoundError("Secret has no versions.")
        return self.versions[-1]


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    principal: str
    action: str
    secret_id: str
    timestamp: datetime
    outcome: str
    details: str


class AccessPolicy:
    """Role-based access control with explicit permissions."""

    ROLE_PERMISSIONS = {
        "developer": {Permission.READ},
        "operator": {
            Permission.READ,
            Permission.ROTATE
        },
        "security_admin": {
            Permission.READ,
            Permission.WRITE,
            Permission.ROTATE,
            Permission.REVOKE,
            Permission.ADMIN
        }
    }

    def authorize(
        self,
        principal: Principal,
        permission: Permission
    ) -> bool:
        if Permission.ADMIN in self.permissions(principal):
            return True

        return permission in self.permissions(principal)

    def permissions(self, principal: Principal) -> set[Permission]:
        result: set[Permission] = set()

        for role in principal.roles:
            result.update(self.ROLE_PERMISSIONS.get(role, set()))

        return result

    def require(
        self,
        principal: Principal,
        permission: Permission
    ) -> None:
        if not self.authorize(principal, permission):
            raise AccessDeniedError(
                f"Principal {principal.principal_id} "
                f"cannot perform {permission.value}."
            )


class SecretValidator:
    NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{2,99}$")

    @classmethod
    def validate_name(cls, name: str) -> None:
        if not cls.NAME_PATTERN.fullmatch(name):
            raise SecretValidationError(
                "Secret name must contain 3-100 valid characters."
            )

    @staticmethod
    def validate_value(value: str) -> None:
        if not isinstance(value, str) or not value:
            raise SecretValidationError("Secret value cannot be empty.")

        if len(value) > 65536:
            raise SecretValidationError("Secret exceeds maximum size.")

        if "\x00" in value:
            raise SecretValidationError("Secret contains invalid characters.")

    @staticmethod
    def validate_environment(environment: str) -> None:
        if environment not in {"development", "testing", "staging", "production"}:
            raise SecretValidationError("Invalid deployment environment.")


class SecretGenerator:
    """Generate cryptographically secure credentials."""

    @staticmethod
    def generate_api_key(length: int = 40) -> str:
        if not 24 <= length <= 128:
            raise SecretValidationError(
                "API key length must be between 24 and 128."
            )

        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_password(length: int = 32) -> str:
        if not 16 <= length <= 128:
            raise SecretValidationError(
                "Password length must be between 16 and 128."
            )

        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for _ in range(length))


class SecretScanner:
    """Detect likely exposed credentials in text."""

    PATTERNS = {
        "generic_api_key": re.compile(
            r"(?i)(api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})"
        ),
        "password": re.compile(
            r"(?i)(password|passwd)\s*[:=]\s*['\"]([^'\"]{8,})"
        ),
        "bearer_token": re.compile(
            r"(?i)bearer\s+([A-Za-z0-9._~-]{20,})"
        ),
        "private_key": re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        )
    }

    @classmethod
    def scan(cls, content: str) -> list[dict[str, Any]]:
        findings = []

        for category, pattern in cls.PATTERNS.items():
            for match in pattern.finditer(content):
                findings.append({
                    "category": category,
                    "position": match.start(),
                    "severity": "critical" if category == "private_key" else "high"
                })

        return findings

    @staticmethod
    def redact(content: str) -> str:
        patterns = [
            r"(?i)(api[_-]?key\s*[:=]\s*)['\"]?[A-Za-z0-9_-]{20,}",
            r"(?i)(password\s*[:=]\s*)['\"][^'\"]+['\"]",
            r"(?i)(bearer\s+)[A-Za-z0-9._~-]{20,}"
        ]

        for pattern in patterns:
            content = re.sub(
                pattern,
                lambda match: match.group(1) + "[REDACTED]",
                content
            )

        return content


class SecretVault:
    """
    Educational in-memory vault.

    A production vault must encrypt values at rest, authenticate
    clients, protect encryption keys separately and use durable,
    tamper-resistant audit storage.
    """

    def __init__(self, policy: AccessPolicy):
        self.policy = policy
        self.records: dict[str, SecretRecord] = {}
        self.name_index: dict[tuple[str, str], str] = {}
        self.audit_events: list[AuditEvent] = {}

    def _audit(
        self,
        principal: Principal,
        action: str,
        secret_id: str,
        outcome: str,
        details: str = ""
    ) -> None:
        self.audit_events.append(
            AuditEvent(
                event_id=secrets.token_hex(12),
                principal=principal.principal_id,
                action=action,
                secret_id=secret_id,
                timestamp=datetime.now(timezone.utc),
                outcome=outcome,
                details=details
            )
        )

    def create(
        self,
        principal: Principal,
        name: str,
        value: str,
        secret_type: SecretType,
        environment: str,
        owner: str,
        ttl_days: int | None = 90,
        tags: set[str] | None = None
    ) -> str:
        secret_id = secrets.token_hex(16)

        try:
            self.policy.require(principal, Permission.WRITE)
            SecretValidator.validate_name(name)
            SecretValidator.validate_value(value)
            SecretValidator.validate_environment(environment)

            if not owner:
                raise SecretValidationError("Owner is required.")

            if ttl_days is not None and not 1 <= ttl_days <= 3650:
                raise SecretValidationError("Invalid expiration period.")

            index_key = (environment, name)

            if index_key in self.name_index:
                raise SecretValidationError(
                    "Secret name already exists in this environment."
                )

            expires = (
                datetime.now(timezone.utc) + timedelta(days=ttl_days)
                if ttl_days is not None else None
            )

            record = SecretRecord(
                secret_id=secret_id,
                name=name,
                secret_type=secret_type,
                owner=owner,
                environment=environment,
                tags=tags or set()
            )

            record.versions.append(
                SecretVersion(
                    version=1,
                    value=value,
                    expires_at=expires
                )
            )

            self.records[secret_id] = record
            self.name_index[index_key] = secret_id

            self._audit(principal, "CREATE", secret_id, "SUCCESS")

            return secret_id

        except Exception as exc:
            self._audit(principal, "CREATE", secret_id, "FAILED", type(exc).__name__)
            raise

    def retrieve(
        self,
        principal: Principal,
        secret_id: str
    ) -> str:
        try:
            self.policy.require(principal, Permission.READ)

            record = self.records.get(secret_id)

            if record is None:
                raise SecretNotFoundError("Secret does not exist.")

            version = record.current_version

            if version.status == SecretStatus.REVOKED:
                raise SecretError("Secret has been revoked.")

            if version.is_expired() or version.status == SecretStatus.EXPIRED:
                version.status = SecretStatus.EXPIRED
                raise SecretExpiredError("Secret has expired.")

            self._audit(principal, "READ", secret_id, "SUCCESS")

            return version.value

        except Exception as exc:
            self._audit(principal, "READ", secret_id, "FAILED", type(exc).__name__)
            raise

    def rotate(
        self,
        principal: Principal,
        secret_id: str,
        new_value: str,
        ttl_days: int = 90
    ) -> int:
        try:
            self.policy.require(principal, Permission.ROTATE)
            SecretValidator.validate_value(new_value)

            if not 1 <= ttl_days <= 3650:
                raise SecretValidationError("Invalid expiration period.")

            record = self.records.get(secret_id)

            if record is None:
                raise SecretNotFoundError("Secret does not exist.")

            current = record.current_version

            if current.status == SecretStatus.REVOKED:
                raise RotationError("Cannot rotate a revoked secret.")

            if hmac.compare_digest(current.value, new_value):
                raise RotationError(
                    "New secret must differ from the existing secret."
                )

            current.status = SecretStatus.EXPIRED

            new_version = SecretVersion(
                version=current.version + 1,
                value=new_value,
                expires_at=datetime.now(timezone.utc)
                + timedelta(days=ttl_days)
            )

            record.versions.append(new_version)

            self._audit(
                principal,
                "ROTATE",
                secret_id,
                "SUCCESS",
                f"Version {new_version.version}"
            )

            return new_version.version

        except Exception as exc:
            self._audit(principal, "ROTATE", secret_id, "FAILED", type(exc).__name__)
            raise

    def revoke(
        self,
        principal: Principal,
        secret_id: str
    ) -> None:
        try:
            self.policy.require(principal, Permission.REVOKE)

            record = self.records.get(secret_id)

            if record is None:
                raise SecretNotFoundError("Secret does not exist.")

            for version in record.versions:
                version.status = SecretStatus.REVOKED

            self._audit(principal, "REVOKE", secret_id, "SUCCESS")

        except Exception as exc:
            self._audit(principal, "REVOKE", secret_id, "FAILED", type(exc).__name__)
            raise

    def metadata(self, principal: Principal, secret_id: str) -> dict:
        self.policy.require(principal, Permission.READ)

        record = self.records.get(secret_id)

        if record is None:
            raise SecretNotFoundError("Secret does not exist.")

        version = record.current_version

        return {
            "secret_id": record.secret_id,
            "name": record.name,
            "type": record.secret_type.value,
            "environment": record.environment,
            "owner": record.owner,
            "version": version.version,
            "status": version.status.value,
            "created_at": version.created_at.isoformat(),
            "expires_at": (
                version.expires_at.isoformat()
                if version.expires_at else None
            ),
            "tags": sorted(record.tags)
        }

    def rotation_candidates(self, days: int = 15) -> list[str]:
        if days < 0:
            raise ValueError("Days cannot be negative.")

        threshold = datetime.now(timezone.utc) + timedelta(days=days)

        return [
            record.secret_id
            for record in self.records.values()
            if record.current_version.status == SecretStatus.ACTIVE
            and record.current_version.expires_at is not None
            and record.current_version.expires_at <= threshold
        ]

    def audit_report(self) -> list[dict]:
        return [
            {
                "event_id": event.event_id,
                "principal": event.principal,
                "action": event.action,
                "secret_id": event.secret_id,
                "timestamp": event.timestamp.isoformat(),
                "outcome": event.outcome,
                "details": event.details
            }
            for event in self.audit_events
        ]


class SecretConfiguration:
    """Read non-secret configuration and secret references from environment."""

    @staticmethod
    def get_required(name: str) -> str:
        value = os.environ.get(name)

        if not value:
            raise SecretValidationError(
                f"Required configuration {name} is missing."
            )

        return value


def save_audit_report(
    events: list[dict],
    destination: str
) -> None:
    """Write metadata-only audit information with restricted file permissions."""

    path = Path(destination)

    if path.suffix.lower() != ".json":
        raise ValueError("Audit output must use a JSON file.")

    payload = json.dumps(events, indent=2)

    with path.open("x", encoding="utf-8") as file:
        file.write(payload)

    try:
        os.chmod(path, 0o600)
    except OSError:
        logger.warning("Could not restrict audit file permissions.")


def run_demonstration() -> None:
    print("\nSECRETS MANAGEMENT DEMONSTRATION")
    print("=" * 55)

    policy = AccessPolicy()
    vault = SecretVault(policy)

    administrator = Principal(
        "security-team",
        frozenset({"security_admin"})
    )

    developer = Principal(
        "application-developer",
        frozenset({"developer"})
    )

    operator = Principal(
        "platform-operator",
        frozenset({"operator"})
    )

    initial_key = SecretGenerator.generate_api_key()

    secret_id = vault.create(
        principal=administrator,
        name="payment_service_api",
        value=initial_key,
        secret_type=SecretType.API_KEY,
        environment="production",
        owner="payment-platform",
        ttl_days=90,
        tags={"payments", "external-api"}
    )

    print("\n1. Secret created")
    print(json.dumps(vault.metadata(administrator, secret_id), indent=2))

    retrieved = vault.retrieve(developer, secret_id)
    print("\n2. Authorized retrieval:", retrieved[:5] + "********")

    print("\n3. Unauthorized write attempt")

    try:
        vault.create(
            developer,
            "unauthorized_key",
            SecretGenerator.generate_api_key(),
            SecretType.API_KEY,
            "testing",
            "developer"
        )
    except AccessDeniedError as exc:
        print("Access denied:", exc)

    print("\n4. Secret rotation")

    new_key = SecretGenerator.generate_api_key()

    version = vault.rotate(
        operator,
        secret_id,
        new_key,
        ttl_days=90
    )

    print("New version:", version)
    print("Current version:", vault.metadata(administrator, secret_id)["version"])

    print("\n5. Exposure scanning")

    sample = (
        "api_key=sk_example_12345678901234567890 "
        "password='ExamplePassword123!'"
    )

    findings = SecretScanner.scan(sample)

    print("Detected findings:", len(findings))
    print("Redacted content:", SecretScanner.redact(sample))

    print("\n6. Rotation candidates")
    print(vault.rotation_candidates(days=15))

    print("\n7. Audit report")
    print(json.dumps(vault.audit_report(), indent=2))

    print("\n8. Revocation")

    vault.revoke(administrator, secret_id)

    try:
        vault.retrieve(developer, secret_id)
    except SecretError as exc:
        print("Retrieval blocked:", exc)

    print("\n9. Security checks")

    assert len(vault.records[secret_id].versions) == 2
    assert all(
        version.status == SecretStatus.REVOKED
        for version in vault.records[secret_id].versions
    )

    print("All demonstration assertions passed.")


if __name__ == "__main__":
    run_demonstration()
