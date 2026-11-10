#!/usr/bin/env python3
"""
Identity and Access Management (IAM)
Authentication, Authorization, Accounting, and Identity Lifecycle Management.

Python 3.10+
Standard-library only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("iam")


class IAMError(Exception):
    pass


class AuthenticationError(IAMError):
    pass


class AuthorizationError(IAMError):
    pass


class LifecycleError(IAMError):
    pass


class IdentityStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"
    TERMINATED = "terminated"


class Role(str, Enum):
    EMPLOYEE = "employee"
    MANAGER = "manager"
    SECURITY_ADMIN = "security_admin"
    AUDITOR = "auditor"


class Permission(str, Enum):
    READ_DOCUMENT = "document:read"
    WRITE_DOCUMENT = "document:write"
    DELETE_DOCUMENT = "document:delete"
    MANAGE_USERS = "users:manage"
    VIEW_AUDIT = "audit:read"
    MANAGE_ROLES = "roles:manage"


class EventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    IDENTITY_CREATED = "identity_created"
    IDENTITY_ACTIVATED = "identity_activated"
    IDENTITY_SUSPENDED = "identity_suspended"
    IDENTITY_DISABLED = "identity_disabled"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    PASSWORD_CHANGED = "password_changed"
    SESSION_REVOKED = "session_revoked"


@dataclass
class Identity:
    identity_id: str
    username: str
    email: str
    password_salt: bytes
    password_hash: bytes
    status: IdentityStatus = IdentityStatus.PENDING
    roles: set[Role] = field(default_factory=set)
    mfa_enabled: bool = False
    failed_attempts: int = 0
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    version: int = 1


@dataclass
class Session:
    token: str
    identity_id: str
    created_at: datetime
    expires_at: datetime
    revoked: bool = False


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    identity_id: Optional[str]
    event_type: EventType
    resource: str
    details: dict
    timestamp: datetime


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    identity_id: str
    permission: str
    reason: str


class IAMService:
    """In-memory IAM service demonstrating a complete IAM workflow."""

    ROLE_PERMISSIONS = {
        Role.EMPLOYEE: {
            Permission.READ_DOCUMENT,
            Permission.WRITE_DOCUMENT,
        },
        Role.MANAGER: {
            Permission.READ_DOCUMENT,
            Permission.WRITE_DOCUMENT,
            Permission.DELETE_DOCUMENT,
        },
        Role.SECURITY_ADMIN: set(Permission),
        Role.AUDITOR: {
            Permission.READ_DOCUMENT,
            Permission.VIEW_AUDIT,
        },
    }

    def __init__(
        self,
        session_minutes: int = 30,
        max_failed_attempts: int = 5,
        lockout_minutes: int = 15,
    ):
        if session_minutes <= 0 or max_failed_attempts <= 0:
            raise ValueError("Session duration and attempt limit must be positive")

        self.identities: dict[str, Identity] = {}
        self.username_index: dict[str, str] = {}
        self.sessions: dict[str, Session] = {}
        self.audit_log: list[AuditEvent] = {}
        self.audit_log = []
        self.session_minutes = session_minutes
        self.max_failed_attempts = max_failed_attempts
        self.lockout_minutes = lockout_minutes
        self.lockouts: dict[str, datetime] = {}

    @staticmethod
    def _normalize_username(username: str) -> str:
        value = username.strip().lower()
        if not value or len(value) > 100:
            raise ValueError("Invalid username")
        return value

    @staticmethod
    def _validate_password(password: str) -> None:
        if len(password) < 12:
            raise ValueError("Password must contain at least 12 characters")
        if len(password) > 1024:
            raise ValueError("Password is too long")

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            310_000,
            dklen=32,
        )

    def _audit(
        self,
        identity_id: Optional[str],
        event_type: EventType,
        resource: str,
        **details,
    ) -> None:
        # Never place passwords, password hashes, MFA secrets or tokens here.
        self.audit_log.append(
            AuditEvent(
                event_id=secrets.token_hex(12),
                identity_id=identity_id,
                event_type=event_type,
                resource=resource,
                details=details,
                timestamp=datetime.now(timezone.utc),
            )
        )

    def create_identity(
        self,
        username: str,
        email: str,
        password: str,
    ) -> Identity:
        username = self._normalize_username(username)
        email = email.strip().lower()

        self._validate_password(password)

        if "@" not in email or len(email) > 254:
            raise ValueError("Invalid email address")

        if username in self.username_index:
            raise ValueError("Username already exists")

        salt = secrets.token_bytes(16)

        identity = Identity(
            identity_id=secrets.token_hex(12),
            username=username,
            email=email,
            password_salt=salt,
            password_hash=self._hash_password(password, salt),
        )

        self.identities[identity.identity_id] = identity
        self.username_index[username] = identity.identity_id

        self._audit(
            identity.identity_id,
            EventType.IDENTITY_CREATED,
            "identity",
            username=username,
        )

        return identity

    def activate_identity(self, identity_id: str) -> None:
        identity = self._get_identity(identity_id)

        if identity.status != IdentityStatus.PENDING:
            raise LifecycleError("Only pending identities can be activated")

        identity.status = IdentityStatus.ACTIVE
        identity.version += 1

        self._audit(
            identity_id,
            EventType.IDENTITY_ACTIVATED,
            "identity",
        )

    def assign_role(self, identity_id: str, role: Role) -> None:
        identity = self._get_identity(identity_id)

        if identity.status != IdentityStatus.ACTIVE:
            raise LifecycleError("Roles can only be assigned to active identities")

        if not isinstance(role, Role):
            raise ValueError("Unknown role")

        if role in identity.roles:
            raise ValueError("Role already assigned")

        identity.roles.add(role)
        identity.version += 1

        self._audit(
            identity_id,
            EventType.ROLE_ASSIGNED,
            "identity",
            role=role.value,
        )

    def remove_role(self, identity_id: str, role: Role) -> None:
        identity = self._get_identity(identity_id)

        if role not in identity.roles:
            raise ValueError("Identity does not have this role")

        identity.roles.remove(role)
        identity.version += 1

        self._audit(
            identity_id,
            EventType.ROLE_REMOVED,
            "identity",
            role=role.value,
        )

    def enable_mfa(self, identity_id: str) -> None:
        identity = self._get_identity(identity_id)

        if identity.status != IdentityStatus.ACTIVE:
            raise LifecycleError("Identity must be active")

        identity.mfa_enabled = True
        identity.version += 1

    def authenticate(
        self,
        username: str,
        password: str,
        mfa_verified: bool = False,
    ) -> Session:
        username = self._normalize_username(username)
        identity_id = self.username_index.get(username)

        # Use a dummy derivation for unknown users to reduce timing differences.
        if identity_id is None:
            self._hash_password(password, b"\x00" * 16)
            self._audit(
                None,
                EventType.LOGIN_FAILURE,
                "authentication",
                username=username,
                reason="invalid_credentials",
            )
            raise AuthenticationError("Invalid credentials")

        identity = self.identities[identity_id]
        now = datetime.now(timezone.utc)

        locked_until = self.lockouts.get(identity_id)

        if locked_until and now < locked_until:
            raise AuthenticationError("Account temporarily locked")

        if identity.status != IdentityStatus.ACTIVE:
            self._audit(
                identity_id,
                EventType.LOGIN_FAILURE,
                "authentication",
                reason="identity_not_active",
            )
            raise AuthenticationError("Identity is not active")

        candidate = self._hash_password(password, identity.password_salt)

        if not hmac.compare_digest(candidate, identity.password_hash):
            identity.failed_attempts += 1

            self._audit(
                identity_id,
                EventType.LOGIN_FAILURE,
                "authentication",
                reason="invalid_credentials",
            )

            if identity.failed_attempts >= self.max_failed_attempts:
                self.lockouts[identity_id] = (
                    now + timedelta(minutes=self.lockout_minutes)
                )

            raise AuthenticationError("Invalid credentials")

        if identity.mfa_enabled and not mfa_verified:
            self._audit(
                identity_id,
                EventType.LOGIN_FAILURE,
                "authentication",
                reason="mfa_required",
            )
            raise AuthenticationError("MFA verification required")

        identity.failed_attempts = 0
        self.lockouts.pop(identity_id, None)

        token = secrets.token_urlsafe(32)

        session = Session(
            token=token,
            identity_id=identity_id,
            created_at=now,
            expires_at=now + timedelta(minutes=self.session_minutes),
        )

        self.sessions[token] = session

        self._audit(
            identity_id,
            EventType.LOGIN_SUCCESS,
            "session",
        )

        return session

    def authorize(
        self,
        token: str,
        permission: Permission,
        resource: str,
    ) -> AccessDecision:
        session = self.sessions.get(token)
        now = datetime.now(timezone.utc)

        if session is None or session.revoked:
            return AccessDecision(
                False, "", permission.value, "invalid_or_revoked_session"
            )

        if now >= session.expires_at:
            session.revoked = True
            self._audit(
                session.identity_id,
                EventType.SESSION_REVOKED,
                "session",
                reason="expired",
            )
            return AccessDecision(
                False, session.identity_id, permission.value, "session_expired"
            )

        identity = self.identities.get(session.identity_id)

        if identity is None or identity.status != IdentityStatus.ACTIVE:
            return AccessDecision(
                False, session.identity_id, permission.value, "identity_not_active"
            )

        granted = any(
            permission in self.ROLE_PERMISSIONS[role]
            for role in identity.roles
        )

        # Authorization is evaluated against current roles, not session-time roles.
        decision = AccessDecision(
            allowed=granted,
            identity_id=identity.identity_id,
            permission=permission.value,
            reason="role_permission_match" if granted else "permission_not_granted",
        )

        self._audit(
            identity.identity_id,
            EventType.ACCESS_GRANTED if granted else EventType.ACCESS_DENIED,
            resource,
            permission=permission.value,
        )

        return decision

    def logout(self, token: str) -> None:
        session = self.sessions.get(token)

        if session is None:
            return

        if not session.revoked:
            session.revoked = True

            self._audit(
                session.identity_id,
                EventType.LOGOUT,
                "session",
            )

    def suspend_identity(self, identity_id: str) -> None:
        identity = self._get_identity(identity_id)

        if identity.status != IdentityStatus.ACTIVE:
            raise LifecycleError("Only active identities can be suspended")

        identity.status = IdentityStatus.SUSPENDED
        identity.version += 1
        self._revoke_sessions(identity_id)

        self._audit(
            identity_id,
            EventType.IDENTITY_SUSPENDED,
            "identity",
        )

    def disable_identity(self, identity_id: str) -> None:
        identity = self._get_identity(identity_id)

        if identity.status in {
            IdentityStatus.DISABLED,
            IdentityStatus.TERMINATED,
        }:
            raise LifecycleError("Identity is already disabled or terminated")

        identity.status = IdentityStatus.DISABLED
        identity.version += 1
        self._revoke_sessions(identity_id)

        self._audit(
            identity_id,
            EventType.IDENTITY_DISABLED,
            "identity",
        )

    def terminate_identity(self, identity_id: str) -> None:
        identity = self._get_identity(identity_id)

        if identity.status not in {
            IdentityStatus.ACTIVE,
            IdentityStatus.SUSPENDED,
            IdentityStatus.DISABLED,
        }:
            raise LifecycleError("Invalid termination transition")

        identity.status = IdentityStatus.TERMINATED
        identity.roles.clear()
        identity.version += 1
        self._revoke_sessions(identity_id)

        self._audit(
            identity_id,
            EventType.IDENTITY_DISABLED,
            "identity",
            reason="terminated",
        )

    def reactivate_identity(self, identity_id: str) -> None:
        identity = self._get_identity(identity_id)

        if identity.status != IdentityStatus.SUSPENDED:
            raise LifecycleError("Only suspended identities can be reactivated")

        identity.status = IdentityStatus.ACTIVE
        identity.version += 1

        self._audit(
            identity_id,
            EventType.IDENTITY_ACTIVATED,
            "identity",
            reason="reactivated",
        )

    def change_password(
        self,
        identity_id: str,
        old_password: str,
        new_password: str,
    ) -> None:
        identity = self._get_identity(identity_id)
        self._validate_password(new_password)

        candidate = self._hash_password(old_password, identity.password_salt)

        if not hmac.compare_digest(candidate, identity.password_hash):
            raise AuthenticationError("Current password is incorrect")

        salt = secrets.token_bytes(16)
        identity.password_salt = salt
        identity.password_hash = self._hash_password(new_password, salt)
        identity.version += 1

        self._revoke_sessions(identity_id)

        self._audit(
            identity_id,
            EventType.PASSWORD_CHANGED,
            "credentials",
        )

    def _revoke_sessions(self, identity_id: str) -> None:
        for session in self.sessions.values():
            if session.identity_id == identity_id and not session.revoked:
                session.revoked = True

    def _get_identity(self, identity_id: str) -> Identity:
        identity = self.identities.get(identity_id)

        if identity is None:
            raise ValueError("Identity not found")

        return identity

    def accounting_report(self) -> dict:
        counts = {}

        for event in self.audit_log:
            key = event.event_type.value
            counts[key] = counts.get(key, 0) + 1

        return {
            "total_events": len(self.audit_log),
            "event_counts": counts,
            "active_identities": sum(
                i.status == IdentityStatus.ACTIVE
                for i in self.identities.values()
            ),
            "active_sessions": sum(
                not s.revoked and s.expires_at > datetime.now(timezone.utc)
                for s in self.sessions.values()
            ),
        }

    def export_audit_log(self, filename: str) -> None:
        # Production systems should use protected append-only storage.
        path = Path(filename)

        records = [
            {
                "event_id": e.event_id,
                "identity_id": e.identity_id,
                "event_type": e.event_type.value,
                "resource": e.resource,
                "details": e.details,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in self.audit_log
        ]

        path.write_text(
            json.dumps(records, indent=2),
            encoding="utf-8",
        )


def demonstrate() -> None:
    iam = IAMService()

    alice = iam.create_identity(
        "alice",
        "alice@example.org",
        "Alice-Strong-Password-2026",
    )

    iam.activate_identity(alice.identity_id)
    iam.assign_role(alice.identity_id, Role.EMPLOYEE)
    iam.enable_mfa(alice.identity_id)

    session = iam.authenticate(
        "alice",
        "Alice-Strong-Password-2026",
        mfa_verified=True,
    )

    read_result = iam.authorize(
        session.token,
        Permission.READ_DOCUMENT,
        "documents/annual-report.pdf",
    )

    delete_result = iam.authorize(
        session.token,
        Permission.DELETE_DOCUMENT,
        "documents/annual-report.pdf",
    )

    print("Read access:", read_result)
    print("Delete access:", delete_result)

    assert read_result.allowed
    assert not delete_result.allowed

    # Removing a role immediately changes authorization decisions.
    iam.logout(session.token)

    iam.suspend_identity(alice.identity_id)

    try:
        iam.authenticate(
            "alice",
            "Alice-Strong-Password-2026",
            mfa_verified=True,
        )
    except AuthenticationError as error:
        print("Expected authentication failure:", error)

    iam.reactivate_identity(alice.identity_id)

    print("Accounting report:")
    print(json.dumps(iam.accounting_report(), indent=2))

    iam.export_audit_log("iam_audit.json")


if __name__ == "__main__":
    demonstrate()
