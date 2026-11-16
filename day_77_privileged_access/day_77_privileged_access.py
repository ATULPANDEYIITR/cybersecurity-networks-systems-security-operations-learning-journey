#!/usr/bin/env python3
"""
Privileged Access Management (PAM)
Admin accounts, privileged groups, credential isolation,
just-in-time access, approval workflows, session controls,
credential rotation, and security auditing.

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import uuid

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("pam")


# ============================================================
# DOMAIN ENUMERATIONS
# ============================================================

class PrivilegeLevel(Enum):
    STANDARD = 1
    ELEVATED = 2
    ADMIN = 3
    SUPER_ADMIN = 4


class AccountStatus(Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"
    PENDING = "pending"


class RequestStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ReviewDecision(Enum):
    APPROVED = "approved"
    DENIED = "denied"


class AuditSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


# ============================================================
# CUSTOM EXCEPTIONS
# ============================================================

class PAMError(Exception):
    """Base exception for PAM operations."""


class ValidationError(PAMError):
    pass


class AuthorizationError(PAMError):
    pass


class CredentialError(PAMError):
    pass


class WorkflowError(PAMError):
    pass


class ResourceNotFoundError(PAMError):
    pass


# ============================================================
# DOMAIN MODELS
# ============================================================

@dataclass
class User:
    user_id: str
    username: str
    department: str
    is_active: bool = True
    mfa_enabled: bool = True
    roles: set[str] = field(default_factory=set)

    def __post_init__(self):
        if not self.username.strip():
            raise ValidationError("Username cannot be empty.")
        if not self.user_id.strip():
            raise ValidationError("User ID cannot be empty.")


@dataclass
class PrivilegedGroup:
    group_id: str
    name: str
    privilege_level: PrivilegeLevel
    members: set[str] = field(default_factory=set)
    requires_approval: bool = True
    maximum_session_minutes: int = 60


@dataclass
class PrivilegedAccount:
    account_id: str
    username: str
    system_name: str
    privilege_level: PrivilegeLevel
    status: AccountStatus = AccountStatus.ACTIVE
    group_ids: set[str] = field(default_factory=set)
    last_rotated: Optional[datetime] = None
    rotation_interval_days: int = 30

    def __post_init__(self):
        if not self.username or not self.system_name:
            raise ValidationError("Account and system names are required.")
        if self.rotation_interval_days < 1:
            raise ValidationError("Rotation interval must be positive.")


@dataclass
class AccessRequest:
    request_id: str
    requester_id: str
    account_id: str
    justification: str
    requested_minutes: int
    status: RequestStatus = RequestStatus.PENDING
    approver_id: Optional[str] = None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    approved_at: Optional[datetime] = None


@dataclass
class PrivilegedSession:
    session_id: str
    request_id: str
    user_id: str
    account_id: str
    started_at: datetime
    expires_at: datetime
    active: bool = True
    recorded: bool = True


@dataclass
class AuditEvent:
    event_id: str
    timestamp: datetime
    actor_id: str
    action: str
    resource: str
    severity: AuditSeverity
    details: dict


# ============================================================
# CREDENTIAL ISOLATION
# ============================================================

class CredentialVault:
    """
    Demonstration vault.

    Stores opaque credential references and one-way fingerprints,
    never returns stored credentials through normal application APIs.

    Production deployment must use a dedicated secrets manager,
    envelope encryption, hardware-backed key management, and
    authenticated secret retrieval.
    """

    def __init__(self):
        self._credentials: dict[str, dict] = {}

    def store(self, account_id: str, secret: str) -> str:
        if not secret or len(secret) < 16:
            raise ValidationError(
                "Credential must contain at least 16 characters."
            )

        reference = f"vault-{uuid.uuid4().hex}"

        fingerprint = hashlib.sha256(
            secret.encode("utf-8")
        ).hexdigest()

        self._credentials[account_id] = {
            "reference": reference,
            "fingerprint": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        return reference

    def get_reference(self, account_id: str) -> str:
        try:
            return self._credentials[account_id]["reference"]
        except KeyError as exc:
            raise CredentialError(
                "Credential not provisioned."
            ) from exc

    def rotate(self, account_id: str, new_secret: str) -> str:
        return self.store(account_id, new_secret)

    def exists(self, account_id: str) -> bool:
        return account_id in self._credentials


# ============================================================
# AUDIT SERVICE
# ============================================================

class AuditService:

    def __init__(self):
        self.events: list[AuditEvent] = []

    def record(
        self,
        actor_id: str,
        action: str,
        resource: str,
        severity: AuditSeverity = AuditSeverity.INFO,
        details: Optional[dict] = None
    ):
        event = AuditEvent(
            event_id=uuid.uuid4().hex,
            timestamp=datetime.now(timezone.utc),
            actor_id=actor_id,
            action=action,
            resource=resource,
            severity=severity,
            details=details or {}
        )

        self.events.append(event)

        logger.info(
            "%s actor=%s resource=%s",
            action,
            actor_id,
            resource
        )

    def export(self, filepath: str):
        records = []

        for event in self.events:
            record = asdict(event)
            record["timestamp"] = event.timestamp.isoformat()
            record["severity"] = event.severity.value
            records.append(record)

        Path(filepath).write_text(
            json.dumps(records, indent=2),
            encoding="utf-8"
        )


# ============================================================
# PRIVILEGED ACCESS MANAGEMENT ENGINE
# ============================================================

class PAMEngine:

    def __init__(self):
        self.users: dict[str, User] = {}
        self.groups: dict[str, PrivilegedGroup] = {}
        self.accounts: dict[str, PrivilegedAccount] = {}
        self.requests: dict[str, AccessRequest] = {}
        self.sessions: dict[str, PrivilegedSession] = {}

        self.vault = CredentialVault()
        self.audit = AuditService()

        # Prevent multiple active sessions for the same request.
        self.active_request_sessions: dict[str, str] = {}

    # --------------------------------------------------------
    # USER MANAGEMENT
    # --------------------------------------------------------

    def register_user(self, user: User):
        if user.user_id in self.users:
            raise ValidationError("User already exists.")

        self.users[user.user_id] = user

        self.audit.record(
            user.user_id,
            "USER_REGISTERED",
            user.user_id
        )

    def register_group(self, group: PrivilegedGroup):
        if group.group_id in self.groups:
            raise ValidationError("Group already exists.")

        if group.maximum_session_minutes < 1:
            raise ValidationError("Invalid session duration.")

        self.groups[group.group_id] = group

    def add_group_member(self, group_id: str, user_id: str):
        group = self._get_group(group_id)
        user = self._get_user(user_id)

        if not user.is_active:
            raise AuthorizationError("Inactive user cannot join group.")

        group.members.add(user_id)

        self.audit.record(
            user_id,
            "GROUP_MEMBERSHIP_GRANTED",
            group_id
        )

    # --------------------------------------------------------
    # PRIVILEGED ACCOUNT MANAGEMENT
    # --------------------------------------------------------

    def register_account(
        self,
        account: PrivilegedAccount,
        initial_secret: str
    ):
        if account.account_id in self.accounts:
            raise ValidationError("Account already exists.")

        for group_id in account.group_ids:
            self._get_group(group_id)

        self.vault.store(account.account_id, initial_secret)

        account.last_rotated = datetime.now(timezone.utc)
        self.accounts[account.account_id] = account

        self.audit.record(
            "SYSTEM",
            "PRIVILEGED_ACCOUNT_REGISTERED",
            account.account_id
        )

    def disable_account(self, account_id: str, actor_id: str):
        account = self._get_account(account_id)
        account.status = AccountStatus.DISABLED

        for session in self.sessions.values():
            if session.account_id == account_id and session.active:
                session.active = False

        self.audit.record(
            actor_id,
            "ACCOUNT_DISABLED",
            account_id,
            AuditSeverity.WARNING
        )

    # --------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------

    def _get_user(self, user_id: str) -> User:
        if user_id not in self.users:
            raise ResourceNotFoundError("User not found.")

        return self.users[user_id]

    def _get_group(self, group_id: str) -> PrivilegedGroup:
        if group_id not in self.groups:
            raise ResourceNotFoundError("Group not found.")

        return self.groups[group_id]

    def _get_account(self, account_id: str) -> PrivilegedAccount:
        if account_id not in self.accounts:
            raise ResourceNotFoundError("Account not found.")

        return self.accounts[account_id]

    def _eligible_groups(self, user_id: str, account_id: str):
        account = self._get_account(account_id)

        return [
            self._get_group(group_id)
            for group_id in account.group_ids
            if user_id in self._get_group(group_id).members
        ]

    def _authorize_request(
        self,
        requester: User,
        account: PrivilegedAccount,
        groups: list[PrivilegedGroup]
    ):
        if not requester.is_active:
            raise AuthorizationError("User is inactive.")

        if not requester.mfa_enabled:
            raise AuthorizationError("MFA is mandatory.")

        if account.status != AccountStatus.ACTIVE:
            raise AuthorizationError("Privileged account unavailable.")

        if not groups:
            raise AuthorizationError(
                "User has no authorized privileged group membership."
            )

        return max(
            group.maximum_session_minutes
            for group in groups
        )

    # --------------------------------------------------------
    # ACCESS REQUEST WORKFLOW
    # --------------------------------------------------------

    def request_access(
        self,
        requester_id: str,
        account_id: str,
        justification: str,
        requested_minutes: int
    ) -> AccessRequest:

        requester = self._get_user(requester_id)
        account = self._get_account(account_id)
        groups = self._eligible_groups(requester_id, account_id)

        maximum = self._authorize_request(
            requester,
            account,
            groups
        )

        if not justification.strip():
            raise ValidationError("Business justification is required.")

        if not 1 <= requested_minutes <= maximum:
            raise ValidationError(
                f"Session must be between 1 and {maximum} minutes."
            )

        request = AccessRequest(
            request_id=uuid.uuid4().hex,
            requester_id=requester_id,
            account_id=account_id,
            justification=justification.strip(),
            requested_minutes=requested_minutes
        )

        self.requests[request.request_id] = request

        self.audit.record(
            requester_id,
            "ACCESS_REQUEST_CREATED",
            request.request_id,
            details={
                "account_id": account_id,
                "requested_minutes": requested_minutes
            }
        )

        return request

    # --------------------------------------------------------
    # APPROVAL WORKFLOW
    # --------------------------------------------------------

    def approve_request(
        self,
        request_id: str,
        approver_id: str,
        decision: ReviewDecision
    ):

        if request_id not in self.requests:
            raise ResourceNotFoundError("Access request not found.")

        request = self.requests[request_id]
        approver = self._get_user(approver_id)

        if request.status != RequestStatus.PENDING:
            raise WorkflowError("Request is not pending.")

        if not approver.is_active or not approver.mfa_enabled:
            raise AuthorizationError("Approver authentication failed.")

        if approver_id == request.requester_id:
            raise AuthorizationError(
                "Self-approval is prohibited."
            )

        if "pam_approver" not in approver.roles:
            raise AuthorizationError(
                "User is not an authorized PAM approver."
            )

        if decision == ReviewDecision.DENIED:
            request.status = RequestStatus.DENIED
            request.approver_id = approver_id

            self.audit.record(
                approver_id,
                "ACCESS_REQUEST_DENIED",
                request_id,
                AuditSeverity.WARNING
            )
            return request

        # Revalidate access at approval time.
        requester = self._get_user(request.requester_id)
        account = self._get_account(request.account_id)
        groups = self._eligible_groups(
            request.requester_id,
            request.account_id
        )

        maximum = self._authorize_request(
            requester,
            account,
            groups
        )

        if request.requested_minutes > maximum:
            raise AuthorizationError(
                "Requested duration is no longer permitted."
            )

        request.status = RequestStatus.APPROVED
        request.approver_id = approver_id
        request.approved_at = datetime.now(timezone.utc)

        self.audit.record(
            approver_id,
            "ACCESS_REQUEST_APPROVED",
            request_id
        )

        return request

    # --------------------------------------------------------
    # JUST-IN-TIME ACCESS AND SESSION MANAGEMENT
    # --------------------------------------------------------

    def start_session(self, request_id: str) -> PrivilegedSession:

        if request_id not in self.requests:
            raise ResourceNotFoundError("Request not found.")

        request = self.requests[request_id]

        if request.status != RequestStatus.APPROVED:
            raise WorkflowError("Approved request required.")

        if request_id in self.active_request_sessions:
            raise WorkflowError("Session already created.")

        requester = self._get_user(request.requester_id)
        account = self._get_account(request.account_id)

        groups = self._eligible_groups(
            request.requester_id,
            request.account_id
        )

        self._authorize_request(requester, account, groups)

        if not self.vault.exists(account.account_id):
            raise CredentialError("Vault credential unavailable.")

        now = datetime.now(timezone.utc)

        session = PrivilegedSession(
            session_id=uuid.uuid4().hex,
            request_id=request_id,
            user_id=request.requester_id,
            account_id=request.account_id,
            started_at=now,
            expires_at=now + timedelta(
                minutes=request.requested_minutes
            )
        )

        self.sessions[session.session_id] = session
        self.active_request_sessions[request_id] = session.session_id

        request.status = RequestStatus.ACTIVE

        self.audit.record(
            requester.user_id,
            "PRIVILEGED_SESSION_STARTED",
            session.session_id,
            details={
                "account_id": account.account_id,
                "recorded": True
            }
        )

        return session

    def get_credential_reference(
        self,
        session_id: str,
        user_id: str
    ) -> str:

        session = self._get_session(session_id)

        if session.user_id != user_id:
            raise AuthorizationError("Session ownership mismatch.")

        if not session.active:
            raise AuthorizationError("Session is inactive.")

        if datetime.now(timezone.utc) >= session.expires_at:
            self._expire_session(session)
            raise AuthorizationError("Session expired.")

        account = self._get_account(session.account_id)

        if account.status != AccountStatus.ACTIVE:
            raise AuthorizationError("Account is unavailable.")

        # Returns a vault reference, never the secret itself.
        return self.vault.get_reference(session.account_id)

    def _get_session(self, session_id: str):
        if session_id not in self.sessions:
            raise ResourceNotFoundError("Session not found.")

        return self.sessions[session_id]

    def _expire_session(self, session: PrivilegedSession):
        session.active = False

        request = self.requests[session.request_id]
        request.status = RequestStatus.EXPIRED

        self.audit.record(
            "SYSTEM",
            "SESSION_EXPIRED",
            session.session_id
        )

    def end_session(self, session_id: str, actor_id: str):
        session = self._get_session(session_id)

        if not session.active:
            return

        session.active = False

        request = self.requests[session.request_id]

        if request.status == RequestStatus.ACTIVE:
            request.status = RequestStatus.EXPIRED

        self.audit.record(
            actor_id,
            "SESSION_TERMINATED",
            session_id
        )

    def revoke_session(self, session_id: str, actor_id: str):
        session = self._get_session(session_id)

        if not session.active:
            return

        session.active = False
        self.requests[session.request_id].status = RequestStatus.REVOKED

        self.audit.record(
            actor_id,
            "SESSION_REVOKED",
            session_id,
            AuditSeverity.CRITICAL
        )

    # --------------------------------------------------------
    # CREDENTIAL ROTATION
    # --------------------------------------------------------

    def rotate_credential(
        self,
        account_id: str,
        new_secret: str,
        actor_id: str
    ):
        account = self._get_account(account_id)

        if account.status != AccountStatus.ACTIVE:
            raise CredentialError(
                "Cannot rotate a disabled account."
            )

        self.vault.rotate(account_id, new_secret)

        account.last_rotated = datetime.now(timezone.utc)

        self.audit.record(
            actor_id,
            "CREDENTIAL_ROTATED",
            account_id,
            AuditSeverity.WARNING
        )

    def accounts_due_for_rotation(self):
        now = datetime.now(timezone.utc)

        return [
            account
            for account in self.accounts.values()
            if account.status == AccountStatus.ACTIVE
            and account.last_rotated is not None
            and now >= account.last_rotated + timedelta(
                days=account.rotation_interval_days
            )
        ]

    # --------------------------------------------------------
    # SECURITY MONITORING
    # --------------------------------------------------------

    def security_report(self):
        return {
            "users": len(self.users),
            "privileged_accounts": len(self.accounts),
            "privileged_groups": len(self.groups),
            "pending_requests": sum(
                r.status == RequestStatus.PENDING
                for r in self.requests.values()
            ),
            "active_sessions": sum(
                s.active for s in self.sessions.values()
            ),
            "rotation_due": len(self.accounts_due_for_rotation()),
            "critical_events": sum(
                e.severity == AuditSeverity.CRITICAL
                for e in self.audit.events
            )
        }


# ============================================================
# EXECUTABLE DEMONSTRATION
# ============================================================

def main():

    pam = PAMEngine()

    admin = User(
        "U001",
        "rahul.admin",
        "Infrastructure",
        roles={"pam_approver", "security_admin"}
    )

    operator = User(
        "U002",
        "neha.operator",
        "Infrastructure",
        roles={"system_operator"}
    )

    pam.register_user(admin)
    pam.register_user(operator)

    group = PrivilegedGroup(
        group_id="G001",
        name="Production Database Administrators",
        privilege_level=PrivilegeLevel.ADMIN,
        requires_approval=True,
        maximum_session_minutes=45
    )

    pam.register_group(group)
    pam.add_group_member("G001", "U002")

    account = PrivilegedAccount(
        account_id="A001",
        username="production_dba",
        system_name="production-postgresql",
        privilege_level=PrivilegeLevel.ADMIN,
        group_ids={"G001"},
        rotation_interval_days=30
    )

    # Demonstration credential only.
    pam.register_account(
        account,
        secrets.token_urlsafe(24)
    )

    request = pam.request_access(
        requester_id="U002",
        account_id="A001",
        justification="Investigate production database latency.",
        requested_minutes=30
    )

    print("\nACCESS REQUEST")
    print(request.request_id, request.status.value)

    pam.approve_request(
        request.request_id,
        "U001",
        ReviewDecision.APPROVED
    )

    session = pam.start_session(request.request_id)

    print("\nPRIVILEGED SESSION")
    print("Session:", session.session_id)
    print("Expires:", session.expires_at.isoformat())

    reference = pam.get_credential_reference(
        session.session_id,
        "U002"
    )

    print("Vault reference:", reference)
    print("Raw credential exposed:", False)

    pam.end_session(session.session_id, "U002")

    print("\nSECURITY REPORT")
    print(json.dumps(pam.security_report(), indent=2))

    # Negative test: self-approval must fail.
    try:
        second = pam.request_access(
            "U002",
            "A001",
            "Emergency database investigation.",
            15
        )

        pam.approve_request(
            second.request_id,
            "U002",
            ReviewDecision.APPROVED
        )

    except PAMError as error:
        print("\nEXPECTED SECURITY CONTROL:", error)

    # Demonstrate audit export.
    pam.audit.export("pam_audit.json")
    print("\nAudit events exported to pam_audit.json")

    # Basic correctness assertions.
    assert not session.active
    assert request.status == RequestStatus.EXPIRED
    assert pam.vault.exists("A001")


if __name__ == "__main__":
    main()
