#!/usr/bin/env python3
"""
Zero Trust Security Model
=========================
Implements:
- Explicit identity verification
- Multi-factor authentication status
- Device posture validation
- Least-privilege authorization
- Resource-level segmentation
- Context-aware access decisions
- Continuous session evaluation
- Session expiration and revocation
- Immutable-style security audit events

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import json
import logging
import secrets
import time

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("zero-trust")


# ---------------------------------------------------------
# Domain enums
# ---------------------------------------------------------

class AccessDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVOKE = "REVOKE"


class TrustLevel(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    VERIFIED = "VERIFIED"
    HIGH = "HIGH"


class ResourceZone(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"
    CRITICAL = "CRITICAL"


class Action(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ADMIN = "ADMIN"


class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class ZeroTrustError(Exception):
    pass


class ValidationError(ZeroTrustError):
    pass


class AuthenticationError(ZeroTrustError):
    pass


class AuthorizationError(ZeroTrustError):
    pass


class SessionError(ZeroTrustError):
    pass


# ---------------------------------------------------------
# Data models
# ---------------------------------------------------------

@dataclass(frozen=True)
class Identity:
    user_id: str
    username: str
    roles: frozenset[str]
    enabled: bool = True
    mfa_verified: bool = False

    def __post_init__(self):
        if not self.user_id or not self.username:
            raise ValidationError("Identity identifiers are required.")

        if not self.roles:
            raise ValidationError("An identity must have at least one role.")


@dataclass(frozen=True)
class Device:
    device_id: str
    owner_id: str
    managed: bool
    encrypted: bool
    patched: bool
    endpoint_protected: bool
    risk_score: int

    def __post_init__(self):
        if not 0 <= self.risk_score <= 100:
            raise ValidationError("Device risk must be between 0 and 100.")

    @property
    def compliant(self) -> bool:
        return (
            self.managed
            and self.encrypted
            and self.patched
            and self.endpoint_protected
            and self.risk_score <= 30
        )


@dataclass(frozen=True)
class Resource:
    resource_id: str
    name: str
    zone: ResourceZone
    allowed_roles: frozenset[str]
    allowed_actions: frozenset[Action]
    minimum_trust: TrustLevel
    require_mfa: bool = True

    def __post_init__(self):
        if not self.resource_id or not self.allowed_roles:
            raise ValidationError("Invalid resource configuration.")


@dataclass(frozen=True)
class AccessContext:
    source_ip: str
    network_zone: str
    requested_action: Action
    risk_score: int
    current_time: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self):
        import ipaddress

        try:
            ipaddress.ip_address(self.source_ip)
        except ValueError as exc:
            raise ValidationError("Invalid source IP address.") from exc

        if not 0 <= self.risk_score <= 100:
            raise ValidationError("Context risk must be between 0 and 100.")


@dataclass
class SecuritySession:
    session_id: str
    user_id: str
    device_id: str
    resource_id: str
    issued_at: datetime
    expires_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE
    last_evaluated: Optional[datetime] = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: datetime
    user_id: str
    resource_id: str
    decision: AccessDecision
    reason: str
    session_id: Optional[str]


# ---------------------------------------------------------
# Identity verification
# ---------------------------------------------------------

class IdentityProvider:

    def __init__(self):
        self.identities: dict[str, Identity] = {}

    def register(self, identity: Identity) -> None:
        if identity.user_id in self.identities:
            raise ValidationError("Duplicate identity.")

        self.identities[identity.user_id] = identity

    def verify(self, user_id: str) -> Identity:
        identity = self.identities.get(user_id)

        if identity is None or not identity.enabled:
            raise AuthenticationError("Identity verification failed.")

        return identity


# ---------------------------------------------------------
# Device trust evaluation
# ---------------------------------------------------------

class DevicePostureService:

    def evaluate(self, device: Device, identity: Identity) -> TrustLevel:
        if device.owner_id != identity.user_id:
            return TrustLevel.UNTRUSTED

        if not device.compliant:
            return TrustLevel.UNTRUSTED

        if identity.mfa_verified and device.risk_score <= 10:
            return TrustLevel.HIGH

        return TrustLevel.VERIFIED


# ---------------------------------------------------------
# Resource segmentation
# ---------------------------------------------------------

class ResourceRegistry:

    def __init__(self):
        self.resources: dict[str, Resource] = {}

    def register(self, resource: Resource) -> None:
        if resource.resource_id in self.resources:
            raise ValidationError("Duplicate resource.")

        self.resources[resource.resource_id] = resource

    def get(self, resource_id: str) -> Resource:
        resource = self.resources.get(resource_id)

        if resource is None:
            raise AuthorizationError("Resource does not exist.")

        return resource


# ---------------------------------------------------------
# Central policy engine
# ---------------------------------------------------------

class PolicyEngine:

    TRUST_RANK = {
        TrustLevel.UNTRUSTED: 0,
        TrustLevel.VERIFIED: 1,
        TrustLevel.HIGH: 2,
    }

    def __init__(self, device_service: DevicePostureService):
        self.device_service = device_service

    def evaluate(
        self,
        identity: Identity,
        device: Device,
        resource: Resource,
        context: AccessContext,
    ) -> tuple[AccessDecision, str]:

        if not identity.enabled:
            return AccessDecision.DENY, "Identity disabled."

        if context.risk_score >= 80:
            return AccessDecision.DENY, "High contextual risk."

        if not device.compliant:
            return AccessDecision.DENY, "Device posture is noncompliant."

        if resource.require_mfa and not identity.mfa_verified:
            return AccessDecision.DENY, "MFA verification required."

        if not identity.roles.intersection(resource.allowed_roles):
            return AccessDecision.DENY, "Role not authorized."

        if context.requested_action not in resource.allowed_actions:
            return AccessDecision.DENY, "Action not permitted."

        trust = self.device_service.evaluate(device, identity)

        if self.TRUST_RANK[trust] < self.TRUST_RANK[resource.minimum_trust]:
            return AccessDecision.DENY, "Insufficient device trust."

        if resource.zone == ResourceZone.CRITICAL:
            if context.risk_score > 10:
                return AccessDecision.DENY, "Critical resource risk threshold exceeded."

            if context.network_zone != "CORPORATE":
                return AccessDecision.DENY, "Critical resource requires corporate network."

            if trust != TrustLevel.HIGH:
                return AccessDecision.DENY, "High device trust required."

        elif resource.zone == ResourceZone.RESTRICTED:
            if context.network_zone not in {"CORPORATE", "VPN"}:
                return AccessDecision.DENY, "Restricted resource requires approved network."

        return AccessDecision.ALLOW, "All access policies satisfied."


# ---------------------------------------------------------
# Session management and continuous evaluation
# ---------------------------------------------------------

class SessionManager:

    def __init__(self, lifetime_minutes: int = 15):
        if lifetime_minutes <= 0:
            raise ValidationError("Session lifetime must be positive.")

        self.lifetime = timedelta(minutes=lifetime_minutes)
        self.sessions: dict[str, SecuritySession] = {}

    def create(
        self,
        identity: Identity,
        device: Device,
        resource: Resource,
        now: datetime,
    ) -> SecuritySession:

        session = SecuritySession(
            session_id=secrets.token_urlsafe(24),
            user_id=identity.user_id,
            device_id=device.device_id,
            resource_id=resource.resource_id,
            issued_at=now,
            expires_at=now + self.lifetime,
        )

        self.sessions[session.session_id] = session
        return session

    def get_active(self, session_id: str, now: datetime) -> SecuritySession:
        session = self.sessions.get(session_id)

        if session is None:
            raise SessionError("Unknown session.")

        if session.status != SessionStatus.ACTIVE:
            raise SessionError("Session is not active.")

        if now >= session.expires_at:
            session.status = SessionStatus.EXPIRED
            raise SessionError("Session expired.")

        return session

    def revoke(self, session_id: str) -> None:
        session = self.sessions.get(session_id)

        if session is None:
            raise SessionError("Unknown session.")

        session.status = SessionStatus.REVOKED


# ---------------------------------------------------------
# Audit service
# ---------------------------------------------------------

class AuditService:

    def __init__(self):
        self.events: list[AuditEvent] = []

    def record(
        self,
        user_id: str,
        resource_id: str,
        decision: AccessDecision,
        reason: str,
        session_id: Optional[str] = None,
    ) -> AuditEvent:

        event = AuditEvent(
            event_id=secrets.token_hex(12),
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            resource_id=resource_id,
            decision=decision,
            reason=reason,
            session_id=session_id,
        )

        self.events.append(event)
        return event

    def export_json(self, path: str) -> None:
        records = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "resource_id": e.resource_id,
                "decision": e.decision.value,
                "reason": e.reason,
                "session_id": e.session_id,
            }
            for e in self.events
        ]

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        with destination.open("w", encoding="utf-8") as file:
            json.dump(records, file, indent=2)


# ---------------------------------------------------------
# Zero Trust access service
# ---------------------------------------------------------

class ZeroTrustService:

    def __init__(self):
        self.identity_provider = IdentityProvider()
        self.device_service = DevicePostureService()
        self.resources = ResourceRegistry()
        self.policy = PolicyEngine(self.device_service)
        self.sessions = SessionManager()
        self.audit = AuditService()

        self.devices: dict[str, Device] = {}

    def register_device(self, device: Device) -> None:
        if device.device_id in self.devices:
            raise ValidationError("Duplicate device.")

        self.devices[device.device_id] = device

    def request_access(
        self,
        user_id: str,
        device_id: str,
        resource_id: str,
        context: AccessContext,
    ) -> tuple[AccessDecision, Optional[SecuritySession]]:

        session = None

        try:
            identity = self.identity_provider.verify(user_id)

            device = self.devices.get(device_id)

            if device is None:
                raise AuthenticationError("Unknown device.")

            resource = self.resources.get(resource_id)

            decision, reason = self.policy.evaluate(
                identity, device, resource, context
            )

            if decision == AccessDecision.ALLOW:
                session = self.sessions.create(
                    identity,
                    device,
                    resource,
                    context.current_time,
                )

            self.audit.record(
                user_id,
                resource_id,
                decision,
                reason,
                session.session_id if session else None,
            )

            return decision, session

        except ZeroTrustError as exc:
            self.audit.record(
                user_id,
                resource_id,
                AccessDecision.DENY,
                str(exc),
            )
            return AccessDecision.DENY, None

    def continuously_evaluate(
        self,
        session_id: str,
        context: AccessContext,
    ) -> AccessDecision:

        try:
            session = self.sessions.get_active(
                session_id,
                context.current_time,
            )

            identity = self.identity_provider.verify(session.user_id)

            device = self.devices.get(session.device_id)

            if device is None:
                raise SessionError("Session device no longer exists.")

            resource = self.resources.get(session.resource_id)

            decision, reason = self.policy.evaluate(
                identity, device, resource, context
            )

            session.last_evaluated = context.current_time

            if decision != AccessDecision.ALLOW:
                self.sessions.revoke(session_id)
                decision = AccessDecision.REVOKE

            self.audit.record(
                identity.user_id,
                resource.resource_id,
                decision,
                reason,
                session_id,
            )

            return decision

        except ZeroTrustError as exc:
            if session_id in self.sessions.sessions:
                self.sessions.revoke(session_id)

            self.audit.record(
                "SYSTEM",
                "UNKNOWN",
                AccessDecision.REVOKE,
                str(exc),
                session_id,
            )

            return AccessDecision.REVOKE


# ---------------------------------------------------------
# Executable scenario and assertions
# ---------------------------------------------------------

def run_demo() -> None:

    service = ZeroTrustService()

    now = datetime.now(timezone.utc)

    service.identity_provider.register(
        Identity(
            user_id="USR-101",
            username="analyst",
            roles=frozenset({"SECURITY_ANALYST"}),
            mfa_verified=True,
        )
    )

    service.register_device(
        Device(
            device_id="DEV-101",
            owner_id="USR-101",
            managed=True,
            encrypted=True,
            patched=True,
            endpoint_protected=True,
            risk_score=5,
        )
    )

    service.resources.register(
        Resource(
            resource_id="RES-101",
            name="Security Monitoring Dashboard",
            zone=ResourceZone.RESTRICTED,
            allowed_roles=frozenset({"SECURITY_ANALYST"}),
            allowed_actions=frozenset({Action.READ}),
            minimum_trust=TrustLevel.VERIFIED,
        )
    )

    service.resources.register(
        Resource(
            resource_id="RES-102",
            name="Production Administration",
            zone=ResourceZone.CRITICAL,
            allowed_roles=frozenset({"SECURITY_ADMIN"}),
            allowed_actions=frozenset({Action.ADMIN}),
            minimum_trust=TrustLevel.HIGH,
        )
    )

    print("\nZERO TRUST ACCESS EVALUATION")
    print("=" * 55)

    context = AccessContext(
        source_ip="10.10.1.25",
        network_zone="VPN",
        requested_action=Action.READ,
        risk_score=5,
        current_time=now,
    )

    decision, session = service.request_access(
        "USR-101",
        "DEV-101",
        "RES-101",
        context,
    )

    print("Valid request:", decision.value)
    assert decision == AccessDecision.ALLOW
    assert session is not None

    updated_context = AccessContext(
        source_ip="10.10.1.25",
        network_zone="VPN",
        requested_action=Action.READ,
        risk_score=90,
        current_time=now + timedelta(minutes=2),
    )

    continuous_result = service.continuously_evaluate(
        session.session_id,
        updated_context,
    )

    print("Continuous evaluation:", continuous_result.value)
    assert continuous_result == AccessDecision.REVOKE

    unauthorized_context = AccessContext(
        source_ip="10.10.1.25",
        network_zone="VPN",
        requested_action=Action.DELETE,
        risk_score=5,
        current_time=now,
    )

    denied, _ = service.request_access(
        "USR-101",
        "DEV-101",
        "RES-101",
        unauthorized_context,
    )

    print("Unauthorized action:", denied.value)
    assert denied == AccessDecision.DENY

    service.audit.export_json("zero_trust_audit.json")

    print("\nAUDIT REPORT")
    for event in service.audit.events:
        print(
            event.decision.value,
            event.user_id,
            event.resource_id,
            event.reason,
        )

    print("\nAll security assertions passed.")


if __name__ == "__main__":
    run_demo()
