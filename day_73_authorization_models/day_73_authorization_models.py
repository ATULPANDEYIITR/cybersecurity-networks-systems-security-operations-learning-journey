"""
Authorization Models: RBAC, ABAC, ACL, DAC, MAC, and Least Privilege.

A self-contained authorization engine demonstrating:
- Role-Based Access Control (RBAC)
- Attribute-Based Access Control (ABAC)
- Access Control Lists (ACL)
- Discretionary Access Control (DAC)
- Mandatory Access Control (MAC)
- Least-privilege enforcement
- Policy evaluation, audit logging, and access revocation

Run:
    python authorization_models.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any
import json
import logging
import os
import tempfile
import unittest
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s | %(message)s"
)

logger = logging.getLogger("authorization")


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    SHARE = "share"
    ADMIN = "admin"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3
    TOP_SECRET = 4


@dataclass(frozen=True)
class User:
    user_id: str
    department: str
    clearance: Classification
    location: str
    active: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Role:
    name: str
    permissions: set[Permission] = field(default_factory=set)


@dataclass
class Resource:
    resource_id: str
    owner_id: str
    department: str
    classification: Classification
    attributes: dict[str, Any] = field(default_factory=dict)
    acl: dict[str, set[Permission]] = field(default_factory=dict)


@dataclass(frozen=True)
class AccessRequest:
    user_id: str
    resource_id: str
    permission: Permission
    purpose: str
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class AuditEvent:
    user_id: str
    resource_id: str
    permission: str
    decision: str
    reasons: list[str]
    timestamp: str


class AuthorizationError(Exception):
    """Base authorization exception."""


class ValidationError(AuthorizationError):
    """Invalid identity, resource, or request."""


class PolicyConflictError(AuthorizationError):
    """Conflicting authorization configuration."""


class AuthorizationEngine:

    def __init__(self):
        self.users: dict[str, User] = {}
        self.roles: dict[str, Role] = {}
        self.user_roles: dict[str, set[str]] = {}
        self.resources: dict[str, Resource] = {}
        self.role_permissions: dict[str, set[Permission]] = {}
        self.deny_rules: list[dict[str, Any]] = []
        self.audit_log: list[AuditEvent] = []

    @staticmethod
    def validate_identifier(value: str, label: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{label} cannot be empty")

        if len(value) > 128:
            raise ValidationError(f"{label} exceeds 128 characters")

    def add_user(self, user: User) -> None:
        self.validate_identifier(user.user_id, "User ID")

        if user.user_id in self.users:
            raise ValidationError("User already exists")

        self.users[user.user_id] = user
        self.user_roles[user.user_id] = set()

    def add_role(self, role: Role) -> None:
        self.validate_identifier(role.name, "Role name")

        if role.name in self.roles:
            raise ValidationError("Role already exists")

        self.roles[role.name] = role

    def assign_role(self, user_id: str, role_name: str) -> None:
        self._require_user(user_id)

        if role_name not in self.roles:
            raise ValidationError("Unknown role")

        self.user_roles[user_id].add(role_name)

    def revoke_role(self, user_id: str, role_name: str) -> None:
        self._require_user(user_id)
        self.user_roles[user_id].discard(role_name)

    def add_resource(self, resource: Resource) -> None:
        self.validate_identifier(resource.resource_id, "Resource ID")
        self._require_user(resource.owner_id)

        if resource.resource_id in self.resources:
            raise ValidationError("Resource already exists")

        self.resources[resource.resource_id] = resource

    def grant_acl(
        self,
        resource_id: str,
        principal_id: str,
        permissions: set[Permission]
    ) -> None:
        resource = self._require_resource(resource_id)

        if principal_id not in self.users and principal_id not in self.roles:
            raise ValidationError("Unknown ACL principal")

        if not permissions:
            raise ValidationError("At least one permission is required")

        resource.acl.setdefault(principal_id, set()).update(permissions)

    def revoke_acl(
        self,
        resource_id: str,
        principal_id: str
    ) -> None:
        resource = self._require_resource(resource_id)
        resource.acl.pop(principal_id, None)

    def add_deny_rule(
        self,
        attribute: str,
        expected_value: Any,
        permission: Permission | None = None
    ) -> None:
        self.deny_rules.append({
            "attribute": attribute,
            "expected_value": expected_value,
            "permission": permission
        })

    def _require_user(self, user_id: str) -> User:
        user = self.users.get(user_id)

        if user is None:
            raise ValidationError(f"Unknown user: {user_id}")

        return user

    def _require_resource(self, resource_id: str) -> Resource:
        resource = self.resources.get(resource_id)

        if resource is None:
            raise ValidationError(f"Unknown resource: {resource_id}")

        return resource

    def evaluate_rbac(self, user_id: str, permission: Permission) -> bool:
        """
        A permission is available if at least one assigned role
        contains it.
        """
        for role_name in self.user_roles[user_id]:
            if permission in self.roles[role_name].permissions:
                return True

        return False

    def evaluate_abac(
        self,
        user: User,
        resource: Resource,
        request: AccessRequest
    ) -> bool:
        """
        Evaluate user, resource, and environmental attributes.
        """
        if request.purpose not in {
            "business",
            "research",
            "maintenance",
            "compliance"
        }:
            return False

        if (
            user.department != resource.department
            and request.purpose != "compliance"
        ):
            return False

        allowed_locations = resource.attributes.get(
            "allowed_locations"
        )

        if allowed_locations is not None:
            if user.location not in allowed_locations:
                return False

        required_mfa = resource.attributes.get("require_mfa", False)

        if required_mfa and not user.attributes.get("mfa_verified", False):
            return False

        return True

    def evaluate_acl(
        self,
        user: User,
        resource: Resource,
        permission: Permission
    ) -> bool:
        """
        ACL entries can identify individual users or role principals.
        """
        if permission in resource.acl.get(user.user_id, set()):
            return True

        for role_name in self.user_roles[user.user_id]:
            if permission in resource.acl.get(role_name, set()):
                return True

        return False

    def evaluate_dac(
        self,
        user: User,
        resource: Resource,
        permission: Permission
    ) -> bool:
        """
        Resource owners can exercise ownership authority.
        This does not override mandatory security restrictions.
        """
        return (
            user.user_id == resource.owner_id
            and permission in {
                Permission.READ,
                Permission.WRITE,
                Permission.SHARE
            }
        )

    def evaluate_mac(
        self,
        user: User,
        resource: Resource,
        permission: Permission
    ) -> bool:
        """
        Simplified confidentiality-oriented MAC:
        user clearance must dominate resource classification.

        This model does not implement a complete Bell-LaPadula
        information-flow system.
        """
        if user.clearance < resource.classification:
            return False

        if (
            permission == Permission.WRITE
            and resource.classification > user.clearance
        ):
            return False

        return True

    def evaluate_least_privilege(
        self,
        user: User,
        resource: Resource,
        permission: Permission
    ) -> bool:
        """
        Explicitly prohibit destructive operations on protected assets
        unless the user has an elevated maintenance attribute.
        """
        if permission == Permission.ADMIN:
            return user.attributes.get("privileged_admin", False)

        if permission == Permission.DELETE:
            return (
                user.attributes.get("delete_authorized", False)
                and resource.attributes.get("deletion_enabled", False)
            )

        return True

    def evaluate(
        self,
        request: AccessRequest
    ) -> tuple[Decision, list[str]]:
        user = self._require_user(request.user_id)
        resource = self._require_resource(request.resource_id)

        reasons: list[str] = []

        if not user.active:
            reasons.append("Inactive user")
            return Decision.DENY, reasons

        if request.timestamp.tzinfo is None:
            raise ValidationError("Request timestamp must be timezone-aware")

        # Explicit deny rules override grants from other models.
        for rule in self.deny_rules:
            if (
                rule["attribute"] in user.attributes
                and user.attributes[rule["attribute"]]
                == rule["expected_value"]
                and (
                    rule["permission"] is None
                    or rule["permission"] == request.permission
                )
            ):
                reasons.append("Explicit deny policy matched")
                return Decision.DENY, reasons

        if not self.evaluate_mac(user, resource, request.permission):
            reasons.append("MAC clearance requirement failed")

        else:
            reasons.append("MAC clearance satisfied")

        if not self.evaluate_least_privilege(
            user, resource, request.permission
        ):
            reasons.append("Least-privilege restriction failed")

        else:
            reasons.append("Least-privilege restriction satisfied")

        if (
            not self.evaluate_abac(user, resource, request)
        ):
            reasons.append("ABAC attributes or purpose rejected")

        else:
            reasons.append("ABAC conditions satisfied")

        # RBAC, ACL, and DAC are alternative grant mechanisms.
        granted = (
            self.evaluate_rbac(request.user_id, request.permission)
            or self.evaluate_acl(
                user, resource, request.permission
            )
            or self.evaluate_dac(
                user, resource, request.permission
            )
        )

        reasons.append(
            "RBAC, ACL, or DAC grant found"
            if granted
            else "No applicable grant found"
        )

        mandatory_conditions = (
            self.evaluate_mac(user, resource, request.permission)
            and self.evaluate_least_privilege(
                user, resource, request.permission
            )
            and self.evaluate_abac(user, resource, request)
        )

        decision = (
            Decision.ALLOW
            if granted and mandatory_conditions
            else Decision.DENY
        )

        return decision, reasons

    def authorize(self, request: AccessRequest) -> Decision:
        try:
            decision, reasons = self.evaluate(request)

        except AuthorizationError:
            self._record(
                request,
                Decision.DENY,
                ["Request validation failed"]
            )
            raise

        self._record(request, decision, reasons)

        logger.info(
            "Access %s | user=%s | resource=%s | permission=%s",
            decision.value,
            request.user_id,
            request.resource_id,
            request.permission.value
        )

        return decision

    def _record(
        self,
        request: AccessRequest,
        decision: Decision,
        reasons: list[str]
    ) -> None:
        self.audit_log.append(
            AuditEvent(
                user_id=request.user_id,
                resource_id=request.resource_id,
                permission=request.permission.value,
                decision=decision.value,
                reasons=reasons,
                timestamp=datetime.now(timezone.utc).isoformat()
            )
        )

    def export_audit(self, destination: Path) -> None:
        """
        Atomic file replacement prevents readers from observing
        a partially written audit file.
        """
        destination.parent.mkdir(parents=True, exist_ok=True)

        payload = [
            event.__dict__
            for event in self.audit_log
        ]

        temporary_path = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=destination.parent,
                delete=False
            ) as temporary:
                json.dump(payload, temporary, indent=2)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)

            os.replace(temporary_path, destination)

        except OSError:
            if temporary_path and temporary_path.exists():
                temporary_path.unlink(missing_ok=True)
            raise


def build_example() -> AuthorizationEngine:
    engine = AuthorizationEngine()

    engine.add_user(User(
        user_id="alice",
        department="engineering",
        clearance=Classification.CONFIDENTIAL,
        location="India",
        attributes={
            "mfa_verified": True,
            "delete_authorized": False
        }
    ))

    engine.add_user(User(
        user_id="bob",
        department="finance",
        clearance=Classification.SECRET,
        location="India",
        attributes={
            "mfa_verified": True,
            "privileged_admin": True,
            "delete_authorized": True
        }
    ))

    engine.add_user(User(
        user_id="charlie",
        department="engineering",
        clearance=Classification.PUBLIC,
        location="United States",
        active=False
    ))

    engine.add_role(Role(
        "developer",
        {Permission.READ, Permission.WRITE}
    ))

    engine.add_role(Role(
        "security_admin",
        {Permission.READ, Permission.ADMIN}
    ))

    engine.assign_role("alice", "developer")
    engine.assign_role("bob", "security_admin")

    engine.add_resource(Resource(
        resource_id="source-code",
        owner_id="alice",
        department="engineering",
        classification=Classification.CONFIDENTIAL,
        attributes={
            "allowed_locations": ["India"],
            "require_mfa": True,
            "deletion_enabled": False
        }
    ))

    engine.add_resource(Resource(
        resource_id="financial-report",
        owner_id="bob",
        department="finance",
        classification=Classification.SECRET,
        attributes={
            "allowed_locations": ["India"],
            "require_mfa": True,
            "deletion_enabled": True
        }
    ))

    engine.grant_acl(
        "financial-report",
        "alice",
        {Permission.READ}
    )

    engine.add_deny_rule(
        "account_suspended",
        True
    )

    return engine


class AuthorizationTests(unittest.TestCase):

    def setUp(self):
        self.engine = build_example()

    def request(
        self,
        user: str,
        resource: str,
        permission: Permission,
        purpose: str = "business"
    ) -> AccessRequest:
        return AccessRequest(
            user_id=user,
            resource_id=resource,
            permission=permission,
            purpose=purpose
        )

    def test_rbac_grant(self):
        self.assertEqual(
            self.engine.authorize(
                self.request("alice", "source-code", Permission.READ)
            ),
            Decision.ALLOW
        )

    def test_acl_grant(self):
        self.assertEqual(
            self.engine.authorize(
                self.request(
                    "alice",
                    "financial-report",
                    Permission.READ,
                    "compliance"
                )
            ),
            Decision.ALLOW
        )

    def test_mac_denial(self):
        self.assertEqual(
            self.engine.authorize(
                self.request(
                    "alice",
                    "financial-report",
                    Permission.WRITE,
                    "compliance"
                )
            ),
            Decision.DENY
        )

    def test_inactive_user(self):
        self.assertEqual(
            self.engine.authorize(
                self.request("charlie", "source-code", Permission.READ)
            ),
            Decision.DENY
        )

    def test_least_privilege(self):
        self.assertEqual(
            self.engine.authorize(
                self.request(
                    "alice",
                    "source-code",
                    Permission.DELETE
                )
            ),
            Decision.DENY
        )

    def test_unknown_user(self):
        with self.assertRaises(ValidationError):
            self.engine.authorize(
                self.request("unknown", "source-code", Permission.READ)
            )

    def test_explicit_deny(self):
        alice = self.engine.users["alice"]

        self.engine.users["alice"] = User(
            user_id=alice.user_id,
            department=alice.department,
            clearance=alice.clearance,
            location=alice.location,
            active=True,
            attributes={
                **alice.attributes,
                "account_suspended": True
            }
        )

        self.assertEqual(
            self.engine.authorize(
                self.request("alice", "source-code", Permission.READ)
            ),
            Decision.DENY
        )


def demonstrate() -> None:
    engine = build_example()

    scenarios = [
        AccessRequest(
            "alice", "source-code", Permission.READ, "business"
        ),
        AccessRequest(
            "alice", "financial-report", Permission.READ, "compliance"
        ),
        AccessRequest(
            "alice", "financial-report", Permission.WRITE, "compliance"
        ),
        AccessRequest(
            "bob", "financial-report", Permission.READ, "business"
        ),
        AccessRequest(
            "alice", "source-code", Permission.DELETE, "maintenance"
        ),
        AccessRequest(
            "charlie", "source-code", Permission.READ, "business"
        )
    ]

    print("\nAUTHORIZATION EVALUATION")

    for request in scenarios:
        decision = engine.authorize(request)

        print(
            f"{request.user_id:10} "
            f"{request.resource_id:20} "
            f"{request.permission.value:10} "
            f"{decision.value}"
        )

    print("\nAUDIT EVENTS:", len(engine.audit_log))

    for event in engine.audit_log:
        print(
            event.user_id,
            event.resource_id,
            event.decision,
            "|".join(event.reasons)
        )

    output = Path("authorization_audit.json")
    engine.export_audit(output)
    print(f"\nAudit exported to {output.resolve()}")


if __name__ == "__main__":
    demonstrate()

    print("\nRUNNING TESTS")
    unittest.main(argv=["authorization_models.py"], exit=False)
