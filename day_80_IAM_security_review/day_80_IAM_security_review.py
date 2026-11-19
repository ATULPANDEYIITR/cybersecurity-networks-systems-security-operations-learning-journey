#!/usr/bin/env python3
"""
IAM SECURITY REVIEW
Identity Attack Surface, Privilege Escalation, and Access Reviews

A self-contained IAM security assessment engine demonstrating:
- Identity and access modeling
- Role-based access control
- Direct and inherited permissions
- Privilege escalation path detection
- Excessive privilege identification
- Separation of duties
- Access certification and review decisions
- Dormant and privileged account detection
- Risk scoring and remediation
- JSON report generation
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s | %(message)s"
)
logger = logging.getLogger("iam-review")


class IdentityType(Enum):
    HUMAN = "human"
    SERVICE = "service"
    APPLICATION = "application"
    EXTERNAL = "external"


class IdentityStatus(Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DISABLED = "disabled"


class ReviewDecision(Enum):
    APPROVE = "approve"
    REVOKE = "revoke"
    REDUCE = "reduce"
    ESCALATE = "escalate"
    PENDING = "pending"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Permission:
    resource: str
    action: str

    def __post_init__(self):
        if not self.resource or not self.action:
            raise ValueError("Permission resource and action are required")

    @property
    def key(self) -> str:
        return f"{self.resource}:{self.action}"


@dataclass
class Role:
    role_id: str
    name: str
    permissions: set[Permission] = field(default_factory=set)
    inherited_roles: set[str] = field(default_factory=set)
    privileged: bool = False

    def __post_init__(self):
        if not self.role_id or not self.name:
            raise ValueError("Role ID and name are required")


@dataclass
class Identity:
    identity_id: str
    name: str
    identity_type: IdentityType
    status: IdentityStatus
    created_at: datetime
    last_login: Optional[datetime]
    role_ids: set[str] = field(default_factory=set)
    direct_permissions: set[Permission] = field(default_factory=set)
    mfa_enabled: bool = False
    owner: str = "unassigned"
    department: str = "unassigned"

    def __post_init__(self):
        if not self.identity_id or not self.name:
            raise ValueError("Identity ID and name are required")
        if self.created_at.tzinfo is None:
            raise ValueError("Creation timestamp must be timezone-aware")
        if self.last_login and self.last_login.tzinfo is None:
            raise ValueError("Login timestamp must be timezone-aware")


@dataclass
class AccessReview:
    identity_id: str
    reviewer: str
    decision: ReviewDecision
    reviewed_at: datetime
    justification: str
    permissions_reviewed: list[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    identity_id: str
    category: str
    severity: Severity
    description: str
    recommendation: str
    risk_score: int


class IAMError(Exception):
    """Base exception for IAM assessment failures."""


class ValidationError(IAMError):
    pass


class PolicyViolation(IAMError):
    pass


class IAMEngine:
    """
    In-memory IAM assessment engine.

    Effective permissions are computed from direct permissions and
    recursively inherited roles. A visited set prevents role cycles.
    """

    SENSITIVE_ACTIONS = {
        "admin",
        "delete",
        "manage_users",
        "manage_roles",
        "manage_policies",
        "manage_credentials",
        "configure_security",
        "manage_billing",
    }

    CRITICAL_RESOURCES = {
        "identity",
        "iam",
        "security",
        "production",
        "secrets",
    }

    def __init__(self):
        self.identities: dict[str, Identity] = {}
        self.roles: dict[str, Role] = {}
        self.reviews: list[AccessReview] = []
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def add_role(self, role: Role) -> None:
        if role.role_id in self.roles:
            raise ValidationError(f"Duplicate role: {role.role_id}")

        self.roles[role.role_id] = role

    def add_identity(self, identity: Identity) -> None:
        if identity.identity_id in self.identities:
            raise ValidationError(
                f"Duplicate identity: {identity.identity_id}"
            )

        missing = identity.role_ids - self.roles.keys()
        if missing:
            raise ValidationError(f"Unknown roles: {sorted(missing)}")

        self.identities[identity.identity_id] = identity

    def validate_role_graph(self) -> None:
        for role in self.roles.values():
            missing = role.inherited_roles - self.roles.keys()
            if missing:
                raise ValidationError(
                    f"Role {role.role_id} references missing roles: "
                    f"{sorted(missing)}"
                )

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(role_id: str) -> None:
            if role_id in visiting:
                raise PolicyViolation(
                    f"Circular role inheritance detected at {role_id}"
                )

            if role_id in visited:
                return

            visiting.add(role_id)

            for parent in self.roles[role_id].inherited_roles:
                visit(parent)

            visiting.remove(role_id)
            visited.add(role_id)

        for role_id in self.roles:
            visit(role_id)

    def effective_permissions(
        self,
        identity_id: str
    ) -> set[Permission]:
        identity = self._get_identity(identity_id)

        if identity.status != IdentityStatus.ACTIVE:
            return set()

        permissions = set(identity.direct_permissions)
        visited: set[str] = set()

        def collect(role_id: str) -> None:
            if role_id in visited:
                return

            visited.add(role_id)
            role = self.roles[role_id]
            permissions.update(role.permissions)

            for parent_id in role.inherited_roles:
                collect(parent_id)

        for role_id in identity.role_ids:
            collect(role_id)

        return permissions

    def _get_identity(self, identity_id: str) -> Identity:
        if identity_id not in self.identities:
            raise ValidationError(f"Unknown identity: {identity_id}")

        return self.identities[identity_id]

    def _add_finding(
        self,
        identity_id: str,
        category: str,
        severity: Severity,
        description: str,
        recommendation: str,
        score: int
    ) -> None:
        self._finding_counter += 1

        self.findings.append(
            Finding(
                finding_id=f"IAM-{self._finding_counter:04d}",
                identity_id=identity_id,
                category=category,
                severity=severity,
                description=description,
                recommendation=recommendation,
                risk_score=min(100, max(0, score))
            )
        )

    def detect_privilege_escalation(self) -> None:
        """
        Detect identities holding sensitive IAM permissions.

        This is a static entitlement assessment, not an exploit simulator.
        """
        for identity in self.identities.values():
            if identity.status != IdentityStatus.ACTIVE:
                continue

            permissions = self.effective_permissions(
                identity.identity_id
            )

            dangerous = [
                permission
                for permission in permissions
                if permission.action in self.SENSITIVE_ACTIONS
                or (
                    permission.resource in self.CRITICAL_RESOURCES
                    and permission.action in {"write", "update", "create"}
                )
            ]

            if dangerous:
                details = ", ".join(
                    sorted(permission.key for permission in dangerous)
                )

                severity = (
                    Severity.CRITICAL
                    if any(
                        permission.action in {
                            "manage_roles",
                            "manage_policies",
                            "manage_credentials",
                            "admin"
                        }
                        for permission in dangerous
                    )
                    else Severity.HIGH
                )

                self._add_finding(
                    identity.identity_id,
                    "privilege_escalation_exposure",
                    severity,
                    f"Sensitive effective permissions: {details}",
                    "Remove unnecessary administrative permissions, "
                    "separate privileged duties, and review role inheritance.",
                    95 if severity == Severity.CRITICAL else 80
                )

    def detect_excessive_privileges(self) -> None:
        for identity in self.identities.values():
            if identity.status != IdentityStatus.ACTIVE:
                continue

            permissions = self.effective_permissions(
                identity.identity_id
            )

            if len(permissions) > 8:
                self._add_finding(
                    identity.identity_id,
                    "excessive_permissions",
                    Severity.MEDIUM,
                    f"Identity has {len(permissions)} effective permissions.",
                    "Apply least privilege and remove unnecessary access.",
                    55
                )

    def detect_dormant_accounts(
        self,
        inactivity_days: int = 90,
        now: Optional[datetime] = None
    ) -> None:
        if inactivity_days < 1:
            raise ValueError("Inactivity threshold must be positive")

        now = now or datetime.now(timezone.utc)

        if now.tzinfo is None:
            raise ValueError("Assessment time must be timezone-aware")

        cutoff = now - timedelta(days=inactivity_days)

        for identity in self.identities.values():
            if identity.status != IdentityStatus.ACTIVE:
                continue

            dormant = (
                identity.last_login is None
                or identity.last_login < cutoff
            )

            if dormant:
                self._add_finding(
                    identity.identity_id,
                    "dormant_identity",
                    Severity.HIGH if identity.identity_type == IdentityType.HUMAN
                    else Severity.CRITICAL,
                    f"No login activity within {inactivity_days} days.",
                    "Verify ownership and business need; disable or rotate "
                    "credentials for unused identities.",
                    85 if identity.identity_type == IdentityType.SERVICE
                    else 70
                )

    def detect_missing_mfa(self) -> None:
        for identity in self.identities.values():
            if (
                identity.status == IdentityStatus.ACTIVE
                and not identity.mfa_enabled
            ):
                privileged = any(
                    self.roles[role_id].privileged
                    for role_id in identity.role_ids
                )

                self._add_finding(
                    identity.identity_id,
                    "missing_mfa",
                    Severity.CRITICAL if privileged else Severity.HIGH,
                    "Active identity does not have MFA enabled.",
                    "Enable phishing-resistant MFA, especially for privileged "
                    "and externally accessible accounts.",
                    95 if privileged else 75
                )

    def detect_separation_of_duties(
        self,
        conflicting_pairs: set[tuple[str, str]]
    ) -> None:
        for identity in self.identities.values():
            assigned = identity.role_ids

            for role_a, role_b in conflicting_pairs:
                if role_a in assigned and role_b in assigned:
                    self._add_finding(
                        identity.identity_id,
                        "separation_of_duties_violation",
                        Severity.CRITICAL,
                        f"Conflicting roles: {role_a} and {role_b}.",
                        "Remove one conflicting role or introduce an "
                        "independent approval control.",
                        95
                    )

    def run_assessment(
        self,
        now: Optional[datetime] = None
    ) -> list[Finding]:
        self.validate_role_graph()
        self.findings.clear()
        self._finding_counter = 0

        self.detect_privilege_escalation()
        self.detect_excessive_privileges()
        self.detect_dormant_accounts(now=now)
        self.detect_missing_mfa()

        self.detect_separation_of_duties({
            ("finance_approver", "payment_creator"),
            ("security_admin", "audit_reviewer"),
        })

        return sorted(
            self.findings,
            key=lambda finding: (
                -finding.risk_score,
                finding.identity_id
            )
        )

    def record_review(self, review: AccessReview) -> None:
        identity = self._get_identity(review.identity_id)

        if not review.reviewer.strip():
            raise ValidationError("Reviewer identity is required")

        if not review.justification.strip():
            raise ValidationError("Review justification is required")

        if review.reviewed_at.tzinfo is None:
            raise ValidationError("Review timestamp must be timezone-aware")

        if review.decision == ReviewDecision.REVOKE:
            identity.status = IdentityStatus.DISABLED
            identity.role_ids.clear()
            identity.direct_permissions.clear()

        elif review.decision == ReviewDecision.REDUCE:
            if not review.permissions_reviewed:
                raise ValidationError(
                    "Reduction requires explicitly identified permissions"
                )

            targets = set(review.permissions_reviewed)

            identity.direct_permissions = {
                permission
                for permission in identity.direct_permissions
                if permission.key not in targets
            }

            for role_id in list(identity.role_ids):
                role = self.roles[role_id]

                if any(
                    permission.key in targets
                    for permission in role.permissions
                ):
                    identity.role_ids.remove(role_id)

        self.reviews.append(review)

        logger.info(
            "Review recorded: identity=%s decision=%s reviewer=%s",
            identity.identity_id,
            review.decision.value,
            review.reviewer
        )

    def export_report(self, output_file: str) -> None:
        """
        Export assessment findings.

        The output directory must be controlled by the application operator.
        """
        output = Path(output_file)
        output.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "assessment_timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "identity_count": len(self.identities),
            "role_count": len(self.roles),
            "finding_count": len(self.findings),
            "findings": [
                {
                    **asdict(finding),
                    "severity": finding.severity.value
                }
                for finding in self.findings
            ],
            "review_count": len(self.reviews)
        }

        with output.open("w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)


def build_demo_engine() -> IAMEngine:
    engine = IAMEngine()

    engine.add_role(
        Role(
            "employee",
            "Standard Employee",
            {Permission("documents", "read")}
        )
    )

    engine.add_role(
        Role(
            "developer",
            "Developer",
            {
                Permission("source_code", "read"),
                Permission("source_code", "write"),
                Permission("deployment", "read")
            },
            inherited_roles={"employee"}
        )
    )

    engine.add_role(
        Role(
            "security_admin",
            "Security Administrator",
            {
                Permission("iam", "manage_roles"),
                Permission("security", "configure_security"),
                Permission("secrets", "manage_credentials")
            },
            privileged=True
        )
    )

    engine.add_role(
        Role(
            "finance_approver",
            "Finance Approver",
            {Permission("payments", "approve")}
        )
    )

    engine.add_role(
        Role(
            "payment_creator",
            "Payment Creator",
            {Permission("payments", "create")}
        )
    )

    now = datetime.now(timezone.utc)

    engine.add_identity(
        Identity(
            "USR-001",
            "Aarav Sharma",
            IdentityType.HUMAN,
            IdentityStatus.ACTIVE,
            now - timedelta(days=300),
            now - timedelta(days=2),
            {"developer"},
            mfa_enabled=True,
            owner="engineering_manager",
            department="engineering"
        )
    )

    engine.add_identity(
        Identity(
            "USR-002",
            "Privileged Operator",
            IdentityType.HUMAN,
            IdentityStatus.ACTIVE,
            now - timedelta(days=400),
            now - timedelta(days=120),
            {"security_admin"},
            mfa_enabled=False,
            owner="security_director",
            department="security"
        )
    )

    engine.add_identity(
        Identity(
            "USR-003",
            "Finance Operator",
            IdentityType.HUMAN,
            IdentityStatus.ACTIVE,
            now - timedelta(days=200),
            now - timedelta(days=1),
            {"finance_approver", "payment_creator"},
            mfa_enabled=True,
            owner="finance_director",
            department="finance"
        )
    )

    engine.add_identity(
        Identity(
            "SVC-001",
            "Legacy Integration",
            IdentityType.SERVICE,
            IdentityStatus.ACTIVE,
            now - timedelta(days=700),
            None,
            {"security_admin"},
            mfa_enabled=False,
            owner="integration_team",
            department="platform"
        )
    )

    engine.add_identity(
        Identity(
            "USR-004",
            "Suspended Contractor",
            IdentityType.EXTERNAL,
            IdentityStatus.SUSPENDED,
            now - timedelta(days=100),
            now - timedelta(days=50),
            {"employee"},
            mfa_enabled=False,
            owner="vendor_manager",
            department="external"
        )
    )

    return engine


def run_tests(engine: IAMEngine) -> None:
    assert Permission("documents", "read").key == "documents:read"

    permissions = engine.effective_permissions("USR-001")
    assert Permission("documents", "read") in permissions
    assert Permission("source_code", "write") in permissions

    assert engine.effective_permissions("USR-004") == set()

    try:
        engine.add_identity(
            Identity(
                "USR-001",
                "Duplicate",
                IdentityType.HUMAN,
                IdentityStatus.ACTIVE,
                datetime.now(timezone.utc),
                None
            )
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("Duplicate identity was accepted")

    logger.info("Core validation tests passed")


def main() -> None:
    engine = build_demo_engine()
    run_tests(engine)

    findings = engine.run_assessment()

    print("\nIAM SECURITY ASSESSMENT")
    print("=" * 72)

    for finding in findings:
        print(
            f"{finding.finding_id} | "
            f"{finding.identity_id} | "
            f"{finding.severity.value.upper()} | "
            f"{finding.category} | "
            f"Risk: {finding.risk_score}"
        )
        print(f"  Finding: {finding.description}")
        print(f"  Action:  {finding.recommendation}")

    print("\nACCESS REVIEW")

    review = AccessReview(
        identity_id="USR-002",
        reviewer="security_director",
        decision=ReviewDecision.REVOKE,
        reviewed_at=datetime.now(timezone.utc),
        justification="Dormant privileged identity without MFA.",
        permissions_reviewed=[]
    )

    engine.record_review(review)

    assert engine.identities["USR-002"].status == IdentityStatus.DISABLED

    print("USR-002: Disabled following access review.")

    print("\nEXPORT")
    engine.export_report("iam_security_report.json")
    print("Assessment exported to iam_security_report.json")


if __name__ == "__main__":
    try:
        main()
    except (IAMError, OSError, ValueError) as error:
        logger.error("Assessment failed: %s", error)
        raise SystemExit(1)
