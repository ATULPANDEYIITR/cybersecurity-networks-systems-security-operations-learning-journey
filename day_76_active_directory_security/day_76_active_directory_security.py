#!/usr/bin/env python3
"""
Active Directory Security Governance Simulator

Models:
- Privileged account governance
- Administrative tier separation
- Kerberos delegation exposure
- Service account security
- Domain and forest trust relationships
- Defensive attack-path analysis
- Least-privilege validation
- Security findings and remediation tracking

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("ad_security")


class SecurityError(Exception):
    """Base exception for security governance errors."""


class ValidationError(SecurityError):
    pass


class AccessDenied(SecurityError):
    pass


class AccountType(Enum):
    USER = "user"
    SERVICE = "service"
    ADMINISTRATOR = "administrator"
    MANAGED_SERVICE = "managed_service"


class PrivilegeTier(Enum):
    TIER_0 = 0
    TIER_1 = 1
    TIER_2 = 2


class DelegationType(Enum):
    NONE = "none"
    UNCONSTRAINED = "unconstrained"
    CONSTRAINED = "constrained"
    RESOURCE_BASED = "resource_based"


class TrustType(Enum):
    EXTERNAL = "external"
    FOREST = "forest"
    PARENT_CHILD = "parent_child"


class TrustDirection(Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class FindingSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(Enum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"


@dataclass
class ADAccount:
    sam_account_name: str
    account_type: AccountType
    tier: PrivilegeTier
    enabled: bool = True
    privileged: bool = False
    mfa_enabled: bool = False
    password_never_expires: bool = False
    interactive_logon_allowed: bool = True
    delegation: DelegationType = DelegationType.NONE
    trusted_to_authenticate: bool = False
    spn_count: int = 0
    password_last_changed_days: int = 30
    managed_password: bool = False
    description: str = ""


@dataclass
class Trust:
    source_domain: str
    target_domain: str
    trust_type: TrustType
    direction: TrustDirection
    selective_authentication: bool = True
    sid_filtering: bool = True
    enabled: bool = True


@dataclass
class Relationship:
    source: str
    target: str
    permission: str
    description: str = ""


@dataclass
class SecurityFinding:
    finding_id: str
    severity: FindingSeverity
    category: str
    subject: str
    description: str
    recommendation: str
    status: FindingStatus = FindingStatus.OPEN
    discovered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ActiveDirectory:
    """In-memory defensive Active Directory security model."""

    ACCOUNT_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

    def __init__(self, domain: str):
        if not domain or len(domain) > 253:
            raise ValidationError("Invalid domain name")

        self.domain = domain.lower()
        self.accounts: dict[str, ADAccount] = {}
        self.trusts: list[Trust] = []
        self.relationships: list[Relationship] = []
        self.findings: list[SecurityFinding] = []
        self._finding_counter = 0

    def add_account(self, account: ADAccount) -> None:
        name = account.sam_account_name

        if not self.ACCOUNT_PATTERN.fullmatch(name):
            raise ValidationError(f"Invalid account identifier: {name}")

        key = name.lower()

        if key in self.accounts:
            raise ValidationError(f"Duplicate account: {name}")

        if account.spn_count < 0:
            raise ValidationError("SPN count cannot be negative")

        if account.password_last_changed_days < 0:
            raise ValidationError("Invalid password age")

        self.accounts[key] = account

    def get_account(self, name: str) -> ADAccount:
        account = self.accounts.get(name.lower())

        if account is None:
            raise ValidationError(f"Account not found: {name}")

        return account

    def add_trust(self, trust: Trust) -> None:
        if trust.source_domain == trust.target_domain:
            raise ValidationError("A domain cannot trust itself")

        if not trust.source_domain or not trust.target_domain:
            raise ValidationError("Trust domains are required")

        self.trusts.append(trust)

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship.source == relationship.target:
            raise ValidationError("Self-referencing relationship")

        if not relationship.permission.strip():
            raise ValidationError("Permission cannot be empty")

        self.relationships.append(relationship)

    def add_finding(
        self,
        severity: FindingSeverity,
        category: str,
        subject: str,
        description: str,
        recommendation: str
    ) -> None:
        self._finding_counter += 1

        self.findings.append(
            SecurityFinding(
                finding_id=f"AD-{self._finding_counter:04d}",
                severity=severity,
                category=category,
                subject=subject,
                description=description,
                recommendation=recommendation
            )
        )

    def audit_privileged_accounts(self) -> None:
        for account in self.accounts.values():
            if not account.enabled:
                continue

            if account.privileged and not account.mfa_enabled:
                self.add_finding(
                    FindingSeverity.CRITICAL,
                    "PRIVILEGED_ACCOUNT",
                    account.sam_account_name,
                    "Privileged account does not have MFA enabled.",
                    "Enforce phishing-resistant MFA and privileged access controls."
                )

            if (
                account.privileged
                and account.tier != PrivilegeTier.TIER_0
                and account.interactive_logon_allowed
                and account.account_type == AccountType.ADMINISTRATOR
            ):
                self.add_finding(
                    FindingSeverity.HIGH,
                    "TIER_SEPARATION",
                    account.sam_account_name,
                    "Administrative account has an inconsistent tier assignment.",
                    "Review administrative role and assign an appropriate security tier."
                )

            if account.privileged and account.password_never_expires:
                self.add_finding(
                    FindingSeverity.HIGH,
                    "PASSWORD_POLICY",
                    account.sam_account_name,
                    "Privileged account has a non-expiring password.",
                    "Use managed credentials and enforce credential lifecycle controls."
                )

    def audit_service_accounts(self) -> None:
        for account in self.accounts.values():
            if account.account_type not in {
                AccountType.SERVICE,
                AccountType.MANAGED_SERVICE
            }:
                continue

            if not account.enabled:
                continue

            if (
                account.account_type == AccountType.SERVICE
                and not account.managed_password
            ):
                self.add_finding(
                    FindingSeverity.HIGH,
                    "SERVICE_ACCOUNT",
                    account.sam_account_name,
                    "Service account does not use managed credentials.",
                    "Evaluate migration to a group Managed Service Account."
                )

            if account.interactive_logon_allowed:
                self.add_finding(
                    FindingSeverity.MEDIUM,
                    "SERVICE_INTERACTIVE_LOGON",
                    account.sam_account_name,
                    "Service account permits interactive logon.",
                    "Restrict interactive logon where the service architecture permits."
                )

            if account.spn_count > 0 and account.password_last_changed_days > 180:
                self.add_finding(
                    FindingSeverity.HIGH,
                    "SERVICE_CREDENTIAL_AGE",
                    account.sam_account_name,
                    "SPN-bearing service account has an old credential.",
                    "Rotate credentials or adopt a managed service identity."
                )

    def audit_delegation(self) -> None:
        for account in self.accounts.values():
            if not account.enabled:
                continue

            if account.delegation == DelegationType.UNCONSTRAINED:
                self.add_finding(
                    FindingSeverity.CRITICAL,
                    "UNCONSTRAINED_DELEGATION",
                    account.sam_account_name,
                    "Account permits unconstrained Kerberos delegation.",
                    "Remove unconstrained delegation and assess constrained alternatives."
                )

            elif account.delegation == DelegationType.CONSTRAINED:
                self.add_finding(
                    FindingSeverity.MEDIUM,
                    "CONSTRAINED_DELEGATION",
                    account.sam_account_name,
                    "Account uses constrained Kerberos delegation.",
                    "Validate allowed services and delegation targets."
                )

            if account.trusted_to_authenticate:
                self.add_finding(
                    FindingSeverity.HIGH,
                    "PROTOCOL_TRANSITION",
                    account.sam_account_name,
                    "Account has protocol transition enabled.",
                    "Review necessity, permitted services, and delegation scope."
                )

    def audit_trusts(self) -> None:
        for trust in self.trusts:
            if not trust.enabled:
                continue

            if not trust.sid_filtering:
                self.add_finding(
                    FindingSeverity.CRITICAL,
                    "TRUST_SID_FILTERING",
                    f"{trust.source_domain}->{trust.target_domain}",
                    "Trust does not enforce SID filtering.",
                    "Enable appropriate SID filtering and validate trust configuration."
                )

            if not trust.selective_authentication:
                self.add_finding(
                    FindingSeverity.HIGH,
                    "TRUST_AUTHENTICATION",
                    f"{trust.source_domain}->{trust.target_domain}",
                    "Trust permits authentication without selective authentication.",
                    "Evaluate selective authentication and restrict target access."
                )

    def analyze_attack_paths(self, start: str, target: str) -> list[list[str]]:
        """
        Defensive graph analysis.

        Edges represent documented security relationships, not
        proof of an exploitable vulnerability.
        """
        adjacency: dict[str, list[str]] = defaultdict(list)

        for relation in self.relationships:
            adjacency[relation.source].append(relation.target)

        if start == target:
            return [[start]]

        queue = deque([(start, [start])])
        paths: list[list[str]] = []
        visited_depth: dict[str, int] = {start: 0}
        shortest_depth: Optional[int] = None

        while queue:
            node, path = queue.popleft()

            if shortest_depth is not None and len(path) - 1 > shortest_depth:
                break

            for neighbor in adjacency[node]:
                if neighbor in path:
                    continue

                new_path = path + [neighbor]

                if neighbor == target:
                    shortest_depth = len(new_path) - 1
                    paths.append(new_path)
                    continue

                depth = len(new_path) - 1

                if depth <= visited_depth.get(neighbor, float("inf")):
                    visited_depth[neighbor] = depth
                    queue.append((neighbor, new_path))

        return paths

    def audit_all(self) -> list[SecurityFinding]:
        self.findings.clear()
        self._finding_counter = 0

        self.audit_privileged_accounts()
        self.audit_service_accounts()
        self.audit_delegation()
        self.audit_trusts()

        return self.findings

    def resolve_finding(
        self,
        finding_id: str,
        status: FindingStatus
    ) -> None:
        for finding in self.findings:
            if finding.finding_id == finding_id:
                finding.status = status
                return

        raise ValidationError(f"Finding not found: {finding_id}")

    def report(self) -> dict:
        severity_counts = {
            severity.value: sum(
                f.severity == severity for f in self.findings
            )
            for severity in FindingSeverity
        }

        return {
            "domain": self.domain,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "account_count": len(self.accounts),
            "enabled_accounts": sum(
                account.enabled for account in self.accounts.values()
            ),
            "privileged_accounts": sum(
                account.privileged and account.enabled
                for account in self.accounts.values()
            ),
            "trust_count": len(self.trusts),
            "relationship_count": len(self.relationships),
            "severity_counts": severity_counts,
            "findings": [
                {
                    **asdict(finding),
                    "severity": finding.severity.value,
                    "status": finding.status.value
                }
                for finding in self.findings
            ]
        }

    def export_report(self, filename: str) -> None:
        path = Path(filename)

        # Restrict accidental writes to unexpected locations.
        if path.name != filename or path.suffix.lower() != ".json":
            raise ValidationError("Use a local JSON filename")

        path.write_text(
            json.dumps(self.report(), indent=2),
            encoding="utf-8"
        )


def build_environment() -> ActiveDirectory:
    ad = ActiveDirectory("corp.example.com")

    accounts = [
        ADAccount(
            "domain_admin",
            AccountType.ADMINISTRATOR,
            PrivilegeTier.TIER_0,
            privileged=True,
            mfa_enabled=True,
            password_never_expires=False
        ),
        ADAccount(
            "helpdesk_admin",
            AccountType.ADMINISTRATOR,
            PrivilegeTier.TIER_2,
            privileged=True,
            mfa_enabled=False
        ),
        ADAccount(
            "sql_service",
            AccountType.SERVICE,
            PrivilegeTier.TIER_1,
            managed_password=False,
            password_never_expires=True,
            interactive_logon_allowed=True,
            spn_count=2,
            password_last_changed_days=240
        ),
        ADAccount(
            "web_gmsa",
            AccountType.MANAGED_SERVICE,
            PrivilegeTier.TIER_1,
            managed_password=True,
            interactive_logon_allowed=False,
            spn_count=1,
            password_last_changed_days=10
        ),
        ADAccount(
            "legacy_server",
            AccountType.SERVICE,
            PrivilegeTier.TIER_1,
            delegation=DelegationType.UNCONSTRAINED,
            trusted_to_authenticate=True,
            spn_count=1
        ),
        ADAccount(
            "employee01",
            AccountType.USER,
            PrivilegeTier.TIER_2,
            mfa_enabled=True
        )
    ]

    for account in accounts:
        ad.add_account(account)

    ad.add_trust(
        Trust(
            "corp.example.com",
            "partner.example.net",
            TrustType.EXTERNAL,
            TrustDirection.BIDIRECTIONAL,
            selective_authentication=False,
            sid_filtering=False
        )
    )

    relationships = [
        Relationship(
            "employee01",
            "helpdesk_admin",
            "documented_group_membership"
        ),
        Relationship(
            "helpdesk_admin",
            "server01",
            "administrative_access"
        ),
        Relationship(
            "server01",
            "legacy_server",
            "service_dependency"
        ),
        Relationship(
            "legacy_server",
            "domain_admin",
            "delegation_exposure"
        ),
        Relationship(
            "employee01",
            "server02",
            "remote_access"
        ),
        Relationship(
            "server02",
            "domain_admin",
            "privileged_dependency"
        )
    ]

    for relationship in relationships:
        ad.add_relationship(relationship)

    return ad


def main() -> None:
    ad = build_environment()

    print("\nACTIVE DIRECTORY SECURITY AUDIT")
    print("=" * 55)

    findings = ad.audit_all()

    for finding in findings:
        print(
            f"[{finding.severity.value.upper()}] "
            f"{finding.finding_id}: "
            f"{finding.category} | {finding.subject}"
        )
        print(f"  Finding: {finding.description}")
        print(f"  Action:  {finding.recommendation}")

    print("\nDEFENSIVE ATTACK-PATH ANALYSIS")
    print("=" * 55)

    paths = ad.analyze_attack_paths(
        "employee01",
        "domain_admin"
    )

    if not paths:
        print("No documented path found.")
    else:
        for index, path in enumerate(paths, start=1):
            print(f"Path {index}: {' -> '.join(path)}")

    print("\nSECURITY REPORT")
    print("=" * 55)

    report = ad.report()
    print(json.dumps(report["severity_counts"], indent=2))

    # Demonstrate finding lifecycle management.
    if findings:
        ad.resolve_finding(
            findings[0].finding_id,
            FindingStatus.MITIGATED
        )

    ad.export_report("ad_security_report.json")
    print("\nReport exported to ad_security_report.json")


if __name__ == "__main__":
    try:
        main()
    except (SecurityError, OSError) as exc:
        logger.error("Execution failed: %s", exc)
        raise SystemExit(1)
