#!/usr/bin/env python3
"""
System Hardening: secure baselines, attack-surface reduction,
service minimization, and patch management.

Self-contained simulation of a host hardening workflow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PatchStatus(str, Enum):
    REQUIRED = "required"
    SCHEDULED = "scheduled"
    INSTALLED = "installed"
    DEFERRED = "deferred"


@dataclass(frozen=True)
class SecureBaseline:
    minimum_password_length: int = 14
    max_password_age_days: int = 90
    firewall_enabled: bool = True
    root_remote_login_disabled: bool = True
    unnecessary_services_disabled: bool = True
    automatic_security_updates: bool = True
    audit_logging_enabled: bool = True
    disk_encryption_required: bool = True


@dataclass
class Service:
    name: str
    port: int | None
    required: bool
    externally_reachable: bool
    encrypted: bool


@dataclass
class Vulnerability:
    identifier: str
    severity: Severity
    affected_service: str
    fixed_version: str
    patch_due: date
    status: PatchStatus = PatchStatus.REQUIRED


@dataclass
class Host:
    hostname: str
    os_version: str
    password_policy_length: int
    password_max_age_days: int
    firewall_enabled: bool
    root_remote_login: bool
    audit_logging: bool
    disk_encryption: bool
    services: list[Service] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    def exposed_services(self) -> list[Service]:
        return [
            service
            for service in self.services
            if service.externally_reachable
        ]


@dataclass(frozen=True)
class Finding:
    category: str
    severity: Severity
    message: str
    remediation: str


class HardeningEngine:
    """Evaluates a host against an explicit secure baseline."""

    def __init__(self, baseline: SecureBaseline) -> None:
        self.baseline = baseline

    def assess_baseline(self, host: Host) -> list[Finding]:
        findings: list[Finding] = []

        if host.password_policy_length < self.baseline.minimum_password_length:
            findings.append(
                Finding(
                    "authentication",
                    Severity.HIGH,
                    "Password minimum length is below the secure baseline.",
                    f"Set minimum length to {self.baseline.minimum_password_length}.",
                )
            )

        if host.password_max_age_days > self.baseline.max_password_age_days:
            findings.append(
                Finding(
                    "authentication",
                    Severity.MEDIUM,
                    "Password maximum age exceeds the baseline.",
                    f"Set maximum age to {self.baseline.max_password_age_days} days.",
                )
            )

        if self.baseline.firewall_enabled and not host.firewall_enabled:
            findings.append(
                Finding(
                    "network",
                    Severity.CRITICAL,
                    "Host firewall is disabled.",
                    "Enable the host firewall before exposing network services.",
                )
            )

        if self.baseline.root_remote_login_disabled and host.root_remote_login:
            findings.append(
                Finding(
                    "access",
                    Severity.CRITICAL,
                    "Remote root login is enabled.",
                    "Disable direct remote root authentication.",
                )
            )

        if self.baseline.audit_logging_enabled and not host.audit_logging:
            findings.append(
                Finding(
                    "logging",
                    Severity.HIGH,
                    "Security audit logging is disabled.",
                    "Enable and protect security audit logs.",
                )
            )

        if self.baseline.disk_encryption_required and not host.disk_encryption:
            findings.append(
                Finding(
                    "storage",
                    Severity.HIGH,
                    "Required disk encryption is absent.",
                    "Enable full-disk or equivalent volume encryption.",
                )
            )

        return findings

    def assess_services(self, host: Host) -> list[Finding]:
        findings: list[Finding] = []

        for service in host.services:
            if not service.required:
                findings.append(
                    Finding(
                        "service-minimization",
                        Severity.HIGH if service.externally_reachable else Severity.MEDIUM,
                        f"Unnecessary service '{service.name}' is installed.",
                        "Disable and remove the service where operationally safe.",
                    )
                )

            if service.externally_reachable and not service.encrypted:
                findings.append(
                    Finding(
                        "network",
                        Severity.HIGH,
                        f"Externally reachable service '{service.name}' lacks encryption.",
                        "Restrict exposure or require an encrypted protocol.",
                    )
                )

        return findings

    def assess_patches(self, host: Host, today: date) -> list[Finding]:
        findings: list[Finding] = []

        for vulnerability in host.vulnerabilities:
            if vulnerability.status == PatchStatus.INSTALLED:
                continue

            if vulnerability.severity == Severity.CRITICAL:
                severity = Severity.CRITICAL
            elif vulnerability.patch_due < today:
                severity = Severity.HIGH
            else:
                severity = vulnerability.severity

            findings.append(
                Finding(
                    "patch-management",
                    severity,
                    (
                        f"{vulnerability.identifier} affects "
                        f"{vulnerability.affected_service}; "
                        f"fixed version is {vulnerability.fixed_version}."
                    ),
                    (
                        f"Install the fixed version by "
                        f"{vulnerability.patch_due.isoformat()}."
                    ),
                )
            )

        return findings

    def assess(self, host: Host, today: date) -> list[Finding]:
        return (
            self.assess_baseline(host)
            + self.assess_services(host)
            + self.assess_patches(host, today)
        )

    @staticmethod
    def attack_surface_score(host: Host) -> int:
        """
        Simple prioritization score.
        Higher values indicate more externally exposed functionality.
        This is not a vulnerability severity score.
        """
        score = 0
        for service in host.services:
            if service.externally_reachable:
                score += 3
            if not service.required:
                score += 2
            if not service.encrypted:
                score += 3
        return score

    @staticmethod
    def patch_priority(vulnerability: Vulnerability, today: date) -> tuple[int, int]:
        severity_weight = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }
        overdue_days = max(0, (today - vulnerability.patch_due).days)
        return severity_weight[vulnerability.severity], overdue_days

    def apply_safe_hardening(self, host: Host) -> list[str]:
        """
        Applies only deterministic hardening actions represented by the model.
        Production systems should use configuration-management tooling with
        change control, backups, and rollback procedures.
        """
        changes: list[str] = []

        if host.password_policy_length < self.baseline.minimum_password_length:
            host.password_policy_length = self.baseline.minimum_password_length
            changes.append("Raised minimum password length.")

        if host.password_max_age_days > self.baseline.max_password_age_days:
            host.password_max_age_days = self.baseline.max_password_age_days
            changes.append("Reduced maximum password age.")

        if self.baseline.firewall_enabled and not host.firewall_enabled:
            host.firewall_enabled = True
            changes.append("Enabled host firewall.")

        if self.baseline.root_remote_login_disabled and host.root_remote_login:
            host.root_remote_login = False
            changes.append("Disabled remote root login.")

        if self.baseline.audit_logging_enabled and not host.audit_logging:
            host.audit_logging = True
            changes.append("Enabled audit logging.")

        if self.baseline.disk_encryption_required and not host.disk_encryption:
            # In a real environment this operation requires platform-specific
            # provisioning and recovery-key management, so the model records
            # the desired state rather than invoking a destructive command.
            host.disk_encryption = True
            changes.append("Marked disk encryption as enabled.")

        for service in host.services:
            if not service.required and service.externally_reachable:
                service.externally_reachable = False
                changes.append(
                    f"Removed external exposure from unnecessary service '{service.name}'."
                )

        return changes


def print_findings(findings: Iterable[Finding]) -> None:
    for finding in findings:
        print(
            f"[{finding.severity.value.upper():8}] "
            f"{finding.category:20} {finding.message}"
        )
        print(f"           Remediation: {finding.remediation}")


def main() -> None:
    today = date(2026, 10, 21)

    baseline = SecureBaseline()

    host = Host(
        hostname="payments-api-01",
        os_version="Ubuntu 24.04 LTS",
        password_policy_length=10,
        password_max_age_days=180,
        firewall_enabled=False,
        root_remote_login=True,
        audit_logging=False,
        disk_encryption=False,
        services=[
            Service("ssh", 22, True, True, True),
            Service("https", 443, True, True, True),
            Service("telnet", 23, False, True, False),
            Service("ftp", 21, False, True, False),
            Service("metrics-agent", 9100, True, False, True),
        ],
        vulnerabilities=[
            Vulnerability(
                "CVE-2026-10001",
                Severity.CRITICAL,
                "https",
                "4.8.2",
                today - timedelta(days=3),
            ),
            Vulnerability(
                "CVE-2026-10017",
                Severity.HIGH,
                "ssh",
                "9.9p2",
                today + timedelta(days=7),
            ),
        ],
    )

    engine = HardeningEngine(baseline)

    print(f"Host: {host.hostname}")
    print(f"Attack-surface score: {engine.attack_surface_score(host)}")
    print("\nBaseline and exposure assessment:")
    print_findings(engine.assess(host, today))

    print("\nExternally reachable services:")
    for service in host.exposed_services():
        print(f"  {service.name}:{service.port}")

    print("\nApplying deterministic hardening changes:")
    for change in engine.apply_safe_hardening(host):
        print(f"  - {change}")

    remaining = engine.assess(host, today)
    print("\nPost-hardening assessment:")
    print_findings(remaining)

    print("\nPatch priority:")
    for vulnerability in sorted(
        host.vulnerabilities,
        key=lambda item: engine.patch_priority(item, today),
        reverse=True,
    ):
        priority = engine.patch_priority(vulnerability, today)
        print(
            f"  {vulnerability.identifier}: "
            f"severity-weight={priority[0]}, overdue-days={priority[1]}"
        )


if __name__ == "__main__":
    main()
