#!/usr/bin/env python3
"""
Linux hardening laboratory: account security, SSH hardening, firewalling,
patch management, and security auditing.

This self-contained simulator evaluates a Linux server's security posture.
It performs no privileged operations and does not modify the host system.

Run:
    python linux_hardening.py
    python linux_hardening.py --json report.json
    python linux_hardening.py --strict

The findings are illustrative policy evaluations, not a substitute for
distribution-specific configuration validation or a professional audit.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unittest
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class Finding:
    control: str
    severity: Severity
    title: str
    evidence: str
    remediation: str


@dataclass
class Account:
    username: str
    uid: int
    shell: str
    password_locked: bool
    password_max_days: int | None
    last_password_change_days_ago: int | None
    sudo_access: bool = False
    service_account: bool = False
    groups: tuple[str, ...] = ()


@dataclass
class SSHConfiguration:
    permit_root_login: str = "no"
    password_authentication: bool = False
    pubkey_authentication: bool = True
    max_auth_tries: int = 3
    max_sessions: int = 5
    login_grace_time_seconds: int = 30
    allow_users: tuple[str, ...] = ("admin", "deploy")
    allow_groups: tuple[str, ...] = ()
    x11_forwarding: bool = False
    tcp_forwarding: bool = False
    client_alive_interval: int = 300
    client_alive_count_max: int = 2
    use_pam: bool = True


@dataclass
class FirewallConfiguration:
    default_inbound: str = "deny"
    default_outbound: str = "allow"
    default_forward: str = "deny"
    rules: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class PatchState:
    distribution: str
    security_updates_pending: int
    critical_updates_pending: int
    reboot_required: bool
    last_successful_update_days_ago: int
    unattended_security_updates: bool


@dataclass
class AuditState:
    auditd_enabled: bool
    audit_rules_persistent: bool
    authentication_logs_enabled: bool
    log_retention_days: int
    time_synchronization_enabled: bool
    file_integrity_monitoring_enabled: bool
    failed_login_threshold: int


@dataclass
class Server:
    hostname: str
    accounts: list[Account]
    ssh: SSHConfiguration
    firewall: FirewallConfiguration
    patches: PatchState
    audit: AuditState
    sensitive_paths: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)


class PolicyError(ValueError):
    """Raised when a proposed security policy is internally inconsistent."""


def finding(
    control: str,
    severity: Severity,
    title: str,
    evidence: str,
    remediation: str,
) -> Finding:
    return Finding(control, severity, title, evidence, remediation)


def validate_account_inventory(accounts: Iterable[Account]) -> list[Finding]:
    findings: list[Finding] = []
    seen_names: set[str] = set()
    seen_uids: set[int] = set()

    for account in accounts:
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}\$?", account.username):
            findings.append(finding(
                "ACC-001", Severity.HIGH, "Invalid account name",
                f"Account name {account.username!r} violates the local naming policy.",
                "Use a validated account name and review account provisioning.",
            ))

        if account.username in seen_names:
            findings.append(finding(
                "ACC-002", Severity.HIGH, "Duplicate account name",
                account.username, "Remove the duplicate inventory entry.",
            ))
        seen_names.add(account.username)

        if account.uid < 0:
            findings.append(finding(
                "ACC-003", Severity.HIGH, "Negative UID",
                f"{account.username}: UID {account.uid}.",
                "Correct the account inventory and investigate provisioning.",
            ))

        if account.uid in seen_uids:
            findings.append(finding(
                "ACC-004", Severity.HIGH, "Duplicate UID",
                f"UID {account.uid} is assigned more than once.",
                "Review shared UID ownership and assign unique UIDs where required.",
            ))
        seen_uids.add(account.uid)

        if account.uid == 0 and account.username != "root":
            findings.append(finding(
                "ACC-005", Severity.CRITICAL, "Unexpected UID 0 account",
                f"{account.username} has UID 0.",
                "Investigate immediately. Remove unintended UID 0 privileges.",
            ))

        if account.uid == 0 and account.username == "root":
            if not account.password_locked:
                findings.append(finding(
                    "ACC-006", Severity.HIGH, "Root password is not locked",
                    "The root account is not marked as password-locked.",
                    "If operationally appropriate, lock direct root password login "
                    "and use controlled privilege escalation.",
                ))

        if account.sudo_access and account.service_account:
            findings.append(finding(
                "ACC-007", Severity.HIGH, "Privileged service account",
                account.username,
                "Remove interactive administrator privileges from service accounts "
                "unless a documented exception exists.",
            ))

        if account.shell in {"/bin/bash", "/bin/sh", "/bin/zsh"}:
            if account.service_account:
                findings.append(finding(
                    "ACC-008", Severity.MEDIUM, "Interactive service account",
                    f"{account.username} uses {account.shell}.",
                    "Use a non-login shell when compatible with the service design.",
                ))

        if not account.password_locked and account.password_max_days is None:
            findings.append(finding(
                "ACC-009", Severity.MEDIUM, "Missing password aging policy",
                account.username,
                "Define an appropriate credential lifecycle policy. Avoid "
                "unnecessary periodic password rotation when stronger controls "
                "and risk-based rotation are appropriate.",
            ))

        if account.password_max_days is not None and account.password_max_days <= 0:
            findings.append(finding(
                "ACC-010", Severity.HIGH, "Invalid password aging value",
                f"{account.username}: {account.password_max_days} days.",
                "Correct the password aging policy.",
            ))

        if (
            account.last_password_change_days_ago is not None
            and account.password_max_days is not None
            and account.last_password_change_days_ago > account.password_max_days
        ):
            findings.append(finding(
                "ACC-011", Severity.MEDIUM, "Password exceeds configured age",
                f"{account.username}: password age is "
                f"{account.last_password_change_days_ago} days.",
                "Review the credential lifecycle and enforce the approved policy.",
            ))

        if account.uid >= 1000 and account.username not in {"nobody"}:
            if account.shell in {"/bin/bash", "/bin/sh", "/bin/zsh"}:
                if not account.password_locked and not account.groups:
                    findings.append(finding(
                        "ACC-012", Severity.LOW, "Unclassified interactive account",
                        account.username,
                        "Verify ownership, group membership, and account necessity.",
                    ))

    return findings


def audit_ssh(config: SSHConfiguration) -> list[Finding]:
    findings: list[Finding] = []

    if config.permit_root_login.lower() != "no":
        severity = (
            Severity.CRITICAL
            if config.permit_root_login.lower() == "yes"
            else Severity.HIGH
        )
        findings.append(finding(
            "SSH-001", severity, "Direct root SSH login permitted",
            f"PermitRootLogin={config.permit_root_login}",
            "Set PermitRootLogin no, then verify that an approved administrative "
            "account and recovery path work before closing the current session.",
        ))

    if config.password_authentication:
        findings.append(finding(
            "SSH-002", Severity.HIGH, "SSH password authentication enabled",
            "PasswordAuthentication=yes",
            "Prefer public-key authentication or centrally managed stronger "
            "authentication where operational requirements permit.",
        ))

    if not config.pubkey_authentication:
        findings.append(finding(
            "SSH-003", Severity.HIGH, "Public-key authentication disabled",
            "PubkeyAuthentication=no",
            "Enable an approved authentication method and test access safely.",
        ))

    if config.max_auth_tries < 1 or config.max_auth_tries > 4:
        findings.append(finding(
            "SSH-004", Severity.MEDIUM, "Excessive or invalid authentication attempts",
            f"MaxAuthTries={config.max_auth_tries}",
            "Set a small positive attempt limit consistent with operational needs.",
        ))

    if config.max_sessions < 1 or config.max_sessions > 10:
        findings.append(finding(
            "SSH-005", Severity.LOW, "SSH session limit outside local policy",
            f"MaxSessions={config.max_sessions}",
            "Set a documented limit appropriate for the host workload.",
        ))

    if config.login_grace_time_seconds <= 0 or config.login_grace_time_seconds > 60:
        findings.append(finding(
            "SSH-006", Severity.MEDIUM, "SSH login grace period outside policy",
            f"LoginGraceTime={config.login_grace_time_seconds}",
            "Use a short positive login grace period.",
        ))

    if not config.allow_users and not config.allow_groups:
        findings.append(finding(
            "SSH-007", Severity.MEDIUM, "No SSH login allowlist",
            "Neither AllowUsers nor AllowGroups is configured in this policy model.",
            "Define a maintainable login allowlist after checking effective SSH "
            "configuration and required automation identities.",
        ))

    if config.x11_forwarding:
        findings.append(finding(
            "SSH-008", Severity.LOW, "X11 forwarding enabled",
            "X11Forwarding=yes",
            "Disable X11 forwarding on servers that do not require it.",
        ))

    if config.client_alive_interval <= 0 or config.client_alive_count_max < 1:
        findings.append(finding(
            "SSH-009", Severity.MEDIUM, "Invalid SSH connection liveness policy",
            "ClientAliveInterval or ClientAliveCountMax is invalid.",
            "Configure positive values appropriate to session policy.",
        ))

    if config.tcp_forwarding:
        findings.append(finding(
            "SSH-010", Severity.MEDIUM, "TCP forwarding enabled",
            "TCP forwarding is enabled in the supplied policy.",
            "Disable forwarding unless required. Where necessary, restrict it "
            "per account and validate the effective sshd configuration.",
        ))

    if not config.use_pam:
        findings.append(finding(
            "SSH-011", Severity.MEDIUM, "PAM integration disabled",
            "UsePAM=no",
            "Review distribution authentication requirements before changing PAM.",
        ))

    return findings


def validate_firewall(config: FirewallConfiguration) -> list[Finding]:
    findings: list[Finding] = []
    valid_policies = {"allow", "deny", "reject"}

    for direction, policy in (
        ("inbound", config.default_inbound),
        ("outbound", config.default_outbound),
        ("forward", config.default_forward),
    ):
        if policy not in valid_policies:
            findings.append(finding(
                "FW-001", Severity.HIGH, "Invalid firewall default policy",
                f"{direction}={policy!r}",
                "Use an explicitly supported default policy.",
            ))

    if config.default_inbound == "allow":
        findings.append(finding(
            "FW-002", Severity.CRITICAL, "Inbound traffic allowed by default",
            "Default inbound policy is allow.",
            "Default to deny or reject and explicitly permit required services.",
        ))

    if config.default_forward == "allow":
        findings.append(finding(
            "FW-003", Severity.HIGH, "Forwarded traffic allowed by default",
            "Default forward policy is allow.",
            "Restrict forwarding to documented network-routing requirements.",
        ))

    seen_rules: set[tuple[Any, ...]] = set()
    for index, rule in enumerate(config.rules):
        direction = rule.get("direction")
        action = rule.get("action")
        protocol = rule.get("protocol")
        port = rule.get("port")
        source = rule.get("source", "any")
        service = rule.get("service", "unspecified")

        if direction not in {"inbound", "outbound", "forward"}:
            findings.append(finding(
                "FW-004", Severity.HIGH, "Invalid firewall direction",
                f"Rule {index}: {direction!r}",
                "Use a supported traffic direction.",
            ))
            continue

        if action not in {"allow", "deny", "reject"}:
            findings.append(finding(
                "FW-005", Severity.HIGH, "Invalid firewall action",
                f"Rule {index}: {action!r}",
                "Use a supported firewall action.",
            ))
            continue

        if protocol not in {"tcp", "udp", "icmp", "any"}:
            findings.append(finding(
                "FW-006", Severity.HIGH, "Invalid firewall protocol",
                f"Rule {index}: {protocol!r}",
                "Use a supported protocol.",
            ))
            continue

        if port is not None and (
            not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535
        ):
            findings.append(finding(
                "FW-007", Severity.HIGH, "Invalid firewall port",
                f"Rule {index}: port={port!r}",
                "Use a valid integer port or omit the port for protocols that "
                "do not use transport ports.",
            ))
            continue

        signature = (direction, action, protocol, port, source, service)
        if signature in seen_rules:
            findings.append(finding(
                "FW-008", Severity.LOW, "Duplicate firewall rule",
                f"Rule {index}: {signature!r}",
                "Remove duplicate rules after checking rule ordering and semantics.",
            ))
        seen_rules.add(signature)

        if (
            direction == "inbound"
            and action == "allow"
            and protocol == "tcp"
            and port == 22
            and source in {"any", "0.0.0.0/0", "::/0"}
        ):
            findings.append(finding(
                "FW-009", Severity.HIGH, "SSH exposed to every IPv4 or IPv6 source",
                f"Rule {index} allows SSH from {source}.",
                "Restrict SSH to trusted administrative networks, a VPN, or an "
                "approved access gateway where feasible.",
            ))

        if (
            direction == "inbound"
            and action == "allow"
            and port in {23, 445, 3389}
            and source in {"any", "0.0.0.0/0", "::/0"}
        ):
            findings.append(finding(
                "FW-010", Severity.HIGH, "Sensitive service exposed broadly",
                f"Rule {index} exposes port {port} from {source}.",
                "Remove unnecessary exposure or restrict it to authorized networks.",
            ))

    return findings


def audit_patching(state: PatchState) -> list[Finding]:
    findings: list[Finding] = []

    if not state.distribution.strip():
        findings.append(finding(
            "PATCH-001", Severity.HIGH, "Distribution not identified",
            "Distribution name is empty.",
            "Identify the operating system and use its supported package manager.",
        ))

    if state.security_updates_pending < 0 or state.critical_updates_pending < 0:
        findings.append(finding(
            "PATCH-002", Severity.HIGH, "Invalid pending update count",
            "Update counts cannot be negative.",
            "Correct the inventory collected from the package manager.",
        ))

    if state.critical_updates_pending > 0:
        findings.append(finding(
            "PATCH-003", Severity.CRITICAL, "Critical updates pending",
            f"{state.critical_updates_pending} critical update(s) pending.",
            "Assess exposure, test the applicable security updates, and install "
            "them through the approved change process with urgency.",
        ))
    elif state.security_updates_pending > 0:
        findings.append(finding(
            "PATCH-004", Severity.HIGH, "Security updates pending",
            f"{state.security_updates_pending} security update(s) pending.",
            "Prioritize applicable security fixes using severity and exposure.",
        ))

    if state.last_successful_update_days_ago < 0:
        findings.append(finding(
            "PATCH-005", Severity.HIGH, "Invalid update timestamp",
            "The recorded update age is negative.",
            "Correct host time and inventory calculations.",
        ))
    elif state.last_successful_update_days_ago > 30:
        findings.append(finding(
            "PATCH-006", Severity.HIGH, "Patch activity is stale",
            f"Last successful update was "
            f"{state.last_successful_update_days_ago} days ago.",
            "Investigate failed jobs, repository connectivity, and patch cadence.",
        ))
    elif state.last_successful_update_days_ago > 7:
        findings.append(finding(
            "PATCH-007", Severity.MEDIUM, "Patch activity exceeds weekly target",
            f"Last successful update was "
            f"{state.last_successful_update_days_ago} days ago.",
            "Review the patch schedule and verify successful package metadata refresh.",
        ))

    if not state.unattended_security_updates:
        findings.append(finding(
            "PATCH-008", Severity.MEDIUM, "Automated security update policy disabled",
            "Unattended security updates are not enabled in the inventory.",
            "Enable an appropriate unattended-update policy or document an "
            "equivalent managed patching process.",
        ))

    if state.reboot_required:
        findings.append(finding(
            "PATCH-009", Severity.HIGH, "Reboot required after maintenance",
            "The host reports a pending reboot.",
            "Schedule a controlled reboot and validate service health afterward.",
        ))

    return findings


def audit_logging(state: AuditState) -> list[Finding]:
    findings: list[Finding] = []

    controls = [
        (
            state.auditd_enabled, "AUDIT-001", "Audit daemon disabled",
            "Enable and validate auditd where supported by the distribution.",
        ),
        (
            state.audit_rules_persistent, "AUDIT-002", "Audit rules not persistent",
            "Persist reviewed rules and validate them after reboot.",
        ),
        (
            state.authentication_logs_enabled, "AUDIT-003",
            "Authentication logging unavailable",
            "Enable authentication logging and verify log collection.",
        ),
        (
            state.time_synchronization_enabled, "AUDIT-004",
            "Time synchronization disabled",
            "Configure an approved time synchronization service.",
        ),
        (
            state.file_integrity_monitoring_enabled, "AUDIT-005",
            "File integrity monitoring disabled",
            "Monitor critical configuration and executable paths for unexpected changes.",
        ),
    ]

    for enabled, code, title, remediation in controls:
        if not enabled:
            findings.append(finding(
                code, Severity.HIGH if code in {"AUDIT-001", "AUDIT-003"} else Severity.MEDIUM,
                title, "The control is disabled in the supplied audit inventory.",
                remediation,
            ))

    if state.log_retention_days < 30:
        findings.append(finding(
            "AUDIT-006", Severity.MEDIUM, "Short log retention",
            f"Configured retention is {state.log_retention_days} days.",
            "Set retention based on legal, operational, storage, and incident-response needs.",
        ))

    if state.failed_login_threshold < 1:
        findings.append(finding(
            "AUDIT-007", Severity.HIGH, "Invalid failed-login threshold",
            str(state.failed_login_threshold),
            "Configure a positive threshold and a safe lockout or alerting policy.",
        ))

    return findings


def audit_file_permissions(paths: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []

    for path, mode in paths.items():
        if not re.fullmatch(r"0?[0-7]{3,4}", mode):
            findings.append(finding(
                "PERM-001", Severity.HIGH, "Malformed permission mode",
                f"{path}: {mode!r}",
                "Represent the mode as three or four octal digits.",
            ))
            continue

        numeric_mode = int(mode, 8)
        world_writable = bool(numeric_mode & 0o002)
        group_writable = bool(numeric_mode & 0o020)

        if path in {"/etc/shadow", "/etc/gshadow"}:
            if numeric_mode & 0o077:
                findings.append(finding(
                    "PERM-002", Severity.CRITICAL, "Credential file too permissive",
                    f"{path} has mode {mode}.",
                    "Use distribution-appropriate restrictive ownership and permissions.",
                ))

        if path in {"/etc/ssh/sshd_config", "/etc/sudoers"}:
            if world_writable or group_writable:
                findings.append(finding(
                    "PERM-003", Severity.CRITICAL, "Security configuration is writable",
                    f"{path} has mode {mode}.",
                    "Restrict write access to authorized administrators and validate "
                    "ownership and include-file permissions.",
                ))

        if world_writable:
            findings.append(finding(
                "PERM-004", Severity.HIGH, "World-writable sensitive path",
                f"{path} has mode {mode}.",
                "Remove unnecessary world-write permissions and inspect existing contents.",
            ))

    return findings


def assess_server(server: Server) -> list[Finding]:
    """Evaluate independent control families and return stable, sorted findings."""
    findings: list[Finding] = []
    findings.extend(validate_account_inventory(server.accounts))
    findings.extend(audit_ssh(server.ssh))
    findings.extend(validate_firewall(server.firewall))
    findings.extend(audit_patching(server.patches))
    findings.extend(audit_logging(server.audit))
    findings.extend(audit_file_permissions(server.sensitive_paths))

    return sorted(
        findings,
        key=lambda item: (SEVERITY_ORDER[item.severity], item.control, item.title),
    )


def build_example_server() -> Server:
    return Server(
        hostname="app-prod-01",
        accounts=[
            Account(
                username="root", uid=0, shell="/bin/bash",
                password_locked=True, password_max_days=None,
                last_password_change_days_ago=None,
            ),
            Account(
                username="admin", uid=1000, shell="/bin/bash",
                password_locked=False, password_max_days=180,
                last_password_change_days_ago=45, sudo_access=True,
                groups=("sudo", "adm"),
            ),
            Account(
                username="deploy", uid=1001, shell="/bin/bash",
                password_locked=True, password_max_days=None,
                last_password_change_days_ago=None,
                groups=("deploy",), service_account=True,
            ),
            Account(
                username="legacyops", uid=1002, shell="/bin/bash",
                password_locked=False, password_max_days=90,
                last_password_change_days_ago=140,
                groups=("users",),
            ),
        ],
        ssh=SSHConfiguration(
            permit_root_login="no",
            password_authentication=True,
            pubkey_authentication=True,
            max_auth_tries=6,
            max_sessions=10,
            login_grace_time_seconds=90,
            allow_users=("admin", "deploy"),
            x11_forwarding=True,
            tcp_forwarding=True,
        ),
        firewall=FirewallConfiguration(
            default_inbound="allow",
            default_outbound="allow",
            default_forward="deny",
            rules=[
                {
                    "direction": "inbound", "action": "allow",
                    "protocol": "tcp", "port": 22, "source": "any",
                    "service": "ssh",
                },
                {
                    "direction": "inbound", "action": "allow",
                    "protocol": "tcp", "port": 443, "source": "any",
                    "service": "https",
                },
            ],
        ),
        patches=PatchState(
            distribution="Ubuntu",
            security_updates_pending=12,
            critical_updates_pending=2,
            reboot_required=True,
            last_successful_update_days_ago=38,
            unattended_security_updates=False,
        ),
        audit=AuditState(
            auditd_enabled=False,
            audit_rules_persistent=False,
            authentication_logs_enabled=True,
            log_retention_days=14,
            time_synchronization_enabled=True,
            file_integrity_monitoring_enabled=False,
            failed_login_threshold=5,
        ),
        sensitive_paths={
            "/etc/shadow": "0640",
            "/etc/gshadow": "0640",
            "/etc/ssh/sshd_config": "0666",
            "/etc/sudoers": "0440",
        },
        metadata={"environment": "production", "owner": "platform-security"},
    )


def risk_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for item in findings:
        counts[item.severity.value] += 1
    return counts


def print_report(server: Server, findings: list[Finding]) -> None:
    print(f"Linux hardening assessment: {server.hostname}")
    print(f"Environment: {server.metadata.get('environment', 'unspecified')}")
    print(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    print(f"Findings: {len(findings)}")
    print(json.dumps(risk_counts(findings), indent=2))

    if not findings:
        print("No findings were detected by this policy model.")
        return

    for item in findings:
        print(f"\n[{item.severity.value.upper()}] {item.control}: {item.title}")
        print(f"Evidence: {item.evidence}")
        print(f"Remediation: {item.remediation}")


def report_as_json(server: Server, findings: list[Finding]) -> dict[str, Any]:
    return {
        "hostname": server.hostname,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "severity_counts": risk_counts(findings),
        "findings": [
            {
                **asdict(item),
                "severity": item.severity.value,
            }
            for item in findings
        ],
    }


class HardeningTests(unittest.TestCase):
    def test_root_password_locked(self) -> None:
        account = Account("root", 0, "/bin/bash", True, None, None)
        self.assertEqual(validate_account_inventory([account]), [])

    def test_non_root_uid_zero_is_critical(self) -> None:
        account = Account("operator", 0, "/bin/bash", True, None, None)
        findings = validate_account_inventory([account])
        self.assertTrue(any(
            item.control == "ACC-005" and item.severity == Severity.CRITICAL
            for item in findings
        ))

    def test_ssh_exposure_is_detected(self) -> None:
        config = SSHConfiguration(
            password_authentication=True,
            allow_users=("admin",),
        )
        self.assertTrue(any(
            item.control == "SSH-002" for item in audit_ssh(config)
        ))

    def test_deny_inbound_is_accepted(self) -> None:
        config = FirewallConfiguration(default_inbound="deny")
        self.assertFalse(any(
            item.control == "FW-002" for item in validate_firewall(config)
        ))

    def test_world_writable_sshd_config_is_critical(self) -> None:
        findings = audit_file_permissions({"/etc/ssh/sshd_config": "0666"})
        self.assertTrue(any(
            item.severity == Severity.CRITICAL for item in findings
        ))

    def test_pending_critical_updates_are_detected(self) -> None:
        state = PatchState("Debian", 3, 1, False, 2, True)
        self.assertTrue(any(
            item.control == "PATCH-003" for item in audit_patching(state)
        ))

    def test_empty_account_inventory_is_valid(self) -> None:
        self.assertEqual(validate_account_inventory([]), [])

    def test_report_is_deterministically_sorted(self) -> None:
        findings = assess_server(build_example_server())
        keys = [
            (SEVERITY_ORDER[item.severity], item.control, item.title)
            for item in findings
        ]
        self.assertEqual(keys, sorted(keys))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate a sample Linux hardening policy without changing the host."
    )
    parser.add_argument(
        "--json", metavar="PATH",
        help="Write a machine-readable assessment report to PATH.",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Return exit status 1 if critical or high findings exist.",
    )
    parser.add_argument(
        "--test", action="store_true",
        help="Run the built-in policy unit tests.",
    )
    args = parser.parse_args()

    if args.test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(HardeningTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    server = build_example_server()
    findings = assess_server(server)
    print_report(server, findings)

    if args.json:
        output_path = Path(args.json)
        try:
            output_path.write_text(
                json.dumps(report_as_json(server, findings), indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            print(f"Could not write JSON report: {exc}", file=sys.stderr)
            return 2
        print(f"\nJSON report written to {output_path}")

    if args.strict and any(
        item.severity in {Severity.CRITICAL, Severity.HIGH}
        for item in findings
    ):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
