"""
Windows Hardening Policy Simulator

Models defensive Windows endpoint controls without changing the host:
- Microsoft Defender configuration
- Windows Firewall profiles and rules
- Security policy requirements
- Application control policies
- Attack Surface Reduction (ASR) rules

The simulator evaluates an endpoint against a hardening baseline and produces
PowerShell commands that an administrator could review and execute separately.
It intentionally performs no privileged system changes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable
import json
import re
import unittest


class Enforcement(str, Enum):
    AUDIT = "Audit"
    BLOCK = "Block"
    ALLOW = "Allow"
    DISABLED = "Disabled"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class DefenderConfig:
    realtime_monitoring: bool
    behavior_monitoring: bool
    ioav_protection: bool
    cloud_protection: bool
    tamper_protection: bool
    signature_age_hours: int

    def validate(self) -> None:
        if self.signature_age_hours < 0:
            raise ValueError("Signature age cannot be negative")


@dataclass(frozen=True)
class FirewallProfile:
    name: str
    enabled: bool
    default_inbound: str
    default_outbound: str

    def validate(self) -> None:
        if self.name not in {"Domain", "Private", "Public"}:
            raise ValueError(f"Unsupported firewall profile: {self.name}")
        if self.default_inbound not in {"Allow", "Block"}:
            raise ValueError("Inbound policy must be Allow or Block")
        if self.default_outbound not in {"Allow", "Block"}:
            raise ValueError("Outbound policy must be Allow or Block")


@dataclass(frozen=True)
class SecurityPolicy:
    password_minimum_length: int
    lockout_threshold: int
    lockout_duration_minutes: int
    audit_logon_events: bool
    audit_process_creation: bool
    powershell_script_block_logging: bool
    powershell_transcription: bool

    def validate(self) -> None:
        if not 1 <= self.password_minimum_length <= 128:
            raise ValueError("Password length must be between 1 and 128")
        if self.lockout_threshold < 0:
            raise ValueError("Lockout threshold cannot be negative")
        if self.lockout_duration_minutes < 0:
            raise ValueError("Lockout duration cannot be negative")


@dataclass(frozen=True)
class ApplicationControl:
    mode: Enforcement
    publisher_rules: bool
    path_rules: bool
    unsigned_binary_blocking: bool


@dataclass(frozen=True)
class ASRRule:
    rule_id: str
    name: str
    required_state: Enforcement
    severity: Severity


@dataclass
class WindowsEndpoint:
    hostname: str
    defender: DefenderConfig
    firewall_profiles: list[FirewallProfile]
    security_policy: SecurityPolicy
    application_control: ApplicationControl
    asr_rules: dict[str, Enforcement]

    def validate(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}", self.hostname):
            raise ValueError("Invalid Windows hostname")

        self.defender.validate()
        self.security_policy.validate()

        if len(self.firewall_profiles) != 3:
            raise ValueError("A baseline requires Domain, Private, and Public profiles")

        for profile in self.firewall_profiles:
            profile.validate()

        for rule_id, state in self.asr_rules.items():
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", rule_id):
                raise ValueError(f"Invalid ASR rule identifier: {rule_id}")
            if not isinstance(state, Enforcement):
                raise ValueError("ASR state must be an Enforcement value")


@dataclass(frozen=True)
class Finding:
    control: str
    severity: Severity
    message: str
    remediation: str


@dataclass(frozen=True)
class Baseline:
    defender: DefenderConfig
    firewall: dict[str, FirewallProfile]
    security_policy: SecurityPolicy
    application_control: ApplicationControl
    asr_rules: tuple[ASRRule, ...]


class HardeningEvaluator:
    """Compares observed endpoint state with a declared security baseline."""

    def __init__(self, baseline: Baseline):
        self.baseline = baseline
        baseline.defender.validate()
        baseline.security_policy.validate()
        for profile in baseline.firewall.values():
            profile.validate()

    def evaluate(self, endpoint: WindowsEndpoint) -> list[Finding]:
        endpoint.validate()
        findings: list[Finding] = []

        required = self.baseline.defender
        actual = endpoint.defender

        defender_boolean_controls = {
            "Real-time monitoring": (actual.realtime_monitoring, required.realtime_monitoring),
            "Behavior monitoring": (actual.behavior_monitoring, required.behavior_monitoring),
            "IOAV protection": (actual.ioav_protection, required.ioav_protection),
            "Cloud protection": (actual.cloud_protection, required.cloud_protection),
            "Tamper protection": (actual.tamper_protection, required.tamper_protection),
        }

        for name, (observed, expected) in defender_boolean_controls.items():
            if expected and not observed:
                findings.append(
                    Finding(
                        "Microsoft Defender",
                        Severity.CRITICAL if name in {"Real-time monitoring", "Tamper protection"} else Severity.HIGH,
                        f"{name} is disabled",
                        f"Enable {name.lower()}",
                    )
                )

        if actual.signature_age_hours > required.signature_age_hours:
            findings.append(
                Finding(
                    "Microsoft Defender",
                    Severity.HIGH,
                    f"Security intelligence is {actual.signature_age_hours} hours old",
                    f"Update security intelligence within {required.signature_age_hours} hours",
                )
            )

        observed_profiles = {p.name: p for p in endpoint.firewall_profiles}
        for name, expected in self.baseline.firewall.items():
            observed = observed_profiles[name]
            if expected.enabled and not observed.enabled:
                findings.append(
                    Finding(
                        "Windows Firewall",
                        Severity.CRITICAL if name == "Public" else Severity.HIGH,
                        f"{name} firewall profile is disabled",
                        f"Enable the {name} firewall profile",
                    )
                )

            if expected.default_inbound == "Block" and observed.default_inbound != "Block":
                findings.append(
                    Finding(
                        "Windows Firewall",
                        Severity.HIGH,
                        f"{name} inbound default policy is {observed.default_inbound}",
                        f"Set {name} inbound default policy to Block",
                    )
                )

        policy = self.baseline.security_policy
        actual_policy = endpoint.security_policy

        if actual_policy.password_minimum_length < policy.password_minimum_length:
            findings.append(
                Finding(
                    "Security Policy",
                    Severity.MEDIUM,
                    "Password minimum length is below baseline",
                    f"Set minimum password length to {policy.password_minimum_length}",
                )
            )

        if policy.lockout_threshold and (
            actual_policy.lockout_threshold == 0
            or actual_policy.lockout_threshold > policy.lockout_threshold
        ):
            findings.append(
                Finding(
                    "Security Policy",
                    Severity.MEDIUM,
                    "Account lockout threshold is weaker than baseline",
                    f"Set lockout threshold to {policy.lockout_threshold}",
                )
            )

        policy_flags = {
            "Logon auditing": (actual_policy.audit_logon_events, policy.audit_logon_events),
            "Process creation auditing": (
                actual_policy.audit_process_creation,
                policy.audit_process_creation,
            ),
            "PowerShell script block logging": (
                actual_policy.powershell_script_block_logging,
                policy.powershell_script_block_logging,
            ),
            "PowerShell transcription": (
                actual_policy.powershell_transcription,
                policy.powershell_transcription,
            ),
        }

        for name, (observed, expected) in policy_flags.items():
            if expected and not observed:
                findings.append(
                    Finding(
                        "Security Policy",
                        Severity.HIGH if "PowerShell" in name else Severity.MEDIUM,
                        f"{name} is disabled",
                        f"Enable {name.lower()}",
                    )
                )

        expected_app = self.baseline.application_control
        actual_app = endpoint.application_control

        if actual_app.mode != expected_app.mode:
            findings.append(
                Finding(
                    "Application Control",
                    Severity.HIGH,
                    f"Application control mode is {actual_app.mode.value}",
                    f"Use {expected_app.mode.value} mode",
                )
            )

        for name in ("publisher_rules", "path_rules", "unsigned_binary_blocking"):
            expected_value = getattr(expected_app, name)
            actual_value = getattr(actual_app, name)
            if expected_value and not actual_value:
                findings.append(
                    Finding(
                        "Application Control",
                        Severity.HIGH,
                        f"{name.replace('_', ' ').title()} is disabled",
                        f"Enable {name.replace('_', ' ')}",
                    )
                )

        for rule in self.baseline.asr_rules:
            actual_state = endpoint.asr_rules.get(rule.rule_id, Enforcement.DISABLED)
            if actual_state != rule.required_state:
                findings.append(
                    Finding(
                        "Attack Surface Reduction",
                        rule.severity,
                        f"{rule.name} is {actual_state.value}; baseline requires {rule.required_state.value}",
                        f"Set ASR rule {rule.rule_id} to {rule.required_state.value}",
                    )
                )

        return findings

    @staticmethod
    def powershell_remediation(findings: Iterable[Finding]) -> list[str]:
        """Generate reviewable PowerShell commands without executing them."""
        commands = []

        for finding in findings:
            if finding.control == "Microsoft Defender":
                commands.append(
                    "Get-MpComputerStatus | "
                    "Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AMServiceEnabled"
                )
            elif finding.control == "Windows Firewall":
                commands.append("Get-NetFirewallProfile | Format-Table Name,Enabled,DefaultInboundAction")
            elif finding.control == "Application Control":
                commands.append("Get-AppLockerPolicy -Effective | Format-List")
            elif finding.control == "Attack Surface Reduction":
                commands.append("Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions")
            elif finding.control == "Security Policy":
                commands.append("auditpol /get /category:*")

        return list(dict.fromkeys(commands))


ASR_RULES = (
    ASRRule(
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
        "Block executable content from email client and webmail",
        Enforcement.BLOCK,
        Severity.HIGH,
    ),
    ASRRule(
        "3b576869-a4ec-4529-8536-b80a7769e899",
        "Block Office applications from creating executable content",
        Enforcement.BLOCK,
        Severity.HIGH,
    ),
    ASRRule(
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
        "Block Office applications from injecting code into other processes",
        Enforcement.BLOCK,
        Severity.HIGH,
    ),
    ASRRule(
        "26190899-1602-49e8-8b27-eb1d0a1ce869",
        "Block Office communication applications from creating child processes",
        Enforcement.AUDIT,
        Severity.MEDIUM,
    ),
)


def build_baseline() -> Baseline:
    defender = DefenderConfig(
        realtime_monitoring=True,
        behavior_monitoring=True,
        ioav_protection=True,
        cloud_protection=True,
        tamper_protection=True,
        signature_age_hours=24,
    )

    firewall = {
        name: FirewallProfile(
            name=name,
            enabled=True,
            default_inbound="Block",
            default_outbound="Allow",
        )
        for name in ("Domain", "Private", "Public")
    }

    policy = SecurityPolicy(
        password_minimum_length=14,
        lockout_threshold=5,
        lockout_duration_minutes=15,
        audit_logon_events=True,
        audit_process_creation=True,
        powershell_script_block_logging=True,
        powershell_transcription=True,
    )

    application_control = ApplicationControl(
        mode=Enforcement.BLOCK,
        publisher_rules=True,
        path_rules=True,
        unsigned_binary_blocking=True,
    )

    return Baseline(
        defender=defender,
        firewall=firewall,
        security_policy=policy,
        application_control=application_control,
        asr_rules=ASR_RULES,
    )


def build_demo_endpoint() -> WindowsEndpoint:
    return WindowsEndpoint(
        hostname="WIN-ENG-042",
        defender=DefenderConfig(
            realtime_monitoring=True,
            behavior_monitoring=False,
            ioav_protection=True,
            cloud_protection=True,
            tamper_protection=False,
            signature_age_hours=31,
        ),
        firewall_profiles=[
            FirewallProfile("Domain", True, "Block", "Allow"),
            FirewallProfile("Private", True, "Block", "Allow"),
            FirewallProfile("Public", False, "Allow", "Allow"),
        ],
        security_policy=SecurityPolicy(
            password_minimum_length=10,
            lockout_threshold=10,
            lockout_duration_minutes=10,
            audit_logon_events=True,
            audit_process_creation=False,
            powershell_script_block_logging=True,
            powershell_transcription=False,
        ),
        application_control=ApplicationControl(
            mode=Enforcement.AUDIT,
            publisher_rules=True,
            path_rules=False,
            unsigned_binary_blocking=False,
        ),
        asr_rules={
            ASR_RULES[0].rule_id: Enforcement.BLOCK,
            ASR_RULES[1].rule_id: Enforcement.AUDIT,
            ASR_RULES[2].rule_id: Enforcement.BLOCK,
            ASR_RULES[3].rule_id: Enforcement.DISABLED,
        },
    )


def report(endpoint: WindowsEndpoint, findings: list[Finding]) -> None:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1

    print(f"Endpoint: {endpoint.hostname}")
    print("Hardening assessment")
    print(json.dumps(counts, indent=2))

    if not findings:
        print("Status: COMPLIANT")
        return

    print("\nFindings")
    for finding in findings:
        print(f"[{finding.severity.value}] {finding.control}: {finding.message}")
        print(f"  Remediation: {finding.remediation}")

    print("\nReviewable diagnostic commands")
    for command in HardeningEvaluator.powershell_remediation(findings):
        print(f"  {command}")


class HardeningTests(unittest.TestCase):
    def test_compliant_endpoint_has_no_findings(self) -> None:
        baseline = build_baseline()
        endpoint = WindowsEndpoint(
            hostname="WIN-COMPLIANT",
            defender=baseline.defender,
            firewall_profiles=list(baseline.firewall.values()),
            security_policy=baseline.security_policy,
            application_control=baseline.application_control,
            asr_rules={rule.rule_id: rule.required_state for rule in baseline.asr_rules},
        )
        self.assertEqual(HardeningEvaluator(baseline).evaluate(endpoint), [])

    def test_invalid_hostname_is_rejected(self) -> None:
        endpoint = build_demo_endpoint()
        endpoint.hostname = "bad hostname with spaces"
        with self.assertRaises(ValueError):
            endpoint.validate()

    def test_missing_asr_rule_is_reported(self) -> None:
        baseline = build_baseline()
        endpoint = build_demo_endpoint()
        endpoint.asr_rules = {}
        findings = HardeningEvaluator(baseline).evaluate(endpoint)
        asr_findings = [
            finding for finding in findings if finding.control == "Attack Surface Reduction"
        ]
        self.assertEqual(len(asr_findings), len(ASR_RULES))


def main() -> None:
    baseline = build_baseline()
    endpoint = build_demo_endpoint()
    findings = HardeningEvaluator(baseline).evaluate(endpoint)
    report(endpoint, findings)

    print("\nSelf-tests")
    unittest.main(argv=["python"], exit=False, verbosity=1)


if __name__ == "__main__":
    main()
