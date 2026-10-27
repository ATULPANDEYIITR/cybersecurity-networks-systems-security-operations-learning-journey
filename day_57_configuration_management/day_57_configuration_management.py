#!/usr/bin/env python3
"""
Secure Configuration Management
Models configuration baselines, drift detection, compliance evaluation,
approval workflows, remediation, audit events, and secure handling of
configuration secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable
import json
import re
import tempfile


class ComplianceState(Enum):
    COMPLIANT = "compliant"
    DRIFTED = "drifted"
    NON_COMPLIANT = "non_compliant"


class ChangeState(Enum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPLIED = "applied"


class ConfigurationError(Exception):
    """Raised for invalid or unsafe configuration operations."""


SECRET_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ConfigItem:
    key: str
    value: Any
    required: bool = True
    secret: bool = False

    def __post_init__(self) -> None:
        if not self.key or not re.fullmatch(r"[A-Za-z0-9_.-]+", self.key):
            raise ConfigurationError(f"Invalid configuration key: {self.key!r}")


@dataclass
class ConfigurationBaseline:
    name: str
    version: int
    items: dict[str, ConfigItem]
    checksum: str = field(init=False)

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ConfigurationError("Baseline version must be positive.")
        self.checksum = self.calculate_checksum()

    def calculate_checksum(self) -> str:
        canonical = {
            key: {
                "value": item.value if not item.secret else "<SECRET>",
                "required": item.required,
                "secret": item.secret,
            }
            for key, item in sorted(self.items.items())
        }
        payload = json.dumps(
            {"name": self.name, "version": self.version, "items": canonical},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return sha256(payload.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> bool:
        return self.checksum == self.calculate_checksum()


@dataclass(frozen=True)
class Drift:
    key: str
    expected: Any
    actual: Any
    reason: str


@dataclass(frozen=True)
class ComplianceRule:
    name: str
    key: str
    predicate: Any
    severity: str = "high"


@dataclass
class AuditEvent:
    action: str
    actor: str
    target: str
    details: str


class ConfigurationManager:
    def __init__(self, baseline: ConfigurationBaseline) -> None:
        self.baseline = baseline
        self.current: dict[str, Any] = {}
        self.audit_log: list[AuditEvent] = []
        self.change_state = ChangeState.PROPOSED

    def load_current(self, configuration: dict[str, Any]) -> None:
        if not isinstance(configuration, dict):
            raise ConfigurationError("Configuration must be a dictionary.")
        self.current = dict(configuration)
        self.audit_log.append(
            AuditEvent("CONFIG_LOADED", "system", self.baseline.name, "Current state loaded")
        )

    def detect_drift(self) -> list[Drift]:
        if not self.baseline.verify_integrity():
            raise ConfigurationError("Baseline integrity verification failed.")

        drift: list[Drift] = []

        for key, item in self.baseline.items.items():
            if key not in self.current:
                if item.required:
                    drift.append(Drift(key, item.value, None, "required key missing"))
                continue

            if item.secret:
                # Secret values are never printed or compared in audit output.
                if self.current[key] != item.value:
                    drift.append(Drift(key, "<SECRET>", "<SECRET>", "secret value differs"))
            elif self.current[key] != item.value:
                drift.append(Drift(key, item.value, self.current[key], "value differs"))

        for key in self.current:
            if key not in self.baseline.items:
                drift.append(Drift(key, None, self.current[key], "unauthorized key present"))

        return drift

    def evaluate_compliance(self, rules: Iterable[ComplianceRule]) -> list[str]:
        violations: list[str] = []
        for rule in rules:
            value = self.current.get(rule.key)
            try:
                valid = bool(rule.predicate(value))
            except Exception as exc:
                violations.append(f"{rule.name}: evaluation failure ({type(exc).__name__})")
                continue
            if not valid:
                violations.append(f"{rule.name}: {rule.severity}")
        return violations

    def propose_change(self, actor: str, key: str, value: Any) -> None:
        if not actor.strip():
            raise ConfigurationError("Actor is required.")
        if key not in self.baseline.items:
            raise ConfigurationError(f"Configuration key is not approved: {key}")
        self.current[key] = value
        self.change_state = ChangeState.PROPOSED
        self.audit_log.append(
            AuditEvent("CHANGE_PROPOSED", actor, key, "Configuration change proposed")
        )

    def approve_change(self, actor: str) -> None:
        if self.change_state != ChangeState.PROPOSED:
            raise ConfigurationError("Only proposed changes can be approved.")
        if not actor.strip():
            raise ConfigurationError("Approver is required.")
        self.change_state = ChangeState.APPROVED
        self.audit_log.append(
            AuditEvent("CHANGE_APPROVED", actor, self.baseline.name, "Change approved")
        )

    def apply_change(self, actor: str) -> None:
        if self.change_state != ChangeState.APPROVED:
            raise ConfigurationError("Change requires approval before application.")

        drift = self.detect_drift()
        if drift:
            raise ConfigurationError("Cannot apply configuration while drift remains.")

        self.change_state = ChangeState.APPLIED
        self.audit_log.append(
            AuditEvent("CHANGE_APPLIED", actor, self.baseline.name, "Configuration applied")
        )

    def remediate(self, actor: str, keys: set[str] | None = None) -> int:
        if keys is None:
            keys = set(self.baseline.items)

        changed = 0
        for key in keys:
            item = self.baseline.items.get(key)
            if item is None:
                continue
            if key not in self.current or self.current[key] != item.value:
                self.current[key] = item.value
                changed += 1

        self.audit_log.append(
            AuditEvent("DRIFT_REMEDIATED", actor, self.baseline.name, f"{changed} item(s)")
        )
        return changed

    def safe_export(self) -> dict[str, Any]:
        """Export configuration without exposing secret values."""
        return {
            key: "<REDACTED>" if item.secret else self.current.get(key)
            for key, item in self.baseline.items.items()
        }


def build_demo() -> tuple[ConfigurationBaseline, list[ComplianceRule], dict[str, Any]]:
    baseline = ConfigurationBaseline(
        name="production-linux-web",
        version=3,
        items={
            "ssh.root_login": ConfigItem("ssh.root_login", False),
            "ssh.password_authentication": ConfigItem(
                "ssh.password_authentication", False
            ),
            "firewall.enabled": ConfigItem("firewall.enabled", True),
            "tls.minimum_version": ConfigItem("tls.minimum_version", "TLS1.2"),
            "audit.enabled": ConfigItem("audit.enabled", True),
            "backup.retention_days": ConfigItem("backup.retention_days", 30),
            "service.http_port": ConfigItem("service.http_port", 443),
            "database.password": ConfigItem(
                "database.password", "not-used-in-production", secret=True
            ),
        },
    )

    rules = [
        ComplianceRule(
            "Root login must be disabled",
            "ssh.root_login",
            lambda value: value is False,
        ),
        ComplianceRule(
            "Password authentication must be disabled",
            "ssh.password_authentication",
            lambda value: value is False,
        ),
        ComplianceRule(
            "Firewall must be enabled",
            "firewall.enabled",
            lambda value: value is True,
        ),
        ComplianceRule(
            "TLS must be 1.2 or newer",
            "tls.minimum_version",
            lambda value: value in {"TLS1.2", "TLS1.3"},
        ),
        ComplianceRule(
            "Backups require at least seven days",
            "backup.retention_days",
            lambda value: isinstance(value, int) and value >= 7,
        ),
    ]

    current = {
        "ssh.root_login": False,
        "ssh.password_authentication": True,
        "firewall.enabled": True,
        "tls.minimum_version": "TLS1.2",
        "audit.enabled": True,
        "backup.retention_days": 30,
        "service.http_port": 443,
        "database.password": "different-secret",
        "debug.enabled": True,
    }
    return baseline, rules, current


def save_audit(path: Path, events: list[AuditEvent]) -> None:
    payload = [
        {
            "action": event.action,
            "actor": event.actor,
            "target": event.target,
            "details": event.details,
        }
        for event in events
    ]
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    baseline, rules, current = build_demo()
    manager = ConfigurationManager(baseline)
    manager.load_current(current)

    print("=== Secure Configuration Management ===")
    print(f"Baseline: {baseline.name} v{baseline.version}")
    print(f"Baseline integrity: {baseline.verify_integrity()}")

    drift = manager.detect_drift()
    print("\nDrift findings:")
    for item in drift:
        print(f"- {item.key}: {item.reason}")

    violations = manager.evaluate_compliance(rules)
    print("\nCompliance violations:")
    for violation in violations:
        print(f"- {violation}")

    print("\nRedacted export:")
    print(json.dumps(manager.safe_export(), indent=2))

    manager.remediate("configuration-admin")
    remaining = manager.detect_drift()
    print(f"\nRemaining drift after remediation: {len(remaining)}")

    manager.propose_change("configuration-admin", "backup.retention_days", 45)
    manager.approve_change("security-reviewer")

    # The proposed state has already been placed into current state, so it can
    # be applied after compliance has been rechecked.
    if not manager.evaluate_compliance(rules):
        manager.apply_change("deployment-service")
        print("Approved configuration change applied.")
    else:
        print("Configuration change blocked by compliance rules.")

    with tempfile.TemporaryDirectory() as directory:
        audit_path = Path(directory) / "audit.json"
        save_audit(audit_path, manager.audit_log)
        print(f"Audit events recorded: {len(manager.audit_log)}")
        print(f"Audit file created: {audit_path.name}")

    # Security-sensitive keys are never exposed by safe_export().
    assert manager.safe_export()["database.password"] == "<REDACTED>"
    assert manager.baseline.verify_integrity()


if __name__ == "__main__":
    main()
