#!/usr/bin/env python3
"""Executable Group Policy laboratory for workstation and account governance.

Models Group Policy Objects, linked scopes, policy precedence, password
requirements, workstation restrictions, audit findings, and policy changes.

Run with: python group_policy_lab.py
Uses only the Python standard library. This is a simulation, not a Windows
Group Policy editor or a replacement for Active Directory policy processing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import json
import re


class PolicyError(Exception):
    """Raised when a policy definition or policy operation is invalid."""


class PolicyCategory(str, Enum):
    SECURITY = "security"
    PASSWORD = "password"
    WORKSTATION = "workstation"


class ScopeType(str, Enum):
    SITE = "site"
    DOMAIN = "domain"
    OU = "ou"


class EnforcementMode(str, Enum):
    NORMAL = "normal"
    ENFORCED = "enforced"


@dataclass(frozen=True)
class PolicySetting:
    """A typed setting with validation appropriate to its security meaning."""

    name: str
    value: Any
    category: PolicyCategory

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise PolicyError("Policy setting name cannot be empty.")

        boolean_settings = {
            "account_lockout_enabled",
            "firewall_enabled",
            "usb_storage_blocked",
            "screen_lock_enabled",
            "local_admin_installation_blocked",
            "removable_media_auditing",
            "interactive_logon_banner_enabled",
        }
        integer_ranges = {
            "minimum_password_length": (8, 128),
            "password_history_count": (0, 50),
            "maximum_password_age_days": (0, 365),
            "minimum_password_age_days": (0, 365),
            "lockout_threshold": (0, 999),
            "lockout_duration_minutes": (0, 1440),
            "screen_lock_timeout_minutes": (1, 1440),
        }

        if self.name in boolean_settings and type(self.value) is not bool:
            raise PolicyError(f"{self.name} must be a Boolean.")

        if self.name in integer_ranges:
            if type(self.value) is not int:
                raise PolicyError(f"{self.name} must be an integer.")
            low, high = integer_ranges[self.name]
            if not low <= self.value <= high:
                raise PolicyError(
                    f"{self.name} must be between {low} and {high}."
                )

        if self.name == "password_complexity_enabled":
            if type(self.value) is not bool:
                raise PolicyError(
                    "password_complexity_enabled must be a Boolean."
                )

        if self.name == "minimum_password_age_days":
            if self.value < 0:
                raise PolicyError("Password age cannot be negative.")

        if self.name == "interactive_logon_banner_enabled":
            if self.category != PolicyCategory.SECURITY:
                raise PolicyError("Logon banner belongs to security policy.")

        if self.name in {
            "minimum_password_length",
            "password_history_count",
            "maximum_password_age_days",
            "minimum_password_age_days",
            "password_complexity_enabled",
        } and self.category != PolicyCategory.PASSWORD:
            raise PolicyError(
                f"{self.name} must belong to the password category."
            )

        if self.name in {
            "firewall_enabled",
            "usb_storage_blocked",
            "screen_lock_enabled",
            "screen_lock_timeout_minutes",
            "local_admin_installation_blocked",
            "removable_media_auditing",
        } and self.category != PolicyCategory.WORKSTATION:
            raise PolicyError(
                f"{self.name} must belong to the workstation category."
            )


@dataclass
class GroupPolicyObject:
    """A named collection of settings that can be linked to a directory scope."""

    name: str
    description: str
    settings: dict[str, PolicySetting] = field(default_factory=dict)
    enabled: bool = True

    def set_setting(self, setting: PolicySetting) -> None:
        self.settings[setting.name] = setting

    def remove_setting(self, name: str) -> None:
        self.settings.pop(name, None)


@dataclass(frozen=True)
class PolicyLink:
    gpo_name: str
    scope_type: ScopeType
    scope_name: str
    link_order: int
    mode: EnforcementMode = EnforcementMode.NORMAL
    enabled: bool = True
    block_inheritance: bool = False

    def __post_init__(self) -> None:
        if self.link_order < 1:
            raise PolicyError("Link order must be positive.")
        if not self.gpo_name or not self.scope_name:
            raise PolicyError("GPO and scope names are required.")


@dataclass
class Workstation:
    hostname: str
    site: str
    domain: str
    organizational_units: list[str]
    user_groups: list[str] = field(default_factory=list)
    local_settings: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyResult:
    effective_settings: dict[str, Any]
    source_by_setting: dict[str, str]
    applied_gpos: list[str]
    warnings: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "effective_settings": self.effective_settings,
            "source_by_setting": self.source_by_setting,
            "applied_gpos": self.applied_gpos,
            "warnings": self.warnings,
        }


class GroupPolicyEngine:
    """Simplified scope processing engine.

    The simulation uses site, domain, and OU links. Within a scope, lower
    link_order values are processed later and win. Normal child-scope settings
    override normal parent settings. Enforced ancestor settings cannot be
    overridden by normal descendant settings. This deliberately models only
    the core precedence rules, not every Windows policy-processing feature.
    """

    def __init__(self) -> None:
        self.gpos: dict[str, GroupPolicyObject] = {}
        self.links: list[PolicyLink] = []

    def add_gpo(self, gpo: GroupPolicyObject) -> None:
        if gpo.name in self.gpos:
            raise PolicyError(f"GPO already exists: {gpo.name}")
        self.gpos[gpo.name] = gpo

    def add_link(self, link: PolicyLink) -> None:
        if link.gpo_name not in self.gpos:
            raise PolicyError(f"Unknown GPO: {link.gpo_name}")
        self.links.append(link)

    def _matching_links(self, machine: Workstation) -> list[PolicyLink]:
        applicable_scopes = [
            (ScopeType.SITE, machine.site),
            (ScopeType.DOMAIN, machine.domain),
        ]
        applicable_scopes.extend(
            (ScopeType.OU, ou) for ou in machine.organizational_units
        )

        matching = [
            link
            for link in self.links
            if link.enabled
            and (link.scope_type, link.scope_name) in applicable_scopes
            and self.gpos[link.gpo_name].enabled
        ]

        # Parent scopes are processed before child scopes.
        depth = {
            ScopeType.SITE: 0,
            ScopeType.DOMAIN: 1,
            ScopeType.OU: 2,
        }
        return sorted(
            matching,
            key=lambda link: (
                depth[link.scope_type],
                link.link_order,
                link.gpo_name,
            ),
        )

    def evaluate(self, machine: Workstation) -> PolicyResult:
        matching = self._matching_links(machine)
        warnings: list[str] = []
        effective: dict[str, Any] = {}
        sources: dict[str, str] = {}
        enforced_sources: dict[str, str] = {}
        applied: list[str] = []

        # Block inheritance is simplified: a child OU's block stops ordinary
        # inherited site/domain links, while enforced links remain applicable.
        blocked_parent_scopes: set[tuple[ScopeType, str]] = set()
        for link in matching:
            if link.scope_type == ScopeType.OU and link.block_inheritance:
                blocked_parent_scopes.update({
                    (ScopeType.SITE, machine.site),
                    (ScopeType.DOMAIN, machine.domain),
                })

        for link in matching:
            if (
                (link.scope_type, link.scope_name) in blocked_parent_scopes
                and link.mode != EnforcementMode.ENFORCED
            ):
                continue

            gpo = self.gpos[link.gpo_name]
            applied.append(gpo.name)

            # Repeated GPO names may appear if linked at multiple scopes.
            for setting_name, setting in gpo.settings.items():
                if link.mode == EnforcementMode.ENFORCED:
                    enforced_sources[setting_name] = gpo.name
                    effective[setting_name] = setting.value
                    sources[setting_name] = gpo.name
                elif setting_name not in enforced_sources:
                    effective[setting_name] = setting.value
                    sources[setting_name] = gpo.name

        if effective.get("minimum_password_age_days", 0) > effective.get(
            "maximum_password_age_days", 365
        ) and effective.get("maximum_password_age_days", 0) != 0:
            warnings.append(
                "Minimum password age exceeds maximum password age."
            )

        threshold = effective.get("lockout_threshold")
        if threshold == 0:
            warnings.append(
                "Account lockout threshold is zero; lockout may be disabled."
            )

        if effective.get("screen_lock_enabled") is False:
            warnings.append("Automatic screen locking is disabled.")

        if effective.get("firewall_enabled") is False:
            warnings.append("Host firewall is disabled.")

        return PolicyResult(effective, sources, applied, warnings)


def password_policy_findings(policy: dict[str, Any]) -> list[str]:
    """Check a password policy for common internal inconsistencies."""
    findings: list[str] = []
    minimum = policy.get("minimum_password_length", 0)
    history = policy.get("password_history_count", 0)
    maximum_age = policy.get("maximum_password_age_days", 0)
    minimum_age = policy.get("minimum_password_age_days", 0)

    if minimum < 14:
        findings.append(
            "Minimum password length is below the organization's 14-character baseline."
        )
    if history < 12:
        findings.append("Password history retains fewer than 12 passwords.")
    if maximum_age != 0 and minimum_age > maximum_age:
        findings.append("Minimum password age exceeds maximum password age.")
    if policy.get("password_complexity_enabled") is not True:
        findings.append("Password complexity policy is not enabled.")
    return findings


def demonstrate_password_validation() -> None:
    """Demonstrate password policy checks without storing real credentials."""
    candidates = [
        "Winter2026",
        "Correct-Horse-Battery-Example",
        "short",
    ]

    for candidate in candidates:
        findings: list[str] = []
        if len(candidate) < 14:
            findings.append("too short")
        if not re.search(r"[a-z]", candidate):
            findings.append("missing lowercase character")
        if not re.search(r"[A-Z]", candidate):
            findings.append("missing uppercase character")
        if not re.search(r"\d", candidate):
            findings.append("missing digit")
        if not re.search(r"[^A-Za-z0-9]", candidate):
            findings.append("missing non-alphanumeric character")

        # A production system should use the identity platform's password
        # screening and breached-password checks, not only regex validation.
        print(
            f"Candidate length={len(candidate)}: "
            + (", ".join(findings) if findings else "passes local checks")
        )


def build_demo_environment() -> tuple[GroupPolicyEngine, Workstation]:
    engine = GroupPolicyEngine()

    baseline = GroupPolicyObject(
        "Domain-Security-Baseline",
        "Baseline security settings for managed domain devices.",
    )
    baseline.set_setting(
        PolicySetting(
            "interactive_logon_banner_enabled",
            True,
            PolicyCategory.SECURITY,
        )
    )
    baseline.set_setting(
        PolicySetting("firewall_enabled", True, PolicyCategory.WORKSTATION)
    )
    baseline.set_setting(
        PolicySetting(
            "minimum_password_length", 14, PolicyCategory.PASSWORD
        )
    )
    baseline.set_setting(
        PolicySetting(
            "password_history_count", 24, PolicyCategory.PASSWORD
        )
    )
    baseline.set_setting(
        PolicySetting(
            "password_complexity_enabled", True, PolicyCategory.PASSWORD
        )
    )
    baseline.set_setting(
        PolicySetting(
            "maximum_password_age_days", 0, PolicyCategory.PASSWORD
        )
    )
    baseline.set_setting(
        PolicySetting(
            "minimum_password_age_days", 1, PolicyCategory.PASSWORD
        )
    )
    baseline.set_setting(
        PolicySetting("lockout_threshold", 10, PolicyCategory.SECURITY)
    )

    engineering = GroupPolicyObject(
        "Engineering-Workstations",
        "Controls removable storage and automatic session locking.",
    )
    engineering.set_setting(
        PolicySetting(
            "usb_storage_blocked", True, PolicyCategory.WORKSTATION
        )
    )
    engineering.set_setting(
        PolicySetting(
            "screen_lock_enabled", True, PolicyCategory.WORKSTATION
        )
    )
    engineering.set_setting(
        PolicySetting(
            "screen_lock_timeout_minutes", 10, PolicyCategory.WORKSTATION
        )
    )
    engineering.set_setting(
        PolicySetting(
            "local_admin_installation_blocked",
            True,
            PolicyCategory.WORKSTATION,
        )
    )
    engineering.set_setting(
        PolicySetting(
            "removable_media_auditing", True, PolicyCategory.WORKSTATION
        )
    )

    legacy = GroupPolicyObject(
        "Legacy-Exception",
        "An intentionally weak policy used to demonstrate precedence.",
    )
    legacy.set_setting(
        PolicySetting("firewall_enabled", False, PolicyCategory.WORKSTATION)
    )

    for gpo in (baseline, engineering, legacy):
        engine.add_gpo(gpo)

    engine.add_link(
        PolicyLink(
            "Domain-Security-Baseline",
            ScopeType.DOMAIN,
            "corp.example",
            1,
            EnforcementMode.ENFORCED,
        )
    )
    engine.add_link(
        PolicyLink(
            "Legacy-Exception",
            ScopeType.OU,
            "Engineering",
            1,
        )
    )
    engine.add_link(
        PolicyLink(
            "Engineering-Workstations",
            ScopeType.OU,
            "Engineering",
            2,
        )
    )

    workstation = Workstation(
        hostname="ENG-WS-042",
        site="North-Office",
        domain="corp.example",
        organizational_units=["Engineering"],
        user_groups=["Engineering", "Standard-Users"],
    )
    return engine, workstation


def run_self_tests() -> None:
    try:
        PolicySetting(
            "minimum_password_length", 4, PolicyCategory.PASSWORD
        )
    except PolicyError:
        pass
    else:
        raise AssertionError("Invalid password length was accepted.")

    engine, machine = build_demo_environment()
    result = engine.evaluate(machine)

    assert result.effective_settings["firewall_enabled"] is True
    assert result.effective_settings["usb_storage_blocked"] is True
    assert result.effective_settings["minimum_password_length"] == 14
    assert "Domain-Security-Baseline" in result.applied_gpos
    assert result.source_by_setting["firewall_enabled"] == (
        "Domain-Security-Baseline"
    )

    # A disabled GPO must not contribute settings.
    engine.gpos["Engineering-Workstations"].enabled = False
    disabled_result = engine.evaluate(machine)
    assert "usb_storage_blocked" not in disabled_result.effective_settings

    print("Self-tests passed.")


def main() -> None:
    run_self_tests()

    engine, machine = build_demo_environment()
    result = engine.evaluate(machine)

    print("\nEffective Group Policy")
    print(json.dumps(result.as_dict(), indent=2))

    print("\nPassword Policy Audit")
    findings = password_policy_findings(result.effective_settings)
    if findings:
        for finding in findings:
            print(f"- {finding}")
    else:
        print("No password policy findings.")

    print("\nLocal Password Validation Demonstration")
    demonstrate_password_validation()

    print("\nWorkstation Restriction Review")
    for name in (
        "firewall_enabled",
        "usb_storage_blocked",
        "screen_lock_enabled",
        "screen_lock_timeout_minutes",
        "local_admin_installation_blocked",
        "removable_media_auditing",
    ):
        print(f"{name}: {result.effective_settings.get(name, 'NOT CONFIGURED')}")

    print("\nGovernance Notes")
    print("- Centralized policy evaluation does not prove client application.")
    print("- Validate actual results with Windows policy diagnostics.")
    print("- Never log password values or store reversible credentials.")
    print("- Test policy changes on a limited device group before broad rollout.")


if __name__ == "__main__":
    main()
