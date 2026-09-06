#!/usr/bin/env python3
"""
Security Architecture: Defense in Depth, Least Privilege, Segmentation,
Zero Trust, Secure Defaults, and Fail-Safe Design

A self-contained study and demonstration script.

The examples are intentionally educational. They model security architecture
principles using Python data structures, policy engines, network segmentation,
identity and authorization checks, secure defaults, fail-safe behavior,
risk scoring, configuration validation, attack-path analysis, testing, and
generation of a diagrams.net-compatible architecture diagram.

No third-party packages are required.

Run:
    python security_architecture.py

The program prints progressively advanced demonstrations and can optionally
write a diagrams.net-compatible XML architecture diagram to disk.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple
import html
import random
import time
import unittest


# ============================================================================
# 1. FUNDAMENTAL SECURITY TERMINOLOGY
# ============================================================================

class TrustLevel(Enum):
    """A simplified representation of trust.

    Real zero-trust systems do not assign permanent trust merely from a
    location. This enum is useful for demonstrating why trust should be
    evaluated as contextual and temporary.
    """

    UNTRUSTED = 0
    LIMITED = 1
    VERIFIED = 2


class Decision(Enum):
    """Authorization outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"


class SecurityZone(Enum):
    """Logical network/security zones."""

    INTERNET = "Internet"
    DMZ = "DMZ"
    APPLICATION = "Application"
    DATABASE = "Database"
    MANAGEMENT = "Management"
    USER = "User"
    SECURITY = "Security"


@dataclass(frozen=True)
class Asset:
    """An asset that requires protection."""

    name: str
    asset_type: str
    zone: SecurityZone
    sensitivity: int
    description: str = ""

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("Asset name cannot be empty.")
        if not 1 <= self.sensitivity <= 5:
            raise ValueError("Sensitivity must be between 1 and 5.")


@dataclass
class Principal:
    """Identity attempting to perform an action."""

    name: str
    roles: Set[str]
    authenticated: bool
    mfa: bool
    device_compliant: bool
    source_ip: str
    risk_score: int = 0
    trust_level: TrustLevel = TrustLevel.UNTRUSTED

    def is_valid_ip(self) -> bool:
        try:
            IPv4Address(self.source_ip)
            return True
        except ValueError:
            return False


@dataclass(frozen=True)
class Request:
    """A request made by a principal against an asset."""

    principal: str
    action: str
    resource: str
    protocol: str
    destination_port: int
    timestamp: float


@dataclass
class AuditEvent:
    """Security-relevant event suitable for centralized logging."""

    request: Request
    decision: Decision
    reason: str
    controls_triggered: List[str] = field(default_factory=list)


# ============================================================================
# 2. SECURITY ARCHITECTURE PRINCIPLES
# ============================================================================

def explain_principles() -> None:
    """Print the major principles and their architectural meaning."""

    principles = {
        "Defense in depth": (
            "Use multiple independent or partially independent controls so "
            "one failed control does not automatically expose the asset."
        ),
        "Least privilege": (
            "Give identities and services only the permissions required for "
            "their legitimate tasks."
        ),
        "Segmentation": (
            "Separate systems into security zones and explicitly control "
            "traffic between zones."
        ),
        "Zero trust": (
            "Do not treat network location as sufficient proof of trust. "
            "Continuously evaluate identity, device, context, resource, "
            "action, and risk."
        ),
        "Secure defaults": (
            "A system should begin in the safer state. Access, features, "
            "network exposure, and privileges should be denied unless "
            "explicitly required."
        ),
        "Fail-safe design": (
            "When an authorization service, validation component, or control "
            "fails, the system should fail into a state that does not create "
            "unintended access."
        ),
    }

    print("\n=== SECURITY ARCHITECTURE PRINCIPLES ===")
    for name, definition in principles.items():
        print(f"\n{name}")
        print(f"  {definition}")


# ============================================================================
# 3. LEAST PRIVILEGE
# ============================================================================

ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "reader": {
        "document:read",
    },
    "analyst": {
        "document:read",
        "report:read",
    },
    "developer": {
        "document:read",
        "application:deploy",
        "logs:read",
    },
    "database_admin": {
        "database:read",
        "database:write",
        "database:schema",
    },
    "security_admin": {
        "logs:read",
        "security:configure",
        "security:investigate",
    },
}


def effective_permissions(principal: Principal) -> Set[str]:
    """Return the union of explicitly assigned role permissions."""

    permissions: Set[str] = set()

    for role in principal.roles:
        permissions.update(ROLE_PERMISSIONS.get(role, set()))

    return permissions


def has_permission(principal: Principal, permission: str) -> bool:
    """Apply least privilege through explicit permission lookup."""

    return permission in effective_permissions(principal)


def demonstrate_least_privilege() -> None:
    print("\n=== LEAST PRIVILEGE ===")

    analyst = Principal(
        name="alice",
        roles={"analyst"},
        authenticated=True,
        mfa=True,
        device_compliant=True,
        source_ip="10.20.10.25",
    )

    for permission in [
        "document:read",
        "report:read",
        "database:write",
        "security:configure",
    ]:
        print(
            f"{permission:22} -> "
            f"{'ALLOWED' if has_permission(analyst, permission) else 'DENIED'}"
        )

    print(
        "\nThe analyst receives only permissions inherited from the "
        "explicitly assigned analyst role."
    )


# ============================================================================
# 4. NETWORK SEGMENTATION
# ============================================================================

@dataclass(frozen=True)
class NetworkSegment:
    """A CIDR-defined network segment."""

    name: str
    network: IPv4Network
    zone: SecurityZone
    description: str

    def contains(self, address: str) -> bool:
        return IPv4Address(address) in self.network


@dataclass(frozen=True)
class FirewallRule:
    """Explicit inter-segment traffic rule."""

    source_zone: SecurityZone
    destination_zone: SecurityZone
    protocol: str
    port: int
    action: Decision
    reason: str


class SegmentationPolicy:
    """Default-deny segmentation policy.

    Rules are explicit allow-list entries. A missing rule results in DENY.
    """

    def __init__(self, rules: Iterable[FirewallRule]) -> None:
        self.rules = list(rules)

    def evaluate(
        self,
        source_zone: SecurityZone,
        destination_zone: SecurityZone,
        protocol: str,
        port: int,
    ) -> Tuple[Decision, str]:
        for rule in self.rules:
            if (
                rule.source_zone == source_zone
                and rule.destination_zone == destination_zone
                and rule.protocol.lower() == protocol.lower()
                and rule.port == port
            ):
                return rule.action, rule.reason

        return Decision.DENY, "No explicit rule exists; default deny applies."


def build_segmentation_policy() -> SegmentationPolicy:
    """Build a small representative zero-trust-style network policy."""

    rules = [
        FirewallRule(
            SecurityZone.INTERNET,
            SecurityZone.DMZ,
            "tcp",
            443,
            Decision.ALLOW,
            "Public HTTPS terminates at the edge.",
        ),
        FirewallRule(
            SecurityZone.DMZ,
            SecurityZone.APPLICATION,
            "tcp",
            8443,
            Decision.ALLOW,
            "Reverse proxy may call the application service.",
        ),
        FirewallRule(
            SecurityZone.APPLICATION,
            SecurityZone.DATABASE,
            "tcp",
            5432,
            Decision.ALLOW,
            "Application service requires PostgreSQL access.",
        ),
        FirewallRule(
            SecurityZone.MANAGEMENT,
            SecurityZone.APPLICATION,
            "tcp",
            22,
            Decision.ALLOW,
            "Approved management subnet may administer application hosts.",
        ),
        FirewallRule(
            SecurityZone.MANAGEMENT,
            SecurityZone.DATABASE,
            "tcp",
            22,
            Decision.ALLOW,
            "Privileged administrators may manage database hosts.",
        ),
    ]

    return SegmentationPolicy(rules)


NETWORK_SEGMENTS = [
    NetworkSegment(
        "public_edge",
        IPv4Network("0.0.0.0/0"),
        SecurityZone.INTERNET,
        "Untrusted external network.",
    ),
    NetworkSegment(
        "dmz",
        IPv4Network("10.10.10.0/24"),
        SecurityZone.DMZ,
        "Public-facing reverse proxies and gateways.",
    ),
    NetworkSegment(
        "application",
        IPv4Network("10.20.20.0/24"),
        SecurityZone.APPLICATION,
        "Internal application services.",
    ),
    NetworkSegment(
        "database",
        IPv4Network("10.30.30.0/24"),
        SecurityZone.DATABASE,
        "Sensitive persistent data stores.",
    ),
    NetworkSegment(
        "management",
        IPv4Network("10.40.40.0/24"),
        SecurityZone.MANAGEMENT,
        "Restricted administrative access.",
    ),
]


def locate_zone(source_ip: str) -> SecurityZone:
    """Identify a representative security zone from an IP address.

    The Internet range is checked last because 0.0.0.0/0 contains every
    IPv4 address.
    """

    for segment in NETWORK_SEGMENTS:
        if segment.zone == SecurityZone.INTERNET:
            continue
        if segment.contains(source_ip):
            return segment.zone

    return SecurityZone.INTERNET


def demonstrate_segmentation() -> None:
    print("\n=== NETWORK SEGMENTATION ===")

    policy = build_segmentation_policy()

    tests = [
        ("10.20.20.10", SecurityZone.DATABASE, "tcp", 5432),
        ("10.20.20.10", SecurityZone.DATABASE, "tcp", 22),
        ("10.10.10.10", SecurityZone.APPLICATION, "tcp", 8443),
        ("10.40.40.10", SecurityZone.DATABASE, "tcp", 22),
        ("8.8.8.8", SecurityZone.DATABASE, "tcp", 5432),
    ]

    for source_ip, destination_zone, protocol, port in tests:
        source_zone = locate_zone(source_ip)
        decision, reason = policy.evaluate(
            source_zone,
            destination_zone,
            protocol,
            port,
        )

        print(
            f"{source_zone.value:12} -> {destination_zone.value:12} "
            f"{protocol.upper():4}/{port:<5} {decision.value:5} | {reason}"
        )


# ============================================================================
# 5. ZERO TRUST AUTHORIZATION
# ============================================================================

@dataclass
class AuthorizationContext:
    """Context used to make a dynamic authorization decision."""

    principal: Principal
    request: Request
    asset: Asset


class ZeroTrustPolicy:
    """A simplified policy decision point.

    Important properties:
    - authentication is required;
    - MFA is required for sensitive operations;
    - device compliance matters;
    - risk influences decisions;
    - resource sensitivity matters;
    - authorization is evaluated per request;
    - network location is not automatically trusted.
    """

    def evaluate(self, context: AuthorizationContext) -> Tuple[Decision, str, List[str]]:
        principal = context.principal
        asset = context.asset
        request = context.request
        controls: List[str] = []

        if not principal.authenticated:
            controls.append("authentication")
            return Decision.DENY, "Identity is not authenticated.", controls

        controls.append("authentication")

        if not principal.is_valid_ip():
            controls.append("input_validation")
            return Decision.DENY, "Source IP is invalid.", controls

        controls.append("input_validation")

        permission = f"{asset.asset_type}:{request.action}"

        if not has_permission(principal, permission):
            controls.append("least_privilege")
            return (
                Decision.DENY,
                f"Required permission {permission!r} is absent.",
                controls,
            )

        controls.append("least_privilege")

        if not principal.device_compliant:
            controls.append("device_posture")
            return Decision.DENY, "Device does not satisfy security posture.", controls

        controls.append("device_posture")

        if asset.sensitivity >= 4 and not principal.mfa:
            controls.append("mfa")
            return Decision.STEP_UP, "MFA is required for sensitive resources.", controls

        if asset.sensitivity >= 4:
            controls.append("mfa")

        if principal.risk_score >= 80:
            controls.append("risk_engine")
            return Decision.DENY, "Risk score is above the blocking threshold.", controls

        if principal.risk_score >= 50:
            controls.append("risk_engine")
            return Decision.STEP_UP, "Elevated risk requires additional verification.", controls

        controls.append("risk_engine")

        return Decision.ALLOW, "All applicable authorization controls passed.", controls


def demonstrate_zero_trust() -> None:
    print("\n=== ZERO TRUST AUTHORIZATION ===")

    database = Asset(
        name="customer_db",
        asset_type="database",
        zone=SecurityZone.DATABASE,
        sensitivity=5,
        description="Sensitive customer records.",
    )

    policy = ZeroTrustPolicy()

    scenarios = [
        Principal(
            name="alice",
            roles={"database_admin"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.20.20",
            risk_score=10,
        ),
        Principal(
            name="bob",
            roles={"database_admin"},
            authenticated=True,
            mfa=False,
            device_compliant=True,
            source_ip="10.20.20.21",
            risk_score=10,
        ),
        Principal(
            name="carol",
            roles={"database_admin"},
            authenticated=True,
            mfa=True,
            device_compliant=False,
            source_ip="10.20.20.22",
            risk_score=10,
        ),
        Principal(
            name="dave",
            roles={"database_admin"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.20.23",
            risk_score=90,
        ),
        Principal(
            name="eve",
            roles={"reader"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.20.24",
            risk_score=10,
        ),
    ]

    for principal in scenarios:
        request = Request(
            principal=principal.name,
            action="write",
            resource=database.name,
            protocol="tcp",
            destination_port=5432,
            timestamp=time.time(),
        )

        decision, reason, controls = policy.evaluate(
            AuthorizationContext(principal, request, database)
        )

        print(
            f"{principal.name:5} -> {decision.value:5} | "
            f"{reason} | controls={', '.join(controls)}"
        )


# ============================================================================
# 6. SECURE DEFAULTS
# ============================================================================

@dataclass
class ServiceConfiguration:
    """Secure-by-default service configuration.

    The safest configuration is represented explicitly rather than relying on
    implicit framework or operating-system defaults.
    """

    authentication_required: bool = True
    authorization_required: bool = True
    encryption_required: bool = True
    debug_mode: bool = False
    public_admin_interface: bool = False
    anonymous_access: bool = False
    default_allow_firewall: bool = False
    audit_logging: bool = True
    secure_headers: bool = True
    rate_limiting: bool = True


def validate_secure_configuration(
    config: ServiceConfiguration,
) -> List[str]:
    """Return configuration violations.

    An empty list means the configuration passes this narrow validation set.
    """

    violations: List[str] = []

    if not config.authentication_required:
        violations.append("Authentication must be required.")

    if not config.authorization_required:
        violations.append("Authorization must be required.")

    if not config.encryption_required:
        violations.append("Encryption must be required.")

    if config.debug_mode:
        violations.append("Debug mode should be disabled in production.")

    if config.public_admin_interface:
        violations.append("Administrative interfaces must not be public.")

    if config.anonymous_access:
        violations.append("Anonymous access is disabled by secure default.")

    if config.default_allow_firewall:
        violations.append("Firewall policy should use default deny.")

    if not config.audit_logging:
        violations.append("Security audit logging must be enabled.")

    if not config.secure_headers:
        violations.append("Security response headers should be enabled.")

    if not config.rate_limiting:
        violations.append("Rate limiting should be enabled where applicable.")

    return violations


def demonstrate_secure_defaults() -> None:
    print("\n=== SECURE DEFAULTS ===")

    secure = ServiceConfiguration()

    insecure = ServiceConfiguration(
        authentication_required=False,
        authorization_required=False,
        encryption_required=False,
        debug_mode=True,
        public_admin_interface=True,
        anonymous_access=True,
        default_allow_firewall=True,
        audit_logging=False,
        secure_headers=False,
        rate_limiting=False,
    )

    for name, config in [("secure", secure), ("insecure", insecure)]:
        violations = validate_secure_configuration(config)

        print(f"\n{name.upper()} configuration:")
        print("  PASS" if not violations else "  FAIL")
        for violation in violations:
            print(f"  - {violation}")


# ============================================================================
# 7. FAIL-SAFE DESIGN
# ============================================================================

class PolicyServiceUnavailable(RuntimeError):
    """Raised when an external policy dependency cannot be reached."""


class RemotePolicyService:
    """Minimal simulation of a remote policy service."""

    def __init__(self, available: bool = True) -> None:
        self.available = available

    def authorize(self, principal: str, action: str) -> bool:
        if not self.available:
            raise PolicyServiceUnavailable("Policy service unavailable.")

        return principal == "approved-admin" and action == "read"


def fail_safe_authorize(
    policy_service: RemotePolicyService,
    principal: str,
    action: str,
) -> bool:
    """Fail closed if the policy dependency is unavailable.

    This is appropriate for a sensitive authorization boundary.

    Some systems require availability-oriented alternatives, such as:
    - cached decisions with strict expiration;
    - emergency break-glass workflows;
    - read-only degraded operation;
    - local policy enforcement.

    Those mechanisms must themselves be designed so they do not become
    permanent bypasses.
    """

    try:
        return policy_service.authorize(principal, action)
    except PolicyServiceUnavailable:
        return False


def demonstrate_fail_safe() -> None:
    print("\n=== FAIL-SAFE DESIGN ===")

    healthy = RemotePolicyService(available=True)
    unavailable = RemotePolicyService(available=False)

    print(
        "Healthy policy service, approved principal:",
        fail_safe_authorize(healthy, "approved-admin", "read"),
    )

    print(
        "Healthy policy service, unapproved principal:",
        fail_safe_authorize(healthy, "ordinary-user", "read"),
    )

    print(
        "Unavailable policy service:",
        fail_safe_authorize(unavailable, "approved-admin", "read"),
    )

    print(
        "\nFor a sensitive authorization boundary, dependency failure "
        "produces DENY rather than accidental access."
    )


# ============================================================================
# 8. DEFENSE IN DEPTH
# ============================================================================

@dataclass
class SecurityControl:
    """A security control participating in a layered defense."""

    name: str
    layer: str
    protects_against: Set[str]
    enabled: bool = True


def build_defense_in_depth_model() -> List[SecurityControl]:
    return [
        SecurityControl(
            "Identity authentication",
            "Identity",
            {"credential_theft", "unauthorized_access"},
        ),
        SecurityControl(
            "MFA",
            "Identity",
            {"credential_theft", "account_takeover"},
        ),
        SecurityControl(
            "Least privilege",
            "Authorization",
            {"privilege_abuse", "lateral_movement"},
        ),
        SecurityControl(
            "Network segmentation",
            "Network",
            {"lateral_movement", "network_exposure"},
        ),
        SecurityControl(
            "Application validation",
            "Application",
            {"malformed_input", "injection"},
        ),
        SecurityControl(
            "Encryption",
            "Data",
            {"data_disclosure"},
        ),
        SecurityControl(
            "Audit logging",
            "Detection",
            {"persistence", "unauthorized_access"},
        ),
        SecurityControl(
            "Incident response",
            "Response",
            {"persistence", "account_takeover", "data_disclosure"},
        ),
    ]


def calculate_residual_risk(
    threat: str,
    controls: Sequence[SecurityControl],
) -> Tuple[int, List[str]]:
    """Illustrative risk reduction model.

    This is not a formal quantitative risk methodology. It demonstrates the
    architectural idea that multiple independent controls reduce residual
    risk, while avoiding the false assumption that security becomes zero-risk.
    """

    base_risk = 100
    applicable = [
        control
        for control in controls
        if control.enabled and threat in control.protects_against
    ]

    reduction = min(90, len(applicable) * 15)
    residual = max(10, base_risk - reduction)

    return residual, [control.name for control in applicable]


def demonstrate_defense_in_depth() -> None:
    print("\n=== DEFENSE IN DEPTH ===")

    controls = build_defense_in_depth_model()

    threats = [
        "credential_theft",
        "lateral_movement",
        "data_disclosure",
        "injection",
    ]

    for threat in threats:
        residual, applicable = calculate_residual_risk(threat, controls)

        print(f"\nThreat: {threat}")
        print(f"  Residual illustrative risk: {residual}/100")
        print(f"  Relevant controls: {', '.join(applicable)}")


# ============================================================================
# 9. ACCESS CONTROL MODELS
# ============================================================================

@dataclass(frozen=True)
class Resource:
    name: str
    owner: str
    classification: str


def demonstrate_access_control_models() -> None:
    """Compare DAC, RBAC, ABAC, and policy-based concepts."""

    print("\n=== ACCESS CONTROL MODELS ===")

    resource = Resource(
        name="financial_report",
        owner="finance",
        classification="confidential",
    )

    user = Principal(
        name="alice",
        roles={"analyst"},
        authenticated=True,
        mfa=True,
        device_compliant=True,
        source_ip="10.20.10.10",
        risk_score=20,
    )

    print("\nDiscretionary Access Control (DAC)")
    print(
        f"  Owner {resource.owner!r} may control access to "
        f"{resource.name!r}."
    )

    print("\nRole-Based Access Control (RBAC)")
    print(
        f"  alice roles={user.roles}; permission is derived from roles."
    )

    print("\nAttribute-Based Access Control (ABAC)")
    print(
        "  A decision can use attributes such as department, device posture, "
        "resource classification, location, time, and risk."
    )

    print("\nPolicy-Based Access Control")
    print(
        "  A centralized policy can combine identity, resource, action, "
        "environment, and risk conditions."
    )


# ============================================================================
# 10. IDENTITY, AUTHENTICATION, AUTHORIZATION, ACCOUNTING
# ============================================================================

def explain_iaaa() -> None:
    print("\n=== IDENTITY AND ACCESS CONTROL FLOW ===")

    steps = [
        ("Identification", "The subject claims an identity."),
        ("Authentication", "The system verifies the identity."),
        ("Authorization", "The system determines permitted actions."),
        ("Accounting / Auditing", "The system records security-relevant activity."),
    ]

    for name, definition in steps:
        print(f"{name:24} {definition}")

    print(
        "\nAuthentication does not imply authorization. A successfully "
        "authenticated identity may still have no permission for a resource."
    )


# ============================================================================
# 11. AUTHENTICATION FACTORS
# ============================================================================

def demonstrate_authentication_factors() -> None:
    print("\n=== AUTHENTICATION FACTORS ===")

    factors = {
        "Knowledge": "Password or PIN",
        "Possession": "Hardware security key or registered device",
        "Inherence": "Biometric characteristic",
        "Context": "Risk, location, time, or device posture",
    }

    for factor, example in factors.items():
        print(f"{factor:12}: {example}")

    print(
        "\nMFA is strongest when it combines independent factors rather than "
        "two credentials that are both effectively 'something you know'."
    )


# ============================================================================
# 12. ZERO-TRUST ARCHITECTURAL COMPONENTS
# ============================================================================

@dataclass
class ZeroTrustComponent:
    name: str
    responsibility: str


def demonstrate_zero_trust_components() -> None:
    print("\n=== ZERO TRUST ARCHITECTURAL COMPONENTS ===")

    components = [
        ZeroTrustComponent(
            "Policy Enforcement Point",
            "Enforces the authorization decision at the access boundary.",
        ),
        ZeroTrustComponent(
            "Policy Decision Point",
            "Evaluates policy and produces an access decision.",
        ),
        ZeroTrustComponent(
            "Identity Provider",
            "Authenticates users and provides identity claims.",
        ),
        ZeroTrustComponent(
            "Device Trust / Posture Service",
            "Reports device security state.",
        ),
        ZeroTrustComponent(
            "Policy / Risk Engine",
            "Combines identity, resource, action, and contextual signals.",
        ),
        ZeroTrustComponent(
            "Telemetry",
            "Supplies logs and signals for continuous evaluation.",
        ),
    ]

    for component in components:
        print(f"{component.name:32} {component.responsibility}")


# ============================================================================
# 13. THREAT MODELING
# ============================================================================

@dataclass
class Threat:
    name: str
    asset: str
    likelihood: int
    impact: int
    mitigations: List[str]

    @property
    def inherent_risk(self) -> int:
        return self.likelihood * self.impact


def prioritize_threats(threats: Sequence[Threat]) -> List[Threat]:
    return sorted(threats, key=lambda threat: threat.inherent_risk, reverse=True)


def demonstrate_threat_modeling() -> None:
    print("\n=== THREAT MODELING ===")

    threats = [
        Threat(
            "Credential theft",
            "Identity system",
            likelihood=4,
            impact=5,
            mitigations=["MFA", "risk detection", "short-lived sessions"],
        ),
        Threat(
            "Lateral movement",
            "Application network",
            likelihood=4,
            impact=5,
            mitigations=["segmentation", "least privilege", "EDR"],
        ),
        Threat(
            "Database exposure",
            "Customer database",
            likelihood=2,
            impact=5,
            mitigations=["private subnet", "encryption", "network policy"],
        ),
        Threat(
            "Misconfiguration",
            "Cloud resources",
            likelihood=5,
            impact=4,
            mitigations=["secure defaults", "configuration validation"],
        ),
    ]

    for threat in prioritize_threats(threats):
        print(
            f"{threat.name:22} asset={threat.asset:20} "
            f"risk={threat.inherent_risk:2} "
            f"mitigations={', '.join(threat.mitigations)}"
        )


# ============================================================================
# 14. ATTACK PATH AND LATERAL MOVEMENT ANALYSIS
# ============================================================================

@dataclass(frozen=True)
class GraphEdge:
    source: str
    destination: str
    control: Optional[str] = None


class SecurityGraph:
    """Small directed graph used to reason about attack paths."""

    def __init__(self, edges: Iterable[GraphEdge]) -> None:
        self.adjacency: Dict[str, List[GraphEdge]] = {}

        for edge in edges:
            self.adjacency.setdefault(edge.source, []).append(edge)

    def find_paths(
        self,
        source: str,
        destination: str,
        max_depth: int = 8,
    ) -> List[List[GraphEdge]]:
        paths: List[List[GraphEdge]] = []

        def dfs(
            current: str,
            visited: Set[str],
            path: List[GraphEdge],
        ) -> None:
            if len(path) > max_depth:
                return

            if current == destination:
                paths.append(path.copy())
                return

            for edge in self.adjacency.get(current, []):
                if edge.destination in visited:
                    continue

                visited.add(edge.destination)
                path.append(edge)
                dfs(edge.destination, visited, path)
                path.pop()
                visited.remove(edge.destination)

        dfs(source, {source}, [])
        return paths


def demonstrate_attack_paths() -> None:
    print("\n=== ATTACK PATH ANALYSIS ===")

    graph = SecurityGraph(
        [
            GraphEdge("Internet", "DMZ", "edge firewall"),
            GraphEdge("DMZ", "Application", "reverse proxy policy"),
            GraphEdge("Application", "Database", "application DB credential"),
            GraphEdge("DMZ", "Database", "MISCONFIGURATION"),
            GraphEdge("Application", "Management", "MISCONFIGURATION"),
        ]
    )

    paths = graph.find_paths("Internet", "Database")

    for index, path in enumerate(paths, start=1):
        route = ["Internet"]
        for edge in path:
            route.append(edge.destination)

        controls = [
            edge.control or "none"
            for edge in path
        ]

        print(f"Path {index}: {' -> '.join(route)}")
        print(f"  Controls: {' | '.join(controls)}")

    print(
        "\nA direct Internet-to-Database path indicates a segmentation "
        "failure even if the database itself has authentication."
    )


# ============================================================================
# 15. SECURITY BOUNDARIES
# ============================================================================

def explain_security_boundaries() -> None:
    print("\n=== SECURITY BOUNDARIES ===")

    boundaries = [
        ("Internet / DMZ", "Controls exposure of public-facing services."),
        ("DMZ / Application", "Restricts application service reachability."),
        ("Application / Database", "Protects sensitive persistent data."),
        ("User / Management", "Separates ordinary users from administration."),
        ("Production / Development", "Prevents development access from becoming production access."),
        ("Tenant / Tenant", "Reduces cross-tenant exposure in shared environments."),
    ]

    for boundary, purpose in boundaries:
        print(f"{boundary:28} {purpose}")


# ============================================================================
# 16. ENCRYPTION AND DATA PROTECTION
# ============================================================================

@dataclass(frozen=True)
class DataProtectionRequirement:
    state: str
    control: str
    objective: str


def demonstrate_data_protection() -> None:
    print("\n=== DATA PROTECTION ===")

    requirements = [
        DataProtectionRequirement(
            "At rest",
            "Storage encryption",
            "Reduce disclosure risk if storage media is accessed.",
        ),
        DataProtectionRequirement(
            "In transit",
            "TLS",
            "Protect data crossing networks from interception and tampering.",
        ),
        DataProtectionRequirement(
            "In use",
            "Application and platform controls",
            "Reduce unauthorized access while data is actively processed.",
        ),
        DataProtectionRequirement(
            "Backups",
            "Encryption + access control + immutability",
            "Protect recovery copies from theft and destructive attacks.",
        ),
    ]

    for requirement in requirements:
        print(
            f"{requirement.state:12} | "
            f"{requirement.control:32} | "
            f"{requirement.objective}"
        )


# ============================================================================
# 17. LOGGING, MONITORING, AND DETECTION
# ============================================================================

class AuditLogger:
    """Simple in-memory audit logger."""

    def __init__(self) -> None:
        self.events: List[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    def failed_authorizations(self) -> List[AuditEvent]:
        return [
            event
            for event in self.events
            if event.decision != Decision.ALLOW
        ]


def demonstrate_auditing() -> None:
    print("\n=== AUDITING AND DETECTION ===")

    logger = AuditLogger()

    request = Request(
        principal="eve",
        action="write",
        resource="customer_db",
        protocol="tcp",
        destination_port=5432,
        timestamp=time.time(),
    )

    logger.record(
        AuditEvent(
            request=request,
            decision=Decision.DENY,
            reason="Least privilege violation.",
            controls_triggered=["least_privilege"],
        )
    )

    logger.record(
        AuditEvent(
            request=request,
            decision=Decision.ALLOW,
            reason="Authorized.",
            controls_triggered=["authentication", "authorization"],
        )
    )

    print(f"Total events: {len(logger.events)}")
    print(f"Non-successful decisions: {len(logger.failed_authorizations())}")

    for event in logger.failed_authorizations():
        print(
            f"  principal={event.request.principal} "
            f"decision={event.decision.value} "
            f"reason={event.reason}"
        )


# ============================================================================
# 18. RATE LIMITING
# ============================================================================

class FixedWindowRateLimiter:
    """Simple fixed-window rate limiter.

    Production systems need distributed coordination, clock handling,
    persistence, abuse-resistant storage, and carefully chosen limits.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("Limit and window must be positive.")

        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}

    def allow(self, identity: str, now: Optional[float] = None) -> bool:
        current_time = time.time() if now is None else now
        window_start = current_time - self.window_seconds

        timestamps = self.requests.setdefault(identity, [])

        self.requests[identity] = [
            timestamp
            for timestamp in timestamps
            if timestamp > window_start
        ]

        if len(self.requests[identity]) >= self.limit:
            return False

        self.requests[identity].append(current_time)
        return True


def demonstrate_rate_limiting() -> None:
    print("\n=== RATE LIMITING ===")

    limiter = FixedWindowRateLimiter(limit=3, window_seconds=10)
    base_time = 1000.0

    results = [
        limiter.allow("alice", base_time + offset)
        for offset in [0, 1, 2, 3]
    ]

    print("Four requests inside a three-request window:", results)
    print(
        "Rate limiting is a supporting control. It does not replace "
        "authentication, authorization, input validation, or network controls."
    )


# ============================================================================
# 19. INPUT VALIDATION
# ============================================================================

def validate_port(port: int) -> int:
    """Validate a TCP/UDP port number."""

    if not isinstance(port, int):
        raise TypeError("Port must be an integer.")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")

    return port


def validate_username(username: str) -> str:
    """Small allow-list validation example."""

    if not isinstance(username, str):
        raise TypeError("Username must be a string.")

    normalized = username.strip()

    if not normalized:
        raise ValueError("Username cannot be empty.")

    if len(normalized) > 64:
        raise ValueError("Username is too long.")

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789._-"
    )

    if any(character not in allowed for character in normalized):
        raise ValueError("Username contains unsupported characters.")

    return normalized


def demonstrate_validation() -> None:
    print("\n=== VALIDATION ===")

    for port in [443, 0, 70000, "443"]:
        try:
            print(f"Port {port!r}: valid -> {validate_port(port)}")
        except (TypeError, ValueError) as error:
            print(f"Port {port!r}: rejected -> {error}")

    for username in ["alice", "", "alice@example.com", "a" * 65]:
        try:
            print(f"Username {username!r}: valid -> {validate_username(username)}")
        except (TypeError, ValueError) as error:
            print(f"Username {username!r}: rejected -> {error}")


# ============================================================================
# 20. CONFIGURATION DRIFT
# ============================================================================

@dataclass
class SecurityBaseline:
    required_settings: Dict[str, object]

    def compare(self, actual: Dict[str, object]) -> Dict[str, Tuple[object, object]]:
        drift: Dict[str, Tuple[object, object]] = {}

        for key, expected in self.required_settings.items():
            observed = actual.get(key)

            if observed != expected:
                drift[key] = (expected, observed)

        return drift


def demonstrate_configuration_drift() -> None:
    print("\n=== CONFIGURATION DRIFT ===")

    baseline = SecurityBaseline(
        required_settings={
            "ssh_password_login": False,
            "root_login": False,
            "public_database": False,
            "logging": True,
            "encryption": True,
        }
    )

    actual = {
        "ssh_password_login": False,
        "root_login": True,
        "public_database": False,
        "logging": True,
        "encryption": False,
    }

    drift = baseline.compare(actual)

    for key, (expected, observed) in drift.items():
        print(
            f"{key:24} expected={expected!r:<6} observed={observed!r}"
        )


# ============================================================================
# 21. SECRETS MANAGEMENT PRINCIPLES
# ============================================================================

def demonstrate_secrets_management() -> None:
    print("\n=== SECRETS MANAGEMENT ===")

    principles = [
        "Do not hard-code passwords, API keys, or private keys in source code.",
        "Use a dedicated secret-management mechanism with access control.",
        "Prefer short-lived credentials where practical.",
        "Rotate secrets according to risk and operational requirements.",
        "Audit secret access.",
        "Avoid exposing secrets in logs, exception messages, and telemetry.",
        "Use separate credentials across environments.",
        "Apply least privilege to services that consume secrets.",
    ]

    for principle in principles:
        print(f"- {principle}")


# ============================================================================
# 22. CLOUD SECURITY ARCHITECTURE
# ============================================================================

@dataclass(frozen=True)
class CloudLayer:
    name: str
    examples: Tuple[str, ...]


def demonstrate_cloud_architecture() -> None:
    print("\n=== CLOUD SECURITY ARCHITECTURE ===")

    layers = [
        CloudLayer(
            "Edge",
            ("WAF", "DDoS protection", "TLS termination", "CDN"),
        ),
        CloudLayer(
            "Identity",
            ("SSO", "MFA", "workload identity", "conditional access"),
        ),
        CloudLayer(
            "Network",
            ("VPC/VNet", "private subnets", "security groups", "network policy"),
        ),
        CloudLayer(
            "Application",
            ("secure APIs", "input validation", "authorization", "dependency security"),
        ),
        CloudLayer(
            "Data",
            ("encryption", "key management", "classification", "backup protection"),
        ),
        CloudLayer(
            "Operations",
            ("logging", "monitoring", "configuration compliance", "incident response"),
        ),
    ]

    for layer in layers:
        print(f"{layer.name:12}: {', '.join(layer.examples)}")


# ============================================================================
# 23. API SECURITY
# ============================================================================

@dataclass(frozen=True)
class ApiEndpoint:
    method: str
    path: str
    required_permission: str
    sensitive: bool = False


API_ENDPOINTS = [
    ApiEndpoint("GET", "/reports", "report:read"),
    ApiEndpoint("POST", "/deployments", "application:deploy", sensitive=True),
    ApiEndpoint("GET", "/documents", "document:read"),
    ApiEndpoint("DELETE", "/database/schema", "database:schema", sensitive=True),
]


def authorize_api_endpoint(
    principal: Principal,
    endpoint: ApiEndpoint,
) -> Decision:
    if not principal.authenticated:
        return Decision.DENY

    if not principal.device_compliant:
        return Decision.DENY

    if not has_permission(principal, endpoint.required_permission):
        return Decision.DENY

    if endpoint.sensitive and not principal.mfa:
        return Decision.STEP_UP

    if principal.risk_score >= 80:
        return Decision.DENY

    return Decision.ALLOW


def demonstrate_api_security() -> None:
    print("\n=== API SECURITY ===")

    developer = Principal(
        name="dev",
        roles={"developer"},
        authenticated=True,
        mfa=False,
        device_compliant=True,
        source_ip="10.20.20.50",
        risk_score=20,
    )

    for endpoint in API_ENDPOINTS:
        decision = authorize_api_endpoint(developer, endpoint)
        print(
            f"{endpoint.method:6} {endpoint.path:24} "
            f"required={endpoint.required_permission:22} "
            f"{decision.value}"
        )


# ============================================================================
# 24. SERVICE-TO-SERVICE SECURITY
# ============================================================================

@dataclass(frozen=True)
class ServiceIdentity:
    name: str
    allowed_targets: Set[str]
    allowed_actions: Set[str]


def authorize_service_call(
    caller: ServiceIdentity,
    target: str,
    action: str,
) -> bool:
    """Workload-level least privilege."""

    return (
        target in caller.allowed_targets
        and action in caller.allowed_actions
    )


def demonstrate_workload_identity() -> None:
    print("\n=== WORKLOAD IDENTITY ===")

    payment_service = ServiceIdentity(
        name="payment-service",
        allowed_targets={"ledger-service"},
        allowed_actions={"ledger:read", "ledger:write"},
    )

    calls = [
        ("ledger-service", "ledger:write"),
        ("user-service", "user:read"),
        ("ledger-service", "admin:delete"),
    ]

    for target, action in calls:
        print(
            f"{payment_service.name} -> {target} / {action}: "
            f"{'ALLOW' if authorize_service_call(payment_service, target, action) else 'DENY'}"
        )


# ============================================================================
# 25. MICROSEGMENTATION
# ============================================================================

@dataclass(frozen=True)
class MicrosegmentRule:
    workload: str
    target: str
    port: int
    allowed: bool


def evaluate_microsegment(
    workload: str,
    target: str,
    port: int,
    rules: Sequence[MicrosegmentRule],
) -> bool:
    for rule in rules:
        if (
            rule.workload == workload
            and rule.target == target
            and rule.port == port
        ):
            return rule.allowed

    return False


def demonstrate_microsegmentation() -> None:
    print("\n=== MICROSEGMENTATION ===")

    rules = [
        MicrosegmentRule("orders-api", "orders-db", 5432, True),
        MicrosegmentRule("orders-api", "inventory-api", 8443, True),
        MicrosegmentRule("orders-api", "identity-service", 443, True),
    ]

    tests = [
        ("orders-api", "orders-db", 5432),
        ("orders-api", "orders-db", 22),
        ("orders-api", "payroll-db", 5432),
    ]

    for workload, target, port in tests:
        print(
            f"{workload:14} -> {target:18} {port}: "
            f"{'ALLOW' if evaluate_microsegment(workload, target, port, rules) else 'DENY'}"
        )


# ============================================================================
# 26. BREAK-GLASS ACCESS
# ============================================================================

@dataclass
class BreakGlassRequest:
    requester: str
    reason: str
    approved_by: Optional[str]
    expires_at: float

    def is_valid(self, now: Optional[float] = None) -> bool:
        current = time.time() if now is None else now

        return (
            bool(self.requester)
            and bool(self.reason)
            and bool(self.approved_by)
            and current < self.expires_at
        )


def demonstrate_break_glass() -> None:
    print("\n=== BREAK-GLASS ACCESS ===")

    request = BreakGlassRequest(
        requester="incident-commander",
        reason="Production outage requires emergency database inspection.",
        approved_by="security-manager",
        expires_at=2000.0,
    )

    print("Before expiration:", request.is_valid(now=1500.0))
    print("After expiration:", request.is_valid(now=2500.0))

    print(
        "\nEmergency access should be explicit, time-bounded, approved, "
        "audited, and difficult to convert into permanent privilege."
    )


# ============================================================================
# 27. SECURITY DESIGN TRADE-OFFS
# ============================================================================

def demonstrate_tradeoffs() -> None:
    print("\n=== SECURITY ARCHITECTURE TRADE-OFFS ===")

    tradeoffs = [
        (
            "Strict segmentation",
            "Reduces lateral movement",
            "Can increase operational complexity",
        ),
        (
            "Least privilege",
            "Limits blast radius",
            "Requires careful permission engineering",
        ),
        (
            "MFA",
            "Reduces credential-compromise risk",
            "Adds authentication friction",
        ),
        (
            "Fail closed",
            "Prevents dependency failure from creating access",
            "Can reduce availability",
        ),
        (
            "Centralized policy",
            "Improves consistency and governance",
            "Creates dependency and availability considerations",
        ),
        (
            "Extensive logging",
            "Improves detection and investigation",
            "Creates storage, privacy, and operational costs",
        ),
    ]

    for control, benefit, cost in tradeoffs:
        print(f"\n{control}")
        print(f"  Benefit: {benefit}")
        print(f"  Trade-off: {cost}")


# ============================================================================
# 28. AVAILABILITY VS SECURITY
# ============================================================================

def compare_fail_modes() -> None:
    print("\n=== FAIL-OPEN VS FAIL-CLOSED ===")

    scenarios = [
        (
            "Authorization service failure",
            "Fail closed",
            "Avoid unintended access to sensitive resources.",
        ),
        (
            "Emergency communication system",
            "Carefully engineered availability mode",
            "Availability may be safety-critical.",
        ),
        (
            "Cache of authorization decisions",
            "Short-lived bounded fallback",
            "Use expiration, scope restrictions, and auditability.",
        ),
    ]

    for system, mode, rationale in scenarios:
        print(f"{system:34} {mode:34} {rationale}")


# ============================================================================
# 29. SECURITY ARCHITECTURE REVIEW CHECKLIST
# ============================================================================

def security_architecture_checklist() -> List[str]:
    return [
        "Assets are identified and classified.",
        "Trust boundaries are documented.",
        "Every external entry point has an explicit security boundary.",
        "Authentication is required where identity matters.",
        "Authorization is explicit and deny-by-default.",
        "Roles and permissions follow least privilege.",
        "Sensitive actions require stronger controls where appropriate.",
        "Networks are segmented according to trust and sensitivity.",
        "East-west traffic is explicitly controlled.",
        "Administrative interfaces are isolated.",
        "Secrets are managed outside source code.",
        "Data is protected at rest and in transit.",
        "Security logging captures important decisions and events.",
        "Monitoring can detect anomalous behavior.",
        "Configuration drift is detectable.",
        "Production defaults are secure.",
        "Dependency failure does not create unintended access.",
        "Break-glass access is bounded and auditable.",
        "Security controls are tested.",
        "Recovery and incident response are part of the architecture.",
    ]


def demonstrate_checklist() -> None:
    print("\n=== ARCHITECTURE REVIEW CHECKLIST ===")

    for index, item in enumerate(security_architecture_checklist(), start=1):
        print(f"{index:02}. {item}")


# ============================================================================
# 30. DIAGRAMS.NET / DRAW.IO XML GENERATION
# ============================================================================

@dataclass(frozen=True)
class DiagramNode:
    node_id: str
    label: str
    x: int
    y: int
    width: int
    height: int
    style: str


@dataclass(frozen=True)
class DiagramEdge:
    edge_id: str
    source: str
    target: str
    label: str
    style: str = (
        "edgeStyle=orthogonalEdgeStyle;"
        "rounded=0;"
        "orthogonalLoop=1;"
        "jettySize=auto;"
        "html=1;"
        "endArrow=block;"
    )


def build_diagram_xml() -> str:
    """Generate a diagrams.net-compatible architecture diagram.

    The resulting XML can be imported into diagrams.net using:
    File -> Import From -> Device

    The architecture demonstrates:
    Internet -> WAF/API Gateway -> Application -> Database,
    with identity, policy, monitoring, management, and segmentation controls.
    """

    nodes = [
        DiagramNode(
            "internet",
            "Internet\\nUntrusted",
            40,
            220,
            140,
            70,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "edge",
            "WAF / API Gateway\\nTLS + Rate Limiting",
            250,
            220,
            190,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "dmz",
            "DMZ\\nReverse Proxy",
            510,
            220,
            160,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "app",
            "Application Zone\\nServices",
            740,
            220,
            180,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "db",
            "Database Zone\\nSensitive Data",
            990,
            220,
            180,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "idp",
            "Identity Provider\\nSSO + MFA",
            500,
            60,
            180,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "policy",
            "Policy Decision Point\\nRisk + Context",
            730,
            60,
            200,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "monitoring",
            "Security Monitoring\\nLogs + Detection",
            980,
            60,
            190,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "management",
            "Management Zone\\nPrivileged Access",
            740,
            380,
            180,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
        DiagramNode(
            "security",
            "Security Controls\\nSegmentation + Baselines",
            990,
            380,
            200,
            80,
            "rounded=1;whiteSpace=wrap;html=1;",
        ),
    ]

    edges = [
        DiagramEdge("e1", "internet", "edge", "HTTPS"),
        DiagramEdge("e2", "edge", "dmz", "Allowed"),
        DiagramEdge("e3", "dmz", "app", "Explicit policy"),
        DiagramEdge("e4", "app", "db", "TCP 5432 only"),
        DiagramEdge("e5", "idp", "policy", "Identity claims"),
        DiagramEdge("e6", "policy", "app", "Authorization"),
        DiagramEdge("e7", "policy", "db", "Sensitive access policy"),
        DiagramEdge("e8", "app", "monitoring", "Audit telemetry"),
        DiagramEdge("e9", "db", "monitoring", "Audit telemetry"),
        DiagramEdge("e10", "management", "app", "Privileged access"),
        DiagramEdge("e11", "management", "db", "Restricted admin"),
        DiagramEdge("e12", "security", "app", "Segmentation"),
        DiagramEdge("e13", "security", "db", "Default deny"),
    ]

    def cell_node(node: DiagramNode) -> str:
        label = html.escape(node.label).replace("\\n", "<br>")
        return (
            f'<mxCell id="{node.node_id}" value="{label}" '
            f'style="{node.style}" vertex="1" parent="1">'
            f'<mxGeometry x="{node.x}" y="{node.y}" '
            f'width="{node.width}" height="{node.height}" as="geometry"/>'
            f"</mxCell>"
        )

    def cell_edge(edge: DiagramEdge) -> str:
        label = html.escape(edge.label)

        return (
            f'<mxCell id="{edge.edge_id}" value="{label}" '
            f'style="{edge.style}" edge="1" parent="1" '
            f'source="{edge.source}" target="{edge.target}">'
            f'<mxGeometry relative="1" as="geometry"/>'
            f"</mxCell>"
        )

    node_xml = "\n".join(cell_node(node) for node in nodes)
    edge_xml = "\n".join(cell_edge(edge) for edge in edges)

    return f"""<mxfile host="app.diagrams.net" modified="2026-09-06T00:00:00.000Z" agent="Security Architecture Study Script" version="24.7.17">
  <diagram name="Security Architecture" id="security-architecture">
    <mxGraphModel dx="1400" dy="900" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="1600" pageHeight="900" math="0" shadow="0">
      <root>
        <mxCell id="0"/>
        <mxCell id="1" parent="0"/>
        {node_xml}
        {edge_xml}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
"""


def write_diagrams_net_file(
    path: str = "security_architecture.drawio",
) -> Path:
    """Write the generated diagrams.net XML to disk."""

    output_path = Path(path)
    output_path.write_text(build_diagram_xml(), encoding="utf-8")
    return output_path


def demonstrate_diagrams_net() -> None:
    print("\n=== DIAGRAMS.NET ARCHITECTURE ===")

    output_path = write_diagrams_net_file()

    print(f"Generated: {output_path}")
    print(
        "The file represents trust boundaries, segmentation, identity, "
        "policy enforcement, monitoring, and restricted management access."
    )


# ============================================================================
# 31. SECURITY TESTING
# ============================================================================

class TestSecurityArchitecture(unittest.TestCase):
    """Executable tests for important security invariants."""

    def test_least_privilege_denies_unassigned_permission(self) -> None:
        principal = Principal(
            name="analyst",
            roles={"analyst"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.10.10",
        )

        self.assertFalse(has_permission(principal, "database:write"))

    def test_segmentation_is_default_deny(self) -> None:
        policy = build_segmentation_policy()

        decision, _ = policy.evaluate(
            SecurityZone.INTERNET,
            SecurityZone.DATABASE,
            "tcp",
            5432,
        )

        self.assertEqual(decision, Decision.DENY)

    def test_sensitive_access_requires_mfa(self) -> None:
        database = Asset(
            name="db",
            asset_type="database",
            zone=SecurityZone.DATABASE,
            sensitivity=5,
        )

        principal = Principal(
            name="admin",
            roles={"database_admin"},
            authenticated=True,
            mfa=False,
            device_compliant=True,
            source_ip="10.20.20.10",
            risk_score=10,
        )

        request = Request(
            principal="admin",
            action="write",
            resource="db",
            protocol="tcp",
            destination_port=5432,
            timestamp=0,
        )

        decision, _, _ = ZeroTrustPolicy().evaluate(
            AuthorizationContext(principal, request, database)
        )

        self.assertEqual(decision, Decision.STEP_UP)

    def test_fail_safe_denies_when_dependency_fails(self) -> None:
        service = RemotePolicyService(available=False)

        self.assertFalse(
            fail_safe_authorize(service, "approved-admin", "read")
        )

    def test_secure_configuration(self) -> None:
        self.assertEqual(
            validate_secure_configuration(ServiceConfiguration()),
            [],
        )

    def test_invalid_port_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_port(0)

    def test_invalid_username_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_username("alice@example.com")

    def test_microsegmentation_is_default_deny(self) -> None:
        self.assertFalse(
            evaluate_microsegment(
                "orders-api",
                "unknown-service",
                443,
                [],
            )
        )


def run_security_tests() -> None:
    print("\n=== SECURITY TESTS ===")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        TestSecurityArchitecture
    )

    result = unittest.TextTestRunner(
        verbosity=1,
    ).run(suite)

    print(
        f"Tests run: {result.testsRun}; "
        f"failures: {len(result.failures)}; "
        f"errors: {len(result.errors)}"
    )


# ============================================================================
# 32. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    print("\n=== IMPORTANT EDGE CASES ===")

    edge_cases = [
        (
            "Authenticated but unauthorized",
            "Authentication proves identity; it does not grant permissions.",
        ),
        (
            "Valid identity, compromised device",
            "Device posture can invalidate otherwise valid credentials.",
        ),
        (
            "Trusted internal IP",
            "Internal network location should not automatically authorize access.",
        ),
        (
            "Policy service unavailable",
            "Sensitive authorization should fail safely or use a bounded fallback.",
        ),
        (
            "Emergency administrator",
            "Break-glass access should be temporary, approved, and audited.",
        ),
        (
            "Stale authorization cache",
            "Cached decisions require expiration and scope restrictions.",
        ),
        (
            "Misconfigured firewall",
            "Network security must not be the only layer protecting a sensitive database.",
        ),
        (
            "Compromised application service",
            "Workload identity and database authorization should constrain blast radius.",
        ),
        (
            "Logging failure",
            "Detection failures should not silently disable preventive authorization controls.",
        ),
    ]

    for case, handling in edge_cases:
        print(f"\n{case}")
        print(f"  {handling}")


# ============================================================================
# 33. COMMON SECURITY ARCHITECTURE MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    print("\n=== COMMON MISTAKES ===")

    mistakes = [
        "Treating an internal network as automatically trusted.",
        "Using one large flat network.",
        "Giving services broad administrative privileges.",
        "Using authentication as a substitute for authorization.",
        "Creating allow-all firewall rules for convenience.",
        "Making database servers directly reachable from the Internet.",
        "Leaving administrative interfaces publicly exposed.",
        "Hard-coding secrets.",
        "Allowing debug functionality in production.",
        "Failing open when a policy service is unavailable.",
        "Keeping emergency privileges permanently enabled.",
        "Logging sensitive secrets or personal data unnecessarily.",
        "Assuming one security control eliminates an entire threat.",
        "Ignoring east-west traffic.",
        "Using security controls without monitoring whether they actually work.",
        "Failing to test security assumptions after architecture changes.",
    ]

    for mistake in mistakes:
        print(f"- {mistake}")


# ============================================================================
# 34. PRODUCTION SECURITY CONSIDERATIONS
# ============================================================================

def demonstrate_production_considerations() -> None:
    print("\n=== PRODUCTION CONSIDERATIONS ===")

    considerations = [
        "Define security requirements before implementation.",
        "Document trust boundaries and data flows.",
        "Use identity-centric authorization for users and workloads.",
        "Separate production, staging, development, and administrative planes.",
        "Use infrastructure-as-code with security validation.",
        "Continuously detect configuration drift.",
        "Centralize security telemetry without creating an excessive blast radius.",
        "Protect logging pipelines against tampering.",
        "Use strong key and secret lifecycle management.",
        "Plan for dependency failures and degraded modes.",
        "Exercise incident response and recovery procedures.",
        "Measure security controls using meaningful operational signals.",
        "Review privileges periodically.",
        "Remove obsolete network paths and unused accounts.",
        "Treat architecture as a continuously changing security system.",
    ]

    for consideration in considerations:
        print(f"- {consideration}")


# ============================================================================
# 35. PERFORMANCE CONSIDERATIONS
# ============================================================================

def demonstrate_performance_considerations() -> None:
    print("\n=== PERFORMANCE CONSIDERATIONS ===")

    considerations = [
        (
            "Central policy evaluation",
            "Can add network latency; caching can reduce latency but must be bounded.",
        ),
        (
            "MFA",
            "Adds user interaction latency and operational dependency.",
        ),
        (
            "Deep inspection",
            "Can increase CPU, memory, and throughput requirements.",
        ),
        (
            "Extensive logging",
            "Can increase storage and ingestion costs and system overhead.",
        ),
        (
            "Microsegmentation",
            "Can increase policy-management complexity and control-plane load.",
        ),
        (
            "Encryption",
            "Modern hardware often makes the cost manageable, but high-throughput systems require capacity planning.",
        ),
    ]

    for control, impact in considerations:
        print(f"{control:26} {impact}")


# ============================================================================
# 36. SECURITY ARCHITECTURE MATURITY
# ============================================================================

def demonstrate_maturity_levels() -> None:
    print("\n=== SECURITY ARCHITECTURE MATURITY ===")

    levels = [
        (
            "Level 1",
            "Perimeter-focused",
            "Security is concentrated around an external firewall.",
        ),
        (
            "Level 2",
            "Segmented",
            "Major environments and sensitive systems are separated.",
        ),
        (
            "Level 3",
            "Identity-centric",
            "Users and workloads receive explicit permissions.",
        ),
        (
            "Level 4",
            "Context-aware",
            "Device posture, risk, resource sensitivity, and context affect decisions.",
        ),
        (
            "Level 5",
            "Continuously evaluated",
            "Architecture continuously uses telemetry, policy, automation, and response.",
        ),
    ]

    for level, name, description in levels:
        print(f"{level:8} {name:24} {description}")


# ============================================================================
# 37. COMPLETE ARCHITECTURE SIMULATION
# ============================================================================

@dataclass
class SecurityArchitecture:
    """Integrated miniature security architecture."""

    assets: Dict[str, Asset]
    segmentation_policy: SegmentationPolicy
    authorization_policy: ZeroTrustPolicy
    logger: AuditLogger

    def handle_request(
        self,
        principal: Principal,
        resource_name: str,
        action: str,
        protocol: str,
        port: int,
    ) -> Decision:
        if resource_name not in self.assets:
            raise KeyError(f"Unknown resource: {resource_name}")

        asset = self.assets[resource_name]

        request = Request(
            principal=principal.name,
            action=action,
            resource=resource_name,
            protocol=protocol,
            destination_port=port,
            timestamp=time.time(),
        )

        source_zone = locate_zone(principal.source_ip)

        network_decision, network_reason = self.segmentation_policy.evaluate(
            source_zone,
            asset.zone,
            protocol,
            port,
        )

        if network_decision != Decision.ALLOW:
            self.logger.record(
                AuditEvent(
                    request=request,
                    decision=Decision.DENY,
                    reason=network_reason,
                    controls_triggered=["segmentation"],
                )
            )
            return Decision.DENY

        decision, reason, controls = self.authorization_policy.evaluate(
            AuthorizationContext(
                principal=principal,
                request=request,
                asset=asset,
            )
        )

        self.logger.record(
            AuditEvent(
                request=request,
                decision=decision,
                reason=reason,
                controls_triggered=["segmentation"] + controls,
            )
        )

        return decision


def build_security_architecture() -> SecurityArchitecture:
    assets = {
        "customer_db": Asset(
            name="customer_db",
            asset_type="database",
            zone=SecurityZone.DATABASE,
            sensitivity=5,
            description="Sensitive customer information.",
        ),
        "reports": Asset(
            name="reports",
            asset_type="report",
            zone=SecurityZone.APPLICATION,
            sensitivity=3,
            description="Internal analytical reports.",
        ),
        "documents": Asset(
            name="documents",
            asset_type="document",
            zone=SecurityZone.APPLICATION,
            sensitivity=2,
            description="General business documents.",
        ),
    }

    for asset in assets.values():
        asset.validate()

    return SecurityArchitecture(
        assets=assets,
        segmentation_policy=build_segmentation_policy(),
        authorization_policy=ZeroTrustPolicy(),
        logger=AuditLogger(),
    )


def demonstrate_integrated_architecture() -> None:
    print("\n=== INTEGRATED SECURITY ARCHITECTURE ===")

    architecture = build_security_architecture()

    identities = [
        Principal(
            name="database-admin",
            roles={"database_admin"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.20.15",
            risk_score=10,
        ),
        Principal(
            name="analyst",
            roles={"analyst"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.20.16",
            risk_score=10,
        ),
        Principal(
            name="compromised-admin",
            roles={"database_admin"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="10.20.20.17",
            risk_score=95,
        ),
        Principal(
            name="internet-user",
            roles={"database_admin"},
            authenticated=True,
            mfa=True,
            device_compliant=True,
            source_ip="203.0.113.20",
            risk_score=10,
        ),
    ]

    requests = [
        ("database-admin", "customer_db", "write", "tcp", 5432),
        ("analyst", "customer_db", "write", "tcp", 5432),
        ("compromised-admin", "customer_db", "write", "tcp", 5432),
        ("internet-user", "customer_db", "write", "tcp", 5432),
    ]

    principal_map = {principal.name: principal for principal in identities}

    for identity, resource, action, protocol, port in requests:
        decision = architecture.handle_request(
            principal_map[identity],
            resource,
            action,
            protocol,
            port,
        )

        print(
            f"{identity:20} -> {resource:15} {action:5} "
            f"{decision.value}"
        )

    print(
        f"\nAudit events generated: {len(architecture.logger.events)}"
    )


# ============================================================================
# 38. RANDOMIZED SECURITY POLICY TESTING
# ============================================================================

def randomized_default_deny_test(iterations: int = 100) -> int:
    """Test that unknown segmentation combinations remain denied.

    Randomized testing helps expose accidental allow behavior caused by
    overly broad matching logic.
    """

    if iterations <= 0:
        raise ValueError("Iterations must be positive.")

    policy = build_segmentation_policy()
    zones = list(SecurityZone)

    failures = 0
    random.seed(42)

    for _ in range(iterations):
        source = random.choice(zones)
        destination = random.choice(zones)
        protocol = random.choice(["tcp", "udp"])
        port = random.choice([22, 80, 443, 4433, 5432, 8443, 9999])

        decision, _ = policy.evaluate(
            source,
            destination,
            protocol,
            port,
        )

        explicitly_allowed = any(
            rule.source_zone == source
            and rule.destination_zone == destination
            and rule.protocol == protocol
            and rule.port == port
            and rule.action == Decision.ALLOW
            for rule in policy.rules
        )

        if not explicitly_allowed and decision != Decision.DENY:
            failures += 1

    return failures


def demonstrate_randomized_testing() -> None:
    print("\n=== RANDOMIZED DEFAULT-DENY TESTING ===")

    failures = randomized_default_deny_test(250)

    print(f"Unexpected allow decisions: {failures}")
    print(
        "Expected result: 0. Unknown combinations must not accidentally "
        "become allowed."
    )


# ============================================================================
# 39. EDUCATIONAL SCENARIO COMPARISON
# ============================================================================

def compare_architectures() -> None:
    print("\n=== ARCHITECTURE COMPARISON ===")

    architectures = [
        (
            "Flat perimeter",
            "Internet firewall",
            "Internal network trusted",
            "High lateral-movement risk",
        ),
        (
            "Segmented perimeter",
            "Firewall + zones",
            "Zones have different trust",
            "Better containment",
        ),
        (
            "Zero trust",
            "Identity + policy + segmentation",
            "No implicit trust",
            "Contextual per-request authorization",
        ),
    ]

    print(
        f"{'Architecture':22} {'Primary controls':28} "
        f"{'Trust model':28} {'Security property'}"
    )
    print("-" * 100)

    for architecture in architectures:
        print(
            f"{architecture[0]:22} "
            f"{architecture[1]:28} "
            f"{architecture[2]:28} "
            f"{architecture[3]}"
        )


# ============================================================================
# 40. MAIN PROGRAM
# ============================================================================

def main() -> None:
    print("=" * 90)
    print("SECURITY ARCHITECTURE STUDY AND IMPLEMENTATION SCRIPT")
    print("=" * 90)

    explain_principles()
    demonstrate_least_privilege()
    demonstrate_segmentation()
    demonstrate_zero_trust()
    demonstrate_secure_defaults()
    demonstrate_fail_safe()
    demonstrate_defense_in_depth()
    demonstrate_access_control_models()
    explain_iaaa()
    demonstrate_authentication_factors()
    demonstrate_zero_trust_components()
    demonstrate_threat_modeling()
    demonstrate_attack_paths()
    explain_security_boundaries()
    demonstrate_data_protection()
    demonstrate_auditing()
    demonstrate_rate_limiting()
    demonstrate_validation()
    demonstrate_configuration_drift()
    demonstrate_secrets_management()
    demonstrate_cloud_architecture()
    demonstrate_api_security()
    demonstrate_workload_identity()
    demonstrate_microsegmentation()
    demonstrate_break_glass()
    demonstrate_tradeoffs()
    compare_fail_modes()
    demonstrate_checklist()
    demonstrate_diagrams_net()
    demonstrate_edge_cases()
    demonstrate_common_mistakes()
    demonstrate_production_considerations()
    demonstrate_performance_considerations()
    demonstrate_maturity_levels()
    demonstrate_integrated_architecture()
    demonstrate_randomized_testing()
    compare_architectures()

    run_security_tests()

    print("\n=== STUDY SCRIPT COMPLETE ===")
    print(
        "A diagrams.net-compatible file named "
        "'security_architecture.drawio' was generated."
    )


if __name__ == "__main__":
    main()
