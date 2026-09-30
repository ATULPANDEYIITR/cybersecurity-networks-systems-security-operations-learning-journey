#!/usr/bin/env python3
"""
Networking Security Review
==========================

A self-contained defensive learning and assessment toolkit covering:

- Network attack surface
- Exposed services
- Insecure protocols
- Network segmentation fundamentals

The program operates only on supplied configuration data and synthetic
network observations. It does not perform network scanning, exploitation,
credential attacks, packet capture, or unauthorized probing.

The implementation progresses from simple asset/service modeling to:

- attack-surface inventory
- exposure classification
- protocol security review
- segmentation-policy evaluation
- risk scoring
- finding generation
- remediation planning
- JSON report generation
- regression tests
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from ipaddress import IPv4Network, IPv4Address
import json
import statistics
import unittest
from typing import Dict, Iterable, List, Optional, Set, Tuple


class Exposure(str, Enum):
    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    MANAGEMENT = "management"
    LOOPBACK = "loopback"


class ProtocolSecurity(str, Enum):
    SECURE = "secure"
    LEGACY = "legacy"
    INSECURE = "insecure"
    CONTEXT_DEPENDENT = "context-dependent"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Service:
    port: int
    protocol: str
    transport: str
    purpose: str
    security: ProtocolSecurity
    authenticated: bool
    encrypted: bool
    internet_exposed: bool = False

    def validate(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError(f"Invalid TCP/UDP port: {self.port}")

        if self.transport.lower() not in {"tcp", "udp"}:
            raise ValueError(f"Unsupported transport: {self.transport}")

        if not self.protocol.strip():
            raise ValueError("Protocol name cannot be empty")

        if self.security == ProtocolSecurity.SECURE and not self.encrypted:
            raise ValueError(
                f"{self.protocol} is marked secure but encryption is disabled"
            )

        if self.internet_exposed and self.security == ProtocolSecurity.INSECURE:
            raise ValueError(
                f"Clearly insecure service {self.protocol}:{self.port} "
                "must not be modeled as an approved Internet-facing service"
            )


@dataclass
class Asset:
    asset_id: str
    hostname: str
    ip_address: str
    network_zone: str
    owner: str
    business_role: str
    criticality: int
    services: List[Service] = field(default_factory=list)

    def validate(self) -> None:
        IPv4Address(self.ip_address)

        if not self.asset_id.strip():
            raise ValueError("Asset ID cannot be empty")

        if not self.hostname.strip():
            raise ValueError("Hostname cannot be empty")

        if not 1 <= self.criticality <= 5:
            raise ValueError("Criticality must be between 1 and 5")

        for service in self.services:
            service.validate()


@dataclass(frozen=True)
class NetworkSegment:
    name: str
    cidr: str
    purpose: str
    trust_level: int

    def validate(self) -> None:
        IPv4Network(self.cidr, strict=False)

        if not 1 <= self.trust_level <= 5:
            raise ValueError("Trust level must be between 1 and 5")


@dataclass(frozen=True)
class FlowRule:
    source_zone: str
    destination_zone: str
    service: str
    port: int
    allowed: bool
    reason: str

    def validate(self) -> None:
        if not self.source_zone.strip() or not self.destination_zone.strip():
            raise ValueError("Flow zones cannot be empty")

        if not 1 <= self.port <= 65535:
            raise ValueError("Flow port must be between 1 and 65535")


@dataclass
class Finding:
    category: str
    severity: Severity
    asset: str
    title: str
    evidence: str
    recommendation: str
    score: float

    def to_dict(self) -> dict:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


@dataclass
class SecurityReviewReport:
    findings: List[Finding]
    reviewed_assets: int
    reviewed_services: int

    def to_dict(self) -> dict:
        severity_counts = {
            severity.value: sum(
                1 for finding in self.findings if finding.severity == severity
            )
            for severity in Severity
        }

        return {
            "reviewed_assets": self.reviewed_assets,
            "reviewed_services": self.reviewed_services,
            "finding_count": len(self.findings),
            "severity_counts": severity_counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }


class AttackSurfaceAnalyzer:
    """
    Converts an asset/service inventory into defensive findings.

    The important distinction is between:
    - existence of a service,
    - network reachability,
    - Internet exposure,
    - protocol security,
    - and business necessity.

    A listening service is not automatically a vulnerability. Risk depends
    on exposure, protocol properties, authentication, encryption, and role.
    """

    def __init__(self, assets: Iterable[Asset]) -> None:
        self.assets = list(assets)

    @staticmethod
    def _severity(score: float) -> Severity:
        if score >= 8:
            return Severity.CRITICAL
        if score >= 6:
            return Severity.HIGH
        if score >= 3:
            return Severity.MEDIUM
        return Severity.LOW

    def review(self) -> List[Finding]:
        findings: List[Finding] = []

        for asset in self.assets:
            asset.validate()

            internet_services = [
                service
                for service in asset.services
                if service.internet_exposed
            ]

            # Attack-surface expansion is assessed at the service boundary.
            if len(internet_services) >= 4:
                score = min(10.0, 5.0 + len(internet_services) * 0.75)
                findings.append(
                    Finding(
                        category="attack_surface",
                        severity=self._severity(score),
                        asset=asset.asset_id,
                        title="Large Internet-facing service surface",
                        evidence=(
                            f"{len(internet_services)} services are modeled as "
                            "Internet exposed"
                        ),
                        recommendation=(
                            "Remove unnecessary public services and place "
                            "administrative interfaces behind controlled access."
                        ),
                        score=score,
                    )
                )

            for service in asset.services:
                if service.internet_exposed and service.security in {
                    ProtocolSecurity.INSECURE,
                    ProtocolSecurity.LEGACY,
                }:
                    score = 8.0 if service.security == ProtocolSecurity.INSECURE else 6.5

                    if not service.authenticated:
                        score += 1.0

                    findings.append(
                        Finding(
                            category="insecure_protocol",
                            severity=self._severity(min(score, 10)),
                            asset=asset.asset_id,
                            title=f"Risky exposed protocol: {service.protocol}",
                            evidence=(
                                f"{service.protocol}/{service.transport} on port "
                                f"{service.port}; encrypted={service.encrypted}; "
                                f"authenticated={service.authenticated}"
                            ),
                            recommendation=(
                                "Replace the protocol with an authenticated, "
                                "encrypted alternative or remove Internet exposure."
                            ),
                            score=min(score, 10),
                        )
                    )

                if service.internet_exposed and not service.authenticated:
                    score = min(
                        10.0,
                        5.0 + asset.criticality * 0.7,
                    )
                    findings.append(
                        Finding(
                            category="exposed_service",
                            severity=self._severity(score),
                            asset=asset.asset_id,
                            title=f"Internet-facing service lacks authentication",
                            evidence=(
                                f"{service.protocol}:{service.port} is reachable "
                                "at the modeled Internet boundary without "
                                "application-level authentication."
                            ),
                            recommendation=(
                                "Restrict reachability, add strong authentication, "
                                "or remove the service from the public boundary."
                            ),
                            score=score,
                        )
                    )

            if asset.network_zone.lower() == "user" and asset.criticality >= 4:
                findings.append(
                    Finding(
                        category="segmentation",
                        severity=Severity.HIGH,
                        asset=asset.asset_id,
                        title="High-criticality asset located in a user zone",
                        evidence=(
                            f"Asset criticality={asset.criticality}, "
                            f"zone={asset.network_zone}"
                        ),
                        recommendation=(
                            "Review whether the asset should be moved into a "
                            "dedicated application or protected server segment."
                        ),
                        score=6.0,
                    )
                )

        return findings


class SegmentationEngine:
    """
    Evaluates intended traffic relationships.

    Segmentation is not simply creating VLANs or subnets. The security
    property comes from controlling which trust zones can communicate,
    for which services, and under what policy.
    """

    def __init__(
        self,
        segments: Iterable[NetworkSegment],
        rules: Iterable[FlowRule],
    ) -> None:
        self.segments = {segment.name: segment for segment in segments}
        self.rules = list(rules)

        for segment in self.segments.values():
            segment.validate()

        for rule in self.rules:
            rule.validate()

    def evaluate(self) -> List[Finding]:
        findings: List[Finding] = []

        for source, source_segment in self.segments.items():
            for destination, destination_segment in self.segments.items():
                if source == destination:
                    continue

                if source_segment.trust_level > destination_segment.trust_level:
                    # A more trusted zone talking to a less trusted zone may
                    # be valid, but should still be explicit rather than broad.
                    continue

                if destination_segment.trust_level >= 4:
                    matching = [
                        rule
                        for rule in self.rules
                        if rule.source_zone == source
                        and rule.destination_zone == destination
                        and rule.allowed
                    ]

                    if not matching:
                        findings.append(
                            Finding(
                                category="segmentation",
                                severity=Severity.HIGH,
                                asset=destination,
                                title="Protected segment lacks explicit inbound policy",
                                evidence=(
                                    f"No allowed rule exists from {source} to "
                                    f"protected zone {destination}"
                                ),
                                recommendation=(
                                    "Use explicit allow rules for required flows "
                                    "and deny unexpected inter-zone traffic."
                                ),
                                score=6.5,
                            )
                        )

        for rule in self.rules:
            if rule.source_zone not in self.segments:
                findings.append(
                    Finding(
                        category="segmentation",
                        severity=Severity.HIGH,
                        asset=rule.source_zone,
                        title="Flow rule references an unknown source zone",
                        evidence=rule.reason,
                        recommendation=(
                            "Correct the policy reference before deployment."
                        ),
                        score=6.0,
                    )
                )

            if rule.destination_zone not in self.segments:
                findings.append(
                    Finding(
                        category="segmentation",
                        severity=Severity.HIGH,
                        asset=rule.destination_zone,
                        title="Flow rule references an unknown destination zone",
                        evidence=rule.reason,
                        recommendation=(
                            "Correct the policy reference before deployment."
                        ),
                        score=6.0,
                    )
                )

            if (
                rule.allowed
                and rule.source_zone in self.segments
                and rule.destination_zone in self.segments
            ):
                destination = self.segments[rule.destination_zone]

                if destination.trust_level >= 4 and rule.port in {22, 3389}:
                    findings.append(
                        Finding(
                            category="segmentation",
                            severity=Severity.HIGH,
                            asset=rule.destination_zone,
                            title="Administrative protocol crosses a protected boundary",
                            evidence=(
                                f"{rule.service}:{rule.port} is allowed from "
                                f"{rule.source_zone} to {rule.destination_zone}"
                            ),
                            recommendation=(
                                "Restrict administrative access to a dedicated "
                                "management zone or tightly controlled jump host."
                            ),
                            score=7.0,
                        )
                    )

        return findings


def build_sample_inventory() -> Tuple[List[Asset], List[NetworkSegment], List[FlowRule]]:
    assets = [
        Asset(
            asset_id="web-01",
            hostname="web-01.example.internal",
            ip_address="10.20.10.20",
            network_zone="dmz",
            owner="Web Platform",
            business_role="Public application gateway",
            criticality=4,
            services=[
                Service(
                    port=443,
                    protocol="HTTPS",
                    transport="tcp",
                    purpose="Public web application",
                    security=ProtocolSecurity.SECURE,
                    authenticated=True,
                    encrypted=True,
                    internet_exposed=True,
                ),
                Service(
                    port=22,
                    protocol="SSH",
                    transport="tcp",
                    purpose="Administration",
                    security=ProtocolSecurity.SECURE,
                    authenticated=True,
                    encrypted=True,
                    internet_exposed=True,
                ),
            ],
        ),
        Asset(
            asset_id="legacy-file-01",
            hostname="legacy-file-01.example.internal",
            ip_address="10.20.30.15",
            network_zone="user",
            owner="Operations",
            business_role="Legacy file transfer",
            criticality=4,
            services=[
                Service(
                    port=21,
                    protocol="FTP",
                    transport="tcp",
                    purpose="Legacy file transfer",
                    security=ProtocolSecurity.INSECURE,
                    authenticated=False,
                    encrypted=False,
                    internet_exposed=True,
                ),
                Service(
                    port=80,
                    protocol="HTTP",
                    transport="tcp",
                    purpose="Legacy administration",
                    security=ProtocolSecurity.INSECURE,
                    authenticated=False,
                    encrypted=False,
                    internet_exposed=False,
                ),
            ],
        ),
        Asset(
            asset_id="payments-api",
            hostname="payments-api.example.internal",
            ip_address="10.20.40.25",
            network_zone="application",
            owner="Payments",
            business_role="Payment processing API",
            criticality=5,
            services=[
                Service(
                    port=443,
                    protocol="HTTPS",
                    transport="tcp",
                    purpose="Payment API",
                    security=ProtocolSecurity.SECURE,
                    authenticated=True,
                    encrypted=True,
                    internet_exposed=False,
                ),
                Service(
                    port=5432,
                    protocol="PostgreSQL",
                    transport="tcp",
                    purpose="Database connection",
                    security=ProtocolSecurity.CONTEXT_DEPENDENT,
                    authenticated=True,
                    encrypted=True,
                    internet_exposed=False,
                ),
            ],
        ),
        Asset(
            asset_id="database-01",
            hostname="database-01.example.internal",
            ip_address="10.20.50.10",
            network_zone="database",
            owner="Data Platform",
            business_role="Transactional database",
            criticality=5,
            services=[
                Service(
                    port=5432,
                    protocol="PostgreSQL",
                    transport="tcp",
                    purpose="Application database",
                    security=ProtocolSecurity.SECURE,
                    authenticated=True,
                    encrypted=True,
                    internet_exposed=False,
                ),
            ],
        ),
    ]

    segments = [
        NetworkSegment(
            name="internet",
            cidr="0.0.0.0/0",
            purpose="Untrusted external network",
            trust_level=1,
        ),
        NetworkSegment(
            name="user",
            cidr="10.20.30.0/24",
            purpose="Employee endpoint network",
            trust_level=2,
        ),
        NetworkSegment(
            name="dmz",
            cidr="10.20.10.0/24",
            purpose="Public-facing application boundary",
            trust_level=3,
        ),
        NetworkSegment(
            name="application",
            cidr="10.20.40.0/24",
            purpose="Application services",
            trust_level=4,
        ),
        NetworkSegment(
            name="database",
            cidr="10.20.50.0/24",
            purpose="Transactional data services",
            trust_level=5,
        ),
        NetworkSegment(
            name="management",
            cidr="10.20.60.0/24",
            purpose="Administrative access",
            trust_level=5,
        ),
    ]

    rules = [
        FlowRule(
            source_zone="internet",
            destination_zone="dmz",
            service="HTTPS",
            port=443,
            allowed=True,
            reason="Public application traffic",
        ),
        FlowRule(
            source_zone="dmz",
            destination_zone="application",
            service="HTTPS",
            port=443,
            allowed=True,
            reason="Reverse proxy to application tier",
        ),
        FlowRule(
            source_zone="application",
            destination_zone="database",
            service="PostgreSQL",
            port=5432,
            allowed=True,
            reason="Application database access",
        ),
        FlowRule(
            source_zone="user",
            destination_zone="management",
            service="SSH",
            port=22,
            allowed=True,
            reason="Broad user-to-management administration rule",
        ),
    ]

    return assets, segments, rules


def print_inventory(assets: List[Asset]) -> None:
    print("\n=== Attack Surface Inventory ===")

    for asset in assets:
        print(
            f"\n{asset.asset_id} | {asset.hostname} | "
            f"zone={asset.network_zone} | criticality={asset.criticality}"
        )

        for service in asset.services:
            exposure = "INTERNET" if service.internet_exposed else "INTERNAL"
            print(
                f"  {service.protocol:<12} "
                f"{service.transport.upper():<3}/{service.port:<5} "
                f"{exposure:<8} "
                f"encrypted={service.encrypted} "
                f"authenticated={service.authenticated}"
            )


def print_findings(findings: List[Finding]) -> None:
    print("\n=== Security Findings ===")

    if not findings:
        print("No findings generated.")
        return

    for finding in sorted(
        findings,
        key=lambda item: (-item.score, item.asset, item.title),
    ):
        print(
            f"\n[{finding.severity.value.upper()}] "
            f"{finding.category} | {finding.asset}"
        )
        print(f"Title: {finding.title}")
        print(f"Evidence: {finding.evidence}")
        print(f"Recommendation: {finding.recommendation}")
        print(f"Risk score: {finding.score:.1f}")


def calculate_surface_metrics(assets: List[Asset]) -> Dict[str, float]:
    services = [
        service
        for asset in assets
        for service in asset.services
    ]

    public_services = [
        service for service in services if service.internet_exposed
    ]

    encrypted_services = [
        service for service in services if service.encrypted
    ]

    risky_public_services = [
        service
        for service in public_services
        if service.security in {
            ProtocolSecurity.INSECURE,
            ProtocolSecurity.LEGACY,
        }
    ]

    return {
        "asset_count": len(assets),
        "service_count": len(services),
        "internet_exposed_services": len(public_services),
        "encrypted_service_ratio": (
            len(encrypted_services) / len(services) if services else 0.0
        ),
        "risky_public_services": len(risky_public_services),
        "median_asset_criticality": (
            statistics.median(asset.criticality for asset in assets)
            if assets
            else 0.0
        ),
    }


def export_report(
    path: str,
    findings: List[Finding],
    assets: List[Asset],
) -> None:
    report = SecurityReviewReport(
        findings=findings,
        reviewed_assets=len(assets),
        reviewed_services=sum(len(asset.services) for asset in assets),
    )

    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report.to_dict(), handle, indent=2)


class SecurityReviewTests(unittest.TestCase):
    def test_invalid_port_is_rejected(self) -> None:
        service = Service(
            port=70000,
            protocol="HTTPS",
            transport="tcp",
            purpose="invalid",
            security=ProtocolSecurity.SECURE,
            authenticated=True,
            encrypted=True,
        )

        with self.assertRaises(ValueError):
            service.validate()

    def test_unencrypted_secure_protocol_is_rejected(self) -> None:
        service = Service(
            port=443,
            protocol="HTTPS",
            transport="tcp",
            purpose="invalid configuration",
            security=ProtocolSecurity.SECURE,
            authenticated=True,
            encrypted=False,
        )

        with self.assertRaises(ValueError):
            service.validate()

    def test_insecure_public_service_creates_finding(self) -> None:
        assets, _, _ = build_sample_inventory()
        findings = AttackSurfaceAnalyzer(assets).review()

        self.assertTrue(
            any(
                finding.category == "insecure_protocol"
                and finding.asset == "legacy-file-01"
                for finding in findings
            )
        )

    def test_database_has_explicit_application_flow(self) -> None:
        _, segments, rules = build_sample_inventory()
        findings = SegmentationEngine(segments, rules).evaluate()

        self.assertFalse(
            any(
                finding.title == "Protected segment lacks explicit inbound policy"
                and finding.asset == "database"
                and "application" in finding.evidence
                for finding in findings
            )
        )

    def test_management_ssh_rule_is_flagged(self) -> None:
        _, segments, rules = build_sample_inventory()
        findings = SegmentationEngine(segments, rules).evaluate()

        self.assertTrue(
            any(
                finding.title
                == "Administrative protocol crosses a protected boundary"
                for finding in findings
            )
        )


def main() -> None:
    assets, segments, rules = build_sample_inventory()

    print("NETWORKING SECURITY REVIEW")
    print("==========================")

    print_inventory(assets)

    metrics = calculate_surface_metrics(assets)

    print("\n=== Surface Metrics ===")
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"{key}: {value:.2f}")
        else:
            print(f"{key}: {value}")

    surface_findings = AttackSurfaceAnalyzer(assets).review()
    segmentation_findings = SegmentationEngine(segments, rules).evaluate()

    all_findings = surface_findings + segmentation_findings

    print_findings(all_findings)

    output_file = "network_security_review_report.json"
    export_report(output_file, all_findings, assets)

    print(f"\nReport written to: {output_file}")

    print("\n=== Defensive Review Principles Demonstrated ===")
    print(
        "Attack surface is reduced by minimizing unnecessary reachable services."
    )
    print(
        "Protocol security requires attention to encryption and authentication, "
        "not only the port number."
    )
    print(
        "Segmentation becomes meaningful when inter-zone traffic is explicitly "
        "controlled rather than merely separated into different subnets."
    )
    print(
        "Management access should use a controlled administrative path instead "
        "of broad access from ordinary user networks."
    )


if __name__ == "__main__":
    # Running this file executes the defensive review simulation.
    # Tests can be executed with: python -m unittest this_file.py
    main()
