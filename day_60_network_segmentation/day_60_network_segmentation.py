#!/usr/bin/env python3
"""
Network segmentation policy simulator.

Models VLAN-based network segmentation, DMZ boundaries, trust zones,
workload-level microsegmentation, and east-west traffic enforcement.

Run:
    python network_segmentation.py
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("network-segmentation")


class Zone(Enum):
    USER = "USER"
    DMZ = "DMZ"
    APPLICATION = "APPLICATION"
    DATA = "DATA"
    MANAGEMENT = "MANAGEMENT"
    INTERNET = "INTERNET"


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"


class Action(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@dataclass(frozen=True)
class NetworkSegment:
    segment_id: str
    name: str
    vlan_id: int
    cidr: str
    zone: Zone

    def __post_init__(self) -> None:
        if not self.segment_id.strip() or not self.name.strip():
            raise ValueError("Segment ID and name are required.")

        if not 1 <= self.vlan_id <= 4094:
            raise ValueError("VLAN ID must be between 1 and 4094.")

        network = ipaddress.ip_network(self.cidr, strict=True)

        if network.version != 4:
            raise ValueError("This simulator supports IPv4 networks.")

        if self.zone == Zone.INTERNET and not network.is_private:
            # Public documentation ranges are accepted for the simulation.
            if not network.is_global and not network.is_reserved:
                raise ValueError("Invalid external network configuration.")

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.cidr, strict=True)


@dataclass(frozen=True)
class Endpoint:
    endpoint_id: str
    segment_id: str
    address: str
    labels: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.endpoint_id.strip():
            raise ValueError("Endpoint ID is required.")

        address = ipaddress.ip_address(self.address)

        if address.version != 4:
            raise ValueError("Only IPv4 endpoints are supported.")

        labels = dict(self.labels)

        if not labels.get("role"):
            raise ValueError("Every endpoint must have a role label.")

        object.__setattr__(self, "labels", MappingProxyType(labels))


@dataclass(frozen=True)
class NetworkRule:
    rule_id: str
    priority: int
    source_zone: Zone
    destination_zone: Zone
    protocol: Protocol
    port_from: int
    port_to: int
    action: Action

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("Network rule ID is required.")

        if self.priority < 0:
            raise ValueError("Rule priority cannot be negative.")

        validate_port_range(self.port_from, self.port_to)


@dataclass(frozen=True)
class MicroRule:
    rule_id: str
    priority: int
    source_role: str
    destination_role: str
    protocol: Protocol
    port_from: int
    port_to: int
    action: Action

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("Microsegmentation rule ID is required.")

        if self.priority < 0:
            raise ValueError("Rule priority cannot be negative.")

        if not self.source_role or not self.destination_role:
            raise ValueError("Workload role selectors are required.")

        validate_port_range(self.port_from, self.port_to)


@dataclass(frozen=True)
class TrafficFlow:
    flow_id: str
    source_endpoint: str
    destination_endpoint: str
    protocol: Protocol
    destination_port: int

    def __post_init__(self) -> None:
        if not self.flow_id.strip():
            raise ValueError("Flow ID is required.")

        validate_port_range(self.destination_port, self.destination_port)


@dataclass(frozen=True)
class Decision:
    flow_id: str
    allowed: bool
    traffic_class: str
    network_result: str
    micro_result: str
    reason: str


def validate_port_range(start: int, end: int) -> None:
    if not 1 <= start <= end <= 65535:
        raise ValueError("Ports must be within 1-65535 and correctly ordered.")


class NetworkInventory:
    """Maintains VLANs, network ranges, and endpoint assignments."""

    def __init__(self) -> None:
        self.segments: dict[str, NetworkSegment] = {}
        self.endpoints: dict[str, Endpoint] = {}
        self.addresses: set[str] = set()

    def add_segment(self, segment: NetworkSegment) -> None:
        if segment.segment_id in self.segments:
            raise ValueError(f"Duplicate segment: {segment.segment_id}")

        if any(s.vlan_id == segment.vlan_id for s in self.segments.values()):
            raise ValueError(f"VLAN {segment.vlan_id} is already assigned.")

        for existing in self.segments.values():
            if segment.network.overlaps(existing.network):
                raise ValueError(
                    f"Overlapping network ranges: "
                    f"{segment.cidr} and {existing.cidr}"
                )

        self.segments[segment.segment_id] = segment

    def add_endpoint(self, endpoint: Endpoint) -> None:
        if endpoint.endpoint_id in self.endpoints:
            raise ValueError(f"Duplicate endpoint: {endpoint.endpoint_id}")

        segment = self.segments.get(endpoint.segment_id)

        if segment is None:
            raise ValueError(f"Unknown segment: {endpoint.segment_id}")

        address = ipaddress.ip_address(endpoint.address)

        if address not in segment.network:
            raise ValueError(
                f"{endpoint.address} does not belong to {segment.cidr}."
            )

        if endpoint.address in self.addresses:
            raise ValueError(f"Duplicate IP address: {endpoint.address}")

        self.endpoints[endpoint.endpoint_id] = endpoint
        self.addresses.add(endpoint.address)

    def get_endpoint(self, endpoint_id: str) -> Endpoint:
        try:
            return self.endpoints[endpoint_id]
        except KeyError as exc:
            raise ValueError(f"Unknown endpoint: {endpoint_id}") from exc

    def get_segment(self, segment_id: str) -> NetworkSegment:
        try:
            return self.segments[segment_id]
        except KeyError as exc:
            raise ValueError(f"Unknown segment: {segment_id}") from exc


class SegmentationEngine:
    """
    Evaluates two independent enforcement layers.

    1. Network rules control communication between VLAN trust zones.
    2. Micro rules control communication between individual workloads.

    Different VLANs must pass both layers. Workloads in the same VLAN
    bypass the inter-VLAN ACL but must still pass microsegmentation.
    """

    def __init__(
        self,
        inventory: NetworkInventory,
        network_rules: list[NetworkRule],
        micro_rules: list[MicroRule],
    ) -> None:
        self.inventory = inventory
        self.network_rules = sorted(
            network_rules,
            key=lambda rule: (rule.priority, rule.rule_id)
        )
        self.micro_rules = sorted(
            micro_rules,
            key=lambda rule: (rule.priority, rule.rule_id)
        )
        self.seen_flow_ids: set[str] = set()
        self.audit_log: list[Decision] = []

        self._validate_unique_rule_ids()

    def _validate_unique_rule_ids(self) -> None:
        for rules, category in (
            (self.network_rules, "network"),
            (self.micro_rules, "microsegmentation"),
        ):
            identifiers = [rule.rule_id for rule in rules]

            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"Duplicate {category} rule ID.")

    def _find_network_action(
        self,
        source_zone: Zone,
        destination_zone: Zone,
        flow: TrafficFlow,
    ) -> Action | None:
        for rule in self.network_rules:
            if (
                rule.source_zone == source_zone
                and rule.destination_zone == destination_zone
                and rule.protocol == flow.protocol
                and rule.port_from <= flow.destination_port <= rule.port_to
            ):
                return rule.action

        return None

    def _find_micro_action(
        self,
        source: Endpoint,
        destination: Endpoint,
        flow: TrafficFlow,
    ) -> Action | None:
        source_role = source.labels["role"]
        destination_role = destination.labels["role"]

        for rule in self.micro_rules:
            source_matches = rule.source_role in ("*", source_role)
            destination_matches = rule.destination_role in (
                "*",
                destination_role,
            )

            if (
                source_matches
                and destination_matches
                and rule.protocol == flow.protocol
                and rule.port_from <= flow.destination_port <= rule.port_to
            ):
                return rule.action

        return None

    def evaluate(self, flow: TrafficFlow) -> Decision:
        if flow.flow_id in self.seen_flow_ids:
            raise ValueError(f"Duplicate flow ID: {flow.flow_id}")

        source = self.inventory.get_endpoint(flow.source_endpoint)
        destination = self.inventory.get_endpoint(
            flow.destination_endpoint
        )

        source_segment = self.inventory.get_segment(source.segment_id)
        destination_segment = self.inventory.get_segment(
            destination.segment_id
        )

        self.seen_flow_ids.add(flow.flow_id)

        if (
            source_segment.zone == Zone.INTERNET
            or destination_segment.zone == Zone.INTERNET
        ):
            traffic_class = "NORTH_SOUTH"
        elif source.segment_id == destination.segment_id:
            traffic_class = "INTRA_SEGMENT"
        else:
            traffic_class = "EAST_WEST"

        same_segment = source.segment_id == destination.segment_id

        if same_segment:
            network_action = Action.ALLOW
            network_result = "NOT_REQUIRED"
        else:
            network_action = self._find_network_action(
                source_segment.zone,
                destination_segment.zone,
                flow,
            ) or Action.DENY
            network_result = network_action.value

        micro_action = self._find_micro_action(
            source,
            destination,
            flow,
        ) or Action.DENY

        micro_result = micro_action.value
        allowed = (
            network_action == Action.ALLOW
            and micro_action == Action.ALLOW
        )

        if network_action == Action.DENY:
            reason = "NETWORK_BOUNDARY_DENY"
        elif micro_action == Action.DENY:
            reason = "MICROSEGMENTATION_DEFAULT_DENY"
        else:
            reason = "BOTH_POLICY_LAYERS_ALLOW"

        decision = Decision(
            flow_id=flow.flow_id,
            allowed=allowed,
            traffic_class=traffic_class,
            network_result=network_result,
            micro_result=micro_result,
            reason=reason,
        )

        self.audit_log.append(decision)
        logger.info(
            "%s | %s | %s | %s",
            flow.flow_id,
            traffic_class,
            "ALLOW" if allowed else "DENY",
            reason,
        )

        return decision


def build_demo_engine() -> SegmentationEngine:
    inventory = NetworkInventory()

    segments = [
        NetworkSegment(
            "users", "User VLAN", 10, "10.10.0.0/24", Zone.USER
        ),
        NetworkSegment(
            "dmz", "DMZ VLAN", 20, "10.20.0.0/24", Zone.DMZ
        ),
        NetworkSegment(
            "apps", "Application VLAN", 30,
            "10.30.0.0/24", Zone.APPLICATION
        ),
        NetworkSegment(
            "data", "Database VLAN", 40, "10.40.0.0/24", Zone.DATA
        ),
        NetworkSegment(
            "management", "Management VLAN", 50,
            "10.50.0.0/24", Zone.MANAGEMENT
        ),
        NetworkSegment(
            "internet", "External Test VLAN", 900,
            "198.51.100.0/24", Zone.INTERNET
        ),
    ]

    for segment in segments:
        inventory.add_segment(segment)

    endpoints = [
        Endpoint(
            "workstation-01", "users", "10.10.0.10",
            {"role": "employee", "environment": "production"}
        ),
        Endpoint(
            "web-01", "dmz", "10.20.0.10",
            {"role": "web", "environment": "production"}
        ),
        Endpoint(
            "api-01", "apps", "10.30.0.10",
            {"role": "api", "environment": "production"}
        ),
        Endpoint(
            "api-02", "apps", "10.30.0.11",
            {"role": "api", "environment": "production"}
        ),
        Endpoint(
            "db-01", "data", "10.40.0.10",
            {"role": "database", "environment": "production"}
        ),
        Endpoint(
            "admin-01", "management", "10.50.0.10",
            {"role": "administrator", "environment": "management"}
        ),
        Endpoint(
            "external-client", "internet", "198.51.100.10",
            {"role": "internet-client", "environment": "external"}
        ),
    ]

    for endpoint in endpoints:
        inventory.add_endpoint(endpoint)

    network_rules = [
        NetworkRule(
            "NET-001", 10, Zone.INTERNET, Zone.DMZ,
            Protocol.TCP, 443, 443, Action.ALLOW
        ),
        NetworkRule(
            "NET-002", 20, Zone.USER, Zone.DMZ,
            Protocol.TCP, 443, 443, Action.ALLOW
        ),
        NetworkRule(
            "NET-003", 30, Zone.DMZ, Zone.APPLICATION,
            Protocol.TCP, 8443, 8443, Action.ALLOW
        ),
        NetworkRule(
            "NET-004", 40, Zone.APPLICATION, Zone.DATA,
            Protocol.TCP, 5432, 5432, Action.ALLOW
        ),
        NetworkRule(
            "NET-005", 50, Zone.MANAGEMENT, Zone.APPLICATION,
            Protocol.TCP, 22, 22, Action.ALLOW
        ),
    ]

    micro_rules = [
        MicroRule(
            "MICRO-001", 10, "internet-client", "web",
            Protocol.TCP, 443, 443, Action.ALLOW
        ),
        MicroRule(
            "MICRO-002", 20, "employee", "web",
            Protocol.TCP, 443, 443, Action.ALLOW
        ),
        MicroRule(
            "MICRO-003", 30, "web", "api",
            Protocol.TCP, 8443, 8443, Action.ALLOW
        ),
        MicroRule(
            "MICRO-004", 40, "api", "database",
            Protocol.TCP, 5432, 5432, Action.ALLOW
        ),
        MicroRule(
            "MICRO-005", 50, "administrator", "api",
            Protocol.TCP, 22, 22, Action.ALLOW
        ),
    ]

    return SegmentationEngine(
        inventory,
        network_rules,
        micro_rules,
    )


def run_tests(engine: SegmentationEngine) -> None:
    scenarios = [
        (
            "FLOW-001", "external-client", "web-01",
            Protocol.TCP, 443, True
        ),
        (
            "FLOW-002", "workstation-01", "web-01",
            Protocol.TCP, 443, True
        ),
        (
            "FLOW-003", "web-01", "api-01",
            Protocol.TCP, 8443, True
        ),
        (
            "FLOW-004", "api-01", "db-01",
            Protocol.TCP, 5432, True
        ),
        (
            "FLOW-005", "web-01", "db-01",
            Protocol.TCP, 5432, False
        ),
        (
            "FLOW-006", "api-01", "api-02",
            Protocol.TCP, 8080, False
        ),
        (
            "FLOW-007", "admin-01", "api-01",
            Protocol.TCP, 22, True
        ),
        (
            "FLOW-008", "api-01", "db-01",
            Protocol.TCP, 443, False
        ),
    ]

    for flow_id, source, destination, protocol, port, expected in scenarios:
        result = engine.evaluate(
            TrafficFlow(
                flow_id,
                source,
                destination,
                protocol,
                port,
            )
        )

        assert result.allowed == expected, (
            f"{flow_id}: expected {expected}, received {result.allowed}"
        )

    print(f"\nValidated {len(scenarios)} traffic scenarios.")

    allowed = sum(item.allowed for item in engine.audit_log)
    denied = len(engine.audit_log) - allowed

    print(f"Allowed flows: {allowed}")
    print(f"Denied flows:  {denied}")

    print("\nDetailed audit:")
    for item in engine.audit_log:
        print(
            f"{item.flow_id:10} "
            f"{item.traffic_class:15} "
            f"{'ALLOW' if item.allowed else 'DENY':5} "
            f"Network={item.network_result:12} "
            f"Micro={item.micro_result:5} "
            f"{item.reason}"
        )


def test_invalid_configuration() -> None:
    inventory = NetworkInventory()
    inventory.add_segment(
        NetworkSegment(
            "segment-a", "Segment A", 100,
            "172.16.10.0/24", Zone.USER
        )
    )

    invalid_configurations = [
        lambda: inventory.add_segment(
            NetworkSegment(
                "segment-b", "Overlapping Segment", 101,
                "172.16.10.128/25", Zone.DATA
            )
        ),
        lambda: NetworkSegment(
            "invalid-vlan", "Invalid VLAN", 4095,
            "172.16.20.0/24", Zone.USER
        ),
        lambda: validate_port_range(9000, 8000),
    ]

    for check in invalid_configurations:
        try:
            check()
        except ValueError:
            continue

        raise AssertionError("An invalid configuration was accepted.")

    print("Invalid configuration checks passed.")


def main() -> None:
    test_invalid_configuration()
    engine = build_demo_engine()
    run_tests(engine)


if __name__ == "__main__":
    main()
