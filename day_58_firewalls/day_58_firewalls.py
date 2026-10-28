#!/usr/bin/env python3

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Iterable, Optional


class Action(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class Direction(Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"


@dataclass(frozen=True)
class Packet:
    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Protocol
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    direction: Direction = Direction.INBOUND
    interface: str = "external"

    def __post_init__(self) -> None:
        if self.protocol in {Protocol.TCP, Protocol.UDP}:
            if self.src_port is None or self.dst_port is None:
                raise ValueError("TCP and UDP packets require source and destination ports")
        else:
            if self.src_port is not None or self.dst_port is not None:
                raise ValueError("ICMP packets cannot have TCP/UDP ports")

        for port in (self.src_port, self.dst_port):
            if port is not None and not 1 <= port <= 65535:
                raise ValueError(f"Invalid port: {port}")


@dataclass(frozen=True)
class FirewallRule:
    name: str
    action: Action
    protocol: Optional[Protocol] = None
    src_network: Optional[IPv4Network] = None
    dst_network: Optional[IPv4Network] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    direction: Optional[Direction] = None
    interface: Optional[str] = None

    def matches(self, packet: Packet) -> bool:
        if self.protocol is not None and packet.protocol != self.protocol:
            return False

        if self.src_network is not None and packet.src_ip not in self.src_network:
            return False

        if self.dst_network is not None and packet.dst_ip not in self.dst_network:
            return False

        if self.src_port is not None and packet.src_port != self.src_port:
            return False

        if self.dst_port is not None and packet.dst_port != self.dst_port:
            return False

        if self.direction is not None and packet.direction != self.direction:
            return False

        if self.interface is not None and packet.interface != self.interface:
            return False

        return True


@dataclass
class Decision:
    action: Action
    rule_name: str
    reason: str


class StatelessFirewall:
    """First-match packet filter with an explicit default-deny policy."""

    def __init__(self, rules: Iterable[FirewallRule], default_action: Action = Action.DENY):
        self.rules = list(rules)
        self.default_action = default_action

    def evaluate(self, packet: Packet) -> Decision:
        for rule in self.rules:
            if rule.matches(packet):
                return Decision(
                    rule.action,
                    rule.name,
                    f"Matched rule {rule.name}",
                )

        return Decision(
            self.default_action,
            "DEFAULT",
            "No configured rule matched the packet",
        )


class ConnectionState(Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"


@dataclass(frozen=True)
class FlowKey:
    src_ip: IPv4Address
    dst_ip: IPv4Address
    protocol: Protocol
    src_port: Optional[int]
    dst_port: Optional[int]

    def reverse(self) -> "FlowKey":
        return FlowKey(
            self.dst_ip,
            self.src_ip,
            self.protocol,
            self.dst_port,
            self.src_port,
        )


@dataclass
class StatefulFirewall:
    rules: list[FirewallRule]
    default_action: Action = Action.DENY
    established_flows: set[FlowKey] = field(default_factory=set)

    def evaluate(self, packet: Packet) -> Decision:
        flow = FlowKey(
            packet.src_ip,
            packet.dst_ip,
            packet.protocol,
            packet.src_port,
            packet.dst_port,
        )

        if flow in self.established_flows or flow.reverse() in self.established_flows:
            return Decision(
                Action.ALLOW,
                "STATEFUL-ESTABLISHED",
                "Packet belongs to an established flow",
            )

        stateless = StatelessFirewall(self.rules, self.default_action)
        decision = stateless.evaluate(packet)

        if decision.action == Action.ALLOW:
            self.established_flows.add(flow)

        return decision

    def expire_flow(self, flow: FlowKey) -> None:
        self.established_flows.discard(flow)


@dataclass(frozen=True)
class Zone:
    name: str
    networks: tuple[IPv4Network, ...]

    def contains(self, ip: IPv4Address) -> bool:
        return any(ip in network for network in self.networks)


@dataclass(frozen=True)
class ZonePolicy:
    source_zone: str
    destination_zone: str
    action: Action
    protocol: Optional[Protocol] = None
    dst_port: Optional[int] = None

    def matches(
        self,
        source_zone: str,
        destination_zone: str,
        packet: Packet,
    ) -> bool:
        return (
            self.source_zone == source_zone
            and self.destination_zone == destination_zone
            and (self.protocol is None or self.protocol == packet.protocol)
            and (self.dst_port is None or self.dst_port == packet.dst_port)
        )


class ZoneFirewall:
    """Zone-aware stateful policy engine with default deny between zones."""

    def __init__(
        self,
        zones: Iterable[Zone],
        policies: Iterable[ZonePolicy],
        default_action: Action = Action.DENY,
    ):
        self.zones = {zone.name: zone for zone in zones}
        self.policies = list(policies)
        self.default_action = default_action
        self.state = set()

    def identify_zone(self, ip: IPv4Address) -> str:
        matches = [name for name, zone in self.zones.items() if zone.contains(ip)]

        if len(matches) == 1:
            return matches[0]

        if not matches:
            return "UNTRUSTED"

        raise ValueError(f"Overlapping zone definitions for {ip}: {matches}")

    def evaluate(self, packet: Packet) -> Decision:
        source_zone = self.identify_zone(packet.src_ip)
        destination_zone = self.identify_zone(packet.dst_ip)

        flow = FlowKey(
            packet.src_ip,
            packet.dst_ip,
            packet.protocol,
            packet.src_port,
            packet.dst_port,
        )

        if flow in self.state or flow.reverse() in self.state:
            return Decision(
                Action.ALLOW,
                "ZONE-ESTABLISHED",
                f"Established flow from {source_zone} to {destination_zone}",
            )

        for policy in self.policies:
            if policy.matches(source_zone, destination_zone, packet):
                if policy.action == Action.ALLOW:
                    self.state.add(flow)

                return Decision(
                    policy.action,
                    f"{source_zone}->{destination_zone}",
                    f"Zone policy matched {source_zone}->{destination_zone}",
                )

        return Decision(
            self.default_action,
            "ZONE-DEFAULT-DENY",
            f"No policy permits {source_zone}->{destination_zone}",
        )


def ip(value: str) -> IPv4Address:
    return IPv4Address(value)


def network(value: str) -> IPv4Network:
    return IPv4Network(value, strict=False)


def build_rules() -> list[FirewallRule]:
    return [
        FirewallRule(
            name="ALLOW-HTTPS-INBOUND",
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            dst_network=network("10.0.10.0/24"),
            dst_port=443,
            direction=Direction.INBOUND,
            interface="external",
        ),
        FirewallRule(
            name="ALLOW-DNS-OUTBOUND",
            action=Action.ALLOW,
            protocol=Protocol.UDP,
            src_network=network("10.0.20.0/24"),
            dst_port=53,
            direction=Direction.OUTBOUND,
        ),
        FirewallRule(
            name="DENY-TELNET",
            action=Action.DENY,
            protocol=Protocol.TCP,
            dst_port=23,
        ),
    ]


def demo_stateless() -> None:
    firewall = StatelessFirewall(build_rules())

    packets = [
        Packet(
            ip("203.0.113.50"),
            ip("10.0.10.25"),
            Protocol.TCP,
            52000,
            443,
            Direction.INBOUND,
            "external",
        ),
        Packet(
            ip("10.0.20.15"),
            ip("8.8.8.8"),
            Protocol.UDP,
            51000,
            53,
            Direction.OUTBOUND,
            "internal",
        ),
        Packet(
            ip("203.0.113.50"),
            ip("10.0.10.25"),
            Protocol.TCP,
            52001,
            23,
            Direction.INBOUND,
            "external",
        ),
        Packet(
            ip("203.0.113.50"),
            ip("10.0.10.25"),
            Protocol.TCP,
            52002,
            22,
            Direction.INBOUND,
            "external",
        ),
    ]

    print("STATELESS FIREWALL")
    for packet in packets:
        decision = firewall.evaluate(packet)
        print(
            f"{packet.src_ip}:{packet.src_port} -> "
            f"{packet.dst_ip}:{packet.dst_port} "
            f"{packet.protocol.value}: "
            f"{decision.action.value} [{decision.rule_name}]"
        )


def demo_stateful() -> None:
    firewall = StatefulFirewall(
        rules=[
            FirewallRule(
                name="ALLOW-OUTBOUND-HTTPS",
                action=Action.ALLOW,
                protocol=Protocol.TCP,
                src_network=network("10.0.20.0/24"),
                dst_port=443,
                direction=Direction.OUTBOUND,
            )
        ]
    )

    outbound = Packet(
        ip("10.0.20.10"),
        ip("198.51.100.20"),
        Protocol.TCP,
        53000,
        443,
        Direction.OUTBOUND,
        "internal",
    )

    inbound_reply = Packet(
        ip("198.51.100.20"),
        ip("10.0.20.10"),
        Protocol.TCP,
        443,
        53000,
        Direction.INBOUND,
        "external",
    )

    unsolicited = Packet(
        ip("198.51.100.20"),
        ip("10.0.20.10"),
        Protocol.TCP,
        443,
        54000,
        Direction.INBOUND,
        "external",
    )

    print("\nSTATEFUL FIREWALL")
    for packet in (outbound, inbound_reply, unsolicited):
        decision = firewall.evaluate(packet)
        print(
            f"{packet.src_ip}:{packet.src_port} -> "
            f"{packet.dst_ip}:{packet.dst_port}: "
            f"{decision.action.value} [{decision.rule_name}]"
        )


def demo_zones() -> None:
    zones = [
        Zone("INTERNET", (network("0.0.0.0/1"), network("128.0.0.0/1"))),
        Zone("DMZ", (network("10.0.10.0/24"),)),
        Zone("INTERNAL", (network("10.0.20.0/24"),)),
    ]

    policies = [
        ZonePolicy("INTERNET", "DMZ", Action.ALLOW, Protocol.TCP, 443),
        ZonePolicy("INTERNAL", "INTERNET", Action.ALLOW, Protocol.TCP, 443),
        ZonePolicy("INTERNAL", "INTERNET", Action.ALLOW, Protocol.UDP, 53),
        ZonePolicy("INTERNET", "INTERNAL", Action.DENY),
    ]

    firewall = ZoneFirewall(zones, policies)

    packets = [
        Packet(
            ip("203.0.113.8"),
            ip("10.0.10.10"),
            Protocol.TCP,
            40000,
            443,
        ),
        Packet(
            ip("10.0.20.25"),
            ip("198.51.100.8"),
            Protocol.TCP,
            40001,
            443,
            Direction.OUTBOUND,
            "internal",
        ),
        Packet(
            ip("203.0.113.8"),
            ip("10.0.20.25"),
            Protocol.TCP,
            40002,
            22,
        ),
    ]

    print("\nZONE FIREWALL")
    for packet in packets:
        decision = firewall.evaluate(packet)
        print(
            f"{packet.src_ip}:{packet.src_port} -> "
            f"{packet.dst_ip}:{packet.dst_port}: "
            f"{decision.action.value} [{decision.rule_name}] "
            f"{decision.reason}"
        )


def validate_security_invariants() -> None:
    rules = build_rules()
    firewall = StatelessFirewall(rules)

    denied = Packet(
        ip("198.51.100.50"),
        ip("10.0.10.50"),
        Protocol.TCP,
        45000,
        22,
    )

    decision = firewall.evaluate(denied)
    assert decision.action == Action.DENY
    assert decision.rule_name == "DEFAULT"

    try:
        Packet(
            ip("10.0.0.1"),
            ip("10.0.0.2"),
            Protocol.TCP,
            0,
            443,
        )
        raise AssertionError("Invalid port was accepted")
    except ValueError:
        pass


def main() -> None:
    validate_security_invariants()
    demo_stateless()
    demo_stateful()
    demo_zones()

    print("\nSECURITY INVARIANTS")
    print("Validation passed: malformed ports are rejected and unmatched traffic is denied.")


if __name__ == "__main__":
    main()
