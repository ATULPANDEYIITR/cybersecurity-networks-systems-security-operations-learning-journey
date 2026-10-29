from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterable
import json
import logging
import re


class Direction(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class LogLevel(str, Enum):
    NONE = "none"
    DENIED = "denied"
    ALL = "all"


@dataclass(frozen=True)
class Connection:
    direction: Direction
    protocol: Protocol
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    application: str
    user: str | None = None


@dataclass(frozen=True)
class FirewallRule:
    rule_id: str
    direction: Direction
    action: Action
    protocol: Protocol = Protocol.ANY
    source_network: str = "0.0.0.0/0"
    destination_network: str = "0.0.0.0/0"
    destination_port: int | None = None
    application: str = "*"
    priority: int = 100
    enabled: bool = True
    log_level: LogLevel = LogLevel.DENIED
    description: str = ""

    def __post_init__(self) -> None:
        if not self.rule_id.strip():
            raise ValueError("rule_id cannot be empty")
        if self.priority < 1:
            raise ValueError("priority must be positive")
        if self.destination_port is not None and not 1 <= self.destination_port <= 65535:
            raise ValueError("destination_port must be between 1 and 65535")
        ip_network(self.source_network, strict=False)
        ip_network(self.destination_network, strict=False)


@dataclass
class Decision:
    action: Action
    rule_id: str
    reason: str
    logged: bool
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class HostFirewall:
    """
    Deterministic first-match firewall engine.

    Rules are evaluated by ascending priority. A real host firewall should
    normally also implement state tracking, kernel-level enforcement, and
    OS-specific application identity controls. This model focuses on policy
    evaluation and auditable logging.
    """

    def __init__(self, default_action: Action = Action.DENY) -> None:
        self.default_action = default_action
        self._rules: list[FirewallRule] = []
        self._logs: list[dict] = []
        self.logger = logging.getLogger("host-firewall")

    def add_rule(self, rule: FirewallRule) -> None:
        if any(existing.rule_id == rule.rule_id for existing in self._rules):
            raise ValueError(f"duplicate rule id: {rule.rule_id}")
        self._rules.append(rule)
        self._rules.sort(key=lambda item: item.priority)

    def remove_rule(self, rule_id: str) -> None:
        original = len(self._rules)
        self._rules = [rule for rule in self._rules if rule.rule_id != rule_id]
        if len(self._rules) == original:
            raise KeyError(f"unknown rule: {rule_id}")

    @staticmethod
    def _ip_matches(value: str, network: str) -> bool:
        try:
            return ip_address(value) in ip_network(network, strict=False)
        except ValueError:
            return False

    @staticmethod
    def _port_matches(connection_port: int | None, rule_port: int | None) -> bool:
        return rule_port is None or connection_port == rule_port

    @staticmethod
    def _application_matches(application: str, pattern: str) -> bool:
        return pattern == "*" or fnmatch(application.lower(), pattern.lower())

    def _matches(self, connection: Connection, rule: FirewallRule) -> bool:
        return (
            rule.enabled
            and connection.direction == rule.direction
            and (rule.protocol == Protocol.ANY or connection.protocol == rule.protocol)
            and self._ip_matches(connection.source_ip, rule.source_network)
            and self._ip_matches(connection.destination_ip, rule.destination_network)
            and self._port_matches(
                connection.destination_port, rule.destination_port
            )
            and self._application_matches(connection.application, rule.application)
        )

    def evaluate(self, connection: Connection) -> Decision:
        for rule in self._rules:
            if self._matches(connection, rule):
                logged = (
                    rule.log_level == LogLevel.ALL
                    or (rule.log_level == LogLevel.DENIED and rule.action == Action.DENY)
                )
                decision = Decision(
                    action=rule.action,
                    rule_id=rule.rule_id,
                    reason=rule.description or "matched firewall rule",
                    logged=logged,
                )
                if logged:
                    self._record(connection, decision)
                return decision

        decision = Decision(
            action=self.default_action,
            rule_id="DEFAULT",
            reason="no explicit rule matched",
            logged=self.default_action == Action.DENY,
        )
        if decision.logged:
            self._record(connection, decision)
        return decision

    def _record(self, connection: Connection, decision: Decision) -> None:
        self._logs.append(
            {
                "timestamp": decision.timestamp,
                "direction": connection.direction.value,
                "protocol": connection.protocol.value,
                "source_ip": connection.source_ip,
                "destination_ip": connection.destination_ip,
                "source_port": connection.source_port,
                "destination_port": connection.destination_port,
                "application": connection.application,
                "user": connection.user,
                "action": decision.action.value,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
            }
        )

    def logs(self) -> list[dict]:
        return list(self._logs)

    def export_logs(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self._logs, indent=2),
            encoding="utf-8",
        )

    def rules(self) -> tuple[FirewallRule, ...]:
        return tuple(self._rules)


def validate_connection(connection: Connection) -> None:
    ip_address(connection.source_ip)
    ip_address(connection.destination_ip)

    for port in (connection.source_port, connection.destination_port):
        if port is not None and not 1 <= port <= 65535:
            raise ValueError(f"invalid port: {port}")

    if not connection.application.strip():
        raise ValueError("application cannot be empty")


def print_decision(connection: Connection, decision: Decision) -> None:
    print(
        f"{connection.direction.value:8} "
        f"{connection.application:16} "
        f"{connection.destination_ip}:{connection.destination_port or '-':5} "
        f"{decision.action.value:5} "
        f"rule={decision.rule_id:12} "
        f"logged={decision.logged}"
    )


def run_demo() -> None:
    logging.basicConfig(level=logging.INFO)

    firewall = HostFirewall(default_action=Action.DENY)

    firewall.add_rule(
        FirewallRule(
            rule_id="ALLOW-SSH-ADMIN",
            direction=Direction.INBOUND,
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            source_network="10.20.0.0/24",
            destination_port=22,
            application="sshd",
            priority=10,
            log_level=LogLevel.ALL,
            description="Administrative SSH is permitted from the management network.",
        )
    )

    firewall.add_rule(
        FirewallRule(
            rule_id="DENY-INBOUND-WEB",
            direction=Direction.INBOUND,
            action=Action.DENY,
            protocol=Protocol.TCP,
            destination_port=8080,
            application="*",
            priority=20,
            log_level=LogLevel.DENIED,
            description="Unapproved inbound application service.",
        )
    )

    firewall.add_rule(
        FirewallRule(
            rule_id="ALLOW-DNS",
            direction=Direction.OUTBOUND,
            action=Action.ALLOW,
            protocol=Protocol.UDP,
            destination_network="10.20.0.53/32",
            destination_port=53,
            application="resolver",
            priority=30,
            log_level=LogLevel.ALL,
            description="DNS queries to the approved resolver.",
        )
    )

    firewall.add_rule(
        FirewallRule(
            rule_id="ALLOW-HTTPS",
            direction=Direction.OUTBOUND,
            action=Action.ALLOW,
            protocol=Protocol.TCP,
            destination_port=443,
            application="browser*",
            priority=40,
            log_level=LogLevel.ALL,
            description="HTTPS traffic generated by approved browser processes.",
        )
    )

    firewall.add_rule(
        FirewallRule(
            rule_id="DENY-UNTRUSTED-OUTBOUND",
            direction=Direction.OUTBOUND,
            action=Action.DENY,
            protocol=Protocol.ANY,
            application="*",
            priority=90,
            log_level=LogLevel.DENIED,
            description="Default outbound restriction for applications without an explicit rule.",
        )
    )

    connections = [
        Connection(
            Direction.INBOUND,
            Protocol.TCP,
            "10.20.0.15",
            "10.20.0.10",
            51000,
            22,
            "sshd",
            "administrator",
        ),
        Connection(
            Direction.INBOUND,
            Protocol.TCP,
            "203.0.113.50",
            "10.20.0.10",
            51001,
            8080,
            "unknown",
        ),
        Connection(
            Direction.OUTBOUND,
            Protocol.UDP,
            "10.20.0.10",
            "10.20.0.53",
            53000,
            53,
            "resolver",
        ),
        Connection(
            Direction.OUTBOUND,
            Protocol.TCP,
            "10.20.0.10",
            "198.51.100.20",
            52000,
            443,
            "browser",
        ),
        Connection(
            Direction.OUTBOUND,
            Protocol.TCP,
            "10.20.0.10",
            "198.51.100.40",
            52001,
            22,
            "unknown",
        ),
    ]

    print("Firewall evaluation")
    print("-" * 95)

    for connection in connections:
        try:
            validate_connection(connection)
            decision = firewall.evaluate(connection)
            print_decision(connection, decision)
        except ValueError as exc:
            print(f"INVALID connection: {exc}")

    # Edge case: malformed source address is rejected before policy evaluation.
    try:
        invalid = Connection(
            Direction.OUTBOUND,
            Protocol.TCP,
            "not-an-ip",
            "198.51.100.1",
            50000,
            443,
            "browser",
        )
        validate_connection(invalid)
    except ValueError as exc:
        print(f"Validation failure handled: {exc}")

    print("\nAudit records:")
    for record in firewall.logs():
        print(json.dumps(record, sort_keys=True))

    output = Path("firewall_audit.json")
    firewall.export_logs(output)
    print(f"\nAudit log written to {output.resolve()}")

    # Lightweight executable assertions.
    assert firewall.evaluate(connections[0]).action == Action.ALLOW
    assert firewall.evaluate(connections[1]).action == Action.DENY
    assert firewall.evaluate(connections[2]).action == Action.ALLOW
    assert firewall.evaluate(connections[3]).action == Action.ALLOW
    assert firewall.evaluate(connections[4]).action == Action.DENY


if __name__ == "__main__":
    run_demo()
