#!/usr/bin/env python3
"""
Linux Networking: interfaces, routes, sockets, DNS configuration, and firewall configuration.

This script is designed for Linux and combines:
- Read-only inspection of network interfaces and addresses
- Routing-table inspection
- Socket inspection
- DNS configuration inspection
- Firewall inspection
- In-memory routing and firewall models for deterministic learning
- Connectivity and DNS tests
- Validation and failure handling

The diagnostic commands are intentionally read-only. Firewall modification is not
performed automatically because changing host firewall rules can disconnect a system.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

class CommandError(RuntimeError):
    """Raised when a Linux diagnostic command cannot be executed successfully."""


def run_command(command: list[str], timeout: float = 5.0) -> str:
    """
    Execute a read-only Linux command and return stdout.

    Using subprocess with a list rather than shell=True avoids shell parsing and
    reduces command-injection risk when arguments originate outside the program.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise CommandError(f"Command not installed: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"Command timed out: {' '.join(command)}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "unknown command failure"
        raise CommandError(
            f"{' '.join(command)} failed with exit code "
            f"{result.returncode}: {detail}"
        )

    return result.stdout


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


# ---------------------------------------------------------------------------
# Network interfaces
# ---------------------------------------------------------------------------

@dataclass
class Interface:
    name: str
    flags: list[str] = field(default_factory=list)
    mtu: Optional[int] = None
    addresses: list[str] = field(default_factory=list)

    @property
    def is_up(self) -> bool:
        return "UP" in self.flags

    def describe(self) -> str:
        state = "UP" if self.is_up else "DOWN"
        addresses = ", ".join(self.addresses) or "no addresses"
        mtu = str(self.mtu) if self.mtu is not None else "unknown"
        return f"{self.name}: {state}, MTU={mtu}, addresses={addresses}"


def inspect_interfaces() -> list[Interface]:
    """
    Prefer `ip -j address`, because JSON output is easier to parse reliably
    than human-oriented command output.
    """
    if not command_exists("ip"):
        raise CommandError("The ip command is required for interface inspection.")

    raw = run_command(["ip", "-j", "address"])
    try:
        records = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CommandError("ip returned invalid JSON.") from exc

    interfaces: list[Interface] = []

    for record in records:
        name = record.get("ifname", "unknown")
        flags = [str(flag).upper() for flag in record.get("flags", [])]
        mtu = record.get("mtu")

        addresses = []
        for addr in record.get("addr_info", []):
            family = addr.get("family")
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if local and prefix is not None:
                addresses.append(f"{local}/{prefix} ({family})")

        interfaces.append(
            Interface(
                name=name,
                flags=flags,
                mtu=mtu,
                addresses=addresses,
            )
        )

    return interfaces


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    destination: str
    gateway: Optional[str]
    device: Optional[str]
    metric: Optional[int]
    protocol: Optional[str]

    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
        return ipaddress.ip_network(self.destination, strict=False)

    def matches(self, address: str) -> bool:
        return ipaddress.ip_address(address) in self.network()


def parse_routes() -> list[Route]:
    """
    Parse `ip -j route` and `ip -j -6 route`.

    Linux routing uses longest-prefix matching. When several routes match an
    address, the most specific prefix normally wins, followed by route metrics
    and other kernel routing rules.
    """
    if not command_exists("ip"):
        raise CommandError("The ip command is required for route inspection.")

    routes: list[Route] = []

    for command, family in ((["ip", "-j", "route"], "ipv4"),
                            (["ip", "-j", "-6", "route"], "ipv6")):
        try:
            records = json.loads(run_command(command))
        except CommandError:
            continue
        except json.JSONDecodeError:
            continue

        for record in records:
            destination = record.get("dst", "::/0" if family == "ipv6" else "default")
            if destination == "default":
                destination = "::/0" if family == "ipv6" else "0.0.0.0/0"

            gateway = record.get("gateway")
            device = record.get("dev")
            metric = record.get("metric")

            routes.append(
                Route(
                    destination=destination,
                    gateway=gateway,
                    device=device,
                    metric=metric,
                    protocol=record.get("protocol"),
                )
            )

    return routes


def select_route(routes: Iterable[Route], destination: str) -> Optional[Route]:
    """
    Demonstrate longest-prefix route selection.

    This is a learning model, not a replacement for the Linux kernel's full
    policy-routing implementation, which can involve rules, tables, marks,
    namespaces, VRFs, and other mechanisms.
    """
    address = ipaddress.ip_address(destination)
    candidates = [route for route in routes if address in route.network()]

    if not candidates:
        return None

    return max(
        candidates,
        key=lambda route: (
            route.network().prefixlen,
            -(route.metric if route.metric is not None else 0),
        ),
    )


# ---------------------------------------------------------------------------
# Socket inspection
# ---------------------------------------------------------------------------

@dataclass
class SocketRecord:
    protocol: str
    state: str
    local: str
    peer: str


def inspect_sockets() -> list[SocketRecord]:
    """
    Use `ss` to inspect TCP and UDP sockets.

    Socket state is different from a route: routes decide where packets should
    be sent, while sockets represent transport/application endpoints.
    """
    if not command_exists("ss"):
        raise CommandError("The ss command is required for socket inspection.")

    records: list[SocketRecord] = []

    for protocol, command in (
        ("tcp", ["ss", "-H", "-tun"]),
        ("udp", ["ss", "-H", "-u"]),
    ):
        try:
            output = run_command(command)
        except CommandError:
            continue

        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue

            state = fields[0] if protocol == "tcp" else "UNCONN"
            local = fields[4] if protocol == "tcp" else fields[3]
            peer = fields[5] if protocol == "tcp" and len(fields) > 5 else "*"

            records.append(
                SocketRecord(
                    protocol=protocol,
                    state=state,
                    local=local,
                    peer=peer,
                )
            )

    return records


# ---------------------------------------------------------------------------
# DNS configuration
# ---------------------------------------------------------------------------

@dataclass
class DnsConfiguration:
    nameservers: list[str]
    search_domains: list[str]
    source: str


def inspect_resolv_conf() -> DnsConfiguration:
    """
    Read /etc/resolv.conf directly.

    On many modern distributions this file is a symlink or generated file
    managed by systemd-resolved, NetworkManager, or another network manager.
    Therefore its contents describe the active resolver configuration but do
    not necessarily identify the ultimate configuration authority.
    """
    path = Path("/etc/resolv.conf")
    nameservers: list[str] = []
    search_domains: list[str] = []

    if not path.exists():
        return DnsConfiguration([], [], str(path))

    try:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            fields = line.split()
            if not fields:
                continue

            if fields[0] == "nameserver" and len(fields) >= 2:
                try:
                    ipaddress.ip_address(fields[1])
                    nameservers.append(fields[1])
                except ValueError:
                    pass

            elif fields[0] in {"search", "domain"}:
                search_domains.extend(fields[1:])

    except PermissionError as exc:
        raise CommandError(f"Cannot read {path}: {exc}") from exc

    return DnsConfiguration(
        nameservers=nameservers,
        search_domains=search_domains,
        source=str(path),
    )


def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname through the system resolver.

    Python delegates this operation to the host's resolver configuration rather
    than manually implementing DNS packets.
    """
    if not hostname or len(hostname) > 253:
        raise ValueError("Hostname length is invalid.")

    if any(character.isspace() for character in hostname):
        raise ValueError("Hostname must not contain whitespace.")

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for {hostname}: {exc}") from exc

    addresses = sorted({result[4][0] for result in results})
    return addresses


# ---------------------------------------------------------------------------
# Firewall inspection
# ---------------------------------------------------------------------------

def inspect_firewall() -> str:
    """
    Inspect whichever common firewall interface is available.

    No rule is added, deleted, or flushed. Firewall changes are intentionally
    outside this diagnostic script because a bad rule can remove remote access.
    """
    if command_exists("nft"):
        try:
            return "nftables:\n" + run_command(["nft", "list", "ruleset"])
        except CommandError as exc:
            return f"nftables is installed but inspection failed: {exc}"

    if command_exists("ufw"):
        try:
            return "UFW:\n" + run_command(["ufw", "status", "verbose"])
        except CommandError as exc:
            return f"UFW is installed but inspection failed: {exc}"

    if command_exists("iptables"):
        try:
            return "iptables:\n" + run_command(["iptables", "-S"])
        except CommandError as exc:
            return f"iptables is installed but inspection failed: {exc}"

    return "No supported firewall command was found."


# ---------------------------------------------------------------------------
# Deterministic firewall model
# ---------------------------------------------------------------------------

class Action(Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"


@dataclass(frozen=True)
class FirewallPacket:
    protocol: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]


@dataclass(frozen=True)
class FirewallRule:
    action: Action
    protocol: Optional[str] = None
    source_network: Optional[str] = None
    destination_network: Optional[str] = None
    destination_port: Optional[int] = None
    comment: str = ""

    def matches(self, packet: FirewallPacket) -> bool:
        if self.protocol and self.protocol.lower() != packet.protocol.lower():
            return False

        if self.source_network:
            if ipaddress.ip_address(packet.source_ip) not in ipaddress.ip_network(
                self.source_network, strict=False
            ):
                return False

        if self.destination_network:
            if ipaddress.ip_address(packet.destination_ip) not in ipaddress.ip_network(
                self.destination_network, strict=False
            ):
                return False

        if self.destination_port is not None:
            if packet.destination_port != self.destination_port:
                return False

        return True


class Firewall:
    """
    Small first-match firewall model.

    Real nftables can express considerably richer policies, including chains,
    sets, connection tracking, NAT, hooks, priorities, and stateful matching.
    """

    def __init__(self, rules: list[FirewallRule], default_action: Action = Action.DROP):
        self.rules = rules
        self.default_action = default_action

    def evaluate(self, packet: FirewallPacket) -> tuple[Action, str]:
        for rule in self.rules:
            if rule.matches(packet):
                return rule.action, rule.comment or "matched rule"

        return self.default_action, "default policy"


# ---------------------------------------------------------------------------
# Connectivity test
# ---------------------------------------------------------------------------

def tcp_connect(host: str, port: int, timeout: float = 3.0) -> tuple[bool, str]:
    """
    Attempt a TCP connection without sending application data.

    A successful TCP connection proves that a TCP path and endpoint accepted the
    connection at that moment. It does not prove that an HTTP service, TLS
    handshake, authentication flow, or application request will succeed.
    """
    if not 1 <= port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")

    started = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.monotonic() - started) * 1000
            return True, f"connected in {elapsed_ms:.1f} ms"
    except OSError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        return False, f"failed after {elapsed_ms:.1f} ms: {exc}"


# ---------------------------------------------------------------------------
# Demonstrations
# ---------------------------------------------------------------------------

def demonstrate_route_selection() -> None:
    print("\n=== Routing decision model ===")

    routes = [
        Route("0.0.0.0/0", "192.0.2.1", "eth0", 100, "static"),
        Route("10.0.0.0/8", None, "eth1", 100, "kernel"),
        Route("10.20.0.0/16", "10.20.0.1", "eth2", 50, "static"),
    ]

    for destination in ("8.8.8.8", "10.50.1.10", "10.20.5.25"):
        route = select_route(routes, destination)
        if route:
            print(
                f"{destination} -> {route.destination}, "
                f"dev={route.device}, gateway={route.gateway}, metric={route.metric}"
            )
        else:
            print(f"{destination} -> no matching route")


def demonstrate_firewall() -> None:
    print("\n=== Stateful-policy concepts through a deterministic firewall model ===")

    firewall = Firewall(
        rules=[
            FirewallRule(
                Action.ACCEPT,
                protocol="tcp",
                destination_port=22,
                source_network="10.20.0.0/16",
                comment="Allow SSH administration from management network",
            ),
            FirewallRule(
                Action.ACCEPT,
                protocol="tcp",
                destination_port=443,
                comment="Allow HTTPS",
            ),
        ],
        default_action=Action.DROP,
    )

    packets = [
        FirewallPacket("tcp", "10.20.10.4", "192.0.2.20", 53000, 22),
        FirewallPacket("tcp", "198.51.100.20", "192.0.2.20", 53001, 22),
        FirewallPacket("tcp", "198.51.100.20", "192.0.2.20", 53002, 443),
        FirewallPacket("udp", "198.51.100.20", "192.0.2.20", 53003, 53),
    ]

    for packet in packets:
        action, reason = firewall.evaluate(packet)
        print(
            f"{packet.protocol.upper()} "
            f"{packet.source_ip}:{packet.source_port} -> "
            f"{packet.destination_ip}:{packet.destination_port}: "
            f"{action.value} ({reason})"
        )


def print_interfaces() -> None:
    print("\n=== Network interfaces ===")
    for interface in inspect_interfaces():
        print(interface.describe())


def print_routes() -> None:
    print("\n=== Kernel routing table ===")
    routes = parse_routes()

    if not routes:
        print("No routes could be read.")
        return

    for route in routes:
        print(
            f"{route.destination:20} "
            f"via={route.gateway or '-':15} "
            f"dev={route.device or '-':10} "
            f"metric={route.metric if route.metric is not None else '-'} "
            f"protocol={route.protocol or '-'}"
        )


def print_sockets() -> None:
    print("\n=== Sockets ===")
    records = inspect_sockets()

    if not records:
        print("No socket records were returned.")
        return

    for record in records[:40]:
        print(
            f"{record.protocol.upper():4} "
            f"{record.state:12} "
            f"{record.local:30} -> {record.peer}"
        )

    if len(records) > 40:
        print(f"... {len(records) - 40} additional sockets omitted.")


def print_dns() -> None:
    print("\n=== DNS configuration ===")
    config = inspect_resolv_conf()
    print(f"Source: {config.source}")
    print(f"Nameservers: {', '.join(config.nameservers) or 'none found'}")
    print(f"Search domains: {', '.join(config.search_domains) or 'none found'}")


def print_firewall() -> None:
    print("\n=== Firewall configuration ===")
    output = inspect_firewall()

    # Avoid dumping an unbounded firewall configuration in normal terminal use.
    lines = output.splitlines()
    for line in lines[:80]:
        print(line)

    if len(lines) > 80:
        print(f"... {len(lines) - 80} additional lines omitted.")


def run_dns_test(hostname: str) -> None:
    print(f"\n=== DNS resolution: {hostname} ===")
    try:
        addresses = resolve_hostname(hostname)
    except (RuntimeError, ValueError) as exc:
        print(exc)
        return

    for address in addresses:
        print(address)


def run_tcp_test(host: str, port: int) -> None:
    print(f"\n=== TCP connectivity: {host}:{port} ===")
    success, message = tcp_connect(host, port)
    print(("SUCCESS: " if success else "FAILURE: ") + message)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Linux networking diagnostics and deterministic networking models."
    )

    parser.add_argument(
        "--interfaces",
        action="store_true",
        help="Inspect Linux interfaces and addresses.",
    )
    parser.add_argument(
        "--routes",
        action="store_true",
        help="Inspect IPv4 and IPv6 routes.",
    )
    parser.add_argument(
        "--sockets",
        action="store_true",
        help="Inspect TCP and UDP sockets.",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Inspect /etc/resolv.conf.",
    )
    parser.add_argument(
        "--firewall",
        action="store_true",
        help="Inspect available firewall configuration.",
    )
    parser.add_argument(
        "--resolve",
        metavar="HOSTNAME",
        help="Resolve a hostname using the system resolver.",
    )
    parser.add_argument(
        "--tcp",
        nargs=2,
        metavar=("HOST", "PORT"),
        help="Test a TCP connection.",
    )
    parser.add_argument(
        "--models",
        action="store_true",
        help="Run deterministic route and firewall models.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all diagnostics and demonstrations.",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not any(vars(args).values()):
        args.models = True

    if args.all:
        args.interfaces = True
        args.routes = True
        args.sockets = True
        args.dns = True
        args.firewall = True
        args.models = True

    operations = [
        (args.interfaces, print_interfaces),
        (args.routes, print_routes),
        (args.sockets, print_sockets),
        (args.dns, print_dns),
        (args.firewall, print_firewall),
        (args.models, demonstrate_route_selection),
        (args.models, demonstrate_firewall),
    ]

    for enabled, operation in operations:
        if not enabled:
            continue
        try:
            operation()
        except (CommandError, OSError, ValueError) as exc:
            print(f"Diagnostic failure: {exc}", file=sys.stderr)

    if args.resolve:
        run_dns_test(args.resolve)

    if args.tcp:
        host, port_text = args.tcp
        try:
            port = int(port_text)
            run_tcp_test(host, port)
        except ValueError:
            print(f"Invalid TCP port: {port_text}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
