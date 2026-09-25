#!/usr/bin/env python3
"""
Network Discovery: Host Discovery, Service Discovery, Banners, Network Mapping

This standalone study script teaches network discovery from beginner through
advanced concepts using safe, explicit TCP connection techniques.

Use only against systems and networks that you own or are explicitly
authorized to test. The examples default to localhost and private-address
documentation examples. They do not implement stealth, evasion, exploitation,
credential attacks, or vulnerability exploitation.

The script covers:

1. Network-discovery terminology
2. IP addresses, ports, protocols, sockets, and services
3. Host discovery concepts
4. TCP connect-based host checks
5. Service discovery
6. TCP banner collection
7. DNS and reverse DNS
8. Network mapping and subnet calculations
9. Port classification
10. Timeouts and failure handling
11. Concurrency for authorized inventory work
12. Result modeling and JSON export
13. Nmap concepts and command interpretation
14. Security, performance, and operational considerations
15. A complete local-network inventory demonstration

The code uses only Python's standard library.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# 1. Fundamental concepts
# ---------------------------------------------------------------------------

COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-SERVER",
    68: "DHCP-CLIENT",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NETBIOS-NS",
    138: "NETBIOS-DGM",
    139: "NETBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-SUBMISSION",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    2375: "DOCKER",
    3306: "MYSQL",
    3389: "RDP",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "ELASTICSEARCH",
}


def utc_now() -> str:
    """Return an unambiguous UTC timestamp for inventory records."""
    return datetime.now(timezone.utc).isoformat()


def explain_network_discovery() -> None:
    """
    Print a compact conceptual lesson.

    Discovery answers different questions at different layers:
      Host discovery: Which IP addresses appear reachable?
      Port discovery: Which TCP/UDP ports are accessible?
      Service discovery: What application appears to be listening?
      Banner discovery: What information does the service voluntarily expose?
      Network mapping: How do discovered addresses relate to subnets and roles?
    """
    print("=" * 78)
    print("NETWORK DISCOVERY: FUNDAMENTALS")
    print("=" * 78)

    concepts = [
        ("Host", "A device or endpoint identified by an address."),
        ("IP address", "A logical network address such as 192.168.1.10."),
        ("Port", "A numbered endpoint used by transport protocols."),
        ("TCP", "Connection-oriented transport protocol."),
        ("UDP", "Connectionless transport protocol."),
        ("Service", "An application accepting network traffic."),
        ("Banner", "Text or protocol metadata exposed by a service."),
        ("Socket", "An operating-system communication endpoint."),
        ("Subnet", "A logical range of IP addresses."),
        ("Network map", "A structured representation of discovered assets."),
        ("Nmap", "A network exploration and security auditing tool."),
    ]

    for term, definition in concepts:
        print(f"{term:16} {definition}")

    print()
    print("Important distinction:")
    print("An open port does not by itself prove which application owns it.")
    print("A service probe provides stronger evidence about the application.")
    print()


# ---------------------------------------------------------------------------
# 2. Data structures
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Result of examining one TCP port."""

    port: int
    protocol: str = "tcp"
    state: str = "unknown"
    service_guess: str = "unknown"
    banner: str = ""
    latency_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class HostResult:
    """Complete inventory record for one discovered address."""

    ip: str
    reachable: bool
    reverse_dns: Optional[str] = None
    latency_ms: Optional[float] = None
    ports: list[PortResult] = field(default_factory=list)
    scanned_at: str = field(default_factory=utc_now)

    @property
    def open_ports(self) -> list[int]:
        return [result.port for result in self.ports if result.state == "open"]


@dataclass
class NetworkMap:
    """Container for host inventory and metadata."""

    target: str
    created_at: str = field(default_factory=utc_now)
    hosts: list[HostResult] = field(default_factory=list)

    def add(self, result: HostResult) -> None:
        self.hosts.append(result)

    def discovered_hosts(self) -> list[HostResult]:
        return [host for host in self.hosts if host.reachable]

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# 3. Address and subnet fundamentals
# ---------------------------------------------------------------------------

def inspect_network(cidr: str) -> None:
    """
    Explain a CIDR network without sending any packets.

    Example:
        192.168.1.0/29

    A /29 contains eight addresses:
        network address + six usable host addresses + broadcast address
        for a conventional IPv4 subnet.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        print(f"Invalid network: {exc}")
        return

    print("=" * 78)
    print("NETWORK STRUCTURE")
    print("=" * 78)
    print(f"Input              : {cidr}")
    print(f"Network address    : {network.network_address}")
    print(f"Broadcast address  : {network.broadcast_address}")
    print(f"Prefix length      : /{network.prefixlen}")
    print(f"Address count      : {network.num_addresses}")

    if isinstance(network, ipaddress.IPv4Network):
        hosts = list(network.hosts())
        print(f"Usable host count  : {len(hosts)}")
        if hosts:
            print(f"First host         : {hosts[0]}")
            print(f"Last host          : {hosts[-1]}")

    print()
    print("Host iteration is performed with ipaddress, not string manipulation.")
    print("That avoids errors around boundaries such as 192.168.1.9/29.")
    print()


def iter_target_addresses(
    target: str,
    max_hosts: int = 256,
) -> list[str]:
    """
    Convert an IP or CIDR target into explicit addresses.

    A safety limit prevents accidental expansion of enormous networks.
    """
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            addresses = [str(address) for address in network.hosts()]
        else:
            ipaddress.ip_address(target)
            addresses = [target]
    except ValueError as exc:
        raise ValueError(f"Invalid target '{target}': {exc}") from exc

    if len(addresses) > max_hosts:
        raise ValueError(
            f"Target contains {len(addresses)} host addresses, exceeding "
            f"the configured limit of {max_hosts}. "
            "Use a smaller authorized network."
        )

    return addresses


# ---------------------------------------------------------------------------
# 4. Reverse DNS
# ---------------------------------------------------------------------------

def reverse_dns(ip_address: str) -> Optional[str]:
    """
    Attempt a PTR/reverse-DNS lookup.

    DNS failure is normal and does not mean the host is unavailable.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# 5. Host discovery
# ---------------------------------------------------------------------------

def tcp_host_discovery(
    ip_address: str,
    ports: Iterable[int] = (80, 443, 22),
    timeout: float = 0.4,
) -> HostResult:
    """
    Determine whether an address appears reachable by attempting TCP
    connections to selected ports.

    This is deliberately a TCP-connect approach. It does not create raw
    packets and does not attempt stealth techniques.

    Important limitation:
      A host may be online even if all selected ports reject connections.
      Firewalls can also silently drop traffic.
    """
    start = time.perf_counter()
    tested_ports = list(ports)

    for port in tested_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            status = sock.connect_ex((ip_address, port))
            if status == 0:
                elapsed = (time.perf_counter() - start) * 1000
                return HostResult(
                    ip=ip_address,
                    reachable=True,
                    reverse_dns=reverse_dns(ip_address),
                    latency_ms=round(elapsed, 2),
                )
        except OSError:
            pass
        finally:
            sock.close()

    elapsed = (time.perf_counter() - start) * 1000
    return HostResult(
        ip=ip_address,
        reachable=False,
        reverse_dns=reverse_dns(ip_address),
        latency_ms=round(elapsed, 2),
    )


# ---------------------------------------------------------------------------
# 6. TCP service discovery
# ---------------------------------------------------------------------------

def classify_port(port: int) -> str:
    """Return a conventional service name for a port number."""
    return COMMON_SERVICES.get(port, "unknown")


def tcp_connect(
    ip_address: str,
    port: int,
    timeout: float = 0.7,
) -> PortResult:
    """
    Determine whether a TCP port accepts a connection.

    connect_ex() returns zero for a successful TCP connection.
    Non-zero results include connection refused, timeout, and routing errors.
    """
    start = time.perf_counter()
    result = PortResult(
        port=port,
        service_guess=classify_port(port),
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        status = sock.connect_ex((ip_address, port))
        elapsed = (time.perf_counter() - start) * 1000
        result.latency_ms = round(elapsed, 2)

        if status == 0:
            result.state = "open"
        elif status in (111, 61, 10061):
            result.state = "closed"
            result.error = f"connection refused (code {status})"
        else:
            result.state = "filtered_or_unreachable"
            result.error = f"connect error (code {status})"

    except socket.timeout:
        result.state = "filtered_or_timeout"
        result.error = "connection timed out"
    except OSError as exc:
        result.state = "error"
        result.error = str(exc)
    finally:
        sock.close()

    return result


def scan_tcp_ports(
    ip_address: str,
    ports: Iterable[int],
    timeout: float = 0.7,
) -> list[PortResult]:
    """Scan a specific, explicitly supplied list of TCP ports."""
    results = []

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port}")

        result = tcp_connect(ip_address, port, timeout)
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# 7. Banner collection
# ---------------------------------------------------------------------------

def clean_banner(data: bytes, maximum_length: int = 512) -> str:
    """
    Convert arbitrary response bytes into printable text.

    Banners are untrusted input. They can contain control characters or
    misleading text, so they are normalized before display/storage.
    """
    decoded = data[:maximum_length].decode("utf-8", errors="replace")
    return "".join(
        character
        for character in decoded
        if character.isprintable() or character in "\r\n\t"
    ).strip()


def grab_tcp_banner(
    ip_address: str,
    port: int,
    timeout: float = 1.0,
) -> Optional[str]:
    """
    Collect a passive TCP banner.

    Many services send identifying text immediately after connection.
    Others require a protocol-specific request.

    This function intentionally performs only a connection and a read. It
    does not send arbitrary probing payloads.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip_address, port))
        data = sock.recv(512)

        if not data:
            return None

        return clean_banner(data)

    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def demonstrate_banner_concept() -> None:
    """
    Explain why banners are evidence rather than absolute identification.
    """
    examples = [
        ("SSH", "SSH-2.0-ExampleSSH_9.0"),
        ("HTTP", "HTTP/1.1 200 OK"),
        ("SMTP", "220 mail.example ESMTP"),
        ("Unknown", "No banner returned"),
    ]

    print("=" * 78)
    print("BANNER CONCEPT")
    print("=" * 78)

    for service, banner in examples:
        print(f"{service:10} -> {banner}")

    print()
    print(
        "A banner can identify software, protocol, version, or configuration, "
        "but services may suppress banners or deliberately return generic text."
    )
    print()


# ---------------------------------------------------------------------------
# 8. Service inventory
# ---------------------------------------------------------------------------

def discover_services(
    ip_address: str,
    ports: Iterable[int],
    timeout: float = 0.7,
    collect_banners: bool = True,
) -> list[PortResult]:
    """
    Perform TCP service discovery followed by optional passive banner reads.
    """
    results = scan_tcp_ports(ip_address, ports, timeout)

    if collect_banners:
        for result in results:
            if result.state == "open":
                result.banner = grab_tcp_banner(
                    ip_address,
                    result.port,
                    timeout=max(timeout, 1.0),
                ) or ""

    return results


# ---------------------------------------------------------------------------
# 9. Complete host inventory
# ---------------------------------------------------------------------------

def inspect_host(
    ip_address: str,
    ports: Iterable[int],
    timeout: float = 0.7,
    collect_banners: bool = True,
) -> HostResult:
    """
    Build a complete host record.

    A direct service scan can be useful when host discovery ICMP/TCP probes
    are blocked, because an open application port itself provides evidence
    that an endpoint is reachable.
    """
    host = tcp_host_discovery(
        ip_address,
        ports=ports,
        timeout=timeout,
    )

    if not host.reachable:
        return host

    host.ports = discover_services(
        ip_address,
        ports,
        timeout=timeout,
        collect_banners=collect_banners,
    )

    return host


# ---------------------------------------------------------------------------
# 10. Concurrent inventory
# ---------------------------------------------------------------------------

def parallel_inventory(
    addresses: list[str],
    ports: list[int],
    timeout: float = 0.7,
    workers: int = 8,
    collect_banners: bool = True,
) -> list[HostResult]:
    """
    Scan multiple authorized addresses concurrently.

    Concurrency reduces waiting time because network I/O is mostly blocked on
    socket operations. It also increases traffic, so worker counts should be
    kept appropriate for the authorized environment.
    """
    if workers < 1:
        raise ValueError("workers must be at least 1")

    workers = min(workers, len(addresses) or 1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                inspect_host,
                address,
                ports,
                timeout,
                collect_banners,
            )
            for address in addresses
        ]

        return [future.result() for future in futures]


# ---------------------------------------------------------------------------
# 11. Formatting and export
# ---------------------------------------------------------------------------

def print_host_result(host: HostResult) -> None:
    """Render one host result for terminal use."""
    status = "UP" if host.reachable else "NOT CONFIRMED"
    hostname = host.reverse_dns or "-"

    print(f"{host.ip:15} {status:14} DNS={hostname}")

    if host.latency_ms is not None:
        print(f"  latency: {host.latency_ms:.2f} ms")

    if not host.ports:
        return

    for port in host.ports:
        banner = port.banner.replace("\n", "\\n") if port.banner else "-"
        print(
            f"  TCP/{port.port:<5} "
            f"{port.state:<22} "
            f"{port.service_guess:<18} "
            f"banner={banner}"
        )


def print_network_map(network_map: NetworkMap) -> None:
    """Render the complete network inventory."""
    print("=" * 78)
    print("NETWORK MAP")
    print("=" * 78)
    print(f"Target: {network_map.target}")
    print(f"Created: {network_map.created_at}")
    print(f"Records: {len(network_map.hosts)}")
    print()

    for host in network_map.hosts:
        print_host_result(host)
        print()


def save_json(network_map: NetworkMap, path: str) -> None:
    """Persist inventory in a portable JSON format."""
    with open(path, "w", encoding="utf-8") as file:
        json.dump(network_map.to_dict(), file, indent=2)


# ---------------------------------------------------------------------------
# 12. Educational Nmap command interpretation
# ---------------------------------------------------------------------------

def explain_nmap() -> None:
    """
    Print examples of common Nmap concepts.

    These are displayed rather than executed. This keeps the study script
    independent of whether Nmap is installed and avoids silently scanning
    a target the operator did not explicitly choose.
    """
    print("=" * 78)
    print("NMAP CONCEPTS")
    print("=" * 78)

    examples = [
        (
            "nmap 192.168.1.10",
            "Basic TCP-oriented host/port discovery behavior for one target."
        ),
        (
            "nmap -sn 192.168.1.0/24",
            "Host discovery without a normal port scan."
        ),
        (
            "nmap -p 22,80,443 192.168.1.10",
            "Examine selected TCP ports."
        ),
        (
            "nmap -sV 192.168.1.10",
            "Attempt service/version identification."
        ),
        (
            "nmap -O 192.168.1.10",
            "Attempt operating-system identification when supported."
        ),
        (
            "nmap -A 192.168.1.10",
            "Combines several detection features and can be substantially more intrusive."
        ),
    ]

    for command, explanation in examples:
        print(f"{command}")
        print(f"  {explanation}")

    print()
    print("Nmap state vocabulary commonly includes:")
    print("  open      -> an application accepted the probe")
    print("  closed    -> the host responded but no application accepted it")
    print("  filtered  -> filtering prevented a reliable determination")
    print("  open|filtered -> insufficient evidence to distinguish the states")
    print()
    print(
        "The exact probe behavior and state interpretation depend on the "
        "scan type, protocol, target, firewall, and Nmap version."
    )
    print()


# ---------------------------------------------------------------------------
# 13. Validation and edge cases
# ---------------------------------------------------------------------------

def validate_ports(ports: Iterable[int]) -> list[int]:
    """Validate and deduplicate ports while preserving order."""
    validated = []
    seen = set()

    for port in ports:
        if not isinstance(port, int):
            raise TypeError(f"Port must be an integer: {port!r}")

        if not 1 <= port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535: {port}")

        if port not in seen:
            validated.append(port)
            seen.add(port)

    if not validated:
        raise ValueError("At least one port is required.")

    return validated


def parse_port_list(value: str) -> list[int]:
    """
    Parse a command-line list such as:
        22,80,443,8080
    """
    try:
        ports = [int(part.strip()) for part in value.split(",") if part.strip()]
    except ValueError as exc:
        raise ValueError("Ports must be comma-separated integers.") from exc

    return validate_ports(ports)


def local_addresses() -> list[str]:
    """
    Obtain local address candidates without performing discovery.

    127.0.0.1 is always included as a safe demonstration target.
    """
    addresses = {"127.0.0.1"}

    try:
        hostname = socket.gethostname()
        for address in socket.gethostbyname_ex(hostname)[2]:
            if address:
                addresses.add(address)
    except OSError:
        pass

    return sorted(addresses)


# ---------------------------------------------------------------------------
# 14. Demonstration modes
# ---------------------------------------------------------------------------

def run_demo() -> None:
    """
    Run a safe localhost demonstration.

    The demonstration examines a small set of conventional ports and does
    not enumerate an external network.
    """
    explain_network_discovery()
    inspect_network("127.0.0.0/30")
    demonstrate_banner_concept()
    explain_nmap()

    print("=" * 78)
    print("LOCALHOST DEMONSTRATION")
    print("=" * 78)

    ports = [22, 80, 443, 8000, 8080]
    print(f"Target: 127.0.0.1")
    print(f"Ports : {ports}")
    print()

    result = inspect_host(
        "127.0.0.1",
        ports=ports,
        timeout=0.5,
        collect_banners=True,
    )

    print_host_result(result)

    print()
    print("Interpretation:")
    print("- A closed port does not mean the host is offline.")
    print("- A timeout can indicate filtering, routing problems, or an unavailable host.")
    print("- An open port identifies an accessible endpoint, not necessarily its software.")
    print("- Banner data is useful evidence but should be treated as untrusted input.")
    print()


def run_inventory(
    target: str,
    ports: list[int],
    timeout: float,
    workers: int,
    output: Optional[str],
    collect_banners: bool,
) -> None:
    """
    Perform an explicitly supplied inventory operation.

    The default address-count limit is intentionally conservative.
    """
    addresses = iter_target_addresses(target, max_hosts=256)

    print("=" * 78)
    print("AUTHORIZED NETWORK INVENTORY")
    print("=" * 78)
    print(f"Target addresses: {len(addresses)}")
    print(f"Ports           : {ports}")
    print(f"Timeout         : {timeout}s")
    print(f"Workers         : {workers}")
    print(f"Banners         : {collect_banners}")
    print()

    started = time.perf_counter()

    results = parallel_inventory(
        addresses=addresses,
        ports=ports,
        timeout=timeout,
        workers=workers,
        collect_banners=collect_banners,
    )

    elapsed = time.perf_counter() - started

    network_map = NetworkMap(target=target)

    for result in sorted(
        results,
        key=lambda host: ipaddress.ip_address(host.ip),
    ):
        network_map.add(result)

    print_network_map(network_map)

    discovered = network_map.discovered_hosts()
    print("=" * 78)
    print("INVENTORY STATISTICS")
    print("=" * 78)
    print(f"Addresses examined : {len(addresses)}")
    print(f"Hosts confirmed    : {len(discovered)}")
    print(
        f"Open TCP ports     : "
        f"{sum(len(host.open_ports) for host in discovered)}"
    )
    print(f"Elapsed time       : {elapsed:.2f}s")

    if output:
        save_json(network_map, output)
        print(f"JSON output        : {output}")


# ---------------------------------------------------------------------------
# 15. Command-line interface
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Educational network discovery using Python standard-library "
            "TCP connections."
        )
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run only the safe localhost educational demonstration.",
    )

    parser.add_argument(
        "--target",
        help="Authorized IPv4 address or CIDR network, e.g. 192.168.1.10.",
    )

    parser.add_argument(
        "--ports",
        default="22,80,443,8080",
        help="Comma-separated TCP ports.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.7,
        help="Socket timeout in seconds.",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Maximum concurrent host workers.",
    )

    parser.add_argument(
        "--output",
        help="Optional JSON output file.",
    )

    parser.add_argument(
        "--no-banners",
        action="store_true",
        help="Do not perform passive banner reads.",
    )

    parser.add_argument(
        "--show-local-addresses",
        action="store_true",
        help="Show local address candidates and exit.",
    )

    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        if args.show_local_addresses:
            print("Local address candidates:")
            for address in local_addresses():
                print(f"  {address}")
            return 0

        if args.demo or not args.target:
            run_demo()
            return 0

        if args.timeout <= 0:
            raise ValueError("timeout must be greater than zero")

        if args.workers < 1:
            raise ValueError("workers must be at least 1")

        ports = parse_port_list(args.ports)

        run_inventory(
            target=args.target,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
            output=args.output,
            collect_banners=not args.no_banners,
        )

        return 0

    except KeyboardInterrupt:
        print("\nOperation interrupted by user.", file=sys.stderr)
        return 130
    except (ValueError, TypeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"Permission error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Operating-system error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
