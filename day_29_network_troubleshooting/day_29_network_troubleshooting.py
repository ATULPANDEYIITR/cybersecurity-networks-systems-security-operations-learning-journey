"""
Network Troubleshooting: DNS, Routing, Packet Loss, Latency, MTU, and Connectivity Diagnostics

A self-contained study and diagnostic program that progresses from networking
fundamentals to practical troubleshooting workflows.

Safety note:
This program performs diagnostic operations only. It does not perform packet
flooding, unauthorized scanning, exploitation, credential collection, or other
intrusive actions.

Tested conceptually with Python 3.x and the standard library.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import platform
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Optional


# ---------------------------------------------------------------------------
# 1. FUNDAMENTALS
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_fundamentals() -> None:
    section("1. NETWORK TROUBLESHOOTING FUNDAMENTALS")

    concepts = {
        "DNS": "Translates names such as example.com into IP addresses.",
        "Routing": "Determines where IP packets should be forwarded.",
        "Latency": "Measures how long traffic takes to travel between endpoints.",
        "Packet loss": "Occurs when packets fail to reach their destination.",
        "MTU": "Maximum Transmission Unit: largest IP packet payload a link can carry without fragmentation at that layer.",
        "Connectivity": "The ability to establish and maintain communication between endpoints.",
        "TCP": "Connection-oriented transport protocol with sequencing, acknowledgements, and retransmission.",
        "UDP": "Connectionless transport protocol without TCP's delivery guarantees.",
        "ICMP": "Network-control protocol commonly used by ping and diagnostic tools.",
    }

    for name, definition in concepts.items():
        print(f"{name:15} {definition}")

    print(
        """
A useful troubleshooting model is to test from the bottom upward:

1. Local interface and configuration
2. Link and local gateway
3. IP addressing and subnet
4. Routing
5. DNS
6. Transport connectivity
7. Application protocol
8. Application behavior

A failed application does not automatically mean the application is broken.
For example:

    browser -> HTTPS -> TCP -> IP routing -> gateway -> DNS -> server

A failure at DNS can look like an application failure. A routing failure can
look like a DNS problem when the resolver itself cannot be reached.

A disciplined diagnostic process separates hypotheses and tests one layer at
a time.
"""
    )


# ---------------------------------------------------------------------------
# 2. ADDRESSING AND SUBNETTING
# ---------------------------------------------------------------------------

def demonstrate_ip_addressing() -> None:
    section("2. IP ADDRESSING AND SUBNETTING")

    examples = [
        "192.168.1.10/24",
        "10.20.30.40/16",
        "172.16.5.25/20",
        "2001:db8::10/64",
    ]

    for value in examples:
        interface = ipaddress.ip_interface(value)
        network = interface.network
        print(f"\nAddress: {interface}")
        print(f"  Version:       IPv{interface.version}")
        print(f"  Network:       {network}")
        print(f"  Netmask:       {network.netmask}")
        print(f"  Broadcast:     {getattr(network, 'broadcast_address', 'N/A')}")
        print(f"  Is private:    {interface.ip.is_private}")
        print(f"  Is loopback:   {interface.ip.is_loopback}")

    network = ipaddress.ip_network("192.168.50.0/26")
    print("\nSubnet example:")
    print(f"  Network: {network}")
    print(f"  Addresses: {network.num_addresses}")
    print(f"  Hosts: {list(network.hosts())[:3]} ... {list(network.hosts())[-3:]}")


def validate_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 3. DNS
# ---------------------------------------------------------------------------

def dns_lookup(hostname: str, family: int = socket.AF_UNSPEC) -> list[tuple]:
    """
    Resolve a hostname using the operating system's configured resolver.

    getaddrinfo() is useful because it can return IPv4 and IPv6 records and
    follows the host-resolution behavior configured for the local system.
    """
    return socket.getaddrinfo(
        hostname,
        None,
        family=family,
        type=socket.SOCK_STREAM,
    )


def demonstrate_dns(hostname: str) -> None:
    section("3. DNS DIAGNOSTICS")

    print(f"Resolving: {hostname}")

    try:
        results = dns_lookup(hostname)
    except socket.gaierror as exc:
        print(f"DNS/host-resolution failure: {exc}")
        print(
            """
Possible causes:
- The hostname does not exist.
- The configured DNS server is unavailable.
- The resolver cannot reach its DNS server.
- A local DNS configuration problem exists.
- Search-domain or split-DNS behavior differs from expectations.
- The requested DNS record family is unavailable.
"""
        )
        return

    addresses = sorted({item[4][0] for item in results})
    for address in addresses:
        print(f"  {address}")

    print(
        """
DNS troubleshooting should distinguish:
- NXDOMAIN: the DNS system says the requested name does not exist.
- SERVFAIL: the resolver failed to obtain a valid answer.
- Timeout: the query did not receive a response in the expected period.
- Successful resolution followed by connection failure: DNS is probably not
  the immediate cause of the application failure.

DNS is not the same thing as internet connectivity. An IP address can be
reachable even when a hostname cannot be resolved.
"""
    )


# ---------------------------------------------------------------------------
# 4. TCP CONNECTIVITY
# ---------------------------------------------------------------------------

@dataclass
class TcpResult:
    host: str
    port: int
    success: bool
    elapsed_ms: Optional[float]
    error: Optional[str]


def tcp_connect_test(host: str, port: int, timeout: float = 3.0) -> TcpResult:
    started = time.perf_counter()

    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.perf_counter() - started) * 1000
            return TcpResult(host, port, True, elapsed, None)
    except OSError as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return TcpResult(host, port, False, elapsed, str(exc))


def demonstrate_tcp(host: str) -> None:
    section("4. TCP CONNECTIVITY DIAGNOSTICS")

    common_ports = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
    }

    print(f"Testing TCP reachability to {host}")

    for port, service in common_ports.items():
        result = tcp_connect_test(host, port)
        status = "OPEN/REACHABLE" if result.success else "FAILED"
        print(
            f"  {service:6} TCP/{port:<5} {status:15} "
            f"{result.elapsed_ms:.2f} ms"
            if result.elapsed_ms is not None
            else f"  {service:6} TCP/{port:<5} {status}"
        )
        if result.error:
            print(f"    Error: {result.error}")

    print(
        """
A failed TCP connection can result from:
- No route to the destination.
- A firewall dropping or rejecting traffic.
- No service listening on the port.
- An intermediate network failure.
- A timeout caused by packet loss or filtering.

A successful TCP connection proves that a TCP handshake can complete. It does
not prove that the application protocol itself works correctly.
"""
    )


# ---------------------------------------------------------------------------
# 5. PING-LIKE LATENCY TEST
# ---------------------------------------------------------------------------

@dataclass
class PingSample:
    sequence: int
    elapsed_ms: Optional[float]
    success: bool
    error: Optional[str]


def ping_with_system_command(
    host: str,
    count: int = 4,
    timeout_seconds: int = 2,
) -> list[PingSample]:
    """
    Use the platform's ping command.

    Windows uses:
        ping -n COUNT -w TIMEOUT_MS HOST

    Unix-like systems generally use:
        ping -c COUNT -W TIMEOUT_SECONDS HOST

    Command syntax varies among operating systems, so output parsing is
    intentionally conservative.
    """
    system = platform.system().lower()

    if shutil.which("ping") is None:
        raise RuntimeError("The system ping executable is not available.")

    if system == "windows":
        command = [
            "ping",
            "-n",
            str(count),
            "-w",
            str(timeout_seconds * 1000),
            host,
        ]
    else:
        command = [
            "ping",
            "-c",
            str(count),
            "-W",
            str(timeout_seconds),
            host,
        ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=max(10, count * timeout_seconds + 5),
        check=False,
    )

    output = completed.stdout + "\n" + completed.stderr

    # Match common output such as:
    # Reply from 1.1.1.1: bytes=32 time=12ms TTL=...
    # 64 bytes from ...: time=12.3 ms
    times = [
        float(match)
        for match in re.findall(
            r"(?:time[=<]\s*)(\d+(?:\.\d+)?)\s*ms",
            output,
            flags=re.IGNORECASE,
        )
    ]

    samples = [
        PingSample(index + 1, value, True, None)
        for index, value in enumerate(times)
    ]

    while len(samples) < count:
        samples.append(
            PingSample(
                len(samples) + 1,
                None,
                False,
                "No parseable reply",
            )
        )

    return samples[:count]


def summarize_latency(samples: Iterable[PingSample]) -> dict[str, Any]:
    values = [
        sample.elapsed_ms
        for sample in samples
        if sample.success and sample.elapsed_ms is not None
    ]

    total = len(list(samples)) if not isinstance(samples, list) else len(samples)
    successful = len(values)

    if not values:
        return {
            "sent": total,
            "received": 0,
            "loss_percent": 100.0 if total else 0.0,
            "min_ms": None,
            "avg_ms": None,
            "max_ms": None,
            "jitter_ms": None,
        }

    jitter = 0.0
    if len(values) > 1:
        differences = [
            abs(values[index] - values[index - 1])
            for index in range(1, len(values))
        ]
        jitter = statistics.mean(differences)

    return {
        "sent": total,
        "received": successful,
        "loss_percent": ((total - successful) / total) * 100 if total else 0,
        "min_ms": min(values),
        "avg_ms": statistics.mean(values),
        "max_ms": max(values),
        "jitter_ms": jitter,
    }


def demonstrate_latency(host: str) -> None:
    section("5. LATENCY AND PACKET LOSS")

    try:
        samples = ping_with_system_command(host, count=4)
    except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
        print(f"Ping test could not be executed: {exc}")
        return

    for sample in samples:
        if sample.success:
            print(
                f"  Sequence {sample.sequence}: "
                f"{sample.elapsed_ms:.2f} ms"
            )
        else:
            print(
                f"  Sequence {sample.sequence}: "
                f"timeout/failure ({sample.error})"
            )

    summary = summarize_latency(samples)

    print("\nStatistics:")
    for key, value in summary.items():
        if isinstance(value, float):
            print(f"  {key:15}: {value:.2f}")
        else:
            print(f"  {key:15}: {value}")

    print(
        """
Latency is not simply "good" or "bad". Interpretation depends on the path,
application, geographic distance, protocol, and expected service.

Packet loss is usually more important than a small increase in latency for
reliable transports because loss can trigger retransmissions and congestion
control.

Jitter describes variation in packet delay. It matters particularly for
real-time traffic such as voice and interactive media.
"""
    )


# ---------------------------------------------------------------------------
# 6. ROUTING
# ---------------------------------------------------------------------------

def run_route_command(host: str) -> None:
    section("6. ROUTING DIAGNOSTICS")

    system = platform.system().lower()

    if system == "windows":
        candidates = [
            ["tracert", "-d", host],
            ["pathping", "-n", "-q", "5", host],
        ]
    else:
        candidates = [
            ["traceroute", "-n", host],
            ["tracepath", host],
        ]

    selected = None
    for command in candidates:
        if shutil.which(command[0]):
            selected = command
            break

    if selected is None:
        print("No traceroute/tracepath diagnostic utility was found.")
        return

    print("Running:", " ".join(selected))
    try:
        completed = subprocess.run(
            selected,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"Route diagnostic failed: {exc}")
        return

    output = completed.stdout or completed.stderr
    print(output[:12000])

    print(
        """
Traceroute reveals successive hops observed along a path. Asterisks or
timeouts do not automatically prove packet loss at that hop.

Routers may:
- Deprioritize diagnostic packets.
- Rate-limit ICMP responses.
- Filter TTL-expired messages.
- Forward traffic normally while suppressing diagnostic replies.

A persistent problem should be correlated across multiple hops and with the
actual destination, rather than interpreted from one intermediate timeout.
"""
    )


# ---------------------------------------------------------------------------
# 7. MTU AND PATH MTU
# ---------------------------------------------------------------------------

def calculate_packet_sizes(mtu: int, ip_version: int = 4) -> dict[str, int]:
    """
    Calculate rough protocol overhead for common Ethernet/IP/TCP scenarios.

    Ethernet's frame size and the IP MTU are related but not identical
    concepts. The calculation here focuses on IP payload capacity.
    """
    ip_header = 20 if ip_version == 4 else 40
    tcp_header = 20

    return {
        "mtu": mtu,
        "max_ip_payload": mtu - ip_header,
        "typical_tcp_mss": mtu - ip_header - tcp_header,
    }


def mtu_test(host: str, payload_size: int) -> bool:
    """
    Run a platform-specific ping with a specified payload size.

    This is a diagnostic probe, not a traffic generator. The operating system
    may impose additional limits and different ping implementations expose
    different fragmentation controls.
    """
    system = platform.system().lower()

    if shutil.which("ping") is None:
        raise RuntimeError("The ping executable is unavailable.")

    if system == "windows":
        command = [
            "ping",
            "-n",
            "1",
            "-f",
            "-l",
            str(payload_size),
            host,
        ]
    else:
        # -M do requests don't fragment on common Linux implementations.
        command = [
            "ping",
            "-c",
            "1",
            "-M",
            "do",
            "-s",
            str(payload_size),
            host,
        ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    output = (completed.stdout + "\n" + completed.stderr).lower()

    failure_markers = [
        "packet needs to be fragmented",
        "message too long",
        "local error",
        "frag needed",
        "100% packet loss",
        "timed out",
        "timeout",
    ]

    return completed.returncode == 0 and not any(
        marker in output for marker in failure_markers
    )


def demonstrate_mtu(host: str) -> None:
    section("7. MTU DIAGNOSTICS")

    print(
        """
MTU is the maximum IP packet size a particular interface/path can carry
without requiring fragmentation at that point.

Common Ethernet MTU:
    1500 bytes

IPv4 ICMP echo payload is smaller than MTU because the IP and ICMP headers
consume space.

Path MTU problems can produce unusual symptoms:
- Small packets work but larger packets fail.
- TCP connections establish but large transfers stall.
- Some websites work while others do not.
- VPN traffic fails while direct traffic works.
- Packet fragmentation or ICMP filtering interferes with PMTUD.
"""
    )

    test_payloads = [1200, 1300, 1400, 1472]

    for payload in test_payloads:
        try:
            success = mtu_test(host, payload)
        except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
            print(f"MTU test unavailable: {exc}")
            return

        print(
            f"  Payload {payload:4} bytes: "
            f"{'successful' if success else 'failed'}"
        )


# ---------------------------------------------------------------------------
# 8. LOCAL SOCKET INFORMATION
# ---------------------------------------------------------------------------

def show_local_network_information() -> None:
    section("8. LOCAL HOST NETWORK INFORMATION")

    print(f"Hostname: {socket.gethostname()}")
    print(f"Platform: {platform.platform()}")

    try:
        host_addresses = socket.gethostbyname_ex(socket.gethostname())
        print(f"Resolved local hostname: {host_addresses}")
    except socket.gaierror as exc:
        print(f"Local hostname resolution failed: {exc}")

    print("\nCommon local diagnostic commands:")

    commands = [
        ("Windows IP configuration", ["ipconfig", "/all"]),
        ("Linux IP configuration", ["ip", "addr"]),
        ("Linux routes", ["ip", "route"]),
        ("Windows routes", ["route", "print"]),
        ("Windows DNS cache", ["ipconfig", "/displaydns"]),
        ("Linux resolver status", ["resolvectl", "status"]),
    ]

    available = []
    for description, command in commands:
        if shutil.which(command[0]):
            available.append((description, command))

    for description, command in available:
        print(f"  {description:30}: {' '.join(command)}")

    print(
        """
Inspecting local configuration can reveal:
- Missing or incorrect IP address.
- Wrong subnet mask/prefix.
- Missing default gateway.
- Unexpected DNS servers.
- VPN adapters taking precedence.
- Multiple active interfaces.
- Duplicate or stale configuration.
"""
    )


# ---------------------------------------------------------------------------
# 9. ERROR CLASSIFICATION
# ---------------------------------------------------------------------------

@dataclass
class DiagnosticObservation:
    symptom: str
    likely_layer: str
    evidence: str
    next_test: str


def classify_symptom(symptom: str) -> DiagnosticObservation:
    normalized = symptom.lower()

    if "dns" in normalized or "name" in normalized:
        return DiagnosticObservation(
            symptom,
            "DNS/application configuration",
            "Hostname resolution is directly implicated.",
            "Resolve the name and compare with direct IP connectivity.",
        )

    if "slow" in normalized or "latency" in normalized:
        return DiagnosticObservation(
            symptom,
            "Path/transport/application",
            "Delay is the primary reported symptom.",
            "Measure latency, jitter, packet loss, and route behavior.",
        )

    if "packet loss" in normalized or "loss" in normalized:
        return DiagnosticObservation(
            symptom,
            "Link/path/transport",
            "Packets may not be arriving consistently.",
            "Compare loss to gateway, intermediate path, and destination.",
        )

    if "mtu" in normalized or "large packet" in normalized:
        return DiagnosticObservation(
            symptom,
            "Link/path",
            "Packet-size sensitivity points toward MTU/PMTUD.",
            "Test progressively smaller probes with fragmentation disabled.",
        )

    if "route" in normalized or "unreachable" in normalized:
        return DiagnosticObservation(
            symptom,
            "IP routing",
            "The destination may not have a usable path.",
            "Inspect routing table and traceroute behavior.",
        )

    return DiagnosticObservation(
        symptom,
        "Unknown",
        "The symptom is insufficient to identify a layer.",
        "Test local configuration, gateway, DNS, routing, TCP, then application.",
    )


# ---------------------------------------------------------------------------
# 10. ADVANCED: ROUTING TABLE MODEL
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    destination: ipaddress.IPv4Network
    gateway: Optional[ipaddress.IPv4Address]
    interface: str
    metric: int


def longest_prefix_match(
    destination: str,
    routes: list[Route],
) -> Optional[Route]:
    """
    Demonstrate the central routing-selection principle.

    Routers generally prefer the most specific matching prefix. Administrative
    distance, policy, metric, and routing protocol behavior can then affect
    which route is selected among otherwise comparable candidates.
    """
    address = ipaddress.ip_address(destination)

    matching = [
        route
        for route in routes
        if address.version == route.destination.version
        and address in route.destination
    ]

    if not matching:
        return None

    return max(
        matching,
        key=lambda route: (route.destination.prefixlen, -route.metric),
    )


def demonstrate_routing_algorithm() -> None:
    section("9. ROUTING DECISION MODEL")

    routes = [
        Route(
            ipaddress.ip_network("0.0.0.0/0"),
            ipaddress.ip_address("192.168.1.1"),
            "eth0",
            100,
        ),
        Route(
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_address("192.168.1.254"),
            "eth0",
            50,
        ),
        Route(
            ipaddress.ip_network("10.20.0.0/16"),
            ipaddress.ip_address("10.20.0.1"),
            "vpn0",
            20,
        ),
        Route(
            ipaddress.ip_network("10.20.30.0/24"),
            None,
            "vpn0",
            10,
        ),
    ]

    for destination in [
        "8.8.8.8",
        "10.5.6.7",
        "10.20.40.10",
        "10.20.30.15",
    ]:
        selected = longest_prefix_match(destination, routes)

        if selected:
            print(
                f"{destination:15} -> "
                f"{selected.destination} via "
                f"{selected.gateway or 'direct'} "
                f"on {selected.interface}"
            )
        else:
            print(f"{destination:15} -> no route")


# ---------------------------------------------------------------------------
# 11. ADVANCED: DIAGNOSTIC DECISION TREE
# ---------------------------------------------------------------------------

def diagnostic_decision_tree(hostname: str) -> None:
    section("10. SYSTEMATIC DIAGNOSTIC WORKFLOW")

    print(f"Target: {hostname}")

    print("\nStep 1: Is the target syntactically valid?")
    print("  -> Hostname accepted.")

    print("\nStep 2: Can the local system resolve the name?")
    try:
        results = dns_lookup(hostname)
        addresses = sorted({result[4][0] for result in results})
        print(f"  -> Yes: {', '.join(addresses)}")
    except socket.gaierror as exc:
        print(f"  -> No: {exc}")
        print("  Diagnostic branch: investigate DNS before testing application ports.")
        return

    addresses = sorted(
        {
            result[4][0]
            for result in dns_lookup(hostname)
            if result[4]
        }
    )

    print("\nStep 3: Can the host establish TCP connectivity?")
    for address in addresses[:4]:
        result = tcp_connect_test(address, 443)
        print(
            f"  {address}: "
            f"{'reachable' if result.success else 'failed'}"
        )

    print(
        """
Interpretation:

DNS succeeds + TCP succeeds
    -> The basic network path to that service exists.

DNS succeeds + TCP fails
    -> Investigate routing, firewall policy, service availability, or port state.

DNS fails + direct IP works
    -> Strong evidence that name resolution is the immediate problem.

Ping fails + TCP succeeds
    -> ICMP may be filtered or deprioritized. Do not equate ping failure with
       total connectivity failure.

Traceroute has a timeout
    -> Does not necessarily mean the corresponding router is dropping the
       application's packets.

Small packets succeed + large packets fail
    -> Investigate MTU, fragmentation, PMTUD, VPN encapsulation, and filtering.
"""
    )


# ---------------------------------------------------------------------------
# 12. ADVANCED: CONFIGURATION VALIDATION
# ---------------------------------------------------------------------------

def validate_network_configuration(
    ip: str,
    prefix: int,
    gateway: str,
    dns_servers: list[str],
) -> list[str]:
    errors: list[str] = []

    try:
        interface = ipaddress.ip_interface(f"{ip}/{prefix}")
    except ValueError as exc:
        errors.append(f"Invalid interface address: {exc}")
        return errors

    try:
        gateway_address = ipaddress.ip_address(gateway)
    except ValueError as exc:
        errors.append(f"Invalid gateway address: {exc}")
        gateway_address = None

    if gateway_address is not None:
        if gateway_address.version != interface.version:
            errors.append("Gateway and interface use different IP versions.")
        elif gateway_address not in interface.network:
            errors.append(
                "Gateway is outside the configured local subnet. "
                "This may be valid in unusual routed designs but is commonly "
                "a configuration error."
            )

    for server in dns_servers:
        if not validate_address(server):
            errors.append(f"Invalid DNS server address: {server}")

    return errors


def demonstrate_configuration_validation() -> None:
    section("11. NETWORK CONFIGURATION VALIDATION")

    tests = [
        (
            "192.168.1.10",
            24,
            "192.168.1.1",
            ["1.1.1.1", "8.8.8.8"],
        ),
        (
            "192.168.1.10",
            24,
            "192.168.2.1",
            ["1.1.1.1", "invalid"],
        ),
    ]

    for values in tests:
        errors = validate_network_configuration(*values)
        print(f"\nConfiguration: {values}")
        if errors:
            for error in errors:
                print(f"  ERROR: {error}")
        else:
            print("  Configuration passes basic validation.")


# ---------------------------------------------------------------------------
# 13. PERFORMANCE CONCEPTS
# ---------------------------------------------------------------------------

def demonstrate_latency_statistics() -> None:
    section("12. PERFORMANCE STATISTICS")

    samples = [10.2, 10.5, 11.1, 10.8, 40.0, 10.4, 10.6]

    mean_value = statistics.mean(samples)
    median_value = statistics.median(samples)
    standard_deviation = statistics.stdev(samples)

    print(f"Samples: {samples}")
    print(f"Mean: {mean_value:.2f} ms")
    print(f"Median: {median_value:.2f} ms")
    print(f"Standard deviation: {standard_deviation:.2f} ms")

    print(
        """
The mean can be strongly affected by outliers. The median can better describe
a typical observation when occasional spikes exist.

For production monitoring, useful measurements often include:
- p50: median
- p95: value below which 95% of observations fall
- p99: value below which 99% fall
- Packet-loss percentage
- Jitter
- Connection failure rate

A single ping result is not a reliable characterization of a network path.
"""
    )


# ---------------------------------------------------------------------------
# 14. SECURITY CONSIDERATIONS
# ---------------------------------------------------------------------------

def security_guidance() -> None:
    section("13. SECURITY CONSIDERATIONS")

    print(
        """
Network diagnostics should be performed only on systems and networks you are
authorized to test.

Important security issues include:

DNS:
- DNS spoofing or manipulation can redirect clients.
- DNSSEC can provide authenticity for signed DNS data where supported.
- Encrypted DNS mechanisms can protect DNS traffic from some observers but
  do not solve every routing or application-security problem.

Routing:
- Incorrect routes can expose or black-hole traffic.
- BGP and routing protocols require appropriate trust and filtering controls.
- A valid route does not imply that the destination is trustworthy.

Diagnostics:
- Diagnostic commands can reveal infrastructure information.
- Logs can contain IP addresses, hostnames, and timestamps.
- Avoid publishing sensitive topology information unnecessarily.

Transport:
- A reachable TCP port is not proof of application security.
- TLS certificate validation and hostname verification remain important.

Operational practice:
- Prefer low-volume diagnostic probes.
- Record timestamps and scope.
- Avoid packet flooding.
- Avoid unauthorized port scanning.
- Protect diagnostic logs when they contain internal network information.
"""
    )


# ---------------------------------------------------------------------------
# 15. TESTABLE MINI-SIMULATION
# ---------------------------------------------------------------------------

def simulate_packet_path(
    hops: list[tuple[str, float, float]],
    packet_count: int = 10,
) -> dict[str, Any]:
    """
    Educational simulation of a path.

    Each tuple contains:
        (hop name, base latency in milliseconds, loss probability)

    This is not a network scanner or traffic generator. It models diagnostic
    observations so students can reason about loss and latency.
    """
    import random

    random_generator = random.Random(42)
    results = []

    for name, base_latency, loss_probability in hops:
        observations = []

        for _ in range(packet_count):
            if random_generator.random() < loss_probability:
                observations.append(None)
            else:
                variation = random_generator.uniform(-1.0, 1.0)
                observations.append(max(0.0, base_latency + variation))

        received = [value for value in observations if value is not None]

        results.append(
            {
                "hop": name,
                "sent": packet_count,
                "received": len(received),
                "loss_percent": (
                    (packet_count - len(received)) / packet_count * 100
                ),
                "average_ms": (
                    statistics.mean(received) if received else None
                ),
            }
        )

    return {"hops": results}


def demonstrate_simulation() -> None:
    section("14. DIAGNOSTIC PATH SIMULATION")

    simulation = simulate_packet_path(
        [
            ("LAN gateway", 1.0, 0.00),
            ("ISP edge", 8.0, 0.02),
            ("Regional router", 20.0, 0.05),
            ("Destination", 35.0, 0.05),
        ]
    )

    for hop in simulation["hops"]:
        average = (
            f"{hop['average_ms']:.2f} ms"
            if hop["average_ms"] is not None
            else "N/A"
        )
        print(
            f"{hop['hop']:20} "
            f"loss={hop['loss_percent']:5.1f}% "
            f"avg={average}"
        )

    print(
        """
Simulation demonstrates an important troubleshooting principle: a symptom
seen at the destination does not identify the exact faulty hop.

A congested or rate-limited intermediate router may report diagnostic loss
while forwarding application traffic successfully. Conversely, loss beginning
at a hop and continuing through every subsequent hop is stronger evidence that
the path after that point may be affected.
"""
    )


# ---------------------------------------------------------------------------
# 16. REPORT GENERATION
# ---------------------------------------------------------------------------

def generate_report(hostname: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "target": hostname,
        "timestamp_epoch": time.time(),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "dns": {},
        "tcp_443": {},
    }

    try:
        dns_results = dns_lookup(hostname)
        addresses = sorted({result[4][0] for result in dns_results})
        report["dns"] = {
            "success": True,
            "addresses": addresses,
        }
    except socket.gaierror as exc:
        report["dns"] = {
            "success": False,
            "error": str(exc),
        }
        return report

    for address in report["dns"]["addresses"][:10]:
        report["tcp_443"][address] = asdict(
            tcp_connect_test(address, 443)
        )

    return report


def demonstrate_report(hostname: str) -> None:
    section("15. MACHINE-READABLE DIAGNOSTIC REPORT")

    report = generate_report(hostname)
    print(json.dumps(report, indent=2))


# ---------------------------------------------------------------------------
# 17. BEGINNER EXAMPLES
# ---------------------------------------------------------------------------

def beginner_examples() -> None:
    section("16. BEGINNER EXAMPLES")

    print("Example 1: Check whether an IPv4 address is valid")
    for value in ["192.168.1.10", "300.1.1.1", "127.0.0.1"]:
        print(f"  {value:15} -> {validate_address(value)}")

    print("\nExample 2: Inspect a network")
    network = ipaddress.ip_network("10.10.10.0/29")
    print(f"  Network: {network}")
    print(f"  Number of addresses: {network.num_addresses}")
    print(f"  Usable hosts: {list(network.hosts())}")

    print("\nExample 3: Understand TCP port notation")
    examples = [
        ("web", "443"),
        ("DNS", "53"),
        ("SSH", "22"),
    ]
    for service, port in examples:
        print(f"  {service}: TCP/{port}")

    print(
        """
Remember:

IP address
    Identifies an endpoint/interface at the IP layer.

Port
    Identifies a transport-layer endpoint.

Hostname
    Human-readable name resolved by DNS or another configured name service.

Socket
    An operating-system abstraction representing communication endpoints.

A useful diagnostic question is:
    "Which layer has actually failed?"
"""
    )


# ---------------------------------------------------------------------------
# 18. MAIN PROGRAM
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Educational network troubleshooting diagnostics for DNS, "
            "TCP connectivity, latency, routing, and MTU."
        )
    )

    parser.add_argument(
        "host",
        nargs="?",
        default="example.com",
        help="Hostname or IP address to test.",
    )

    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run a compact diagnostic instead of the complete lesson.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable diagnostic report.",
    )

    return parser


def quick_diagnostic(host: str) -> None:
    section("QUICK DIAGNOSTIC")

    print(f"Target: {host}")

    if validate_address(host):
        addresses = [host]
        print("Input is an IP address; DNS lookup is skipped.")
    else:
        try:
            addresses = sorted(
                {
                    result[4][0]
                    for result in dns_lookup(host)
                    if result[4]
                }
            )
            print(f"Resolved addresses: {addresses}")
        except socket.gaierror as exc:
            print(f"DNS resolution failed: {exc}")
            return

    for address in addresses[:4]:
        result = tcp_connect_test(address, 443)
        if result.success:
            print(
                f"TCP/443 {address}: "
                f"success ({result.elapsed_ms:.2f} ms)"
            )
        else:
            print(
                f"TCP/443 {address}: failed "
                f"({result.error})"
            )

    try:
        samples = ping_with_system_command(host, count=2)
        print("Ping statistics:", json.dumps(summarize_latency(samples)))
    except Exception as exc:
        print(f"Ping unavailable: {exc}")


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.json:
        print(json.dumps(generate_report(args.host), indent=2))
        return

    if args.quick:
        quick_diagnostic(args.host)
        return

    explain_fundamentals()
    beginner_examples()
    demonstrate_ip_addressing()
    demonstrate_dns(args.host)
    demonstrate_tcp(args.host)
    demonstrate_latency(args.host)
    run_route_command(args.host)
    demonstrate_mtu(args.host)
    show_local_network_information()
    demonstrate_routing_algorithm()
    diagnostic_decision_tree(args.host)
    demonstrate_configuration_validation()
    demonstrate_latency_statistics()
    security_guidance()
    demonstrate_simulation()
    demonstrate_report(args.host)

    section("END OF STUDY PROGRAM")
    print(
        """
Recommended diagnostic order for a real incident:

    1. Define the exact symptom.
    2. Identify the affected scope and time window.
    3. Check local configuration.
    4. Check gateway reachability.
    5. Check DNS independently from application connectivity.
    6. Test the destination IP.
    7. Test the relevant TCP/UDP service.
    8. Inspect routing and path behavior.
    9. Investigate packet loss, latency, jitter, and MTU when indicated.
   10. Correlate observations with application and server logs.

Avoid changing multiple variables simultaneously. A reproducible test and a
recorded baseline make troubleshooting much more reliable.
"""
    )


if __name__ == "__main__":
    main()
