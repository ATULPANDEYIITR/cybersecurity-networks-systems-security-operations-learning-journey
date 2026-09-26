#!/usr/bin/env python3
"""
Nmap Fundamentals: TCP Scans, UDP Scans, Port States, Service Detection,
and OS Detection

This standalone study script teaches the major ideas behind Nmap while
demonstrating safe local-network concepts with Python's standard library.

Default target:
    127.0.0.1

The script intentionally defaults to localhost. Network scanning should only
be performed against systems and networks for which you have explicit
authorization.

Topics covered:
    1. Ports and sockets
    2. TCP connection scanning
    3. TCP port states
    4. UDP probing
    5. Service detection
    6. OS detection concepts
    7. Nmap command construction and interpretation
    8. Timeouts and concurrency
    9. Validation and error handling
    10. Security and operational considerations
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# SECTION 1: FUNDAMENTAL TERMINOLOGY
# ---------------------------------------------------------------------------

def explain_fundamentals() -> None:
    print("=" * 78)
    print("NMAP FUNDAMENTALS")
    print("=" * 78)

    concepts = {
        "IP address": "Identifies a network interface or host.",
        "Port": "A numbered endpoint used by transport-layer protocols.",
        "TCP": "Connection-oriented transport protocol using a connection handshake.",
        "UDP": "Connectionless transport protocol with no TCP-style handshake.",
        "Socket": "An operating-system abstraction representing network communication.",
        "TCP connect scan": "Attempts a complete TCP connection to determine reachability.",
        "UDP scan": "Sends UDP probes and interprets replies or timeouts.",
        "Service detection": "Attempts to determine the application/service behind a port.",
        "OS detection": "Uses network-response characteristics to infer operating-system families.",
        "Port state": "A classification such as open, closed, filtered, or open|filtered.",
    }

    for name, description in concepts.items():
        print(f"{name:22} {description}")

    print()


# ---------------------------------------------------------------------------
# SECTION 2: DATA MODELS
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    banner: str = ""
    latency_ms: Optional[float] = None
    reason: str = ""


# ---------------------------------------------------------------------------
# SECTION 3: VALIDATION
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    """
    Validate an IPv4/IPv6 address or hostname.

    The default target is localhost. Hostnames are resolved so that the
    scanner can operate without external packages.
    """
    if not target.strip():
        raise ValueError("Target cannot be empty.")

    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    if len(target) > 253:
        raise ValueError("Hostname is too long.")

    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", target):
        raise ValueError("Target contains unsupported characters.")

    try:
        socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        raise ValueError(f"Target could not be resolved: {exc}") from exc

    return target


def parse_ports(port_text: str) -> list[int]:
    """
    Parse:
        22
        22,80,443
        20-25
        22,80,8000-8010
    """
    ports: set[int] = set()

    for part in port_text.split(","):
        part = part.strip()

        if not part:
            continue

        if "-" in part:
            pieces = part.split("-", 1)
            if len(pieces) != 2:
                raise ValueError(f"Invalid port range: {part}")

            start = int(pieces[0])
            end = int(pieces[1])

            if start > end:
                start, end = end, start

            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("No ports were supplied.")

    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535.")

    return sorted(ports)


# ---------------------------------------------------------------------------
# SECTION 4: COMMON SERVICE DATABASE
# ---------------------------------------------------------------------------

COMMON_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp-server",
    68: "dhcp-client",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
}


def service_name(port: int) -> str:
    """Return a common service name based on the port number."""
    return COMMON_SERVICES.get(port, "unknown")


# ---------------------------------------------------------------------------
# SECTION 5: TCP CONNECT SCANNING
# ---------------------------------------------------------------------------

def tcp_connect_scan(
    target: str,
    port: int,
    timeout: float = 0.5,
) -> PortResult:
    """
    Perform a TCP connect-style probe.

    Python's socket.create_connection() asks the operating system to establish
    a real TCP connection. If the connection succeeds, the port is open.

    Typical interpretations:
        Connection succeeds -> open
        Connection refused  -> closed
        Timeout              -> potentially filtered
        Other network error  -> unknown/error condition
    """
    started = time.perf_counter()

    try:
        with socket.create_connection((target, port), timeout=timeout):
            latency = (time.perf_counter() - started) * 1000
            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                service=service_name(port),
                latency_ms=round(latency, 2),
                reason="TCP connection succeeded",
            )

    except ConnectionRefusedError:
        latency = (time.perf_counter() - started) * 1000
        return PortResult(
            port=port,
            protocol="tcp",
            state="closed",
            service=service_name(port),
            latency_ms=round(latency, 2),
            reason="Host actively refused the connection",
        )

    except socket.timeout:
        latency = (time.perf_counter() - started) * 1000
        return PortResult(
            port=port,
            protocol="tcp",
            state="filtered",
            service=service_name(port),
            latency_ms=round(latency, 2),
            reason="No TCP response before timeout",
        )

    except OSError as exc:
        latency = (time.perf_counter() - started) * 1000
        return PortResult(
            port=port,
            protocol="tcp",
            state="error",
            service=service_name(port),
            latency_ms=round(latency, 2),
            reason=str(exc),
        )


def scan_tcp_ports(
    target: str,
    ports: Iterable[int],
    timeout: float,
    workers: int,
) -> list[PortResult]:
    """
    Scan several TCP ports concurrently.

    Concurrency improves throughput for network I/O, but excessive concurrency
    can increase resource consumption and network load.
    """
    ports = list(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(tcp_connect_scan, target, port, timeout)
            for port in ports
        ]
        return [future.result() for future in futures]


# ---------------------------------------------------------------------------
# SECTION 6: TCP SERVICE DETECTION
# ---------------------------------------------------------------------------

def detect_http_service(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> str:
    """
    Send a minimal HTTP request to a likely HTTP service.

    This is a simple educational example of application-layer service
    detection. Real Nmap service detection is considerably more sophisticated
    and uses a database of probes and response fingerprints.
    """
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            request = (
                "HEAD / HTTP/1.0\r\n"
                f"Host: {target}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii", errors="ignore")

            sock.sendall(request)
            data = sock.recv(2048)

        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()

        if lines:
            status_line = lines[0].strip()
            server_header = ""

            for line in lines:
                if line.lower().startswith("server:"):
                    server_header = line.strip()
                    break

            if server_header:
                return f"{status_line}; {server_header}"

            return status_line

    except (OSError, UnicodeError):
        pass

    return ""


def detect_banner(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> str:
    """
    Perform lightweight banner/service probing.

    SSH and many text-oriented services send a banner immediately.
    HTTP services require the client to send a request first.
    """
    known = service_name(port)

    if known in {"http", "http-alt"}:
        return detect_http_service(target, port, timeout)

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # A small passive read is useful for protocols that send an
            # identification string immediately, such as SSH.
            data = sock.recv(1024)

        if not data:
            return ""

        return data.decode("utf-8", errors="replace").strip()[:300]

    except (OSError, UnicodeError):
        return ""


def perform_service_detection(
    target: str,
    results: list[PortResult],
    timeout: float,
) -> None:
    """Add lightweight application-level observations to open TCP ports."""
    for result in results:
        if result.protocol != "tcp" or result.state != "open":
            continue

        result.banner = detect_banner(target, result.port, timeout)

        if result.banner:
            result.service = f"{result.service} | {result.banner}"


# ---------------------------------------------------------------------------
# SECTION 7: UDP SCANNING
# ---------------------------------------------------------------------------

def udp_probe(
    target: str,
    port: int,
    timeout: float = 1.0,
) -> PortResult:
    """
    Perform a minimal UDP probe.

    UDP differs from TCP:
        - There is no connection handshake.
        - An application may not reply to an empty or unexpected payload.
        - An ICMP "port unreachable" response may indicate a closed port.
        - Silence can represent open|filtered rather than definitively open.

    Therefore this function intentionally reports uncertainty instead of
    pretending that every timeout proves a port is open.
    """
    started = time.perf_counter()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)

            # DNS port gets a small syntactically valid DNS query. This is a
            # meaningful application probe rather than arbitrary data.
            if port == 53:
                payload = (
                    b"\x12\x34"       # transaction ID
                    b"\x01\x00"       # standard query
                    b"\x00\x01"       # one question
                    b"\x00\x00"       # answer count
                    b"\x00\x00"       # authority count
                    b"\x00\x00"       # additional count
                    b"\x00\x00\x01"  # root label + terminator
                    b"\x00\x01"       # type A
                    b"\x00\x01"       # class IN
                )
            else:
                # A zero-length datagram is enough to illustrate the transport
                # behavior while avoiding protocol-specific payloads.
                payload = b""

            sock.sendto(payload, (target, port))

            try:
                data, _ = sock.recvfrom(4096)
                latency = (time.perf_counter() - started) * 1000

                return PortResult(
                    port=port,
                    protocol="udp",
                    state="open",
                    service=service_name(port),
                    banner=data[:100].hex(),
                    latency_ms=round(latency, 2),
                    reason="UDP application response received",
                )

            except socket.timeout:
                latency = (time.perf_counter() - started) * 1000

                return PortResult(
                    port=port,
                    protocol="udp",
                    state="open|filtered",
                    service=service_name(port),
                    latency_ms=round(latency, 2),
                    reason="No UDP response; open and filtered cannot be distinguished",
                )

    except ConnectionRefusedError:
        latency = (time.perf_counter() - started) * 1000

        return PortResult(
            port=port,
            protocol="udp",
            state="closed",
            service=service_name(port),
            latency_ms=round(latency, 2),
            reason="ICMP/OS-level port-unreachable condition",
        )

    except OSError as exc:
        latency = (time.perf_counter() - started) * 1000

        return PortResult(
            port=port,
            protocol="udp",
            state="error",
            service=service_name(port),
            latency_ms=round(latency, 2),
            reason=str(exc),
        )


def scan_udp_ports(
    target: str,
    ports: Iterable[int],
    timeout: float,
    workers: int,
) -> list[PortResult]:
    """Run UDP probes concurrently with a conservative worker count."""
    ports = list(ports)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(udp_probe, target, port, timeout)
            for port in ports
        ]
        return [future.result() for future in futures]


# ---------------------------------------------------------------------------
# SECTION 8: OS DETECTION CONCEPTS
# ---------------------------------------------------------------------------

def explain_os_detection() -> None:
    print("=" * 78)
    print("OS DETECTION CONCEPTS")
    print("=" * 78)

    print(
        """
Nmap OS detection is fundamentally different from simply asking a host for
its operating-system name.

It can analyze characteristics of network responses, including:
    * TCP/IP behavior
    * TCP window characteristics
    * TCP options
    * packet sequencing behavior
    * IP header characteristics
    * responses to carefully selected probes
    * ICMP behavior
    * timing-related characteristics

Nmap compares observations against OS fingerprints.

A result such as:
    Linux
    Windows
    FreeBSD

should be understood as a fingerprint-based inference, not as a guarantee.

The small demonstration below shows the local Python runtime's operating
system. This is NOT equivalent to remote Nmap OS detection.
"""
    )

    print(f"Local kernel/system reported by Python: {platform.system()}")
    print(f"Platform string: {platform.platform()}")
    print()


# ---------------------------------------------------------------------------
# SECTION 9: NMAP COMMAND REFERENCE
# ---------------------------------------------------------------------------

def build_nmap_commands(target: str, ports: str) -> list[str]:
    """
    Build safe, explicit Nmap examples.

    These strings are displayed for study. The script does not execute them
    automatically.
    """
    return [
        f"nmap -sT -p {ports} {target}",
        f"nmap -sU -p {ports} {target}",
        f"nmap -sT -sV -p {ports} {target}",
        f"nmap -O -p {ports} {target}",
        f"nmap -sT -sV -O -p {ports} {target}",
    ]


def show_nmap_reference(target: str, ports: str) -> None:
    print("=" * 78)
    print("NMAP COMMAND REFERENCE")
    print("=" * 78)

    descriptions = [
        ("-sT", "TCP connect scan"),
        ("-sU", "UDP scan"),
        ("-sV", "Service/version detection"),
        ("-O", "Operating-system detection"),
        ("-p", "Select ports"),
    ]

    for option, meaning in descriptions:
        print(f"{option:5} {meaning}")

    print("\nStudy commands:")
    for command in build_nmap_commands(target, ports):
        print(f"  {command}")

    print(
        "\nOS detection often requires elevated privileges and additional "
        "probe behavior. Nmap may report an uncertain or partial result."
    )
    print()


# ---------------------------------------------------------------------------
# SECTION 10: SAFE LOCAL NMAP EXECUTION
# ---------------------------------------------------------------------------

def is_local_target(target: str) -> bool:
    """Permit automatic Nmap execution only for loopback addresses."""
    try:
        address = ipaddress.ip_address(socket.gethostbyname(target))
        return address.is_loopback
    except (ValueError, socket.gaierror):
        return False


def run_local_nmap(
    target: str,
    ports: str,
) -> None:
    """
    Optionally execute Nmap against localhost only.

    This demonstrates how Python can integrate with a system security tool
    while keeping the automated example restricted to a loopback target.
    """
    if not is_local_target(target):
        print("Automatic Nmap execution is restricted to localhost.")
        return

    executable = "nmap"

    try:
        subprocess.run(
            [executable, "-sT", "-sV", "-p", ports, target],
            check=False,
            timeout=30,
        )
    except FileNotFoundError:
        print("Nmap is not installed or is not available in PATH.")
    except subprocess.TimeoutExpired:
        print("Nmap execution exceeded the 30-second timeout.")
    except OSError as exc:
        print(f"Unable to execute Nmap: {exc}")


# ---------------------------------------------------------------------------
# SECTION 11: REPORTING
# ---------------------------------------------------------------------------

def print_results(results: list[PortResult]) -> None:
    print("=" * 78)
    print("SCAN RESULTS")
    print("=" * 78)

    if not results:
        print("No results.")
        return

    print(
        f"{'PORT':>6} {'PROTO':<6} {'STATE':<15} "
        f"{'SERVICE':<30} {'LATENCY':>10}"
    )
    print("-" * 78)

    for result in sorted(results, key=lambda item: (item.protocol, item.port)):
        latency = (
            f"{result.latency_ms:.2f} ms"
            if result.latency_ms is not None
            else "-"
        )

        print(
            f"{result.port:>6} "
            f"{result.protocol:<6} "
            f"{result.state:<15} "
            f"{result.service[:30]:<30} "
            f"{latency:>10}"
        )

        if result.reason:
            print(f"       reason: {result.reason}")

        if result.banner:
            print(f"       probe:  {result.banner[:120]}")

    print()


def save_json(results: list[PortResult], filename: str) -> None:
    """Save structured scan data for later analysis."""
    with open(filename, "w", encoding="utf-8") as file:
        json.dump([asdict(result) for result in results], file, indent=2)

    print(f"Saved structured results to {filename}")


# ---------------------------------------------------------------------------
# SECTION 12: PORT-STATE ANALYSIS
# ---------------------------------------------------------------------------

def explain_states() -> None:
    print("=" * 78)
    print("PORT STATE INTERPRETATION")
    print("=" * 78)

    states = [
        (
            "open",
            "An application appears to be accepting traffic on the port.",
        ),
        (
            "closed",
            "The host is reachable, but no application is accepting the port.",
        ),
        (
            "filtered",
            "A firewall or filtering mechanism prevents a reliable determination.",
        ),
        (
            "open|filtered",
            "Common with UDP when silence could mean either open or filtered.",
        ),
        (
            "closed|filtered",
            "A condition where available evidence cannot cleanly separate states.",
        ),
    ]

    for state, explanation in states:
        print(f"{state:18} {explanation}")

    print()


# ---------------------------------------------------------------------------
# SECTION 13: EDGE CASES AND COMMON MISTAKES
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    print("=" * 78)
    print("EDGE CASES AND COMMON MISTAKES")
    print("=" * 78)

    print(
        """
1. A timeout does not automatically mean a port is open.
   UDP is the classic example: no response can mean open|filtered.

2. A port number does not prove the service.
   Port 8080 is commonly associated with HTTP, but any application can use it.

3. A TCP connect scan is not the same as a SYN scan.
   A connect scan completes the operating-system-level connection.
   A SYN scan uses lower-level packet behavior and normally requires
   additional privileges.

4. Service detection is an application-layer activity.
   It goes beyond identifying that a port accepts connections.

5. OS detection is fingerprinting.
   It is an inference based on network behavior.

6. Firewalls can alter observations.
   A scanner sees network behavior, not necessarily the actual configuration.

7. NAT can change the apparent topology.
   The address being scanned may represent a router or translated endpoint.

8. IPv4 and IPv6 can behave differently.
   A hostname may resolve to multiple addresses.

9. Timeouts involve trade-offs.
   Very short timeouts reduce waiting but can create false uncertainty.
   Long timeouts improve patience but reduce scan speed.

10. Scanning more ports increases coverage and network activity.
    Good operational practice is to use the smallest scope required.
"""
    )


# ---------------------------------------------------------------------------
# SECTION 14: PERFORMANCE DISCUSSION
# ---------------------------------------------------------------------------

def explain_performance() -> None:
    print("=" * 78)
    print("PERFORMANCE CONSIDERATIONS")
    print("=" * 78)

    print(
        """
Sequential scanning:
    For N ports, total time can approach N * timeout when many ports do not
    respond.

Concurrent scanning:
    Multiple network operations can be in flight simultaneously.
    This is effective because socket operations are I/O-bound.

Too much concurrency:
    * consumes file descriptors and memory
    * increases local scheduling overhead
    * can overwhelm the target or network
    * can produce unreliable results

Production scanners therefore balance:
    * timeout
    * retry policy
    * concurrency
    * packet rate
    * target size
    * network conditions
    * accuracy requirements
"""
    )


# ---------------------------------------------------------------------------
# SECTION 15: COMMAND-LINE INTERFACE
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Educational Nmap fundamentals scanner."
    )

    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target hostname/IP. Defaults to localhost.",
    )

    parser.add_argument(
        "--ports",
        default="22,53,80,443,8080",
        help="Ports or ranges such as 22,80,8000-8010.",
    )

    parser.add_argument(
        "--mode",
        choices=["tcp", "udp", "both", "reference"],
        default="both",
        help="Demonstration mode.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds.",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Maximum concurrent probes.",
    )

    parser.add_argument(
        "--service-detection",
        action="store_true",
        help="Perform lightweight service/banner detection on open TCP ports.",
    )

    parser.add_argument(
        "--nmap-localhost",
        action="store_true",
        help="Run a TCP service-detection Nmap command against localhost only.",
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Write scan results to a JSON file.",
    )

    return parser


# ---------------------------------------------------------------------------
# SECTION 16: MAIN PROGRAM
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        target = validate_target(args.target)
        ports = parse_ports(args.ports)

        if args.timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        if args.workers < 1:
            raise ValueError("Workers must be at least 1.")

    except ValueError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2

    explain_fundamentals()
    explain_states()
    explain_os_detection()
    explain_performance()
    demonstrate_edge_cases()

    print(f"Target: {target}")
    print(f"Ports:  {ports}")
    print()

    if args.mode == "reference":
        show_nmap_reference(target, args.ports)
        return 0

    results: list[PortResult] = []

    if args.mode in {"tcp", "both"}:
        print("Running TCP connect probes...")
        tcp_results = scan_tcp_ports(
            target=target,
            ports=ports,
            timeout=args.timeout,
            workers=args.workers,
        )

        if args.service_detection:
            print("Running lightweight TCP service detection...")
            perform_service_detection(
                target=target,
                results=tcp_results,
                timeout=max(args.timeout, 1.0),
            )

        results.extend(tcp_results)

    if args.mode in {"udp", "both"}:
        print("Running UDP probes...")
        udp_results = scan_udp_ports(
            target=target,
            ports=ports,
            timeout=max(args.timeout, 0.5),
            workers=min(args.workers, 8),
        )
        results.extend(udp_results)

    print_results(results)

    if args.json:
        try:
            save_json(results, args.json)
        except OSError as exc:
            print(f"Could not save JSON: {exc}", file=sys.stderr)
            return 1

    show_nmap_reference(target, args.ports)

    if args.nmap_localhost:
        print("=" * 78)
        print("LOCAL NMAP EXECUTION")
        print("=" * 78)
        run_local_nmap(target, args.ports)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
