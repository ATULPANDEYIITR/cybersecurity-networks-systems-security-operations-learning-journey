#!/usr/bin/env python3
"""Windows networking laboratory: SMB, RDP, WinRM, RPC, and Windows Firewall.

Uses the Python standard library. Network checks are read-only and should be
performed only against authorized systems. Port reachability does not prove
that a service is authenticated, correctly configured, or safe.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable


@dataclass(frozen=True)
class WindowsService:
    name: str
    purpose: str
    ports: tuple[int, ...]
    transport: str
    security_notes: str


SERVICES = {
    "SMB": WindowsService(
        "SMB",
        "Windows file and printer sharing",
        (445,),
        "TCP",
        "Prefer SMB 3.x, signing where required, encryption for sensitive "
        "shares, least-privilege ACLs, and no public Internet exposure.",
    ),
    "RDP": WindowsService(
        "RDP",
        "Remote graphical desktop sessions",
        (3389,),
        "TCP",
        "Require Network Level Authentication where supported, strong "
        "authentication, restricted source networks, and preferably a VPN.",
    ),
    "WinRM": WindowsService(
        "WinRM",
        "Windows Remote Management for PowerShell remoting",
        (5985, 5986),
        "TCP",
        "Use HTTPS on 5986 when configured, trusted authentication, restricted "
        "administrative access, and narrowly scoped firewall rules.",
    ),
    "RPC": WindowsService(
        "RPC",
        "Remote procedure calls used by Windows management components",
        (135,),
        "TCP",
        "TCP 135 is the RPC endpoint mapper. RPC services may also use "
        "dynamic ports, so checking 135 alone is insufficient.",
    ),
}


@dataclass
class PortResult:
    host: str
    port: int
    reachable: bool
    elapsed_ms: float
    error: str | None


def validate_host(host: str) -> str:
    """Validate a hostname or IP literal without requiring DNS availability."""
    candidate = host.strip()
    if not candidate or any(char.isspace() for char in candidate):
        raise ValueError("Host must be a non-empty hostname or IP address.")

    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    if len(candidate) > 253:
        raise ValueError("Hostname is too long.")

    name = candidate.rstrip(".")
    labels = name.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(ch.isalnum() or ch == "-" for ch in label)
        ):
            raise ValueError(f"Invalid hostname: {candidate!r}")

    return name


def tcp_probe(host: str, port: int, timeout: float = 2.0) -> PortResult:
    """Attempt a bounded TCP connection; never sends application credentials."""
    if not 1 <= port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535.")
    if not 0.1 <= timeout <= 30:
        raise ValueError("Timeout must be between 0.1 and 30 seconds.")

    started = time.perf_counter()
    error = None

    try:
        with socket.create_connection((host, port), timeout=timeout):
            reachable = True
    except (OSError, TimeoutError) as exc:
        reachable = False
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = (time.perf_counter() - started) * 1000
    return PortResult(
        host=host,
        port=port,
        reachable=reachable,
        elapsed_ms=round(elapsed_ms, 2),
        error=error,
    )


def inspect_service(host: str, service_name: str, timeout: float) -> dict:
    """Check the standard TCP endpoints associated with one Windows service."""
    normalized = service_name.upper()
    if normalized not in SERVICES:
        raise ValueError(
            f"Unknown service {service_name!r}. Choose from "
            f"{', '.join(SERVICES)}."
        )

    service = SERVICES[normalized]
    results = [
        asdict(tcp_probe(host, port, timeout))
        for port in service.ports
    ]

    return {
        "service": service.name,
        "purpose": service.purpose,
        "transport": service.transport,
        "security_notes": service.security_notes,
        "ports": results,
    }


def build_firewall_guidance() -> list[str]:
    """Return defensive PowerShell examples without changing firewall state."""
    return [
        "# Run in an elevated PowerShell session only after reviewing policy.",
        "Get-NetFirewallProfile | "
        "Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction",
        "Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True | "
        "Select-Object DisplayName, Direction, Action, Profile",
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress, LocalPort, OwningProcess",
        "# Review existing SMB-related rules before making changes.",
        "Get-SmbServerConfiguration | "
        "Select-Object EnableSMB1Protocol, RequireSecuritySignature, "
        "EncryptData",
        "# Review RDP state and NLA configuration.",
        "Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name UserAuthentication -ErrorAction SilentlyContinue",
        "# Review WinRM listener configuration.",
        "winrm enumerate winrm/config/listener",
        "# Inspect RPC endpoint mappings locally.",
        "rpcdump.exe /s localhost",
    ]


def windows_only(command: list[str], timeout: float = 10.0) -> dict:
    """Execute an explicitly selected local inspection command on Windows."""
    if platform.system() != "Windows":
        return {
            "executed": False,
            "reason": "Local Windows inspection is available only on Windows.",
        }

    if not command:
        raise ValueError("Command cannot be empty.")

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
        return {
            "executed": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "executed": False,
            "reason": f"{type(exc).__name__}: {exc}",
        }


def print_report(host: str, service_names: Iterable[str], timeout: float) -> None:
    report = {
        "target": host,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "warning": (
            "TCP reachability is not proof of successful authentication, "
            "protocol negotiation, or application health."
        ),
        "services": [
            inspect_service(host, name, timeout)
            for name in service_names
        ],
    }
    print(json.dumps(report, indent=2))


def demonstrate_network_basics() -> None:
    print("\nWindows networking concepts")
    print("- SMB: file sharing and named-pipe access, commonly TCP 445.")
    print("- RDP: interactive remote desktop, commonly TCP 3389.")
    print("- WinRM: remote management, commonly TCP 5985 or 5986.")
    print("- RPC: endpoint mapper TCP 135 plus service-specific endpoints.")
    print("- Windows Firewall: filters traffic according to profile and rules.")

    print("\nStandard endpoint reference")
    for service in SERVICES.values():
        print(
            f"{service.name:6} ports={','.join(map(str, service.ports)):9} "
            f"{service.purpose}"
        )


def run_self_tests() -> None:
    assert validate_host("localhost") == "localhost"
    assert validate_host("server-01.example.com") == "server-01.example.com"
    assert validate_host("192.168.1.10") == "192.168.1.10"

    for invalid in ("", "bad host", "-invalid.example", "host..example"):
        try:
            validate_host(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected invalid hostname: {invalid!r}")

    try:
        inspect_service("localhost", "TELNET", 1.0)
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown services must be rejected.")

    try:
        tcp_probe("localhost", 0)
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid ports must be rejected.")

    print("Self-tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect standard Windows networking TCP endpoints."
    )
    parser.add_argument(
        "--host",
        help="Authorized target hostname or IP address.",
    )
    parser.add_argument(
        "--services",
        nargs="+",
        choices=list(SERVICES),
        default=list(SERVICES),
        help="Services to inspect.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="TCP connection timeout in seconds.",
    )
    parser.add_argument(
        "--concepts",
        action="store_true",
        help="Print the service reference table.",
    )
    parser.add_argument(
        "--firewall-guidance",
        action="store_true",
        help="Print read-only PowerShell inspection commands.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run local input-validation tests.",
    )
    args = parser.parse_args()

    try:
        if args.self_test:
            run_self_tests()

        if args.concepts:
            demonstrate_network_basics()

        if args.firewall_guidance:
            print("\nRead-only Windows inspection commands")
            print("\n".join(build_firewall_guidance()))

        if args.host:
            host = validate_host(args.host)
            print_report(host, args.services, args.timeout)

        if not any(
            (args.self_test, args.concepts, args.firewall_guidance, args.host)
        ):
            parser.print_help()

    except (ValueError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
