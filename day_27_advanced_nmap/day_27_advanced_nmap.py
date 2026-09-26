#!/usr/bin/env python3
"""
Advanced Nmap: NSE scripts, timing, output formats, scan interpretation,
and defensive scanning.

This standalone study program is intentionally designed around authorized
defensive assessment. The executable scan examples default to localhost.
Before scanning any other system, obtain explicit authorization and use
the smallest scope necessary.

Requirements:
    - Python 3.10+
    - Nmap installed and available as `nmap` on PATH for live demonstrations.

The script can also teach and analyze Nmap concepts without Nmap installed.
Run:
    python advanced_nmap.py

Optional:
    python advanced_nmap.py --host 127.0.0.1
    python advanced_nmap.py --demo-scan
    python advanced_nmap.py --parse-xml scan.xml
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PortObservation:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class HostObservation:
    address: str
    hostname: str = ""
    status: str = "unknown"
    ports: list[PortObservation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Safety-oriented validation
# ---------------------------------------------------------------------------

def validate_authorized_target(target: str) -> tuple[bool, str]:
    """
    Validate a target for this study program.

    The program permits:
      * localhost
      * loopback IPv4/IPv6
      * private IPv4 addresses
      * hostnames explicitly supplied by the user

    This is not a replacement for authorization. It is an additional guard
    against accidentally copying a public Internet target into a demo.
    """
    target = target.strip()

    if not target:
        return False, "Target cannot be empty."

    if target in {"localhost", "localhost.localdomain"}:
        return True, target

    try:
        address = ipaddress.ip_address(target)
        if address.is_loopback or address.is_private or address.is_link_local:
            return True, target
        return False, (
            "This study program only executes live scans against loopback, "
            "private, or link-local IP addresses."
        )
    except ValueError:
        pass

    # Hostnames are allowed for educational parsing/configuration, but live
    # execution remains restricted unless they resolve to a private address.
    if re.fullmatch(r"[A-Za-z0-9.-]+", target):
        try:
            resolved = socket.gethostbyname(target)
            address = ipaddress.ip_address(resolved)
            if address.is_loopback or address.is_private or address.is_link_local:
                return True, target
            return False, (
                f"{target} resolves to a public IPv4 address ({resolved}). "
                "Use an explicitly authorized private/lab target."
            )
        except socket.gaierror:
            return False, f"Could not resolve hostname: {target}"

    return False, "Target contains unsupported characters."


# ---------------------------------------------------------------------------
# Nmap concepts
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def print_bullets(items: Iterable[str]) -> None:
    for item in items:
        print(f"  • {item}")


def explain_fundamentals() -> None:
    print_section("1. NMAP FUNDAMENTALS")

    print_bullets([
        "Nmap is a network discovery and security-auditing tool.",
        "A host discovery result answers whether a target appears reachable.",
        "Port scanning determines which TCP or UDP ports respond or otherwise "
        "provide evidence about their state.",
        "Service/version detection attempts to identify software associated "
        "with discovered services.",
        "NSE, the Nmap Scripting Engine, extends Nmap with Lua-based scripts.",
        "Timing controls affect scan speed, parallelism, retransmission behavior, "
        "and waiting intervals.",
        "Output formats allow results to be consumed by people and software.",
        "Interpretation requires distinguishing observations from conclusions."
    ])

    print("\nImportant TCP port states:")
    print_bullets([
        "open: an application is listening and accepting connections.",
        "closed: the port is reachable but no application is listening.",
        "filtered: packet filtering prevents Nmap from determining the state.",
        "open|filtered: Nmap cannot distinguish the two states with confidence.",
        "closed|filtered: Nmap cannot distinguish the two states with confidence."
    ])

    print("\nA port state is not a vulnerability finding.")
    print("An open SSH port, for example, is evidence of an exposed service,")
    print("not proof that SSH is vulnerable.")


def explain_scan_types() -> None:
    print_section("2. SCAN TYPES AND THEIR INTERPRETATION")

    examples = [
        ("TCP SYN scan", "-sS",
         "Uses TCP SYN behavior and is commonly used for efficient TCP discovery."),
        ("TCP connect scan", "-sT",
         "Uses the operating system's normal connect mechanism."),
        ("UDP scan", "-sU",
         "Investigates UDP services; it can be substantially slower."),
        ("Service detection", "-sV",
         "Attempts to identify service software and versions."),
        ("OS detection", "-O",
         "Uses network behavior to estimate the operating system."),
        ("Default scripts", "-sC",
         "Runs Nmap's default NSE script category."),
        ("Host discovery", "-sn",
         "Performs host discovery without a normal port scan.")
    ]

    for name, flag, explanation in examples:
        print(f"\n{name} ({flag})")
        print(f"  {explanation}")

    print("\nInterpretation principle:")
    print("A scan is a measurement process. Different scan methods expose")
    print("different evidence and have different visibility, speed, and accuracy.")


# ---------------------------------------------------------------------------
# NSE education
# ---------------------------------------------------------------------------

def explain_nse() -> None:
    print_section("3. NMAP SCRIPTING ENGINE (NSE)")

    print_bullets([
        "NSE scripts are Lua programs executed by Nmap's scripting engine.",
        "Scripts can support discovery, version-related inspection, configuration "
        "checking, vulnerability assessment, authentication auditing, and more.",
        "Script categories include safe, default, discovery, version, auth, "
        "vuln, intrusive, brute, exploit, malware, and external.",
        "Category selection matters because scripts can have substantially "
        "different operational impact.",
        "A script result is evidence that must be interpreted in context."
    ])

    print("\nUseful defensive NSE patterns:")
    print("  nmap -sV --script=default TARGET")
    print("  nmap -sV --script=safe TARGET")
    print("  nmap --script-help=default")
    print("  nmap --script-help=safe")

    print("\nScript-selection principle:")
    print("Prefer narrowly scoped, documented scripts appropriate to the assessment.")
    print("Avoid running intrusive or exploit-oriented scripts against systems")
    print("without explicit authorization and a defined testing procedure.")

    print("\nScript arguments:")
    print("NSE scripts may accept arguments. Arguments are script-specific and")
    print("should be reviewed with --script-help before operational use.")


# ---------------------------------------------------------------------------
# Timing education
# ---------------------------------------------------------------------------

def explain_timing() -> None:
    print_section("4. TIMING AND PERFORMANCE")

    timing = {
        "-T0": "paranoid; extremely slow",
        "-T1": "sneaky; very slow",
        "-T2": "polite; reduced scan aggressiveness",
        "-T3": "normal; default timing template",
        "-T4": "aggressive; faster assumptions",
        "-T5": "insane; fastest assumptions and least conservative timing",
    }

    for flag, description in timing.items():
        print(f"  {flag:<4} {description}")

    print("\nTiming is not simply a speed slider.")
    print_bullets([
        "Higher timing can reduce elapsed time but can increase packet rate.",
        "Fast scans can produce more retransmissions or less reliable results "
        "on slow or unstable networks.",
        "Network distance, packet loss, latency, filtering, host capacity, "
        "and parallelism all affect scan duration.",
        "For defensive production scanning, predictable load is usually more "
        "important than maximum speed.",
        "Use a small pilot scan before scaling the scope."
    ])


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------

def explain_output_formats() -> None:
    print_section("5. NMAP OUTPUT FORMATS")

    formats = [
        ("Normal", "-oN file.txt",
         "Human-readable output."),
        ("XML", "-oX file.xml",
         "Structured output suitable for parsing and automation."),
        ("Grepable", "-oG file.txt",
         "Legacy line-oriented format useful for simple processing."),
        ("All major formats", "-oA basename",
         "Writes normal, XML, and grepable output."),
        ("Script output", "-oS file",
         "Script-oriented output format; less commonly used for modern automation.")
    ]

    for name, flag, purpose in formats:
        print(f"\n{name}: {flag}")
        print(f"  {purpose}")

    print("\nFor automation, XML is especially useful because its structure")
    print("preserves hosts, ports, states, services, and NSE script results.")


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def parse_nmap_xml(xml_path: str | Path) -> list[HostObservation]:
    """
    Parse common Nmap XML structures.

    This parser deliberately ignores unknown XML elements, allowing it to
    continue working when Nmap adds metadata that is irrelevant to the report.
    """
    path = Path(xml_path)

    if not path.exists():
        raise FileNotFoundError(f"XML file does not exist: {path}")

    tree = ET.parse(path)
    root = tree.getroot()
    observations: list[HostObservation] = []

    for host in root.findall("host"):
        status_node = host.find("status")
        status = (
            status_node.get("state", "unknown")
            if status_node is not None
            else "unknown"
        )

        addresses = host.findall("address")
        address = ""
        for address_node in addresses:
            if address_node.get("addrtype") in {"ipv4", "ipv6"}:
                address = address_node.get("addr", "")
                break

        if not address and addresses:
            address = addresses[0].get("addr", "unknown")

        hostname = ""
        hostname_node = host.find("./hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name", "")

        observation = HostObservation(
            address=address or "unknown",
            hostname=hostname,
            status=status,
        )

        for port_node in host.findall("./ports/port"):
            try:
                port_number = int(port_node.get("portid", "0"))
            except ValueError:
                continue

            protocol = port_node.get("protocol", "unknown")

            state_node = port_node.find("state")
            state = (
                state_node.get("state", "unknown")
                if state_node is not None
                else "unknown"
            )

            service_node = port_node.find("service")
            service = ""
            product = ""
            version = ""
            extra_info = ""

            if service_node is not None:
                service = service_node.get("name", "")
                product = service_node.get("product", "")
                version = service_node.get("version", "")
                extra_info = service_node.get("extrainfo", "")

            scripts: dict[str, str] = {}
            for script_node in port_node.findall("script"):
                script_id = script_node.get("id", "unknown")
                output = script_node.get("output", "")
                scripts[script_id] = output

            observation.ports.append(
                PortObservation(
                    port=port_number,
                    protocol=protocol,
                    state=state,
                    service=service,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    scripts=scripts,
                )
            )

        observations.append(observation)

    return observations


def print_observations(observations: list[HostObservation]) -> None:
    print_section("6. STRUCTURED SCAN INTERPRETATION")

    if not observations:
        print("No host records were found.")
        return

    for host in observations:
        display_name = host.hostname or host.address
        print(f"\nHost: {display_name}")
        print(f"Address: {host.address}")
        print(f"Status: {host.status}")

        if not host.ports:
            print("  No port records were present in the XML.")
            continue

        for port in host.ports:
            service_details = " ".join(
                value for value in [
                    port.service,
                    port.product,
                    port.version,
                    port.extra_info,
                ] if value
            )

            print(
                f"  {port.port}/{port.protocol:<3} "
                f"{port.state:<14} "
                f"{service_details}"
            )

            for script_id, output in port.scripts.items():
                print(f"      NSE {script_id}: {output}")


# ---------------------------------------------------------------------------
# Defensive interpretation
# ---------------------------------------------------------------------------

def interpret_port(port: PortObservation) -> list[str]:
    """
    Produce cautious observations rather than claiming vulnerabilities.
    """
    findings: list[str] = []

    if port.state == "open":
        findings.append(
            f"{port.port}/{port.protocol} exposes an active service"
        )

        if port.service:
            findings.append(
                f"identified service family: {port.service}"
            )

        if port.product and port.version:
            findings.append(
                f"reported product/version: {port.product} {port.version}"
            )

    elif port.state == "filtered":
        findings.append(
            f"{port.port}/{port.protocol} is filtered or otherwise "
            "not directly classifiable"
        )

    elif port.state == "closed":
        findings.append(
            f"{port.port}/{port.protocol} is reachable but closed"
        )

    return findings


def generate_defensive_report(observations: list[HostObservation]) -> None:
    print_section("7. DEFENSIVE REPORTING")

    for host in observations:
        print(f"\n[{host.address}] {host.status}")

        open_ports = [
            port for port in host.ports
            if port.state == "open"
        ]

        if not open_ports:
            print("  No open ports recorded.")
            continue

        print("  Exposed services:")
        for port in open_ports:
            print(f"    - {port.port}/{port.protocol}: {port.service or 'unknown'}")

        print("  Defensive review questions:")
        print("    - Is each exposed service required?")
        print("    - Is the service reachable only from intended networks?")
        print("    - Is the software supported and appropriately patched?")
        print("    - Is encryption configured where sensitive data is involved?")
        print("    - Are firewall rules consistent with the intended architecture?")
        print("    - Are scan results being compared with an approved baseline?")


# ---------------------------------------------------------------------------
# Safe live scanning
# ---------------------------------------------------------------------------

def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def build_safe_scan_command(
    target: str,
    timing_template: str = "-T3",
) -> list[str]:
    """
    Build a deliberately constrained defensive scan.

    The command uses:
      - service detection
      - default NSE scripts
      - XML output
      - a moderate timing template

    It does not include exploit, brute-force, or intrusive script categories.
    """
    return [
        "nmap",
        "-sV",
        "-sC",
        timing_template,
        "-oX",
        "-",
        target,
    ]


def run_safe_local_scan(target: str) -> Optional[list[HostObservation]]:
    allowed, message = validate_authorized_target(target)

    if not allowed:
        print(f"Refusing live scan: {message}")
        return None

    if not nmap_available():
        print("Nmap is not installed or is not available on PATH.")
        return None

    command = build_safe_scan_command(target)

    print_section("8. SAFE LIVE DEMONSTRATION")
    print("Target:", target)
    print("Command:", " ".join(command))
    print(
        "\nThe demonstration is limited to a loopback/private/link-local "
        "target and uses default NSE scripts."
    )

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("Nmap exceeded the 180-second demonstration timeout.")
        return None
    except OSError as exc:
        print(f"Could not execute Nmap: {exc}")
        return None

    if completed.returncode != 0:
        print("Nmap returned an error.")
        if completed.stderr:
            print(textwrap.indent(completed.stderr.strip(), "  "))
        return None

    if not completed.stdout.strip():
        print("Nmap returned no XML data.")
        return None

    try:
        root = ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        print(f"Could not parse Nmap XML output: {exc}")
        return None

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".xml",
        delete=False,
        encoding="utf-8",
    ) as temporary_file:
        temporary_file.write(completed.stdout)
        temporary_path = temporary_file.name

    try:
        observations = parse_nmap_xml(temporary_path)
    finally:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass

    print(f"Parsed Nmap XML root element: {root.tag}")
    print_observations(observations)
    generate_defensive_report(observations)

    return observations


# ---------------------------------------------------------------------------
# Timing and output planning
# ---------------------------------------------------------------------------

def demonstrate_scan_planning() -> None:
    print_section("9. DEFENSIVE SCAN PLANNING")

    phases = [
        ("1. Scope", "Document authorized IP ranges, hosts, ports, and exclusions."),
        ("2. Pilot", "Scan a small representative subset first."),
        ("3. Baseline", "Record expected services and normal scan behavior."),
        ("4. Production scan", "Use a documented timing profile and maintenance window."),
        ("5. Parse", "Store XML for repeatable machine processing."),
        ("6. Interpret", "Separate observations from vulnerability conclusions."),
        ("7. Remediate", "Validate unnecessary exposure, configuration, and patching."),
        ("8. Retest", "Repeat the relevant scan and compare with the baseline."),
    ]

    for phase, description in phases:
        print(f"{phase}: {description}")


# ---------------------------------------------------------------------------
# Edge cases and common mistakes
# ---------------------------------------------------------------------------

def explain_edge_cases() -> None:
    print_section("10. EDGE CASES AND COMMON MISTAKES")

    mistakes = [
        (
            "Treating filtered as closed",
            "Filtering means the scanner lacks sufficient evidence; "
            "it does not prove that no service exists."
        ),
        (
            "Treating service detection as certainty",
            "Nmap's identification is an inference based on responses and "
            "fingerprints. Validate important findings independently."
        ),
        (
            "Assuming one scan is complete",
            "TCP, UDP, IPv4, IPv6, filtering, routing, and application behavior "
            "can produce different observations."
        ),
        (
            "Using -T5 indiscriminately",
            "Very aggressive timing can increase load and reduce reliability "
            "on networks with latency or packet loss."
        ),
        (
            "Running every NSE script",
            "NSE categories have different purposes and operational impact. "
            "Broad script execution is not automatically better."
        ),
        (
            "Parsing human-readable output with fragile regular expressions",
            "Structured XML is preferable for automation."
        ),
        (
            "Calling every open port vulnerable",
            "Exposure and vulnerability are different concepts."
        ),
        (
            "Ignoring scan time and date",
            "Services change. Reports need timestamps and scope information."
        ),
    ]

    for title, explanation in mistakes:
        print(f"\n{title}:")
        print(f"  {explanation}")


# ---------------------------------------------------------------------------
# Advanced interpretation helpers
# ---------------------------------------------------------------------------

def compare_service_inventory(
    before: list[HostObservation],
    after: list[HostObservation],
) -> None:
    """
    Compare two parsed Nmap inventories.

    This is useful for defensive change detection. It does not attempt to
    decide whether a change is malicious or vulnerable.
    """
    print_section("11. INVENTORY CHANGE DETECTION")

    def inventory(
        observations: list[HostObservation],
    ) -> dict[tuple[str, int, str], str]:
        result: dict[tuple[str, int, str], str] = {}

        for host in observations:
            for port in host.ports:
                if port.state == "open":
                    key = (host.address, port.port, port.protocol)
                    service = port.service or "unknown"
                    result[key] = service

        return result

    before_map = inventory(before)
    after_map = inventory(after)

    added = sorted(set(after_map) - set(before_map))
    removed = sorted(set(before_map) - set(after_map))

    changed = sorted(
        key for key in set(before_map) & set(after_map)
        if before_map[key] != after_map[key]
    )

    print("Newly observed open services:")
    if added:
        for key in added:
            print(f"  + {key}: {after_map[key]}")
    else:
        print("  None")

    print("No-longer-observed open services:")
    if removed:
        for key in removed:
            print(f"  - {key}: {before_map[key]}")
    else:
        print("  None")

    print("Changed service identification:")
    if changed:
        for key in changed:
            print(
                f"  * {key}: {before_map[key]} -> {after_map[key]}"
            )
    else:
        print("  None")


def demonstrate_complexity() -> None:
    print_section("12. PERFORMANCE CONSIDERATIONS")

    print("A scan's elapsed time depends on many interacting variables.")
    print_bullets([
        "Number of hosts.",
        "Number of ports.",
        "TCP versus UDP behavior.",
        "Latency and packet loss.",
        "Host discovery behavior.",
        "Service/version detection.",
        "NSE script execution.",
        "Timing and parallelism.",
        "Firewall behavior and retransmissions.",
    ])

    print("\nFor a simple inventory:")
    print("  Work roughly increases with the number of target hosts × ports examined.")

    print("\nFor service detection and NSE:")
    print("  The effective cost also depends on how many services respond and")
    print("  how much processing each selected probe or script performs.")

    print("\nOperational optimization:")
    print("  Narrow the scope first, then increase coverage deliberately.")
    print("  Store XML once and perform multiple offline analyses rather than")
    print("  repeatedly rescanning merely to regenerate reports.")


# ---------------------------------------------------------------------------
# Sample XML for offline learning
# ---------------------------------------------------------------------------

def create_sample_xml(path: Path) -> None:
    sample = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV -sC -oX scan.xml 192.168.1.10">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="lab-server"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Example Web Server" version="1.2"/>
        <script id="http-title" output="Example internal application"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    path.write_text(sample, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Advanced Nmap defensive scanning study program."
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Private/lab target for the optional live demonstration.",
    )

    parser.add_argument(
        "--demo-scan",
        action="store_true",
        help="Run a constrained live Nmap demonstration.",
    )

    parser.add_argument(
        "--parse-xml",
        metavar="FILE",
        help="Parse an existing Nmap XML file instead of performing a scan.",
    )

    parser.add_argument(
        "--sample-xml",
        metavar="FILE",
        help="Create a sample Nmap XML file for offline study.",
    )

    return parser.parse_args()


def main() -> int:
    args = parse_arguments()

    print("ADVANCED NMAP DEFENSIVE SCANNING STUDY")
    print("Timestamp:", dt.datetime.now().astimezone().isoformat())
    print("Python:", sys.version.split()[0])

    explain_fundamentals()
    explain_scan_types()
    explain_nse()
    explain_timing()
    explain_output_formats()
    demonstrate_scan_planning()
    explain_edge_cases()
    demonstrate_complexity()

    if args.sample_xml:
        sample_path = Path(args.sample_xml)
        create_sample_xml(sample_path)
        print_section("13. SAMPLE XML CREATED")
        print(f"Created: {sample_path.resolve()}")

    if args.parse_xml:
        print_section("14. XML PARSING DEMONSTRATION")
        try:
            observations = parse_nmap_xml(args.parse_xml)
            print_observations(observations)
            generate_defensive_report(observations)
        except (OSError, ET.ParseError, ValueError) as exc:
            print(f"Could not process XML: {exc}")
            return 1

    if args.demo_scan:
        run_safe_local_scan(args.host)

    print_section("15. STUDY CHECKLIST")
    print_bullets([
        "Can you explain the difference between open, closed, and filtered?",
        "Can you explain why service detection is an inference?",
        "Can you select NSE categories according to assessment scope?",
        "Can you explain why timing affects both speed and reliability?",
        "Can you choose XML when results need structured automation?",
        "Can you distinguish exposure from vulnerability?",
        "Can you compare two scan inventories without over-interpreting changes?",
        "Can you document scope, timing, timestamp, and scan configuration?"
    ])

    print("\nThe examples above are designed for authorized defensive assessment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
