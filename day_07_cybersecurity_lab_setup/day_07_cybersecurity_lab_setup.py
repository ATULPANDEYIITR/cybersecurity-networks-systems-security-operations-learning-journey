"""
Cybersecurity Lab Setup
=======================

A comprehensive, self-contained study script covering how to design and reason
about a safe cybersecurity laboratory using:

- Virtualization concepts
- VirtualBox and VMware concepts
- Kali Linux as an attacker/testing machine
- Windows as a defender/target machine
- Isolated virtual networks
- Snapshots and restoration
- Host-only and internal networking
- NAT and Internet exposure trade-offs
- Lab safety
- Machine hardening
- Logging and monitoring
- Detection engineering concepts
- Validation and troubleshooting
- Automation helpers for documenting a lab

This script does NOT configure hypervisors automatically because hypervisor APIs,
machine names, adapters, and security settings vary by host environment.

The executable examples simulate the concepts that should be understood before
building or operating a cybersecurity lab.

IMPORTANT SAFETY PRINCIPLE
--------------------------
Only perform security testing against systems, networks, virtual machines, and
accounts that you own or are explicitly authorized to test.

A properly designed lab should prevent accidental interaction with production
networks and unrelated Internet systems.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import random
import secrets
import shutil
import socket
import subprocess
import sys
import textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


# =============================================================================
# 1. FUNDAMENTALS: WHAT A CYBERSECURITY LAB IS
# =============================================================================

def print_section(title: str) -> None:
    """Print a visually separated educational section."""
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def demonstrate_lab_purpose() -> None:
    """
    A cybersecurity lab is a controlled environment used to learn, test, detect,
    and analyze security behavior without affecting production systems.

    A useful mental model is:

        Host Computer
            |
            +-- Hypervisor
                    |
                    +-- Attacker/Test VM
                    +-- Defender/Target VM
                    +-- Monitoring VM
                    |
                    +-- Isolated Virtual Network

    The host is the physical operating system. The hypervisor runs virtual
    machines. Virtual networking determines which systems can communicate.
    """

    print_section("1. Cybersecurity Lab Fundamentals")

    components = {
        "Host": "The physical computer running Windows, Linux, or macOS.",
        "Hypervisor": "Software such as VirtualBox or VMware that runs VMs.",
        "Virtual Machine": "An isolated software-defined computer.",
        "Attacker/Test VM": "A machine used to generate authorized test activity.",
        "Defender/Target VM": "A machine configured for learning detection and defense.",
        "Virtual Network": "A software-defined network connecting selected VMs.",
        "Snapshot": "A saved VM state used for restoration.",
        "Isolation Boundary": "Controls that prevent unintended communication.",
    }

    for name, description in components.items():
        print(f"{name:20} -> {description}")


# =============================================================================
# 2. VIRTUALIZATION CONCEPTS
# =============================================================================

class HypervisorType(str, Enum):
    """High-level hypervisor classifications."""

    TYPE_1 = "Type 1 - Bare-metal hypervisor"
    TYPE_2 = "Type 2 - Hosted hypervisor"


@dataclass
class VirtualMachineSpec:
    """
    A simplified representation of a virtual machine.

    Real hypervisors contain many additional configuration values.
    """

    name: str
    operating_system: str
    cpu_cores: int
    memory_mb: int
    disk_gb: int
    role: str
    powered_on: bool = False

    def validate(self) -> List[str]:
        """Validate common configuration constraints."""
        errors: List[str] = []

        if not self.name.strip():
            errors.append("VM name cannot be empty.")

        if self.cpu_cores < 1:
            errors.append("A VM must have at least one virtual CPU.")

        if self.memory_mb < 256:
            errors.append("Memory allocation is unrealistically small.")

        if self.disk_gb < 5:
            errors.append("Disk allocation is too small for most modern operating systems.")

        if not self.operating_system.strip():
            errors.append("Operating system must be specified.")

        return errors


def demonstrate_virtualization() -> None:
    """Demonstrate VM resource definitions and validation."""

    print_section("2. Virtualization")

    kali_vm = VirtualMachineSpec(
        name="kali-lab",
        operating_system="Kali Linux",
        cpu_cores=2,
        memory_mb=4096,
        disk_gb=40,
        role="Authorized security testing workstation",
    )

    windows_vm = VirtualMachineSpec(
        name="windows-defender-lab",
        operating_system="Windows",
        cpu_cores=2,
        memory_mb=4096,
        disk_gb=60,
        role="Defender and telemetry analysis target",
    )

    for vm in (kali_vm, windows_vm):
        print(f"\nVM: {vm.name}")
        print(f"Role: {vm.role}")
        print(f"Resources: {vm.cpu_cores} CPU, {vm.memory_mb} MB RAM, {vm.disk_gb} GB disk")

        validation_errors = vm.validate()
        if validation_errors:
            for error in validation_errors:
                print("Configuration issue:", error)
        else:
            print("Configuration validation: PASSED")

    print("\nHosted hypervisors commonly used for desktop labs:")
    print("- VirtualBox")
    print("- VMware Workstation family")
    print("\nThe key design concern is not the brand of hypervisor.")
    print("The critical concern is whether networking and isolation are configured safely.")


# =============================================================================
# 3. LAB ROLES AND MULTI-MACHINE DESIGN
# =============================================================================

@dataclass
class LabMachine:
    """Represents a logical machine in a cybersecurity lab."""

    name: str
    role: str
    operating_system: str
    services: List[str] = field(default_factory=list)
    network_names: List[str] = field(default_factory=list)
    snapshots: List[str] = field(default_factory=list)


def demonstrate_lab_roles() -> List[LabMachine]:
    """Create a representative lab architecture."""

    print_section("3. Attacker, Defender, and Monitoring Roles")

    machines = [
        LabMachine(
            name="kali-lab",
            role="Security testing workstation",
            operating_system="Kali Linux",
            services=["SSH client", "Browser", "Security testing tools"],
            network_names=["lab-internal"],
            snapshots=["clean-install"],
        ),
        LabMachine(
            name="windows-defender",
            role="Defender and monitored endpoint",
            operating_system="Windows",
            services=["Windows Event Logging", "Defender", "Sysmon if intentionally installed"],
            network_names=["lab-internal"],
            snapshots=["clean-baseline", "logging-enabled"],
        ),
        LabMachine(
            name="monitoring-node",
            role="Centralized log collection and analysis",
            operating_system="Linux",
            services=["Log collection", "Time synchronization", "Analysis tools"],
            network_names=["lab-internal"],
            snapshots=["clean-monitoring-baseline"],
        ),
    ]

    for machine in machines:
        print(f"\n{machine.name}")
        print(f"  Role: {machine.role}")
        print(f"  OS: {machine.operating_system}")
        print(f"  Networks: {', '.join(machine.network_names)}")
        print(f"  Snapshots: {', '.join(machine.snapshots)}")

    return machines


# =============================================================================
# 4. VIRTUAL NETWORKING FUNDAMENTALS
# =============================================================================

class NetworkMode(str, Enum):
    """
    Common virtualization networking modes.

    Names can differ slightly between hypervisor products.
    """

    NAT = "NAT"
    NAT_NETWORK = "NAT Network"
    HOST_ONLY = "Host-Only"
    INTERNAL = "Internal Network"
    BRIDGED = "Bridged"


@dataclass
class VirtualNetwork:
    """A simplified virtual network model."""

    name: str
    mode: NetworkMode
    subnet: ipaddress.IPv4Network
    internet_access: bool
    host_access: bool
    lan_access: bool


def demonstrate_network_modes() -> List[VirtualNetwork]:
    """
    Explain major network modes.

    Bridged networking often exposes a VM to the same network as the host.
    This can be appropriate for controlled enterprise labs but is generally a
    poor default for an isolated beginner security lab.
    """

    print_section("4. Virtual Network Modes")

    networks = [
        VirtualNetwork(
            name="isolated-internal",
            mode=NetworkMode.INTERNAL,
            subnet=ipaddress.ip_network("10.10.10.0/24"),
            internet_access=False,
            host_access=False,
            lan_access=False,
        ),
        VirtualNetwork(
            name="host-management",
            mode=NetworkMode.HOST_ONLY,
            subnet=ipaddress.ip_network("192.168.56.0/24"),
            internet_access=False,
            host_access=True,
            lan_access=False,
        ),
        VirtualNetwork(
            name="temporary-update-network",
            mode=NetworkMode.NAT,
            subnet=ipaddress.ip_network("10.0.2.0/24"),
            internet_access=True,
            host_access=False,
            lan_access=False,
        ),
        VirtualNetwork(
            name="bridged-example",
            mode=NetworkMode.BRIDGED,
            subnet=ipaddress.ip_network("192.168.1.0/24"),
            internet_access=True,
            host_access=True,
            lan_access=True,
        ),
    ]

    for network in networks:
        print(f"\nNetwork: {network.name}")
        print(f"  Mode: {network.mode.value}")
        print(f"  Subnet: {network.subnet}")
        print(f"  Internet access: {network.internet_access}")
        print(f"  Host access: {network.host_access}")
        print(f"  Physical LAN access: {network.lan_access}")

    print("\nSafety interpretation:")
    print("- Internal networking is useful for strongly isolated multi-VM exercises.")
    print("- Host-only networking permits controlled host-to-lab administration.")
    print("- NAT can provide outbound connectivity for legitimate updates.")
    print("- Bridged mode can expose a VM to a physical network and should not be a")
    print("  default choice for intentionally vulnerable training systems.")

    return networks


# =============================================================================
# 5. IP ADDRESSING AND SUBNET VALIDATION
# =============================================================================

@dataclass
class NetworkEndpoint:
    """Represents a machine interface assigned to a virtual network."""

    machine_name: str
    interface_name: str
    address: ipaddress.IPv4Address
    network: ipaddress.IPv4Network


def validate_endpoint(endpoint: NetworkEndpoint) -> bool:
    """Check whether an endpoint address belongs to its declared subnet."""
    return endpoint.address in endpoint.network


def detect_duplicate_addresses(endpoints: Iterable[NetworkEndpoint]) -> List[ipaddress.IPv4Address]:
    """Detect duplicate addresses assigned within a modeled lab."""
    seen: Set[ipaddress.IPv4Address] = set()
    duplicates: Set[ipaddress.IPv4Address] = set()

    for endpoint in endpoints:
        if endpoint.address in seen:
            duplicates.add(endpoint.address)
        seen.add(endpoint.address)

    return sorted(duplicates)


def demonstrate_ip_addressing() -> None:
    """Demonstrate safe private addressing and common configuration mistakes."""

    print_section("5. IP Addressing and Subnet Design")

    isolated_subnet = ipaddress.ip_network("10.10.10.0/24")

    endpoints = [
        NetworkEndpoint(
            machine_name="kali-lab",
            interface_name="eth0",
            address=ipaddress.ip_address("10.10.10.10"),
            network=isolated_subnet,
        ),
        NetworkEndpoint(
            machine_name="windows-defender",
            interface_name="Ethernet0",
            address=ipaddress.ip_address("10.10.10.20"),
            network=isolated_subnet,
        ),
        NetworkEndpoint(
            machine_name="monitoring-node",
            interface_name="eth0",
            address=ipaddress.ip_address("10.10.10.30"),
            network=isolated_subnet,
        ),
    ]

    for endpoint in endpoints:
        result = validate_endpoint(endpoint)
        print(
            f"{endpoint.machine_name:20} "
            f"{endpoint.address} in {endpoint.network}: {result}"
        )

    duplicates = detect_duplicate_addresses(endpoints)
    print("Duplicate addresses:", duplicates if duplicates else "None")

    invalid_endpoint = NetworkEndpoint(
        machine_name="misconfigured-vm",
        interface_name="eth0",
        address=ipaddress.ip_address("192.168.1.25"),
        network=isolated_subnet,
    )

    print(
        f"Misconfiguration check: {invalid_endpoint.address} in "
        f"{invalid_endpoint.network}: {validate_endpoint(invalid_endpoint)}"
    )

    print("\nCommon addressing mistakes:")
    print("- Assigning the same static IP address to multiple VMs.")
    print("- Using an address outside the configured subnet.")
    print("- Accidentally configuring a default gateway on an isolated network.")
    print("- Connecting a vulnerable VM to both an isolated and bridged adapter.")
    print("- Reusing a subnet that conflicts with existing host VPN or LAN routes.")


# =============================================================================
# 6. CONNECTIVITY POLICY MODEL
# =============================================================================

class ConnectivityPolicy:
    """
    A simplified allow-list connectivity model.

    In production systems, real enforcement is performed by switches, firewalls,
    hypervisors, operating systems, and network security controls.
    """

    def __init__(self) -> None:
        self.allowed_connections: Set[Tuple[str, str]] = set()

    def allow(self, source: str, destination: str) -> None:
        self.allowed_connections.add((source, destination))

    def can_connect(self, source: str, destination: str) -> bool:
        return (source, destination) in self.allowed_connections


def demonstrate_connectivity_policy() -> None:
    """Demonstrate why explicit communication boundaries are valuable."""

    print_section("6. Connectivity Policies")

    policy = ConnectivityPolicy()

    policy.allow("kali-lab", "windows-defender")
    policy.allow("windows-defender", "monitoring-node")
    policy.allow("monitoring-node", "windows-defender")

    attempts = [
        ("kali-lab", "windows-defender"),
        ("kali-lab", "monitoring-node"),
        ("windows-defender", "monitoring-node"),
        ("windows-defender", "internet"),
    ]

    for source, destination in attempts:
        status = "ALLOWED" if policy.can_connect(source, destination) else "BLOCKED"
        print(f"{source:20} -> {destination:20} {status}")

    print("\nPrinciple demonstrated: least connectivity.")
    print("A machine should only have network paths required for the lab objective.")


# =============================================================================
# 7. SNAPSHOTS AND STATE MANAGEMENT
# =============================================================================

@dataclass
class Snapshot:
    """Metadata describing a saved virtual machine state."""

    name: str
    created_at: str
    description: str


class SnapshotManager:
    """
    A conceptual snapshot manager.

    Real snapshots are created by the hypervisor and may consume significant
    disk space. Long snapshot chains can also affect storage performance.
    """

    def __init__(self, machine_name: str) -> None:
        self.machine_name = machine_name
        self.snapshots: List[Snapshot] = []

    def create(self, name: str, description: str) -> Snapshot:
        snapshot = Snapshot(
            name=name,
            created_at=datetime.now(timezone.utc).isoformat(),
            description=description,
        )
        self.snapshots.append(snapshot)
        return snapshot

    def restore_target(self, name: str) -> Optional[Snapshot]:
        for snapshot in self.snapshots:
            if snapshot.name == name:
                return snapshot
        return None


def demonstrate_snapshots() -> None:
    """Demonstrate baseline and experiment snapshot planning."""

    print_section("7. Snapshots and Restoration")

    manager = SnapshotManager("windows-defender")

    manager.create(
        "clean-install",
        "Fresh operating system with no lab experiment changes.",
    )
    manager.create(
        "defender-baseline",
        "Security controls and telemetry configured for the lab.",
    )
    manager.create(
        "pre-experiment",
        "Known-good state immediately before a controlled experiment.",
    )

    print("Snapshots created:")
    for snapshot in manager.snapshots:
        print(f"- {snapshot.name}: {snapshot.description}")

    target = manager.restore_target("pre-experiment")

    if target:
        print(f"\nRestore target found: {target.name}")
    else:
        print("\nRestore target was not found.")

    print("\nSnapshot best practices:")
    print("- Create a clean baseline before major configuration changes.")
    print("- Use descriptive names tied to experiment stages.")
    print("- Avoid treating snapshots as permanent backups.")
    print("- Monitor available disk space.")
    print("- Consolidate or remove unnecessary snapshot chains.")
    print("- Verify that restoring a snapshot produces the expected network state.")


# =============================================================================
# 8. LAB SAFETY AND AUTHORIZATION
# =============================================================================

class SafetyViolation(ValueError):
    """Raised when a modeled lab configuration violates a safety rule."""


@dataclass
class LabSafetyConfiguration:
    """
    Safety settings for a conceptual cybersecurity lab.

    These settings represent design checks rather than direct hypervisor control.
    """

    isolated_network: bool
    vulnerable_machine_bridged: bool
    port_forwarding_enabled: bool
    host_shared_folders_enabled: bool
    clipboard_bidirectional: bool
    internet_access_enabled: bool
    explicit_authorization: bool


def evaluate_lab_safety(config: LabSafetyConfiguration) -> List[str]:
    """Return safety findings for a modeled lab configuration."""

    findings: List[str] = []

    if not config.explicit_authorization:
        findings.append("Security testing must have explicit authorization.")

    if not config.isolated_network:
        findings.append("Lab network is not isolated.")

    if config.vulnerable_machine_bridged:
        findings.append(
            "A vulnerable machine is bridged to a physical network, increasing exposure risk."
        )

    if config.port_forwarding_enabled:
        findings.append(
            "Port forwarding can expose a VM through the host and should be justified."
        )

    if config.host_shared_folders_enabled:
        findings.append(
            "Host shared folders reduce isolation and can expose host files to the VM."
        )

    if config.clipboard_bidirectional:
        findings.append(
            "Bidirectional clipboard sharing can move untrusted data between host and VM."
        )

    if config.internet_access_enabled:
        findings.append(
            "Internet access should be limited to required activities such as updates."
        )

    return findings


def demonstrate_lab_safety() -> None:
    """Evaluate a safe and unsafe example configuration."""

    print_section("8. Lab Safety")

    safer_configuration = LabSafetyConfiguration(
        isolated_network=True,
        vulnerable_machine_bridged=False,
        port_forwarding_enabled=False,
        host_shared_folders_enabled=False,
        clipboard_bidirectional=False,
        internet_access_enabled=False,
        explicit_authorization=True,
    )

    unsafe_configuration = LabSafetyConfiguration(
        isolated_network=False,
        vulnerable_machine_bridged=True,
        port_forwarding_enabled=True,
        host_shared_folders_enabled=True,
        clipboard_bidirectional=True,
        internet_access_enabled=True,
        explicit_authorization=False,
    )

    for name, config in [
        ("Safer Example", safer_configuration),
        ("Unsafe Example", unsafe_configuration),
    ]:
        findings = evaluate_lab_safety(config)
        print(f"\n{name}")
        if not findings:
            print("No modeled safety findings.")
        else:
            for finding in findings:
                print("-", finding)


# =============================================================================
# 9. KALI LINUX AS A TESTING WORKSTATION
# =============================================================================

@dataclass
class ToolCategory:
    """A conceptual category of security tools."""

    category: str
    purpose: str
    lab_use: str


def demonstrate_kali_role() -> None:
    """
    Kali Linux is a security-focused Linux distribution.

    Installing a security distribution does not itself provide authorization to
    test systems. Tools must be used only in an approved environment.
    """

    print_section("9. Kali Linux in the Lab")

    categories = [
        ToolCategory(
            "Network discovery",
            "Identify hosts and services in authorized environments.",
            "Verify which lab machines are visible on an isolated subnet.",
        ),
        ToolCategory(
            "Packet analysis",
            "Inspect network traffic and protocols.",
            "Compare expected and observed lab communication.",
        ),
        ToolCategory(
            "Web testing",
            "Evaluate authorized web applications.",
            "Study intentionally deployed training applications.",
        ),
        ToolCategory(
            "Password auditing",
            "Evaluate password strength under authorization.",
            "Test known lab accounts and controlled sample hashes.",
        ),
        ToolCategory(
            "Forensics",
            "Analyze files, metadata, and evidence artifacts.",
            "Practice investigation of intentionally generated lab events.",
        ),
    ]

    for category in categories:
        print(f"\n{category.category}")
        print("  Purpose:", category.purpose)
        print("  Lab use:", category.lab_use)

    print("\nImportant distinction:")
    print("Kali Linux is a platform containing many tools. Each tool has different")
    print("capabilities, risks, legal requirements, and appropriate use cases.")


# =============================================================================
# 10. WINDOWS AS A DEFENDER AND TELEMETRY TARGET
# =============================================================================

@dataclass
class SecurityEvent:
    """Represents a simplified security-relevant event."""

    timestamp: str
    host: str
    event_type: str
    user: str
    details: Dict[str, str]


class EventStore:
    """Stores and searches simulated security events."""

    def __init__(self) -> None:
        self.events: List[SecurityEvent] = []

    def add(self, event: SecurityEvent) -> None:
        self.events.append(event)

    def find_by_type(self, event_type: str) -> List[SecurityEvent]:
        return [event for event in self.events if event.event_type == event_type]


def demonstrate_defender_machine() -> EventStore:
    """
    Demonstrate the concept of collecting telemetry from a defender machine.

    Real Windows event IDs and logging behavior depend on operating system
    version, audit policy, and installed telemetry tools.
    """

    print_section("10. Windows Defender Machine and Telemetry")

    store = EventStore()

    events = [
        SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host="windows-defender",
            event_type="process_start",
            user="lab-user",
            details={
                "process": "example.exe",
                "parent": "explorer.exe",
            },
        ),
        SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host="windows-defender",
            event_type="authentication",
            user="lab-user",
            details={
                "result": "success",
                "source": "local",
            },
        ),
        SecurityEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            host="windows-defender",
            event_type="network_connection",
            user="SYSTEM",
            details={
                "destination": "10.10.10.30",
                "protocol": "TCP",
            },
        ),
    ]

    for event in events:
        store.add(event)

    print("Collected events:")
    for event in store.events:
        print(
            f"- {event.timestamp} | {event.host} | "
            f"{event.event_type} | {event.details}"
        )

    return store


# =============================================================================
# 11. SIMPLE DETECTION ENGINEERING
# =============================================================================

@dataclass
class DetectionRule:
    """A simple rule for detecting patterns in simulated events."""

    name: str
    event_type: str
    required_details: Dict[str, str]

    def matches(self, event: SecurityEvent) -> bool:
        if event.event_type != self.event_type:
            return False

        for key, expected_value in self.required_details.items():
            if event.details.get(key) != expected_value:
                return False

        return True


def demonstrate_detection_engineering(event_store: EventStore) -> None:
    """
    Demonstrate the relationship between:

    Activity -> Telemetry -> Detection Rule -> Alert

    Detection engineering should consider false positives and false negatives.
    """

    print_section("11. Detection Engineering")

    rule = DetectionRule(
        name="Connection to Monitoring Node",
        event_type="network_connection",
        required_details={
            "destination": "10.10.10.30",
            "protocol": "TCP",
        },
    )

    matches = [
        event for event in event_store.events
        if rule.matches(event)
    ]

    print("Detection rule:", rule.name)
    print("Matches:", len(matches))

    for match in matches:
        print(
            f"- Host={match.host}, Type={match.event_type}, "
            f"Details={match.details}"
        )

    print("\nDetection limitations:")
    print("- Missing telemetry can prevent detection.")
    print("- Overly strict rules can miss legitimate variations.")
    print("- Overly broad rules can produce excessive false positives.")
    print("- Timestamps should be synchronized across lab machines.")


# =============================================================================
# 12. PASSWORD HANDLING AND CREDENTIAL SAFETY
# =============================================================================

def hash_password_demo(password: str, salt: bytes) -> str:
    """
    Demonstrate a password hashing primitive.

    PBKDF2 is used here only to illustrate the concept. Production authentication
    systems should use modern, reviewed password hashing implementations and
    appropriate parameters.
    """

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
    )

    return derived_key.hex()


def demonstrate_password_safety() -> None:
    """Demonstrate why plaintext passwords should not be stored."""

    print_section("12. Credential and Password Safety")

    lab_password = "ExampleLabPassword123!"
    salt = secrets.token_bytes(16)

    password_hash = hash_password_demo(lab_password, salt)

    print("Password hashing demonstration")
    print("Salt length:", len(salt), "bytes")
    print("Derived hash prefix:", password_hash[:24] + "...")

    same_password_same_salt = hash_password_demo(lab_password, salt)
    different_password_same_salt = hash_password_demo("DifferentPassword!", salt)

    print("Same password matches:", password_hash == same_password_same_salt)
    print("Different password matches:", password_hash == different_password_same_salt)

    print("\nLab credential practices:")
    print("- Do not reuse personal or production passwords in training VMs.")
    print("- Use unique lab-only accounts.")
    print("- Assume intentionally vulnerable lab systems may be compromised.")
    print("- Rotate or reset credentials when restoring experiment environments.")


# =============================================================================
# 13. FILE INTEGRITY MONITORING CONCEPTS
# =============================================================================

def calculate_file_sha256(path: Path) -> str:
    """Calculate SHA-256 for a local file."""

    digest = hashlib.sha256()

    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()


def demonstrate_file_integrity() -> None:
    """Create a temporary file and demonstrate integrity checking."""

    print_section("13. File Integrity Monitoring")

    temporary_directory = Path.cwd() / "cyber_lab_demo_temp"
    temporary_directory.mkdir(exist_ok=True)

    sample_file = temporary_directory / "sample.txt"

    try:
        sample_file.write_text(
            "Baseline content for an authorized cybersecurity laboratory.\n",
            encoding="utf-8",
        )

        baseline_hash = calculate_file_sha256(sample_file)

        print("Baseline SHA-256:", baseline_hash)

        sample_file.write_text(
            "Baseline content for an authorized cybersecurity laboratory.\n"
            "Authorized configuration change recorded.\n",
            encoding="utf-8",
        )

        changed_hash = calculate_file_sha256(sample_file)

        print("Changed SHA-256: ", changed_hash)
        print("Integrity changed:", baseline_hash != changed_hash)

    finally:
        if sample_file.exists():
            sample_file.unlink()

        if temporary_directory.exists():
            temporary_directory.rmdir()


# =============================================================================
# 14. TIME SYNCHRONIZATION AND LOG CORRELATION
# =============================================================================

def demonstrate_time_correlation() -> None:
    """
    Demonstrate why synchronized clocks matter.

    Incident investigation often requires correlating events across machines.
    """

    print_section("14. Time Synchronization and Log Correlation")

    base_time = datetime.now(timezone.utc)

    events = [
        ("kali-lab", base_time),
        ("windows-defender", base_time),
        ("monitoring-node", base_time),
    ]

    for machine, event_time in events:
        print(f"{machine:20} {event_time.isoformat()}")

    print("\nIf clocks differ significantly, event ordering can become misleading.")
    print("A controlled lab should define how time is synchronized and recorded.")


# =============================================================================
# 15. SAFE NETWORK SERVICE VALIDATION
# =============================================================================

def safe_local_tcp_check(host: str, port: int, timeout: float = 1.0) -> str:
    """
    Check whether a single explicitly specified TCP endpoint accepts a connection.

    This function is intentionally limited to one host and one port supplied by
    the caller. It is not a network scanner.

    Use only against systems you own or are authorized to test.
    """

    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "reachable"
    except ConnectionRefusedError:
        return "connection refused"
    except socket.timeout:
        return "timeout"
    except OSError as error:
        return f"connection error: {error.__class__.__name__}"


def demonstrate_service_validation() -> None:
    """
    Demonstrate input validation without probing arbitrary systems.

    The function is not executed against external hosts.
    """

    print_section("15. Safe Service Validation")

    test_cases = [
        ("127.0.0.1", 1),
        ("127.0.0.1", 65535),
    ]

    for host, port in test_cases:
        try:
            result = safe_local_tcp_check(host, port, timeout=0.1)
            print(f"{host}:{port} -> {result}")
        except ValueError as error:
            print(f"{host}:{port} -> invalid input: {error}")

    try:
        safe_local_tcp_check("127.0.0.1", 70000)
    except ValueError as error:
        print("Invalid port example:", error)


# =============================================================================
# 16. FIREWALL CONCEPTUAL MODEL
# =============================================================================

class Action(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class FirewallRule:
    """A simplified allow/deny firewall rule."""

    source_network: ipaddress.IPv4Network
    destination_network: ipaddress.IPv4Network
    protocol: str
    action: Action


class SimpleFirewall:
    """
    Educational firewall model.

    Rules are evaluated in order. The first matching rule determines the result.
    """

    def __init__(self, default_action: Action = Action.DENY) -> None:
        self.rules: List[FirewallRule] = []
        self.default_action = default_action

    def add_rule(self, rule: FirewallRule) -> None:
        self.rules.append(rule)

    def evaluate(
        self,
        source: ipaddress.IPv4Address,
        destination: ipaddress.IPv4Address,
        protocol: str,
    ) -> Action:
        for rule in self.rules:
            if (
                source in rule.source_network
                and destination in rule.destination_network
                and rule.protocol.lower() == protocol.lower()
            ):
                return rule.action

        return self.default_action


def demonstrate_firewall_model() -> None:
    """Demonstrate default-deny and explicit allow rules."""

    print_section("16. Firewall Model")

    firewall = SimpleFirewall(default_action=Action.DENY)

    firewall.add_rule(
        FirewallRule(
            source_network=ipaddress.ip_network("10.10.10.0/24"),
            destination_network=ipaddress.ip_network("10.10.10.0/24"),
            protocol="tcp",
            action=Action.ALLOW,
        )
    )

    scenarios = [
        ("10.10.10.10", "10.10.10.20", "tcp"),
        ("10.10.10.10", "8.8.8.8", "tcp"),
        ("192.168.1.10", "10.10.10.20", "tcp"),
    ]

    for source, destination, protocol in scenarios:
        result = firewall.evaluate(
            ipaddress.ip_address(source),
            ipaddress.ip_address(destination),
            protocol,
        )
        print(f"{source} -> {destination} ({protocol}) = {result.value}")


# =============================================================================
# 17. LAB CONFIGURATION DOCUMENTATION
# =============================================================================

@dataclass
class LabConfiguration:
    """Structured documentation for a cybersecurity lab."""

    lab_name: str
    created_at: str
    host_os: str
    hypervisor: str
    machines: List[LabMachine]
    networks: List[Dict[str, str]]
    safety_notes: List[str]


def create_lab_configuration(
    machines: List[LabMachine],
    networks: List[VirtualNetwork],
) -> LabConfiguration:
    """Build a serializable lab configuration record."""

    return LabConfiguration(
        lab_name="Isolated Cybersecurity Training Lab",
        created_at=datetime.now(timezone.utc).isoformat(),
        host_os=platform.platform(),
        hypervisor="VirtualBox or VMware, depending on local installation",
        machines=machines,
        networks=[
            {
                "name": network.name,
                "mode": network.mode.value,
                "subnet": str(network.subnet),
                "internet_access": str(network.internet_access),
                "host_access": str(network.host_access),
                "lan_access": str(network.lan_access),
            }
            for network in networks
        ],
        safety_notes=[
            "Use only systems and accounts you own or are authorized to test.",
            "Keep intentionally vulnerable systems off bridged physical networks.",
            "Use snapshots before controlled experiments.",
            "Limit Internet connectivity to necessary administrative tasks.",
            "Avoid exposing VM services through unnecessary port forwarding.",
            "Avoid sharing sensitive host directories with untrusted lab machines.",
        ],
    )


def save_lab_configuration(configuration: LabConfiguration, path: Path) -> None:
    """Save lab documentation as JSON."""

    serializable = asdict(configuration)

    with path.open("w", encoding="utf-8") as file_handle:
        json.dump(serializable, file_handle, indent=2)


def demonstrate_configuration_documentation(
    machines: List[LabMachine],
    networks: List[VirtualNetwork],
) -> None:
    """Demonstrate reproducible lab documentation."""

    print_section("17. Lab Documentation")

    configuration = create_lab_configuration(machines, networks)

    output_path = Path.cwd() / "lab_configuration_example.json"

    try:
        save_lab_configuration(configuration, output_path)

        print("Configuration written to:", output_path.name)
        print("Documented machines:", len(configuration.machines))
        print("Documented networks:", len(configuration.networks))

        loaded = json.loads(output_path.read_text(encoding="utf-8"))
        print("Loaded lab name:", loaded["lab_name"])

    finally:
        if output_path.exists():
            output_path.unlink()


# =============================================================================
# 18. RESOURCE PLANNING
# =============================================================================

@dataclass
class HostResources:
    """Host resource inventory used for simple planning."""

    total_cpu_cores: int
    total_memory_mb: int
    available_disk_gb: int


def estimate_lab_resources(
    host: HostResources,
    machines: List[VirtualMachineSpec],
) -> Dict[str, object]:
    """
    Estimate whether requested VM resources fit within a conservative budget.

    CPU is intentionally not treated as a strict reservation because modern
    hypervisors schedule virtual CPUs differently from physical CPUs.
    """

    requested_cpu = sum(vm.cpu_cores for vm in machines)
    requested_memory = sum(vm.memory_mb for vm in machines)
    requested_disk = sum(vm.disk_gb for vm in machines)

    recommended_memory_budget = int(host.total_memory_mb * 0.70)
    recommended_disk_budget = int(host.available_disk_gb * 0.80)

    return {
        "requested_cpu_cores": requested_cpu,
        "requested_memory_mb": requested_memory,
        "requested_disk_gb": requested_disk,
        "recommended_memory_budget_mb": recommended_memory_budget,
        "recommended_disk_budget_gb": recommended_disk_budget,
        "memory_budget_ok": requested_memory <= recommended_memory_budget,
        "disk_budget_ok": requested_disk <= recommended_disk_budget,
        "cpu_overcommit_ratio": (
            requested_cpu / host.total_cpu_cores
            if host.total_cpu_cores > 0
            else None
        ),
    }


def demonstrate_resource_planning() -> None:
    """Demonstrate capacity planning before creating multiple VMs."""

    print_section("18. Resource Planning")

    host = HostResources(
        total_cpu_cores=max(os.cpu_count() or 1, 1),
        total_memory_mb=16_000,
        available_disk_gb=200,
    )

    machines = [
        VirtualMachineSpec("kali-lab", "Kali Linux", 2, 4096, 40, "Testing"),
        VirtualMachineSpec("windows-defender", "Windows", 2, 4096, 60, "Defending"),
        VirtualMachineSpec("monitoring-node", "Linux", 2, 2048, 30, "Monitoring"),
    ]

    estimate = estimate_lab_resources(host, machines)

    for key, value in estimate.items():
        print(f"{key}: {value}")

    print("\nPerformance considerations:")
    print("- Running too many VMs can cause host swapping and severe slowdown.")
    print("- Snapshot storage can significantly increase disk usage.")
    print("- Dynamic virtual disks may grow over time.")
    print("- SSD storage generally improves VM responsiveness.")
    print("- Telemetry collection and monitoring can consume CPU and memory.")


# =============================================================================
# 19. NETWORK ISOLATION TESTING LOGIC
# =============================================================================

@dataclass
class NetworkAttachment:
    """Represents one VM attachment to one modeled network."""

    machine: str
    network: str


def build_connectivity_graph(
    attachments: List[NetworkAttachment],
) -> Dict[str, Set[str]]:
    """
    Build a graph where machines attached to the same virtual network can
    potentially communicate.

    This is a simplified model and does not replace firewall or hypervisor rules.
    """

    graph: Dict[str, Set[str]] = {}

    by_network: Dict[str, List[str]] = {}

    for attachment in attachments:
        by_network.setdefault(attachment.network, []).append(attachment.machine)
        graph.setdefault(attachment.machine, set())

    for machines in by_network.values():
        for source in machines:
            for destination in machines:
                if source != destination:
                    graph[source].add(destination)

    return graph


def demonstrate_isolation_graph() -> None:
    """Show how multiple adapters can unintentionally create connectivity paths."""

    print_section("19. Isolation and Multi-Adapter Risks")

    safe_attachments = [
        NetworkAttachment("kali-lab", "lab-internal"),
        NetworkAttachment("windows-defender", "lab-internal"),
        NetworkAttachment("monitoring-node", "lab-internal"),
    ]

    unsafe_attachments = safe_attachments + [
        NetworkAttachment("windows-defender", "physical-lan"),
        NetworkAttachment("host-gateway", "physical-lan"),
    ]

    for label, attachments in [
        ("Isolated Design", safe_attachments),
        ("Expanded Exposure Design", unsafe_attachments),
    ]:
        print(f"\n{label}")

        graph = build_connectivity_graph(attachments)

        for machine, peers in graph.items():
            print(f"{machine:20} -> {sorted(peers)}")

    print("\nA second adapter can create an unintended path between networks.")
    print("Isolation must be evaluated across every adapter, route, gateway, and")
    print("service configuration rather than by looking at a single VM setting.")


# =============================================================================
# 20. ROUTING CONCEPTS
# =============================================================================

@dataclass
class Route:
    """A simplified IPv4 routing table entry."""

    destination: ipaddress.IPv4Network
    next_hop: Optional[ipaddress.IPv4Address]
    interface: str
    metric: int


def choose_route(
    routes: List[Route],
    destination: ipaddress.IPv4Address,
) -> Optional[Route]:
    """
    Apply longest-prefix matching and then metric comparison.

    This is a simplified model of common IP routing behavior.
    """

    matching_routes = [
        route for route in routes
        if destination in route.destination
    ]

    if not matching_routes:
        return None

    matching_routes.sort(
        key=lambda route: (
            route.destination.prefixlen,
            -route.metric,
        ),
        reverse=True,
    )

    return matching_routes[0]


def demonstrate_routing() -> None:
    """Demonstrate why default routes matter for lab isolation."""

    print_section("20. Routing and Default Gateways")

    routes = [
        Route(
            destination=ipaddress.ip_network("10.10.10.0/24"),
            next_hop=None,
            interface="lab0",
            metric=10,
        ),
        Route(
            destination=ipaddress.ip_network("0.0.0.0/0"),
            next_hop=ipaddress.ip_address("192.168.56.1"),
            interface="management0",
            metric=100,
        ),
    ]

    destinations = [
        ipaddress.ip_address("10.10.10.20"),
        ipaddress.ip_address("8.8.8.8"),
    ]

    for destination in destinations:
        route = choose_route(routes, destination)

        if route:
            print(
                f"{destination} -> {route.destination} "
                f"via {route.interface}, next hop={route.next_hop}"
            )

    print("\nIsolation lesson:")
    print("An isolated interface may be safe by itself, but another interface with a")
    print("default route can still provide external connectivity.")


# =============================================================================
# 21. INPUT VALIDATION FOR LAB AUTOMATION
# =============================================================================

def validate_lab_name(name: str) -> str:
    """
    Validate a simple lab identifier.

    Avoid accepting arbitrary shell content when building automation that later
    interacts with hypervisor command-line tools.
    """

    allowed = set(
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-_"
    )

    if not name:
        raise ValueError("Lab name cannot be empty.")

    if len(name) > 64:
        raise ValueError("Lab name is too long.")

    if any(character not in allowed for character in name):
        raise ValueError(
            "Lab name may contain only letters, numbers, hyphens, and underscores."
        )

    return name


def demonstrate_input_validation() -> None:
    """Demonstrate safe handling of automation input."""

    print_section("21. Automation Input Validation")

    examples = [
        "cyber_lab_01",
        "windows-defender",
        "lab name with spaces",
        "../../unexpected",
    ]

    for example in examples:
        try:
            validated = validate_lab_name(example)
            print(f"{example!r} -> accepted as {validated!r}")
        except ValueError as error:
            print(f"{example!r} -> rejected: {error}")

    print("\nSecurity principle:")
    print("Validate input before passing it to external commands, file paths, APIs,")
    print("or hypervisor management tools.")


# =============================================================================
# 22. SAFE SUBPROCESS DESIGN
# =============================================================================

def demonstrate_safe_subprocess_design() -> None:
    """
    Demonstrate subprocess safety principles without executing hypervisor commands.

    Avoid shell=True when unnecessary. Prefer argument lists.
    """

    print_section("22. Safe Subprocess Design")

    command = ["echo", "Lab automation should validate external command arguments."]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    print("Command output:", completed.stdout.strip())

    print("\nSafer automation practices:")
    print("- Prefer argument lists over shell command strings.")
    print("- Validate machine and snapshot names.")
    print("- Use absolute paths when appropriate.")
    print("- Check return codes.")
    print("- Log administrative actions.")
    print("- Avoid embedding credentials in command arguments.")


# =============================================================================
# 23. DEBUGGING A CYBERSECURITY LAB
# =============================================================================

@dataclass
class TroubleshootingCase:
    """A common lab problem with a structured debugging approach."""

    symptom: str
    possible_causes: List[str]
    checks: List[str]


def demonstrate_troubleshooting() -> None:
    """Provide systematic debugging cases."""

    print_section("23. Lab Troubleshooting")

    cases = [
        TroubleshootingCase(
            symptom="Two VMs cannot communicate",
            possible_causes=[
                "Different virtual networks",
                "Incorrect IP address",
                "Host firewall or guest firewall rule",
                "Network adapter disabled",
            ],
            checks=[
                "Verify adapter attachment names",
                "Verify interface status",
                "Verify IP address and subnet",
                "Review routing tables",
                "Review guest firewall rules",
            ],
        ),
        TroubleshootingCase(
            symptom="VM unexpectedly reaches the Internet",
            possible_causes=[
                "NAT adapter attached",
                "Bridged adapter attached",
                "Unexpected default route",
            ],
            checks=[
                "Inspect all VM network adapters",
                "Inspect guest routing table",
                "Remove unnecessary gateways",
                "Verify hypervisor network mode",
            ],
        ),
        TroubleshootingCase(
            symptom="Snapshot restore does not produce expected behavior",
            possible_causes=[
                "External dependencies changed",
                "Dynamic network configuration changed",
                "Snapshot was taken after configuration drift",
            ],
            checks=[
                "Document snapshot contents",
                "Verify network settings",
                "Check time and DHCP behavior",
                "Create a known clean baseline snapshot",
            ],
        ),
    ]

    for case in cases:
        print(f"\nSymptom: {case.symptom}")
        print("Possible causes:")
        for cause in case.possible_causes:
            print("  -", cause)

        print("Checks:")
        for check in case.checks:
            print("  -", check)


# =============================================================================
# 24. COMMON MISTAKES AND DESIGN TRADE-OFFS
# =============================================================================

def demonstrate_common_mistakes() -> None:
    """Explain common lab mistakes and their implications."""

    print_section("24. Common Mistakes and Trade-Offs")

    mistakes = {
        "Using bridged networking by default": (
            "Convenient connectivity but reduced isolation and possible exposure "
            "to physical network systems."
        ),
        "Running experiments without snapshots": (
            "Less storage overhead but slower recovery and less reproducibility."
        ),
        "Sharing host folders broadly": (
            "Convenient file transfer but weaker separation between host and VM."
        ),
        "Using personal passwords in lab machines": (
            "Convenient memorability but unnecessary credential exposure risk."
        ),
        "Ignoring disk growth": (
            "Initial VM size may appear manageable while snapshots and logs consume "
            "additional storage."
        ),
        "Installing multiple security products without planning": (
            "More telemetry can be useful, but compatibility and performance issues "
            "can complicate experiments."
        ),
        "Testing without written scope": (
            "Creates ambiguity about what systems, accounts, and actions are authorized."
        ),
    }

    for mistake, explanation in mistakes.items():
        print(f"\n{mistake}")
        print(textwrap.fill(explanation, width=76))


# =============================================================================
# 25. PRODUCTION VS LAB ENVIRONMENTS
# =============================================================================

def demonstrate_lab_vs_production() -> None:
    """Compare controlled training environments with production systems."""

    print_section("25. Lab Versus Production")

    comparisons = [
        (
            "Availability",
            "Lab: interruptions and restoration are expected.",
            "Production: service continuity is a primary requirement.",
        ),
        (
            "Snapshots",
            "Lab: frequent snapshots are useful.",
            "Production: backup and recovery policies are more complex.",
        ),
        (
            "Vulnerabilities",
            "Lab: intentionally vulnerable systems may be used under isolation.",
            "Production: vulnerabilities should be minimized and remediated.",
        ),
        (
            "Logging",
            "Lab: logging can be adjusted aggressively for learning.",
            "Production: logging must balance visibility, cost, privacy, and performance.",
        ),
        (
            "Networking",
            "Lab: isolated segments support controlled experimentation.",
            "Production: segmentation supports security, availability, and business needs.",
        ),
    ]

    for concept, lab, production in comparisons:
        print(f"\n{concept}")
        print(" ", lab)
        print(" ", production)


# =============================================================================
# 26. SIMPLE LAB READINESS CHECKLIST
# =============================================================================

@dataclass
class ChecklistItem:
    """A readiness requirement."""

    name: str
    passed: bool
    details: str


def build_readiness_checklist(
    safety_config: LabSafetyConfiguration,
    machines: List[LabMachine],
    networks: List[VirtualNetwork],
) -> List[ChecklistItem]:
    """Build a repeatable readiness checklist."""

    isolated_network_exists = any(
        network.mode == NetworkMode.INTERNAL
        and not network.internet_access
        and not network.lan_access
        for network in networks
    )

    baseline_snapshots_exist = all(
        len(machine.snapshots) > 0
        for machine in machines
    )

    return [
        ChecklistItem(
            "Explicit authorization",
            safety_config.explicit_authorization,
            "Testing scope and ownership are confirmed.",
        ),
        ChecklistItem(
            "Isolated network available",
            isolated_network_exists,
            "At least one modeled internal isolated network exists.",
        ),
        ChecklistItem(
            "No bridged vulnerable target",
            not safety_config.vulnerable_machine_bridged,
            "Vulnerable targets should not be exposed to physical LANs by default.",
        ),
        ChecklistItem(
            "No unnecessary port forwarding",
            not safety_config.port_forwarding_enabled,
            "Host-to-guest exposure should be minimized.",
        ),
        ChecklistItem(
            "Baseline snapshots",
            baseline_snapshots_exist,
            "Each modeled machine has at least one restoration point.",
        ),
        ChecklistItem(
            "Host shared folders restricted",
            not safety_config.host_shared_folders_enabled,
            "Untrusted guest systems should not broadly access host files.",
        ),
    ]


def demonstrate_readiness_checklist(
    machines: List[LabMachine],
    networks: List[VirtualNetwork],
) -> None:
    """Run and print the readiness checklist."""

    print_section("26. Lab Readiness Checklist")

    config = LabSafetyConfiguration(
        isolated_network=True,
        vulnerable_machine_bridged=False,
        port_forwarding_enabled=False,
        host_shared_folders_enabled=False,
        clipboard_bidirectional=False,
        internet_access_enabled=False,
        explicit_authorization=True,
    )

    checklist = build_readiness_checklist(config, machines, networks)

    for item in checklist:
        status = "PASS" if item.passed else "FAIL"
        print(f"[{status}] {item.name}")
        print("       ", item.details)


# =============================================================================
# 27. REAL-WORLD LAB WORKFLOW SIMULATION
# =============================================================================

class ExperimentState(str, Enum):
    PLANNED = "planned"
    BASELINED = "baselined"
    EXECUTING = "executing"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    RESTORED = "restored"
    COMPLETED = "completed"


@dataclass
class LabExperiment:
    """
    Models a controlled experiment lifecycle.

    A real experiment should also document scope, authorization, systems,
    network configuration, expected behavior, and cleanup requirements.
    """

    name: str
    state: ExperimentState = ExperimentState.PLANNED
    history: List[Tuple[str, str]] = field(default_factory=list)

    def transition(self, new_state: ExperimentState) -> None:
        self.state = new_state
        self.history.append(
            (
                datetime.now(timezone.utc).isoformat(),
                new_state.value,
            )
        )


def demonstrate_experiment_lifecycle() -> None:
    """Demonstrate reproducible experiment state transitions."""

    print_section("27. Controlled Experiment Lifecycle")

    experiment = LabExperiment(
        name="Authorized endpoint telemetry validation"
    )

    sequence = [
        ExperimentState.BASELINE,
        ExperimentState.EXECUTING,
        ExperimentState.COLLECTING,
        ExperimentState.ANALYZING,
        ExperimentState.RESTORED,
        ExperimentState.COMPLETED,
    ]

    for state in sequence:
        experiment.transition(state)

    print("Experiment:", experiment.name)

    for timestamp, state in experiment.history:
        print(f"{timestamp} -> {state}")

    print("\nA reproducible workflow separates:")
    print("1. Planning and authorization")
    print("2. Baseline creation")
    print("3. Controlled activity")
    print("4. Telemetry collection")
    print("5. Analysis")
    print("6. Restoration and cleanup")


# =============================================================================
# 28. ADVANCED DESIGN: NETWORK SEGMENTATION
# =============================================================================

@dataclass
class NetworkSegment:
    """Represents a security zone in a larger lab."""

    name: str
    subnet: ipaddress.IPv4Network
    purpose: str


def demonstrate_network_segmentation() -> None:
    """
    Demonstrate a larger lab architecture.

    Segmentation helps prevent one experimental area from automatically gaining
    access to all other systems.
    """

    print_section("28. Advanced Network Segmentation")

    segments = [
        NetworkSegment(
            "attacker-zone",
            ipaddress.ip_network("10.10.10.0/24"),
            "Authorized testing workstation network",
        ),
        NetworkSegment(
            "target-zone",
            ipaddress.ip_network("10.10.20.0/24"),
            "Controlled defender and target systems",
        ),
        NetworkSegment(
            "monitoring-zone",
            ipaddress.ip_network("10.10.30.0/24"),
            "Telemetry collection and analysis",
        ),
        NetworkSegment(
            "management-zone",
            ipaddress.ip_network("10.10.40.0/24"),
            "Administrative access where required",
        ),
    ]

    for segment in segments:
        print(
            f"{segment.name:20} "
            f"{str(segment.subnet):18} "
            f"{segment.purpose}"
        )

    print("\nSegmentation trade-off:")
    print("More segments improve control and realism but increase configuration and")
    print("troubleshooting complexity.")


# =============================================================================
# 29. ADVANCED DESIGN: CONFIGURATION DRIFT
# =============================================================================

def dictionary_difference(
    baseline: Dict[str, str],
    current: Dict[str, str],
) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    """
    Compare two configuration dictionaries.

    Returns:
        key -> (baseline_value, current_value)
    """

    differences: Dict[str, Tuple[Optional[str], Optional[str]]] = {}

    all_keys = set(baseline) | set(current)

    for key in sorted(all_keys):
        baseline_value = baseline.get(key)
        current_value = current.get(key)

        if baseline_value != current_value:
            differences[key] = (baseline_value, current_value)

    return differences


def demonstrate_configuration_drift() -> None:
    """Demonstrate how configuration drift can affect experiment reproducibility."""

    print_section("29. Configuration Drift")

    baseline = {
        "network_mode": "internal",
        "internet_access": "false",
        "shared_folder": "false",
        "snapshot": "clean-baseline",
    }

    current = {
        "network_mode": "internal",
        "internet_access": "true",
        "shared_folder": "true",
        "snapshot": "pre-experiment",
    }

    differences = dictionary_difference(baseline, current)

    for key, (old, new) in differences.items():
        print(f"{key}: {old!r} -> {new!r}")

    print("\nConfiguration drift can invalidate assumptions made during testing.")
    print("Record important changes and restore known baselines when appropriate.")


# =============================================================================
# 30. HOST SECURITY CONSIDERATIONS
# =============================================================================

def demonstrate_host_security() -> None:
    """
    The host is a critical security boundary.

    Virtual machines reduce direct interaction but do not make the host immune
    to risk. Hypervisor vulnerabilities, shared resources, mounted folders, and
    unsafe files can affect the host.
    """

    print_section("30. Host Security")

    checks = [
        "Keep the host operating system updated.",
        "Keep the hypervisor updated.",
        "Store VM files in controlled locations.",
        "Avoid unnecessary host-to-guest shared folders.",
        "Avoid using personal credentials inside intentionally risky lab VMs.",
        "Review USB passthrough before connecting physical devices to untrusted guests.",
        "Monitor disk capacity because snapshots and logs can grow rapidly.",
        "Treat files copied from untrusted guests as potentially unsafe.",
    ]

    for check in checks:
        print("-", check)


# =============================================================================
# 31. CLEANUP AND REPRODUCIBILITY
# =============================================================================

def demonstrate_cleanup() -> None:
    """Explain why cleanup is part of the experiment design."""

    print_section("31. Cleanup and Reproducibility")

    actions = [
        "Record the final experiment state.",
        "Export required logs or artifacts.",
        "Verify that no unnecessary network exposure remains.",
        "Restore the intended baseline snapshot.",
        "Remove temporary credentials created for the experiment.",
        "Remove temporary shared folders or adapter configurations.",
        "Document configuration changes that affected results.",
    ]

    for index, action in enumerate(actions, start=1):
        print(f"{index}. {action}")


# =============================================================================
# 32. COMPLETE STUDY FLOW
# =============================================================================

def main() -> None:
    """Run the complete cybersecurity lab study program."""

    demonstrate_lab_purpose()
    demonstrate_virtualization()

    machines = demonstrate_lab_roles()
    networks = demonstrate_network_modes()

    demonstrate_ip_addressing()
    demonstrate_connectivity_policy()
    demonstrate_snapshots()
    demonstrate_lab_safety()
    demonstrate_kali_role()

    event_store = demonstrate_defender_machine()
    demonstrate_detection_engineering(event_store)

    demonstrate_password_safety()
    demonstrate_file_integrity()
    demonstrate_time_correlation()
    demonstrate_service_validation()
    demonstrate_firewall_model()

    demonstrate_configuration_documentation(machines, networks)
    demonstrate_resource_planning()
    demonstrate_isolation_graph()
    demonstrate_routing()
    demonstrate_input_validation()
    demonstrate_safe_subprocess_design()
    demonstrate_troubleshooting()
    demonstrate_common_mistakes()
    demonstrate_lab_vs_production()
    demonstrate_readiness_checklist(machines, networks)
    demonstrate_experiment_lifecycle()
    demonstrate_network_segmentation()
    demonstrate_configuration_drift()
    demonstrate_host_security()
    demonstrate_cleanup()

    print_section("Cybersecurity Lab Study Complete")
    print(
        "The central design principle is controlled experimentation: "
        "authorized systems, explicit isolation boundaries, reproducible "
        "snapshots, limited connectivity, observable telemetry, and cleanup."
    )


if __name__ == "__main__":
    main()
