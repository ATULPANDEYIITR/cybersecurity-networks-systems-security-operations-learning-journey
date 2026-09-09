#!/usr/bin/env python3
"""
OSI MODEL, ENCAPSULATION, DECAPSULATION, SECURITY, AND WIRESHARK
================================================================

A self-contained study script covering the OSI reference model from
absolute beginner through advanced practical networking concepts.

The script uses only Python's standard library. It does not require
Wireshark to execute, but includes practical Wireshark-oriented packet
analysis guidance, packet/header simulations, protocol classification,
security analysis, and a small PCAP file parser for Ethernet/IPv4/TCP/UDP
frames when a PCAP file is supplied.

Run:
    python osi_model.py

Optional PCAP analysis:
    python osi_model.py capture.pcap

The PCAP parser supports classic libpcap files and Ethernet link-layer
captures containing common IPv4 TCP/UDP traffic. It is intentionally
educational rather than a replacement for Wireshark or a complete PCAP
library.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct
import sys
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Optional


# ============================================================================
# SECTION 1: FOUNDATIONAL TERMINOLOGY
# ============================================================================

def print_title(title: str) -> None:
    """Print a consistent section heading."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain(message: str) -> None:
    """Print wrapped educational text."""
    print(textwrap.fill(message, width=78))


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a small dependency-free table."""
    widths = [len(header) for header in headers]

    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))

    separator = "-+-".join("-" * width for width in widths)
    print(" | ".join(header.ljust(widths[index])
                    for index, header in enumerate(headers)))
    print(separator)

    for row in rows:
        print(" | ".join(str(value).ljust(widths[index])
                        for index, value in enumerate(row)))


class OSILayer(Enum):
    """The seven layers of the OSI reference model."""

    APPLICATION = 7
    PRESENTATION = 6
    SESSION = 5
    TRANSPORT = 4
    NETWORK = 3
    DATA_LINK = 2
    PHYSICAL = 1


LAYER_NAMES = {
    7: "Application",
    6: "Presentation",
    5: "Session",
    4: "Transport",
    3: "Network",
    2: "Data Link",
    1: "Physical",
}

LAYER_PDU_NAMES = {
    7: "Data",
    6: "Data",
    5: "Data",
    4: "Segment / Datagram",
    3: "Packet",
    2: "Frame",
    1: "Bits",
}


def show_osi_model() -> None:
    """Introduce all seven layers and their primary responsibilities."""
    print_title("1. THE SEVEN-LAYER OSI MODEL")

    explain(
        "The Open Systems Interconnection (OSI) model is a conceptual "
        "reference framework for describing how network communication can "
        "be divided into seven logical layers. It is a model, not a literal "
        "implementation that every modern protocol stack follows exactly. "
        "The Internet protocol suite, commonly called TCP/IP, does not map "
        "one-to-one onto all seven OSI layers."
    )

    rows = [
        [
            "7",
            "Application",
            "Network services used by applications",
            "HTTP, DNS, SMTP, SSH",
            "Data",
        ],
        [
            "6",
            "Presentation",
            "Representation, encoding, compression, encryption",
            "TLS concepts, UTF-8, JPEG, JSON",
            "Data",
        ],
        [
            "5",
            "Session",
            "Session establishment, management, synchronization",
            "RPC/session concepts, dialog control",
            "Data",
        ],
        [
            "4",
            "Transport",
            "End-to-end delivery, ports, reliability, flow control",
            "TCP, UDP",
            "Segment/Datagram",
        ],
        [
            "3",
            "Network",
            "Logical addressing and routing",
            "IPv4, IPv6, ICMP",
            "Packet",
        ],
        [
            "2",
            "Data Link",
            "Local delivery, framing, MAC addressing",
            "Ethernet, Wi-Fi, ARP",
            "Frame",
        ],
        [
            "1",
            "Physical",
            "Signals, media, transmission of bits",
            "Copper, fiber, radio",
            "Bits",
        ],
    ]

    print_table(
        ["Layer", "Name", "Main responsibility", "Examples", "PDU"],
        rows,
    )

    print("\nMnemonic from Layer 7 down to Layer 1:")
    print("Application -> Presentation -> Session -> Transport ->")
    print("Network -> Data Link -> Physical")

    print("\nMnemonic from Layer 1 up to Layer 7:")
    print("Physical -> Data Link -> Network -> Transport ->")
    print("Session -> Presentation -> Application")


# ============================================================================
# SECTION 2: DETAILED LAYER RESPONSIBILITIES
# ============================================================================

def explain_layer_details() -> None:
    """Explain each layer with practical examples and boundaries."""
    print_title("2. DETAILED RESPONSIBILITIES OF EACH LAYER")

    layers = {
        7: (
            "Application",
            [
                "Provides network-facing services to application processes.",
                "Examples include HTTP, DNS, SMTP, FTP, SSH and DHCP.",
                "It is not simply 'the application itself'; it describes "
                "network services and protocols visible to applications.",
                "Security concerns include authentication, authorization, "
                "injection attacks, malicious input and protocol abuse.",
            ],
        ),
        6: (
            "Presentation",
            [
                "Deals conceptually with data representation and transformation.",
                "Typical concerns include character encoding, serialization, "
                "compression and encryption.",
                "Modern Internet architectures frequently combine or distribute "
                "these responsibilities across application protocols and libraries.",
                "TLS is often discussed around OSI layers 5-7 rather than being "
                "a clean single-layer protocol.",
            ],
        ),
        5: (
            "Session",
            [
                "Coordinates logical conversations or sessions between endpoints.",
                "Concepts include establishing, maintaining, synchronizing and "
                "terminating communication sessions.",
                "Modern TCP/IP systems commonly implement session behavior within "
                "application protocols, middleware or libraries.",
            ],
        ),
        4: (
            "Transport",
            [
                "Provides process-to-process communication.",
                "Port numbers identify application endpoints.",
                "TCP provides connection-oriented reliable byte-stream delivery.",
                "UDP provides connectionless datagrams without TCP-style reliability.",
                "Security concerns include scanning, spoofing limitations, "
                "resource exhaustion and protocol abuse.",
            ],
        ),
        3: (
            "Network",
            [
                "Provides logical addressing and routing between networks.",
                "IPv4 and IPv6 use IP addresses.",
                "Routers make forwarding decisions using Layer 3 information.",
                "ICMP communicates network control and diagnostic information.",
                "Security concerns include IP spoofing, route manipulation, "
                "packet filtering and denial-of-service traffic.",
            ],
        ),
        2: (
            "Data Link",
            [
                "Provides local-link delivery and framing.",
                "Ethernet frames contain source and destination MAC addresses.",
                "Switches normally make forwarding decisions using MAC addresses.",
                "ARP maps IPv4 addresses to local-link MAC addresses.",
                "Security concerns include ARP spoofing, MAC flooding and VLAN attacks.",
            ],
        ),
        1: (
            "Physical",
            [
                "Carries raw signals representing bits.",
                "Media include copper, fiber and wireless radio.",
                "Relevant properties include bandwidth, attenuation, interference "
                "and signal quality.",
                "Security concerns include physical tapping, electromagnetic "
                "interference and unauthorized physical access.",
            ],
        ),
    }

    for number in range(7, 0, -1):
        name, responsibilities = layers[number]
        print(f"\nLayer {number}: {name}")
        for item in responsibilities:
            print(f"  - {item}")


# ============================================================================
# SECTION 3: OSI VS TCP/IP
# ============================================================================

def compare_osi_and_tcp_ip() -> None:
    """Compare the conceptual OSI model with the Internet protocol stack."""
    print_title("3. OSI MODEL VERSUS TCP/IP MODEL")

    explain(
        "The OSI model is primarily a conceptual reference model with seven "
        "layers. The Internet protocol suite is commonly represented using "
        "four or five layers depending on the teaching convention. TCP/IP "
        "combines several OSI responsibilities."
    )

    rows = [
        ["OSI 7", "Application", "TCP/IP Application"],
        ["OSI 6", "Presentation", "TCP/IP Application"],
        ["OSI 5", "Session", "TCP/IP Application"],
        ["OSI 4", "Transport", "TCP/IP Transport"],
        ["OSI 3", "Network", "TCP/IP Internet"],
        ["OSI 2", "Data Link", "TCP/IP Link / Network Access"],
        ["OSI 1", "Physical", "TCP/IP Link / Network Access"],
    ]

    print_table(
        ["OSI", "OSI responsibility", "Common TCP/IP mapping"],
        rows,
    )

    print("\nImportant distinction:")
    explain(
        "Do not assume that a real protocol must belong to exactly one OSI "
        "layer. TLS, ARP, ICMP, VLAN tagging, DNS and tunneling technologies "
        "can create practical situations where a strict seven-layer mapping "
        "is ambiguous or depends on the perspective being used."
    )


# ============================================================================
# SECTION 4: ENCAPSULATION
# ============================================================================

@dataclass
class ProtocolData:
    """Represents data as it moves through a conceptual protocol stack."""

    payload: bytes
    headers: list[str] = field(default_factory=list)

    def add_header(self, header: str) -> None:
        """Add a conceptual header to the beginning of the representation."""
        self.headers.insert(0, header)

    def describe(self) -> str:
        """Return the current conceptual protocol structure."""
        if not self.headers:
            return f"Data({len(self.payload)} bytes)"

        return " | ".join(self.headers) + f" | Payload({len(self.payload)} bytes)"


def demonstrate_encapsulation() -> None:
    """Show how headers are added while data moves down the stack."""
    print_title("4. ENCAPSULATION")

    explain(
        "Encapsulation is the conceptual process in which each lower layer "
        "adds control information to data received from the layer above it. "
        "A real packet may contain headers, trailers, options, padding and "
        "nested protocols. The simple simulation below focuses on the core idea."
    )

    application_data = ProtocolData(
        payload=b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
    )

    print("\nApplication:")
    print(application_data.describe())

    application_data.add_header("TCP Header")
    print("\nAfter Transport Layer:")
    print(application_data.describe())

    application_data.add_header("IPv4 Header")
    print("\nAfter Network Layer:")
    print(application_data.describe())

    application_data.add_header("Ethernet Header")
    print("\nAfter Data Link Layer:")
    print(application_data.describe())

    print("\nPhysical Layer:")
    print("The resulting frame is represented as a stream of bits/signals.")


# ============================================================================
# SECTION 5: DECAPSULATION
# ============================================================================

def demonstrate_decapsulation() -> None:
    """Show the reverse conceptual process at the receiving endpoint."""
    print_title("5. DECAPSULATION")

    explain(
        "At the destination, the process is reversed. The receiving host "
        "examines the Data Link frame, extracts the network-layer packet, "
        "passes the transport payload to the correct socket using port "
        "information, and ultimately delivers application data."
    )

    encapsulated_headers = [
        "Ethernet Header",
        "IPv4 Header",
        "TCP Header",
    ]

    print("\nIncoming representation:")
    print(" -> ".join(encapsulated_headers) + " -> Application Data")

    for header in encapsulated_headers:
        print(f"Removing/processing: {header}")

    print("Result: application receives the original payload.")


# ============================================================================
# SECTION 6: ADDRESSING
# ============================================================================

@dataclass
class Endpoint:
    """Represent a network endpoint."""

    mac_address: str
    ip_address: str
    port: Optional[int] = None


def validate_mac(mac: str) -> bool:
    """Validate a conventional colon-separated MAC address."""
    parts = mac.split(":")
    if len(parts) != 6:
        return False

    try:
        return all(0 <= int(part, 16) <= 255 and len(part) == 2
                   for part in parts)
    except ValueError:
        return False


def validate_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 text."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def demonstrate_addressing() -> None:
    """Explain MAC, IP and port addressing."""
    print_title("6. ADDRESSING: MAC, IP AND PORTS")

    explain(
        "Different layers use different addressing concepts. A MAC address "
        "identifies a network interface on a local link. An IP address "
        "identifies a logical network endpoint used for routing. A transport "
        "port identifies a service endpoint within a host. These are not "
        "interchangeable identifiers."
    )

    examples = [
        ("MAC", "00:11:22:33:44:55", validate_mac),
        ("IPv4", "192.168.1.10", validate_ip),
        ("IPv6", "2001:db8::10", validate_ip),
    ]

    for name, value, validator in examples:
        print(f"{name:8} {value:25} valid={validator(value)}")

    print("\nTypical TCP endpoint:")
    endpoint = Endpoint(
        mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.10",
        port=443,
    )
    print(endpoint)

    print("\nLayer association:")
    print("MAC address -> Data Link")
    print("IP address  -> Network")
    print("Port        -> Transport")


# ============================================================================
# SECTION 7: TRANSPORT PROTOCOLS
# ============================================================================

def tcp_flags_to_names(flags: int) -> list[str]:
    """Decode common TCP flags."""
    mapping = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
        0x40: "ECE",
        0x80: "CWR",
    }

    return [name for bit, name in mapping.items() if flags & bit]


def simulate_tcp_three_way_handshake() -> None:
    """Demonstrate the conceptual TCP connection establishment process."""
    print_title("7. TCP THREE-WAY HANDSHAKE")

    explain(
        "TCP establishes a connection using a three-message handshake. "
        "The client normally sends SYN, the server responds with SYN+ACK, "
        "and the client sends ACK. Sequence numbers and acknowledgments "
        "allow both endpoints to synchronize their state."
    )

    handshake = [
        ("Client", "Server", 1000, 0, 0x02),
        ("Server", "Client", 5000, 1001, 0x12),
        ("Client", "Server", 1001, 5001, 0x10),
    ]

    for source, destination, seq, ack, flags in handshake:
        print(
            f"{source:8} -> {destination:8} "
            f"SEQ={seq:<5} ACK={ack:<5} "
            f"FLAGS={'+'.join(tcp_flags_to_names(flags))}"
        )

    print("\nImportant:")
    print("- SYN consumes one sequence number.")
    print("- ACK acknowledges received sequence space.")
    print("- The handshake does not itself carry normal application payload.")


def compare_tcp_udp() -> None:
    """Compare TCP and UDP at the transport layer."""
    print_title("8. TCP VERSUS UDP")

    rows = [
        ["Connection model", "Connection-oriented", "Connectionless"],
        ["Reliability", "Built-in retransmission/ordering", "No TCP-style guarantee"],
        ["Ordering", "Ordered byte stream", "Datagrams retain message boundaries"],
        ["Flow control", "Yes", "No TCP-style flow control"],
        ["Congestion control", "Yes", "Not provided by UDP itself"],
        ["Header", "Larger", "Smaller"],
        ["Typical uses", "HTTP(S), SSH, databases", "DNS, streaming, QUIC transport"],
    ]

    print_table(["Property", "TCP", "UDP"], rows)

    explain(
        "UDP is not inherently 'faster' in every application. It provides "
        "fewer transport guarantees, which can reduce protocol overhead, "
        "but applications may need to implement reliability, ordering, "
        "congestion control or security themselves. QUIC, for example, uses "
        "UDP as its underlying transport substrate while implementing "
        "substantial transport behavior above UDP."
    )


# ============================================================================
# SECTION 9: NETWORK-LAYER ADDRESSING AND ROUTING
# ============================================================================

def subnet_information(network: str) -> None:
    """Print useful IPv4/IPv6 network information."""
    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        print(f"Invalid network: {exc}")
        return

    print(f"\nNetwork:       {parsed}")
    print(f"Version:       IPv{parsed.version}")
    print(f"Prefix length: /{parsed.prefixlen}")
    print(f"Network addr:  {parsed.network_address}")
    print(f"Broadcast:     {getattr(parsed, 'broadcast_address', 'N/A')}")
    print(f"Total addresses: {parsed.num_addresses}")

    if parsed.version == 4:
        hosts = list(parsed.hosts())
        if hosts:
            print(f"First usable:  {hosts[0]}")
            print(f"Last usable:   {hosts[-1]}")
        else:
            print("Usable hosts:  none under conventional host rules")


def demonstrate_routing_and_subnetting() -> None:
    """Explain logical addressing, networks and routing decisions."""
    print_title("9. IP ADDRESSING, SUBNETTING AND ROUTING")

    explain(
        "Routers operate primarily on Layer 3 information. A router examines "
        "the destination IP address and consults its routing table to choose "
        "an outgoing interface or next hop. Subnet masks and prefix lengths "
        "define which addresses belong to a network."
    )

    for network in ["192.168.1.0/24", "10.10.0.0/16", "2001:db8:1::/64"]:
        subnet_information(network)

    print("\nLongest-prefix matching example:")

    routes = [
        ("0.0.0.0/0", "Internet gateway"),
        ("10.0.0.0/8", "Router A"),
        ("10.20.0.0/16", "Router B"),
        ("10.20.30.0/24", "Router C"),
    ]

    destination = ipaddress.ip_address("10.20.30.55")
    matches = []

    for prefix, next_hop in routes:
        network = ipaddress.ip_network(prefix)
        if destination in network:
            matches.append((network.prefixlen, prefix, next_hop))

    matches.sort(reverse=True)

    for prefix_length, prefix, next_hop in matches:
        print(f"Matched {prefix:<15} -> {next_hop}")

    print(f"Selected route: {matches[0][1]} -> {matches[0][2]}")


# ============================================================================
# SECTION 10: DATA LINK, ETHERNET AND ARP
# ============================================================================

@dataclass
class EthernetFrame:
    """Simplified Ethernet frame representation."""

    destination_mac: str
    source_mac: str
    ether_type: int
    payload: bytes

    def describe(self) -> str:
        """Return a human-readable frame description."""
        return (
            f"Ethernet dst={self.destination_mac}, "
            f"src={self.source_mac}, "
            f"EtherType=0x{self.ether_type:04x}, "
            f"payload={len(self.payload)} bytes"
        )


def demonstrate_ethernet_and_arp() -> None:
    """Explain Ethernet frames and ARP's role."""
    print_title("10. ETHERNET, MAC ADDRESSES AND ARP")

    explain(
        "Ethernet frames provide local-link delivery. An Ethernet header "
        "contains destination and source MAC addresses plus an EtherType "
        "identifying the encapsulated protocol. ARP is used by IPv4 hosts "
        "on a local broadcast domain to discover the MAC address associated "
        "with an IPv4 address."
    )

    frame = EthernetFrame(
        destination_mac="aa:bb:cc:dd:ee:ff",
        source_mac="00:11:22:33:44:55",
        ether_type=0x0800,
        payload=b"IPv4 packet bytes",
    )

    print(frame.describe())

    print("\nCommon EtherTypes:")
    print("0x0800 -> IPv4")
    print("0x0806 -> ARP")
    print("0x86DD -> IPv6")
    print("0x8100 -> IEEE 802.1Q VLAN-tagged Ethernet")

    print("\nConceptual ARP exchange:")
    print("Host A: Who has 192.168.1.20?")
    print("Host B: 192.168.1.20 is at aa:bb:cc:dd:ee:ff")


# ============================================================================
# SECTION 11: DNS AND APPLICATION-LAYER EXAMPLES
# ============================================================================

def explain_dns_and_http() -> None:
    """Connect common application protocols to the OSI model."""
    print_title("11. DNS, HTTP AND APPLICATION-LAYER TRAFFIC")

    explain(
        "Application protocols define the semantics of network requests and "
        "responses. DNS resolves names to records such as IP addresses. "
        "HTTP defines request and response semantics for web communication."
    )

    print("\nSimplified HTTP request:")
    http_request = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: text/html\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    print(http_request)

    print("Conceptual stack:")
    print("HTTP")
    print("  -> TCP")
    print("      -> IP")
    print("          -> Ethernet")
    print("              -> Physical medium")

    print("\nDNS example:")
    hostname = "example.com"
    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        unique_addresses = sorted({item[4][0] for item in addresses})
        for address in unique_addresses[:5]:
            print(f"{hostname} -> {address}")
    except OSError:
        print("DNS resolution is unavailable in this execution environment.")


# ============================================================================
# SECTION 12: SECURITY BY OSI LAYER
# ============================================================================

def demonstrate_security_by_layer() -> None:
    """Map representative security concerns to OSI layers."""
    print_title("12. SECURITY IMPLICATIONS BY OSI LAYER")

    rows = [
        [
            "7",
            "Application",
            "Injection, broken authentication, malicious input, API abuse",
            "Input validation, authentication, authorization",
        ],
        [
            "6",
            "Presentation",
            "Weak cryptography, unsafe serialization, malformed encodings",
            "Strong cryptography, safe parsers, strict encoding",
        ],
        [
            "5",
            "Session",
            "Session hijacking, fixation, weak session state",
            "Secure session identifiers, expiration, reauthentication",
        ],
        [
            "4",
            "Transport",
            "Port exposure, SYN floods, connection exhaustion",
            "Firewalls, rate limiting, state controls",
        ],
        [
            "3",
            "Network",
            "IP spoofing, route attacks, packet manipulation",
            "ACLs, routing security, IP filtering, segmentation",
        ],
        [
            "2",
            "Data Link",
            "ARP spoofing, MAC flooding, VLAN attacks",
            "Switch security, VLAN controls, DHCP snooping",
        ],
        [
            "1",
            "Physical",
            "Cable tapping, device theft, interference",
            "Physical access controls, secure facilities",
        ],
    ]

    print_table(
        ["Layer", "Name", "Threat examples", "Representative controls"],
        rows,
    )

    explain(
        "The layer model should not be treated as a security boundary. A "
        "single attack can involve multiple layers. For example, a malicious "
        "application request may travel over TLS, TCP, IP and Ethernet while "
        "the actual vulnerability exists entirely in application logic."
    )


# ============================================================================
# SECTION 13: FIREWALLS, IDS AND IPS
# ============================================================================

@dataclass
class PacketMetadata:
    """Small abstraction used to simulate firewall decisions."""

    source_ip: str
    destination_ip: str
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: str


@dataclass
class FirewallRule:
    """Simple rule for educational packet filtering."""

    action: str
    protocol: Optional[str] = None
    destination_port: Optional[int] = None

    def matches(self, packet: PacketMetadata) -> bool:
        """Return whether the rule matches a packet."""
        if self.protocol and self.protocol.upper() != packet.protocol.upper():
            return False

        if (
            self.destination_port is not None
            and self.destination_port != packet.destination_port
        ):
            return False

        return True


def simulate_firewall() -> None:
    """Demonstrate basic packet-filtering logic."""
    print_title("13. FIREWALL DECISION SIMULATION")

    rules = [
        FirewallRule("ALLOW", "TCP", 443),
        FirewallRule("ALLOW", "TCP", 22),
        FirewallRule("DENY"),
    ]

    packets = [
        PacketMetadata("10.0.0.10", "10.0.0.20", 51000, 443, "TCP"),
        PacketMetadata("10.0.0.10", "10.0.0.20", 51001, 22, "TCP"),
        PacketMetadata("10.0.0.10", "10.0.0.20", 51002, 23, "TCP"),
        PacketMetadata("10.0.0.10", "10.0.0.20", 51003, 53, "UDP"),
    ]

    for packet in packets:
        decision = "NO MATCH"
        for rule in rules:
            if rule.matches(packet):
                decision = rule.action
                break

        print(
            f"{packet.protocol:4} "
            f"{packet.source_ip}:{packet.source_port} -> "
            f"{packet.destination_ip}:{packet.destination_port} "
            f"=> {decision}"
        )

    explain(
        "Real firewalls are substantially more complex. They may track "
        "connection state, inspect application protocols, perform NAT, "
        "enforce identity-aware policies, rate-limit traffic, integrate "
        "with intrusion prevention systems and apply rules in a defined "
        "ordering model."
    )


# ============================================================================
# SECTION 14: PACKET STRUCTURES
# ============================================================================

@dataclass
class IPv4Header:
    """Decoded subset of an IPv4 header."""

    version: int
    header_length: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    source: str
    destination: str


@dataclass
class TCPHeader:
    """Decoded subset of a TCP header."""

    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    header_length: int
    flags: int
    window_size: int
    checksum: int
    urgent_pointer: int


@dataclass
class UDPHeader:
    """Decoded UDP header."""

    source_port: int
    destination_port: int
    length: int
    checksum: int


def parse_ipv4_header(packet: bytes) -> tuple[IPv4Header, bytes]:
    """Parse a minimal IPv4 header from raw bytes."""
    if len(packet) < 20:
        raise ValueError("IPv4 packet is shorter than the minimum header.")

    first_byte = packet[0]
    version = first_byte >> 4
    ihl = first_byte & 0x0F
    header_length = ihl * 4

    if version != 4:
        raise ValueError(f"Expected IPv4, found version {version}.")

    if ihl < 5:
        raise ValueError("Invalid IPv4 IHL.")

    if len(packet) < header_length:
        raise ValueError("Packet is shorter than the declared IPv4 header.")

    (
        _version_ihl,
        _tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        source_raw,
        destination_raw,
    ) = struct.unpack("!BBHHHBBH4s4s", packet[:20])

    flags = flags_fragment >> 13
    fragment_offset = flags_fragment & 0x1FFF

    source = socket.inet_ntoa(source_raw)
    destination = socket.inet_ntoa(destination_raw)

    payload_end = min(total_length, len(packet))
    payload = packet[header_length:payload_end]

    return (
        IPv4Header(
            version=version,
            header_length=header_length,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            checksum=checksum,
            source=source,
            destination=destination,
        ),
        payload,
    )


def parse_tcp_header(packet: bytes) -> tuple[TCPHeader, bytes]:
    """Parse a TCP header."""
    if len(packet) < 20:
        raise ValueError("TCP segment is shorter than the minimum header.")

    (
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        offset_reserved_flags,
        window_size,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIBBHHH", packet[:17])

    # The preceding unpack format is intentionally not used because TCP's
    # offset/flags field is 16 bits. Parse the correct complete header below.
    (
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        offset_reserved_flags,
        window_size,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIHHHH", packet[:20])

    header_length = ((offset_reserved_flags >> 12) & 0xF) * 4
    flags = offset_reserved_flags & 0x01FF

    if header_length < 20:
        raise ValueError("Invalid TCP header length.")

    if len(packet) < header_length:
        raise ValueError("Packet is shorter than declared TCP header.")

    return (
        TCPHeader(
            source_port=source_port,
            destination_port=destination_port,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            header_length=header_length,
            flags=flags,
            window_size=window_size,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
        ),
        packet[header_length:],
    )


def parse_udp_header(packet: bytes) -> tuple[UDPHeader, bytes]:
    """Parse a UDP header."""
    if len(packet) < 8:
        raise ValueError("UDP datagram is shorter than 8 bytes.")

    source_port, destination_port, length, checksum = struct.unpack(
        "!HHHH",
        packet[:8],
    )

    if length < 8:
        raise ValueError("Invalid UDP length.")

    payload_end = min(length, len(packet))

    return (
        UDPHeader(
            source_port=source_port,
            destination_port=destination_port,
            length=length,
            checksum=checksum,
        ),
        packet[8:payload_end],
    )


def demonstrate_packet_headers() -> None:
    """Show important fields in common packet headers."""
    print_title("14. PACKET HEADER STRUCTURES")

    print("\nIPv4 fields:")
    print("- Version")
    print("- IHL")
    print("- Total Length")
    print("- Identification")
    print("- Flags / Fragment Offset")
    print("- TTL")
    print("- Protocol")
    print("- Header Checksum")
    print("- Source Address")
    print("- Destination Address")

    print("\nTCP fields:")
    print("- Source Port / Destination Port")
    print("- Sequence Number")
    print("- Acknowledgment Number")
    print("- Header Length")
    print("- Flags")
    print("- Window Size")
    print("- Checksum")
    print("- Urgent Pointer")

    print("\nUDP fields:")
    print("- Source Port")
    print("- Destination Port")
    print("- Length")
    print("- Checksum")

    print("\nCommon IPv4 protocol numbers:")
    print("1  -> ICMP")
    print("6  -> TCP")
    print("17 -> UDP")


# ============================================================================
# SECTION 15: CHECKSUM CONCEPT
# ============================================================================

def internet_checksum(data: bytes) -> int:
    """
    Calculate the standard one's-complement Internet checksum.

    This demonstrates the mathematical mechanism conceptually used by
    protocols such as IPv4, TCP and UDP, with protocol-specific handling
    around pseudo-headers and checksum fields.
    """
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for offset in range(0, len(data), 2):
        word = (data[offset] << 8) | data[offset + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def demonstrate_checksum() -> None:
    """Demonstrate checksum calculation and its limitations."""
    print_title("15. CHECKSUMS")

    data = b"OSI networking"
    checksum = internet_checksum(data)

    print(f"Data:     {data!r}")
    print(f"Checksum: 0x{checksum:04x}")

    explain(
        "Checksums detect many accidental transmission errors. They are not "
        "cryptographic integrity mechanisms. An attacker who can intentionally "
        "modify data can generally recompute a non-cryptographic checksum. "
        "Cryptographic authentication requires mechanisms such as authenticated "
        "encryption or message authentication codes."
    )


# ============================================================================
# SECTION 16: WIRESHARK FUNDAMENTALS
# ============================================================================

def explain_wireshark() -> None:
    """Provide practical Wireshark workflow and filter examples."""
    print_title("16. WIRESHARK: PACKET ANALYSIS")

    explain(
        "Wireshark is a graphical packet analyzer used to capture and inspect "
        "network traffic. Its packet details pane exposes protocol fields, "
        "making it useful for connecting real traffic to OSI-layer concepts."
    )

    print("\nTypical Wireshark workflow:")
    workflow = [
        "1. Select the correct capture interface.",
        "2. Start a capture or open an existing capture file.",
        "3. Identify the traffic of interest.",
        "4. Apply a display filter.",
        "5. Inspect packet details layer by layer.",
        "6. Follow a TCP or other protocol stream where appropriate.",
        "7. Correlate timestamps, addresses, ports, flags and payload.",
        "8. Form a hypothesis and verify it against multiple packets.",
    ]

    for item in workflow:
        print(item)

    print("\nUseful Wireshark display filters:")
    filters = [
        ("ip", "IPv4 traffic"),
        ("ipv6", "IPv6 traffic"),
        ("tcp", "TCP traffic"),
        ("udp", "UDP traffic"),
        ("icmp", "ICMP traffic"),
        ("arp", "ARP traffic"),
        ("dns", "DNS traffic"),
        ("http", "HTTP traffic when dissected as HTTP"),
        ("tls", "TLS traffic"),
        ("tcp.port == 443", "TCP traffic involving port 443"),
        ("ip.addr == 192.168.1.10", "Packets involving an IPv4 address"),
        ("ip.src == 192.168.1.10", "Packets sourced by an IPv4 address"),
        ("ip.dst == 192.168.1.10", "Packets destined for an IPv4 address"),
        ("tcp.flags.syn == 1", "TCP SYN packets"),
        ("tcp.flags.reset == 1", "TCP reset packets"),
        ("tcp.analysis.retransmission", "TCP retransmissions identified by Wireshark"),
        ("dns.qry.name", "Packets containing DNS query information"),
    ]

    print_table(["Filter", "Purpose"], [[a, b] for a, b in filters])

    print("\nCapture-filter versus display-filter distinction:")
    print(
        "Capture filters restrict what is captured; display filters restrict "
        "what is displayed after capture."
    )


# ============================================================================
# SECTION 17: READING A WIRESHARK PACKET
# ============================================================================

def explain_wireshark_packet_tree() -> None:
    """Explain the protocol tree typically visible in Wireshark."""
    print_title("17. HOW TO READ A WIRESHARK PACKET")

    example_tree = [
        "Frame",
        "  Ethernet II",
        "    Destination: aa:bb:cc:dd:ee:ff",
        "    Source: 00:11:22:33:44:55",
        "    Type: IPv4",
        "  Internet Protocol Version 4",
        "    Source: 192.168.1.10",
        "    Destination: 93.184.216.34",
        "    Protocol: TCP",
        "    TTL: 64",
        "  Transmission Control Protocol",
        "    Source Port: 51514",
        "    Destination Port: 443",
        "    Flags: SYN",
        "    Sequence Number: 0",
        "  Transport/Application payload",
    ]

    for line in example_tree:
        print(line)

    explain(
        "The important analytical habit is to move from the outside toward "
        "the inside: frame, network packet, transport segment, then application "
        "protocol. Do not infer an application's behavior from a single field "
        "when the complete packet sequence can answer the question."
    )


# ============================================================================
# SECTION 18: TCP ANALYSIS IN WIRESHARK
# ============================================================================

def demonstrate_tcp_wireshark_analysis() -> None:
    """Show how TCP behavior can be interpreted from packet sequences."""
    print_title("18. TCP ANALYSIS WITH WIRESHARK")

    packets = [
        ("10.0.0.10", "10.0.0.20", 50000, 443, "SYN", 1000, 0),
        ("10.0.0.20", "10.0.0.10", 443, 50000, "SYN, ACK", 7000, 1001),
        ("10.0.0.10", "10.0.0.20", 50000, 443, "ACK", 1001, 7001),
        ("10.0.0.10", "10.0.0.20", 50000, 443, "PSH, ACK", 1001, 7001),
        ("10.0.0.20", "10.0.0.10", 443, 50000, "ACK", 7001, 1051),
    ]

    print_table(
        ["Source", "Destination", "SrcPort", "DstPort", "Flags", "SEQ", "ACK"],
        [[str(value) for value in packet] for packet in packets],
    )

    print("\nInterpretation:")
    print("1. SYN establishes connection state.")
    print("2. SYN+ACK acknowledges the SYN and sends the server SYN.")
    print("3. ACK completes the handshake.")
    print("4. PSH+ACK indicates application data being delivered with ACK state.")
    print("5. The following ACK acknowledges received sequence space.")

    print("\nUseful Wireshark TCP analysis concepts:")
    print("- Relative sequence numbers")
    print("- Retransmissions")
    print("- Duplicate ACKs")
    print("- Out-of-order segments")
    print("- Zero-window conditions")
    print("- Window scaling")
    print("- Selective acknowledgments")
    print("- TCP handshake and teardown")
    print("- Round-trip timing")


# ============================================================================
# SECTION 19: COMMON WIRESHARK TROUBLESHOOTING
# ============================================================================

def troubleshoot_with_wireshark() -> None:
    """Map common symptoms to packet-level evidence."""
    print_title("19. NETWORK TROUBLESHOOTING WITH WIRESHARK")

    cases = [
        [
            "DNS failure",
            "DNS query has no response or returns an error",
            "Inspect DNS server address, query, response code and timing",
        ],
        [
            "TCP connection failure",
            "SYN receives RST or no response",
            "Inspect destination reachability, firewall behavior and listener",
        ],
        [
            "Slow application",
            "Large delays between request and response",
            "Compare TCP RTT, server response delay and retransmissions",
        ],
        [
            "Packet loss symptoms",
            "Retransmissions or duplicate ACK patterns",
            "Inspect loss, congestion, wireless errors and path conditions",
        ],
        [
            "TLS problem",
            "Handshake does not complete",
            "Inspect ClientHello, ServerHello, alerts and TCP state",
        ],
        [
            "ARP problem",
            "ARP requests repeat without successful resolution",
            "Inspect ARP request/reply and local broadcast domain",
        ],
    ]

    print_table(
        ["Problem", "Packet evidence", "Investigation"],
        cases,
    )

    explain(
        "Packet captures show what was observed on a particular capture "
        "point. They do not automatically prove what happened elsewhere. "
        "A missing packet may have been dropped before the capture point, "
        "after it, or may not have been transmitted at all. Capture location "
        "and timestamp synchronization therefore matter."
    )


# ============================================================================
# SECTION 20: SECURITY ANALYSIS WITH WIRESHARK
# ============================================================================

def wireshark_security_analysis() -> None:
    """Demonstrate defensive packet-analysis questions."""
    print_title("20. SECURITY ANALYSIS WITH WIRESHARK")

    questions = [
        "Which hosts communicate with each other?",
        "Which ports and protocols are exposed?",
        "Are there unexpected clear-text credentials or sensitive payloads?",
        "Are there unusual DNS requests or high query volumes?",
        "Are there repeated TCP connection attempts?",
        "Are there unexpected external destinations?",
        "Are ARP replies inconsistent with the expected local network?",
        "Are there signs of scanning or connection enumeration?",
        "Are there repeated retransmissions or resets that indicate disruption?",
        "Does encrypted traffic use the expected protocol and endpoint?",
    ]

    for index, question in enumerate(questions, start=1):
        print(f"{index:2}. {question}")

    explain(
        "Packet analysis should be performed only on traffic that you are "
        "authorized to inspect. Captures can contain credentials, tokens, "
        "personal information, internal addresses and other sensitive data. "
        "Treat PCAP files as sensitive evidence and protect them accordingly."
    )


# ============================================================================
# SECTION 21: PROTOCOL CLASSIFICATION ENGINE
# ============================================================================

@dataclass
class ProtocolObservation:
    """Describe a protocol and its conceptual OSI placement."""

    name: str
    layer: str
    pdu: str
    purpose: str


def build_protocol_catalog() -> list[ProtocolObservation]:
    """Return a useful set of protocol examples."""
    return [
        ProtocolObservation(
            "HTTP",
            "Application (7)",
            "Data",
            "Web request/response semantics",
        ),
        ProtocolObservation(
            "DNS",
            "Application (7)",
            "Data",
            "Name and service resolution",
        ),
        ProtocolObservation(
            "TLS",
            "Presentation/session/application boundary",
            "Protected records",
            "Confidentiality and authenticated communication",
        ),
        ProtocolObservation(
            "TCP",
            "Transport (4)",
            "Segment",
            "Reliable ordered byte stream",
        ),
        ProtocolObservation(
            "UDP",
            "Transport (4)",
            "Datagram",
            "Connectionless datagram delivery",
        ),
        ProtocolObservation(
            "IPv4",
            "Network (3)",
            "Packet",
            "Logical addressing and routing",
        ),
        ProtocolObservation(
            "IPv6",
            "Network (3)",
            "Packet",
            "Next-generation IP addressing and routing",
        ),
        ProtocolObservation(
            "ICMP",
            "Network (3)",
            "Message",
            "Network control and diagnostics",
        ),
        ProtocolObservation(
            "ARP",
            "Data Link / Network boundary",
            "Frame/message",
            "IPv4-to-MAC resolution on local networks",
        ),
        ProtocolObservation(
            "Ethernet",
            "Data Link (2)",
            "Frame",
            "Local-link framing and MAC addressing",
        ),
    ]


def demonstrate_protocol_catalog() -> None:
    """Display protocol-to-layer mappings."""
    print_title("21. PROTOCOL-TO-LAYER CLASSIFICATION")

    catalog = build_protocol_catalog()

    rows = [
        [item.name, item.layer, item.pdu, item.purpose]
        for item in catalog
    ]

    print_table(["Protocol", "OSI placement", "PDU", "Purpose"], rows)


# ============================================================================
# SECTION 22: PCAP PARSER
# ============================================================================

@dataclass
class PcapPacket:
    """Represent one classic PCAP record."""

    timestamp_seconds: int
    timestamp_fraction: int
    captured_length: int
    original_length: int
    data: bytes


@dataclass
class ParsedPacket:
    """Store educationally decoded packet information."""

    number: int
    timestamp: str
    source_mac: Optional[str] = None
    destination_mac: Optional[str] = None
    ether_type: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    transport: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tcp_flags: list[str] = field(default_factory=list)
    payload_length: int = 0
    notes: list[str] = field(default_factory=list)


class PcapReader:
    """
    Minimal classic PCAP reader.

    Supported:
        - Standard libpcap global headers
        - Little/big endian variants
        - Ethernet link type
        - Ethernet II
        - Optional single 802.1Q VLAN tag
        - IPv4
        - TCP
        - UDP

    Not a complete PCAP/PCAPNG implementation.
    """

    MAGIC_LITTLE_USEC = 0xA1B2C3D4
    MAGIC_BIG_USEC = 0xD4C3B2A1
    MAGIC_LITTLE_NSEC = 0xA1B23C4D
    MAGIC_BIG_NSEC = 0x4D3CB2A1

    def __init__(self, filename: str):
        self.filename = filename
        self.endian = "<"
        self.timestamp_divisor = 1_000_000
        self.link_type = None

    def _read_global_header(self, file_handle: Any) -> None:
        """Read and interpret the 24-byte classic PCAP global header."""
        raw = file_handle.read(24)

        if len(raw) != 24:
            raise ValueError("PCAP file is shorter than the global header.")

        magic_raw = raw[:4]

        little_magic = struct.unpack("<I", magic_raw)[0]
        big_magic = struct.unpack(">I", magic_raw)[0]

        if little_magic == self.MAGIC_LITTLE_USEC:
            self.endian = "<"
            self.timestamp_divisor = 1_000_000
        elif little_magic == self.MAGIC_LITTLE_NSEC:
            self.endian = "<"
            self.timestamp_divisor = 1_000_000_000
        elif big_magic == self.MAGIC_BIG_USEC:
            self.endian = ">"
            self.timestamp_divisor = 1_000_000
        elif big_magic == self.MAGIC_BIG_NSEC:
            self.endian = ">"
            self.timestamp_divisor = 1_000_000_000
        else:
            raise ValueError(
                "Unsupported PCAP magic number. "
                "PCAPNG is not supported by this educational parser."
            )

        (
            _magic,
            _major,
            _minor,
            _thiszone,
            _sigfigs,
            _snaplen,
            self.link_type,
        ) = struct.unpack(self.endian + "IHHiiii", raw)

    def packets(self) -> Iterable[PcapPacket]:
        """Yield packets from a classic PCAP file."""
        with open(self.filename, "rb") as file_handle:
            self._read_global_header(file_handle)

            if self.link_type != 1:
                raise ValueError(
                    f"Unsupported link type {self.link_type}. "
                    "This parser expects Ethernet."
                )

            number = 0

            while True:
                record_header = file_handle.read(16)

                if not record_header:
                    break

                if len(record_header) != 16:
                    raise ValueError("Truncated PCAP record header.")

                (
                    timestamp_seconds,
                    timestamp_fraction,
                    captured_length,
                    original_length,
                ) = struct.unpack(self.endian + "IIII", record_header)

                data = file_handle.read(captured_length)

                if len(data) != captured_length:
                    raise ValueError("Truncated PCAP packet data.")

                number += 1

                yield PcapPacket(
                    timestamp_seconds=timestamp_seconds,
                    timestamp_fraction=timestamp_fraction,
                    captured_length=captured_length,
                    original_length=original_length,
                    data=data,
                )


def format_mac(raw: bytes) -> str:
    """Format six raw bytes as a MAC address."""
    if len(raw) != 6:
        raise ValueError("MAC address must contain six bytes.")

    return ":".join(f"{byte:02x}" for byte in raw)


def parse_ethernet_packet(packet_number: int, timestamp: str,
                          frame: bytes) -> ParsedPacket:
    """Decode an Ethernet frame and common payloads."""
    parsed = ParsedPacket(
        number=packet_number,
        timestamp=timestamp,
    )

    if len(frame) < 14:
        parsed.notes.append("Truncated Ethernet frame.")
        return parsed

    parsed.destination_mac = format_mac(frame[0:6])
    parsed.source_mac = format_mac(frame[6:12])

    ether_type = struct.unpack("!H", frame[12:14])[0]
    payload_offset = 14

    # 802.1Q VLAN tag.
    if ether_type == 0x8100:
        if len(frame) < 18:
            parsed.notes.append("Truncated VLAN-tagged frame.")
            return parsed

        vlan_tci = struct.unpack("!H", frame[14:16])[0]
        parsed.notes.append(f"802.1Q VLAN ID={vlan_tci & 0x0FFF}")

        ether_type = struct.unpack("!H", frame[16:18])[0]
        payload_offset = 18

    parsed.ether_type = ether_type
    network_payload = frame[payload_offset:]

    if ether_type == 0x0800:
        parse_ipv4_into_result(parsed, network_payload)
    elif ether_type == 0x0806:
        parsed.notes.append("ARP frame")
    elif ether_type == 0x86DD:
        parsed.notes.append("IPv6 frame")
    else:
        parsed.notes.append(
            f"Unsupported/unknown EtherType 0x{ether_type:04x}"
        )

    return parsed


def parse_ipv4_into_result(parsed: ParsedPacket, packet: bytes) -> None:
    """Decode IPv4 and TCP/UDP details into a ParsedPacket."""
    try:
        ipv4, transport_payload = parse_ipv4_header(packet)
    except ValueError as exc:
        parsed.notes.append(f"IPv4 parse error: {exc}")
        return

    parsed.source_ip = ipv4.source
    parsed.destination_ip = ipv4.destination

    protocol_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    parsed.transport = protocol_map.get(
        ipv4.protocol,
        f"Protocol {ipv4.protocol}",
    )

    if ipv4.protocol == 6:
        try:
            tcp, application_payload = parse_tcp_header(transport_payload)
            parsed.source_port = tcp.source_port
            parsed.destination_port = tcp.destination_port
            parsed.tcp_flags = tcp_flags_to_names(tcp.flags)
            parsed.payload_length = len(application_payload)
        except ValueError as exc:
            parsed.notes.append(f"TCP parse error: {exc}")

    elif ipv4.protocol == 17:
        try:
            udp, application_payload = parse_udp_header(transport_payload)
            parsed.source_port = udp.source_port
            parsed.destination_port = udp.destination_port
            parsed.payload_length = len(application_payload)
        except ValueError as exc:
            parsed.notes.append(f"UDP parse error: {exc}")

    else:
        parsed.payload_length = len(transport_payload)


def analyze_pcap(filename: str, limit: int = 50) -> None:
    """Read and display a bounded number of packets from a PCAP file."""
    print_title(f"22. PCAP ANALYSIS: {filename}")

    if not os.path.isfile(filename):
        print("File does not exist.")
        return

    reader = PcapReader(filename)

    try:
        packets = reader.packets()

        parsed_packets = []

        for index, packet in enumerate(packets, start=1):
            if index > limit:
                break

            fraction = packet.timestamp_fraction / reader.timestamp_divisor
            timestamp = f"{packet.timestamp_seconds}.{int(fraction * 1_000_000):06d}"

            parsed = parse_ethernet_packet(
                index,
                timestamp,
                packet.data,
            )
            parsed_packets.append(parsed)

        if not parsed_packets:
            print("No packets found.")
            return

        rows = []

        for packet in parsed_packets:
            flags = ",".join(packet.tcp_flags)
            endpoint = ""

            if packet.source_port is not None:
                endpoint = (
                    f"{packet.source_port} -> "
                    f"{packet.destination_port}"
                )

            rows.append(
                [
                    str(packet.number),
                    packet.timestamp,
                    packet.source_ip or "-",
                    packet.destination_ip or "-",
                    packet.transport or "-",
                    endpoint,
                    flags or "-",
                    str(packet.payload_length),
                ]
            )

        print_table(
            [
                "#",
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Transport",
                "Ports",
                "TCP flags",
                "Payload",
            ],
            rows,
        )

        print("\nPacket notes:")

        for packet in parsed_packets:
            if packet.notes:
                print(
                    f"Packet {packet.number}: "
                    + "; ".join(packet.notes)
                )

        print(f"\nDisplayed up to {limit} packet(s).")

    except (OSError, ValueError, struct.error) as exc:
        print(f"PCAP analysis failed: {exc}")


# ============================================================================
# SECTION 23: PCAP ANALYSIS EXERCISES
# ============================================================================

def pcap_analysis_methodology() -> None:
    """Explain a disciplined methodology for packet investigations."""
    print_title("23. A DISCIPLINED PACKET-ANALYSIS METHOD")

    steps = [
        "Define the question before filtering.",
        "Identify the capture point and interface.",
        "Establish the time window.",
        "Identify source and destination systems.",
        "Identify protocols and ports.",
        "Inspect the relevant conversation.",
        "Check packet ordering and TCP state.",
        "Check retransmissions, resets, duplicate ACKs and timing.",
        "Inspect application-layer fields where visible and authorized.",
        "Compare observations against the expected network design.",
        "Record evidence separately from interpretation.",
    ]

    for index, step in enumerate(steps, start=1):
        print(f"{index:2}. {step}")

    explain(
        "A packet capture is evidence, not automatically an explanation. "
        "For example, a TCP retransmission proves that a segment was "
        "retransmitted according to the observed endpoint behavior, but "
        "additional evidence may be required to establish why the original "
        "segment was not acknowledged."
    )


# ============================================================================
# SECTION 24: FRAGMENTATION
# ============================================================================

def demonstrate_ipv4_fragmentation() -> None:
    """Explain the important concepts surrounding IPv4 fragmentation."""
    print_title("24. IPV4 FRAGMENTATION")

    explain(
        "IPv4 permits fragmentation when a packet is too large for a network "
        "link's MTU under relevant conditions. The Identification field, "
        "fragment offset and More Fragments flag allow fragments to be "
        "reassembled at the destination. Fragmentation can complicate "
        "inspection and filtering and can create operational and security "
        "issues when devices interpret fragments differently."
    )

    print("\nImportant fields:")
    print("- Identification: associates fragments with an original datagram.")
    print("- Fragment Offset: identifies the fragment's position.")
    print("- MF flag: indicates that more fragments follow.")
    print("- DF flag: requests that a packet not be fragmented.")

    print("\nExample conceptual fragments:")
    fragments = [
        ("Fragment 1", 0, 1),
        ("Fragment 2", 185, 1),
        ("Fragment 3", 370, 0),
    ]

    print_table(
        ["Fragment", "Offset units", "More Fragments"],
        [[name, str(offset), str(mf)] for name, offset, mf in fragments],
    )


# ============================================================================
# SECTION 25: VLAN AND SWITCHING
# ============================================================================

def demonstrate_vlan_concepts() -> None:
    """Explain VLANs and their relationship to Layer 2."""
    print_title("25. VLANS AND SWITCHING")

    explain(
        "A VLAN logically separates Layer 2 broadcast domains. IEEE 802.1Q "
        "adds a VLAN tag to Ethernet frames on tagged links. Access ports "
        "normally carry traffic associated with one VLAN, while trunk links "
        "can carry multiple VLANs."
    )

    rows = [
        ["Access port", "Usually one VLAN", "End host connection"],
        ["Trunk port", "Multiple VLANs", "Switch-to-switch or network-device link"],
        ["802.1Q tag", "Carries VLAN identifier", "Inserted into Ethernet framing"],
        ["Broadcast domain", "Logical Layer 2 scope", "VLAN-specific"],
    ]

    print_table(["Concept", "Typical behavior", "Purpose"], rows)


# ============================================================================
# SECTION 26: NAT
# ============================================================================

def demonstrate_nat() -> None:
    """Explain basic network address translation."""
    print_title("26. NETWORK ADDRESS TRANSLATION")

    explain(
        "NAT changes address and sometimes port information as packets cross "
        "a translation device. Port Address Translation, commonly called PAT, "
        "allows multiple private hosts to share a public IPv4 address by "
        "tracking transport-layer port mappings."
    )

    mapping = {
        ("192.168.1.10", 51514): ("203.0.113.10", 40001),
        ("192.168.1.11", 51515): ("203.0.113.10", 40002),
    }

    print_table(
        ["Private endpoint", "Translated public endpoint"],
        [
            [
                f"{private_ip}:{private_port}",
                f"{public_ip}:{public_port}",
            ]
            for (private_ip, private_port), (public_ip, public_port)
            in mapping.items()
        ],
    )

    explain(
        "NAT is not equivalent to a firewall. It can reduce unsolicited "
        "reachability in common configurations, but security policy should "
        "be implemented explicitly rather than relying on address translation."
    )


# ============================================================================
# SECTION 27: TLS AND ENCRYPTION
# ============================================================================

def explain_tls_security() -> None:
    """Explain TLS in relation to the OSI model."""
    print_title("27. TLS AND THE OSI MODEL")

    explain(
        "TLS provides cryptographic protections for application communication. "
        "Its responsibilities include authentication of the server through "
        "certificates, confidentiality and integrity of protected records. "
        "Because the OSI model separates presentation and session concepts "
        "that modern Internet stacks often combine, TLS is frequently mapped "
        "loosely to Layers 5-7 rather than one exact layer."
    )

    print("\nTLS protects against:")
    print("- Passive interception of protected application content.")
    print("- Undetected modification when authentication succeeds.")
    print("- Server impersonation when certificate validation is performed correctly.")

    print("\nTLS does not automatically hide:")
    print("- The existence of network traffic.")
    print("- IP addresses in ordinary IP routing.")
    print("- Transport ports.")
    print("- Packet sizes and timing patterns.")
    print("- Every metadata field visible outside encrypted records.")

    print("\nOperational lesson:")
    print(
        "Encryption protects content, but packet metadata can remain valuable "
        "for troubleshooting and traffic analysis."
    )


# ============================================================================
# SECTION 28: SECURITY ATTACK MAPPING
# ============================================================================

def map_attack_to_layers() -> None:
    """Map representative attacks to the layers they can involve."""
    print_title("28. ATTACKS AND LAYER INTERACTIONS")

    attacks = [
        ["ARP spoofing", "2 / boundary with 3", "False IP-to-MAC associations"],
        ["MAC flooding", "2", "Switch forwarding-table exhaustion"],
        ["IP spoofing", "3", "Forged source IP information"],
        ["Port scanning", "4", "Discovery of reachable services"],
        ["SYN flood", "4", "Large volume of incomplete TCP handshakes"],
        ["DNS abuse", "7", "Malicious or abnormal name-resolution activity"],
        ["HTTP injection", "7", "Application input interpreted as commands"],
        ["TLS downgrade", "5-7", "Weakening negotiation under vulnerable conditions"],
        ["Physical tapping", "1", "Unauthorized access to transmission medium"],
    ]

    print_table(
        ["Attack", "Layer", "Core idea"],
        attacks,
    )

    explain(
        "Layer classification is useful for reasoning but should not be used "
        "to force an attack into one box. Many attacks exploit assumptions "
        "across layers, and defensive controls commonly operate across "
        "multiple layers."
    )


# ============================================================================
# SECTION 29: EDGE CASES AND SUBTLE BEHAVIOR
# ============================================================================

def demonstrate_edge_cases() -> None:
    """Demonstrate networking edge cases that commonly cause confusion."""
    print_title("29. EDGE CASES AND SUBTLE BEHAVIOR")

    cases = [
        (
            "Port 443 does not prove HTTPS",
            "A service can listen on any port; port numbers are conventions "
            "rather than cryptographic proof of application identity.",
        ),
        (
            "TCP does not preserve messages",
            "TCP provides an ordered byte stream. Application message "
            "boundaries must be defined by the application protocol.",
        ),
        (
            "UDP does preserve datagram boundaries",
            "Each UDP datagram is independently represented at the transport layer, "
            "though delivery is not guaranteed.",
        ),
        (
            "A packet capture may be incomplete",
            "Capture filters, snap length, dropped packets, offloading and "
            "capture-point placement can affect observations.",
        ),
        (
            "Checksum validation can be misleading on a host capture",
            "Checksum offloading may cause Wireshark to report apparent bad "
            "checksums for packets before hardware/software completes them.",
        ),
        (
            "Wireshark protocol classification is heuristic",
            "Dissectors may infer protocols from ports, signatures, conversation "
            "state or explicit metadata.",
        ),
        (
            "OSI layers are conceptual",
            "Real protocol stacks do not always implement seven independent layers.",
        ),
    ]

    print_table(
        ["Case", "Why it matters"],
        [[name, explanation] for name, explanation in cases],
    )


# ============================================================================
# SECTION 30: OFFLOADING
# ============================================================================

def explain_offloading() -> None:
    """Explain common NIC offloading effects visible in packet captures."""
    print_title("30. NIC OFFLOADING AND WIRESHARK")

    explain(
        "Modern network interfaces and operating systems can offload work "
        "such as checksum calculation, TCP segmentation and receive-side "
        "processing. A host capture may therefore show packet characteristics "
        "that differ from what actually crossed the physical wire."
    )

    print("\nExamples:")
    print("- TCP Segmentation Offload (TSO)")
    print("- Generic Segmentation Offload (GSO)")
    print("- Large Receive Offload (LRO)")
    print("- Checksum offloading")

    print("\nTroubleshooting principle:")
    print(
        "When a host capture shows unusual checksum or segmentation behavior, "
        "compare the capture point and NIC offload configuration before "
        "concluding that the network is corrupt."
    )


# ============================================================================
# SECTION 31: PERFORMANCE CONSIDERATIONS
# ============================================================================

def discuss_performance() -> None:
    """Discuss how layer behavior influences network performance."""
    print_title("31. PERFORMANCE CONSIDERATIONS")

    rows = [
        [
            "Latency",
            "Propagation, processing, queueing and transmission delay",
            "Measure packet timestamps and RTT carefully",
        ],
        [
            "Bandwidth",
            "Maximum transmission capacity",
            "Do not confuse bandwidth with actual throughput",
        ],
        [
            "Throughput",
            "Useful data delivered per unit time",
            "Affected by congestion, loss, protocol overhead and application behavior",
        ],
        [
            "Jitter",
            "Variation in packet delay",
            "Important for interactive and real-time applications",
        ],
        [
            "Packet loss",
            "Packets fail to reach the expected destination",
            "Can trigger retransmissions and reduce application throughput",
        ],
        [
            "MTU",
            "Maximum transmission-unit constraints",
            "Oversized packets can cause fragmentation or PMTUD issues",
        ],
    ]

    print_table(
        ["Metric", "Meaning", "Practical implication"],
        rows,
    )

    explain(
        "Network performance should be analyzed end-to-end. A high-speed "
        "physical link does not guarantee high application throughput if "
        "the path has loss, congestion, inefficient transport behavior, "
        "server delay or application-level bottlenecks."
    )


# ============================================================================
# SECTION 32: DEBUGGING PRINCIPLES
# ============================================================================

def demonstrate_debugging_method() -> None:
    """Show a structured approach to troubleshooting network failures."""
    print_title("32. DEBUGGING NETWORK PROBLEMS")

    layers = [
        "1. Physical: Is the interface/link actually operational?",
        "2. Data Link: Is local neighbor resolution and switching working?",
        "3. Network: Is the destination routable and reachable?",
        "4. Transport: Is the expected port listening and responding?",
        "5-7. Session/Application: Does the protocol exchange complete correctly?",
    ]

    for layer in layers:
        print(layer)

    print("\nExample diagnosis:")
    print("Symptom: Browser cannot reach an HTTPS service.")
    print("Step 1: Check DNS resolution.")
    print("Step 2: Check TCP SYN/SYN-ACK/ACK.")
    print("Step 3: Check TLS handshake.")
    print("Step 4: Check HTTP request/response.")
    print("Step 5: Correlate delays, resets, retransmissions and errors.")

    explain(
        "The OSI model is particularly valuable during troubleshooting because "
        "it encourages a systematic separation of concerns. It prevents a "
        "common mistake: changing multiple unrelated variables before the "
        "actual failure domain is established."
    )


# ============================================================================
# SECTION 33: TESTING PACKET PARSERS
# ============================================================================

def build_ipv4_packet(
    source: str,
    destination: str,
    protocol: int,
    payload: bytes,
    identification: int = 1,
    ttl: int = 64,
) -> bytes:
    """Build a minimal IPv4 packet for parser testing."""
    source_raw = socket.inet_aton(source)
    destination_raw = socket.inet_aton(destination)

    version_ihl = (4 << 4) | 5
    total_length = 20 + len(payload)

    flags_fragment = 0

    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        0,
        source_raw,
        destination_raw,
    )

    checksum = internet_checksum(header_without_checksum)

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        checksum,
        source_raw,
        destination_raw,
    )

    return header + payload


def build_tcp_segment(
    source_port: int,
    destination_port: int,
    sequence_number: int,
    acknowledgment_number: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    """Build a minimal TCP segment without calculating its pseudo-header checksum."""
    data_offset = 5
    offset_flags = (data_offset << 12) | (flags & 0x01FF)

    header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence_number,
        acknowledgment_number,
        offset_flags,
        65535,
        0,
        0,
    )

    return header + payload


def build_ethernet_frame(
    source_mac: bytes,
    destination_mac: bytes,
    ether_type: int,
    payload: bytes,
) -> bytes:
    """Build a minimal Ethernet II frame."""
    if len(source_mac) != 6 or len(destination_mac) != 6:
        raise ValueError("Ethernet MAC values must contain six bytes.")

    return (
        destination_mac
        + source_mac
        + struct.pack("!H", ether_type)
        + payload
    )


def test_packet_parsers() -> None:
    """Run assertions against the educational packet parsers."""
    print_title("33. UNIT TESTS FOR PACKET PARSERS")

    tcp_segment = build_tcp_segment(
        source_port=50000,
        destination_port=443,
        sequence_number=1000,
        acknowledgment_number=0,
        flags=0x02,
    )

    ip_packet = build_ipv4_packet(
        source="192.168.1.10",
        destination="192.168.1.20",
        protocol=6,
        payload=tcp_segment,
    )

    ethernet_frame = build_ethernet_frame(
        source_mac=bytes.fromhex("001122334455"),
        destination_mac=bytes.fromhex("aabbccddeeff"),
        ether_type=0x0800,
        payload=ip_packet,
    )

    parsed = parse_ethernet_packet(
        1,
        "0.000001",
        ethernet_frame,
    )

    assert parsed.source_mac == "00:11:22:33:44:55"
    assert parsed.destination_mac == "aa:bb:cc:dd:ee:ff"
    assert parsed.source_ip == "192.168.1.10"
    assert parsed.destination_ip == "192.168.1.20"
    assert parsed.transport == "TCP"
    assert parsed.source_port == 50000
    assert parsed.destination_port == 443
    assert "SYN" in parsed.tcp_flags

    print("PASS: Ethernet parser")
    print("PASS: IPv4 parser")
    print("PASS: TCP parser")
    print("PASS: TCP SYN flag decoding")

    try:
        parse_ipv4_header(b"\x45")
    except ValueError:
        print("PASS: Truncated IPv4 packet rejected")
    else:
        raise AssertionError("Truncated IPv4 packet should fail")


# ============================================================================
# SECTION 34: BUILD A SYN PACKET FOR ANALYSIS
# ============================================================================

def demonstrate_constructed_packet() -> None:
    """Construct and decode a simple synthetic Ethernet/IP/TCP packet."""
    print_title("34. CONSTRUCTING AND DECODING A SYN PACKET")

    tcp_segment = build_tcp_segment(
        source_port=51514,
        destination_port=443,
        sequence_number=12345,
        acknowledgment_number=0,
        flags=0x02,
    )

    ipv4_packet = build_ipv4_packet(
        source="192.168.1.50",
        destination="93.184.216.34",
        protocol=6,
        payload=tcp_segment,
        identification=42,
    )

    ethernet_frame = build_ethernet_frame(
        source_mac=bytes.fromhex("001122334455"),
        destination_mac=bytes.fromhex("aabbccddeeff"),
        ether_type=0x0800,
        payload=ipv4_packet,
    )

    parsed = parse_ethernet_packet(
        1,
        "0.000000",
        ethernet_frame,
    )

    print(f"Ethernet source:      {parsed.source_mac}")
    print(f"Ethernet destination: {parsed.destination_mac}")
    print(f"IPv4 source:          {parsed.source_ip}")
    print(f"IPv4 destination:     {parsed.destination_ip}")
    print(f"Transport:            {parsed.transport}")
    print(f"Source port:          {parsed.source_port}")
    print(f"Destination port:     {parsed.destination_port}")
    print(f"TCP flags:            {', '.join(parsed.tcp_flags)}")


# ============================================================================
# SECTION 35: DESIGN AND PRODUCTION CONSIDERATIONS
# ============================================================================

def discuss_production_considerations() -> None:
    """Discuss production-level packet analysis and networking concerns."""
    print_title("35. PRODUCTION CONSIDERATIONS")

    considerations = [
        (
            "Capture placement",
            "A packet seen on one interface does not represent every point in the path."
        ),
        (
            "Time synchronization",
            "Accurate clocks make correlation across hosts and captures possible."
        ),
        (
            "Packet loss during capture",
            "High-speed environments may drop packets before analysis."
        ),
        (
            "Privacy",
            "PCAP files may contain sensitive personal or business information."
        ),
        (
            "Encryption",
            "TLS protects content but does not eliminate all observable metadata."
        ),
        (
            "Protocol evolution",
            "Modern protocols can blur traditional OSI boundaries."
        ),
        (
            "Hardware acceleration",
            "Offloads can alter the appearance of packets in host captures."
        ),
        (
            "Scale",
            "Large captures require filtering, indexing and careful storage management."
        ),
        (
            "Evidence integrity",
            "Security investigations require controlled acquisition and preservation."
        ),
    ]

    print_table(
        ["Concern", "Production implication"],
        [[name, implication] for name, implication in considerations],
    )


# ============================================================================
# SECTION 36: COMMON MISTAKES
# ============================================================================

def common_mistakes() -> None:
    """List common misconceptions and their corrections."""
    print_title("36. COMMON OSI AND WIRESHARK MISTAKES")

    mistakes = [
        [
            "Thinking OSI is the exact Internet implementation",
            "Treat OSI as a conceptual reference model.",
        ],
        [
            "Calling an IP packet a frame",
            "Use frame for Layer 2 and packet for Layer 3.",
        ],
        [
            "Assuming TCP is an application protocol",
            "TCP is a transport protocol.",
        ],
        [
            "Assuming port 443 guarantees HTTPS",
            "Ports are identifiers/conventions, not proof of protocol identity.",
        ],
        [
            "Assuming TCP preserves application messages",
            "TCP provides a byte stream, not message boundaries.",
        ],
        [
            "Assuming encrypted traffic is invisible",
            "Metadata such as addresses, ports, sizes and timing can remain visible.",
        ],
        [
            "Treating a bad checksum in a host capture as definite corruption",
            "Consider checksum offloading.",
        ],
        [
            "Using one packet to explain an entire failure",
            "Analyze the complete exchange and relevant packet sequence.",
        ],
        [
            "Assuming absence in a capture means absence on the network",
            "Consider capture location, filters and packet loss.",
        ],
        [
            "Treating checksums as security",
            "Checksums detect accidental errors; cryptographic integrity is different.",
        ],
    ]

    print_table(
        ["Mistake", "Correct interpretation"],
        mistakes,
    )


# ============================================================================
# SECTION 37: QUICK REFERENCE
# ============================================================================

def quick_reference() -> None:
    """Print a compact OSI and Wireshark reference."""
    print_title("37. QUICK REFERENCE")

    print("\nOSI:")
    for number in range(7, 0, -1):
        print(
            f"Layer {number}: {LAYER_NAMES[number]:<15} "
            f"PDU={LAYER_PDU_NAMES[number]}"
        )

    print("\nCommon protocols:")
    print("HTTP/HTTPS -> Application")
    print("DNS        -> Application")
    print("TLS        -> Often discussed across Layers 5-7")
    print("TCP        -> Transport")
    print("UDP        -> Transport")
    print("IPv4/IPv6  -> Network")
    print("ICMP       -> Network")
    print("ARP        -> Layer 2/3 boundary")
    print("Ethernet   -> Data Link")
    print("Wi-Fi      -> Data Link + Physical responsibilities")

    print("\nCommon Wireshark filters:")
    for expression in [
        "tcp",
        "udp",
        "dns",
        "http",
        "tls",
        "arp",
        "icmp",
        "tcp.port == 443",
        "tcp.flags.syn == 1",
        "tcp.analysis.retransmission",
    ]:
        print(f"  {expression}")


# ============================================================================
# SECTION 38: KNOWLEDGE CHECK
# ============================================================================

def knowledge_check() -> None:
    """Provide self-contained questions with answers."""
    print_title("38. KNOWLEDGE CHECK")

    questions = [
        (
            "Which OSI layer is responsible for routing?",
            "Layer 3, Network.",
        ),
        (
            "Which OSI layer uses MAC addresses?",
            "Layer 2, Data Link.",
        ),
        (
            "Which layer uses TCP and UDP?",
            "Layer 4, Transport.",
        ),
        (
            "What is the TCP PDU commonly called?",
            "A segment.",
        ),
        (
            "What is the UDP PDU commonly called?",
            "A datagram.",
        ),
        (
            "What is the Layer 2 PDU?",
            "A frame.",
        ),
        (
            "What is the Layer 3 PDU?",
            "A packet.",
        ),
        (
            "What does ARP do in IPv4 networks?",
            "It resolves an IPv4 address to a MAC address on the local link.",
        ),
        (
            "What are the three TCP handshake messages?",
            "SYN, SYN+ACK and ACK.",
        ),
        (
            "Does TCP preserve application message boundaries?",
            "No. TCP provides an ordered byte stream.",
        ),
        (
            "Does a checksum provide cryptographic authentication?",
            "No.",
        ),
        (
            "What is the difference between capture and display filters?",
            "Capture filters restrict captured traffic; display filters restrict what is shown.",
        ),
    ]

    for number, (question, answer) in enumerate(questions, start=1):
        print(f"\n{number}. {question}")
        print(f"   Answer: {answer}")


# ============================================================================
# SECTION 39: ADVANCED RELATIONSHIPS
# ============================================================================

def advanced_relationships() -> None:
    """Explain cross-layer interactions."""
    print_title("39. ADVANCED CROSS-LAYER RELATIONSHIPS")

    relationships = [
        (
            "DNS -> UDP/TCP -> IP -> Ethernet",
            "Application name resolution depends on transport and network delivery."
        ),
        (
            "HTTP -> TLS -> TCP -> IP -> Ethernet",
            "A web application can be protected by TLS before TCP transport."
        ),
        (
            "QUIC -> UDP -> IP -> Ethernet",
            "QUIC implements substantial transport behavior above UDP."
        ),
        (
            "ARP -> Ethernet",
            "IPv4 local neighbor resolution is carried through Layer 2 mechanisms."
        ),
        (
            "DHCP -> UDP -> IP/Ethernet",
            "Address configuration relies on lower-layer communication before normal IP use."
        ),
        (
            "VLAN -> Ethernet",
            "VLAN segmentation modifies Layer 2 framing and broadcast scope."
        ),
    ]

    print_table(
        ["Stack relationship", "Meaning"],
        [[stack, meaning] for stack, meaning in relationships],
    )

    explain(
        "These relationships demonstrate why protocol analysis should focus "
        "on the actual encapsulation and packet sequence rather than memorizing "
        "a rigid list of protocol-to-layer assignments."
    )


# ============================================================================
# SECTION 40: MAIN PROGRAM
# ============================================================================

def run_tutorial() -> None:
    """Run the complete educational tutorial."""
    show_osi_model()
    explain_layer_details()
    compare_osi_and_tcp_ip()
    demonstrate_encapsulation()
    demonstrate_decapsulation()
    demonstrate_addressing()
    simulate_tcp_three_way_handshake()
    compare_tcp_udp()
    demonstrate_routing_and_subnetting()
    demonstrate_ethernet_and_arp()
    explain_dns_and_http()
    demonstrate_security_by_layer()
    simulate_firewall()
    demonstrate_packet_headers()
    demonstrate_checksum()
    explain_wireshark()
    explain_wireshark_packet_tree()
    demonstrate_tcp_wireshark_analysis()
    troubleshoot_with_wireshark()
    wireshark_security_analysis()
    demonstrate_protocol_catalog()
    pcap_analysis_methodology()
    demonstrate_ipv4_fragmentation()
    demonstrate_vlan_concepts()
    demonstrate_nat()
    explain_tls_security()
    map_attack_to_layers()
    demonstrate_edge_cases()
    explain_offloading()
    discuss_performance()
    demonstrate_debugging_method()
    test_packet_parsers()
    demonstrate_constructed_packet()
    discuss_production_considerations()
    common_mistakes()
    advanced_relationships()
    quick_reference()
    knowledge_check()


def main() -> None:
    """Program entry point."""
    print_title("OSI MODEL, ENCAPSULATION, SECURITY AND WIRESHARK")
    print(
        "This executable study file demonstrates networking concepts from "
        "beginner fundamentals through practical packet analysis."
    )

    if len(sys.argv) > 1:
        pcap_filename = sys.argv[1]

        # The tutorial remains available when a PCAP is supplied. This makes
        # the script useful both as a study guide and as a small parser.
        run_tutorial()
        analyze_pcap(pcap_filename)
    else:
        run_tutorial()

    print_title("END OF STUDY SCRIPT")
    print(
        "The examples are conceptual and educational. Real packet analysis "
        "should account for capture location, protocol behavior, encryption, "
        "offloading, filtering, packet loss and authorization."
    )


if __name__ == "__main__":
    main()
