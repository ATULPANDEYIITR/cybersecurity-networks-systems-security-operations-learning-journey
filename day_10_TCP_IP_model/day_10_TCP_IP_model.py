"""
TCP/IP MODEL: NETWORK ACCESS, INTERNET, TRANSPORT, APPLICATION LAYERS
=====================================================================

A self-contained study and demonstration script covering the TCP/IP model
from absolute beginner concepts through advanced networking concepts.

The script uses only Python's standard library.

Topics covered:
- What a network protocol and network model are
- TCP/IP architecture and its four-layer model
- Network Access layer
- Internet layer
- Transport layer
- Application layer
- OSI model comparison and mapping
- Encapsulation and decapsulation
- Frames, packets, segments, and application data
- MAC addresses, IP addresses, ports, and sockets
- Ethernet, ARP, IPv4, IPv6, ICMP
- TCP and UDP
- TCP connection establishment and termination
- TCP reliability, ordering, acknowledgements, retransmission, flow control
- UDP characteristics and use cases
- DNS, HTTP, HTTPS, DHCP, SSH, SMTP, FTP concepts
- Routing and default gateways
- NAT and private addressing
- Client-server communication
- Socket programming
- IPv4 subnet calculations
- CIDR and network prefixes
- Checksums and integrity
- MTU and fragmentation concepts
- TCP/IP troubleshooting
- Security considerations
- Performance considerations
- Common mistakes and edge cases
- Practical simulations and demonstrations
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Iterable, Optional


# ============================================================================
# 1. FUNDAMENTAL TERMINOLOGY
# ============================================================================

def section(title: str) -> None:
    """Print a clearly separated educational section."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_basic_networking() -> None:
    section("1. FUNDAMENTAL NETWORKING TERMINOLOGY")

    concepts = {
        "Network": "A group of interconnected devices that can exchange data.",
        "Protocol": "A defined set of rules used by communicating systems.",
        "Host": "A device or endpoint participating in network communication.",
        "Client": "A program or device that requests a service.",
        "Server": "A program or device that provides a service.",
        "Packet": "A general term for a unit of network-layer data.",
        "Frame": "A data-link/network-access-layer unit carrying network-layer data.",
        "Segment": "The usual name for a TCP transport-layer data unit.",
        "Datagram": "Commonly used for a UDP transport-layer data unit.",
        "IP address": "A logical address used to identify a network interface at the Internet layer.",
        "MAC address": "A link-layer hardware/interface address used on local networks.",
        "Port": "A transport-layer identifier used to distinguish application services.",
        "Socket": "An operating-system communication endpoint identified by address and port.",
        "Routing": "The process of determining where IP traffic should be forwarded.",
        "Switching": "Forwarding frames within a local network, commonly using MAC addresses.",
    }

    for name, definition in concepts.items():
        print(f"{name:15} -> {definition}")

    print("\nImportant distinction:")
    print("MAC addresses primarily identify interfaces on a local link.")
    print("IP addresses provide logical addressing across interconnected networks.")
    print("Ports identify transport-layer application endpoints.")


# ============================================================================
# 2. TCP/IP MODEL OVERVIEW
# ============================================================================

class TCPIPLayer(Enum):
    NETWORK_ACCESS = 1
    INTERNET = 2
    TRANSPORT = 3
    APPLICATION = 4


def show_tcp_ip_model() -> None:
    section("2. TCP/IP MODEL")

    layers = [
        (
            "4. Application",
            "Application protocols and network services",
            "HTTP, HTTPS, DNS, DHCP, SSH, SMTP, FTP"
        ),
        (
            "3. Transport",
            "Process-to-process communication",
            "TCP, UDP"
        ),
        (
            "2. Internet",
            "Logical addressing and routing",
            "IPv4, IPv6, ICMP"
        ),
        (
            "1. Network Access",
            "Local-link delivery and physical transmission",
            "Ethernet, Wi-Fi, ARP"
        ),
    ]

    for layer, responsibility, examples in layers:
        print(f"{layer}")
        print(f"  Responsibility: {responsibility}")
        print(f"  Examples:       {examples}")
        print()

    print("The four-layer TCP/IP model is commonly taught as:")
    print("Application -> Transport -> Internet -> Network Access")

    print("\nData moves downward through the stack during transmission.")
    print("Data moves upward through the stack during reception.")


# ============================================================================
# 3. TCP/IP AND OSI MAPPING
# ============================================================================

def show_osi_mapping() -> None:
    section("3. OSI MODEL TO TCP/IP MODEL MAPPING")

    mapping = [
        ("OSI 7. Application", "TCP/IP Application"),
        ("OSI 6. Presentation", "TCP/IP Application"),
        ("OSI 5. Session", "TCP/IP Application"),
        ("OSI 4. Transport", "TCP/IP Transport"),
        ("OSI 3. Network", "TCP/IP Internet"),
        ("OSI 2. Data Link", "TCP/IP Network Access"),
        ("OSI 1. Physical", "TCP/IP Network Access"),
    ]

    for osi, tcp_ip in mapping:
        print(f"{osi:28} -> {tcp_ip}")

    print("\nKey point:")
    print("OSI has seven conceptual layers.")
    print("The traditional TCP/IP model has four layers.")
    print("The TCP/IP Application layer combines OSI Application, Presentation,")
    print("and Session responsibilities.")
    print("The TCP/IP Network Access layer commonly combines OSI Data Link and")
    print("Physical responsibilities.")

    print("\nThe models are conceptual frameworks rather than physical components.")
    print("Real protocols do not always fit perfectly into one conceptual layer.")


# ============================================================================
# 4. ENCAPSULATION AND DECAPSULATION
# ============================================================================

@dataclass
class ApplicationData:
    payload: bytes


@dataclass
class TransportSegment:
    source_port: int
    destination_port: int
    payload: bytes
    protocol: str = "TCP"


@dataclass
class IPPacket:
    source_ip: str
    destination_ip: str
    payload: bytes
    protocol: str = "TCP"


@dataclass
class EthernetFrame:
    source_mac: str
    destination_mac: str
    payload: bytes
    ether_type: str = "IPv4"


def demonstrate_encapsulation() -> None:
    section("4. ENCAPSULATION AND DECAPSULATION")

    application_data = ApplicationData(
        payload=b"GET /index.html HTTP/1.1"
    )

    print("Application layer:")
    print(f"  Data: {application_data.payload!r}")

    transport = TransportSegment(
        source_port=51514,
        destination_port=80,
        payload=application_data.payload,
        protocol="TCP",
    )

    print("\nTransport layer:")
    print(
        f"  TCP header information: "
        f"{transport.source_port} -> {transport.destination_port}"
    )
    print(f"  Payload: {transport.payload!r}")

    # This is a conceptual serialization, not a real TCP header.
    transport_bytes = (
        transport.source_port.to_bytes(2, "big")
        + transport.destination_port.to_bytes(2, "big")
        + transport.payload
    )

    internet = IPPacket(
        source_ip="192.168.1.10",
        destination_ip="93.184.216.34",
        payload=transport_bytes,
        protocol="TCP",
    )

    print("\nInternet layer:")
    print(f"  Source IP:      {internet.source_ip}")
    print(f"  Destination IP: {internet.destination_ip}")
    print(f"  Protocol:       {internet.protocol}")

    frame = EthernetFrame(
        source_mac="00:11:22:33:44:55",
        destination_mac="AA:BB:CC:DD:EE:FF",
        payload=b"IPv4 header + TCP segment",
    )

    print("\nNetwork Access layer:")
    print(f"  Source MAC:      {frame.source_mac}")
    print(f"  Destination MAC: {frame.destination_mac}")
    print(f"  EtherType:       {frame.ether_type}")

    print("\nConceptual sequence:")
    print("Application data")
    print("    ↓")
    print("TCP segment")
    print("    ↓")
    print("IP packet")
    print("    ↓")
    print("Ethernet frame")

    print("\nAt the destination the process is reversed:")
    print("Ethernet frame -> IP packet -> TCP segment -> application data")


# ============================================================================
# 5. NETWORK ACCESS LAYER
# ============================================================================

def demonstrate_network_access_layer() -> None:
    section("5. NETWORK ACCESS LAYER")

    print("Primary responsibilities:")
    print("1. Local-link delivery")
    print("2. Framing")
    print("3. MAC addressing")
    print("4. Media access")
    print("5. Transmission over a local physical/link technology")

    print("\nTypical technologies:")
    technologies = [
        "Ethernet",
        "Wi-Fi",
        "ARP-related local-link address resolution",
        "Fiber and copper Ethernet media",
        "Wireless LAN technologies",
    ]

    for item in technologies:
        print(f"  - {item}")

    print("\nMAC address example:")
    mac = "00:1A:2B:3C:4D:5E"
    print(f"  {mac}")

    octets = mac.split(":")
    print(f"  Number of hexadecimal octets: {len(octets)}")
    print("  Traditional MAC addresses contain 48 bits.")

    print("\nImportant limitation:")
    print("A MAC address is normally useful only within the relevant local-link")
    print("broadcast domain. Routers do not generally forward Ethernet frames")
    print("unchanged across the Internet.")


# ============================================================================
# 6. MAC ADDRESS VALIDATION
# ============================================================================

def is_valid_mac(mac_address: str) -> bool:
    """Validate a conventional colon-separated 48-bit MAC address."""
    parts = mac_address.split(":")
    if len(parts) != 6:
        return False

    return all(
        len(part) == 2 and all(character in "0123456789abcdefABCDEF" for character in part)
        for part in parts
    )


def demonstrate_mac_validation() -> None:
    section("6. MAC ADDRESS VALIDATION")

    examples = [
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF",
        "00:11:22:33:44",
        "GG:11:22:33:44:55",
        "0011:2233:4455",
    ]

    for address in examples:
        print(f"{address:25} -> {is_valid_mac(address)}")


# ============================================================================
# 7. ARP CONCEPT
# ============================================================================

def simulate_arp() -> None:
    section("7. ARP CONCEPT")

    print("ARP, Address Resolution Protocol, is used in IPv4 local networks")
    print("to discover the MAC address associated with an IPv4 address.")

    arp_table = {
        "192.168.1.1": "AA:AA:AA:AA:AA:01",
        "192.168.1.10": "BB:BB:BB:BB:BB:10",
        "192.168.1.20": "CC:CC:CC:CC:CC:20",
    }

    requested_ip = "192.168.1.20"

    print(f"\nHost asks: Who has {requested_ip}?")
    print(f"Simulated response: {arp_table[requested_ip]}")

    print("\nConceptual ARP exchange:")
    print("Host A -> Ethernet broadcast: Who has 192.168.1.20?")
    print("Host B -> Host A: 192.168.1.20 is at CC:CC:CC:CC:CC:20")

    print("\nImportant distinction:")
    print("IPv6 does not use ARP. IPv6 uses Neighbor Discovery Protocol (NDP),")
    print("which operates through ICMPv6.")


# ============================================================================
# 8. INTERNET LAYER
# ============================================================================

def demonstrate_internet_layer() -> None:
    section("8. INTERNET LAYER")

    print("The Internet layer provides:")
    print("1. Logical addressing")
    print("2. Routing between networks")
    print("3. Packet forwarding")
    print("4. Network-level diagnostics and control")

    print("\nImportant protocols:")
    print("  IPv4")
    print("  IPv6")
    print("  ICMP")
    print("  ICMPv6")

    print("\nExample:")
    source = ipaddress.ip_address("192.168.1.10")
    destination = ipaddress.ip_address("8.8.8.8")

    print(f"Source:      {source}")
    print(f"Destination: {destination}")
    print(f"Source version:      IPv{source.version}")
    print(f"Destination version: IPv{destination.version}")

    print("\nThe router makes forwarding decisions using IP addressing and routing")
    print("information rather than application-layer information in the normal case.")


# ============================================================================
# 9. IPV4 ADDRESSING
# ============================================================================

def demonstrate_ipv4_addressing() -> None:
    section("9. IPV4 ADDRESSING")

    addresses = [
        "192.168.1.10",
        "10.0.0.25",
        "172.16.5.100",
        "8.8.8.8",
        "127.0.0.1",
    ]

    for address in addresses:
        ip = ipaddress.ip_address(address)
        print(
            f"{address:15} "
            f"version=IPv{ip.version}, "
            f"loopback={ip.is_loopback}, "
            f"private={ip.is_private}, "
            f"global={ip.is_global}"
        )

    print("\nCommon IPv4 special ranges:")
    print("  10.0.0.0/8       Private")
    print("  172.16.0.0/12    Private")
    print("  192.168.0.0/16   Private")
    print("  127.0.0.0/8      Loopback")
    print("  169.254.0.0/16   Link-local")


# ============================================================================
# 10. IPV6 ADDRESSING
# ============================================================================

def demonstrate_ipv6() -> None:
    section("10. IPV6 ADDRESSING")

    addresses = [
        "2001:db8::1",
        "::1",
        "fe80::1",
    ]

    for address in addresses:
        ip = ipaddress.ip_address(address)
        print(
            f"{address:20} "
            f"version=IPv{ip.version}, "
            f"loopback={ip.is_loopback}, "
            f"link_local={ip.is_link_local}"
        )

    print("\nIPv6 provides a 128-bit address space.")
    print("IPv4 provides a 32-bit address space.")

    print("\nIPv6 also introduces or emphasizes mechanisms such as:")
    print("  - Neighbor Discovery")
    print("  - Stateless Address Autoconfiguration")
    print("  - Multicast")
    print("  - Extension headers")


# ============================================================================
# 11. SUBNETTING AND CIDR
# ============================================================================

def demonstrate_subnetting() -> None:
    section("11. SUBNETTING AND CIDR")

    networks = [
        "192.168.1.0/24",
        "192.168.1.0/26",
        "10.0.0.0/16",
        "172.16.10.0/28",
    ]

    for network_text in networks:
        network = ipaddress.ip_network(network_text)
        hosts = list(network.hosts())

        print(f"\nNetwork: {network}")
        print(f"  Network address:   {network.network_address}")
        print(f"  Broadcast address: {network.broadcast_address}")
        print(f"  Prefix length:     /{network.prefixlen}")
        print(f"  Total addresses:   {network.num_addresses}")

        if hosts:
            print(f"  First host:        {hosts[0]}")
            print(f"  Last host:         {hosts[-1]}")
        else:
            print("  No conventional host addresses.")

    print("\nCIDR notation expresses the number of leading network bits.")
    print("/24 means 24 network bits and 8 remaining address bits in IPv4.")

    print("\nImportant edge cases:")
    print("/31 and /32 have special uses.")
    print("/31 is commonly used for point-to-point links.")
    print("/32 identifies one IPv4 address.")


# ============================================================================
# 12. ROUTING AND DEFAULT GATEWAY
# ============================================================================

@dataclass
class Route:
    destination: ipaddress.IPv4Network
    next_hop: str
    interface: str


def longest_prefix_match(
    destination: str,
    routes: Iterable[Route],
) -> Optional[Route]:
    """Return the route with the most specific matching prefix."""
    destination_ip = ipaddress.ip_address(destination)
    matching_routes = [
        route for route in routes
        if destination_ip in route.destination
    ]

    if not matching_routes:
        return None

    return max(matching_routes, key=lambda route: route.destination.prefixlen)


def demonstrate_routing() -> None:
    section("12. ROUTING AND DEFAULT GATEWAY")

    routes = [
        Route(
            destination=ipaddress.ip_network("192.168.1.0/24"),
            next_hop="direct",
            interface="LAN",
        ),
        Route(
            destination=ipaddress.ip_network("10.0.0.0/8"),
            next_hop="10.0.0.1",
            interface="WAN1",
        ),
        Route(
            destination=ipaddress.ip_network("0.0.0.0/0"),
            next_hop="192.168.1.1",
            interface="LAN",
        ),
    ]

    destinations = [
        "192.168.1.50",
        "10.20.30.40",
        "8.8.8.8",
    ]

    for destination in destinations:
        route = longest_prefix_match(destination, routes)
        print(f"\nDestination: {destination}")
        if route:
            print(f"  Selected network: {route.destination}")
            print(f"  Next hop:          {route.next_hop}")
            print(f"  Interface:         {route.interface}")
        else:
            print("  No route found.")

    print("\nThe default route 0.0.0.0/0 matches any IPv4 destination.")
    print("A more specific route wins because routing uses longest-prefix matching.")


# ============================================================================
# 13. TRANSPORT LAYER
# ============================================================================

def demonstrate_transport_layer() -> None:
    section("13. TRANSPORT LAYER")

    print("The transport layer provides communication between application processes.")
    print("\nIts major responsibilities can include:")
    print("  - Process-to-process delivery")
    print("  - Port addressing")
    print("  - Multiplexing and demultiplexing")
    print("  - Reliability, when provided by the protocol")
    print("  - Ordering, when provided by the protocol")
    print("  - Flow control, when provided by the protocol")
    print("  - Congestion control, when provided by the protocol")

    print("\nThe two fundamental Internet transport protocols are TCP and UDP.")


# ============================================================================
# 14. TCP VERSUS UDP
# ============================================================================

def compare_tcp_udp() -> None:
    section("14. TCP VERSUS UDP")

    comparisons = [
        ("Connection", "Connection-oriented", "Connectionless"),
        ("Reliability", "Reliable byte stream", "No built-in delivery guarantee"),
        ("Ordering", "Maintains byte order", "No ordering guarantee"),
        ("Retransmission", "Yes", "No"),
        ("Flow control", "Yes", "No built-in TCP-style flow control"),
        ("Congestion control", "Yes", "No built-in TCP-style congestion control"),
        ("Data model", "Byte stream", "Datagrams"),
        ("Typical use", "Web, SSH, databases", "DNS, streaming, real-time traffic"),
    ]

    print(f"{'Property':20} {'TCP':35} {'UDP':35}")
    print("-" * 92)

    for property_name, tcp, udp in comparisons:
        print(f"{property_name:20} {tcp:35} {udp:35}")

    print("\nImportant nuance:")
    print("UDP is not inherently 'faster' in every real application.")
    print("It has less protocol machinery, but application behavior, network")
    print("conditions, congestion, retransmission strategy, and protocol design")
    print("determine actual performance.")


# ============================================================================
# 15. TCP HEADER CONCEPTS
# ============================================================================

def demonstrate_tcp_header_concepts() -> None:
    section("15. TCP HEADER CONCEPTS")

    tcp_fields = [
        "Source port",
        "Destination port",
        "Sequence number",
        "Acknowledgment number",
        "Data offset",
        "Flags",
        "Window size",
        "Checksum",
        "Urgent pointer",
        "Options",
    ]

    for index, field in enumerate(tcp_fields, start=1):
        print(f"{index:2}. {field}")

    print("\nImportant TCP flags:")
    print("  SYN  -> synchronize sequence numbers / initiate connection")
    print("  ACK  -> acknowledgment field is valid")
    print("  FIN  -> sender has finished sending")
    print("  RST  -> reset connection")
    print("  PSH  -> request prompt delivery to application")
    print("  URG  -> urgent pointer has significance")


# ============================================================================
# 16. TCP THREE-WAY HANDSHAKE
# ============================================================================

@dataclass
class TCPSegment:
    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    flags: set[str]
    payload: bytes = b""


def simulate_tcp_handshake() -> None:
    section("16. TCP THREE-WAY HANDSHAKE")

    client_isn = 1000
    server_isn = 5000

    syn = TCPSegment(
        source_port=50000,
        destination_port=443,
        sequence_number=client_isn,
        acknowledgment_number=0,
        flags={"SYN"},
    )

    syn_ack = TCPSegment(
        source_port=443,
        destination_port=50000,
        sequence_number=server_isn,
        acknowledgment_number=client_isn + 1,
        flags={"SYN", "ACK"},
    )

    ack = TCPSegment(
        source_port=50000,
        destination_port=443,
        sequence_number=client_isn + 1,
        acknowledgment_number=server_isn + 1,
        flags={"ACK"},
    )

    print("1. Client -> Server")
    print(f"   SYN seq={syn.sequence_number}")

    print("2. Server -> Client")
    print(
        f"   SYN+ACK seq={syn_ack.sequence_number} "
        f"ack={syn_ack.acknowledgment_number}"
    )

    print("3. Client -> Server")
    print(
        f"   ACK seq={ack.sequence_number} "
        f"ack={ack.acknowledgment_number}"
    )

    print("\nThe handshake establishes the initial sequence-number state")
    print("and confirms bidirectional communication capability.")


# ============================================================================
# 17. TCP RELIABILITY SIMULATION
# ============================================================================

def simulate_tcp_reliability() -> None:
    section("17. TCP RELIABILITY SIMULATION")

    messages = [
        (1000, b"Hello"),
        (1005, b"World"),
        (1010, b"TCP"),
    ]

    received = {
        1000: b"Hello",
        1010: b"TCP",
    }

    print("Sender transmits:")
    for sequence, payload in messages:
        print(f"  seq={sequence}, data={payload!r}")

    print("\nReceiver receives:")
    for sequence, payload in received.items():
        print(f"  seq={sequence}, data={payload!r}")

    missing = [
        (sequence, payload)
        for sequence, payload in messages
        if sequence not in received
    ]

    print("\nMissing segments:")
    for sequence, payload in missing:
        print(f"  seq={sequence}, data={payload!r}")

    print("\nA real TCP implementation can retransmit missing data based on")
    print("acknowledgements, timers, duplicate acknowledgements, and other mechanisms.")


# ============================================================================
# 18. TCP FLOW CONTROL
# ============================================================================

def demonstrate_flow_control() -> None:
    section("18. TCP FLOW CONTROL")

    receiver_buffer = 8192
    bytes_in_buffer = 3000
    advertised_window = receiver_buffer - bytes_in_buffer

    print(f"Receiver buffer capacity: {receiver_buffer} bytes")
    print(f"Bytes currently occupied:  {bytes_in_buffer} bytes")
    print(f"Advertised window:         {advertised_window} bytes")

    print("\nThe receive window communicates how much additional data the receiver")
    print("is currently prepared to accept without overflowing its receive buffer.")

    print("\nZero-window condition:")
    bytes_in_buffer = receiver_buffer
    advertised_window = receiver_buffer - bytes_in_buffer
    print(f"Advertised window: {advertised_window} bytes")

    print("The sender must avoid continuously sending normal data when the")
    print("receiver advertises no available receive window.")


# ============================================================================
# 19. TCP CONGESTION CONTROL CONCEPT
# ============================================================================

def demonstrate_congestion_control() -> None:
    section("19. TCP CONGESTION CONTROL")

    print("TCP congestion control protects the network from excessive traffic.")
    print("\nImportant conceptual variables include:")
    print("  - Congestion window (cwnd)")
    print("  - Slow-start threshold (ssthresh)")
    print("  - Round-trip time (RTT)")
    print("  - Retransmission timeout (RTO)")

    cwnd = 1
    print("\nSimplified slow-start illustration:")
    for round_number in range(1, 7):
        print(f"  RTT {round_number}: conceptual cwnd = {cwnd}")
        cwnd *= 2

    print("\nThis is intentionally simplified.")
    print("Real TCP implementations use sophisticated algorithms and congestion")
    print("signals, and modern TCP behavior is more nuanced than a simple doubling rule.")


# ============================================================================
# 20. TCP CONNECTION TERMINATION
# ============================================================================

def simulate_tcp_termination() -> None:
    section("20. TCP CONNECTION TERMINATION")

    print("A common graceful termination involves FIN and ACK exchanges.")

    steps = [
        "Endpoint A -> Endpoint B: FIN",
        "Endpoint B -> Endpoint A: ACK",
        "Endpoint B -> Endpoint A: FIN",
        "Endpoint A -> Endpoint B: ACK",
    ]

    for number, step in enumerate(steps, start=1):
        print(f"{number}. {step}")

    print("\nTCP can also terminate abnormally with RST.")
    print("TIME_WAIT is an important TCP state used after active close to")
    print("help prevent delayed old segments from interfering with a later connection.")


# ============================================================================
# 21. PORTS AND SOCKETS
# ============================================================================

def demonstrate_ports_and_sockets() -> None:
    section("21. PORTS AND SOCKETS")

    examples = [
        ("HTTP", 80),
        ("HTTPS", 443),
        ("DNS", 53),
        ("SSH", 22),
        ("SMTP", 25),
    ]

    for service, port in examples:
        print(f"{service:10} -> {port}")

    print("\nA TCP endpoint can be described conceptually as:")
    print("(IP address, TCP port)")

    print("\nA complete TCP connection is commonly distinguished by:")
    print("(source IP, source port, destination IP, destination port)")

    print("\nExample:")
    print("(192.168.1.10, 51514, 93.184.216.34, 443)")


# ============================================================================
# 22. APPLICATION LAYER
# ============================================================================

def demonstrate_application_layer() -> None:
    section("22. APPLICATION LAYER")

    applications = {
        "HTTP": "Web application protocol",
        "HTTPS": "HTTP protected with TLS",
        "DNS": "Maps domain names to DNS records",
        "DHCP": "Automatically configures IP networking parameters",
        "SSH": "Secure remote administration protocol",
        "SMTP": "Email transfer protocol",
        "FTP": "File transfer protocol",
        "NTP": "Network time synchronization protocol",
    }

    for protocol, purpose in applications.items():
        print(f"{protocol:8} -> {purpose}")

    print("\nThe Application layer is where application-level network protocols")
    print("define messages, semantics, commands, responses, and data formats.")


# ============================================================================
# 23. HTTP REQUEST/RESPONSE
# ============================================================================

def demonstrate_http() -> None:
    section("23. HTTP REQUEST AND RESPONSE")

    request = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Accept: text/html\r\n"
        "\r\n"
    )

    response = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 13\r\n"
        "\r\n"
        "Hello, World!"
    )

    print("Conceptual HTTP request:")
    print(request)

    print("Conceptual HTTP response:")
    print(response)

    print("HTTP itself defines application-layer semantics.")
    print("TCP or another suitable transport carries the HTTP traffic depending")
    print("on the HTTP version and deployment.")


# ============================================================================
# 24. DNS CONCEPT
# ============================================================================

def demonstrate_dns() -> None:
    section("24. DNS CONCEPT")

    print("DNS, Domain Name System, translates names into resource records.")
    print("\nCommon DNS record types:")
    records = {
        "A": "IPv4 address",
        "AAAA": "IPv6 address",
        "CNAME": "Canonical name / alias",
        "MX": "Mail exchange",
        "NS": "Authoritative name server",
        "TXT": "Text information",
        "PTR": "Reverse lookup",
    }

    for record_type, meaning in records.items():
        print(f"  {record_type:6} -> {meaning}")

    print("\nConceptual lookup:")
    print("www.example.com")
    print("      ↓")
    print("DNS resolver")
    print("      ↓")
    print("DNS response")
    print("      ↓")
    print("IP address")


# ============================================================================
# 25. DNS LOOKUP USING PYTHON
# ============================================================================

def demonstrate_real_dns_lookup(hostname: str = "example.com") -> None:
    section("25. DNS LOOKUP WITH PYTHON")

    try:
        addresses = socket.getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        print(f"DNS lookup failed: {error}")
        return

    unique_addresses = sorted({
        result[4][0]
        for result in addresses
    })

    print(f"Hostname: {hostname}")
    print("Resolved addresses:")
    for address in unique_addresses:
        print(f"  {address}")

    print("\ngetaddrinfo() may return IPv4 and IPv6 results depending on")
    print("the local resolver configuration and network environment.")


# ============================================================================
# 26. DHCP CONCEPT
# ============================================================================

def demonstrate_dhcp() -> None:
    section("26. DHCP CONCEPT")

    print("DHCP dynamically supplies network configuration information.")
    print("\nClassic IPv4 DHCP exchange:")
    print("  DORA")
    print("  D = Discover")
    print("  O = Offer")
    print("  R = Request")
    print("  A = Acknowledgment")

    print("\nA DHCP configuration can include:")
    print("  - IP address")
    print("  - Subnet mask/prefix")
    print("  - Default gateway")
    print("  - DNS servers")
    print("  - Lease duration")

    print("\nDHCP is an Application-layer protocol even though it configures")
    print("parameters used by lower layers.")


# ============================================================================
# 27. NAT CONCEPT
# ============================================================================

@dataclass
class NATMapping:
    private_ip: str
    private_port: int
    public_ip: str
    public_port: int
    destination_ip: str
    destination_port: int


def demonstrate_nat() -> None:
    section("27. NAT AND PRIVATE ADDRESSING")

    mapping = NATMapping(
        private_ip="192.168.1.10",
        private_port=51514,
        public_ip="203.0.113.20",
        public_port=62001,
        destination_ip="93.184.216.34",
        destination_port=443,
    )

    print("Private connection:")
    print(
        f"  {mapping.private_ip}:{mapping.private_port}"
        f" -> {mapping.destination_ip}:{mapping.destination_port}"
    )

    print("\nNAT-translated connection:")
    print(
        f"  {mapping.public_ip}:{mapping.public_port}"
        f" -> {mapping.destination_ip}:{mapping.destination_port}"
    )

    print("\nNAT is not one of the four TCP/IP layers.")
    print("It is a network-functioning technique commonly implemented by routers")
    print("and gateways.")


# ============================================================================
# 28. CHECKSUM CONCEPT
# ============================================================================

def internet_checksum(data: bytes) -> int:
    """
    Compute the standard Internet checksum algorithm used conceptually
    by several Internet protocols.

    The implementation handles odd-length data by padding one zero byte.
    """
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for offset in range(0, len(data), 2):
        word = (data[offset] << 8) + data[offset + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def demonstrate_checksum() -> None:
    section("28. INTERNET CHECKSUM")

    samples = [
        b"hello",
        b"TCP/IP",
        b"network packet",
        b"",
    ]

    for sample in samples:
        checksum = internet_checksum(sample)
        print(f"{sample!r:20} -> checksum 0x{checksum:04X}")

    print("\nChecksums provide an integrity check against certain transmission errors.")
    print("They are not a cryptographic security mechanism.")
    print("A checksum cannot replace authentication or encryption.")


# ============================================================================
# 29. MTU AND FRAGMENTATION
# ============================================================================

def demonstrate_mtu() -> None:
    section("29. MTU AND PACKET SIZE")

    mtu = 1500
    ipv4_header = 20
    tcp_header = 20

    maximum_tcp_payload = mtu - ipv4_header - tcp_header

    print(f"Example Ethernet MTU:       {mtu} bytes")
    print(f"IPv4 header assumption:      {ipv4_header} bytes")
    print(f"TCP header assumption:       {tcp_header} bytes")
    print(f"Approximate TCP payload:     {maximum_tcp_payload} bytes")

    print("\nThe actual available payload can differ because of:")
    print("  - IPv4 options")
    print("  - TCP options")
    print("  - IPv6 headers and extension headers")
    print("  - Tunneling")
    print("  - VPN encapsulation")
    print("  - Different link MTUs")

    print("\nPath MTU Discovery helps endpoints determine an appropriate packet size.")
    print("IPv6 routers do not fragment packets in transit.")


# ============================================================================
# 30. SOCKET PROGRAMMING BASICS
# ============================================================================

def demonstrate_socket_creation() -> None:
    section("30. SOCKET PROGRAMMING BASICS")

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        print("TCP socket:")
        print(f"  family:  {tcp_socket.family}")
        print(f"  type:    {tcp_socket.type}")

        print("\nUDP socket:")
        print(f"  family:  {udp_socket.family}")
        print(f"  type:    {udp_socket.type}")

        print("\nAF_INET represents IPv4.")
        print("SOCK_STREAM commonly represents TCP.")
        print("SOCK_DGRAM commonly represents UDP.")
    finally:
        tcp_socket.close()
        udp_socket.close()


# ============================================================================
# 31. LOCAL TCP SERVER AND CLIENT
# ============================================================================

def tcp_server(
    host: str,
    port: int,
    ready_event: threading.Event,
) -> None:
    """
    Minimal local TCP server.

    The server accepts one client, receives data, and sends an uppercase
    response. Binding to loopback keeps this demonstration local.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(5.0)
        ready_event.set()

        connection, address = server.accept()

        with connection:
            print(f"Server accepted connection from {address}")
            data = connection.recv(4096)
            print(f"Server received: {data!r}")
            connection.sendall(data.upper())

    except Exception as error:
        print(f"TCP server error: {error}")
        ready_event.set()
    finally:
        server.close()


def demonstrate_local_tcp() -> None:
    section("31. LOCAL TCP CLIENT-SERVER COMMUNICATION")

    host = "127.0.0.1"

    # Bind to port 0 so the operating system selects an unused local port.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((host, 0))
    selected_port = probe.getsockname()[1]
    probe.close()

    ready_event = threading.Event()

    server_thread = threading.Thread(
        target=tcp_server,
        args=(host, selected_port, ready_event),
        daemon=True,
    )
    server_thread.start()

    if not ready_event.wait(timeout=2):
        print("Server did not become ready.")
        return

    time.sleep(0.05)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.settimeout(3)
        client.connect((host, selected_port))

        message = b"tcp/ip fundamentals"
        print(f"Client sends: {message!r}")

        client.sendall(message)
        response = client.recv(4096)

        print(f"Client receives: {response!r}")
    except OSError as error:
        print(f"Client error: {error}")
    finally:
        client.close()

    server_thread.join(timeout=2)

    print("\nThis example demonstrates:")
    print("  Application data -> socket -> TCP -> IP -> loopback interface")
    print("and the reverse process on the receiving side.")


# ============================================================================
# 32. UDP SOCKET DEMONSTRATION
# ============================================================================

def udp_server(
    host: str,
    port: int,
    ready_event: threading.Event,
) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        server.bind((host, port))
        server.settimeout(5.0)
        ready_event.set()

        data, address = server.recvfrom(4096)
        print(f"UDP server received {data!r} from {address}")

        server.sendto(data.upper(), address)

    except Exception as error:
        print(f"UDP server error: {error}")
        ready_event.set()
    finally:
        server.close()


def demonstrate_local_udp() -> None:
    section("32. LOCAL UDP CLIENT-SERVER COMMUNICATION")

    host = "127.0.0.1"

    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind((host, 0))
    selected_port = probe.getsockname()[1]
    probe.close()

    ready_event = threading.Event()

    server_thread = threading.Thread(
        target=udp_server,
        args=(host, selected_port, ready_event),
        daemon=True,
    )
    server_thread.start()

    if not ready_event.wait(timeout=2):
        print("UDP server did not become ready.")
        return

    time.sleep(0.05)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        client.settimeout(3)
        message = b"udp/ip fundamentals"

        print(f"Client sends datagram: {message!r}")
        client.sendto(message, (host, selected_port))

        response, address = client.recvfrom(4096)
        print(f"Client receives from {address}: {response!r}")

    except OSError as error:
        print(f"UDP client error: {error}")
    finally:
        client.close()

    server_thread.join(timeout=2)

    print("\nUDP preserves message/datagram boundaries.")
    print("UDP itself does not provide TCP-style reliability or ordering.")


# ============================================================================
# 33. SOCKET TIMEOUTS AND ROBUSTNESS
# ============================================================================

def demonstrate_socket_timeout() -> None:
    section("33. SOCKET TIMEOUTS AND ROBUSTNESS")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.settimeout(1.0)
        print(f"Socket timeout: {sock.gettimeout()} seconds")
        print("A timeout prevents a blocking network operation from waiting indefinitely.")
    finally:
        sock.close()

    print("\nProduction network programs should consider:")
    print("  - Connection timeouts")
    print("  - Read timeouts")
    print("  - Write timeouts")
    print("  - Retries with appropriate limits")
    print("  - Connection cleanup")
    print("  - Partial reads and writes")
    print("  - Remote disconnects")
    print("  - Resource limits")


# ============================================================================
# 34. TCP IS A BYTE STREAM
# ============================================================================

def demonstrate_tcp_byte_stream() -> None:
    section("34. TCP IS A BYTE STREAM")

    print("A common beginner mistake is assuming one send() equals one recv().")
    print("TCP does not preserve application message boundaries.")

    conceptual_application_message = b"HELLO-WORLD"

    print(f"Application writes: {conceptual_application_message!r}")

    possible_reads = [
        b"HELLO",
        b"-WORLD",
    ]

    print("The receiving application might observe:")
    for chunk in possible_reads:
        print(f"  recv() -> {chunk!r}")

    print("\nApplications needing message boundaries must define their own framing.")
    print("Examples include:")
    print("  - Fixed-length records")
    print("  - Delimiter-based messages")
    print("  - Length-prefixed messages")
    print("  - Structured serialization formats")


# ============================================================================
# 35. LENGTH-PREFIXED APPLICATION PROTOCOL
# ============================================================================

def encode_message(message: bytes) -> bytes:
    """Encode a message with a four-byte network-order length prefix."""
    if len(message) > 0xFFFFFFFF:
        raise ValueError("Message is too large for a 32-bit length field.")

    return struct.pack("!I", len(message)) + message


def decode_messages(buffer: bytearray) -> list[bytes]:
    """
    Decode every complete length-prefixed message currently present.

    Incomplete bytes remain in the buffer for a future recv().
    """
    messages = []

    while True:
        if len(buffer) < 4:
            break

        message_length = struct.unpack("!I", buffer[:4])[0]

        if len(buffer) < 4 + message_length:
            break

        message = bytes(buffer[4:4 + message_length])
        del buffer[:4 + message_length]
        messages.append(message)

    return messages


def demonstrate_application_framing() -> None:
    section("35. APPLICATION-LAYER MESSAGE FRAMING")

    original_messages = [
        b"first",
        b"second message",
        b"third",
    ]

    wire_data = b"".join(
        encode_message(message)
        for message in original_messages
    )

    print(f"Encoded byte stream length: {len(wire_data)}")

    receive_buffer = bytearray()

    # Simulate arbitrary TCP recv() boundaries.
    chunks = [
        wire_data[:3],
        wire_data[3:8],
        wire_data[8:],
    ]

    for chunk in chunks:
        receive_buffer.extend(chunk)
        decoded = decode_messages(receive_buffer)

        print(f"Received chunk: {chunk!r}")
        print(f"Decoded messages: {decoded}")

    print(f"Remaining incomplete buffer: {bytes(receive_buffer)!r}")


# ============================================================================
# 36. APPLICATION LAYER PROTOCOL STACK EXAMPLE
# ============================================================================

def demonstrate_web_stack() -> None:
    section("36. COMPLETE WEB COMMUNICATION STACK")

    stack = [
        ("Application", "HTTP", "GET / HTTP/1.1"),
        ("Transport", "TCP", "source port -> destination port"),
        ("Internet", "IP", "source IP -> destination IP"),
        ("Network Access", "Ethernet/Wi-Fi", "source MAC -> destination MAC"),
    ]

    for layer, protocol, example in stack:
        print(f"{layer:18} | {protocol:12} | {example}")

    print("\nWhen HTTPS is used, TLS provides cryptographic protection.")
    print("TLS is generally positioned between application protocols and the")
    print("transport protocol in practical protocol-stack discussions, although")
    print("the exact conceptual layering can vary.")


# ============================================================================
# 37. APPLICATION PROTOCOL PORTS
# ============================================================================

def demonstrate_common_ports() -> None:
    section("37. COMMON APPLICATION PROTOCOL PORTS")

    ports = {
        20: "FTP data",
        21: "FTP control",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        67: "DHCP server",
        68: "DHCP client",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        587: "SMTP submission",
        993: "IMAPS",
        995: "POP3S",
    }

    for port, service in ports.items():
        print(f"{port:5} -> {service}")

    print("\nPort numbers identify services at the transport layer.")
    print("They do not guarantee that a particular service is actually running on")
    print("that port.")


# ============================================================================
# 38. EPHEMERAL PORTS
# ============================================================================

def demonstrate_ephemeral_ports() -> None:
    section("38. EPHEMERAL PORTS")

    print("Client applications commonly use dynamically allocated local ports.")
    print("These are often called ephemeral ports.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.bind(("127.0.0.1", 0))
        address, port = sock.getsockname()
        print(f"Operating system selected local endpoint: {address}:{port}")
    finally:
        sock.close()

    print("\nPort 0 is not normally used as an application destination service port.")
    print("When binding, it can request an available ephemeral port from the OS.")


# ============================================================================
# 39. ICMP CONCEPT
# ============================================================================

def demonstrate_icmp() -> None:
    section("39. ICMP")

    print("ICMP, Internet Control Message Protocol, supports network diagnostics")
    print("and error/control messaging.")

    messages = [
        "Echo Request",
        "Echo Reply",
        "Destination Unreachable",
        "Time Exceeded",
        "Packet Too Big in IPv6",
    ]

    for message in messages:
        print(f"  - {message}")

    print("\nThe ping utility commonly uses ICMP Echo Request and Echo Reply.")
    print("Traceroute can use mechanisms involving TTL/Hop Limit expiration and")
    print("ICMP responses, depending on implementation and platform.")


# ============================================================================
# 40. DNS, HTTP, AND TCP RELATIONSHIP
# ============================================================================

def demonstrate_protocol_relationships() -> None:
    section("40. PROTOCOL RELATIONSHIPS")

    print("A typical web visit may involve several protocols:")
    print("1. DHCP may configure the host.")
    print("2. ARP/NDP may resolve local next-hop addressing.")
    print("3. DNS may resolve a hostname.")
    print("4. TCP may establish a transport connection.")
    print("5. TLS may establish cryptographic protection.")
    print("6. HTTP may exchange web application messages.")
    print("7. IP routes the packets.")
    print("8. Ethernet/Wi-Fi transports frames over local links.")

    print("\nThese protocols cooperate rather than replacing one another.")


# ============================================================================
# 41. LOOPBACK
# ============================================================================

def demonstrate_loopback() -> None:
    section("41. LOOPBACK INTERFACE")

    print("IPv4 loopback:")
    print("  127.0.0.0/8")
    print("  Commonly used address: 127.0.0.1")

    print("\nIPv6 loopback:")
    print("  ::1")

    print("\nLoopback traffic stays within the host.")
    print("It is useful for local development, testing, and inter-process communication.")


# ============================================================================
# 42. NETWORK BYTE ORDER
# ============================================================================

def demonstrate_network_byte_order() -> None:
    section("42. NETWORK BYTE ORDER")

    value = 0x12345678

    network_bytes = struct.pack("!I", value)
    host_little_endian = struct.pack("<I", value)

    print(f"Value:                  0x{value:08X}")
    print(f"Network byte order:     {network_bytes.hex()}")
    print(f"Little-endian example:  {host_little_endian.hex()}")

    print("\nThe ! format in Python's struct module uses network byte order")
    print("and standard sizes for supported formats.")

    print("\nNetwork protocols often specify byte ordering explicitly so different")
    print("CPU architectures interpret multi-byte fields consistently.")


# ============================================================================
# 43. IPV4 HEADER CONCEPTS
# ============================================================================

def demonstrate_ipv4_header() -> None:
    section("43. IPV4 HEADER CONCEPTS")

    fields = [
        "Version",
        "IHL",
        "DSCP/ECN",
        "Total Length",
        "Identification",
        "Flags",
        "Fragment Offset",
        "TTL",
        "Protocol",
        "Header Checksum",
        "Source Address",
        "Destination Address",
        "Options",
    ]

    for field in fields:
        print(f"  - {field}")

    print("\nTTL, Time To Live, limits how long an IPv4 packet can remain in")
    print("routing loops. Routers decrement it as the packet is forwarded.")
    print("When it reaches zero, the packet is discarded.")


# ============================================================================
# 44. IPV6 HEADER CONCEPTS
# ============================================================================

def demonstrate_ipv6_header() -> None:
    section("44. IPV6 HEADER CONCEPTS")

    fields = [
        "Version",
        "Traffic Class",
        "Flow Label",
        "Payload Length",
        "Next Header",
        "Hop Limit",
        "Source Address",
        "Destination Address",
    ]

    for field in fields:
        print(f"  - {field}")

    print("\nIPv6 uses Hop Limit, conceptually corresponding to the forwarding")
    print("lifetime function provided by IPv4 TTL.")

    print("\nIPv6 has a fixed base header size of 40 bytes.")
    print("Optional functionality can be represented using extension headers.")


# ============================================================================
# 45. SECURITY CONSIDERATIONS
# ============================================================================

def demonstrate_security_considerations() -> None:
    section("45. TCP/IP SECURITY CONSIDERATIONS")

    considerations = [
        (
            "IP spoofing",
            "Attackers may forge source addresses in some contexts."
        ),
        (
            "ARP spoofing",
            "Attackers on a local IPv4 network may attempt to manipulate ARP mappings."
        ),
        (
            "DNS attacks",
            "DNS traffic can be manipulated or redirected when not adequately protected."
        ),
        (
            "TCP SYN floods",
            "Attackers can consume server resources through large volumes of connection attempts."
        ),
        (
            "Port scanning",
            "Systems can be probed to identify reachable services."
        ),
        (
            "Unencrypted application protocols",
            "Protocols without encryption may expose sensitive information."
        ),
        (
            "TLS",
            "Provides encryption, integrity protection, and endpoint authentication when correctly configured."
        ),
        (
            "Network segmentation",
            "Separating networks can reduce the impact of compromise."
        ),
    ]

    for issue, explanation in considerations:
        print(f"{issue:25} -> {explanation}")

    print("\nSecurity principles:")
    print("  - Use encryption for sensitive data.")
    print("  - Authenticate endpoints where required.")
    print("  - Minimize exposed services.")
    print("  - Validate untrusted input.")
    print("  - Apply least privilege.")
    print("  - Monitor unusual network behavior.")
    print("  - Avoid treating private IP addressing as a security boundary.")
    print("  - Keep protocol implementations and operating systems maintained.")


# ============================================================================
# 46. TLS POSITIONING
# ============================================================================

def demonstrate_tls() -> None:
    section("46. TLS AND HTTPS")

    print("HTTPS means HTTP carried through a secure TLS connection.")
    print("\nTLS provides:")
    print("  - Confidentiality")
    print("  - Integrity")
    print("  - Server authentication through certificates")
    print("  - Optional client authentication")

    print("\nConceptual stack:")
    print("HTTP")
    print("TLS")
    print("TCP")
    print("IP")
    print("Ethernet/Wi-Fi")

    print("\nModern HTTP deployments can use different transports.")
    print("HTTP/3 uses QUIC, which is based on UDP and incorporates transport")
    print("features together with TLS 1.3 in the QUIC protocol design.")


# ============================================================================
# 47. PERFORMANCE CONSIDERATIONS
# ============================================================================

def demonstrate_performance() -> None:
    section("47. PERFORMANCE CONSIDERATIONS")

    print("Network performance is influenced by multiple factors.")

    factors = [
        "Bandwidth",
        "Latency",
        "Round-trip time",
        "Packet loss",
        "Jitter",
        "Congestion",
        "MTU",
        "TCP window behavior",
        "CPU overhead",
        "Encryption overhead",
        "Application processing time",
        "Server response time",
    ]

    for factor in factors:
        print(f"  - {factor}")

    print("\nBandwidth is capacity.")
    print("Latency is delay.")
    print("Throughput is the rate at which useful data is delivered.")
    print("Good bandwidth does not automatically imply low latency.")

    print("\nA simple bandwidth-delay product estimate:")
    bandwidth_bits_per_second = 100_000_000
    round_trip_time_seconds = 0.050

    bandwidth_delay_product = (
        bandwidth_bits_per_second * round_trip_time_seconds
    )

    print(f"Bandwidth: {bandwidth_bits_per_second:,} bits/s")
    print(f"RTT:       {round_trip_time_seconds * 1000:.0f} ms")
    print(f"BDP:       {bandwidth_delay_product / 8:,.0f} bytes")


# ============================================================================
# 48. LATENCY BREAKDOWN
# ============================================================================

def demonstrate_latency_components() -> None:
    section("48. LATENCY COMPONENTS")

    components = {
        "Propagation": 5.0,
        "Transmission": 1.0,
        "Processing": 0.5,
        "Queueing": 2.5,
    }

    total = sum(components.values())

    for component, milliseconds in components.items():
        print(f"{component:15} {milliseconds:6.2f} ms")

    print(f"{'Total':15} {total:6.2f} ms")

    print("\nQueueing delay can vary substantially during congestion.")
    print("This is one reason measured network latency can fluctuate over time.")


# ============================================================================
# 49. TROUBLESHOOTING METHODOLOGY
# ============================================================================

def demonstrate_troubleshooting() -> None:
    section("49. TCP/IP TROUBLESHOOTING METHODOLOGY")

    layers = [
        ("Physical/link", "Is the interface connected? Is Wi-Fi associated?"),
        ("Local addressing", "Does the host have a valid IP configuration?"),
        ("Gateway", "Can the host reach its local gateway?"),
        ("Routing", "Is there a valid route to the destination?"),
        ("DNS", "Does the hostname resolve correctly?"),
        ("Transport", "Is the destination port reachable?"),
        ("TLS/security", "Is the secure handshake succeeding?"),
        ("Application", "Is the service responding correctly?"),
    ]

    for layer, question in layers:
        print(f"{layer:20} -> {question}")

    print("\nUseful operating-system tools include:")
    print("  ping")
    print("  traceroute / tracert")
    print("  ip / ipconfig")
    print("  route")
    print("  nslookup / dig")
    print("  netstat / ss")
    print("  arp")
    print("  tcpdump / packet analyzers")

    print("\nA strong troubleshooting process isolates one layer or boundary at a time.")


# ============================================================================
# 50. COMMON TCP/IP MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    section("50. COMMON TCP/IP MISTAKES")

    mistakes = [
        (
            "TCP guarantees application messages arrive as separate messages.",
            "False. TCP provides an ordered byte stream."
        ),
        (
            "UDP guarantees delivery.",
            "False. UDP has no built-in TCP-style delivery guarantee."
        ),
        (
            "MAC addresses route packets across the Internet.",
            "False. IP addresses are used for Internet-layer routing."
        ),
        (
            "Private IP addresses are automatically secure.",
            "False. Private addressing is not equivalent to security."
        ),
        (
            "Port 443 always means HTTPS.",
            "False. A port number does not force a protocol."
        ),
        (
            "DNS is the same thing as the Internet.",
            "False. DNS is one application-layer naming system."
        ),
        (
            "A successful ping proves an application is healthy.",
            "False. ICMP reachability does not prove a TCP service is functioning."
        ),
        (
            "High bandwidth means low latency.",
            "False. Bandwidth and latency are different properties."
        ),
    ]

    for misconception, correction in mistakes:
        print(f"\nMisconception: {misconception}")
        print(f"Correction:    {correction}")


# ============================================================================
# 51. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    section("51. IMPORTANT EDGE CASES")

    print("1. IPv4 address 0.0.0.0 can represent an unspecified address or")
    print("   appear in routing contexts as the default route.")
    print("2. 127.0.0.1 refers to IPv4 loopback.")
    print("3. ::1 refers to IPv6 loopback.")
    print("4. 255.255.255.255 is the IPv4 limited broadcast address.")
    print("5. IPv4 /32 identifies a single address.")
    print("6. IPv4 /31 can be used for point-to-point links.")
    print("7. TCP can receive fewer bytes than the sender supplied in one send().")
    print("8. recv() returning b'' on a TCP socket normally indicates an orderly")
    print("   remote shutdown.")
    print("9. UDP datagrams can be lost, duplicated, delayed, or reordered.")
    print("10. DNS can return multiple addresses.")
    print("11. IPv4 and IPv6 can coexist using dual-stack configurations.")
    print("12. NAT can cause an endpoint's public address to differ from its private address.")


# ============================================================================
# 52. IP NETWORK MEMBERSHIP
# ============================================================================

def demonstrate_network_membership() -> None:
    section("52. CHECKING IP NETWORK MEMBERSHIP")

    network = ipaddress.ip_network("192.168.10.0/24")

    candidates = [
        "192.168.10.1",
        "192.168.10.254",
        "192.168.11.1",
        "192.168.10.0",
        "192.168.10.255",
    ]

    print(f"Network: {network}")

    for candidate in candidates:
        address = ipaddress.ip_address(candidate)
        print(f"{candidate:16} -> {address in network}")


# ============================================================================
# 53. SUBNET CALCULATION
# ============================================================================

def demonstrate_subnet_calculation() -> None:
    section("53. SUBNET CALCULATION EXAMPLE")

    network = ipaddress.ip_network("192.168.100.0/26")

    print(f"Network:             {network}")
    print(f"Prefix length:       {network.prefixlen}")
    print(f"Subnet mask:         {network.netmask}")
    print(f"Wildcard mask:       {network.hostmask}")
    print(f"Total addresses:     {network.num_addresses}")

    hosts = list(network.hosts())

    print(f"Usable host addresses: {len(hosts)}")

    if hosts:
        print(f"First usable host:     {hosts[0]}")
        print(f"Last usable host:      {hosts[-1]}")
        print(f"Broadcast:             {network.broadcast_address}")


# ============================================================================
# 54. TCP STATE MACHINE
# ============================================================================

def demonstrate_tcp_states() -> None:
    section("54. TCP STATE MACHINE")

    states = [
        "CLOSED",
        "LISTEN",
        "SYN-SENT",
        "SYN-RECEIVED",
        "ESTABLISHED",
        "FIN-WAIT-1",
        "FIN-WAIT-2",
        "CLOSE-WAIT",
        "CLOSING",
        "LAST-ACK",
        "TIME-WAIT",
    ]

    for state in states:
        print(f"  - {state}")

    print("\nA simplified active-open path:")
    print("CLOSED -> SYN-SENT -> ESTABLISHED")

    print("\nA simplified passive-open path:")
    print("LISTEN -> SYN-RECEIVED -> ESTABLISHED")

    print("\nThe full TCP state machine contains many transitions and is more")
    print("detailed than these simplified paths.")


# ============================================================================
# 55. TCP BACKLOG AND LISTEN
# ============================================================================

def demonstrate_listen_accept() -> None:
    section("55. TCP LISTEN AND ACCEPT")

    print("A TCP server typically performs:")
    print("1. socket()")
    print("2. bind()")
    print("3. listen()")
    print("4. accept()")
    print("5. recv()/send() or recv()/sendall()")
    print("6. close()")

    print("\nA listening socket and an accepted connected socket have different roles.")
    print("The listening socket waits for new connections.")
    print("The accepted socket communicates with a particular client.")


# ============================================================================
# 56. SOCKET ERROR HANDLING
# ============================================================================

def demonstrate_socket_error_handling() -> None:
    section("56. SOCKET ERROR HANDLING")

    try:
        socket.create_connection(("127.0.0.1", 1), timeout=0.2)
    except ConnectionRefusedError:
        print("Connection refused: no service accepted the connection.")
    except TimeoutError:
        print("Connection timed out.")
    except OSError as error:
        print(f"Other operating-system networking error: {error}")


# ============================================================================
# 57. PROTOCOL LAYER RESPONSIBILITY TEST
# ============================================================================

def classify_protocols() -> None:
    section("57. PROTOCOL CLASSIFICATION")

    protocol_layers = {
        "Ethernet": "Network Access",
        "Wi-Fi": "Network Access",
        "ARP": "Network Access / local address resolution",
        "IPv4": "Internet",
        "IPv6": "Internet",
        "ICMP": "Internet",
        "TCP": "Transport",
        "UDP": "Transport",
        "HTTP": "Application",
        "HTTPS": "Application-level web protocol using TLS",
        "DNS": "Application",
        "DHCP": "Application",
        "SSH": "Application",
        "SMTP": "Application",
    }

    for protocol, layer in protocol_layers.items():
        print(f"{protocol:10} -> {layer}")


# ============================================================================
# 58. MULTIPLEXING AND DEMULTIPLEXING
# ============================================================================

def demonstrate_multiplexing() -> None:
    section("58. TRANSPORT MULTIPLEXING AND DEMULTIPLEXING")

    applications = [
        ("Browser", 51514, 443),
        ("DNS resolver", 51515, 53),
        ("SSH client", 51516, 22),
    ]

    print("Multiple application flows can share the same host and IP address.")

    for application, source_port, destination_port in applications:
        print(
            f"{application:15} "
            f"{source_port:5} -> {destination_port:5}"
        )

    print("\nTransport ports allow the operating system to deliver incoming")
    print("traffic to the appropriate application socket.")


# ============================================================================
# 59. CONNECTION IDENTIFICATION
# ============================================================================

def demonstrate_connection_identity() -> None:
    section("59. CONNECTION IDENTITY")

    connection_a = (
        "192.168.1.10",
        50000,
        "203.0.113.50",
        443,
    )

    connection_b = (
        "192.168.1.10",
        50001,
        "203.0.113.50",
        443,
    )

    print("Connection A:")
    print(f"  {connection_a}")

    print("Connection B:")
    print(f"  {connection_b}")

    print("\nThe differing source ports allow multiple simultaneous connections")
    print("from the same client IP to the same server IP and server port.")


# ============================================================================
# 60. APPLICATION DATA VALIDATION
# ============================================================================

def validate_port(port: int) -> None:
    if not isinstance(port, int):
        raise TypeError("Port must be an integer.")

    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535.")


def demonstrate_validation() -> None:
    section("60. NETWORK INPUT VALIDATION")

    examples = [80, 443, 0, 65535, -1, 70000, "443"]

    for port in examples:
        try:
            validate_port(port)
            print(f"{port!r:10} -> valid")
        except (TypeError, ValueError) as error:
            print(f"{port!r:10} -> invalid: {error}")

    print("\nValidation is essential because network input is external and")
    print("cannot be assumed to be trustworthy.")


# ============================================================================
# 61. SAFE HOSTNAME VALIDATION
# ============================================================================

def resolve_hostname(hostname: str) -> list[str]:
    """
    Resolve a hostname using the operating system resolver.

    The function intentionally avoids shell commands, which reduces the
    risk of shell injection compared with constructing a shell command
    from untrusted input.
    """
    if not hostname or len(hostname) > 253:
        raise ValueError("Hostname length is invalid.")

    addresses = socket.getaddrinfo(
        hostname,
        None,
        type=socket.SOCK_STREAM,
    )

    return sorted({
        result[4][0]
        for result in addresses
    })


def demonstrate_safe_resolution() -> None:
    section("61. SAFE HOSTNAME RESOLUTION")

    hostname = "example.com"

    try:
        addresses = resolve_hostname(hostname)
        print(f"{hostname} ->")
        for address in addresses:
            print(f"  {address}")
    except (socket.gaierror, ValueError) as error:
        print(f"Resolution failed: {error}")

    print("\nAvoid building shell commands from untrusted hostnames.")
    print("Prefer structured APIs such as socket.getaddrinfo().")


# ============================================================================
# 62. PACKET VERSUS FRAME VERSUS SEGMENT
# ============================================================================

def demonstrate_pdu_names() -> None:
    section("62. PROTOCOL DATA UNIT TERMINOLOGY")

    pdus = [
        ("Application", "Data / message"),
        ("Transport", "TCP segment / UDP datagram"),
        ("Internet", "IP packet / IP datagram"),
        ("Network Access", "Frame"),
    ]

    for layer, pdu in pdus:
        print(f"{layer:18} -> {pdu}")

    print("\nTerminology can vary by textbook and protocol.")
    print("The important concept is that each layer adds or interprets control")
    print("information appropriate to its responsibility.")


# ============================================================================
# 63. ENCAPSULATION WITH ABSTRACT HEADERS
# ============================================================================

@dataclass
class LayerData:
    name: str
    header: str
    payload: object


def demonstrate_nested_encapsulation() -> None:
    section("63. NESTED ENCAPSULATION MODEL")

    application = LayerData(
        name="Application",
        header="HTTP header",
        payload="Application content",
    )

    transport = LayerData(
        name="Transport",
        header="TCP header",
        payload=application,
    )

    internet = LayerData(
        name="Internet",
        header="IP header",
        payload=transport,
    )

    access = LayerData(
        name="Network Access",
        header="Ethernet header/trailer",
        payload=internet,
    )

    print("Outer structure:")
    print(access.name)
    print(f"  {access.header}")
    print("  ->", access.payload.name)
    print(f"     {access.payload.header}")
    print("     ->", access.payload.payload.name)
    print(f"        {access.payload.payload.header}")
    print("        ->", access.payload.payload.payload.name)
    print(
        f"           {access.payload.payload.payload.header}"
    )

    print("\nReal implementations serialize these structures into bytes.")


# ============================================================================
# 64. REAL SOCKET LOCAL ADDRESS INFORMATION
# ============================================================================

def demonstrate_local_socket_information() -> None:
    section("64. LOCAL SOCKET INFORMATION")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.bind(("127.0.0.1", 0))
        print(f"Local endpoint before connection: {sock.getsockname()}")
    finally:
        sock.close()

    print("\nA socket endpoint contains addressing information understood by")
    print("the operating system networking stack.")


# ============================================================================
# 65. RETRY STRATEGY CONCEPT
# ============================================================================

def exponential_backoff_delays(
    initial_delay: float,
    retries: int,
    maximum_delay: float,
) -> list[float]:
    delays = []
    delay = initial_delay

    for _ in range(retries):
        delays.append(min(delay, maximum_delay))
        delay = min(delay * 2, maximum_delay)

    return delays


def demonstrate_retry_strategy() -> None:
    section("65. NETWORK RETRIES AND BACKOFF")

    delays = exponential_backoff_delays(
        initial_delay=0.5,
        retries=6,
        maximum_delay=8.0,
    )

    print("Example exponential backoff schedule:")
    for attempt, delay in enumerate(delays, start=1):
        print(f"  Retry {attempt}: wait approximately {delay:.1f} seconds")

    print("\nRetries should not be unlimited.")
    print("Poor retry design can amplify congestion and create retry storms.")
    print("Production systems should combine bounded retries, backoff, and")
    print("appropriate timeout policies.")


# ============================================================================
# 66. NETWORK RESOURCE MANAGEMENT
# ============================================================================

def demonstrate_resource_management() -> None:
    section("66. NETWORK RESOURCE MANAGEMENT")

    print("Network programs consume operating-system resources such as:")
    print("  - File descriptors")
    print("  - Socket buffers")
    print("  - Memory")
    print("  - Threads")
    print("  - CPU")
    print("  - Connection tracking entries")

    print("\nBest practices:")
    print("  - Close sockets reliably.")
    print("  - Use context managers where practical.")
    print("  - Bound input sizes.")
    print("  - Configure timeouts.")
    print("  - Limit concurrent connections appropriately.")
    print("  - Avoid unbounded buffering.")


# ============================================================================
# 67. SIMPLE TCP TESTS
# ============================================================================

def test_mac_validation() -> None:
    assert is_valid_mac("00:11:22:33:44:55")
    assert not is_valid_mac("00:11:22:33:44")
    assert not is_valid_mac("GG:11:22:33:44:55")


def test_checksum() -> None:
    assert internet_checksum(b"") == 0xFFFF
    assert internet_checksum(b"hello") == internet_checksum(b"hello")


def test_network_membership() -> None:
    network = ipaddress.ip_network("192.168.1.0/24")
    assert ipaddress.ip_address("192.168.1.10") in network
    assert ipaddress.ip_address("192.168.2.10") not in network


def test_message_framing() -> None:
    encoded = encode_message(b"hello") + encode_message(b"world")
    buffer = bytearray(encoded)

    decoded = decode_messages(buffer)

    assert decoded == [b"hello", b"world"]
    assert buffer == bytearray()


def run_tests() -> None:
    section("67. BASIC IMPLEMENTATION TESTS")

    tests: list[Callable[[], None]] = [
        test_mac_validation,
        test_checksum,
        test_network_membership,
        test_message_framing,
    ]

    passed = 0

    for test in tests:
        try:
            test()
            print(f"PASS: {test.__name__}")
            passed += 1
        except AssertionError as error:
            print(f"FAIL: {test.__name__}: {error}")

    print(f"\n{passed}/{len(tests)} tests passed.")


# ============================================================================
# 68. INTEGRATED TCP/IP FLOW
# ============================================================================

def demonstrate_integrated_flow() -> None:
    section("68. INTEGRATED TCP/IP COMMUNICATION FLOW")

    print("Scenario: a browser requests an HTTPS resource.")

    flow = [
        "Application: Browser creates an HTTP request.",
        "Security: TLS protects the application exchange.",
        "Transport: TCP identifies the connection with ports and manages delivery.",
        "Internet: IP provides source/destination logical addresses.",
        "Network Access: Ethernet/Wi-Fi creates local-link frames.",
        "Router: examines the IP destination and forwards traffic.",
        "Destination: reverse processing removes lower-layer encapsulation.",
        "Transport: destination TCP stack delivers bytes to the correct socket.",
        "Application: web server processes the HTTP request.",
        "Response: the process occurs in reverse.",
    ]

    for number, step in enumerate(flow, start=1):
        print(f"{number:2}. {step}")

    print("\nThe same conceptual process applies to many other applications,")
    print("although the protocols and transport mechanisms can differ.")


# ============================================================================
# 69. LAYER COMPARISON TABLE
# ============================================================================

def demonstrate_layer_comparison() -> None:
    section("69. TCP/IP LAYER COMPARISON")

    rows = [
        (
            "Network Access",
            "Local delivery",
            "MAC/link addressing",
            "Ethernet/Wi-Fi",
            "Frame",
        ),
        (
            "Internet",
            "Inter-network delivery",
            "IP addressing",
            "IPv4/IPv6",
            "Packet",
        ),
        (
            "Transport",
            "Process delivery",
            "Ports",
            "TCP/UDP",
            "Segment/Datagram",
        ),
        (
            "Application",
            "Application services",
            "Protocol-specific",
            "HTTP/DNS/SSH/etc.",
            "Message/Data",
        ),
    ]

    header = (
        f"{'Layer':18}"
        f"{'Primary role':24}"
        f"{'Addressing':20}"
        f"{'Examples':24}"
        f"{'PDU':20}"
    )

    print(header)
    print("-" * len(header))

    for row in rows:
        print(
            f"{row[0]:18}"
            f"{row[1]:24}"
            f"{row[2]:20}"
            f"{row[3]:24}"
            f"{row[4]:20}"
        )


# ============================================================================
# 70. ADVANCED CONCEPT: ROUTING VERSUS SWITCHING
# ============================================================================

def compare_routing_switching() -> None:
    section("70. ROUTING VERSUS SWITCHING")

    print("Switching:")
    print("  - Primarily concerns local-link frame forwarding.")
    print("  - Commonly uses MAC addresses.")
    print("  - Usually operates within a broadcast domain or VLAN context.")

    print("\nRouting:")
    print("  - Moves IP packets between different networks.")
    print("  - Uses IP prefixes and routing information.")
    print("  - Routers separate broadcast domains.")

    print("\nA packet can cross multiple routed networks while the local Ethernet")
    print("frame carrying it is replaced at each routed hop.")


# ============================================================================
# 71. ADVANCED CONCEPT: EACH HOP CHANGES THE FRAME
# ============================================================================

def demonstrate_hop_by_hop_frames() -> None:
    section("71. HOP-BY-HOP FRAME CHANGES")

    print("Suppose a host sends an IP packet through a router.")

    print("\nAt Host -> Router:")
    print("  Ethernet source MAC:      Host MAC")
    print("  Ethernet destination MAC: Router LAN MAC")

    print("\nAt Router -> Next Router:")
    print("  Ethernet source MAC:      Router outbound MAC")
    print("  Ethernet destination MAC: Next-hop MAC")

    print("\nThe IP packet normally retains its source and destination IP addresses")
    print("across routed hops, subject to mechanisms such as NAT.")
    print("The link-layer frame is recreated for the next link.")


# ============================================================================
# 72. ADVANCED CONCEPT: TTL/HOP LIMIT
# ============================================================================

def simulate_ttl() -> None:
    section("72. TTL AND HOP LIMIT SIMULATION")

    ttl = 5

    print(f"Initial TTL: {ttl}")

    for hop in range(1, 7):
        ttl -= 1

        if ttl <= 0:
            print(f"Hop {hop}: TTL expired. Packet is discarded.")
            break

        print(f"Hop {hop}: TTL becomes {ttl}")

    print("\nThis mechanism prevents packets from circulating indefinitely in")
    print("a routing loop.")


# ============================================================================
# 73. ADVANCED CONCEPT: DNS CACHING
# ============================================================================

@dataclass
class DNSCacheEntry:
    hostname: str
    address: str
    expires_at: float


def demonstrate_dns_cache() -> None:
    section("73. DNS CACHING CONCEPT")

    now = time.time()

    cache = {
        "example.com": DNSCacheEntry(
            hostname="example.com",
            address="93.184.216.34",
            expires_at=now + 60,
        )
    }

    entry = cache.get("example.com")

    if entry and entry.expires_at > time.time():
        print(f"Cache hit: {entry.hostname} -> {entry.address}")
        print(f"Remaining TTL: {entry.expires_at - time.time():.1f} seconds")
    else:
        print("Cache miss or expired entry.")

    print("\nDNS caching reduces repeated lookup traffic and can reduce latency.")
    print("DNS records can change, so cached information must respect TTL and")
    print("resolver policy.")


# ============================================================================
# 74. ADVANCED CONCEPT: APPLICATION PROTOCOL DESIGN
# ============================================================================

def demonstrate_protocol_design() -> None:
    section("74. APPLICATION PROTOCOL DESIGN")

    print("A robust application protocol should define:")
    design_elements = [
        "Message format",
        "Message boundaries",
        "Encoding",
        "Maximum message size",
        "Request and response semantics",
        "Error representation",
        "Timeout expectations",
        "Authentication",
        "Authorization",
        "Versioning",
        "Backward compatibility",
        "Idempotency where applicable",
        "Rate limiting",
    ]

    for element in design_elements:
        print(f"  - {element}")

    print("\nA transport protocol cannot compensate for an ambiguous application")
    print("protocol. Application semantics must be designed explicitly.")


# ============================================================================
# 75. ADVANCED CONCEPT: IDEMPOTENCY
# ============================================================================

def demonstrate_idempotency() -> None:
    section("75. APPLICATION IDEMPOTENCY")

    print("An operation is idempotent when repeating it produces the same intended")
    print("state as performing it once, under the operation's defined semantics.")

    examples = [
        ("Set account status to ACTIVE", "Typically idempotent"),
        ("Delete resource X", "Often idempotent after first successful deletion"),
        ("Charge credit card $100", "Not inherently idempotent"),
    ]

    for operation, classification in examples:
        print(f"{operation:40} -> {classification}")

    print("\nThis matters because networks fail.")
    print("A client may not know whether a request reached the server before a")
    print("timeout occurred, so blindly retrying non-idempotent operations can")
    print("produce duplicate effects.")


# ============================================================================
# 76. ADVANCED CONCEPT: APPLICATION TIMEOUTS
# ============================================================================

def demonstrate_timeout_design() -> None:
    section("76. TIMEOUT DESIGN")

    timeout_categories = {
        "Connect timeout": "Maximum time allowed to establish a connection.",
        "Read timeout": "Maximum waiting time for expected data.",
        "Write timeout": "Maximum time allowed for a write operation.",
        "Overall deadline": "Maximum time allowed for the complete operation.",
    }

    for category, definition in timeout_categories.items():
        print(f"{category:20} -> {definition}")

    print("\nAn overall deadline can be more useful than an unlimited collection")
    print("of independent waits because it bounds total operation time.")


# ============================================================================
# 77. ADVANCED CONCEPT: UDP APPLICATION RELIABILITY
# ============================================================================

def demonstrate_udp_reliability_design() -> None:
    section("77. BUILDING RELIABILITY ABOVE UDP")

    print("UDP itself does not provide TCP's reliability mechanisms.")
    print("An application can implement selected reliability features when needed.")

    features = [
        "Sequence numbers",
        "Acknowledgements",
        "Retransmission timers",
        "Duplicate detection",
        "Ordering buffers",
        "Application-level checksums",
        "Congestion control",
        "Flow control",
    ]

    for feature in features:
        print(f"  - {feature}")

    print("\nThis flexibility is useful for specialized protocols.")
    print("It also means application designers inherit substantial complexity.")


# ============================================================================
# 78. ADVANCED CONCEPT: SECURITY BOUNDARIES
# ============================================================================

def demonstrate_security_boundaries() -> None:
    section("78. SECURITY BOUNDARIES IN TCP/IP")

    print("Layered architecture does not mean every layer provides security.")
    print("\nExamples:")
    print("  Ethernet does not inherently provide end-to-end confidentiality.")
    print("  IP does not inherently authenticate every packet source.")
    print("  TCP provides transport reliability, not encryption.")
    print("  UDP provides minimal transport functionality, not encryption.")
    print("  HTTP alone does not provide confidentiality.")
    print("  TLS can provide confidentiality and authentication for supported uses.")

    print("\nSecurity must be designed according to the threat model and communication")
    print("requirements rather than assumed from the existence of a network layer.")


# ============================================================================
# 79. ADVANCED CONCEPT: OBSERVABILITY
# ============================================================================

def demonstrate_observability() -> None:
    section("79. NETWORK OBSERVABILITY")

    print("Useful observability signals include:")
    signals = [
        "Connection counts",
        "Connection failures",
        "DNS resolution latency",
        "TCP handshake latency",
        "TLS handshake latency",
        "HTTP response latency",
        "Packet loss",
        "Retransmissions",
        "Throughput",
        "Error rates",
        "Timeout rates",
    ]

    for signal in signals:
        print(f"  - {signal}")

    print("\nMeasuring only application response time can hide whether the")
    print("problem originates in DNS, TCP connection establishment, TLS, routing,")
    print("server processing, or the application itself.")


# ============================================================================
# 80. COMPLETE STUDY DEMONSTRATION
# ============================================================================

def run_all_demos() -> None:
    explain_basic_networking()
    show_tcp_ip_model()
    show_osi_mapping()
    demonstrate_encapsulation()
    demonstrate_network_access_layer()
    demonstrate_mac_validation()
    simulate_arp()
    demonstrate_internet_layer()
    demonstrate_ipv4_addressing()
    demonstrate_ipv6()
    demonstrate_subnetting()
    demonstrate_routing()
    demonstrate_transport_layer()
    compare_tcp_udp()
    demonstrate_tcp_header_concepts()
    simulate_tcp_handshake()
    simulate_tcp_reliability()
    demonstrate_flow_control()
    demonstrate_congestion_control()
    simulate_tcp_termination()
    demonstrate_ports_and_sockets()
    demonstrate_application_layer()
    demonstrate_http()
    demonstrate_dns()
    demonstrate_real_dns_lookup()
    demonstrate_dhcp()
    demonstrate_nat()
    demonstrate_checksum()
    demonstrate_mtu()
    demonstrate_socket_creation()
    demonstrate_local_tcp()
    demonstrate_local_udp()
    demonstrate_socket_timeout()
    demonstrate_tcp_byte_stream()
    demonstrate_application_framing()
    demonstrate_web_stack()
    demonstrate_common_ports()
    demonstrate_ephemeral_ports()
    demonstrate_icmp()
    demonstrate_protocol_relationships()
    demonstrate_loopback()
    demonstrate_network_byte_order()
    demonstrate_ipv4_header()
    demonstrate_ipv6_header()
    demonstrate_security_considerations()
    demonstrate_tls()
    demonstrate_performance()
    demonstrate_latency_components()
    demonstrate_troubleshooting()
    demonstrate_common_mistakes()
    demonstrate_edge_cases()
    demonstrate_network_membership()
    demonstrate_subnet_calculation()
    demonstrate_tcp_states()
    demonstrate_listen_accept()
    demonstrate_socket_error_handling()
    classify_protocols()
    demonstrate_multiplexing()
    demonstrate_connection_identity()
    demonstrate_validation()
    demonstrate_safe_resolution()
    demonstrate_pdu_names()
    demonstrate_nested_encapsulation()
    demonstrate_local_socket_information()
    demonstrate_retry_strategy()
    demonstrate_resource_management()
    run_tests()
    demonstrate_integrated_flow()
    demonstrate_layer_comparison()
    compare_routing_switching()
    demonstrate_hop_by_hop_frames()
    simulate_ttl()
    demonstrate_dns_cache()
    demonstrate_protocol_design()
    demonstrate_idempotency()
    demonstrate_timeout_design()
    demonstrate_udp_reliability_design()
    demonstrate_security_boundaries()
    demonstrate_observability()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    print("TCP/IP MODEL STUDY SCRIPT")
    print("Network Access -> Internet -> Transport -> Application")
    print("This script uses Python's standard library only.")

    run_all_demos()
