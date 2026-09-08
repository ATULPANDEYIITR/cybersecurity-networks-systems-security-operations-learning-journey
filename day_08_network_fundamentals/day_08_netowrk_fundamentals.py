"""
Networking Fundamentals
A self-contained study script covering beginner to advanced networking concepts.

Topics:
- Network types: PAN, LAN, MAN, WAN
- Network topologies
- Bandwidth, throughput, latency, jitter
- Packets, frames, segments, datagrams
- OSI and TCP/IP models
- MAC and IP addressing
- Switching and routing concepts
- TCP and UDP
- DNS, DHCP, ARP
- Ports and sockets
- Subnetting
- Network calculations and simulations
- Packet/frame representations
- Error handling and validation
- Performance considerations
- Security considerations
- Wireshark concepts
- Cisco Packet Tracer concepts

The script uses only Python's standard library.
"""

from __future__ import annotations

import ipaddress
import math
import random
import socket
import statistics
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# =============================================================================
# 1. FUNDAMENTAL NETWORKING TERMINOLOGY
# =============================================================================

print("=" * 80)
print("NETWORKING FUNDAMENTALS")
print("=" * 80)


class NetworkType(Enum):
    """Classification based primarily on geographic coverage."""

    PAN = "Personal Area Network"
    LAN = "Local Area Network"
    MAN = "Metropolitan Area Network"
    WAN = "Wide Area Network"


NETWORK_TYPES = {
    NetworkType.PAN: {
        "coverage": "A few meters",
        "examples": ["Bluetooth devices", "Smartwatch connection", "Personal hotspot"],
    },
    NetworkType.LAN: {
        "coverage": "Room, building, office, campus",
        "examples": ["Home network", "Office Ethernet", "University network"],
    },
    NetworkType.MAN: {
        "coverage": "City or metropolitan region",
        "examples": ["City-wide fiber network", "Metropolitan service provider network"],
    },
    NetworkType.WAN: {
        "coverage": "Countries or continents",
        "examples": ["Corporate global network", "Internet backbone"],
    },
}

print("\nNETWORK TYPES")
for network_type, details in NETWORK_TYPES.items():
    print(f"\n{network_type.name}: {network_type.value}")
    print(f"  Coverage: {details['coverage']}")
    print(f"  Examples: {', '.join(details['examples'])}")


# =============================================================================
# 2. NETWORK TOPOLOGIES
# =============================================================================

class Topology(Enum):
    BUS = "Bus"
    STAR = "Star"
    RING = "Ring"
    MESH = "Mesh"
    TREE = "Tree"
    HYBRID = "Hybrid"


TOPOLOGIES = {
    Topology.BUS: {
        "structure": "All devices share a common communication backbone.",
        "strength": "Simple and inexpensive for very small networks.",
        "weakness": "Backbone failure can affect the entire network.",
    },
    Topology.STAR: {
        "structure": "Devices connect to a central switch or hub.",
        "strength": "Easy management and fault isolation.",
        "weakness": "Central device can become a single point of failure.",
    },
    Topology.RING: {
        "structure": "Each device connects to two neighboring devices.",
        "strength": "Predictable communication path.",
        "weakness": "A failure can disrupt communication without redundancy.",
    },
    Topology.MESH: {
        "structure": "Devices have multiple interconnections.",
        "strength": "High redundancy and fault tolerance.",
        "weakness": "High implementation complexity and cost.",
    },
    Topology.TREE: {
        "structure": "Hierarchical arrangement of interconnected star networks.",
        "strength": "Scalable for large organizations.",
        "weakness": "Higher-level failures can affect lower branches.",
    },
    Topology.HYBRID: {
        "structure": "Combination of multiple topology types.",
        "strength": "Flexible and adaptable.",
        "weakness": "More complex design and troubleshooting.",
    },
}

print("\n" + "=" * 80)
print("NETWORK TOPOLOGIES")
print("=" * 80)

for topology, details in TOPOLOGIES.items():
    print(f"\n{topology.value}")
    print(f"  Structure: {details['structure']}")
    print(f"  Strength: {details['strength']}")
    print(f"  Weakness: {details['weakness']}")


# =============================================================================
# 3. BANDWIDTH, THROUGHPUT, LATENCY AND JITTER
# =============================================================================

def bits_to_megabits(bits: float) -> float:
    """Convert bits to megabits using decimal networking units."""
    return bits / 1_000_000


def calculate_transfer_time(file_size_bytes: int, bandwidth_bps: int) -> float:
    """
    Calculate ideal transfer time.

    This is an idealized calculation and ignores protocol overhead,
    congestion, retransmissions, encryption overhead, and other factors.
    """
    if file_size_bytes < 0:
        raise ValueError("File size cannot be negative.")
    if bandwidth_bps <= 0:
        raise ValueError("Bandwidth must be greater than zero.")

    file_size_bits = file_size_bytes * 8
    return file_size_bits / bandwidth_bps


def calculate_bandwidth_delay_product(
    bandwidth_bps: float,
    latency_seconds: float,
) -> float:
    """
    Calculate the bandwidth-delay product.

    The result estimates how many bits can be "in flight" on a network path.
    """
    if bandwidth_bps < 0 or latency_seconds < 0:
        raise ValueError("Bandwidth and latency cannot be negative.")

    return bandwidth_bps * latency_seconds


def calculate_jitter(latencies_ms: List[float]) -> float:
    """
    Calculate a simple jitter measurement.

    Here jitter is defined as the average absolute difference between
    consecutive latency measurements.
    """
    if len(latencies_ms) < 2:
        return 0.0

    differences = [
        abs(latencies_ms[index] - latencies_ms[index - 1])
        for index in range(1, len(latencies_ms))
    ]

    return statistics.mean(differences)


print("\n" + "=" * 80)
print("BANDWIDTH, THROUGHPUT, LATENCY AND JITTER")
print("=" * 80)

file_size = 100 * 1_000_000  # 100 MB in decimal bytes.
bandwidth = 100 * 1_000_000  # 100 Mbps.

ideal_time = calculate_transfer_time(file_size, bandwidth)

print(f"\nFile size: {file_size:,} bytes")
print(f"Bandwidth: {bits_to_megabits(bandwidth):.2f} Mbps")
print(f"Ideal transfer time: {ideal_time:.2f} seconds")

round_trip_time = 0.050  # 50 milliseconds.
bdp = calculate_bandwidth_delay_product(bandwidth, round_trip_time)

print(f"\nRound-trip time: {round_trip_time * 1000:.2f} ms")
print(f"Bandwidth-delay product: {bdp:,.0f} bits")
print(f"Bandwidth-delay product: {bdp / 8:,.0f} bytes")

latency_samples = [20.1, 22.4, 19.8, 25.0, 21.5, 20.7]
print(f"\nLatency samples: {latency_samples}")
print(f"Average latency: {statistics.mean(latency_samples):.2f} ms")
print(f"Jitter: {calculate_jitter(latency_samples):.2f} ms")


# =============================================================================
# 4. OSI MODEL
# =============================================================================

OSI_LAYERS = [
    (7, "Application", "Network services used by applications"),
    (6, "Presentation", "Data representation, encryption, compression"),
    (5, "Session", "Session establishment and management"),
    (4, "Transport", "End-to-end delivery, TCP, UDP"),
    (3, "Network", "Logical addressing and routing, IP"),
    (2, "Data Link", "Frames, MAC addresses, switching"),
    (1, "Physical", "Electrical, optical, radio signals"),
]

print("\n" + "=" * 80)
print("OSI MODEL")
print("=" * 80)

for number, name, purpose in OSI_LAYERS:
    print(f"Layer {number}: {name:<12} - {purpose}")


# =============================================================================
# 5. TCP/IP MODEL
# =============================================================================

TCP_IP_LAYERS = [
    ("Application", "HTTP, HTTPS, DNS, SMTP, SSH"),
    ("Transport", "TCP, UDP, ports"),
    ("Internet", "IP, routing"),
    ("Network Access", "Ethernet, Wi-Fi, MAC addressing"),
]

print("\n" + "=" * 80)
print("TCP/IP MODEL")
print("=" * 80)

for layer, examples in TCP_IP_LAYERS:
    print(f"{layer:<16}: {examples}")


# =============================================================================
# 6. DATA ENCAPSULATION
# =============================================================================

class ProtocolDataUnit(Enum):
    DATA = "Data"
    SEGMENT = "Segment"
    DATAGRAM = "Datagram"
    PACKET = "Packet"
    FRAME = "Frame"
    BITS = "Bits"


def demonstrate_encapsulation(application_data: str) -> Dict[str, str]:
    """
    Demonstrate conceptual encapsulation.

    Real networking headers are binary structures. This example uses readable
    strings to show how information is progressively encapsulated.
    """
    transport_segment = f"[TCP HEADER | {application_data}]"
    network_packet = f"[IP HEADER | {transport_segment}]"
    data_link_frame = f"[ETHERNET HEADER | {network_packet} | FCS]"
    physical_bits = "".join(format(ord(character), "08b") for character in data_link_frame)

    return {
        "application_data": application_data,
        "transport_segment": transport_segment,
        "network_packet": network_packet,
        "data_link_frame": data_link_frame,
        "physical_bits_preview": physical_bits[:128] + "...",
    }


print("\n" + "=" * 80)
print("ENCAPSULATION")
print("=" * 80)

encapsulation = demonstrate_encapsulation("GET /index.html HTTP/1.1")

for stage, representation in encapsulation.items():
    print(f"\n{stage}:")
    print(representation)


# =============================================================================
# 7. MAC ADDRESS VALIDATION AND REPRESENTATION
# =============================================================================

def validate_mac_address(mac_address: str) -> bool:
    """
    Validate common colon-separated MAC address notation.

    Valid example:
        AA:BB:CC:DD:EE:FF
    """
    parts = mac_address.split(":")

    if len(parts) != 6:
        return False

    for part in parts:
        if len(part) != 2:
            return False

        try:
            value = int(part, 16)
        except ValueError:
            return False

        if not 0 <= value <= 255:
            return False

    return True


def normalize_mac_address(mac_address: str) -> str:
    """Return an uppercase normalized MAC address."""
    if not validate_mac_address(mac_address):
        raise ValueError(f"Invalid MAC address: {mac_address}")

    return mac_address.upper()


def mac_to_integer(mac_address: str) -> int:
    """Convert a MAC address to its integer representation."""
    normalized = normalize_mac_address(mac_address)
    hexadecimal = normalized.replace(":", "")
    return int(hexadecimal, 16)


print("\n" + "=" * 80)
print("MAC ADDRESSES")
print("=" * 80)

sample_mac_addresses = [
    "00:1A:2B:3C:4D:5E",
    "aa:bb:cc:dd:ee:ff",
    "00:11:22:33:44",
    "INVALID",
]

for mac in sample_mac_addresses:
    is_valid = validate_mac_address(mac)
    print(f"{mac:<20} Valid: {is_valid}")

    if is_valid:
        print(f"  Normalized: {normalize_mac_address(mac)}")
        print(f"  Integer: {mac_to_integer(mac)}")


# =============================================================================
# 8. IP ADDRESSING
# =============================================================================

print("\n" + "=" * 80)
print("IP ADDRESSING")
print("=" * 80)


def describe_ip_address(address: str) -> None:
    """Display useful information about an IPv4 or IPv6 address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as error:
        print(f"{address}: Invalid IP address ({error})")
        return

    print(f"\nAddress: {ip}")
    print(f"Version: IPv{ip.version}")
    print(f"Private: {ip.is_private}")
    print(f"Loopback: {ip.is_loopback}")
    print(f"Multicast: {ip.is_multicast}")
    print(f"Global: {ip.is_global}")


for address in [
    "192.168.1.10",
    "10.0.0.5",
    "127.0.0.1",
    "8.8.8.8",
    "::1",
    "2001:db8::1",
]:
    describe_ip_address(address)


# =============================================================================
# 9. SUBNETTING
# =============================================================================

@dataclass
class SubnetInformation:
    network: str
    netmask: str
    prefix_length: int
    broadcast: Optional[str]
    total_addresses: int
    usable_hosts: int
    first_usable: Optional[str]
    last_usable: Optional[str]


def calculate_subnet(network_string: str) -> SubnetInformation:
    """
    Calculate subnet information.

    IPv4 networks use a broadcast address. IPv6 does not use broadcast
    addresses in the same manner.
    """
    network = ipaddress.ip_network(network_string, strict=False)

    if network.version == 4:
        total_addresses = network.num_addresses

        if network.prefixlen == 32:
            usable_hosts = 1
            first_usable = str(network.network_address)
            last_usable = str(network.network_address)
        elif network.prefixlen == 31:
            # /31 networks can be used for point-to-point links.
            usable_hosts = 2
            first_usable = str(network.network_address)
            last_usable = str(network.broadcast_address)
        else:
            usable_hosts = max(total_addresses - 2, 0)

            if usable_hosts > 0:
                first_usable = str(network.network_address + 1)
                last_usable = str(network.broadcast_address - 1)
            else:
                first_usable = None
                last_usable = None

        return SubnetInformation(
            network=str(network.network_address),
            netmask=str(network.netmask),
            prefix_length=network.prefixlen,
            broadcast=str(network.broadcast_address),
            total_addresses=total_addresses,
            usable_hosts=usable_hosts,
            first_usable=first_usable,
            last_usable=last_usable,
        )

    return SubnetInformation(
        network=str(network.network_address),
        netmask=str(network.netmask),
        prefix_length=network.prefixlen,
        broadcast=None,
        total_addresses=network.num_addresses,
        usable_hosts=network.num_addresses,
        first_usable=str(network.network_address),
        last_usable=str(network.broadcast_address),
    )


subnet_examples = [
    "192.168.1.0/24",
    "192.168.1.0/30",
    "192.168.1.0/31",
    "192.168.1.10/32",
    "2001:db8::/64",
]

for subnet_string in subnet_examples:
    information = calculate_subnet(subnet_string)

    print(f"\nSubnet: {subnet_string}")
    print(f"Network: {information.network}")
    print(f"Netmask: {information.netmask}")
    print(f"Prefix length: /{information.prefix_length}")
    print(f"Broadcast: {information.broadcast}")
    print(f"Total addresses: {information.total_addresses}")
    print(f"Usable hosts: {information.usable_hosts}")
    print(f"First usable: {information.first_usable}")
    print(f"Last usable: {information.last_usable}")


# =============================================================================
# 10. NETWORK AND HOST PORTIONS
# =============================================================================

def ipv4_to_binary(address: str) -> str:
    """Return a dotted binary representation of an IPv4 address."""
    ip = ipaddress.IPv4Address(address)
    return ".".join(format(octet, "08b") for octet in ip.packed)


print("\n" + "=" * 80)
print("BINARY REPRESENTATION OF IPv4")
print("=" * 80)

sample_ip = "192.168.10.25"
print(f"Decimal: {sample_ip}")
print(f"Binary : {ipv4_to_binary(sample_ip)}")


# =============================================================================
# 11. PACKETS AND FRAMES
# =============================================================================

@dataclass
class EthernetFrame:
    """
    Simplified Ethernet frame representation.

    Actual Ethernet frames contain additional details and restrictions.
    """

    destination_mac: str
    source_mac: str
    ether_type: int
    payload: bytes

    def validate(self) -> None:
        if not validate_mac_address(self.destination_mac):
            raise ValueError("Invalid destination MAC address.")

        if not validate_mac_address(self.source_mac):
            raise ValueError("Invalid source MAC address.")

        if not 0 <= self.ether_type <= 0xFFFF:
            raise ValueError("EtherType must fit into 16 bits.")

    def describe(self) -> None:
        self.validate()

        print("\nEthernet Frame")
        print(f"  Destination MAC: {normalize_mac_address(self.destination_mac)}")
        print(f"  Source MAC:      {normalize_mac_address(self.source_mac)}")
        print(f"  EtherType:       0x{self.ether_type:04X}")
        print(f"  Payload length:  {len(self.payload)} bytes")


@dataclass
class IPv4Packet:
    """
    Simplified IPv4 packet representation.

    Real IPv4 packets include fields such as version, IHL, DSCP, flags,
    fragmentation offset, TTL, protocol, checksum and options.
    """

    source_ip: str
    destination_ip: str
    ttl: int
    protocol: str
    payload: bytes

    def validate(self) -> None:
        source = ipaddress.ip_address(self.source_ip)
        destination = ipaddress.ip_address(self.destination_ip)

        if source.version != 4 or destination.version != 4:
            raise ValueError("This simplified class requires IPv4 addresses.")

        if not 1 <= self.ttl <= 255:
            raise ValueError("TTL must be between 1 and 255.")

    def forward(self) -> None:
        """
        Simulate router forwarding.

        Routers decrement TTL. A packet reaching TTL zero is discarded.
        """
        self.validate()
        self.ttl -= 1

        if self.ttl <= 0:
            raise RuntimeError("TTL expired. Packet would be discarded.")

    def describe(self) -> None:
        self.validate()

        print("\nIPv4 Packet")
        print(f"  Source IP:       {self.source_ip}")
        print(f"  Destination IP:  {self.destination_ip}")
        print(f"  TTL:             {self.ttl}")
        print(f"  Protocol:        {self.protocol}")
        print(f"  Payload length:  {len(self.payload)} bytes")


packet = IPv4Packet(
    source_ip="192.168.1.10",
    destination_ip="8.8.8.8",
    ttl=3,
    protocol="UDP",
    payload=b"Example DNS request",
)

frame = EthernetFrame(
    destination_mac="AA:BB:CC:DD:EE:FF",
    source_mac="00:1A:2B:3C:4D:5E",
    ether_type=0x0800,  # IPv4
    payload=packet.payload,
)

print("\n" + "=" * 80)
print("PACKETS AND FRAMES")
print("=" * 80)

packet.describe()
frame.describe()

print("\nSimulating router hops:")
for hop in range(1, 5):
    try:
        packet.forward()
        print(f"Hop {hop}: TTL is now {packet.ttl}")
    except RuntimeError as error:
        print(f"Hop {hop}: {error}")
        break


# =============================================================================
# 12. SWITCHING AND MAC ADDRESS TABLES
# =============================================================================

@dataclass
class SwitchPort:
    name: str
    connected_device: Optional[str] = None


class LearningSwitch:
    """
    Simplified Ethernet learning switch.

    A switch learns source MAC addresses and associates them with incoming
    ports. For unknown destinations, it floods frames to other ports.
    """

    def __init__(self, ports: List[str]) -> None:
        if len(set(ports)) != len(ports):
            raise ValueError("Switch ports must be unique.")

        self.ports = {port: SwitchPort(port) for port in ports}
        self.mac_table: Dict[str, str] = {}

    def learn(self, source_mac: str, incoming_port: str) -> None:
        if incoming_port not in self.ports:
            raise ValueError(f"Unknown port: {incoming_port}")

        normalized_mac = normalize_mac_address(source_mac)
        self.mac_table[normalized_mac] = incoming_port

    def forward(
        self,
        source_mac: str,
        destination_mac: str,
        incoming_port: str,
    ) -> List[str]:
        """
        Learn source MAC and determine outgoing ports.

        Broadcast destination:
            FF:FF:FF:FF:FF:FF

        Unknown unicast:
            Flood to all ports except the incoming port.

        Known unicast:
            Send only through the learned destination port.
        """
        self.learn(source_mac, incoming_port)

        normalized_destination = normalize_mac_address(destination_mac)

        if normalized_destination == "FF:FF:FF:FF:FF:FF":
            return [
                port
                for port in self.ports
                if port != incoming_port
            ]

        destination_port = self.mac_table.get(normalized_destination)

        if destination_port is None:
            return [
                port
                for port in self.ports
                if port != incoming_port
            ]

        if destination_port == incoming_port:
            # Filtering prevents unnecessary forwarding back through
            # the same port.
            return []

        return [destination_port]

    def show_mac_table(self) -> None:
        print("\nSwitch MAC Address Table")
        if not self.mac_table:
            print("  <empty>")
            return

        for mac, port in sorted(self.mac_table.items()):
            print(f"  {mac} -> {port}")


print("\n" + "=" * 80)
print("SWITCHING SIMULATION")
print("=" * 80)

switch = LearningSwitch(["Fa0/1", "Fa0/2", "Fa0/3", "Fa0/4"])

actions = [
    ("00:00:00:00:00:01", "00:00:00:00:00:02", "Fa0/1"),
    ("00:00:00:00:00:02", "00:00:00:00:00:01", "Fa0/2"),
    ("00:00:00:00:00:03", "FF:FF:FF:FF:FF:FF", "Fa0/3"),
]

for source, destination, incoming in actions:
    outgoing = switch.forward(source, destination, incoming)

    print(f"\nIncoming port: {incoming}")
    print(f"Source MAC: {source}")
    print(f"Destination MAC: {destination}")
    print(f"Outgoing ports: {outgoing}")

switch.show_mac_table()


# =============================================================================
# 13. ROUTING AND LONGEST PREFIX MATCH
# =============================================================================

@dataclass
class Route:
    network: ipaddress.IPv4Network
    next_hop: str
    interface: str


class Router:
    """
    Simplified IPv4 router using longest prefix matching.

    The most specific matching route wins.
    """

    def __init__(self) -> None:
        self.routes: List[Route] = []

    def add_route(
        self,
        network: str,
        next_hop: str,
        interface: str,
    ) -> None:
        route_network = ipaddress.ip_network(network, strict=False)

        if route_network.version != 4:
            raise ValueError("This router example supports IPv4 only.")

        self.routes.append(
            Route(
                network=route_network,
                next_hop=next_hop,
                interface=interface,
            )
        )

    def lookup(self, destination: str) -> Optional[Route]:
        destination_ip = ipaddress.ip_address(destination)

        matching_routes = [
            route
            for route in self.routes
            if destination_ip in route.network
        ]

        if not matching_routes:
            return None

        return max(
            matching_routes,
            key=lambda route: route.network.prefixlen,
        )

    def route_packet(self, destination: str) -> None:
        route = self.lookup(destination)

        if route is None:
            print(f"No route found for {destination}")
            return

        print(
            f"Destination {destination} -> "
            f"network {route.network}, "
            f"next hop {route.next_hop}, "
            f"interface {route.interface}"
        )


print("\n" + "=" * 80)
print("ROUTING SIMULATION")
print("=" * 80)

router = Router()

router.add_route("0.0.0.0/0", "203.0.113.1", "GigabitEthernet0/0")
router.add_route("10.0.0.0/8", "10.0.0.1", "GigabitEthernet0/1")
router.add_route("10.10.0.0/16", "10.10.0.1", "GigabitEthernet0/2")
router.add_route("10.10.20.0/24", "10.10.20.1", "GigabitEthernet0/3")

for destination in [
    "8.8.8.8",
    "10.20.30.40",
    "10.10.5.5",
    "10.10.20.50",
]:
    router.route_packet(destination)


# =============================================================================
# 14. TCP AND UDP
# =============================================================================

class TransportProtocol(Enum):
    TCP = "Transmission Control Protocol"
    UDP = "User Datagram Protocol"


TRANSPORT_COMPARISON = {
    TransportProtocol.TCP: {
        "connection": "Connection-oriented",
        "reliability": "Reliable delivery through acknowledgments and retransmission",
        "ordering": "Preserves byte-stream order",
        "overhead": "Higher",
        "typical_uses": ["Web traffic", "SSH", "Email", "File transfer"],
    },
    TransportProtocol.UDP: {
        "connection": "Connectionless",
        "reliability": "Application-dependent",
        "ordering": "No built-in delivery ordering guarantee",
        "overhead": "Lower",
        "typical_uses": ["DNS", "Streaming", "Real-time communication"],
    },
}

print("\n" + "=" * 80)
print("TCP VS UDP")
print("=" * 80)

for protocol, details in TRANSPORT_COMPARISON.items():
    print(f"\n{protocol.name}")
    for key, value in details.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")


# =============================================================================
# 15. TCP THREE-WAY HANDSHAKE SIMULATION
# =============================================================================

class TCPState(Enum):
    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"


@dataclass
class TCPConnectionSimulation:
    client_state: TCPState = TCPState.CLOSED
    server_state: TCPState = TCPState.LISTEN

    def handshake(self) -> None:
        print("\nTCP Three-Way Handshake")

        # Step 1: Client sends SYN.
        self.client_state = TCPState.SYN_SENT
        print("1. Client -> Server: SYN")

        # Step 2: Server receives SYN and sends SYN-ACK.
        self.server_state = TCPState.SYN_RECEIVED
        print("2. Server -> Client: SYN-ACK")

        # Step 3: Client sends ACK.
        self.client_state = TCPState.ESTABLISHED
        self.server_state = TCPState.ESTABLISHED
        print("3. Client -> Server: ACK")

        print(
            f"Client state: {self.client_state.value}, "
            f"Server state: {self.server_state.value}"
        )


print("\n" + "=" * 80)
print("TCP CONNECTION ESTABLISHMENT")
print("=" * 80)

tcp_simulation = TCPConnectionSimulation()
tcp_simulation.handshake()


# =============================================================================
# 16. PORTS AND SOCKETS
# =============================================================================

COMMON_PORTS = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP server",
    68: "DHCP client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    3389: "RDP",
}


def describe_port(port: int) -> str:
    """Return a known service or a generic description."""
    if not 0 <= port <= 65535:
        raise ValueError("Port must be between 0 and 65535.")

    return COMMON_PORTS.get(port, "Unassigned or application-specific")


print("\n" + "=" * 80)
print("PORTS")
print("=" * 80)

for port in [22, 53, 80, 443, 8080, 65535]:
    print(f"Port {port:<5}: {describe_port(port)}")


def local_hostname_information() -> None:
    """
    Demonstrate Python socket APIs without contacting an external server.
    """
    hostname = socket.gethostname()

    print("\nLocal socket information")
    print(f"Hostname: {hostname}")

    try:
        resolved_ip = socket.gethostbyname(hostname)
        print(f"Resolved IPv4 address: {resolved_ip}")
    except socket.gaierror as error:
        print(f"Hostname resolution failed: {error}")


local_hostname_information()


# =============================================================================
# 17. DNS CONCEPTS
# =============================================================================

class SimpleDNSResolver:
    """
    Simplified DNS resolver.

    Real DNS is distributed and hierarchical. This class demonstrates
    caching and hostname-to-address mapping conceptually.
    """

    def __init__(self) -> None:
        self.records: Dict[str, str] = {}
        self.cache: Dict[str, Tuple[str, float]] = {}

    def add_record(self, hostname: str, address: str) -> None:
        normalized_hostname = hostname.lower().rstrip(".")

        ipaddress.ip_address(address)
        self.records[normalized_hostname] = address

    def resolve(self, hostname: str, ttl_seconds: float = 60.0) -> str:
        normalized_hostname = hostname.lower().rstrip(".")
        current_time = time.monotonic()

        cached = self.cache.get(normalized_hostname)

        if cached is not None:
            address, expiry = cached

            if current_time < expiry:
                print(f"DNS cache hit: {normalized_hostname}")
                return address

            del self.cache[normalized_hostname]

        if normalized_hostname not in self.records:
            raise KeyError(f"DNS record not found: {hostname}")

        address = self.records[normalized_hostname]
        self.cache[normalized_hostname] = (
            address,
            current_time + ttl_seconds,
        )

        print(f"DNS authoritative lookup: {normalized_hostname}")
        return address


print("\n" + "=" * 80)
print("DNS SIMULATION")
print("=" * 80)

dns = SimpleDNSResolver()
dns.add_record("server.example.test", "192.168.1.100")

print(dns.resolve("server.example.test"))
print(dns.resolve("SERVER.EXAMPLE.TEST."))


# =============================================================================
# 18. DHCP CONCEPTS
# =============================================================================

@dataclass
class DHCPLease:
    client_id: str
    ip_address: str
    lease_expiry: float


class SimpleDHCPServer:
    """
    Simplified DHCP server.

    Demonstrates allocation from a finite address pool.
    """

    def __init__(self, network: str, lease_seconds: int = 3600) -> None:
        self.network = ipaddress.ip_network(network, strict=False)

        if self.network.version != 4:
            raise ValueError("Only IPv4 is supported in this example.")

        self.lease_seconds = lease_seconds
        self.leases: Dict[str, DHCPLease] = {}
        self.allocated_ips: Dict[str, str] = {}

    def _available_addresses(self) -> List[str]:
        reserved = {
            str(self.network.network_address),
            str(self.network.broadcast_address),
        }

        available = []

        for address in self.network:
            address_string = str(address)

            if address_string in reserved:
                continue

            if address_string not in self.allocated_ips:
                available.append(address_string)

        return available

    def request_address(self, client_id: str) -> DHCPLease:
        current_time = time.monotonic()

        existing = self.leases.get(client_id)

        if existing is not None:
            if current_time < existing.lease_expiry:
                return existing

            del self.allocated_ips[existing.ip_address]
            del self.leases[client_id]

        available = self._available_addresses()

        if not available:
            raise RuntimeError("No addresses available.")

        selected_ip = available[0]

        lease = DHCPLease(
            client_id=client_id,
            ip_address=selected_ip,
            lease_expiry=current_time + self.lease_seconds,
        )

        self.leases[client_id] = lease
        self.allocated_ips[selected_ip] = client_id

        return lease


print("\n" + "=" * 80)
print("DHCP SIMULATION")
print("=" * 80)

dhcp_server = SimpleDHCPServer("192.168.50.0/29")

for client in ["laptop-001", "phone-001", "printer-001"]:
    lease = dhcp_server.request_address(client)
    print(f"{lease.client_id} received {lease.ip_address}")


# =============================================================================
# 19. ARP CONCEPTS
# =============================================================================

class ARPTable:
    """
    Simplified ARP table mapping IPv4 addresses to MAC addresses.
    """

    def __init__(self) -> None:
        self.entries: Dict[str, str] = {}

    def add_entry(self, ip_address: str, mac_address: str) -> None:
        ip = ipaddress.ip_address(ip_address)

        if ip.version != 4:
            raise ValueError("ARP is demonstrated here with IPv4 only.")

        normalized_mac = normalize_mac_address(mac_address)
        self.entries[str(ip)] = normalized_mac

    def lookup(self, ip_address: str) -> Optional[str]:
        return self.entries.get(ip_address)


print("\n" + "=" * 80)
print("ARP TABLE")
print("=" * 80)

arp_table = ARPTable()
arp_table.add_entry("192.168.1.1", "AA:AA:AA:AA:AA:01")
arp_table.add_entry("192.168.1.10", "AA:AA:AA:AA:AA:10")

for ip_address in ["192.168.1.1", "192.168.1.10", "192.168.1.99"]:
    mac = arp_table.lookup(ip_address)
    print(f"{ip_address} -> {mac if mac else 'No entry'}")


# =============================================================================
# 20. PACKET LOSS AND RETRANSMISSION SIMULATION
# =============================================================================

def simulate_packet_delivery(
    packet_count: int,
    loss_probability: float,
    random_seed: int = 42,
) -> Tuple[int, int]:
    """
    Simulate packet transmission with random loss.

    Returns:
        delivered_packets, lost_packets
    """
    if packet_count < 0:
        raise ValueError("Packet count cannot be negative.")

    if not 0.0 <= loss_probability <= 1.0:
        raise ValueError("Loss probability must be between 0 and 1.")

    random_generator = random.Random(random_seed)

    delivered = 0
    lost = 0

    for _ in range(packet_count):
        if random_generator.random() < loss_probability:
            lost += 1
        else:
            delivered += 1

    return delivered, lost


print("\n" + "=" * 80)
print("PACKET LOSS SIMULATION")
print("=" * 80)

delivered_packets, lost_packets = simulate_packet_delivery(
    packet_count=1000,
    loss_probability=0.02,
)

print(f"Delivered packets: {delivered_packets}")
print(f"Lost packets:      {lost_packets}")
print(
    f"Observed loss:     "
    f"{lost_packets / (delivered_packets + lost_packets) * 100:.2f}%"
)


# =============================================================================
# 21. QUEUEING AND NETWORK CONGESTION
# =============================================================================

@dataclass
class QueueSimulationResult:
    processed: int
    dropped: int
    remaining: int


def simulate_router_queue(
    incoming_packets_per_tick: List[int],
    processing_capacity_per_tick: int,
    maximum_queue_size: int,
) -> QueueSimulationResult:
    """
    Simulate a finite router queue.

    When the queue is full, newly arriving packets are dropped.
    """
    if processing_capacity_per_tick < 0:
        raise ValueError("Processing capacity cannot be negative.")

    if maximum_queue_size < 0:
        raise ValueError("Maximum queue size cannot be negative.")

    queue_size = 0
    processed = 0
    dropped = 0

    for incoming in incoming_packets_per_tick:
        if incoming < 0:
            raise ValueError("Incoming packet counts cannot be negative.")

        available_space = maximum_queue_size - queue_size
        accepted = min(incoming, available_space)
        dropped += incoming - accepted
        queue_size += accepted

        processed_now = min(queue_size, processing_capacity_per_tick)
        queue_size -= processed_now
        processed += processed_now

    return QueueSimulationResult(
        processed=processed,
        dropped=dropped,
        remaining=queue_size,
    )


print("\n" + "=" * 80)
print("NETWORK CONGESTION SIMULATION")
print("=" * 80)

queue_result = simulate_router_queue(
    incoming_packets_per_tick=[10, 25, 40, 15, 60, 20],
    processing_capacity_per_tick=20,
    maximum_queue_size=50,
)

print(f"Processed: {queue_result.processed}")
print(f"Dropped:   {queue_result.dropped}")
print(f"Remaining: {queue_result.remaining}")


# =============================================================================
# 22. MAXIMUM TRANSMISSION UNIT AND FRAGMENTATION CONCEPTS
# =============================================================================

def fragment_payload(
    payload_size: int,
    mtu: int,
    header_size: int,
) -> List[int]:
    """
    Divide a payload into fragments.

    This is a conceptual fragmentation calculation. Real fragmentation rules
    depend on the protocol. IPv4 fragments, for example, have alignment rules
    for all but the final fragment.
    """
    if payload_size < 0:
        raise ValueError("Payload size cannot be negative.")

    if mtu <= header_size:
        raise ValueError("MTU must be larger than header size.")

    payload_per_fragment = mtu - header_size

    if payload_size == 0:
        return [0]

    fragments = []

    remaining = payload_size

    while remaining > 0:
        fragment_size = min(remaining, payload_per_fragment)
        fragments.append(fragment_size)
        remaining -= fragment_size

    return fragments


print("\n" + "=" * 80)
print("MTU AND FRAGMENTATION")
print("=" * 80)

payload_size = 5000
mtu = 1500
header_size = 20

fragments = fragment_payload(payload_size, mtu, header_size)

print(f"Original payload: {payload_size} bytes")
print(f"MTU: {mtu} bytes")
print(f"Header size: {header_size} bytes")
print(f"Fragments: {fragments}")
print(f"Number of fragments: {len(fragments)}")


# =============================================================================
# 23. WIRESHARK CONCEPTS
# =============================================================================

class CaptureProtocol(Enum):
    ETHERNET = "Ethernet"
    ARP = "ARP"
    IPv4 = "IPv4"
    TCP = "TCP"
    UDP = "UDP"
    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"


@dataclass
class CapturedPacket:
    """
    Simplified representation of a packet capture entry.

    Wireshark displays significantly more protocol information.
    """

    timestamp: float
    source: str
    destination: str
    protocol: CaptureProtocol
    length: int
    info: str


def filter_packets(
    packets: List[CapturedPacket],
    protocol: Optional[CaptureProtocol] = None,
    source: Optional[str] = None,
    destination: Optional[str] = None,
) -> List[CapturedPacket]:
    """
    Conceptually similar to applying display-filter conditions.

    Real Wireshark display filters use a specialized expression language.
    """
    results = []

    for packet_capture in packets:
        if protocol is not None and packet_capture.protocol != protocol:
            continue

        if source is not None and packet_capture.source != source:
            continue

        if destination is not None and packet_capture.destination != destination:
            continue

        results.append(packet_capture)

    return results


print("\n" + "=" * 80)
print("WIRESHARK-STYLE PACKET CAPTURE SIMULATION")
print("=" * 80)

capture = [
    CapturedPacket(
        timestamp=0.001,
        source="192.168.1.10",
        destination="192.168.1.1",
        protocol=CaptureProtocol.DNS,
        length=74,
        info="Standard query A example.test",
    ),
    CapturedPacket(
        timestamp=0.020,
        source="192.168.1.1",
        destination="192.168.1.10",
        protocol=CaptureProtocol.DNS,
        length=90,
        info="Standard query response A 203.0.113.10",
    ),
    CapturedPacket(
        timestamp=0.100,
        source="192.168.1.10",
        destination="203.0.113.10",
        protocol=CaptureProtocol.TCP,
        length=74,
        info="SYN",
    ),
    CapturedPacket(
        timestamp=0.130,
        source="203.0.113.10",
        destination="192.168.1.10",
        protocol=CaptureProtocol.TCP,
        length=74,
        info="SYN, ACK",
    ),
    CapturedPacket(
        timestamp=0.160,
        source="192.168.1.10",
        destination="203.0.113.10",
        protocol=CaptureProtocol.TCP,
        length=66,
        info="ACK",
    ),
]

dns_packets = filter_packets(
    capture,
    protocol=CaptureProtocol.DNS,
)

print("\nPackets matching conceptual DNS filter:")
for captured_packet in dns_packets:
    print(
        f"{captured_packet.timestamp:.3f} "
        f"{captured_packet.source} -> "
        f"{captured_packet.destination} "
        f"{captured_packet.protocol.value} "
        f"{captured_packet.info}"
    )


# =============================================================================
# 24. COMMON WIRESHARK DISPLAY FILTER CONCEPTS
# =============================================================================

WIRESHARK_FILTER_CONCEPTS = {
    "ip.addr == 192.168.1.10": "Packets where the IP appears as source or destination",
    "ip.src == 192.168.1.10": "Packets with the specified IPv4 source",
    "ip.dst == 192.168.1.10": "Packets with the specified IPv4 destination",
    "tcp": "TCP packets",
    "udp": "UDP packets",
    "dns": "DNS packets",
    "tcp.port == 443": "TCP packets involving port 443",
    "http": "HTTP protocol packets recognized by the dissector",
}

print("\n" + "=" * 80)
print("WIRESHARK DISPLAY FILTER CONCEPTS")
print("=" * 80)

for filter_expression, meaning in WIRESHARK_FILTER_CONCEPTS.items():
    print(f"{filter_expression:<30} -> {meaning}")


# =============================================================================
# 25. CISCO PACKET TRACER CONCEPTS
# =============================================================================

PACKET_TRACER_WORKFLOW = [
    (
        "1. Place devices",
        "Add PCs, switches, routers, servers, and other supported devices.",
    ),
    (
        "2. Connect devices",
        "Select appropriate cables or supported automatic connections.",
    ),
    (
        "3. Configure interfaces",
        "Assign IP addresses, subnet masks, and enable interfaces.",
    ),
    (
        "4. Configure switching",
        "Create VLANs and configure switch ports when required.",
    ),
    (
        "5. Configure routing",
        "Use static routes or supported dynamic routing protocols.",
    ),
    (
        "6. Test connectivity",
        "Use ping, simulation mode, and protocol inspection.",
    ),
    (
        "7. Troubleshoot",
        "Check addressing, interfaces, routing tables, VLAN membership, and ACLs.",
    ),
]

print("\n" + "=" * 80)
print("CISCO PACKET TRACER WORKFLOW")
print("=" * 80)

for step, description in PACKET_TRACER_WORKFLOW:
    print(f"\n{step}")
    print(f"  {description}")


# =============================================================================
# 26. SIMPLE NETWORK DESIGN VALIDATION
# =============================================================================

@dataclass
class HostConfiguration:
    hostname: str
    ip_address: str
    gateway: str
    subnet: str


def validate_host_configuration(configuration: HostConfiguration) -> List[str]:
    """
    Validate whether host and gateway are inside the configured subnet.
    """
    errors = []

    try:
        network = ipaddress.ip_network(configuration.subnet, strict=False)
        host_ip = ipaddress.ip_address(configuration.ip_address)
        gateway_ip = ipaddress.ip_address(configuration.gateway)

        if host_ip not in network:
            errors.append(
                f"Host IP {host_ip} is not inside subnet {network}."
            )

        if gateway_ip not in network:
            errors.append(
                f"Gateway {gateway_ip} is not inside subnet {network}."
            )

        if host_ip == network.network_address:
            errors.append("Host IP is the network address.")

        if network.version == 4 and host_ip == network.broadcast_address:
            errors.append("Host IP is the broadcast address.")

        if host_ip == gateway_ip:
            errors.append("Host IP and gateway should not normally be identical.")

    except ValueError as error:
        errors.append(f"Invalid configuration: {error}")

    return errors


print("\n" + "=" * 80)
print("NETWORK CONFIGURATION VALIDATION")
print("=" * 80)

host_configurations = [
    HostConfiguration(
        hostname="PC-1",
        ip_address="192.168.1.10",
        gateway="192.168.1.1",
        subnet="192.168.1.0/24",
    ),
    HostConfiguration(
        hostname="PC-2",
        ip_address="192.168.1.10",
        gateway="192.168.2.1",
        subnet="192.168.1.0/24",
    ),
]

for configuration in host_configurations:
    errors = validate_host_configuration(configuration)

    print(f"\nHost: {configuration.hostname}")

    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
    else:
        print("Configuration is valid.")


# =============================================================================
# 27. NETWORK LATENCY SIMULATION
# =============================================================================

@dataclass
class NetworkHop:
    name: str
    propagation_delay_ms: float
    processing_delay_ms: float
    queueing_delay_ms: float


def calculate_path_latency(hops: List[NetworkHop]) -> float:
    """Calculate total one-way latency across multiple network hops."""
    total_latency = 0.0

    for hop in hops:
        if (
            hop.propagation_delay_ms < 0
            or hop.processing_delay_ms < 0
            or hop.queueing_delay_ms < 0
        ):
            raise ValueError("Latency values cannot be negative.")

        total_latency += (
            hop.propagation_delay_ms
            + hop.processing_delay_ms
            + hop.queueing_delay_ms
        )

    return total_latency


print("\n" + "=" * 80)
print("MULTI-HOP LATENCY")
print("=" * 80)

network_path = [
    NetworkHop("Access Switch", 0.1, 0.2, 0.1),
    NetworkHop("Edge Router", 1.0, 0.5, 2.0),
    NetworkHop("ISP Router", 10.0, 0.8, 5.0),
    NetworkHop("Remote Router", 8.0, 0.7, 1.0),
]

total_latency = calculate_path_latency(network_path)

for hop in network_path:
    hop_latency = (
        hop.propagation_delay_ms
        + hop.processing_delay_ms
        + hop.queueing_delay_ms
    )

    print(f"{hop.name:<20}: {hop_latency:.2f} ms")

print(f"Total one-way latency: {total_latency:.2f} ms")
print(f"Estimated round-trip latency: {total_latency * 2:.2f} ms")


# =============================================================================
# 28. ERROR DETECTION WITH CHECKSUMS
# =============================================================================

def internet_checksum(data: bytes) -> int:
    """
    Calculate a simplified Internet-style one's-complement checksum.

    Networking protocols may use specific checksum scopes and pseudo-headers.
    This function demonstrates the core arithmetic principle.
    """
    if len(data) % 2 == 1:
        data += b"\x00"

    total = 0

    for index in range(0, len(data), 2):
        word = (data[index] << 8) + data[index + 1]
        total += word

        # Fold carries back into the lower 16 bits.
        total = (total & 0xFFFF) + (total >> 16)

    # Final carry folding.
    total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


print("\n" + "=" * 80)
print("CHECKSUM DEMONSTRATION")
print("=" * 80)

sample_data = b"Networking fundamentals"
checksum = internet_checksum(sample_data)

print(f"Data: {sample_data}")
print(f"Checksum: 0x{checksum:04X}")


# =============================================================================
# 29. BASIC BINARY PROTOCOL SERIALIZATION
# =============================================================================

@dataclass
class SimpleHeader:
    """
    Demonstrates binary serialization using struct.

    Fields:
    - version: 1 byte
    - message_type: 1 byte
    - sequence_number: 4 bytes
    """

    version: int
    message_type: int
    sequence_number: int

    FORMAT = "!BBI"

    def serialize(self) -> bytes:
        if not 0 <= self.version <= 255:
            raise ValueError("Version must fit into one byte.")

        if not 0 <= self.message_type <= 255:
            raise ValueError("Message type must fit into one byte.")

        if not 0 <= self.sequence_number <= 0xFFFFFFFF:
            raise ValueError("Sequence number must fit into four bytes.")

        return struct.pack(
            self.FORMAT,
            self.version,
            self.message_type,
            self.sequence_number,
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "SimpleHeader":
        expected_size = struct.calcsize(cls.FORMAT)

        if len(data) != expected_size:
            raise ValueError(
                f"Expected {expected_size} bytes, received {len(data)}."
            )

        version, message_type, sequence_number = struct.unpack(
            cls.FORMAT,
            data,
        )

        return cls(
            version=version,
            message_type=message_type,
            sequence_number=sequence_number,
        )


print("\n" + "=" * 80)
print("BINARY HEADER SERIALIZATION")
print("=" * 80)

header = SimpleHeader(
    version=1,
    message_type=2,
    sequence_number=123456,
)

serialized_header = header.serialize()
deserialized_header = SimpleHeader.deserialize(serialized_header)

print(f"Original header: {header}")
print(f"Serialized bytes: {serialized_header.hex()}")
print(f"Deserialized header: {deserialized_header}")


# =============================================================================
# 30. NETWORK SECURITY FUNDAMENTALS
# =============================================================================

SECURITY_PRINCIPLES = {
    "Segmentation": (
        "Separate systems into logical or physical network segments to "
        "limit unnecessary communication and reduce blast radius."
    ),
    "Least Privilege": (
        "Allow only required network access, ports, protocols and destinations."
    ),
    "Encryption": (
        "Protect data confidentiality and integrity when traversing untrusted networks."
    ),
    "Authentication": (
        "Verify identities before granting access to network resources."
    ),
    "Monitoring": (
        "Collect logs, flow information and packet evidence for detection and investigation."
    ),
    "Patch Management": (
        "Maintain network devices and services to reduce exposure to known vulnerabilities."
    ),
    "Firewalling": (
        "Filter traffic according to explicitly defined security policy."
    ),
}

print("\n" + "=" * 80)
print("NETWORK SECURITY FUNDAMENTALS")
print("=" * 80)

for principle, explanation in SECURITY_PRINCIPLES.items():
    print(f"\n{principle}")
    print(f"  {explanation}")


# =============================================================================
# 31. FIREWALL RULE SIMULATION
# =============================================================================

@dataclass
class FirewallRule:
    source_network: ipaddress.IPv4Network
    destination_network: ipaddress.IPv4Network
    protocol: str
    port: Optional[int]
    action: str


class SimpleFirewall:
    """
    Ordered firewall rule processor.

    Rules are evaluated from top to bottom. The first matching rule wins.
    """

    def __init__(self, default_action: str = "DENY") -> None:
        default_action = default_action.upper()

        if default_action not in {"ALLOW", "DENY"}:
            raise ValueError("Default action must be ALLOW or DENY.")

        self.rules: List[FirewallRule] = []
        self.default_action = default_action

    def add_rule(
        self,
        source_network: str,
        destination_network: str,
        protocol: str,
        port: Optional[int],
        action: str,
    ) -> None:
        action = action.upper()

        if action not in {"ALLOW", "DENY"}:
            raise ValueError("Firewall action must be ALLOW or DENY.")

        if port is not None and not 0 <= port <= 65535:
            raise ValueError("Port must be between 0 and 65535.")

        self.rules.append(
            FirewallRule(
                source_network=ipaddress.ip_network(
                    source_network,
                    strict=False,
                ),
                destination_network=ipaddress.ip_network(
                    destination_network,
                    strict=False,
                ),
                protocol=protocol.upper(),
                port=port,
                action=action,
            )
        )

    def evaluate(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str,
        port: Optional[int],
    ) -> str:
        source = ipaddress.ip_address(source_ip)
        destination = ipaddress.ip_address(destination_ip)
        normalized_protocol = protocol.upper()

        for rule in self.rules:
            if source not in rule.source_network:
                continue

            if destination not in rule.destination_network:
                continue

            if rule.protocol != normalized_protocol:
                continue

            if rule.port is not None and rule.port != port:
                continue

            return rule.action

        return self.default_action


print("\n" + "=" * 80)
print("FIREWALL SIMULATION")
print("=" * 80)

firewall = SimpleFirewall(default_action="DENY")

firewall.add_rule(
    source_network="192.168.1.0/24",
    destination_network="0.0.0.0/0",
    protocol="TCP",
    port=443,
    action="ALLOW",
)

firewall.add_rule(
    source_network="192.168.1.0/24",
    destination_network="192.168.2.0/24",
    protocol="TCP",
    port=22,
    action="ALLOW",
)

traffic_tests = [
    ("192.168.1.10", "8.8.8.8", "TCP", 443),
    ("192.168.1.10", "8.8.8.8", "TCP", 80),
    ("192.168.1.10", "192.168.2.20", "TCP", 22),
]

for source, destination, protocol, port in traffic_tests:
    action = firewall.evaluate(
        source,
        destination,
        protocol,
        port,
    )

    print(
        f"{source} -> {destination} "
        f"{protocol}/{port}: {action}"
    )


# =============================================================================
# 32. PERFORMANCE CONSIDERATIONS
# =============================================================================

def transmission_delay_seconds(
    packet_size_bytes: int,
    bandwidth_bps: int,
) -> float:
    """
    Transmission delay is the time required to place packet bits onto a link.
    """
    if packet_size_bytes < 0:
        raise ValueError("Packet size cannot be negative.")

    if bandwidth_bps <= 0:
        raise ValueError("Bandwidth must be greater than zero.")

    return packet_size_bytes * 8 / bandwidth_bps


def propagation_delay_seconds(
    distance_meters: float,
    propagation_speed_meters_per_second: float,
) -> float:
    """
    Propagation delay is the time required for a signal to travel.

    Signals in fiber and copper travel below the speed of light.
    """
    if distance_meters < 0:
        raise ValueError("Distance cannot be negative.")

    if propagation_speed_meters_per_second <= 0:
        raise ValueError("Propagation speed must be greater than zero.")

    return distance_meters / propagation_speed_meters_per_second


print("\n" + "=" * 80)
print("TRANSMISSION VS PROPAGATION DELAY")
print("=" * 80)

packet_size = 1500
link_bandwidth = 100_000_000
distance = 1_000_000
fiber_speed = 200_000_000

transmission_delay = transmission_delay_seconds(
    packet_size,
    link_bandwidth,
)

propagation_delay = propagation_delay_seconds(
    distance,
    fiber_speed,
)

print(
    f"Transmission delay: {transmission_delay * 1000:.4f} ms"
)
print(
    f"Propagation delay:  {propagation_delay * 1000:.4f} ms"
)


# =============================================================================
# 33. NETWORK DESIGN TRADE-OFFS
# =============================================================================

DESIGN_TRADE_OFFS = [
    (
        "High redundancy",
        "Improves availability",
        "Increases cost and configuration complexity",
    ),
    (
        "Large broadcast domain",
        "Simplifies some deployments",
        "Can increase unnecessary broadcast traffic",
    ),
    (
        "Network segmentation",
        "Improves security and fault isolation",
        "Requires routing and policy management",
    ),
    (
        "TCP",
        "Provides reliability and ordering",
        "Adds protocol overhead and congestion-control behavior",
    ),
    (
        "UDP",
        "Lower protocol overhead",
        "Reliability and ordering may need application-level handling",
    ),
]

print("\n" + "=" * 80)
print("NETWORK DESIGN TRADE-OFFS")
print("=" * 80)

for design, advantage, cost in DESIGN_TRADE_OFFS:
    print(f"\nDesign choice: {design}")
    print(f"  Advantage: {advantage}")
    print(f"  Trade-off: {cost}")


# =============================================================================
# 34. COMMON TROUBLESHOOTING MODEL
# =============================================================================

TROUBLESHOOTING_SEQUENCE = [
    (
        "Physical layer",
        "Check power, cables, Wi-Fi association, interface status.",
    ),
    (
        "Data link layer",
        "Check MAC learning, VLAN membership, switch ports.",
    ),
    (
        "Network layer",
        "Check IP address, subnet mask, gateway and routes.",
    ),
    (
        "Transport layer",
        "Check protocol, ports, firewall policy and service availability.",
    ),
    (
        "Application layer",
        "Check DNS, authentication, application configuration and logs.",
    ),
]

print("\n" + "=" * 80)
print("SYSTEMATIC NETWORK TROUBLESHOOTING")
print("=" * 80)

for layer, action in TROUBLESHOOTING_SEQUENCE:
    print(f"\n{layer}")
    print(f"  {action}")


# =============================================================================
# 35. PRACTICAL CONNECTIVITY TESTING LOGIC
# =============================================================================

@dataclass
class ConnectivityTest:
    host: str
    ip_address: str
    gateway_reachable: bool
    dns_working: bool
    remote_host_reachable: bool


def diagnose_connectivity(test: ConnectivityTest) -> List[str]:
    """
    Produce a basic diagnosis from conceptual connectivity observations.
    """
    diagnosis = []

    if not test.gateway_reachable:
        diagnosis.append(
            "Local network or default gateway connectivity is failing."
        )

    if test.gateway_reachable and not test.dns_working:
        diagnosis.append(
            "Basic network connectivity may exist, but name resolution is failing."
        )

    if (
        test.gateway_reachable
        and test.dns_working
        and not test.remote_host_reachable
    ):
        diagnosis.append(
            "Check routing, remote firewall policy, service availability, "
            "or Internet connectivity."
        )

    if (
        test.gateway_reachable
        and test.dns_working
        and test.remote_host_reachable
    ):
        diagnosis.append("Connectivity tests indicate normal operation.")

    return diagnosis


print("\n" + "=" * 80)
print("CONNECTIVITY DIAGNOSIS")
print("=" * 80)

connectivity_tests = [
    ConnectivityTest(
        host="PC-1",
        ip_address="192.168.1.10",
        gateway_reachable=False,
        dns_working=False,
        remote_host_reachable=False,
    ),
    ConnectivityTest(
        host="PC-2",
        ip_address="192.168.1.20",
        gateway_reachable=True,
        dns_working=False,
        remote_host_reachable=False,
    ),
    ConnectivityTest(
        host="PC-3",
        ip_address="192.168.1.30",
        gateway_reachable=True,
        dns_working=True,
        remote_host_reachable=True,
    ),
]

for test in connectivity_tests:
    print(f"\nHost: {test.host}")

    for finding in diagnose_connectivity(test):
        print(f"  - {finding}")


# =============================================================================
# 36. ADVANCED CONCEPT: EFFECTIVE THROUGHPUT
# =============================================================================

def effective_throughput(
    useful_payload_bytes: int,
    total_transmitted_bytes: int,
    transmission_time_seconds: float,
) -> Tuple[float, float]:
    """
    Calculate:
    - Useful application throughput in bits per second.
    - Efficiency as useful payload / total transmitted bytes.
    """
    if useful_payload_bytes < 0:
        raise ValueError("Useful payload cannot be negative.")

    if total_transmitted_bytes <= 0:
        raise ValueError("Total transmitted bytes must be positive.")

    if transmission_time_seconds <= 0:
        raise ValueError("Transmission time must be positive.")

    if useful_payload_bytes > total_transmitted_bytes:
        raise ValueError(
            "Useful payload cannot exceed total transmitted bytes."
        )

    throughput_bps = (
        useful_payload_bytes * 8 / transmission_time_seconds
    )

    efficiency = (
        useful_payload_bytes / total_transmitted_bytes
    )

    return throughput_bps, efficiency


print("\n" + "=" * 80)
print("EFFECTIVE THROUGHPUT AND PROTOCOL OVERHEAD")
print("=" * 80)

throughput, efficiency = effective_throughput(
    useful_payload_bytes=1400,
    total_transmitted_bytes=1540,
    transmission_time_seconds=0.001,
)

print(f"Useful throughput: {throughput / 1_000_000:.2f} Mbps")
print(f"Payload efficiency: {efficiency * 100:.2f}%")


# =============================================================================
# 37. ADVANCED CONCEPT: SUBNET CAPACITY PLANNING
# =============================================================================

def required_prefix_for_hosts(required_hosts: int) -> int:
    """
    Determine the smallest IPv4 prefix that supports the requested number
    of traditional usable host addresses.

    The calculation uses:
        usable hosts = 2^(host_bits) - 2

    /31 and /32 special cases are intentionally excluded because this
    function models conventional multi-host subnet planning.
    """
    if required_hosts <= 0:
        raise ValueError("Required hosts must be greater than zero.")

    host_bits = math.ceil(math.log2(required_hosts + 2))

    if host_bits > 30:
        raise ValueError("Requested host count exceeds IPv4 capacity.")

    return 32 - host_bits


print("\n" + "=" * 80)
print("SUBNET CAPACITY PLANNING")
print("=" * 80)

for host_requirement in [10, 50, 100, 500, 1000]:
    prefix = required_prefix_for_hosts(host_requirement)
    capacity = (2 ** (32 - prefix)) - 2

    print(
        f"Required hosts: {host_requirement:<5} "
        f"Recommended prefix: /{prefix:<2} "
        f"Usable capacity: {capacity}"
    )


# =============================================================================
# 38. IMPORTANT COMMON MISTAKES
# =============================================================================

COMMON_MISTAKES = [
    (
        "Confusing bandwidth with throughput",
        "Bandwidth is theoretical link capacity; throughput is observed useful transfer rate.",
    ),
    (
        "Confusing latency with bandwidth",
        "A high-bandwidth network can still have high latency.",
    ),
    (
        "Using an incorrect subnet mask",
        "Devices that appear similar may be placed in different logical networks.",
    ),
    (
        "Assigning network or broadcast addresses to hosts",
        "Traditional IPv4 subnets reserve these addresses.",
    ),
    (
        "Ignoring default gateway configuration",
        "A host may communicate locally but fail to reach remote networks.",
    ),
    (
        "Assuming a switch performs routing",
        "Traditional Layer 2 switching and Layer 3 routing have different responsibilities.",
    ),
    (
        "Opening unnecessary ports",
        "Unnecessary exposed services increase attack surface.",
    ),
    (
        "Capturing sensitive traffic without authorization",
        "Packet captures can contain credentials, personal data and confidential information.",
    ),
]

print("\n" + "=" * 80)
print("COMMON NETWORKING MISTAKES")
print("=" * 80)

for mistake, explanation in COMMON_MISTAKES:
    print(f"\n{mistake}")
    print(f"  {explanation}")


# =============================================================================
# 39. FINAL INTEGRATED MINI-SCENARIO
# =============================================================================

print("\n" + "=" * 80)
print("INTEGRATED NETWORKING SCENARIO")
print("=" * 80)

print(
    """
Scenario:
A laptop with IP address 192.168.10.25/24 needs to communicate with
a server at 10.20.30.40.

Conceptual flow:

1. The laptop determines that 10.20.30.40 is outside 192.168.10.0/24.
2. It sends the packet to its default gateway.
3. ARP resolves the gateway's IPv4 address to a local MAC address.
4. The laptop creates an Ethernet frame addressed to the gateway MAC.
5. The frame contains an IP packet addressed to 10.20.30.40.
6. A switch forwards the frame according to its MAC address table.
7. A router removes the incoming Layer 2 frame.
8. The router examines the destination IP address.
9. The router performs longest-prefix route lookup.
10. The router decrements TTL.
11. The router creates a new Layer 2 frame for the next network segment.
12. The process repeats across routers until the destination network is reached.
13. The destination host processes the transport protocol.
14. TCP or UDP delivers data to the appropriate application port.
"""
)


# =============================================================================
# 40. MAIN COMPLETION MESSAGE
# =============================================================================

print("=" * 80)
print("NETWORKING FUNDAMENTALS SCRIPT COMPLETED")
print("=" * 80)
print(
    "Concepts demonstrated include network types, topologies, OSI and TCP/IP "
    "models, addressing, subnetting, frames, packets, switching, routing, "
    "TCP, UDP, DNS, DHCP, ARP, ports, latency, congestion, MTU, packet "
    "analysis concepts, Packet Tracer workflow, security, firewalls, "
    "performance calculations and troubleshooting."
)
