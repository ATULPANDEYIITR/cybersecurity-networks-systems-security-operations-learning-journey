#!/usr/bin/env python3
"""
ARP: Address Resolution Protocol
================================

A standalone educational study program covering:

- IPv4-to-MAC address resolution
- ARP requests and replies
- ARP packet fields
- Broadcast and unicast behavior
- ARP cache operation
- Gratuitous ARP
- ARP cache states and aging
- Same-subnet versus routed communication
- ARP resolution simulations
- ARP poisoning concepts
- Defensive detection logic
- Wireshark-oriented packet interpretation
- Validation, edge cases, troubleshooting, and security considerations

The program deliberately simulates ARP behavior rather than transmitting
real ARP packets. This makes the examples safe, deterministic, and usable
without special network privileges or third-party packages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import time
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Fundamental terminology
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_basics() -> None:
    print_section("1. ARP fundamentals")

    print(
        """
ARP stands for Address Resolution Protocol.

For a typical IPv4 Ethernet LAN, an application may know the destination
IPv4 address but Ethernet transmission requires a destination MAC address.

Example:

    IPv4 destination: 192.168.1.20
    Ethernet destination MAC: aa:bb:cc:dd:ee:20

ARP provides the mapping:

    IPv4 address -> MAC address

A host normally sends an ARP request as an Ethernet broadcast:

    "Who has 192.168.1.20? Tell 192.168.1.10."

The owner of 192.168.1.20 can respond with a unicast ARP reply:

    "192.168.1.20 is at aa:bb:cc:dd:ee:20."

The result can then be stored in the local ARP cache.
"""
    )


# ---------------------------------------------------------------------------
# 2. MAC-address and IPv4 validation
# ---------------------------------------------------------------------------

MAC_LENGTH = 17


def normalize_mac(mac_address: str) -> str:
    """
    Validate and normalize a conventional colon-separated MAC address.

    Example:
        AA:BB:CC:DD:EE:FF -> aa:bb:cc:dd:ee:ff
    """
    parts = mac_address.strip().lower().split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError(f"Invalid MAC address: {mac_address}")

    try:
        values = [int(part, 16) for part in parts]
    except ValueError as exc:
        raise ValueError(f"Invalid MAC address: {mac_address}") from exc

    if any(value < 0 or value > 255 for value in values):
        raise ValueError(f"Invalid MAC address: {mac_address}")

    return ":".join(f"{value:02x}" for value in values)


def validate_ipv4(address: str) -> str:
    """Return a canonical IPv4 string or raise ValueError."""
    parsed = ipaddress.ip_address(address)
    if parsed.version != 4:
        raise ValueError(f"Expected IPv4 address: {address}")
    return str(parsed)


def demonstrate_validation() -> None:
    print_section("2. Address validation")

    valid_mac = normalize_mac("AA:BB:CC:DD:EE:FF")
    valid_ip = validate_ipv4("192.168.1.10")

    print("Normalized MAC:", valid_mac)
    print("Validated IPv4:", valid_ip)

    for invalid_value in ["AA:BB:CC", "not-a-mac"]:
        try:
            normalize_mac(invalid_value)
        except ValueError as error:
            print("Rejected MAC:", invalid_value, "|", error)

    for invalid_value in ["999.1.1.1", "192.168.1.999"]:
        try:
            validate_ipv4(invalid_value)
        except ValueError as error:
            print("Rejected IPv4:", invalid_value, "|", error)


# ---------------------------------------------------------------------------
# 3. ARP operation codes and packet structure
# ---------------------------------------------------------------------------

class ArpOperation(Enum):
    REQUEST = 1
    REPLY = 2


@dataclass
class ARPPacket:
    """
    Simplified representation of an Ethernet/IPv4 ARP message.

    Real ARP has fixed-width fields. The simulation stores the semantic
    values needed to understand resolution.
    """

    operation: ArpOperation
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    def __post_init__(self) -> None:
        self.sender_mac = normalize_mac(self.sender_mac)
        self.target_mac = normalize_mac(self.target_mac)
        self.sender_ip = validate_ipv4(self.sender_ip)
        self.target_ip = validate_ipv4(self.target_ip)

    def describe(self) -> str:
        operation = self.operation.name
        return (
            f"ARP {operation}: "
            f"{self.sender_ip} ({self.sender_mac}) -> "
            f"{self.target_ip} ({self.target_mac})"
        )


def demonstrate_arp_packets() -> None:
    print_section("3. ARP request and reply")

    request = ARPPacket(
        operation=ArpOperation.REQUEST,
        sender_mac="02:00:00:00:00:10",
        sender_ip="192.168.1.10",
        target_mac="00:00:00:00:00:00",
        target_ip="192.168.1.20",
    )

    reply = ARPPacket(
        operation=ArpOperation.REPLY,
        sender_mac="02:00:00:00:00:20",
        sender_ip="192.168.1.20",
        target_mac="02:00:00:00:00:10",
        target_ip="192.168.1.10",
    )

    print(request.describe())
    print(reply.describe())

    print(
        """
Important distinction:

ARP request:
    Ethernet destination is normally ff:ff:ff:ff:ff:ff.
    The target MAC is unknown, so the ARP target hardware address is
    commonly represented as all zeroes.

ARP reply:
    The reply is normally sent directly to the requesting host's MAC.
"""
    )


# ---------------------------------------------------------------------------
# 4. ARP cache
# ---------------------------------------------------------------------------

class CacheState(Enum):
    REACHABLE = "reachable"
    STALE = "stale"
    STATIC = "static"


@dataclass
class ARPCacheEntry:
    ip_address: str
    mac_address: str
    state: CacheState
    learned_at: float = field(default_factory=time.time)

    def age(self, now: Optional[float] = None) -> float:
        current_time = time.time() if now is None else now
        return max(0.0, current_time - self.learned_at)


class ARPCache:
    """
    Educational ARP cache.

    Real operating systems have implementation-specific cache states and
    timers. This class intentionally uses a small, explicit model.
    """

    def __init__(self, reachable_timeout: float = 60.0) -> None:
        self.entries: Dict[str, ARPCacheEntry] = {}
        self.reachable_timeout = reachable_timeout

    def add(
        self,
        ip_address: str,
        mac_address: str,
        state: CacheState = CacheState.REACHABLE,
        learned_at: Optional[float] = None,
    ) -> None:
        ip_address = validate_ipv4(ip_address)
        mac_address = normalize_mac(mac_address)

        self.entries[ip_address] = ARPCacheEntry(
            ip_address=ip_address,
            mac_address=mac_address,
            state=state,
            learned_at=time.time() if learned_at is None else learned_at,
        )

    def lookup(self, ip_address: str) -> Optional[ARPCacheEntry]:
        ip_address = validate_ipv4(ip_address)
        entry = self.entries.get(ip_address)

        if entry is None:
            return None

        if (
            entry.state == CacheState.REACHABLE
            and entry.age() > self.reachable_timeout
        ):
            entry.state = CacheState.STALE

        return entry

    def remove(self, ip_address: str) -> bool:
        ip_address = validate_ipv4(ip_address)
        return self.entries.pop(ip_address, None) is not None

    def display(self) -> None:
        if not self.entries:
            print("(empty ARP cache)")
            return

        print(f"{'IPv4':<18}{'MAC':<20}{'State':<12}{'Age(s)':>8}")
        print("-" * 58)

        now = time.time()
        for entry in self.entries.values():
            print(
                f"{entry.ip_address:<18}"
                f"{entry.mac_address:<20}"
                f"{entry.state.value:<12}"
                f"{entry.age(now):>8.1f}"
            )


def demonstrate_arp_cache() -> None:
    print_section("4. ARP cache")

    cache = ARPCache(reachable_timeout=30)

    cache.add(
        "192.168.1.1",
        "02:00:00:00:00:01",
        CacheState.STATIC,
    )
    cache.add(
        "192.168.1.20",
        "02:00:00:00:00:20",
        CacheState.REACHABLE,
    )

    cache.display()

    entry = cache.lookup("192.168.1.20")
    print("\nLookup 192.168.1.20:")
    print(entry)

    print("\nLookup of unknown host:")
    print(cache.lookup("192.168.1.99"))


# ---------------------------------------------------------------------------
# 5. Ethernet and subnet reasoning
# ---------------------------------------------------------------------------

@dataclass
class Host:
    name: str
    ip_address: str
    mac_address: str

    def __post_init__(self) -> None:
        self.ip_address = validate_ipv4(self.ip_address)
        self.mac_address = normalize_mac(self.mac_address)


def same_subnet(
    first_ip: str,
    second_ip: str,
    prefix_length: int,
) -> bool:
    first = ipaddress.ip_interface(f"{first_ip}/{prefix_length}")
    second = ipaddress.ip_interface(f"{second_ip}/{prefix_length}")
    return first.network == second.network


def demonstrate_subnet_logic() -> None:
    print_section("5. Same-subnet communication")

    examples = [
        ("192.168.1.10", "192.168.1.20", 24),
        ("192.168.1.10", "192.168.2.20", 24),
        ("10.0.0.10", "10.0.0.11", 24),
    ]

    for first_ip, second_ip, prefix in examples:
        print(
            first_ip,
            "and",
            second_ip,
            f"with /{prefix}:",
            same_subnet(first_ip, second_ip, prefix),
        )

    print(
        """
ARP normally resolves an Ethernet address for a local Layer-2 destination.

When the final destination is on another IP network, the sender normally
resolves the MAC address of its default gateway instead of resolving the
remote host's MAC address directly.
"""
    )


# ---------------------------------------------------------------------------
# 6. LAN simulation
# ---------------------------------------------------------------------------

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"


class SimulatedLAN:
    """Safe in-memory model of ARP request/reply behavior."""

    def __init__(self, subnet: str) -> None:
        self.network = ipaddress.ip_network(subnet)
        self.hosts: Dict[str, Host] = {}
        self.caches: Dict[str, ARPCache] = {}

    def add_host(self, host: Host) -> None:
        address = ipaddress.ip_address(host.ip_address)
        if address not in self.network:
            raise ValueError(
                f"{host.ip_address} is outside {self.network}"
            )

        self.hosts[host.ip_address] = host
        self.caches[host.ip_address] = ARPCache()

    def send_arp_request(
        self,
        requester_ip: str,
        target_ip: str,
    ) -> Optional[ARPPacket]:
        requester = self.hosts.get(requester_ip)
        if requester is None:
            raise KeyError(f"Unknown requester: {requester_ip}")

        print(
            f"\n{requester.name} broadcasts: "
            f"Who has {target_ip}? Tell {requester_ip}"
        )
        print(f"Ethernet destination: {BROADCAST_MAC}")

        target = self.hosts.get(target_ip)
        if target is None:
            print("No host answers the request.")
            return None

        reply = ARPPacket(
            operation=ArpOperation.REPLY,
            sender_mac=target.mac_address,
            sender_ip=target.ip_address,
            target_mac=requester.mac_address,
            target_ip=requester.ip_address,
        )

        self.caches[requester.ip_address].add(
            target.ip_address,
            target.mac_address,
        )

        print(
            f"{target.name} replies: "
            f"{target.ip_address} is at {target.mac_address}"
        )

        return reply

    def resolve_mac(
        self,
        requester_ip: str,
        target_ip: str,
    ) -> Optional[str]:
        cache = self.caches[requester_ip]
        entry = cache.lookup(target_ip)

        if entry is not None and entry.state != CacheState.STALE:
            print(
                f"Cache hit: {target_ip} -> {entry.mac_address}"
            )
            return entry.mac_address

        print(f"Cache miss: {target_ip}")
        reply = self.send_arp_request(requester_ip, target_ip)

        if reply is None:
            return None

        return reply.sender_mac


def demonstrate_lan() -> None:
    print_section("6. Complete ARP resolution simulation")

    lan = SimulatedLAN("192.168.1.0/24")

    alice = Host(
        "Alice",
        "192.168.1.10",
        "02:00:00:00:00:10",
    )
    bob = Host(
        "Bob",
        "192.168.1.20",
        "02:00:00:00:00:20",
    )
    router = Host(
        "Router",
        "192.168.1.1",
        "02:00:00:00:00:01",
    )

    for host in [alice, bob, router]:
        lan.add_host(host)

    lan.resolve_mac(alice.ip_address, bob.ip_address)
    lan.resolve_mac(alice.ip_address, bob.ip_address)

    print("\nAlice's ARP cache:")
    lan.caches[alice.ip_address].display()

    print("\nAlice resolves the gateway:")
    lan.resolve_mac(alice.ip_address, router.ip_address)


# ---------------------------------------------------------------------------
# 7. Gratuitous ARP
# ---------------------------------------------------------------------------

def create_gratuitous_arp(host: Host) -> ARPPacket:
    """
    A simplified gratuitous ARP representation.

    A host announces its own IP-to-MAC association without first asking
    another host to resolve it.
    """
    return ARPPacket(
        operation=ArpOperation.REQUEST,
        sender_mac=host.mac_address,
        sender_ip=host.ip_address,
        target_mac=ZERO_MAC,
        target_ip=host.ip_address,
    )


def demonstrate_gratuitous_arp() -> None:
    print_section("7. Gratuitous ARP")

    host = Host(
        "Server",
        "192.168.1.50",
        "02:00:00:00:00:50",
    )

    packet = create_gratuitous_arp(host)

    print(packet.describe())
    print(
        """
Common legitimate purposes include:

- Detecting duplicate IPv4 addresses.
- Announcing a changed MAC address after failover.
- Updating neighboring hosts after network changes.
- Supporting certain high-availability designs.

Because unsolicited ARP information can also affect caches, network
defenders should understand and monitor unusual gratuitous ARP activity.
"""
    )


# ---------------------------------------------------------------------------
# 8. ARP poisoning concept
# ---------------------------------------------------------------------------

@dataclass
class ARPObservation:
    timestamp: float
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str
    operation: ArpOperation


class ARPSecurityMonitor:
    """
    Passive educational detector.

    It does not send packets or modify real ARP caches. It watches simulated
    observations and identifies an IP address being associated with multiple
    MAC addresses.
    """

    def __init__(self) -> None:
        self.ip_to_macs: Dict[str, set[str]] = {}

    def observe(self, packet: ARPPacket) -> Optional[str]:
        macs = self.ip_to_macs.setdefault(packet.sender_ip, set())
        previous_count = len(macs)
        macs.add(packet.sender_mac)

        if len(macs) > previous_count and len(macs) > 1:
            values = ", ".join(sorted(macs))
            return (
                f"Possible ARP anomaly: {packet.sender_ip} "
                f"has been observed with multiple MAC addresses: {values}"
            )

        return None


def demonstrate_poisoning_detection() -> None:
    print_section("8. ARP poisoning concepts and passive detection")

    print(
        """
ARP was designed before modern LAN threat models were fully developed.
Classic ARP has no cryptographic authentication mechanism that proves
that a received mapping came from the legitimate owner of an IPv4 address.

ARP poisoning, also called ARP spoofing, refers to malicious manipulation
of ARP mappings so that a victim associates an IP address with an
attacker-controlled MAC address.

A common conceptual pattern is:

    Legitimate:
        192.168.1.1 -> aa:aa:aa:aa:aa:01

    Suspicious conflicting observation:
        192.168.1.1 -> bb:bb:bb:bb:bb:02

Consequences can include traffic interception, traffic disruption,
incorrect gateway resolution, or denial of service.

This program does NOT perform poisoning. It demonstrates a passive
detection technique based on conflicting IP-to-MAC observations.
"""
    )

    monitor = ARPSecurityMonitor()

    normal = ARPPacket(
        ArpOperation.REPLY,
        "02:00:00:00:00:01",
        "192.168.1.1",
        "02:00:00:00:00:10",
        "192.168.1.10",
    )

    suspicious = ARPPacket(
        ArpOperation.REPLY,
        "02:00:00:00:00:99",
        "192.168.1.1",
        "02:00:00:00:00:10",
        "192.168.1.10",
    )

    for packet in [normal, suspicious]:
        alert = monitor.observe(packet)
        print(packet.describe())
        if alert:
            print("ALERT:", alert)


# ---------------------------------------------------------------------------
# 9. Detection heuristics
# ---------------------------------------------------------------------------

def detect_ip_mac_conflicts(
    observations: List[ARPPacket],
) -> Dict[str, List[str]]:
    """
    Return IPv4 addresses observed with more than one MAC address.

    This is a heuristic, not proof of an attack. Legitimate causes include
    failover systems, virtualization, proxy ARP, load balancing, or network
    reconfiguration.
    """
    mappings: Dict[str, set[str]] = {}

    for packet in observations:
        mappings.setdefault(packet.sender_ip, set()).add(packet.sender_mac)

    return {
        ip_address: sorted(mac_addresses)
        for ip_address, mac_addresses in mappings.items()
        if len(mac_addresses) > 1
    }


def demonstrate_detection_heuristics() -> None:
    print_section("9. ARP anomaly detection")

    observations = [
        ARPPacket(
            ArpOperation.REPLY,
            "02:00:00:00:00:01",
            "192.168.1.1",
            "02:00:00:00:00:10",
            "192.168.1.10",
        ),
        ARPPacket(
            ArpOperation.REPLY,
            "02:00:00:00:00:20",
            "192.168.1.20",
            "02:00:00:00:00:10",
            "192.168.1.10",
        ),
        ARPPacket(
            ArpOperation.REPLY,
            "02:00:00:00:00:99",
            "192.168.1.1",
            "02:00:00:00:00:10",
            "192.168.1.10",
        ),
    ]

    conflicts = detect_ip_mac_conflicts(observations)

    if conflicts:
        for ip_address, mac_addresses in conflicts.items():
            print(
                f"{ip_address} -> "
                f"{', '.join(mac_addresses)}"
            )
    else:
        print("No conflicts detected.")

    print(
        """
Detection should combine multiple signals rather than treating every
mapping change as malicious.

Useful signals include:

- One IP suddenly associated with multiple MAC addresses.
- Repeated unsolicited ARP replies.
- A gateway IP changing MAC unexpectedly.
- High ARP packet volume.
- Unexpected gratuitous ARP announcements.
- Changes inconsistent with known DHCP or network-management events.
"""
    )


# ---------------------------------------------------------------------------
# 10. Wireshark interpretation
# ---------------------------------------------------------------------------

def wireshark_reference() -> None:
    print_section("10. Wireshark analysis")

    print(
        """
Wireshark can decode Ethernet and ARP frames and expose their individual
fields.

Useful display filters include:

    arp
        Show ARP traffic.

    arp.opcode == 1
        Show ARP requests.

    arp.opcode == 2
        Show ARP replies.

    arp.src.proto_ipv4 == 192.168.1.1
        Show ARP packets whose sender IPv4 address is 192.168.1.1.

    arp.dst.proto_ipv4 == 192.168.1.20
        Show packets whose target IPv4 address is 192.168.1.20.

    arp.src.hw_mac == 02:00:00:00:00:01
        Show packets from a particular sender MAC.

    eth.dst == ff:ff:ff:ff:ff:ff && arp
        Focus on Ethernet-broadcast ARP traffic.

Typical request:

    Ethernet II
        Destination: ff:ff:ff:ff:ff:ff
        Source: victim MAC
    Address Resolution Protocol
        Opcode: request
        Sender MAC: victim MAC
        Sender IP: victim IP
        Target MAC: 00:00:00:00:00:00
        Target IP: destination IP

Typical reply:

    Ethernet II
        Destination: victim MAC
        Source: destination MAC
    Address Resolution Protocol
        Opcode: reply
        Sender MAC: destination MAC
        Sender IP: destination IP
        Target MAC: victim MAC
        Target IP: victim IP

When investigating an anomaly, compare:

    sender IPv4 address
        against
    sender MAC address

across multiple frames and over time.

Important limitation:
A packet capture from one host or one network segment provides only a
partial view. A missing ARP packet does not prove that an ARP event never
occurred elsewhere.
"""
    )


# ---------------------------------------------------------------------------
# 11. Common mistakes
# ---------------------------------------------------------------------------

def common_mistakes() -> None:
    print_section("11. Common mistakes")

    mistakes = {
        "Mistake 1": (
            "Assuming ARP resolves every remote Internet destination. "
            "The local host normally resolves the next-hop gateway MAC."
        ),
        "Mistake 2": (
            "Confusing an IP address with a MAC address. "
            "IP is a Layer 3 addressing mechanism; MAC is used by Ethernet "
            "at Layer 2."
        ),
        "Mistake 3": (
            "Assuming every ARP reply is automatically malicious. "
            "Legitimate systems can update mappings during normal operation."
        ),
        "Mistake 4": (
            "Assuming an ARP cache never changes. "
            "Entries can expire, become stale, be replaced, or be statically "
            "configured."
        ),
        "Mistake 5": (
            "Using packet captures without understanding direction. "
            "Sender and target fields must be interpreted in the context "
            "of the ARP operation."
        ),
        "Mistake 6": (
            "Treating an IP/MAC conflict as proof of poisoning. "
            "Virtualization, high availability, proxy ARP, and network "
            "changes can create legitimate conflicts."
        ),
    }

    for name, description in mistakes.items():
        print(f"{name}: {description}")


# ---------------------------------------------------------------------------
# 12. Performance considerations
# ---------------------------------------------------------------------------

def performance_model() -> None:
    print_section("12. Performance considerations")

    print(
        """
ARP has a useful caching property:

Without a cache:
    application needs destination
        -> ARP request
        -> ARP reply
        -> Ethernet transmission

With a valid cache entry:
    application needs destination
        -> cache lookup
        -> Ethernet transmission

A cache reduces broadcast traffic and resolution latency.

A simplified lookup in this program uses a Python dictionary, giving
average O(1) lookup by IPv4 address.

For n observed packets, the conflict detector performs approximately:

    Time:  O(n)
    Space: O(k)

where k is the number of distinct IP-to-MAC associations retained.

Real operating systems use substantially more sophisticated cache state,
timers, neighbor-state logic, synchronization, and kernel networking
integration.
"""
    )


# ---------------------------------------------------------------------------
# 13. Defensive design
# ---------------------------------------------------------------------------

def defensive_controls() -> None:
    print_section("13. Defensive controls")

    print(
        """
Defensive measures can include:

1. Static ARP entries
   Useful for small, controlled environments, but difficult to maintain
   at large scale.

2. Dynamic ARP Inspection
   Network switches can validate ARP information against trusted sources
   such as DHCP snooping databases, depending on platform capabilities.

3. DHCP snooping
   Helps a switch build bindings between ports, IP addresses, and MAC
   addresses in supported environments.

4. Segmentation
   VLANs and appropriate Layer 3 boundaries reduce the scope of broadcast
   domains and can limit the impact of local attacks.

5. Monitoring
   Alert on unexpected gateway-MAC changes, excessive ARP traffic, and
   repeated IP/MAC conflicts.

6. Secure application protocols
   TLS and other authenticated protocols reduce the usefulness of traffic
   interception even if a Layer 2 redirection attack succeeds.

7. Network access controls
   Port security, authentication, and managed switching can restrict
   which devices are allowed to appear on particular access ports.

No single control solves every ARP-related problem.
"""
    )


# ---------------------------------------------------------------------------
# 14. End-to-end demonstration
# ---------------------------------------------------------------------------

def end_to_end() -> None:
    print_section("14. End-to-end learning scenario")

    client = Host(
        "Client",
        "10.10.10.10",
        "02:10:00:00:00:10",
    )
    server = Host(
        "Server",
        "10.10.10.20",
        "02:10:00:00:00:20",
    )

    cache = ARPCache()

    print("Initial cache:")
    cache.display()

    print("\nClient needs Server's MAC.")
    entry = cache.lookup(server.ip_address)

    if entry is None:
        print("Cache miss -> broadcast ARP request.")

        request = ARPPacket(
            ArpOperation.REQUEST,
            client.mac_address,
            client.ip_address,
            ZERO_MAC,
            server.ip_address,
        )

        print("Request:", request.describe())

        reply = ARPPacket(
            ArpOperation.REPLY,
            server.mac_address,
            server.ip_address,
            client.mac_address,
            client.ip_address,
        )

        print("Reply:", reply.describe())

        cache.add(
            server.ip_address,
            server.mac_address,
            CacheState.REACHABLE,
        )

    print("\nUpdated cache:")
    cache.display()

    print(
        "\nThe next transmission can use the cached MAC without "
        "performing another resolution immediately."
    )


# ---------------------------------------------------------------------------
# 15. Mini assessment
# ---------------------------------------------------------------------------

def assessment() -> None:
    print_section("15. Knowledge check")

    questions = [
        (
            "What address does ARP primarily map?",
            "IPv4 addresses to MAC addresses on a local Ethernet network."
        ),
        (
            "Why is an ARP request broadcast?",
            "The sender does not yet know the target MAC address."
        ),
        (
            "Why is an ARP reply normally unicast?",
            "The responder can address the requester after learning its MAC."
        ),
        (
            "What does an ARP cache accomplish?",
            "It avoids repeated resolution when a valid mapping is available."
        ),
        (
            "What is the basic security weakness of traditional ARP?",
            "ARP does not inherently authenticate the claimed IP-to-MAC mapping."
        ),
        (
            "Does an IP/MAC conflict automatically prove poisoning?",
            "No. Legitimate network changes and special architectures can cause conflicts."
        ),
    ]

    for question, answer in questions:
        print(f"\nQ: {question}")
        print(f"A: {answer}")


# ---------------------------------------------------------------------------
# 16. Main program
# ---------------------------------------------------------------------------

def main() -> None:
    print("ARP STUDY PROGRAM")
    print("Safe simulation of IPv4-to-MAC address resolution")

    explain_basics()
    demonstrate_validation()
    demonstrate_arp_packets()
    demonstrate_arp_cache()
    demonstrate_subnet_logic()
    demonstrate_lan()
    demonstrate_gratuitous_arp()
    demonstrate_poisoning_detection()
    demonstrate_detection_heuristics()
    wireshark_reference()
    common_mistakes()
    performance_model()
    defensive_controls()
    end_to_end()
    assessment()

    print_section("Program complete")
    print(
        "All network behavior demonstrated by this program is simulated "
        "in memory; no real ARP frames are transmitted."
    )


if __name__ == "__main__":
    main()
