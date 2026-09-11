"""
Ethernet: MAC Addresses, Frames, NICs, Switching, Broadcast Domains,
and Collision Domains

A self-contained study and simulation program that teaches Ethernet from
absolute beginner level through advanced concepts.

The examples use only Python's standard library.

Run:
    python ethernet_learning.py

The script demonstrates:
    1. Ethernet fundamentals
    2. MAC addresses
    3. Ethernet frame structure
    4. NIC behavior
    5. Unicast, broadcast, and multicast delivery
    6. Ethernet switches and MAC address learning
    7. Forwarding, filtering, and flooding
    8. Broadcast domains
    9. Collision domains
    10. Half-duplex Ethernet and CSMA/CD
    11. Full-duplex Ethernet
    12. Hubs versus switches
    13. Switch loops and broadcast storms
    14. VLANs and broadcast-domain separation
    15. CAM/MAC address tables
    16. Frame validation and error cases
    17. Unknown unicast behavior
    18. Security considerations
    19. Performance considerations
    20. Practical network design
    21. Automated assertions and demonstrations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import random
import re
import time
from typing import Dict, List, Optional, Set, Tuple


# =============================================================================
# 1. INTRODUCTION
# =============================================================================

def section(title: str) -> None:
    """Print a visually distinct learning section."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain(text: str) -> None:
    """Print an explanatory paragraph."""
    print(text)


def subsection(title: str) -> None:
    print(f"\n--- {title} ---")


# =============================================================================
# 2. MAC ADDRESSES
# =============================================================================

class MACAddress:
    """
    Represents a 48-bit Ethernet MAC address.

    Ethernet commonly represents a MAC address as six hexadecimal octets:

        00:1A:2B:3C:4D:5E

    Important address categories:

    Unicast:
        The least significant bit of the first octet is 0.

    Multicast:
        The least significant bit of the first octet is 1.

    Broadcast:
        FF:FF:FF:FF:FF:FF

    The first three octets are commonly called the OUI portion.
    The remaining three identify an interface within that allocation.

    Modern networking can also use locally administered MAC addresses,
    so the first three octets should not automatically be interpreted as
    a permanent manufacturer identity.
    """

    BROADCAST = "ff:ff:ff:ff:ff:ff"

    def __init__(self, value: str):
        normalized = value.strip().lower().replace("-", ":")
        parts = normalized.split(":")

        if len(parts) != 6:
            raise ValueError(
                "A MAC address must contain exactly six hexadecimal octets."
            )

        if any(
            len(part) != 2 or not re.fullmatch(r"[0-9a-f]{2}", part)
            for part in parts
        ):
            raise ValueError(
                "Each MAC address octet must contain exactly two hexadecimal digits."
            )

        self.value = ":".join(parts)

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"MACAddress('{self.value}')"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, MACAddress):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == MACAddress(other).value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    @property
    def bytes(self) -> bytes:
        return bytes(int(part, 16) for part in self.value.split(":"))

    @property
    def first_octet(self) -> int:
        return self.bytes[0]

    @property
    def is_broadcast(self) -> bool:
        return self.value == self.BROADCAST

    @property
    def is_multicast(self) -> bool:
        return (self.first_octet & 0x01) == 1

    @property
    def is_unicast(self) -> bool:
        return not self.is_multicast

    @property
    def is_locally_administered(self) -> bool:
        return (self.first_octet & 0x02) != 0

    @property
    def oui(self) -> str:
        return ":".join(self.value.split(":")[:3])

    @classmethod
    def broadcast(cls) -> "MACAddress":
        return cls(cls.BROADCAST)

    @classmethod
    def random(cls, local: bool = True) -> "MACAddress":
        """
        Generate a random MAC address.

        If local=True, the locally administered bit is set.
        The multicast bit is cleared, making the result a unicast address.
        """
        data = [random.randint(0, 255) for _ in range(6)]
        data[0] &= 0xFC

        if local:
            data[0] |= 0x02

        return cls(":".join(f"{value:02x}" for value in data))


# =============================================================================
# 3. ETHERNET FRAME
# =============================================================================

@dataclass
class EthernetFrame:
    """
    Simplified Ethernet II frame.

    Conceptual Ethernet II fields:

        Destination MAC
        Source MAC
        EtherType
        Payload
        Frame Check Sequence (FCS)

    A real Ethernet frame also involves physical-layer details such as
    preamble and Start Frame Delimiter. The simulation focuses on the
    fields most useful for understanding switching and Layer 2 behavior.
    """

    destination: MACAddress
    source: MACAddress
    ether_type: int
    payload: bytes
    fcs_valid: bool = True
    vlan_id: Optional[int] = None

    MIN_PAYLOAD_SIZE = 46
    MAX_PAYLOAD_SIZE = 1500

    def __post_init__(self) -> None:
        if not 0 <= self.ether_type <= 0xFFFF:
            raise ValueError("EtherType must fit into 16 bits.")

        if len(self.payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(
                "Payload exceeds the traditional Ethernet MTU payload size "
                "of 1500 bytes."
            )

        if self.vlan_id is not None and not 1 <= self.vlan_id <= 4094:
            raise ValueError("An 802.1Q VLAN ID must normally be 1 through 4094.")

    @property
    def payload_size(self) -> int:
        return len(self.payload)

    @property
    def padded_payload_size(self) -> int:
        return max(len(self.payload), self.MIN_PAYLOAD_SIZE)

    @property
    def is_broadcast(self) -> bool:
        return self.destination.is_broadcast

    @property
    def is_multicast(self) -> bool:
        return self.destination.is_multicast and not self.destination.is_broadcast

    @property
    def is_unicast(self) -> bool:
        return self.destination.is_unicast

    @property
    def frame_size_without_preamble(self) -> int:
        """
        Approximate frame size from destination through FCS.

        The minimum Ethernet frame size is traditionally 64 bytes,
        including the 4-byte FCS, but excluding the 8-byte preamble/SFD.
        """
        header_size = 14

        if self.vlan_id is not None:
            header_size += 4

        return header_size + self.padded_payload_size + 4

    def validate(self) -> Tuple[bool, str]:
        if not self.fcs_valid:
            return False, "FCS validation failed."

        if self.frame_size_without_preamble < 64:
            return False, "Frame is shorter than the Ethernet minimum."

        if self.frame_size_without_preamble > 1522:
            return False, "Frame exceeds the traditional tagged-frame limit."

        return True, "Frame is valid."

    def summary(self) -> str:
        destination_type = (
            "broadcast"
            if self.is_broadcast
            else "multicast"
            if self.is_multicast
            else "unicast"
        )

        vlan_text = f", VLAN={self.vlan_id}" if self.vlan_id is not None else ""

        return (
            f"{destination_type} frame | "
            f"src={self.source} | dst={self.destination} | "
            f"EtherType=0x{self.ether_type:04x} | "
            f"payload={self.payload_size} bytes | "
            f"wire-size≈{self.frame_size_without_preamble} bytes"
            f"{vlan_text}"
        )


# Common EtherTypes used in Ethernet networks.
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100


def make_frame(
    source: MACAddress,
    destination: MACAddress,
    message: str,
    ether_type: int = ETHERTYPE_IPV4,
    vlan_id: Optional[int] = None,
) -> EthernetFrame:
    """Convenience function for creating an Ethernet frame."""
    return EthernetFrame(
        destination=destination,
        source=source,
        ether_type=ether_type,
        payload=message.encode("utf-8"),
        vlan_id=vlan_id,
    )


# =============================================================================
# 4. NETWORK INTERFACE CARDS
# =============================================================================

@dataclass
class NIC:
    """
    Simplified Network Interface Card.

    A NIC connects a host to an Ethernet link.

    Responsibilities include:
        - possessing a MAC address
        - transmitting Ethernet frames
        - receiving frames
        - checking whether a frame is addressed to the interface
        - reporting received frames

    A real NIC performs substantially more hardware-level work.
    """

    name: str
    mac: MACAddress
    promiscuous_mode: bool = False
    received_frames: List[EthernetFrame] = field(default_factory=list)
    transmitted_frames: List[EthernetFrame] = field(default_factory=list)

    def transmit(
        self,
        destination: MACAddress,
        message: str,
        ether_type: int = ETHERTYPE_IPV4,
        vlan_id: Optional[int] = None,
    ) -> EthernetFrame:
        frame = make_frame(
            source=self.mac,
            destination=destination,
            message=message,
            ether_type=ether_type,
            vlan_id=vlan_id,
        )

        self.transmitted_frames.append(frame)
        return frame

    def should_accept(self, frame: EthernetFrame) -> bool:
        """
        Normal NIC behavior accepts:
            - frames addressed to its own MAC
            - broadcasts
            - multicast frames that the host has joined

        This simplified model treats all multicast frames as acceptable.

        Promiscuous mode accepts frames regardless of destination.
        """
        if self.promiscuous_mode:
            return True

        return (
            frame.destination == self.mac
            or frame.destination.is_broadcast
            or frame.destination.is_multicast
        )

    def receive(self, frame: EthernetFrame) -> bool:
        valid, _ = frame.validate()

        if not valid:
            return False

        if self.should_accept(frame):
            self.received_frames.append(frame)
            return True

        return False


# =============================================================================
# 5. BASIC ETHERNET DELIVERY TYPES
# =============================================================================

class DeliveryType(Enum):
    UNICAST = "Unicast"
    BROADCAST = "Broadcast"
    MULTICAST = "Multicast"


def classify_destination(mac: MACAddress) -> DeliveryType:
    if mac.is_broadcast:
        return DeliveryType.BROADCAST

    if mac.is_multicast:
        return DeliveryType.MULTICAST

    return DeliveryType.UNICAST


# =============================================================================
# 6. ETHERNET SWITCH
# =============================================================================

class PortState(Enum):
    UP = "up"
    DOWN = "down"


@dataclass
class SwitchPort:
    port_id: str
    nic: Optional[NIC] = None
    state: PortState = PortState.UP
    vlan_id: int = 1

    @property
    def connected_mac(self) -> Optional[MACAddress]:
        return self.nic.mac if self.nic else None


class EthernetSwitch:
    """
    Simplified Layer 2 Ethernet switch.

    Core switch behavior:

    1. Learn the source MAC address.
    2. Examine the destination MAC address.
    3. If destination is known on another port, forward there.
    4. If destination is unknown, flood it within the VLAN.
    5. If destination is broadcast, flood it within the VLAN.
    6. If destination is on the same ingress port, filter the frame.

    This is the fundamental mechanism behind switched Ethernet.
    """

    def __init__(self, name: str, port_count: int = 8):
        self.name = name
        self.ports: Dict[str, SwitchPort] = {
            f"p{i}": SwitchPort(port_id=f"p{i}")
            for i in range(1, port_count + 1)
        }

        # A simplified CAM/MAC address table:
        # (VLAN, MAC) -> ingress port
        self.mac_table: Dict[Tuple[int, MACAddress], str] = {}

        self.forwarded_frames = 0
        self.flooded_frames = 0
        self.dropped_frames = 0

    def connect(self, port_id: str, nic: NIC, vlan_id: int = 1) -> None:
        if port_id not in self.ports:
            raise KeyError(f"Unknown switch port: {port_id}")

        port = self.ports[port_id]

        if port.nic is not None:
            raise ValueError(f"{port_id} is already occupied.")

        port.nic = nic
        port.vlan_id = vlan_id

    def disconnect(self, port_id: str) -> None:
        if port_id not in self.ports:
            raise KeyError(f"Unknown switch port: {port_id}")

        self.ports[port_id].nic = None

    def learn(self, source: MACAddress, ingress_port: str, vlan_id: int) -> None:
        """
        Learn where a source MAC was seen.

        MAC learning is dynamic. If a device moves to another port,
        the switch can update its table when it sees the source again.
        """
        self.mac_table[(vlan_id, source)] = ingress_port

    def lookup(self, destination: MACAddress, vlan_id: int) -> Optional[str]:
        return self.mac_table.get((vlan_id, destination))

    def eligible_ports(
        self,
        ingress_port: str,
        vlan_id: int,
    ) -> List[SwitchPort]:
        return [
            port
            for port_id, port in self.ports.items()
            if (
                port_id != ingress_port
                and port.state == PortState.UP
                and port.nic is not None
                and port.vlan_id == vlan_id
            )
        ]

    def receive(self, ingress_port: str, frame: EthernetFrame) -> List[str]:
        """
        Process an incoming Ethernet frame and return destination port IDs.

        The switch learns from the source MAC before making the forwarding
        decision.
        """
        if ingress_port not in self.ports:
            raise KeyError(f"Unknown ingress port: {ingress_port}")

        ingress = self.ports[ingress_port]

        if ingress.state != PortState.UP:
            self.dropped_frames += 1
            return []

        vlan_id = frame.vlan_id or ingress.vlan_id

        if vlan_id != ingress.vlan_id:
            self.dropped_frames += 1
            return []

        valid, _ = frame.validate()

        if not valid:
            self.dropped_frames += 1
            return []

        # Step 1: source MAC learning.
        self.learn(frame.source, ingress_port, vlan_id)

        destination_port = self.lookup(frame.destination, vlan_id)

        # Broadcast and multicast frames are flooded within the VLAN.
        if frame.is_broadcast or frame.is_multicast:
            output_ports = [
                port.port_id
                for port in self.eligible_ports(ingress_port, vlan_id)
            ]
            self.flooded_frames += 1
            return output_ports

        # Unknown unicast is flooded.
        if destination_port is None:
            output_ports = [
                port.port_id
                for port in self.eligible_ports(ingress_port, vlan_id)
            ]
            self.flooded_frames += 1
            return output_ports

        # Destination is known on the ingress port.
        # There is no reason to send the frame back to the same port.
        if destination_port == ingress_port:
            return []

        destination = self.ports[destination_port]

        if destination.state != PortState.UP or destination.nic is None:
            self.dropped_frames += 1
            return []

        if destination.vlan_id != vlan_id:
            self.dropped_frames += 1
            return []

        self.forwarded_frames += 1
        return [destination_port]

    def transmit_from_port(
        self,
        ingress_port: str,
        frame: EthernetFrame,
    ) -> List[str]:
        """
        Process and physically deliver a frame to destination NICs.
        """
        output_ports = self.receive(ingress_port, frame)

        for port_id in output_ports:
            port = self.ports[port_id]

            if port.nic is not None:
                port.nic.receive(frame)

        return output_ports

    def show_mac_table(self) -> None:
        print(f"\nMAC address table for {self.name}")

        if not self.mac_table:
            print("  <empty>")
            return

        for (vlan_id, mac), port in sorted(
            self.mac_table.items(),
            key=lambda item: (item[0][0], item[0][1].value),
        ):
            print(f"  VLAN {vlan_id:<4} {mac} -> {port}")


# =============================================================================
# 7. HUB SIMULATION
# =============================================================================

class EthernetHub:
    """
    Simplified Ethernet hub.

    A hub operates at the physical layer.

    When a hub receives a signal on one port, it repeats it to all other
    active ports. It does not learn MAC addresses.

    Therefore:
        - all attached devices share one collision domain
        - every device sees the electrical/physical transmission
        - NICs decide whether they actually accept the frame
    """

    def __init__(self, name: str, port_count: int = 8):
        self.name = name
        self.ports: Dict[str, Optional[NIC]] = {
            f"p{i}": None for i in range(1, port_count + 1)
        }

    def connect(self, port_id: str, nic: NIC) -> None:
        if port_id not in self.ports:
            raise KeyError(port_id)

        if self.ports[port_id] is not None:
            raise ValueError(f"{port_id} already occupied.")

        self.ports[port_id] = nic

    def transmit(self, ingress_port: str, frame: EthernetFrame) -> List[str]:
        output_ports = [
            port_id
            for port_id, nic in self.ports.items()
            if port_id != ingress_port and nic is not None
        ]

        for port_id in output_ports:
            self.ports[port_id].receive(frame)

        return output_ports


# =============================================================================
# 8. COLLISION DOMAIN MODEL
# =============================================================================

class CollisionDomain:
    """
    Educational model of an Ethernet collision domain.

    A collision domain is a portion of an Ethernet network in which
    simultaneous transmissions can interfere with one another.

    Important distinction:

        Hub:
            All connected devices share one collision domain.

        Modern switched full-duplex Ethernet:
            Each switch port/link is effectively its own collision domain,
            and full-duplex operation eliminates ordinary Ethernet collisions.

    The class below models the older shared-medium case.
    """

    def __init__(self, participants: List[str]):
        self.participants = participants

    def transmit_simultaneously(
        self,
        senders: List[str],
    ) -> Tuple[bool, str]:
        if len(senders) <= 1:
            return False, "No collision: zero or one sender transmitted."

        sender_text = ", ".join(senders)
        return True, f"Collision detected among: {sender_text}"


# =============================================================================
# 9. CSMA/CD
# =============================================================================

class CSMACD:
    """
    Simplified CSMA/CD simulation.

    CSMA/CD means:

        Carrier Sense Multiple Access with Collision Detection.

    Historical half-duplex Ethernet behavior:

        1. Listen before transmitting.
        2. If medium is busy, wait.
        3. Transmit when medium appears idle.
        4. Detect collision while transmitting.
        5. Send a jam signal.
        6. Stop transmitting.
        7. Wait using binary exponential backoff.
        8. Retry, up to a maximum attempt count.

    Modern switched full-duplex Ethernet normally does not use CSMA/CD
    because the sender and receiver have separate transmit and receive
    paths on the link and simultaneous transmission does not create the
    same shared-medium collision condition.
    """

    def __init__(
        self,
        max_attempts: int = 16,
        slot_time: int = 1,
        seed: int = 7,
    ):
        self.max_attempts = max_attempts
        self.slot_time = slot_time
        self.random = random.Random(seed)

    def binary_exponential_backoff(self, attempt: int) -> int:
        """
        Return a simulated number of slot times to wait.

        The contention window grows approximately as 2^attempt,
        subject to implementation limits in real Ethernet systems.
        """
        exponent = min(attempt, 10)
        upper_bound = (2 ** exponent) - 1

        if upper_bound <= 0:
            return 0

        return self.random.randint(0, upper_bound) * self.slot_time

    def transmit(self, collision_attempts: Set[int]) -> List[str]:
        events: List[str] = []

        for attempt in range(1, self.max_attempts + 1):
            events.append(
                f"Attempt {attempt}: sense carrier, then transmit."
            )

            if attempt in collision_attempts:
                events.append("  Collision detected.")
                events.append("  Jam signal sent.")
                backoff = self.binary_exponential_backoff(attempt)
                events.append(
                    f"  Binary exponential backoff: {backoff} slot time(s)."
                )
                continue

            events.append("  Transmission completed successfully.")
            return events

        events.append(
            "Transmission abandoned after reaching the maximum retry limit."
        )
        return events


# =============================================================================
# 10. BROADCAST DOMAINS
# =============================================================================

class BroadcastDomain:
    """
    Represents a set of devices that receive a Layer 2 broadcast
    within a particular logical segment.

    A switch by itself does not normally break a broadcast domain.

    Example:

        PC-A ----+
        PC-B ----+---- Switch ---- PC-C

    With no VLAN/router separation, a broadcast sent by one host is
    flooded to the other hosts in that same Layer 2 domain.

    Routers and Layer 3 boundaries can separate broadcast domains.

    VLANs also logically partition a switch into separate broadcast domains.
    """

    def __init__(self, name: str):
        self.name = name
        self.members: Set[str] = set()

    def add(self, device_name: str) -> None:
        self.members.add(device_name)

    def broadcast_recipients(self, sender: str) -> Set[str]:
        return self.members - {sender}


# =============================================================================
# 11. VLAN-AWARE SWITCHING
# =============================================================================

class VLANSwitch(EthernetSwitch):
    """
    Switch model emphasizing VLAN-based broadcast-domain separation.

    A VLAN creates a separate Layer 2 broadcast domain.

    Devices in VLAN 10 should not receive ordinary Layer 2 broadcasts
    from VLAN 20 through normal access-port switching.

    Inter-VLAN communication requires Layer 3 routing.
    """

    def set_port_vlan(self, port_id: str, vlan_id: int) -> None:
        if not 1 <= vlan_id <= 4094:
            raise ValueError("VLAN IDs normally range from 1 to 4094.")

        self.ports[port_id].vlan_id = vlan_id

    def broadcast_scope(self, ingress_port: str) -> List[str]:
        vlan_id = self.ports[ingress_port].vlan_id

        return [
            port.port_id
            for port in self.ports.values()
            if (
                port.port_id != ingress_port
                and port.nic is not None
                and port.state == PortState.UP
                and port.vlan_id == vlan_id
            )
        ]


# =============================================================================
# 12. LEARNING EXAMPLE
# =============================================================================

def demonstrate_mac_address_basics() -> None:
    section("1. MAC addresses")

    mac = MACAddress("00:1A:2B:3C:4D:5E")

    print("Address:", mac)
    print("Raw bytes:", mac.bytes)
    print("OUI portion:", mac.oui)
    print("Unicast:", mac.is_unicast)
    print("Multicast:", mac.is_multicast)
    print("Locally administered:", mac.is_locally_administered)

    broadcast = MACAddress.broadcast()
    print("\nBroadcast address:", broadcast)
    print("Broadcast:", broadcast.is_broadcast)
    print("Multicast classification:", broadcast.is_multicast)

    local_random = MACAddress.random(local=True)
    print("\nExample locally administered unicast MAC:", local_random)
    print("Locally administered:", local_random.is_locally_administered)

    print("\nMAC address concepts:")
    print("  - Ethernet MAC addresses are normally 48 bits.")
    print("  - They are commonly written as six hexadecimal octets.")
    print("  - The destination MAC controls Layer 2 delivery.")
    print("  - FF:FF:FF:FF:FF:FF represents Ethernet broadcast.")
    print("  - The first-octet bits distinguish unicast/multicast and")
    print("    universally/locally administered addressing.")


def demonstrate_frame_structure() -> None:
    section("2. Ethernet frames")

    source = MACAddress("02:00:00:00:00:01")
    destination = MACAddress("02:00:00:00:00:02")

    frame = make_frame(
        source=source,
        destination=destination,
        message="Hello from Ethernet",
        ether_type=ETHERTYPE_IPV4,
    )

    print(frame.summary())
    print("Validation:", frame.validate())

    print("\nConceptual Ethernet II structure:")
    print("  Destination MAC : 6 bytes")
    print("  Source MAC      : 6 bytes")
    print("  EtherType       : 2 bytes")
    print("  Payload         : typically up to 1500 bytes")
    print("  FCS             : 4 bytes")

    print("\nImportant size concepts:")
    print("  - Ethernet has a minimum frame size.")
    print("  - Small payloads are padded to satisfy the minimum.")
    print("  - Traditional Ethernet payload MTU is commonly 1500 bytes.")
    print("  - A VLAN tag adds four bytes to the Ethernet header.")
    print("  - Jumbo frames exceed the traditional 1500-byte payload size,")
    print("    but support must exist across the relevant network path.")


def demonstrate_nic() -> None:
    section("3. NIC behavior")

    laptop = NIC(
        name="Laptop-NIC",
        mac=MACAddress("02:00:00:00:10:01"),
    )

    server = MACAddress("02:00:00:00:10:02")
    broadcast = MACAddress.broadcast()

    frame_for_laptop = laptop.transmit(
        destination=server,
        message="Traffic leaving laptop",
    )

    print("Transmitted:", frame_for_laptop.summary())

    incoming = make_frame(
        source=server,
        destination=laptop.mac,
        message="Traffic arriving at laptop",
    )

    accepted = laptop.receive(incoming)
    print("Frame accepted by laptop:", accepted)
    print("Received frame count:", len(laptop.received_frames))

    broadcast_frame = make_frame(
        source=server,
        destination=broadcast,
        message="ARP-style broadcast example",
        ether_type=ETHERTYPE_ARP,
    )

    print("Broadcast accepted:", laptop.receive(broadcast_frame))

    unrelated = make_frame(
        source=server,
        destination=MACAddress("02:00:00:00:10:99"),
        message="Not for laptop",
    )

    print("Unrelated unicast accepted:", laptop.receive(unrelated))


# =============================================================================
# 13. SWITCHING DEMONSTRATION
# =============================================================================

def demonstrate_switch_learning() -> None:
    section("4. Ethernet switching and MAC learning")

    switch = EthernetSwitch("SW1", port_count=4)

    pc_a = NIC("PC-A", MACAddress("02:00:00:00:01:0A"))
    pc_b = NIC("PC-B", MACAddress("02:00:00:00:01:0B"))
    pc_c = NIC("PC-C", MACAddress("02:00:00:00:01:0C"))

    switch.connect("p1", pc_a)
    switch.connect("p2", pc_b)
    switch.connect("p3", pc_c)

    print("Initial switch table:")
    switch.show_mac_table()

    frame = pc_a.transmit(
        destination=pc_b.mac,
        message="Hello PC-B",
    )

    print("\nPC-A sends to PC-B.")
    output = switch.transmit_from_port("p1", frame)
    print("Output ports:", output)

    print("\nAfter the first frame, the switch has learned PC-A:")
    switch.show_mac_table()

    print("\nPC-B has not yet sent traffic, so its MAC is unknown.")
    print("The destination is therefore treated as an unknown unicast")
    print("and flooded within the VLAN.")

    reply = pc_b.transmit(
        destination=pc_a.mac,
        message="Hello PC-A",
    )

    output = switch.transmit_from_port("p2", reply)

    print("\nPC-B replies to PC-A.")
    print("Output ports:", output)

    print("\nThe switch now knows both source locations:")
    switch.show_mac_table()

    second = pc_a.transmit(
        destination=pc_b.mac,
        message="Second message",
    )

    output = switch.transmit_from_port("p1", second)

    print("\nPC-A sends to the now-known PC-B.")
    print("Output ports:", output)
    print("The switch forwards only to the destination port.")

    print("\nCounters:")
    print("  Forwarded:", switch.forwarded_frames)
    print("  Flooded:", switch.flooded_frames)
    print("  Dropped:", switch.dropped_frames)


# =============================================================================
# 14. BROADCAST DEMONSTRATION
# =============================================================================

def demonstrate_broadcast() -> None:
    section("5. Broadcast behavior")

    switch = EthernetSwitch("Broadcast-SW", port_count=5)

    devices = [
        NIC("Host-A", MACAddress("02:00:00:00:02:0A")),
        NIC("Host-B", MACAddress("02:00:00:00:02:0B")),
        NIC("Host-C", MACAddress("02:00:00:00:02:0C")),
        NIC("Host-D", MACAddress("02:00:00:00:02:0D")),
    ]

    for index, device in enumerate(devices, start=1):
        switch.connect(f"p{index}", device)

    broadcast_frame = devices[0].transmit(
        destination=MACAddress.broadcast(),
        message="Who is on this Layer 2 segment?",
        ether_type=ETHERTYPE_ARP,
    )

    output = switch.transmit_from_port("p1", broadcast_frame)

    print("Broadcast output ports:", output)
    print("Host-A receives its own transmitted frame only if the")
    print("network implementation loops traffic locally; this model")
    print("delivers the switch's copies to the other ports.")

    for device in devices:
        print(
            f"{device.name}: "
            f"{len(device.received_frames)} received frame(s)"
        )

    print("\nA normal Layer 2 switch does not route a broadcast.")
    print("It floods the broadcast to eligible ports in the same VLAN.")


# =============================================================================
# 15. UNKNOWN UNICAST
# =============================================================================

def demonstrate_unknown_unicast() -> None:
    section("6. Unknown unicast flooding")

    switch = EthernetSwitch("Unknown-Unicast-SW", port_count=3)

    sender = NIC("Sender", MACAddress("02:00:00:00:03:01"))
    receiver = NIC("Receiver", MACAddress("02:00:00:00:03:02"))
    observer = NIC("Observer", MACAddress("02:00:00:00:03:03"))

    switch.connect("p1", sender)
    switch.connect("p2", receiver)
    switch.connect("p3", observer)

    unknown_destination = MACAddress("02:00:00:00:03:99")

    frame = sender.transmit(
        destination=unknown_destination,
        message="Unknown destination",
    )

    output = switch.transmit_from_port("p1", frame)

    print("Destination:", unknown_destination)
    print("Output ports:", output)
    print("Reason: destination MAC is absent from the switch table.")

    print(
        "\nNotice that the switch floods the frame, but normal NICs "
        "discard copies not addressed to them."
    )

    print("Receiver accepted:", len(receiver.received_frames))
    print("Observer accepted:", len(observer.received_frames))


# =============================================================================
# 16. PROMISCUOUS MODE
# =============================================================================

def demonstrate_promiscuous_mode() -> None:
    section("7. Promiscuous mode")

    switch = EthernetSwitch("Capture-SW", port_count=3)

    sender = NIC("Sender", MACAddress("02:00:00:00:04:01"))
    receiver = NIC("Receiver", MACAddress("02:00:00:00:04:02"))
    analyzer = NIC(
        "Analyzer",
        MACAddress("02:00:00:00:04:03"),
        promiscuous_mode=True,
    )

    switch.connect("p1", sender)
    switch.connect("p2", receiver)
    switch.connect("p3", analyzer)

    first = sender.transmit(
        destination=receiver.mac,
        message="Private unicast",
    )

    switch.transmit_from_port("p1", first)

    print("Analyzer received:", len(analyzer.received_frames))
    print(
        "Important: promiscuous mode by itself does not force a modern "
        "switch to send all unicast traffic to the analyzer."
    )

    print(
        "Traffic visibility usually requires an appropriate mechanism "
        "such as a monitoring port configuration, depending on the switch."
    )


# =============================================================================
# 17. HUB VS SWITCH
# =============================================================================

def demonstrate_hub_vs_switch() -> None:
    section("8. Hub versus switch")

    hub = EthernetHub("HUB1", port_count=3)

    switch = EthernetSwitch("SW1", port_count=3)

    hub_a = NIC("Hub-A", MACAddress("02:00:00:00:05:01"))
    hub_b = NIC("Hub-B", MACAddress("02:00:00:00:05:02"))
    hub_c = NIC("Hub-C", MACAddress("02:00:00:00:05:03"))

    switch_a = NIC("Switch-A", MACAddress("02:00:00:00:06:01"))
    switch_b = NIC("Switch-B", MACAddress("02:00:00:00:06:02"))
    switch_c = NIC("Switch-C", MACAddress("02:00:00:00:06:03"))

    hub.connect("p1", hub_a)
    hub.connect("p2", hub_b)
    hub.connect("p3", hub_c)

    switch.connect("p1", switch_a)
    switch.connect("p2", switch_b)
    switch.connect("p3", switch_c)

    hub_frame = hub_a.transmit(
        destination=hub_b.mac,
        message="Traffic through hub",
    )

    hub_outputs = hub.transmit("p1", hub_frame)

    switch_frame = switch_a.transmit(
        destination=switch_b.mac,
        message="Traffic through switch",
    )

    switch_outputs = switch.transmit_from_port("p1", switch_frame)

    print("Hub output ports:", hub_outputs)
    print("Switch output ports:", switch_outputs)

    print("\nConceptual differences:")
    print("  Hub:")
    print("    - Layer 1 device")
    print("    - Repeats signals")
    print("    - No MAC learning")
    print("    - Shared collision domain")
    print("    - Historically associated with half-duplex Ethernet")

    print("\n  Switch:")
    print("    - Primarily Layer 2 device")
    print("    - Learns source MAC addresses")
    print("    - Selectively forwards known unicast")
    print("    - Floods broadcasts and unknown unicasts")
    print("    - Modern switched links commonly operate full-duplex")


# =============================================================================
# 18. COLLISION DOMAIN
# =============================================================================

def demonstrate_collision_domains() -> None:
    section("9. Collision domains")

    hub_domain = CollisionDomain(
        ["Host-A", "Host-B", "Host-C", "Host-D"]
    )

    collision, message = hub_domain.transmit_simultaneously(
        ["Host-A", "Host-C"]
    )

    print("Hub/shared-medium model:")
    print("  Collision:", collision)
    print("  ", message)

    print("\nSwitched full-duplex model:")
    print("  Host-A -> Switch port 1 -> Switch port 2 -> Host-B")
    print("  Each point-to-point link is isolated from other access links.")
    print("  Simultaneous senders on different full-duplex links do not")
    print("  create the traditional shared-medium collision.")

    print("\nKey distinction:")
    print("  Collision domain = where transmissions can collide.")
    print("  Broadcast domain = where Layer 2 broadcasts propagate.")


# =============================================================================
# 19. CSMA/CD
# =============================================================================

def demonstrate_csma_cd() -> None:
    section("10. CSMA/CD and binary exponential backoff")

    simulator = CSMACD(max_attempts=8, seed=42)

    events = simulator.transmit(
        collision_attempts={1, 2, 4}
    )

    for event in events:
        print(event)

    print(
        "\nCSMA/CD is historically important for understanding classic "
        "shared Ethernet. It is not the normal operating mechanism of "
        "modern full-duplex switched Ethernet."
    )


# =============================================================================
# 20. FULL-DUPLEX ETHERNET
# =============================================================================

def demonstrate_full_duplex() -> None:
    section("11. Full-duplex Ethernet")

    print("Half-duplex:")
    print("  Device A <---- shared medium ----> Device B")
    print("  A and B cannot independently transmit at the same instant")
    print("  without the possibility of interference.")

    print("\nFull-duplex:")
    print("  Device A <==== dedicated link ====> Device B")
    print("  A can transmit while B transmits.")
    print("  Normal Ethernet collisions are eliminated on the link.")

    print("\nPractical implication:")
    print(
        "Modern Ethernet performance is generally improved by replacing "
        "shared-media hubs with switches and using full-duplex links."
    )


# =============================================================================
# 21. VLAN BROADCAST DOMAINS
# =============================================================================

def demonstrate_vlans() -> None:
    section("12. VLANs and broadcast domains")

    switch = VLANSwitch("VLAN-SW", port_count=4)

    vlan10_a = NIC("VLAN10-A", MACAddress("02:00:00:00:10:01"))
    vlan10_b = NIC("VLAN10-B", MACAddress("02:00:00:00:10:02"))
    vlan20_a = NIC("VLAN20-A", MACAddress("02:00:00:00:20:01"))
    vlan20_b = NIC("VLAN20-B", MACAddress("02:00:00:00:20:02"))

    switch.connect("p1", vlan10_a, vlan_id=10)
    switch.connect("p2", vlan10_b, vlan_id=10)
    switch.connect("p3", vlan20_a, vlan_id=20)
    switch.connect("p4", vlan20_b, vlan_id=20)

    print("Port assignments:")
    for port_id, port in switch.ports.items():
        if port.nic:
            print(
                f"  {port_id}: {port.nic.name}, "
                f"MAC={port.nic.mac}, VLAN={port.vlan_id}"
            )

    print("\nBroadcast from VLAN 10:")
    print("  Eligible ports:", switch.broadcast_scope("p1"))

    print("Broadcast from VLAN 20:")
    print("  Eligible ports:", switch.broadcast_scope("p3"))

    print(
        "\nThe switch still contains one physical switching platform, "
        "but VLANs create separate logical Layer 2 broadcast domains."
    )

    print(
        "Communication between VLAN 10 and VLAN 20 requires Layer 3 "
        "routing, such as a router or multilayer switch."
    )


# =============================================================================
# 22. MAC TABLE AGING
# =============================================================================

@dataclass
class MACTableEntry:
    mac: MACAddress
    port: str
    vlan_id: int
    learned_at: float


class AgingMACTable:
    """
    A MAC table with aging behavior.

    Real switches do not generally retain dynamic MAC entries forever.
    Entries age out after a configurable period when they are not refreshed.
    """

    def __init__(self, aging_seconds: float = 300.0):
        self.aging_seconds = aging_seconds
        self.entries: Dict[Tuple[int, MACAddress], MACTableEntry] = {}

    def learn(self, mac: MACAddress, port: str, vlan_id: int) -> None:
        self.entries[(vlan_id, mac)] = MACTableEntry(
            mac=mac,
            port=port,
            vlan_id=vlan_id,
            learned_at=time.monotonic(),
        )

    def age(self, now: Optional[float] = None) -> None:
        current_time = time.monotonic() if now is None else now

        expired = [
            key
            for key, entry in self.entries.items()
            if current_time - entry.learned_at >= self.aging_seconds
        ]

        for key in expired:
            del self.entries[key]

    def lookup(
        self,
        mac: MACAddress,
        vlan_id: int,
    ) -> Optional[str]:
        self.age()
        entry = self.entries.get((vlan_id, mac))
        return entry.port if entry else None


def demonstrate_mac_aging() -> None:
    section("13. MAC table aging")

    table = AgingMACTable(aging_seconds=10)

    mac = MACAddress("02:00:00:00:30:01")

    table.learn(mac, "p1", vlan_id=1)

    print("Learned:", mac, "on p1")
    print("Lookup:", table.lookup(mac, vlan_id=1))

    print(
        "Dynamic MAC entries are typically aged out so that stale "
        "information does not remain indefinitely."
    )


# =============================================================================
# 23. MAC MOVEMENT
# =============================================================================

def demonstrate_mac_movement() -> None:
    section("14. MAC movement and relearning")

    switch = EthernetSwitch("MOVE-SW", port_count=3)

    device = NIC("Moving-Device", MACAddress("02:00:00:00:40:01"))
    peer = NIC("Peer", MACAddress("02:00:00:00:40:02"))

    switch.connect("p1", device)
    switch.connect("p2", peer)

    first = device.transmit(
        destination=peer.mac,
        message="First location",
    )

    switch.transmit_from_port("p1", first)

    print("Initial MAC table:")
    switch.show_mac_table()

    # Simulate the device being moved to another switch port.
    switch.disconnect("p1")
    switch.connect("p3", device)

    second = device.transmit(
        destination=peer.mac,
        message="Device moved",
    )

    switch.transmit_from_port("p3", second)

    print("\nAfter the device sends from p3:")
    switch.show_mac_table()

    print(
        "\nThe switch updates the source MAC entry when it observes "
        "the same source MAC arriving on a different port."
    )


# =============================================================================
# 24. FRAME ERROR HANDLING
# =============================================================================

def demonstrate_frame_errors() -> None:
    section("15. Frame validation and errors")

    source = MACAddress("02:00:00:00:50:01")
    destination = MACAddress("02:00:00:00:50:02")

    valid_frame = make_frame(
        source=source,
        destination=destination,
        message="Valid frame",
    )

    print("Valid frame:", valid_frame.validate())

    corrupted = EthernetFrame(
        source=source,
        destination=destination,
        ether_type=ETHERTYPE_IPV4,
        payload=b"Corrupted",
        fcs_valid=False,
    )

    print("Corrupted frame:", corrupted.validate())

    print(
        "\nFCS is used to detect corruption. A frame failing FCS validation "
        "is not treated as a valid Layer 2 frame."
    )

    print(
        "FCS detects many transmission errors but is not a cryptographic "
        "integrity or authenticity mechanism."
    )


# =============================================================================
# 25. ETHERNET ADDRESSING EXAMPLES
# =============================================================================

def demonstrate_addressing() -> None:
    section("16. Unicast, broadcast, and multicast")

    addresses = {
        "Unicast": MACAddress("02:00:00:00:60:01"),
        "Broadcast": MACAddress("ff:ff:ff:ff:ff:ff"),
        "Multicast": MACAddress("01:00:5e:00:00:01"),
    }

    for label, mac in addresses.items():
        print(
            f"{label:<10} {mac} -> "
            f"classified as {classify_destination(mac).value}"
        )

    print(
        "\nUnicast normally targets one Layer 2 destination. "
        "Broadcast targets all eligible hosts in the Layer 2 broadcast "
        "domain. Multicast targets a logical group and is handled through "
        "multicast-aware mechanisms when available."
    )


# =============================================================================
# 26. SWITCH FORWARDING LOGIC
# =============================================================================

def forwarding_decision(
    destination: MACAddress,
    ingress_port: str,
    mac_table: Dict[MACAddress, str],
    all_ports: List[str],
) -> Tuple[str, List[str]]:
    """
    Standalone implementation of basic Layer 2 forwarding logic.

    Returns:
        (decision_type, output_ports)
    """
    if destination.is_broadcast or destination.is_multicast:
        outputs = [port for port in all_ports if port != ingress_port]
        return "flood", outputs

    known_port = mac_table.get(destination)

    if known_port is None:
        outputs = [port for port in all_ports if port != ingress_port]
        return "unknown-unicast-flood", outputs

    if known_port == ingress_port:
        return "filter", []

    return "forward", [known_port]


def demonstrate_forwarding_algorithm() -> None:
    section("17. Basic switch forwarding algorithm")

    mac_a = MACAddress("02:00:00:00:70:01")
    mac_b = MACAddress("02:00:00:00:70:02")
    mac_unknown = MACAddress("02:00:00:00:70:99")

    table = {
        mac_a: "p1",
        mac_b: "p2",
    }

    ports = ["p1", "p2", "p3", "p4"]

    decisions = [
        ("Known unicast", mac_b, "p1"),
        ("Unknown unicast", mac_unknown, "p1"),
        ("Broadcast", MACAddress.broadcast(), "p1"),
        ("Known destination on ingress", mac_a, "p1"),
    ]

    for label, destination, ingress in decisions:
        decision, outputs = forwarding_decision(
            destination,
            ingress,
            table,
            ports,
        )

        print(
            f"{label:<32} "
            f"decision={decision:<22} "
            f"outputs={outputs}"
        )


# =============================================================================
# 27. SWITCH LOOP AND BROADCAST STORM
# =============================================================================

class BroadcastStormSimulator:
    """
    Educational demonstration of why redundant Layer 2 paths can be
    dangerous without loop-prevention mechanisms.

    Ethernet broadcast frames do not contain a normal Layer 2 TTL field.
    A physical Layer 2 loop can therefore allow broadcasts and unknown
    unicasts to circulate repeatedly.

    Real switched networks use loop-prevention mechanisms such as
    Spanning Tree Protocol variants.
    """

    def __init__(self):
        self.forwarded_copies = 0

    def simulate(self, number_of_switches: int, iterations: int) -> int:
        """
        Simple growth model, not a physical switch implementation.

        Each iteration represents another opportunity for a broadcast
        to replicate around a loop.
        """
        copies = 1

        for _ in range(iterations):
            copies *= max(number_of_switches, 2)

        self.forwarded_copies = copies
        return copies


def demonstrate_layer2_loop() -> None:
    section("18. Layer 2 loops and broadcast storms")

    simulator = BroadcastStormSimulator()

    copies = simulator.simulate(
        number_of_switches=3,
        iterations=4,
    )

    print("Illustrative broadcast copies after repeated replication:", copies)

    print("\nWhy this matters:")
    print("  - Broadcasts can be flooded.")
    print("  - Unknown unicasts can also be flooded.")
    print("  - Ethernet has no ordinary Layer 2 TTL to stop a looping frame.")
    print("  - Redundant switch links can therefore create severe loops.")

    print(
        "\nLoop-prevention protocols such as Spanning Tree Protocol "
        "build a loop-free logical topology while preserving selected "
        "redundant links for failover."
    )


# =============================================================================
# 28. COLLISION DOMAIN COUNTING
# =============================================================================

def count_collision_domains(
    number_of_hosts: int,
    using_hub: bool,
) -> int:
    """
    Simplified educational rule:

        Hub/shared medium:
            one collision domain.

        Switched Ethernet:
            approximately one collision domain per active point-to-point
            switch link.
    """
    if number_of_hosts <= 0:
        return 0

    if using_hub:
        return 1

    return number_of_hosts


def demonstrate_domain_counting() -> None:
    section("19. Collision-domain comparison")

    hosts = 6

    print("Six hosts connected through one hub:")
    print("  Collision domains:", count_collision_domains(hosts, True))

    print("Six hosts connected to individual switch ports:")
    print("  Collision domains:", count_collision_domains(hosts, False))

    print(
        "\nThis is a conceptual count. Actual topology, link aggregation, "
        "virtualization, and intermediate devices can change how a real "
        "network should be analyzed."
    )


# =============================================================================
# 29. BROADCAST DOMAIN EXAMPLE
# =============================================================================

def demonstrate_broadcast_domain_counting() -> None:
    section("20. Broadcast-domain comparison")

    no_vlan = BroadcastDomain("Single LAN")

    for device in ["PC1", "PC2", "PC3", "PC4"]:
        no_vlan.add(device)

    print("Single Layer 2 LAN:")
    print("  Members:", sorted(no_vlan.members))
    print("  Broadcast recipients from PC1:",
          sorted(no_vlan.broadcast_recipients("PC1")))

    vlan10 = BroadcastDomain("VLAN 10")
    vlan20 = BroadcastDomain("VLAN 20")

    for device in ["PC1", "PC2"]:
        vlan10.add(device)

    for device in ["PC3", "PC4"]:
        vlan20.add(device)

    print("\nAfter logical VLAN separation:")
    print("  VLAN 10 members:", sorted(vlan10.members))
    print("  VLAN 20 members:", sorted(vlan20.members))
    print(
        "  VLAN 10 broadcast from PC1:",
        sorted(vlan10.broadcast_recipients("PC1")),
    )
    print(
        "  VLAN 20 broadcast from PC3:",
        sorted(vlan20.broadcast_recipients("PC3")),
    )


# =============================================================================
# 30. ETHERNET FRAME ENCAPSULATION
# =============================================================================

def demonstrate_encapsulation() -> None:
    section("21. Encapsulation")

    print("Application data")
    print("      ↓")
    print("Transport segment/datagram")
    print("      ↓")
    print("IP packet")
    print("      ↓")
    print("Ethernet frame")
    print("      ↓")
    print("Physical transmission")

    print(
        "\nEthernet provides Layer 2 framing and local-link delivery. "
        "IP operates at Layer 3 and supplies logical addressing and routing."
    )

    print(
        "\nA common host-to-host path may therefore look like:"
    )
    print(
        "Host A NIC -> Ethernet switch -> router -> Ethernet switch "
        "-> Host B NIC"
    )

    print(
        "\nAt each routed hop, the Layer 2 Ethernet header normally changes "
        "for the next link, while the Layer 3 packet is forwarded toward "
        "its destination."
    )


# =============================================================================
# 31. SAME-SUBNET VS ROUTED TRAFFIC
# =============================================================================

def demonstrate_same_lan_vs_routed() -> None:
    section("22. Same-LAN traffic versus routed traffic")

    print("Same Layer 2 segment:")
    print("  Host A knows Host B's MAC address.")
    print("  Host A sends an Ethernet frame directly toward Host B.")
    print("  A switch uses the destination MAC to select the output port.")

    print("\nDifferent IP subnet:")
    print("  Host A sends the Ethernet frame toward its default gateway.")
    print("  The router receives the frame.")
    print("  The router makes a Layer 3 forwarding decision.")
    print("  A new Layer 2 frame is constructed on the outgoing interface.")

    print(
        "\nThis distinction is fundamental: MAC addresses are primarily "
        "used for local Layer 2 delivery, while IP addresses support "
        "Layer 3 logical communication across networks."
    )


# =============================================================================
# 32. ARP RELATIONSHIP
# =============================================================================

def demonstrate_arp_relationship() -> None:
    section("23. ARP and Ethernet")

    print("Suppose an IPv4 host knows:")
    print("  Destination IP: 192.168.1.20")
    print("but does not know the corresponding MAC address.")

    print("\nA simplified ARP process:")
    print("  1. Host sends an ARP request as an Ethernet broadcast.")
    print("  2. Hosts in the broadcast domain receive the request.")
    print("  3. The owner of 192.168.1.20 responds.")
    print("  4. The sender learns the destination MAC.")
    print("  5. Subsequent IPv4 traffic can use a unicast Ethernet frame.")

    print(
        "\nThis illustrates the relationship between Layer 3 addressing "
        "and Layer 2 addressing."
    )


# =============================================================================
# 33. MAC SPOOFING AND SWITCH SECURITY
# =============================================================================

def demonstrate_security() -> None:
    section("24. Ethernet security considerations")

    print("Important Layer 2 security issues:")

    issues = [
        (
            "MAC spoofing",
            "A device can claim a different source MAC address."
        ),
        (
            "MAC flooding",
            "An attacker may attempt to overwhelm a switch's MAC table."
        ),
        (
            "ARP spoofing",
            "An attacker can attempt to associate its MAC with another IP."
        ),
        (
            "Broadcast abuse",
            "Excessive broadcasts can consume bandwidth and host resources."
        ),
        (
            "Layer 2 loops",
            "Misconfiguration can create repeated frame propagation."
        ),
        (
            "Unauthorized switch access",
            "Physical or administrative access can enable significant attacks."
        ),
    ]

    for issue, explanation_text in issues:
        print(f"  {issue}: {explanation_text}")

    print("\nCommon defensive mechanisms include:")
    print("  - Port security and MAC limits")
    print("  - VLAN segmentation")
    print("  - 802.1X network access control")
    print("  - DHCP snooping")
    print("  - Dynamic ARP Inspection")
    print("  - Spanning Tree protections")
    print("  - Storm control")
    print("  - Secure management access")
    print("  - Physical security")

    print(
        "\nSecurity controls must be selected according to the network "
        "architecture and the capabilities of the specific switching platform."
    )


# =============================================================================
# 34. PERFORMANCE CONSIDERATIONS
# =============================================================================

def demonstrate_performance() -> None:
    section("25. Ethernet performance considerations")

    print("Important factors:")

    factors = {
        "Bandwidth": "How many bits per second a link can carry.",
        "Latency": "Time required for traffic to travel through the network.",
        "Frame rate": "Number of frames transmitted per unit of time.",
        "Frame size": "Affects overhead and transmission efficiency.",
        "Duplex": "Full-duplex removes ordinary shared-medium collisions.",
        "Switch buffering": "Buffers absorb temporary differences in traffic rates.",
        "Oversubscription": "Aggregate input demand can exceed an uplink's capacity.",
        "Broadcast volume": "Excessive broadcasts consume link and host resources.",
    }

    for name, description in factors.items():
        print(f"  {name:<20}: {description}")

    print(
        "\nA faster access link does not guarantee faster end-to-end "
        "communication if an uplink, server interface, router, or WAN path "
        "is the bottleneck."
    )


# =============================================================================
# 35. SWITCHING VS ROUTING
# =============================================================================

def demonstrate_switching_vs_routing() -> None:
    section("26. Switching versus routing")

    print("Ethernet switching:")
    print("  Primary address: MAC address")
    print("  Typical device: Layer 2 switch")
    print("  Main table: MAC/CAM table")
    print("  Main operation: forward/filter/flood")
    print("  Broadcast: normally stays within the Layer 2 domain/VLAN")

    print("\nIP routing:")
    print("  Primary address: IP address")
    print("  Typical device: router or Layer 3 switch")
    print("  Main table: routing table")
    print("  Main operation: choose a Layer 3 next hop")
    print("  Broadcast: generally not routed as ordinary Layer 2 broadcast")

    print(
        "\nModern multilayer switches can perform both Layer 2 switching "
        "and Layer 3 routing, but the concepts remain distinct."
    )


# =============================================================================
# 36. FRAME FLOODING MODEL
# =============================================================================

def demonstrate_flooding_rules() -> None:
    section("27. Flooding rules")

    print("A switch may flood a frame when:")

    rules = [
        "The destination is Ethernet broadcast.",
        "The destination is multicast and the switch floods that traffic.",
        "The destination is an unknown unicast.",
        "A relevant control or protocol mechanism requires flooding.",
    ]

    for number, rule in enumerate(rules, start=1):
        print(f"  {number}. {rule}")

    print("\nA switch normally does not flood a known unicast.")
    print(
        "Instead, it consults the MAC address table and forwards the "
        "frame toward the associated port."
    )


# =============================================================================
# 37. MAC TABLE SECURITY DEMONSTRATION
# =============================================================================

def demonstrate_mac_table_pressure() -> None:
    section("28. MAC-table pressure")

    table: Dict[MACAddress, str] = {}

    for index in range(1, 11):
        fake_mac = MACAddress(
            f"02:00:00:aa:{index:02x}:{(index * 7) % 256:02x}"
        )
        table[fake_mac] = "p1"

    print("Illustrative learned entries:", len(table))

    print(
        "\nA real switch has finite hardware resources for MAC entries. "
        "Security controls such as port security can limit the number or "
        "type of addresses learned on an access port."
    )


# =============================================================================
# 38. ETHERNET LINK AGGREGATION CONCEPT
# =============================================================================

def demonstrate_link_aggregation() -> None:
    section("29. Link aggregation")

    print("Link aggregation combines multiple physical links into")
    print("one logical bundle for supported traffic flows.")

    print("\nPotential benefits:")
    print("  - Increased aggregate capacity")
    print("  - Redundancy")
    print("  - Better utilization of multiple physical links")

    print("\nImportant limitation:")
    print(
        "A single traffic flow is often distributed according to a hash "
        "rather than being arbitrarily split bit-by-bit across links."
    )

    print(
        "\nLoop-prevention and aggregation protocols must work together "
        "so bundled links are treated as intended by the topology."
    )


# =============================================================================
# 39. MTU AND JUMBO FRAME CONCEPTS
# =============================================================================

def demonstrate_mtu() -> None:
    section("30. MTU and jumbo frames")

    sizes = [20, 46, 1500]

    for size in sizes:
        frame = make_frame(
            source=MACAddress("02:00:00:00:80:01"),
            destination=MACAddress("02:00:00:00:80:02"),
            message="X" * size,
        )

        print(
            f"Payload={size:4} bytes -> "
            f"wire frame size≈{frame.frame_size_without_preamble} bytes"
        )

    print(
        "\nThe traditional Ethernet payload limit is 1500 bytes. "
        "Jumbo frames can use larger payloads, but all relevant interfaces, "
        "switches, and paths must support the chosen frame size."
    )


# =============================================================================
# 40. VLAN TAGGING
# =============================================================================

def demonstrate_vlan_tagging() -> None:
    section("31. VLAN tagging")

    source = MACAddress("02:00:00:00:90:01")
    destination = MACAddress("02:00:00:00:90:02")

    tagged = make_frame(
        source=source,
        destination=destination,
        message="VLAN-tagged traffic",
        vlan_id=100,
    )

    print(tagged.summary())

    print("\n802.1Q tagging conceptually adds:")
    print("  - Tag protocol identifier")
    print("  - VLAN identifier and priority-related fields")

    print(
        "\nAccess ports normally present traffic to attached end devices "
        "as belonging to an access VLAN, while trunk links can carry "
        "multiple VLANs using tagging."
    )


# =============================================================================
# 41. BROADCAST STORM CONTROL
# =============================================================================

def demonstrate_storm_control() -> None:
    section("32. Broadcast storm control")

    print("Storm control attempts to limit excessive traffic such as:")
    print("  - Broadcast")
    print("  - Multicast")
    print("  - Unknown unicast")

    print(
        "\nThe goal is to prevent abnormal Layer 2 traffic from consuming "
        "all available bandwidth or overwhelming connected systems."
    )

    print(
        "\nStorm control is not a substitute for correcting the root cause "
        "of a Layer 2 loop or a compromised device."
    )


# =============================================================================
# 42. PRACTICAL TOPOLOGY
# =============================================================================

@dataclass
class Link:
    endpoint_a: str
    endpoint_b: str
    full_duplex: bool = True
    speed_mbps: int = 1000


def demonstrate_practical_topology() -> None:
    section("33. Practical Ethernet topology")

    topology = [
        Link("PC-A", "Access-Switch-1"),
        Link("PC-B", "Access-Switch-1"),
        Link("Server", "Access-Switch-1"),
        Link("Access-Switch-1", "Distribution-Switch"),
        Link("Distribution-Switch", "Router"),
    ]

    for link in topology:
        print(
            f"{link.endpoint_a:<22} <-> "
            f"{link.endpoint_b:<22} "
            f"{link.speed_mbps} Mbps "
            f"{'full-duplex' if link.full_duplex else 'half-duplex'}"
        )

    print(
        "\nA typical enterprise network separates access connectivity, "
        "aggregation/distribution, routing, security boundaries, and "
        "WAN or Internet connectivity."
    )


# =============================================================================
# 43. TROUBLESHOOTING
# =============================================================================

def demonstrate_troubleshooting() -> None:
    section("34. Ethernet troubleshooting logic")

    print("When a host cannot communicate, check systematically:")

    checks = [
        "Is the physical link up?",
        "Is the NIC enabled?",
        "Is the switch port enabled?",
        "Is the correct VLAN assigned?",
        "Is the MAC address being learned?",
        "Are frames being dropped because of errors?",
        "Is there a duplex or speed mismatch?",
        "Is the destination MAC known?",
        "Is ARP resolving the expected Layer 3 neighbor?",
        "Is the default gateway reachable?",
        "Is there a Layer 2 loop or broadcast storm?",
        "Is the problem actually above Layer 2?",
    ]

    for index, check in enumerate(checks, start=1):
        print(f"  {index:2}. {check}")

    print(
        "\nA packet capture can distinguish whether a problem occurs "
        "before transmission, at Ethernet framing, during switching, "
        "during routing, or at a higher protocol layer."
    )


# =============================================================================
# 44. MINI NETWORK SIMULATION
# =============================================================================

def run_mini_network() -> None:
    section("35. Complete mini Ethernet simulation")

    switch = EthernetSwitch("Core-SW", port_count=5)

    hosts = {
        "Alice": NIC("Alice", MACAddress("02:00:00:00:A0:01")),
        "Bob": NIC("Bob", MACAddress("02:00:00:00:A0:02")),
        "Carol": NIC("Carol", MACAddress("02:00:00:00:A0:03")),
        "Dave": NIC("Dave", MACAddress("02:00:00:00:A0:04")),
    }

    ports = {
        "Alice": "p1",
        "Bob": "p2",
        "Carol": "p3",
        "Dave": "p4",
    }

    for name, host in hosts.items():
        switch.connect(ports[name], host)

    print("Step 1: Alice sends to Bob.")
    frame = hosts["Alice"].transmit(
        destination=hosts["Bob"].mac,
        message="Hello Bob",
    )
    print("  Frame:", frame.summary())
    print("  Switch output:", switch.transmit_from_port("p1", frame))

    print("\nStep 2: Bob replies to Alice.")
    frame = hosts["Bob"].transmit(
        destination=hosts["Alice"].mac,
        message="Hello Alice",
    )
    print("  Frame:", frame.summary())
    print("  Switch output:", switch.transmit_from_port("p2", frame))

    print("\nStep 3: Alice sends to Bob again.")
    frame = hosts["Alice"].transmit(
        destination=hosts["Bob"].mac,
        message="Known destination now",
    )
    print("  Switch output:", switch.transmit_from_port("p1", frame))

    print("\nStep 4: Carol sends a broadcast.")
    frame = hosts["Carol"].transmit(
        destination=MACAddress.broadcast(),
        message="Broadcast message",
        ether_type=ETHERTYPE_ARP,
    )
    print("  Switch output:", switch.transmit_from_port("p3", frame))

    print("\nFinal MAC table:")
    switch.show_mac_table()

    print("\nReceived frame counts:")
    for name, host in hosts.items():
        print(f"  {name:<8}: {len(host.received_frames)}")


# =============================================================================
# 45. EDGE CASES
# =============================================================================

def demonstrate_edge_cases() -> None:
    section("36. Important edge cases")

    subsection("Invalid MAC address")

    invalid_addresses = [
        "00:11:22:33:44",
        "00:11:22:33:44:GG",
        "0011:2233:4455",
    ]

    for value in invalid_addresses:
        try:
            MACAddress(value)
            print("Unexpectedly accepted:", value)
        except ValueError as exc:
            print(f"{value!r} -> rejected: {exc}")

    subsection("Oversized Ethernet payload")

    try:
        EthernetFrame(
            destination=MACAddress("02:00:00:00:B0:01"),
            source=MACAddress("02:00:00:00:B0:02"),
            ether_type=ETHERTYPE_IPV4,
            payload=b"X" * 1501,
        )
    except ValueError as exc:
        print("Oversized payload rejected:", exc)

    subsection("Invalid VLAN")

    try:
        make_frame(
            source=MACAddress("02:00:00:00:B0:01"),
            destination=MACAddress("02:00:00:00:B0:02"),
            message="Invalid VLAN",
            vlan_id=5000,
        )
    except ValueError as exc:
        print("Invalid VLAN rejected:", exc)

    subsection("Corrupt FCS")

    frame = EthernetFrame(
        destination=MACAddress("02:00:00:00:B0:01"),
        source=MACAddress("02:00:00:00:B0:02"),
        ether_type=ETHERTYPE_IPV4,
        payload=b"data",
        fcs_valid=False,
    )

    print("Corrupt frame validation:", frame.validate())


# =============================================================================
# 46. PRACTICAL DESIGN RULES
# =============================================================================

def demonstrate_design_rules() -> None:
    section("37. Ethernet design principles")

    principles = [
        "Use switches rather than legacy shared-media hubs.",
        "Prefer full-duplex links.",
        "Keep Layer 2 broadcast domains appropriately sized.",
        "Use VLANs where logical segmentation is required.",
        "Use Layer 3 routing between separate IP/VLAN segments.",
        "Avoid accidental Layer 2 loops.",
        "Use loop-prevention mechanisms where redundant paths exist.",
        "Monitor errors, drops, utilization, and broadcast rates.",
        "Document switch ports, VLAN assignments, and uplinks.",
        "Apply Layer 2 security controls appropriate to the environment.",
        "Validate MTU compatibility before deploying nonstandard frame sizes.",
        "Use redundancy deliberately rather than simply adding links.",
    ]

    for principle in principles:
        print("  -", principle)


# =============================================================================
# 47. AUTOMATED TESTS
# =============================================================================

def run_assertions() -> None:
    section("38. Automated correctness checks")

    # MAC address tests.
    broadcast = MACAddress.broadcast()
    assert broadcast.is_broadcast
    assert broadcast.is_multicast

    unicast = MACAddress("02:00:00:00:C0:01")
    assert unicast.is_unicast
    assert not unicast.is_broadcast
    assert unicast.is_locally_administered

    # Frame tests.
    frame = make_frame(
        source=unicast,
        destination=MACAddress("02:00:00:00:C0:02"),
        message="test",
    )

    valid, message = frame.validate()
    assert valid, message
    assert frame.frame_size_without_preamble >= 64

    # Switch learning and forwarding.
    switch = EthernetSwitch("TEST-SW", port_count=2)

    host_a = NIC("A", MACAddress("02:00:00:00:C1:01"))
    host_b = NIC("B", MACAddress("02:00:00:00:C1:02"))

    switch.connect("p1", host_a)
    switch.connect("p2", host_b)

    first = host_a.transmit(
        destination=host_b.mac,
        message="first",
    )

    outputs = switch.transmit_from_port("p1", first)

    # First frame is unknown unicast, so it is flooded to p2.
    assert outputs == ["p2"]
    assert ("1", host_a.mac) not in switch.mac_table

    # The switch uses integer VLAN IDs as table keys.
    assert (1, host_a.mac) in switch.mac_table

    second = host_a.transmit(
        destination=host_b.mac,
        message="second",
    )

    outputs = switch.transmit_from_port("p1", second)
    assert outputs == ["p2"]

    # Broadcast behavior.
    broadcast = host_a.transmit(
        destination=MACAddress.broadcast(),
        message="broadcast",
        ether_type=ETHERTYPE_ARP,
    )

    outputs = switch.transmit_from_port("p1", broadcast)
    assert outputs == ["p2"]

    # Collision-domain behavior.
    domain = CollisionDomain(["A", "B"])
    collision, _ = domain.transmit_simultaneously(["A", "B"])
    assert collision

    collision, _ = domain.transmit_simultaneously(["A"])
    assert not collision

    print("All assertions passed.")


# =============================================================================
# 48. CONCEPT CHECK
# =============================================================================

def concept_check() -> None:
    section("39. Concept check")

    questions = [
        (
            "What address does an Ethernet switch primarily learn?",
            "The source MAC address."
        ),
        (
            "What happens when a switch knows the destination MAC?",
            "The frame is forwarded toward the associated port."
        ),
        (
            "What happens to an unknown unicast?",
            "It is normally flooded within the relevant Layer 2 domain/VLAN."
        ),
        (
            "What happens to an Ethernet broadcast?",
            "It is flooded within the relevant broadcast domain/VLAN."
        ),
        (
            "Does a normal Layer 2 switch break a broadcast domain?",
            "No. VLANs or Layer 3 boundaries can provide separation."
        ),
        (
            "Does a switch reduce collision domains compared with a hub?",
            "Yes. Modern switched links isolate collision domains."
        ),
        (
            "Are ordinary collisions expected on full-duplex switched Ethernet?",
            "No."
        ),
        (
            "What does a NIC primarily use to decide whether a frame is for it?",
            "The destination MAC address and relevant receive configuration."
        ),
        (
            "What detects many Ethernet transmission errors?",
            "The frame check sequence (FCS)."
        ),
        (
            "What separates VLAN broadcast domains?",
            "The VLAN boundary; communication between VLANs requires Layer 3 routing."
        ),
    ]

    for question, answer in questions:
        print(f"\nQ: {question}")
        print(f"A: {answer}")


# =============================================================================
# 49. MAIN PROGRAM
# =============================================================================

def main() -> None:
    """
    Run every educational module in a logical progression.
    """

    print("=" * 78)
    print("ETHERNET LEARNING PROGRAM")
    print("MAC addresses, frames, NICs, switching, broadcast domains,")
    print("collision domains, and advanced Layer 2 behavior")
    print("=" * 78)

    demonstrate_mac_address_basics()
    demonstrate_frame_structure()
    demonstrate_nic()
    demonstrate_switch_learning()
    demonstrate_broadcast()
    demonstrate_unknown_unicast()
    demonstrate_promiscuous_mode()
    demonstrate_hub_vs_switch()
    demonstrate_collision_domains()
    demonstrate_csma_cd()
    demonstrate_full_duplex()
    demonstrate_vlans()
    demonstrate_mac_aging()
    demonstrate_mac_movement()
    demonstrate_frame_errors()
    demonstrate_addressing()
    demonstrate_forwarding_algorithm()
    demonstrate_layer2_loop()
    demonstrate_domain_counting()
    demonstrate_broadcast_domain_counting()
    demonstrate_encapsulation()
    demonstrate_same_lan_vs_routed()
    demonstrate_arp_relationship()
    demonstrate_security()
    demonstrate_performance()
    demonstrate_switching_vs_routing()
    demonstrate_flooding_rules()
    demonstrate_mac_table_pressure()
    demonstrate_link_aggregation()
    demonstrate_mtu()
    demonstrate_vlan_tagging()
    demonstrate_storm_control()
    demonstrate_practical_topology()
    demonstrate_troubleshooting()
    run_mini_network()
    demonstrate_edge_cases()
    demonstrate_design_rules()
    run_assertions()
    concept_check()

    section("40. Program completed")

    print(
        "The simulation covered Ethernet addressing, framing, NIC behavior, "
        "switch learning, forwarding, flooding, broadcast domains, collision "
        "domains, full-duplex operation, VLAN separation, errors, security, "
        "performance, troubleshooting, and practical design."
    )


if __name__ == "__main__":
    main()
