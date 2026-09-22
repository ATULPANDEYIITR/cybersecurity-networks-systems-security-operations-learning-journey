"""
DHCP Discovery, Offers, Requests, Acknowledgments, Leases, Rogue DHCP,
and Wireshark-Oriented Packet Analysis

This standalone study program builds a DHCP model from first principles and
progressively develops it into a small network simulation.

The implementation deliberately avoids changing the machine's real network
configuration. It models DHCP packets, client state transitions, address
allocation, leases, renewal, expiration, rogue-server detection, and
Wireshark-style filtering.

Important real-world facts:
- DHCP commonly uses UDP port 67 for servers and UDP port 68 for clients.
- DHCP uses a four-message exchange commonly called DORA:
  Discover -> Offer -> Request -> Acknowledgment.
- DHCP clients can initially use limited broadcast communication because
  they may not yet have an IP address.
- DHCP servers maintain address leases.
- DHCP option 53 identifies the DHCP message type.
- Option 50 can identify a requested IP address.
- Option 54 identifies a DHCP server identifier.
- Option 51 represents lease time.
- DHCP relay agents can forward DHCP messages between clients and servers
  across routed networks.
- A rogue DHCP server can provide unauthorized configuration and redirect
  clients toward an unintended gateway or DNS server.

Run with:
    python dhcp_learning.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Address, IPv4Network
from typing import Dict, List, Optional, Tuple
import random
import time


# ---------------------------------------------------------------------------
# 1. Fundamental DHCP terminology
# ---------------------------------------------------------------------------

class DHCPMessageType(Enum):
    DISCOVER = "DHCPDISCOVER"
    OFFER = "DHCPOFFER"
    REQUEST = "DHCPREQUEST"
    ACK = "DHCPACK"
    NAK = "DHCPNAK"
    DECLINE = "DHCPDECLINE"
    RELEASE = "DHCPRELEASE"
    INFORM = "DHCPINFORM"


class ClientState(Enum):
    INIT = "INIT"
    SELECTING = "SELECTING"
    REQUESTING = "REQUESTING"
    BOUND = "BOUND"
    RENEWING = "RENEWING"
    REBINDING = "REBINDING"
    EXPIRED = "EXPIRED"


@dataclass
class DHCPPacket:
    """
    A simplified representation of a DHCP packet.

    A real DHCP packet contains BOOTP fields plus a DHCP options area.
    This model focuses on fields useful for learning DHCP behavior.
    """
    message_type: DHCPMessageType
    transaction_id: int
    client_mac: str
    source_ip: str = "0.0.0.0"
    destination_ip: str = "255.255.255.255"
    server_identifier: Optional[str] = None
    requested_ip: Optional[str] = None
    offered_ip: Optional[str] = None
    subnet_mask: Optional[str] = None
    router: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    lease_time: Optional[int] = None
    relay_agent_ip: Optional[str] = None

    def summary(self) -> str:
        return (
            f"{self.message_type.value:<12} "
            f"xid=0x{self.transaction_id:08x} "
            f"client={self.client_mac} "
            f"src={self.source_ip} dst={self.destination_ip}"
        )

    def options(self) -> Dict[str, object]:
        """Return important DHCP options in human-readable form."""
        return {
            "53": self.message_type.value,
            "50": self.requested_ip,
            "54": self.server_identifier,
            "51": self.lease_time,
            "1": self.subnet_mask,
            "3": self.router,
            "6": self.dns_servers,
        }


# ---------------------------------------------------------------------------
# 2. Utility functions
# ---------------------------------------------------------------------------

def generate_transaction_id() -> int:
    """DHCP clients use a transaction ID to associate messages."""
    return random.randint(0, 0xFFFFFFFF)


def normalize_mac(mac: str) -> str:
    """
    Validate and normalize a MAC address.

    Accepts forms such as:
        aa:bb:cc:dd:ee:ff
        AA-BB-CC-DD-EE-FF
    """
    cleaned = mac.replace("-", ":").lower()
    parts = cleaned.split(":")

    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        raise ValueError(f"Invalid MAC address: {mac}")

    try:
        [int(part, 16) for part in parts]
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal MAC address: {mac}") from exc

    return ":".join(parts)


def ip_is_available(
    address: str,
    network: IPv4Network,
    reserved: set[str],
) -> bool:
    """Check whether an address belongs to the pool and is not reserved."""
    ip = IPv4Address(address)
    return ip in network and address not in reserved


# ---------------------------------------------------------------------------
# 3. DHCP lease representation
# ---------------------------------------------------------------------------

@dataclass
class Lease:
    mac_address: str
    ip_address: str
    server_identifier: str
    lease_seconds: int
    start_time: float
    state: str = "ACTIVE"

    @property
    def expiration_time(self) -> float:
        return self.start_time + self.lease_seconds

    def is_expired(self, now: Optional[float] = None) -> bool:
        current = time.time() if now is None else now
        return current >= self.expiration_time

    def remaining_seconds(self, now: Optional[float] = None) -> int:
        current = time.time() if now is None else now
        return max(0, int(self.expiration_time - current))


# ---------------------------------------------------------------------------
# 4. DHCP server
# ---------------------------------------------------------------------------

class DHCPServer:
    """
    Simplified stateful DHCP server.

    Real DHCP servers have substantially more behavior, including:
    - persistent lease databases
    - reservations
    - relay support
    - option processing
    - conflict detection
    - failover/high availability
    - authorization controls
    - logging
    """

    def __init__(
        self,
        server_identifier: str,
        network: str,
        pool_start: str,
        pool_end: str,
        router: str,
        dns_servers: List[str],
        lease_seconds: int = 3600,
    ):
        self.server_identifier = server_identifier
        self.network = IPv4Network(network)
        self.pool_start = IPv4Address(pool_start)
        self.pool_end = IPv4Address(pool_end)
        self.router = router
        self.dns_servers = dns_servers
        self.lease_seconds = lease_seconds

        self.leases_by_mac: Dict[str, Lease] = {}
        self.leases_by_ip: Dict[str, Lease] = {}

        if self.pool_start > self.pool_end:
            raise ValueError("Pool start must not exceed pool end.")

        if self.pool_start not in self.network:
            raise ValueError("Pool start is outside the network.")

        if self.pool_end not in self.network:
            raise ValueError("Pool end is outside the network.")

    def _pool_addresses(self):
        """Generate all addresses in the configured pool."""
        current = self.pool_start
        while current <= self.pool_end:
            yield str(current)
            current += 1

    def _release_expired_leases(self, now: Optional[float] = None) -> None:
        """Remove expired leases from active allocation tables."""
        current = time.time() if now is None else now

        expired_ips = [
            ip
            for ip, lease in self.leases_by_ip.items()
            if lease.expiration_time <= current
        ]

        for ip in expired_ips:
            lease = self.leases_by_ip.pop(ip)
            self.leases_by_mac.pop(lease.mac_address, None)

    def _find_available_ip(self) -> Optional[str]:
        self._release_expired_leases()

        for address in self._pool_addresses():
            if address not in self.leases_by_ip:
                return address

        return None

    def receive_discover(self, packet: DHCPPacket) -> Optional[DHCPPacket]:
        """
        Process DHCPDISCOVER.

        The server selects an address and creates a DHCPOFFER.
        The lease is not considered fully committed until DHCPREQUEST /
        DHCPACK completes the exchange.
        """
        mac = normalize_mac(packet.client_mac)

        existing = self.leases_by_mac.get(mac)
        if existing and not existing.is_expired():
            offered_ip = existing.ip_address
        else:
            offered_ip = self._find_available_ip()

        if offered_ip is None:
            return None

        return DHCPPacket(
            message_type=DHCPMessageType.OFFER,
            transaction_id=packet.transaction_id,
            client_mac=mac,
            source_ip=self.server_identifier,
            destination_ip="255.255.255.255",
            server_identifier=self.server_identifier,
            offered_ip=offered_ip,
            subnet_mask=str(self.network.netmask),
            router=self.router,
            dns_servers=self.dns_servers,
            lease_time=self.lease_seconds,
        )

    def receive_request(self, packet: DHCPPacket) -> DHCPPacket:
        """
        Process DHCPREQUEST.

        A client may identify the selected DHCP server using option 54 and
        identify the requested address using option 50.
        """
        mac = normalize_mac(packet.client_mac)

        if packet.server_identifier != self.server_identifier:
            # In a real broadcast exchange, another DHCP server's selected
            # offer causes this server to withdraw its own offer.
            return DHCPPacket(
                message_type=DHCPMessageType.NAK,
                transaction_id=packet.transaction_id,
                client_mac=mac,
                source_ip=self.server_identifier,
                destination_ip="255.255.255.255",
                server_identifier=self.server_identifier,
            )

        requested_ip = packet.requested_ip
        if requested_ip is None:
            return DHCPPacket(
                message_type=DHCPMessageType.NAK,
                transaction_id=packet.transaction_id,
                client_mac=mac,
                source_ip=self.server_identifier,
                destination_ip="255.255.255.255",
                server_identifier=self.server_identifier,
            )

        if not ip_is_available(
            requested_ip,
            self.network,
            set(),
        ):
            return DHCPPacket(
                message_type=DHCPMessageType.NAK,
                transaction_id=packet.transaction_id,
                client_mac=mac,
                source_ip=self.server_identifier,
                destination_ip="255.255.255.255",
                server_identifier=self.server_identifier,
            )

        existing_ip_lease = self.leases_by_ip.get(requested_ip)

        if (
            existing_ip_lease
            and existing_ip_lease.mac_address != mac
            and not existing_ip_lease.is_expired()
        ):
            return DHCPPacket(
                message_type=DHCPMessageType.NAK,
                transaction_id=packet.transaction_id,
                client_mac=mac,
                source_ip=self.server_identifier,
                destination_ip="255.255.255.255",
                server_identifier=self.server_identifier,
            )

        now = time.time()

        old_lease = self.leases_by_mac.get(mac)
        if old_lease and old_lease.ip_address != requested_ip:
            self.leases_by_ip.pop(old_lease.ip_address, None)

        lease = Lease(
            mac_address=mac,
            ip_address=requested_ip,
            server_identifier=self.server_identifier,
            lease_seconds=self.lease_seconds,
            start_time=now,
        )

        self.leases_by_mac[mac] = lease
        self.leases_by_ip[requested_ip] = lease

        return DHCPPacket(
            message_type=DHCPMessageType.ACK,
            transaction_id=packet.transaction_id,
            client_mac=mac,
            source_ip=self.server_identifier,
            destination_ip="255.255.255.255",
            server_identifier=self.server_identifier,
            offered_ip=requested_ip,
            subnet_mask=str(self.network.netmask),
            router=self.router,
            dns_servers=self.dns_servers,
            lease_time=self.lease_seconds,
        )

    def release(self, mac_address: str) -> bool:
        """Release an active lease."""
        mac = normalize_mac(mac_address)
        lease = self.leases_by_mac.pop(mac, None)

        if lease is None:
            return False

        self.leases_by_ip.pop(lease.ip_address, None)
        lease.state = "RELEASED"
        return True

    def print_lease_table(self) -> None:
        """Display the server's current lease database."""
        self._release_expired_leases()

        print("\nDHCP lease table")
        print("-" * 78)

        if not self.leases_by_mac:
            print("No active leases.")
            return

        print(
            f"{'MAC':20} {'IP':15} {'Remaining':10} "
            f"{'Server':15} {'State':10}"
        )

        for lease in self.leases_by_mac.values():
            print(
                f"{lease.mac_address:20} "
                f"{lease.ip_address:15} "
                f"{lease.remaining_seconds():<10} "
                f"{lease.server_identifier:15} "
                f"{lease.state:10}"
            )


# ---------------------------------------------------------------------------
# 5. DHCP client state machine
# ---------------------------------------------------------------------------

class DHCPClient:
    """
    Simplified DHCP client.

    The client transitions approximately through:

        INIT
          |
          v
      SELECTING
          |
          v
      REQUESTING
          |
          v
        BOUND
        /   \
       /     \
  RENEWING  REBINDING
       |       |
       +---+---+
           |
          BOUND

    If the lease expires without successful renewal, the client becomes
    EXPIRED and must obtain another configuration.
    """

    def __init__(self, mac_address: str):
        self.mac_address = normalize_mac(mac_address)
        self.state = ClientState.INIT
        self.transaction_id = 0

        self.ip_address: Optional[str] = None
        self.server_identifier: Optional[str] = None
        self.subnet_mask: Optional[str] = None
        self.router: Optional[str] = None
        self.dns_servers: List[str] = []
        self.lease_seconds: Optional[int] = None
        self.lease_start: Optional[float] = None

    def create_discover(self) -> DHCPPacket:
        """Generate DHCPDISCOVER from the INIT state."""
        self.transaction_id = generate_transaction_id()
        self.state = ClientState.SELECTING

        return DHCPPacket(
            message_type=DHCPMessageType.DISCOVER,
            transaction_id=self.transaction_id,
            client_mac=self.mac_address,
            source_ip="0.0.0.0",
            destination_ip="255.255.255.255",
        )

    def create_request(self, offer: DHCPPacket) -> DHCPPacket:
        """
        Select one offer.

        In a real network a client may receive multiple offers and choose
        according to its implementation and configuration.
        """
        if offer.message_type != DHCPMessageType.OFFER:
            raise ValueError("Client can request only a DHCP offer.")

        if offer.transaction_id != self.transaction_id:
            raise ValueError("Transaction ID does not match.")

        if offer.offered_ip is None:
            raise ValueError("Offer contains no IP address.")

        if offer.server_identifier is None:
            raise ValueError("Offer contains no server identifier.")

        self.state = ClientState.REQUESTING

        return DHCPPacket(
            message_type=DHCPMessageType.REQUEST,
            transaction_id=self.transaction_id,
            client_mac=self.mac_address,
            source_ip="0.0.0.0",
            destination_ip="255.255.255.255",
            server_identifier=offer.server_identifier,
            requested_ip=offer.offered_ip,
        )

    def process_ack(self, ack: DHCPPacket) -> None:
        """Install the configuration supplied by DHCPACK."""
        if ack.message_type != DHCPMessageType.ACK:
            raise ValueError("Expected DHCPACK.")

        if ack.transaction_id != self.transaction_id:
            raise ValueError("ACK transaction ID mismatch.")

        if ack.offered_ip is None:
            raise ValueError("ACK contains no assigned address.")

        self.ip_address = ack.offered_ip
        self.server_identifier = ack.server_identifier
        self.subnet_mask = ack.subnet_mask
        self.router = ack.router
        self.dns_servers = ack.dns_servers
        self.lease_seconds = ack.lease_time
        self.lease_start = time.time()
        self.state = ClientState.BOUND

    def process_nak(self) -> None:
        """A NAK means the current request was rejected."""
        self.ip_address = None
        self.server_identifier = None
        self.lease_seconds = None
        self.lease_start = None
        self.state = ClientState.INIT

    def lease_fraction_used(self, now: Optional[float] = None) -> float:
        """Return how much of the current lease has elapsed."""
        if self.lease_start is None or self.lease_seconds is None:
            return 0.0

        current = time.time() if now is None else now
        elapsed = current - self.lease_start

        return max(0.0, min(1.0, elapsed / self.lease_seconds))

    def refresh_state(self, now: Optional[float] = None) -> ClientState:
        """
        Model the important DHCP timer states.

        Simplified timing:
        - before 50%: BOUND
        - 50% to 87.5%: RENEWING
        - 87.5% to 100%: REBINDING
        - after 100%: EXPIRED
        """
        if self.lease_start is None or self.lease_seconds is None:
            return self.state

        fraction = self.lease_fraction_used(now)

        if fraction >= 1.0:
            self.state = ClientState.EXPIRED
        elif fraction >= 0.875:
            self.state = ClientState.REBINDING
        elif fraction >= 0.5:
            self.state = ClientState.RENEWING
        else:
            self.state = ClientState.BOUND

        return self.state

    def create_renewal_request(self) -> DHCPPacket:
        """
        Create a simplified renewal request.

        During normal renewal, DHCP behavior differs from initial discovery:
        the client can communicate directly with the known server once it
        has a valid address and server information.
        """
        if self.ip_address is None or self.server_identifier is None:
            raise ValueError("Client has no active lease.")

        if self.state not in (
            ClientState.RENEWING,
            ClientState.REBINDING,
            ClientState.BOUND,
        ):
            raise ValueError(f"Cannot renew from state {self.state.value}.")

        return DHCPPacket(
            message_type=DHCPMessageType.REQUEST,
            transaction_id=generate_transaction_id(),
            client_mac=self.mac_address,
            source_ip=self.ip_address,
            destination_ip=self.server_identifier,
            server_identifier=self.server_identifier,
            requested_ip=self.ip_address,
        )

    def display_configuration(self) -> None:
        print("\nClient configuration")
        print("-" * 50)
        print(f"MAC address:     {self.mac_address}")
        print(f"State:            {self.state.value}")
        print(f"IPv4 address:     {self.ip_address}")
        print(f"Subnet mask:      {self.subnet_mask}")
        print(f"Default gateway:  {self.router}")
        print(f"DNS servers:      {', '.join(self.dns_servers)}")
        print(f"DHCP server:      {self.server_identifier}")
        print(f"Lease seconds:    {self.lease_seconds}")


# ---------------------------------------------------------------------------
# 6. Simulated DHCP exchange
# ---------------------------------------------------------------------------

def demonstrate_dora(server: DHCPServer, client: DHCPClient) -> None:
    """
    Demonstrate the four major messages:

        DHCPDISCOVER
        DHCPOFFER
        DHCPREQUEST
        DHCPACK
    """
    print("\n" + "=" * 80)
    print("DORA: DHCPDISCOVER -> DHCPOFFER -> DHCPREQUEST -> DHCPACK")
    print("=" * 80)

    discover = client.create_discover()
    print("\n1. Client sends:")
    print(discover.summary())

    offer = server.receive_discover(discover)

    if offer is None:
        print("No DHCP address is available.")
        return

    print("\n2. Server sends:")
    print(offer.summary())
    print(f"   Offered IP: {offer.offered_ip}")
    print(f"   Server ID:  {offer.server_identifier}")
    print(f"   Lease:      {offer.lease_time} seconds")

    request = client.create_request(offer)
    print("\n3. Client sends:")
    print(request.summary())
    print(f"   Requested IP: {request.requested_ip}")
    print(f"   Selected server: {request.server_identifier}")

    response = server.receive_request(request)
    print("\n4. Server sends:")
    print(response.summary())

    if response.message_type == DHCPMessageType.ACK:
        client.process_ack(response)
        print("   DHCPACK accepted. Client is now BOUND.")
    else:
        client.process_nak()
        print("   DHCPNAK received. Client returned to INIT.")

    client.display_configuration()


# ---------------------------------------------------------------------------
# 7. Multiple DHCP servers and offer selection
# ---------------------------------------------------------------------------

class SimulatedRogueDHCPServer(DHCPServer):
    """
    A deliberately simplified unauthorized DHCP server.

    This class is for defensive education. It demonstrates how a rogue
    server can offer a valid-looking IP configuration with a different
    gateway/DNS configuration.

    The code does not attack any real network.
    """

    pass


def demonstrate_multiple_offers(
    legitimate_server: DHCPServer,
    rogue_server: SimulatedRogueDHCPServer,
    client: DHCPClient,
) -> None:
    print("\n" + "=" * 80)
    print("MULTIPLE DHCP OFFERS AND ROGUE DHCP DETECTION")
    print("=" * 80)

    discover = client.create_discover()

    legitimate_offer = legitimate_server.receive_discover(discover)
    rogue_offer = rogue_server.receive_discover(discover)

    offers = [
        offer
        for offer in (legitimate_offer, rogue_offer)
        if offer is not None
    ]

    for index, offer in enumerate(offers, start=1):
        print(f"\nOffer {index}")
        print(offer.summary())
        print(f"  Offered IP: {offer.offered_ip}")
        print(f"  Server ID:  {offer.server_identifier}")
        print(f"  Gateway:    {offer.router}")
        print(f"  DNS:        {offer.dns_servers}")

    print("\nDefensive observation:")
    print("A client may receive multiple offers. The DHCP server identifier,")
    print("gateway, DNS values, lease time, and network policy should be")
    print("validated against the organization's expected configuration.")

    legitimate_ids = {legitimate_server.server_identifier}

    for offer in offers:
        if offer.server_identifier not in legitimate_ids:
            print(
                f"\nWARNING: unexpected DHCP server detected: "
                f"{offer.server_identifier}"
            )


# ---------------------------------------------------------------------------
# 8. Wireshark-oriented packet analysis
# ---------------------------------------------------------------------------

def wireshark_filter_examples() -> None:
    """
    Show useful Wireshark display filters.

    These strings are examples of display filters. They do not require
    Wireshark to be installed.
    """
    filters = {
        "All DHCP traffic":
            "dhcp",
        "DHCPv4 traffic using BOOTP dissector":
            "bootp",
        "DHCP Discover":
            'bootp.option.dhcp == 1',
        "DHCP Offer":
            'bootp.option.dhcp == 2',
        "DHCP Request":
            'bootp.option.dhcp == 3',
        "DHCP ACK":
            'bootp.option.dhcp == 5',
        "DHCP NAK":
            'bootp.option.dhcp == 6',
        "UDP port 67 or 68":
            "udp.port == 67 || udp.port == 68",
        "Specific DHCP server":
            'bootp.option.dhcp_server == "192.168.10.1"',
        "Specific client MAC":
            'eth.addr == aa:bb:cc:dd:ee:ff',
        "Packets containing DHCP option 54":
            "bootp.option.dhcp_server",
    }

    print("\n" + "=" * 80)
    print("WIRESHARK DISPLAY FILTER EXAMPLES")
    print("=" * 80)

    for description, display_filter in filters.items():
        print(f"{description:38} {display_filter}")

    print("\nPacket-analysis workflow:")
    print("1. Capture traffic on the relevant interface.")
    print("2. Filter for DHCP/BOOTP.")
    print("3. Identify the transaction ID.")
    print("4. Follow the Discover -> Offer -> Request -> ACK sequence.")
    print("5. Compare DHCP server identifiers.")
    print("6. Inspect assigned IP, subnet mask, router, DNS, and lease time.")
    print("7. Investigate unexpected DHCP servers.")
    print("8. Correlate timestamps, MAC addresses, switch ports, and VLANs.")


def analyze_packet(packet: DHCPPacket) -> None:
    """Print a Wireshark-like interpretation of a simulated packet."""
    print("\nPacket analysis")
    print("-" * 60)
    print(f"Message type:     {packet.message_type.value}")
    print(f"Transaction ID:   0x{packet.transaction_id:08x}")
    print(f"Client MAC:       {packet.client_mac}")
    print(f"Source IP:        {packet.source_ip}")
    print(f"Destination IP:   {packet.destination_ip}")

    for option_number, value in packet.options().items():
        if value is not None and value != []:
            print(f"Option {option_number:<3}:         {value}")


# ---------------------------------------------------------------------------
# 9. Lease exhaustion and edge cases
# ---------------------------------------------------------------------------

def demonstrate_pool_exhaustion() -> None:
    print("\n" + "=" * 80)
    print("EDGE CASE: DHCP POOL EXHAUSTION")
    print("=" * 80)

    tiny_server = DHCPServer(
        server_identifier="192.168.50.1",
        network="192.168.50.0/29",
        pool_start="192.168.50.2",
        pool_end="192.168.50.3",
        router="192.168.50.1",
        dns_servers=["192.168.50.1"],
        lease_seconds=120,
    )

    clients = [
        DHCPClient("00:11:22:33:44:01"),
        DHCPClient("00:11:22:33:44:02"),
        DHCPClient("00:11:22:33:44:03"),
    ]

    for client in clients:
        discover = client.create_discover()
        offer = tiny_server.receive_discover(discover)

        if offer is None:
            print(f"{client.mac_address}: no address available")
            continue

        request = client.create_request(offer)
        ack = tiny_server.receive_request(request)

        if ack.message_type == DHCPMessageType.ACK:
            client.process_ack(ack)
            print(f"{client.mac_address}: assigned {client.ip_address}")


def demonstrate_invalid_request(server: DHCPServer) -> None:
    print("\n" + "=" * 80)
    print("EDGE CASE: INVALID REQUEST")
    print("=" * 80)

    client = DHCPClient("de:ad:be:ef:00:01")
    client.transaction_id = generate_transaction_id()
    client.state = ClientState.REQUESTING

    invalid_request = DHCPPacket(
        message_type=DHCPMessageType.REQUEST,
        transaction_id=client.transaction_id,
        client_mac=client.mac_address,
        requested_ip="10.10.10.10",
        server_identifier=server.server_identifier,
    )

    response = server.receive_request(invalid_request)

    print(invalid_request.summary())
    print("Requested IP:", invalid_request.requested_ip)
    print("Server response:", response.message_type.value)


# ---------------------------------------------------------------------------
# 10. Security concepts
# ---------------------------------------------------------------------------

def explain_rogue_dhcp_defenses() -> None:
    print("\n" + "=" * 80)
    print("ROGUE DHCP: DEFENSIVE CONTROLS")
    print("=" * 80)

    controls = [
        (
            "DHCP snooping",
            "Switch feature that identifies trusted DHCP server ports and "
            "can block unauthorized DHCP server responses."
        ),
        (
            "Trusted uplinks/server ports",
            "Only infrastructure interfaces connected to authorized DHCP "
            "servers or relays should be configured as trusted."
        ),
        (
            "Access-layer monitoring",
            "Unexpected DHCP servers, gateways, DNS values, or DHCP rates "
            "can be detected through network monitoring."
        ),
        (
            "Port security and segmentation",
            "Network segmentation can reduce the scope of unauthorized "
            "DHCP activity."
        ),
        (
            "IP source validation",
            "Related switch security features can help prevent hosts from "
            "using addresses they did not legitimately receive."
        ),
    ]

    for name, description in controls:
        print(f"\n{name}")
        print(description)

    print(
        "\nImportant distinction: DHCP snooping is a network-switch security "
        "control, while Wireshark is primarily a packet capture and analysis "
        "tool. Wireshark can reveal evidence of rogue DHCP behavior but does "
        "not itself enforce DHCP authorization."
    )


# ---------------------------------------------------------------------------
# 11. Main educational demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    random.seed(42)

    print("=" * 80)
    print("DHCP LEARNING LAB")
    print("=" * 80)
    print(
        """
DHCP dynamically supplies network configuration to hosts.

The fundamental exchange is:
    DHCPDISCOVER -> DHCPOFFER -> DHCPREQUEST -> DHCPACK

Common DHCP information includes:
    IPv4 address
    subnet mask
    default gateway
    DNS servers
    lease duration
    DHCP server identifier
"""
    )

    legitimate_server = DHCPServer(
        server_identifier="192.168.10.1",
        network="192.168.10.0/24",
        pool_start="192.168.10.100",
        pool_end="192.168.10.110",
        router="192.168.10.1",
        dns_servers=["192.168.10.1", "1.1.1.1"],
        lease_seconds=3600,
    )

    client = DHCPClient("AA:BB:CC:DD:EE:01")

    demonstrate_dora(legitimate_server, client)

    legitimate_server.print_lease_table()

    if client.lease_start is not None and client.lease_seconds is not None:
        simulated_now = client.lease_start + client.lease_seconds * 0.60
        client.refresh_state(simulated_now)

        print("\nSimulated lease timer at 60%:")
        print("Client state:", client.state.value)

    wireshark_filter_examples()

    discover_for_analysis = DHCPPacket(
        message_type=DHCPMessageType.DISCOVER,
        transaction_id=0x12345678,
        client_mac="AA:BB:CC:DD:EE:01",
    )
    analyze_packet(discover_for_analysis)

    rogue_server = SimulatedRogueDHCPServer(
        server_identifier="192.168.10.254",
        network="192.168.10.0/24",
        pool_start="192.168.10.200",
        pool_end="192.168.10.210",
        router="192.168.10.254",
        dns_servers=["192.168.10.254"],
        lease_seconds=7200,
    )

    demonstrate_multiple_offers(
        legitimate_server,
        rogue_server,
        DHCPClient("AA:BB:CC:DD:EE:02"),
    )

    demonstrate_pool_exhaustion()
    demonstrate_invalid_request(legitimate_server)
    explain_rogue_dhcp_defenses()

    print("\n" + "=" * 80)
    print("KEY DHCP STATE AND MESSAGE RELATIONSHIPS")
    print("=" * 80)

    relationships = [
        ("DISCOVER", "Client", "Requests available DHCP configuration"),
        ("OFFER", "Server", "Proposes an address and configuration"),
        ("REQUEST", "Client", "Selects a server/address"),
        ("ACK", "Server", "Confirms the lease"),
        ("NAK", "Server", "Rejects an invalid or unacceptable request"),
        ("DECLINE", "Client", "Reports that offered address appears unusable"),
        ("RELEASE", "Client", "Returns the lease before expiration"),
        ("INFORM", "Client", "Requests configuration information without a lease"),
    ]

    for message, sender, meaning in relationships:
        print(f"{message:<10} | {sender:<8} | {meaning}")

    print("\nStudy principle:")
    print(
        "DHCP is best understood as a stateful protocol rather than merely "
        "a mechanism that assigns an IP address. Transaction IDs, server "
        "identifiers, options, lease timers, client states, and network "
        "security controls all contribute to correct operation."
    )


if __name__ == "__main__":
    main()
