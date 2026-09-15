"""
IPv6 Networking: A comprehensive executable study guide.

This script teaches IPv6 addressing, notation, SLAAC, link-local addresses,
multicast, routing concepts, address selection, validation, subnetting,
security considerations, and practical implementation patterns.

The examples are intentionally self-contained and use only Python's standard
library.
"""

from __future__ import annotations

import ipaddress
import random
import secrets
import socket
import struct
from dataclasses import dataclass
from typing import Iterable


# ============================================================================
# 1. FUNDAMENTALS
# ============================================================================

def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_ipv6_basics() -> None:
    section("1. IPv6 fundamentals")

    print(
        """
IPv6 is the Internet Protocol version designed to replace IPv4 at Internet
scale. An IPv6 address contains 128 bits, normally written as eight groups of
four hexadecimal digits.

Example:
    2001:0db8:0000:0000:0000:ff00:0042:8329

Each hexadecimal digit represents four bits:
    32 hexadecimal digits × 4 bits = 128 bits.

Important address concepts:
    - Unicast: identifies one interface.
    - Multicast: identifies a group of interfaces.
    - Anycast: the same unicast address is assigned to multiple interfaces;
      routing selects a topologically appropriate instance.
    - Link-local: automatically usable on a local IPv6 link.
    - Global unicast: generally routable IPv6 addressing.
    - Unique local: private-style addressing using fc00::/7, commonly fd00::/8.
    - Multicast: ff00::/8.
    - IPv6 has no broadcast address. Multicast replaces broadcast behavior.

IPv6 packet forwarding is based on prefixes and longest-prefix matching.
Routers generally do not need NAT merely to conserve address space.
"""
    )


# ============================================================================
# 2. NOTATION AND NORMALIZATION
# ============================================================================

def demonstrate_notation() -> None:
    section("2. IPv6 notation and canonical representation")

    examples = [
        "2001:0db8:0000:0000:0000:ff00:0042:8329",
        "2001:db8::ff00:42:8329",
        "fe80:0000:0000:0000:021c:7eff:fe4a:1234",
        "::1",
        "::",
    ]

    for text in examples:
        address = ipaddress.IPv6Address(text)
        print(f"Input:      {text}")
        print(f"Compressed: {address.compressed}")
        print(f"Exploded:   {address.exploded}")
        print(f"Integer:    {int(address)}")
        print()

    print(
        """
Notation rules:
1. Leading zeroes inside a group may be removed.
2. One contiguous sequence of all-zero groups may be replaced by ::.
3. :: may appear only once in an address.
4. Hexadecimal letters are conventionally written in lowercase in canonical
   textual form.
5. The prefix length is written after /, for example 2001:db8:1::/48.
"""
    )


# ============================================================================
# 3. ADDRESS TYPES
# ============================================================================

def classify_address(address: ipaddress.IPv6Address) -> list[str]:
    classifications: list[str] = []

    if address.is_unspecified:
        classifications.append("unspecified")
    if address.is_loopback:
        classifications.append("loopback")
    if address.is_link_local:
        classifications.append("link-local")
    if address.is_multicast:
        classifications.append("multicast")
    if address.is_private:
        classifications.append("private/unique-local-like")
    if address.is_global:
        classifications.append("global")
    if address.is_reserved:
        classifications.append("reserved")

    if not classifications:
        classifications.append("ordinary unicast/other")

    return classifications


def demonstrate_address_classes() -> None:
    section("3. IPv6 address classes")

    addresses = [
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "ff02::2",
        "fc00::1",
        "fd12:3456:789a::1",
        "2001:db8::1",
    ]

    for text in addresses:
        address = ipaddress.IPv6Address(text)
        print(f"{text:25} -> {', '.join(classify_address(address))}")

    print(
        """
Important examples:
    ::1        IPv6 loopback
    ::         unspecified address
    fe80::/10  link-local unicast
    ff00::/8   multicast
    fc00::/7   unique local address space
    2000::/3   global unicast range traditionally used for Internet unicast

2001:db8::/32 is reserved for documentation and examples. It should not be
used as real production Internet addressing.
"""
    )


# ============================================================================
# 4. PREFIXES AND SUBNETTING
# ============================================================================

def subnet_examples() -> None:
    section("4. Prefixes and IPv6 subnetting")

    networks = [
        ipaddress.IPv6Network("2001:db8:abcd::/48"),
        ipaddress.IPv6Network("2001:db8:abcd:1200::/56"),
        ipaddress.IPv6Network("2001:db8:abcd:1200::/64"),
        ipaddress.IPv6Network("fd12:3456:789a:1::/64"),
    ]

    for network in networks:
        print(
            f"{network} | prefix length={network.prefixlen} | "
            f"network={network.network_address} | "
            f"mask={network.netmask}"
        )

    base = ipaddress.IPv6Network("2001:db8:abcd::/48")
    subnets = list(base.subnets(new_prefix=64))

    print(f"\nA /48 divided into /64 networks creates {len(subnets)} subnets.")
    print("First five:")
    for subnet in subnets[:5]:
        print(" ", subnet)

    print(
        """
IPv6 commonly uses /64 for ordinary LAN/interface subnets. This is important
because SLAAC relies on a 64-bit interface identifier in conventional
addressing models.

Unlike IPv4, there is normally little reason to create tiny host-sized
subnets merely to conserve addresses.
"""
    )


# ============================================================================
# 5. SLAAC
# ============================================================================

@dataclass
class RouterAdvertisement:
    prefix: ipaddress.IPv6Network
    autonomous: bool = True
    on_link: bool = True
    router_lifetime_seconds: int = 1800


@dataclass
class HostInterface:
    mac_address: str
    link_local: ipaddress.IPv6Address | None = None
    global_addresses: list[ipaddress.IPv6Address] | None = None

    def __post_init__(self) -> None:
        if self.global_addresses is None:
            self.global_addresses = []


def normalize_mac(mac: str) -> str:
    cleaned = mac.replace("-", ":").replace(".", "").lower()

    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) != 6 or any(len(part) != 2 for part in parts):
            raise ValueError("Invalid MAC address")
        return ":".join(parts)

    if len(cleaned) != 12 or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("Invalid MAC address")

    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def mac_to_eui64(mac: str) -> int:
    """
    Construct a modified EUI-64 identifier.

    This mechanism inserts ff:fe into a 48-bit MAC and flips the universal/
    local (U/L) bit. Modern systems may deliberately avoid exposing stable
    MAC-derived interface identifiers because of privacy implications.
    """
    normalized = normalize_mac(mac)
    octets = [int(part, 16) for part in normalized.split(":")]

    octets[0] ^= 0x02
    eui64_bytes = octets[:3] + [0xFF, 0xFE] + octets[3:]

    return int.from_bytes(bytes(eui64_bytes), byteorder="big")


def eui64_address(prefix: ipaddress.IPv6Network, mac: str) -> ipaddress.IPv6Address:
    if prefix.prefixlen != 64:
        raise ValueError("Traditional EUI-64 construction requires a /64 prefix")

    identifier = mac_to_eui64(mac)
    return ipaddress.IPv6Address(int(prefix.network_address) | identifier)


def stable_random_interface_identifier() -> int:
    """
    Generate a random 64-bit interface identifier.

    A production host can use privacy/stable address mechanisms instead of
    exposing an identifier derived directly from the physical MAC address.
    """
    return secrets.randbits(64)


def create_slaac_address(prefix: ipaddress.IPv6Network) -> ipaddress.IPv6Address:
    if prefix.prefixlen != 64:
        raise ValueError("This educational SLAAC example expects a /64 prefix")

    identifier = stable_random_interface_identifier()
    return ipaddress.IPv6Address(int(prefix.network_address) | identifier)


def simulate_slaac() -> None:
    section("5. SLAAC simulation")

    host = HostInterface(mac_address="00:1c:42:2e:60:4a")

    # IPv6 hosts can derive a link-local address automatically.
    link_local_prefix = ipaddress.IPv6Network("fe80::/64")
    host.link_local = eui64_address(link_local_prefix, host.mac_address)

    router_advertisement = RouterAdvertisement(
        prefix=ipaddress.IPv6Network("2001:db8:100:20::/64")
    )

    if router_advertisement.autonomous:
        global_address = create_slaac_address(router_advertisement.prefix)
        host.global_addresses.append(global_address)

    print("Host MAC:", host.mac_address)
    print("Derived EUI-64 link-local:", host.link_local)
    print("Router Advertisement prefix:", router_advertisement.prefix)
    print("SLAAC address:", host.global_addresses[0])

    print(
        """
SLAAC means Stateless Address Autoconfiguration.

A simplified sequence is:
    1. Interface becomes active.
    2. Host creates a link-local address.
    3. Duplicate Address Detection (DAD) checks whether the address is usable.
    4. Host receives a Router Advertisement (RA), commonly as part of ICMPv6
       Neighbor Discovery.
    5. If the prefix has the Autonomous flag, the host forms an address.
    6. The host installs appropriate on-link/default-router information.

SLAAC is not simply "IPv6 assigns an address automatically". Router
Advertisements communicate network configuration and Neighbor Discovery is
fundamental to IPv6 operation.
"""
    )


# ============================================================================
# 6. LINK-LOCAL ADDRESSING
# ============================================================================

def link_local_demo() -> None:
    section("6. Link-local addresses")

    network = ipaddress.IPv6Network("fe80::/64")
    addresses = [
        ipaddress.IPv6Address("fe80::1"),
        ipaddress.IPv6Address("fe80::a8bb:ccff:fedd:eeff"),
    ]

    print("Link-local prefix:", network)
    for address in addresses:
        print(address, "is link-local:", address.is_link_local)

    print(
        """
Link-local addresses use fe80::/10.

They are valid only on the local Layer-2/link scope. Routers do not forward
ordinary link-local traffic between links.

Because the same link-local address can exist on different interfaces or links,
applications may need a scope identifier when communicating with a specific
interface. On many systems this appears as syntax similar to:
    fe80::1%eth0

The exact interface/scope syntax varies by operating system and API.
"""
    )


# ============================================================================
# 7. MULTICAST
# ============================================================================

def multicast_scope(address: ipaddress.IPv6Address) -> int:
    if not address.is_multicast:
        raise ValueError("Address is not multicast")

    # ffXY:: where the low four bits of the second byte encode scope.
    second_byte = (int(address) >> 112) & 0xFF
    return second_byte & 0x0F


def multicast_demo() -> None:
    section("7. IPv6 multicast")

    addresses = [
        "ff02::1",   # all nodes on the local link
        "ff02::2",   # all routers on the local link
        "ff02::5",   # OSPFv3 routers
        "ff02::6",   # OSPFv3 designated routers
        "ff02::9",   # RIPng routers
        "ff02::fb",  # mDNS
        "ff02::1:2", # DHCPv6 relay agents and servers
    ]

    for text in addresses:
        address = ipaddress.IPv6Address(text)
        print(
            f"{text:15} multicast={address.is_multicast} "
            f"scope={multicast_scope(address)}"
        )

    print(
        """
IPv6 multicast addresses start with ff.

The address structure includes:
    ff | flags | scope | multicast group ID

Common scopes include:
    1 = interface-local
    2 = link-local
    5 = site-local (historical/specialized interpretation)
    8 = organization-local
    e = global

IPv6 does not use broadcast. Protocols such as Neighbor Discovery use
multicast groups instead.
"""
    )


# ============================================================================
# 8. ADDRESS VALIDATION AND PREFIX OPERATIONS
# ============================================================================

def address_validation_demo() -> None:
    section("8. Validation and prefix membership")

    candidates = [
        "2001:db8:1::10",
        "fe80::1234",
        "192.168.1.1",
        "2001:db8::zzzz",
        "::1",
    ]

    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
            print(f"{candidate:22} -> valid {address.version=}")
        except ValueError as error:
            print(f"{candidate:22} -> invalid ({error})")

    network = ipaddress.IPv6Network("2001:db8:100::/48")
    test_addresses = [
        "2001:db8:100::1",
        "2001:db8:101::1",
        "2001:db8:100:abcd::1",
    ]

    print("\nPrefix membership:")
    for text in test_addresses:
        address = ipaddress.IPv6Address(text)
        print(f"{address} in {network}: {address in network}")


# ============================================================================
# 9. ADDRESS SELECTION AND PREFERENCES
# ============================================================================

def address_selection_demo() -> None:
    section("9. Address selection considerations")

    addresses = [
        ipaddress.IPv6Address("::1"),
        ipaddress.IPv6Address("fe80::1"),
        ipaddress.IPv6Address("fd12:3456:789a::1"),
        ipaddress.IPv6Address("2001:db8:1234::1"),
        ipaddress.IPv6Address("ff02::1"),
    ]

    for address in addresses:
        print(
            f"{address:40} "
            f"link_local={address.is_link_local:<5} "
            f"multicast={address.is_multicast:<5} "
            f"loopback={address.is_loopback:<5}"
        )

    print(
        """
Real operating systems apply address-selection rules rather than blindly
choosing the first address. Factors can include destination scope, source
scope, reachability, policy tables, and interface state.

An application should normally allow the operating system networking stack to
perform destination/source selection rather than implementing its own global
address-selection algorithm.
"""
    )


# ============================================================================
# 10. DNS AND SOCKETS
# ============================================================================

def dns_and_socket_demo() -> None:
    section("10. IPv6 in application networking")

    try:
        results = socket.getaddrinfo(
            "localhost",
            80,
            family=socket.AF_INET6,
            type=socket.SOCK_STREAM,
        )
        print("IPv6 localhost records returned by the local resolver:")
        for result in results[:5]:
            print(" ", result[4])
    except socket.gaierror as error:
        print("IPv6 DNS/socket lookup unavailable:", error)

    print(
        """
Python applications can explicitly request AF_INET6 sockets.

For dual-stack applications, getaddrinfo() is generally preferable to
hard-coding a single address family because it allows the operating system to
return addresses appropriate to the environment.

A server should validate:
    - address family
    - port
    - scope/interface where relevant
    - application-level authorization
    - whether the address is permitted by policy

An IPv6 firewall should not be treated as optional merely because an IPv4
firewall already exists.
"""
    )


# ============================================================================
# 11. NEIGHBOR DISCOVERY
# ============================================================================

def neighbor_discovery_demo() -> None:
    section("11. Neighbor Discovery Protocol concepts")

    print(
        """
IPv6 Neighbor Discovery (ND) uses ICMPv6 and multicast.

Important messages include:
    Router Solicitation (RS)
        Host asks routers for configuration information.

    Router Advertisement (RA)
        Router advertises prefixes, router information, and configuration
        parameters.

    Neighbor Solicitation (NS)
        Used for neighbor discovery and Duplicate Address Detection.

    Neighbor Advertisement (NA)
        Response/announcement about a neighbor's link-layer reachability.

    Redirect
        A router can inform a host of a better next-hop.

ND replaces several IPv4 mechanisms, including functions historically
associated with ARP and router discovery.

Because ND depends on ICMPv6, indiscriminately blocking ICMPv6 can break IPv6.
"""
    )


# ============================================================================
# 12. PRIVACY ADDRESSES
# ============================================================================

def privacy_address_demo() -> None:
    section("12. Privacy and temporary interface identifiers")

    prefix = ipaddress.IPv6Network("2001:db8:200:10::/64")

    identifiers = [secrets.randbits(64) for _ in range(3)]

    for identifier in identifiers:
        address = ipaddress.IPv6Address(
            int(prefix.network_address) | identifier
        )
        print(address)

    print(
        """
A stable MAC-derived interface identifier can reveal information about a
device across networks. Privacy-oriented IPv6 implementations can generate
temporary addresses whose interface identifiers change over time.

This creates a trade-off:
    Stable addresses:
        + predictable
        + useful for servers and infrastructure
        - potentially easier to correlate

    Temporary/privacy addresses:
        + better resistance to long-term host tracking
        - complicate long-lived inbound connections
        - require lifecycle management
"""
    )


# ============================================================================
# 13. SECURITY CONSIDERATIONS
# ============================================================================

def security_demo() -> None:
    section("13. IPv6 security considerations")

    security_points = {
        "RA spoofing": (
            "A rogue router can advertise malicious prefixes or routes. "
            "Controls such as RA Guard and switch-level protections can help."
        ),
        "ND attacks": (
            "Neighbor Discovery can be attacked through forged ND messages. "
            "Network controls and appropriate SEND-related designs may help."
        ),
        "Firewall parity": (
            "Security policy must cover IPv6 independently. Do not assume an "
            "IPv4 firewall automatically protects IPv6 traffic."
        ),
        "Extension headers": (
            "Security devices must correctly parse IPv6 extension headers and "
            "avoid inconsistent interpretations between firewall and host."
        ),
        "ICMPv6 filtering": (
            "Blocking all ICMPv6 can break essential IPv6 functions. Filtering "
            "should be selective and policy-driven."
        ),
        "Dual-stack exposure": (
            "A service may be protected on IPv4 but unintentionally exposed "
            "through IPv6."
        ),
        "Privacy": (
            "Address identifiers and logs can create tracking and correlation "
            "risks."
        ),
    }

    for issue, mitigation in security_points.items():
        print(f"{issue}: {mitigation}")

    print(
        """
A practical security model should include:
    - IPv4 and IPv6 firewall rules
    - secure router configuration
    - RA/ND protections
    - ingress and egress filtering
    - service binding review
    - logging and monitoring for both protocols
    - least-privilege network access
    - secure management interfaces
    - validation of externally supplied addresses
"""
    )


# ============================================================================
# 14. ROUTING TABLE SIMULATION
# ============================================================================

@dataclass(frozen=True)
class Route:
    prefix: ipaddress.IPv6Network
    next_hop: str
    metric: int = 100


def longest_prefix_match(
    destination: ipaddress.IPv6Address,
    routes: Iterable[Route],
) -> Route | None:
    matches = [route for route in routes if destination in route.prefix]

    if not matches:
        return None

    # Longest prefix wins. Metric breaks a tie between equal prefixes.
    return min(matches, key=lambda route: (-route.prefix.prefixlen, route.metric))


def routing_demo() -> None:
    section("14. Longest-prefix routing")

    routes = [
        Route(ipaddress.IPv6Network("::/0"), "ISP-A", 200),
        Route(ipaddress.IPv6Network("2001:db8::/32"), "CORE-1", 100),
        Route(ipaddress.IPv6Network("2001:db8:100::/48"), "CORE-2", 100),
        Route(ipaddress.IPv6Network("2001:db8:100:42::/64"), "EDGE-42", 50),
    ]

    destinations = [
        "2001:db8:100:42::10",
        "2001:db8:100:99::10",
        "2001:db8:999::10",
        "2606:4700:4700::1111",
    ]

    for destination_text in destinations:
        destination = ipaddress.IPv6Address(destination_text)
        route = longest_prefix_match(destination, routes)

        if route:
            print(
                f"{destination} -> {route.next_hop} "
                f"via {route.prefix} metric={route.metric}"
            )
        else:
            print(destination, "-> no route")


# ============================================================================
# 15. ADDRESS PLANNING
# ============================================================================

def address_planning_demo() -> None:
    section("15. Practical IPv6 address planning")

    allocation = ipaddress.IPv6Network("2001:db8:1234::/48")

    departments = {
        "engineering": 0x0010,
        "finance": 0x0020,
        "operations": 0x0030,
        "guest": 0x0040,
    }

    for name, subnet_id in departments.items():
        subnet = ipaddress.IPv6Network(
            f"2001:db8:1234:{subnet_id:04x}::/64"
        )
        print(f"{name:15} {subnet}")

    print(
        f"\nAllocated aggregate: {allocation}"
        "\nThe /48 gives an organization 16 bits between the /48 and /64 "
        "boundary, corresponding to 65,536 conventional /64 subnets."
    )


# ============================================================================
# 16. EDGE CASES
# ============================================================================

def edge_cases_demo() -> None:
    section("16. Important edge cases")

    cases = [
        "::",
        "::1",
        "::ffff:192.0.2.128",
        "fe80::1",
        "ff02::1",
        "2001:db8::/128",
        "2001:db8::/129",
    ]

    for value in cases:
        try:
            if "/" in value:
                network = ipaddress.IPv6Network(value, strict=False)
                print(
                    f"{value:28} -> network={network.network_address}, "
                    f"prefix={network.prefixlen}"
                )
            else:
                address = ipaddress.IPv6Address(value)
                print(
                    f"{value:28} -> compressed={address.compressed}, "
                    f"mapped_v4={address.ipv4_mapped}"
                )
        except ValueError as error:
            print(f"{value:28} -> invalid: {error}")

    print(
        """
IPv4-mapped IPv6 addresses such as ::ffff:192.0.2.128 are useful in APIs
that represent both IPv4 and IPv6 addresses. They do not mean that ordinary
IPv4 packets have magically become IPv6 packets.

A /128 identifies a single IPv6 address.
A /129 is invalid because IPv6 prefixes can contain at most 128 bits.
"""
    )


# ============================================================================
# 17. CONFIGURATION VALIDATION
# ============================================================================

@dataclass
class InterfaceConfiguration:
    name: str
    addresses: list[ipaddress.IPv6Interface]
    default_gateway: ipaddress.IPv6Address | None = None


def validate_interface(configuration: InterfaceConfiguration) -> list[str]:
    errors: list[str] = []

    if not configuration.name:
        errors.append("Interface name cannot be empty.")

    if not configuration.addresses:
        errors.append("At least one IPv6 address is required.")

    for interface in configuration.addresses:
        if interface.ip.is_multicast:
            errors.append(
                f"{interface} is multicast and should not normally be "
                "configured as an ordinary unicast interface address."
            )

        if interface.network.prefixlen != 64:
            errors.append(
                f"{interface} uses /{interface.network.prefixlen}; "
                "verify that the subnet size is intentional."
            )

    if configuration.default_gateway:
        if configuration.default_gateway.is_multicast:
            errors.append("Default gateway must not be multicast.")

    return errors


def configuration_validation_demo() -> None:
    section("17. Configuration validation")

    configuration = InterfaceConfiguration(
        name="eth0",
        addresses=[
            ipaddress.IPv6Interface("2001:db8:10:20::25/64"),
            ipaddress.IPv6Interface("fe80::25/64"),
        ],
        default_gateway=ipaddress.IPv6Address("2001:db8:10:20::1"),
    )

    errors = validate_interface(configuration)

    if errors:
        print("Configuration errors:")
        for error in errors:
            print(" -", error)
    else:
        print("Configuration passes the educational validation rules.")


# ============================================================================
# 18. TESTS
# ============================================================================

def run_self_tests() -> None:
    section("18. Automated self-tests")

    assert ipaddress.IPv6Address("::1").is_loopback
    assert ipaddress.IPv6Address("fe80::1").is_link_local
    assert ipaddress.IPv6Address("ff02::1").is_multicast

    network = ipaddress.IPv6Network("2001:db8::/32")
    assert ipaddress.IPv6Address("2001:db8:1::1") in network
    assert ipaddress.IPv6Address("2001:dead::1") not in network

    mac = "00:1c:42:2e:60:4a"
    address = eui64_address(ipaddress.IPv6Network("fe80::/64"), mac)
    assert address.is_link_local

    route = longest_prefix_match(
        ipaddress.IPv6Address("2001:db8:100:42::10"),
        [
            Route(ipaddress.IPv6Network("::/0"), "default"),
            Route(ipaddress.IPv6Network("2001:db8::/32"), "core"),
            Route(ipaddress.IPv6Network("2001:db8:100:42::/64"), "edge"),
        ],
    )
    assert route is not None
    assert route.next_hop == "edge"

    print("All self-tests passed.")


# ============================================================================
# 19. MINI IPv6 ADDRESS PLANNER
# ============================================================================

def generate_subnet_plan(
    aggregate: str,
    new_prefix: int,
    names: list[str],
) -> dict[str, ipaddress.IPv6Network]:
    network = ipaddress.IPv6Network(aggregate)
    subnets = list(network.subnets(new_prefix=new_prefix))

    if len(names) > len(subnets):
        raise ValueError("Not enough subnets available for the requested names.")

    return dict(zip(names, subnets))


def address_planner_demo() -> None:
    section("19. Mini IPv6 address planner")

    names = [
        "office",
        "servers",
        "wireless",
        "management",
        "guest",
        "lab",
    ]

    plan = generate_subnet_plan("2001:db8:5000::/48", 64, names)

    for name, subnet in plan.items():
        first_host = ipaddress.IPv6Address(int(subnet.network_address) + 1)
        print(f"{name:12} subnet={subnet} example-host={first_host}")


# ============================================================================
# 20. PERFORMANCE AND REPRESENTATION
# ============================================================================

def performance_representation_demo() -> None:
    section("20. Integer representation and performance")

    address = ipaddress.IPv6Address("2001:db8:abcd:12::42")
    numeric_value = int(address)

    print("Address:", address)
    print("128-bit integer:", numeric_value)
    print("Bit length:", numeric_value.bit_length())

    # Membership in a prefix can be expressed as a mask operation.
    prefix_length = 64
    mask = ((1 << 128) - 1) ^ ((1 << (128 - prefix_length)) - 1)

    address_value = int(address)
    network_value = address_value & mask

    print(
        "Network represented as integer:",
        ipaddress.IPv6Address(network_value),
    )

    print(
        """
For large routing or address-analysis systems, representations matter.

Possible approaches:
    - ipaddress.IPv6Address for correctness and readability.
    - 128-bit integers where the language/runtime supports them efficiently.
    - two 64-bit words in systems languages.
    - binary structures for packet-processing systems.

Correctness should generally come before micro-optimization. Prefix lookup
systems may use tries, radix trees, compressed prefix trees, or specialized
routing-table structures when the number of prefixes becomes large.
"""
    )


# ============================================================================
# 21. PACKET HEADER CONCEPT
# ============================================================================

def ipv6_header_layout_demo() -> None:
    section("21. IPv6 base header")

    print(
        """
The IPv6 base header is fixed at 40 bytes and contains:

    Version                 4 bits
    Traffic Class           8 bits
    Flow Label             20 bits
    Payload Length         16 bits
    Next Header              8 bits
    Hop Limit                8 bits
    Source Address         128 bits
    Destination Address    128 bits

Next Header identifies the next protocol/header, such as TCP, UDP, ICMPv6,
or an IPv6 extension header.

IPv6 moves optional functionality into extension headers instead of making
the base header variable length.
"""
    )


# ============================================================================
# 22. SECURITY-SAFE INPUT HANDLING
# ============================================================================

def safe_client_address(value: str) -> str:
    """
    Parse and normalize an address supplied by an application user.

    This prevents accidental string-based comparisons such as treating
    differently formatted representations as different addresses.
    """
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as error:
        raise ValueError("Invalid IP address") from error

    return address.compressed


def input_validation_demo() -> None:
    section("22. Safe address input handling")

    inputs = [
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "  FE80::1  ",
        "not-an-ip",
    ]

    for value in inputs:
        try:
            print(f"{value!r} -> {safe_client_address(value)}")
        except ValueError as error:
            print(f"{value!r} -> rejected: {error}")

    print(
        """
Never trust an IP address supplied by a client merely because it parses.

Parsing answers "is this syntactically an IP address?".
Authorization answers "is this address allowed to perform this action?".

Applications should avoid security decisions based on raw string equality.
Normalize first, then apply explicit policy.
"""
    )


# ============================================================================
# MAIN
# ============================================================================

def main() -> None:
    explain_ipv6_basics()
    demonstrate_notation()
    demonstrate_address_classes()
    subnet_examples()
    simulate_slaac()
    link_local_demo()
    multicast_demo()
    address_validation_demo()
    address_selection_demo()
    dns_and_socket_demo()
    neighbor_discovery_demo()
    privacy_address_demo()
    security_demo()
    routing_demo()
    address_planning_demo()
    edge_cases_demo()
    configuration_validation_demo()
    run_self_tests()
    address_planner_demo()
    performance_representation_demo()
    ipv6_header_layout_demo()
    input_validation_demo()

    section("Study checklist")
    checklist = [
        "128-bit addressing and hexadecimal notation",
        "compressed and exploded representations",
        "unicast, multicast, and anycast",
        "global, link-local, unique-local, loopback, and unspecified addresses",
        "prefix lengths and /64 subnetting",
        "SLAAC and Router Advertisements",
        "Duplicate Address Detection",
        "Neighbor Discovery and ICMPv6",
        "IPv6 multicast scopes and well-known groups",
        "privacy-oriented addressing",
        "longest-prefix routing",
        "IPv6 application socket behavior",
        "dual-stack security",
        "RA and ND attack considerations",
        "IPv6 firewall and monitoring requirements",
    ]

    for item in checklist:
        print("[x]", item)


if __name__ == "__main__":
    main()
