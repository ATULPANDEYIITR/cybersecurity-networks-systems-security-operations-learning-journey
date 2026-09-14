"""
Advanced Subnetting: VLSM, Route Summarization, Supernetting, and Subnet Design
Packet Tracer-Oriented Study Script

This standalone script teaches IPv4 subnetting from fundamentals through advanced
design concepts. It includes:

1. IPv4 addressing fundamentals
2. Binary representation
3. Subnet masks and CIDR
4. Network, broadcast, host ranges
5. Fixed-length subnetting
6. VLSM
7. Efficient address allocation
8. Route summarization
9. Supernetting
10. Longest-prefix matching
11. Address planning
12. Point-to-point links
13. WAN and LAN design
14. Validation and error detection
15. Packet Tracer-oriented topology planning
16. Routing implications
17. Edge cases and common mistakes
18. Testing and practical design exercises

The script intentionally uses only Python's standard library.
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from typing import Iterable


# ============================================================================
# SECTION 1: BASIC TERMINOLOGY
# ============================================================================

def print_title(title: str) -> None:
    """Print a consistent section heading."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_basic_terminology() -> None:
    print_title("1. IPv4 Addressing Fundamentals")

    terms = {
        "IPv4 address": "A 32-bit logical address normally written as four decimal octets.",
        "Octet": "One group of 8 bits. IPv4 contains four octets.",
        "Network address": "The first address of a subnet; it identifies the subnet itself.",
        "Broadcast address": "The last address of an IPv4 subnet; IPv4 broadcasts are sent here.",
        "Host address": "An address that can normally be assigned to an interface.",
        "Subnet mask": "A 32-bit value identifying which bits represent the network portion.",
        "Prefix length": "The number of network bits, written after a slash, such as /24.",
        "CIDR": "Classless Inter-Domain Routing, which represents networks using prefix lengths.",
        "VLSM": "Variable Length Subnet Masking, allowing different subnet sizes in one address block.",
        "Supernetting": "Combining multiple contiguous networks into a larger address block.",
        "Route summarization": "Representing multiple routes with a shorter, aggregated route.",
        "Longest-prefix match": "Routing behavior where the most specific matching route wins.",
    }

    for name, description in terms.items():
        print(f"{name:24} : {description}")


# ============================================================================
# SECTION 2: BINARY REPRESENTATION
# ============================================================================

def ipv4_to_binary(address: str) -> str:
    """Convert an IPv4 address into a 32-bit binary string."""
    ip = ipaddress.IPv4Address(address)
    return ".".join(f"{octet:08b}" for octet in ip.packed)


def binary_to_ipv4(binary: str) -> str:
    """Convert a 32-bit binary IPv4 representation into dotted decimal."""
    cleaned = binary.replace(".", "")

    if len(cleaned) != 32 or any(bit not in "01" for bit in cleaned):
        raise ValueError("Binary IPv4 address must contain exactly 32 bits.")

    octets = [cleaned[index:index + 8] for index in range(0, 32, 8)]
    return ".".join(str(int(octet, 2)) for octet in octets)


def demonstrate_binary() -> None:
    print_title("2. Binary Representation")

    addresses = [
        "192.168.1.1",
        "172.16.25.10",
        "10.20.30.40",
        "255.255.255.0",
    ]

    for address in addresses:
        binary = ipv4_to_binary(address)
        print(f"{address:15} -> {binary}")

    example_binary = "11000000.10101000.00000001.00001010"
    print(f"\nBinary: {example_binary}")
    print(f"IPv4 : {binary_to_ipv4(example_binary)}")


# ============================================================================
# SECTION 3: SUBNET MASKS AND CIDR
# ============================================================================

def prefix_to_mask(prefix_length: int) -> str:
    """Convert a CIDR prefix length into a dotted-decimal subnet mask."""
    if not 0 <= prefix_length <= 32:
        raise ValueError("IPv4 prefix length must be between 0 and 32.")

    network = ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}")
    return str(network.netmask)


def mask_to_prefix(mask: str) -> int:
    """Convert a dotted-decimal subnet mask into a prefix length."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError as error:
        raise ValueError(f"Invalid or non-contiguous subnet mask: {mask}") from error


def host_bits(prefix_length: int) -> int:
    return 32 - prefix_length


def total_addresses(prefix_length: int) -> int:
    return 2 ** host_bits(prefix_length)


def usable_host_count(prefix_length: int) -> int:
    """
    Return the conventional usable IPv4 host count.

    /31 and /32 are special cases:
    - /31 is commonly used for point-to-point links under RFC 3021.
    - /32 identifies a single address and has no conventional subnet host range.
    """
    if prefix_length == 31:
        return 2
    if prefix_length == 32:
        return 1
    return max(0, total_addresses(prefix_length) - 2)


def demonstrate_masks() -> None:
    print_title("3. CIDR Prefixes and Subnet Masks")

    for prefix in [8, 16, 20, 24, 25, 26, 27, 28, 29, 30, 31, 32]:
        print(
            f"/{prefix:<2}  "
            f"mask={prefix_to_mask(prefix):15}  "
            f"addresses={total_addresses(prefix):>10}  "
            f"conventional usable={usable_host_count(prefix):>10}"
        )

    print("\nMask conversion:")
    masks = [
        "255.255.255.0",
        "255.255.255.128",
        "255.255.255.192",
        "255.255.255.224",
        "255.255.255.240",
    ]

    for mask in masks:
        print(f"{mask:18} -> /{mask_to_prefix(mask)}")


# ============================================================================
# SECTION 4: BASIC SUBNET ANALYSIS
# ============================================================================

@dataclass
class SubnetDetails:
    network: str
    prefix: int
    subnet_mask: str
    first_host: str | None
    last_host: str | None
    broadcast: str | None
    total_addresses: int
    usable_hosts: int


def analyze_subnet(cidr: str) -> SubnetDetails:
    """Analyze an IPv4 subnet without requiring host bits to be zero."""
    network = ipaddress.IPv4Network(cidr, strict=False)

    if network.prefixlen <= 30:
        first_host = str(network.network_address + 1)
        last_host = str(network.broadcast_address - 1)
    elif network.prefixlen == 31:
        first_host = str(network.network_address)
        last_host = str(network.broadcast_address)
    else:
        first_host = str(network.network_address)
        last_host = str(network.network_address)

    return SubnetDetails(
        network=str(network.network_address),
        prefix=network.prefixlen,
        subnet_mask=str(network.netmask),
        first_host=first_host,
        last_host=last_host,
        broadcast=str(network.broadcast_address),
        total_addresses=network.num_addresses,
        usable_hosts=usable_host_count(network.prefixlen),
    )


def print_subnet_details(cidr: str) -> None:
    details = analyze_subnet(cidr)

    print(f"\nInput:              {cidr}")
    print(f"Network:            {details.network}/{details.prefix}")
    print(f"Subnet mask:        {details.subnet_mask}")
    print(f"First host:         {details.first_host}")
    print(f"Last host:          {details.last_host}")
    print(f"Broadcast:          {details.broadcast}")
    print(f"Total addresses:    {details.total_addresses}")
    print(f"Usable host count:  {details.usable_hosts}")


def demonstrate_basic_subnetting() -> None:
    print_title("4. Basic Subnet Analysis")

    examples = [
        "192.168.10.0/24",
        "192.168.10.37/26",
        "172.16.20.130/25",
        "10.10.10.200/27",
        "192.168.50.1/30",
        "192.168.50.0/31",
        "192.168.50.10/32",
    ]

    for cidr in examples:
        print_subnet_details(cidr)


# ============================================================================
# SECTION 5: FIXED-LENGTH SUBNETTING
# ============================================================================

def split_subnet(cidr: str, new_prefix: int) -> list[ipaddress.IPv4Network]:
    """
    Split a parent IPv4 network into equal-sized child networks.

    This represents traditional fixed-length subnetting where every child
    subnet uses the same prefix length.
    """
    parent = ipaddress.IPv4Network(cidr, strict=True)

    if new_prefix < parent.prefixlen:
        raise ValueError("New prefix cannot be shorter than the parent prefix.")

    return list(parent.subnets(new_prefix=new_prefix))


def demonstrate_fixed_length_subnetting() -> None:
    print_title("5. Fixed-Length Subnetting")

    parent = "192.168.100.0/24"
    children = split_subnet(parent, 26)

    print(f"Parent network: {parent}")
    print("Splitting /24 into /26 networks produces:")
    print()

    for number, child in enumerate(children, start=1):
        print(
            f"Subnet {number}: {child} | "
            f"hosts={usable_host_count(child.prefixlen)} | "
            f"broadcast={child.broadcast_address}"
        )

    print(
        "\nA /24 contains 256 total addresses. "
        "A /26 contains 64 addresses, so four /26 networks fit exactly."
    )


# ============================================================================
# SECTION 6: SUBNET SIZE CALCULATION
# ============================================================================

def smallest_prefix_for_hosts(required_hosts: int) -> int:
    """
    Calculate the smallest conventional IPv4 prefix that can support the
    requested number of hosts.

    Two addresses are reserved in normal IPv4 subnetting:
    network and broadcast.
    """
    if required_hosts < 1:
        raise ValueError("Required hosts must be at least 1.")

    for prefix in range(31):
        if usable_host_count(prefix) >= required_hosts:
            return prefix

    raise ValueError("No conventional IPv4 subnet can satisfy the requirement.")


def demonstrate_host_calculation() -> None:
    print_title("6. Calculating Required Prefix Length")

    requirements = [2, 5, 10, 14, 30, 50, 100, 200, 500, 1000, 2000]

    for hosts in requirements:
        prefix = smallest_prefix_for_hosts(hosts)
        print(
            f"Required hosts={hosts:4} -> /{prefix:<2} -> "
            f"{usable_host_count(prefix):4} conventional usable hosts"
        )

    print(
        "\nImportant design rule: choose the smallest subnet that satisfies "
        "the host requirement while leaving appropriate growth capacity."
    )


# ============================================================================
# SECTION 7: VLSM
# ============================================================================

@dataclass
class VLSMRequirement:
    name: str
    hosts: int
    purpose: str = ""


@dataclass
class VLSMAllocation:
    name: str
    requested_hosts: int
    purpose: str
    network: ipaddress.IPv4Network


def allocate_vlsm(
    parent_cidr: str,
    requirements: Iterable[VLSMRequirement],
) -> list[VLSMAllocation]:
    """
    Allocate subnets using VLSM.

    The largest host requirement is allocated first. This is essential because
    allocating large blocks late can leave unusable fragments in the address
    space.
    """
    parent = ipaddress.IPv4Network(parent_cidr, strict=True)
    ordered = sorted(requirements, key=lambda item: item.hosts, reverse=True)

    allocations: list[VLSMAllocation] = []
    available = [parent]

    for requirement in ordered:
        prefix = smallest_prefix_for_hosts(requirement.hosts)

        candidate_index = None
        candidate_network = None

        for index, block in enumerate(available):
            if block.prefixlen <= prefix:
                possible = list(block.subnets(new_prefix=prefix))

                if possible:
                    candidate_index = index
                    candidate_network = possible[0]
                    break

        if candidate_network is None or candidate_index is None:
            raise ValueError(
                f"Unable to allocate /{prefix} for {requirement.name} "
                f"inside {parent}."
            )

        source_block = available.pop(candidate_index)

        remaining_blocks = list(source_block.address_exclude(candidate_network))
        available.extend(remaining_blocks)
        available.sort(key=lambda network: int(network.network_address))

        allocations.append(
            VLSMAllocation(
                name=requirement.name,
                requested_hosts=requirement.hosts,
                purpose=requirement.purpose,
                network=candidate_network,
            )
        )

    return sorted(allocations, key=lambda allocation: int(allocation.network.network_address))


def print_vlsm_allocations(allocations: list[VLSMAllocation]) -> None:
    print(
        f"{'Subnet':18} {'Requested':>10} {'CIDR':18} "
        f"{'Usable':>8} {'First':15} {'Last':15}"
    )
    print("-" * 90)

    for allocation in allocations:
        network = allocation.network
        if network.prefixlen <= 30:
            first = str(network.network_address + 1)
            last = str(network.broadcast_address - 1)
        else:
            first = str(network.network_address)
            last = str(network.broadcast_address)

        print(
            f"{allocation.name:18} "
            f"{allocation.requested_hosts:10} "
            f"{str(network):18} "
            f"{usable_host_count(network.prefixlen):8} "
            f"{first:15} "
            f"{last:15}"
        )


def demonstrate_vlsm() -> None:
    print_title("7. Variable Length Subnet Masking (VLSM)")

    parent = "10.20.0.0/24"

    requirements = [
        VLSMRequirement("Engineering", 60, "Engineering LAN"),
        VLSMRequirement("Finance", 30, "Finance LAN"),
        VLSMRequirement("HR", 14, "HR LAN"),
        VLSMRequirement("Management", 6, "Management LAN"),
        VLSMRequirement("Router-Link-1", 2, "Point-to-point WAN"),
        VLSMRequirement("Router-Link-2", 2, "Point-to-point WAN"),
    ]

    allocations = allocate_vlsm(parent, requirements)

    print(f"Parent address block: {parent}\n")
    print_vlsm_allocations(allocations)

    print(
        "\nVLSM uses different prefix lengths according to actual requirements. "
        "This avoids assigning a /24 to every department when smaller blocks "
        "are sufficient."
    )


# ============================================================================
# SECTION 8: VLSM DESIGN EFFICIENCY
# ============================================================================

def address_waste(network: ipaddress.IPv4Network, required_hosts: int) -> int:
    """Calculate conventional address capacity left unused for a subnet."""
    return usable_host_count(network.prefixlen) - required_hosts


def demonstrate_vlsm_efficiency() -> None:
    print_title("8. VLSM Efficiency Comparison")

    requirements = [60, 30, 14, 6, 2]

    fixed_prefix = smallest_prefix_for_hosts(max(requirements))

    fixed_total = len(requirements) * total_addresses(fixed_prefix)

    vlsm_total = sum(
        total_addresses(smallest_prefix_for_hosts(hosts))
        for hosts in requirements
    )

    print(f"Host requirements: {requirements}")
    print(f"Largest requirement requires /{fixed_prefix}.")
    print(
        f"Equal-size design uses {fixed_total} total addresses "
        f"for {len(requirements)} subnets."
    )
    print(f"VLSM uses {vlsm_total} total addresses for the same requirements.")
    print(f"Address savings: {fixed_total - vlsm_total}")

    print(
        "\nVLSM improves address utilization, but it requires more careful "
        "planning and makes the addressing scheme less visually uniform."
    )


# ============================================================================
# SECTION 9: ROUTE SUMMARIZATION
# ============================================================================

def summarize_networks(
    networks: Iterable[str],
) -> list[ipaddress.IPv4Network]:
    """
    Return the smallest standard set of CIDR networks covering the input
    networks without requiring them to be contiguous.
    """
    parsed = [ipaddress.IPv4Network(network, strict=True) for network in networks]
    return list(ipaddress.collapse_addresses(parsed))


def demonstrate_route_summarization() -> None:
    print_title("9. Route Summarization")

    routes = [
        "10.1.0.0/24",
        "10.1.1.0/24",
        "10.1.2.0/24",
        "10.1.3.0/24",
    ]

    summaries = summarize_networks(routes)

    print("Specific routes:")
    for route in routes:
        print(f"  {route}")

    print("\nCollapsed representation:")
    for summary in summaries:
        print(f"  {summary}")

    print(
        "\nFour contiguous /24 networks can be represented by 10.1.0.0/22 "
        "because the /22 covers exactly 10.1.0.0 through 10.1.3.255."
    )


# ============================================================================
# SECTION 10: SAFE AND UNSAFE SUMMARIZATION
# ============================================================================

def addresses_covered_by_summary(
    summary: ipaddress.IPv4Network,
) -> set[int]:
    """Return integer addresses represented by a summary for small examples."""
    return {int(address) for address in summary.hosts()}


def demonstrate_summary_boundaries() -> None:
    print_title("10. Route Summarization Boundaries")

    good_routes = [
        "192.168.0.0/24",
        "192.168.1.0/24",
        "192.168.2.0/24",
        "192.168.3.0/24",
    ]

    bad_routes = [
        "192.168.0.0/24",
        "192.168.2.0/24",
    ]

    print("Contiguous aligned routes:")
    for network in summarize_networks(good_routes):
        print(f"  {network}")

    print("\nNon-contiguous routes:")
    for network in summarize_networks(bad_routes):
        print(f"  {network}")

    print(
        "\nA careless summary can advertise addresses that are not actually "
        "reachable through the summarizing router. A summary must therefore "
        "be evaluated for alignment and routing correctness, not only size."
    )


# ============================================================================
# SECTION 11: SUPERNETTING
# ============================================================================

def common_prefix_length(
    networks: list[ipaddress.IPv4Network],
) -> int:
    """
    Find the common binary prefix shared by network addresses.

    This function is useful for understanding how a supernet is derived.
    """
    if not networks:
        raise ValueError("At least one network is required.")

    first = int(networks[0].network_address)

    common_bits = 32

    for network in networks[1:]:
        value = int(network.network_address)
        difference = first ^ value

        if difference:
            highest_different_bit = difference.bit_length()
            common_bits = min(common_bits, 32 - highest_different_bit)

    return common_bits


def calculate_supernet(networks: list[str]) -> ipaddress.IPv4Network:
    """
    Calculate a CIDR supernet based on the common prefix of network addresses.

    The result can cover additional address space. That is an important
    distinction between mathematically possible aggregation and safe route
    summarization.
    """
    parsed = [ipaddress.IPv4Network(network, strict=True) for network in networks]

    prefix = common_prefix_length(parsed)
    first_address = min(int(network.network_address) for network in parsed)

    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    supernet_address = first_address & mask

    return ipaddress.IPv4Network(
        f"{ipaddress.IPv4Address(supernet_address)}/{prefix}",
        strict=True,
    )


def demonstrate_supernetting() -> None:
    print_title("11. Supernetting")

    networks = [
        "172.16.0.0/24",
        "172.16.1.0/24",
        "172.16.2.0/24",
        "172.16.3.0/24",
    ]

    result = calculate_supernet(networks)

    print("Networks:")
    for network in networks:
        print(f"  {network}")

    print(f"\nCalculated supernet: {result}")

    print(
        "\nSupernetting is the process of combining smaller networks into a "
        "larger CIDR block. Route summarization often uses the same CIDR "
        "aggregation mechanism, but its purpose is to reduce routing entries."
    )


# ============================================================================
# SECTION 12: LONGEST-PREFIX MATCH
# ============================================================================

@dataclass
class Route:
    network: ipaddress.IPv4Network
    next_hop: str
    interface: str


def longest_prefix_match(
    destination: str,
    routes: Iterable[Route],
) -> Route | None:
    """Return the most specific route matching a destination address."""
    ip = ipaddress.IPv4Address(destination)

    matching_routes = [
        route
        for route in routes
        if ip in route.network
    ]

    if not matching_routes:
        return None

    return max(
        matching_routes,
        key=lambda route: route.network.prefixlen,
    )


def demonstrate_longest_prefix_match() -> None:
    print_title("12. Longest-Prefix Match")

    routes = [
        Route(ipaddress.IPv4Network("10.0.0.0/8"), "192.0.2.1", "G0/0"),
        Route(ipaddress.IPv4Network("10.10.0.0/16"), "192.0.2.2", "G0/1"),
        Route(ipaddress.IPv4Network("10.10.10.0/24"), "192.0.2.3", "G0/2"),
        Route(ipaddress.IPv4Network("10.10.10.128/25"), "192.0.2.4", "G0/3"),
    ]

    destinations = [
        "10.20.1.5",
        "10.10.20.5",
        "10.10.10.20",
        "10.10.10.200",
        "8.8.8.8",
    ]

    for destination in destinations:
        match = longest_prefix_match(destination, routes)

        if match:
            print(
                f"{destination:15} -> {match.network:18} "
                f"via {match.next_hop} on {match.interface}"
            )
        else:
            print(f"{destination:15} -> no matching route")

    print(
        "\nThe /25 wins over the /24 for 10.10.10.200 because /25 is more "
        "specific. This is the core idea behind longest-prefix matching."
    )


# ============================================================================
# SECTION 13: ROUTE TABLE DESIGN
# ============================================================================

def build_route_table_from_vlsm(
    allocations: list[VLSMAllocation],
    next_hop: str = "192.0.2.254",
) -> list[Route]:
    """Create illustrative routes from VLSM allocations."""
    return [
        Route(
            network=allocation.network,
            next_hop=next_hop,
            interface=f"LAN-{index}",
        )
        for index, allocation in enumerate(allocations, start=1)
    ]


def demonstrate_route_table() -> None:
    print_title("13. VLSM Networks as Routing Entries")

    requirements = [
        VLSMRequirement("Sales", 50),
        VLSMRequirement("IT", 25),
        VLSMRequirement("HR", 10),
        VLSMRequirement("WAN-A", 2),
    ]

    allocations = allocate_vlsm("10.50.0.0/24", requirements)
    routes = build_route_table_from_vlsm(allocations)

    for route in routes:
        print(
            f"Destination={route.network!s:18} "
            f"Next-hop={route.next_hop:15} "
            f"Interface={route.interface}"
        )


# ============================================================================
# SECTION 14: ADDRESS VALIDATION
# ============================================================================

def is_valid_host_address(address: str, subnet: str) -> bool:
    """
    Check whether an IPv4 address is assignable as a conventional host
    address in a subnet.
    """
    ip = ipaddress.IPv4Address(address)
    network = ipaddress.IPv4Network(subnet, strict=True)

    if ip not in network:
        return False

    if network.prefixlen <= 30:
        return ip not in {
            network.network_address,
            network.broadcast_address,
        }

    if network.prefixlen == 31:
        return True

    return True


def validate_interface_configuration(
    interface_ip: str,
    interface_subnet: str,
    default_gateway: str | None = None,
) -> list[str]:
    """Return configuration errors instead of silently accepting bad input."""
    errors: list[str] = []

    try:
        ip = ipaddress.IPv4Address(interface_ip)
    except ValueError:
        return [f"Invalid IPv4 address: {interface_ip}"]

    try:
        network = ipaddress.IPv4Network(interface_subnet, strict=True)
    except ValueError:
        return [f"Invalid subnet: {interface_subnet}"]

    if not is_valid_host_address(interface_ip, interface_subnet):
        errors.append(
            f"{ip} is not a conventional host address inside {network}."
        )

    if default_gateway is not None:
        try:
            gateway = ipaddress.IPv4Address(default_gateway)
        except ValueError:
            errors.append(f"Invalid default gateway: {default_gateway}")
        else:
            if gateway not in network:
                errors.append(
                    f"Default gateway {gateway} is outside {network}."
                )
            elif not is_valid_host_address(default_gateway, interface_subnet):
                errors.append(
                    f"Default gateway {gateway} is not an assignable host "
                    f"address in {network}."
                )

    return errors


def demonstrate_validation() -> None:
    print_title("14. Address Configuration Validation")

    examples = [
        ("192.168.1.10", "192.168.1.0/24", "192.168.1.1"),
        ("192.168.1.0", "192.168.1.0/24", "192.168.1.1"),
        ("192.168.1.255", "192.168.1.0/24", "192.168.1.1"),
        ("192.168.2.10", "192.168.1.0/24", "192.168.1.1"),
        ("192.168.1.10", "192.168.1.0/24", "192.168.2.1"),
    ]

    for ip, subnet, gateway in examples:
        errors = validate_interface_configuration(ip, subnet, gateway)

        if errors:
            print(f"{ip} / {subnet} / GW {gateway}")
            for error in errors:
                print(f"  ERROR: {error}")
        else:
            print(f"{ip} / {subnet} / GW {gateway} -> VALID")


# ============================================================================
# SECTION 15: ADDRESS OVERLAP DETECTION
# ============================================================================

def find_overlaps(
    networks: Iterable[str],
) -> list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]:
    """Find pairs of overlapping IPv4 networks."""
    parsed = [
        ipaddress.IPv4Network(network, strict=True)
        for network in networks
    ]

    overlaps = []

    for index, first in enumerate(parsed):
        for second in parsed[index + 1:]:
            if first.overlaps(second):
                overlaps.append((first, second))

    return overlaps


def demonstrate_overlap_detection() -> None:
    print_title("15. Detecting Overlapping Subnets")

    networks = [
        "10.0.0.0/24",
        "10.0.1.0/24",
        "10.0.0.128/25",
        "10.0.2.0/26",
    ]

    overlaps = find_overlaps(networks)

    print("Configured networks:")
    for network in networks:
        print(f"  {network}")

    print("\nOverlaps:")
    if overlaps:
        for first, second in overlaps:
            print(f"  {first} overlaps {second}")
    else:
        print("  None")


# ============================================================================
# SECTION 16: PACKET TRACER ADDRESSING PLAN
# ============================================================================

@dataclass
class DeviceInterface:
    device: str
    interface: str
    address: str
    subnet: str
    role: str


def create_packet_tracer_plan() -> list[DeviceInterface]:
    """
    Produce an addressing plan suitable for a small Packet Tracer lab.

    Topology:
        PC1 --- SW1 --- R1 --- R2 --- SW2 --- PC2
                         |
                         +--- SW3 --- PC3

    The exact Cisco CLI configuration is intentionally represented as a data
    plan so the subnetting logic remains independent from Packet Tracer.
    """
    return [
        DeviceInterface(
            "R1", "G0/0", "10.60.0.1", "10.60.0.0/26", "Engineering gateway"
        ),
        DeviceInterface(
            "PC1", "NIC", "10.60.0.10", "10.60.0.0/26", "Engineering host"
        ),
        DeviceInterface(
            "R1", "G0/1", "10.60.0.65", "10.60.0.64/27", "Finance gateway"
        ),
        DeviceInterface(
            "PC2", "NIC", "10.60.0.70", "10.60.0.64/27", "Finance host"
        ),
        DeviceInterface(
            "R1", "S0/0/0", "10.60.0.97", "10.60.0.96/30", "WAN endpoint"
        ),
        DeviceInterface(
            "R2", "S0/0/0", "10.60.0.98", "10.60.0.96/30", "WAN endpoint"
        ),
        DeviceInterface(
            "R2", "G0/0", "10.60.0.129", "10.60.0.128/26", "Operations gateway"
        ),
        DeviceInterface(
            "PC3", "NIC", "10.60.0.140", "10.60.0.128/26", "Operations host"
        ),
    ]


def print_packet_tracer_plan() -> None:
    print_title("16. Packet Tracer-Oriented Addressing Plan")

    plan = create_packet_tracer_plan()

    print(
        f"{'Device':8} {'Interface':10} {'Address':15} "
        f"{'Subnet':18} {'Role'}"
    )
    print("-" * 95)

    for item in plan:
        print(
            f"{item.device:8} "
            f"{item.interface:10} "
            f"{item.address:15} "
            f"{item.subnet:18} "
            f"{item.role}"
        )

    print(
        "\nPacket Tracer implementation sequence:\n"
        "1. Place routers, switches, and end devices.\n"
        "2. Connect the devices using appropriate links.\n"
        "3. Configure router interface addresses and masks.\n"
        "4. Configure PC addresses, masks, and default gateways.\n"
        "5. Verify directly connected networks.\n"
        "6. Add static routes or configure a dynamic routing protocol.\n"
        "7. Test connectivity with ping.\n"
        "8. Use traceroute and routing tables to diagnose failures."
    )


# ============================================================================
# SECTION 17: STATIC ROUTE CONCEPTS
# ============================================================================

def generate_static_route_example(
    destination: str,
    next_hop: str,
) -> str:
    """
    Generate an illustrative Cisco IOS static-route command.

    This function does not execute commands. It only constructs the command
    a learner would enter in a Cisco router CLI.
    """
    network = ipaddress.IPv4Network(destination, strict=True)
    return f"ip route {network.network_address} {network.netmask} {next_hop}"


def demonstrate_static_routes() -> None:
    print_title("17. Static Routing with Subnetted Networks")

    examples = [
        ("10.60.0.128/26", "10.60.0.98"),
        ("10.60.0.64/27", "10.60.0.97"),
    ]

    for destination, next_hop in examples:
        command = generate_static_route_example(destination, next_hop)
        print(command)

    print(
        "\nA static route must use the correct destination network, mask, and "
        "next hop. An incorrect mask can create a route that is too broad or "
        "too narrow."
    )


# ============================================================================
# SECTION 18: ROUTE SUMMARIZATION FOR A HIERARCHICAL NETWORK
# ============================================================================

@dataclass
class Site:
    name: str
    networks: list[str]


def summarize_site(site: Site) -> list[ipaddress.IPv4Network]:
    return summarize_networks(site.networks)


def demonstrate_hierarchical_summarization() -> None:
    print_title("18. Hierarchical Addressing and Summarization")

    sites = [
        Site(
            "North",
            [
                "10.100.0.0/24",
                "10.100.1.0/24",
                "10.100.2.0/24",
                "10.100.3.0/24",
            ],
        ),
        Site(
            "South",
            [
                "10.100.4.0/24",
                "10.100.5.0/24",
                "10.100.6.0/24",
                "10.100.7.0/24",
            ],
        ),
    ]

    for site in sites:
        summaries = summarize_site(site)
        print(f"\n{site.name} site:")
        for summary in summaries:
            print(f"  Advertise: {summary}")

    print(
        "\nHierarchical addressing makes summarization easier because related "
        "networks are intentionally placed into contiguous address ranges."
    )


# ============================================================================
# SECTION 19: SUMMARIZATION AND BLACK HOLE RISK
# ============================================================================

def contains_all_networks(
    summary: str,
    networks: Iterable[str],
) -> bool:
    """Check whether every supplied network is inside a summary."""
    summary_network = ipaddress.IPv4Network(summary, strict=True)

    return all(
        ipaddress.IPv4Network(network, strict=True).subnet_of(summary_network)
        for network in networks
    )


def demonstrate_black_hole_risk() -> None:
    print_title("19. Summary Routes and Black-Hole Risk")

    real_networks = [
        "10.200.0.0/24",
        "10.200.1.0/24",
        "10.200.2.0/24",
    ]

    proposed_summary = "10.200.0.0/22"

    print(f"Real networks: {real_networks}")
    print(f"Proposed summary: {proposed_summary}")
    print(
        f"Summary contains all real networks: "
        f"{contains_all_networks(proposed_summary, real_networks)}"
    )

    extra = [
        str(network)
        for network in ipaddress.IPv4Network(proposed_summary).subnets(new_prefix=24)
        if str(network) not in real_networks
    ]

    print(f"Additional /24 space covered by summary: {extra}")

    print(
        "\nIf a router advertises a summary that includes unused or unreachable "
        "space, traffic to that space can be attracted toward the summarizing "
        "router. Network designers must decide whether a discard/null route, "
        "more-specific route, or different summary boundary is appropriate."
    )


# ============================================================================
# SECTION 20: WILDCARD MASKS
# ============================================================================

def wildcard_mask(prefix_length: int) -> str:
    """Return the inverse of a subnet mask, commonly used in ACLs."""
    mask = ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}").netmask
    wildcard = int(ipaddress.IPv4Address("255.255.255.255")) ^ int(mask)
    return str(ipaddress.IPv4Address(wildcard))


def demonstrate_wildcard_masks() -> None:
    print_title("20. Wildcard Masks")

    for prefix in [24, 25, 26, 27, 28, 30]:
        print(
            f"/{prefix:<2} subnet mask={prefix_to_mask(prefix):15} "
            f"wildcard={wildcard_mask(prefix)}"
        )

    print(
        "\nWildcard masks are not subnet masks. A wildcard bit of 0 means "
        "the corresponding bit must match; a wildcard bit of 1 means it is "
        "ignored. Cisco ACLs and some routing configurations use this concept."
    )


# ============================================================================
# SECTION 21: PREFIX BOUNDARY VISUALIZATION
# ============================================================================

def show_prefix_boundary(address: str, prefix: int) -> None:
    """
    Show which bits belong to the network and host portions.

    N = network bit
    H = host bit
    """
    binary = ipv4_to_binary(address).replace(".", "")
    labels = "N" * prefix + "H" * (32 - prefix)

    print(f"Address : {binary}")
    print(f"Role    : {labels}")
    print(
        f"Network bits: {prefix}, Host bits: {32 - prefix}"
    )


def demonstrate_prefix_boundaries() -> None:
    print_title("21. Network Bits and Host Bits")

    show_prefix_boundary("192.168.10.130", 26)

    print(
        "\nFor /26, the first 26 bits identify the network and the final 6 bits "
        "identify addresses within that network. Therefore each /26 contains "
        "2^6 = 64 total addresses."
    )


# ============================================================================
# SECTION 22: SPECIAL PREFIXES AND EDGE CASES
# ============================================================================

def explain_special_prefixes() -> None:
    print_title("22. Special IPv4 Prefix Cases")

    special_cases = {
        "/30": "Four addresses. Traditionally two usable host addresses. Common in older point-to-point links.",
        "/31": "Two addresses. Commonly used for point-to-point links under RFC 3021, with both addresses usable.",
        "/32": "A single IPv4 address. Used for loopbacks, host routes, and highly specific routing entries.",
        "/0": "The default route. Matches every IPv4 destination.",
        "/127 IPv6": "Not an IPv4 prefix. IPv6 has different subnetting rules and must not be mixed into IPv4 calculations.",
    }

    for prefix, explanation in special_cases.items():
        print(f"{prefix:8} : {explanation}")

    print(
        "\nThe /31 and /32 cases are particularly important because applying "
        "the traditional 'network and broadcast are unusable' rule blindly "
        "can produce incorrect designs."
    )


# ============================================================================
# SECTION 23: ADDRESS SPACE CAPACITY
# ============================================================================

def calculate_subnet_count(
    parent_prefix: int,
    child_prefix: int,
) -> int:
    """Calculate equal-size child subnet count."""
    if child_prefix < parent_prefix:
        raise ValueError("Child prefix must be equal to or longer than parent.")

    return 2 ** (child_prefix - parent_prefix)


def demonstrate_subnet_counts() -> None:
    print_title("23. Number of Equal-Size Subnets")

    examples = [
        (24, 26),
        (24, 27),
        (16, 20),
        (16, 24),
        (20, 28),
    ]

    for parent, child in examples:
        count = calculate_subnet_count(parent, child)
        print(f"/{parent} -> /{child}: {count} equal-size subnets")


# ============================================================================
# SECTION 24: DESIGNING A REAL ADDRESS PLAN
# ============================================================================

def design_enterprise_address_plan() -> list[VLSMAllocation]:
    """
    Build an example enterprise plan from a /20 private address block.

    Requirements are deliberately different so VLSM produces a hierarchy
    containing large LANs, medium LANs, small infrastructure segments, and
    point-to-point links.
    """
    requirements = [
        VLSMRequirement("Data-Center", 500, "Server and application network"),
        VLSMRequirement("Engineering", 250, "Engineering users"),
        VLSMRequirement("Operations", 120, "Operations users"),
        VLSMRequirement("Finance", 60, "Finance users"),
        VLSMRequirement("HR", 30, "HR users"),
        VLSMRequirement("Guest", 100, "Guest wireless"),
        VLSMRequirement("Network-Management", 20, "Management interfaces"),
        VLSMRequirement("WAN-01", 2, "Router point-to-point link"),
        VLSMRequirement("WAN-02", 2, "Router point-to-point link"),
        VLSMRequirement("WAN-03", 2, "Router point-to-point link"),
    ]

    return allocate_vlsm("10.80.0.0/20", requirements)


def demonstrate_enterprise_design() -> None:
    print_title("24. Enterprise VLSM Design")

    allocations = design_enterprise_address_plan()
    print_vlsm_allocations(allocations)

    print(
        "\nDesign principle: the address hierarchy should reflect organizational "
        "or geographic structure where practical. That makes route aggregation "
        "and operational troubleshooting easier."
    )


# ============================================================================
# SECTION 25: SUBNET MEMBERSHIP
# ============================================================================

def demonstrate_membership() -> None:
    print_title("25. Determining Whether Addresses Belong to the Same Subnet")

    subnet = ipaddress.IPv4Network("192.168.40.64/26")

    addresses = [
        "192.168.40.65",
        "192.168.40.100",
        "192.168.40.126",
        "192.168.40.127",
        "192.168.40.128",
    ]

    print(f"Subnet: {subnet}")

    for address in addresses:
        ip = ipaddress.IPv4Address(address)
        print(f"{address:16} -> {'inside' if ip in subnet else 'outside'}")

    print(
        "\nFor a /26 beginning at .64, the address range is .64 through .127. "
        "The conventional host range is .65 through .126."
    )


# ============================================================================
# SECTION 26: MANUAL SUBNET CALCULATION LOGIC
# ============================================================================

def manual_network_calculation(address: str, prefix: int) -> str:
    """
    Demonstrate the underlying bitwise operation used to calculate a network.

    network = address AND subnet mask
    """
    ip_value = int(ipaddress.IPv4Address(address))
    mask_value = int(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    network_value = ip_value & mask_value

    return str(ipaddress.IPv4Address(network_value))


def demonstrate_manual_network_math() -> None:
    print_title("26. Manual Network Calculation with Bitwise AND")

    examples = [
        ("192.168.10.130", 26),
        ("172.16.75.200", 20),
        ("10.50.70.200", 27),
    ]

    for address, prefix in examples:
        calculated = manual_network_calculation(address, prefix)
        expected = str(
            ipaddress.IPv4Network(
                f"{address}/{prefix}",
                strict=False,
            ).network_address
        )

        print(
            f"{address}/{prefix:<2} -> "
            f"manual={calculated:15} "
            f"library={expected:15}"
        )

    print(
        "\nThis illustrates the fundamental operation behind subnet "
        "calculation: an address is ANDed with the subnet mask."
    )


# ============================================================================
# SECTION 27: HOST CAPACITY AND GROWTH
# ============================================================================

@dataclass
class GrowthPlan:
    department: str
    current_hosts: int
    growth_percent: float


def prefix_for_growth(plan: GrowthPlan) -> tuple[int, int, int]:
    """Return required future hosts, selected prefix, and usable capacity."""
    future_hosts = math.ceil(
        plan.current_hosts * (1 + plan.growth_percent / 100)
    )
    prefix = smallest_prefix_for_hosts(future_hosts)
    capacity = usable_host_count(prefix)

    return future_hosts, prefix, capacity


def demonstrate_growth_planning() -> None:
    print_title("27. Capacity Planning and Growth")

    plans = [
        GrowthPlan("Engineering", 45, 25),
        GrowthPlan("Finance", 20, 50),
        GrowthPlan("Support", 70, 30),
        GrowthPlan("IoT", 180, 40),
    ]

    for plan in plans:
        future_hosts, prefix, capacity = prefix_for_growth(plan)

        print(
            f"{plan.department:15} current={plan.current_hosts:4} "
            f"growth={plan.growth_percent:5.1f}% "
            f"future={future_hosts:4} "
            f"prefix=/{prefix:<2} capacity={capacity:4}"
        )


# ============================================================================
# SECTION 28: STATIC ROUTE SUMMARIZATION
# ============================================================================

def generate_summary_route_command(
    summary: str,
    next_hop: str,
) -> str:
    """Generate an illustrative Cisco IOS summary route command."""
    network = ipaddress.IPv4Network(summary, strict=True)
    return f"ip route {network.network_address} {network.netmask} {next_hop}"


def demonstrate_summary_route_commands() -> None:
    print_title("28. Cisco IOS-Style Summary Route Commands")

    commands = [
        ("10.100.0.0/22", "192.0.2.1"),
        ("10.100.4.0/22", "192.0.2.1"),
        ("10.100.8.0/21", "192.0.2.1"),
    ]

    for summary, next_hop in commands:
        print(generate_summary_route_command(summary, next_hop))

    print(
        "\nThese are examples of command syntax for a lab environment. "
        "The exact command must be chosen according to the actual topology "
        "and routing design."
    )


# ============================================================================
# SECTION 29: COMMON DESIGN MISTAKES
# ============================================================================

def demonstrate_common_mistakes() -> None:
    print_title("29. Common Subnetting Mistakes")

    mistakes = [
        (
            "Using a host address as the network address",
            "A subnet such as 192.168.1.37/26 actually belongs to 192.168.1.0/26.",
        ),
        (
            "Assigning the broadcast address",
            "The last address of a conventional subnet is reserved for broadcast.",
        ),
        (
            "Using the wrong prefix in a route",
            "A route to /24 and a route to /27 do not represent the same destination space.",
        ),
        (
            "Allocating small VLSM blocks first",
            "Large requirements should normally be allocated first to reduce fragmentation.",
        ),
        (
            "Creating a summary without checking alignment",
            "A summary may accidentally include address space that is not actually reachable.",
        ),
        (
            "Assuming every /31 has zero usable addresses",
            "Point-to-point /31 networks are a special case under RFC 3021.",
        ),
        (
            "Ignoring growth",
            "A subnet that barely meets today's requirement may force renumbering later.",
        ),
        (
            "Overlapping subnets",
            "Overlapping addressing creates ambiguous or invalid routing and Layer 3 designs.",
        ),
    ]

    for mistake, correction in mistakes:
        print(f"\nMistake:   {mistake}")
        print(f"Correction: {correction}")


# ============================================================================
# SECTION 30: SECURITY AND OPERATIONAL CONSIDERATIONS
# ============================================================================

def explain_security_considerations() -> None:
    print_title("30. Security and Operational Considerations")

    points = [
        "Subnetting is an addressing mechanism, not a complete security boundary.",
        "Traffic filtering should use appropriate controls such as ACLs or firewalls.",
        "Guest, management, server, user, and IoT networks should normally be separated.",
        "A summary route should not unintentionally expose or attract traffic for unrelated networks.",
        "Management interfaces should not be placed casually in user-accessible subnets.",
        "Documentation should record network address, prefix, gateway, DHCP scope, VLAN, and purpose.",
        "Unused address space should be tracked so future allocations do not overlap existing networks.",
        "Routing changes should be tested because a summary can change the path of large amounts of traffic.",
    ]

    for point in points:
        print(f"- {point}")


# ============================================================================
# SECTION 31: PERFORMANCE AND SCALABILITY
# ============================================================================

def explain_performance_considerations() -> None:
    print_title("31. Performance and Scalability")

    points = [
        (
            "Routing table size",
            "Summarization can reduce the number of prefixes routers need to process and store."
        ),
        (
            "Control-plane efficiency",
            "Fewer advertised routes can reduce routing protocol update volume."
        ),
        (
            "Convergence",
            "A hierarchical design can limit how widely some routing changes propagate."
        ),
        (
            "Address efficiency",
            "VLSM reduces wasted address capacity compared with equal-size subnetting."
        ),
        (
            "Operational complexity",
            "Highly fragmented VLSM plans can be harder to document and troubleshoot."
        ),
    ]

    for subject, explanation in points:
        print(f"{subject:22}: {explanation}")


# ============================================================================
# SECTION 32: DESIGN TRADE-OFFS
# ============================================================================

def compare_design_strategies() -> None:
    print_title("32. Design Trade-Offs")

    comparisons = [
        (
            "FLSM",
            "Same prefix for every subnet",
            "Simple and predictable",
            "Can waste addresses",
        ),
        (
            "VLSM",
            "Different prefixes according to need",
            "Efficient address utilization",
            "More planning complexity",
        ),
        (
            "Summarization",
            "Several routes represented by one aggregate",
            "Smaller routing tables",
            "Requires careful address hierarchy",
        ),
        (
            "Supernetting",
            "Multiple networks combined into a larger prefix",
            "Efficient aggregation",
            "May include additional address space",
        ),
    ]

    print(
        f"{'Technique':18} {'Structure':35} "
        f"{'Primary benefit':30} {'Trade-off'}"
    )
    print("-" * 125)

    for row in comparisons:
        print(f"{row[0]:18} {row[1]:35} {row[2]:30} {row[3]}")


# ============================================================================
# SECTION 33: MINI SUBNETTING EXERCISES
# ============================================================================

def solve_subnet_exercise(
    address: str,
    prefix: int,
) -> dict[str, str | int]:
    """Return the principal values for a subnetting exercise."""
    network = ipaddress.IPv4Network(
        f"{address}/{prefix}",
        strict=False,
    )

    return {
        "network": str(network.network_address),
        "prefix": network.prefixlen,
        "mask": str(network.netmask),
        "broadcast": str(network.broadcast_address),
        "total_addresses": network.num_addresses,
        "usable_hosts": usable_host_count(network.prefixlen),
        "first_host": (
            str(network.network_address + 1)
            if network.prefixlen <= 30
            else str(network.network_address)
        ),
        "last_host": (
            str(network.broadcast_address - 1)
            if network.prefixlen <= 30
            else str(network.broadcast_address)
        ),
    }


def demonstrate_exercises() -> None:
    print_title("33. Worked Subnetting Exercises")

    exercises = [
        ("192.168.5.77", 26),
        ("172.20.55.100", 20),
        ("10.10.10.200", 27),
        ("192.168.100.14", 28),
    ]

    for address, prefix in exercises:
        result = solve_subnet_exercise(address, prefix)

        print(f"\nExercise: {address}/{prefix}")
        for key, value in result.items():
            print(f"  {key:17}: {value}")


# ============================================================================
# SECTION 34: ADVANCED AGGREGATION TEST
# ============================================================================

def test_aggregation(
    source_networks: list[str],
    expected_summary: str,
) -> None:
    """
    Test whether collapse_addresses produces the expected aggregate.
    """
    summaries = summarize_networks(source_networks)

    expected = ipaddress.IPv4Network(expected_summary, strict=True)

    if expected not in summaries:
        raise AssertionError(
            f"Expected {expected} in {summaries}"
        )


def demonstrate_aggregation_tests() -> None:
    print_title("34. Aggregation Validation Tests")

    test_aggregation(
        [
            "10.1.0.0/24",
            "10.1.1.0/24",
            "10.1.2.0/24",
            "10.1.3.0/24",
        ],
        "10.1.0.0/22",
    )

    test_aggregation(
        [
            "172.16.8.0/25",
            "172.16.8.128/25",
        ],
        "172.16.8.0/24",
    )

    print("Aggregation tests passed.")


# ============================================================================
# SECTION 35: PACKET TRACER TROUBLESHOOTING MODEL
# ============================================================================

@dataclass
class Host:
    name: str
    address: str
    subnet: str
    gateway: str


def same_subnet(first: Host, second: Host) -> bool:
    """Determine whether two hosts belong to the same IPv4 subnet."""
    first_network = ipaddress.IPv4Network(first.subnet, strict=True)
    second_ip = ipaddress.IPv4Address(second.address)

    return second_ip in first_network


def diagnose_host_pair(first: Host, second: Host) -> str:
    """
    Provide a basic Layer 3 diagnostic result.

    Real connectivity also depends on ARP, VLANs, switch ports, interfaces,
    routing, ACLs, firewall rules, cabling, and device state.
    """
    if same_subnet(first, second):
        return (
            f"{first.name} and {second.name} appear to be in the same subnet. "
            "They should use local Layer 2/ARP resolution rather than a router "
            "for ordinary same-subnet communication."
        )

    return (
        f"{first.name} and {second.name} are in different subnets. "
        "Communication requires a Layer 3 routing path, normally through "
        "the configured default gateway."
    )


def demonstrate_troubleshooting() -> None:
    print_title("35. Packet Tracer Troubleshooting Logic")

    pc1 = Host(
        "PC1",
        "10.60.0.10",
        "10.60.0.0/26",
        "10.60.0.1",
    )

    pc2 = Host(
        "PC2",
        "10.60.0.70",
        "10.60.0.64/27",
        "10.60.0.65",
    )

    print(diagnose_host_pair(pc1, pc2))

    print(
        "\nA practical Packet Tracer troubleshooting order is:\n"
        "1. Check physical links and interface status.\n"
        "2. Verify IP address and subnet mask.\n"
        "3. Verify default gateway.\n"
        "4. Check VLAN membership when switches are involved.\n"
        "5. Check ARP for same-subnet communication.\n"
        "6. Check routing tables for remote subnets.\n"
        "7. Test with ping.\n"
        "8. Use traceroute to locate the routing boundary.\n"
        "9. Check ACLs and other traffic filters."
    )


# ============================================================================
# SECTION 36: FINAL DESIGN CHECKLIST
# ============================================================================

def print_design_checklist() -> None:
    print_title("36. Advanced Subnetting Design Checklist")

    checklist = [
        "Identify the total address block available.",
        "List every LAN, WAN, loopback, infrastructure, and special-purpose requirement.",
        "Estimate current host requirements.",
        "Add realistic growth requirements.",
        "Choose the smallest suitable prefix for each requirement.",
        "Allocate VLSM blocks from largest requirement to smallest.",
        "Ensure every subnet is aligned on its correct CIDR boundary.",
        "Verify that no subnets overlap.",
        "Reserve addresses or blocks for future growth where appropriate.",
        "Design hierarchical addressing when route summarization is desirable.",
        "Calculate valid summary boundaries.",
        "Check that summaries do not accidentally attract unwanted destinations.",
        "Document gateways, VLANs, interfaces, DHCP scopes, and routing boundaries.",
        "Configure the Packet Tracer devices.",
        "Verify interfaces and addressing before troubleshooting routing.",
        "Test local and remote connectivity.",
        "Inspect routing tables and longest-prefix behavior.",
        "Review security boundaries and management access.",
    ]

    for number, item in enumerate(checklist, start=1):
        print(f"{number:2}. {item}")


# ============================================================================
# SECTION 37: AUTOMATED SANITY CHECKS
# ============================================================================

def run_sanity_checks() -> None:
    print_title("37. Automated Sanity Checks")

    # Basic prefix conversion.
    assert prefix_to_mask(24) == "255.255.255.0"
    assert prefix_to_mask(26) == "255.255.255.192"
    assert mask_to_prefix("255.255.255.224") == 27

    # Network calculations.
    assert manual_network_calculation("192.168.1.130", 26) == "192.168.1.128"
    assert manual_network_calculation("10.10.10.200", 27) == "10.10.10.192"

    # Host capacity.
    assert usable_host_count(24) == 254
    assert usable_host_count(30) == 2
    assert usable_host_count(31) == 2
    assert usable_host_count(32) == 1

    # VLSM.
    requirements = [
        VLSMRequirement("A", 50),
        VLSMRequirement("B", 20),
        VLSMRequirement("C", 5),
    ]

    allocations = allocate_vlsm("192.168.200.0/24", requirements)

    assert len(allocations) == 3
    assert all(
        allocation.network.subnet_of(ipaddress.IPv4Network("192.168.200.0/24"))
        for allocation in allocations
    )

    # No overlaps.
    networks = [allocation.network for allocation in allocations]
    for index, first in enumerate(networks):
        for second in networks[index + 1:]:
            assert not first.overlaps(second)

    # Longest-prefix matching.
    routes = [
        Route(ipaddress.IPv4Network("10.0.0.0/8"), "A", "G0/0"),
        Route(ipaddress.IPv4Network("10.10.0.0/16"), "B", "G0/1"),
        Route(ipaddress.IPv4Network("10.10.10.0/24"), "C", "G0/2"),
    ]

    match = longest_prefix_match("10.10.10.50", routes)
    assert match is not None
    assert match.network == ipaddress.IPv4Network("10.10.10.0/24")

    print("All sanity checks passed.")


# ============================================================================
# SECTION 38: STUDY MODE
# ============================================================================

def study_questions() -> None:
    print_title("38. Advanced Subnetting Study Questions")

    questions = [
        "Why does a /26 contain 64 total addresses?",
        "Why does a conventional /24 provide 254 usable host addresses?",
        "Why should large VLSM requirements normally be allocated first?",
        "What makes a route summary valid from a routing perspective?",
        "How does longest-prefix matching resolve overlapping route coverage?",
        "Why can an incorrectly designed summary create a black-hole problem?",
        "When is /31 appropriate?",
        "Why are /32 routes useful for loopbacks and host routes?",
        "How does hierarchical addressing support summarization?",
        "What trade-off exists between VLSM efficiency and operational complexity?",
        "Why is subnetting not itself a complete security mechanism?",
        "How would you design address space for future organizational growth?",
        "What should you check in Packet Tracer before investigating routing?",
    ]

    for number, question in enumerate(questions, start=1):
        print(f"{number:2}. {question}")


# ============================================================================
# SECTION 39: MAIN PROGRAM
# ============================================================================

def main() -> None:
    """
    Run the complete educational demonstration.

    The script is intentionally organized so that each section can also be
    copied into a Python REPL or studied independently.
    """
    print_title("ADVANCED SUBNETTING STUDY PROGRAM")
    print(
        "Topics: VLSM | Route Summarization | Supernetting | Subnet Design | "
        "Packet Tracer"
    )
    print(
        "\nThis program demonstrates the calculations and design principles "
        "behind advanced IPv4 subnetting."
    )

    explain_basic_terminology()
    demonstrate_binary()
    demonstrate_masks()
    demonstrate_basic_subnetting()
    demonstrate_fixed_length_subnetting()
    demonstrate_host_calculation()
    demonstrate_vlsm()
    demonstrate_vlsm_efficiency()
    demonstrate_route_summarization()
    demonstrate_summary_boundaries()
    demonstrate_supernetting()
    demonstrate_longest_prefix_match()
    demonstrate_route_table()
    demonstrate_validation()
    demonstrate_overlap_detection()
    print_packet_tracer_plan()
    demonstrate_static_routes()
    demonstrate_hierarchical_summarization()
    demonstrate_black_hole_risk()
    demonstrate_wildcard_masks()
    demonstrate_prefix_boundaries()
    explain_special_prefixes()
    demonstrate_subnet_counts()
    demonstrate_enterprise_design()
    demonstrate_membership()
    demonstrate_manual_network_math()
    demonstrate_growth_planning()
    demonstrate_summary_route_commands()
    demonstrate_common_mistakes()
    explain_security_considerations()
    explain_performance_considerations()
    compare_design_strategies()
    demonstrate_exercises()
    demonstrate_aggregation_tests()
    demonstrate_troubleshooting()
    print_design_checklist()
    run_sanity_checks()
    study_questions()

    print_title("END OF ADVANCED SUBNETTING PROGRAM")
    print(
        "The calculations above can be translated into a Packet Tracer lab "
        "by implementing the displayed addressing plans on routers, switches, "
        "and end devices and then validating Layer 2 and Layer 3 connectivity."
    )


if __name__ == "__main__":
    main()
