"""
Subnetting: CIDR, subnet masks, prefix lengths, subnet calculation, and host ranges.

This standalone study script teaches IPv4 subnetting from absolute beginner level
through advanced practical calculations.

The script intentionally uses only Python's standard library.

Run:
    python subnetting.py

The demonstrations cover:
- IPv4 addresses and binary representation
- Network addresses and host addresses
- Subnet masks and prefix lengths
- CIDR notation
- Network, broadcast, and usable host ranges
- Number of hosts and subnets
- Borrowing host bits
- Fixed-length subnetting
- Variable-length subnetting concepts
- VLSM allocation
- Supernetting and route aggregation
- Private IPv4 ranges
- Special-use addresses
- Edge cases such as /31 and /32
- Subnet membership
- IP range validation
- Address summarization
- Binary AND operations
- Address planning
- Practical examples
- Error handling
- Performance-oriented integer calculations
- Unit tests
"""

from __future__ import annotations

import ipaddress
import math
import unittest
from dataclasses import dataclass
from typing import Iterable, Optional


# ============================================================================
# 1. FUNDAMENTAL IPv4 CONCEPTS
# ============================================================================

def ipv4_to_binary(ip: str) -> str:
    """
    Convert an IPv4 address into its 32-bit binary representation.

    Example:
        192.168.1.10
        11000000.10101000.00000001.00001010
    """
    address = ipaddress.IPv4Address(ip)
    return ".".join(f"{octet:08b}" for octet in address.packed)


def binary_to_ipv4(binary: str) -> str:
    """
    Convert four 8-bit binary octets into dotted-decimal IPv4 notation.

    The function accepts:
        11000000.10101000.00000001.00001010

    and returns:
        192.168.1.10
    """
    parts = binary.split(".")

    if len(parts) != 4:
        raise ValueError("Binary IPv4 address must contain exactly four octets.")

    for part in parts:
        if len(part) != 8 or any(bit not in "01" for bit in part):
            raise ValueError("Each binary octet must contain exactly 8 bits.")

    decimal_parts = [str(int(part, 2)) for part in parts]
    return ".".join(decimal_parts)


def ipv4_to_integer(ip: str) -> int:
    """Represent an IPv4 address as a 32-bit integer."""
    return int(ipaddress.IPv4Address(ip))


def integer_to_ipv4(value: int) -> str:
    """Convert a 32-bit integer into an IPv4 address."""
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("IPv4 integer must be between 0 and 4,294,967,295.")
    return str(ipaddress.IPv4Address(value))


# ============================================================================
# 2. SUBNET MASKS AND PREFIX LENGTHS
# ============================================================================

def prefix_to_mask(prefix: int) -> str:
    """
    Convert a CIDR prefix length into a dotted-decimal subnet mask.

    /24 -> 255.255.255.0
    /16 -> 255.255.0.0
    /30 -> 255.255.255.252
    """
    if not 0 <= prefix <= 32:
        raise ValueError("IPv4 prefix length must be between 0 and 32.")

    network = ipaddress.IPv4Network(f"0.0.0.0/{prefix}")
    return str(network.netmask)


def mask_to_prefix(mask: str) -> int:
    """
    Convert a dotted-decimal subnet mask into a prefix length.

    The ipaddress module also validates that the mask is contiguous.

    Valid:
        255.255.255.0

    Invalid:
        255.0.255.0
    """
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except ValueError as exc:
        raise ValueError(f"Invalid contiguous IPv4 subnet mask: {mask}") from exc

    return network.prefixlen


def prefix_to_wildcard(prefix: int) -> str:
    """
    Convert a prefix length into a wildcard mask.

    A wildcard mask is the bitwise inverse of the subnet mask.

    /24:
        Subnet mask  = 255.255.255.0
        Wildcard     = 0.0.0.255
    """
    mask = int(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)
    wildcard = mask ^ 0xFFFFFFFF
    return str(ipaddress.IPv4Address(wildcard))


# ============================================================================
# 3. BASIC SUBNET MATHEMATICS
# ============================================================================

def total_addresses(prefix: int) -> int:
    """Return the total number of IPv4 addresses in a prefix."""
    if not 0 <= prefix <= 32:
        raise ValueError("Prefix must be between 0 and 32.")
    return 2 ** (32 - prefix)


def traditional_usable_hosts(prefix: int) -> int:
    """
    Return the traditional number of usable host addresses.

    Traditional subnetting reserves:
    - the network address
    - the broadcast address

    Therefore:
        usable = 2^host_bits - 2

    /30 -> 2 usable hosts
    /29 -> 6 usable hosts

    For /31 and /32, this traditional formula is not appropriate.
    """
    addresses = total_addresses(prefix)

    if prefix >= 31:
        return 0

    return addresses - 2


def host_bits(prefix: int) -> int:
    """Return the number of bits available for hosts."""
    if not 0 <= prefix <= 32:
        raise ValueError("Prefix must be between 0 and 32.")
    return 32 - prefix


def required_prefix_for_hosts(host_count: int) -> int:
    """
    Find the smallest IPv4 prefix capable of supporting host_count hosts
    under traditional network/broadcast reservations.

    Example:
        50 hosts -> /26
        100 hosts -> /25
        500 hosts -> /23
    """
    if host_count < 1:
        raise ValueError("Host count must be positive.")

    for prefix in range(31, -1, -1):
        if traditional_usable_hosts(prefix) >= host_count:
            return prefix

    raise ValueError("Requested host count cannot fit into an IPv4 subnet.")


def required_prefix_for_addresses(address_count: int) -> int:
    """
    Find the smallest IPv4 prefix containing at least address_count addresses.

    Unlike required_prefix_for_hosts(), this does not reserve network or
    broadcast addresses.
    """
    if address_count < 1:
        raise ValueError("Address count must be positive.")

    exponent = math.ceil(math.log2(address_count))

    if exponent > 32:
        raise ValueError("Requested address count exceeds IPv4 capacity.")

    return 32 - exponent


# ============================================================================
# 4. CORE SUBNET INFORMATION
# ============================================================================

@dataclass(frozen=True)
class SubnetInfo:
    """A structured representation of important subnet properties."""

    network: str
    prefix: int
    subnet_mask: str
    wildcard_mask: str
    first_address: str
    last_address: str
    broadcast: str
    total_addresses: int
    traditional_usable_hosts: int
    host_bits: int

    @property
    def cidr(self) -> str:
        return f"{self.network}/{self.prefix}"


def calculate_subnet(cidr: str) -> SubnetInfo:
    """
    Calculate the main properties of an IPv4 network.

    strict=False is intentional. If the input is a host address such as
    192.168.1.37/24, the function identifies the containing network:
    192.168.1.0/24.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 CIDR: {cidr}") from exc

    return SubnetInfo(
        network=str(network.network_address),
        prefix=network.prefixlen,
        subnet_mask=str(network.netmask),
        wildcard_mask=str(network.hostmask),
        first_address=str(network.network_address),
        last_address=str(network.broadcast_address),
        broadcast=str(network.broadcast_address),
        total_addresses=network.num_addresses,
        traditional_usable_hosts=(
            network.num_addresses - 2 if network.prefixlen < 31 else 0
        ),
        host_bits=32 - network.prefixlen,
    )


def usable_host_range(cidr: str) -> tuple[str, str]:
    """
    Return the traditional usable host range.

    /24:
        192.168.1.1 - 192.168.1.254

    /31:
        No traditional usable range.
    """
    network = ipaddress.IPv4Network(cidr, strict=False)

    if network.prefixlen >= 31:
        raise ValueError(
            "Traditional network/broadcast host range is not defined for /31 or /32."
        )

    return str(network.network_address + 1), str(network.broadcast_address - 1)


# ============================================================================
# 5. BINARY SUBNET CALCULATION
# ============================================================================

def binary_and(ip1: str, ip2: str) -> str:
    """
    Perform a bitwise AND between two IPv4 addresses.

    Subnetting uses:
        IP address AND subnet mask = network address
    """
    value1 = ipv4_to_integer(ip1)
    value2 = ipv4_to_integer(ip2)
    return integer_to_ipv4(value1 & value2)


def calculate_network_by_and(ip: str, mask: str) -> str:
    """Calculate the network address using a bitwise AND."""
    return binary_and(ip, mask)


def show_binary_subnet_calculation(ip: str, prefix: int) -> None:
    """
    Display the IP, mask, and network address in binary.

    This is useful for understanding exactly what subnetting does at the bit
    level.
    """
    mask = prefix_to_mask(prefix)
    network = calculate_network_by_and(ip, mask)

    print(f"IP address : {ip}")
    print(f"Binary IP  : {ipv4_to_binary(ip)}")
    print(f"Subnet mask: {mask}")
    print(f"Binary mask: {ipv4_to_binary(mask)}")
    print(f"Network    : {network}")
    print(f"Binary net : {ipv4_to_binary(network)}")


# ============================================================================
# 6. CIDR AND HOST MEMBERSHIP
# ============================================================================

def address_belongs_to_subnet(ip: str, cidr: str) -> bool:
    """Return True if an IPv4 address belongs to the specified subnet."""
    try:
        address = ipaddress.IPv4Address(ip)
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("Invalid IPv4 address or CIDR network.") from exc

    return address in network


def classify_address_in_subnet(ip: str, cidr: str) -> str:
    """
    Explain the role of an address inside a subnet.

    The function distinguishes network address, broadcast address, and host.
    """
    address = ipaddress.IPv4Address(ip)
    network = ipaddress.IPv4Network(cidr, strict=False)

    if address not in network:
        return "outside subnet"

    if address == network.network_address:
        return "network address"

    if address == network.broadcast_address:
        return "broadcast address"

    if network.prefixlen == 31:
        return "point-to-point address"

    if network.prefixlen == 32:
        return "single-host route"

    return "usable host address"


# ============================================================================
# 7. FIXED-LENGTH SUBNETTING
# ============================================================================

def subnet_count(parent_prefix: int, child_prefix: int) -> int:
    """
    Calculate how many equal-sized child subnets fit inside a parent subnet.

    Example:
        192.168.1.0/24 divided into /26:
        2^(26-24) = 4 subnets
    """
    if not 0 <= parent_prefix <= 32 or not 0 <= child_prefix <= 32:
        raise ValueError("Prefixes must be between 0 and 32.")

    if child_prefix < parent_prefix:
        raise ValueError("Child prefix must be equal to or longer than parent.")

    return 2 ** (child_prefix - parent_prefix)


def split_into_subnets(cidr: str, new_prefix: int) -> list[str]:
    """
    Divide a network into equal-sized child networks.

    Example:
        split_into_subnets("192.168.1.0/24", 26)

    produces:
        192.168.1.0/26
        192.168.1.64/26
        192.168.1.128/26
        192.168.1.192/26
    """
    network = ipaddress.IPv4Network(cidr, strict=False)

    if new_prefix < network.prefixlen:
        raise ValueError("New prefix must be equal to or longer than parent.")

    return [str(subnet) for subnet in network.subnets(new_prefix=new_prefix)]


def borrowed_bits(parent_prefix: int, child_prefix: int) -> int:
    """Return the number of host bits borrowed to create equal subnets."""
    if child_prefix < parent_prefix:
        raise ValueError("Child prefix cannot be shorter than parent prefix.")
    return child_prefix - parent_prefix


# ============================================================================
# 8. VLSM
# ============================================================================

@dataclass(frozen=True)
class VLSMRequirement:
    """Represents a department or site and its required host capacity."""

    name: str
    hosts_required: int


@dataclass(frozen=True)
class VLSMAllocation:
    """Represents an allocated VLSM subnet."""

    name: str
    requested_hosts: int
    cidr: str
    network: str
    first_host: Optional[str]
    last_host: Optional[str]
    broadcast: str
    total_addresses: int
    usable_hosts: int


def allocate_vlsm(
    parent_cidr: str,
    requirements: Iterable[VLSMRequirement],
) -> list[VLSMAllocation]:
    """
    Allocate variable-length subnets using a largest-first strategy.

    Largest requirements are allocated first because this reduces the risk
    of fragmentation in the remaining address space.

    The algorithm:
    1. Validate the parent network.
    2. Sort requirements by descending host demand.
    3. Select the smallest subnet capable of satisfying each requirement.
    4. Allocate sequentially from the beginning of the parent range.
    5. Raise an error if the parent network cannot satisfy all requirements.
    """
    parent = ipaddress.IPv4Network(parent_cidr, strict=False)

    sorted_requirements = sorted(
        requirements,
        key=lambda requirement: requirement.hosts_required,
        reverse=True,
    )

    allocations: list[VLSMAllocation] = []
    current = int(parent.network_address)
    parent_end = int(parent.broadcast_address)

    for requirement in sorted_requirements:
        if requirement.hosts_required < 1:
            raise ValueError(
                f"Host requirement for {requirement.name!r} must be positive."
            )

        prefix = required_prefix_for_hosts(requirement.hosts_required)
        block_size = total_addresses(prefix)

        # Align the starting address to the subnet's block boundary.
        aligned_current = ((current + block_size - 1) // block_size) * block_size

        if aligned_current + block_size - 1 > parent_end:
            raise ValueError(
                f"Insufficient address space to allocate {requirement.name!r}."
            )

        subnet = ipaddress.IPv4Network(
            (aligned_current, prefix),
            strict=False,
        )

        if not subnet.subnet_of(parent):
            raise ValueError(
                f"Allocation for {requirement.name!r} falls outside parent network."
            )

        if subnet.prefixlen < 31:
            first_host = str(subnet.network_address + 1)
            last_host = str(subnet.broadcast_address - 1)
            usable = subnet.num_addresses - 2
        else:
            first_host = None
            last_host = None
            usable = 0

        allocations.append(
            VLSMAllocation(
                name=requirement.name,
                requested_hosts=requirement.hosts_required,
                cidr=str(subnet),
                network=str(subnet.network_address),
                first_host=first_host,
                last_host=last_host,
                broadcast=str(subnet.broadcast_address),
                total_addresses=subnet.num_addresses,
                usable_hosts=usable,
            )
        )

        current = int(subnet.broadcast_address) + 1

    return allocations


# ============================================================================
# 9. SUPERNETTING AND ROUTE AGGREGATION
# ============================================================================

def summarize_networks(networks: Iterable[str]) -> list[str]:
    """
    Produce the smallest set of CIDR networks covering the supplied networks.

    The standard library's collapse_addresses() performs CIDR aggregation.

    Aggregation is useful for reducing routing-table entries when networks
    are contiguous and correctly aligned.
    """
    parsed = [ipaddress.IPv4Network(network, strict=False) for network in networks]

    if not parsed:
        return []

    return [str(network) for network in ipaddress.collapse_addresses(parsed)]


def common_prefix_length(ip1: str, ip2: str) -> int:
    """
    Return the number of leading bits shared by two IPv4 addresses.

    This demonstrates how a common prefix can be derived from XOR.
    """
    value1 = ipv4_to_integer(ip1)
    value2 = ipv4_to_integer(ip2)

    xor_value = value1 ^ value2

    if xor_value == 0:
        return 32

    return 32 - xor_value.bit_length()


def smallest_covering_network(ip1: str, ip2: str) -> str:
    """
    Return the smallest CIDR network containing both IPv4 addresses.
    """
    prefix = common_prefix_length(ip1, ip2)
    network_value = ipv4_to_integer(ip1) & int(
        ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
    )

    return f"{integer_to_ipv4(network_value)}/{prefix}"


# ============================================================================
# 10. PRIVATE AND SPECIAL IPv4 RANGES
# ============================================================================

PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def is_private_rfc1918(ip: str) -> bool:
    """
    Check specifically for the three RFC 1918 private address blocks.

    This is intentionally different from IPv4Address.is_private, which also
    recognizes other special-use address ranges.
    """
    address = ipaddress.IPv4Address(ip)
    return any(address in network for network in PRIVATE_NETWORKS)


def describe_address_type(ip: str) -> list[str]:
    """Return useful classifications exposed by Python's IPv4Address API."""
    address = ipaddress.IPv4Address(ip)
    descriptions = []

    if address.is_private:
        descriptions.append("private/special-purpose according to Python's API")

    if address.is_loopback:
        descriptions.append("loopback")

    if address.is_link_local:
        descriptions.append("link-local")

    if address.is_multicast:
        descriptions.append("multicast")

    if address.is_unspecified:
        descriptions.append("unspecified")

    if address.is_reserved:
        descriptions.append("reserved")

    if not descriptions:
        descriptions.append("ordinary globally routable-looking IPv4 address")

    return descriptions


# ============================================================================
# 11. EDGE CASES: /31 AND /32
# ============================================================================

def explain_special_prefix(prefix: int) -> str:
    """
    Explain why /31 and /32 differ from ordinary host subnets.

    /31 is commonly used for point-to-point links where the traditional
    network/broadcast distinction is not needed.

    /32 represents exactly one IPv4 address and is often used for host routes,
    loopback-style identifiers, or precise routing entries.
    """
    if prefix == 31:
        return (
            "/31 contains two addresses and is commonly used for point-to-point "
            "links. Traditional network/broadcast host counting does not apply."
        )

    if prefix == 32:
        return (
            "/32 contains exactly one address and identifies a single host or "
            "route rather than a normal multi-host subnet."
        )

    return "This prefix follows ordinary IPv4 subnet behavior."


# ============================================================================
# 12. SUBNET PLANNING HELPERS
# ============================================================================

def subnet_for_host_requirement(hosts: int) -> dict[str, object]:
    """
    Determine a suitable prefix and explain its capacity.

    Example:
        60 hosts -> /26
        total addresses = 64
        traditional usable = 62
    """
    prefix = required_prefix_for_hosts(hosts)

    return {
        "requested_hosts": hosts,
        "prefix": prefix,
        "cidr_size": f"/{prefix}",
        "subnet_mask": prefix_to_mask(prefix),
        "total_addresses": total_addresses(prefix),
        "usable_hosts": traditional_usable_hosts(prefix),
        "wildcard_mask": prefix_to_wildcard(prefix),
    }


def address_efficiency(hosts_required: int, prefix: int) -> float:
    """
    Calculate the percentage of traditional usable addresses actually needed.

    This helps compare address utilization during subnet planning.
    """
    capacity = traditional_usable_hosts(prefix)

    if capacity <= 0:
        return 0.0

    return (hosts_required / capacity) * 100.0


# ============================================================================
# 13. PRACTICAL EXAMPLES
# ============================================================================

def example_basic_subnet() -> None:
    print("\n=== BASIC SUBNET CALCULATION ===")

    cidr = "192.168.10.37/24"
    info = calculate_subnet(cidr)

    print(f"Input CIDR              : {cidr}")
    print(f"Normalized network      : {info.cidr}")
    print(f"Subnet mask             : {info.subnet_mask}")
    print(f"Wildcard mask           : {info.wildcard_mask}")
    print(f"Network address         : {info.network}")
    print(f"First address           : {info.first_address}")
    print(f"Last address            : {info.last_address}")
    print(f"Broadcast address       : {info.broadcast}")
    print(f"Total addresses         : {info.total_addresses}")
    print(f"Traditional usable host : {info.traditional_usable_hosts}")


def example_subnetting_24_to_26() -> None:
    print("\n=== DIVIDING /24 INTO /26 SUBNETS ===")

    parent = "192.168.1.0/24"
    children = split_into_subnets(parent, 26)

    print(f"Parent network : {parent}")
    print("New prefix     : /26")
    print(f"Number of subnets: {len(children)}")
    print(f"Expected count : {subnet_count(24, 26)}")

    for index, child in enumerate(children, start=1):
        network = ipaddress.IPv4Network(child)
        print(
            f"Subnet {index}: {child:18} "
            f"hosts={network.num_addresses - 2:2} "
            f"range={network.network_address + 1} - "
            f"{network.broadcast_address - 1}"
        )


def example_binary_and() -> None:
    print("\n=== BINARY AND CALCULATION ===")

    show_binary_subnet_calculation("192.168.10.77", 26)


def example_host_requirements() -> None:
    print("\n=== HOST REQUIREMENT CALCULATIONS ===")

    for hosts in [2, 6, 14, 30, 50, 62, 100, 250, 500, 1000]:
        result = subnet_for_host_requirement(hosts)

        print(
            f"{hosts:4} hosts -> {result['cidr_size']:>3} | "
            f"mask={result['subnet_mask']} | "
            f"usable={result['usable_hosts']}"
        )


def example_membership() -> None:
    print("\n=== SUBNET MEMBERSHIP ===")

    cidr = "10.20.30.0/24"

    test_addresses = [
        "10.20.30.1",
        "10.20.30.100",
        "10.20.31.1",
        "10.20.30.0",
        "10.20.30.255",
    ]

    for ip in test_addresses:
        print(
            f"{ip:15} -> "
            f"{classify_address_in_subnet(ip, cidr)}"
        )


def example_vlsm() -> None:
    print("\n=== VLSM ADDRESS PLANNING ===")

    parent = "10.0.0.0/24"

    requirements = [
        VLSMRequirement("Engineering", 100),
        VLSMRequirement("Finance", 50),
        VLSMRequirement("HR", 25),
        VLSMRequirement("Point-to-point link", 2),
    ]

    allocations = allocate_vlsm(parent, requirements)

    print(f"Parent network: {parent}")

    for allocation in allocations:
        print(
            f"{allocation.name:20} "
            f"requested={allocation.requested_hosts:3} "
            f"allocated={allocation.cidr:18} "
            f"usable={allocation.usable_hosts:3}"
        )


def example_summarization() -> None:
    print("\n=== CIDR ROUTE SUMMARIZATION ===")

    networks = [
        "192.168.0.0/24",
        "192.168.1.0/24",
        "192.168.2.0/24",
        "192.168.3.0/24",
    ]

    summary = summarize_networks(networks)

    print("Input networks:")
    for network in networks:
        print(f"  {network}")

    print("Aggregated result:")
    for network in summary:
        print(f"  {network}")


def example_common_prefix() -> None:
    print("\n=== COMMON PREFIX ===")

    ip1 = "192.168.10.20"
    ip2 = "192.168.10.200"

    prefix = common_prefix_length(ip1, ip2)
    covering = smallest_covering_network(ip1, ip2)

    print(f"Address 1              : {ip1}")
    print(f"Address 2              : {ip2}")
    print(f"Shared leading bits    : {prefix}")
    print(f"Smallest covering CIDR : {covering}")


def example_private_addresses() -> None:
    print("\n=== PRIVATE ADDRESS RANGES ===")

    addresses = [
        "10.10.10.10",
        "172.16.5.20",
        "172.31.255.254",
        "192.168.1.100",
        "8.8.8.8",
    ]

    for ip in addresses:
        print(
            f"{ip:15} -> "
            f"RFC1918 private={is_private_rfc1918(ip)}"
        )


def example_special_prefixes() -> None:
    print("\n=== /31 AND /32 EDGE CASES ===")

    for prefix in [30, 31, 32]:
        network = ipaddress.IPv4Network(f"192.0.2.0/{prefix}", strict=False)

        print(
            f"{network}: "
            f"addresses={network.num_addresses}, "
            f"traditional_usable={traditional_usable_hosts(prefix)}, "
            f"{explain_special_prefix(prefix)}"
        )


def example_address_efficiency() -> None:
    print("\n=== ADDRESS UTILIZATION ===")

    requirements = [
        ("Small office", 10, 28),
        ("Department", 50, 26),
        ("Large department", 100, 25),
        ("Data center segment", 500, 23),
    ]

    for name, required, prefix in requirements:
        capacity = traditional_usable_hosts(prefix)
        efficiency = address_efficiency(required, prefix)

        print(
            f"{name:20} "
            f"required={required:4} "
            f"capacity={capacity:4} "
            f"utilization={efficiency:6.2f}%"
        )


# ============================================================================
# 14. ERROR HANDLING EXAMPLES
# ============================================================================

def demonstrate_validation() -> None:
    print("\n=== VALIDATION AND ERROR HANDLING ===")

    invalid_values = [
        "300.1.1.1",
        "192.168.1.1/33",
        "192.168.1.1/not-a-prefix",
        "255.0.255.0",
    ]

    for value in invalid_values:
        try:
            if "/" in value:
                calculate_subnet(value)
            elif value.count(".") == 3:
                mask_to_prefix(value)
            else:
                ipv4_to_binary(value)

            print(f"{value}: unexpectedly accepted")
        except ValueError as exc:
            print(f"{value}: rejected correctly -> {exc}")


# ============================================================================
# 15. ADVANCED ADDRESS-PLANNING EXAMPLE
# ============================================================================

def advanced_network_design() -> None:
    """
    Design several departments from a /20 block.

    This demonstrates how VLSM can create different subnet sizes instead of
    assigning every department an identical subnet.
    """
    print("\n=== ADVANCED VLSM NETWORK DESIGN ===")

    parent = "172.20.0.0/20"

    requirements = [
        VLSMRequirement("Data center", 700),
        VLSMRequirement("Engineering", 400),
        VLSMRequirement("Operations", 180),
        VLSMRequirement("Sales", 90),
        VLSMRequirement("HR", 40),
        VLSMRequirement("Management", 20),
        VLSMRequirement("Network links", 10),
    ]

    allocations = allocate_vlsm(parent, requirements)

    for allocation in allocations:
        print(
            f"{allocation.name:20} "
            f"{allocation.cidr:18} "
            f"usable={allocation.usable_hosts:4} "
            f"requested={allocation.requested_hosts:4}"
        )


# ============================================================================
# 16. PERFORMANCE CONSIDERATIONS
# ============================================================================

def benchmark_style_integer_calculation() -> None:
    """
    Demonstrate why integer representations can be useful for repeated
    address calculations.

    Python's ipaddress module is normally preferable for clarity and
    correctness. Direct integer operations can be useful inside high-volume
    algorithms where the representation and validation strategy are controlled.
    """
    print("\n=== INTEGER-BASED ADDRESS CALCULATION ===")

    ip = "192.168.50.123"
    prefix = 24

    ip_value = ipv4_to_integer(ip)
    mask_value = int(ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask)

    network_value = ip_value & mask_value
    broadcast_value = network_value | (mask_value ^ 0xFFFFFFFF)

    print(f"IP integer        : {ip_value}")
    print(f"Mask integer      : {mask_value}")
    print(f"Network integer   : {network_value}")
    print(f"Network address   : {integer_to_ipv4(network_value)}")
    print(f"Broadcast address : {integer_to_ipv4(broadcast_value)}")


# ============================================================================
# 17. COMPARISON OF SUBNET TYPES
# ============================================================================

def compare_common_prefixes() -> None:
    print("\n=== PREFIX CAPACITY COMPARISON ===")

    prefixes = [8, 12, 16, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32]

    print(
        f"{'Prefix':>6} "
        f"{'Mask':>15} "
        f"{'Host bits':>9} "
        f"{'Total':>12} "
        f"{'Traditional usable':>20}"
    )

    for prefix in prefixes:
        print(
            f"/{prefix:<5} "
            f"{prefix_to_mask(prefix):>15} "
            f"{host_bits(prefix):>9} "
            f"{total_addresses(prefix):>12} "
            f"{traditional_usable_hosts(prefix):>20}"
        )


# ============================================================================
# 18. STUDY CHECKS
# ============================================================================

def run_study_checks() -> None:
    """
    Small knowledge checks expressed as executable assertions.

    These are intentionally simple. They reinforce the core subnetting rules.
    """
    print("\n=== STUDY CHECKS ===")

    assert prefix_to_mask(24) == "255.255.255.0"
    assert prefix_to_mask(16) == "255.255.0.0"
    assert mask_to_prefix("255.255.255.0") == 24

    assert total_addresses(24) == 256
    assert traditional_usable_hosts(24) == 254

    assert calculate_subnet("192.168.1.99/24").network == "192.168.1.0"
    assert calculate_subnet("10.0.15.200/20").network == "10.0.0.0"

    assert address_belongs_to_subnet(
        "192.168.1.100",
        "192.168.1.0/24",
    )

    assert not address_belongs_to_subnet(
        "192.168.2.100",
        "192.168.1.0/24",
    )

    assert subnet_count(24, 26) == 4
    assert borrowed_bits(24, 26) == 2

    assert binary_to_ipv4(
        "11000000.10101000.00000001.00001010"
    ) == "192.168.1.10"

    assert binary_and(
        "192.168.1.77",
        "255.255.255.192",
    ) == "192.168.1.64"

    assert required_prefix_for_hosts(50) == 26
    assert required_prefix_for_hosts(100) == 25

    print("All study checks passed.")


# ============================================================================
# 19. UNIT TESTS
# ============================================================================

class TestSubnetting(unittest.TestCase):
    """Automated tests for important subnetting operations."""

    def test_binary_conversion(self) -> None:
        ip = "192.168.1.10"
        self.assertEqual(binary_to_ipv4(ipv4_to_binary(ip)), ip)

    def test_prefix_mask_conversion(self) -> None:
        self.assertEqual(prefix_to_mask(24), "255.255.255.0")
        self.assertEqual(mask_to_prefix("255.255.255.0"), 24)

    def test_basic_network(self) -> None:
        info = calculate_subnet("192.168.1.37/24")

        self.assertEqual(info.network, "192.168.1.0")
        self.assertEqual(info.broadcast, "192.168.1.255")
        self.assertEqual(info.total_addresses, 256)
        self.assertEqual(info.traditional_usable_hosts, 254)

    def test_non_octet_prefix(self) -> None:
        info = calculate_subnet("192.168.1.77/26")

        self.assertEqual(info.network, "192.168.1.64")
        self.assertEqual(info.broadcast, "192.168.1.127")

    def test_membership(self) -> None:
        self.assertTrue(
            address_belongs_to_subnet(
                "10.10.10.100",
                "10.10.10.0/24",
            )
        )

        self.assertFalse(
            address_belongs_to_subnet(
                "10.10.11.100",
                "10.10.10.0/24",
            )
        )

    def test_subnet_count(self) -> None:
        self.assertEqual(subnet_count(24, 26), 4)
        self.assertEqual(subnet_count(16, 20), 16)

    def test_split_subnets(self) -> None:
        result = split_into_subnets("192.168.1.0/24", 26)

        self.assertEqual(
            result,
            [
                "192.168.1.0/26",
                "192.168.1.64/26",
                "192.168.1.128/26",
                "192.168.1.192/26",
            ],
        )

    def test_host_requirement(self) -> None:
        self.assertEqual(required_prefix_for_hosts(2), 29)
        self.assertEqual(required_prefix_for_hosts(6), 29)
        self.assertEqual(required_prefix_for_hosts(14), 28)
        self.assertEqual(required_prefix_for_hosts(30), 27)
        self.assertEqual(required_prefix_for_hosts(50), 26)

    def test_vlsm(self) -> None:
        requirements = [
            VLSMRequirement("A", 50),
            VLSMRequirement("B", 20),
            VLSMRequirement("C", 10),
        ]

        allocations = allocate_vlsm("192.168.10.0/24", requirements)

        self.assertEqual(allocations[0].cidr, "192.168.10.0/26")
        self.assertEqual(allocations[1].cidr, "192.168.10.64/27")
        self.assertEqual(allocations[2].cidr, "192.168.10.96/28")

    def test_summarization(self) -> None:
        networks = [
            "192.168.0.0/24",
            "192.168.1.0/24",
            "192.168.2.0/24",
            "192.168.3.0/24",
        ]

        self.assertEqual(
            summarize_networks(networks),
            ["192.168.0.0/22"],
        )

    def test_special_prefixes(self) -> None:
        self.assertEqual(total_addresses(31), 2)
        self.assertEqual(total_addresses(32), 1)

    def test_invalid_prefix(self) -> None:
        with self.assertRaises(ValueError):
            prefix_to_mask(33)

    def test_invalid_mask(self) -> None:
        with self.assertRaises(ValueError):
            mask_to_prefix("255.0.255.0")


def run_unit_tests() -> None:
    """
    Run the test suite without allowing unittest to terminate the whole
    educational demonstration unexpectedly.
    """
    print("\n=== UNIT TESTS ===")

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestSubnetting)
    result = unittest.TextTestRunner(verbosity=1).run(suite)

    if not result.wasSuccessful():
        raise RuntimeError("One or more subnetting tests failed.")


# ============================================================================
# 20. MAIN PROGRAM
# ============================================================================

def main() -> None:
    """
    Execute the complete subnetting study program.

    The order follows the learning progression:
        representation
        masks
        arithmetic
        subnet calculation
        binary mechanics
        subnet splitting
        VLSM
        aggregation
        special cases
        validation
        planning
        tests
    """
    print("=" * 78)
    print("IPv4 SUBNETTING STUDY PROGRAM")
    print("CIDR | Subnet Masks | Prefix Lengths | Network Calculation | Host Ranges")
    print("=" * 78)

    example_basic_subnet()
    example_subnetting_24_to_26()
    example_binary_and()
    example_host_requirements()
    example_membership()
    example_vlsm()
    example_summarization()
    example_common_prefix()
    example_private_addresses()
    example_special_prefixes()
    example_address_efficiency()
    demonstrate_validation()
    advanced_network_design()
    benchmark_style_integer_calculation()
    compare_common_prefixes()
    run_study_checks()
    run_unit_tests()

    print("\n=== BASIC REFERENCE ===")
    print("CIDR prefix length = number of network bits.")
    print("Host bits = 32 - prefix length.")
    print("Total addresses = 2^(host bits).")
    print("Traditional usable hosts = total addresses - 2.")
    print("Network address = IP address AND subnet mask.")
    print("Broadcast address = network address OR wildcard mask.")
    print("Longer prefix = smaller subnet.")
    print("Shorter prefix = larger subnet.")
    print("VLSM assigns different subnet sizes according to demand.")
    print("CIDR summarization combines aligned networks into shorter prefixes.")
    print("=" * 78)


if __name__ == "__main__":
    main()
