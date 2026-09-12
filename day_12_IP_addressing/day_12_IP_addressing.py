"""
IP ADDRESSING: IPv4, Binary, Decimal, Network ID, Host ID, Public/Private Addresses

A self-contained study script that teaches IPv4 addressing from absolute beginner
through advanced practical concepts.

The script uses only Python's standard library and demonstrates:
- IPv4 structure and terminology
- Decimal and binary representation
- IPv4 validation
- Binary conversion
- Network ID and host ID
- Subnet masks and prefix notation
- Network and broadcast addresses
- Host ranges
- Public and private IPv4 addresses
- Special IPv4 ranges
- Classful addressing and its historical limitations
- CIDR
- Subnetting
- VLSM
- Address capacity calculations
- Same-subnet decisions
- Routing-table style longest-prefix matching
- Private-address detection
- NAT concepts
- Address planning
- Edge cases and common mistakes
- Performance-conscious integer-based calculations
- Testing and practical diagnostics

Run the file directly with:
    python ip_addressing.py
"""

from __future__ import annotations

import ipaddress
import math
from dataclasses import dataclass
from typing import Iterable, Optional


# =============================================================================
# 1. BASIC IPv4 CONCEPTS
# =============================================================================

def print_section(title: str) -> None:
    """Print a readable section heading."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_ipv4_basics() -> None:
    """
    Introduce IPv4 at the conceptual level.

    IPv4 uses 32 bits.
    Those 32 bits are normally written as four decimal octets:
        192.168.1.10

    Each octet contains 8 bits, so:
        8 + 8 + 8 + 8 = 32 bits

    Every octet ranges from 0 through 255 because:
        2^8 = 256 possible values
        0 through 255 gives 256 values.
    """
    print_section("1. IPv4 fundamentals")

    print("IPv4 is a 32-bit logical addressing system.")
    print("An IPv4 address contains four 8-bit octets.")
    print("Example:", "192.168.1.10")
    print("Number of bits:", 32)
    print("Bits per octet:", 8)
    print("Possible values in one octet:", 0, "through", 255)

    address = "192.168.1.10"
    octets = address.split(".")

    print("\nAddress:", address)
    for position, octet in enumerate(octets, start=1):
        value = int(octet)
        print(f"Octet {position}: {value:3d} = {value:08b}")

    print("\nThe binary form is:")
    print(".".join(f"{int(o):08b}" for o in octets))


# =============================================================================
# 2. DECIMAL <-> BINARY CONVERSION
# =============================================================================

def decimal_octet_to_binary(value: int) -> str:
    """
    Convert one decimal IPv4 octet to exactly eight binary digits.

    Valid input:
        0 through 255
    """
    if not isinstance(value, int):
        raise TypeError("An IPv4 octet must be an integer.")

    if not 0 <= value <= 255:
        raise ValueError("An IPv4 octet must be between 0 and 255.")

    return format(value, "08b")


def binary_octet_to_decimal(bits: str) -> int:
    """
    Convert exactly eight binary digits into a decimal IPv4 octet.
    """
    if not isinstance(bits, str):
        raise TypeError("Binary input must be a string.")

    if len(bits) != 8 or any(bit not in "01" for bit in bits):
        raise ValueError("An IPv4 binary octet must contain exactly 8 bits.")

    return int(bits, 2)


def ipv4_to_binary(address: str) -> str:
    """
    Convert dotted-decimal IPv4 into dotted-binary representation.

    Example:
        192.168.1.10
    becomes:
        11000000.10101000.00000001.00001010
    """
    octets = address.split(".")

    if len(octets) != 4:
        raise ValueError("IPv4 must contain exactly four octets.")

    binary_octets = []
    for octet in octets:
        if not octet.isdigit():
            raise ValueError(f"Invalid decimal octet: {octet}")

        binary_octets.append(decimal_octet_to_binary(int(octet)))

    return ".".join(binary_octets)


def binary_to_ipv4(binary_address: str) -> str:
    """
    Convert dotted eight-bit binary IPv4 into dotted decimal.
    """
    octets = binary_address.split(".")

    if len(octets) != 4:
        raise ValueError("Binary IPv4 must contain four octets.")

    decimal_octets = [
        str(binary_octet_to_decimal(octet))
        for octet in octets
    ]

    return ".".join(decimal_octets)


def demonstrate_binary_conversion() -> None:
    print_section("2. Binary and decimal conversion")

    values = [0, 1, 10, 127, 128, 192, 224, 255]

    print("Decimal to binary:")
    for value in values:
        print(f"{value:3d} -> {decimal_octet_to_binary(value)}")

    address = "192.168.1.10"
    binary = ipv4_to_binary(address)

    print("\nIPv4 conversion:")
    print("Decimal:", address)
    print("Binary :", binary)
    print("Back   :", binary_to_ipv4(binary))

    print("\nBinary place values for one octet:")
    print("128 64 32 16 8 4 2 1")
    print("Example for 192:")
    print("1   1   0  0  0 0 0 0")
    print("128 + 64 = 192")


# =============================================================================
# 3. VALIDATION
# =============================================================================

def is_valid_ipv4(address: str) -> bool:
    """Return True only when the input is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def validate_ipv4_examples() -> None:
    print_section("3. IPv4 validation")

    examples = [
        "192.168.1.10",
        "10.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "256.1.1.1",
        "192.168.1",
        "192.168.1.999",
        "hello.world.1.1",
    ]

    for address in examples:
        print(f"{address:20s} -> {is_valid_ipv4(address)}")


# =============================================================================
# 4. IPv4 AS A 32-BIT INTEGER
# =============================================================================

def ipv4_to_integer(address: str) -> int:
    """
    Convert IPv4 into its unsigned 32-bit integer representation.

    This representation is useful for:
    - comparisons
    - range calculations
    - subnet operations
    - efficient routing-table matching
    """
    return int(ipaddress.IPv4Address(address))


def integer_to_ipv4(value: int) -> str:
    """Convert an integer in the IPv4 range back to dotted decimal."""
    if not isinstance(value, int):
        raise TypeError("IPv4 integer must be an integer.")

    if not 0 <= value <= 2**32 - 1:
        raise ValueError("IPv4 integer must be between 0 and 2^32 - 1.")

    return str(ipaddress.IPv4Address(value))


def demonstrate_integer_representation() -> None:
    print_section("4. IPv4 as a 32-bit integer")

    address = "192.168.1.10"
    value = ipv4_to_integer(address)

    print("IPv4 address :", address)
    print("Integer      :", value)
    print("32-bit binary:", f"{value:032b}")
    print("Converted back:", integer_to_ipv4(value))

    print("\nThe integer representation allows direct numerical comparison.")
    print("For example:")
    print("10.0.0.1 integer <", "10.0.0.2 integer:",
          ipv4_to_integer("10.0.0.1") < ipv4_to_integer("10.0.0.2"))


# =============================================================================
# 5. SUBNET MASKS AND PREFIX LENGTHS
# =============================================================================

def prefix_to_mask(prefix_length: int) -> str:
    """Convert a CIDR prefix length into a dotted-decimal subnet mask."""
    if not isinstance(prefix_length, int):
        raise TypeError("Prefix length must be an integer.")

    if not 0 <= prefix_length <= 32:
        raise ValueError("IPv4 prefix length must be between 0 and 32.")

    network = ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}")
    return str(network.netmask)


def mask_to_prefix(mask: str) -> int:
    """Convert a valid contiguous IPv4 subnet mask into prefix length."""
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 subnet mask: {mask}") from exc

    return network.prefixlen


def mask_to_binary(mask: str) -> str:
    """Return an IPv4 subnet mask in dotted binary notation."""
    return ipv4_to_binary(mask)


def demonstrate_masks() -> None:
    print_section("5. Subnet masks and CIDR prefixes")

    prefixes = [8, 16, 20, 24, 25, 26, 27, 28, 30, 32]

    print(f"{'Prefix':>8} {'Subnet mask':>18} {'Binary mask'}")
    print("-" * 68)

    for prefix in prefixes:
        mask = prefix_to_mask(prefix)
        binary = mask_to_binary(mask)
        print(f"/{prefix:<7} {mask:>18} {binary}")

    print("\nExamples:")
    print("255.255.255.0 corresponds to /24")
    print("255.255.255.128 corresponds to /25")
    print("255.255.255.192 corresponds to /26")


# =============================================================================
# 6. NETWORK ID, HOST ID, BROADCAST ADDRESS
# =============================================================================

@dataclass
class IPv4NetworkDetails:
    """Structured information about an IPv4 network."""

    address: str
    network: str
    prefix_length: int
    subnet_mask: str
    broadcast: str
    first_usable: Optional[str]
    last_usable: Optional[str]
    total_addresses: int
    usable_hosts: int
    host_bits: int


def analyze_network(address_with_prefix: str) -> IPv4NetworkDetails:
    """
    Analyze an IPv4 network.

    Example:
        192.168.1.25/24

    Network ID:
        192.168.1.0

    Broadcast:
        192.168.1.255

    Host portion:
        the bits not covered by the /24 prefix.
    """
    interface = ipaddress.IPv4Interface(address_with_prefix)
    network = interface.network

    total = network.num_addresses

    # For /31 and /32, the traditional concept of usable hosts is different.
    # ipaddress intentionally treats /31 as a two-address point-to-point network.
    if network.prefixlen == 32:
        first_usable = None
        last_usable = None
        usable_hosts = 1
    elif network.prefixlen == 31:
        first_usable = str(network.network_address)
        last_usable = str(network.broadcast_address)
        usable_hosts = 2
    else:
        first_usable = str(network.network_address + 1)
        last_usable = str(network.broadcast_address - 1)
        usable_hosts = max(total - 2, 0)

    return IPv4NetworkDetails(
        address=str(interface.ip),
        network=str(network.network_address),
        prefix_length=network.prefixlen,
        subnet_mask=str(network.netmask),
        broadcast=str(network.broadcast_address),
        first_usable=first_usable,
        last_usable=last_usable,
        total_addresses=total,
        usable_hosts=usable_hosts,
        host_bits=32 - network.prefixlen,
    )


def display_network_analysis(address_with_prefix: str) -> None:
    details = analyze_network(address_with_prefix)

    print(f"\nAddress             : {details.address}")
    print(f"Network ID          : {details.network}")
    print(f"Prefix length       : /{details.prefix_length}")
    print(f"Subnet mask         : {details.subnet_mask}")
    print(f"Broadcast address   : {details.broadcast}")
    print(f"First usable host   : {details.first_usable}")
    print(f"Last usable host    : {details.last_usable}")
    print(f"Total addresses     : {details.total_addresses}")
    print(f"Usable hosts        : {details.usable_hosts}")
    print(f"Host bits           : {details.host_bits}")


def demonstrate_network_and_host_ids() -> None:
    print_section("6. Network ID, host ID and broadcast address")

    examples = [
        "192.168.1.25/24",
        "192.168.1.130/26",
        "10.20.30.40/20",
        "172.16.50.100/16",
    ]

    for example in examples:
        display_network_analysis(example)

    print("\nConceptual rule:")
    print("Network bits identify the subnet.")
    print("Host bits identify an address within that subnet.")
    print("For a /24 network:")
    print("  Network bits = 24")
    print("  Host bits    = 8")
    print("  Total addresses = 2^8 = 256")


# =============================================================================
# 7. NETWORK AND HOST BITS IN BINARY
# =============================================================================

def binary_network_visualization(address_with_prefix: str) -> None:
    """
    Display network and host bits.

    Example:
        192.168.1.25/24

    Network bits:
        11000000.10101000.00000001
    Host bits:
        00011001
    """
    interface = ipaddress.IPv4Interface(address_with_prefix)
    address_bits = f"{int(interface.ip):032b}"

    network_bits = address_bits[: interface.network.prefixlen]
    host_bits = address_bits[interface.network.prefixlen :]

    print("\nAddress:", interface.ip)
    print("Prefix :", f"/{interface.network.prefixlen}")
    print("Binary :", address_bits)
    print("Network:", network_bits)
    print("Host   :", host_bits)

    grouped_network = (
        network_bits + ("-" * len(host_bits))
    )

    print("Visual :", grouped_network)


def demonstrate_bitwise_network_calculation() -> None:
    print_section("7. Finding network ID using binary and bitwise logic")

    address = "192.168.1.130"
    mask = "255.255.255.192"

    address_int = ipv4_to_integer(address)
    mask_int = ipv4_to_integer(mask)
    network_int = address_int & mask_int

    print("Address:", address)
    print("Mask   :", mask)
    print("Address binary:", f"{address_int:032b}")
    print("Mask binary   :", f"{mask_int:032b}")
    print("AND result    :", f"{network_int:032b}")
    print("Network ID    :", integer_to_ipv4(network_int))

    binary_network_visualization("192.168.1.130/26")


# =============================================================================
# 8. HOST CAPACITY
# =============================================================================

def total_ipv4_addresses(prefix_length: int) -> int:
    """Return the total number of addresses in a prefix."""
    if not 0 <= prefix_length <= 32:
        raise ValueError("Prefix must be between 0 and 32.")

    return 2 ** (32 - prefix_length)


def traditional_usable_hosts(prefix_length: int) -> int:
    """
    Calculate traditional usable host count.

    For /31 and /32, ordinary subnet arithmetic needs special treatment.
    """
    total = total_ipv4_addresses(prefix_length)

    if prefix_length == 32:
        return 1

    if prefix_length == 31:
        return 2

    return max(total - 2, 0)


def demonstrate_host_capacity() -> None:
    print_section("8. Address and host capacity")

    print(f"{'Prefix':>8} {'Total':>12} {'Traditional usable hosts':>28}")
    print("-" * 52)

    for prefix in range(16, 33):
        print(
            f"/{prefix:<7}"
            f"{total_ipv4_addresses(prefix):>12}"
            f"{traditional_usable_hosts(prefix):>28}"
        )

    print("\nThe familiar formula for ordinary subnets is:")
    print("usable hosts = 2^(host bits) - 2")
    print("The subtraction accounts for network and broadcast addresses.")
    print("That rule does not describe /31 point-to-point links correctly.")


# =============================================================================
# 9. PUBLIC AND PRIVATE IPv4 ADDRESSES
# =============================================================================

PRIVATE_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def is_private_rfc1918(address: str) -> bool:
    """Check specifically for the three RFC 1918 private address ranges."""
    ip = ipaddress.IPv4Address(address)
    return any(ip in network for network in PRIVATE_NETWORKS)


def classify_special_ipv4(address: str) -> list[str]:
    """
    Return useful classifications for an IPv4 address.

    A single address may satisfy more than one conceptual category, so a list
    is more informative than a single mutually exclusive label.
    """
    ip = ipaddress.IPv4Address(address)
    classifications: list[str] = []

    if is_private_rfc1918(address):
        classifications.append("RFC 1918 private")

    if ip.is_loopback:
        classifications.append("loopback")

    if ip.is_link_local:
        classifications.append("IPv4 link-local")

    if ip.is_multicast:
        classifications.append("multicast")

    if ip.is_unspecified:
        classifications.append("unspecified")

    if ip.is_reserved:
        classifications.append("reserved")

    if not classifications:
        classifications.append("ordinary globally routable candidate")

    return classifications


def demonstrate_public_private_addresses() -> None:
    print_section("9. Public, private and special IPv4 addresses")

    examples = [
        "10.0.0.1",
        "10.255.255.254",
        "172.16.0.1",
        "172.31.255.254",
        "172.32.0.1",
        "192.168.1.1",
        "192.168.0.1",
        "8.8.8.8",
        "127.0.0.1",
        "169.254.10.20",
        "224.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
    ]

    for address in examples:
        print(
            f"{address:16s} "
            f"private={is_private_rfc1918(address)!s:5s} "
            f"classification={', '.join(classify_special_ipv4(address))}"
        )

    print("\nRFC 1918 private IPv4 ranges:")
    print("10.0.0.0/8")
    print("172.16.0.0/12")
    print("192.168.0.0/16")

    print("\nImportant distinction:")
    print("Private does not mean 'secret'.")
    print("Private addresses are normally not directly routed across the public Internet.")
    print("NAT commonly allows private-addressed hosts to communicate externally.")


# =============================================================================
# 10. CLASSFUL ADDRESSING
# =============================================================================

def classful_ipv4_class(address: str) -> str:
    """
    Determine the historical IPv4 class based on the first octet.

    Classful addressing is largely obsolete for modern routing because CIDR
    provides more flexible prefixes, but understanding it remains useful.
    """
    first_octet = int(ipaddress.IPv4Address(address).packed[0])

    if 1 <= first_octet <= 126:
        return "Class A"
    if 128 <= first_octet <= 191:
        return "Class B"
    if 192 <= first_octet <= 223:
        return "Class C"
    if 224 <= first_octet <= 239:
        return "Class D (multicast)"
    if 240 <= first_octet <= 255:
        return "Class E (historically experimental/reserved)"
    return "Special/reserved"


def demonstrate_classful_addressing() -> None:
    print_section("10. Historical IPv4 classes")

    examples = [
        "10.0.0.1",
        "128.0.0.1",
        "172.16.1.1",
        "192.168.1.1",
        "224.0.0.1",
        "240.0.0.1",
        "127.0.0.1",
    ]

    for address in examples:
        print(f"{address:16s} -> {classful_ipv4_class(address)}")

    print("\nTraditional class defaults:")
    print("Class A -> /8")
    print("Class B -> /16")
    print("Class C -> /24")
    print("Class D -> multicast")
    print("Class E -> experimental/reserved history")

    print("\nModern networks generally use CIDR instead of relying on these defaults.")


# =============================================================================
# 11. CIDR
# =============================================================================

def cidr_contains(network: str, address: str) -> bool:
    """Return whether an IPv4 address belongs to a CIDR network."""
    return ipaddress.IPv4Address(address) in ipaddress.IPv4Network(network)


def compare_same_subnet(
    address_a: str,
    address_b: str,
    prefix_length: int,
) -> bool:
    """Determine whether two addresses belong to the same subnet."""
    network_a = ipaddress.IPv4Network(
        f"{address_a}/{prefix_length}",
        strict=False,
    )
    network_b = ipaddress.IPv4Network(
        f"{address_b}/{prefix_length}",
        strict=False,
    )

    return network_a.network_address == network_b.network_address


def demonstrate_cidr() -> None:
    print_section("11. CIDR and prefix notation")

    networks = [
        "192.168.1.0/24",
        "192.168.1.0/25",
        "192.168.1.128/25",
        "10.0.0.0/8",
        "172.16.0.0/12",
    ]

    for network_text in networks:
        network = ipaddress.IPv4Network(network_text)
        print(
            f"{network_text:20s} "
            f"mask={network.netmask} "
            f"addresses={network.num_addresses}"
        )

    print("\nMembership examples:")
    tests = [
        ("192.168.1.0/24", "192.168.1.100"),
        ("192.168.1.0/24", "192.168.2.100"),
        ("192.168.1.128/25", "192.168.1.200"),
        ("192.168.1.128/25", "192.168.1.100"),
    ]

    for network, address in tests:
        print(
            f"{address:16s} in {network:18s} -> "
            f"{cidr_contains(network, address)}"
        )

    print("\nSame-subnet examples using /24:")
    pairs = [
        ("192.168.1.10", "192.168.1.200"),
        ("192.168.1.10", "192.168.2.10"),
    ]

    for a, b in pairs:
        print(
            f"{a} and {b}: "
            f"{compare_same_subnet(a, b, 24)}"
        )


# =============================================================================
# 12. SUBNETTING
# =============================================================================

def subnet_networks(network: str, new_prefix: int) -> list[str]:
    """
    Split a network into smaller equal-sized IPv4 subnets.

    Example:
        192.168.1.0/24 split into /26
        produces four /26 networks.
    """
    parent = ipaddress.IPv4Network(network)

    if new_prefix < parent.prefixlen:
        raise ValueError(
            "New prefix must be greater than or equal to the parent prefix."
        )

    return [str(subnet) for subnet in parent.subnets(new_prefix=new_prefix)]


def demonstrate_subnetting() -> None:
    print_section("12. Subnetting")

    parent = "192.168.1.0/24"
    children = subnet_networks(parent, 26)

    print(f"Parent network: {parent}")
    print("Splitting /24 into /26 produces:")
    for subnet in children:
        network = ipaddress.IPv4Network(subnet)
        print(
            f"  {subnet:20s} "
            f"range={network.network_address} - {network.broadcast_address}"
        )

    print("\nWhy /26 creates four subnets:")
    print("/24 -> /26 borrows 2 bits.")
    print("2^2 = 4 subnets.")
    print("Each /26 contains 2^6 = 64 addresses.")


# =============================================================================
# 13. SUBNETTING FROM HOST REQUIREMENTS
# =============================================================================

def smallest_prefix_for_hosts(required_hosts: int) -> int:
    """
    Find the smallest prefix that supports the requested number of traditional
    usable hosts.

    For ordinary LAN subnets:
        usable = 2^host_bits - 2
    """
    if not isinstance(required_hosts, int):
        raise TypeError("Required hosts must be an integer.")

    if required_hosts < 1:
        raise ValueError("Required hosts must be positive.")

    for prefix in range(32, -1, -1):
        if traditional_usable_hosts(prefix) >= required_hosts:
            return prefix

    raise ValueError("No IPv4 prefix can satisfy the requirement.")


def demonstrate_host_requirement_calculation() -> None:
    print_section("13. Choosing a subnet from a host requirement")

    requirements = [2, 6, 14, 30, 62, 100, 250, 500, 1000]

    for hosts in requirements:
        prefix = smallest_prefix_for_hosts(hosts)
        total = total_ipv4_addresses(prefix)
        usable = traditional_usable_hosts(prefix)

        print(
            f"Required={hosts:4d} "
            f"-> /{prefix:<2d} "
            f"total={total:<5d} "
            f"usable={usable:<5d}"
        )

    print("\nSubnet design principle:")
    print("Choose enough host bits to satisfy the requirement without wasting")
    print("large amounts of address space.")


# =============================================================================
# 14. VLSM
# =============================================================================

@dataclass
class VLSMAllocation:
    name: str
    required_hosts: int
    network: str
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    first_host: Optional[str]
    last_host: Optional[str]
    broadcast: str


def allocate_vlsm(
    base_network: str,
    requirements: Iterable[tuple[str, int]],
) -> list[VLSMAllocation]:
    """
    Allocate variable-length subnets using a largest-first strategy.

    Largest-first allocation reduces fragmentation in straightforward VLSM
    planning scenarios.
    """
    base = ipaddress.IPv4Network(base_network)

    sorted_requirements = sorted(
        requirements,
        key=lambda item: item[1],
        reverse=True,
    )

    current = int(base.network_address)
    end = int(base.broadcast_address)
    allocations: list[VLSMAllocation] = []

    for name, required_hosts in sorted_requirements:
        prefix = smallest_prefix_for_hosts(required_hosts)
        block_size = total_ipv4_addresses(prefix)

        # Align the current address to the required subnet boundary.
        aligned = (
            (current + block_size - 1) // block_size
        ) * block_size

        candidate_end = aligned + block_size - 1

        if candidate_end > end:
            raise ValueError(
                f"Not enough address space for requirement '{name}'."
            )

        subnet = ipaddress.IPv4Network(
            f"{integer_to_ipv4(aligned)}/{prefix}"
        )

        usable = traditional_usable_hosts(prefix)

        if prefix == 32:
            first_host = str(subnet.network_address)
            last_host = str(subnet.network_address)
        elif prefix == 31:
            first_host = str(subnet.network_address)
            last_host = str(subnet.broadcast_address)
        else:
            first_host = str(subnet.network_address + 1)
            last_host = str(subnet.broadcast_address - 1)

        allocations.append(
            VLSMAllocation(
                name=name,
                required_hosts=required_hosts,
                network=str(subnet.network_address),
                prefix_length=prefix,
                total_addresses=block_size,
                usable_hosts=usable,
                first_host=first_host,
                last_host=last_host,
                broadcast=str(subnet.broadcast_address),
            )
        )

        current = candidate_end + 1

    return allocations


def demonstrate_vlsm() -> None:
    print_section("14. VLSM: Variable Length Subnet Masking")

    base_network = "192.168.100.0/24"

    requirements = [
        ("Engineering", 60),
        ("Sales", 30),
        ("Management", 12),
        ("Point-to-point", 2),
    ]

    allocations = allocate_vlsm(base_network, requirements)

    print("Base network:", base_network)
    print("\nAllocated subnets, largest requirement first:")

    for allocation in allocations:
        print(
            f"{allocation.name:15s} "
            f"needs={allocation.required_hosts:3d} "
            f"-> {allocation.network}/{allocation.prefix_length:<2d} "
            f"usable={allocation.usable_hosts:3d} "
            f"hosts={allocation.first_host} - {allocation.last_host} "
            f"broadcast={allocation.broadcast}"
        )


# =============================================================================
# 15. SPECIAL IPv4 ADDRESS TYPES
# =============================================================================

def demonstrate_special_ranges() -> None:
    print_section("15. Important IPv4 special-purpose ranges")

    ranges = [
        ("0.0.0.0/0", "Default route / all IPv4 destinations"),
        ("0.0.0.0/32", "Unspecified address when used as an address"),
        ("127.0.0.0/8", "Loopback"),
        ("10.0.0.0/8", "Private"),
        ("172.16.0.0/12", "Private"),
        ("192.168.0.0/16", "Private"),
        ("169.254.0.0/16", "Link-local"),
        ("224.0.0.0/4", "Multicast"),
        ("255.255.255.255/32", "Limited broadcast"),
    ]

    for network, description in ranges:
        print(f"{network:20s} -> {description}")

    print("\nThe exact routing behavior of an address depends on context.")
    print("A range's purpose should not be inferred solely from whether it")
    print("looks public or private.")


# =============================================================================
# 16. NETWORK, BROADCAST AND HOST EDGE CASES
# =============================================================================

def demonstrate_edge_cases() -> None:
    print_section("16. Edge cases")

    examples = [
        "192.168.1.0/24",
        "192.168.1.255/24",
        "192.168.1.1/24",
        "192.168.1.254/24",
        "10.0.0.0/31",
        "10.0.0.1/31",
        "10.0.0.0/32",
    ]

    for example in examples:
        details = analyze_network(example)
        print(
            f"{example:22s} "
            f"network={details.network:15s} "
            f"broadcast={details.broadcast:15s} "
            f"usable={details.usable_hosts}"
        )

    print("\nImportant:")
    print("- Network and broadcast conventions apply to ordinary subnet designs.")
    print("- /31 is commonly used for point-to-point links.")
    print("- /32 represents a single IPv4 address.")
    print("- Do not blindly apply the traditional '-2 hosts' formula to /31 or /32.")


# =============================================================================
# 17. ROUTING AND LONGEST-PREFIX MATCH
# =============================================================================

@dataclass
class Route:
    network: ipaddress.IPv4Network
    next_hop: str


def longest_prefix_match(
    destination: str,
    routes: Iterable[Route],
) -> Optional[Route]:
    """
    Select the route with the longest matching prefix.

    This models the basic decision principle used by IP routing:
    when several routes match, the most specific matching prefix wins.
    """
    destination_ip = ipaddress.IPv4Address(destination)

    matching_routes = [
        route
        for route in routes
        if destination_ip in route.network
    ]

    if not matching_routes:
        return None

    return max(
        matching_routes,
        key=lambda route: route.network.prefixlen,
    )


def demonstrate_longest_prefix_matching() -> None:
    print_section("17. Routing and longest-prefix matching")

    routes = [
        Route(ipaddress.IPv4Network("0.0.0.0/0"), "ISP gateway"),
        Route(ipaddress.IPv4Network("10.0.0.0/8"), "Router A"),
        Route(ipaddress.IPv4Network("10.20.0.0/16"), "Router B"),
        Route(ipaddress.IPv4Network("10.20.30.0/24"), "Router C"),
    ]

    destinations = [
        "10.20.30.40",
        "10.20.50.10",
        "10.50.1.1",
        "8.8.8.8",
    ]

    for destination in destinations:
        match = longest_prefix_match(destination, routes)

        if match is None:
            print(destination, "-> no route")
        else:
            print(
                f"{destination:15s} -> "
                f"{str(match.network):18s} -> {match.next_hop}"
            )

    print("\nFor 10.20.30.40, several routes match:")
    print("0.0.0.0/0")
    print("10.0.0.0/8")
    print("10.20.0.0/16")
    print("10.20.30.0/24")
    print("The /24 route is the most specific and therefore wins.")


# =============================================================================
# 18. NAT CONCEPT
# =============================================================================

@dataclass
class NATTranslation:
    private_source: str
    public_source: str
    destination: str


def demonstrate_nat_concept() -> None:
    print_section("18. Private addresses and NAT")

    translation = NATTranslation(
        private_source="192.168.1.20:51500",
        public_source="203.0.113.10:40001",
        destination="198.51.100.20:443",
    )

    print("Internal client :", translation.private_source)
    print("Translated source:", translation.public_source)
    print("Destination     :", translation.destination)

    print("\nConceptual flow:")
    print("1. A private host creates an outbound connection.")
    print("2. A NAT device maps the private source to a public address/port.")
    print("3. The packet crosses the external network using the translated source.")
    print("4. Return traffic is mapped back to the internal connection.")

    print("\nNAT is not the same thing as IPv4 addressing.")
    print("NAT is a translation mechanism commonly used because public IPv4 space")
    print("is limited and private addressing is useful inside organizations.")


# =============================================================================
# 19. ADDRESS PLANNING
# =============================================================================

@dataclass
class AddressPlan:
    department: str
    subnet: str
    mask: str
    usable_hosts: int


def create_simple_address_plan() -> list[AddressPlan]:
    """Create an example address plan for several departments."""
    networks = [
        ("Engineering", "10.10.0.0/24"),
        ("Sales", "10.10.1.0/25"),
        ("Management", "10.10.1.128/26"),
        ("Infrastructure", "10.10.1.192/27"),
    ]

    plan = []

    for department, network_text in networks:
        network = ipaddress.IPv4Network(network_text)

        plan.append(
            AddressPlan(
                department=department,
                subnet=network_text,
                mask=str(network.netmask),
                usable_hosts=traditional_usable_hosts(network.prefixlen),
            )
        )

    return plan


def demonstrate_address_planning() -> None:
    print_section("19. Practical IPv4 address planning")

    plan = create_simple_address_plan()

    print(
        f"{'Department':18s} "
        f"{'Subnet':20s} "
        f"{'Mask':18s} "
        f"{'Usable hosts':>13s}"
    )
    print("-" * 72)

    for entry in plan:
        print(
            f"{entry.department:18s} "
            f"{entry.subnet:20s} "
            f"{entry.mask:18s} "
            f"{entry.usable_hosts:13d}"
        )

    print("\nPlanning considerations:")
    print("- Leave room for expected growth.")
    print("- Keep address assignments predictable.")
    print("- Use separate subnets when segmentation is required.")
    print("- Document gateways, DHCP pools, reserved addresses and infrastructure.")
    print("- Avoid overlapping subnets.")


# =============================================================================
# 20. OVERLAPPING NETWORK DETECTION
# =============================================================================

def detect_overlaps(networks: Iterable[str]) -> list[tuple[str, str]]:
    """
    Return pairs of overlapping IPv4 networks.
    """
    parsed = [ipaddress.IPv4Network(network) for network in networks]
    overlaps: list[tuple[str, str]] = []

    for index, first in enumerate(parsed):
        for second in parsed[index + 1 :]:
            if first.overlaps(second):
                overlaps.append((str(first), str(second)))

    return overlaps


def demonstrate_overlap_detection() -> None:
    print_section("20. Detecting overlapping IPv4 networks")

    networks = [
        "10.0.0.0/8",
        "10.20.0.0/16",
        "192.168.1.0/24",
        "192.168.2.0/24",
        "172.16.0.0/12",
    ]

    overlaps = detect_overlaps(networks)

    print("Networks:")
    for network in networks:
        print(" ", network)

    print("\nOverlaps:")
    for first, second in overlaps:
        print(f"  {first} overlaps {second}")

    print("\nOverlapping address plans can cause ambiguous routing and difficult")
    print("network segmentation. Network boundaries should be deliberately designed.")


# =============================================================================
# 21. ADDRESS RANGE ENUMERATION
# =============================================================================

def list_hosts(network: str, limit: int = 10) -> list[str]:
    """
    Return up to 'limit' traditional usable host addresses.

    The function deliberately avoids materializing very large networks.
    """
    if limit < 1:
        raise ValueError("Limit must be positive.")

    parsed = ipaddress.IPv4Network(network)

    if parsed.prefixlen >= 31:
        addresses = list(parsed)
    else:
        addresses = list(parsed.hosts())

    return [str(address) for address in addresses[:limit]]


def demonstrate_host_enumeration() -> None:
    print_section("21. Enumerating addresses safely")

    for network in [
        "192.168.1.0/29",
        "10.0.0.0/30",
        "10.0.0.0/31",
    ]:
        print(network, "->", list_hosts(network, limit=10))

    print("\nLarge networks should not be blindly converted to a full list.")
    print("Iterators and bounded processing avoid unnecessary memory consumption.")


# =============================================================================
# 22. IP ADDRESS SORTING
# =============================================================================

def sort_ipv4_addresses(addresses: Iterable[str]) -> list[str]:
    """Sort IPv4 addresses by numerical address value."""
    return sorted(addresses, key=ipaddress.IPv4Address)


def demonstrate_sorting() -> None:
    print_section("22. Sorting IPv4 addresses correctly")

    addresses = [
        "192.168.1.100",
        "10.0.0.5",
        "192.168.1.2",
        "10.0.0.20",
        "8.8.8.8",
    ]

    print("Original:")
    print(addresses)

    print("\nCorrect numerical IPv4 sorting:")
    print(sort_ipv4_addresses(addresses))

    print("\nString sorting is not equivalent to numerical IP sorting.")
    print("For example, lexical order places '192.168.1.100' before or after")
    print("other values based on characters rather than the 32-bit address value.")


# =============================================================================
# 23. IPV4 NETWORK AGGREGATION CONCEPT
# =============================================================================

def summarize_networks(addresses: Iterable[str]) -> list[str]:
    """
    Return the minimal CIDR summary for individual IPv4 addresses.

    This demonstrates route summarization from address data.
    """
    return [
        str(network)
        for network in ipaddress.summarize_address_range(
            min(
                (ipaddress.IPv4Address(address) for address in addresses),
                default=ipaddress.IPv4Address("0.0.0.0"),
            ),
            max(
                (ipaddress.IPv4Address(address) for address in addresses),
                default=ipaddress.IPv4Address("0.0.0.0"),
            ),
        )
    ]


def demonstrate_route_summarization() -> None:
    print_section("23. Route summarization")

    # Four contiguous /24 networks can be represented by one /22 network.
    first = ipaddress.IPv4Network("192.168.0.0/24")
    last = ipaddress.IPv4Network("192.168.3.255/32")

    summaries = list(
        ipaddress.summarize_address_range(
            first.network_address,
            last.broadcast_address,
        )
    )

    print("Address space:")
    print("192.168.0.0/24")
    print("192.168.1.0/24")
    print("192.168.2.0/24")
    print("192.168.3.0/24")

    print("\nSummarized route(s):")
    for summary in summaries:
        print(summary)

    print("\nRoute summarization can reduce the number of routing entries.")
    print("It must only be used when the summarized address space is valid for")
    print("the routing design and does not accidentally attract unrelated traffic.")


# =============================================================================
# 24. SECURITY AND OPERATIONAL CONSIDERATIONS
# =============================================================================

def demonstrate_security_considerations() -> None:
    print_section("24. Security and operational considerations")

    considerations = [
        (
            "Private addressing",
            "Reduces direct public exposure but does not replace firewall policy."
        ),
        (
            "Subnet segmentation",
            "Can separate systems and reduce unnecessary broadcast or routing scope."
        ),
        (
            "Network overlap",
            "Can cause routing ambiguity and operational failures."
        ),
        (
            "Address spoofing",
            "An IPv4 source address does not by itself prove sender identity."
        ),
        (
            "Logging",
            "IP addresses are useful operational identifiers but may not uniquely "
            "identify a human or device."
        ),
        (
            "NAT",
            "Can obscure internal addressing but should not be treated as a complete "
            "security boundary."
        ),
    ]

    for topic, explanation in considerations:
        print(f"{topic}:")
        print(f"  {explanation}")

    print("\nSecurity principle:")
    print("Addressing controls where traffic can be addressed;")
    print("firewalls, authentication, authorization, encryption and monitoring")
    print("provide additional security controls.")


# =============================================================================
# 25. PERFORMANCE CONSIDERATIONS
# =============================================================================

def benchmark_style_comparison() -> None:
    """
    Demonstrate why integer/prefix calculations are useful.

    This is not a formal benchmark. It illustrates algorithmic structure rather
    than claiming a specific hardware-dependent performance number.
    """
    print_section("25. Performance considerations")

    addresses = [
        "10.0.0.1",
        "10.0.1.1",
        "10.0.2.1",
        "192.168.1.1",
        "172.16.10.20",
    ]

    print("Converting addresses once to integers:")
    converted = {
        address: ipv4_to_integer(address)
        for address in addresses
    }

    for address, integer_value in converted.items():
        print(f"{address:16s} -> {integer_value}")

    print("\nFor repeated routing or range operations, useful practices include:")
    print("- Parse and validate input once when possible.")
    print("- Represent IPv4 addresses as integers for direct numerical operations.")
    print("- Represent networks as an integer prefix and mask.")
    print("- Avoid constructing huge address lists unnecessarily.")
    print("- Use prefix-based data structures for large routing datasets.")


# =============================================================================
# 26. MANUAL NETWORK CALCULATION
# =============================================================================

def manual_network_calculation(
    address: str,
    prefix_length: int,
) -> tuple[str, str, str]:
    """
    Calculate network address, broadcast address and host-bit count manually
    using integer bitwise operations.
    """
    if not 0 <= prefix_length <= 32:
        raise ValueError("Prefix must be between 0 and 32.")

    address_int = ipv4_to_integer(address)

    if prefix_length == 0:
        mask_int = 0
    else:
        mask_int = (
            ((2**32 - 1) << (32 - prefix_length))
            & (2**32 - 1)
        )

    network_int = address_int & mask_int
    broadcast_int = network_int | ((2**32 - 1) ^ mask_int)
    host_bits = 32 - prefix_length

    return (
        integer_to_ipv4(network_int),
        integer_to_ipv4(broadcast_int),
        str(host_bits),
    )


def demonstrate_manual_calculation() -> None:
    print_section("26. Manual CIDR calculation using bitwise operations")

    examples = [
        ("192.168.1.130", 26),
        ("10.20.30.40", 20),
        ("172.16.50.100", 16),
        ("8.8.8.8", 8),
        ("192.168.1.10", 32),
    ]

    for address, prefix in examples:
        network, broadcast, host_bits = manual_network_calculation(
            address,
            prefix,
        )

        print(
            f"{address}/{prefix:<2d} -> "
            f"network={network:15s}, "
            f"broadcast={broadcast:15s}, "
            f"host_bits={host_bits}"
        )


# =============================================================================
# 27. DHCP CONCEPT
# =============================================================================

def demonstrate_dhcp_concept() -> None:
    print_section("27. DHCP and IPv4 address assignment")

    print("A typical DHCP exchange is often described using DORA:")
    print("1. Discover  -> client searches for DHCP servers.")
    print("2. Offer     -> server offers configuration.")
    print("3. Request   -> client requests the offered configuration.")
    print("4. ACK       -> server confirms the lease.")

    print("\nA DHCP configuration may provide:")
    print("- IPv4 address")
    print("- subnet mask")
    print("- default gateway")
    print("- DNS server information")
    print("- lease duration")

    print("\nDHCP assigns addresses from a configured pool.")
    print("Static reservations or manually configured addresses can be used")
    print("for infrastructure that requires predictable addressing.")


# =============================================================================
# 28. DEFAULT GATEWAY CONCEPT
# =============================================================================

def demonstrate_default_gateway() -> None:
    print_section("28. Default gateway")

    host = ipaddress.IPv4Interface("192.168.10.50/24")
    gateway = ipaddress.IPv4Address("192.168.10.1")
    remote = ipaddress.IPv4Address("8.8.8.8")

    local_network = host.network

    print("Host address:", host)
    print("Network     :", local_network)
    print("Gateway     :", gateway)
    print("Remote host :", remote)

    print("\nLocal destination check:")
    print("192.168.10.80 is local:",
          ipaddress.IPv4Address("192.168.10.80") in local_network)

    print("8.8.8.8 is local:",
          remote in local_network)

    print("\nIf a destination is outside the host's directly connected subnet,")
    print("the host normally sends the traffic toward its configured default gateway.")


# =============================================================================
# 29. COMMON MISTAKES
# =============================================================================

def demonstrate_common_mistakes() -> None:
    print_section("29. Common IPv4 addressing mistakes")

    mistakes = [
        (
            "Treating every 172.x.x.x address as private",
            "Only 172.16.0.0 through 172.31.255.255 is RFC 1918 private."
        ),
        (
            "Assuming /24 is the only normal subnet size",
            "CIDR supports prefixes from /0 through /32."
        ),
        (
            "Forgetting network and broadcast addresses",
            "Traditional LAN host calculations reserve both."
        ),
        (
            "Applying -2 to /31",
            "Point-to-point /31 links are a special case."
        ),
        (
            "Confusing public with safe",
            "A public address is routable addressing, not a security guarantee."
        ),
        (
            "Confusing private with encrypted",
            "Private addressing does not provide encryption."
        ),
        (
            "Comparing IP addresses as strings",
            "Use numerical or IP-aware comparison."
        ),
        (
            "Creating overlapping subnets",
            "Overlaps can make routing and segmentation ambiguous."
        ),
        (
            "Using the wrong subnet mask",
            "A host can appear unreachable or incorrectly classify peers."
        ),
    ]

    for mistake, correction in mistakes:
        print(f"\nMistake: {mistake}")
        print(f"Correct principle: {correction}")


# =============================================================================
# 30. TESTS
# =============================================================================

def run_tests() -> None:
    """Run correctness checks for the educational implementations."""
    print_section("30. Built-in tests")

    assert decimal_octet_to_binary(192) == "11000000"
    assert binary_octet_to_decimal("11000000") == 192

    address = "192.168.1.10"
    assert binary_to_ipv4(ipv4_to_binary(address)) == address

    assert is_valid_ipv4("192.168.1.1")
    assert not is_valid_ipv4("256.1.1.1")

    assert prefix_to_mask(24) == "255.255.255.0"
    assert mask_to_prefix("255.255.255.0") == 24

    details = analyze_network("192.168.1.130/26")
    assert details.network == "192.168.1.128"
    assert details.broadcast == "192.168.1.191"
    assert details.first_usable == "192.168.1.129"
    assert details.last_usable == "192.168.1.190"
    assert details.usable_hosts == 62

    assert is_private_rfc1918("10.1.2.3")
    assert is_private_rfc1918("172.16.1.1")
    assert is_private_rfc1918("172.31.255.255")
    assert is_private_rfc1918("192.168.1.1")
    assert not is_private_rfc1918("172.32.0.1")

    assert cidr_contains("192.168.1.0/24", "192.168.1.50")
    assert not cidr_contains("192.168.1.0/24", "192.168.2.50")

    assert compare_same_subnet(
        "192.168.1.10",
        "192.168.1.200",
        24,
    )
    assert not compare_same_subnet(
        "192.168.1.10",
        "192.168.2.10",
        24,
    )

    subnet_list = subnet_networks("192.168.1.0/24", 26)
    assert len(subnet_list) == 4

    assert smallest_prefix_for_hosts(62) == 26
    assert smallest_prefix_for_hosts(30) == 27

    manual = manual_network_calculation("192.168.1.130", 26)
    assert manual == ("192.168.1.128", "192.168.1.191", "6")

    routes = [
        Route(ipaddress.IPv4Network("0.0.0.0/0"), "default"),
        Route(ipaddress.IPv4Network("10.0.0.0/8"), "A"),
        Route(ipaddress.IPv4Network("10.20.0.0/16"), "B"),
        Route(ipaddress.IPv4Network("10.20.30.0/24"), "C"),
    ]

    match = longest_prefix_match("10.20.30.40", routes)
    assert match is not None
    assert match.next_hop == "C"

    print("All tests passed.")


# =============================================================================
# 31. PRACTICAL SCENARIO
# =============================================================================

def practical_scenario() -> None:
    print_section("31. Practical scenario: small organization")

    print("Scenario:")
    print("An organization receives 192.168.50.0/24 for an internal lab.")
    print("It needs separate networks for:")
    print("- Development: 100 hosts")
    print("- Operations: 40 hosts")
    print("- Administration: 20 hosts")
    print("- Network devices: 10 hosts")

    requirements = [
        ("Development", 100),
        ("Operations", 40),
        ("Administration", 20),
        ("Network devices", 10),
    ]

    allocations = allocate_vlsm(
        "192.168.50.0/24",
        requirements,
    )

    for allocation in allocations:
        print(
            f"\n{allocation.name}")
        print(f"  Required hosts : {allocation.required_hosts}")
        print(f"  Subnet         : {allocation.network}/{allocation.prefix_length}")
        print(f"  Mask           : {prefix_to_mask(allocation.prefix_length)}")
        print(f"  Usable hosts   : {allocation.usable_hosts}")
        print(f"  Host range     : {allocation.first_host} - {allocation.last_host}")
        print(f"  Broadcast      : {allocation.broadcast}")

    print("\nDesign observation:")
    print("VLSM allows each department to receive a subnet sized closer to its")
    print("actual requirement instead of assigning the same subnet size to all.")


# =============================================================================
# 32. QUICK REFERENCE
# =============================================================================

def quick_reference() -> None:
    print_section("32. IPv4 quick reference")

    reference = [
        ("IPv4 size", "32 bits"),
        ("Octets", "4"),
        ("Bits per octet", "8"),
        ("Octet range", "0-255"),
        ("Private 1", "10.0.0.0/8"),
        ("Private 2", "172.16.0.0/12"),
        ("Private 3", "192.168.0.0/16"),
        ("Loopback", "127.0.0.0/8"),
        ("Link-local", "169.254.0.0/16"),
        ("Multicast", "224.0.0.0/4"),
        ("CIDR", "address/prefix-length"),
        ("Network address", "Host bits all zero"),
        ("Broadcast", "Host bits all one in traditional IPv4 subnetting"),
        ("Host bits", "32 - prefix length"),
        ("Total addresses", "2^(host bits)"),
        ("Traditional usable hosts", "2^(host bits) - 2"),
    ]

    width = max(len(name) for name, _ in reference)

    for name, value in reference:
        print(f"{name:<{width}} : {value}")


# =============================================================================
# 33. MAIN PROGRAM
# =============================================================================

def main() -> None:
    """
    Execute the complete IPv4 study program.

    Each section is intentionally independent enough to be studied separately.
    """
    explain_ipv4_basics()
    demonstrate_binary_conversion()
    validate_ipv4_examples()
    demonstrate_integer_representation()
    demonstrate_masks()
    demonstrate_network_and_host_ids()
    demonstrate_bitwise_network_calculation()
    demonstrate_host_capacity()
    demonstrate_public_private_addresses()
    demonstrate_classful_addressing()
    demonstrate_cidr()
    demonstrate_subnetting()
    demonstrate_host_requirement_calculation()
    demonstrate_vlsm()
    demonstrate_special_ranges()
    demonstrate_edge_cases()
    demonstrate_longest_prefix_matching()
    demonstrate_nat_concept()
    demonstrate_address_planning()
    demonstrate_overlap_detection()
    demonstrate_host_enumeration()
    demonstrate_sorting()
    demonstrate_route_summarization()
    demonstrate_security_considerations()
    benchmark_style_comparison()
    demonstrate_manual_calculation()
    demonstrate_dhcp_concept()
    demonstrate_default_gateway()
    demonstrate_common_mistakes()
    run_tests()
    practical_scenario()
    quick_reference()

    print_section("Study program completed")
    print("The examples above cover IPv4 addressing from binary fundamentals")
    print("through subnetting, CIDR, VLSM, routing and operational considerations.")


if __name__ == "__main__":
    main()
