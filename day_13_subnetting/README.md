# IPv4 subnetting: CIDR, subnet masks, prefix lengths, subnet calculation, and host ranges

## Introduction

Subnetting is the process of dividing an IPv4 address space into smaller logical networks. It is one of the fundamental mechanisms used in IP network design because a single large address block is rarely appropriate for every department, site, VLAN, point-to-point link, or routing domain.

This study file uses Python to demonstrate subnetting mathematically and programmatically. The material progresses from the binary representation of an IPv4 address to CIDR notation, subnet masks, network-address calculation, host ranges, fixed-length subnetting, VLSM, route summarization, special prefixes, validation, and automated testing.

The examples use the Python standard-library `ipaddress` module where appropriate. Several calculations are also implemented directly with integer and bitwise operations so that the underlying mechanics of subnetting remain visible.

## IPv4 address structure

An IPv4 address contains 32 bits. These bits are normally displayed as four decimal octets separated by periods.

For example:

    192.168.1.10

Each octet contains eight bits, so the complete address contains:

    8 + 8 + 8 + 8 = 32 bits

The binary representation of `192.168.1.10` is:

    11000000.10101000.00000001.00001010

The script provides `ipv4_to_binary()` and `binary_to_ipv4()` for converting between dotted-decimal and binary representations.

The binary representation is important because subnetting is fundamentally a bit-level operation. A subnet mask determines which bits belong to the network portion and which bits remain available for host addressing.

## Network bits and host bits

An IPv4 address is divided conceptually into:

- Network bits
- Host bits

The prefix length determines how many of the 32 bits are network bits.

For example, `/24` means:

    Network bits = 24
    Host bits   = 32 - 24 = 8

A `/16` network has:

    Network bits = 16
    Host bits   = 16

A `/28` network has:

    Network bits = 28
    Host bits   = 4

As the prefix length increases, the number of host bits decreases. This produces smaller networks.

## CIDR notation

CIDR stands for Classless Inter-Domain Routing.

CIDR represents a network using:

    network-address/prefix-length

For example:

    192.168.1.0/24

The `/24` is the prefix length. It states that the first 24 bits identify the network and the remaining eight bits identify addresses within that network.

CIDR replaced the older class-based model in which IPv4 networks were commonly described as Class A, Class B, and Class C. Modern network planning relies on prefix lengths rather than the historical class boundaries.

Examples include:

    10.0.0.0/8
    172.16.0.0/12
    192.168.1.0/24
    192.168.1.64/26
    192.168.1.128/27

## Subnet masks

A subnet mask is another representation of the network prefix.

For `/24`, the mask is:

    255.255.255.0

For `/16`:

    255.255.0.0

For `/8`:

    255.0.0.0

For `/26`:

    255.255.255.192

The binary representation of a subnet mask contains contiguous ones followed by contiguous zeros.

For `/26`:

    11111111.11111111.11111111.11000000

The 26 ones identify network bits, while the six zeros identify host bits.

A mask such as:

    255.0.255.0

is not a valid conventional IPv4 subnet mask because its network bits are not contiguous.

The script validates masks through `mask_to_prefix()`.

## Wildcard masks

A wildcard mask is the bitwise inverse of a subnet mask.

For `/24`:

    Subnet mask = 255.255.255.0
    Wildcard    = 0.0.0.255

For `/26`:

    Subnet mask = 255.255.255.192
    Wildcard    = 0.0.0.63

Wildcard masks are encountered in several networking technologies, particularly access-control and routing configurations.

The function `prefix_to_wildcard()` calculates the wildcard mask programmatically.

## Total addresses in a subnet

The number of host bits determines the total number of addresses.

The general formula is:

    Total addresses = 2^(number of host bits)

Since:

    host bits = 32 - prefix length

the formula can also be written as:

    Total addresses = 2^(32 - prefix length)

For `/24`:

    Host bits = 8
    Total addresses = 2^8
                   = 256

For `/26`:

    Host bits = 6
    Total addresses = 2^6
                   = 64

For `/30`:

    Host bits = 2
    Total addresses = 2^2
                   = 4

The script implements this calculation through `total_addresses()`.

## Traditional usable host calculation

For ordinary IPv4 subnets, two addresses traditionally have special roles:

- Network address
- Broadcast address

The traditional usable-host formula is therefore:

    Usable hosts = 2^(host bits) - 2

For `/24`:

    256 - 2 = 254 usable hosts

For `/26`:

    64 - 2 = 62 usable hosts

For `/30`:

    4 - 2 = 2 usable hosts

This formula should not be blindly applied to every prefix. `/31` and `/32` have special meanings and are discussed separately in this document.

## Network address

The network address identifies the subnet itself.

A network address has all host bits set to zero.

For:

    192.168.1.77/24

the first 24 bits identify the network and the final eight bits represent the host portion.

The network address is:

    192.168.1.0

The script intentionally accepts a host address together with a prefix and normalizes it to the containing network when `strict=False` is used.

## Broadcast address

For a traditional IPv4 subnet, the broadcast address is the address with all host bits set to one.

For:

    192.168.1.0/24

the broadcast address is:

    192.168.1.255

For:

    192.168.1.64/26

the host portion contains six bits, so the broadcast address is:

    192.168.1.127

The network and broadcast addresses define the boundaries of a traditional subnet.

## Usable host range

For a normal subnet with a prefix shorter than `/31`, the traditional host range is:

    First host = network address + 1
    Last host  = broadcast address - 1

For:

    192.168.1.0/24

the range is:

    192.168.1.1 - 192.168.1.254

For:

    192.168.1.64/26

the range is:

    192.168.1.65 - 192.168.1.126

The function `usable_host_range()` calculates this range and deliberately rejects `/31` and `/32` because their traditional host-range interpretation is different.

## Subnet calculation using bitwise AND

The fundamental mathematical operation behind finding a network address is:

    IP address AND subnet mask = network address

Consider:

    IP address:
    192.168.1.77

    Mask:
    255.255.255.192

In binary, the operation is performed independently on every bit.

A bitwise AND follows these rules:

    1 AND 1 = 1
    1 AND 0 = 0
    0 AND 1 = 0
    0 AND 0 = 0

The result is:

    192.168.1.64

The script implements this operation through `binary_and()` and `calculate_network_by_and()`.

This is an important distinction: subnetting is not based on decimal arithmetic such as rounding an octet to the nearest familiar value. The correct result comes from binary masking.

## Non-octet subnet masks

Many subnetting problems use prefix lengths that do not end on an octet boundary.

Examples include:

    /25
    /26
    /27
    /28
    /29
    /30

These prefixes are particularly important for practical subnet calculations.

For `/26`:

    Prefix = 26
    Host bits = 6
    Total addresses = 64

The mask is:

    255.255.255.192

The last octet therefore divides into blocks of 64:

    0
    64
    128
    192

Consequently, the `/26` networks within `192.168.1.0/24` are:

    192.168.1.0/26
    192.168.1.64/26
    192.168.1.128/26
    192.168.1.192/26

The script demonstrates this through `split_into_subnets()`.

## Block size

For an octet-based subnetting calculation, the block size can be determined from the relevant mask octet.

For example, `/26` has:

    Mask = 255.255.255.192

The block size is:

    256 - 192 = 64

The network boundaries are therefore multiples of 64:

    0
    64
    128
    192

This is a convenient manual technique, but the underlying principle remains binary masking.

## Borrowing host bits

Subnetting can be viewed as borrowing bits from the host portion and using them as additional network bits.

Suppose:

    Parent network = /24
    New subnet    = /26

The number of borrowed bits is:

    26 - 24 = 2

Two additional bits create:

    2^2 = 4

equal-sized subnets.

The script exposes this relationship through:

    borrowed_bits()
    subnet_count()

For a `/24` divided into `/28` networks:

    Borrowed bits = 28 - 24 = 4
    Number of subnets = 2^4 = 16

Each `/28` contains:

    2^(32 - 28) = 16 addresses

Under traditional host counting, this gives:

    16 - 2 = 14 usable hosts

## Fixed-length subnetting

Fixed-length subnetting divides a parent network into equal-sized child networks.

For example:

    Parent: 192.168.1.0/24
    Child prefix: /26

The result is four equal subnets:

    192.168.1.0/26
    192.168.1.64/26
    192.168.1.128/26
    192.168.1.192/26

Each contains 64 total addresses.

Each traditional subnet has 62 usable host addresses.

Fixed-length subnetting is simple and predictable, but it can waste addresses when different departments or links have substantially different requirements.

## Host requirement calculations

A common network-design problem starts with a required number of hosts rather than a prefix.

The objective is to find the smallest subnet that can support the requirement.

For example, suppose 50 hosts are required.

A `/27` provides:

    2^5 = 32 total addresses
    32 - 2 = 30 traditional usable hosts

That is insufficient.

A `/26` provides:

    2^6 = 64 total addresses
    64 - 2 = 62 usable hosts

Therefore:

    50 hosts -> /26

The function `required_prefix_for_hosts()` performs this calculation programmatically.

The script tests requirements including 2, 6, 14, 30, 50, 62, 100, 250, 500, and 1000 hosts.

## Prefix capacity reference

Important common IPv4 prefixes include:

    /24 -> 256 total, 254 traditional usable
    /25 -> 128 total, 126 traditional usable
    /26 -> 64 total, 62 traditional usable
    /27 -> 32 total, 30 traditional usable
    /28 -> 16 total, 14 traditional usable
    /29 -> 8 total, 6 traditional usable
    /30 -> 4 total, 2 traditional usable

The host capacity falls rapidly as the prefix length increases.

A longer prefix does not mean more hosts. It means more network bits and fewer host bits.

## Prefix-length comparison

The script produces a comparison table covering prefixes from `/8` through `/32`.

The general relationship is:

    Smaller prefix number -> larger address block
    Larger prefix number  -> smaller address block

For example:

    /16 > /20 > /24 > /28

in terms of address-space size.

In terms of prefix length itself:

    16 < 20 < 24 < 28

The two concepts should not be confused.

## Subnet membership

To determine whether an address belongs to a subnet, the address is compared with the subnet's network and prefix.

For example:

    192.168.1.100
    192.168.1.0/24

belongs to the subnet because it falls between:

    192.168.1.0
    192.168.1.255

An address such as:

    192.168.2.100

does not belong to that subnet.

The function `address_belongs_to_subnet()` performs this test.

`classify_address_in_subnet()` goes further and identifies whether an address is:

- Outside the subnet
- The network address
- The broadcast address
- A traditional usable host address
- A point-to-point address
- A single-host route

## VLSM

VLSM stands for Variable Length Subnet Mask.

VLSM allows different parts of the same parent network to use different prefix lengths.

This is useful because real networks rarely have identical requirements.

For example:

    Engineering: 100 hosts
    Finance:      50 hosts
    HR:            25 hosts
    Point-to-point link: 2 addresses

Giving every group a `/24` would waste a large amount of address space.

VLSM can instead allocate approximately:

    100 hosts -> /25
    50 hosts  -> /26
    25 hosts  -> /27
    2 hosts   -> /29 under traditional host-count requirements

The script's `allocate_vlsm()` function uses a largest-first strategy.

## Why VLSM uses largest requirements first

A VLSM allocator must consider address-space fragmentation.

If a small subnet is placed in an unfortunate location before a large subnet is allocated, the remaining space may become unsuitable for the larger block.

The largest-first approach reduces this risk.

The script therefore:

1. Validates the parent network.
2. Sorts requirements by descending host demand.
3. Determines the smallest suitable prefix for each requirement.
4. Aligns each allocation to an appropriate subnet boundary.
5. Ensures the allocation remains inside the parent network.
6. Advances the allocation pointer.
7. Reports an error when the parent block cannot satisfy the requirements.

This demonstrates the difference between calculating subnet capacity and actually planning a collection of subnets.

## VLSM alignment

CIDR networks have alignment requirements.

A subnet is not valid merely because it contains the required number of addresses. Its starting address must correspond to the boundary determined by its prefix.

For example, a `/26` has 64 addresses, so valid boundaries in a `/24` include:

    .0
    .64
    .128
    .192

An arbitrary address such as:

    192.168.1.37/26

is a host address within:

    192.168.1.0/26

The normalized network is therefore:

    192.168.1.0/26

This boundary behavior is essential when manually allocating VLSM blocks.

## Supernetting and route aggregation

Subnetting divides address space into smaller networks.

Supernetting or route aggregation combines multiple appropriately aligned networks into a larger summarized prefix.

For example:

    192.168.0.0/24
    192.168.1.0/24
    192.168.2.0/24
    192.168.3.0/24

can be summarized as:

    192.168.0.0/22

because four `/24` networks contain:

    4 × 256 = 1024 addresses

and:

    1024 = 2^10

so the combined prefix contains 10 host bits:

    32 - 10 = /22

The networks must be contiguous and correctly aligned for such aggregation.

The function `summarize_networks()` uses `ipaddress.collapse_addresses()` to perform this operation safely.

## Common prefix length

Two addresses can be compared by examining their leading bits.

The script's `common_prefix_length()` uses XOR to determine where the two addresses first differ.

If two addresses are identical, all 32 bits are shared.

If the XOR result contains a one in a particular position, the addresses differ at that position.

The number of leading zero bits in the XOR result therefore corresponds to the number of shared leading bits.

This technique is closely related to prefix matching in routing.

## Smallest covering network

The function `smallest_covering_network()` finds the smallest CIDR network containing two IPv4 addresses.

For example, addresses within the same `/24` will produce a covering network no broader than necessary for those two endpoints.

This illustrates the relationship between address comparison, common prefixes, and CIDR aggregation.

## Private IPv4 addressing

The three traditional RFC 1918 private IPv4 ranges are:

    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16

These ranges are widely used inside private networks and are not globally routed as ordinary public IPv4 address space.

The script defines these networks explicitly and uses `is_private_rfc1918()` to distinguish RFC 1918 membership from Python's broader special-address classification.

This distinction matters because the term "private" can be used more broadly in software libraries to include special-purpose address ranges.

## Special IPv4 addresses

IPv4 contains address ranges and individual addresses with special meanings.

The script demonstrates properties such as:

- Private or special-purpose status
- Loopback
- Link-local
- Multicast
- Unspecified
- Reserved

The exact classification should be based on the intended networking standard and context rather than assuming that every address marked `private` by a software library belongs specifically to RFC 1918.

## The `/31` prefix

A `/31` contains exactly two IPv4 addresses.

Traditional subnet mathematics would normally identify one address as the network address and one as the broadcast address, leaving zero traditional usable hosts.

Point-to-point links changed the practical interpretation of this case. A `/31` can be used for point-to-point links because such links do not require a conventional broadcast destination in the same way that multi-access LANs do.

Therefore, the common classroom formula:

    2^host_bits - 2

should not be treated as a universal rule for every IPv4 prefix.

The script explicitly identifies `/31` as a special case.

## The `/32` prefix

A `/32` contains exactly one address.

There are:

    2^(32 - 32) = 1

total addresses.

A `/32` is not an ordinary multi-host subnet. It commonly represents a single host route, loopback identifier, or precise routing object.

For this reason, the traditional network-plus-broadcast host formula is not appropriate for `/32`.

## Error handling

Subnetting software must validate input because malformed addresses and prefixes can otherwise lead to incorrect network plans.

The script demonstrates validation for inputs such as:

    300.1.1.1
    192.168.1.1/33
    192.168.1.1/not-a-prefix
    255.0.255.0

These are rejected.

A robust implementation should distinguish:

- Invalid IPv4 syntax
- Invalid prefix length
- Invalid subnet mask
- Non-contiguous subnet mask
- Host requirements that cannot be represented
- VLSM allocations that exceed the parent block
- Child prefixes that are shorter than their parent prefix

The script raises `ValueError` for invalid user-level subnet parameters.

## Address efficiency

Subnet selection is a trade-off between capacity and address utilization.

Suppose an organization requires 50 traditional usable host addresses.

A `/26` provides 62 usable addresses.

The unused capacity is:

    62 - 50 = 12 addresses

A `/27` would provide only 30 usable addresses and therefore cannot satisfy the requirement.

The script's `address_efficiency()` function calculates the percentage of usable capacity consumed by a requirement.

This is useful during network planning because the smallest technically valid subnet is often preferable when address conservation is important.

## Fixed-length subnetting versus VLSM

Fixed-length subnetting gives each subnet the same size.

Advantages include:

- Simple planning
- Predictable boundaries
- Straightforward administration
- Simple calculations

Limitations include:

- Address waste when requirements vary
- Less flexible allocation
- Potentially larger routing or segmentation blocks than necessary

VLSM permits different subnet sizes.

Advantages include:

- Better address utilization
- More flexible network design
- Appropriate allocation for departments of different sizes
- Efficient treatment of point-to-point links

Limitations include:

- More complex planning
- Greater risk of allocation mistakes
- Greater need for accurate documentation
- More complicated manual calculations

## CIDR versus traditional classful addressing

Classful addressing historically associated major network sizes with Classes A, B, and C.

Examples included:

    Class A -> /8
    Class B -> /16
    Class C -> /24

Modern CIDR does not require networks to follow these boundaries.

CIDR permits prefixes such as:

    /13
    /19
    /22
    /27
    /30

This flexibility is essential for efficient address allocation and modern routing.

The important unit is the prefix length rather than the historical class.

## Common subnetting mistakes

### Mistaking prefix length for host capacity

A `/28` does not provide 28 host bits.

It provides:

    32 - 28 = 4 host bits

### Forgetting network and broadcast reservations

For a traditional `/24`:

    256 total
    254 traditional usable

not 256 traditional host addresses.

### Treating `/31` like an ordinary subnet

The traditional `total - 2` rule does not describe practical point-to-point `/31` usage correctly.

### Treating `/32` as a normal LAN subnet

A `/32` identifies one IPv4 address.

### Choosing an arbitrary network address

A CIDR network must begin on the correct boundary for its prefix.

### Assuming every four `/24` networks can always be summarized

Aggregation requires correct alignment and coverage. Merely having four networks is not sufficient if their addresses do not form a valid contiguous aligned block.

### Confusing subnet mask and wildcard mask

A subnet mask has ones for network bits and zeros for host bits.

A wildcard mask reverses those bits.

For `/24`:

    Subnet mask: 255.255.255.0
    Wildcard:    0.0.0.255

### Ignoring actual requirements

A network should be designed from expected address consumption rather than assigning the same arbitrary prefix to every segment.

## Implementation considerations

The script uses Python's `ipaddress` module for reliable IPv4 parsing, normalization, membership testing, subnet generation, and address aggregation.

This is preferable to manually parsing strings in production software because it reduces the number of opportunities for validation and arithmetic errors.

The script also converts IPv4 addresses into integers when demonstrating low-level calculations.

An IPv4 address can be represented as an integer from:

    0

through:

    4,294,967,295

This allows network operations to be expressed using ordinary integer bitwise operators.

For example:

    network = ip_integer & mask_integer

The broadcast address can be derived using the inverse mask:

    broadcast = network | wildcard

## Performance considerations

For ordinary network planning, the Python `ipaddress` module provides sufficient performance and considerably improves readability.

For very large address-processing workloads, integer representations can be useful because:

- IPv4 addresses map naturally to 32-bit integers.
- Bitwise operations are efficient.
- Range comparisons can be performed directly.
- Prefix matching can be implemented without repeated string parsing.

The script's integer calculation demonstration shows this approach.

Performance should not be optimized at the expense of correctness. Address validation and clear representation are generally more important than eliminating a small amount of parsing overhead.

## Security considerations

Subnetting itself is an addressing technique rather than a complete security mechanism.

Network segmentation can support security architecture by separating systems into different address ranges, VLANs, routing domains, or security zones.

A subnet boundary does not automatically create a security boundary.

Effective network security may also require:

- Routing controls
- Firewall policies
- Access-control rules
- Authentication
- Network monitoring
- Proper service exposure
- Least-privilege communication paths

Incorrect subnet calculations can also create security problems. An overly broad rule may unintentionally permit traffic from more addresses than intended.

For this reason, exact CIDR interpretation is important when implementing network access-control policies.

## Debugging considerations

When debugging a subnet calculation, verify the following in order:

1. The IPv4 address is syntactically valid.
2. The prefix length is between `/0` and `/32`.
3. The subnet mask corresponds to the intended prefix.
4. The number of host bits is `32 - prefix`.
5. The total address count is `2^host_bits`.
6. The network address has all host bits cleared.
7. The broadcast address has all host bits set.
8. The intended host lies inside the calculated network.
9. Special prefixes such as `/31` and `/32` are handled correctly.
10. VLSM allocations are aligned and remain inside the parent block.

Binary representation is especially useful when a result appears unexpected.

## Production considerations

A production subnet-management system should consider requirements beyond the educational calculations shown here.

Important concerns include:

- Input validation
- IPv4 and IPv6 support
- Duplicate allocation detection
- Overlapping-network detection
- Persistent address-allocation records
- Change management
- Audit trails
- Role-based access control
- Documentation
- Transaction safety
- Concurrency
- Integration with DNS and DHCP systems
- Integration with routing infrastructure
- Testing against authoritative network requirements

The study script focuses specifically on IPv4 subnetting and does not attempt to implement a full enterprise IP address management system.

## Testing

The script includes a `unittest` test suite.

The tests verify:

- Binary conversion
- Prefix and mask conversion
- Basic network calculations
- Non-octet prefixes
- Subnet membership
- Subnet counts
- Equal subnet splitting
- Host-capacity calculations
- VLSM allocation
- CIDR summarization
- `/31` and `/32` address counts
- Invalid prefixes
- Invalid subnet masks

Testing is particularly important for subnetting because a one-bit error can change the network boundary and affect many addresses.

## Important formulas

### Host bits

    Host bits = 32 - prefix length

### Total addresses

    Total addresses = 2^(32 - prefix length)

### Traditional usable hosts

    Usable hosts = 2^(32 - prefix length) - 2

This traditional formula applies to ordinary multi-host IPv4 subnets, not blindly to `/31` and `/32`.

### Number of equal child subnets

If a parent prefix is divided into a longer child prefix:

    Number of child subnets = 2^(child prefix - parent prefix)

For `/24` to `/26`:

    2^(26 - 24)
    = 2^2
    = 4

### Network address

    IP AND subnet mask = network address

### Broadcast address

    Network OR wildcard mask = broadcast address

### Wildcard mask

    Wildcard = bitwise inverse of subnet mask

## Worked example

Consider:

    192.168.10.77/26

The prefix is `/26`.

Therefore:

    Network bits = 26
    Host bits = 6

The total number of addresses is:

    2^6 = 64

The subnet mask is:

    255.255.255.192

The `/26` boundaries in the final octet are:

    0
    64
    128
    192

The value `77` falls into the block beginning at `64`.

Therefore:

    Network address = 192.168.10.64
    Broadcast address = 192.168.10.127

The traditional usable host range is:

    192.168.10.65 - 192.168.10.126

The traditional number of usable hosts is:

    62

This example demonstrates why the prefix length, rather than the host's decimal value alone, determines the subnet boundaries.

## Relationship between subnetting and routing

Routers make forwarding decisions based on destination IP addresses and routing prefixes.

CIDR allows routes to be expressed at different levels of specificity.

For example:

    10.0.0.0/8

is broader than:

    10.20.0.0/16

which is broader than:

    10.20.30.0/24

When multiple routes match a destination, routing systems generally use the most specific applicable prefix. This is commonly described as longest-prefix matching.

Subnetting therefore has a direct relationship with routing-table design.

## Why subnetting matters in practical networks

Subnetting is used to organize address space for:

- Corporate departments
- Office locations
- Cloud networks
- VLANs
- Data centers
- Branch offices
- Point-to-point links
- Infrastructure management
- Server networks
- Application tiers
- Routing domains
- Network security zones

The objective is not simply to perform arithmetic. Good subnet design balances address capacity, organizational boundaries, routing behavior, operational simplicity, and future growth.

## Scope of this study file

The Python script focuses on IPv4 subnetting and covers:

- IPv4 binary representation
- CIDR notation
- Prefix lengths
- Dotted-decimal subnet masks
- Wildcard masks
- Network addresses
- Broadcast addresses
- Traditional usable host ranges
- Host-bit calculations
- Equal-sized subnetting
- Host-capacity planning
- Subnet membership
- VLSM
- CIDR aggregation
- Common-prefix analysis
- RFC 1918 private addressing
- `/31` and `/32`
- Input validation
- Error handling
- Integer-based calculations
- Address-efficiency analysis
- Automated testing

The implementation deliberately keeps the examples self-contained and uses the Python standard library rather than depending on external packages.
