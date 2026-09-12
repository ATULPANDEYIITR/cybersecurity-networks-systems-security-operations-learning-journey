# IPv4 addressing

## Topic introduction

IPv4 addressing is the system used to identify interfaces and endpoints within an IPv4 network. An IPv4 address contains 32 bits and is normally represented as four decimal octets separated by periods.

A typical address is:

    192.168.1.10

Each octet contains eight bits, so an IPv4 address contains:

    8 + 8 + 8 + 8 = 32 bits

An individual octet can represent values from 0 through 255 because eight binary bits provide 256 possible combinations:

    2^8 = 256

The Python script develops IPv4 addressing from binary representation through network identification, subnet masks, CIDR, subnetting, VLSM, public and private addressing, routing concepts, NAT, address planning, edge cases and operational considerations.

## IPv4 terminology

### IPv4 address

An IPv4 address is a 32-bit value used to identify an IPv4 interface or endpoint.

For example:

    192.168.1.10

The decimal notation is called dotted-decimal notation.

The same address in binary is:

    11000000.10101000.00000001.00001010

The four groups correspond to the four octets.

### Octet

An octet is an eight-bit portion of an IPv4 address.

For example:

    192.168.1.10

contains the octets:

    192
    168
    1
    10

Each octet ranges from 0 to 255.

### Bit

A bit is a binary digit that can contain either 0 or 1.

The eight positions in an octet have these values:

    128 64 32 16 8 4 2 1

For example, decimal 192 is:

    128 + 64 = 192

Therefore its binary representation is:

    11000000

### Network ID

The network ID identifies the subnet to which an IPv4 address belongs.

For:

    192.168.1.25/24

the network ID is:

    192.168.1.0

The first 24 bits identify the network, while the remaining eight bits identify the host portion.

### Host ID

The host portion identifies an address within the subnet.

For a /24 network, there are eight host bits.

For:

    192.168.1.25/24

the host portion is represented by the final eight bits.

The network and host portions are determined by the subnet mask or CIDR prefix. They are not permanently attached to particular decimal octets.

### Subnet mask

A subnet mask identifies which bits belong to the network portion and which belong to the host portion.

For example:

    255.255.255.0

is equivalent to:

    /24

Its binary representation is:

    11111111.11111111.11111111.00000000

The 24 ones represent network bits and the eight zeroes represent host bits.

### CIDR prefix

CIDR stands for Classless Inter-Domain Routing.

A CIDR prefix expresses the number of network bits after a slash:

    192.168.1.0/24

The `/24` means that the first 24 of the 32 bits belong to the network portion.

The number of host bits is:

    32 - 24 = 8

## Binary representation

IPv4 addressing is fundamentally binary even though administrators usually work with decimal notation.

For example:

    192.168.1.10

can be converted to:

    11000000.10101000.00000001.00001010

The script implements conversion in both directions and validates that each binary octet contains exactly eight binary digits.

Understanding binary is important because subnetting is based on individual bits rather than decimal numbers.

For example, the masks:

    255.255.255.0
    255.255.255.128
    255.255.255.192

correspond to:

    /24
    /25
    /26

The difference between these masks is the number of bits borrowed from the host portion.

## IPv4 as a 32-bit integer

An IPv4 address can also be represented as an unsigned 32-bit integer.

For example:

    192.168.1.10

has a numerical representation that can be compared, masked and manipulated mathematically.

This representation is useful for programming because network calculations can then be expressed using integer operations.

The script demonstrates conversion in both directions.

The valid integer range for IPv4 is:

    0 through 2^32 - 1

which corresponds to:

    0 through 4294967295

## Subnet masks and prefix lengths

Common prefix lengths include:

| Prefix | Subnet mask | Host bits | Total addresses |
|---|---|---:|---:|
| /8 | 255.0.0.0 | 24 | 16,777,216 |
| /16 | 255.255.0.0 | 16 | 65,536 |
| /20 | 255.255.240.0 | 12 | 4,096 |
| /24 | 255.255.255.0 | 8 | 256 |
| /25 | 255.255.255.128 | 7 | 128 |
| /26 | 255.255.255.192 | 6 | 64 |
| /27 | 255.255.255.224 | 5 | 32 |
| /28 | 255.255.255.240 | 4 | 16 |
| /30 | 255.255.255.252 | 2 | 4 |
| /31 | 255.255.255.254 | 1 | 2 |
| /32 | 255.255.255.255 | 0 | 1 |

The general formula for the number of addresses in an IPv4 network is:

    2^(32 - prefix length)

For example, a /26 network has:

    32 - 26 = 6 host bits

Therefore:

    2^6 = 64

total addresses.

## Network address and broadcast address

For traditional IPv4 subnetting, the network address has all host bits set to zero.

For:

    192.168.1.0/24

the network address is:

    192.168.1.0

The broadcast address has all host bits set to one:

    192.168.1.255

For an ordinary subnet, the addresses between these two boundaries are traditionally used for hosts.

For a /24:

    Network:   192.168.1.0
    First host: 192.168.1.1
    Last host:  192.168.1.254
    Broadcast:  192.168.1.255

This produces:

    256 total addresses
    254 traditional usable host addresses

The traditional formula is:

    usable hosts = 2^host_bits - 2

The two excluded addresses are the network address and broadcast address.

## Bitwise calculation of a network ID

The network address can be calculated using a bitwise AND operation between the IPv4 address and its subnet mask.

For example:

    Address: 192.168.1.130
    Mask:    255.255.255.192

The corresponding binary values are:

    Address:
    11000000.10101000.00000001.10000010

    Mask:
    11111111.11111111.11111111.11000000

Applying AND produces the network bits:

    11000000.10101000.00000001.10000000

which is:

    192.168.1.128

Therefore:

    192.168.1.130/26

belongs to:

    192.168.1.128/26

The script implements this calculation directly using integer bitwise operations.

## Host capacity

The number of host bits determines the address capacity of a subnet.

For a /24:

    Host bits = 32 - 24
              = 8

    Total addresses = 2^8
                    = 256

For traditional host addressing:

    Usable hosts = 256 - 2
                 = 254

For a /26:

    Host bits = 6
    Total addresses = 64
    Traditional usable hosts = 62

For a /30:

    Host bits = 2
    Total addresses = 4
    Traditional usable hosts = 2

The script calculates these values for multiple prefix lengths.

## /31 and /32 special cases

The traditional `2^host_bits - 2` formula should not be applied blindly to every prefix.

A /31 contains two addresses:

    10.0.0.0/31

It is commonly used for point-to-point links, where both addresses can be used as endpoints and there is no conventional broadcast host requirement.

A /32 represents one address:

    10.0.0.1/32

It is commonly used when referring to one specific IPv4 address, such as a host route or loopback-style routing entry.

These special cases demonstrate why subnetting rules must be interpreted according to network context.

## CIDR

CIDR replaced the rigid assumptions of traditional classful addressing with arbitrary prefix lengths.

For example, these are all valid CIDR networks:

    10.0.0.0/8
    10.20.0.0/16
    10.20.30.0/24
    10.20.30.0/27

The prefix length directly defines the network boundary.

CIDR improves address allocation efficiency because networks do not have to conform to only /8, /16 or /24 boundaries.

## Classful addressing

Historically, IPv4 addresses were divided into classes.

| Class | First-octet range | Traditional default prefix | Historical purpose |
|---|---:|---:|---|
| A | 1-126 | /8 | Large networks |
| B | 128-191 | /16 | Medium networks |
| C | 192-223 | /24 | Smaller networks |
| D | 224-239 | Not ordinary host addressing | Multicast |
| E | 240-255 | Special | Experimental/reserved history |

Classful addressing is important historically and educationally, but modern IPv4 routing primarily uses CIDR.

A common mistake is assuming that the first octet alone determines the modern network boundary. In CIDR, the prefix length determines the boundary.

## Public and private IPv4 addresses

Private IPv4 addressing is defined by three RFC 1918 address blocks:

    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16

Examples include:

    10.0.0.1
    172.16.20.10
    192.168.1.100

These addresses are intended for private network use and are not normally routed as ordinary globally reachable IPv4 destinations across the public Internet.

A critical distinction is that private does not mean encrypted or automatically secure.

A private network can still contain compromised systems, vulnerable services or unauthorized users.

Public IPv4 addresses are addresses intended for use in globally routed addressing contexts. Whether an individual address is actually reachable depends on routing, firewall rules, NAT, provider configuration and other operational factors.

## Important private-addressing edge case

Not every address beginning with `172` is private.

The private range is:

    172.16.0.0/12

which covers:

    172.16.0.0 through 172.31.255.255

Therefore:

    172.16.1.1

is private, while:

    172.32.1.1

is not part of the RFC 1918 private range.

This is one of the most common IPv4 addressing mistakes.

## Special IPv4 ranges

Several IPv4 ranges have specialized meanings.

### Unspecified address

    0.0.0.0

The unspecified address can represent the absence of a specific IPv4 address in appropriate contexts.

The network:

    0.0.0.0/0

has a different and very important routing meaning: it represents the default route covering all IPv4 destinations.

### Loopback

    127.0.0.0/8

The loopback range is used for communication within the local host.

The most familiar loopback address is:

    127.0.0.1

It is commonly used to refer to the local machine.

### Link-local

    169.254.0.0/16

IPv4 link-local addresses can be automatically configured when a device cannot obtain an appropriate address through another mechanism in supported environments.

### Multicast

    224.0.0.0/4

This range is used for IPv4 multicast addressing rather than ordinary unicast host addressing.

### Limited broadcast

    255.255.255.255

This address represents the limited broadcast address in IPv4.

Special-purpose addresses should be interpreted according to their defined networking context rather than treated as ordinary host addresses.

## Subnetting

Subnetting divides a larger network into smaller networks.

Suppose the original network is:

    192.168.1.0/24

and it is divided into /26 networks.

The prefix changes from /24 to /26, meaning two additional bits are used for subnetting.

The number of resulting equal-sized subnets is:

    2^(26 - 24)
    = 2^2
    = 4

The four networks are:

    192.168.1.0/26
    192.168.1.64/26
    192.168.1.128/26
    192.168.1.192/26

Each contains 64 total addresses and traditionally 62 usable host addresses.

## Choosing a subnet from a host requirement

Subnet design often begins with a requirement such as:

    Department needs 50 hosts.

The designer must select a subnet with enough host capacity.

For 50 hosts:

    2^5 - 2 = 30

is insufficient.

The next size is:

    2^6 - 2 = 62

Therefore a /26 network is appropriate for the traditional host-count model.

The script calculates the smallest prefix capable of supporting several host requirements.

This approach avoids unnecessarily assigning a much larger subnet than required.

## VLSM

VLSM stands for Variable Length Subnet Masking.

VLSM allows different subnets within a larger address block to use different prefix lengths.

Consider a /24 network containing departments requiring:

    Development: 100 hosts
    Operations: 40 hosts
    Administration: 20 hosts
    Network devices: 10 hosts

Giving every department a /24 would waste substantial address space.

VLSM can instead allocate approximately sized networks:

    100 hosts -> /25
    40 hosts  -> /26
    20 hosts  -> /27
    10 hosts  -> /28

The exact allocation must also respect subnet boundaries and available address space.

The script implements a largest-first VLSM allocation strategy and verifies that the resulting blocks fit within the parent network.

## Same-subnet determination

Two IPv4 addresses are in the same subnet when their network portions are identical under the selected prefix.

For example:

    192.168.1.10/24
    192.168.1.200/24

both belong to:

    192.168.1.0/24

Therefore they are in the same /24 subnet.

By contrast:

    192.168.1.10/24
    192.168.2.10/24

belong to different networks:

    192.168.1.0/24
    192.168.2.0/24

The script performs these checks using Python's IPv4 network representation.

## Default gateway

A host uses a directly connected network to determine whether a destination is local.

For example, a host configured as:

    192.168.10.50/24

belongs to:

    192.168.10.0/24

An address such as:

    192.168.10.80

is in the same subnet.

An address such as:

    8.8.8.8

is outside that subnet.

For an external destination, the host normally forwards the packet toward its configured default gateway.

The default gateway is therefore a fundamental component of IPv4 host configuration.

## DHCP

DHCP is commonly used to automatically provide IPv4 configuration to hosts.

The commonly taught DHCP exchange is represented by DORA:

    Discover
    Offer
    Request
    Acknowledgement

DHCP can provide information such as:

    IPv4 address
    subnet mask
    default gateway
    DNS server information
    lease duration

DHCP reduces manual configuration and makes address allocation easier to manage.

Infrastructure that requires stable addressing can use static configuration or DHCP reservations according to the network design.

## Routing and longest-prefix matching

Routers can have multiple routes that match the same destination.

Consider:

    0.0.0.0/0
    10.0.0.0/8
    10.20.0.0/16
    10.20.30.0/24

The destination:

    10.20.30.40

matches all four networks.

The most specific matching route is:

    10.20.30.0/24

This is called longest-prefix matching.

The route with the largest prefix length among matching routes is considered more specific.

This principle is fundamental to IP routing decisions.

## Route summarization

Route summarization combines contiguous address space into a smaller number of routing entries when the address structure permits it.

For example, these four /24 networks:

    192.168.0.0/24
    192.168.1.0/24
    192.168.2.0/24
    192.168.3.0/24

can be represented by:

    192.168.0.0/22

when the entire range is intentionally reachable through the same summarized route.

Route summarization can reduce routing-table size.

Incorrect summarization can attract traffic toward the wrong location, so the summarized range must accurately reflect the underlying network topology.

## NAT and private addresses

NAT stands for Network Address Translation.

A common deployment uses private addresses internally and translates outbound connections to a public IPv4 address.

Conceptually:

    Internal source:
    192.168.1.20:51500

    NAT-translated source:
    203.0.113.10:40001

    Destination:
    198.51.100.20:443

The translation can include both an address and a transport-layer port.

NAT helps organizations use private IPv4 address space while sharing one or more public addresses.

NAT should not be confused with encryption or a complete security boundary.

Security still requires appropriate firewall policies, authentication, authorization, monitoring and other controls.

## Address planning

An IPv4 address plan should establish predictable and non-overlapping network boundaries.

Useful planning considerations include:

- Number of current hosts
- Expected growth
- Department or functional segmentation
- Infrastructure addresses
- DHCP pools
- Reserved addresses
- Default gateways
- Routing boundaries
- Security zones
- Documentation requirements

A well-designed plan avoids unnecessary fragmentation while preserving enough capacity for expected growth.

## Overlapping networks

Overlapping networks are networks whose address ranges intersect.

For example:

    10.0.0.0/8

contains:

    10.20.0.0/16

If these are intended to represent independent networks, the design is problematic because the address spaces overlap.

Overlaps can create:

- Ambiguous routing
- Incorrect subnet classification
- Difficult VPN configuration
- Complicated network migrations
- Problems with network segmentation
- Unexpected traffic paths

The script includes a function that detects overlapping IPv4 networks.

## Address enumeration and memory efficiency

Small networks can be enumerated directly.

For example:

    192.168.1.0/29

contains only eight total addresses.

Large networks should not automatically be converted into a complete Python list.

A /8 contains:

    16,777,216

addresses.

Materializing millions of objects unnecessarily consumes memory.

A more efficient approach is to use iterators, process addresses incrementally, or perform arithmetic using integer representations and prefixes.

The script limits host enumeration to a specified number of results.

## Correct IPv4 sorting

IPv4 addresses should not be treated as ordinary strings when numerical ordering is required.

For example:

    192.168.1.2
    192.168.1.100

are numerically ordered according to their IPv4 values, not their character sequences.

The Python `ipaddress` module provides IPv4-aware comparison behavior.

For systems processing large address collections, converting addresses to integers can also make numerical operations straightforward.

## Performance considerations

IPv4 calculations can often be represented efficiently using:

- 32-bit integer values
- Integer subnet masks
- Prefix lengths
- Bitwise AND operations
- Prefix-based lookup structures

For example, network identification can be calculated as:

    network = address AND mask

Repeated parsing of the same address is unnecessary when the integer form can be cached.

Large routing systems require efficient lookup structures because checking every route sequentially does not scale well. Real routing implementations use specialized algorithms and data structures designed for prefix matching.

The Python implementations in the script are intended for learning and small-scale computation rather than replacing production routing software.

## Security considerations

IPv4 addressing contributes to network organization but does not independently provide security.

### Private addressing is not encryption

A private address such as:

    192.168.1.10

does not mean that traffic is encrypted.

Encryption must be provided by appropriate protocols and systems.

### Public does not mean automatically unsafe

A public address can be protected by firewalls, access controls, authentication and other mechanisms.

The classification of an address as public or private should not be used as the only security decision.

### IP addresses are not identity proofs

An IPv4 source address identifies a network-layer source address in the packet. It does not inherently prove the identity of the person or application generating the traffic.

Source-address spoofing is one reason network-layer addressing should not be treated as an authentication mechanism.

### Segmentation

Subnetting can support network segmentation by separating groups of systems into different address spaces.

Segmentation is most effective when combined with routing policy, firewall rules and appropriate access controls.

### Logging

IPv4 addresses are useful for troubleshooting and security monitoring, but an address should not automatically be interpreted as a unique human identity.

Dynamic addressing, NAT, shared devices and other network mechanisms can result in multiple users or systems appearing behind the same public address.

## Common mistakes

### Mistake: treating every 172.x.x.x address as private

Only:

    172.16.0.0/12

is part of the RFC 1918 private address space.

### Mistake: assuming every network is a /24

Modern IPv4 networks use CIDR prefixes of many sizes.

Examples include:

    /8
    /16
    /20
    /24
    /27
    /30
    /31
    /32

### Mistake: ignoring the network address

In traditional subnetting, the address with all host bits equal to zero represents the network itself.

### Mistake: ignoring the broadcast address

In traditional IPv4 subnetting, the address with all host bits equal to one represents the subnet's broadcast address.

### Mistake: applying the traditional host formula to /31

A /31 is a special case commonly used for point-to-point links.

### Mistake: assuming private means secure

Private addressing does not replace firewalling, encryption, authentication or authorization.

### Mistake: comparing IP addresses as strings

IP addresses should be compared numerically or with an IP-aware library.

### Mistake: creating overlapping subnets

Overlapping address spaces can make routing and segmentation difficult or impossible to operate correctly.

### Mistake: confusing network ID with host ID

The network and host portions depend on the prefix length.

For:

    192.168.1.10/24

the boundary occurs after 24 bits.

For:

    192.168.1.10/26

the boundary occurs after 26 bits.

The same decimal address can therefore have different network and host portions under different prefixes.

## Edge cases

### 0.0.0.0

Its meaning depends on context. It can represent an unspecified address, while `0.0.0.0/0` is commonly used as the default IPv4 route.

### 127.0.0.1

This is a loopback address and refers to the local host in common usage.

### 169.254.0.0/16

This is the IPv4 link-local range.

### 224.0.0.0/4

This is the IPv4 multicast range.

### 255.255.255.255

This is the limited broadcast address.

### /32

A /32 contains exactly one IPv4 address and has zero host bits.

### /31

A /31 contains two addresses and is commonly used for point-to-point links.

These cases demonstrate why IPv4 rules should be applied according to context rather than by memorized formulas alone.

## Implementation considerations

The script uses Python's standard-library `ipaddress` module for reliable IPv4 parsing and network manipulation.

The module provides objects such as:

    IPv4Address
    IPv4Interface
    IPv4Network

The script also implements several calculations manually to demonstrate what happens underneath the higher-level abstraction.

The manual network calculation uses:

    address AND subnet mask

to obtain the network address.

The broadcast address is obtained by combining the network address with the inverted host mask.

This combination of library-based validation and manual bitwise demonstrations is useful for understanding both practical programming and the underlying networking mathematics.

## Testing

The script includes assertions covering:

- Decimal-to-binary conversion
- Binary-to-decimal conversion
- IPv4 round-trip conversion
- IPv4 validation
- Prefix-to-mask conversion
- Mask-to-prefix conversion
- Network identification
- Broadcast calculation
- Private-address detection
- CIDR membership
- Same-subnet checks
- Subnet generation
- Host-capacity calculations
- Manual bitwise network calculation
- Longest-prefix routing selection

The test section is intentionally contained within the same study file so that the examples are executable and their core calculations can be checked automatically.

## Practical IPv4 design example

The script includes a practical VLSM scenario using:

    192.168.50.0/24

with requirements for:

    Development: 100 hosts
    Operations: 40 hosts
    Administration: 20 hosts
    Network devices: 10 hosts

The required subnet sizes are determined from the host requirements and allocated within the parent address space.

This illustrates how a real address plan can move from:

    business or technical requirement

to:

    host requirement

to:

    prefix length

to:

    subnet boundary

to:

    host range

to:

    broadcast address

This process is central to practical IPv4 network design.

## IPv4 formula reference

### Number of host bits

    host_bits = 32 - prefix_length

### Total addresses

    total_addresses = 2^host_bits

### Traditional usable hosts

    usable_hosts = 2^host_bits - 2

The traditional usable-host formula applies to ordinary IPv4 subnetting and requires special consideration for /31 and /32.

### Number of equal subnets

When increasing a prefix from an original length to a new length:

    number_of_subnets = 2^(new_prefix - original_prefix)

For example:

    /24 -> /26

gives:

    2^(26 - 24)
    = 4

subnets.

## IPv4 reference table

| Concept | Value or rule |
|---|---|
| IPv4 size | 32 bits |
| Number of octets | 4 |
| Bits per octet | 8 |
| Octet range | 0-255 |
| Private range | 10.0.0.0/8 |
| Private range | 172.16.0.0/12 |
| Private range | 192.168.0.0/16 |
| Loopback | 127.0.0.0/8 |
| Link-local | 169.254.0.0/16 |
| Multicast | 224.0.0.0/4 |
| Network bits | Prefix length |
| Host bits | 32 minus prefix length |
| Total addresses | 2^(host bits) |
| Traditional usable hosts | 2^(host bits) - 2 |
| Single-address prefix | /32 |
| Point-to-point special prefix | /31 |
| Default route | 0.0.0.0/0 |

## Relationship between the major concepts

IPv4 addressing concepts form a connected sequence.

An IPv4 address contains 32 bits.

The subnet mask or CIDR prefix divides those bits into network and host portions.

The network portion determines the network ID.

The host portion determines the position of the address within that network.

The number of host bits determines address capacity.

Changing the prefix changes the size of the network.

Subnetting uses additional network bits to create smaller networks.

VLSM allows those smaller networks to have different sizes.

CIDR provides the addressing model used for modern classless network design.

Routing uses prefixes to determine where traffic should be forwarded.

Longest-prefix matching selects the most specific route when multiple routes match.

Private IPv4 addressing provides non-public address space for internal networks, while NAT can translate private addresses into public addressing contexts.

These relationships connect binary arithmetic, subnet masks, address planning and routing into one coherent IPv4 addressing model.
