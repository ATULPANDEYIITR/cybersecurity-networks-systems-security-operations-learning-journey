# Ethernet: MAC addresses, frames, NICs, switching, broadcast domains, and collision domains

## Topic introduction

Ethernet is one of the fundamental technologies used to connect devices within local area networks. It defines how devices communicate over a local link, how data is placed into frames, how network interfaces identify one another, and how Layer 2 switches decide where frames should be sent.

The central concepts covered by the accompanying Python script are:

- MAC addresses
- Ethernet frames
- Network Interface Cards (NICs)
- Ethernet switches
- MAC address learning
- Forwarding and filtering
- Flooding
- Unicast, broadcast, and multicast
- Broadcast domains
- Collision domains
- Hubs
- Half-duplex and full-duplex Ethernet
- CSMA/CD
- VLANs
- MAC address tables
- Frame validation
- Layer 2 loops
- Broadcast storms
- Ethernet security
- Ethernet performance
- Troubleshooting and network design

The Python program implements simplified versions of these mechanisms so that the behavior can be observed directly.

## Ethernet fundamentals

Ethernet primarily operates at the Data Link Layer, Layer 2, of the OSI model. Ethernet is responsible for framing data for transmission across a local network link and for identifying local Layer 2 destinations using MAC addresses.

A simplified communication path can be represented as:

Application data → transport data → IP packet → Ethernet frame → physical transmission

Ethernet itself does not provide the complete functionality required for communication across arbitrary networks. IP addressing and routing operate at Layer 3, while Ethernet normally provides local-link delivery.

A common modern network can therefore contain:

- End hosts
- NICs
- Ethernet switches
- Routers or Layer 3 switches
- Access points
- Firewalls
- Other network infrastructure

The script concentrates on the Ethernet and Layer 2 portion of this architecture.

## MAC addresses

A MAC address is a Layer 2 address associated with a network interface.

A commonly encountered Ethernet MAC address is 48 bits long and is written as six hexadecimal octets:

    00:1A:2B:3C:4D:5E

Each octet contains eight bits, so:

    6 octets × 8 bits = 48 bits

The Python `MACAddress` class validates and represents this structure.

### MAC address components

A traditional globally administered MAC address is commonly discussed as containing:

- An organizationally significant first portion
- An interface-specific remaining portion

The first three octets are commonly associated with an Organizationally Unique Identifier, or OUI.

Modern systems also use locally administered MAC addresses. Therefore, the first three octets should not automatically be assumed to identify the actual physical manufacturer in every situation.

### Unicast addresses

A unicast MAC address identifies an individual Layer 2 destination.

Example:

    02:00:00:00:00:01

A switch can learn the port associated with such an address and subsequently forward traffic selectively.

### Broadcast address

Ethernet broadcast uses:

    FF:FF:FF:FF:FF:FF

A broadcast is intended for all eligible devices within the relevant Layer 2 broadcast domain.

ARP requests are a common example of IPv4-related traffic that uses Ethernet broadcast.

### Multicast addresses

Multicast addresses identify a group rather than one individual destination.

The first-octet multicast bit distinguishes multicast addressing from unicast addressing.

The script classifies addresses into:

- Unicast
- Broadcast
- Multicast

## Network Interface Card

A Network Interface Card, or NIC, provides the host with an interface to a network.

An Ethernet NIC is responsible for significant hardware and firmware operations, including transmission and reception of Ethernet frames.

The simplified `NIC` class in the script models several important concepts:

- A device name
- A MAC address
- Frame transmission
- Frame reception
- Destination filtering
- Promiscuous mode
- Storage of received and transmitted frames

A normal NIC does not simply accept every Ethernet frame it sees. It examines the destination and relevant receive configuration.

A frame addressed to another unicast MAC will normally be discarded by the host's NIC.

Broadcast frames are normally accepted.

Multicast handling depends on multicast configuration and group membership.

## Promiscuous mode

Promiscuous mode allows a network interface to receive frames that would normally be discarded because their destination MAC does not match the interface.

This capability is useful for traffic analysis and network troubleshooting.

Promiscuous mode does not mean that a switch automatically sends every unicast frame to the monitoring device. A switched network normally forwards known unicast traffic only to the destination port.

Network monitoring therefore often requires an appropriate switch configuration, such as a monitoring or mirror mechanism.

## Ethernet frames

An Ethernet frame is the Layer 2 unit used to carry data across an Ethernet link.

A simplified Ethernet II frame contains:

- Destination MAC address
- Source MAC address
- EtherType
- Payload
- Frame Check Sequence

The Python `EthernetFrame` class represents these fields.

### Destination MAC

The destination MAC identifies the intended Layer 2 recipient.

Examples include:

    02:00:00:00:01:01

for a unicast destination, and:

    FF:FF:FF:FF:FF:FF

for broadcast.

### Source MAC

The source MAC identifies the interface that originated the frame on that local Ethernet segment.

Switches use the source MAC as an important input to their learning process.

### EtherType

EtherType identifies the protocol carried by the Ethernet payload.

Examples implemented in the script include:

- `0x0800`: IPv4
- `0x0806`: ARP
- `0x86DD`: IPv6
- `0x8100`: VLAN-tagging context

EtherType allows a receiver to determine how the payload should be interpreted.

### Payload

The payload contains the higher-layer data carried by the Ethernet frame.

Traditional Ethernet commonly uses a maximum payload size of 1500 bytes for the standard MTU.

The script validates payload sizes against this traditional limit.

### Frame Check Sequence

The Frame Check Sequence, or FCS, provides error-detection information.

It is used to detect corruption of frames during transmission.

The FCS is not an authentication mechanism. A valid FCS does not prove that a frame originated from a trusted device, nor does it provide cryptographic security.

## Ethernet frame size

Traditional Ethernet has a minimum frame size.

Small payloads are padded so that the frame reaches the required minimum size.

The script therefore distinguishes between:

- Actual payload size
- Padded payload size
- Approximate frame size

The traditional Ethernet payload limit is commonly 1500 bytes.

A standard Ethernet II frame has a 14-byte untagged header:

- 6-byte destination MAC
- 6-byte source MAC
- 2-byte EtherType

A VLAN tag adds four bytes to the Ethernet header.

## MTU

MTU means Maximum Transmission Unit.

For conventional Ethernet, a common IP MTU is:

    1500 bytes

This represents the maximum IP payload carried without requiring fragmentation or other handling at that Layer 3 boundary.

Jumbo frames use larger Ethernet payloads than the traditional 1500-byte value.

Jumbo frames are not automatically supported simply because one device supports them. All relevant components and paths need compatible configuration.

The script demonstrates the relationship between payload size and frame size.

## Ethernet switching

A switch connects multiple Ethernet devices and selectively forwards Layer 2 frames.

The most important mechanism demonstrated by the script is MAC address learning.

A switch observes the source MAC of an incoming frame and records where that MAC was seen.

A simplified MAC table may look like:

    MAC address                  Port
    02:00:00:00:01:01            p1
    02:00:00:00:01:02            p2
    02:00:00:00:01:03            p3

The exact implementation and hardware architecture vary between switch platforms, but the conceptual model is fundamental.

## MAC address learning

When a frame enters a switch on a port, the switch can learn:

    Source MAC → Incoming port

For example, if a frame arrives on `p1` with source MAC:

    02:00:00:00:01:01

the switch can record:

    02:00:00:00:01:01 → p1

The script implements this behavior through its switch MAC table.

Learning is dynamic. If the same source MAC later appears on another port, the switch can update the corresponding entry.

## CAM and MAC address tables

The term CAM table is commonly used in Ethernet switching discussions because hardware implementations historically used Content Addressable Memory for rapid lookup.

The conceptual purpose is the same:

    Destination MAC → forwarding port

The script uses a Python dictionary to model this mapping.

Real switches use specialized hardware and implementation techniques to provide very fast forwarding.

## Switch forwarding behavior

A simplified switch decision process is:

1. Receive a valid frame.
2. Examine the source MAC.
3. Learn the source MAC on the incoming port.
4. Examine the destination MAC.
5. Determine whether the destination is broadcast, multicast, known unicast, or unknown unicast.
6. Forward, filter, or flood the frame accordingly.

### Known unicast

If the destination MAC is present in the switch table and belongs to another port, the switch forwards the frame to that port.

Example:

    Destination MAC → p4

The switch does not need to send the frame to every port.

This reduces unnecessary traffic compared with a shared-medium design.

### Destination on the incoming port

If the switch determines that the destination is already located on the incoming port, sending the frame back out that same port is unnecessary.

The frame can therefore be filtered.

### Unknown unicast

If the destination MAC is not present in the table, the switch does not know which port leads to the destination.

The frame is normally flooded within the relevant Layer 2 domain or VLAN.

Once the destination device sends traffic, the switch can learn its source MAC and future traffic can become selectively forwarded.

## Flooding

Flooding means sending a frame through multiple eligible ports rather than selecting one known destination port.

A switch may flood:

- Broadcast frames
- Some multicast traffic
- Unknown unicast frames
- Certain protocol-specific traffic

The incoming port is normally excluded from ordinary flooding.

Flooding is an important part of Ethernet behavior because a switch cannot selectively forward traffic to an unknown destination.

## Unicast, broadcast, and multicast

The script demonstrates three major Ethernet destination categories.

### Unicast

One logical destination.

Example:

    PC-A → PC-B

The switch can normally forward a known unicast only to PC-B's switch port.

### Broadcast

All eligible devices within the Layer 2 broadcast domain.

Example:

    PC-A → FF:FF:FF:FF:FF:FF

A switch floods the broadcast within the appropriate VLAN.

### Multicast

A logical group of receivers.

Multicast behavior can be optimized by switch features such as multicast snooping, depending on the technology and configuration.

The simplified program treats multicast as traffic that may be flooded within the relevant domain.

## Hub versus switch

A hub is fundamentally different from a switch.

### Hub

A traditional Ethernet hub operates at the physical layer.

It does not learn MAC addresses.

When a signal enters one port, the hub repeats it toward the other ports.

Therefore, devices attached to the same hub share the same collision domain.

### Switch

A switch primarily operates at Layer 2.

It:

- Learns source MAC addresses
- Maintains a forwarding table
- Selectively forwards known unicast frames
- Filters frames where appropriate
- Floods broadcast and unknown unicast traffic

Modern Ethernet networks therefore generally use switches rather than traditional shared-media hubs.

## Collision domains

A collision domain is a portion of an Ethernet network in which simultaneous transmissions can interfere with each other.

This concept is particularly important for older shared Ethernet.

With a hub:

    Host A
       |
    Host B --- Hub --- Host C
       |
    Host D

all hosts share a collision domain.

If two hosts transmit simultaneously, their signals can interfere.

With modern switched full-duplex Ethernet, each point-to-point link is isolated from other switch access links.

A simplified switched topology is:

    Host A ---- Switch ---- Host B
    Host C ---- Switch ---- Host D

Each host-to-switch link represents its own collision domain under the usual conceptual model.

## Broadcast domains

A broadcast domain is the set of devices that receive a Layer 2 broadcast within a particular logical network segment.

A basic switch does not normally break a broadcast domain.

If four devices are connected to the same VLAN:

    PC-A
    PC-B
    PC-C
    PC-D

a broadcast sent by PC-A can reach the other eligible devices.

Broadcast domains can be separated using:

- VLANs
- Routers
- Layer 3 switch interfaces
- Other Layer 3 boundaries

## Collision domain versus broadcast domain

These concepts must not be confused.

| Concept | Meaning |
|---|---|
| Collision domain | Area where simultaneous Ethernet transmissions can collide |
| Broadcast domain | Area through which Layer 2 broadcasts propagate |

A switch reduces collision-domain size while normally leaving the broadcast domain intact.

VLANs allow a switch to contain multiple separate broadcast domains.

## Half-duplex Ethernet

Half-duplex communication allows transmission in one direction at a time over a shared medium.

A simplified model is:

    A ←→ Shared medium ←→ B

If both sides transmit at the same time, a collision can occur.

Half-duplex Ethernet therefore historically required collision-management mechanisms.

## Full-duplex Ethernet

Full-duplex communication allows both sides of a point-to-point link to transmit simultaneously.

Conceptually:

    A ⇄ dedicated link ⇄ B

Full-duplex switched Ethernet eliminates the ordinary shared-medium collision condition on that link.

Modern Ethernet networks overwhelmingly rely on full-duplex switched connectivity.

## CSMA/CD

CSMA/CD stands for:

    Carrier Sense Multiple Access with Collision Detection

It was fundamental to classic shared Ethernet.

The simplified process is:

1. Listen to the medium.
2. If the medium is busy, wait.
3. Transmit when the medium is available.
4. Detect a collision if one occurs.
5. Stop transmitting.
6. Send a jam signal.
7. Wait using a backoff algorithm.
8. Retry.
9. Give up after the maximum number of attempts.

The script implements an educational simulation of this process.

## Binary exponential backoff

After a collision, Ethernet historically used binary exponential backoff to reduce the probability that the same devices would immediately collide again.

The contention window expands as repeated collisions occur.

The basic principle is:

    More collisions → potentially larger waiting interval

This distributes retransmission attempts over increasingly broad intervals.

The precise protocol details involve slot times, retry limits, and contention-window rules.

CSMA/CD should be understood as an important historical and conceptual Ethernet mechanism rather than the normal mechanism used by modern full-duplex switched Ethernet.

## VLANs

VLAN means Virtual Local Area Network.

VLANs allow one physical switching infrastructure to contain multiple logical Layer 2 networks.

For example:

    VLAN 10:
        PC-A
        PC-B

    VLAN 20:
        PC-C
        PC-D

A broadcast originating in VLAN 10 should not normally be delivered to VLAN 20 through ordinary Layer 2 switching.

Therefore:

    VLAN 10 = one broadcast domain
    VLAN 20 = another broadcast domain

## VLAN IDs

IEEE 802.1Q provides VLAN tagging.

The VLAN identifier is commonly represented using a 12-bit VLAN ID field, providing values from 0 through 4095, with certain values reserved or treated specially.

The script uses the common operational range of:

    1 through 4094

for ordinary VLAN identification.

A VLAN-tagged Ethernet frame carries additional tagging information compared with an untagged Ethernet frame.

## Access ports and trunk links

An access port is normally associated with one access VLAN for attached end devices.

A trunk link can carry traffic for multiple VLANs and normally uses VLAN tagging to distinguish those logical networks.

Conceptually:

    Access port:
        End device → one VLAN

    Trunk:
        Switch ⇄ Switch
        VLAN 10
        VLAN 20
        VLAN 30
        ...

The exact configuration depends on the switching platform and network architecture.

## Inter-VLAN communication

Devices in separate VLANs cannot normally communicate directly through Layer 2 switching.

For example:

    VLAN 10 → VLAN 20

requires a Layer 3 boundary.

A router or multilayer switch can perform this function.

The process can be summarized as:

    VLAN 10
       ↓
    Layer 3 gateway
       ↓
    VLAN 20

This is one of the key relationships between switching and routing.

## Switching versus routing

Switching and routing solve different problems.

| Characteristic | Ethernet switching | IP routing |
|---|---|---|
| Main address | MAC address | IP address |
| Main table | MAC/CAM table | Routing table |
| Typical device | Layer 2 switch | Router or Layer 3 switch |
| Main decision | Forward within Layer 2 | Select Layer 3 path |
| Broadcast behavior | Normally floods within VLAN | Normally does not route ordinary Layer 2 broadcasts |

Modern multilayer switches can perform both functions.

## Same-subnet communication

Suppose two hosts are on the same local IP subnet.

A simplified process is:

1. Host A determines that Host B is local.
2. Host A resolves Host B's MAC address.
3. Host A creates an Ethernet frame.
4. The destination MAC is Host B's MAC.
5. The switch forwards the frame toward Host B.

The Ethernet destination is therefore local to the Layer 2 network.

## Communication through a router

If the destination is on another IP subnet:

1. Host A determines that the destination is remote.
2. Host A sends the Ethernet frame toward its default gateway.
3. The router receives the frame.
4. The router makes a Layer 3 forwarding decision.
5. The router sends a new Ethernet frame on the outgoing interface.

The Layer 2 header normally changes at the Layer 3 routing boundary.

This demonstrates why MAC addresses and IP addresses have different purposes.

## ARP and Ethernet

ARP stands for Address Resolution Protocol.

For IPv4, ARP can map an IP address to a MAC address on the local network.

A simplified sequence is:

1. Host A knows an IPv4 destination address.
2. Host A does not know the destination MAC.
3. Host A sends an ARP request as an Ethernet broadcast.
4. Hosts in the broadcast domain receive it.
5. The appropriate host responds.
6. Host A learns the MAC address.
7. Subsequent traffic can use Ethernet unicast.

ARP therefore illustrates the interaction between Layer 3 addressing and Layer 2 addressing.

IPv6 uses Neighbor Discovery rather than ARP.

## MAC address aging

Switches cannot retain every learned MAC address forever.

Dynamic entries normally have an aging mechanism.

If an address is not refreshed for the configured aging period, the switch can remove the entry.

This prevents stale information from remaining indefinitely.

The script includes an `AgingMACTable` class to demonstrate this concept.

## MAC address movement

A device can physically move between switch ports.

Suppose a MAC address was previously learned on:

    p1

and later appears on:

    p3

The switch can update its table:

    MAC → p3

This dynamic relearning is essential for practical switched networks.

Unexpected MAC movement can also be an important troubleshooting signal.

## Ethernet errors

Ethernet frames include an FCS for error detection.

If a frame is corrupted during transmission, the receiver can detect the error when the FCS does not match the received contents.

The script models this with the `fcs_valid` property.

An invalid FCS results in a rejected frame in the simplified model.

Real networking equipment maintains counters for many types of errors and drops, which are valuable during troubleshooting.

## FCS limitations

FCS provides error detection, not security authentication.

A valid FCS does not mean:

- The sender is trusted
- The payload is confidential
- The sender is authentic
- The frame has not been intentionally manipulated by an attacker capable of recomputing the checksum

Cryptographic mechanisms are required for security properties such as authentication and integrity against an active attacker.

## Layer 2 loops

Ethernet Layer 2 loops can be dangerous.

Consider:

    Switch A -------- Switch B
       \                /
        \--------------/

If redundant links are not managed correctly, a broadcast may circulate repeatedly.

A Layer 2 Ethernet frame does not have an ordinary Layer 3-style TTL field that automatically causes it to expire after a fixed number of hops.

Consequently, a Layer 2 loop can create:

- Broadcast storms
- Unknown-unicast flooding
- MAC-table instability
- Excessive bandwidth consumption
- CPU load
- Network-wide instability

## Spanning Tree

Spanning Tree Protocol and related variants provide loop-prevention mechanisms for switched networks.

The fundamental idea is to create a loop-free logical topology while retaining redundant physical paths that can be activated when failures occur.

The script does not implement a complete Spanning Tree algorithm. It demonstrates the problem that loop-prevention protocols are designed to address.

## Broadcast storms

A broadcast storm occurs when excessive broadcast traffic consumes significant network resources.

Potential causes include:

- Layer 2 loops
- Faulty devices
- Misconfigured applications
- Network attacks
- Excessive broadcast-generating protocols

Controls such as storm control can limit broadcast, multicast, or unknown-unicast traffic on appropriate switch ports.

Storm control is a mitigation mechanism rather than a substitute for fixing a topology problem.

## MAC-table pressure and MAC flooding

Switches have finite resources for learned MAC addresses.

An attacker may attempt to generate large numbers of source MAC addresses, potentially placing pressure on the switch's MAC-learning resources.

Historically, this is associated with MAC flooding attacks.

Security mechanisms such as port security can limit the number of MAC addresses learned on an access port.

The exact behavior during MAC-table exhaustion depends on switch architecture and configuration.

## Ethernet security

Important Layer 2 security concerns include:

### MAC spoofing

A device can configure or generate traffic using another MAC address.

This can interfere with address learning and may support other attacks.

### ARP spoofing

An attacker can attempt to associate its MAC address with another device's IP address.

This can enable traffic interception or disruption on vulnerable networks.

### MAC flooding

Large numbers of source MAC addresses can be generated to stress switch learning resources.

### Broadcast abuse

Excessive broadcasts can consume bandwidth and host resources.

### Layer 2 loops

Misconfiguration or unauthorized connections can create loops.

### Unauthorized switch access

Physical or administrative access to network infrastructure can provide extensive opportunities for disruption or compromise.

## Layer 2 security controls

Common controls include:

- Port security
- MAC address limits
- 802.1X authentication
- VLAN segmentation
- DHCP snooping
- Dynamic ARP Inspection
- Spanning Tree protections
- Broadcast and storm control
- Secure management protocols
- Physical security

The appropriate combination depends on the network's design and threat model.

## Performance considerations

Ethernet performance is influenced by several factors.

### Link bandwidth

Bandwidth represents the amount of data a link can carry per unit of time.

Examples include:

- 100 Mbps
- 1 Gbps
- 10 Gbps
- 25 Gbps
- 40 Gbps
- 100 Gbps
- Higher rates in specialized environments

### Latency

Latency is the time required for traffic to travel through the network.

A high-bandwidth link can still have significant latency.

### Frame size

Frame size affects protocol overhead and transmission efficiency.

Very small frames require proportionally more header and physical overhead.

### Full duplex

Full-duplex operation eliminates normal shared-medium collisions and allows simultaneous transmission in both directions.

### Switch buffering

Switches use buffers to absorb temporary differences between incoming and outgoing traffic rates.

Buffers cannot create additional link capacity. A persistently overloaded link remains a bottleneck.

### Oversubscription

Suppose many 1 Gbps access ports feed one 1 Gbps uplink.

The aggregate theoretical input bandwidth may exceed the uplink's capacity.

This creates oversubscription.

Network design must account for expected traffic patterns rather than simply adding high-speed access ports.

### Broadcast volume

Large broadcast domains can increase the amount of traffic processed by hosts and network devices.

Appropriate segmentation can reduce unnecessary broadcast propagation.

## Link aggregation

Link aggregation combines multiple physical links into one logical bundle.

Potential benefits include:

- Increased aggregate capacity
- Redundancy
- Improved utilization

Traffic distribution is normally based on a hashing or load-distribution algorithm.

A single flow is not necessarily split arbitrarily across every physical link.

Link aggregation must also be coordinated with Layer 2 loop-prevention and switching configuration.

## Troubleshooting Ethernet

Ethernet problems can be approached systematically.

### Physical layer checks

Check:

- Cable
- Transceiver
- Link LEDs
- Interface state
- Speed
- Duplex
- Physical errors

### NIC checks

Verify:

- Interface enabled
- Expected MAC address
- Driver or hardware status
- Receive and transmit counters

### Switch checks

Verify:

- Port state
- VLAN assignment
- MAC address learning
- MAC-table entries
- Errors
- Drops
- Interface utilization
- Broadcast levels

### Layer 2 checks

Investigate:

- Unknown unicast flooding
- Broadcast storms
- MAC movement
- VLAN mismatches
- Layer 2 loops
- Spanning Tree state

### Layer 3 checks

If Layer 2 is working, investigate:

- IP configuration
- ARP or Neighbor Discovery
- Default gateway
- Routing
- ACLs
- Firewall policies

This layered troubleshooting approach helps identify the actual point of failure instead of treating every connectivity problem as an Ethernet problem.

## Common mistakes

### Mistaking a MAC address for an IP address

MAC addresses are Layer 2 identifiers.

IP addresses are Layer 3 logical addresses.

They serve different purposes.

### Assuming a switch eliminates broadcasts

A normal switch does not automatically eliminate a broadcast domain.

Broadcasts are normally flooded within a VLAN.

### Assuming every frame is forwarded to every port

Known unicast traffic is normally selectively forwarded.

Flooding occurs when the switch does not have a usable specific destination-port mapping or when the traffic type requires flooding.

### Confusing collision domains with broadcast domains

A switch can reduce collision-domain size without reducing the broadcast domain.

### Assuming modern Ethernet uses CSMA/CD

Modern switched full-duplex Ethernet normally does not experience the shared-medium collision behavior for which CSMA/CD was designed.

### Assuming a valid FCS means secure traffic

FCS detects transmission errors.

It does not provide authentication, confidentiality, or cryptographic integrity.

### Assuming VLANs automatically provide complete security

VLANs provide logical Layer 2 separation, but security architecture requires appropriate Layer 3 controls, access controls, authentication, firewalling, and configuration.

### Ignoring Layer 2 loops

Redundant physical links are useful, but uncontrolled redundancy can create severe Layer 2 problems.

## Important distinctions

| Topic | Key distinction |
|---|---|
| MAC address | Layer 2 local addressing |
| IP address | Layer 3 logical addressing |
| NIC | Host interface connecting to the network |
| Frame | Ethernet Layer 2 data unit |
| Switch | Selectively forwards Layer 2 frames |
| Hub | Repeats physical-layer signals |
| Unicast | One destination |
| Broadcast | All eligible devices in the broadcast domain |
| Multicast | Group-oriented delivery |
| Collision domain | Region where simultaneous transmissions can collide |
| Broadcast domain | Region receiving a Layer 2 broadcast |
| VLAN | Logical Layer 2 segmentation |
| Router | Makes Layer 3 forwarding decisions |
| FCS | Detects many transmission errors |
| CSMA/CD | Historical shared-medium collision-management method |
| Full duplex | Simultaneous transmission in both directions |

## Practical network architecture

A simplified enterprise Ethernet design might contain:

    End devices
        ↓
    Access switches
        ↓
    Distribution or aggregation
        ↓
    Layer 3 routing
        ↓
    Core / WAN / Internet

At the access layer, switches provide connectivity to:

- Computers
- Servers
- Printers
- IP phones
- Wireless access points
- IoT devices
- Other Ethernet endpoints

VLANs can separate different logical groups.

Layer 3 gateways provide communication between those groups.

## Implementation details in the Python script

The script contains several educational implementations.

### `MACAddress`

Represents a validated 48-bit MAC address and provides:

- Formatting
- Byte conversion
- Broadcast detection
- Multicast detection
- Unicast detection
- OUI extraction
- Locally administered detection
- Random local MAC generation

### `EthernetFrame`

Represents a simplified Ethernet II frame.

It provides:

- Destination MAC
- Source MAC
- EtherType
- Payload
- FCS state
- VLAN ID
- Frame-size calculation
- Validation
- Frame classification

### `NIC`

Models a simplified network interface.

It provides:

- Transmission
- Reception
- Destination filtering
- Promiscuous mode
- Frame history

### `EthernetSwitch`

Models fundamental switch behavior:

- Source MAC learning
- MAC table lookup
- Known-unicast forwarding
- Unknown-unicast flooding
- Broadcast flooding
- Multicast flooding
- Filtering
- VLAN-aware forwarding
- Statistics

### `EthernetHub`

Models the behavior of a traditional physical-layer hub.

### `CollisionDomain`

Provides a conceptual shared-medium collision model.

### `CSMACD`

Models:

- Carrier sensing
- Transmission attempts
- Collision detection
- Jam signaling
- Binary exponential backoff
- Retry limits

### `VLANSwitch`

Extends the switch model to demonstrate VLAN-based broadcast-domain separation.

### `AgingMACTable`

Demonstrates dynamic MAC address aging.

### `BroadcastStormSimulator`

Illustrates the potentially explosive behavior of Layer 2 broadcast propagation in a loop.

## Edge cases demonstrated

The script deliberately handles several invalid or unusual conditions.

These include:

- Invalid MAC formatting
- Invalid hexadecimal characters
- Missing MAC octets
- Oversized Ethernet payloads
- Invalid VLAN IDs
- Invalid FCS
- MAC movement between switch ports
- Unknown unicast destinations
- Broadcast destinations
- Multicast destinations
- Destination addresses located on the ingress port

These cases demonstrate why networking software and hardware must validate inputs rather than assuming every frame is valid.

## Production considerations

A real Ethernet implementation is considerably more complex than the educational simulation.

Real switches can include:

- Hardware forwarding ASICs
- CAM and TCAM resources
- Multiple VLANs
- Trunking
- Link aggregation
- Spanning Tree variants
- QoS
- ACLs
- Multicast optimization
- Port security
- 802.1X
- DHCP snooping
- Dynamic ARP Inspection
- Storm control
- Redundant supervisors
- Layer 3 routing
- High-speed interfaces
- Monitoring and telemetry

The Python implementation intentionally focuses on the core concepts rather than attempting to reproduce switch hardware.

## Design considerations

A robust Ethernet network should consider:

- Required bandwidth
- Link redundancy
- Broadcast-domain size
- VLAN structure
- Layer 3 boundaries
- Loop prevention
- Security controls
- MTU consistency
- Uplink capacity
- Failure scenarios
- Monitoring
- Physical topology
- Device capabilities
- Operational simplicity

Redundancy should be designed deliberately. Additional physical links can increase availability, but they also require correct control-plane and Layer 2 configuration.

## Real-world relevance

Ethernet concepts appear throughout practical networking.

They are relevant to:

- Home networks
- Enterprise LANs
- Data centers
- Campus networks
- Industrial networks
- Cloud infrastructure
- Virtualized environments
- Server networking
- Network security
- Network troubleshooting
- Network monitoring

Understanding Ethernet provides a foundation for understanding switching, VLANs, ARP, IP routing, network security, packet capture, and network troubleshooting.

## Scope of the simulation

The Python program intentionally simplifies several real-world mechanisms.

It does not implement a complete Ethernet PHY, real electrical signaling, Manchester encoding, physical autonegotiation, complete IEEE 802.3 timing, actual CRC calculation, a complete Spanning Tree implementation, complete multicast forwarding, real switch ASIC behavior, or complete router functionality.

The simplifications allow the important Layer 2 concepts to be represented clearly in executable Python without requiring external networking hardware or third-party packages.
