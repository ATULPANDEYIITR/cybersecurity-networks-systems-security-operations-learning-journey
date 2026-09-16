# ARP: Address Resolution Protocol

## Topic scope

This study covers Address Resolution Protocol (ARP) for IPv4 Ethernet networks. The implementations examine how IPv4 addresses are mapped to MAC addresses, how ARP requests and replies operate, how mappings are cached, how local and routed communication differ, and how ARP behavior can be investigated with Wireshark.

The security portion explains ARP spoofing and ARP poisoning as network-security concepts and demonstrates passive detection of conflicting IP-to-MAC observations. The programs do not transmit forged ARP packets or modify real network interfaces.

The three implementations use different perspectives:

- Python provides a detailed educational simulation with explicit data models and validation.
- JavaScript demonstrates ARP state through application-level objects, maps, sets, and event-driven monitoring.
- C++ develops an industry-style managed-LAN case study with separate classes for validation, packet modeling, caching, LAN resolution, and security monitoring.

---

## Fundamental concepts

ARP stands for Address Resolution Protocol. It is used primarily with IPv4 networks to determine the MAC address associated with an IPv4 address on a local Ethernet network.

An IPv4 address identifies a Layer 3 endpoint. An Ethernet MAC address identifies a Layer 2 interface within the local Ethernet domain.

Suppose a host has:

- Local IPv4 address: `192.168.1.10`
- Local MAC address: `02:00:00:00:00:10`
- Destination IPv4 address: `192.168.1.20`

The application and IP layer may know that the destination is `192.168.1.20`, but an Ethernet frame still needs a destination MAC address.

ARP resolves the missing relationship:

`192.168.1.20 -> destination MAC`

After successful resolution, the sender can construct an Ethernet frame addressed to the destination MAC.

---

## ARP terminology

### IPv4 address

An IPv4 address is a 32-bit Layer 3 address normally represented in dotted-decimal notation, such as `192.168.1.10`.

### MAC address

A MAC address is a Layer 2 hardware or interface identifier used by Ethernet. A conventional representation contains six hexadecimal octets, such as `02:00:00:00:00:10`.

### ARP request

An ARP request asks which MAC address owns a specified IPv4 address.

A typical request can be described as:

`Who has 192.168.1.20? Tell 192.168.1.10.`

The Ethernet destination is normally the broadcast MAC address:

`ff:ff:ff:ff:ff:ff`

The requester does not yet know the target's MAC address, which is why the request is broadcast.

### ARP reply

An ARP reply supplies the requested mapping.

Conceptually:

`192.168.1.20 is at 02:00:00:00:00:20`

The responder can normally send the reply directly to the requesting host's MAC address.

### ARP cache

An ARP cache stores recently learned IPv4-to-MAC mappings.

A simplified cache might contain:

`192.168.1.1 -> 02:00:00:00:00:01`

`192.168.1.20 -> 02:00:00:00:00:20`

A valid cache entry allows a host to avoid performing ARP resolution every time it communicates with the same local destination.

### Gratuitous ARP

Gratuitous ARP refers to an unsolicited ARP announcement or request associated with a host's own address.

Legitimate uses include duplicate-address detection and notifying neighboring systems about a changed MAC address after certain failover events.

Because gratuitous ARP can affect neighboring ARP information, unexpected announcements can also be useful monitoring signals.

### ARP poisoning

ARP poisoning, also called ARP spoofing, describes manipulation of ARP information so that a victim associates an IPv4 address with an unintended MAC address.

For example, a legitimate gateway might normally be:

`192.168.1.1 -> aa:aa:aa:aa:aa:01`

A suspicious conflicting observation could be:

`192.168.1.1 -> bb:bb:bb:bb:bb:02`

The existence of two mappings does not by itself prove an attack. Virtualization, high availability, proxy ARP, load balancing, and legitimate network changes can also produce multiple observed mappings.

---

## Core ARP mechanism

A simplified resolution sequence is:

1. An application needs to communicate with an IPv4 destination.
2. The IP layer determines whether the destination is local or requires a router.
3. The host checks its neighbor or ARP cache.
4. If an appropriate mapping exists, the cached MAC address can be used.
5. If no suitable mapping exists for a local destination, the host sends an ARP request.
6. The request is delivered as an Ethernet broadcast.
7. The host owning the requested IPv4 address can send an ARP reply.
8. The requester learns the IPv4-to-MAC relationship.
9. The mapping may be stored in the ARP or neighbor cache.
10. Subsequent traffic can use the cached mapping until it becomes invalid or is replaced.

This is a simplified educational model. Operating systems implement substantially more detailed neighbor-state and cache behavior.

---

## ARP request structure

An ARP request contains information equivalent to:

- Operation: request
- Sender hardware address
- Sender protocol address
- Target hardware address
- Target protocol address

A conventional IPv4-over-Ethernet request can have:

- Ethernet destination: `ff:ff:ff:ff:ff:ff`
- Sender MAC: requester's MAC
- Sender IPv4: requester's IPv4 address
- Target MAC: `00:00:00:00:00:00`
- Target IPv4: the address being resolved

The target MAC is unknown at the time of the request.

The Python and C++ implementations represent these fields explicitly through `ARPPacket` and `ArpPacket`.

---

## ARP reply structure

A reply contains the responder's mapping.

A simplified reply can have:

- Ethernet destination: requester's MAC
- Ethernet source: responder's MAC
- ARP operation: reply
- Sender MAC: responder's MAC
- Sender IPv4: responder's IPv4
- Target MAC: requester's MAC
- Target IPv4: requester's IPv4

The responder can address the requester because the ARP request already exposed the requester's MAC address.

---

## Why ARP is normally local

ARP is associated with the local Layer 2 broadcast domain.

Consider:

`192.168.1.10/24`

communicating with:

`192.168.1.20/24`

These addresses belong to the same `/24` network, so the sender can resolve the destination host's MAC address directly.

Now consider:

`192.168.1.10/24`

communicating with:

`8.8.8.8`

The destination is not on the local IPv4 subnet. The sender does not normally broadcast an ARP request asking which local Ethernet device owns `8.8.8.8`.

Instead, the sender generally resolves the MAC address of its local next-hop router or default gateway. The router then handles forwarding toward the remote network.

This distinction is fundamental when interpreting packet captures.

---

## ARP cache behavior

A cache improves efficiency by remembering previously resolved mappings.

Without caching, repeated communication could repeatedly require:

`ARP request -> ARP reply -> data transmission`

With a valid mapping:

`cache lookup -> data transmission`

The Python implementation uses a dictionary for cache lookup. The JavaScript implementation uses a `Map`. The C++ implementation uses `std::unordered_map`.

These structures provide average constant-time lookup by IP address under normal hashing assumptions.

Actual operating-system ARP or neighbor caches can contain states, timers, retransmission logic, synchronization, and kernel-specific behavior that is more sophisticated than the educational models here.

---

## Cache aging

ARP mappings cannot be assumed to remain valid forever.

A device's network interface can change, a virtual machine can move, a failover system can activate another interface, or a network configuration can change.

The Python and C++ models distinguish states such as:

- `reachable`
- `stale`
- `static`

The JavaScript model uses equivalent string states.

The precise semantics and timing of real cache states depend on the operating system and networking implementation.

A static mapping has a different operational purpose from a dynamically learned mapping. Static entries can provide predictability in small controlled environments but can become difficult to maintain at scale.

---

## Python implementation

The Python program is organized as an educational progression.

### Address validation

`normalize_mac()` checks that a MAC address has six hexadecimal octets separated by colons.

`validate_ipv4()` uses Python's standard `ipaddress` module to validate an IPv4 address.

This establishes an important implementation principle: network input should be validated before it becomes part of application state.

### ARP packet model

`ARPPacket` represents the important semantic fields of an ARP message:

- Operation
- Sender MAC
- Sender IPv4
- Target MAC
- Target IPv4

The `ArpOperation` enumeration separates requests from replies.

### ARP cache

`ARPCache` stores `ARPCacheEntry` objects indexed by IPv4 address.

The cache supports:

- insertion
- lookup
- removal
- state tracking
- simple aging
- display

The dictionary gives average O(1) lookup complexity.

### Simulated LAN

`SimulatedLAN` models multiple hosts.

A resolution operation follows this sequence:

1. Check the requester's cache.
2. Use the cached mapping if it is still usable.
3. Otherwise broadcast a simulated ARP request.
4. Locate the simulated target host.
5. Generate a simulated ARP reply.
6. Store the mapping in the requester's cache.

No network interface is accessed.

### Security monitoring

`ARPSecurityMonitor` records the MAC addresses observed for each sender IPv4 address.

If an IP address is observed with more than one MAC address, the monitor produces an anomaly message.

This is a heuristic rather than a definitive attack detector.

### Wireshark analysis

The Python script also documents practical Wireshark filters such as `arp`, `arp.opcode == 1`, and `arp.opcode == 2`.

---

## JavaScript implementation

The JavaScript implementation emphasizes application-level modeling and event-driven behavior.

### Validation

`normalizeMac()` validates conventional MAC notation.

`validateIPv4()` validates dotted-decimal IPv4 values.

### Integer representation of IPv4 addresses

`ipv4ToInteger()` converts an IPv4 address into a 32-bit integer.

`networkAddress()` uses the integer representation and a prefix length to calculate the network address.

`sameSubnet()` compares network addresses to determine whether two IPv4 addresses belong to the same modeled subnet.

This demonstrates why understanding binary representation is useful when implementing network software.

### ARP cache

`ArpCache` uses JavaScript's `Map`.

Each entry stores:

- IP address
- MAC address
- state
- learning timestamp

The timestamp allows the example to model cache aging.

### Simulated LAN

`SimulatedLan` stores hosts and their caches.

`resolveMac()` first performs a cache lookup. A cache miss causes a simulated ARP request.

The second resolution of the same destination demonstrates why caching reduces repeated ARP traffic.

### Event-driven monitoring

The `ArpEventBus` class demonstrates an application-level event model.

ARP observations can produce:

`arp`

and security anomalies can produce:

`arp-alert`

This structure is useful when network telemetry is processed by an application that needs to separate packet ingestion from detection logic.

---

## C++ case study

The C++ implementation models a managed enterprise LAN.

The simulated environment contains:

- An engineering client
- An application server
- A default gateway

The client needs to communicate with the application server and gateway.

### Problem being modeled

The client knows the IPv4 address of another local system but does not initially know its MAC address.

The system must:

1. Validate the addresses.
2. Check the ARP cache.
3. Broadcast an ARP request on a cache miss.
4. Identify the target host.
5. Generate an ARP reply.
6. Add the mapping to the cache.
7. Reuse the cache for subsequent requests.
8. Monitor observations for conflicting mappings.

### Major components

`AddressValidator`

Provides validation of IPv4 and MAC addresses.

`ArpPacket`

Represents the semantic contents of an ARP packet.

`Host`

Represents a network endpoint.

`ArpCache`

Stores mappings and models cache state and aging.

`EnterpriseLan`

Coordinates hosts, caches, ARP resolution, and simulated broadcast behavior.

`ArpSecurityMonitor`

Tracks IP-to-MAC observations and identifies conflicting relationships.

### Design approach

The implementation separates data modeling from system behavior.

This provides several advantages:

- Address validation does not depend on ARP logic.
- Cache management is isolated from LAN behavior.
- Packet representation is independent of detection logic.
- Security monitoring can consume observations without modifying network behavior.
- Components can be tested independently.

This is closer to how larger systems are structured than placing all functionality in a single procedure.

---

## ARP packet interpretation in Wireshark

Wireshark can decode ARP frames and display their Ethernet and ARP fields.

Useful display filters include:

`arp`

Shows ARP packets.

`arp.opcode == 1`

Shows ARP requests.

`arp.opcode == 2`

Shows ARP replies.

`arp.src.proto_ipv4 == 192.168.1.1`

Filters on the ARP sender IPv4 address.

`arp.dst.proto_ipv4 == 192.168.1.20`

Filters on the ARP target IPv4 address.

`arp.src.hw_mac == 02:00:00:00:00:01`

Filters on the sender MAC address.

`eth.dst == ff:ff:ff:ff:ff:ff && arp`

Focuses on Ethernet-broadcast ARP traffic.

Filter syntax can depend on the Wireshark version and field names available in the installed protocol dissector. When a filter does not work, inspect the decoded packet fields and use Wireshark's displayed field names.

---

## Reading an ARP request in Wireshark

A typical request can be interpreted as:

Ethernet:

- Destination: `ff:ff:ff:ff:ff:ff`
- Source: requester MAC

ARP:

- Opcode: request
- Sender MAC: requester MAC
- Sender IPv4: requester IPv4
- Target MAC: usually zero
- Target IPv4: address being resolved

The critical relationship is:

`Target IPv4 = address for which the requester wants a MAC`

The requester does not yet possess that target MAC.

---

## Reading an ARP reply in Wireshark

A typical reply can be interpreted as:

Ethernet:

- Destination: requester MAC
- Source: responder MAC

ARP:

- Opcode: reply
- Sender MAC: responder MAC
- Sender IPv4: responder IPv4
- Target MAC: requester MAC
- Target IPv4: requester IPv4

The responder is effectively communicating the mapping:

`Sender IPv4 -> Sender MAC`

---

## Investigating ARP anomalies

A useful defensive investigation begins by establishing the normal mapping.

For example:

`192.168.1.1 -> 02:00:00:00:00:01`

If later observations show:

`192.168.1.1 -> 02:00:00:00:00:99`

the change should be investigated.

Useful questions include:

- Did the gateway interface actually change?
- Was a failover event occurring?
- Is virtualization involved?
- Is proxy ARP being used?
- Did network maintenance occur?
- Is the same mapping changing repeatedly?
- Are there many unsolicited ARP replies?
- Did the change affect multiple hosts?
- Does the switch identify the unexpected MAC on an unexpected port?

The programs model only the IP-to-MAC conflict portion of this investigation.

---

## ARP poisoning concepts

Traditional ARP does not provide cryptographic authentication for IP-to-MAC assertions.

A host therefore has limited protocol-level ability to determine whether an ARP message is an authentic statement from the legitimate owner of the IPv4 address.

An attacker who can influence ARP traffic within an applicable Layer 2 environment may attempt to cause victims to associate a sensitive IP address with an unintended MAC address.

A common conceptual target is the default gateway.

A successful redirection can potentially place another device between a victim and its gateway, or can instead cause traffic disruption.

The exact outcome depends on network topology, switching behavior, host configuration, routing, encryption, and the attacker's position.

The implementations do not perform the attack. They model its observable consequence: an IP address appearing with multiple MAC addresses.

---

## Why an IP/MAC conflict is not proof

A detector should not treat every mapping change as malicious.

Legitimate causes include:

- High-availability failover
- Virtual machines
- Containerized networking
- Proxy ARP
- Network interface replacement
- Load balancing
- DHCP changes
- Network maintenance
- MAC randomization or interface behavior
- Address migration between systems

A robust monitoring system should correlate ARP observations with other network and infrastructure information.

---

## Defensive controls

### DHCP snooping

On supported managed switches, DHCP snooping can help establish trusted IP-to-MAC-to-port relationships.

### Dynamic ARP Inspection

Dynamic ARP Inspection can validate ARP traffic against trusted bindings on supported network equipment.

### Network segmentation

VLANs and Layer 3 boundaries can reduce the size of Layer 2 broadcast domains and limit the scope of some local network attacks.

### Port security

Switch-level controls can restrict which MAC addresses or devices are permitted on particular access ports.

### Monitoring

Useful signals include:

- Unexpected gateway MAC changes
- Multiple MAC addresses for one important IP
- Large numbers of ARP packets
- Repeated unsolicited ARP replies
- Unexpected gratuitous ARP traffic
- Changes inconsistent with known infrastructure events

### Authenticated application protocols

Encryption and authentication at higher layers, such as TLS, can reduce the usefulness of traffic interception even when Layer 2 traffic redirection occurs.

ARP security therefore works best as part of layered network security rather than as a single isolated control.

---

## Edge cases

### Destination does not exist

If no host owns the requested IPv4 address, the requester may receive no ARP reply.

The Python, JavaScript, and C++ simulations explicitly model this failure.

### Duplicate IPv4 addresses

Two systems should not normally claim the same IPv4 address within the same network configuration.

Duplicate-address situations can cause connectivity failures and conflicting ARP observations.

### Multiple MAC addresses for one IP

Multiple observed MAC addresses can be suspicious, but legitimate network designs can also produce them.

### Stale cache entry

A cached mapping may no longer reflect current network state. Real implementations use operating-system-specific neighbor states and timers.

### Static cache entry

A static mapping may intentionally remain fixed. It can prevent certain dynamic changes but introduces an administrative maintenance burden.

### Remote destination

A remote destination generally does not require direct ARP resolution for the remote host. The sender normally resolves the local next-hop router.

### Broadcast domain boundaries

ARP broadcasts do not normally traverse routers in the same way that routed IP packets do. This is one reason network segmentation changes the scope of ARP behavior.

---

## Common mistakes

### Confusing IP and MAC addresses

An IP address is a Layer 3 address. A MAC address is used by Ethernet at Layer 2.

They serve different purposes even though ARP connects them for IPv4-over-Ethernet communication.

### Assuming ARP is a routing protocol

ARP resolves a local Layer 2 destination associated with an IPv4 next hop. It does not determine Internet routes.

### Assuming every ARP reply is malicious

ARP replies occur during normal network operation. Their presence alone is not evidence of an attack.

### Assuming every mapping change indicates poisoning

Operational events can legitimately change IP-to-MAC relationships.

### Ignoring the default gateway

For remote destinations, the gateway's MAC is often the relevant local Layer 2 mapping.

### Looking at one packet in isolation

Security analysis should consider the sequence of observations and the surrounding network context.

---

## Performance considerations

The primary performance optimization in ARP is caching.

A simplified workflow without caching is:

`request -> reply -> transmission`

With caching:

`lookup -> transmission`

The Python dictionary, JavaScript `Map`, and C++ `std::unordered_map` all provide average O(1) lookup behavior under normal conditions.

For `n` ARP observations, the basic IP-to-MAC conflict detector operates in approximately:

`O(n)`

time.

If `k` unique MAC relationships are retained, memory usage is approximately:

`O(k)`

The actual performance of a production network monitor depends on packet rate, retention duration, parsing cost, concurrency, storage, indexing, and the number of monitored interfaces or network segments.

---

## Security considerations in implementation

A network-monitoring application should validate packet fields before using them.

Important considerations include:

- Validate IPv4 addresses.
- Validate MAC addresses.
- Do not trust packet contents simply because they use valid syntax.
- Separate observation from response.
- Avoid automatically treating a heuristic anomaly as confirmed compromise.
- Preserve timestamps for event correlation.
- Record sufficient context to investigate changes.
- Protect monitoring logs from unauthorized modification.
- Control access to captured traffic because packet captures can contain sensitive information.
- Consider privacy and data-retention requirements when storing network telemetry.

A passive detector should generally be designed so that an unexpected packet cannot directly cause destructive administrative actions without additional validation.

---

## Python, JavaScript, and C++ comparison

| Aspect | Python | JavaScript | C++ |
|---|---|---|---|
| Primary focus | Educational simulation | Application and event model | Enterprise-style case study |
| Packet representation | `ARPPacket` | `ArpPacket` | `ArpPacket` |
| Cache structure | `dict` | `Map` | `std::unordered_map` |
| Set handling | Python `set` | JavaScript `Set` | `std::unordered_set` |
| Validation | `ipaddress` plus custom MAC validation | Custom validation | Standard-library implementation |
| Security detection | Passive conflict detector | Passive monitor and event bus | Passive enterprise monitor |
| Subnet logic | Python `ipaddress` | Explicit integer arithmetic | Modeled through LAN structure |
| Architectural emphasis | Progressive teaching | Event-driven processing | Class-based system design |
| External dependencies | None beyond the standard library | None | C++ standard library |

Python is effective for expressing network concepts concisely and creating readable simulations.

JavaScript demonstrates how ARP-related telemetry can be represented in application code, especially when event-driven processing and web-oriented systems are involved.

C++ is useful for showing stronger control over system architecture, data structures, error handling, and performance-oriented implementation choices.

---

## Implementation limitations

These programs are educational simulations.

They do not:

- Capture real Ethernet frames.
- Open a packet-capture interface.
- Inject ARP packets.
- Modify the operating system's ARP cache.
- Perform ARP poisoning.
- Implement a complete Ethernet frame parser.
- Reproduce every operating-system-specific neighbor-cache state.
- Replace Wireshark's protocol dissector.
- Detect attacks with production-grade confidence.

Real ARP behavior depends on operating systems, switches, network topology, VLAN configuration, virtual networking, NIC behavior, proxy ARP, routing, and other infrastructure.

The simulations intentionally abstract those details so that the fundamental mechanisms remain visible.

---

## Real-world applications

ARP knowledge is relevant to:

- Network troubleshooting
- Enterprise LAN administration
- Security monitoring
- Incident response
- Packet analysis
- Infrastructure engineering
- Network automation
- Virtualization
- High-availability systems
- Switch configuration
- DHCP snooping
- Dynamic ARP Inspection
- Network segmentation
- Security operations

A network engineer investigating a local connectivity problem may inspect ARP state to determine whether the host knows the destination or gateway MAC.

A security analyst may inspect ARP traffic for unexpected changes in important IP-to-MAC relationships.

A network administrator may use switch security controls and trusted bindings to reduce the impact of unauthorized ARP behavior.

---

## Conceptual workflow

The central ARP workflow demonstrated by the implementations is:

`IPv4 destination`

then:

`Determine local versus remote destination`

then, for a local destination:

`Check ARP cache`

then, on a cache miss:

`Broadcast ARP request`

then:

`Receive ARP reply`

then:

`Store IPv4-to-MAC mapping`

then:

`Transmit Ethernet frame`

For a remote destination, the equivalent Layer 2 target is normally the local next-hop gateway rather than the final remote host.

---

## Security-monitoring workflow

A passive ARP monitoring system can conceptually follow:

`Capture observation`

then:

`Validate fields`

then:

`Extract sender IPv4 and sender MAC`

then:

`Compare with historical observations`

then:

`Detect unexpected changes`

then:

`Correlate with infrastructure context`

then:

`Generate an investigation event`

The important distinction is between an anomaly and a confirmed attack.

An IP-to-MAC conflict is evidence that a relationship changed or that multiple relationships were observed. Determining why it changed requires additional context.

---

## Important distinctions

### ARP versus DNS

ARP maps IPv4 addresses to MAC addresses within applicable local networking contexts.

DNS maps domain names to resource records such as IP addresses.

They solve different problems.

### ARP versus routing

ARP resolves a Layer 2 destination for IPv4 communication.

Routing determines where an IP packet should be forwarded.

### ARP versus DHCP

DHCP can provide network configuration such as an IPv4 address, subnet information, default gateway, and DNS servers.

ARP resolves IPv4-to-MAC relationships needed for local Ethernet delivery.

### ARP versus IPv6 Neighbor Discovery

IPv6 does not use ARP. IPv6 uses Neighbor Discovery Protocol (NDP), which operates through ICMPv6.

The security and protocol details therefore differ even though both mechanisms address neighboring-node discovery.

---

## Production considerations

A production ARP-monitoring system would require additional capabilities beyond these examples.

Relevant concerns include:

- High-rate packet capture
- Efficient protocol parsing
- Timestamping
- Interface identification
- VLAN awareness
- Duplicate suppression
- Event correlation
- Persistent storage
- Alert management
- Baseline creation
- Infrastructure inventory
- Switch-port correlation
- Access control
- Secure logging
- Time synchronization
- Monitoring-system availability
- False-positive management

A production detector should also understand legitimate infrastructure events so that normal failover or virtualization behavior is not automatically classified as malicious.

---

## Example learning sequence represented by the implementations

The Python program begins with address validation and packet representation, then builds an ARP cache, subnet logic, a simulated LAN, gratuitous ARP modeling, passive security detection, Wireshark analysis, performance considerations, and defensive controls.

The JavaScript program adds application-oriented subnet arithmetic, cache state using `Map`, set-based conflict detection, and an event bus representing how network observations can flow through a monitoring application.

The C++ program integrates the concepts into a more structured enterprise scenario. It separates validation, packet representation, hosts, cache management, LAN resolution, and security monitoring into independent components.

Together, these implementations show ARP as both a network protocol mechanism and a practical subject for network troubleshooting and security monitoring.
