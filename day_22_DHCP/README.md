# DHCP Discovery, Offers, Requests, Acknowledgments, Leases, Rogue DHCP, and Wireshark

## Topic introduction

The Dynamic Host Configuration Protocol, commonly called DHCP, is an application-layer protocol used to provide hosts with network configuration dynamically. In an IPv4 network, DHCP can provide an IPv4 address, subnet mask, default gateway, DNS server addresses, lease duration, DHCP server identity, and many other configuration parameters.

The central DHCP workflow is commonly represented by the acronym **DORA**:

`DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK`

The four messages describe a negotiation rather than a simple one-way assignment. A client initially does not necessarily know which DHCP server exists, which address it should use, or which server should be selected. The client therefore begins with a discovery message. DHCP servers can respond with offers. The client selects an offer and requests it. The selected server confirms the configuration with an acknowledgment.

DHCP normally operates over UDP. DHCP servers commonly listen on UDP port `67`, while DHCP clients use UDP port `68`. The initial exchange can use broadcast addressing because the client may not yet have a usable IPv4 address. DHCP can also operate through DHCP relay agents when the client and server are separated by routed networks.

The three implementations in this repository model DHCP behavior without changing the host's actual network configuration. Python focuses on protocol fundamentals and stateful modeling. JavaScript emphasizes object-oriented and asynchronous event-driven simulation. C++ develops the subject into a more structured enterprise-network case study with explicit data structures, validation, lease management, and rogue-server analysis.

## Fundamental DHCP terminology

### DHCP client

A DHCP client is a host requesting network configuration. A workstation, laptop, virtual machine, IP phone, or other network-connected device can act as a DHCP client.

A client may begin without an IPv4 address. Its DHCP software therefore has to handle a special initialization state before normal IP communication is available.

The Python implementation represents this behavior with the `DHCPClient` class. The JavaScript implementation provides a corresponding `DHCPClient` class, while the C++ implementation uses a dedicated `DHCPClient` class with explicit state and configuration members.

### DHCP server

A DHCP server maintains address pools and configuration policies. When it receives a valid DHCPDISCOVER, it can generate a DHCPOFFER. When a client subsequently sends a DHCPREQUEST selecting that server and requesting an appropriate address, the server can commit the lease and return DHCPACK.

The implementations maintain two important mappings:

`MAC address → lease`

and

`IP address → lease`

This is important because a DHCP server needs to determine both which address belongs to a particular client and whether an address is already allocated.

### DHCP lease

A DHCP lease is a time-limited allocation of an address to a client. The lease has a beginning time and an expiration time.

The Python `Lease` class records the MAC address, assigned IP address, server identifier, lease duration, and start time. The JavaScript `DHCPLease` class models the same concepts. The C++ `DHCPLease` structure uses a simulation clock so lease expiration can be demonstrated without waiting for hours in real time.

A lease is fundamentally different from permanent ownership of an address. When a lease expires, the address can become available for another client according to the server's allocation policy.

### Transaction ID

DHCP messages belonging to the same client transaction need to be correlated. The DHCP transaction identifier, commonly represented as `xid`, is therefore important during packet analysis.

The examples generate a transaction ID for a DHCPDISCOVER and carry that identifier through the DORA sequence. A response with a mismatching transaction identifier should not simply be accepted as the response to the current transaction.

This is especially useful in Wireshark because the transaction ID can help connect the packets belonging to one DHCP negotiation.

### DHCP server identifier

The DHCP server identifier identifies the server participating in the transaction. In the simulations it is represented as the server's configured address.

The server identifier is particularly important when multiple DHCP servers are present. A client may receive several offers, but its DHCPREQUEST identifies the selected server.

### DHCP options

DHCP uses options to communicate configuration and protocol information.

The implementations demonstrate several important option concepts:

- Option `53`: DHCP message type
- Option `50`: requested IP address
- Option `54`: DHCP server identifier
- Option `51`: IP address lease time
- Option `1`: subnet mask
- Option `3`: router/default gateway
- Option `6`: DNS servers

The exact set of options in a real packet can be much larger. DHCP options allow the protocol to communicate configuration beyond the basic address allocation process.

## The DORA process

### DHCPDISCOVER

The client begins by transmitting DHCPDISCOVER to locate available DHCP servers.

The Python implementation creates the message with:

`source_ip = 0.0.0.0`

and

`destination_ip = 255.255.255.255`

This models the common initial situation in which the client has no usable IPv4 address and must discover DHCP infrastructure.

The DHCPDISCOVER includes the client's hardware address and transaction identifier. The server uses this information to associate subsequent messages with the client.

### DHCPOFFER

A DHCP server receiving the discovery can generate a DHCPOFFER.

The offer can contain:

- Proposed IPv4 address
- Subnet mask
- Default gateway
- DNS servers
- Lease duration
- Server identifier

An important distinction is that an offer is not necessarily the final lease commitment. The client still needs to select an offer and send a DHCPREQUEST.

The simulations explicitly separate `receive_discover()` from `receive_request()` so this distinction is visible in the code.

### DHCPREQUEST

The client sends DHCPREQUEST after selecting an offer.

The request identifies the requested address and selected server. In the implementations, the requested address corresponds to DHCP option 50 and the selected server corresponds to option 54.

This is one of the most important stages for understanding multiple DHCP servers. Several servers can respond to the same discovery, but the client selects one.

Servers that were not selected can recognize that another server was chosen and should not commit the address to that transaction.

### DHCPACK

The selected DHCP server responds with DHCPACK after validating the request.

The acknowledgment provides the configuration that the client can install. The client transitions into a bound state and starts its lease timer.

The Python and JavaScript clients store the assigned address, subnet mask, gateway, DNS servers, DHCP server identifier, lease duration, and lease start time.

The C++ implementation performs the same operation using a strongly structured client model.

### DHCPNAK

DHCPNAK indicates that the server rejects the requested configuration.

The simulations generate a NAK when conditions such as an invalid requested address or incorrect server selection occur.

A client receiving a NAK should not treat the requested configuration as valid. The Python and JavaScript implementations reset important client configuration when a NAK is processed.

## DHCP client states and lease timers

DHCP is easier to understand when modeled as a state machine.

The implementations use the following states:

`INIT`

The client has no active DHCP transaction.

`SELECTING`

The client has sent DHCPDISCOVER and is considering offers.

`REQUESTING`

The client has selected an offer and sent DHCPREQUEST.

`BOUND`

The client has a valid DHCP lease.

`RENEWING`

The client has reached the normal renewal point and attempts to renew the lease with the original DHCP server.

`REBINDING`

The client has passed the normal renewal period without successful renewal and attempts to obtain renewal through broader DHCP communication.

`EXPIRED`

The lease has expired without successful renewal.

The examples model the common lease timing concepts where T1 is approximately 50 percent of the lease duration and T2 is approximately 87.5 percent. Exact DHCP behavior depends on protocol details and configuration, so the simulation intentionally treats these values as a simplified educational model.

The JavaScript implementation demonstrates this with `updateLeaseState()`. The Python implementation uses `refresh_state()`, while the C++ implementation models lease state transitions using `SimulationClock`.

A major design advantage of using a simulation clock is that a one-hour lease can be tested in milliseconds rather than requiring the program to actually wait for one hour.

## Python implementation

The Python implementation provides the broadest protocol-oriented learning model.

### DHCP packet modeling

`DHCPPacket` represents the important fields of a DHCP message. It contains:

- Message type
- Transaction ID
- Client MAC address
- Source IP
- Destination IP
- Server identifier
- Requested IP
- Offered IP
- Subnet mask
- Router
- DNS servers
- Lease duration

The `options()` method provides a conceptual mapping between option numbers and values.

This makes the program useful for understanding the relationship between abstract DHCP concepts and packet-level fields.

### DHCP server implementation

`DHCPServer` manages an address pool and active leases.

The `_find_available_ip()` function searches for an unused address. `_release_expired_leases()` removes expired allocations so that addresses can eventually be reused.

`receive_discover()` generates a DHCPOFFER, while `receive_request()` validates the client's DHCPREQUEST and produces either DHCPACK or DHCPNAK.

This separation is important because discovery and allocation are different protocol stages.

### Client implementation

The `DHCPClient` class implements the client state machine.

`create_discover()` begins a new transaction.

`create_request()` selects an offer.

`process_ack()` installs the network configuration.

`refresh_state()` evaluates lease progress.

`create_renewal_request()` demonstrates how a client with an existing address can request renewal.

### Error handling

The Python implementation validates MAC addresses and rejects malformed values.

It also checks:

- Transaction IDs
- Missing server identifiers
- Missing requested addresses
- Invalid pool membership
- Conflicting leases
- Invalid message types

These checks illustrate an important networking principle: protocol software must validate externally supplied information rather than assuming every received packet is correct.

## JavaScript implementation

The JavaScript implementation emphasizes event-driven behavior and asynchronous processing.

### Object-oriented protocol modeling

The file uses classes for:

`DHCPPacket`

`DHCPLease`

`DHCPServer`

`DHCPClient`

This makes the relationships between protocol objects explicit.

The server owns leases. The client owns its configuration state. Packets transfer information between them.

### Asynchronous behavior

The `delay()` function returns a Promise and is used to model network latency.

The DORA simulation therefore follows an asynchronous sequence:

client sends Discover → simulated delay → server processes → simulated delay → client sends Request → simulated delay → server returns ACK.

No real network packets are sent. The asynchronous model is intended to demonstrate how an event-driven application can represent network operations.

### Multiple DHCP servers

The `collectOffers()` function uses `Promise.all()` to process several simulated DHCP servers.

This represents an important DHCP behavior: multiple servers may see the same broadcast discovery and independently produce offers.

The `detectUnexpectedServers()` function compares the observed server identifiers with a set of trusted identifiers.

This is a simplified defensive detection mechanism rather than a replacement for switch-level controls or enterprise DHCP authorization.

### JavaScript-specific validation

The implementation uses `Map` for lease indexes.

`Map` is useful when frequent key-based lookups are required. The server maintains:

`leasesByMac`

and

`leasesByIp`

This avoids repeatedly scanning an entire lease collection when processing common operations.

## C++ enterprise network case study

The C++ implementation turns the protocol concepts into a more structured network-system model.

### Problem being modeled

The case study represents an enterprise IPv4 network in which:

- Authorized DHCP infrastructure provides addresses.
- Clients dynamically obtain configuration.
- Leases expire over time.
- Multiple DHCP servers may respond to a discovery.
- An unauthorized DHCP server may provide competing configuration.
- Network administrators need packet-level evidence for investigation.
- Address pool exhaustion must be handled.
- Invalid requests must be rejected.

This scenario connects protocol mechanics with operational network administration.

### Simulation clock

The `SimulationClock` class is one of the most important architectural components.

Waiting for a real DHCP lease to expire would make testing impractical. The simulation therefore uses an artificial clock.

`advance()` moves the simulated time forward.

The DHCP server uses the clock to determine whether leases have expired.

This approach is common in software testing because time-dependent behavior becomes deterministic and fast.

### Lease indexes

The server maintains:

`unordered_map<string, DHCPLease> leasesByMac`

and

`unordered_map<string, string> macByIp`

The first structure answers:

"Which lease belongs to this client?"

The second answers:

"Which client currently owns this IP?"

This dual-index approach avoids unnecessary linear searches.

For a larger implementation, the precise data structure and persistence design would depend on the scale, concurrency requirements, database architecture, and lease-update frequency.

### Validation and failure handling

The C++ server rejects requests when:

- The message type is incorrect.
- The server identifier does not identify the server.
- The requested IP is missing.
- The requested address is outside the configured pool.
- Another active client already owns the address.

The program uses exceptions for invalid configuration and unexpected program-level conditions.

A production DHCP server would need additional protocol validation, persistence, concurrency controls, logging, authorization, conflict detection, and integration with the operating environment.

## Multiple DHCP servers and rogue DHCP

A normal network can contain multiple legitimate DHCP servers when correctly designed, but an unexpected DHCP server is a security concern.

A rogue DHCP server is an unauthorized system that responds to DHCP requests.

The risk is not limited to assigning an incorrect IP address. DHCP can distribute other critical network parameters such as:

- Default gateway
- DNS servers
- Domain configuration
- Lease duration
- Other DHCP options

An unauthorized server could therefore provide configuration that changes where clients send traffic or which DNS infrastructure they use.

The simulations deliberately demonstrate this by creating a legitimate server and a second server with a different server identifier, gateway, DNS configuration, and address pool.

The detection logic compares observed DHCP server identifiers with an expected trusted set.

The important analytical point is that **the presence of multiple DHCP offers is not automatically proof of an attack**. Multiple authorized DHCP servers can be intentional. Investigation requires knowledge of the network's expected architecture.

## Wireshark packet analysis

Wireshark is a packet capture and protocol analysis tool. DHCP analysis becomes especially useful when the packet sequence is examined rather than looking at individual packets in isolation.

Useful display filters demonstrated in the implementations include:

`dhcp`

`bootp`

`udp.port == 67 || udp.port == 68`

`bootp.option.dhcp == 1`

`bootp.option.dhcp == 2`

`bootp.option.dhcp == 3`

`bootp.option.dhcp == 5`

`bootp.option.dhcp == 6`

`bootp.option.dhcp_server`

The DHCP message type values commonly used by the dissector are useful for identifying the DORA sequence.

A practical analysis sequence is:

1. Locate DHCPDISCOVER.
2. Record its transaction ID.
3. Identify all DHCPOFFER messages associated with that transaction.
4. Record each DHCP server identifier.
5. Compare the offered IP addresses.
6. Compare gateway and DNS configuration.
7. Locate the DHCPREQUEST.
8. Determine which server was selected.
9. Locate DHCPACK or DHCPNAK.
10. Investigate any unexpected DHCP server.

The transaction ID is particularly useful because a busy network can contain DHCP exchanges from many clients simultaneously.

## Reading important DHCP packet fields

### Client MAC address

The client MAC address identifies the hardware interface involved in the simulated DHCP transaction.

In real captures, the exact packet structure can include multiple address fields and relay information, so the MAC address should be interpreted in the context of the complete packet.

### Transaction ID

The transaction ID helps associate requests and responses with the same DHCP exchange.

When troubleshooting, a transaction that appears incomplete can be investigated by filtering or visually correlating packets with the same transaction identifier.

### Server identifier

The server identifier is critical when several DHCP servers are present.

Unexpected server identifiers can be an important investigation clue.

### Requested IP

The requested IP allows the client to communicate which address it is requesting.

A server should validate that the requested address is appropriate for the client and server's configuration.

### Lease time

Lease duration determines how long an allocation remains valid before renewal or expiration behavior becomes relevant.

Short leases can allow addresses to be recycled more quickly, while longer leases can reduce DHCP traffic for relatively stable networks. The appropriate value depends on network characteristics and operational requirements.

## Rogue DHCP defensive architecture

### DHCP snooping

DHCP snooping is a switch-level security mechanism designed to distinguish trusted DHCP infrastructure from untrusted access ports.

A common architecture marks interfaces connected to authorized DHCP servers or DHCP relay infrastructure as trusted while treating client-facing interfaces as untrusted.

An unauthorized DHCP response arriving through an untrusted interface can then be blocked according to the switch's configuration.

This is fundamentally different from Wireshark.

**Wireshark provides visibility and analysis. DHCP snooping provides enforcement at supported network infrastructure.**

### Trusted server interfaces

The trust boundary is an important part of DHCP security.

If every switch port is treated as equally trusted, an unauthorized host may be able to generate DHCP server responses.

The exact configuration depends on the network architecture and switch platform.

### Monitoring

Network monitoring can look for:

- Unexpected DHCP server identifiers
- Unexpected gateways
- Unexpected DNS servers
- Unusual DHCP response rates
- Unexpected DHCP traffic sources
- Changes in DHCP behavior across VLANs

Packet captures can provide evidence for investigating these observations.

### Segmentation

DHCP discovery is fundamentally connected to the broadcast domain.

Network segmentation can therefore influence DHCP behavior and security boundaries.

In routed networks, DHCP relay agents can forward client requests toward centralized DHCP servers. This allows DHCP services to operate across multiple IP subnets without extending a single broadcast domain across the entire enterprise.

## DHCP relay concepts

A DHCP relay is a network device or service that forwards DHCP messages between clients and DHCP servers across routed boundaries.

Without a relay, a DHCP broadcast normally does not cross an IP router in the same way that ordinary routed traffic does.

A relay can receive the client's DHCP message and forward it toward the appropriate DHCP server. The server can then use relay information to determine the client's network context.

The Python packet model includes a `relay_agent_ip` field to introduce this concept, although the primary simulation focuses on a single broadcast domain.

In production environments, relay behavior becomes important when centralized DHCP infrastructure serves many VLANs or subnets.

## DHCP message distinctions

The main messages demonstrated are:

| Message | Typical sender | Purpose |
|---|---|---|
| DHCPDISCOVER | Client | Searches for DHCP servers |
| DHCPOFFER | Server | Proposes configuration |
| DHCPREQUEST | Client | Requests a selected configuration |
| DHCPACK | Server | Confirms the lease |
| DHCPNAK | Server | Rejects the request |
| DHCPDECLINE | Client | Reports an address conflict or unusable offer |
| DHCPRELEASE | Client | Returns a lease |
| DHCPINFORM | Client | Requests configuration information without requesting a new address lease |

The DORA sequence is the most important starting point, but DHCP is broader than these four messages.

## Edge cases demonstrated

### DHCP pool exhaustion

The Python, JavaScript, and C++ programs create small pools to demonstrate what happens when more clients request addresses than the pool contains.

A server with two available addresses cannot successfully allocate a third address unless another lease becomes available or another allocation mechanism exists.

Pool exhaustion is an operational concern in real networks.

Possible causes include:

- Too-small DHCP pools
- Excessively long leases
- Large numbers of transient devices
- Guest networks
- Misconfigured clients
- Abandoned leases
- Address reservations
- Network growth

### Invalid requested address

The examples request an address outside the configured DHCP pool.

The server rejects it.

This demonstrates why DHCP servers cannot blindly accept every address supplied by a client.

### Conflicting allocation

The server checks whether another active lease already owns the requested address.

This protects the server's internal allocation model from assigning the same address to two active clients.

Real-world DHCP systems may also use additional conflict-detection mechanisms depending on implementation and configuration.

### Expired lease

The simulations remove expired leases from active allocation structures.

The C++ implementation makes this behavior especially explicit because the simulated clock can be advanced instantly.

## Common mistakes

### Assuming DHCP is only an IP assignment mechanism

DHCP can provide a broad collection of network parameters. An incorrect gateway or DNS server can be as operationally significant as an incorrect IP address.

### Looking at only one DHCP packet

A single DHCPOFFER does not tell the entire story.

The Discover, Offer, Request, and ACK sequence should be correlated.

### Ignoring transaction IDs

Without correlating transactions, packets from multiple clients can easily be confused.

### Treating every second DHCP server as automatically malicious

Multiple legitimate DHCP servers can exist in properly designed networks.

An unexpected DHCP server should be investigated against the organization's intended topology and DHCP architecture.

### Assuming Wireshark blocks rogue DHCP

Wireshark is primarily an analysis and packet-capture tool.

It can expose evidence of unauthorized DHCP activity but does not replace switch security mechanisms such as DHCP snooping.

### Treating a DHCP lease as permanent ownership

A lease has a duration and renewal process.

Address allocation therefore needs lifecycle management.

## Important distinctions

### DHCP versus DNS

DHCP provides host configuration, including potentially the addresses of DNS servers.

DNS translates names into resource records and provides name-resolution services.

They frequently work together but solve different problems.

### DHCP versus ARP

DHCP can assign an IPv4 address.

ARP maps IPv4 addresses to link-layer addresses within a local network.

They operate at different points in the network communication process.

### DHCP server versus DHCP relay

A DHCP server owns the address allocation and configuration policy.

A DHCP relay forwards DHCP traffic between network segments.

A relay does not necessarily own the address pool.

### Wireshark versus DHCP snooping

Wireshark provides packet-level observation and analysis.

DHCP snooping is a network-infrastructure security mechanism.

The two can complement each other during investigation and troubleshooting.

## Performance considerations

DHCP servers need efficient allocation and lookup mechanisms as network size increases.

The examples use direct mappings from client MAC addresses to leases and from IP addresses to client ownership.

For a collection of `n` leases:

- Hash-table lookup is approximately O(1) average-case.
- Scanning every lease is O(n).
- Searching a small address pool linearly is O(p), where `p` is the number of addresses in the pool.

For small laboratory networks, a linear pool scan is adequate and easy to understand.

Large production implementations can use more sophisticated allocation structures, persistent databases, lease-state synchronization, reservations, and high-availability mechanisms.

## Security considerations

DHCP itself should not be treated as an authentication mechanism for network trust.

Important security considerations include:

- Unauthorized DHCP servers
- Malicious or incorrect gateway configuration
- Malicious or incorrect DNS configuration
- DHCP starvation or resource exhaustion
- Incorrect VLAN or relay configuration
- Inadequate switch trust configuration
- Insufficient monitoring
- Weak operational controls around DHCP infrastructure

The defensive focus should be on validating which DHCP infrastructure is authorized and limiting which network interfaces are allowed to provide DHCP server responses.

## Production implementation considerations

A production DHCP system is considerably more complex than these educational simulations.

A production implementation may require:

- Persistent lease storage
- Address reservations
- Multiple scopes
- Exclusions
- DHCP relay support
- Multiple VLANs
- High availability
- Lease synchronization
- Detailed logging
- Audit trails
- Configuration management
- Conflict detection
- Access controls
- Monitoring
- Rate controls
- Security integration
- Failure recovery

The simulations intentionally focus on the core protocol concepts while still showing how these concepts map into a larger architecture.

## Python, JavaScript, and C++ comparison

| Aspect | Python | JavaScript | C++ |
|---|---|---|---|
| Primary emphasis | Protocol learning | Event-driven simulation | Enterprise-style case study |
| Packet model | Dataclass | Class | Struct/class |
| Lease storage | Dictionaries | Maps | Unordered maps |
| State machine | Enum | Frozen object | Enum class |
| Time model | System time | JavaScript timestamps | Simulation clock |
| Async behavior | Not central | Promises and delays | Synchronous simulation |
| Error handling | Exceptions | Exceptions and rejected operations | Exceptions |
| Security model | Rogue server concepts | Concurrent offer analysis | Structured security case study |
| Wireshark focus | Filters and packet fields | Filter reference | Packet-field analysis |
| Main strength | Rapid protocol modeling | Event-driven application behavior | Explicit systems architecture |

Python makes it easy to represent protocol structures and experiment with stateful behavior.

JavaScript provides a useful model for event-driven network applications because asynchronous operations and concurrent responses are natural parts of the language's runtime model.

C++ makes data ownership, object structure, validation, and algorithmic organization explicit, which is valuable when considering systems-oriented implementations.

## Implementation best practices demonstrated

The implementations apply several practical design principles.

**Validate external input.** DHCP messages should never be assumed to be valid simply because they arrive from the network.

**Correlate transactions.** Transaction identifiers are essential for matching responses to requests.

**Track state explicitly.** DHCP is a stateful protocol, so a state machine is more reliable than a collection of unrelated flags.

**Separate allocation from observation.** A DHCP server manages leases, while Wireshark observes packets. Keeping those roles distinct makes the architecture easier to understand.

**Use deterministic time in tests.** The C++ simulation clock avoids waiting for real lease expiration.

**Maintain useful indexes.** MAC-to-lease and IP-to-lease mappings make common allocation operations efficient.

**Treat unexpected DHCP infrastructure as an investigation signal.** A DHCP server identifier should be compared against the intended network architecture rather than evaluated in isolation.

## Practical applications

DHCP knowledge is directly useful in:

- Enterprise network administration
- Network troubleshooting
- Security monitoring
- Incident investigation
- VLAN configuration
- Wireshark packet analysis
- Network automation
- Data-center networking
- Campus networks
- Wireless networks
- Guest networks
- Virtualized environments
- IP address management
- Network security engineering

A strong DHCP troubleshooting process combines protocol knowledge with packet-level observation.

For example, if a workstation receives an unexpected gateway, an administrator can inspect the DHCP exchange, identify the server identifier, compare the gateway and DNS options, determine whether multiple offers were present, and then correlate the source with the network infrastructure.

That workflow demonstrates why understanding DHCP at both the protocol and packet-analysis levels is important.

## Relationship between the three implementations

The Python implementation establishes the conceptual foundation: DHCP packets, server behavior, client states, leases, DORA, pool exhaustion, rogue DHCP concepts, and Wireshark filters.

The JavaScript implementation builds on the same protocol model while emphasizing asynchronous behavior. Multiple simulated DHCP servers can process a discovery concurrently, which makes the event-driven nature of network applications easier to observe.

The C++ implementation develops the concepts into an industry-style scenario. It uses explicit classes and data structures, a simulation clock, lease indexes, validation, multiple servers, rogue DHCP analysis, and packet-field inspection.

Together, the implementations demonstrate the same protocol from three technical perspectives without requiring actual DHCP packets to be transmitted onto the host network.
