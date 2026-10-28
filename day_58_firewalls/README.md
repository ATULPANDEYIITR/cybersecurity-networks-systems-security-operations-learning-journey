# Firewall Filtering and Policy Enforcement

## Scope

This project models packet filtering as a layered security decision process. The implementations distinguish four core firewall concepts:

| Concept | Role |
|---|---|
| Stateless filtering | Evaluates each packet independently against ordered rules |
| Stateful firewalling | Maintains connection state and permits packets belonging to established flows |
| Firewall rules | Define explicit traffic conditions and actions |
| Zones and default deny | Group networks by trust boundary and deny traffic that lacks an explicit permit |

The central security model is:

`Packet → Validation → Zone/Rule Matching → State Evaluation → ALLOW or DENY`

The examples use IPv4, TCP, UDP, and ICMP concepts and use default deny as the baseline security posture.

## Firewall Architecture

A firewall sits between network interfaces or security zones and decides whether traffic may cross a boundary.

A simplified deployment model is:

`Internet → Firewall → DMZ → Firewall Policy → Internal Network`

The important distinction is between traffic characteristics and policy state.

A packet has properties such as:

- Source IP address
- Destination IP address
- Protocol
- Source port
- Destination port
- Direction
- Interface

A rule converts those properties into a decision.

A stateful firewall adds another input:

- Existing connection state

A zone-based design adds another abstraction:

- Source security zone
- Destination security zone

These mechanisms should not be treated as interchangeable. A rule describes a permitted or denied traffic condition. State tracking describes whether a packet belongs to an already permitted flow. Zones describe trust boundaries around groups of networks.

## Stateless Filtering

A stateless firewall evaluates each packet without remembering previous packets.

The Python, JavaScript, C++17, Java 17, and PostgreSQL implementations use ordered rules. The first matching rule determines the decision.

A representative rule contains:

| Field | Purpose |
|---|---|
| Name | Identifies the policy |
| Action | `ALLOW` or `DENY` |
| Protocol | Restricts traffic to TCP, UDP, or ICMP |
| Source network | Restricts the source address range |
| Destination network | Restricts the destination address range |
| Source port | Restricts TCP or UDP source ports |
| Destination port | Restricts TCP or UDP destination ports |
| Direction | Distinguishes inbound and outbound traffic |
| Interface | Associates the rule with a network interface |

The order is significant.

For example:

`ALLOW HTTPS → DENY TELNET → DEFAULT DENY`

A TCP packet destined for port `443` can match the HTTPS rule. A TCP packet destined for port `23` can match the Telnet denial rule. A TCP packet destined for port `22` has no explicit permit and therefore reaches the default-deny decision.

This is different from a firewall that evaluates every rule and combines their results. The implementations deliberately use first-match semantics because ordered rule processing is common in packet-filtering systems.

## Stateful Firewalls

A stateful firewall records permitted flows.

For a TCP flow such as:

`10.0.20.10:51000 → 198.51.100.20:443`

the firewall can store a flow key containing:

`source IP + destination IP + protocol + source port + destination port`

The reverse direction is recognized as:

`198.51.100.20:443 → 10.0.20.10:51000`

Once the outbound connection has been permitted, the corresponding return traffic can be accepted as established traffic without requiring a separate broad inbound rule.

This is a significant distinction from stateless filtering.

A stateless firewall asks:

`Does this individual packet match a permit rule?`

A stateful firewall can ask:

`Does this packet belong to a flow that was previously permitted?`

The examples use simplified flow tracking rather than implementing the complete TCP state machine. Production firewalls normally track more protocol-specific state, timeouts, sequence behavior, connection termination, and resource limits.

## Rules and Rule Ordering

Rules are policy statements.

A simplified policy can be represented as:

| Priority | Rule | Protocol | Destination | Action |
|---:|---|---|---:|---|
| 10 | `ALLOW-HTTPS-INBOUND` | TCP | 443 | ALLOW |
| 20 | `ALLOW-DNS-OUTBOUND` | UDP | 53 | ALLOW |
| 30 | `DENY-TELNET` | TCP | 23 | DENY |
| Default | `DEFAULT-DENY` | Any | Any | DENY |

Rule ordering is a security control.

A broad permit placed before a restrictive rule can make the restrictive rule unreachable. For this reason, rule review should examine both the individual condition and its position in the policy.

The implementations validate ports, protocols, IP addresses, and other packet properties before evaluating policy.

## Zones

Zones represent security boundaries rather than individual packets.

The examples use:

| Zone | Example network | Trust interpretation |
|---|---|---|
| INTERNET | Public IPv4 space | Low trust |
| DMZ | `10.0.10.0/24` | Public-facing services |
| INTERNAL | `10.0.20.0/24` | Higher-trust systems |

A zone policy can express a relationship such as:

`INTERNET → DMZ : TCP/443 : ALLOW`

while another policy can express:

`INTERNET → INTERNAL : no permit : DENY`

This makes the trust boundary explicit.

Zone classification also introduces an important validation condition. An address should not unexpectedly belong to multiple mutually exclusive zones. The Python, JavaScript, and Java implementations detect ambiguous zone assignments instead of silently selecting one.

## Default Deny

Default deny means that traffic without an explicit permit is rejected.

The policy model is:

`if matching permit exists → ALLOW`

`else → DENY`

This reduces the risk of accidentally exposing a service when a new rule is added for another service.

The examples deliberately test traffic to an unapproved SSH port. Since there is no corresponding permit, the packet is denied.

Default deny does not eliminate the need for carefully designed rules. An overly broad allow rule can still create excessive access.

## Python Implementation

The Python implementation uses `dataclass` domain models and enums for actions, protocols, and directions.

The main components are:

- `Packet`
- `FirewallRule`
- `StatelessFirewall`
- `StatefulFirewall`
- `Zone`
- `ZonePolicy`
- `ZoneFirewall`

`Packet.__post_init__` performs structural validation. TCP and UDP require ports, while ICMP does not accept TCP/UDP ports.

`FirewallRule.matches()` isolates rule matching from policy evaluation. This makes the first-match algorithm explicit and reusable.

`StatefulFirewall` stores `FlowKey` objects in a set. The reverse flow is checked so that return traffic can be associated with the established connection.

`ZoneFirewall` first classifies source and destination addresses and then evaluates zone policies. If no policy matches, the firewall returns a zone-level default denial.

The executable assertions verify two security invariants:

- Invalid port values are rejected.
- Traffic without an applicable permit is denied.

## JavaScript Implementation

The JavaScript implementation is designed around Node.js standard-library features.

It uses:

- `EventEmitter` for decision events
- `Map` for established-flow timestamps
- `Set` for state tracking
- Promises and `setImmediate()` for asynchronous audit processing
- explicit validation functions
- classes for rules, policies, and firewalls

`Firewall` emits a `decision` event whenever traffic is evaluated. This separates policy evaluation from operational logging.

The stateful implementation stores flow keys and timestamps. `expireOlderThan()` provides a simple resource-management mechanism for removing old state.

`ZoneFirewall` performs zone classification before policy evaluation. Ambiguous zone assignments result in an exception rather than an arbitrary decision.

The JavaScript implementation therefore emphasizes event-driven processing and operational observability rather than reproducing the Python class structure line by line.

## C++17 Implementation

The C++17 program models a firewall as a technical case study with strongly typed domain objects.

Important types include:

- `IPv4`
- `Network`
- `Packet`
- `Rule`
- `Decision`
- `StatefulFirewall`
- `ZoneFirewall`

`IPv4` converts dotted-decimal addresses into 32-bit values. `Network::contains()` then applies a CIDR mask to perform efficient membership checks.

`StatefulFirewall` uses an `unordered_set` for flow state. Average lookup and insertion are constant-time operations, subject to normal hash-table behavior.

The program separates packet validation from rule matching and rule matching from state handling.

Exceptions are used for malformed addresses, invalid ports, incomplete TCP/UDP packets, and failed security invariants.

The C++ implementation also exposes the number of tracked flows, making memory growth an explicit operational consideration.

## Java 17 Implementation

The Java implementation uses enterprise-oriented domain modeling.

Records represent immutable value types:

- `IPv4`
- `Network`
- `Packet`
- `FlowKey`
- `Rule`
- `Decision`

Interfaces and policy objects represent policy behavior. `Policy` separates policy semantics from the firewall service itself.

`StatefulFirewall` maintains established flows using a `HashSet`. `ZoneFirewall` maintains network-to-zone mappings and explicit zone policies.

Java streams are used for zone classification. The implementation rejects overlapping zone assignments because ambiguous security boundaries can produce unintended policy decisions.

The domain model uses explicit enums for:

- `Action`
- `Protocol`
- `Direction`
- `FirewallState`
- `Zone`

This prevents loosely typed strings from representing security-critical state.

## PostgreSQL Implementation

The PostgreSQL implementation treats firewall policy as relational data.

The schema contains:

- `repositories`
- `zones`
- `networks`
- `firewall_rules`
- `connections`
- `packets`
- `packet_decisions`
- `zone_policies`

The relationships are:

`Repository → Zones → Networks`

`Repository → Rules`

`Repository → Connections → Packets → Decisions`

`Repository → Zone Policies`

Primary keys identify entities, foreign keys maintain relationships, unique constraints prevent duplicate policy identifiers, and check constraints validate ports and protocol-specific conditions.

PostgreSQL `CIDR` and `INET` types are used for network and address operations.

The expression `source_ip <<= source_network` performs CIDR containment directly in PostgreSQL.

## Database-Level Validation

The database uses triggers to enforce protocol-specific packet rules.

TCP and UDP require source and destination ports.

ICMP cannot contain TCP/UDP ports.

This validation is important because application-level validation alone cannot protect a database from every possible client.

The same principle applies to state data. Constraints prevent invalid port values even when data is inserted directly through SQL.

## PostgreSQL Rule Evaluation

The `evaluate_packet()` function implements ordered firewall rule evaluation.

It:

1. Restricts evaluation to one repository.
2. Ignores disabled rules.
3. Checks protocol.
4. Checks source CIDR.
5. Checks destination CIDR.
6. Checks ports.
7. Checks direction.
8. Checks interface.
9. Orders candidates by `rule_order`.
10. Returns the first matching decision.
11. Returns `DENY` when no rule matches.

The explicit default-deny result is generated inside the database function rather than being left to the calling application.

## Transactional Policy Changes

The SQL script demonstrates a transaction around a policy modification.

The transaction disables the Telnet denial rule, inspects the resulting state, and then rolls the change back.

This illustrates an important operational principle: security policy changes should be treated as controlled state transitions rather than arbitrary individual updates.

A production change process would normally add authorization, audit records, change identifiers, approval requirements, testing, and controlled deployment.

## Failure Conditions

The implementations deliberately cover failure cases.

| Failure condition | Expected behavior |
|---|---|
| Invalid IPv4 address | Validation error |
| Invalid port | Validation error |
| TCP without ports | Validation error |
| ICMP with ports | Validation error |
| No matching allow rule | Default deny |
| Ambiguous zone | Configuration error |
| Unapproved inbound SSH | Deny |
| Explicit Telnet denial | Deny |
| Established permitted flow | Allow according to simplified state model |

The distinction between a malformed packet and a policy denial is important.

A malformed packet is invalid input.

A valid but unauthorized packet is a policy decision.

A configuration containing overlapping zones is a security configuration failure.

## Performance Considerations

A basic first-match firewall performs rule evaluation in `O(R)` time per packet, where `R` is the number of active rules.

Stateful flow lookup uses hash-based collections in the Python, JavaScript, C++, and Java implementations, providing expected `O(1)` lookup.

The PostgreSQL design adds indexes for common relational access patterns:

- Repository and rule order
- Packet history by repository and time
- Packet-to-decision relationships
- Connection flow attributes
- Zone-to-network relationships

Large production firewalls often use compiled rule structures, prefix trees, hash tables, connection-tracking tables, hardware acceleration, or other optimized mechanisms instead of scanning every rule for every packet.

## Security Considerations

The examples use default deny because accidental exposure is generally safer to prevent than accidental access.

Important operational controls include:

- Keep rules narrow.
- Place specific rules before broad rules.
- Avoid unnecessary source ranges.
- Avoid unrestricted destination ports.
- Separate public-facing systems from internal systems.
- Review state-table growth.
- Expire stale connection state.
- Detect overlapping or ambiguous zones.
- Log policy decisions without exposing unnecessary sensitive data.
- Protect firewall configuration from unauthorized modification.
- Validate configuration before activation.
- Treat rule order as security-sensitive state.

The examples intentionally use documentation-oriented IPv4 addresses and private address ranges rather than real organizational addresses.

## Relationship Between the Mechanisms

The mechanisms form a layered model:

`Packet`
`  ↓`
`Input Validation`
`  ↓`
`Zone Classification`
`  ↓`
`Existing Connection State`
`  ↓`
`Ordered Firewall Rules`
`  ↓`
`Default Deny`
`  ↓`
`Decision and Audit Record`

These stages have different responsibilities.

Stateless filtering evaluates the packet itself.

Stateful filtering evaluates the packet together with previously observed flow state.

Rules express the actual traffic conditions.

Zones express trust boundaries.

Default deny supplies the fallback when no permit exists.

None of these concepts should be treated as a substitute for the others. A zone is not a rule, a state entry is not an approval, and a default-deny result is not the same as an explicit deny rule.

## Practical Scenario

Consider a web server in the DMZ at `10.0.10.20`.

The intended policy is:

`Internet → DMZ TCP/443 → ALLOW`

`Internet → DMZ TCP/22 → DENY`

`Internet → DMZ TCP/23 → DENY`

`Internal → Internet TCP/443 → ALLOW`

`Internal → Internet UDP/53 → ALLOW`

`Everything else → DENY`

A client connecting to HTTPS can establish a permitted flow. Return traffic can then be recognized by a stateful firewall.

An unsolicited SSH connection does not match a permit and is denied.

An unsolicited Telnet connection can be denied explicitly.

Traffic between the Internet and the internal network remains denied because no policy grants that path.

This scenario demonstrates why packet matching, connection state, zones, and default-deny policy solve different parts of the firewall problem.
