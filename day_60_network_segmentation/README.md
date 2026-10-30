# Network Segmentation: VLANs, DMZ, Microsegmentation and Trust Zones

## 1. Domain and Security Architecture

Network segmentation divides an organization's network into separate logical or physical security domains. Each domain has a defined purpose, addressing structure, trust level, and permitted communication paths.

The central objective is to limit unnecessary connectivity between systems. A compromised endpoint should not automatically gain access to every other endpoint reachable through the organization's network.

This implementation treats network segmentation as a collection of related but distinct controls:

| Mechanism | Primary responsibility | Enforcement scope |
|---|---|---|
| VLAN | Separates Layer 2 broadcast domains | Switching infrastructure |
| Subnet | Defines an IP addressing range | Layer 3 addressing and routing |
| Trust zone | Groups networks by security classification | Network security policy |
| DMZ | Isolates externally accessible services | External-to-internal boundary |
| Network ACL | Controls communication between segments | Network and routing boundaries |
| Microsegmentation | Restricts workload-to-workload communication | Individual workloads |
| East-west filtering | Controls internal workload communication | Internal traffic paths |

These mechanisms are complementary. A VLAN does not automatically provide application-level security, and a subnet alone does not enforce access restrictions.

## 2. Reference Network Architecture

The implementations use a segmented enterprise network with six principal security zones.

| Segment | VLAN | Subnet | Trust zone | Example purpose |
|---|---:|---|---|---|
| Corporate users | 10 | 10.10.0.0/24 | USER | Employee workstations |
| DMZ | 20 | 10.20.0.0/24 | DMZ | Public-facing web services |
| Applications | 30 | 10.30.0.0/24 | APPLICATION | Internal APIs |
| Databases | 40 | 10.40.0.0/24 | DATA | Restricted database services |
| Management | 50 | 10.50.0.0/24 | MANAGEMENT | Administrative systems |
| External test network | 900 | 198.51.100.0/24 | INTERNET | Simulated external traffic |

The external test network uses a documentation-only IPv4 range. It represents an external source in the simulation rather than a real public Internet connection.

### Communication architecture

    EXTERNAL CLIENT
          |
          | HTTPS : 443
          v
    +-----------------------+
    |       INTERNET        |
    +-----------------------+
          |
          v
    +-----------------------+
    |          DMZ          |
    |      Web Server       |
    +-----------------------+
          |
          | HTTPS : 8443
          v
    +-----------------------+
    |     APPLICATION      |
    |       API Tier        |
    +-----------------------+
          |
          | PostgreSQL : 5432
          v
    +-----------------------+
    |         DATA          |
    |     Database Tier     |
    +-----------------------+

    MANAGEMENT
         |
         | Authorized SSH
         v
    APPLICATION

    USER
      |
      | HTTPS
      v
    DMZ

The architecture separates public access, application processing, persistent data, user access, and infrastructure administration.

The permitted application path is:

`External Client → DMZ Web → Application API → Database`

Direct communication between the DMZ web server and the database is denied.

## 3. VLANs and Subnet-Based Segmentation

### 3.1 Virtual LANs

A Virtual Local Area Network creates a logical Layer 2 broadcast domain within switching infrastructure.

VLAN assignment allows an organization to separate groups of devices without requiring each group to use physically independent switching equipment.

The implementation associates each VLAN with:

- A unique VLAN identifier.
- A named network segment.
- An IPv4 CIDR range.
- A security trust zone.
- A collection of registered endpoints.

VLAN identifiers in the examples remain within the normal usable range of 1 through 4094.

The inventory rejects duplicate VLAN identifiers, duplicate segment identifiers, and overlapping IPv4 subnets.

### 3.2 Subnet boundaries

A subnet identifies an IPv4 network and its host-address range.

For example:

| Property | Value |
|---|---|
| Network | 10.30.0.0/24 |
| Network mask | 255.255.255.0 |
| Address range | 10.30.0.0–10.30.0.255 |
| Conventional usable host range | 10.30.0.1–10.30.0.254 |
| Broadcast address | 10.30.0.255 |

A subnet and a VLAN frequently have a one-to-one relationship in enterprise networks, but they represent different concepts.

VLANs provide logical Layer 2 separation. Subnets provide Layer 3 addressing and routing boundaries.

Inter-VLAN communication generally requires a Layer 3 routing function. Routing establishes reachability, while security controls decide whether that reachability should be permitted.

### 3.3 Implementation decisions

All five implementations validate IPv4 ranges and reject overlapping subnet definitions.

The Python implementation uses `ipaddress.IPv4Network` and `ipaddress.ip_address`.

JavaScript converts validated IPv4 addresses into `BigInt` values and calculates network boundaries using bit masks.

C++17 stores IPv4 addresses as unsigned 32-bit integers and implements network containment and overlap detection with bit operations.

Java 17 uses immutable `IPv4Range` records with explicit address parsing and range validation.

PostgreSQL uses native `CIDR` and `INET` data types, together with triggers that validate subnet assignments.

## 4. Trust Zones and Security Boundaries

A trust zone groups systems that share a security classification and common communication requirements.

The example uses these classifications:

| Trust zone | Security purpose | Typical policy |
|---|---|---|
| USER | Employee devices | Restrict access to approved services |
| DMZ | Public-facing systems | Permit narrowly scoped external access |
| APPLICATION | Business applications and APIs | Allow approved service communication |
| DATA | Persistent information systems | Restrict access to designated application workloads |
| MANAGEMENT | Administrative infrastructure | Permit authorized management operations |
| INTERNET | Untrusted external sources | Allow only explicitly authorized ingress |

Trust zones are logical policy constructs. A trust-zone label does not independently enforce security. Enforcement must occur through routing controls, firewalls, access lists, distributed policies, or equivalent security infrastructure.

### Default-deny enforcement

All implementations adopt a default-deny approach.

A connection is permitted only when a matching policy authorizes it.

A missing rule does not imply permission.

The network engine applies rules in ascending priority order. The first matching rule determines the applicable action.

The implementation uses a deterministic secondary ordering by rule identifier where equal priorities exist. The Java implementation and PostgreSQL schema require unique priorities within each rule set.

Explicit deny rules and missing-rule denials are both represented as denied decisions. Production monitoring should preserve the matching rule identifier to distinguish those causes.

## 5. DMZ Architecture

A Demilitarized Zone is an isolated network area used for services that must communicate with untrusted external systems while remaining separated from sensitive internal networks.

Examples include:

- Public web servers.
- Reverse proxies.
- External service gateways.
- Public-facing application entry points.
- Controlled mail gateways.

The DMZ is not intended to be a trusted extension of the internal application or database network.

The reference policy permits external HTTPS access to the web tier. The web tier can communicate with the application API over TCP port 8443. The application tier can reach the database over TCP port 5432.

Direct DMZ-to-database communication has no matching network-boundary permission and is therefore denied.

### DMZ traffic policy

| Source | Destination | Protocol | Port | Result |
|---|---|---|---:|---|
| INTERNET | DMZ | TCP | 443 | Allow |
| USER | DMZ | TCP | 443 | Allow |
| DMZ | APPLICATION | TCP | 8443 | Allow |
| DMZ | DATA | TCP | 5432 | Deny |
| INTERNET | DATA | TCP | 5432 | Deny |

The design separates the public service boundary from the application and data boundaries.

A production DMZ may also require reverse proxies, intrusion detection, application gateways, egress filtering, certificate management, logging, and dedicated firewall interfaces.

## 6. Microsegmentation

Microsegmentation applies access restrictions at the workload or individual endpoint level rather than relying exclusively on network-level separation.

Traditional VLAN segmentation can isolate departments or infrastructure tiers while still allowing broad communication within an individual VLAN.

Microsegmentation addresses this limitation by evaluating workload identity, labels, application roles, and permitted service ports.

For example, two API servers may occupy the same application VLAN. They remain separate workloads, and the policy engine can deny unauthorized communication between them.

### 6.1 Workload identity

Each endpoint has a collection of labels.

The principal label used in the example is `role`.

| Endpoint | Segment | Role |
|---|---|---|
| web-01 | DMZ | web |
| api-01 | APPLICATION | api |
| api-02 | APPLICATION | api |
| db-01 | DATA | database |
| admin-01 | MANAGEMENT | administrator |
| external-client | INTERNET | internet-client |

The microsegmentation engine matches source and destination roles against policy selectors.

Supported selectors include exact roles and the wildcard `*`.

Wildcards permit broader policies and therefore require careful control. Production implementations should restrict their use, require appropriate authorization, and evaluate whether a wildcard exposes unnecessary services.

### 6.2 Microsegmentation rules

| Source role | Destination role | Protocol | Port | Decision |
|---|---|---|---:|---|
| internet-client | web | TCP | 443 | Allow |
| employee | web | TCP | 443 | Allow |
| web | api | TCP | 8443 | Allow |
| api | database | TCP | 5432 | Allow |
| administrator | api | TCP | 22 | Allow |

The API-to-database rule does not authorize unrelated ports.

An API workload connecting to a database on TCP port 443 receives a denial even though the network segment pair may be permitted to communicate on the designated database service port.

### 6.3 Network segmentation versus microsegmentation

Network segmentation controls which network domains can communicate.

Microsegmentation controls which workloads within those domains can communicate.

The two controls operate at different levels and should not be treated as replacements for each other.

The implementations apply both policies to cross-segment workload traffic.

For endpoints within the same VLAN, the inter-VLAN policy is marked `NOT_REQUIRED`. Microsegmentation remains mandatory.

## 7. East-West and North-South Traffic

Traffic direction helps determine where security controls should be applied.

### North-south traffic

North-south traffic crosses the organization's network perimeter or moves between an external network and internal infrastructure.

Examples:

- An Internet client connecting to a public web server.
- An internal user reaching an external service.
- An external system accessing a controlled gateway.

### East-west traffic

East-west traffic travels between internal systems or workloads.

Examples:

- A web server calling an application API.
- An application connecting to a database.
- One container communicating with another container.
- An internal service attempting to connect directly to a different application tier.

East-west traffic is important because an attacker who compromises an internal system may attempt to move laterally toward additional systems.

The application-to-database flow is an east-west connection across trust-zone boundaries.

The API-to-API flow in the same VLAN is an intra-segment connection and is still subject to workload-level restrictions.

### Traffic classification implemented

| Condition | Classification |
|---|---|
| Either endpoint is in INTERNET | NORTH_SOUTH |
| Both endpoints are in the same segment | INTRA_SEGMENT |
| Both endpoints are internal but in different segments | EAST_WEST |

These classifications support auditing and traffic analysis. They are not substitutes for a complete network-routing topology.

## 8. Policy Evaluation Workflow

The common policy evaluation sequence is:

    Register network segments
             |
             v
    Validate VLAN and CIDR ranges
             |
             v
    Register endpoints and workload labels
             |
             v
    Create network boundary rules
             |
             v
    Create microsegmentation rules
             |
             v
    Validate policy configuration
             |
             v
    Receive traffic-flow request
             |
             v
    Identify source and destination
             |
             v
    Determine traffic classification
             |
             v
    Evaluate inter-segment policy
             |
             v
    Evaluate workload policy
             |
             v
    Apply default-deny behavior
             |
             v
    Record decision in audit history

The final authorization condition for cross-segment traffic is:

`Final Allow = Network Policy Allow AND Microsegmentation Allow`

For same-segment traffic:

`Final Allow = Microsegmentation Allow`

An explicit network denial overrides an otherwise permitted workload rule.

## 9. Python Implementation

**File:** `network_segmentation.py`

The Python implementation provides a repository-style configuration and traffic simulation through object-oriented domain models.

### Main components

| Component | Responsibility |
|---|---|
| `Zone` | Defines trust-zone classifications |
| `Protocol` | Restricts supported transport protocols |
| `Action` | Defines ALLOW and DENY decisions |
| `NetworkSegment` | Validates VLAN and IPv4 network metadata |
| `Endpoint` | Stores workload identity and labels |
| `NetworkRule` | Represents inter-zone access permissions |
| `MicroRule` | Represents workload-level permissions |
| `TrafficFlow` | Models an attempted connection |
| `NetworkInventory` | Maintains segments and endpoint assignments |
| `SegmentationEngine` | Evaluates policies and records decisions |

### Python-specific mechanisms

The implementation uses:

- `dataclasses` for strongly structured domain records.
- `Enum` for controlled trust-zone, protocol, and action values.
- `MappingProxyType` for read-only endpoint labels.
- Dictionaries for constant-time inventory lookup.
- Sets for VLAN-independent IP uniqueness and flow deduplication.
- `ipaddress` for subnet parsing, validation, and overlap detection.
- Exceptions for invalid topology and traffic inputs.
- Logging for policy evaluation events.
- Assertions for executable verification.

The engine separates network rules from microsegmentation rules.

It sorts rule lists before processing so that rule precedence is deterministic.

A flow receives a decision only after its endpoints and segment assignments have been validated.

The audit history stores the resulting traffic class, decisions from each policy layer, and the reason for the final result.

### Validation scenarios

The program checks both permitted and prohibited traffic.

It verifies external HTTPS access, employee-to-web access, web-to-API communication, API-to-database access, and administrative SSH.

It also verifies direct DMZ-to-database denial, unauthorized same-VLAN communication, and incorrect database service-port access.

The configuration tests reject overlapping networks, invalid VLAN identifiers, and reversed port ranges.

## 10. JavaScript Implementation

**File:** `network_segmentation.js`

The JavaScript implementation focuses on event-driven evaluation and asynchronous processing of connection requests.

It is designed for a Node.js runtime and requires no third-party npm packages.

### Main components

| Component | Responsibility |
|---|---|
| `NetworkInventory` | Stores segments, endpoints, and unique network assignments |
| `TrafficPolicyEngine` | Evaluates network and workload policies |
| `EventEmitter` | Publishes security decisions and evaluation errors |
| `evaluateFlow()` | Processes an individual flow asynchronously |
| `evaluateBatch()` | Processes multiple flows using bounded concurrency |

### JavaScript-specific mechanisms

The implementation uses `Map` for segment and endpoint indexes.

`Set` provides duplicate detection for VLAN identifiers, endpoint addresses, and flow IDs.

`Object.freeze()` is used to protect registered inventory objects and policy records from ordinary property reassignment.

The IPv4 implementation converts addresses to `BigInt` values because JavaScript's ordinary number representation is not appropriate for all unsigned 32-bit bitwise operations.

The CIDR parser calculates network boundaries and validates address membership.

### Asynchronous processing

The policy engine processes a collection of flow requests using worker functions.

A shared cursor assigns each request to a worker. The requested concurrency is limited to a maximum of 32 workers.

Individual evaluation failures are captured as error results instead of terminating the entire batch.

The event interface exposes:

- `decision` for completed flow evaluations.
- `evaluationError` for invalid or failed requests.

Metrics are maintained by traffic classification and final decision.

Audit history is bounded to prevent unlimited memory growth in long-running simulations.

The implementation is suitable for understanding asynchronous policy evaluation. A real network enforcement agent would also need transport integration, durable audit storage, authenticated policy updates, and protection against untrusted event sources.

## 11. C++17 Implementation

**File:** `network_segmentation.cpp`

The C++ implementation treats network segmentation as a governance and evaluation engine with explicit memory ownership and numeric network calculations.

### Main components

| Component | Responsibility |
|---|---|
| `IPv4Range` | Parses IPv4 networks and evaluates address ranges |
| `Segment` | Represents a VLAN and trust zone |
| `Endpoint` | Represents a registered workload |
| `NetworkInventory` | Enforces inventory uniqueness and subnet membership |
| `NetworkRule` | Represents boundary-level filtering |
| `MicroRule` | Represents workload-level filtering |
| `TrafficFlow` | Represents a connection request |
| `SegmentationEngine` | Evaluates policies and records the result |
| `Decision` | Captures the outcome of both enforcement layers |

### C++ implementation mechanisms

IPv4 addresses are represented using `std::uint32_t`.

Subnet masks, first addresses, last addresses, and containment checks are calculated with bitwise operations.

`std::unordered_map` provides endpoint and segment lookup.

`std::unordered_set` protects against duplicate identifiers and IP assignments.

`std::vector` stores ordered policy rules and audit records.

`std::optional<Action>` distinguishes a matching policy rule from the absence of a matching rule.

Exceptions reject invalid configuration and invalid flow requests.

The engine uses a reference to the inventory rather than copying the complete network model for every evaluation.

This approach avoids unnecessary inventory duplication but requires the inventory to remain alive for the lifetime of the engine.

### Engineering considerations

The CIDR parser uses explicit IPv4 parsing rather than a networking dependency.

The program sorts rule vectors once during engine construction, avoiding repeated sorting for individual traffic requests.

Rule evaluation is linear in the number of rules in the relevant policy layer.

For large rule collections, additional indexing by source zone, destination zone, protocol, port range, and workload role would reduce repeated scanning.

The program demonstrates the distinction between a missing matching rule and an accepted rule through `std::optional`, while applying default-deny behavior when no rule matches.

## 12. Java 17 Enterprise Implementation

**File:** `NetworkSegmentationGovernance.java`

The Java implementation emphasizes enterprise policy governance, approval control, immutable records, and explicit policy lifecycle management.

### Domain model

Java records represent:

- `IPv4Range`
- `Segment`
- `Endpoint`
- `NetworkRule`
- `MicroRule`
- `TrafficFlow`
- `Evaluation`

The `NetworkInventory` class controls additions to the segment and endpoint collections.

Records provide immutable data structures for registered policy inputs.

### Policy revision lifecycle

A policy revision is maintained as a controlled domain object.

It uses three states:

| State | Meaning |
|---|---|
| DRAFT | Rules and required approvals can be configured |
| ACTIVE | The approved policy can evaluate traffic |
| RETIRED | The revision is no longer eligible for evaluation |

The supported transitions are:

    DRAFT
      |
      | Required approvals complete
      v
    ACTIVE
      |
      | Retirement operation
      v
    RETIRED

Other transitions are rejected.

### Separation of duties

The revision requires approval from two roles:

- NETWORK_SECURITY
- PLATFORM_OPERATIONS

A principal who created a policy revision cannot approve that revision.

One principal cannot submit multiple approvals under different identities within the same revision object.

Activation requires every configured approval role to be represented.

This is a basic separation-of-duties model. A production approval service would also need authenticated identities, role assignments derived from an authoritative identity provider, approval timestamps, immutable historical records, and protected administrative operations.

### Evaluation service

`NetworkPolicyService` accepts only active policy revisions.

It stores immutable copies of the rule lists and rejects duplicate identifiers and priorities.

Java Streams are used to locate the first matching rule.

The service records every successful policy evaluation in an audit collection.

It does not permit a retired policy revision to continue evaluating new traffic.

The implementation demonstrates enterprise governance controls without mixing approval decisions with actual network access rules.

## 13. PostgreSQL Relational Implementation

**File:** `network_segmentation.sql`

The PostgreSQL implementation stores the segmentation topology, policy configurations, approval requirements, and traffic audit history.

It represents the domain through related relational tables rather than maintaining all state in application memory.

### 13.1 Relational entities

| Table | Purpose |
|---|---|
| `segments` | VLAN identities, CIDR networks, and trust zones |
| `endpoints` | IP addresses, endpoint identities, and workload labels |
| `policy_revisions` | Versioned network policy configurations |
| `approval_requirements` | Required organizational approval roles |
| `policy_approvals` | Individual policy approval records |
| `network_rules` | Inter-zone access rules |
| `micro_rules` | Workload-level access rules |
| `flow_audit` | Persisted traffic evaluation decisions |

### 13.2 Relational structure

    segments
       |
       +-------------------+
       |                   |
       v                   v
    endpoints       policy_revisions
                           |
              +------------+------------+
              |            |            |
              v            v            v
         network_rules  micro_rules  approval_requirements
                                       |
                                       v
                                policy_approvals

    policy_revisions
          |
          v
      flow_audit
          |
          +----------------------+
          |                      |
          v                      v
    source endpoint       destination endpoint

The relationships preserve endpoint ownership, policy revision identity, and approval history.

### 13.3 Database constraints

The schema applies primary keys, foreign keys, unique constraints, and check constraints.

VLAN IDs must be between 1 and 4094.

Endpoint addresses must be IPv4 addresses assigned to the network of their associated segment.

Trust zones are restricted to the supported classifications.

Protocols, ports, policy actions, and policy states are validated at the database level.

A unique partial index prevents more than one active revision of the same named policy.

### 13.4 Triggers

The schema implements triggers for several integrity requirements.

**Subnet overlap protection**

`prevent_segment_overlap()` rejects overlapping CIDR networks before a segment is inserted or updated.

**Endpoint subnet membership**

`validate_endpoint_network()` verifies that an endpoint's IP address is within its assigned network.

**Policy lifecycle enforcement**

`validate_policy_state_transition()` restricts policy transitions to the supported lifecycle.

**Draft-only configuration**

`enforce_draft_policy_revision()` prevents modification of policy rules, approval requirements, and approval records after activation.

**Approval validation**

`validate_policy_approval()` prevents self-approval and rejects approvals from roles that are not required by the revision.

### 13.5 Transactional activation

The `activate_policy_revision()` function locks the revision row while validating its activation conditions.

It requires at least one configured approval requirement and verifies that every required role has supplied an approval.

The activation operation updates the revision state only after successful validation.

This provides atomic policy activation within the database transaction.

### 13.6 Traffic evaluation

The `evaluate_flow()` function performs the complete decision workflow.

It first checks the active policy revision and registered endpoints.

It identifies the source and destination trust zones, determines the traffic classification, and evaluates network-boundary rules.

It then evaluates workload-level microsegmentation rules.

A missing matching rule becomes a denial.

The resulting decision is inserted into `flow_audit`.

The function returns the traffic classification, each policy-layer outcome, the final authorization decision, and the reason.

### 13.7 Views and reporting

Three views provide reusable operational queries.

| View | Reporting purpose |
|---|---|
| `v_segment_inventory` | VLANs, networks, trust zones, and active endpoint counts |
| `v_active_policy_summary` | Active revisions and their rule and approval counts |
| `v_flow_security_report` | Readable traffic decisions with endpoint identities and roles |

Additional queries demonstrate traffic aggregation, denial investigation, approval validation, policy retrieval, and CTE-based security reporting.

The SQL script is designed to be executed as a complete schema setup and demonstration transaction.

## 14. Integrated Security Scenarios

The same reference scenarios are represented across the implementations.

| Flow | Source | Destination | Port | Expected outcome | Reason |
|---|---|---|---:|---|---|
| FLOW-001 | Internet client | Web server | 443 | ALLOW | Approved external HTTPS |
| FLOW-002 | Employee | Web server | 443 | ALLOW | Approved user access |
| FLOW-003 | Web server | API | 8443 | ALLOW | Authorized application path |
| FLOW-004 | API | Database | 5432 | ALLOW | Authorized data service |
| FLOW-005 | Web server | Database | 5432 | DENY | DMZ-to-data boundary restriction |
| FLOW-006 | API-01 | API-02 | 8080 | DENY | Same-VLAN microsegmentation restriction |
| FLOW-007 | Administrator | API | 22 | ALLOW | Authorized management path |
| FLOW-008 | API | Database | 443 | DENY | Unauthorized database service port |

The scenarios illustrate why network boundaries and workload-level permissions must be evaluated separately.

FLOW-005 is rejected by the network-boundary policy.

FLOW-006 does not require inter-VLAN filtering because its source and destination belong to the same segment. It is rejected by the microsegmentation policy.

FLOW-008 demonstrates that membership in an otherwise permitted source-to-destination zone pair does not authorize every destination port.

## 15. Validation, Failure Handling and Security Controls

The implementations validate configuration before accepting traffic evaluations.

| Failure condition | Expected behavior |
|---|---|
| Duplicate VLAN ID | Reject segment registration |
| Duplicate endpoint ID | Reject endpoint registration |
| Overlapping IPv4 networks | Reject network configuration |
| Invalid IPv4 address | Reject endpoint registration |
| Endpoint outside assigned subnet | Reject endpoint registration |
| Invalid port | Reject rule or flow |
| Unknown endpoint | Reject flow evaluation |
| Duplicate flow ID | Reject duplicate processing |
| Missing boundary permission | Deny cross-segment communication |
| Missing microsegmentation permission | Deny workload communication |
| Incomplete policy approvals | Prevent activation |
| Unauthorized approval role | Reject approval |
| Policy creator self-approval | Reject approval |
| Modification of active policy | Reject configuration change |
| Evaluation against inactive Java policy | Reject evaluation |

### Security considerations

The examples are policy simulators. They do not configure actual VLANs, routing tables, firewall appliances, software-defined networking controllers, hypervisors, or container networking systems.

A production deployment must translate the approved policy model into enforcement rules supported by the relevant network infrastructure.

Important operational controls include:

- Authenticate all network policy administrators.
- Authorize policy changes through role-based access control.
- Protect management networks from user and application networks.
- Restrict administrative access to approved management paths.
- Authenticate policy distribution to enforcement points.
- Prevent unauthorized modification of active policies.
- Retain auditable policy revisions and traffic decisions.
- Monitor denied east-west connections.
- Validate rule changes before deployment.
- Use controlled rollback and policy versioning.
- Protect audit records against unauthorized modification.
- Apply explicit egress restrictions.
- Monitor policy drift between intended and deployed configurations.

The example database uses role names as policy attributes. Those values are not proof of user identity. Production approval records must be linked to authenticated identities and authoritative authorization data.

## 16. Performance and Scalability

Policy evaluation performance depends on the number of segments, endpoints, rules, and traffic requests.

The examples use indexed lookup structures for inventory operations and sort policy rules during initialization.

| Implementation | Inventory lookup | Policy matching | Audit storage |
|---|---|---|---|
| Python | Dictionary | Ordered list scan | In-memory list |
| JavaScript | Map | Ordered array scan | Bounded in-memory history |
| C++17 | Unordered map | Ordered vector scan | In-memory vector |
| Java 17 | HashMap | Stream over ordered immutable lists | In-memory list |
| PostgreSQL | B-tree and expression indexes | Indexed SQL queries | Relational table |

The rule matching approach has linear worst-case scanning cost relative to the number of rules in the relevant policy layer.

For larger deployments, suitable optimization strategies include:

- Indexing rules by source and destination zone.
- Partitioning rule collections by protocol and service port.
- Indexing endpoint workload identities.
- Caching active policy snapshots.
- Separating control-plane updates from data-plane enforcement.
- Partitioning large traffic-audit tables by time.
- Using retention policies for historical flow records.
- Processing traffic decisions in controlled batches.

The JavaScript worker model is an asynchronous processing demonstration. It does not provide CPU parallelism for its policy calculations.

The in-memory audit implementations are intended for bounded simulations and should be replaced by durable storage and controlled retention mechanisms in production.

## 17. Implementation Comparison

| Capability | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Segment inventory | Yes | Yes | Yes | Yes | Yes |
| IPv4 validation | `ipaddress` | `BigInt` arithmetic | 32-bit arithmetic | Immutable range record | Native CIDR and INET |
| Trust-zone evaluation | Yes | Yes | Yes | Yes | Yes |
| Network-boundary rules | Yes | Yes | Yes | Yes | Yes |
| Microsegmentation | Yes | Yes | Yes | Yes | Yes |
| East-west classification | Yes | Yes | Yes | Yes | Yes |
| Default-deny behavior | Yes | Yes | Yes | Yes | Yes |
| Duplicate flow prevention | Yes | Yes | Yes | Yes | Unique constraint |
| Policy approvals | Not modeled | Not modeled | Not modeled | Explicit lifecycle | Relational workflow |
| Durable audit storage | No | No | No | No | Yes |
| Asynchronous batch processing | No | Yes | No | No | Database execution |

Each implementation uses the same security scenario but emphasizes a different engineering concern.

Python focuses on domain modeling and validation.

JavaScript focuses on asynchronous traffic processing and event-driven reporting.

C++17 focuses on efficient numeric network calculations and explicit data structures.

Java 17 focuses on enterprise policy lifecycle, approval requirements, and separation of duties.

PostgreSQL focuses on relational integrity, controlled policy activation, and persistent security reporting.

## 18. Important Technical Limitations

The implementations use IPv4 and TCP or UDP traffic with destination-port-based matching.

They do not implement complete packet inspection, connection tracking, stateful firewall behavior, routing protocols, NAT, IPv6, ICMP policy evaluation, or encrypted tunnel processing.

They also do not implement physical switch configuration or direct firewall deployment.

A production microsegmentation system may need workload identity from orchestration platforms, endpoint agents, host firewalls, distributed firewall controls, service-mesh authorization, or network virtualization.

A network boundary rule does not establish that an application endpoint is healthy or that the application-layer request is authorized.

Similarly, a permitted IP-level connection does not establish that a user has permission to access a particular record or business operation.

Network segmentation therefore remains one layer of a broader security architecture, working alongside identity management, application authorization, endpoint protection, monitoring, and infrastructure governance.
