# Host-Based Firewalls: Inbound and Outbound Controls, Application Rules, and Logging

## Scope

This project models a host-based firewall as a policy engine that evaluates network connections against ordered rules. The implementation separates four important concerns:

- inbound traffic control
- outbound traffic control
- application-specific rules
- security logging and audit records

The same domain is implemented from five engineering perspectives:

| Implementation | Primary perspective |
|---|---|
| Python | Deterministic firewall simulation with validation and audit export |
| JavaScript | Event-driven policy evaluation with asynchronous audit persistence |
| C++17 | Native governance-oriented rule engine |
| Java 17 | Enterprise domain model with explicit policy services |
| PostgreSQL | Relational firewall, traffic, audit, and governance model |

The examples use private addresses such as `10.20.0.10` and documentation addresses such as `198.51.100.20`. They represent policy scenarios rather than live network endpoints.

## Firewall Model

A host-based firewall applies policy directly to traffic associated with an individual host. A connection can be evaluated using several dimensions:

- direction
- transport protocol
- source address
- destination address
- destination port
- application identity
- user identity where available

A simplified evaluation path is:

`Connection -> Validation -> Ordered Rules -> First Match -> Allow/Deny -> Audit`

The examples use a default-deny policy. A connection that does not match an explicit allow rule is denied.

This is a policy simulation rather than a kernel firewall. It does not modify operating-system packet-filtering state.

## Inbound Controls

Inbound controls determine which externally initiated traffic may reach services on the host.

The examples permit administrative SSH only when the connection:

- is inbound
- uses TCP
- originates from `10.20.0.0/24`
- targets port `22`
- identifies the application as `sshd`

A connection from `203.0.113.50` targeting an application service on port `8080` is denied.

This distinction matters because allowing a port without restricting its source or application context can create a wider attack surface.

The Python, C++, JavaScript, and Java implementations represent inbound restrictions as ordered rules. PostgreSQL stores the same policy as relational data and supports network containment through PostgreSQL `inet` and `cidr` operators.

## Outbound Controls

Outbound controls determine which applications and destinations a host may contact.

The examples allow:

- DNS queries from the resolver to `10.20.0.53` on UDP port `53`
- HTTPS from the approved browser application on TCP port `443`

Unknown outbound traffic is denied by a lower-priority catch-all rule.

This creates an explicit distinction between:

`known required communication -> allow`

and:

`unclassified communication -> deny`

Outbound controls are useful for limiting unauthorized software communication, reducing unnecessary egress paths, and producing useful security telemetry.

A production policy normally needs additional considerations such as stateful connection tracking, IPv6, DNS over HTTPS, proxy traffic, local services, service accounts, certificate validation, and operating-system-specific application identity.

## Application Rules

A port-based rule answers a network question: which destination service is reachable?

An application rule answers a process-policy question: which software is permitted to generate or receive the traffic?

The examples therefore combine:

- protocol
- network
- destination port
- application identity

For example, TCP port `443` alone does not establish that every local process should have unrestricted HTTPS access. The example associates the outbound HTTPS rule with `browser`.

The Python implementation supports shell-style application patterns. JavaScript provides wildcard matching through regular expressions. C++ uses a compact prefix-style wildcard implementation. Java represents application policy through explicit enterprise policy objects.

Real operating systems require stronger application identity mechanisms than a user-provided process name. A production firewall may bind rules to executable paths, code signatures, service identities, package identities, security labels, or operating-system firewall objects.

## Rule Ordering

Rule priority is a central design decision.

The examples sort rules by ascending priority and evaluate them from the smallest value to the largest.

For example:

| Priority | Rule | Purpose |
|---:|---|---|
| 10 | `ALLOW-SSH-MGMT` | Permit trusted administrative SSH |
| 20 | `DENY-INBOUND-APP` | Reject an exposed application service |
| 30 | `ALLOW-DNS` | Permit approved DNS |
| 40 | `ALLOW-HTTPS` | Permit approved browser HTTPS |
| 90 | `DENY-UNKNOWN-OUTBOUND` | Reject unmatched outbound traffic |

The explicit rules are evaluated before the catch-all denial.

A production firewall must define rule ordering unambiguously. Ambiguous ordering can produce unexpected access.

## Logging and Audit

Logging is separate from the allow-or-deny decision.

A rule can specify:

- `none`: do not record the decision
- `denied`: record denials
- `all`: record both allowed and denied decisions

Audit records contain fields such as:

- timestamp
- direction
- protocol
- source address
- destination address
- ports
- application
- user
- action
- rule identifier
- decision reason

Logging policy should be designed with storage volume and sensitive-data exposure in mind. High-volume allowed traffic can generate substantially more data than denied traffic.

Security logging should also protect records from unauthorized modification and should use controlled retention periods.

## Python Implementation

The Python implementation is a self-contained policy simulator.

`FirewallRule` is a frozen dataclass representing immutable policy configuration. `Connection` represents a traffic request, while `Decision` represents the policy result.

The `HostFirewall` class provides:

- rule registration
- duplicate rule detection
- priority ordering
- CIDR matching
- application pattern matching
- default-deny behavior
- decision logging
- JSON audit export

Validation occurs before policy evaluation. Invalid IP addresses and ports are rejected rather than silently interpreted.

The executable assertions verify the principal policy outcomes. The generated `firewall_audit.json` file contains logged decisions after the program runs.

The rule scan is `O(R)` per connection, where `R` is the number of enabled rules. For a large rule set, production implementations should use indexing or native firewall mechanisms rather than scanning every rule.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library facilities.

`EventEmitter` provides an event-driven audit mechanism. A decision can be evaluated synchronously while audit consumers react to the resulting event.

The implementation uses:

- classes for firewall rules and connections
- frozen constants for policy enumerations
- `Map`-compatible structured data concepts
- `EventEmitter` for audit events
- asynchronous `fs.writeFile` for audit persistence
- native IP validation through Node's `net` module

The application matcher converts wildcard patterns into regular expressions after escaping regular-expression metacharacters. This prevents a rule pattern from accidentally becoming arbitrary regular-expression syntax.

The asynchronous audit export demonstrates a useful separation between policy evaluation and persistence.

## C++17 Implementation

The C++ program treats the firewall as a native policy engine.

The `IPv4Network` class converts IPv4 addresses and CIDR networks into integer representations. Network containment then uses bit masking.

This provides a compact implementation of:

`address & mask == network & mask`

The rule engine uses:

- `enum class` for policy states
- `struct` for domain records
- `std::vector` for ordered rules
- `std::optional` for optional ports
- STL algorithms for sorting and duplicate detection
- exceptions for invalid policy and input
- deterministic first-match evaluation

The C++ implementation deliberately emphasizes explicit memory ownership and low-level network representation.

Its principal complexity is `O(R)` per evaluation with `O(R)` rule storage. IPv4 network matching itself is constant time.

## Java 17 Implementation

The Java implementation models firewall policy as an enterprise service.

Records provide immutable representations for:

- connections
- firewall rules
- audit events
- policy configuration
- decisions

The `RulePolicy` interface separates policy validation from connection matching. `EnterprisePolicy` can reject an otherwise matching rule when organizational constraints are violated.

This produces two distinct stages:

`network rule matching -> enterprise policy validation`

That separation is useful when firewall configuration must obey organizational controls beyond basic packet characteristics.

The Java service also exposes immutable audit results through `List.copyOf`.

Custom exceptions distinguish policy violations from ordinary invalid arguments.

## PostgreSQL Implementation

The PostgreSQL implementation stores the firewall as a relational system.

Core entities include:

- `repositories`
- `hosts`
- `applications`
- `firewall_rules`
- `firewall_connections`
- `firewall_decisions`
- `branch_protection_policies`
- `status_checks`
- `pull_requests`
- `reviewers`
- `review_policies`
- `reviews`
- `review_comments`

The firewall portion uses PostgreSQL `inet` and `cidr`, allowing database-native network containment operations.

The schema enforces:

- valid ports
- unique rule names per host
- foreign-key relationships
- valid workflow states
- valid review states
- positive rule priorities

The `evaluate_pull_request` function is included as a repository-governance workflow model because the domain also demonstrates how host-security changes can be subject to repository-level controls before deployment.

## Database Firewall Evaluation

The connection query joins traffic with applicable firewall rules and ranks matching rules using:

`ROW_NUMBER() OVER (PARTITION BY connection_id ORDER BY priority)`

The first-ranked rule represents the selected policy.

This mirrors the ordered evaluation performed by the source-language implementations while allowing PostgreSQL to perform network matching and reporting over stored traffic.

The database also supports aggregation of denied events by host.

## Transactional Integrity

The PostgreSQL example records a connection and its selected decision inside a transaction.

The transaction ensures that a connection record and its associated decision are committed together.

If either operation fails, the transaction can be rolled back rather than leaving a connection without a corresponding decision.

This is important for audit systems because partial records can make incident reconstruction unreliable.

## Failure Conditions

The implementations explicitly handle several failure conditions:

| Failure | Handling |
|---|---|
| Invalid IP address | Validation exception |
| Invalid port | Validation failure |
| Duplicate rule | Rule-registration error |
| Missing application identity | Validation failure |
| No rule match | Default denial |
| Disabled rule | Skipped during evaluation |
| Stale approval in the database | Approval does not satisfy current-commit validation |
| Unresolved review comments | Merge eligibility remains false |
| Failed required status check | Merge eligibility remains false |
| Insufficient approvals | Merge eligibility remains false |

The firewall default-deny behavior is intentionally conservative.

## Security Considerations

A policy engine should not treat a hostname, process name, or user-provided application string as a cryptographically strong application identity.

Production deployments should consider:

- authenticated process identity
- executable integrity
- operating-system firewall APIs
- IPv6 policy
- stateful connection tracking
- least-privilege rules
- protected configuration files
- administrator authorization
- tamper-resistant logging
- time synchronization
- log retention
- alerting for repeated denials
- protection against rule-order mistakes
- configuration change auditing

The sample addresses are documentation-oriented values. They are not intended as real public endpoints.

## Relationship to Repository Governance

The PostgreSQL model also represents the repository controls needed when firewall configuration is maintained as source code.

The governance chain is:

`Repository -> Branch -> Pull Request -> Review -> Approval -> Status Checks -> Branch Protection -> Merge`

These concepts are related but are not interchangeable.

A Pull Request provides the workflow for proposing a change.

Code Review evaluates the proposed changes and records reviewer feedback.

Approvals represent reviewer decisions on a particular revision.

Branch Protection enforces repository-level conditions before the change can be merged.

An approval can become stale when new commits change the reviewed revision. A protected branch can require fresh approvals, successful status checks, resolved conversations, or other repository conditions.

## Practical Workflow

A realistic firewall policy change can follow this sequence:

`Policy requirement`
`      ↓`
`Firewall rule change`
`      ↓`
`Pull Request`
`      ↓`
`Automated validation`
`      ↓`
`Code Review`
`      ↓`
`Required Approvals`
`      ↓`
`Branch Protection`
`      ↓`
`Merge`
`      ↓`
`Deployment`
`      ↓`
`Host Enforcement`
`      ↓`
`Security Logging`

The source files focus on the host-policy and evaluation stages. The PostgreSQL governance model shows how repository controls can determine whether a policy change is eligible for integration.

## Design Distinctions

The project keeps four security concepts distinct:

| Concept | Question answered |
|---|---|
| Inbound control | Which traffic may enter the host? |
| Outbound control | Which traffic may leave the host? |
| Application rule | Which local software is associated with the traffic? |
| Logging | Which decisions and events should be recorded? |

A firewall decision is therefore not just an allow-or-deny operation. It is the result of validated traffic attributes, ordered policy, application context, and logging requirements.

## Limitations

The implementations are educational policy engines rather than replacements for operating-system firewall subsystems.

They do not implement:

- kernel packet filtering
- TCP state tracking
- connection teardown
- NAT
- IPv6 firewall enforcement
- packet inspection
- encrypted traffic decryption
- executable signature verification
- real operating-system process attribution

Those mechanisms depend on the operating system, network stack, firewall framework, and deployment architecture.

The examples instead provide a deterministic model for reasoning about firewall policy, application restrictions, audit behavior, validation, and database-backed governance.
