# Linux Hardening: Account Security, SSH, Firewalls, Patching, and Auditing

## Scope

Linux hardening reduces the attack surface of a host and limits the consequences of a compromised account, exposed network service, unpatched package, or undetected configuration change. Effective hardening combines preventive controls, timely maintenance, and evidence that the controls remain active.

This laboratory examines five connected control families:

- **Account security** governs identities, UIDs, privileged access, service accounts, shells, and credential lifecycle.
- **SSH hardening** restricts remote administrative authentication, login eligibility, and tunnelling capabilities.
- **Firewalling** controls permitted inbound, outbound, and forwarded network traffic.
- **Patching** manages security fixes, package freshness, unattended updates, and restarts needed to activate updates.
- **Auditing** records security-relevant events and supports investigations through persistent logs, reliable timestamps, and file-integrity monitoring.

The implementations are assessment models. They consume supplied configuration inventories and report findings; they do not claim to discover the real state of an operating system automatically or apply privileged changes.

## Control relationships

Hardening controls reinforce each other, but they address different attack paths. A restrictive firewall reduces exposure to network services. SSH configuration limits remote login methods and eligible accounts. Account policies limit what an authenticated identity can do. Patching reduces exposure to known vulnerabilities. Auditing helps investigators determine what happened and whether remediation was effective.

A firewall cannot make an insecure local account safe. Public-key SSH authentication cannot compensate for an administrator account with unnecessary privileges. Installing a security package does not prove that a required reboot has occurred. Logs that are collected without trustworthy timestamps can be difficult to correlate during an incident.

The assessment therefore evaluates several control families independently rather than treating a single successful check as evidence that the entire host is secure.

## Account security

### Identity and privilege

Linux accounts are represented by user identifiers, group memberships, authentication settings, shells, and other attributes. The UID determines the numeric identity associated with file ownership and process credentials. UID 0 has superuser privileges; an unexpected non-root account with UID 0 deserves immediate investigation.

The Python, JavaScript, C++, and Java implementations detect duplicate account records, UID collisions, and unexpected UID 0 identities. The SQL schema enforces host-local uniqueness for usernames and UIDs through `UNIQUE (repository_id, username)` and `UNIQUE (repository_id, uid)`. This prevents duplicate inventory entries at the database layer, while the application implementations can report collisions encountered in imported inventory.

A duplicate UID is not merely a naming issue. Files owned by that UID can be accessible to processes running under either account, subject to normal discretionary access controls. Investigations should inspect account provenance, file ownership, group membership, running processes, and any legitimate UID-sharing requirements.

### Administrative access

Sudo access should be assigned according to operational responsibilities. Administrative permissions granted to a service identity can turn a compromised application or scheduled job into a privileged host compromise. Service accounts should normally have narrowly scoped permissions, non-interactive authentication where feasible, and no unnecessary login shell.

The account checks distinguish `sudo_access`, `service_account`, `interactive`, and `shell` attributes instead of inferring privilege solely from the account name. A service account is not automatically insecure, and a login shell is not automatically a vulnerability, but their combination with broad administrative permissions requires justification.

Password locking also requires careful interpretation. Locking a local password does not necessarily disable public-key authentication, every PAM mechanism, or every possible login path. Account status must be interpreted alongside SSH configuration, PAM, identity services, and the distribution's authentication stack.

### Credential lifecycle

Password aging should be evaluated against an approved credential policy. A configured maximum age and the observed age of a credential can indicate that review or action is needed, but password expiry alone is not a complete security strategy. Strong authentication, protected credential storage, monitoring, revocation procedures, and risk-based rotation remain important.

The Python account model distinguishes missing aging configuration from an expired configured age. The JavaScript model checks whether an interactive, password-capable identity lacks a lifecycle policy. These checks intentionally report policy concerns rather than assuming that every account must follow an identical expiry interval.

## SSH hardening

SSH provides encrypted remote administration and supports several authentication and forwarding mechanisms. Its effective security depends on both the server configuration and the identities authorized to use it.

### Authentication controls

The implementations evaluate the following directives and related policy values:

| Control | Security purpose |
|---|---|
| `PermitRootLogin no` | Prevents direct SSH login as root while allowing an authorized administrator to elevate privileges separately. |
| `PasswordAuthentication no` | Disables SSH password authentication when compatible with the approved access design. |
| `PubkeyAuthentication yes` | Enables public-key authentication. Keys must still be protected, authorized, and revoked when necessary. |
| `MaxAuthTries` | Limits authentication attempts within a connection. |
| `AllowUsers` or `AllowGroups` | Restricts which identities may authenticate, subject to the effective configuration and other access controls. |
| `LoginGraceTime` | Limits the time available to complete authentication. |
| `MaxSessions` | Limits multiplexed sessions within a connection. |
| `AllowTcpForwarding` | Controls SSH TCP tunnelling, which can otherwise create paths around intended network restrictions. |
| `X11Forwarding` | Enables X11 forwarding where required; disabling it reduces unnecessary functionality on servers. |

Setting an allowlist is not always equivalent to authorizing only the named users in every configuration context. SSH options may be combined from global settings, included files, and matching user or address blocks. The effective configuration must be checked using the installed OpenSSH version and its supported configuration-testing mechanisms.

The Python example models an explicit allowlist, while the C++ and Java models make authentication policy a separate domain object. The SQL tables store both the SSH policy and the permitted user identities, preserving the relationship between a policy snapshot and its account allowlist.

### Safe configuration changes

Changing SSH authentication on a remote host can lock out administrators. A controlled change should verify the effective configuration, validate syntax with the distribution's supported SSH configuration checker, confirm that an approved administrator can authenticate through a new session, and preserve a recovery path before ending the existing session.

Disabling password authentication without first confirming working keys or another approved authentication mechanism is an operational failure even if the resulting configuration appears restrictive.

## Firewalling

### Default policy and explicit exceptions

A deny-by-default inbound policy blocks unapproved traffic unless a rule explicitly permits it. Outbound and forwarded traffic require separate policy decisions because a host can initiate connections or route traffic independently of its inbound exposure.

The examples model rules with direction, action, protocol, port, and source. They flag a permissive inbound default and broadly exposed SSH or sensitive services. The C++ implementation additionally detects duplicate rule signatures, while the JavaScript implementation validates a limited subset of IPv4 source address and CIDR syntax.

A production firewall requires more than the presence of a rule in an inventory. Rule order, connection state, interface binding, address family, NAT behavior, container networking, cloud security groups, and the actual active ruleset can change the effective result. The database therefore includes `active_rules_verified` and `effective`-style evidence fields instead of assuming that stored intent proves enforcement.

### SSH and application exposure

Allowing TCP port 22 from every source can expose the SSH service to automated attacks and credential abuse. Restricting access to a trusted administrative network, VPN, or access gateway reduces the number of potential sources. Public application services such as HTTPS may need broader access, but that exception should be intentional.

The sample firewall includes a public HTTPS rule and a broadly exposed SSH rule. These have different operational purposes and should not be treated identically. Similarly, ports such as Telnet (23), SMB (445), and RDP (3389) require particular scrutiny when exposed to untrusted networks.

### Rule validation limitations

The JavaScript source validator supports IPv4 addresses and CIDR notation only. It deliberately does not claim to validate IPv6 or replace a native firewall parser. The C++ example uses explicit source labels to model policy intent. PostgreSQL's `CIDR` type in the SQL model validates IP-network syntax for stored IPv4 and IPv6 networks.

A production assessment should query the active firewall backend and compare the effective rules with approved policy. UFW, firewalld, nftables, iptables, and cloud firewalls have different management interfaces and behavior.

## Patching and maintenance

### Inventory freshness

Patching involves more than counting available packages. A meaningful maintenance record includes the distribution, package manager, repository metadata freshness, pending security fixes, critical fixes, last successful update, and reboot status.

The sample assessments distinguish critical pending updates from other security updates. They also flag stale maintenance records and pending reboots. Severity in these examples is a local policy choice, not a universal classification for every host.

A production workflow should assess package applicability, vulnerability severity, external exposure, service dependencies, compatibility, and available mitigations. Updates should be tested according to operational risk, then installed through an approved maintenance process.

### Automated updates and restarts

Unattended security updates can reduce exposure windows, but automation must match the host's availability and change requirements. Organizations may instead use centrally managed patch orchestration with approval, staged rollout, and monitoring.

A reboot-required state is operationally significant because some kernel, library, and service updates do not fully take effect until affected processes restart or the host reboots. After maintenance, health checks should confirm that applications, networking, authentication, monitoring, and scheduled jobs continue to function.

The Java change model makes the maintenance lifecycle explicit: proposed changes must be approved and scheduled before execution, and an executing change can be verified, failed, or rolled back. A verified change cannot be reopened through an invalid state transition.

## Auditing and evidence

### Audit collection

Security auditing requires reliable event collection and enough context to reconstruct activity. The assessment models inspect:

- Whether the audit daemon is enabled where supported.
- Whether reviewed audit rules persist across reboot.
- Whether authentication logs are available.
- Whether time synchronization is enabled.
- Whether critical file integrity monitoring is active.
- Whether log retention matches operational and compliance requirements.
- Whether central log delivery is part of the collection design.

The Python and Java implementations report missing controls independently. The C++ implementation groups related checks into an audit inventory. The JavaScript implementation emits immutable remediation events so that status changes can be observed by downstream workflow handlers.

### File permissions

The Python permission audit examines sensitive configuration and credential paths, including `/etc/shadow`, `/etc/gshadow`, `/etc/ssh/sshd_config`, and `/etc/sudoers`. A world-writable SSH configuration can permit an unauthorized local user to alter future authentication behavior if the system accepts that file as configuration.

Permission checks must be interpreted alongside ownership, ACLs, parent-directory permissions, symlinks, mount options, and the effective service configuration. A mode string alone cannot establish complete access safety.

The SQL model stores file permission evidence with the path, owner, group, mode, and a generated world-writable indicator. This permits repeatable reporting and investigation of changes over time.

### Time and retention

Reliable timestamps allow investigators to correlate authentication failures, privilege escalation, package installation, firewall changes, and application incidents. Time synchronization should use an approved service and a trustworthy source.

Retention depends on incident-response requirements, legal obligations, storage capacity, and privacy constraints. The example threshold of 30 days is an illustrative policy, not a universal requirement. High-risk environments may need longer retention and protected, centralized storage.

## Python implementation

The Python script is an executable policy simulator built from standard-library data classes, enums, collections, JSON serialization, command-line argument parsing, and unit tests.

`Server` composes separate account, SSH, firewall, patch, and audit records. Each evaluator returns structured `Finding` objects containing a control identifier, severity, evidence, and remediation. The aggregate evaluator sorts findings by severity and stable control identifiers so repeated runs of the same inventory produce a consistent finding order.

`build_example_server()` supplies a production-like inventory with deliberate weaknesses: password authentication, excessive SSH attempts, permissive inbound traffic, pending critical patches, a required reboot, incomplete audit collection, and a writable SSH configuration file.

Run the default assessment with `python linux_hardening.py`. The `--json report.json` option produces machine-readable evidence, and `--strict` returns a nonzero status when critical or high findings remain. The `--test` option executes unit tests for identity validation, SSH findings, firewall defaults, permission checks, patch inventory, and report ordering.

The script never opens or changes the real host's privileged configuration. Its findings depend on the supplied records, and its inventory must not be mistaken for a live system scan.

## JavaScript implementation

The Node.js program models hardening as a set of independent evaluators and adds an event-driven remediation workflow.

`Finding` validates required fields and severity before freezing each record. The evaluators use `Set` and `Map` collections to identify duplicate identities and duplicate firewall rules. The IPv4 validator illustrates explicit validation boundaries rather than claiming full IP-stack coverage.

`RemediationWorkflow` uses `EventEmitter` to publish status events when an operator records an action. Each event includes the finding identifier, actor, action, timestamp, and severity. The workflow also calculates the remaining critical and high findings that have no recorded action.

This distinction matters operationally: accepting a remediation is not the same as implementing it, and neither action proves that the resulting control is effective. A production system should distinguish acknowledgement, approval, implementation, independent verification, and closure.

Run `node linux-hardening.js` for a human-readable report, `node linux-hardening.js --json` for structured output, or `node linux-hardening.js --test` for the built-in assertions.

## C++ case study

The C++ program models an incident-response assessment for a production API host. Its `GovernanceEngine` separates account, SSH, firewall, patch, and audit evaluation into methods that return a common `Finding` structure.

The case study uses `std::map` to track UID ownership, `std::set` to detect duplicate account names and firewall rules, and `std::vector` to collect findings. Sorting by severity and control identifier makes the report suitable for deterministic review.

The firewall evaluator checks default inbound and forwarding policies, validates direction and action labels, and detects exposed SSH and selected sensitive ports. The patch evaluator distinguishes critical updates, stale patch activity, pending reboots, and disabled unattended-update policy.

The audit evaluator uses a table of related boolean controls to avoid repeating the same reporting mechanism for each independent control. The final decision illustrates how critical findings can affect a release decision, while leaving actual deployment approval to an operational process.

The program compiles with C++17 or later. Its policy inventory is illustrative and should be extended with native firewall parsing, distribution-specific configuration inspection, and authenticated evidence collection before being used in production.

## Java enterprise model

The Java program emphasizes explicit domain types and controlled state transitions. Records represent account identities, SSH policies, firewall rules, patch inventories, audit inventories, and servers. Their constructors reject invalid identifiers, negative UIDs, invalid port ranges, and negative patch counts.

Separate policy services evaluate each control family. `AssessmentService` aggregates immutable result lists and orders findings by severity, family, and control identifier. This structure makes the assessment logic testable and provides clear boundaries for future integration with configuration collectors and change-management systems.

`ChangeRequest` represents a maintenance change independently of the findings. Its state machine permits a proposed change to be approved or rejected through failure, an approved change to be scheduled, and an executing change to be verified, failed, or rolled back. Invalid transitions throw `IllegalStateException`.

The distinction between findings and change state is important. A security finding describes evidence and a recommended action; a change request tracks authorization and execution of a specific intervention. Marking a finding as serious should not automatically modify a host or bypass maintenance controls.

Compile and run with `javac LinuxHardening.java` followed by `java LinuxHardening`. The implementation requires Java 17 or later and no third-party dependencies.

## PostgreSQL relational model

The SQL script uses PostgreSQL types and constraints to represent hosts, assessment snapshots, accounts, account groups, SSH policies, SSH allowlists, firewall policies, ordered firewall rules, patch assessments, audit controls, file permission evidence, findings, remediation events, and maintenance changes.

### Integrity enforcement

Primary keys identify individual records, while foreign keys preserve the relationships between a host, its assessments, policies, and findings. Unique constraints prevent duplicate usernames and UIDs on a host. Check constraints restrict account names, policy values, update counts, ports, directions, actions, and remediation states.

The `firewall_rules` table stores transport port ranges, CIDR source and destination networks, rule order, and enabled status. Its constraints distinguish TCP and UDP rules, which require ports, from ICMP or protocol-independent rules, which do not use the same transport-port model.

The `hardening_findings` table stores evidence as JSONB and requires a resolved finding to have a resolution timestamp. The remediation trigger records changes to finding status in `remediation_events`, providing a basic history of status transitions.

### Queries and indexes

The assessment queries combine SSH, firewall, patch, and audit inventories into one host-level view of current risks. Separate queries identify broadly exposed sensitive services, service accounts with interactive shells or administrative access, and permissive file modes.

The open-finding index is partial, so it focuses on unresolved work rather than every historical finding. Time-oriented indexes support retrieval of the latest assessment or patch inventory. A GIN index on the JSONB evidence field supports containment and related evidence searches when such queries are used.

The demonstration uses a transaction for a remediation status update. If an update fails, the transaction can be rolled back rather than leaving a partially applied database workflow.

### Database boundaries

Database constraints enforce consistency of stored records; they do not prove that the host matches those records. For example, `active_rules_verified = false` signals that a firewall inventory has not been independently verified, but even a true value depends on the collection process and its trustworthiness.

Similarly, the schema does not enforce every cross-table policy, such as whether a particular host has an approved SSH allowlist or whether the newest patch assessment is recent enough. These are evaluated by queries or application policy because they depend on relationships and current evidence across several records.

The sample inserts are designed to execute in PostgreSQL. The commented invalid insert illustrates a rule that would be rejected by the database and is intentionally not executed.

## Testing and interpretation

The built-in tests verify selected policy rules, not the security of an actual Linux distribution. Passing tests establishes that the example evaluators behave as expected for those cases; it does not prove that a host is hardened.

A live assessment should gather evidence from authoritative system sources, preserve timestamps and collection errors, identify the relevant distribution and version, and validate effective configuration. It should also distinguish an absent record from an explicitly disabled control.

False positives can occur when a scanner misinterprets inherited configuration, an approved network exception, a service identity, or an environment-specific maintenance schedule. False negatives can occur when a control exists outside the scanned configuration or the inventory is stale.

A reliable operational workflow therefore combines evidence collection, policy evaluation, risk-based prioritization, authorized remediation, post-change verification, and retained audit evidence. Each phase addresses a different failure mode and should remain separately observable.
