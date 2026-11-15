# Active Directory Security Governance

## Technical Scope

This project models security governance for Microsoft Active Directory environments. It examines privileged identities, administrative tier separation, Kerberos delegation, service accounts, domain and forest trusts, and documented relationships that may create security exposure.

The implementations provide five complementary perspectives:

| Implementation | Engineering perspective |
|---|---|
| Python | Directory security inventory, configuration auditing, and defensive relationship analysis |
| JavaScript | Event-driven security policy evaluation and finding management |
| C++17 | Efficient governance evaluation and graph-based security analysis |
| Java 17 | Enterprise domain modeling, policy objects, and governance services |
| PostgreSQL | Relational security inventory, audit execution, integrity enforcement, and reporting |

The implementations use representative directory records. They are security governance simulators, not LDAP clients, domain controllers, Kerberos implementations, or automated remediation agents.

## 1. Active Directory Security Fundamentals

Active Directory is Microsoft's directory service for centrally managing identities, computers, groups, authentication, and authorization in Windows domain environments.

Its security model depends on several interacting components:

| Component | Security responsibility |
|---|---|
| Domain | Administrative and authentication boundary |
| Forest | Shared schema, configuration, and forest-wide trust boundary |
| Domain Controller | Directory operations and domain authentication |
| User Account | Represents an individual identity |
| Computer Account | Represents a domain-joined computer |
| Security Group | Provides membership-based authorization |
| Service Account | Supplies an identity to an application or service |
| Group Managed Service Account | Supports automatically managed service credentials |
| Kerberos | Provides ticket-based authentication |
| Group Policy | Applies centrally managed configuration |
| Access Control List | Defines permissions on directory objects and resources |
| Trust | Establishes an authentication relationship between domains or forests |

Active Directory security requires control over both authentication and authorization.

Authentication establishes which identity is being represented. Authorization determines which operations and resources that identity can access.

A valid authentication event does not establish that the identity should have administrative access.

## 2. Privileged Accounts

Privileged accounts possess permissions beyond ordinary user access.

Examples include:

- Domain Administrators.
- Enterprise Administrators.
- Schema Administrators.
- Domain Controller administrators.
- Server administrators.
- Delegated Active Directory administrators.
- Backup and recovery operators.
- Identity management administrators.

A compromised privileged identity can create extensive security exposure because its permissions may extend across multiple directory objects, systems, and administrative boundaries.

### 2.1 Privileged identity separation

Administrative identities should be separated from ordinary productivity identities.

An administrator should not routinely use the same account for email, web browsing, document processing, and domain administration.

This separation limits the transfer of credential exposure between ordinary computing environments and privileged administrative environments.

### 2.2 Administrative security tiers

The implementations use three administrative tiers.

| Tier | Scope | Representative resources |
|---|---|---|
| Tier 0 | Identity infrastructure | Domain Controllers, directory administration, forest-level identities |
| Tier 1 | Server and application infrastructure | Application servers, database servers, infrastructure services |
| Tier 2 | End-user computing | Workstations, desktop support, ordinary user administration |

The tiers represent security boundaries rather than simple organizational job classifications.

An account should not be permitted to move from a lower-trust environment into a higher-trust administrative environment without an explicitly authorized access path.

A Tier 2 administrator should not routinely authenticate to Tier 0 systems.

### 2.3 Privileged account controls

The implementations evaluate:

- MFA configuration.
- Administrative tier assignment.
- Account enablement.
- Password lifecycle.
- Interactive logon permissions.
- Delegation configuration.
- Privileged account exposure.

MFA reduces the risk associated with stolen passwords. Phishing-resistant authentication is preferable for sensitive administrative access.

Privileged account inventory should distinguish active accounts from disabled accounts. Disabled identities should not automatically be treated as active exposure, although their historical configuration may still require investigation.

## 3. Service Account Security

Service accounts represent applications, background processes, scheduled tasks, database services, and other non-human workloads.

They frequently require access to resources that ordinary user accounts cannot access.

Their security risk depends on credential management, assigned permissions, service dependencies, and authentication configuration.

### 3.1 Traditional service accounts

Traditional service accounts generally use manually managed passwords.

Common operational problems include:

- Passwords that remain unchanged for long periods.
- Credentials stored in application configuration.
- Excessive directory permissions.
- Interactive logon permissions.
- Unnecessary group memberships.
- Shared credentials between applications.
- SPNs associated with poorly governed identities.

An SPN, or Service Principal Name, identifies a service instance for Kerberos authentication.

An SPN is associated with the account under which the service operates.

SPN-bearing service accounts require careful credential management because their authentication configuration creates additional security considerations.

### 3.2 Group Managed Service Accounts

A group Managed Service Account (gMSA) provides automatic password management for supported services.

Its operational benefits include:

- Managed password generation.
- Automatic password rotation.
- Reduced manual credential handling.
- Support for authorized service hosts.
- Reduced dependence on manually maintained passwords.

A gMSA is not automatically secure merely because its password is managed.

Its permissions, authorized retrieval hosts, service configuration, and SPN assignments still require review.

### 3.3 Service account lifecycle

The implemented audit models examine:

| Control | Security purpose |
|---|---|
| Managed password | Reduces manual credential management |
| SPN inventory | Identifies Kerberos service identities |
| Password age | Identifies potentially stale credentials |
| Interactive logon | Restricts unnecessary human logon |
| Service ownership | Establishes accountability |
| Business justification | Documents why the identity exists |
| Privilege assignment | Limits excessive permissions |

The Python and JavaScript implementations classify service identities using account attributes.

The Java implementation applies reusable policy rules.

The SQL implementation separates general directory accounts from service-specific ownership and lifecycle records.

## 4. Kerberos Delegation Security

Kerberos delegation allows a service to act on behalf of an authenticated user when accessing another service.

It supports multi-tier application architectures.

For example:

User → Web Application → Database Service

The web application may need to access the database using the user's identity.

Delegation must be restricted to the intended services and resources.

### 4.1 Unconstrained delegation

Unconstrained delegation allows a service to receive and use delegated authentication information with a broad scope.

This configuration can create significant credential exposure if the delegated service is compromised.

The implementations classify unconstrained delegation as a critical finding under the default policy.

### 4.2 Constrained delegation

Constrained delegation restricts delegation to specified services.

It reduces the scope of delegation compared with unconstrained delegation.

The allowed services and associated SPNs must still be reviewed.

### 4.3 Resource-based constrained delegation

Resource-based constrained delegation allows the resource-owning service or computer to determine which identities may delegate to it.

This changes where the authorization decision is configured.

The target resource's security configuration therefore becomes important.

### 4.4 Protocol transition

Protocol transition allows a service to use a non-Kerberos authentication mechanism for an incoming request and obtain Kerberos credentials for a downstream service under configured conditions.

Its use should be justified and restricted.

The implementations separately track protocol transition through the `trusted_to_authenticate` attribute.

Delegation type and protocol transition are distinct configuration properties. One must not be inferred solely from the other.

### 4.5 Delegation assessment

| Configuration | Governance treatment |
|---|---|
| No delegation | Baseline configuration |
| Unconstrained delegation | Critical review |
| Constrained delegation | Validate allowed services |
| Resource-based constrained delegation | Validate resource permissions |
| Protocol transition | Review necessity and scope |

The sample applications do not request Kerberos tickets or manipulate delegation settings. They evaluate documented configuration attributes.

## 5. Domain and Forest Trust Security

A trust establishes an authentication relationship between directory domains or forests.

Trusts support cross-domain access, organizational collaboration, and distributed enterprise environments.

They also introduce additional identity and authorization boundaries.

### 5.1 Trust classifications

| Trust type | Description |
|---|---|
| External | Connects domains in different forests without forest-wide transitivity |
| Forest | Connects two forests |
| Parent-child | Connects parent and child domains in the same forest |

### 5.2 Trust direction

| Direction | Meaning |
|---|---|
| Inbound | The receiving domain trusts authentication from the specified source domain |
| Outbound | The source domain trusts authentication from the specified target domain |
| Bidirectional | The trust relationship operates in both directions |

Trust direction describes authentication relationships. It does not automatically grant access to every resource.

Resource permissions and authorization controls remain necessary.

### 5.3 SID filtering

Security Identifiers (SIDs) identify security principals and groups.

SID filtering provides protection against inappropriate SID information crossing trust boundaries.

Trust configurations must be evaluated in the context of their trust type, forest configuration, and operational requirements.

Disabling appropriate SID filtering can introduce serious security exposure.

### 5.4 Selective authentication

Selective authentication restricts which users from a trusted domain may authenticate to resources in the trusting domain.

Without suitable restrictions, the authentication boundary may be broader than intended.

The implementations flag trusts without selective authentication under the default policy.

### 5.5 Trust governance

Trust review should include:

- Business justification.
- Source and target domains.
- Trust direction.
- Trust type.
- SID filtering.
- Selective authentication.
- Authentication scope.
- Resource permissions.
- Review ownership.
- Periodic recertification.

A trust relationship should not be interpreted as unrestricted authorization.

## 6. Defensive Attack-Path Analysis

An attack path represents a sequence of relationships that may connect an ordinary identity to a sensitive resource or privileged identity.

The implementations model these relationships as directed graph edges.

For example:

Employee Account
→ Administrative Group
→ Server
→ Service Identity
→ Privileged Resource

This representation helps security teams identify potentially dangerous combinations of permissions and dependencies.

### 6.1 Graph model

The graph consists of:

- Vertices: accounts, groups, servers, and resources.
- Directed edges: documented membership, access, dependency, and delegation relationships.
- Source: an identity or resource under examination.
- Target: a sensitive account or protected resource.

The Python, JavaScript, C++, and Java implementations use breadth-first search to identify shortest documented paths.

The PostgreSQL implementation uses a recursive common table expression.

### 6.2 Relationship classification

| Relationship | Interpretation |
|---|---|
| Group membership | Identity belongs to a security group |
| Administrative access | Identity has documented administrative permissions |
| Service dependency | One service depends on another identity or service |
| Delegation exposure | A delegation-related relationship requires investigation |
| Remote access | An identity has documented remote access |
| Resource access | Identity can access a resource |
| Privileged dependency | A dependency connects to a sensitive identity or resource |

### 6.3 Understanding graph results

A graph path is an investigation lead, not proof of compromise.

A documented relationship does not establish that every intermediate permission is effective, exploitable, or currently valid.

A production assessment should validate:

- Actual group membership.
- Nested group expansion.
- Effective access-control permissions.
- Object ownership.
- Delegation configuration.
- Resource reachability.
- Trust direction and authentication scope.
- Disabled identities.
- Current directory state.

The shortest-path algorithms provide a useful prioritization mechanism.

They do not calculate every possible privilege escalation condition.

## 7. Python Implementation

The Python script uses a domain-oriented object model.

### Main components

| Component | Responsibility |
|---|---|
| `ADAccount` | Stores account configuration |
| `Trust` | Models domain trust settings |
| `Relationship` | Represents documented security relationships |
| `SecurityFinding` | Stores audit results |
| `ActiveDirectory` | Coordinates inventory, audits, and reports |

### Important mechanisms

**Dataclasses**

Dataclasses provide structured representations of directory objects and security findings.

**Enums**

Enumerations restrict account types, tiers, delegation configurations, and finding states to known values.

**Dictionaries**

Account inventory uses dictionary-based indexing for efficient account lookup.

**Sets and graph relationships**

Relationship analysis avoids repeated nodes within a path and prevents cycles from producing infinite traversal.

**Breadth-first search**

The attack-path analyzer identifies shortest documented paths.

**Finding lifecycle**

Findings support open, mitigated, and accepted states.

**JSON reporting**

The script exports a structured audit report using the Python standard library.

### Execution

Requirements:

- Python 3.10 or later.
- No external packages.

Run the file using `python active_directory_security.py`.

The script creates `ad_security_report.json` in the working directory.

## 8. JavaScript Implementation

The JavaScript implementation emphasizes event-driven governance and policy evaluation.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityPolicy` | Evaluates directory security rules |
| `DirectorySecurityEngine` | Manages directory inventory |
| `EventEmitter` | Publishes account, finding, and audit events |
| `Map` | Stores accounts, trusts, and findings |
| `Set` | Supports relationship uniqueness |
| `shortestPaths()` | Evaluates documented security paths |

### Event-driven architecture

The engine emits events when:

- Accounts are registered.
- Findings are created.
- Findings are updated.
- Audits are completed.

This separates security evaluation from reporting and event handling.

For example, a reporting component can listen for finding creation events without modifying the policy evaluation logic.

### Asynchronous operations

The report export operation uses asynchronous filesystem APIs.

Errors propagate to the main execution handler.

### Execution

Requirements:

- Node.js 18 or later.
- No npm dependencies.

Run using `node active_directory_security.js`.

The script creates `ad_security_report.json`.

## 9. C++17 Implementation

The C++ implementation emphasizes explicit domain modeling, validation, STL containers, and graph traversal.

### Main components

| Component | Responsibility |
|---|---|
| `Account` | Directory identity |
| `Trust` | Cross-domain trust configuration |
| `Relationship` | Directed security relationship |
| `Finding` | Audit result |
| `SecurityPolicy` | Governance configuration |
| `DirectoryGovernance` | Audit and reporting engine |

### Engineering decisions

`unordered_map` supports efficient account and trust lookup.

`vector` stores relationships and audit findings.

`queue` implements breadth-first search.

`unordered_map` maintains graph traversal depth.

`enum class` prevents accidental mixing of unrelated domain values.

Exceptions represent invalid inventory records, duplicate identifiers, and report-writing failures.

The program uses standard C++17 functionality without third-party dependencies.

### Execution

Compile using a C++17-compatible compiler.

The output executable produces console findings and a JSON report named `ad_security_report.json`.

## 10. Java 17 Implementation

The Java implementation models an enterprise governance architecture using immutable domain records and separate policy services.

### Main components

| Component | Responsibility |
|---|---|
| `Account` | Immutable directory account |
| `Trust` | Immutable trust definition |
| `Relationship` | Documented relationship |
| `SecurityFinding` | Immutable audit result |
| `GovernancePolicy` | Central policy configuration |
| `AccountPolicy` | Account-level evaluation |
| `TrustPolicy` | Trust-level evaluation |
| `DirectoryRepository` | Directory inventory |
| `FindingRegistry` | Finding lifecycle |
| `GovernanceService` | Enterprise audit orchestration |
| `AttackPathAnalyzer` | Graph traversal |

### Policy objects

The `SecurityRule` interface defines a common evaluation contract.

`AccountPolicy` and `TrustPolicy` implement different evaluation rules.

This separation avoids combining unrelated security responsibilities into one large conditional structure.

### Immutable records

Java records represent domain objects with validated construction.

The finding registry replaces immutable finding instances when their status changes.

### Streams and collections

Streams support finding filtering and aggregation.

Collections maintain directory inventory and relationship graphs.

The `EnumMap` implementation provides typed severity aggregation.

### Execution

Requirements:

- Java 17.
- No third-party dependencies.

Compile using the Java compiler and execute the `ActiveDirectorySecurity` class.

The program exports `ad_security_report.json`.

## 11. PostgreSQL Implementation

The SQL implementation models the security governance workflow using normalized relational structures.

### Database schema

The `ad_security` schema contains the complete security inventory and audit model.

| Table | Purpose |
|---|---|
| `domains` | Domain and forest inventory |
| `directory_accounts` | User, administrator, and service identities |
| `security_groups` | Security group inventory |
| `group_memberships` | Account-to-group membership |
| `service_accounts` | Service ownership and credential lifecycle |
| `domain_trusts` | Trust configuration |
| `security_relationships` | Documented security graph |
| `governance_policies` | Security policy configuration |
| `audit_runs` | Audit execution history |
| `security_findings` | Identified configuration issues |
| `remediation_history` | Remediation evidence |

### Relational integrity

Primary keys provide record identity.

Foreign keys enforce relationships between directory entities.

Unique constraints prevent duplicate domain accounts, groups, memberships, and trust definitions.

Check constraints validate account attributes and configuration values.

Partial indexes accelerate queries against active privileged accounts and open findings.

### Functions and procedures

The database includes:

- `update_modified_timestamp()`
- `create_security_finding()`
- `audit_directory_accounts()`
- `audit_domain_trusts()`
- `execute_security_audit()`
- `find_security_paths()`

The audit procedure coordinates account and trust evaluation.

The recursive SQL function identifies validated relationship paths between two accounts.

### Triggers

The account trigger automatically updates modification timestamps.

The finding transition trigger enforces remediation-state requirements.

An accepted finding requires an accountable identity.

A mitigated finding receives a resolution timestamp.

### Views

The reporting layer provides:

- `privileged_account_inventory`
- `service_account_risk_inventory`
- `open_security_findings`
- `security_risk_summary`

### Transactions

The sample workflow creates audit records and findings within a transaction.

The remediation example records an action and updates the finding status atomically.

This ensures that remediation history and finding state remain consistent when both operations succeed.

### Execution

Requirements:

- PostgreSQL 15 or later.
- Permission to create schemas, types, tables, functions, procedures, and triggers.

Execute the SQL file using `psql` against a test database.

The script creates the schema, inserts representative records, executes an audit, and runs reporting queries.

The SQL script is designed for a fresh database or an environment where the `ad_security` schema does not already contain objects with conflicting names.

## 12. Security Governance Workflow

The implementations follow a common security assessment sequence.

    Directory Inventory
           |
           v
    Identity Classification
           |
           v
    Privilege and Tier Assessment
           |
           v
    Service Account Assessment
           |
           v
    Kerberos Delegation Assessment
           |
           v
    Trust Configuration Assessment
           |
           v
    Relationship Graph Analysis
           |
           v
    Security Policy Evaluation
           |
           v
    Findings and Risk Prioritization
           |
           v
    Remediation and Evidence
           |
           v
    Periodic Reassessment

Each stage contributes a different type of evidence.

Identity classification identifies the principal.

Privilege assessment determines the administrative scope.

Service account assessment examines non-human credentials.

Delegation assessment identifies authentication forwarding exposure.

Trust assessment examines cross-domain authentication boundaries.

Graph analysis identifies connected relationships requiring investigation.

Policy evaluation converts configuration observations into actionable findings.

Remediation records the actions taken and supports subsequent verification.

## 13. Important Security Distinctions

The following concepts must remain separate during an Active Directory security assessment.

| Concepts | Distinction |
|---|---|
| Authentication and authorization | Establishing identity is different from granting resource access |
| User and service accounts | Human identities and workload identities have different lifecycle requirements |
| Privileged and ordinary accounts | Administrative permissions create a different risk category |
| Tier 0 and Tier 1 | Identity infrastructure and server infrastructure require separate administrative boundaries |
| Unconstrained and constrained delegation | Delegation configurations differ in the scope of permitted forwarding |
| Constrained and resource-based delegation | The location of delegation authorization differs |
| Trust and resource permission | A trust does not automatically authorize access to every resource |
| SID filtering and selective authentication | These controls address different aspects of trust security |
| Finding and vulnerability | A configuration finding requires validation before its practical impact is established |
| Attack path and confirmed compromise | A relationship graph does not establish that an attack occurred |

## 14. Validation and Failure Handling

The five implementations include validation for common inventory and processing failures.

| Failure condition | Expected handling |
|---|---|
| Duplicate account | Reject the record |
| Invalid account identifier | Reject the record |
| Negative password age | Reject the record |
| Negative SPN count | Reject the record |
| Missing trust endpoint | Reject the trust |
| Self-referencing relationship | Reject the relationship |
| Invalid security tier | Reject the record |
| Unknown finding identifier | Reject the state update |
| Invalid report filename | Reject the export |
| Missing SQL domain | Abort the audit |
| Inactive SQL policy | Reject audit execution |
| Missing attack-path endpoint | Reject graph analysis |

The sample implementations intentionally use representative attributes.

A production implementation must distinguish unavailable inventory data from a verified secure configuration.

Missing information should not automatically be interpreted as evidence that a control is compliant.

## 15. Performance Considerations

| Component | Main operation | Complexity |
|---|---|---|
| Python account lookup | Dictionary lookup | Average O(1) |
| JavaScript account lookup | Map lookup | Average O(1) |
| C++ account lookup | Unordered map lookup | Average O(1) |
| Java account lookup | Hash-based lookup | Average O(1) |
| Graph construction | Relationship indexing | O(V + E) |
| Breadth-first traversal | Shortest unweighted path | O(V + E) per traversal |
| Finding aggregation | Finding scan | O(F) |
| SQL indexed account lookup | B-tree or partial index | Approximately O(log N) |

Where:

- V represents vertices.
- E represents relationships.
- F represents findings.
- N represents database records.

The graph implementations use shortest-path traversal rather than enumerating every possible path.

The SQL recursive query uses validated directed relationships and limits traversal depth.

For large enterprise directories, graph traversal should use indexed adjacency structures, bounded queries, and carefully selected starting identities.

## 16. Security and Production Limitations

These implementations demonstrate governance logic rather than complete enterprise directory integration.

A production deployment would require additional controls.

### Directory collection

A live integration should use authorized directory interfaces and read-only collection wherever possible.

Relevant inventory sources include:

- LDAP directory attributes.
- Active Directory PowerShell modules.
- Security group membership.
- Group Policy configuration.
- Domain and forest trust configuration.
- Kerberos delegation attributes.
- Windows security event logs.

Collection permissions should follow least privilege.

### Credential security

The sample implementations do not store passwords, hashes, Kerberos tickets, private keys, or other authentication secrets.

Production systems should avoid placing credentials in reports, application logs, source repositories, and database inventory tables.

### Evidence quality

Every important finding should have:

- A source record.
- An observation timestamp.
- An affected identity or trust.
- A policy identifier.
- A severity classification.
- Supporting evidence.
- An assigned owner.
- A remediation decision.
- Verification evidence.

### Risk prioritization

Severity should not be confused with a complete risk calculation.

A production assessment should consider privilege level, exposure, business impact, asset criticality, exploitability, compensating controls, and confidence in the underlying evidence.

### Automated remediation

The included examples record remediation status but do not modify a live Active Directory environment.

Changes to privileged accounts, trust settings, group memberships, or delegation configuration require authorization, change control, testing, and post-change verification.

## 17. Expected Outputs

The five implementations produce complementary results.

| Implementation | Primary output |
|---|---|
| Python | Configuration findings, shortest documented paths, JSON report |
| JavaScript | Policy events, finding distribution, relationship paths, JSON report |
| C++17 | Governance findings, severity statistics, graph paths, JSON report |
| Java 17 | Enterprise policy evaluation, immutable findings, graph analysis, JSON report |
| PostgreSQL | Persistent inventory, audit history, remediation records, SQL reports |

The shared domain model allows the five implementations to examine the same major Active Directory security categories while retaining different programming and architectural approaches.
