# IAM Security Review

## 1. Domain Scope

Identity and Access Management (IAM) controls which human users, service accounts, applications, and external entities can access organizational resources.

An IAM security review evaluates whether identities are legitimate, whether their permissions are appropriate, whether privileged access is adequately controlled, and whether access decisions are supported by accountable review processes.

This implementation examines three connected security areas:

- **Identity attack surface:** The identities, credentials, roles, permissions, and authentication mechanisms that can potentially be abused.
- **Privilege escalation exposure:** Excessive or sensitive permissions that could allow an identity to obtain greater control over organizational resources.
- **Access reviews:** Periodic certification of existing access by accountable reviewers, followed by approval, reduction, revocation, or escalation.

The five implementations provide complementary perspectives:

| Implementation | Primary responsibility |
|---|---|
| Python | IAM inventory, risk detection, and access review simulation |
| JavaScript | Event-driven IAM assessment and policy evaluation |
| C++17 | Repository-independent governance and risk evaluation engine |
| Java 17 | Enterprise IAM domain model and controlled state transitions |
| PostgreSQL | Persistent IAM records, integrity enforcement, reporting, and review workflows |

## 2. IAM Architecture

The implementations use Role-Based Access Control (RBAC) as their principal access model.

The architecture separates identities, roles, permissions, and governance decisions.

### 2.1 Identity

An identity represents an entity that can authenticate or interact with organizational resources.

| Identity category | Description | Security considerations |
|---|---|---|
| Human | Employee or administrator | Authentication, MFA, employment status, and ownership |
| Service | Non-human workload identity | Secret rotation, workload authentication, and expiration |
| Application | Software application identity | Application permissions, credentials, and API access |
| External | Contractor or partner identity | Contract duration, restricted access, and periodic certification |

An identity has an independent lifecycle:

`Created → Active → Suspended → Disabled`

A suspended or disabled identity must not receive effective permissions through the assessment engine.

Disabling an identity is different from deleting its historical records. Retaining historical records supports investigation, compliance, and auditability.

### 2.2 Authentication and Authorization

Authentication establishes the identity of an entity.

Authorization determines which operations that authenticated entity may perform.

These controls address different questions:

| Control | Question |
|---|---|
| Authentication | Who is requesting access? |
| MFA | Has the identity satisfied an additional authentication factor? |
| Authorization | Is the requested operation permitted? |
| Access certification | Is the existing access still justified? |
| Privileged access governance | Are sensitive capabilities appropriately controlled? |

Multi-factor authentication does not automatically make an authorization assignment appropriate. A properly authenticated identity can still possess excessive permissions.

### 2.3 Role-Based Access Control

RBAC assigns permissions to roles and assigns roles to identities.

The relationship is:

`Identity → Assigned Role → Permission → Resource`

For example:

- Employee: read business documents.
- Developer: read and modify source code.
- Security Administrator: administer IAM policies and credentials.
- Finance Approver: approve financial transactions.

An identity can receive permissions through multiple roles.

The effective permission set is:

`Effective Permissions = Direct Permissions ∪ Inherited Role Permissions`

Role inheritance allows one role to obtain permissions from another role.

For example:

`Developer → Employee`

The Developer role receives its own permissions and the permissions assigned to Employee.

The implementations use visited sets during recursive traversal to avoid processing the same role repeatedly. They also validate the inheritance graph to detect circular dependencies.

The PostgreSQL implementation uses a recursive CTE and `UNION` to calculate inherited roles.

## 3. Identity Attack Surface

The identity attack surface consists of the identities and access mechanisms that could become entry points for unauthorized activity.

It includes:

- Human accounts.
- Privileged administrator accounts.
- Service accounts.
- Application identities.
- External identities.
- Authentication credentials.
- API credentials and secrets.
- Direct permission assignments.
- Role inheritance.
- Dormant accounts.
- Accounts without MFA.
- Unowned or inadequately governed identities.

### 3.1 Excessive Privileges

Excessive privileges occur when an identity receives permissions beyond its legitimate business requirements.

Example:

A software developer may require source-code modification access but does not necessarily require permission to manage organization-wide IAM policies.

The assessment identifies identities with unusually large effective permission sets and flags sensitive permissions.

The implementations use a configurable threshold of eight permissions for the demonstration.

This is a detection heuristic, not a universal security standard. Production thresholds should consider the resource type, business function, permission sensitivity, and organizational role design.

### 3.2 Dormant Accounts

Dormant identities are accounts that have not recorded activity within a defined period.

They may remain active after:

- Employee departure.
- Contractor engagement completion.
- Application retirement.
- Service migration.
- Ownership changes.
- Business-process changes.

A dormant privileged account creates additional exposure because its credentials or associated secrets may remain usable without ongoing operational supervision.

The implementations use a 90-day inactivity threshold.

A missing login timestamp is treated as an inactivity condition rather than proof that an identity is harmless.

Service accounts require special treatment because some legitimate workloads authenticate without conventional interactive logins. Their activity should also be evaluated through workload telemetry, token usage, credential rotation, and ownership records.

### 3.3 Missing MFA

Multi-factor authentication reduces the risk of account compromise caused by stolen or reused credentials.

Privileged identities require particular attention because successful compromise may provide access to:

- User administration.
- Security policies.
- Credential stores.
- Production infrastructure.
- Sensitive organizational data.

The implementations assign higher risk to privileged identities without MFA.

For production environments, phishing-resistant authentication should be preferred for administrative access.

### 3.4 Unowned Identities

Every organizational identity should have an accountable owner.

The owner is responsible for confirming:

- The business purpose.
- The identity's operational necessity.
- Its permitted access.
- Its lifecycle.
- Its review requirements.

An identity without an accountable owner cannot be reliably certified.

Ownership must be distinguished from the identity itself. An application account, for example, can be owned by a designated engineering team rather than an individual employee.

## 4. Privilege Escalation

Privilege escalation occurs when an unauthorized actor obtains access beyond the privileges originally assigned or authorized.

It is important to distinguish between an existing privilege exposure and an actual successful escalation.

An IAM inventory can identify dangerous entitlements, but it cannot establish that an attacker has exploited them.

### 4.1 Vertical Privilege Escalation

Vertical privilege escalation involves moving from a lower level of authority to a higher level.

Illustrative progression:

`Standard User → Application Administrator → Security Administrator`

The exposure may originate from:

- Administrative permissions granted unnecessarily.
- Excessive role inheritance.
- Misconfigured delegation.
- Overly broad service-account permissions.
- Inadequate privilege separation.
- Weak administrative authentication.

### 4.2 Horizontal Privilege Escalation

Horizontal privilege escalation involves obtaining access to another identity's resources without obtaining a higher organizational privilege level.

For example, one ordinary employee accessing another employee's restricted records represents a horizontal authorization failure.

The security assessment must therefore examine both privilege levels and resource ownership boundaries.

### 4.3 Sensitive Permissions

The implementations identify permissions associated with high-impact administrative operations.

| Permission | Security significance |
|---|---|
| `manage_roles` | Changes role assignments and access structures |
| `manage_policies` | Changes authorization rules |
| `manage_credentials` | Controls protected credentials |
| `configure_security` | Changes security configuration |
| `admin` | Indicates broad administrative capability |
| `delete` | Can destroy protected organizational resources |

A permission's risk depends on its scope and context. A narrowly scoped delete operation is not necessarily equivalent to an organization-wide administrative delete operation.

The implementations use action and resource classification to identify potentially dangerous access.

### 4.4 Role Inheritance Exposure

Inherited permissions can make an identity more privileged than its directly assigned role names suggest.

Consider:

`Developer → Employee`

If Employee later receives sensitive permissions, every Developer identity inheriting that role also receives those permissions.

Therefore, role reviews must consider effective permissions, not only directly assigned roles.

A role graph must also be acyclic. Circular inheritance makes authorization evaluation unreliable and can create implementation-specific errors.

### 4.5 Privilege Escalation Assessment

The assessment engine follows this sequence:

1. Retrieve active identities.
2. Retrieve directly assigned roles.
3. Resolve inherited roles.
4. Calculate effective permissions.
5. Identify sensitive actions.
6. Identify privileged roles.
7. Evaluate MFA and inactivity.
8. Check separation-of-duties conflicts.
9. Assign risk classifications.
10. Produce findings and remediation actions.

The resulting findings represent exposure indicators requiring investigation.

They do not establish that an identity has been compromised.

## 5. Access Reviews and Certification

An access review is a formal examination of existing identity permissions.

Its purpose is to determine whether access remains necessary, authorized, and consistent with organizational policy.

Access certification is particularly important when organizational responsibilities change over time.

### 5.1 Review Participants

| Participant | Responsibility |
|---|---|
| Identity owner | Maintains the identity and its business purpose |
| Manager | Confirms employment or operational necessity |
| Application owner | Confirms application-level access requirements |
| Security reviewer | Examines privileged access and security exposure |
| Compliance reviewer | Checks governance and control requirements |
| System administrator | Implements authorized access changes |

The person responsible for approving access should not automatically be the person responsible for implementing every change.

Independent review is especially important for sensitive administrative permissions.

### 5.2 Review Decisions

The implementations support five review states:

| Decision | Meaning | Expected effect |
|---|---|---|
| Approve | Existing access remains justified | Retain access |
| Revoke | Access is no longer justified | Disable or remove access |
| Reduce | Some access is unnecessary | Remove specified assignments |
| Escalate | Additional investigation is required | Refer for independent assessment |
| Pending | No final decision has been recorded | Keep the review open |

Approval is a review decision, not a permission grant.

A reviewer approving an existing role assignment does not automatically create new privileges.

Likewise, a pending review is not equivalent to approval.

### 5.3 Review Evidence

A defensible access review should retain:

- Identity identifier.
- Reviewer identifier.
- Review timestamp.
- Assigned roles.
- Effective permissions.
- Decision.
- Justification.
- Remediation details.
- Completion status.

A decision without meaningful justification provides weak audit evidence.

The implementations validate reviewer identity and review justification before processing a decision.

### 5.4 Reduction of Access

Access can originate from two different sources:

1. Direct permission assignment.
2. Role-based permission assignment.

These sources require different remediation procedures.

Removing a direct permission affects one identity.

Removing a permission from a shared role may affect every identity assigned that role.

Consequently, a role-level reduction requires separate governance and impact assessment.

The implementations preserve this distinction rather than silently modifying shared role definitions.

### 5.5 Revocation

Revocation is required when an identity no longer has a legitimate access requirement.

Typical reasons include:

- Employment termination.
- Contract expiration.
- Application retirement.
- Compromised identity.
- Unauthorized access.
- Failed ownership certification.

The demonstration engines disable the identity and clear its assignments.

Production implementations should also invalidate active sessions, refresh tokens, API credentials, workload credentials, and associated secrets where applicable.

## 6. Separation of Duties

Separation of Duties (SoD) prevents a single identity from exercising conflicting capabilities within a sensitive business process.

It reduces the possibility of unauthorized activity occurring without independent oversight.

Consider a financial process:

`Payment Creation → Independent Payment Approval`

The person creating a payment should not also be able to approve the same transaction where policy requires independent authorization.

Another example is:

`Security Administration ≠ Independent Security Audit`

The administrator who configures security controls should not independently certify the effectiveness of those controls without appropriate safeguards.

The implementations demonstrate two conflicting role pairs:

| Role A | Role B | Conflict |
|---|---|---|
| Finance Approver | Payment Creator | Transaction initiation and approval |
| Security Administrator | Audit Reviewer | Security configuration and independent audit |

SoD conflicts can be:

- Static: An identity possesses two conflicting roles.
- Dynamic: An identity performs conflicting operations within one transaction.
- Contextual: An otherwise valid assignment becomes inappropriate for a particular resource or business process.

The sample implementations primarily demonstrate static SoD.

A production system should also implement transaction-level controls and exception handling for authorized emergency access.

## 7. Risk Assessment and Prioritization

The assessment engines assign risk scores to detected conditions.

The scores support prioritization and should not be interpreted as statistically calibrated probabilities of compromise.

Illustrative risk classification:

| Risk score | Classification | Suggested response |
|---|---|---|
| 0–24 | Low | Monitor |
| 25–49 | Medium | Review |
| 50–74 | High | Prioritize remediation |
| 75–100 | Critical | Immediate investigation and control action |

The implementations use category-specific scores rather than treating every finding equally.

Examples include:

- Privileged account without MFA: critical.
- Sensitive administrative permission: critical.
- Dormant privileged service identity: critical.
- Excessive ordinary permissions: medium.
- Dormant ordinary account: high.

Risk prioritization should consider:

- Permission sensitivity.
- Identity type.
- Privilege level.
- Authentication strength.
- Account activity.
- Ownership.
- Exposure of the associated resource.
- Existing compensating controls.

Duplicate findings should be correlated during production reporting so that one underlying access problem is not incorrectly treated as several independent security incidents.

## 8. Python Implementation

The Python implementation provides an executable IAM simulation using standard-library features.

### 8.1 Domain Model

The implementation defines:

- `Permission`
- `Role`
- `Identity`
- `AccessReview`
- `Finding`
- `IAMEngine`

Dataclasses provide structured records, while enums constrain identity types, identity states, review decisions, and finding severity.

Sets represent role assignments and permissions. Dictionaries provide efficient identity and role lookup.

### 8.2 Effective Permission Calculation

`effective_permissions()` recursively traverses assigned roles and inherited roles.

A visited set prevents repeated processing of the same role.

The resulting permission set combines direct and role-based permissions.

Disabled and suspended identities return an empty effective permission set.

### 8.3 Detection Mechanisms

The engine includes:

- Sensitive permission detection.
- Excessive permission detection.
- Dormant account detection.
- Missing MFA detection.
- Separation-of-duties detection.

Each finding includes an identifier, identity, category, severity, evidence, recommendation, and numerical risk score.

### 8.4 Access Review Processing

`record_review()` supports approval, reduction, escalation, and revocation.

Reduction requires explicit permission identifiers.

The implementation removes direct permissions and affected role assignments from the reviewed identity without changing shared role definitions.

Revocation disables the identity and clears its access assignments.

### 8.5 Reporting

The engine exports a JSON report containing:

- Assessment timestamp.
- Identity count.
- Role count.
- Finding count.
- Individual findings.
- Review count.

The report is generated through standard-library JSON and file-handling capabilities.

### 8.6 Validation and Limitations

The implementation validates duplicate identities, unknown roles, role cycles, timezone-aware timestamps, and incomplete review decisions.

It is an in-memory simulation. It does not provide distributed identity synchronization, persistent database transactions, production authentication, or atomic multi-system revocation.

## 9. JavaScript Implementation

The JavaScript implementation emphasizes event-driven processing and separation between IAM state and assessment behavior.

### 9.1 Event-Driven Architecture

`IAMRepository` extends Node.js `EventEmitter`.

It emits events when:

- An identity is created.
- A role is created.
- An assessment completes.
- An access review is processed.
- A review is escalated.

The audit event contains a unique identifier, actor, subject, timestamp, event type, and structured details.

This design separates state changes from event consumers.

A production implementation could publish corresponding events to an external audit or security monitoring platform.

### 9.2 Map-Based Storage

The repository uses `Map` for identity and role lookup.

`Set` represents role membership and permission-related collections.

These structures support efficient membership checks and avoid repeatedly scanning entire identity collections.

### 9.3 Asynchronous Assessment

`assessAll()` uses `Promise.all()` to evaluate identities asynchronously.

The example remains self-contained and performs in-memory operations.

For large production environments, unrestricted parallel evaluation should be replaced with bounded concurrency, pagination, and workload isolation.

### 9.4 Policy Evaluation

The implementation maintains explicit policies for:

- Privileged MFA.
- Account inactivity.
- Review justification.
- Separation of duties.

Policy evaluation is separated from the access-review decision.

An identity can pass an authentication control while still failing an authorization or certification requirement.

### 9.5 Audit Reporting

The implementation produces a JSON report and records audit events.

It uses UUIDs for event identifiers and Node.js file permissions for the demonstration output.

Production audit storage should use centralized, access-controlled, tamper-evident retention.

## 10. C++17 Implementation

The C++17 implementation provides a strongly structured governance engine using STL containers and domain-specific types.

### 10.1 Data Structures

| Structure | Responsibility |
|---|---|
| `map` | Identity and role lookup |
| `set` | Unique permissions and role membership |
| `vector` | Findings and review history |
| `struct` | Identity, role, permission, and finding records |
| `enum class` | Restricted state and decision values |

The ordered containers provide predictable lookup and traversal behavior.

### 10.2 Governance Engine

`GovernanceEngine` contains the principal IAM operations:

- Role registration.
- Identity registration.
- Role graph validation.
- Effective permission resolution.
- Privileged identity detection.
- SoD conflict evaluation.
- Finding generation.
- Access review processing.

The engine separates the permission catalog from the identity's assigned permissions.

### 10.3 Failure Handling

The program uses standard exceptions to reject:

- Duplicate identities.
- Duplicate roles.
- Unknown roles.
- Invalid permissions.
- Circular inheritance.
- Invalid review evidence.
- Attempts to remove unassigned permissions.

An invalid review is rejected before its access changes are applied.

### 10.4 Performance Considerations

For a role graph containing V roles and E inheritance relationships, graph traversal is O(V + E).

Permission collection depends on the number of distinct reachable roles and permissions.

The ordered STL containers provide O(log n) lookup, insertion, and deletion.

For very large IAM inventories, indexed database storage and caching of effective permissions may be preferable, provided that role changes correctly invalidate affected cache entries.

## 11. Java 17 Implementation

The Java implementation uses an enterprise-oriented domain model with explicit records, policy objects, immutable collections, and controlled state transitions.

### 11.1 Domain Types

The implementation uses:

- `Permission` record.
- `Role` record.
- `AuditEvent` record.
- `ReviewRequest` record.
- `ReviewRecord` record.
- `Finding` record.
- `ApprovalPolicy` record.
- `ProtectionPolicy` record.

Records provide concise immutable value objects.

The mutable `Identity` class is deliberately separate because its status and access assignments change through authorized review operations.

### 11.2 Policy Objects

`ReviewPolicy` separates reviewer eligibility from the identity inventory.

The approval policy describes requirements such as:

- Minimum review count.
- Minimum approval count.
- Independent reviewers.
- Self-review restrictions.
- Privileged MFA requirements.

The protection policy describes organizational security restrictions.

These policy objects provide a structured basis for extending the engine with department-specific and application-specific governance rules.

### 11.3 State Transitions

`IAMRepository.recordReview()` validates the review before performing the requested state transition.

The decision determines the resulting action:

- Approve: Retain existing access.
- Revoke: Disable the identity.
- Reduce: Remove explicitly identified direct permissions.
- Escalate: Record an investigation event.

The implementation does not treat approval as an authorization grant.

### 11.4 Enterprise Auditability

Each audit event contains:

- UUID.
- Timestamp.
- Actor.
- Event type.
- Subject.
- Details.

The event model supports traceability between the review decision and the corresponding identity state change.

### 11.5 Limitations

The Java implementation uses an in-memory repository.

Its review policies demonstrate enterprise governance concepts but do not implement a complete multi-reviewer approval workflow or persistent approval ledger.

Production deployment requires database transactions, authenticated reviewer identities, authorization enforcement, concurrency control, and integration with the organization's identity provider.

## 12. PostgreSQL Database Architecture

The PostgreSQL implementation provides a relational model for persistent IAM governance.

The schema separates identity information from access assignments and governance decisions.

### 12.1 Entity Relationships

The principal relationships are:

| Entity | Relationship |
|---|---|
| `identities` | Stores identity inventory |
| `roles` | Defines reusable access roles |
| `permissions` | Defines resource-action capabilities |
| `role_permissions` | Connects roles to permissions |
| `role_inheritance` | Connects child roles to parent roles |
| `identity_roles` | Assigns roles to identities |
| `direct_permissions` | Stores identity-specific grants |
| `role_conflicts` | Defines conflicting role combinations |
| `access_review_campaigns` | Defines certification campaigns |
| `access_reviews` | Stores reviewer decisions |
| `review_scope` | Records reviewed access objects |
| `security_findings` | Stores detected risk conditions |
| `audit_events` | Stores historical governance events |

### 12.2 Effective Permissions

The `get_effective_permissions()` function uses a recursive CTE to resolve assigned and inherited roles.

It combines:

- Active role assignments.
- Inherited role assignments.
- Direct permissions.
- Role-derived permissions.

Assignments with expired validity periods are excluded.

The `UNION` operation in recursive role traversal removes duplicate role identifiers and prevents repeated traversal of the same role through multiple inheritance paths.

### 12.3 Privilege Exposure Detection

`detect_privilege_exposure()` identifies identities with sensitive effective permissions or privileged role assignments.

The returned records contain:

- Identity identifier.
- External identity reference.
- Number of sensitive permissions.
- Number of privileged roles.
- Calculated risk score.

The function provides an inventory-level detection mechanism rather than attempting to simulate an actual compromise.

### 12.4 Separation of Duties

`role_conflicts` stores prohibited combinations.

`find_separation_of_duties_violations()` identifies active identities with conflicting assignments.

The table-driven design allows additional conflict rules to be added without changing the underlying query logic.

The demonstration checks static role combinations. Transaction-specific controls require a separate business-process model.

### 12.5 Access Review Campaigns

An access review campaign defines the scope and due date of a certification exercise.

Each identity receives a corresponding review record.

The review state distinguishes pending decisions from completed decisions.

The `process_access_review()` procedure:

1. Locks the relevant review and identity records.
2. Confirms that the campaign remains open.
3. Validates reviewer and justification.
4. Records the decision.
5. Applies the corresponding revocation or reduction.
6. Writes an audit event.

The procedure is designed to run within a PostgreSQL transaction.

### 12.6 Database Integrity

The schema uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Recursive queries.
- Triggers.
- Stored functions.
- Stored procedures.
- Partial indexes.

The inheritance trigger rejects circular role dependencies.

The audit trigger rejects updates and deletions, making audit records append-only through ordinary database operations.

A production deployment must also restrict database ownership, prevent unauthorized trigger alteration, and enforce appropriate privileges on audit tables.

### 12.7 Performance

Indexes support common operational queries:

- Active identity retrieval.
- Owner-based access reviews.
- Role-to-identity lookup.
- Pending review identification.
- Risk-prioritized finding retrieval.
- Time-ordered audit investigation.

The partial indexes on active identities and open findings reduce index size for frequently used filtered queries.

For larger installations, partitioning audit events by time and maintaining indexed materialized reporting structures may improve operational performance.

## 13. Branches of IAM Governance

IAM security controls can be understood through the following functional separation:

| Governance area | Primary question |
|---|---|
| Identity lifecycle | Does this identity still need to exist? |
| Authentication | Can the entity prove its identity? |
| Authorization | What can the identity access? |
| Privilege management | Does it possess excessive authority? |
| Access certification | Is the assigned access still justified? |
| Separation of duties | Are conflicting responsibilities assigned together? |
| Auditability | Can access decisions and changes be reconstructed? |

These areas interact but are not interchangeable.

For example, disabling an identity addresses its lifecycle state. Removing an unnecessary role addresses authorization. Requiring MFA addresses authentication. Certifying access addresses governance.

A complete IAM program needs all these controls to operate together.

## 14. Security Controls and Operational Considerations

### 14.1 Least Privilege

Grant only the permissions necessary for an approved business function.

Prefer narrowly scoped roles over broad administrative assignments.

### 14.2 Just-in-Time Privileged Access

Privileged access should be granted for a limited period where operational requirements permit.

Assignments should expire automatically and require explicit authorization.

### 14.3 Service Account Governance

Service identities should have:

- Named owners.
- Defined business purposes.
- Restricted permissions.
- Credential rotation.
- Expiration or periodic recertification.
- Workload-specific authentication.
- Monitoring for unexpected use.

Non-human identities should not be excluded from access reviews.

### 14.4 Credential Security

Secrets should not be stored in source files, configuration repositories, or unprotected logs.

Production implementations should use managed secret storage, controlled credential rotation, and appropriate workload identity mechanisms.

### 14.5 Audit Protection

Audit records should capture the actor, subject, operation, timestamp, and relevant decision evidence.

Audit retention should be independent of ordinary identity administration wherever practical.

### 14.6 Revocation Propagation

An IAM database status change does not guarantee that all access paths are immediately revoked.

A complete revocation process may need to invalidate:

- Authentication sessions.
- Refresh tokens.
- API keys.
- Application sessions.
- Service credentials.
- Temporary cloud credentials.
- Delegated access tokens.

Revocation should be verified across connected systems.

### 14.7 Concurrent Access Reviews

Two reviewers or administrators may attempt to process the same identity simultaneously.

Production implementations should use optimistic version checks or transactional locking to prevent conflicting decisions and lost updates.

The PostgreSQL procedure demonstrates row locking for the review and identity records.

### 14.8 Risk-Based Review Frequency

Not every identity requires identical review frequency.

| Identity category | Review emphasis |
|---|---|
| Privileged administrators | Frequent certification and authentication checks |
| Service identities | Ownership, credential rotation, and workload necessity |
| Standard employees | Role appropriateness and employment status |
| External identities | Contract validity and expiration |
| Application identities | Application ownership and permission scope |

The appropriate review frequency should be defined by organizational risk, regulatory obligations, and the sensitivity of the associated resources.

## 15. Practical Workflow

The complete assessment workflow is:

`Identity Inventory`

`↓`

`Role and Permission Resolution`

`↓`

`Effective Access Calculation`

`↓`

`Sensitive Permission Detection`

`↓`

`Privilege and SoD Evaluation`

`↓`

`Risk Classification`

`↓`

`Access Review Campaign`

`↓`

`Reviewer Decision`

`↓`

`Approval / Reduction / Revocation / Escalation`

`↓`

`Remediation Verification`

`↓`

`Audit and Reporting`

The workflow should operate continuously for high-risk changes and periodically for formal access certification.

## 16. Implementation Coverage

| Requirement | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Identity inventory | Yes | Yes | Yes | Yes | Yes |
| Role management | Yes | Yes | Yes | Yes | Yes |
| Direct permissions | Yes | Yes | Yes | Yes | Yes |
| Role inheritance | Yes | Yes | Yes | Yes | Yes |
| Effective permissions | Yes | Yes | Yes | Yes | Yes |
| Privilege exposure | Yes | Yes | Yes | Yes | Yes |
| Dormant accounts | Yes | Yes | Yes | Yes | Yes |
| MFA assessment | Yes | Yes | Yes | Yes | Yes |
| SoD detection | Yes | Yes | Yes | Yes | Yes |
| Access reviews | Yes | Yes | Yes | Yes | Yes |
| Permission reduction | Yes | Yes | Yes | Yes | Yes |
| Access revocation | Yes | Yes | Yes | Yes | Yes |
| Audit records | Yes | Yes | Review history | Yes | Yes |
| JSON reporting | Yes | Yes | Console | Console | JSONB evidence |
| Persistent relational storage | No | No | No | No | Yes |

## 17. Execution Requirements

| Deliverable | Runtime | External dependencies |
|---|---|---|
| Python | Python 3.10+ | None |
| JavaScript | Node.js 18+ | None |
| C++17 | C++17 compiler | None |
| Java | Java 17 | None |
| PostgreSQL | PostgreSQL 14+ | PostgreSQL server |

### Python

The script runs as a standalone program and generates `iam_security_report.json` in its working directory.

### JavaScript

The program runs with Node.js and generates `iam_security_report.json`.

### C++17

Compile the source using a C++17-compatible compiler.

The executable prints identity permissions, risk findings, review decisions, and post-remediation findings.

### Java 17

Compile the source file as `IAMSecurityReview.java` and execute its main class.

The program prints the identity inventory, risk findings, certification decisions, and audit events.

### PostgreSQL

Execute the SQL script against a database account with permission to create schemas, types, tables, functions, triggers, and procedures.

The script creates the `iam` schema and inserts demonstration records. It uses a transaction for the sample database setup and review workflow.

The demonstration data should be kept separate from operational identity records.

## 18. Limitations and Interpretation

The implementations are educational IAM governance engines rather than complete identity-provider products.

Their principal limitations are:

- No integration with a production identity provider.
- No real authentication or credential verification.
- No live cloud entitlement discovery.
- No actual exploitation or attack execution.
- No distributed authorization enforcement.
- No production secrets management.
- No complete dynamic SoD evaluation.
- No automated synchronization with HR systems.
- No complete multi-party certification workflow.
- No distributed revocation verification.

The numerical risk scores are illustrative prioritization values. They are not measured probabilities of unauthorized access.

Role inheritance and effective permission calculations demonstrate RBAC behavior. Real IAM platforms may also use attribute-based policies, resource-level conditions, explicit deny rules, policy precedence, delegated administration, and contextual authorization.

Those mechanisms require additional policy evaluation beyond the simplified models implemented here.
