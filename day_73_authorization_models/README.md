# Authorization Models: RBAC, ABAC, ACL, DAC, MAC, and Least Privilege

## 1. Authorization Fundamentals

Authorization determines whether an authenticated identity can perform a particular operation on a particular resource.

Authentication establishes identity. Authorization evaluates permissions and applicable security policies.

An authorization decision normally considers:

- **Subject:** The user, service account, or process requesting access.
- **Object:** The resource being accessed.
- **Action:** The requested operation.
- **Context:** Environmental and organizational attributes.
- **Policy:** The rules governing access.
- **Decision:** Whether access is permitted or rejected.

A general authorization request can be represented as:

`Subject + Resource + Action + Context → Policy Evaluation → Decision`

The six concepts implemented in this project represent different authorization approaches. They are complementary in some architectures, but they are not interchangeable.

## 2. Authorization Models

### 2.1 Role-Based Access Control (RBAC)

RBAC assigns permissions to roles rather than directly assigning every permission to every user.

The principal relationships are:

- Users receive roles.
- Roles receive permissions.
- Permissions authorize operations on resources.

Example:

| Role | Permissions |
|---|---|
| Developer | READ, WRITE |
| Security Administrator | READ, ADMIN |
| Auditor | READ |
| Analyst | READ |

A developer receives permissions through the developer role.

The effective permission set is the union of permissions granted by assigned roles, subject to additional restrictions.

Conceptually:

`User → Assigned Roles → Role Permissions → Effective Grants`

**Implementation:** All five implementations maintain role definitions, permission assignments, and user-role relationships.

The Python implementation uses dictionaries and sets. JavaScript uses `Map` and `Set`. C++ uses STL maps and sets. Java uses immutable role records and collections. PostgreSQL implements RBAC using normalized user-role and role-permission relationship tables.

**Advantages**

- Centralized permission administration.
- Consistent permissions across users with similar responsibilities.
- Easier onboarding and offboarding.
- Reduced duplication of permission assignments.

**Limitations**

- Role proliferation when organizational responsibilities become highly specialized.
- Difficulty representing complex environmental conditions using roles alone.
- Excessive permissions when roles are designed too broadly.

Role assignment should follow job responsibilities rather than convenience.

### 2.2 Attribute-Based Access Control (ABAC)

ABAC evaluates attributes associated with the subject, resource, requested operation, and environment.

Unlike RBAC, authorization does not depend exclusively on membership in a predefined role.

Example attributes:

| Attribute category | Example |
|---|---|
| User | Department = Engineering |
| User | Location = India |
| User | MFA verified = True |
| Resource | Classification = Confidential |
| Resource | Department = Engineering |
| Environment | Purpose = Business |
| Environment | Request time |

A representative policy is:

- The user must be active.
- The user must belong to the resource department unless the purpose is compliance.
- The user's location must be permitted.
- MFA must be verified when required.

A simplified expression is:

`DepartmentMatch AND LocationAllowed AND MFARequiredSatisfied`

ABAC is useful when access depends on circumstances rather than a static job role.

**Implementation:** The policy evaluators in Python, JavaScript, C++ and Java inspect user attributes, resource attributes, and request purpose. PostgreSQL stores resource attributes in JSONB and evaluates selected attributes using SQL conditions.

**Advantages**

- Fine-grained authorization.
- Context-sensitive access decisions.
- Flexible organizational policies.
- Reduced dependence on large numbers of narrowly defined roles.

**Limitations**

- Policy complexity.
- Attribute quality and freshness requirements.
- More difficult policy testing.
- Potential evaluation overhead.

Attributes must come from trusted sources. A client must not be allowed to assert privileged attributes such as verified MFA or administrative status.

### 2.3 Access Control Lists (ACLs)

An ACL specifies which principals may perform particular operations on an individual resource.

A principal can be an individual user or a role.

Example:

| Resource | Principal | Permission |
|---|---|---|
| Financial report | Alice | READ |
| Source code | Developer | WRITE |
| Security document | Auditor | READ |

An ACL is resource-oriented. It answers which principals may access a particular object.

It is distinct from RBAC, which defines permissions through role membership.

A resource can have separate ACL entries for different users and roles.

**Implementation:** Resource objects maintain ACL collections in Python, JavaScript, C++, and Java. PostgreSQL uses `access_control_entries`, which references resources, users or roles, and permissions.

**Advantages**

- Resource-specific permissions.
- Direct grants to individual users.
- Support for collaboration and sharing.
- Clear representation of resource-level access.

**Limitations**

- Large ACLs can become difficult to administer.
- Permissions may become inconsistent across resources.
- Revocation must consider both direct and role-based entries.
- Reviewing effective permissions requires evaluating multiple principals.

ACL administration should be restricted to authorized resource owners or delegated administrators.

### 2.4 Discretionary Access Control (DAC)

DAC allows an authorized resource owner to decide who receives access to that resource.

Ownership provides a limited administrative authority over resource permissions.

Example:

- Alice owns a source-code repository.
- Alice grants Bob READ access.
- Bob receives permission through an ownership-controlled grant.
- Alice revokes that grant when collaboration ends.

DAC is based on ownership and discretionary delegation.

It differs from ACL because DAC describes the authority and model governing permission delegation, while an ACL is a mechanism for recording resource-specific grants.

An ACL can implement DAC.

**Implementation:** The examples give resource owners limited READ, WRITE, and SHARE authority. They also demonstrate owner-controlled ACL grants and revocation.

The PostgreSQL trigger validates that the principal issuing an ACL grant is the resource owner.

**Advantages**

- Flexible collaboration.
- Resource-level delegation.
- Decentralized administration.
- Reduced dependence on central administrators for ordinary sharing.

**Limitations**

- Owners may grant excessive permissions.
- Permissions can spread through uncontrolled delegation.
- Central governance may become difficult.
- Ownership changes require careful permission reassessment.

DAC should operate within organizational security restrictions. Resource ownership must not override mandatory classification or security policies.

### 2.5 Mandatory Access Control (MAC)

MAC enforces centrally defined security classifications and clearance requirements.

Users receive security clearances, and resources receive classifications.

The implementation uses the following ordered levels:

| Level | Rank |
|---|---:|
| PUBLIC | 0 |
| INTERNAL | 1 |
| CONFIDENTIAL | 2 |
| SECRET | 3 |
| TOP_SECRET | 4 |

The implemented confidentiality rule requires:

`User Clearance >= Resource Classification`

For example:

- A CONFIDENTIAL user can access PUBLIC resources.
- A SECRET user can access CONFIDENTIAL resources.
- A PUBLIC user cannot access SECRET resources.

Unlike DAC, individual resource owners cannot override MAC restrictions.

**Implementation:** Python uses `IntEnum`, JavaScript uses numeric classification constants, C++ uses an enum, Java uses an enum with explicit ranking, and PostgreSQL uses an enumerated classification type with a ranking function.

**Important distinction:** The implementations provide a simplified confidentiality-oriented MAC check. They do not implement a complete information-flow security model.

A full Bell-LaPadula implementation must also account for security properties such as:

- No read up.
- No write down.

A complete MAC system may require additional controls for compartments, categories, trusted subjects, information-flow restrictions, and declassification.

**Advantages**

- Centralized classification enforcement.
- Reduced dependence on individual owners.
- Consistent treatment of sensitive information.
- Stronger control over classified resources.

**Limitations**

- Classification administration is demanding.
- Incorrect classifications can block legitimate work.
- Clearance changes require governance.
- Security labels must remain trustworthy throughout the resource lifecycle.

## 3. Least Privilege

Least privilege is a security principle requiring each user, service, or process to receive only the permissions necessary to perform its authorized responsibilities.

It is not a separate grant mechanism equivalent to RBAC or ACL.

It constrains the permissions granted by other authorization mechanisms.

For example, a developer may have READ and WRITE permissions but should not automatically receive DELETE or ADMIN permissions.

The implementations enforce additional restrictions:

| Operation | Additional requirement |
|---|---|
| READ | Ordinary grant and mandatory policies |
| WRITE | Ordinary grant and mandatory policies |
| DELETE | Explicit user authorization and resource deletion enabled |
| ADMIN | Explicit privileged administrator attribute |
| SHARE | Ownership or applicable grant |

A useful model is:

`Effective Access = Applicable Grant AND All Mandatory Restrictions`

Least privilege should be applied to:

- Human users.
- Database accounts.
- API service identities.
- Background jobs.
- Cloud workloads.
- Administrative accounts.
- Temporary credentials.

Privilege elevation should be time-limited, approved, monitored, and revoked when no longer required.

## 4. Differences Between Authorization Models

| Model | Primary decision basis | Main focus |
|---|---|---|
| RBAC | Assigned roles | Organizational responsibilities |
| ABAC | Subject, resource, and environmental attributes | Context |
| ACL | Principal-resource permission entries | Resource-level grants |
| DAC | Resource ownership and delegation | Discretionary permission administration |
| MAC | Security labels and clearances | Mandatory classification |
| Least Privilege | Minimum necessary authority | Permission restriction |

The models can operate together.

For example, a developer might receive WRITE through RBAC, receive READ on a financial resource through an ACL, and still be denied access because MAC clearance is insufficient.

A valid grant is not necessarily a valid authorization decision.

## 5. Integrated Authorization Architecture

The implementations use a combined authorization strategy.

The general decision flow is:

`Access Request`

`    |`

`    v`

`Identity and Resource Validation`

`    |`

`    v`

`Explicit Deny Evaluation`

`    |`

`    v`

`Account Status Validation`

`    |`

`    v`

`Mandatory Policy Evaluation`

`    |`

`    +---- MAC`

`    +---- ABAC`

`    +---- Least Privilege`

`    |`

`    v`

`Grant Evaluation`

`    |`

`    +---- RBAC`

`    +---- ACL`

`    +---- DAC`

`    |`

`    v`

`Grant Found AND Mandatory Policies Passed`

`    |`

`    +---- YES → ALLOW`

`    |`

`    +---- NO  → DENY`

`    |`

`    v`

`Audit Event`

The grant mechanisms are evaluated as alternative sources of permission. The mandatory restrictions must also pass.

Explicit denial takes precedence over ordinary grants.

This is an application-level evaluation design. Production environments must also enforce permissions at the resource boundary, such as through database privileges, API authorization middleware, operating-system controls, or cloud access policies.

## 6. Python Implementation

**File:** `authorization_models.py`

The Python program implements an in-memory authorization engine.

### Domain structures

| Structure | Responsibility |
|---|---|
| `User` | Identity, department, clearance, and attributes |
| `Role` | Named permission collection |
| `Resource` | Ownership, classification, and ACL |
| `AccessRequest` | Requested resource operation and purpose |
| `AuditEvent` | Recorded authorization outcome |
| `AuthorizationEngine` | Central policy evaluation |

The program uses:

- Dataclasses for domain objects.
- Enums for permissions, decisions, and classification.
- Dictionaries for identity and resource lookup.
- Sets for role assignments and permissions.
- Exceptions for invalid requests.
- JSON for audit export.
- Unit tests for authorization scenarios.

### Policy evaluation

`evaluate_rbac()` checks role-derived permissions.

`evaluate_abac()` evaluates department, purpose, location, and MFA attributes.

`evaluate_acl()` checks direct user grants and role-based ACL entries.

`evaluate_dac()` checks resource ownership.

`evaluate_mac()` checks security clearance against resource classification.

`evaluate_least_privilege()` restricts administrative and destructive operations.

`authorize()` combines these decisions and records the result.

### Audit handling

Audit events include the user, resource, permission, decision, timestamp, and policy evaluation reasons.

The JSON export uses a temporary file and atomic replacement to reduce the risk of exposing incomplete audit output.

The demonstration also executes unit tests for successful access, ACL grants, inactive accounts, classification failures, invalid identities, and least-privilege restrictions.

## 7. JavaScript Implementation

**File:** `authorization_models.js`

The JavaScript implementation uses an event-driven architecture rather than simply reproducing the Python structure.

### Main components

| Component | Responsibility |
|---|---|
| `AuthorizationPolicy` | Registers and executes named policy functions |
| `PolicyResult` | Stores the decision and evaluation reasons |
| `AuthorizationEngine` | Maintains identities, resources, roles, and audit records |
| `EventEmitter` | Publishes authorization outcomes |

`Map` supports identity and resource lookup. `Set` prevents duplicate role assignments and permission grants.

Policy registration separates the definition of a policy from the authorization request.

This makes it possible to introduce additional policy rules without embedding every condition inside one large function.

### Asynchronous processing

`authorize()` is asynchronous and publishes authorization events.

The application can attach event listeners for:

- Security monitoring.
- Authorization metrics.
- Operational logging.
- Incident investigation.

Audit export uses Node.js file operations and a temporary file.

The implementation uses built-in modules and does not require npm dependencies.

### Failure handling

Invalid identities, permissions, resources, and policy results produce explicit errors.

Invalid requests are recorded as denied validation events before the error is propagated.

This separates an invalid request from a valid request that fails a security policy.

## 8. C++17 Implementation

**File:** `authorization_engine.cpp`

The C++ implementation focuses on efficient in-memory authorization evaluation and explicit domain modeling.

### Data structures

| Structure | Purpose |
|---|---|
| `map` | User, role, and resource lookup |
| `set` | Unique permissions and role assignments |
| `vector` | Audit history and evaluation reasons |
| `struct` | User, resource, request, and policy records |
| `enum class` | Strongly typed security states |

The engine separates grant evaluation from mandatory security checks.

RBAC uses assigned-role lookup. ACL checks direct and role-based entries. DAC checks ownership. MAC compares classification ranks. ABAC evaluates organizational and contextual attributes.

### Performance considerations

Map-based identity and resource lookup typically costs O(log n).

Set-based permission lookup typically costs O(log p), where p is the number of permissions in the relevant set.

Role evaluation depends on the number of assigned roles and the number of relevant permission checks.

For larger authorization systems, indexed hash-based lookup structures, compiled policy expressions, and cached authorization decisions may improve throughput.

Caches must account for permission revocation, role changes, account suspension, and policy updates.

The program uses the C++17 standard library and requires no external dependencies.

## 9. Java 17 Implementation

**File:** `AuthorizationGovernance.java`

The Java implementation emphasizes enterprise domain modeling, explicit policy registration, and immutable records.

### Enterprise components

| Component | Responsibility |
|---|---|
| `User` record | Immutable user identity and security attributes |
| `Role` record | Immutable role permissions |
| `Resource` record | Resource classification and ownership |
| `AccessRequest` record | Typed authorization request |
| `PolicyContext` record | Shared evaluation context |
| `PolicyRegistry` | Named authorization rules |
| `AuthorizationService` | Authorization orchestration |
| `AuditEvent` record | Immutable audit event |

The `AuthorizationRule` interface provides a common contract for different policy implementations.

The `PolicyRegistry` stores named rules, allowing each mandatory policy to be evaluated independently.

The service distinguishes:

- Role-derived permissions.
- Resource-specific ACL grants.
- Ownership-based permissions.
- Mandatory policy restrictions.

The implementation also demonstrates immutable audit records, exception handling, decision aggregation, and revocation.

Java records provide concise data models, while defensive collection copies prevent external modification of stored permission sets.

## 10. PostgreSQL Implementation

**File:** `authorization_models.sql`

The PostgreSQL implementation provides a relational authorization model with integrity constraints, indexes, policy evaluation, and audit reporting.

### Relational schema

| Table | Responsibility |
|---|---|
| `departments` | Organizational units |
| `users` | Identity and security attributes |
| `roles` | RBAC role definitions |
| `permissions` | Available operations |
| `role_permissions` | Role-to-permission mapping |
| `user_roles` | User-to-role mapping |
| `resources` | Protected objects |
| `resource_attributes` | ABAC resource attributes |
| `access_control_entries` | ACL and DAC grants |
| `authorization_policies` | Policy definitions |
| `explicit_deny_rules` | Explicit denial conditions |
| `access_requests` | Authorization requests |
| `authorization_audit` | Decision history |

### Database integrity

The schema uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated types.
- Cascading deletion where appropriate.
- JSONB attributes.
- Indexes for common lookups.

The ACL principal constraint ensures that an entry identifies either a user or a role, but not both.

The ACL ownership trigger restricts grant creation to the resource owner.

The audit trigger prevents modification or deletion of existing audit records.

In a production system, audit immutability should also be enforced through database privileges, separate audit ownership, restricted administrative access, and external tamper-resistant storage.

### Authorization function

`evaluate_access()` evaluates:

1. User and resource existence.
2. Explicit deny rules.
3. Account activity.
4. Resource activity.
5. RBAC grants.
6. ACL grants.
7. DAC ownership.
8. MAC classification.
9. ABAC conditions.
10. Least-privilege restrictions.

The function returns individual policy results alongside the final decision.

### Workflow procedure

`process_access_request()`:

- Resolves the username.
- Resolves the resource.
- Creates an access request.
- Executes authorization evaluation.
- Stores the decision and explanation.
- Creates an audit record.

The procedure runs within the caller's transaction.

The sample workflow demonstrates successful requests, denied requests, classification failures, inactive accounts, explicit denial, and transactional role revocation.

### Reporting

The script provides queries for:

- Effective role permissions.
- Resource ownership.
- Access history.
- Classification mismatches.
- Allow and deny counts.
- User-level authorization activity.
- Resource-level access statistics.
- Denial percentages.
- Effective authorization decisions.

The GIN index on resource attributes supports JSONB-oriented searches. Additional indexes support common user, resource, permission, and timestamp lookups.

## 11. Realistic Authorization Scenario

Consider an organization with Engineering, Finance, Security, and Compliance departments.

Alice is a developer with CONFIDENTIAL clearance. Bob is a finance administrator with SECRET clearance. Charlie has an inactive account.

The organization maintains a source-code resource and a financial report.

| Scenario | Applicable mechanism | Expected result |
|---|---|---|
| Alice reads source code | RBAC | ALLOW |
| Alice reads financial report for compliance | ACL grant but insufficient MAC clearance | DENY |
| Alice modifies financial report | MAC and ABAC restrictions | DENY |
| Bob reads financial report | RBAC and mandatory policies | ALLOW |
| Alice deletes source code | Least privilege | DENY |
| Charlie reads source code | Account status | DENY |
| Alice accesses after an explicit deny rule | Explicit denial | DENY |

The scenarios demonstrate why the existence of a permission grant does not automatically establish authorization.

## 12. Common Authorization Failure Modes

| Failure | Security consequence | Appropriate control |
|---|---|---|
| Excessive role permissions | Unnecessary access | Role review |
| Stale role assignment | Retained privileges | Periodic recertification |
| Incorrect resource classification | Unauthorized disclosure | Classification governance |
| Overly broad ACL | Unnecessary sharing | ACL audits |
| Uncontrolled ownership delegation | Privilege propagation | Delegation restrictions |
| Untrusted ABAC attributes | Policy manipulation | Trusted attribute sources |
| Missing MFA enforcement | Weak access assurance | Authentication integration |
| Missing account revocation | Continued access | Centralized account lifecycle |
| Excessive administrative privileges | High-impact compromise | Privileged access management |
| Stale authorization cache | Access after revocation | Cache invalidation |
| Incomplete audit records | Weak accountability | Durable audit storage |

## 13. Security and Production Considerations

### Policy precedence

Authorization systems need an explicitly defined precedence model.

The implementations use the following simplified rule:

- Explicit denial overrides ordinary grants.
- Inactive and suspended accounts are rejected.
- MAC, ABAC, and least-privilege restrictions must pass.
- At least one configured grant mechanism must authorize the operation.

Different organizations may use more restrictive policy-combination strategies. Their precedence rules must be explicit and consistently enforced.

### Separation of duties

RBAC systems should account for incompatible responsibilities.

For example, a user who creates a financial transaction should not necessarily be allowed to approve the same transaction.

Role-conflict rules and approval workflows should be evaluated separately from ordinary permission checks.

### Privileged access

Administrative access should use dedicated privileged identities, strong authentication, time-limited elevation, approval records, and continuous monitoring.

An ordinary role assignment should not automatically create unrestricted administrative access.

### API enforcement

Authorization must be performed on the server side for every protected operation.

Client-side interface restrictions are not sufficient because a user can bypass the interface and call an API directly.

Every request should be evaluated against the current identity, resource, operation, and applicable policies.

### Database enforcement

Application-level authorization should be complemented by appropriate PostgreSQL permissions.

For sensitive workloads, row-level security can provide an additional database enforcement layer.

Database owners, superusers, and roles with policy-bypass privileges require special controls because ordinary row-level policies may not constrain them.

### Audit integrity

Audit records should capture:

- Request identity.
- Resource identity.
- Requested operation.
- Decision.
- Policy evaluation outcome.
- Timestamp.
- Relevant correlation identifiers.

Audit logs should not expose passwords, authentication tokens, secret attributes, or unnecessary personal information.

### Performance

Authorization performance depends on:

- Number of assigned roles.
- Number of resource ACL entries.
- Attribute lookup costs.
- Policy complexity.
- Database query execution.
- Network calls to identity providers.
- Cache behavior.

Authorization caches must be invalidated when roles, ACLs, clearances, account states, or policy definitions change.

For distributed systems, revocation propagation and consistency are important security requirements.

## 14. Testing and Expected Execution

| Deliverable | Execution | Dependencies |
|---|---|---|
| Python | `python authorization_models.py` | Python 3.10+ |
| JavaScript | `node authorization_models.js` | Node.js 18+ |
| C++17 | Compile with `g++ -std=c++17 -O2 -Wall -Wextra` | C++17 compiler |
| Java 17 | `javac AuthorizationGovernance.java` followed by `java AuthorizationGovernance` | JDK 17 |
| PostgreSQL | Execute the SQL script using `psql` | PostgreSQL 15+ |

The Python and JavaScript implementations export audit data to JSON files. The C++ and Java implementations print audit records to the console. PostgreSQL stores audit records relationally.

Expected functional checks include:

- Successful role-based authorization.
- Successful ACL-based authorization where mandatory policies permit access.
- Resource ownership permissions.
- Classification-based denial.
- Attribute-based denial.
- Least-privilege restrictions.
- Inactive account rejection.
- Explicit denial precedence.
- Invalid identity handling.
- Permission revocation.
- Audit event creation.

## 15. Scope and Limitations

These implementations are educational authorization engines, not complete enterprise identity and access management platforms.

They do not provide:

- Production authentication.
- Cryptographic identity verification.
- Complete Bell-LaPadula or Biba enforcement.
- Distributed policy synchronization.
- Full policy administration and lifecycle management.
- Enterprise identity federation.
- Complete separation-of-duties analysis.
- Automatic privileged-access approval.
- Tamper-proof external audit storage.
- Production-grade concurrent authorization transactions.
- Comprehensive attribute provenance and freshness verification.

The SQL procedure also assumes a trusted database execution environment. A production deployment must restrict direct table modification, secure procedure execution privileges, validate caller identity, and prevent unauthorized changes to authorization policies.

The central engineering distinction remains:

**A grant establishes a potential permission. An authorization decision determines whether that permission can be exercised under the applicable security constraints.**
