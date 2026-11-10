# Identity and Access Management (IAM)

## 1. Domain Overview

Identity and Access Management is the collection of processes, policies, technologies and controls used to manage digital identities and regulate access to organizational resources.

An IAM system determines:

- Who or what is requesting access.
- Whether the presented identity can be authenticated.
- Which resources the identity can access.
- Which operations are permitted.
- Whether access should be restricted or revoked.
- Which security events must be recorded.
- How identities are created, modified, suspended and terminated.

The implementations cover four closely related but technically distinct IAM functions.

| Function | Primary question | Main mechanism |
|---|---|---|
| Authentication | Who is requesting access? | Credentials, MFA and sessions |
| Authorization | What can the authenticated identity do? | Roles, permissions and policies |
| Accounting | What happened during access and administrative operations? | Audit events and activity records |
| Identity lifecycle management | How does an identity change over time? | Provisioning, activation, suspension and termination |

The implementations use Role-Based Access Control (RBAC) as their primary authorization model.

## 2. IAM Architecture

The logical architecture follows this sequence:

Identity Provisioning
        |
        v
Identity Registry
        |
        v
Credential Verification
        |
        v
Multi-Factor Authentication
        |
        v
Session Creation
        |
        v
Authorization Policy Evaluation
        |
        v
Access Decision
        |
        +------ ALLOW
        |
        +------ DENY
        |
        v
Accounting and Audit Records
        |
        v
Identity Lifecycle Administration

Authentication establishes an authenticated identity. Authorization evaluates its current privileges. Accounting records relevant security activities. Lifecycle management controls whether the identity remains eligible to use the system.

These functions must operate together, but one successful operation does not automatically imply that another has succeeded.

## 3. Authentication

Authentication is the process of verifying an identity claim.

A username identifies an account. It does not prove ownership of that account.

Authentication generally involves one or more factors:

| Factor | Description | Example |
|---|---|---|
| Knowledge | Something the user knows | Password |
| Possession | Something the user possesses | Hardware security key |
| Inherence | Something the user is | Biometric characteristic |

Multi-Factor Authentication (MFA) requires verification using independent authentication factors.

A password followed by a second authentication factor provides stronger protection than password-only authentication.

### Password verification

The Python implementation uses:

- Random salts.
- PBKDF2-HMAC-SHA256.
- 310,000 derivation iterations.
- 32-byte derived credentials.
- Constant-time comparison through `hmac.compare_digest`.

The salt prevents identical passwords from producing identical stored hashes.

The password itself is never stored in the identity object or audit records.

The JavaScript implementation uses Node.js `crypto.pbkdf2Sync`, random salts and `crypto.timingSafeEqual`.

The C++ and Java implementations separate credential verification from repository and identity governance logic. They use an explicit credential-provider boundary rather than presenting a custom password-hashing implementation as production security infrastructure.

### Authentication workflow

1. Normalize and validate the username.
2. Retrieve the corresponding identity.
3. Verify that the identity is active.
4. Check temporary account restrictions.
5. Verify the credential.
6. Verify MFA when required.
7. Reset failed-attempt counters.
8. Generate a session token.
9. Record the authentication result.

An authentication failure must not produce an authorized session.

### Failed authentication

Repeated incorrect credentials can indicate credential stuffing, password guessing or other suspicious activity.

The Python and JavaScript implementations apply a configurable failed-attempt threshold and temporary lockout.

The enterprise implementations record failed authentication events separately from successful sessions.

Production deployments should combine account-level controls with network-level rate limiting, monitoring, credential-stuffing detection and carefully designed recovery procedures.

### Session management

A session represents an authenticated interaction between an identity and an application.

Important session properties include:

- Session identifier.
- Identity identifier.
- Creation timestamp.
- Expiration timestamp.
- Revocation state.
- Last activity timestamp.

A session must be rejected when it is expired, revoked or associated with an inactive identity.

The Python and JavaScript implementations use cryptographically random bearer tokens. The PostgreSQL implementation stores a token hash rather than the raw bearer token.

Session expiration and session revocation are different operations:

| Operation | Meaning |
|---|---|
| Expiration | Access becomes invalid after a defined period |
| Revocation | Access is invalidated before the original expiration |
| Logout | The current session is explicitly revoked |
| Administrative revocation | Sessions are invalidated following an identity or security event |

## 4. Authorization

Authorization determines whether an authenticated identity may perform a particular operation on a particular resource.

An access request can be represented as:

`Identity + Resource + Permission + Context`

For example:

- Identity: Alice.
- Resource: `documents/financial-report.pdf`.
- Permission: `document:read`.
- Context: Active session and active identity.

The authorization engine evaluates the applicable policy and returns an access decision.

### Role-Based Access Control

RBAC associates permissions with roles and roles with identities.

The relationship is:

Identity → Role Assignment → Role → Permissions

The implementations define four roles.

| Role | Read | Write | Delete | Manage Users | Manage Roles | Read Audit |
|---|---|---|---|---|---|---|
| Employee | Yes | Yes | No | No | No | No |
| Manager | Yes | Yes | Yes | No | No | No |
| Security Admin | Yes | Yes | Yes | Yes | Yes | Yes |
| Auditor | Yes | No | No | No | No | Yes |

The table represents the default policy implemented in the Python, JavaScript, C++ and Java programs.

### Permission evaluation

An identity can receive permissions through multiple assigned roles.

The evaluator checks whether at least one active role grants the requested permission.

A missing permission results in denial.

The implementations also support an explicit identity-level denial in their policy-evaluation models. This demonstrates how a restrictive policy can override an otherwise valid role grant.

### Least privilege

The Principle of Least Privilege requires an identity to receive only the permissions necessary for its responsibilities.

For example, an auditor may require read access to audit records but should not automatically receive permission to modify employee accounts.

Least privilege reduces the impact of compromised credentials and accidental misuse.

### Role assignment

Role assignment must be controlled because privileged roles can expose sensitive organizational resources.

The implementations validate identity status before allowing role assignment.

They also prevent duplicate role assignments and record role changes.

The PostgreSQL implementation models role assignments using a separate relationship table and supports optional expiration timestamps.

## 5. Accounting and Security Auditing

Accounting records activities performed within the IAM environment.

It answers questions such as:

- Which identity authenticated?
- When did authentication occur?
- Which authentication attempts failed?
- Which resource was accessed?
- Which permission was requested?
- Was access granted or denied?
- Who changed an identity's role?
- When was an account suspended?
- Which sessions were revoked?

### Audit event structure

An audit event contains:

| Field | Purpose |
|---|---|
| Event ID | Unique event identifier |
| Identity ID | Identity associated with the operation |
| Event type | Category of activity |
| Resource | Affected resource or subsystem |
| Details | Structured contextual information |
| Timestamp | Time at which the event occurred |

The Python implementation uses immutable dataclasses for individual audit records.

The JavaScript implementation uses an event-driven audit ledger and `EventEmitter` subscriptions.

The C++ implementation maintains an ordered vector of events with monotonically increasing sequence numbers.

The Java implementation uses immutable records and an atomic event sequence.

The PostgreSQL implementation stores structured event details in `JSONB`.

### Important event categories

| Category | Example |
|---|---|
| Authentication | `LOGIN_SUCCESS`, `LOGIN_FAILURE` |
| Authorization | `ACCESS_GRANTED`, `ACCESS_DENIED` |
| Identity administration | `IDENTITY_CREATED`, `IDENTITY_DISABLED` |
| Privilege administration | `ROLE_ASSIGNED`, `ROLE_REMOVED` |
| Session administration | `SESSION_REVOKED` |
| Credential administration | `PASSWORD_CHANGED` |

### Audit integrity

Audit records should provide a reliable history of security-relevant activities.

The PostgreSQL implementation uses a trigger that rejects updates and deletes on the audit table.

This provides application-level append-only enforcement, but it does not make the table cryptographically tamper-proof against database superusers.

Production environments should consider:

- Restricted database privileges.
- Independent audit storage.
- Centralized security monitoring.
- Log integrity verification.
- Retention and archival policies.
- Time synchronization.
- Sensitive-data redaction.
- Separation of audit administration from identity administration.

Audit logs should never contain passwords, raw bearer tokens, password hashes or MFA secrets.

## 6. Identity Lifecycle Management

Identity lifecycle management controls an identity from its initial creation until its final termination.

The lifecycle is important because organizational access requirements change when employees join, change responsibilities, take temporary leave or leave an organization.

### Identity states

| State | Meaning | Authentication |
|---|---|---|
| PENDING | Identity created but not activated | Denied |
| ACTIVE | Identity approved for use | Permitted subject to authentication |
| SUSPENDED | Access temporarily restricted | Denied |
| DISABLED | Account administratively disabled | Denied |
| TERMINATED | Identity permanently terminated | Denied |

### Lifecycle state transitions

PENDING
   |
   v
ACTIVE
   |
   +------ SUSPENDED
   |           |
   |           v
   |         ACTIVE
   |
   +------ DISABLED
   |           |
   |           v
   |       TERMINATED
   |
   +------ TERMINATED

SUSPENDED can also transition to DISABLED or TERMINATED.

A DISABLED identity can transition to TERMINATED.

TERMINATED is a final state in these implementations.

The state machine prevents invalid transitions, such as activating a terminated identity.

### Joiner, mover and leaver processes

IAM lifecycle management is commonly organized around three operational processes.

| Process | Organizational event | IAM operation |
|---|---|---|
| Joiner | Employee joins | Create, validate and activate identity |
| Mover | Employee changes department or position | Review and modify role assignments |
| Leaver | Employee exits | Disable identity and revoke sessions |

The mover process is particularly important.

When an employee changes responsibilities, obsolete permissions should be removed rather than accumulated.

### Suspension and termination

Suspension is appropriate when access must be restricted temporarily.

Termination is appropriate when an identity permanently leaves the organization's authorization environment.

Both operations revoke active sessions.

The PostgreSQL lifecycle trigger performs session revocation in the same database transaction as the identity state change.

This avoids leaving valid database sessions associated with an identity that has just been suspended or disabled.

Production offboarding should also revoke external application sessions, API keys, refresh tokens, service credentials and other independently managed credentials.

## 7. Python Implementation

The Python program provides an integrated IAM simulation.

### Main components

| Component | Responsibility |
|---|---|
| `Identity` | Identity attributes, credentials, roles and lifecycle state |
| `Session` | Session creation, expiration and revocation |
| `AuditEvent` | Immutable accounting record |
| `IAMService` | Main IAM application service |
| `Role` | Organizational role definitions |
| `Permission` | Individual access privileges |
| `IdentityStatus` | Lifecycle state definitions |

### Important implementation decisions

**Dataclasses**

Identity, session, audit and access-decision objects use dataclasses to maintain structured domain information.

**Enums**

Enums restrict lifecycle states, permissions, roles and event types to defined values.

**Dictionary indexes**

Identity lookup uses a dictionary keyed by identity ID, with a separate username index.

Session lookup uses the session token as a dictionary key.

These structures provide expected constant-time lookup.

**Set-based permissions**

Role permissions and identity role assignments use sets to avoid duplicate values and support efficient membership testing.

**Credential verification**

PBKDF2 is used for password derivation, and constant-time comparison is used for verification.

**Session invalidation**

Administrative lifecycle operations revoke associated sessions.

**Audit export**

The audit ledger can be exported to JSON for examination.

The example export is not an independent or tamper-resistant audit repository.

### Demonstrated scenario

Alice is provisioned, activated and assigned the Employee role.

She enables MFA and authenticates.

The authorization engine permits document reading and denies document deletion.

The session is then revoked, and the identity is suspended and subsequently reactivated.

The accounting report shows the security events generated by the workflow.

## 8. JavaScript Implementation

The JavaScript implementation provides an event-driven perspective.

### Main components

| Component | Responsibility |
|---|---|
| `Identity` | Identity state and role assignments |
| `AuditLedger` | Event storage and event subscriptions |
| `AccessPolicy` | Authorization evaluation |
| `IAMService` | Identity and session operations |
| `RolePermissions` | Role-to-permission mapping |

### Event-driven accounting

The audit ledger extends Node.js `EventEmitter`.

When an event is recorded, subscribers receive the event immediately.

This allows monitoring components to react to security events without tightly coupling them to authentication and authorization functions.

For example, an event subscriber can process login failures, access denials or administrative changes.

A production event pipeline should use durable delivery, controlled retries and independent storage rather than relying exclusively on an in-memory event emitter.

### Asynchronous operations

The JavaScript service uses asynchronous methods for audit export and application-level workflows.

The demonstration uses synchronous PBKDF2 verification to keep the example self-contained. A high-throughput Node.js authentication service should use the asynchronous cryptographic API or an external credential provider to avoid blocking the event loop.

### Policy evaluation

`AccessPolicy` separates access decisions from identity administration.

It evaluates:

- Identity status.
- Explicit denial.
- Resource validity.
- Role membership.
- Permission membership.

The decision includes a reason code so that an application can distinguish a missing permission from an inactive identity.

## 9. C++17 Implementation

The C++ implementation focuses on an efficient repository-independent governance engine for identity and access decisions.

### Main components

| Component | Responsibility |
|---|---|
| `Identity` | Identity domain structure |
| `Session` | Session state |
| `RolePolicy` | Permission evaluation |
| `CredentialVerifier` | External authentication verification boundary |
| `AuditLedger` | Ordered accounting records |
| `IAMEngine` | Identity lifecycle and access operations |

### Data structures

The program uses:

- `unordered_map` for identity and session lookup.
- `unordered_set` for explicit denials and permission membership.
- `set` for deterministic role storage.
- `vector` for ordered audit events.
- `map` for event aggregation.
- `enum class` for strongly typed states.

Identity and session lookup use expected constant-time hash-table operations.

Permission evaluation iterates over the roles assigned to an identity and checks the relevant permission set.

### Credential boundary

The C++ program intentionally separates external credential verification from authorization.

The `CredentialVerifier` accepts a verified credential result and MFA result.

This is an architectural boundary, not a password-hashing algorithm.

In an enterprise deployment, credential verification should be implemented through a dedicated authentication provider.

### Policy behavior

The engine supports:

- Role-based permission grants.
- Explicit identity denials.
- Session expiration.
- Identity suspension.
- Identity disablement.
- Identity termination.
- Automatic session revocation.
- Audit reporting.

The implementation demonstrates how identity state and current role assignments influence authorization decisions.

## 10. Java 17 Implementation

The Java implementation models an enterprise IAM service using explicit domain types, interfaces, records and service classes.

### Architecture

| Component | Responsibility |
|---|---|
| `IAMService` | Main application service |
| `Identity` | Enterprise identity model |
| `Session` | Authenticated session |
| `CredentialProvider` | Credential verification contract |
| `RolePolicy` | RBAC permission mapping |
| `ReviewPolicy` | Access decision evaluation |
| `AuditService` | Accounting and event aggregation |
| `AccessDecision` | Immutable authorization result |
| `IdentitySnapshot` | Immutable identity representation |

### Interface-based authentication

`CredentialProvider` separates authentication infrastructure from identity management.

`DemoCredentialProvider` supplies a self-contained demonstration implementation.

The provider can be replaced by an enterprise identity provider without redesigning the authorization service.

The demonstration provider is not suitable for storing production passwords.

### Records and immutability

Java records represent audit events, authentication results, access decisions and identity snapshots.

Records reduce accidental modification of returned domain information.

`IdentitySnapshot` also uses `Set.copyOf` to prevent external modification of its role collection.

### Enterprise policy design

The service separates three important responsibilities:

1. Credential verification.
2. Role-based permission evaluation.
3. Explicit access restrictions.

The `ReviewPolicy` evaluates access against the current identity state and role assignments.

The service uses concurrent collections for shared identity, session and lockout registries. Lifecycle mutations are synchronized at the service boundary.

For a distributed production system, these in-memory controls must be replaced or supplemented by transactional persistence, distributed session revocation and consistent policy evaluation.

## 11. PostgreSQL Implementation

The PostgreSQL implementation models IAM as a relational system.

It separates identity information, role definitions, permission definitions, authentication records, sessions, authorization decisions and accounting events.

### Relational model

| Table | Purpose |
|---|---|
| `departments` | Organizational structure |
| `identities` | Digital identity registry |
| `roles` | Role definitions |
| `permissions` | Permission definitions |
| `role_permissions` | Role-to-permission mapping |
| `identity_roles` | Identity-to-role mapping |
| `authentication_attempts` | Authentication history |
| `sessions` | Session management |
| `resources` | Protected resources |
| `access_decisions` | Authorization decisions |
| `audit_events` | Accounting and security events |

### Relationship diagram

DEPARTMENTS
    |
    v
IDENTITIES
    |
    +------ IDENTITY_ROLES
    |              |
    |              v
    |            ROLES
    |              |
    |              v
    |        ROLE_PERMISSIONS
    |              |
    |              v
    |          PERMISSIONS
    |
    +------ SESSIONS
    |
    +------ AUTHENTICATION_ATTEMPTS
    |
    +------ ACCESS_DECISIONS
    |
    +------ AUDIT_EVENTS

RESOURCES
    |
    v
ACCESS_DECISIONS

### Referential integrity

Primary keys uniquely identify records.

Foreign keys maintain relationships between identities, roles, permissions, sessions and resources.

Unique constraints prevent duplicate usernames, email addresses, role names and permission codes.

Check constraints validate fields such as failed authentication counters, identity versions and session expiration.

### Database functions

`check_access` evaluates whether an identity possesses a requested permission through an active role assignment.

`validate_session` verifies that a session is:

- Present.
- Not revoked.
- Not expired.
- Associated with an active identity.

`record_access_decision` evaluates a request and persists its authorization result and audit event.

### Triggers

The identity lifecycle trigger validates permitted state transitions.

The lifecycle audit trigger records state changes and revokes active sessions when an identity becomes suspended, disabled or terminated.

Role assignment triggers create audit events when privileges are granted or removed.

The audit immutability trigger prevents ordinary SQL updates and deletes against historical audit records.

### Views

`active_identity_directory` provides a view of active identities.

`identity_effective_permissions` exposes the effective role-derived permission assignments.

`identity_session_summary` provides session counts for identity monitoring.

### CTEs and reporting

The script includes Common Table Expressions for effective permission aggregation.

Additional reports identify:

- Authentication failures.
- Access denials.
- Role distributions.
- Privileged identities without MFA.
- Expired role assignments.
- Active identities without roles.
- Audit event distributions.
- Invalid active sessions associated with inactive identities.

### Transaction management

The offboarding example executes identity suspension within an explicit transaction.

The associated trigger revokes active sessions and records the lifecycle event.

The transaction ensures that the identity state change and database session-revocation operation are committed together.

## 12. IAM Security Principles

### Least privilege

Grant only the privileges required for a defined responsibility.

### Separation of duties

Avoid concentrating incompatible administrative responsibilities in one identity.

For example, identity provisioning, privileged role approval and audit review can be assigned to different organizational functions.

### Defense in depth

Use multiple independent security controls:

- Strong authentication.
- MFA.
- Role-based authorization.
- Session expiration.
- Session revocation.
- Audit monitoring.
- Privileged access restrictions.
- Database access controls.

### Default deny

When an authorization rule cannot establish permission, access should be denied.

A missing role assignment must never be interpreted as an implicit grant.

### Privileged access management

Privileged accounts require stronger controls than ordinary employee accounts.

Relevant controls include:

- Mandatory MFA.
- Restricted administrative sessions.
- Time-limited privilege elevation.
- Privileged activity recording.
- Periodic access reviews.
- Emergency access procedures.

### Credential protection

Credential storage and verification must use dedicated security mechanisms.

Password hashing should use an appropriate password-hashing algorithm with deployment-specific parameters.

Raw passwords, authentication tokens and MFA secrets must not appear in logs.

### Session protection

Applications should use secure transport, appropriately configured cookies or protected bearer tokens, session expiration and revocation.

Sensitive applications may require reauthentication for high-impact operations.

## 13. Important Distinctions

| Concept | What it establishes | What it does not establish |
|---|---|---|
| Identity | An entity represented in the IAM system | Proof of identity ownership |
| Authentication | Verification of an identity claim | Permission to access every resource |
| Authorization | Permission to perform an operation | Proof that the operation was performed |
| Accounting | A record of security-related activities | Prevention of every unauthorized operation |
| Role | A collection of associated privileges | Direct authentication |
| Permission | An allowed operation | Identity ownership |
| Session | A time-bounded authenticated interaction | Permanent access rights |
| Lifecycle state | The current administrative condition of an identity | A complete authorization decision |
| MFA | Verification using multiple factors | Automatic authorization |

## 14. Edge Cases and Failure Conditions

The implementations demonstrate several important failure conditions.

| Condition | Expected behavior |
|---|---|
| Duplicate username | Identity creation rejected |
| Invalid email | Provisioning rejected |
| Weak password | Password validation fails |
| Unknown identity | Authentication rejected |
| Incorrect credential | Authentication rejected and failure recorded |
| MFA required but missing | Authentication rejected |
| Repeated failed attempts | Temporary lockout |
| Pending identity | Authentication rejected |
| Suspended identity | Authentication rejected |
| Expired session | Session rejected |
| Revoked session | Session rejected |
| Missing permission | Authorization denied |
| Duplicate role assignment | Assignment rejected |
| Missing role assignment | Removal rejected |
| Invalid lifecycle transition | State change rejected |
| Identity termination | Roles removed and sessions revoked |
| Missing resource | Authorization evaluation rejected or denied |

An authorization decision should be reevaluated when identity status or role assignments change.

A session that was created while an identity had a particular role should not retain that role's permissions indefinitely after the role is removed.

## 15. Performance and Operational Considerations

### Identity lookup

Hash-based indexes provide efficient identity and session retrieval.

Relational databases use unique indexes on usernames and emails.

### Permission evaluation

RBAC reduces repeated policy definitions by associating permissions with roles.

The effective permissions can be cached, but cache invalidation must occur whenever role assignments or policies change.

### Session management

Large systems should avoid scanning every session during routine authorization.

Sessions should be indexed by identity, expiration and revocation state.

Distributed deployments require a shared session-revocation strategy.

### Audit processing

In-memory audit lists are appropriate for demonstrations but are not sufficient for enterprise accounting.

Production environments should use durable event storage, retention policies and controlled archival.

### Concurrency

Concurrent identity modifications require consistent state transitions.

Production implementations should use database transactions, optimistic version checks or suitable locking.

### Scalability

Large organizations may separate IAM into independent services for:

- Identity provisioning.
- Authentication.
- Authorization.
- Session management.
- Privileged access.
- Accounting and monitoring.

These services must maintain consistent identity and authorization state.

## 16. Limitations of the Demonstrations

The implementations focus on fundamental IAM mechanisms and controlled enterprise workflows.

They do not constitute a complete production identity platform.

The following areas require additional infrastructure and integration:

| Area | Production requirement |
|---|---|
| Federated authentication | OIDC, OAuth 2.0 or SAML integration |
| MFA | Verified TOTP, WebAuthn or hardware security keys |
| Password management | Dedicated secure credential storage and recovery |
| Provisioning | Directory and HR system integration |
| Authorization | Context-aware policies and resource-level enforcement |
| Privileged access | Just-in-time elevation and approval workflows |
| Session management | Distributed revocation and refresh-token rotation |
| Accounting | Centralized durable audit infrastructure |
| Lifecycle | Automated joiner, mover and leaver workflows |
| Compliance | Retention, access reviews and evidence collection |

The in-memory implementations are single-process demonstrations. Their collections do not provide distributed consistency or durable persistence.

The PostgreSQL implementation provides relational persistence, but its authentication and session functions are intended to be called by a trusted application service.

The SQL lifecycle triggers enforce database-level consistency within the modeled schema. They do not automatically revoke credentials managed by external applications.

The JavaScript and Python examples also require production-grade MFA verification and credential-management integrations before deployment.

## 17. Execution and File Structure

The six deliverables are designed as independent implementations of the same IAM domain.

| File | Runtime | Dependencies |
|---|---|---|
| Python implementation | Python 3.10+ | Standard library |
| JavaScript implementation | Node.js 18+ | Standard library |
| C++ implementation | C++17 compiler | Standard library |
| Java implementation | Java 17 | Standard library |
| PostgreSQL implementation | PostgreSQL 14+ | `pgcrypto` extension |
| README | Markdown | None |

The PostgreSQL script uses `gen_random_uuid()` and `digest()` from PostgreSQL's `pgcrypto` extension. The extension must be available and enabled in the target database before execution.

The SQL script recreates its dedicated `iam` schema and therefore should be executed only in a database where replacing that schema is acceptable.

The source programs maintain independent demonstration state. Their identity records and sessions are not automatically synchronized with the PostgreSQL database.
