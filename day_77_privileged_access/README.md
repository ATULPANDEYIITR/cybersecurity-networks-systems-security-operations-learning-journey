# Privileged Access Management (PAM)

## 1. Domain Overview

Privileged Access Management (PAM) is a security discipline for controlling, monitoring, and governing access to administrative identities and high-impact system resources.

Privileged identities can modify infrastructure, manage databases, configure security controls, change authentication settings, administer cloud environments, and access sensitive information.

A compromised privileged identity can create significantly greater organizational risk than a compromised standard user account.

This project models an enterprise PAM environment through five independent implementations:

- Python: repository-style workflow simulation adapted to privileged identity and access management.
- JavaScript: asynchronous, event-driven policy evaluation and session orchestration.
- C++17: a repository-independent governance and merge-eligibility engine adapted to access authorization decisions.
- Java 17: enterprise domain modeling and service-oriented access governance.
- PostgreSQL: relational persistence, constraints, approval workflows, security checks, and reporting.

The central engineering objective is to ensure that privileged access is authorized, limited, traceable, and revocable.

## 2. Core Concepts

### 2.1 Privileged accounts

A privileged account is an identity with administrative or elevated permissions over a system or resource.

Examples include:

- Linux root accounts.
- Windows Domain Administrator accounts.
- Active Directory service administrators.
- PostgreSQL superuser accounts.
- Cloud organization administrators.
- Kubernetes cluster administrators.
- Firewall and network-device administrators.
- Application infrastructure administrators.
- Privileged service accounts.

A privileged account is different from an ordinary employee identity because its permissions can affect system availability, confidentiality, integrity, and security configuration.

The implementations distinguish the human requesting access from the privileged account being accessed.

This separation is important because the employee should authenticate using an individual identity while the PAM system controls access to the administrative identity.

### 2.2 Administrative accounts

Administrative accounts can be categorized according to their scope and impact.

| Account category | Typical permissions | Risk |
|---|---|---|
| Standard user | Ordinary business operations | Low |
| Elevated user | Limited administrative operations | Moderate |
| System administrator | Server and infrastructure administration | High |
| Super administrator | Broad infrastructure or organizational control | Critical |
| Service account | Automated application operations | Depends on permissions |

Service accounts require particular attention because they may operate without interactive human authentication.

Their credentials should not be shared informally or embedded in source code, configuration repositories, or deployment scripts.

### 2.3 Privileged groups

A privileged group is a collection of users authorized to request access to a defined category of administrative resources.

Examples include:

- Production Database Administrators.
- Cloud Infrastructure Administrators.
- Network Security Administrators.
- Linux System Administrators.
- Identity Management Administrators.

Group membership establishes an authorization relationship.

It does not automatically establish permission to use every privileged account in the organization.

The implementations therefore associate privileged accounts with groups and independently validate the requester's active membership.

Membership may also be restricted by validity dates and administrative approval.

### 2.4 Privilege levels

The implementations use four privilege levels:

| Level | Meaning |
|---|---|
| STANDARD | Ordinary account permissions |
| ELEVATED | Limited additional permissions |
| ADMIN | Administrative permissions |
| SUPER_ADMIN | Broad administrative authority |

Privilege levels provide a useful classification mechanism.

They are not a complete authorization policy. Actual access decisions must also consider resource scope, group membership, identity status, MFA, approvals, session duration, and organizational requirements.

## 3. Privileged Access Management Architecture

The implemented domain follows this relationship:

    User
      |
      v
    Privileged Group
      |
      v
    Group Membership
      |
      v
    Privileged Account
      |
      v
    Access Request
      |
      v
    Policy Evaluation
      |
      v
    Approval Workflow
      |
      v
    Security Checks
      |
      v
    Just-in-Time Session
      |
      v
    Credential Vault Reference
      |
      v
    Session Monitoring
      |
      v
    Termination / Revocation
      |
      v
    Audit and Reporting

Each stage represents a distinct security control.

Passing one stage does not automatically establish eligibility at every subsequent stage.

## 4. Privileged Access Governance

### 4.1 Principle of least privilege

The principle of least privilege states that users should receive only the permissions necessary to perform their authorized responsibilities.

A database operator investigating an incident may need temporary administrative access to one production database.

That requirement does not justify permanent super-administrator privileges across the entire infrastructure.

The implementations enforce least-privilege decisions through:

- Explicit group membership.
- Account-specific authorization.
- Maximum session durations.
- Identity validation.
- Approval requirements.
- Session termination.
- Credential isolation.

### 4.2 Separation of duties

Separation of duties prevents a person from exercising incompatible responsibilities within a sensitive workflow.

An employee requesting production access should not independently approve the same request.

The implementations distinguish:

- Requester: initiates access.
- Approver: evaluates and authorizes access.
- Security administrator: manages policies and privileged identities.
- Auditor: examines security events and control effectiveness.

The Python, JavaScript, C++, and Java implementations reject self-approval.

The PostgreSQL implementation enforces the same restriction through a database trigger.

This provides an important distinction between application-level validation and database-level integrity enforcement.

### 4.3 Multi-factor authentication

Multi-factor authentication requires additional authentication evidence beyond a single password.

PAM systems should require strong authentication before allowing users to request or exercise privileged access.

The implementations model MFA through an identity attribute.

An inactive or MFA-disabled identity cannot pass the configured authorization policy.

The examples simulate the MFA result. They do not implement an actual authenticator, hardware security key, biometric system, or identity-provider integration.

### 4.4 Just-in-time access

Just-in-Time (JIT) access grants privileged permissions for a limited period rather than maintaining permanent access.

A typical JIT workflow is:

1. An operator identifies a business or operational requirement.
2. The operator requests access to a specific privileged account.
3. The PAM system validates identity and group membership.
4. An authorized reviewer evaluates the request.
5. Automated security checks are evaluated.
6. The system creates a time-limited privileged session.
7. The session is monitored.
8. Access is terminated or revoked when appropriate.

The implementations enforce requested session duration against both policy and group restrictions.

For example, if an organizational policy permits 60 minutes but the privileged group permits only 45 minutes, the effective maximum is 45 minutes.

This is an intersection of permissions, not an accumulation of permissions.

## 5. Credential Isolation

Credential isolation prevents users and application components from directly accessing or distributing administrative secrets unnecessarily.

### 5.1 Credential vault

A credential vault is a protected system for managing privileged passwords, keys, certificates, and other authentication material.

The implementations model a vault using opaque references.

The application retrieves a reference identifying a credential rather than returning the raw secret.

A production architecture should separate:

- Credential storage.
- Credential encryption.
- Encryption-key management.
- Credential retrieval authorization.
- Credential rotation.
- Credential versioning.
- Credential access auditing.

### 5.2 Opaque credential references

An opaque credential reference identifies a secret stored in a separate secrets-management system.

For example:

    Account ID: ACC001
    Vault reference: vault://production/account/ACC001
    Credential version: 1

The reference does not contain the actual password.

The Python and JavaScript implementations use generated identifiers.

The C++ implementation uses an illustrative reference.

The Java implementation uses a dedicated vault interface with an isolated in-memory implementation.

The PostgreSQL database stores a vault provider and an opaque secret reference.

None of these demonstrations implements a production-grade external vault.

### 5.3 Credential rotation

Credential rotation replaces an existing credential with a new credential.

A rotation workflow should include:

- Rotation scheduling.
- Credential generation.
- Secure storage.
- Target-system update.
- Version tracking.
- Validation of the new credential.
- Recovery handling.
- Audit recording.

Rotation should be coordinated with the target system.

Updating a vault reference alone does not prove that the corresponding operating-system, database, or cloud credential has successfully changed.

The implementations track rotation timestamps and identify accounts requiring rotation.

The SQL model also maintains credential versions and rotation history.

### 5.4 Why plaintext storage is avoided

Plaintext administrative credentials in ordinary relational tables create unnecessary exposure.

Database administrators, backup operators, reporting systems, and application components may gain access to information they do not need.

The SQL implementation therefore stores only vault references.

Production systems should use an established secrets manager with encryption, access policies, key management, secure rotation, and independently protected audit records.

## 6. Access Request Lifecycle

The access request is the central workflow object.

Its lifecycle is:

    PENDING
       |
       +------> DENIED
       |
       v
    APPROVED
       |
       v
    ACTIVE
       |
       +------> EXPIRED
       |
       +------> REVOKED

An access request records:

- Requester.
- Target privileged account.
- Business justification.
- Requested session duration.
- Creation timestamp.
- Approval decisions.
- Security-check results.
- Current workflow status.

### 6.1 Pending requests

A request enters the pending state after successful initial validation.

The requester must provide a meaningful justification.

The system checks:

- User existence.
- User activation status.
- MFA status.
- Privileged group membership.
- Account availability.
- Maximum session duration.

### 6.2 Approved requests

An approval is a decision by an eligible reviewer that a particular access request satisfies the applicable authorization requirements.

Approval does not mean that an administrative session has already started.

The implementations preserve this distinction by using separate APPROVED and ACTIVE states.

### 6.3 Denied requests

A request is denied when an authorized reviewer rejects the access requirement.

A denied request must not create a privileged session.

The decision should remain available for auditing.

### 6.4 Expired requests and sessions

A session expires when its authorized duration ends.

The system must not treat an expired session as an active authorization merely because its original request was approved.

The Python, JavaScript, C++, and Java implementations check session expiry before credential-reference retrieval.

The PostgreSQL implementation provides a session-expiration procedure.

### 6.5 Revocation

Revocation is an explicit termination of previously authorized access.

Common reasons include:

- Suspected credential compromise.
- Employee termination.
- Emergency security intervention.
- Account disablement.
- Policy violation.
- Incorrect group membership.
- Completion of an operational requirement.

Revocation is distinct from normal session expiry.

Expiry follows the authorized time limit. Revocation is an intervention that terminates access before or independently of that limit.

## 7. Security Policy Evaluation

PAM decisions should be based on multiple independent conditions.

The effective access decision can be represented as:

\[
E = I \land M \land G \land A \land P \land C
\]

Where:

- \(I\): Valid and active identity.
- \(M\): Required MFA verification.
- \(G\): Authorized privileged group membership.
- \(A\): Active target account.
- \(P\): Required approval decisions.
- \(C\): Successful mandatory security checks.

A request is eligible only when all required conditions are satisfied.

### 7.1 Policy conflicts

Different organizational policies may specify different restrictions.

For example:

| Policy | Maximum session |
|---|---:|
| Organization | 60 minutes |
| Production DBA group | 45 minutes |
| Individual request | 30 minutes |

The effective session duration is:

\[
T_{\text{effective}} =
\min(T_{\text{organization}}, T_{\text{group}}, T_{\text{request}})
\]

Therefore:

\[
T_{\text{effective}} = 30 \text{ minutes}
\]

A requested duration greater than the permitted maximum is rejected.

### 7.2 Automated security checks

Automated checks evaluate conditions independently of human approval.

The implementations model checks such as:

- Identity validity.
- MFA verification.
- Account availability.
- Group membership.
- Credential-vault availability.

A check can be PENDING, PASSED, or FAILED.

An approved request with an unresolved or failed mandatory check is not eligible for session activation.

This separation prevents a human approval from automatically overriding technical security failures.

### 7.3 Concurrent sessions

Concurrent administrative sessions can complicate accountability and incident investigation.

The JavaScript, C++, and Java implementations model restrictions against concurrent sessions.

The SQL design includes a policy-controlled concurrent-session check.

Production systems should enforce this rule transactionally, including protection against concurrent requests arriving at approximately the same time.

## 8. Privileged Session Management

A privileged session is a time-bounded execution context associated with an approved access request.

The session records:

- Session identifier.
- Request identifier.
- User identity.
- Privileged account.
- Start timestamp.
- Expiry timestamp.
- Session status.
- Recording configuration.

A production PAM deployment may use a session broker or privileged access gateway to control the actual connection.

Examples include:

- SSH proxying.
- Remote desktop gateways.
- Database connection proxies.
- Kubernetes administrative gateways.
- Cloud management access brokers.

The demonstrations model authorization and session lifecycle behavior. They do not establish a real remote connection to an administrative target.

### 8.1 Session recording

Session recording captures administrative activity for accountability and investigation.

Depending on the environment, recordings may include:

- Terminal commands.
- Remote desktop activity.
- Database administration operations.
- Session metadata.
- Connection information.
- Start and termination events.

Recording metadata should be protected against unauthorized modification.

Recording alone does not guarantee complete visibility into every operation performed by a privileged identity.

### 8.2 Session termination

A session should be terminated when:

- Its permitted duration expires.
- The user finishes the task.
- An administrator revokes access.
- The underlying account becomes unavailable.
- A security event requires immediate intervention.

The implementations provide explicit session termination and revocation operations.

A production implementation must also propagate termination to the actual target connection.

## 9. Python Implementation

The Python script models the PAM domain through classes, dictionaries, dataclasses, enumerations, and custom exceptions.

### 9.1 Architecture

| Component | Responsibility |
|---|---|
| User | Human identity and MFA state |
| PrivilegedGroup | Administrative membership and limits |
| PrivilegedAccount | Target account inventory |
| AccessRequest | Authorization workflow |
| PrivilegedSession | Time-limited access state |
| CredentialVault | Opaque credential references |
| AuditService | Security event recording |
| PAMEngine | Workflow orchestration |

### 9.2 Important mechanisms

The implementation uses dictionaries for indexed object lookup.

For example, privileged accounts are indexed by account identifier.

This gives average constant-time lookup under normal hash-table assumptions.

Sets represent group membership and avoid duplicate membership entries.

Dataclasses provide structured domain objects.

Enums prevent arbitrary string values from representing workflow and privilege states.

Custom exceptions distinguish validation, authorization, credential, workflow, and resource-lookup failures.

The script also exports audit records to JSON.

### 9.3 Executable scenario

The demonstration registers:

- A database operator.
- A security approver.
- A production DBA group.
- A production PostgreSQL administrative account.

The operator requests 30 minutes of access.

The security approver authorizes the request.

The system starts a session and returns an opaque vault reference.

A self-approval attempt is rejected.

The session is terminated and an audit report is exported.

## 10. JavaScript Implementation

The JavaScript implementation emphasizes asynchronous execution, event-driven auditing, policy objects, and serialized state-changing operations.

### 10.1 Event-driven architecture

The PAM engine extends Node.js EventEmitter.

Security actions generate events such as:

- USER_REGISTERED.
- ACCESS_REQUESTED.
- REQUEST_APPROVE.
- SESSION_STARTED.
- VAULT_REFERENCE_ACCESSED.
- SESSION_REVOKED.
- ACCOUNT_DISABLED.
- CREDENTIAL_ROTATED.

The event listener collects audit records independently of the access workflow.

This separates business operations from audit-event consumption.

### 10.2 Asynchronous operations

The implementation exposes asynchronous methods returning Promises.

The private serialization mechanism prevents simultaneous state-changing operations from interleaving within the single engine instance.

It is useful for demonstrating workflow ordering.

It is not a distributed transaction mechanism.

A production deployment should use persistent storage, transactional database operations, distributed locking where necessary, and reliable event delivery.

### 10.3 Private fields and Maps

JavaScript private class fields protect internal maps and vault state from direct access through the public interface.

Maps provide efficient identifier-based retrieval.

The implementation uses a separate AccessPolicy object to centralize authorization rules.

This avoids scattering policy configuration across individual workflow methods.

## 11. C++17 Implementation

The C++ program implements a governance engine using strongly typed domain structures and explicit eligibility evaluation.

### 11.1 Domain modeling

The implementation uses:

- Structs for domain records.
- Enums for workflow states.
- Maps for indexed resources.
- Sets for membership.
- Vectors for audit events and security checks.
- Functions for policy evaluation.
- Exceptions for failed operations.

### 11.2 Governance engine

The engine evaluates:

1. Identity validity.
2. MFA requirements.
3. Group membership.
4. Account status.
5. Approval status.
6. Automated security checks.
7. Credential availability.
8. Session duration.
9. Concurrent-session restrictions.

The `evaluateMergeEligibility` operation is a policy-gate abstraction. It determines whether a request satisfies the required conditions before the session is created.

It does not implement Git or repository branch merging.

### 11.3 Failure handling

The demonstration deliberately introduces a failed credential-availability check.

The request remains ineligible even though an approver has approved it.

After the check is restored to PASSED, the engine allows session creation.

This illustrates the distinction between human authorization and independent technical eligibility.

## 12. Java 17 Implementation

The Java implementation follows an enterprise-oriented service architecture.

### 12.1 Domain structure

| Component | Responsibility |
|---|---|
| User | Immutable identity record |
| PrivilegedGroup | Group authorization |
| PrivilegedAccount | Administrative identity |
| AccessRequest | Request lifecycle |
| Approval | Individual review decision |
| ApprovalPolicy | Authorization configuration |
| StatusCheck | Technical validation |
| PrivilegedSession | Session state |
| Vault | Credential-management interface |
| AuditService | Event recording |
| AccessControlService | Business workflow |

### 12.2 Records and immutable structures

Java records represent immutable data structures such as users, approvals, status checks, and audit events.

Collections are copied when constructing relevant domain objects.

This reduces accidental changes to identity attributes and role assignments.

The implementation uses interfaces for vault abstraction.

The same application service can be connected to a different vault implementation without changing the main access-request model.

### 12.3 Service-level transactions

The AccessControlService uses a ReentrantLock around critical workflow operations.

The lock illustrates serialized approval and session-creation decisions.

It does not replace database transactions or provide distributed concurrency control.

A production service should use transaction boundaries and database-level locking for operations involving multiple application instances.

### 12.4 Approval counting

The Java implementation supports a configurable minimum approval count.

Approvals are evaluated against the current reviewer's eligibility.

The policy can therefore require multiple distinct reviewers rather than treating a single positive decision as universally sufficient.

The example configuration uses one required approval.

## 13. PostgreSQL Database Architecture

The PostgreSQL implementation provides a normalized relational model for persistent PAM governance.

### 13.1 Entity relationships

    users
      |
      +---- user_roles ---- roles
      |
      +---- group_memberships ---- privileged_groups
      |                                  |
      |                                  |
      |                         account_group_assignments
      |                                  |
      |                           privileged_accounts
      |                                  |
      |                           vault_references
      |                                  |
      |                           credential_rotations
      |
      +---- access_requests
                 |
                 +---- access_request_policies
                 |              |
                 |       approval_policies
                 |
                 +---- approvals
                 |
                 +---- security_checks
                 |
                 +---- privileged_sessions
                                |
                         session_recordings

### 13.2 Relational integrity

Primary keys identify individual records.

Foreign keys maintain relationships between identities, groups, accounts, requests, approvals, and sessions.

Unique constraints prevent duplicate usernames, role names, system accounts, memberships, and reviewer decisions.

Check constraints enforce valid durations, rotation intervals, credential versions, and time periods.

These constraints reduce the possibility of invalid records entering the database.

### 13.3 Database triggers

Three important mechanisms are implemented:

**Request status audit trigger**

Records changes to access-request status.

**Self-approval prevention trigger**

Rejects an approval when the approver is also the requester and the applicable policy prohibits self-approval.

**Approver eligibility trigger**

Requires an active user with MFA and the PAM approver role.

Triggers provide database-level enforcement, even when an operation is not initiated through the main application service.

### 13.4 Stored functions and procedures

`evaluate_request` calculates approval sufficiency and unresolved security checks.

`activate_access` performs final eligibility validation and creates a privileged session within a transaction.

`expire_sessions` identifies sessions whose permitted duration has elapsed.

`disable_account` disables an administrative account and revokes its associated active sessions.

These procedures demonstrate database-controlled workflow processing.

### 13.5 Views

| View | Purpose |
|---|---|
| `v_rotation_due` | Identifies credentials requiring rotation |
| `v_active_sessions` | Lists current privileged sessions |
| `v_access_request_report` | Combines requests, approvals, and checks |
| `v_audit_summary` | Aggregates security events |

### 13.6 Indexing

Indexes support frequent access patterns:

- Requests by requester and creation time.
- Requests by workflow status.
- Approvals by request.
- Security checks by request and status.
- Active memberships by user and group.
- Active sessions by expiry.
- Audit records by resource and timestamp.
- JSONB audit-detail searches.

Partial indexes reduce the index size for frequently queried active records.

Index design should be evaluated using actual query plans and production data distributions.

## 14. Distinguishing Important PAM Controls

The following mechanisms are related but not interchangeable.

| Mechanism | Primary responsibility |
|---|---|
| Privileged identity management | Maintains administrative identities |
| Group management | Organizes privileged membership |
| Authentication | Establishes user identity |
| MFA | Strengthens authentication |
| Authorization | Determines permitted access |
| Approval | Records an authorized access decision |
| JIT access | Limits the duration of privileged authorization |
| Credential isolation | Protects administrative secrets |
| Credential rotation | Replaces existing credentials |
| Session management | Controls active administrative sessions |
| Session recording | Captures administrative activity |
| Audit logging | Records security-relevant events |

A successful authentication does not establish privileged authorization.

An approval does not guarantee that automated security checks have passed.

A vault reference does not prove that the target system has successfully authenticated the user.

A session record does not prove that the remote connection has actually terminated.

Each mechanism addresses a different security requirement.

## 15. Security and Failure Scenarios

| Scenario | Expected control |
|---|---|
| Inactive requester | Reject access |
| MFA disabled | Reject access |
| Missing group membership | Reject access |
| Disabled privileged account | Reject access |
| Empty justification | Reject request |
| Excessive session duration | Reject request |
| Self-approval | Reject decision |
| Unauthorized approver | Reject decision |
| Failed security check | Block session creation |
| Missing vault reference | Block session creation |
| Session ownership mismatch | Reject credential-reference retrieval |
| Expired session | Terminate authorization |
| Account compromise | Revoke sessions |
| Failed credential rotation | Record failure and investigate |
| Concurrent access | Apply configured concurrency policy |

These scenarios are represented through validation logic, exception handling, database constraints, or workflow procedures.

## 16. Production Security Considerations

The implementations are executable learning models. They are not complete production PAM products.

A production deployment requires additional controls.

### Identity and authentication

- Integrate with an authoritative identity provider.
- Require phishing-resistant MFA for highly privileged operations where feasible.
- Validate identity lifecycle events.
- Apply account disablement and termination policies.
- Review privileged group membership periodically.

### Credential security

- Use a dedicated secrets-management platform.
- Encrypt credentials using managed encryption keys.
- Apply envelope encryption and key separation.
- Restrict secret retrieval to authorized session brokers.
- Rotate credentials through verified target-system operations.
- Prevent credentials from appearing in application logs.

### Session security

- Use controlled administrative gateways.
- Record privileged activity where legally and operationally appropriate.
- Enforce session expiration at the connection layer.
- Support emergency revocation.
- Monitor unusual administrative behavior.
- Protect session recordings and metadata.

### Database security

- Separate database ownership from application runtime roles.
- Apply least-privilege grants.
- Enforce TLS.
- Protect audit records against unauthorized modification.
- Use transaction isolation and row-level locking.
- Protect backup and recovery processes.
- Validate stored-procedure execution permissions.

### Operational governance

- Conduct periodic privileged-access reviews.
- Establish emergency-access procedures.
- Monitor service accounts separately.
- Maintain approval evidence.
- Review stale and unused administrative identities.
- Test credential rotation and recovery.
- Establish incident-response procedures.

## 17. Complexity and Performance

The implementations use hash-based maps and sets for resource lookup and membership checking.

| Operation | Typical implementation complexity |
|---|---|
| User lookup | O(1) average |
| Account lookup | O(1) average |
| Group membership lookup | O(1) average |
| Request insertion | O(1) average |
| Approval evaluation | O(A), where A is the number of approvals |
| Security-check evaluation | O(C), where C is the number of checks |
| Session scan | O(S), where S is the number of sessions |
| Audit export | O(E), where E is the number of events |

Database indexes improve retrieval performance for common query patterns.

The in-memory session scans are appropriate for the demonstration but should be replaced by indexed database queries for larger deployments.

Audit records should be retained and partitioned according to organizational requirements.

## 18. Execution

| File | Runtime |
|---|---|
| Python | Python 3.10 or later |
| JavaScript | Node.js 18 or later |
| C++17 | C++ compiler supporting C++17 |
| Java | JDK 17 |
| PostgreSQL | PostgreSQL 15 or later |

The Python and JavaScript implementations use only runtime standard-library capabilities.

The C++ program uses the C++17 standard library.

The Java program uses Java 17 standard-library features.

The PostgreSQL script creates its own `pam` schema and database objects. It requires permission to create schemas, types, tables, procedures, and functions.

The SQL script uses PostgreSQL's `gen_random_uuid()` function.

## 19. Technical Limitations

The following boundaries are important when interpreting the implementations:

- The vault implementations simulate credential isolation; they do not provide production encryption or secret delivery.
- MFA is represented as a verified identity attribute rather than a real authentication protocol.
- The session models do not establish actual SSH, RDP, database, or cloud connections.
- In-memory locks do not provide distributed transaction guarantees.
- Audit collections are demonstrations rather than tamper-proof audit infrastructure.
- Credential rotation tracking does not independently verify password changes on remote systems.
- Session recording metadata does not implement actual video or terminal recording.
- The C++ implementation models one approval in its demonstration workflow, while the Java implementation supports configurable multiple approvals.
- The PostgreSQL workflow demonstrates relational and procedural enforcement but still requires integration with an external identity provider, vault, and session broker.

These boundaries distinguish authorization workflow simulation from a complete privileged-access enforcement platform.
