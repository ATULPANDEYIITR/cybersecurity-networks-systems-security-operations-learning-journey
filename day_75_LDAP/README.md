# LDAP Directory Structure, Queries, Authentication and Directory Security

## 1. LDAP Fundamentals

LDAP (Lightweight Directory Access Protocol) is an application protocol for accessing and managing directory information. It provides a standardized way to locate identities, organizational information, groups, devices and application resources.

Unlike a conventional transactional database designed primarily around business records, an LDAP directory is organized around hierarchical identity information and attribute-based searches.

LDAP is commonly used for:

- Centralized user identity management
- Enterprise authentication
- Organizational directories
- Group membership management
- Application access control
- Service account management
- Centralized identity administration
- Integration with enterprise identity providers

LDAP separates directory information, authentication operations and authorization decisions. These mechanisms are related but perform different functions.

## 2. Directory Information Tree

The Directory Information Tree (DIT) is the hierarchical structure used to organize directory entries.

Each entry represents an object and contains attributes describing that object.

Example directory:

    dc=example,dc=com
    |
    +-- ou=people
    |   |
    |   +-- uid=alice
    |   +-- uid=bob
    |   +-- uid=carol
    |
    +-- ou=groups
        |
        +-- cn=administrators
        +-- cn=engineering

The tree has a root, intermediate organizational entries and leaf entries.

| Component | Meaning |
|---|---|
| `dc` | Domain Component |
| `ou` | Organizational Unit |
| `uid` | User Identifier |
| `cn` | Common Name |
| `sn` | Surname |
| `dn` | Distinguished Name |
| `rdn` | Relative Distinguished Name |

An entry's position in the tree is determined by its Distinguished Name.

### Distinguished Name

A Distinguished Name uniquely identifies an entry within the directory namespace.

Example:

`uid=alice,ou=people,dc=example,dc=com`

Its components are:

- `uid=alice`: Relative Distinguished Name.
- `ou=people`: Parent organizational unit.
- `dc=example,dc=com`: Domain hierarchy.

The DN identifies the complete directory location. The UID identifies the user attribute and is not interchangeable with the complete DN.

DN normalization requires careful handling of attribute types, escaped characters, spaces and case rules. Production implementations should use a standards-compliant DN parser rather than simple string manipulation.

## 3. LDAP Entries and Attributes

An LDAP entry contains an object identity and a collection of attributes.

Example:

| Attribute | Value |
|---|---|
| objectClass | top |
| objectClass | person |
| objectClass | inetOrgPerson |
| uid | alice |
| cn | Alice Sharma |
| sn | Sharma |
| department | Engineering |
| mail | alice@example.com |
| active | true |

LDAP attributes can contain multiple values.

For example, an employee can have multiple telephone numbers, email addresses or group memberships.

### Object Classes

Object classes define the types of entries and the attributes they can contain.

Important distinctions:

- Structural object classes define the primary type of an entry.
- Auxiliary object classes add supplementary characteristics.
- Abstract object classes provide foundational definitions.

The Python, JavaScript, C++17 and Java implementations model object classes as directory attributes. The PostgreSQL implementation stores them in an array associated with each directory entry.

The examples use common LDAP object class names, but do not implement complete LDAP schema validation.

## 4. LDAP Queries and Search Operations

LDAP searches identify entries using a search base, scope and filter.

A search operation generally consists of:

1. Selecting the search base.
2. Selecting the search scope.
3. Providing an LDAP filter.
4. Selecting requested attributes.
5. Applying result limits.
6. Processing matching entries.

### Search scopes

| Scope | Behavior |
|---|---|
| Base | Searches only the specified entry |
| One-level | Searches immediate children |
| Subtree | Searches the base and all descendants |

Example search base:

`ou=people,dc=example,dc=com`

A one-level search finds Alice, Bob and Carol when they are direct children of this organizational unit.

A subtree search also considers entries in nested organizational units.

### LDAP Filter Syntax

LDAP filters use a parenthesized expression format.

| Filter | Purpose |
|---|---|
| `(uid=alice)` | Exact attribute match |
| `(uid=*)` | Attribute presence |
| `(&(department=Engineering)(active=true))` | Logical AND |
| `(|(uid=alice)(uid=bob))` | Logical OR |
| `(!(active=false))` | Logical NOT |

A filter determines which entries match. It does not determine which attributes the requester is authorized to read.

This distinction is essential for secure directory implementations.

### Filter Security

LDAP filter values must be escaped according to LDAP filter encoding rules.

The special characters include:

- `*`
- `(`
- `)`
- `\`
- NUL

Unescaped user input can alter filter semantics and produce LDAP injection vulnerabilities.

The sample implementations support a deliberately restricted equality-filter grammar. They are educational evaluators rather than complete RFC 4515 parsers.

Production implementations should use a mature LDAP library and parameter-safe filter construction.

### Search Performance

Directory searches can become expensive when the directory contains millions of entries.

Important performance controls include:

- Indexing frequently searched attributes.
- Restricting the search base.
- Selecting an appropriate scope.
- Limiting returned attributes.
- Applying server-side result limits.
- Using paged-results controls.
- Monitoring search execution time.
- Avoiding unbounded wildcard searches.

The PostgreSQL implementation uses indexes on attribute names and normalized values to support attribute-based retrieval.

## 5. LDAP Authentication

Authentication establishes whether an identity can successfully authenticate.

LDAP commonly performs authentication through the Bind operation.

The client supplies a bind identity and credentials. The directory server validates those credentials and returns an authentication result.

### Bind Authentication Workflow

    Client
      |
      v
    Establish LDAP connection
      |
      v
    Establish TLS protection
      |
      v
    Submit Bind Request
      |
      v
    Locate directory identity
      |
      v
    Validate credentials
      |
      +------ Invalid ------> Reject authentication
      |
      +------ Valid --------> Establish authenticated connection

The implementations demonstrate:

- Identity lookup through DN.
- Password verification.
- Authentication success.
- Authentication failure.
- Failed-attempt counting.
- Account lockout.
- Account reset.
- Authentication auditing.

### Simple Bind and SASL

LDAP supports different authentication mechanisms.

**Simple Bind**

Uses a DN and password. It must be protected by TLS to prevent credentials from being exposed during transmission.

**SASL Bind**

Uses the Simple Authentication and Security Layer to support authentication mechanisms beyond simple username and password submission.

The actual mechanism depends on the server, client and enterprise authentication configuration.

### Password Storage

Passwords must never be stored as plaintext.

The Python and JavaScript implementations use PBKDF2-HMAC-SHA256 with random salts.

The Java implementation uses Java's standard cryptographic APIs and `PBKDF2WithHmacSHA256`.

The C++ demonstration uses an explicitly identified placeholder verifier for illustrating authentication state transitions. It is not a production password-storage implementation.

The PostgreSQL schema stores a verifier reference and algorithm designation. Its authentication functions record outcomes but deliberately do not verify passwords.

Production systems should use:

- A modern password hashing scheme.
- Unique cryptographic salts.
- Appropriate work factors.
- Secure credential transport.
- Protected password-reset procedures.
- Credential rotation.
- Constant-time verification where applicable.
- Restricted access to authentication data.

PBKDF2 parameters must be selected and periodically reviewed according to the organization's security requirements.

## 6. Account Management and Lockout

Authentication security requires more than password verification.

An account can have several states:

| State | Meaning |
|---|---|
| Active | Authentication is permitted |
| Locked | Authentication is temporarily or administratively blocked |
| Disabled | Authentication is prohibited |
| Pending | Account activation is incomplete |

The implementations track failed attempts and lock accounts after a configured threshold.

The Python, JavaScript, C++17 and Java examples use five failed attempts as the demonstration threshold.

The PostgreSQL implementation maintains:

- Failed authentication count.
- Maximum permitted failures.
- Lock expiration.
- Account status.
- Last successful login.
- Authentication audit records.

An operational lockout policy should include recovery procedures, monitoring and protection against denial-of-service attacks caused by deliberate account-locking attempts.

Temporary lockouts, rate limiting and adaptive authentication can be combined to reduce this risk.

## 7. Directory Security and Access Control

Directory security controls who can authenticate, access entries, read attributes and modify directory information.

Authentication and authorization are separate decisions.

Authentication answers:

*Who has successfully authenticated?*

Authorization answers:

*What is that authenticated identity allowed to do?*

### Role-Based Access Control

The implementations demonstrate role-based access control (RBAC).

| Role | Read | Search | Write | Delete |
|---|---|---|---|---|
| Administrator | Yes | Yes | Yes | Yes |
| Directory Manager | Yes | Yes | Yes | No |
| Employee | Yes | Yes | No | No |
| Service Account | Yes | Yes | No | No |

A successful Bind operation does not automatically grant administrative permissions.

The application must evaluate the authenticated identity's permissions before performing sensitive operations.

### Attribute-Level Security

Not every attribute should be available to every requester.

Sensitive attributes may include:

- Authentication verifiers.
- Personal contact information.
- Employment information.
- Security-related group memberships.
- Account recovery information.

The Python and JavaScript examples restrict modification of protected attributes such as `objectClass` and `userPassword`.

A production LDAP directory should implement access control lists (ACLs) that define permissions at the appropriate directory, entry and attribute levels.

### Transport Security

LDAP security depends on protecting communication between clients and directory servers.

Two commonly used approaches are:

| Mechanism | Purpose |
|---|---|
| LDAPS | LDAP over TLS, conventionally on port 636 |
| StartTLS | Upgrades an LDAP connection to TLS, commonly on port 389 |

Certificate validation, trusted certificate authorities and secure TLS configurations are necessary.

Unprotected simple binds should not be permitted.

### Additional Security Controls

- Disable anonymous access where inappropriate.
- Restrict administrative accounts.
- Apply least-privilege permissions.
- Protect service account credentials.
- Monitor failed Bind operations.
- Audit directory modifications.
- Restrict network access.
- Review group memberships.
- Apply account lifecycle policies.
- Protect backups and replication traffic.
- Monitor directory server configuration changes.

## 8. Python Implementation

The Python implementation provides a complete in-memory directory simulation.

### Main Components

| Component | Responsibility |
|---|---|
| `DirectoryEntry` | Stores DN and multivalued attributes |
| `LDAPFilter` | Parses and evaluates restricted LDAP filters |
| `PasswordManager` | Generates and verifies PBKDF2 password hashes |
| `AccessController` | Evaluates role permissions |
| `LDAPDirectory` | Manages entries, searches and authentication |
| `SearchResult` | Represents selected search results |
| `AccountStatus` | Represents account lifecycle states |
| `Scope` | Defines search scope |

### Important Mechanisms

The directory uses a dictionary indexed by normalized DN.

This provides average constant-time entry lookup under normal hash-table conditions.

The filter parser creates a tree representation of AND, OR, NOT and equality operations.

The evaluator recursively processes the expression against directory attributes.

Authentication uses salted password derivation and constant-time digest comparison.

The directory also provides attribute modification, deletion restrictions, account reset and audit records.

### Executable Scenarios

The demonstration includes:

- Directory creation.
- Organizational unit creation.
- Employee entry creation.
- Engineering department searches.
- One-level searches.
- Successful Bind authentication.
- Failed authentication.
- Attribute modification.
- Unauthorized modification.
- Invalid filter handling.
- Search assertions.

## 9. JavaScript Implementation

The JavaScript implementation uses an event-driven architecture.

Its primary distinction is the separation of directory operations from event processing.

### Main Components

| Component | Responsibility |
|---|---|
| `LDAPDirectory` | Directory operations and state |
| `DirectoryEntry` | Entry attributes and account state |
| `LDAPFilter` | Filter parsing and evaluation |
| `PasswordService` | Asynchronous password derivation |
| `AccessPolicy` | Permission evaluation |
| `EventEmitter` | Directory event notification |

### Asynchronous Authentication

Node.js cryptographic password derivation is performed asynchronously through `crypto.pbkdf2`.

This avoids performing the password derivation synchronously on the main JavaScript execution thread.

The Bind operation returns a Promise and rejects unsuccessful authentication attempts.

### Event-Driven Auditing

Directory operations emit events such as:

- ADD
- MODIFY
- BIND
- SEARCH
- PASSWORD_CHANGE
- ACCOUNT_RESET

An audit listener receives structured events without requiring each business operation to implement its own reporting interface.

This architecture is useful when directory activity must trigger monitoring, security notifications or additional application workflows.

## 10. C++17 Implementation

The C++ implementation emphasizes domain modeling and policy evaluation.

It includes both a directory engine and a repository-governance example to demonstrate structured evaluation of independent policy conditions.

### Directory Components

| Component | Responsibility |
|---|---|
| `DirectoryEntry` | Directory identity and attributes |
| `FilterParser` | LDAP filter parsing |
| `Directory` | Entry management and search |
| `SearchResult` | Search response |
| `AccountStatus` | Authentication state |
| `SearchScope` | Search boundaries |

The directory stores entries in an ordered STL map.

This provides logarithmic lookup and ordered iteration, with different performance characteristics from the hash-based Python and JavaScript implementations.

### Governance Evaluation

The governance engine evaluates several independent conditions:

- Pull Request state.
- Source and target branches.
- Proposed commits.
- Review eligibility.
- Stale approvals.
- Required status checks.
- Unresolved conversations.
- Base branch synchronization.
- Merge conflicts.

The `BranchProtection` structure defines repository-level enforcement conditions.

The `GovernanceEngine` evaluates the complete Pull Request and produces specific reasons when merging is blocked.

This illustrates an important architectural distinction: individual review decisions and automated status results are inputs to a separate merge-eligibility decision.

The C++ implementation is an educational simulation, not an LDAP network server or a production cryptographic authentication service.

## 11. Java 17 Implementation

The Java implementation emphasizes enterprise-oriented domain modeling and explicit service boundaries.

### Directory Architecture

| Component | Responsibility |
|---|---|
| `DN` | Distinguished Name validation |
| `DirectoryEntry` | Immutable attribute representation |
| `Credentials` | Password verification data |
| `PasswordService` | PBKDF2 operations |
| `AccessPolicy` | Role-based authorization |
| `LDAPFilter` | Search filter evaluation |
| `DirectoryService` | Directory management |
| `AuditEvent` | Structured security events |

Java records represent immutable value objects such as search results, credentials and audit events.

Collections are used to separate directory entries, attributes, roles and permissions.

`ConcurrentHashMap` provides concurrent directory lookup, while synchronization protects authentication state transitions for individual accounts.

The attribute-update operation constructs a replacement entry rather than modifying the original immutable attribute map.

The replacement is applied through a conditional map operation to reduce the possibility of overwriting concurrent updates.

### Enterprise Merge Eligibility

The Java implementation also defines an enterprise policy service using:

- `BranchProtection`
- `Review`
- `StatusCheck`
- `PullRequest`
- `Eligibility`
- `EligibilityPolicy`
- `MergeEligibilityService`

The policy service returns both an eligibility decision and the violations that prevent merging.

This separates policy definition, domain data and policy evaluation.

## 12. PostgreSQL Directory Model

The PostgreSQL implementation uses a relational representation of directory information.

It is not a replacement for an LDAP protocol server. It provides persistent relational storage for directory-oriented application workflows.

### Database Relationship

    Organizational Units
          |
          v
    Directory Entries
          |
          +------ Directory Attributes
          |
          +------ Identity Accounts
                        |
                        +------ Account Roles
                        |
                        +------ Authentication Audit

    Directory Roles
          |
          +------ Role Permissions
                        |
                        +------ Directory Permissions

### Core Tables

| Table | Purpose |
|---|---|
| `organizational_units` | Organizational hierarchy |
| `directory_entries` | Distinguished Names and entry metadata |
| `directory_attributes` | Multivalued directory attributes |
| `identity_accounts` | Authentication account state |
| `directory_roles` | Application roles |
| `directory_permissions` | Individual permissions |
| `role_permissions` | Role-to-permission mapping |
| `account_roles` | Account-to-role mapping |
| `directory_audit` | Security and operational audit records |

### Relational Design Decisions

The implementation separates directory entries from their attributes.

This allows one directory entry to have multiple values for an attribute without requiring a separate database column for every possible LDAP attribute.

Primary keys establish record identity.

Foreign keys enforce relationships between directory entries, accounts, organizational units and permission assignments.

Check constraints validate important attribute and account conditions.

Indexes support DN hierarchy retrieval, account-state queries and attribute searches.

The recursive CTE reconstructs the Directory Information Tree from parent-child relationships.

### Database Functions

The SQL implementation includes functions for:

- Authentication failure recording.
- Authentication success recording.
- Temporary account lockout.
- Expired lockout recovery.
- Directory searches.
- Directory hierarchy validation.
- Entry timestamp management.

The search function accepts a base DN, scope, attribute name and exact value.

It does not execute dynamically constructed SQL from user-provided LDAP filters.

The authentication functions update authentication state and audit events. Password verification remains the responsibility of a trusted application authentication service.

## 13. Important Distinctions

LDAP directory operations should not be confused with the broader identity and access management processes that use them.

| Concept | Responsibility |
|---|---|
| Directory structure | Organizes identity information |
| Distinguished Name | Identifies an entry |
| Attribute | Describes an entry |
| Search filter | Selects matching entries |
| Bind authentication | Validates an identity's credentials |
| Authorization | Determines permitted operations |
| Access control | Enforces access restrictions |
| Account lockout | Restricts authentication after failures |
| Audit logging | Records security-relevant activity |
| TLS | Protects communication |

A successful search does not prove that the requester is authorized to read every matching attribute.

A successful Bind does not establish permission to modify the directory.

An account's active status does not automatically grant access to protected resources.

These decisions require separate controls.

## 14. Standards and Implementation Limitations

The implementations deliberately provide a restricted LDAP model for executable learning.

They do not implement the complete LDAP protocol or all LDAP standards.

Important limitations include:

- No LDAP network listener.
- No LDAP BER encoding or decoding.
- No complete RFC 4514 DN parser.
- No complete RFC 4515 filter parser.
- No complete LDAP schema engine.
- No LDAP referral processing.
- No LDAP replication.
- No SASL implementation.
- No production LDAP ACL engine.
- No complete LDAP paging protocol.
- No production-grade distributed account-lockout service.

A production deployment should use a standards-compliant directory server and client library.

The simplified directory simulations demonstrate the underlying concepts and should not be exposed directly as production authentication infrastructure.

## 15. Execution Requirements

| Deliverable | Runtime | Dependencies |
|---|---|---|
| Python | Python 3.10+ | Standard library |
| JavaScript | Node.js 18+ | Standard library |
| C++17 | C++17 compiler | Standard library |
| Java | Java 17 | Standard library |
| PostgreSQL | PostgreSQL 15+ | Standard database features |

### Python

The Python script can be executed directly with the Python interpreter.

### JavaScript

The JavaScript implementation uses Node.js cryptographic and event modules.

### C++17

The C++ program requires a compiler supporting the C++17 standard.

### Java 17

The Java program uses the Java cryptography APIs and Java 17 language features.

### PostgreSQL

The SQL script creates the `ldap_directory` schema and its tables, constraints, indexes, triggers, functions, views and demonstration records.

Run the script in a database where the executing role has the required schema and object-creation privileges.

The script uses a transaction for its database setup and sample operations.

## 16. Practical Engineering Considerations

A production LDAP-based identity system requires coordinated controls across the directory server, authentication service, application and database.

Important engineering decisions include:

- Use standards-compliant DN and filter parsing.
- Enforce TLS certificate validation.
- Avoid plaintext credential storage.
- Separate authentication from authorization.
- Apply least-privilege access policies.
- Restrict sensitive attributes.
- Monitor account lockouts.
- Audit privileged modifications.
- Protect service account credentials.
- Apply safe search limits.
- Index frequently accessed attributes.
- Protect concurrent account-state updates.
- Define credential recovery procedures.
- Monitor directory availability and replication health.

The implementations demonstrate how directory structure, search, authentication, authorization, persistent storage and security auditing can be modeled as separate but coordinated engineering responsibilities.
