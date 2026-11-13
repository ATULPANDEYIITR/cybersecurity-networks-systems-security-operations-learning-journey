# Kerberos Authentication: Tickets, TGT, Service Tickets, KDC and Authentication Flow

## 1. Technical Overview

Kerberos is a network authentication protocol that uses symmetric cryptography and a trusted third party to authenticate users and services across an insecure network.

Its central security objective is to establish authenticated identities without repeatedly transmitting user passwords to individual application services.

Kerberos uses tickets, time-based authentication, session keys and a centralized Key Distribution Center (KDC).

The implementation models the following authentication architecture:

- Client: Requests authentication and obtains tickets.
- Authentication Server (AS): Verifies the client and issues a Ticket Granting Ticket.
- Ticket Granting Server (TGS): Validates the TGT and issues service-specific tickets.
- Key Distribution Center (KDC): Maintains principal information and coordinates authentication.
- Service Server: Validates service tickets and authenticates clients.
- Realm: Administrative authentication domain.
- Principal: Identity of a user, service or KDC component.

The five implementations provide complementary models of ticket issuance, ticket validation, authentication policy, service access, replay detection and audit management.

## 2. Kerberos Architecture

### Key Distribution Center

The KDC is the trusted authentication authority within a Kerberos realm.

It consists of two logical services:

| Component | Responsibility |
|---|---|
| Authentication Server | Initial client authentication and TGT issuance |
| Ticket Granting Server | Service-ticket issuance |
| Principal database | Stores registered identities and authentication information |
| Key management | Maintains long-term keys and key versions |
| Authentication audit | Records authentication decisions |

The KDC relies on long-term symmetric keys shared with the relevant principals.

The client and each service also receive temporary session keys for individual authentication relationships.

### Principal Naming

Kerberos identities use principal names.

Examples:

- `alice@EXAMPLE.LOCAL`
- `http/web.example.local`
- `postgres/db.example.local`
- `krbtgt/EXAMPLE.LOCAL`

A user principal identifies a human or application identity.

A service principal identifies a network service. The service name commonly contains a service type and hostname.

The realm identifies the administrative authentication domain.

Principal names must be managed consistently because service identity and realm information participate in ticket validation.

## 3. Kerberos Tickets

A ticket is a protected data structure issued by the KDC. It establishes that a trusted authority has authenticated an identity and authorized the use of a particular authentication relationship.

A ticket contains information such as:

- Client principal.
- Service principal, where applicable.
- Realm.
- Session key.
- Ticket validity period.
- Ticket flags.
- Encryption type.
- Ticket-specific metadata.

The service does not simply trust a client-supplied identity. It validates the ticket using its own long-term key.

### Ticket Granting Ticket

A Ticket Granting Ticket (TGT) is issued by the Authentication Server.

Its purpose is to allow a successfully authenticated client to request service tickets without repeatedly presenting its password.

The TGT is intended for the Ticket Granting Server, not ordinary application services.

Its principal relationship is:

`Client → Authentication Server → TGT → Ticket Granting Server`

The TGT is protected using a key associated with the TGS.

### Service Ticket

A service ticket authorizes an authentication attempt against a particular service principal.

For example:

- `http/web.example.local`
- `postgres/db.example.local`

The service ticket is protected using the long-term key associated with the target service.

The target service validates the ticket and uses the session key to verify the client authenticator.

A service ticket is not interchangeable with a TGT.

| Property | TGT | Service ticket |
|---|---|---|
| Issued by | AS | TGS |
| Intended recipient | TGS | Target service |
| Protected using | TGS long-term key | Service long-term key |
| Identifies | Client and realm | Client and specific service |
| Main purpose | Obtain service tickets | Authenticate to a service |
| Session key | Client-TGS session key | Client-service session key |

### Session Keys

Session keys are temporary symmetric keys established during ticket issuance.

The two principal relationships are:

1. Client and TGS session key.
2. Client and service session key.

A service session key is distinct from the user's long-term password-derived key and the service's long-term key.

Session keys should be protected in memory, transmitted only through protected protocol structures and discarded when no longer needed.

## 4. Kerberos Authentication Flow

The protocol separates initial authentication from subsequent service authentication.

<text />

### Stage 1: Initial Authentication

The client begins by requesting authentication from the Authentication Server.

The logical exchange is:

`Client → AS: AS-REQ`

The request identifies the client principal and includes the necessary pre-authentication information when required by the realm's policy.

The AS verifies the client's identity and authentication material.

When authentication succeeds, the AS returns:

`AS → Client: AS-REP`

The response provides the client with a TGT and the associated client-TGS session key.

The TGT itself is protected for the TGS.

The client does not need to disclose its password to each application service.

### Stage 2: Requesting a Service Ticket

When the client needs a service, it requests a service ticket from the TGS.

`Client → TGS: TGS-REQ`

The request contains:

- Existing TGT.
- Requested service principal.
- Authenticator protected using the client-TGS session key.
- Relevant protocol options.

The TGS validates the TGT, verifies the authenticator, checks ticket validity and evaluates the requested service.

If the request succeeds:

`TGS → Client: TGS-REP`

The response contains the service ticket and the client-service session key.

The service ticket is protected using the target service's long-term key.

### Stage 3: Service Authentication

The client presents the service ticket to the target application.

`Client → Service: AP-REQ`

The AP-REQ contains the service ticket and an authenticator.

The service:

1. Identifies its own service principal.
2. Decrypts and validates the ticket.
3. Checks the client and service identities.
4. Extracts the client-service session key.
5. Validates the authenticator.
6. Checks timestamps and replay conditions.
7. Accepts or rejects the authentication request.

The client has now authenticated to the requested service.

### Stage 4: Mutual Authentication

Some applications require the service to demonstrate its own identity to the client.

The service can return:

`Service → Client: AP-REP`

The response proves possession of the appropriate session key.

The client verifies the response.

Mutual authentication reduces the risk of a client accepting an unauthenticated or impersonated service.

### Complete Authentication Sequence

`CLIENT`
  |
  | AS-REQ
  v
`AUTHENTICATION SERVER`
  |
  | Verify initial credentials
  | Generate client-TGS session key
  | Issue TGT
  v
`CLIENT`
  |
  | TGS-REQ + TGT + Authenticator
  v
`TICKET GRANTING SERVER`
  |
  | Validate TGT
  | Validate Authenticator
  | Generate client-service session key
  | Issue Service Ticket
  v
`CLIENT`
  |
  | AP-REQ + Service Ticket + Authenticator
  v
`APPLICATION SERVICE`
  |
  | Validate ticket and authenticator
  | Optional AP-REP
  v
`AUTHENTICATED SESSION`

## 5. Pre-Authentication

Pre-authentication is an important defense against unauthorized ticket issuance and offline password attacks.

The client supplies authentication information that demonstrates knowledge of the appropriate credentials.

A common Kerberos mechanism is timestamp-based encrypted pre-authentication.

The KDC verifies the pre-authentication information before issuing the initial authentication response.

Without suitable pre-authentication controls, an attacker may obtain encrypted responses that facilitate offline password guessing.

Pre-authentication policies should be enforced consistently across user principals.

The Python, JavaScript and Java educational models verify password-derived material before issuing a TGT. They do not implement the complete RFC 4120 pre-authentication exchange.

## 6. Cryptographic Protection

Kerberos uses symmetric cryptography because the KDC and participating principals maintain trusted long-term keys.

Important cryptographic relationships include:

| Key | Purpose |
|---|---|
| Client long-term key | Protects client authentication material |
| TGS long-term key | Protects TGT contents |
| Service long-term key | Protects service-ticket contents |
| Client-TGS session key | Protects communication related to TGS requests |
| Client-service session key | Protects client-service authentication |

### Encryption and Integrity

Encryption protects ticket confidentiality.

Integrity protection detects unauthorized modification.

These are related but distinct security properties.

A ticket must not be trusted merely because its contents can be decoded or its structure appears valid.

The actual Kerberos protocol uses supported encryption types and cryptographic checksums according to its negotiated cryptographic configuration.

### Important Implementation Distinction

The Python, JavaScript and Java implementations use HMAC-SHA256 to demonstrate ticket integrity and authenticator verification.

Their ticket payloads are encoded for transport but are not encrypted.

Base64 encoding does not provide confidentiality.

The C++ implementation concentrates on domain modeling and ticket lifecycle management rather than production cryptography.

The PostgreSQL implementation stores ticket metadata and simulated signatures, not decrypted production ticket contents.

These implementations are educational models and are not substitutes for an interoperable Kerberos implementation.

## 7. Ticket Lifecycle and Validation

A ticket has a defined lifetime.

The lifecycle involves:

`ISSUED → VALIDATED → USED → EXPIRED`

A ticket may also be rejected or administratively invalidated.

### Ticket Expiration

Every ticket has an issue time and expiration time.

The service must reject an expired ticket.

Service tickets should not remain valid beyond the lifetime of the TGT from which they were issued when the relevant policy requires this relationship.

The implementations validate:

- Issuance timestamp.
- Expiration timestamp.
- Ticket type.
- Client identity.
- Service identity.
- Parent TGT relationship.
- Realm consistency.

### Ticket Renewal

Kerberos supports renewable tickets under defined protocol conditions.

A renewable ticket includes a renewable-until time.

Renewal does not mean that an expired ticket can be extended indefinitely.

The renewal request must be validated by the KDC, and renewal must comply with the relevant lifetime and policy restrictions.

The SQL schema includes a `renewable_until` field for lifecycle representation. The example programs do not implement the complete renewable-ticket protocol.

### Ticket Revocation

Kerberos tickets are generally self-contained and have limited validity periods.

Immediate revocation is not equivalent to changing a database status.

A production deployment may use account disabling, key rotation, short ticket lifetimes, service-side authorization checks and other operational controls.

The database includes a ticket status field to represent administrative lifecycle states.

## 8. Replay Protection and Clock Synchronization

### Replay Attacks

A replay attack occurs when an attacker captures a previously valid authentication message and attempts to submit it again.

An authenticator is designed to make this harder by including fresh, time-sensitive information protected using the appropriate session key.

Replay protection uses:

- Ticket identity.
- Authenticator timestamp.
- Nonce or other unique request information.
- Clock tolerance.
- Replay cache.

The implementations maintain a replay cache containing previously accepted ticket-authenticator combinations.

Repeated authenticators are rejected.

### Clock Synchronization

Kerberos relies on time-based authentication.

A large difference between client and server clocks can cause legitimate authentication attempts to fail.

Administrators should maintain reliable time synchronization across:

- Domain controllers.
- KDC servers.
- Application servers.
- Client systems.

Clock tolerance must balance operational reliability and security.

Increasing the tolerance unnecessarily increases the period in which certain captured authentication messages may remain useful.

## 9. Code Implementation: Python

**File:** `kerberos_authentication.py`

The Python implementation provides an executable end-to-end authentication simulation.

### Main components

| Component | Implementation responsibility |
|---|---|
| `Principal` | Represents a registered identity |
| `TicketCodec` | Creates and validates signed ticket envelopes |
| `ReplayCache` | Prevents repeated authenticator acceptance |
| `KerberosKDC` | Coordinates AS and TGS operations |
| `KerberosClient` | Obtains TGTs and accesses services |
| `AuthenticationSession` | Maintains client authentication state |
| `AuditEvent` | Records authentication operations |

### Implementation mechanisms

The password verifier uses PBKDF2-HMAC-SHA256 with a unique random salt.

The TGT is signed using the KDC's TGS key.

A service ticket is signed using the corresponding service key.

The client obtains a separate session key for each requested service.

The authenticator uses HMAC-SHA256 to verify the client-service relationship.

The implementation uses constant-time signature comparison through `hmac.compare_digest`.

### Demonstrated operations

- Principal registration.
- Service registration.
- Initial client authentication.
- TGT issuance.
- Service-ticket issuance.
- Service authentication.
- Server proof verification.
- Invalid-password rejection.
- Authenticator replay rejection.
- Authentication auditing.

### Performance characteristics

Dictionary-based principal and service lookup provides expected O(1) lookup time.

Replay-cache lookup uses a dictionary.

Ticket processing is dominated by cryptographic operations and serialization.

The in-memory audit list is appropriate for a demonstration but should be replaced with durable and access-controlled audit storage in an operational deployment.

## 10. Code Implementation: JavaScript

**File:** `kerberos_authentication.js`

The JavaScript implementation emphasizes asynchronous identity management and event-driven authentication.

### Main components

| Component | Responsibility |
|---|---|
| `Principal` | Identity and role representation |
| `TicketPolicy` | Ticket lifetime and clock validation |
| `ReplayProtection` | Duplicate authenticator detection |
| `KeyDistributionCenter` | AS and TGS processing |
| `KerberosClient` | Client authentication and service access |
| `EventEmitter` | Authentication event publication |

### JavaScript-specific design

The implementation uses Node.js cryptographic capabilities rather than external packages.

Password verification uses asynchronous `crypto.scrypt`.

The KDC publishes events for:

- Principal registration.
- Service registration.
- TGT issuance.
- Service-ticket issuance.
- Successful service authentication.

`Map` provides principal and service lookup.

A separate replay-protection map tracks previously accepted authenticators.

Promises allow the initial authentication operation to perform asynchronous password derivation.

The implementation validates ticket structures, service identity, timestamp boundaries and authenticator signatures.

The event-driven design separates authentication processing from audit consumers.

### Practical considerations

Event listeners should not be allowed to interfere with critical authentication decisions.

Production systems should avoid exposing session keys in application logs or untrusted event payloads.

Long-lived service keys require controlled rotation and secure storage.

## 11. Code Implementation: C++17

**File:** `kerberos_authentication.cpp`

The C++ implementation concentrates on explicit domain modeling and authentication-state management.

### Domain structures

| Structure | Purpose |
|---|---|
| `Principal` | Represents an authenticated identity |
| `Service` | Represents a registered service |
| `Ticket` | Represents TGT or service-ticket metadata |
| `Authenticator` | Represents time-sensitive client authentication |
| `Policy` | Defines ticket lifetime and clock tolerance |
| `AuditRecord` | Captures authentication decisions |

### Architecture

`KeyDistributionCenter` maintains principal, service and ticket registries.

`ReplayCache` manages accepted authenticator identifiers.

`KerberosClient` performs initial authentication and requests service access.

### Design decisions

The implementation uses:

- `unordered_map` for principal, service and ticket lookup.
- `vector` for audit history.
- `optional` for client TGT state.
- `enum class` for strongly typed ticket and authentication states.
- `chrono` for timestamp and lifetime management.
- Exceptions for rejected authentication operations.

The C++ implementation deliberately models ticket lifecycle and service authorization decisions without introducing external cryptographic dependencies.

Its credential verifier is an educational comparison value, not a secure password-storage design.

### Complexity

| Operation | Expected complexity |
|---|---|
| Principal lookup | O(1) |
| Service lookup | O(1) |
| Ticket lookup | O(1) |
| Ticket issuance | O(1) average |
| Replay-cache lookup | O(1) average |
| Audit traversal | O(n) |

The replay-cache cleanup operation is O(n) in the number of stored entries.

A high-volume production system would use expiry-aware cache structures to avoid unnecessary full scans.

## 12. Code Implementation: Java 17

**File:** `KerberosEnterprise.java`

The Java implementation presents an enterprise-oriented authentication architecture.

### Domain types

Java records represent immutable values:

- `Ticket`
- `Authenticator`
- `AuditRecord`
- `TicketPolicy`

Enums represent ticket types, principal states, session states and audit operations.

The `Principal` and `ServicePrincipal` classes encapsulate identity-specific information.

### Enterprise components

`KeyDistributionCenter` owns the principal and service registries.

`AuthenticationSession` manages client authentication transitions.

`ReplayCache` uses concurrent collections to prevent duplicate authenticator acceptance.

`CryptoSupport` centralizes password derivation, HMAC generation and secure random identifier creation.

### State transitions

`CREATED → AUTHENTICATED → SERVICE_AUTHENTICATED`

An unsuccessful initial authentication transitions to `REJECTED`.

An invalid transition is rejected instead of silently continuing.

### Concurrency considerations

The implementation uses concurrent maps for principal, service and ticket registries.

An atomic reference manages authentication-session state.

Audit records use synchronized access.

The replay cache uses `putIfAbsent` to ensure that concurrent requests cannot both accept the same ticket-nonce combination.

The implementation is appropriate for studying enterprise domain boundaries and concurrent authentication state.

## 13. Code Implementation: PostgreSQL

**File:** `kerberos_authentication.sql`

The database implementation models the persistent information required by a Kerberos-oriented authentication service.

### Relational model

| Table | Purpose |
|---|---|
| `realms` | Authentication domains |
| `principals` | User, service and KDC identities |
| `principal_roles` | Identity-role relationships |
| `principal_keys` | Long-term key metadata |
| `service_principals` | Registered network services |
| `authentication_sessions` | Client authentication sessions |
| `tickets` | TGT and service-ticket metadata |
| `authentication_attempts` | AS, TGS and service outcomes |
| `authenticators` | Authenticator metadata and replay protection |
| `service_access_events` | Service authentication results |
| `kdc_audit` | Security and operational events |

### Referential integrity

Foreign keys connect:

- Principals to realms.
- Service principals to principals.
- Tickets to client principals.
- Service tickets to service principals.
- Service tickets to their parent TGTs.
- Tickets to authentication sessions.
- Authenticators to tickets.
- Service access records to tickets and principals.

The ticket validation trigger prevents a service ticket from referring to an unrelated TGT.

It also checks that a service ticket does not outlive its parent TGT.

### Replay protection

The `authenticators` table enforces uniqueness through:

`UNIQUE (ticket_id, nonce)`

The `accept_authenticator()` function checks:

- Ticket existence.
- Ticket status.
- Ticket expiration.
- Timestamp tolerance.
- Nonce validity.
- Signature presence.
- Duplicate authenticator submission.

The database constraint provides atomic duplicate detection under concurrent insertion.

It does not independently verify the cryptographic HMAC. That verification belongs in the trusted authentication service.

### Eligibility evaluation

`service_ticket_eligibility()` evaluates whether a TGT can be used to request a particular service ticket.

It checks:

- TGT existence.
- TGT type.
- Ticket status.
- Ticket expiration.
- Principal status.
- Service availability.

`issue_service_ticket()` performs ticket issuance inside a database transaction.

### Reporting

The SQL script includes queries for:

- Principal and role retrieval.
- Ticket inventory.
- Service-ticket eligibility.
- Ticket-parent relationship validation.
- Authentication success rates.
- Expiring tickets.
- Service-access aggregation.
- Authentication timelines.
- Failed authentication analysis.
- KDC audit history.
- Authentication performance.

Indexes support common principal, ticket, service and audit queries.

## 14. Kerberos Security Controls

Kerberos security depends on correct implementation, configuration and key management.

### Credential Protection

User passwords should never be transmitted repeatedly to individual application services.

Password verifiers should use appropriate salted, computationally expensive password derivation.

Production Kerberos should use protocol-supported pre-authentication mechanisms.

### Long-Term Key Management

The long-term keys of the KDC and service principals are highly sensitive.

They should be protected using appropriate operating-system security, key-management infrastructure and restricted administrative access.

A compromised service key can enable service impersonation.

A compromised TGS key can undermine the protection of TGTs.

### Ticket Security

Security controls should include:

- Appropriate encryption types.
- Ticket lifetime restrictions.
- Authenticator verification.
- Timestamp validation.
- Replay detection.
- Service identity verification.
- Secure key rotation.
- Monitoring of unusual authentication activity.

### Service Identity

A service must validate the identity for which a ticket was issued.

Accepting a ticket intended for a different service creates an authentication boundary failure.

Service principal names and DNS configuration must remain consistent.

### Account Security

Disabled and expired principals should not receive new service tickets.

Account changes and key rotations must be coordinated with relevant authentication and service infrastructure.

## 15. Common Authentication Failures

| Failure | Cause | Expected behavior |
|---|---|---|
| Unknown principal | Identity is not registered | Reject initial authentication |
| Invalid credentials | Password or pre-authentication mismatch | Reject AS request |
| Expired TGT | TGT lifetime exceeded | Require a new valid TGT |
| Invalid TGT | Invalid signature or ticket structure | Reject TGS request |
| Unknown service | Service principal unavailable | Reject service-ticket request |
| Expired service ticket | Ticket lifetime exceeded | Reject service authentication |
| Clock mismatch | Client and server clocks differ excessively | Reject authenticator |
| Replay attempt | Authenticator already accepted | Reject repeated request |
| Key mismatch | Incorrect or rotated service key | Reject ticket validation |
| Realm mismatch | Ticket belongs to another realm | Reject authentication |
| Disabled principal | Administrative account restriction | Reject authentication |
| Mutual-authentication failure | Invalid server proof | Do not trust the service |

## 16. Kerberos Compared with Other Authentication Mechanisms

| Mechanism | Primary approach | Important distinction |
|---|---|---|
| Kerberos | Symmetric-key tickets | Centralized ticket-based authentication |
| LDAP authentication | Directory-based identity verification | Directory access does not inherently provide Kerberos ticket exchange |
| NTLM | Challenge-response authentication | Does not use the Kerberos TGT/TGS ticket architecture |
| OAuth 2.0 | Authorization framework | Primarily delegates access authorization |
| OpenID Connect | Identity layer over OAuth 2.0 | Provides federated user authentication |
| SAML | XML-based federated identity assertions | Uses signed assertions rather than Kerberos service-ticket exchange |
| TLS client authentication | Certificate-based authentication | Establishes identity through certificates and TLS handshakes |

Kerberos and OAuth 2.0 address different protocol requirements.

Kerberos establishes authenticated principals through a trusted KDC.

OAuth 2.0 provides delegated authorization.

These mechanisms may coexist in enterprise architectures.

## 17. Practical Enterprise Applications

Kerberos is commonly associated with centralized enterprise identity infrastructure.

Its practical applications include:

- Enterprise workstation authentication.
- Windows Active Directory environments.
- Secure internal web services.
- Database authentication.
- Hadoop and distributed data-processing environments.
- Internal application single sign-on.
- Service-to-service authentication.
- Centralized authentication across trusted domains.

A typical enterprise architecture may authenticate a user once and subsequently provide access to several registered services through service-specific tickets.

This reduces repeated credential handling and centralizes authentication policy.

## 18. Implementation Limitations

The five implementations intentionally model different aspects of Kerberos rather than implementing a complete interoperable Kerberos protocol stack.

| Implementation | Main limitation |
|---|---|
| Python | Signed Base64 ticket envelopes are not encrypted RFC 4120 tickets |
| JavaScript | Uses HMAC-signed educational tickets rather than Kerberos ASN.1 structures |
| C++17 | Models ticket lifecycle without production cryptography |
| Java 17 | Uses an educational HMAC ticket representation and simplified mutual authentication |
| PostgreSQL | Stores metadata and simulated signatures rather than performing full Kerberos cryptographic validation |

A production Kerberos deployment requires:

- RFC 4120-compatible protocol messages.
- Appropriate AES encryption types.
- Secure ticket encryption and integrity.
- Proper pre-authentication.
- Secure long-term key storage.
- Service-key distribution and rotation.
- Clock synchronization.
- Cross-realm trust configuration.
- Ticket renewal and delegation policy.
- Secure replay-cache management.
- Auditing and incident response.
- Correct service principal and hostname configuration.

The simplified server-proof mechanisms in the programs illustrate mutual authentication but are not complete RFC 4120 AP-REP implementations.

The database procedure demonstrates ticket issuance and integrity constraints. It does not replace cryptographic validation in a trusted KDC.

## 19. Execution and Technical Requirements

| Deliverable | File | Runtime |
|---|---|---|
| Python | `kerberos_authentication.py` | Python 3.10+ |
| JavaScript | `kerberos_authentication.js` | Node.js 18+ |
| C++ | `kerberos_authentication.cpp` | C++17 compiler |
| Java | `KerberosEnterprise.java` | Java 17 |
| PostgreSQL | `kerberos_authentication.sql` | PostgreSQL 15+ |

The PostgreSQL script uses `gen_random_uuid()` and requires the function to be available in the database.

The implementations use built-in language capabilities and avoid third-party application dependencies.

## 20. Technical Learning Outcomes

The implementations establish the relationship between centralized authentication, symmetric cryptography, ticket issuance, session-key management and distributed service authentication.

The main technical distinctions are:

- A principal represents an identity.
- A realm defines an authentication boundary.
- The KDC coordinates trusted authentication.
- The AS performs initial authentication.
- A TGT enables subsequent service-ticket requests.
- The TGS issues service-specific tickets.
- A service ticket establishes a protected client-service authentication relationship.
- An authenticator demonstrates current possession of the relevant session key.
- A replay cache prevents repeated acceptance of authentication messages.
- Mutual authentication allows the client to verify the service.
- Ticket expiration limits the useful lifetime of authentication credentials.

The combined implementations demonstrate how these mechanisms interact across application logic, event-driven systems, strongly typed domain models, concurrent enterprise services and relational database workflows.
