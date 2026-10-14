# Windows Authentication: Local Accounts, NTLM, Kerberos, and Authentication Flows

## Scope

Windows authentication establishes the identity associated with a logon or a request to a network service. The mechanism depends on the account type, the machine or domain environment, the service being accessed, and the security configuration.

This repository models three related but distinct authentication approaches:

- **Local account authentication** validates an identity maintained by a particular Windows machine.
- **NTLM** uses a challenge-response authentication mechanism that can support network authentication without sending the user's plaintext password as the response.
- **Kerberos** uses tickets issued through a Key Distribution Center (KDC) to authenticate clients to services, supporting domain-based authentication and service-specific credentials.

Authentication is distinct from authorization. Establishing an identity does not automatically grant access to every file, application, administrative function, or network resource.

The implementations use synthetic credentials, challenges, sessions, and tickets. They explain protocol roles and application-level decisions without attempting to implement the Windows security subsystem or interoperable authentication protocols.

## Account identities and Windows security boundaries

### Local accounts

A local account belongs to one computer. Its identity and credential information are managed locally, traditionally through the Security Accounts Manager (SAM) and Windows security components.

A local identity such as `WORKSTATION\helpdesk` is not automatically the same identity as `CORP\helpdesk`, even if both accounts use the same username. Account names must be interpreted within their security authority.

Local authentication is appropriate for machine-specific access and certain administrative scenarios. Its scope differs from domain authentication, which can support centralized identity management and access to domain resources.

A local account logon can establish a local security context, but the effective permissions of that context depend on group membership, privileges, local security policy, and resource access-control rules.

### Domain accounts

A domain account is managed through a domain identity infrastructure, commonly Microsoft Active Directory Domain Services. Domain authentication allows clients and services to rely on centrally managed identities and security policies.

A domain principal must be interpreted in its domain context. The same username may exist in multiple domains or as a separate local account.

A domain account being valid does not guarantee that it can authenticate to every service. Account status, protocol requirements, service configuration, domain connectivity, and security policy affect the outcome.

### Service identities

Services may run under dedicated identities. Kerberos service authentication commonly depends on the service principal name (SPN), which identifies the service instance for which a ticket is issued.

A service principal name must identify the intended service and host. Incorrect or duplicate SPN registrations can cause authentication failures or prevent clients from using Kerberos as intended.

The JavaScript, Java, and SQL models represent service identities separately from ordinary user accounts so that a client principal and the destination service are not treated as interchangeable identities.

## Local authentication flow

A simplified local authentication sequence is:

`User -> Local logon interface -> Windows authentication components -> Local account validation -> Security context`

The Windows implementation involves operating-system components, credential providers, the Local Security Authority (LSA), and account validation mechanisms. The precise path depends on the logon type and configuration.

The Python implementation provides an `AccountDirectory` and `LocalAuthenticator`. The directory associates each account with a salted password verifier. The authenticator checks account type and state, verifies the supplied credential, records failed attempts, and creates an `AuthenticatedSession` after successful validation.

The simulator uses `hashlib.scrypt` with a unique salt per account. This is an educational password-verification mechanism, not the Windows NT password-hash format. The verifier cannot be used to validate real NTLM responses.

The local flow demonstrates several distinct failure conditions:

- Unknown usernames fail account lookup.
- Incorrect passwords increment a failure counter.
- Disabled or locked accounts cannot create new sessions.
- A domain account cannot be authenticated by the local-account service.
- Successful authentication resets the example's failed-attempt counter.

The example lockout threshold is a demonstration policy, not a claim about default Windows lockout settings. Real account-lockout behavior depends on applicable local or domain policy and account type.

## NTLM challenge-response

### Protocol purpose

NTLM is a Windows authentication protocol family based on challenge-response exchanges. A typical conceptual sequence is:

`Client -> Server: authentication negotiation`

`Server -> Client: challenge`

`Client -> Server: identity and challenge response`

`Server or validating authority: response verification`

The client response depends on protocol-specific calculations involving challenge data and credential-derived material. The response is not intended to be the user's plaintext password.

A challenge helps prevent simple replay of a previously captured response when fresh challenges are correctly generated and validated. A secure implementation must also account for message integrity, credential protection, relay risks, server identity, channel binding where applicable, and the precise protocol configuration.

NTLM is not a ticket-based protocol equivalent to Kerberos. Its authentication exchange and credential-verification model differ from Kerberos's TGT and service-ticket exchanges.

### Python implementation

`NtlmConceptSimulator` issues a random challenge associated with a server name and timestamp. The challenge has a lifetime and a unique identifier. Authentication consumes the challenge so that the same identifier cannot be used for a second successful exchange.

The example response uses HMAC-SHA256 with a key derived from a supplied password. It binds the response to the challenge nonce, server name, username, and domain. The response is compared using `hmac.compare_digest`.

This calculation is deliberately different from actual NTLM algorithms. The simulator accepts the password during verification because it does not maintain an NTLM-compatible verifier.

### JavaScript implementation

`NtlmExchange` models the exchange through an event-oriented service. The server issues a challenge, the client computes a demonstration response, and the authentication service consumes the challenge before validating the account and response.

Node.js cryptographic functions produce random challenge data and a synthetic HMAC response. `crypto.timingSafeEqual` is used after checking that the buffers have equal length.

The challenge registry separates challenge issuance from response verification. This makes replay prevention, expiration, account-state validation, and audit events explicit.

### C++ implementation

`ChallengeRegistry` maintains outstanding challenges in a map. `consume()` removes the challenge before returning it for validation. The mechanism prevents repeated use of the same challenge identifier within the simulation.

`FileService::ntlmChallengeResponse()` uses an externally supplied verification result. This is an architectural boundary, not a real NTLM validator. It represents the separation between protocol verification and session creation without implementing cryptography.

### Java implementation

`NtlmChallengeService` tracks challenge identifiers and timestamps, creates synthetic response values, and validates the domain principal before issuing a session.

The challenge is removed from the registry before response verification. A failed attempt therefore cannot reuse the same identifier. Production systems must use the actual protocol's challenge lifecycle and cryptographic validation rules rather than relying on this demonstration.

## Kerberos authentication

### The KDC and its ticket exchanges

Kerberos uses a Key Distribution Center, generally associated with the domain's authentication infrastructure. The KDC has an Authentication Service (AS) role and a Ticket Granting Service (TGS) role.

A simplified exchange is:

`Client -> AS: initial authentication request`

`AS -> Client: Ticket Granting Ticket (TGT)`

`Client -> TGS: TGT and request for a service`

`TGS -> Client: service ticket`

`Client -> Service: service ticket and authenticator`

`Service -> Client: service response, with mutual authentication where configured`

A real Kerberos exchange includes protocol-defined messages, cryptographic protection, authenticators, time handling, and ticket validation. The ticket contains protected information intended for the relevant service or authority. The service must not accept a ticket merely because a client presents an arbitrary identifier.

### Ticket Granting Ticket

The TGT allows a client to request service tickets without repeating the complete initial authentication exchange for every service. Its validity is limited by ticket lifetime and domain policy.

The TGT is not a universal password or an unrestricted authorization token. It has a defined role within the Kerberos protocol and is subject to the relevant security checks.

### Service tickets and SPNs

A service ticket identifies the intended service principal. An HTTP service and a CIFS file service are distinct destinations, even when both are hosted in the same organization.

The client requests a ticket for a service principal name such as `HTTP/intranet.corp.example`. The target service must validate a ticket intended for its own identity.

The examples reject a ticket presented to the wrong service and reject expired tickets. They model these checks without implementing real Kerberos encryption or ticket decryption.

### Python implementation

`KerberosConceptSimulator` separates initial credential validation, TGT issuance, service-ticket issuance, and service-ticket validation.

`request_tgt()` checks that the identity is a valid, enabled domain account and verifies the supplied password. `request_service_ticket()` checks the TGT and creates a service-specific ticket. `validate_service_ticket()` checks the ticket type, expiration, target service, and current account state before creating a session.

The simulator keeps tickets in memory and gives them random identifiers and synthetic session keys. It does not implement the Kerberos ASN.1 message format, encryption types, PAC processing, authenticators, delegation, or mutual authentication.

### JavaScript implementation

`KerberosTicketAuthority` separates the AS-like operation from the TGS-like operation. A TGT is created only after initial credential verification. A service ticket is created only when a valid TGT is presented and the requested service principal has the expected format.

The private `#issue()` method centralizes ticket creation and auditing. Service tickets inherit an expiration boundary that cannot exceed the parent TGT's expiration.

`validateServiceTicket()` verifies the intended service and rechecks the account's current state. This models the distinction between ticket possession and the application's decision to accept a request.

### C++ implementation

The C++ case study uses `Ticket` records and a ticket registry. `issueTgt()` represents the initial authentication stage, while `issueServiceTicket()` models the ticket-granting stage.

`acceptServiceTicket()` verifies the ticket type, expiration, service name, and client identity before creating a session. The use of `std::map` supports direct ticket lookup; these operations have logarithmic lookup cost in the number of stored tickets.

The credential-verification argument is explicitly synthetic. A production Kerberos service must validate protocol-compliant tickets and authenticators with the proper cryptographic keys and domain trust configuration.

### Java implementation

`KerberosTicketService` represents TGT issuance, service-ticket issuance, and service acceptance as separate operations. Immutable records describe ticket metadata, while the service maintains an in-memory registry.

The service principal and client principal are distinct fields. This avoids confusing the identity requesting access with the identity of the destination service.

The program uses synthetic tickets with expiration timestamps. It does not implement encrypted ticket contents, authenticators, ticket renewal, delegation, clock-skew validation, or the complete Kerberos trust model.

## Authentication, sessions, and authorization

Authentication establishes an identity. Authorization determines what that identity may do.

An authenticated session may contain a principal, authentication protocol, logon type, group memberships, and a session identifier. These fields describe the example's application model; they are not substitutes for a real Windows access token.

A Windows access token carries security information used by the operating system during access checks. Resource permissions can depend on user and group SIDs, privileges, mandatory integrity levels, access-control entries, and other security mechanisms.

The examples use groups and resource names to illustrate the authorization boundary. A session belonging to `Domain Users` may receive permission to read intranet content but still be denied access to payroll administration.

The Python `ResourcePolicy`, JavaScript `ResourceAuthorizationService`, C++ `FileService::authorize()`, and Java `AuthorizationService` keep resource decisions separate from authentication protocol processing.

This separation prevents a common design error: assuming that a successful password check or a valid authentication ticket automatically grants administrative rights.

## Logon types and session boundaries

Windows supports different logon types, including interactive, network, service, and remote interactive logons. They represent different access patterns and security contexts.

A local interactive sign-in and a network authentication request should not be assumed to create identical security contexts. Credential delegation, local resource access, network resource access, and the availability of credentials can differ by logon type and policy.

The examples represent logon types as explicit enum values. Their session objects retain the authentication mechanism and logon type so that the audit output does not reduce every successful authentication to a generic login event.

The models do not implement Windows logon sessions, token duplication, impersonation, credential delegation, Remote Desktop authentication, or the operating system's logon APIs.

## Audit records and failure analysis

Authentication telemetry should record enough information to investigate failed and suspicious requests without recording secrets.

The implementations capture outcomes such as invalid credentials, expired challenges, reused challenge identifiers, unavailable accounts, and service-ticket mismatches.

The Python `AuditLog` stores structured events. The JavaScript `AuditTrail` uses event-driven processing so that authentication outcomes can be observed independently of the authentication service. The C++ `AuditLog` stores typed records, and the Java `AuditService` produces immutable event records.

The PostgreSQL schema stores authentication attempts with protocol, logon type, source host, result, reason code, timestamp, and correlation identifier.

The audit model deliberately excludes plaintext passwords, reusable challenge responses, and session keys. Real deployments must also consider log access permissions, retention, time synchronization, event integrity, privacy requirements, and the possibility of malicious log injection.

## PostgreSQL data model

The SQL script creates the `windows_auth_lab` schema and separates identity data, protocol artifacts, session state, and resource permissions.

| Table | Purpose |
|---|---|
| `accounts` | Stores local, domain, and service identity metadata, account state, and failed-attempt counts. |
| `account_groups` | Defines named authorization groups. |
| `account_group_memberships` | Connects accounts to groups through a many-to-many relationship. |
| `service_principals` | Maps a service identity to its host and service account. |
| `authentication_attempts` | Records successful, failed, rejected, and expired authentication outcomes. |
| `ntlm_challenges` | Tracks synthetic challenge issuance, expiration, consumption, and response outcomes. |
| `kerberos_tickets` | Represents TGTs and service tickets, including parent relationships and expiration. |
| `authenticated_sessions` | Records the authentication mechanism, logon type, validity interval, and source host. |
| `resources` | Defines resources that require access checks. |
| `group_resource_permissions` | Associates groups with explicit read, write, and administrative capabilities. |
| `resource_access_events` | Records whether resource access was granted or denied. |

### Integrity constraints

The `accounts` table enforces consistency between account scope and domain name. A local account cannot be assigned a domain name, while domain and service identities require one.

Ticket constraints distinguish TGTs from service tickets. A service ticket must have a target service and parent TGT. The `validate_ticket_relationship()` trigger also verifies that the parent exists, has TGT type, belongs to the same account, and expires no earlier than the service ticket.

The authentication trigger prevents inserting a successful authentication event for an account that is not enabled at the time of validation. This is an audit-integrity safeguard, not a complete authentication engine.

Foreign keys preserve relationships among accounts, groups, service principals, tickets, sessions, and resources. Indexes support lookups by account and ticket expiration, active challenge expiration, recent session activity, and access-event time.

### Querying authentication behavior

The SQL queries group attempts by protocol and outcome to reveal whether failures are concentrated in local, NTLM-concept, or Kerberos-concept flows.

The challenge query identifies outstanding challenges that have expired. The ticket query distinguishes revoked, expired, and time-valid ticket records.

The authorization query joins sessions, accounts, group memberships, permissions, and resources. It evaluates effective read permission from the example's group policy rather than treating session creation as an authorization grant.

The script also demonstrates constraint failures inside exception-handling blocks. Invalid local/domain combinations and service tickets without parent TGTs are rejected while the outer script continues.

These queries evaluate recorded model data. They do not validate real Windows credentials, decode actual Kerberos tickets, or inspect the operating system's security database.

## Security limitations and production distinctions

The programs are teaching models, not authentication products.

- The Python implementation uses scrypt for synthetic local credential verification. Its NTLM and Kerberos artifacts are not interoperable with Windows.
- The JavaScript implementation uses Node.js cryptographic primitives to demonstrate challenge binding, event handling, and ticket state. Its response format is not NTLM-compatible.
- The C++ implementation isolates protocol verification behind explicit verification decisions. It demonstrates session issuance and service policy rather than real protocol cryptography.
- The Java implementation models authentication with domain types, immutable records, validation, and separate services. Its synthetic response construction and ticket records do not implement the Windows security protocols.
- The SQL implementation models relational integrity, audit history, and authorization queries. Its constraints do not prove that a real client possesses valid credentials or that a ticket's cryptographic protection is valid.

A production Windows authentication deployment must rely on the operating system's supported security interfaces and protocol implementations. It must also use appropriate account policies, secure service configuration, correctly registered SPNs, protected credential material, network protections, and monitored authentication events.

NTLM relay, pass-the-hash, credential theft, Kerberos ticket theft, SPN misconfiguration, excessive privileges, and weak service-account management represent different risk classes. A challenge-response exchange alone does not eliminate relay risk, and possession of a ticket alone does not justify unrestricted resource access.

The relevant security decision must be made at the correct layer: account validation establishes identity, protocol exchanges establish or prove authentication, session creation establishes a security context, and resource access checks determine whether the requested operation is permitted.
