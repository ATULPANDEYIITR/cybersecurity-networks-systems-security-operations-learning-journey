# TLS Deep Dive: Handshake, Cipher Suites, Certificates, and Session Keys

## 1. Technical Scope

Transport Layer Security (TLS) protects communication between applications over an untrusted network. It provides:

- Confidentiality through symmetric encryption.
- Integrity through authenticated encryption.
- Authentication through certificates and cryptographic proofs.
- Key establishment through an authenticated key exchange.
- Session resumption to reduce the cost of subsequent connections.

This project examines TLS 1.2 and TLS 1.3 through five implementations:

| File | Engineering perspective |
|---|---|
| Python | TLS connection inspection and certificate diagnostics |
| JavaScript | Event-driven TLS connection and session management |
| C++17 | TLS handshake state and security policy simulation |
| Java 17 | Enterprise TLS connection assessment and governance |
| PostgreSQL | TLS endpoint, certificate, handshake, and compliance management |

The implementations distinguish actual TLS operations from simulated protocol behavior.

## 2. TLS Architecture

A TLS connection consists of several coordinated mechanisms.

- Protocol negotiation determines the TLS version.
- Cipher negotiation selects compatible cryptographic algorithms.
- Certificate validation establishes the server's identity.
- Key exchange establishes shared cryptographic material.
- The TLS key schedule derives traffic secrets and symmetric keys.
- Finished messages authenticate the handshake transcript.
- Application data is encrypted and authenticated using traffic keys.

### Communication architecture

Client application
→ TLS client implementation
→ ClientHello
→ ServerHello
→ Certificate and authentication
→ Key establishment
→ Finished messages
→ Protected application data

The TLS handshake is separate from the application protocol. HTTPS, for example, uses HTTP over TLS.

## 3. TLS 1.2 and TLS 1.3

TLS 1.2 and TLS 1.3 provide similar security objectives but use different handshake and cryptographic designs.

| Property | TLS 1.2 | TLS 1.3 |
|---|---|---|
| Protocol version | TLS 1.2 | TLS 1.3 |
| Handshake design | Multiple supported handshake patterns | Streamlined handshake |
| Cipher suite scope | Includes key exchange, authentication, encryption, and hash/MAC choices | Specifies AEAD algorithm and transcript hash |
| Forward secrecy | Depends on negotiated key exchange | Ephemeral (EC)DHE in the standard full handshake |
| RSA key transport | Supported by older cipher suites | Removed |
| Static DH key exchange | Supported by older configurations | Removed |
| AEAD | Supported | Required |
| 0-RTT | Not supported | Supported with restrictions |
| Handshake encryption | Several handshake messages remain unencrypted | Most messages after ServerHello are encrypted |

TLS 1.3 reduces handshake complexity and removes several obsolete cryptographic options.

TLS 1.2 remains relevant for compatibility with systems that have not migrated to TLS 1.3.

## 4. TLS Handshake

### 4.1 ClientHello

The client initiates the connection by transmitting a ClientHello message.

Important fields and extensions include:

- Supported protocol versions.
- Cipher suite list.
- Client random.
- Supported groups.
- Key shares.
- Signature algorithms.
- Server Name Indication (SNI).
- Application-Layer Protocol Negotiation (ALPN).
- Session resumption information where applicable.

SNI allows a client to indicate the intended hostname during the TLS handshake.

ALPN allows the client and server to negotiate an application protocol such as HTTP/2 or HTTP/1.1.

### 4.2 ServerHello

The server selects compatible parameters.

These include:

- TLS protocol version.
- Cipher suite.
- Key exchange parameters.
- Server key share when using an ephemeral key exchange.

A handshake cannot proceed when there is no acceptable combination of supported protocol parameters.

### 4.3 Certificate authentication

The server supplies its certificate chain when certificate authentication is used.

The client evaluates:

- Certificate signatures.
- Issuer relationships.
- Trusted root certificates.
- Validity periods.
- Subject Alternative Name entries.
- Hostname matching.
- Key usage.
- Extended key usage.
- Certificate revocation information when supported by the validation environment.

The server must also prove possession of the corresponding private key.

In TLS 1.3, CertificateVerify provides a signature over the handshake transcript using the certificate's private key.

Possessing a certificate alone does not establish successful authentication.

### 4.4 Finished messages

Finished messages authenticate the handshake transcript.

They provide confirmation that both parties derived compatible handshake secrets and processed the same authenticated handshake state.

An invalid Finished message indicates that the handshake cannot be trusted.

### 4.5 Application data

After the handshake succeeds, both endpoints protect application data using symmetric traffic keys.

TLS uses directional traffic secrets so that client-to-server and server-to-client traffic have separate key material.

## 5. Cipher Suites

A cipher suite identifies cryptographic algorithms used by a TLS connection.

### TLS 1.2 cipher suite example

`ECDHE-RSA-AES128-GCM-SHA256`

Its components are:

| Component | Meaning |
|---|---|
| ECDHE | Ephemeral elliptic-curve Diffie-Hellman key exchange |
| RSA | Certificate-based authentication |
| AES-128-GCM | Authenticated symmetric encryption |
| SHA-256 | Handshake PRF and related hash selection |

### TLS 1.3 cipher suite example

`TLS_AES_128_GCM_SHA256`

Its components are:

| Component | Meaning |
|---|---|
| AES-128-GCM | Authenticated symmetric encryption |
| SHA-256 | Transcript hash and key schedule hash |

TLS 1.3 negotiates authentication algorithms and supported groups separately from the cipher suite.

### Common TLS 1.3 suites

| Cipher suite | Encryption | Hash |
|---|---|---|
| TLS_AES_128_GCM_SHA256 | AES-128-GCM | SHA-256 |
| TLS_AES_256_GCM_SHA384 | AES-256-GCM | SHA-384 |
| TLS_CHACHA20_POLY1305_SHA256 | ChaCha20-Poly1305 | SHA-256 |

### Cipher selection considerations

A secure cipher policy should consider:

- Protocol compatibility.
- Authenticated encryption.
- Cryptographic strength.
- Forward secrecy.
- Implementation support.
- Performance on available hardware.
- Organizational compliance requirements.

Legacy CBC-based suites, obsolete algorithms, and RSA key transport configurations should not be accepted merely because a client and server support them.

A cipher suite's name alone is not a complete security assessment. Certificate algorithms, key exchange groups, certificate validity, implementation behavior, and protocol configuration must also be evaluated.

## 6. Digital Certificates

An X.509 certificate binds an identity to a public key.

### Important certificate fields

| Field | Purpose |
|---|---|
| Subject | Certificate identity |
| Issuer | Certificate authority or issuing entity |
| Serial number | Certificate identifier assigned by issuer |
| Not Before | Beginning of validity |
| Not After | End of validity |
| Subject Alternative Name | DNS names and other identities |
| Public key | Key used for the relevant cryptographic operations |
| Signature algorithm | Algorithm used to sign the certificate |
| Basic Constraints | Identifies CA certificates |
| Key Usage | Restricts permitted cryptographic operations |
| Extended Key Usage | Identifies intended purposes such as server authentication |

### Certificate chain

A typical certificate chain is:

Server certificate
→ Intermediate CA certificate
→ Trusted root CA certificate

The client validates the chain using its configured trust store.

A certificate may have a valid signature but still be rejected because:

- Its hostname does not match.
- Its validity period has ended.
- Its issuer is not trusted.
- Its key usage is unsuitable.
- Its chain cannot be constructed.
- It has been revoked where revocation checking is performed.

### Certificate fingerprint

The Python, JavaScript, and Java implementations calculate a SHA-256 fingerprint from the DER-encoded certificate.

A fingerprint is useful for certificate identification and comparison.

It is not a substitute for certificate-chain validation.

Certificate renewal should be performed before expiration. Renewal procedures should include private-key protection, deployment validation, chain verification, and rollback planning.

## 7. Session Keys and Key Derivation

TLS uses asymmetric cryptography during authentication and key establishment, then symmetric cryptography for application data.

The two mechanisms serve different purposes.

### Key exchange

In a typical modern TLS handshake, ephemeral Diffie-Hellman key exchange establishes shared secret material.

The client and server independently calculate the same shared secret using their respective private values and the exchanged public key shares.

The shared secret is not transmitted over the network.

Certificate authentication binds the server's identity to the handshake and protects against an unauthenticated intermediary.

### TLS 1.3 key schedule

TLS 1.3 uses HKDF, a key derivation construction based on HMAC.

The key schedule derives:

- Early Secret.
- Handshake Secret.
- Client Handshake Traffic Secret.
- Server Handshake Traffic Secret.
- Master Secret.
- Client Application Traffic Secret.
- Server Application Traffic Secret.
- Exporter Secret.
- Resumption Master Secret.

The Finished key is derived from the appropriate handshake traffic secret.

Directional application traffic keys and IVs are derived from the application traffic secrets.

### TLS 1.2 key derivation

TLS 1.2 uses a different key derivation mechanism.

The master secret is used to derive the key block, which supplies encryption keys, IVs where applicable, and authentication material depending on the selected cipher suite.

The precise mechanism depends on the negotiated TLS 1.2 cipher suite.

### Session keys versus session identifiers

These terms should not be confused.

| Term | Meaning |
|---|---|
| Shared secret | Secret material established during key exchange |
| Traffic secret | Secret used to derive traffic protection keys |
| Traffic key | Symmetric key used to encrypt and authenticate records |
| Session identifier | Reference used by some session-resumption mechanisms |
| Session ticket | Protected server-issued session-resumption state |
| PSK | Pre-shared key used in applicable resumption or authentication mechanisms |

Raw traffic keys, session tickets, private keys, and resumption PSKs must not be logged or stored in ordinary application databases.

## 8. Session Resumption

Session resumption reduces the cost of subsequent TLS connections.

TLS 1.2 supports session identifiers and session tickets.

TLS 1.3 primarily uses ticket-based PSK resumption.

A TLS 1.3 resumption ticket allows the client and server to establish a later connection using previously established session state.

Session resumption must still respect security policy.

Relevant controls include:

- Ticket lifetime.
- Ticket expiration.
- Server-side ticket protection.
- Key rotation.
- Revocation policy.
- Application authentication.
- Server configuration changes.
- Replay protection for early data.

### 0-RTT early data

TLS 1.3 permits certain resumed connections to send early application data.

Early data has replay risks.

Applications should not use 0-RTT for operations whose repeated execution could cause harmful side effects, such as financial transfers or irreversible state changes, unless suitable replay controls exist.

Session resumption does not mean that a client can ignore certificate and identity security requirements.

## 9. Python Implementation

The Python script uses the standard library.

### Main components

| Component | Responsibility |
|---|---|
| TLSConfig | Validates connection configuration |
| HandshakeState | Represents connection lifecycle states |
| HandshakeReport | Stores negotiated connection information |
| TLSPolicy | Evaluates protocol and cipher policy |
| TLSInspector | Establishes and inspects TLS connections |

### Practical workflow

1. Validate the hostname, port, and timeout.
2. Create a client TLS context.
3. Configure the minimum and maximum protocol versions.
4. Load the operating system's trusted certificates.
5. Establish a TCP connection.
6. Wrap the connection using TLS with hostname verification.
7. Complete the handshake.
8. Inspect negotiated protocol and cipher information.
9. Retrieve the peer certificate.
10. Calculate its SHA-256 fingerprint.
11. Evaluate the local cipher policy.
12. Record failures and diagnostic information.

The script also supports JSON reporting and optional OpenSSL diagnostics.

### Important implementation decisions

- `ssl.PROTOCOL_TLS_CLIENT` provides a client-oriented TLS context.
- `CERT_REQUIRED` requires certificate validation.
- `check_hostname` verifies the server identity.
- `OP_NO_COMPRESSION` disables TLS-level compression.
- `getpeercert()` retrieves certificate metadata.
- `getpeercert(binary_form=True)` retrieves the DER certificate.
- `get_ciphers()` displays cipher suites supported by the local runtime.

The script inspects a live TLS endpoint. It does not implement the TLS cryptographic handshake independently.

The local cipher allowlist is an example governance policy and may require adjustment for a particular production environment.

## 10. JavaScript Implementation

The JavaScript implementation uses Node.js native modules.

### Main components

| Component | Responsibility |
|---|---|
| TLSConfiguration | Validates TLS parameters |
| CipherPolicy | Checks negotiated cipher policy |
| TLSConnection | Manages asynchronous handshake state |
| TLSSessionManager | Maintains session metadata |
| EventEmitter | Publishes connection lifecycle events |

### Event-driven workflow

The connection follows:

`CREATED → CONNECTING → ESTABLISHED → CLOSED`

Failure follows:

`CONNECTING → FAILED → CLOSED`

The state transition method rejects invalid transitions.

### Important Node.js mechanisms

- `tls.connect()` creates the TLS connection.
- `secureConnect` indicates successful TLS establishment.
- `getProtocol()` retrieves the negotiated TLS version.
- `getCipher()` retrieves negotiated cipher information.
- `getPeerCertificate()` retrieves peer certificate metadata.
- `getSession()` retrieves session data for supported session mechanisms.
- `isSessionReused()` indicates whether the connection reused a session.
- `EventEmitter` communicates state changes.
- `Promise` represents asynchronous connection completion.

The session manager copies buffers when storing and retrieving session data to prevent external modification of its internal entries.

The example demonstrates session handling for diagnostics. A production client must follow Node.js and server-specific session-resumption requirements, apply appropriate expiration limits, and protect session material.

## 11. C++17 Implementation

The C++ program models TLS negotiation and security policy as explicit domain objects.

It does not implement real TLS cryptography.

### Main components

| Component | Responsibility |
|---|---|
| CipherSuite | Represents cryptographic suite properties |
| Certificate | Represents certificate validation attributes |
| TLSClientHello | Represents client capabilities |
| TLSNegotiation | Stores negotiation state |
| CipherRegistry | Maintains available cipher policies |
| CertificateValidator | Enforces certificate checks |
| TLSHandshakeEngine | Simulates protocol negotiation |
| BranchlessSessionCache | Demonstrates session metadata expiration |

### State transitions

The simulation follows:

`CREATED`

→ `CLIENT_HELLO_SENT`

→ `SERVER_HELLO_RECEIVED`

→ `CERTIFICATE_VERIFIED`

→ `KEY_ESTABLISHED`

→ `FINISHED`

Any failed validation causes an exception and rejects the handshake.

### Engineering decisions

- `enum class` prevents accidental mixing of unrelated states.
- `struct` provides explicit domain models.
- `std::map` provides indexed cipher lookup.
- `std::optional` represents missing negotiated values.
- `std::set` and STL algorithms support policy evaluation.
- `std::chrono` provides monotonic session expiration measurements.
- Exceptions prevent invalid protocol transitions from being treated as successful.

The session cache uses a bounded capacity and removes the oldest entry when necessary.

The simulation marks key establishment and transcript authentication as logical states. It does not calculate Diffie-Hellman secrets, execute HKDF, verify real X.509 signatures, or encrypt TLS records.

## 12. Java 17 Implementation

The Java implementation represents an enterprise TLS assessment service.

### Main components

| Component | Responsibility |
|---|---|
| TLSConfiguration | Defines protocol and timeout policy |
| CipherPolicy | Models cipher requirements |
| CipherPolicyService | Evaluates negotiated cipher suites |
| CertificateService | Inspects and validates certificate properties |
| SessionRegistry | Tracks session metadata |
| TLSConnectionService | Establishes and evaluates TLS connections |
| TLSReport | Produces an immutable assessment record |

### Enterprise workflow

The connection service:

1. Validates the destination.
2. Creates an SSL context.
3. Configures allowed TLS versions.
4. Enables HTTPS endpoint identification.
5. Starts the handshake.
6. Checks session validity.
7. Evaluates the negotiated protocol.
8. Evaluates the cipher suite.
9. Retrieves the peer certificate chain.
10. Inspects the leaf certificate.
11. Produces an immutable report.

### Certificate validation

The implementation uses Java's JSSE certificate and trust infrastructure.

`SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` enables hostname verification during the handshake.

`X509Certificate.checkValidity()` checks the certificate validity period.

The certificate service also inspects:

- Basic constraints.
- Key usage.
- Extended key usage.
- Issuer.
- Subject.
- Serial number.
- Signature algorithm.
- SHA-256 fingerprint.

The configured trust store remains responsible for trust-chain validation.

The implementation uses the default JSSE session behavior. The session registry is a metadata example, not a replacement for JSSE's internal session cache.

## 13. PostgreSQL Implementation

The PostgreSQL script models the governance and operational records of an organization's TLS infrastructure.

### Relational domain model

`Security Teams`
→ `TLS Endpoints`
→ `Endpoint Policies`
→ `TLS Policies`

`TLS Endpoints`
→ `Endpoint Cipher Preferences`
→ `Cipher Suites`

`TLS Endpoints`
→ `Certificates`
→ `Certificate Chains`

`TLS Endpoints`
→ `Handshake Assessments`
→ `TLS Sessions`

`TLS Endpoints`
→ `Security Findings`
→ `TLS Audit Events`

### Core tables

| Table | Purpose |
|---|---|
| security_teams | Endpoint ownership |
| tls_endpoints | Network endpoint inventory |
| cipher_suites | Cryptographic suite inventory |
| endpoint_cipher_preferences | Endpoint cipher preferences |
| certificates | Certificate metadata and validity |
| certificate_chain | Issuer relationships |
| tls_policies | Organization-level security requirements |
| endpoint_policies | Policy assignment |
| handshake_assessments | Negotiated TLS connection records |
| tls_sessions | Session metadata |
| security_findings | Security issues and remediation states |
| tls_audit_events | Governance audit history |

### Integrity controls

The schema uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated states.
- Partial indexes.
- Validation triggers.
- Audit triggers.
- Reporting views.
- Functions.
- Procedures.

### Certificate validation trigger

The certificate trigger rejects a certificate marked as valid when required hostname verification, chain verification, or server authentication conditions are missing.

It also prevents a CA certificate from being registered as a server leaf certificate.

### Handshake validation trigger

The handshake trigger checks that:

- The negotiated protocol matches the selected cipher suite.
- The cipher suite is approved.
- Authenticated encryption is required.
- Forward secrecy is required for successful compliant handshakes.

### Reporting

The reporting views provide:

- Endpoint security posture.
- Successful and failed handshakes.
- Certificate expiration information.
- Cipher suite usage.
- Open security findings.

The compliance function evaluates a recorded handshake against the assigned endpoint policy.

### Session storage security

The database stores only a session reference hash and operational metadata.

It deliberately excludes:

- TLS traffic keys.
- Private keys.
- Raw session tickets.
- PSKs.
- Handshake secrets.
- Application encryption keys.

Database access should be restricted through appropriate roles, grants, audit controls, and encryption at rest.

## 14. Security Considerations

### Certificate security

- Validate the complete certificate chain.
- Verify DNS names against Subject Alternative Name entries.
- Reject expired and not-yet-valid certificates.
- Validate server authentication usage.
- Protect certificate private keys.
- Monitor renewal deadlines.
- Maintain an appropriate trust store.
- Apply certificate revocation controls where required.

### Cipher security

- Prefer TLS 1.3.
- Require authenticated encryption.
- Disable obsolete protocol versions.
- Reject weak or prohibited cipher suites.
- Require forward secrecy according to organizational policy.
- Review supported cryptographic groups and signature algorithms.

### Key management

- Use ephemeral key exchange where applicable.
- Never log traffic secrets.
- Protect private keys using appropriate key-management controls.
- Rotate ticket-protection keys.
- Limit session lifetimes.
- Revoke compromised credentials and applicable session state.
- Restrict access to sensitive cryptographic material.

### Operational security

- Monitor handshake failures.
- Monitor certificate expiration.
- Detect protocol downgrade attempts.
- Review unusual cipher negotiation.
- Protect TLS configuration files.
- Maintain secure runtime and library versions.
- Record security events without exposing secrets.

## 15. Failure Scenarios

| Failure | Cause | Appropriate response |
|---|---|---|
| Handshake failure | Incompatible protocol parameters | Review supported versions and configuration |
| Certificate expired | Validity period ended | Renew and redeploy certificate |
| Hostname mismatch | Incorrect certificate identity | Correct DNS or certificate configuration |
| Untrusted issuer | Missing or invalid trust chain | Verify and repair certificate chain |
| No common cipher | Incompatible cipher policies | Align approved cryptographic capabilities |
| Invalid signature | Authentication verification failure | Reject the connection |
| Timeout | Network or server delay | Apply bounded retries and investigate |
| Session expiration | Ticket or session lifetime ended | Perform a full handshake |
| Session rejection | Server does not accept resumption state | Establish a new authenticated session |
| 0-RTT replay | Repeated early-data processing | Restrict non-idempotent operations |

A failed TLS handshake must not be silently downgraded to plaintext communication.

## 16. Performance Considerations

TLS introduces computational and network overhead.

Important factors include:

- Full handshake frequency.
- Certificate chain size.
- Public-key operations.
- Network round trips.
- Symmetric encryption throughput.
- Session resumption frequency.
- Connection reuse.
- Hardware acceleration.
- Cryptographic implementation quality.

TLS 1.3 generally reduces handshake round trips compared with traditional TLS 1.2 handshakes.

Session resumption reduces the work required to establish later connections.

Connection pooling can reduce repeated handshakes in applications that maintain persistent connections.

Session resumption and connection pooling solve related but different performance problems.

## 17. Implementation Limitations

The five implementations have different responsibilities.

| Implementation | Actual cryptography | Main limitation |
|---|---|---|
| Python | Yes, through OpenSSL-backed `ssl` | Does not implement the TLS protocol itself |
| JavaScript | Yes, through Node.js TLS/OpenSSL | Session behavior depends on the runtime and server |
| C++17 | No, protocol-state simulation | Does not perform real key exchange or certificate cryptography |
| Java 17 | Yes, through JSSE | Certificate and cipher support depend on the installed security provider |
| PostgreSQL | No | Stores assessment and governance information, not live TLS traffic |

The local cipher allowlists are policy examples. They should be reviewed against actual runtime capabilities, organizational standards, and deployment requirements.

The database's compliance function is a simplified governance evaluator. Production deployments should additionally evaluate protocol range semantics, certificate status, endpoint-specific requirements, and current policy versions.

A successful TLS connection alone does not establish application-level authorization or guarantee the security of the application.

## 18. Execution

| File | Execution |
|---|---|
| Python | `python tls_deep_dive.py` |
| Python JSON | `python tls_deep_dive.py --host example.com --json` |
| Python OpenSSL diagnostics | `python tls_deep_dive.py --host example.com --openssl` |
| JavaScript | `node tls_deep_dive.js` |
| C++17 | Compile using a C++17-compatible compiler |
| Java 17 | `javac TLSDeepDive.java` followed by `java TLSDeepDive` |
| PostgreSQL | Execute the SQL script using a PostgreSQL client |

Live endpoint inspection requires network access, a reachable TLS service, a valid system trust store, and compatible cryptographic support.

The C++ implementation is intentionally executable without external dependencies because its purpose is to model negotiation and security-policy behavior rather than replace a production TLS library.
