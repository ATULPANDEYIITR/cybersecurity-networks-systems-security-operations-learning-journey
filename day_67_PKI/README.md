# Public Key Infrastructure (PKI)

## 1. Introduction

Public Key Infrastructure (PKI) is a framework for creating, issuing, distributing, validating, renewing, and revoking digital certificates.

It establishes relationships between public keys and identities through certificates issued by trusted Certificate Authorities (CAs).

PKI supports authentication, encrypted communication, digital signatures, and integrity verification.

Typical applications include:

- HTTPS and TLS server authentication.
- Mutual TLS authentication between applications.
- Enterprise device and user authentication.
- Software and code signing.
- Secure email.
- Document signing.
- Machine-to-machine authentication.
- Public-sector and enterprise identity systems.

The implementations model a hierarchical PKI environment with root authorities, intermediate authorities, end-entity certificates, trust anchors, certificate policies, validation, renewal, and revocation.

## 2. PKI Architecture

A conventional hierarchical PKI contains three principal certificate categories.

### 2.1 Root Certificate Authority

A Root CA occupies the top of a certificate hierarchy.

Its certificate is generally self-issued and self-signed. Its public key is distributed through trust stores maintained by operating systems, browsers, applications, and enterprise administrators.

Root CA responsibilities include:

- Establishing the trust hierarchy.
- Issuing intermediate CA certificates.
- Defining certificate issuance policies.
- Protecting its private signing key.
- Maintaining certificate lifecycle controls.
- Managing subordinate CA authorization.
- Supporting trust-anchor distribution.

Root CA private keys require particularly strong protection because compromise can undermine the trust relationships established beneath the root.

Typical security controls include:

- Hardware Security Modules (HSMs).
- Offline root CA operation.
- Multi-person authorization.
- Restricted administrative access.
- Controlled signing ceremonies.
- Backup and recovery procedures.
- Detailed audit records.

A root certificate does not become trusted merely because it is self-signed. Trust is established when a relying party explicitly accepts it as a trust anchor.

### 2.2 Intermediate Certificate Authority

An Intermediate CA operates beneath a root CA or another authorized intermediate CA.

It receives its certificate from its parent CA and can issue certificates according to its authorization and policy constraints.

Intermediate authorities provide separation between root trust and routine certificate issuance.

Their responsibilities include:

- Issuing server certificates.
- Issuing client authentication certificates.
- Managing subordinate certificate requests.
- Applying certificate lifetime restrictions.
- Enforcing permitted key usages.
- Managing revocation.
- Maintaining issuance records.

A typical organization may maintain separate intermediate authorities for:

- TLS server certificates.
- Employee authentication.
- Device authentication.
- Code signing.
- Internal application identities.

Compromising an intermediate CA can affect certificates issued beneath that authority without necessarily requiring immediate replacement of every unrelated CA in the hierarchy.

### 2.3 End-Entity Certificates

End-entity certificates are issued to systems, applications, devices, services, or individuals.

They do not have CA privileges.

Examples include:

| Certificate | Subject |
|---|---|
| TLS server | `DNS=api.example.com` |
| Client authentication | `CN=enterprise-client` |
| Application identity | `CN=payment-service` |
| Device identity | `CN=device-1042` |
| Code signing | Software publisher identity |

End-entity certificates provide identity and public-key information for their intended usage.

They must not receive unauthorized certificate-signing privileges.

## 3. Certificate Hierarchy and Chain of Trust

A certificate chain connects an end-entity certificate to a trusted root.

The hierarchy implemented in the source files is:

    Enterprise Root CA
           |
           v
    Enterprise Intermediate CA
           |
           +----------------------+
           |                      |
           v                      v
    TLS Server Certificate   Client Certificate
           |
           v
    Certificate Validation
           |
           v
    Trusted Root Anchor

A certificate contains information about its subject, issuer, public key, validity period, extensions, and digital signature.

Important certificate fields include:

| Field | Purpose |
|---|---|
| Subject | Identity represented by the certificate |
| Issuer | Authority responsible for issuing the certificate |
| Serial number | Identifier assigned by the issuing CA |
| Not Before | Beginning of certificate validity |
| Not After | End of certificate validity |
| Subject Public Key Info | Public key and associated algorithm |
| Subject Key Identifier | Identifies the subject public key |
| Authority Key Identifier | Identifies the issuing authority's key |
| Key Usage | Permitted cryptographic operations |
| Basic Constraints | Identifies CA certificates and path constraints |
| Signature Algorithm | Algorithm used for certificate signing |
| Fingerprint | Digest identifying a particular certificate |

### 3.1 Chain Validation

A relying party evaluates the certificate chain before accepting a certificate.

A typical validation process involves:

1. Identifying the end-entity certificate.
2. Locating its issuing CA.
3. Checking issuer and subject relationships.
4. Matching Authority Key Identifier and Subject Key Identifier where applicable.
5. Checking certificate validity periods.
6. Checking revocation status.
7. Verifying certificate signatures.
8. Evaluating CA constraints and path length.
9. Checking permitted key usage and extended key usage.
10. Establishing a trusted root certificate.

The chain is normally evaluated from the end-entity certificate toward the trust anchor.

A certificate can be correctly formatted and still fail validation because its issuer is untrusted, its validity period has ended, its key usage is inappropriate, or its revocation status indicates that it must not be accepted.

**Important distinction:** A trust anchor is configured independently of ordinary certificate signature verification. A relying party establishes trust in the root through its trust-store policy.

## 4. Certificate Authority Policies

Certificate authorities operate according to issuance and operational policies.

These policies define which certificates an authority may issue and under what conditions.

Typical policy attributes include:

| Policy | Example |
|---|---|
| Maximum validity | 90 days |
| Permitted key usage | Digital signature and key encipherment |
| Intermediate issuance | Prohibited for an issuing CA |
| Subject validation | Required |
| Serial uniqueness | Required |
| CA certificate issuance | Restricted |
| Revocation handling | Mandatory |
| Audit retention | Policy-defined |

The implementations enforce validity restrictions, permitted key usage, CA authorization, and certificate hierarchy constraints.

### 4.1 Basic Constraints

The X.509 Basic Constraints extension identifies whether a certificate represents a CA.

The `CA` value distinguishes CA certificates from end-entity certificates.

The `pathLenConstraint` limits the number of subordinate non-self-issued CA certificates that may follow a CA in a certification path.

For example:

- Root CA path length: 2.
- Intermediate CA path length: 0.
- End-entity certificate: no CA path length.

A path length of zero permits the CA to issue end-entity certificates but does not authorize another subordinate CA level.

### 4.2 Key Usage

Key Usage defines permitted operations for the public key.

Common values include:

| Key usage | Purpose |
|---|---|
| digitalSignature | Digital signatures |
| keyEncipherment | Key transport |
| keyAgreement | Key agreement |
| dataEncipherment | Data encryption |
| contentCommitment | Non-repudiation-related signature usage |
| keyCertSign | Signing certificates |
| cRLSign | Signing certificate revocation lists |

CA certificates generally require `keyCertSign` and may use `cRLSign`.

End-entity certificates must receive only the privileges required by their intended applications.

Extended Key Usage further restricts certificate purposes, such as TLS server authentication, TLS client authentication, and code signing.

Key Usage and Extended Key Usage are distinct certificate extensions.

## 5. Certificate Lifecycle

A certificate passes through several operational stages.

    Certificate Request
           |
           v
    Identity Verification
           |
           v
    Issuance Policy Evaluation
           |
           v
    Certificate Issuance
           |
           v
    Certificate Distribution
           |
           v
    Certificate Deployment
           |
           v
    Continuous Validation
           |
           +-------------------+
           |                   |
           v                   v
        Renewal             Revocation
           |                   |
           v                   v
    Replacement          CRL / OCSP Status
           |
           v
    Deployment of New Certificate

### 5.1 Certificate Request

An applicant requests a certificate by submitting identity information and a public key.

A Certificate Signing Request (CSR) generally contains:

- Subject information.
- Public key.
- Requested certificate extensions.
- Optional attributes.
- A signature created using the corresponding private key.

The CA validates the request and verifies that the applicant is authorized to request the certificate.

A CSR does not itself establish identity or guarantee certificate issuance.

### 5.2 Certificate Issuance

The CA evaluates the request against its issuance policy.

The issuance workflow includes:

1. Request authentication.
2. Identity verification.
3. Subject validation.
4. Public-key algorithm evaluation.
5. Key-size and cryptographic policy checks.
6. Validity-period evaluation.
7. Key Usage and Extended Key Usage selection.
8. Certificate generation.
9. Certificate signing.
10. Audit recording.

The issuing CA signs the certificate using its private key.

The corresponding public key is used to verify the certificate signature during chain validation.

### 5.3 Certificate Deployment

After issuance, the certificate is installed in the relevant application, server, device, or operating-system certificate store.

A TLS server deployment commonly requires:

- The server certificate.
- The corresponding private key.
- Required intermediate certificates.
- Appropriate TLS configuration.

The private key must remain protected and must never be distributed with the public certificate.

### 5.4 Certificate Renewal

Renewal replaces a certificate before or around its expiration.

The replacement certificate normally receives:

- A new serial number.
- A new validity period.
- A newly issued certificate.
- A new certificate fingerprint.

Renewal does not necessarily require generating a new public/private key pair. Key rotation and certificate renewal are related but separate operations.

A secure renewal workflow should evaluate whether the existing key remains appropriate.

Key compromise requires a different response from routine expiration.

The Python, JavaScript, C++, and Java implementations associate an old certificate with its replacement.

The PostgreSQL implementation uses the `replacement_for` relationship.

### 5.5 Certificate Revocation

Revocation invalidates a certificate before its normal expiration.

Typical revocation reasons include:

| Reason | Description |
|---|---|
| KEY_COMPROMISE | Private key compromise |
| CA_COMPROMISE | CA private key compromise |
| SUPERSEDED | Certificate replaced |
| CESSATION_OF_OPERATION | Service or identity discontinued |
| PRIVILEGE_WITHDRAWN | Certificate holder no longer authorized |
| CERTIFICATE_HOLD | Temporary suspension where supported |

Revocation is particularly important when a private key is compromised or a certificate has been issued incorrectly.

A relying party must evaluate revocation information according to its security policy.

Revoking a CA certificate can invalidate certificates beneath it because the affected chain can no longer be accepted.

### 5.6 Certificate Expiration

A certificate is valid only within its specified validity period.

A certificate that has expired must not be accepted as currently valid under normal certificate validation rules.

Expiration and revocation represent different conditions:

- Expiration occurs when the validity period ends.
- Revocation occurs when an authorized authority invalidates the certificate before or during its validity period.

A certificate can be revoked before expiration.

## 6. Certificate Revocation Mechanisms

### 6.1 Certificate Revocation List

A Certificate Revocation List (CRL) is a digitally signed list published by a CA.

It contains information about certificates revoked by that authority.

Typical CRL fields include:

- Issuer.
- CRL number.
- This Update.
- Next Update.
- Revoked certificate serial numbers.
- Revocation dates.
- Revocation reasons.
- CRL signature.

The PostgreSQL implementation models:

- `crl_publications`
- `crl_entries`
- `certificate_revocations`

A CRL can become stale when it is not refreshed within its expected publication interval.

Applications must consider CRL freshness and retrieval failures.

### 6.2 Online Certificate Status Protocol

OCSP provides an online mechanism for checking certificate status.

A relying party sends a certificate status request to an OCSP responder.

The response generally indicates whether the certificate is:

- Good.
- Revoked.
- Unknown.

OCSP can reduce the need to retrieve complete CRLs for every validation operation.

Important operational considerations include:

- Responder availability.
- Response signatures.
- Response freshness.
- Nonce handling where applicable.
- Caching.
- Privacy implications.
- Soft-fail and hard-fail policies.

### 6.3 CRL and OCSP Comparison

| Attribute | CRL | OCSP |
|---|---|---|
| Mechanism | Published revocation list | Individual status response |
| Data retrieval | List-based | Request-response |
| Network usage | Periodic retrieval | Individual or cached requests |
| Freshness | This Update and Next Update | Response validity interval |
| Scaling | Large lists can be expensive | Requires responder infrastructure |
| Availability | Cached CRLs can remain available | Responder availability matters |

Neither mechanism eliminates the need for correct certificate-chain validation.

## 7. Implementation Architecture

The five source files implement related PKI lifecycle concepts using different engineering approaches.

### 7.1 Python

The Python implementation uses:

- Dataclasses for certificate and audit records.
- Enums for CA types, certificate statuses, and revocation reasons.
- Dictionaries for certificate and authority registries.
- Sets for trust anchors and key usage.
- Exceptions for invalid lifecycle operations.
- Functions for chain construction and validation.
- Assertions for verification of expected behavior.

The `PKIManager` class manages the certificate hierarchy.

Its primary operations are:

| Method | Responsibility |
|---|---|
| `create_root_ca()` | Creates a trust anchor |
| `create_intermediate_ca()` | Establishes a subordinate CA |
| `issue_certificate()` | Issues an end-entity certificate |
| `build_chain()` | Constructs the issuer hierarchy |
| `validate_certificate()` | Evaluates structural trust |
| `revoke_certificate()` | Records revocation |
| `renew_certificate()` | Creates a replacement |
| `certificate_report()` | Displays the inventory |
| `audit_report()` | Displays lifecycle events |

The implementation uses dictionaries for constant-time average identifier lookup.

The audit log retains lifecycle events for operational inspection.

### 7.2 JavaScript

The JavaScript implementation adopts an event-driven architecture.

It uses:

- ES6 classes.
- Private class fields.
- Maps for registry management.
- Sets for trust anchors and key usage.
- EventEmitter for lifecycle events.
- Promises for asynchronous workflow handling.
- A serialized operation queue.
- Structured JSON inventory records.

The `PKIManager` class extends `EventEmitter`.

Each important lifecycle operation records an event and emits a notification.

The `enqueue()` method serializes asynchronous operations so that queued lifecycle changes execute in order.

This model is relevant to certificate management services that receive multiple requests from applications, devices, and enterprise automation processes.

### 7.3 C++17

The C++ implementation emphasizes explicit domain modeling and controlled state management.

It uses:

- Structures for certificate records.
- Enumerations for lifecycle states.
- Maps for registry lookup.
- Sets for trust anchors and key usage.
- Optional values for missing issuer and revocation information.
- Exceptions for operational failures.
- STL algorithms for chain processing.
- Assertions for validation tests.

The `PKIManager` class owns the certificate registry and controls modifications.

Using `std::map` provides logarithmic lookup complexity.

Using `std::set` provides logarithmic membership checks.

The certificate hierarchy is represented explicitly through issuer identifiers.

### 7.4 Java 17

The Java implementation models an enterprise PKI service through domain-oriented components.

Its main components are:

| Component | Responsibility |
|---|---|
| `Certificate` | Immutable certificate identity and metadata |
| `CertificateAuthority` | CA state and issuance authorization |
| `CertificateRepository` | Certificate persistence abstraction |
| `TrustStore` | Trusted root management |
| `IssuancePolicy` | Certificate issuance restrictions |
| `PKIService` | Lifecycle operations |
| `ValidationResult` | Structured validation outcome |
| `AuditEvent` | Lifecycle event representation |

Java records provide immutable structures for audit events, validation results, and policy definitions.

The repository separates certificate storage from lifecycle logic.

The service evaluates issuance policies before creating certificates.

The use of immutable collections prevents external modification of important policy and validation data.

### 7.5 PostgreSQL

The database implementation models a relational certificate management system.

The `pki` schema separates PKI objects from unrelated application data.

Principal tables include:

| Table | Purpose |
|---|---|
| `organizations` | Enterprise ownership |
| `certificate_authorities` | Root and intermediate CA records |
| `certificates` | Certificate metadata |
| `issuance_policies` | CA issuance restrictions |
| `trust_anchors` | Trusted root configuration |
| `certificate_revocations` | Revocation records |
| `crl_publications` | CRL publication metadata |
| `crl_entries` | CRL membership |
| `certificate_validations` | Validation history |
| `pki_audit_events` | Lifecycle audit history |

The database uses primary keys, foreign keys, unique constraints, check constraints, indexes, triggers, functions, procedures, views, and recursive CTEs.

The `get_certificate_status()` function evaluates certificate lifecycle state.

The `validate_certificate_issuance()` function evaluates issuance eligibility.

The `validate_certificate()` function checks certificate hierarchy, lifecycle state, issuer relationships, and trust-anchor membership.

The `revoke_certificate()` procedure performs revocation and records an audit event.

The `certificate_inventory` view presents certificate metadata and current lifecycle status.

The `ca_hierarchy` view uses a recursive CTE to display the CA hierarchy.

## 8. Certificate Validation Rules

Certificate validation must evaluate multiple independent conditions.

| Validation condition | Failure example |
|---|---|
| Certificate existence | Unknown serial number |
| Validity period | Expired certificate |
| Revocation | Compromised private key |
| Issuer availability | Missing intermediate |
| Issuer relationship | Incorrect issuer |
| Key identifier | Authority key mismatch |
| Trust anchor | Untrusted root |
| CA authorization | Non-CA issuer |
| Key Usage | Missing certificate-signing permission |
| Path length | Excessive CA hierarchy |
| Certificate purpose | Incorrect Extended Key Usage |

A structurally correct issuer relationship does not prove that a certificate signature is cryptographically valid.

A production X.509 validator must also verify:

- Every certificate signature.
- Subject Alternative Name requirements.
- Basic Constraints.
- Key Usage.
- Extended Key Usage.
- Name Constraints.
- Policy Constraints.
- Certificate Policies.
- Algorithm restrictions.
- Critical extensions.
- Applicable revocation information.

The source files deliberately distinguish lifecycle and governance modeling from full cryptographic X.509 validation.

## 9. Security Considerations

### 9.1 Private Key Protection

Private keys are more sensitive than public certificates.

Appropriate controls include:

- Hardware-backed key storage.
- Strong access control.
- Separation of signing and administrative roles.
- Key rotation.
- Encrypted backups.
- Multi-person authorization for root operations.
- Monitoring of signing activity.

Private keys must not be stored in ordinary certificate inventory tables.

### 9.2 Root CA Protection

Root CA compromise can undermine an entire certificate hierarchy.

A root CA should have a restricted operational environment and a controlled signing process.

Intermediate CAs handle routine issuance to reduce exposure of the root signing key.

### 9.3 Certificate Lifetime

Shorter certificate lifetimes can reduce the period during which an improperly issued certificate remains valid.

They also increase renewal frequency and operational workload.

Certificate lifetime policy should balance security, availability, automation, and administrative capacity.

### 9.4 Revocation Availability

A certificate validation system depends on reliable revocation information.

Unavailable CRL or OCSP services can affect authentication decisions.

Applications should define explicit revocation-checking behavior rather than applying an undocumented failure policy.

### 9.5 Algorithm Security

Certificate issuance policies must restrict cryptographic algorithms and key sizes.

An organization should prevent issuance using deprecated or insecure algorithms.

The certificate signature algorithm and public-key algorithm represent different properties and must be evaluated separately.

### 9.6 Audit Integrity

PKI audit records should capture:

- Certificate issuance.
- Renewal.
- Revocation.
- CA status changes.
- Trust-anchor modifications.
- Administrative actions.
- Validation outcomes.
- Policy changes.

Production audit systems should protect logs against unauthorized modification and deletion.

## 10. Performance and Scalability

A PKI service may manage thousands or millions of certificates.

Important performance considerations include:

| Component | Performance consideration |
|---|---|
| Certificate lookup | Index serial numbers and identifiers |
| Subject lookup | Index normalized subject information |
| CA hierarchy | Maintain indexed issuer relationships |
| Revocation lookup | Index certificate identifiers |
| Expiration monitoring | Index validity dates |
| Audit reporting | Index event timestamps and event types |
| Validation | Cache carefully with short, policy-controlled lifetimes |
| CRL processing | Use efficient serial-number lookup |
| OCSP processing | Apply bounded caching and concurrency controls |

The in-memory implementations use maps or dictionaries for certificate retrieval.

The PostgreSQL implementation creates indexes for issuer identifiers, validity periods, revocation records, and validation history.

A production service should avoid rebuilding the complete certificate hierarchy for every request when validated intermediate results can be safely reused.

Cached validation results must be invalidated or restricted when revocation, trust-store, or policy information changes.

## 11. Edge Cases and Failure Scenarios

The implementations exercise several important failure conditions.

| Scenario | Expected behavior |
|---|---|
| Unknown CA | Issuance rejected |
| Inactive CA | Issuance rejected |
| Expired CA | Issuance rejected |
| Excessive validity | Policy violation |
| Empty subject | Request rejected |
| Invalid key usage | Request rejected |
| Duplicate certificate identifier | Registration rejected |
| Missing issuer | Chain validation fails |
| Incorrect authority key identifier | Chain validation fails |
| Untrusted root | Chain validation fails |
| Expired end-entity certificate | Validation fails |
| Revoked certificate | Validation fails |
| Repeated revocation | Operation rejected |
| Invalid renewal target | Renewal rejected |
| Excessive path length | Chain validation fails |
| Revoked intermediate | Descendant chains cannot be trusted |

These conditions demonstrate why certificate lifecycle management requires policy enforcement, consistent state transitions, and auditability.

## 12. Limitations and Production Boundaries

The Python, JavaScript, C++, and Java programs are executable PKI lifecycle simulations.

They model:

- Certificate metadata.
- CA relationships.
- Trust anchors.
- Issuance policies.
- Certificate validity.
- Revocation state.
- Renewal relationships.
- Structural chain evaluation.
- Audit events.

They do not generate real X.509 certificates, generate cryptographic key pairs, sign certificate structures, or verify actual certificate signatures.

Their simulated key identifiers and fingerprints are not substitutes for public-key-derived X.509 identifiers and cryptographic certificate fingerprints.

The PostgreSQL implementation provides relational lifecycle management and structural validation. It does not independently verify X.509 signatures.

The sample SQL records use representative certificate metadata and should not be treated as production-issued certificates.

A production PKI must integrate:

- Real X.509 certificate processing.
- Cryptographic signature verification.
- Secure key generation.
- HSM-backed CA signing.
- CSR processing.
- Certificate profile enforcement.
- CRL and OCSP publication.
- Secure trust-store management.
- Certificate transparency requirements where applicable.
- Identity verification.
- Secure administrative authentication.
- Disaster recovery.
- Key compromise response.
- Auditable CA operations.

The lifecycle registry and the cryptographic certificate-validation engine are separate architectural responsibilities. Both are required for a complete production PKI.
