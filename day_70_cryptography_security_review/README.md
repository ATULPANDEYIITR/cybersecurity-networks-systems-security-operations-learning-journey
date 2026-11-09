# Cryptography Security Review

## 1. Project Overview

Cryptography Security Review is a security assessment and governance system for identifying weaknesses in cryptographic configurations, evaluating key management practices, examining certificate security, and managing remediation activities.

Cryptography protects confidentiality, integrity, authentication, and trust across applications, infrastructure, communications, and stored information. Its effectiveness depends on more than selecting a strong algorithm. Incorrect implementation, weak configuration, compromised keys, invalid certificates, and inadequate operational controls can undermine otherwise sound cryptographic designs.

The project models a practical security assessment process across five implementations:

| Implementation | Engineering perspective | Main responsibility |
|---|---|---|
| Python | Security assessment and simulation | Asset analysis, finding generation, reporting, and testing |
| JavaScript | Event-driven security operations | Asynchronous assessment, events, and finding management |
| C++17 | Security evaluation engine | Algorithm, key, certificate, and risk analysis |
| Java 17 | Enterprise security governance | Policies, reviewers, audit records, and state transitions |
| PostgreSQL | Relational security management | Asset inventory, assessment records, reviews, and reporting |

Each implementation uses its own domain model and processing approach. The examples are independent and do not require a shared application server.

## 2. Cryptography Security Fundamentals

Cryptography uses mathematical algorithms and secret or public information to provide security properties.

The principal security objectives are:

| Objective | Meaning | Cryptographic mechanism |
|---|---|---|
| Confidentiality | Prevent unauthorized disclosure | Encryption |
| Integrity | Detect unauthorized modification | Hashes and authentication mechanisms |
| Authentication | Establish the identity of a communicating party | Certificates, signatures, and authentication protocols |
| Non-repudiation | Provide evidence supporting attribution of an action | Digital signatures and controlled key management |

A security review must determine whether the cryptographic mechanism is appropriate for its purpose, whether it has been configured correctly, and whether its supporting keys and trust relationships remain secure.

### 2.1 Cryptographic algorithm categories

| Category | Purpose | Examples |
|---|---|---|
| Symmetric encryption | Encrypt and decrypt using a shared secret | AES |
| Asymmetric cryptography | Public-key encryption, key establishment, and signatures | RSA, elliptic-curve cryptography |
| Hash functions | Produce fixed-length digests | SHA-256, SHA-384, SHA-512 |
| Message authentication | Verify message authenticity and integrity | HMAC |
| Digital signatures | Authenticate signed information | RSA-PSS, ECDSA, EdDSA |
| Key derivation | Derive cryptographic keys from input material | HKDF, PBKDF2, Argon2id |

These mechanisms are not interchangeable. A cryptographic hash does not encrypt information, and encryption without authentication does not necessarily protect ciphertext integrity.

## 3. Common Cryptographic Failures

Cryptographic failures frequently result from inappropriate algorithm selection, insecure implementation, incorrect configuration, or poor operational practices.

### 3.1 Weak and deprecated algorithms

Older algorithms can have insufficient security margins or known structural weaknesses.

| Algorithm | Security concern | Assessment |
|---|---|---|
| MD5 | Practical collision attacks | Unsuitable for security-sensitive collision resistance |
| SHA-1 | Practical collision attacks | Deprecated for collision-resistant applications |
| DES | Insufficient key length | Insecure for modern encryption |
| 3DES | Legacy construction and performance limitations | Avoid for new systems |
| RC4 | Statistical biases and practical attacks | Deprecated |
| RSA-1024 | Insufficient security strength | Below the project's minimum RSA policy |
| AES-ECB | Reveals patterns in repeated plaintext blocks | Avoid |
| TLS 1.0 | Obsolete protocol version | Reject under the project policy |

Algorithm suitability depends on the intended operation. For example, SHA-1 should not be used for new digital signature or collision-resistant integrity designs, but the presence of SHA-1 in every possible context does not imply the same vulnerability.

The assessment engines identify deprecated algorithms and configurations that violate the defined policy.

### 3.2 Weak encryption modes

AES is a standardized block cipher. Its security depends partly on how the cipher is used.

ECB encrypts identical plaintext blocks into identical ciphertext blocks under the same key. This can expose structural information.

CBC requires correct initialization vector handling and a separate integrity mechanism when used without authentication.

GCM provides authenticated encryption with associated data. It provides confidentiality and integrity when implemented correctly.

Important GCM requirements include:

- Use a unique nonce for every encryption operation under the same key.
- Never reuse a nonce with the same key.
- Verify the authentication tag before accepting decrypted plaintext.
- Use appropriate tag lengths.
- Define safe key rotation and usage limits.

The implementations flag ECB and explicitly unauthenticated encryption configurations. They do not claim to detect actual nonce reuse from configuration metadata alone.

### 3.3 Weak randomness

Cryptographic systems depend on unpredictable values.

Predictable randomness can compromise:

- Encryption keys.
- Session identifiers.
- Authentication tokens.
- Nonces and initialization vectors.
- Password reset tokens.
- Key establishment operations.

General-purpose random number generators are not necessarily cryptographically secure.

The Python implementation identifies sources such as `random.random()` and `math.random()`.

The JavaScript implementation uses the distinction between general-purpose random generation and Node.js cryptographic facilities such as `crypto.randomBytes()`.

The C++ and Java implementations evaluate the recorded randomness configuration as security metadata.

Production systems should use operating-system-backed cryptographic random number generators.

A nonce does not necessarily need to be secret, but it must satisfy the uniqueness or unpredictability requirements of its specific cryptographic construction.

## 4. Cryptographic Key Management

Key management governs the complete lifecycle of cryptographic keys.

A secure algorithm cannot compensate for an exposed private key or an improperly protected symmetric key.

### 4.1 Key lifecycle

The lifecycle modeled in the project is:

`Key Generation → Registration → Secure Storage → Distribution → Usage → Rotation → Revocation → Destruction`

Each stage introduces different security responsibilities.

| Lifecycle stage | Security requirement | Common failure |
|---|---|---|
| Generation | Cryptographically secure randomness | Predictable key material |
| Registration | Accurate metadata and ownership | Unknown key ownership |
| Storage | Protected key custody | Plaintext key files |
| Distribution | Authenticated and secure transfer | Key interception |
| Usage | Restricted permissions and purpose | Unauthorized key operations |
| Rotation | Defined cryptoperiod | Excessively old keys |
| Revocation | Immediate response to compromise | Continued use of compromised keys |
| Destruction | Verifiable removal | Residual secret material |

### 4.2 Key exposure

Key exposure occurs when secret or private key material becomes accessible to unauthorized parties.

Potential exposure channels include:

- Public source repositories.
- Application logs.
- Debugging output.
- Unencrypted backups.
- Misconfigured cloud storage.
- Compromised endpoints.
- Unauthorized memory access.
- Improper key export.

An exposed key must be treated as compromised.

The response should include:

1. Identifying affected cryptographic assets.
2. Revoking or disabling the compromised key.
3. Rotating dependent credentials.
4. Reviewing systems and records that used the key.
5. Investigating the exposure mechanism.
6. Evaluating historical data and signatures affected by the compromise.
7. Recording the incident and remediation evidence.

Simply changing a configuration flag does not remediate a compromised key.

### 4.3 Hardware security modules

A Hardware Security Module (HSM) provides a controlled hardware environment for cryptographic operations and key protection.

HSM-backed operations can reduce direct exposure of private key material.

Key custody policies should consider:

- Key generation boundaries.
- Export restrictions.
- Access authorization.
- Administrative separation.
- Backup and recovery.
- Rotation and revocation.
- Hardware availability.
- Auditability.

The implementations distinguish HSM storage from ordinary file-based storage.

An HSM designation alone does not establish secure operation. Configuration, access controls, administrative procedures, and the actual hardware boundary must also be examined.

### 4.4 Cryptoperiod and rotation

A cryptoperiod is the approved period during which a cryptographic key may be used.

Rotation requirements depend on:

- Key type.
- Cryptographic purpose.
- Exposure history.
- Data sensitivity.
- Usage volume.
- Applicable standards.
- Organizational policy.

The implementations provide a configurable default rotation threshold of 365 days.

This is an example policy value, not a universal requirement for every key.

Emergency rotation is necessary when a key is compromised, even if its normal cryptoperiod has not ended.

## 5. Certificate Security Review

Digital certificates bind identities to public keys through digitally signed statements issued by certificate authorities.

Certificate security requires more than checking the expiration date.

### 5.1 Certificate components

| Component | Function |
|---|---|
| Subject | Identifies the certificate holder |
| Issuer | Identifies the issuing authority |
| Public key | Provides the public cryptographic component |
| Validity period | Defines the certificate's permitted time interval |
| Signature algorithm | Defines how the certificate was signed |
| Subject Alternative Name | Specifies supported DNS names or other identities |
| Certificate chain | Connects the certificate to a trusted root |
| Serial number | Identifies the certificate within its issuing CA |

### 5.2 Certificate validation requirements

The project assesses the following conditions:

**Expiration**

A certificate must be within its validity period. Expired certificates can cause service interruptions and authentication failures.

**Not-before validation**

A certificate must not be accepted before its validity start time.

**Hostname verification**

The requested hostname must match an appropriate certificate identity, normally represented through the Subject Alternative Name extension.

**Issuer trust**

The issuing certificate authority must be trusted under the applicable trust configuration.

**Certificate chain**

Intermediate certificates and their signatures must form a valid chain to an accepted trust anchor.

**Revocation**

Revocation status must be checked through appropriate mechanisms, such as OCSP or CRLs, according to the system's requirements.

**Signature strength**

Deprecated signature algorithms must be rejected where they violate the security policy.

**Public-key strength**

The certificate's public key must satisfy the applicable algorithm and key-size requirements.

### 5.3 Wildcard hostname matching

A wildcard certificate such as `*.example.com` normally covers a single DNS label.

Examples:

| Hostname | Expected result |
|---|---|
| `api.example.com` | Match |
| `mail.example.com` | Match |
| `example.com` | No match |
| `a.b.example.com` | No match |

The Python, JavaScript, and Java implementations include wildcard matching logic for this simplified domain model.

Actual certificate validation must use a standards-compliant TLS or X.509 implementation and the certificate's Subject Alternative Name extension.

A certificate's Common Name should not be treated as a universal replacement for SAN validation.

### 5.4 Certificate trust workflow

`Server Certificate → Validity Check → Hostname Check → Chain Construction → Signature Verification → Trust Anchor → Revocation Check → Acceptance Decision`

A certificate can be unexpired and still be invalid because its hostname, signature, issuer, or chain is incorrect.

## 6. TLS Security Review

Transport Layer Security protects communication between endpoints.

The project identifies legacy TLS versions and accepts TLS 1.2 and TLS 1.3 as its baseline protocol versions.

A production TLS review should examine:

- Minimum and maximum protocol versions.
- Cipher suite configuration.
- Forward secrecy.
- Certificate identity verification.
- Certificate chain validation.
- Server and client authentication requirements.
- Secure renegotiation where applicable.
- Session resumption.
- Protocol downgrade resistance.
- TLS termination points.
- Certificate renewal and deployment.

TLS 1.3 changes several aspects of the handshake and cipher suite configuration compared with earlier versions.

A protocol-version check alone cannot establish that a TLS deployment is secure.

The implementations treat protocol version as one assessment input rather than a complete TLS validation mechanism.

## 7. Security Assessment Architecture

The system separates asset information, security policies, assessment logic, findings, and remediation records.

### 7.1 Logical architecture

             CRYPTOGRAPHIC ASSETS
                      |
                      v
              ASSET INVENTORY
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Algorithm    Key         Certificate
       Analysis   Analysis       Analysis
          |           |           |
          +-----------+-----------+
                      |
                      v
              POLICY EVALUATION
                      |
                      v
              SECURITY FINDINGS
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       Severity    Risk Score   Classification
          |           |           |
          +-----------+-----------+
                      |
                      v
              REVIEW WORKFLOW
                      |
                      v
               REMEDIATION
                      |
                      v
              AUDIT AND REPORTING

### 7.2 Core domain relationships

| Domain object     | Responsibility                                                       |
|-------------------|----------------------------------------------------------------------|
| CryptoAsset       | Represents an application, service, or component using cryptography |
| SecurityPolicy    | Defines approved configurations and thresholds                      |
| KeyRecord         | Stores key lifecycle metadata                                        |
| CertificateRecord | Stores certificate validation metadata                               |
| SecurityFinding   | Represents an identified security weakness                           |
| Reviewer          | Represents an authorized security reviewer                           |
| ReviewRecord      | Stores a review decision                                             |
| AuditEvent        | Records security-related operations                                  |

The asset inventory identifies where cryptographic mechanisms are used. Assessment engines evaluate those configurations against a policy.

A finding records an identified weakness independently of the asset's configuration record.

This distinction supports multiple findings for one asset and allows remediation progress to be tracked without losing the original assessment information.

## 8. Security Finding Management

A security finding represents an actionable observation from an assessment.

### 8.1 Finding categories

| Category       | Assessment focus                            |
|----------------|---------------------------------------------|
| WEAK_ALGORITHM | Deprecated or insufficient algorithms      |
| KEY_MANAGEMENT | Key storage, exportability, and rotation    |
| KEY_EXPOSURE   | Compromised or exposed keys                 |
| CERTIFICATE    | Expiration, trust, identity, and signatures |
| TLS            | Legacy protocol configurations              |
| RANDOMNESS     | Predictable random sources                  |
| CONFIGURATION  | Unsafe cryptographic settings               |

### 8.2 Severity classification

| Severity      | Weight | Meaning                                          |
|---------------|--------|--------------------------------------------------|
| CRITICAL      | 10     | Severe compromise or immediate security concern |
| HIGH          | 7      | Significant weakness requiring prompt correction |
| MEDIUM        | 4      | Material security deficiency                    |
| LOW           | 2      | Limited security concern                         |
| INFORMATIONAL | 1      | Observation requiring awareness                 |

The sample risk calculation adds the weights of open findings and caps the result at 100.

Risk classification uses these ranges:

| Score  | Classification   |
|--------|------------------|
| 0      | NO_OPEN_FINDINGS  |
| 1–7    | LOW               |
| 8–17   | MEDIUM            |
| 18–29  | HIGH              |
| 30–100 | CRITICAL          |

This scoring mechanism is an illustrative prioritization model. It is not a standardized vulnerability score and should not replace contextual risk analysis.

Production scoring should consider exploitability, asset criticality, exposure, business impact, compensating controls, and evidence quality.

### 8.3 Finding state transitions

The implemented lifecycle is:

                  +----------------+
                  |      OPEN      |
                  +----------------+
                         |
                         v
                  +----------------+
                  |   IN_REVIEW    |
                  +----------------+
                     /     |      \
                    /      |       \
                   v       v        v
           REMEDIATED  ACCEPTED   FALSE_POSITIVE
                       RISK

The model also permits returning an in-review or accepted-risk finding to an appropriate active state.

Remediated and false-positive findings are terminal in the supplied implementations.

Accepted risk is not equivalent to remediation. It records a governance decision to tolerate a documented risk.

## 9. Python Implementation

### 9.1 Design

The Python application uses dataclasses and enumerations to define its domain objects.

The main components are:

| Component | Responsibility |
|---|---|
| `CryptoPolicy` | Defines assessment thresholds |
| `CryptoAsset` | Represents a cryptographic implementation |
| `KeyRecord` | Represents key lifecycle metadata |
| `CertificateRecord` | Represents certificate metadata |
| `AlgorithmAnalyzer` | Identifies weak algorithms and configurations |
| `KeyAnalyzer` | Assesses key exposure and rotation |
| `CertificateAnalyzer` | Checks certificate metadata |
| `RiskScorer` | Calculates aggregate risk |
| `CryptoSecurityReview` | Coordinates assessments and reporting |

### 9.2 Algorithm analysis

The `AlgorithmAnalyzer` evaluates:

- Deprecated hash algorithms.
- Weak symmetric algorithms.
- Insufficient RSA key sizes.
- Unsafe AES modes.
- Missing authenticated encryption.
- Unsupported TLS versions.
- Predictable randomness sources.

The analyzer produces structured finding data rather than mixing assessment decisions with report formatting.

### 9.3 Key lifecycle assessment

The `KeyAnalyzer` evaluates whether a key has been exposed, whether it is exportable outside the recorded hardware protection boundary, and whether its rotation is overdue.

Key records contain metadata only. They do not contain private or symmetric key material.

### 9.4 Certificate assessment

The `CertificateAnalyzer` examines validity periods, revocation status, issuer trust, chain validity, hostname matching, signature algorithms, and RSA public-key size.

Its hostname matching implementation demonstrates basic single-label wildcard behavior.

### 9.5 Testing and reporting

The script includes unit tests for:

- Deprecated hash detection.
- Duplicate asset rejection.
- Finding transitions.
- Terminal finding states.
- Secure randomness classification.
- Wildcard hostname matching.
- Risk scoring.

The report is exported as JSON.

The implementation uses Python standard-library facilities, including `dataclasses`, `enum`, `datetime`, `json`, `logging`, `pathlib`, and `unittest`.

## 10. JavaScript Implementation

### 10.1 Event-driven architecture

The JavaScript implementation uses Node.js standard-library capabilities.

`SecurityReviewService` extends `EventEmitter`, allowing assessment operations and finding changes to produce events.

Important events include:

| Event | Purpose |
|---|---|
| `asset:registered` | Indicates asset registration |
| `finding:created` | Announces a new security finding |
| `finding:updated` | Records a finding state change |

This design separates the security assessment process from consumers of assessment events.

An enterprise application could use these events to initiate notifications, dashboards, or downstream remediation workflows.

### 10.2 Asynchronous assessment

The `assessAsset()` method is asynchronous.

The `assessInBatches()` function coordinates concurrent asset assessment using a bounded worker pattern.

Its concurrency parameter controls how many assessment workers execute simultaneously.

This prevents a large asset inventory from being submitted without an explicit concurrency limit.

The example performs in-memory assessments. It does not implement distributed task execution or durable job recovery.

### 10.3 Policy and lifecycle evaluation

The JavaScript policy object stores deprecated algorithms, weak ciphers, RSA requirements, and approved TLS versions.

The key lifecycle inspector calculates age from creation and rotation timestamps.

The certificate inspector validates metadata and wildcard hostname behavior.

### 10.4 Report generation

The application generates a JSON report containing:

- Asset count.
- Finding count.
- Risk score.
- Risk classification.
- Severity distribution.
- Finding status distribution.
- Individual finding records.

The report writer uses asynchronous filesystem operations and restrictive file permissions where supported.

Reports should still be stored in an appropriately secured directory with access controls and retention policies.

## 11. C++17 Implementation

### 11.1 Domain-oriented engine

The C++ implementation emphasizes explicit domain structures, validation, and controlled state management.

Its main components are:

| Component | Responsibility |
|---|---|
| `CryptoAsset` | Cryptographic asset definition |
| `KeyRecord` | Key lifecycle information |
| `Certificate` | Certificate metadata |
| `Finding` | Security finding and lifecycle |
| `SecurityPolicy` | Assessment configuration |
| `CryptoSecurityEngine` | Central assessment engine |
| `RiskScorer` | Risk calculation |

### 11.2 Assessment mechanisms

The engine uses STL containers for asset registration, finding storage, and lookup.

An unordered map provides average constant-time asset lookup.

A vector stores findings and supports ordered reporting.

The finding index maps finding identifiers to vector positions.

The engine evaluates:

- Deprecated hash algorithms.
- Weak encryption ciphers.
- RSA key strength.
- Encryption modes.
- Authentication configuration.
- TLS versions.
- Randomness sources.
- Key lifecycle conditions.
- Certificate trust and expiration metadata.

### 11.3 State management

The `Finding` structure implements explicit transition validation.

The engine rejects attempts to reopen findings directly after remediation or false-positive closure.

Exceptions provide clear failure information for invalid identifiers, duplicate assets, invalid inputs, and prohibited state changes.

### 11.4 Performance characteristics

Let:

- A represent the number of assets.
- K represent the number of key records.
- C represent the number of certificates.
- F represent the number of findings.

Average unordered-map lookup is approximately O(1).

Asset registration is approximately O(1) on average.

Risk calculation is O(F).

Report generation is O(F log F) if findings are sorted for severity-based output.

The implementation is designed for in-memory educational assessment workloads rather than a production-scale distributed scanning service.

## 12. Java 17 Implementation

### 12.1 Enterprise domain model

The Java application separates assessment logic from governance responsibilities.

Java records define immutable data objects for assets, keys, certificates, policies, reviewers, reviews, and audit events.

The `SecurityFinding` class maintains controlled mutable state.

This separation prevents ordinary callers from modifying finding lifecycle information without invoking its transition rules.

### 12.2 Policy-driven evaluation

The `SecurityPolicy` record defines:

- Minimum RSA key size.
- Maximum key age.
- Certificate expiration warning threshold.
- Deprecated hash algorithms.
- Weak ciphers.
- Approved TLS versions.

The policy uses defensive immutable sets through `Set.copyOf()`.

This prevents external modifications to the collection values after policy construction.

### 12.3 Reviewer governance

The `Reviewer` record identifies reviewer responsibilities.

The `GovernanceService` checks whether the reviewer is active and authorized to assess the finding category.

It supports three decisions:

| Decision | Meaning |
|---|---|
| `APPROVE_REMEDIATION` | Accepts the remediation decision |
| `REJECT_REMEDIATION` | Rejects the proposed remediation |
| `ACCEPT_RISK` | Records an accepted-risk decision |

The application also records review events through an `AuditSink` interface.

The supplied `InMemoryAuditSink` demonstrates event capture without introducing a database dependency.

### 12.4 Concurrency considerations

The Java finding transition method is synchronized.

This prevents simultaneous callers from changing the same finding state without synchronization.

The collection-level application services in the example are designed for a single-process demonstration. A production deployment requires transaction boundaries, database concurrency controls, authenticated reviewer identities, and durable audit records.

## 13. PostgreSQL Data Model

### 13.1 Relational architecture

The PostgreSQL implementation stores cryptographic security information in the `crypto_audit` schema.

The main relationships are:

SECURITY_POLICIES
       |
       v
CRYPTO_ASSETS
       |
       +----------------------+
       |                      |
       v                      v
CRYPTOGRAPHIC_KEYS       CERTIFICATES
       |                      |
       +----------+-----------+
                  |
                  v
            SECURITY_FINDINGS
                  |
           +-------+--------+
           |                |
           v                v
      SECURITY_REVIEWS   STATUS_HISTORY
           |
           v
        REVIEWERS
           |
           v
 REVIEWER_SPECIALIZATIONS

CRYPTO_ASSETS
       |
       v
SECURITY_STATUS_CHECKS

ALL IMPORTANT OPERATIONS
       |
       v
AUDIT_EVENTS

### 13.2 Table responsibilities

| Table                      | Purpose                                       |
| -------------------------- | --------------------------------------------- |
| `security_policies`        | Defines security assessment thresholds        |
| `crypto_assets`            | Maintains cryptographic asset inventory       |
| `cryptographic_keys`       | Stores key metadata and lifecycle information |
| `certificates`             | Maintains certificate records                 |
| `reviewers`                | Stores security reviewer identities           |
| `reviewer_specializations` | Defines reviewer responsibilities             |
| `security_findings`        | Stores assessment results                     |
| `finding_status_history`   | Maintains status transition history           |
| `security_reviews`         | Stores reviewer decisions                     |
| `security_status_checks`   | Stores automated check results                |
| `audit_events`             | Maintains operational audit events            |

### 13.3 Integrity constraints

The schema uses:

- Primary keys for record identification.
- Foreign keys for relational integrity.
- Unique constraints for business identifiers.
- Check constraints for valid ranges and states.
- Enumerated types for controlled categories.
- Indexes for frequently queried attributes.

The key table does not contain raw key material.

This is an intentional security decision. Key metadata and secret key material have different storage and access requirements.

### 13.4 Database triggers

The implementation provides several triggers.

**Finding transition trigger**

Validates status transitions and records status history.

**Finding audit trigger**

Records finding creation, modification, and deletion events.

**Reviewer eligibility trigger**

Ensures that a reviewer is active, security-qualified, and specialized in the finding category.

**Key exposure trigger**

Automatically creates a critical security finding when a key changes from unexposed to exposed.

Triggers provide database-level integrity enforcement independently of application-level validation.

### 13.5 Assessment functions and procedures

The SQL script implements:

| Function or procedure      | Responsibility                                  |
| -------------------------- | ----------------------------------------------- |
| `evaluate_asset()`         | Assesses algorithm and configuration weaknesses |
| `evaluate_key_lifecycle()` | Evaluates key rotation and storage              |
| `evaluate_certificates()`  | Identifies certificate failures                 |
| `run_full_assessment()`    | Coordinates the assessment                      |
| `process_review()`         | Processes a reviewer decision                   |
| `calculate_risk_score()`   | Calculates risk from open findings              |

The functions use structured inserts and unique finding codes to avoid repeatedly creating the same assessment finding during subsequent scans.

### 13.6 Reporting and analytical queries

The SQL script includes:

- Asset retrieval.
- Weak algorithm identification.
- Exposed key retrieval.
- Certificate health reporting.
- Severity aggregation.
- Owner-team risk reporting.
- Key rotation reporting.
- Status-check pass rates.
- Audit history.
- Review history.
- CTE-based management reporting.

The reporting views separate frequently required reporting logic from operational table structures.

## 14. Distinctions Between Security Mechanisms

Several cryptographic concepts are related but have different responsibilities.

### 14.1 Hashing versus encryption

| Property        | Hashing                             | Encryption                          |
| --------------- | ----------------------------------- | ----------------------------------- |
| Primary purpose | Digest generation                   | Confidentiality                     |
| Reversible      | No practical reversal is intended   | Yes, with the appropriate key       |
| Key requirement | Usually no key                      | Requires cryptographic key material |
| Typical use     | Integrity and password verification | Data protection                     |

Passwords should not be stored using a general-purpose fast hash alone. Password storage requires an appropriate password-hashing construction, unique salts, and suitable work factors.

### 14.2 Encryption versus authenticated encryption

Encryption without authentication may provide confidentiality while leaving ciphertext vulnerable to modification.

Authenticated encryption combines confidentiality with integrity and authenticity protection.

The project identifies configurations explicitly recorded as unauthenticated.

### 14.3 Public keys versus private keys

Asymmetric cryptography uses related public and private keys.

The public key may be distributed according to the protocol's trust requirements.

The private key must remain protected and should only be accessible to authorized cryptographic operations.

A public-key certificate does not contain the corresponding private key.

### 14.4 Certificate validity versus certificate trust

A certificate can be within its validity period and still be untrusted.

Trust depends on multiple conditions, including issuer trust, certificate signatures, chain construction, hostname verification, and revocation status.

### 14.5 Security findings versus remediation

A security finding records an identified weakness.

Remediation is the process of correcting that weakness and providing evidence that the correction is effective.

A finding should not be marked remediated merely because a configuration change was proposed.

The implementation models status transitions and review records separately to maintain this distinction.

## 15. Security Controls and Operational Considerations

A cryptography security review should consider both technical controls and operational governance.

| Area              | Required consideration                          |
| ----------------- | ----------------------------------------------- |
| Access control    | Restrict key and certificate administration     |
| Secret protection | Prevent private key and password disclosure     |
| Logging           | Avoid logging secret material                   |
| Key rotation      | Apply purpose-specific cryptoperiods            |
| Revocation        | Respond to exposed or compromised keys          |
| Certificates      | Validate identity, trust, and revocation        |
| Encryption        | Use approved authenticated encryption           |
| Randomness        | Use cryptographically secure generators         |
| TLS               | Disable deprecated protocols                    |
| Auditability      | Preserve assessment and remediation history     |
| Backup            | Protect encrypted backups and recovery material |
| Change management | Require evidence for security-sensitive changes |

### 15.1 Least privilege

Only authorized identities should be able to perform key operations, modify cryptographic policies, approve remediation, or accept security risks.

### 15.2 Separation of duties

Key administration, security assessment, remediation, and risk acceptance should be separated where organizational requirements demand independent authorization.

### 15.3 Audit integrity

Security audit records should be protected against unauthorized alteration and deletion.

The in-memory Python, JavaScript, and Java audit mechanisms demonstrate event capture. They do not provide tamper-evident durable storage.

### 15.4 Secure evidence handling

Assessment evidence must not contain:

- Plaintext private keys.
- Symmetric encryption keys.
- Passwords.
- Authentication tokens.
- Secret recovery material.
- Unredacted sensitive configuration values.

Evidence should contain configuration metadata, affected asset identifiers, validation results, and sanitized diagnostic information.

## 16. Limitations and Assessment Boundaries

The implementations are configuration-oriented assessment and governance examples.

They do not constitute a complete cryptographic penetration testing platform or a replacement for a cryptographic library.

The following distinctions are important:

| Assessment area    | Implemented capability           | Additional validation required                   |
| ------------------ | -------------------------------- | ------------------------------------------------ |
| Weak algorithms    | Algorithm identification         | Actual implementation and usage inspection       |
| AES modes          | Configuration evaluation         | Ciphertext and implementation analysis           |
| GCM                | Authenticated-mode configuration | Nonce uniqueness and tag verification            |
| Key exposure       | Exposure metadata and workflow   | Secret scanning and forensic investigation       |
| Key rotation       | Age-based evaluation             | Key usage limits and dependency analysis         |
| HSM                | Storage classification           | Hardware and access-control verification         |
| Certificate expiry | Date evaluation                  | Actual X.509 certificate parsing                 |
| Hostname matching  | Simplified wildcard matching     | SAN parsing and standards-compliant verification |
| Certificate chain  | Trust metadata evaluation        | Actual signature and chain verification          |
| Revocation         | Revocation metadata              | OCSP or CRL validation                           |
| TLS                | Protocol-version assessment      | Live handshake and cipher-suite inspection       |
| Randomness         | Source classification            | Actual entropy and implementation analysis       |

The RSA minimum in the example is a configurable policy threshold. Cryptographic strength should be selected according to applicable standards and the intended security lifetime.

The certificate warning threshold is also configurable.

The risk score is a simplified internal prioritization mechanism and is not equivalent to CVSS or another formal risk methodology.

## 17. Execution and Validation

### Python

Requirements:

- Python 3.10 or later.
- No third-party packages.

Run the assessment script directly. It executes the demonstration, prints the assessment report, and runs its unit tests.

### JavaScript

Requirements:

- Node.js 18 or later.
- No npm packages.

Run the JavaScript file using Node.js. It executes the tests, processes assets asynchronously, produces finding events, and writes a JSON assessment report.

### C++17

Requirements:

- C++17-compatible compiler.

Compile with the C++17 language standard and execute the resulting program.

The application runs its validation tests before processing the sample assets.

### Java 17

Requirements:

- Java Development Kit 17.

Compile the source file and execute the `CryptoSecurityReview` class.

The application runs validation tests before executing the enterprise assessment demonstration.

### PostgreSQL

Requirements:

- PostgreSQL 14 or later.
- Permission to create a schema, types, tables, functions, procedures, and triggers.

Execute the SQL script in a dedicated development database.

The script creates the schema, loads sample data, executes assessments, and runs reporting queries.

The demonstration includes a deliberate transaction rollback to illustrate transaction isolation.

## 18. Practical Assessment Scenarios

The sample implementations cover the following situations.

| Scenario                                                   | Expected assessment                  |
| ---------------------------------------------------------- | ------------------------------------ |
| Legacy application uses MD5                                | High-severity algorithm finding      |
| Payment system uses AES-ECB                                | High-severity configuration finding  |
| API uses RSA-1024                                          | High-severity key-strength finding   |
| Service supports TLS 1.0                                   | High-severity TLS finding            |
| Token generator uses predictable randomness                | Critical randomness finding          |
| Key is exposed                                             | Critical key-exposure finding        |
| Exportable key is outside the HSM boundary                 | High-severity key-management finding |
| Key exceeds its configured cryptoperiod                    | Medium-severity rotation finding     |
| Certificate has expired                                    | Critical certificate finding         |
| Certificate issuer is untrusted                            | High-severity certificate finding    |
| Certificate hostname does not match                        | High-severity certificate finding    |
| Certificate has been revoked                               | Critical certificate finding         |
| Certificate uses a deprecated signature                    | High-severity certificate finding    |
| Finding is marked remediated without an allowed transition | Rejected workflow operation          |
| Reviewer lacks the required specialization                 | Rejected review operation            |

These scenarios demonstrate the relationship between cryptographic configuration, key protection, certificate trust, assessment decisions, and remediation governance.

## 19. Performance and Scalability

The implementations use data structures suited to their respective execution models.

| Implementation | Performance consideration                                            |
| -------------- | -------------------------------------------------------------------- |
| Python         | Dictionary-based asset and finding lookup                            |
| JavaScript     | Map-based lookup and bounded asynchronous workers                    |
| C++17          | Unordered maps for average constant-time lookup                      |
| Java 17        | Hash-based collections and stream-based aggregation                  |
| PostgreSQL     | Relational indexes, filtered indexes, views, and aggregation queries |

For a production assessment platform, additional considerations include:

- Incremental assessment instead of repeated full scans.
- Parallel processing across independent assets.
- Caching of unchanged assessment results.
- Idempotent finding creation.
- Durable task execution.
- Database connection pooling.
- Partitioning high-volume audit tables.
- Retention and archival policies.
- Concurrent update handling.
- Assessment versioning.
- Policy version tracking.
- Evidence integrity and provenance.

A production implementation should also retain the policy version and assessment timestamp associated with each finding so that changes in security requirements can be distinguished from changes in the assessed asset.

## 20. Educational and Technical Outcomes

The project demonstrates how cryptographic security assessment can be implemented across different programming paradigms.

The Python implementation emphasizes structured assessment and automated testing.

The JavaScript implementation demonstrates asynchronous processing and event-driven finding management.

The C++17 implementation emphasizes explicit domain structures, validation, state management, and risk evaluation.

The Java implementation demonstrates enterprise policy modeling, reviewer authorization, audit interfaces, and controlled state transitions.

The PostgreSQL implementation demonstrates relational integrity, automated assessment, database triggers, transactional workflow processing, and analytical reporting.

Together, the implementations establish a consistent assessment model:

`Cryptographic Inventory → Policy Evaluation → Security Finding → Risk Classification → Review → Remediation → Audit`

This model distinguishes algorithm security, key lifecycle protection, certificate trust, and transport security while providing a structured mechanism for tracking identified weaknesses and their resolution.
