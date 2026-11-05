# Digital Signatures: Signing, Verification, Certificates, and Trust

## 1. Technical Scope

Digital signatures establish the authenticity and integrity of digitally signed information through asymmetric cryptography.

The implementations demonstrate four connected mechanisms:

| Mechanism | Purpose |
|---|---|
| Signing | Creates a cryptographic signature using a private key |
| Verification | Checks a signature using the corresponding public key |
| Certificates | Bind an identity to a public key through an issuer's signature |
| Trust | Determines whether the certificate's issuing authority is accepted |

The implementations use Ed25519 for practical cryptographic signing in Python, JavaScript, and Java 17. The C++ implementation uses a deliberately small RSA mathematical simulation. PostgreSQL manages the associated certificate, document, signature, and verification records.

These mechanisms solve different security problems. A mathematically valid signature does not automatically establish that the signer is a trusted person.

## 2. Digital Signature Fundamentals

A digital signature is a cryptographic value generated from document data and a private signing key.

The basic process is:

1. A signer generates an asymmetric key pair.
2. The signer retains the private key securely.
3. The corresponding public key is distributed or certified.
4. The signing algorithm processes the document using the private key.
5. The recipient verifies the signature using the public key.

Conceptually:

    Document + Private Key
              |
              v
       Signing Algorithm
              |
              v
       Digital Signature

    Document + Signature + Public Key
              |
              v
      Verification Algorithm
              |
          +---+---+
          |       |
         Valid  Invalid

A private key must never be distributed with the signed document.

### 2.1 Asymmetric cryptography

Asymmetric cryptography uses two mathematically related keys.

| Key | Responsibility |
|---|---|
| Private key | Signing |
| Public key | Verification |

The public key does not need to remain secret. Its authenticity must be established.

A public key obtained from an untrusted source may belong to an attacker. Certificate-based identity validation addresses this problem.

### 2.2 Hashing and integrity

A cryptographic hash function converts input data into a fixed-length digest.

The implementations use SHA-256 where applicable.

For a document D:

    H = SHA-256(D)

The digest is sensitive to document modifications. Changing even a small portion of the document normally produces a different digest.

A secure digital signature algorithm protects the signed message or its cryptographic representation.

A hash value alone is not a digital signature because anyone can calculate a hash without possessing the signer's private key.

### 2.3 Signature versus encryption

These operations have different purposes.

| Property | Digital signature | Encryption |
|---|---|---|
| Primary purpose | Authenticity and integrity | Confidentiality |
| Main operation | Private-key signing | Encryption using an appropriate encryption key |
| Verification or recovery | Public-key verification | Decryption using the corresponding decryption key |
| Confidentiality | Not provided | Provided when correctly implemented |

Signing a document does not hide its contents.

A signed document may be publicly readable while still allowing recipients to detect unauthorized modification.

## 3. Signing Mechanisms

### 3.1 Ed25519

Ed25519 is an elliptic-curve digital signature algorithm.

It provides efficient signing and verification with relatively compact public keys and signatures.

The Python implementation uses the `cryptography` package.

The JavaScript implementation uses Node.js's built-in `crypto` module.

The Java implementation uses the Java Cryptography Architecture with the `Ed25519` algorithm.

These implementations generate key pairs independently and sign document bytes.

### 3.2 RSA signatures

RSA is an asymmetric cryptographic system based on modular arithmetic.

Its fundamental operations use:

- Public exponent.
- Private exponent.
- Modulus.

For a simplified mathematical representation:

    Signature = Message^d mod n

    Verification = Signature^e mod n

Where:

- `d` is the private exponent.
- `e` is the public exponent.
- `n` is the modulus.

Production RSA signatures require secure padding and hashing, such as RSA-PSS with SHA-256.

The C++ program demonstrates modular exponentiation, modular inverses, and public-key verification.

Its small RSA parameters and integer message encoding are intentionally insecure. They demonstrate mathematical relationships, not a deployable signature scheme.

## 4. Signature Verification

Verification checks whether the supplied signature corresponds to the supplied document and public key.

The verification process must consider:

- Document integrity.
- Signature correctness.
- Signer identity.
- Certificate validity.
- Certificate issuer authenticity.
- Certificate revocation.
- Trust configuration.

A successful cryptographic verification establishes that the signature is consistent with the public key and signed data.

It does not independently prove that the public key belongs to the claimed person.

### 4.1 Verification outcomes

The implementations distinguish several failure conditions.

| Result | Meaning |
|---|---|
| VALID | Signature and relevant trust checks succeeded |
| INVALID | Signature, identity, or integrity check failed |
| EXPIRED | Certificate validity period ended |
| NOT_YET_VALID | Certificate validity has not started |
| REVOKED | Certificate has been revoked |
| UNTRUSTED | Issuing authority is not accepted |

These states should not be collapsed into a single Boolean value in enterprise workflows.

For example, an expired certificate and a modified document represent different security conditions and require different operational responses.

### 4.2 Document tampering

The examples sign financial agreements and subsequently modify their contents.

The original signature must not verify against modified content.

A valid signature cannot be transferred to a different document merely by retaining the original signature bytes.

The Python and JavaScript implementations also retain document hashes to detect changes in stored content.

The Java implementation uses immutable records for signed-document metadata.

The PostgreSQL implementation prevents changing a registered document hash after signatures have been recorded.

## 5. Digital Certificates

A digital certificate associates an identity with a public key.

A certificate generally contains:

- Subject identity.
- Issuer identity.
- Subject public key.
- Serial number.
- Validity period.
- Signature algorithm.
- Issuer's digital signature.
- Additional certificate extensions.

The X.509 standard defines the widely used certificate structure.

### 5.1 Certificate issuance

The certificate authority validates an applicant according to its issuance policy.

It then creates a certificate containing the applicant's identity and public key.

The authority signs the certificate using its private key.

    Subject Public Key
           |
           v
    Certificate Fields
           |
           v
    Certificate Authority
           |
      CA Private Key
           |
           v
    Signed Certificate

A recipient uses the authority's trusted public key to verify the certificate signature.

The certificate signature protects the certificate contents against unauthorized modification.

### 5.2 Certificate validity

A certificate has a defined validity interval.

    notBefore <= currentTime <= notAfter

A certificate outside this interval must not be treated as currently valid.

The Python, JavaScript, and Java implementations evaluate these timestamps.

The SQL implementation stores the validity interval and evaluates certificate eligibility through a PostgreSQL function.

### 5.3 Certificate revocation

A certificate may become invalid before its expiration date.

Possible reasons include:

- Private-key compromise.
- Employee departure.
- Unauthorized certificate issuance.
- Incorrect identity information.
- Organizational policy violations.

Revocation mechanisms include:

| Mechanism | Function |
|---|---|
| CRL | Certificate Revocation List containing revoked certificate serial numbers |
| OCSP | Online Certificate Status Protocol for querying certificate status |
| Internal revocation registry | Organization-managed certificate status records |

The implementations maintain revocation sets or database status records.

A production certificate-validation system must integrate authoritative revocation information and define its behavior when revocation services are unavailable.

## 6. Certificate Chains and Trust

Certificates are generally validated through a chain of issuing authorities.

A typical hierarchy is:

    Trusted Root CA
          |
          v
    Intermediate CA
          |
          v
    Organization CA
          |
          v
    Employee Certificate
          |
          v
    Document Signature

A trust anchor is a public key or certificate explicitly accepted by the relying party.

An intermediate certificate must be validated through its issuing authority until the chain reaches an accepted trust anchor.

### 6.1 Trust is not the same as signature validity

Consider two situations:

**Situation A**

A signature is mathematically valid, and the certificate belongs to a trusted authority.

The verification process can accept the signature if all other validation requirements succeed.

**Situation B**

A signature is mathematically valid, but the certificate was issued by an unknown authority.

The signature may be cryptographically correct while the identity remains untrusted.

This distinction is implemented through separate signature-verification and certificate-trust operations.

### 6.2 Trust-store management

A trust store maintains the authorities accepted by an application or organization.

The examples use:

- Python dictionaries.
- JavaScript Maps.
- C++ associative containers.
- Java concurrent maps.
- PostgreSQL authority records.

Trust anchors should be installed through controlled administrative processes.

An attacker who can modify the trust store may introduce an unauthorized authority and compromise identity verification.

## 7. Python Implementation

The Python implementation provides an object-oriented signature-management workflow.

### Main components

| Component | Responsibility |
|---|---|
| `DigitalSigner` | Generates signing keys and signs documents |
| `Certificate` | Stores subject, issuer, key, serial number, and validity |
| `CertificateAuthority` | Issues signed certificates |
| `TrustStore` | Maintains trusted issuers and revoked serial numbers |
| `SignedDocument` | Stores signed document metadata |
| `SignatureService` | Coordinates signing and verification |

### Important implementation decisions

- Ed25519 avoids implementing cryptographic primitives manually.
- SHA-256 fingerprints provide stable public-key identifiers.
- Dataclasses represent certificate and document records.
- Enums provide explicit verification outcomes.
- Exceptions reject malformed inputs and identity mismatches.
- Unit tests cover successful verification, tampering, revocation, expiration, and unknown issuers.

The certificate model represents a simplified single-level authority. It does not implement complete X.509 path validation, certificate policies, or OCSP.

The public-key fingerprint is calculated from the raw Ed25519 public key representation.

## 8. JavaScript Implementation

The JavaScript implementation uses Node.js event-driven processing.

### Main components

| Component | Responsibility |
|---|---|
| `KeyIdentity` | Generates signing identities |
| `CertificateAuthority` | Issues signed certificate records |
| `TrustStore` | Maintains trust anchors and revocations |
| `DocumentSignature` | Represents immutable signed-document metadata |
| `SignatureService` | Signs documents and evaluates verification results |

### Event-driven behavior

The service extends `EventEmitter`.

Two events are exposed:

- `document:signed`
- `document:verified`

These events support audit collection, notification systems, and downstream document-processing services.

The implementation uses:

- `Map` for trusted authority lookup.
- `Set` for revoked serial numbers.
- `Buffer` for document bytes.
- Node.js cryptographic APIs for Ed25519.
- Promises for asynchronous workflow integration.

Certificate payloads are serialized using a deterministic JSON representation before signing.

This is a simplified application-level certificate format, not an X.509 certificate implementation.

Production systems must use a standardized canonical encoding and strict input validation when exchanging signed objects between independent systems.

## 9. C++17 Implementation

The C++ implementation focuses on the mathematical mechanics of RSA and certificate-based verification.

### Main components

| Component | Responsibility |
|---|---|
| `RSAKey` | Stores modulus and exponent |
| `RSAKeyPair` | Holds public and private keys |
| `Certificate` | Represents a simplified certificate |
| `CertificateAuthority` | Issues and revokes certificates |
| `DigitalSigner` | Creates and verifies mathematical signatures |
| `TrustStore` | Stores accepted authorities |
| `VerificationEngine` | Evaluates certificate and signature conditions |

### Mathematical operations

The implementation contains:

- Greatest common divisor calculation.
- Modular exponentiation.
- Modular inverse calculation.
- Extended Euclidean algorithm.
- RSA signing.
- RSA verification.

Modular exponentiation uses repeated squaring.

Its time complexity is:

    O(log exponent)

The modular multiplication routine avoids intermediate unsigned multiplication overflow for the supported integer range.

### Security limitation

The C++ implementation intentionally uses very small RSA parameters.

Its integer-based message representation is not a cryptographic hash.

It does not implement RSA-PSS, PKCS#1 padding, secure key generation, or standardized certificate encoding.

It must not be used to protect actual documents, financial transactions, or communications.

The implementation is intended to demonstrate the mathematical relationship between private-key signing and public-key verification.

## 10. Java 17 Implementation

The Java implementation models an enterprise document approval workflow using the Java Cryptography Architecture.

### Domain types

| Type | Responsibility |
|---|---|
| `KeyIdentity` | Immutable signing identity |
| `CertificateRecord` | Certificate metadata and issuer signature |
| `SignedDocument` | Immutable signed-document record |
| `CertificateAuthority` | Certificate issuance |
| `TrustStore` | Trusted issuer and revocation management |
| `DocumentService` | Document signing and storage |
| `VerificationService` | Certificate and signature validation |

### Enterprise considerations

The implementation uses:

- Java records for immutable domain data.
- `ConcurrentHashMap` for document and trust-store access.
- `ConcurrentHashMap.newKeySet()` for revocation tracking.
- `MessageDigest` for SHA-256.
- `Signature` for Ed25519 operations.
- `Instant` for UTC timestamps.
- `MessageDigest.isEqual` for public-key byte comparison.

The document service uses `putIfAbsent` to avoid duplicate document identifiers during concurrent submissions.

A failed signature or identity check raises an explicit security validation exception.

The certificate format is simplified and application-specific. It does not replace X.509 certificate parsing or complete PKIX validation.

## 11. PostgreSQL Implementation

The SQL implementation models the persistent enterprise signature-management workflow.

### Database relationships

    Signers
       |
       v
    Certificates
       |
       v
    Certificate Authorities
       |
       v
    Trust Anchors

    Documents
       |
       v
    Digital Signatures
       |
       v
    Verification Audit

### Tables

| Table | Purpose |
|---|---|
| `signers` | Stores document-signing identities |
| `certificate_authorities` | Stores issuing authorities and trust-anchor configuration |
| `certificates` | Stores certificate metadata and public-key information |
| `documents` | Stores document references and content hashes |
| `digital_signatures` | Stores signature values and signing metadata |
| `verification_audit` | Records signature-verification decisions |

### Integrity enforcement

The database uses:

- Primary keys for record identification.
- Foreign keys for relationships.
- Unique constraints for certificate serials and document references.
- Check constraints for fingerprints, validity intervals, and algorithms.
- Triggers for document-integrity and signer-certificate consistency.
- Indexes for signer lookup, certificate status, document retrieval, and audit queries.

### Certificate evaluation

The `evaluate_certificate` function checks:

1. Certificate existence.
2. Revocation status.
3. Suspension status.
4. Validity start time.
5. Expiration time.
6. Issuer configuration.
7. Trust-anchor status.

It evaluates certificate metadata rather than performing cryptographic signature verification.

### Verification recording

The `record_verification` function:

- Locks the signature record.
- Checks the verifier identity.
- Validates the supplied verification evidence.
- Inserts an audit record.
- Updates the signature state.

The function requires successful chain and cryptographic checks before accepting a `VALID` result.

In a production deployment, execution privileges must be restricted to an authenticated verification service. Application-provided Boolean values must never be trusted without independent authorization and verification controls.

### Transaction handling

Certificate revocation is demonstrated inside a transaction.

This ensures that the status change and associated metadata are committed together.

The audit table preserves individual verification decisions instead of retaining only the latest state.

## 12. Important Security Distinctions

| Concept | What it establishes | What it does not establish |
|---|---|---|
| Hash | Data fingerprint | Signer identity |
| Digital signature | Cryptographic authenticity and integrity relative to a public key | Whether that public key is trusted |
| Public key | Verification capability | Identity by itself |
| Certificate | Signed identity-to-key binding | Guaranteed current trust |
| Trust anchor | Accepted starting point for certificate validation | Validity of every certificate issued under it |
| Revocation | Certificate no longer accepted under applicable policy | Whether earlier signatures were invalid when created |

A digital signature also does not automatically establish legal validity or non-repudiation in every jurisdiction.

Those outcomes depend on identity proofing, private-key control, signing intent, applicable law, evidence preservation, and organizational procedures.

## 13. Operational Workflow

A practical enterprise signing workflow follows this sequence:

    1. Register signer identity
              |
              v
    2. Generate signing key pair
              |
              v
    3. Obtain identity certificate
              |
              v
    4. Validate certificate and trust
              |
              v
    5. Calculate document digest
              |
              v
    6. Sign document
              |
              v
    7. Store signature and audit metadata
              |
              v
    8. Recipient retrieves signed document
              |
              v
    9. Validate certificate chain and revocation
              |
              v
    10. Verify document signature
              |
          +---+---+
          |       |
        Valid   Invalid
          |       |
          v       v
       Accept   Reject

Certificate validation and document-signature verification are separate operations. Both are required before accepting a signed document under the demonstrated policy.

## 14. Performance Considerations

| Operation | Consideration |
|---|---|
| Key generation | More expensive than ordinary document hashing |
| Signing | Depends on the selected signature algorithm and key |
| Verification | Can be parallelized across independent documents |
| SHA-256 hashing | Linear in document size |
| Trust-store lookup | Average constant-time lookup with hash-based maps |
| Certificate lookup | Efficient with indexed serial numbers |
| Revocation lookup | Efficient with indexed records or in-memory sets |
| Audit reporting | Benefits from indexes on signature IDs and timestamps |

For large documents, applications can stream document bytes into a hash calculation rather than loading the complete document into memory.

The signed content must remain unambiguous. A signature should cover a precisely defined byte representation rather than an inconsistent textual rendering.

## 15. Production Security Requirements

A production digital-signature system should implement the following controls.

### Private-key protection

- Use hardware security modules or managed key-management systems where appropriate.
- Restrict access to signing operations.
- Encrypt private keys at rest.
- Rotate and revoke compromised keys.
- Separate signing privileges from document administration privileges.

### Certificate validation

- Validate the complete certificate chain.
- Check certificate validity periods.
- Verify certificate key usage and extended key usage.
- Enforce certificate policies.
- Check revocation through CRLs or OCSP.
- Maintain controlled trust anchors.

### Signature validation

- Use standardized cryptographic algorithms.
- Reject malformed or unsupported signature encodings.
- Bind signatures to exact document bytes.
- Check the certificate identity against the expected signer.
- Prevent document substitution and replay.
- Record verification timestamps and outcomes.

### Audit and evidence

Maintain records of:

- Document identifier.
- Original document digest.
- Signer identity.
- Certificate serial number.
- Certificate issuer.
- Signature algorithm.
- Signing timestamp.
- Verification result.
- Revocation information.
- Verification service identity.

A trustworthy audit trail should be access-controlled and protected against unauthorized modification.

## 16. Limitations and Design Boundaries

The five implementations intentionally use different levels of cryptographic abstraction.

| Implementation | Cryptographic approach | Certificate approach |
|---|---|---|
| Python | Ed25519 using `cryptography` | Simplified signed certificate |
| JavaScript | Ed25519 using Node.js `crypto` | Simplified signed certificate |
| C++17 | Educational small-integer RSA | Simplified mathematical certificate |
| Java 17 | Ed25519 using JCA | Simplified signed certificate |
| PostgreSQL | Stores verification evidence | Relational certificate and trust metadata |

The Python, JavaScript, and Java certificate models do not implement the full X.509 and PKIX standards.

The PostgreSQL database cannot independently establish cryptographic authenticity merely by storing a signature value.

The C++ program is not suitable for production cryptography.

A production deployment should use interoperable X.509 certificates, validated certificate chains, secure key storage, standardized signature formats, and independently authenticated verification services.
