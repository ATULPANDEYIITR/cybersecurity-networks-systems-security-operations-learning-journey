# Asymmetric Cryptography: RSA, ECC, Public/Private Keys, Encryption and Signing

## Scope

This project implements asymmetric cryptography through two major families:

- RSA public-key encryption and digital signatures.
- Elliptic-curve cryptography through ECC key pairs and ECDSA-style signatures.

The implementations deliberately distinguish four concepts that are often confused:

| Concept | Private key | Public key | Primary purpose |
|---|---|---|---|
| RSA encryption | Decrypts | Encrypts | Confidentiality |
| RSA signature | Signs | Verifies | Authenticity and integrity |
| ECC key agreement/signature | Participates in private operations | Participates in public verification | Secure key operations and signatures |
| Hashing | Not a key operation | Not a key operation | Fixed-size integrity representation |

The Python implementation exposes the mathematical mechanics. JavaScript uses Node.js cryptographic primitives and event-driven processing. C++17 models a governance-oriented cryptographic case study. Java 17 separates cryptographic services from enterprise policy evaluation. PostgreSQL stores keys, repositories, reviews, policies, and merge decisions as a transactional relational workflow.

## Core Cryptographic Distinctions

Asymmetric cryptography uses a mathematically related key pair.

The public key may be distributed to other parties. The private key must remain confidential.

For encryption:

`plaintext -> recipient public key -> ciphertext -> recipient private key -> plaintext`

For signatures:

`message -> private key -> signature`

and:

`message + public key + signature -> valid / invalid`

The operations have different security objectives. Encryption protects confidentiality. Signing provides evidence that a message was produced by the holder of the private key and that the signed content has not been modified.

A cryptographic hash is normally applied to the message before signing. The hash provides a compact representation of the data whose integrity is being authenticated.

## RSA

RSA relies on arithmetic over a modulus derived from two large prime numbers.

The simplified mathematical model used by the Python implementation is:

`n = p × q`

`phi(n) = (p - 1)(q - 1)`

A public exponent `e` is selected and the private exponent `d` satisfies:

`e × d ≡ 1 mod phi(n)`

The public key is represented by `(n, e)` and the private key by `(n, d)`.

The Python implementation includes:

- probable-prime generation using Miller-Rabin testing;
- modular inverse calculation;
- RSA key-pair generation;
- modular-exponentiation encryption;
- modular-exponentiation decryption;
- RSA-style signing;
- signature verification;
- input-size validation;
- malformed-signature handling;
- audit events;
- file-based audit output.

The RSA mathematical implementation is educational. It intentionally exposes the core arithmetic rather than pretending that textbook RSA is a production encryption protocol.

Production RSA encryption should use a standardized padding scheme such as RSA-OAEP. Production RSA signatures should use a standardized scheme such as RSA-PSS or a correctly configured PKCS#1 v1.5 signature scheme.

The Node.js implementation uses RSA-OAEP for encryption and RSA-PSS for signatures. This provides a separate implementation perspective from the Python mathematical model.

## ECC

Elliptic-curve cryptography operates on points satisfying a curve equation over a finite field.

The Python program uses a small toy curve to make point addition and scalar multiplication executable:

`y² = x³ + ax + b mod p`

The implementation includes:

- point-at-infinity representation;
- point addition;
- point doubling;
- scalar multiplication;
- private scalar generation;
- public point generation;
- ECDSA-style signing;
- ECDSA-style verification.

The curve is intentionally small and is not suitable for protecting real data.

The JavaScript and Java implementations use established runtime cryptographic primitives instead of reproducing low-level elliptic-curve arithmetic. The JavaScript implementation uses Node.js EC keys with `prime256v1`. The Java implementation uses EC key generation and `SHA256withECDSA`.

## Encryption Versus Signing

Encryption and signing answer different questions.

Encryption asks:

> Can an unauthorized party read the protected data?

Signing asks:

> Can the verifier establish that the data was signed by the private-key holder and that the signed data has not changed?

A signature does not provide confidentiality.

An encrypted message does not automatically provide sender authentication.

For a real application requiring both properties, a protocol can combine encryption and signatures or use authenticated encryption with an appropriate key-management design.

## Hybrid Encryption

Public-key encryption is computationally expensive for large documents.

A practical architecture therefore uses hybrid encryption:

`document`
`  -> random symmetric key`
`  -> authenticated symmetric encryption`
`  -> encrypted symmetric key using recipient public key`

The symmetric algorithm handles the bulk data. RSA-OAEP or an appropriate elliptic-curve-based key-agreement mechanism protects the small symmetric key.

The Python program intentionally encrypts only small demonstration messages because its educational RSA routine does not implement a complete hybrid-encryption protocol.

The Node.js implementation also demonstrates RSA encryption of a small secret rather than attempting to encrypt an arbitrary large file directly.

## Key Management

A public key can be distributed through a certificate, trusted directory, repository configuration, or another authenticated key-distribution mechanism.

A private key requires substantially stronger controls:

- restricted filesystem permissions;
- protected secret storage;
- controlled process access;
- key rotation;
- key revocation;
- audit logging;
- separation of signing and encryption keys where appropriate;
- avoidance of private-key material in source control;
- secure backup and recovery procedures.

The JavaScript registry stores key objects in memory and exposes fingerprints for identification. The PostgreSQL schema stores public-key metadata and a reference to private-key storage rather than placing a private key directly into ordinary repository records.

## Python Implementation

The Python file is a self-contained mathematical case study.

Its main components are:

| Component | Function |
|---|---|
| `generate_prime` | Generates probable primes for RSA |
| `mod_inverse` | Computes modular inverses |
| `generate_rsa_keypair` | Builds an RSA key pair |
| `rsa_encrypt` | Performs educational RSA encryption |
| `rsa_decrypt` | Performs educational RSA decryption |
| `rsa_sign` | Produces an RSA-style signature |
| `rsa_verify` | Verifies an RSA-style signature |
| `ToyECC` | Implements elliptic-curve point arithmetic |
| `ecc_sign` | Produces an ECDSA-style signature |
| `ecc_verify` | Verifies an ECDSA-style signature |
| `SecureDocumentService` | Adds operation auditing and validation |

The program also verifies a modified document and demonstrates an expected RSA size failure.

The audit file is written with JSON serialization so the sequence of successful and failed cryptographic operations can be inspected after execution.

## JavaScript Implementation

The JavaScript file uses Node.js built-in cryptography instead of implementing cryptographic primitives manually.

Its design uses:

- `crypto.generateKeyPairSync`;
- RSA-2048;
- RSA-OAEP with SHA-256;
- RSA-PSS with SHA-256;
- elliptic-curve keys using `prime256v1`;
- `Map` for key registration;
- `EventEmitter` for operation events;
- asynchronous service methods;
- structured validation;
- JSON audit output.

The `KeyRegistry` separates key lookup from cryptographic operations.

The `RepositoryCryptoService` performs signing, verification, and RSA encryption. Each operation emits a structured event containing the operation type, key identifier, algorithm, and success state.

This design makes operational logging independent from the cryptographic operation itself.

## C++17 Implementation

The C++ program approaches asymmetric cryptography through a repository-governance case study.

It models:

`Repository -> Branch Policy -> Pull Request -> Reviews + Status Checks -> Merge Eligibility`

The `MergeEligibilityEngine` evaluates:

- Pull Request state;
- draft status;
- source and target branch equality;
- presence of commits;
- merge conflicts;
- required status checks;
- eligible approvals;
- requested changes;
- unresolved conversations.

This separates cryptographic concerns from repository enforcement.

A cryptographic signing system can authenticate release artifacts, while branch protection determines whether an authenticated release change is permitted to enter a protected branch.

The implementation uses:

- enums for domain states;
- structs for records;
- STL vectors;
- `unordered_map`;
- exception handling;
- immutable policy references;
- explicit eligibility results.

The engine returns all detected failure reasons rather than stopping at the first failed condition. This is useful for administrative review because a blocked merge can expose the complete set of unmet gates.

## Java 17 Implementation

The Java program combines cryptographic services with enterprise domain modeling.

It uses:

- `record` types for immutable domain values;
- interfaces for merge-policy abstraction;
- enums for explicit workflow states;
- collections for reviews and checks;
- streams for approval and status-check evaluation;
- custom state transitions;
- Java security providers;
- RSA key generation;
- EC key generation;
- `SHA256withRSA`;
- `SHA256withECDSA`.

The `EnterpriseMergePolicy` evaluates repository-level requirements separately from cryptographic signing.

The Pull Request can transition through explicit states such as `OPEN`, `CLOSED`, and `MERGED`. The merge operation is permitted only after policy evaluation succeeds.

This separation is important because a valid cryptographic signature is not equivalent to authorization to merge code.

## PostgreSQL Implementation

The PostgreSQL model represents the complete operational domain.

The main relationships are:

`Repository`
`  -> Branch`
`      -> Branch Protection`
`  -> Commit`
`  -> Pull Request`
`      -> Pull Request Commit`
`      -> Review`
`          -> Reviewer`
`          -> Review Comment`
`      -> Status Check`
`  -> Cryptographic Key`

Branch protection is stored independently from Pull Requests because it belongs to repository governance rather than to one individual change request.

The schema enforces important conditions with:

- primary keys;
- foreign keys;
- unique constraints;
- enum types;
- check constraints;
- indexes;
- triggers;
- views;
- SQL functions;
- stored procedures.

The `evaluate_merge_eligibility` function combines Pull Request state, approvals, status checks, branch policy, and conversation state into one decision.

The `merge_pull_request` procedure performs a transactional eligibility check before changing the Pull Request to `MERGED`.

The database therefore treats merge eligibility as a governed state transition rather than an unchecked update.

## Security Boundaries

The implementations use different security boundaries deliberately.

### Private-key boundary

Private keys must not be treated as ordinary public configuration. The database model therefore stores `private_key_reference` rather than requiring private-key material to be stored in the relational record.

### Public-key identification

Public-key fingerprints provide compact identifiers that help detect accidental key substitution.

### Signature validation

A verifier must validate both the signature and the exact message associated with it. Changing even one byte of the signed message should cause verification to fail.

### Algorithm separation

RSA and ECC are modeled as distinct algorithms. A public key for one algorithm is not silently interpreted as another algorithm.

### Authorization separation

A valid signature does not automatically grant permission to merge code.

Cryptographic authenticity and repository authorization are separate controls.

## Failure Conditions

The implementations explicitly handle several failure classes.

| Failure | Expected behavior |
|---|---|
| RSA plaintext exceeds modulus capacity | Encryption fails |
| Invalid RSA ciphertext | Decryption fails |
| Malformed signature | Verification returns failure |
| Modified signed document | Verification fails |
| Invalid ECC signature parameters | Verification fails |
| Missing required review | Merge eligibility fails |
| Failed status check | Merge eligibility fails |
| Unresolved review conversation | Merge eligibility fails |
| Draft Pull Request | Merge is rejected |
| Merge conflict | Merge is rejected |
| Invalid merge method | Database procedure rejects the operation |

These failures represent different layers. Cryptographic failures concern authenticity or confidentiality. Governance failures concern authorization and repository state.

## Performance Considerations

RSA operations involve large-integer modular exponentiation. Key generation is substantially more expensive than ordinary hashing.

ECC uses smaller keys for comparable security levels and is often attractive where key and signature sizes matter.

For large payloads, asymmetric encryption should not be used as a bulk-data encryption primitive. Hybrid encryption reduces the expensive public-key operation to protection of a small symmetric key.

Signature verification and status-check evaluation can be parallelized in larger systems, but the final authorization decision should remain deterministic.

Database indexes are placed on common relationship and workflow fields such as Pull Request state, review state, status-check state, and repository commit identifiers.

## Operational Workflow

A realistic signed release workflow can be represented as:

`Release artifact`
`    |`
`    v`
`Hash artifact`
`    |`
`    v`
`Sign hash using protected private key`
`    |`
`    v`
`Publish artifact + signature + public-key identity`
`    |`
`    v`
`Open Pull Request`
`    |`
`    +--> Code review`
`    +--> Status checks`
`    +--> Signature verification`
`    +--> Branch protection`
`    |`
`    v`
`Merge eligibility`
`    |`
`    v`
`Protected branch`

Each stage has a different responsibility. Cryptographic signing establishes authenticity and integrity. Review establishes human or organizational assessment. Automated checks establish machine-verifiable conditions. Branch protection enforces repository policy.

## Implementation Boundaries

The Python and ECC mathematical routines are educational implementations and must not be substituted for vetted production cryptographic libraries.

The JavaScript and Java implementations use standard runtime cryptographic facilities for actual key generation, signing, verification, and RSA encryption.

The PostgreSQL implementation focuses on metadata, workflow state, policy enforcement, and auditability. It does not attempt to implement RSA or ECC arithmetic inside SQL.

The distinction is intentional: cryptographic primitives should normally come from reviewed cryptographic implementations, while application databases should enforce key metadata, authorization state, lifecycle, and audit rules.

## Practical Security Model

A production deployment should maintain the following separation:

| Layer | Responsibility |
|---|---|
| Cryptographic library | Key generation, encryption, signatures, verification |
| Key-management system | Private-key protection, rotation, access control |
| Application service | Protocol and business workflow |
| Repository service | Pull Requests, reviews, status checks |
| Branch protection | Repository-level merge enforcement |
| Database | Durable state, constraints, transactions, audit records |

The central architectural distinction is:

`Encryption protects secrecy.`

`Signing protects authenticity and integrity.`

`Branch protection controls repository authorization.`

These mechanisms complement one another but do not replace one another.
