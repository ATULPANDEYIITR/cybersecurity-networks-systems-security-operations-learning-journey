# Symmetric Cryptography: AES, Key Management, IVs, Modes, and Authenticated Encryption

## Technical Scope

This learning artifact models symmetric cryptography as a complete engineering workflow rather than as a collection of isolated cipher examples.

The central relationship is:

`plaintext → encryption key → IV/nonce → cipher mode → ciphertext → authentication → protected envelope`

The implementations focus on AES and distinguish four important concerns:

| Concern | Purpose |
|---|---|
| AES | Symmetric block cipher providing confidentiality |
| Key management | Controls creation, activation, rotation, retirement, and revocation of keys |
| IV/nonce management | Prevents unsafe reuse of initialization values |
| Authenticated encryption | Protects confidentiality and detects ciphertext or metadata modification |

The five implementations use different engineering perspectives while representing the same cryptographic principles.

## Core Cryptographic Model

AES is a symmetric block cipher operating on 128-bit blocks. The security of an AES-based application depends on more than selecting AES itself.

A complete design must specify:

- AES key size
- encryption mode
- IV or nonce size
- IV or nonce generation
- authentication mechanism
- authenticated metadata
- key lifecycle
- failure behavior
- storage format
- rotation strategy

The artifact uses 256-bit AES keys in the JavaScript, C++, and Java implementations and a compact 128-bit AES implementation in Python. The PostgreSQL model represents 256-bit key material.

A protected record is conceptually represented as:

`key_id + algorithm + IV/nonce + ciphertext + authentication tag + AAD`

The `key_id` identifies the key without embedding the key itself in the encrypted record.

## AES Modes

AES alone does not define how arbitrary-length application data is encrypted. A mode of operation supplies that construction.

### AES-CBC

CBC combines each plaintext block with the previous ciphertext block before AES encryption.

The relationship is:

`C[i] = AES(K, P[i] XOR C[i-1])`

where the IV acts as the initial `C[i-1]`.

CBC requires padding when plaintext is not an exact multiple of the AES block size. The Python implementation contains PKCS#7 padding logic, while the Java implementation uses the standard `AES/CBC/PKCS5Padding` transformation.

CBC does not authenticate ciphertext. A production CBC design therefore requires a separate integrity mechanism. The JavaScript, Java, and conceptual database designs use HMAC-based protection where CBC is shown.

CBC should not be selected merely because it is available. Modern application protocols generally prefer authenticated encryption such as AES-GCM.

### AES-CTR

CTR turns AES into a stream-like construction.

The encryption operation is conceptually:

`C = P XOR AES(K, counter)`

The counter must never repeat for the same key and nonce construction.

CTR provides confidentiality but does not provide integrity. The JavaScript implementation therefore pairs CTR with HMAC-SHA256.

The Python implementation directly demonstrates the counter transformation and performs a round-trip test.

### AES-GCM

GCM combines counter-mode encryption with authentication.

It produces:

`ciphertext + authentication tag`

It can also authenticate additional data without encrypting that data. This is called Additional Authenticated Data, or AAD.

Typical AAD can contain:

- record identifiers
- protocol versions
- tenant identifiers
- key identifiers
- algorithm identifiers
- message types

The AAD remains visible but any modification causes authentication failure.

AES-GCM is the primary recommended construction represented by these implementations because confidentiality and integrity are designed together.

## IV and Nonce Management

An IV or nonce is not normally a secret.

Its security role depends on the mode.

For GCM, the implementations use a fresh 96-bit random IV for every encryption operation. Reusing a GCM nonce with the same key is a critical failure because it can undermine confidentiality and authentication.

The envelope therefore stores the IV beside the ciphertext.

The key remains secret.

The IV does not.

The authentication tag does not need to be secret either.

A typical GCM envelope is:

`key_id | algorithm | iv | ciphertext | tag | aad`

The key identifier allows a service to determine which key should be used without embedding the secret key in every record.

## Key Management

Key management is separated from encryption operations.

The Python `KeyManager`, JavaScript `KeyManager`, Java `KeyManager`, C++ `KeyStore`, and PostgreSQL `encryption_keys` table all represent key lifecycle concepts.

A key can move through states such as:

`ACTIVE → RETIRED`

or:

`ACTIVE → REVOKED`

An active key is eligible for new encryption operations.

A retired key may remain necessary for decrypting older records during a migration window.

A revoked key represents a stronger operational failure state and should not be accepted for ordinary decryption.

The key identifier is separate from key material:

`key_id → secret key`

This separation makes rotation possible without changing the structure of every encrypted record.

## Key Rotation

Key rotation creates a new encryption key while preserving historical metadata.

The PostgreSQL workflow records:

- previous key
- new key
- rotation timestamp
- rotation reason

The JavaScript, Java, C++, and Python implementations expose explicit rotation behavior.

A practical rotation process is:

1. Generate a new cryptographically random key.
2. Mark the previous key as retired.
3. Activate the new key.
4. Store the new key under a new identifier.
5. Encrypt new records with the new key.
6. Keep retired keys only as long as historical decryption requires.
7. Re-encrypt historical data when policy requires migration.
8. Revoke keys when retention and recovery requirements permit.

Rotation does not automatically mean that old ciphertext has been re-encrypted.

## Python Implementation

The Python file is a self-contained educational cryptographic implementation.

It contains an AES-128 block implementation rather than depending on an external cryptography package.

The AES implementation includes:

- finite-field multiplication
- S-box construction
- key expansion
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey
- AES block encryption

It then builds higher-level constructions around the AES primitive.

### CBC

The Python implementation contains:

- PKCS#7 padding
- CBC chaining
- random IV validation
- block-level processing

The implementation deliberately does not pretend that CBC encryption alone provides integrity.

### CTR

CTR uses:

`12-byte nonce + 32-bit counter`

to create AES input blocks.

The same transformation encrypts and decrypts because XOR is reversible.

### GCM

The Python GCM implementation contains:

- 96-bit IV handling
- counter construction
- CTR encryption
- GHASH
- authentication tag generation
- AAD processing
- constant-time tag comparison

The implementation validates a known AES-128 test vector before running application-level examples.

It also modifies ciphertext intentionally and verifies that authentication fails.

### Python Key Protection

The Python key-management layer uses `hashlib.scrypt` to derive a wrapping key from a password.

The workflow is:

`password + random salt → scrypt → wrapping key → AES-GCM → protected key`

The salt is stored with the wrapped key. The password is not stored.

This demonstrates the distinction between a data-encryption key and a password-derived wrapping key.

## JavaScript Implementation

The JavaScript implementation uses Node.js's standard `crypto` module.

It focuses on event-driven key management and multiple encryption constructions.

### AES-GCM

`crypto.createCipheriv('aes-256-gcm', key, iv)` provides the primary authenticated encryption path.

AAD is supplied using `setAAD`.

The authentication tag is extracted with `getAuthTag`.

Decryption supplies the tag through `setAuthTag`.

A failed tag check produces an integrity failure rather than returning potentially manipulated plaintext.

### CBC-HMAC

CBC is implemented as an Encrypt-then-MAC construction.

The authentication input contains:

`algorithm marker + IV + ciphertext`

The HMAC is verified before CBC decryption is accepted.

This prevents unauthenticated CBC from being treated as a secure message format.

### CTR-HMAC

CTR provides the confidentiality transformation.

HMAC supplies integrity.

The separation makes the distinction between encryption and authentication explicit.

### Event-Driven Key Management

The JavaScript `KeyManager` extends `EventEmitter`.

Key rotation emits a `keyRotated` event.

This models an operational system where key-management actions can trigger:

- audit records
- monitoring
- cache invalidation
- downstream configuration updates
- security notifications

The event does not contain the secret key.

Only non-secret metadata is emitted.

## C++17 Implementation

The C++ implementation uses OpenSSL's EVP interface.

The EVP abstraction prevents application code from implementing low-level AES rounds directly and provides a well-tested cryptographic library interface.

The primary construction is AES-256-GCM.

The encryption workflow is:

`EVP_EncryptInit_ex → IV configuration → key initialization → AAD → ciphertext → authentication tag`

The decryption workflow reverses this sequence and refuses plaintext when the authentication tag does not validate.

### Repository-Governance Scenario

The C++ case study treats encrypted deployment configuration as protected repository data.

The `MergeSecretService` creates an envelope containing:

- algorithm
- key identifier
- IV
- ciphertext
- authentication tag
- AAD

The AAD contains repository-oriented metadata.

This means the metadata can remain visible while still being cryptographically bound to the encrypted payload.

Changing the AAD causes authentication failure.

### C++ Key Store

`KeyStore` maintains active and retired key states.

The service does not generate IVs from predictable counters. It obtains fresh random values from OpenSSL's secure random generator.

The program tests:

- successful GCM encryption
- successful GCM decryption
- ciphertext modification
- AAD modification
- key rotation

## Java 17 Implementation

The Java implementation uses standard JCA/JCE APIs.

Its primary transformation is:

`AES/GCM/NoPadding`

The domain model uses records and explicit classes for:

- key records
- cipher envelopes
- key status
- encryption mode
- cryptographic services

### Domain Separation

`KeyManager` owns lifecycle state.

`GcmService` owns authenticated encryption.

`CbcHmacService` owns the separate CBC-plus-HMAC construction.

This prevents encryption code from becoming responsible for unrelated key-lifecycle operations.

### Java GCM Envelope

The Java GCM transformation returns ciphertext and the authentication tag together. The implementation separates them before constructing the application envelope.

The envelope retains:

- algorithm
- key identifier
- IV
- ciphertext
- tag
- AAD

During decryption the tag is reconstructed after the ciphertext and supplied to the GCM cipher.

### Password-Based Key Derivation

The Java implementation uses PBKDF2 with HMAC-SHA256 for password-based key derivation.

The derived key is distinct from the application data key.

The example uses a random salt and a deliberately expensive derivation configuration.

In production, password-based key protection should be governed by the application's password and key-management policy, with parameters selected according to current hardware and security requirements.

## PostgreSQL Implementation

The PostgreSQL file models the cryptographic system relationally.

The principal entities are:

| Table | Purpose |
|---|---|
| `encryption_keys` | Key lifecycle and algorithm metadata |
| `encrypted_records` | Ciphertext envelopes and cryptographic metadata |
| `key_rotation_events` | Rotation history |
| `encryption_audit` | Encryption and security events |

### Key Constraints

`encryption_keys` enforces:

- unique key versions
- 32-byte AES-256 key material
- valid lifecycle states
- one active key

The partial unique index:

`one_active_encryption_key`

prevents multiple active keys.

This converts a key-management rule into a database invariant rather than leaving it entirely to application code.

### Encrypted Records

`encrypted_records` stores:

- `key_id`
- algorithm
- IV
- ciphertext
- authentication tag
- AAD
- creation timestamp
- decryption timestamp

The constraints enforce algorithm-specific IV lengths.

For GCM, the design requires:

- 12-byte IV
- 16-byte authentication tag

The key itself is not copied into each encrypted record.

### Rotation Procedure

`rotate_encryption_key`:

1. Locks the current active key.
2. Determines the next key version.
3. Retires the current key.
4. Generates a new 32-byte key.
5. Activates the new key.
6. Records a rotation event.
7. Records an audit event.

The transaction boundary protects the lifecycle transition.

### PostgreSQL Encryption Boundary

The database example uses `pgcrypto` for executable database-side symmetric encryption.

The relational model explicitly represents an AES-GCM-style application envelope, but `pgcrypto`'s `pgp_sym_encrypt` is not presented as AES-GCM.

This distinction is important.

A database storing an `authentication_tag` column does not automatically mean that its underlying primitive produced a GCM authentication tag.

When strict AES-GCM semantics are required, application-side encryption using a GCM-capable cryptographic API should produce the ciphertext, tag, IV, and AAD before persistence.

The PostgreSQL model is therefore useful for:

- key identifiers
- ciphertext storage
- cryptographic metadata
- lifecycle constraints
- audit records
- rotation state
- validation queries

## Authenticated Encryption and AAD

Authenticated encryption protects both secrecy and integrity.

For a GCM operation:

`Encrypt(K, IV, plaintext, AAD) → ciphertext, tag`

Decryption succeeds only when:

`K + IV + ciphertext + AAD + tag`

are mutually consistent.

Changing any authenticated component causes failure.

AAD is useful when metadata should remain readable but must not be alterable without detection.

Example:

`repository=payments;classification=confidential`

can remain outside the ciphertext while still being authenticated.

## Failure Handling

Cryptographic failures must not be silently converted into successful operations.

Important failure states include:

| Failure | Required behavior |
|---|---|
| Unknown key ID | Reject operation |
| Retired key for new encryption | Reject operation |
| Revoked key | Reject operation |
| Invalid IV length | Reject operation |
| Invalid authentication tag | Reject operation |
| Modified ciphertext | Reject operation |
| Modified AAD | Reject operation |
| Unsupported algorithm | Reject operation |
| Invalid padding | Reject operation |
| Weak password input | Reject or enforce policy |
| Key-generation failure | Fail closed |

A decrypted value should never be accepted merely because the cipher operation returned bytes.

Authentication must be validated first when the construction requires it.

## Security Distinctions

Several concepts must remain separate.

### Confidentiality

Confidentiality prevents unauthorized parties from reading plaintext.

AES provides the underlying symmetric encryption primitive.

### Integrity

Integrity detects unauthorized modification.

AES-CBC and AES-CTR do not provide this property by themselves.

HMAC or authenticated encryption is required.

### Authentication

Authentication confirms that the protected data was produced under the expected secret and has not been altered.

GCM provides this through its authentication tag.

### Key Management

Key management controls the lifecycle of secrets.

It is not provided merely by selecting AES-256.

### IV Management

An IV or nonce is an input to a mode construction.

It is not a replacement for a key.

For GCM, nonce uniqueness under a key is a critical security requirement.

## Performance Considerations

AES-GCM is generally suitable for high-throughput application encryption because modern processors often provide AES acceleration.

Performance considerations include:

- avoid repeatedly deriving keys for every record
- reuse initialized key material where the API permits safe reuse of key objects
- generate IVs efficiently
- keep authentication and encryption in one operation
- avoid unnecessary plaintext copies
- use streaming APIs for large payloads
- batch database writes when appropriate
- index key identifiers used for retrieval
- avoid decrypting records merely to determine metadata

The PostgreSQL index on `(key_id, created_at)` supports common key-to-record and historical-key queries.

## Edge Cases

The implementations explicitly address several edge cases.

### Empty Plaintext

Authenticated encryption APIs must handle zero-length plaintext correctly.

The ciphertext can be empty while the authentication tag remains meaningful.

### Modified Ciphertext

A single changed ciphertext byte causes GCM authentication failure.

### Modified AAD

A changed AAD value causes authentication failure even though the AAD was never encrypted.

### Invalid IV Length

The implementations reject IVs that do not match the expected construction.

### Key Rotation

New records use the current active key while historical records can retain their original key identifier.

### Retired Keys

A retired key should not be selected for new encryption.

Whether it remains available for decryption depends on the application's retention and migration policy.

### Revoked Keys

Revocation represents a stronger security condition and normally prevents ordinary decryption.

## Practical Envelope Design

A durable encrypted-record format should contain enough metadata to interpret the ciphertext without embedding secrets.

A suitable logical structure is:

`version`
`algorithm`
`key_id`
`iv`
`ciphertext`
`tag`
`aad`

The version permits future envelope changes.

The algorithm identifies the cryptographic construction.

The key identifier supports key rotation.

The IV is public cryptographic metadata.

The ciphertext contains the protected content.

The tag protects authenticity.

The AAD identifies metadata that must be authenticated but does not need confidentiality.

## Security Boundaries

The most important security boundary is the key.

The following should not be stored casually in source code:

- master encryption keys
- password-derived wrapping keys
- production database encryption keys
- private key-management credentials

The examples generate keys locally for demonstration purposes.

A production deployment should place long-lived secrets in an appropriate KMS, HSM, or controlled secret-management system.

Application logs should contain:

- key identifiers
- algorithm names
- operation status
- error categories
- timestamps

Application logs should not contain:

- raw encryption keys
- plaintext secrets
- authentication tags when unnecessary
- complete ciphertext payloads when sensitive
- passwords

## Relationship Between the Five Implementations

| Implementation | Primary perspective | Main mechanism |
|---|---|---|
| Python | Cryptographic mechanics | Self-contained AES and GCM construction |
| JavaScript | Event-driven application service | Node.js `crypto`, GCM, CBC-HMAC, CTR-HMAC |
| C++17 | Systems-level cryptographic service | OpenSSL EVP AES-256-GCM |
| Java 17 | Enterprise domain model | JCA/JCE, records, services, key lifecycle |
| PostgreSQL | Persistence and governance | Relational key lifecycle, envelopes, constraints, audit |

The implementations intentionally do not represent the same program in five syntaxes.

Python exposes lower-level cipher mechanics.

JavaScript emphasizes runtime cryptography and event-driven key operations.

C++ emphasizes explicit resource-managed use of a native cryptographic library.

Java models cryptographic operations as enterprise domain services.

PostgreSQL models persistence, lifecycle enforcement, rotation, auditing, and queryable cryptographic metadata.

## Operational Workflow

A practical encrypted-record lifecycle is:

`Generate Key`
        |
        v
`Activate Key`
        |
        v
`Generate Fresh IV/Nonce`
        |
        v
`Encrypt Plaintext`
        |
        v
`Authenticate Ciphertext + AAD`
        |
        v
`Store Envelope + Key ID`
        |
        v
`Retrieve Record`
        |
        v
`Resolve Key`
        |
        v
`Verify Authentication`
        |
        v
`Decrypt`
        |
        v
`Use Plaintext`

Key rotation operates beside this path:

`Active Key`
        |
        v
`Generate New Key`
        |
        v
`Retire Previous Key`
        |
        v
`Activate New Key`
        |
        v
`Encrypt New Records With New Key`

Historical ciphertext remains associated with its original key identifier until migration or retention policy removes the dependency.

## Implementation Limitations

The Python AES implementation is intentionally educational and should not replace a mature cryptographic library in production.

The PostgreSQL example demonstrates relational cryptographic governance and executable `pgcrypto` operations, but its `pgp_sym_encrypt` path is not equivalent to an application-generated AES-GCM envelope.

The examples use in-memory key stores in application code. Production key management requires stronger isolation, access control, auditing, backup, recovery, and rotation procedures.

Password-derived keys require carefully selected KDF parameters and should not be treated as substitutes for dedicated key-management infrastructure.

The central engineering rule remains:

`AES is a primitive; a secure system is a complete protocol around the primitive.`
