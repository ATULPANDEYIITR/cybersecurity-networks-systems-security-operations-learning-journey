# Cryptography Fundamentals

## Scope

This project models the fundamental relationship between plaintext, ciphertext, cryptographic keys, symmetric encryption, and asymmetric encryption.

The implementations deliberately separate four concepts:

| Concept | Meaning | Primary role |
|---|---|---|
| Plaintext | Original readable information | Application data before encryption |
| Ciphertext | Transformed protected representation | Conceals plaintext |
| Symmetric key | Shared secret used by both sides | Efficient bulk encryption |
| Asymmetric key pair | Public and private keys with different roles | Key distribution, key wrapping, and public-key operations |

The implementations also distinguish encryption from integrity protection. Encryption provides confidentiality. Authentication mechanisms such as HMAC or authenticated encryption provide protection against undetected modification.

## Cryptographic Model

The basic symmetric relationship is:

Plaintext + Secret Key
        |
        v
  Symmetric Encryption
        |
        v
   Ciphertext
        |
        |
   Secret Key
        |
        v
  Symmetric Decryption
        |
        v
     Plaintext

The asymmetric relationship is different:

Plaintext
    |
    v
Public Key Encryption
    |
    v
Ciphertext
    |
    v
Private Key Decryption
    |
    v
Plaintext

The public key is designed to be distributable. The private key must remain secret.

A practical hybrid design commonly combines both models:

Application Data
      |
      v
Symmetric Encryption
      |
      +----> Ciphertext
      |
      v
Symmetric Data Key
      |
      v
Asymmetric Key Wrapping
      |
      v
Protected Data Key

The symmetric algorithm handles the large payload efficiently. The asymmetric algorithm protects the smaller symmetric key.

## Plaintext and Ciphertext

Plaintext is the information an application intends to protect. It can be text, binary data, records, files, or serialized application objects.

Ciphertext is the result of applying an encryption operation using a cryptographic key and algorithm.

The Python implementation begins with a Caesar transformation because it makes the plaintext-to-ciphertext relationship visible. It is intentionally not treated as secure encryption. The transformation demonstrates that a reversible transformation is not automatically a secure cryptographic construction.

The JavaScript implementation uses the same basic distinction before moving to real cryptographic primitives supplied by the Node.js cryptographic library.

The C++ program separates byte-oriented plaintext from ciphertext and explicitly models the encryption mode.

The Java program uses a domain-level encrypted envelope containing the initialization vector, ciphertext, authentication tag, and state.

The PostgreSQL model stores ciphertext separately from labels describing the protected plaintext. Plaintext labels are metadata, not the original secret content.

## Symmetric Encryption

Symmetric encryption uses a shared secret.

The same secret is required to transform protected data back into its original form. This makes symmetric encryption computationally efficient and suitable for large amounts of data.

The implementations use two different perspectives.

### Demonstration Model

The Python and C++ programs include an XOR-based transformation to expose the mechanics of using a repeating secret byte sequence.

For each byte:

`ciphertext[i] = plaintext[i] XOR key[i mod key_length]`

Applying the same operation again restores the plaintext because XOR has the property:

`A XOR B XOR B = A`

This construction is useful for understanding the mechanics of reversible transformations but is not secure encryption. A repeating XOR key can expose patterns and is vulnerable to known-plaintext and statistical attacks.

### Production-Oriented Model

The JavaScript implementation uses `AES-256-GCM`.

The Java implementation also uses `AES/GCM/NoPadding`.

AES provides the symmetric encryption primitive. GCM adds authenticated encryption so that decryption can detect unauthorized modification.

An AES-GCM message consists conceptually of:

- Secret key
- Initialization vector
- Ciphertext
- Authentication tag

The initialization vector is not a secret. It must be unique for a given key when used with GCM.

The authentication tag is essential because successful decryption alone is not sufficient evidence that ciphertext was not modified.

## Initialization Vectors

An initialization vector, or IV, introduces unique state into many encryption modes.

For AES-GCM, a 96-bit IV is commonly used. The JavaScript implementation generates a fresh 12-byte IV for each encryption operation. The Java implementation does the same.

The IV can be stored with the ciphertext:

`IV + Ciphertext + Authentication Tag`

The IV does not replace the secret key. It is public metadata required for decryption.

Reusing a GCM IV with the same key is a serious security failure because it can compromise authentication and confidentiality.

## Authentication and Integrity

Encryption and integrity are separate security properties.

A ciphertext can conceal data while still being vulnerable to unauthorized modification if the encryption construction does not authenticate the ciphertext.

The Python implementation uses HMAC-SHA256 with a separate authentication key.

The JavaScript implementation uses HMAC-SHA256 for the same conceptual purpose and uses a constant-time comparison for tag verification.

The Java implementation uses `Mac` with HMAC-SHA256 and `MessageDigest.isEqual` for comparison.

The database implementation stores authentication-related material separately from ciphertext and records whether an operation has an authentication tag.

Authenticated encryption such as AES-GCM combines confidentiality and integrity in one standardized construction. When AES-GCM is used, applications should normally rely on the authentication failure generated by the cryptographic API rather than creating a second independent MAC without a specific architectural reason.

## Key Separation

Keys should have clearly defined purposes.

The implementations distinguish:

| Key purpose | Example |
|---|---|
| Data encryption | AES-256-GCM key |
| Authentication | HMAC-SHA256 secret |
| Asymmetric encryption | RSA public key |
| Asymmetric decryption | RSA private key |
| Key wrapping | RSA public/private pair |

The Python implementation generates separate encryption and authentication keys.

The Java enterprise model represents key purpose explicitly through `CryptoPolicy`.

The PostgreSQL model records `key_purpose` and `key_type` as constrained fields.

Using one secret for unrelated cryptographic purposes can create unwanted relationships between protocols and complicate key rotation.

## Asymmetric Encryption

Asymmetric cryptography uses two mathematically related keys.

The public key may be distributed to other systems. The private key remains controlled by the key owner.

For encryption:

`Ciphertext = Encrypt(PublicKey, Plaintext)`

For decryption:

`Plaintext = Decrypt(PrivateKey, Ciphertext)`

The Python and C++ programs contain small educational RSA implementations. They demonstrate modular exponentiation, prime generation, Euler's totient, public exponent selection, and modular inversion.

Those implementations intentionally use very small keys so that the mathematical operations remain executable and inspectable. They are not suitable for protecting real data.

The JavaScript implementation uses Node.js RSA-OAEP with SHA-256 and a 2048-bit RSA key pair.

The Java implementation uses `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` and explicitly enforces a 2048-bit minimum RSA policy.

## RSA Key Roles

RSA encryption normally separates the roles of the keys:

| Key | Visibility | Encryption role |
|---|---|---|
| Public key | Distributable | Encrypt or verify, depending on operation |
| Private key | Secret | Decrypt or sign, depending on operation |

Encryption and digital signatures are related to asymmetric cryptography but are not interchangeable operations.

A private key should not be treated as simply the secret version of a public encryption key. Its use depends on the cryptographic operation and protocol.

## Hybrid Encryption

Directly applying RSA to large application payloads is inefficient and subject to strict size constraints.

A practical architecture therefore uses hybrid encryption.

The workflow implemented conceptually by the C++ and Java programs is:

1. Generate a random symmetric data key.
2. Encrypt application data with the symmetric key.
3. Encrypt or wrap the symmetric key using the recipient's public key.
4. Store or transmit the ciphertext and wrapped key.
5. The recipient uses the private key to recover the symmetric key.
6. The recipient uses the recovered symmetric key to decrypt the data.
7. Authenticated encryption verifies that the ciphertext has not been modified.

This separates bulk-data performance from key-distribution requirements.

## Python Implementation

The Python script contains several distinct layers.

### Basic transformation

`caesar_encrypt` and `caesar_decrypt` demonstrate the reversible relationship between plaintext and ciphertext.

The implementation preserves non-alphabetic characters and normalizes large shifts.

### Symmetric demonstration

`SymmetricKey` stores generated random key material.

The XOR demonstration performs byte-wise transformation and validates that decryption restores the original bytes.

### Integrity

`hmac_sha256` creates an HMAC-SHA256 authentication value. `verify_hmac` uses `hmac.compare_digest` to avoid a simple early-exit comparison.

The program modifies one ciphertext byte and confirms that the authentication value no longer matches.

### RSA

The Python RSA model includes:

- Prime generation
- Euler totient calculation
- Public exponent selection
- Modular inverse
- Public-key encryption
- Private-key decryption

The implementation uses small educational keys and explicitly limits the RSA message size.

### Validation

The program rejects:

- Empty plaintext
- Short symmetric keys
- Invalid RSA ciphertext values
- Excessively large plaintext
- Invalid key configurations

## JavaScript Implementation

The JavaScript implementation is event-oriented and uses Node.js standard cryptographic facilities.

### AES-GCM

`aesGcmEncrypt` generates a random IV and returns an envelope containing:

- IV
- Ciphertext
- Authentication tag

`aesGcmDecrypt` reconstructs the authenticated input and allows the cryptographic API to reject modified ciphertext.

### RSA-OAEP

`generateRsaKeyPair` creates a 2048-bit RSA key pair.

`rsaEncrypt` uses RSA-OAEP with SHA-256. `rsaDecrypt` uses the matching private key.

The implementation also tests an unrelated private key and expects decryption to fail.

### HMAC

HMAC-SHA256 is implemented separately so that confidentiality and integrity concepts can be observed independently.

### Event Processing

The asynchronous policy section models cryptographic policy events such as key creation and encryption requests.

`Promise.all` processes independent events concurrently while a `Set` represents the approved algorithm policy.

This separates cryptographic operations from application-level event handling.

## C++17 Implementation

The C++ program models a secure-message service rather than reproducing the JavaScript API.

### Domain Types

The program defines:

- `SymmetricKey`
- `PublicKey`
- `PrivateKey`
- `RSAKeyPair`
- `EncryptedMessage`
- `EncryptionMode`

These types make key roles and encryption modes explicit.

### RSA Mathematics

The educational RSA engine implements:

- Prime testing
- Random prime selection
- Modular exponentiation
- Extended Euclidean algorithm
- Modular inverse
- Key-pair generation

The modular exponentiation algorithm repeatedly squares the base while processing the exponent in binary, reducing the number of multiplication operations from linear in the exponent to logarithmic in its value.

### Hybrid Encryption

The hybrid demonstration creates a symmetric data key, encrypts the data, then protects the data key with an RSA public key.

The RSA private key recovers the data key.

The recovered symmetric key then decrypts the original application data.

This represents the architectural pattern used by many real systems, while the underlying demonstration primitives remain intentionally simplified.

### Failure Handling

The program rejects:

- Symmetric keys shorter than the required minimum
- RSA ciphertext values outside the modulus
- Invalid round trips
- Tampered demonstration ciphertext

Exceptions provide explicit failure boundaries.

## Java 17 Implementation

The Java program uses an enterprise-oriented domain model.

### `CryptoPolicy`

`CryptoPolicy` centralizes minimum security requirements.

It enforces:

- AES keys of at least 256 bits
- RSA keys of at least 2048 bits
- AES as the approved symmetric algorithm

This separates security policy from the service implementation.

### `SecureMessageService`

The service provides:

- AES key generation
- RSA key-pair generation
- AES-GCM encryption
- AES-GCM decryption
- RSA-OAEP key wrapping
- RSA-OAEP key unwrapping
- HMAC-SHA256 generation
- HMAC verification

The service explicitly checks application-level states before decryption.

### Immutable Domain Data

The `EncryptedEnvelope`, `ProtectedKey`, and `AuditEvent` records model immutable data structures.

The envelope records the IV, ciphertext, authentication tag, and message state.

This prevents application code from treating ciphertext as an unstructured byte array with no associated security metadata.

### Audit Model

`AuditLog` records actor, operation, state, and authorization information.

The workflow records:

`CREATE_DATA_KEY -> ENCRYPT -> WRAP_DATA_KEY -> DECRYPT`

This demonstrates how cryptographic operations can be integrated into enterprise service auditing.

## PostgreSQL Implementation

The PostgreSQL script models cryptographic operations as relational data.

### `cryptographic_keys`

This table records:

- Key identifier
- Key name
- Key type
- Algorithm
- Purpose
- Status
- Version
- Fingerprint
- Public material
- Encrypted secret material
- Creation timestamp
- Expiration timestamp

Constraints prevent invalid key types, algorithms, purposes, and statuses.

A unique fingerprint prevents accidental duplication of key identities.

### `encryption_operations`

This table records cryptographic activity.

Each operation references a cryptographic key through a foreign key.

The table records:

- Operation reference
- Operation type
- Plaintext label
- Ciphertext
- Authentication tag
- Status
- Requesting service
- Creation time

The database does not store the original sensitive plaintext as part of the operation record.

### Database-Level Validation

The `validate_encryption_key` trigger checks that an operation is compatible with the selected key.

For example:

- Symmetric encryption requires AES-256-GCM.
- HMAC requires HMAC-SHA256.
- Key wrapping requires RSA-OAEP-SHA256.
- Inactive keys cannot process new operations.

This prevents application-level mistakes from silently producing invalid cryptographic workflows.

### PostgreSQL Cryptographic Functions

The script enables `pgcrypto`.

`pgp_sym_encrypt` and `pgp_sym_decrypt` provide a PostgreSQL-native demonstration of symmetric protected data.

`digest` demonstrates SHA-256 hashing.

The database model also records RSA public-key material for asymmetric workflows. Public-key encryption can be performed by application services using vetted cryptographic libraries while PostgreSQL maintains the metadata, audit records, key state, and workflow constraints.

## Key Lifecycle

A cryptographic key should have a defined lifecycle.

A simplified lifecycle is:

`ACTIVE -> ROTATING -> EXPIRED`

or:

`ACTIVE -> REVOKED`

Key rotation creates a new key version rather than modifying historical ciphertext.

Historical records should retain the identifier or version of the key that protected them so that older data remains decryptable according to the organization's retention and recovery policy.

The PostgreSQL model uses `key_version`, `key_status`, `created_at`, and `expires_at` to represent lifecycle information.

## Failure Conditions

Important failure cases represented by the implementations include:

| Failure | Expected behavior |
|---|---|
| Empty plaintext | Reject before encryption |
| Short symmetric key | Reject |
| Invalid RSA ciphertext | Reject |
| Wrong private key | Decryption fails |
| Modified AES-GCM ciphertext | Authentication failure |
| Modified HMAC input | Verification failure |
| Inactive database key | Database trigger rejects operation |
| Unsupported algorithm | Policy or constraint rejects operation |
| Expired key | Excluded from normal active-key selection |

Failure handling is part of cryptographic correctness. An application that silently continues after authentication failure can turn a secure primitive into an insecure workflow.

## Security Considerations

The educational implementations make several deliberate distinctions.

### Do not use the toy RSA implementations in production

The Python and C++ RSA implementations use small primes and omit production padding and hardened key-generation mechanisms.

Real RSA requires appropriately sized keys, secure randomness, proper padding such as OAEP for encryption, and careful key handling.

### Do not use repeating XOR as encryption

The XOR implementation exposes symmetric transformation mechanics. A repeating key is not an adequate modern encryption system.

Production systems should use established authenticated-encryption constructions such as AES-GCM or ChaCha20-Poly1305 through trusted libraries.

### Protect private keys

Public keys can be distributed. Private keys and symmetric secrets require controlled access.

Private key material should normally be stored using a dedicated key-management system or hardware-backed security mechanism where appropriate.

### Do not log secrets

The examples print fingerprints rather than raw secret keys where possible.

Production audit logs should not contain:

- Plaintext secrets
- Symmetric key material
- Private keys
- Passwords
- Authentication secrets
- Unprotected decrypted payloads

### Use secure randomness

Cryptographic keys, IVs, and nonces require a cryptographically secure random source.

The Python implementation uses `secrets`.

The JavaScript implementation uses Node's `crypto.randomBytes`.

The Java implementation uses `SecureRandom`.

The C++ demonstration uses the standard random facilities only for educational purposes and should not be interpreted as a production key-generation implementation.

## Performance Considerations

Symmetric encryption is normally much faster than public-key encryption for bulk data.

The practical division is therefore:

| Operation | Typical role |
|---|---|
| AES-GCM | Large application data |
| RSA-OAEP | Small keys or key-wrapping operations |
| HMAC-SHA256 | Integrity/authentication where required |
| SHA-256 | Fingerprints and non-secret integrity-related identifiers |

The hybrid model avoids attempting to encrypt large payloads directly with RSA.

The Python and C++ educational RSA implementations also make the computational cost visible by operating on individual bytes. Production cryptographic libraries use optimized implementations and carefully defined padding schemes.

## Relationship Between the Five Implementations

| Language | Primary engineering perspective |
|---|---|
| Python | Conceptual model, validation, educational RSA mathematics, HMAC |
| JavaScript | Node.js cryptographic APIs, AES-GCM, RSA-OAEP, asynchronous event processing |
| C++17 | Typed cryptographic domain model, modular arithmetic, hybrid workflow |
| Java 17 | Enterprise policy objects, immutable records, service layer, JCA/JCE |
| PostgreSQL | Key metadata, encrypted records, constraints, triggers, auditing, reporting |

The five implementations intentionally do not represent the same program translated into five languages.

They use different structures to expose different engineering concerns while preserving the same cryptographic vocabulary.

## Practical Workflow

A realistic application workflow is:

`Application Data`
→ `Validate Input`
→ `Generate or Retrieve Data Key`
→ `Encrypt with Authenticated Symmetric Cipher`
→ `Protect Data Key with Recipient Public Key`
→ `Store Ciphertext + IV + Tag + Wrapped Key`
→ `Audit Operation`
→ `Retrieve`
→ `Unwrap Data Key`
→ `Verify Authentication`
→ `Decrypt`
→ `Return Plaintext`

The important boundaries are:

- Plaintext is application data.
- Ciphertext is protected data.
- The symmetric key protects the payload.
- The asymmetric key pair protects or distributes the symmetric key.
- Authentication validates that protected data was not modified.
- Key metadata controls lifecycle and usage.
- Application policy determines which cryptographic mechanisms are permitted.

## Limitations

The educational Python and C++ cryptographic primitives are intentionally simplified.

They demonstrate mathematical and architectural concepts rather than providing production cryptographic implementations.

The production-oriented JavaScript and Java examples use established platform cryptographic APIs, but secure deployment still requires correct key management, nonce management, access control, logging practices, rotation procedures, and protocol design.

The PostgreSQL script demonstrates database-level cryptographic operations and governance. A database should not automatically become the long-term owner of all private cryptographic material merely because it can store encrypted bytes.

Cryptographic security depends on the complete system, not only on the encryption algorithm.
