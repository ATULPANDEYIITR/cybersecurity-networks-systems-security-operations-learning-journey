# Password Security

## 1. Technical Scope

Password security protects user credentials against unauthorized access, offline password cracking, credential reuse, and automated authentication attacks.

This project implements five complementary approaches:

| Implementation | Primary mechanism | Security focus |
|---|---|---|
| Python | scrypt | Memory-hard password hashing |
| JavaScript | Node.js crypto.scrypt | Asynchronous authentication |
| C++17 | PBKDF2-HMAC-SHA-256 | Cryptographic derivation and account governance |
| Java 17 | PBKDF2WithHmacSHA256 | Enterprise credential management |
| PostgreSQL | pgcrypto bcrypt | Relational credential management |

The implementations distinguish password validation, password hashing, salt generation, key stretching, password verification, account management, and authentication security.

## 2. Password Security Fundamentals

### 2.1 Passwords and authentication

A password is a knowledge-based authentication factor.

During registration, an application receives a password and derives a password verifier. The verifier is stored instead of the original password.

During authentication, the application derives a new verifier from the submitted password and compares it with the stored verifier.

The process is:

Registration:

User password → Policy validation → Random salt → Password hashing → Stored verifier

Authentication:

Submitted password → Stored salt and parameters → Password hashing → Verification → Authentication decision

The original password should never be stored in plaintext.

### 2.2 Password hashing versus encryption

Password hashing and encryption serve different purposes.

| Property | Password hashing | Encryption |
|---|---|---|
| Operation | One-way derivation | Reversible transformation |
| Original password recovery | Not intended | Possible with the key |
| Primary purpose | Authentication | Confidentiality |
| Typical mechanisms | Argon2id, scrypt, bcrypt, PBKDF2 | AES-GCM, ChaCha20-Poly1305 |
| Secret required for verification | No application encryption key required | Decryption key required |

A password verifier is not an encrypted password.

Applications should not use ordinary SHA-256, MD5, or SHA-1 directly as password storage algorithms. These algorithms are designed for fast hashing, making large-scale password guessing more efficient.

## 3. Password Hashing Algorithms

### 3.1 scrypt

Python and JavaScript implement scrypt.

scrypt is a memory-hard password-based key derivation function. Its computational and memory requirements make large-scale parallel password guessing more expensive.

Its parameters include:

| Parameter | Meaning |
|---|---|
| N | CPU and memory cost parameter |
| r | Block size parameter |
| p | Parallelization parameter |
| Salt | Unique random input |
| dklen | Derived key length |

The approximate dominant memory requirement is:

`128 × N × r bytes`

For the configured values:

- N = 16,384
- r = 8
- p = 1
- Derived key length = 32 bytes
- Salt length = 16 bytes

The dominant memory requirement is approximately 16 MiB per derivation.

The actual resource requirement also depends on the implementation and runtime.

The parameters must be benchmarked against the production hardware and authentication workload.

### 3.2 PBKDF2

C++17 and Java 17 implement PBKDF2-HMAC-SHA-256.

PBKDF2 repeatedly applies a pseudorandom function to derive a key from a password and salt.

For one output block:

`U1 = PRF(password, salt || INT_32_BE(1))`

`U2 = PRF(password, U1)`

`U3 = PRF(password, U2)`

The final derived block is:

`T1 = U1 XOR U2 XOR ... XOR Uc`

Here, `c` represents the iteration count.

The implementation uses 600,000 iterations and produces a 256-bit derived key.

PBKDF2 increases the computational cost of each password guess. Unlike scrypt, it does not provide the same memory-hard properties.

The C++ implementation contains SHA-256, HMAC, and PBKDF2 implementations to demonstrate the underlying cryptographic construction. Custom cryptographic implementations require independent security auditing and should not replace established production libraries.

### 3.3 bcrypt

The PostgreSQL implementation uses bcrypt through the `pgcrypto` extension.

The relevant PostgreSQL operations are:

- `gen_salt('bf', cost)` generates a random bcrypt salt.
- `crypt(password, salt)` derives a password verifier.
- `crypt(password, stored_hash)` derives a candidate verifier for verification.

The resulting bcrypt verifier contains the algorithm identifier, work factor, salt, and derived password hash.

The configured bcrypt cost is 12.

bcrypt has a practical limitation: its password input handling has a 72-byte limit. Applications using bcrypt must enforce compatible input handling and avoid silently truncating passwords.

### 3.4 Algorithm comparison

| Algorithm | Memory hardness | Main cost control | Implementation |
|---|---|---|---|
| scrypt | Yes | N, r, p | Python, JavaScript |
| PBKDF2-HMAC-SHA-256 | No | Iterations | C++17, Java 17 |
| bcrypt | Limited memory requirement | Cost factor | PostgreSQL |

Argon2id is another widely recommended password hashing algorithm and is generally preferred for new password storage systems when a maintained implementation is available.

## 4. Salts

A salt is a unique random value generated for each password record.

It prevents identical passwords from automatically producing identical stored verifiers.

For example:

- User A selects a particular password.
- User B selects the same password.
- User A receives salt A.
- User B receives salt B.
- Their derived password verifiers differ.

The salt is not a secret.

It is stored with the password verifier so that the same derivation can be performed during authentication.

### Salt requirements

- Use a cryptographically secure random number generator.
- Generate a separate salt for every password.
- Use at least 16 random bytes.
- Store the salt with the verifier.
- Never substitute a fixed salt.
- Never reuse a salt across accounts intentionally.

The implementations use:

| Language | Salt generation |
|---|---|
| Python | `secrets.token_bytes()` |
| JavaScript | `crypto.randomBytes()` |
| C++17 | `std::random_device` demonstration |
| Java 17 | `SecureRandom` |
| PostgreSQL | `gen_salt()` |

The C++ implementation demonstrates the construction but uses a platform-dependent random source. Production deployments should obtain salts from an audited operating-system cryptographic random generator or established cryptographic library.

## 5. Key Stretching

Key stretching deliberately increases the cost of password verification.

An attacker attempting an offline dictionary attack must perform the configured derivation for every candidate password.

For example, if an application uses PBKDF2 with 600,000 iterations, each candidate requires the corresponding repeated computation.

Key stretching is important because human-selected passwords usually have much less entropy than randomly generated cryptographic keys.

### Important distinctions

| Mechanism | Purpose |
|---|---|
| Salt | Prevents identical password inputs from sharing identical verifiers |
| Key stretching | Increases the cost of password guessing |
| Memory hardness | Increases memory requirements for password guessing |
| Pepper | Adds a separate secret maintained outside the password database |
| Work factor | Controls the computational or memory cost of derivation |

A pepper is optional and must be protected separately from the database. Losing the pepper can make stored password verifiers unusable.

## 6. Password Policy Management

Password policies define which passwords an application accepts.

The implementations demonstrate:

- Minimum password length.
- Maximum password length.
- Rejection of empty passwords.
- Rejection of null characters.
- Common-password blocklisting.
- Validation before hashing.
- Password changes.
- Password history.
- Authentication failure tracking.

The examples use a minimum length of 15 characters and a maximum of 128 characters.

They deliberately avoid mandatory uppercase, lowercase, digit, and special-character combinations.

Length, uniqueness, and resistance to commonly used or compromised passwords are more meaningful policy objectives than arbitrary character-composition rules.

### Password policy considerations

| Policy | Security purpose |
|---|---|
| Minimum length | Reduces susceptibility to guessing |
| Maximum length | Prevents resource abuse |
| Common-password blocklist | Rejects predictable passwords |
| Compromised-password screening | Prevents known exposed credentials |
| Password history | Prevents immediate reuse |
| Rate limiting | Restricts repeated authentication attempts |
| MFA | Adds another authentication factor |

A production blocklist should be substantially larger than the demonstration lists and should include compromised passwords.

Password policy should not unnecessarily require periodic password changes without evidence of compromise or another security justification.

## 7. Python Implementation

### 7.1 Architecture

The Python implementation uses separate classes for policy validation, password derivation, password records, and authentication.

| Component | Responsibility |
|---|---|
| `ScryptConfig` | Hashing parameters |
| `PasswordPolicy` | Password validation |
| `PasswordRecord` | Credential serialization |
| `PasswordHasher` | Hashing and verification |
| `UserAccount` | Account state |
| `AuthenticationService` | Registration, authentication, and password changes |

### 7.2 Password record

The password record contains:

- Algorithm identifier.
- scrypt N parameter.
- scrypt r parameter.
- scrypt p parameter.
- Encoded salt.
- Encoded derived key.

The record can be serialized into JSON and restored for subsequent verification.

The deserialization process validates algorithm identifiers, parameter ranges, salt lengths, and derived-key lengths.

This prevents malformed records from silently entering the verification workflow.

### 7.3 Authentication

Authentication uses `hmac.compare_digest()` to compare derived keys.

The implementation also includes:

- Failed authentication counters.
- Account locking after five failures.
- Password change validation.
- Password record verification.
- Hash parameter upgrade detection.

The demonstration includes unit tests for successful authentication, incorrect passwords, unique salts, serialization, password policy, account locking, and password changes.

## 8. JavaScript Implementation

### 8.1 Asynchronous password derivation

The JavaScript implementation uses Node.js's native `crypto` module.

Password derivation is asynchronous through the Promise-based scrypt API.

This avoids blocking the main event loop while password derivation is running.

Password hashing is represented as a versioned record.

The record contains:

- Version.
- Algorithm.
- N, r, and p parameters.
- Salt.
- Derived hash.

### 8.2 Event-driven authentication

The implementation separates account operations from security event reporting.

The authentication service publishes events such as:

| Event | Meaning |
|---|---|
| `account.registered` | Account successfully created |
| `authentication.succeeded` | Password verification succeeded |
| `authentication.failed` | Password verification failed |
| `account.locked` | Failed-attempt threshold reached |
| `password.changed` | Password successfully rotated |
| `password.rehashed` | Existing verifier upgraded |

Listeners receive structured event information.

Audit subscribers cannot interrupt authentication processing if their callback fails.

The example stores audit events in memory. Production auditing should use durable, access-controlled storage.

### 8.3 Hash upgrades

Password hashing parameters may change as hardware capabilities improve.

The `needsRehash()` method identifies records whose parameters differ from the current configuration.

After successful authentication, the service can generate a new verifier using updated parameters.

The user does not need to know the original password's stored salt or derived key.

## 9. C++17 Implementation

### 9.1 Cryptographic components

The C++ program implements three connected components:

1. SHA-256.
2. HMAC-SHA-256.
3. PBKDF2-HMAC-SHA-256.

SHA-256 processes data in 512-bit blocks.

HMAC combines a secret key with inner and outer padding to construct a keyed message authentication function.

PBKDF2 repeatedly applies HMAC to increase the cost of password derivation.

### 9.2 Password verifier

The C++ password record contains:

| Field | Purpose |
|---|---|
| Algorithm | Identifies PBKDF2-HMAC-SHA-256 |
| Iterations | Records key-stretching cost |
| Salt | Stores the random salt in hexadecimal |
| Hash | Stores the derived key in hexadecimal |

The implementation rejects malformed records and invalid iteration counts.

### 9.3 Account governance

The account model contains:

- Username.
- Password record.
- Failed-attempt count.
- Account status.

The authentication service supports registration, verification, password rotation, and account locking.

The program uses constant-time comparison for fixed-length derived keys.

Its cryptographic implementation is intended to explain the algorithms and their interaction. Production systems should use independently audited cryptographic implementations, platform-provided secure randomness, and appropriate memory protection.

## 10. Java 17 Implementation

### 10.1 Enterprise architecture

The Java implementation uses domain types and service classes to separate responsibilities.

| Component | Responsibility |
|---|---|
| `PasswordPolicy` | Defines password acceptance criteria |
| `PolicyResult` | Represents validation outcomes |
| `PasswordRecord` | Immutable password verifier |
| `PasswordHasher` | PBKDF2 derivation and verification |
| `UserAccount` | Account and password history state |
| `AuthenticationService` | Registration and authentication |
| `SecurityEvent` | Structured audit information |

The implementation uses Java records for immutable data structures and collections for account and event management.

### 10.2 PBKDF2 implementation

Java uses the standard `SecretKeyFactory` interface with `PBKDF2WithHmacSHA256`.

`PBEKeySpec` receives:

- Password characters.
- Salt.
- Iteration count.
- Derived key length.

The specification is cleared after derivation.

Derived byte arrays are also cleared after verification where possible.

Java applications must recognize that clearing arrays does not guarantee that every temporary copy created by the runtime or string operations has been removed from memory.

### 10.3 Account state

The account model supports:

- `ACTIVE`
- `LOCKED`
- `DISABLED`

A failed authentication increases the failure counter.

After five failures, the account enters the locked state.

The example uses a temporary lock duration of 60 seconds.

The lock expires when a subsequent authentication attempt checks account availability.

### 10.4 Password history

The account maintains a bounded history of previous password verifiers.

Password rotation checks the new password against the current verifier and retained historical verifiers.

The history is limited to five previous records.

In a production deployment, password history should be stored durably and managed transactionally.

## 11. PostgreSQL Implementation

### 11.1 Relational architecture

The database implementation uses the `password_security` schema.

The principal relationships are:

    password_policies
           |
           v
       user_accounts
           |
           +------------------+
           |                  |
           v                  v
    password_history     security_audit

The schema includes:

| Table | Responsibility |
|---|---|
| `password_policies` | Active password rules |
| `common_passwords` | Blocklisted passwords |
| `user_accounts` | Account and password verifier storage |
| `password_history` | Previous password verifiers |
| `security_audit` | Authentication and password events |

### 11.2 Constraints and indexes

Database constraints enforce:

- Unique usernames.
- Unique email addresses.
- Valid account statuses.
- Valid password policy values.
- Valid hashing cost parameters.
- Valid failed-attempt counters.
- Valid password verifier storage.

Indexes support:

- Account status retrieval.
- Locked-account searches.
- Password expiration reporting.
- Password history retrieval.
- Audit event aggregation.

### 11.3 Registration workflow

The `register_user()` function:

1. Retrieves the active password policy.
2. Validates the submitted password.
3. Generates a bcrypt verifier.
4. Inserts the account.
5. Records an account creation event.
6. Returns the generated account identifier.

The database does not insert the original password into the account table.

### 11.4 Authentication workflow

The `authenticate_user()` function:

1. Retrieves and locks the account row.
2. Checks account status.
3. Checks whether an existing lock has expired.
4. Verifies the password against the stored bcrypt verifier.
5. Resets failed attempts after success.
6. Increments failed attempts after failure.
7. Locks the account when the configured threshold is reached.
8. Records an audit event.

The `FOR UPDATE` clause serializes concurrent authentication attempts against the same account row.

This helps prevent lost updates to the failed-attempt counter.

The function returns a Boolean authentication result.

### 11.5 Password rotation

The `change_user_password()` function verifies the current password before accepting a new one.

It also checks:

- Current password correctness.
- New password policy compliance.
- Current-password reuse.
- Historical-password reuse.
- Password history retention.

The previous verifier is inserted into `password_history` before the account record is updated.

The function operates within the calling transaction, allowing the password change and associated audit event to succeed or fail together.

### 11.6 Reporting

Three views support operational reporting.

**`password_expiration_report`**

Identifies accounts with no expiration, valid passwords, expiring passwords, or expired passwords.

**`account_security_report`**

Displays account status, failed attempts, policy information, and retained password history.

**`security_event_summary`**

Aggregates security events and affected accounts.

The SQL script also includes CTE-based account risk reporting and queries for account retrieval, password policy validation, lockout status, and audit history.

## 12. Password Verification and Attack Resistance

### 12.1 Offline dictionary attacks

An attacker who obtains a password database can attempt candidate passwords without interacting with the authentication service.

Salts prevent precomputed hash tables from being directly reused across accounts.

Key stretching increases the cost of each candidate.

Memory-hard algorithms increase the resources required for large-scale guessing.

None of these mechanisms makes weak passwords impossible to crack.

### 12.2 Brute-force attacks

A brute-force attacker systematically attempts possible passwords.

Increasing password length and entropy increases the search space.

Password hashing makes every candidate more expensive to test.

Online rate limiting and authentication monitoring address repeated attempts against live accounts.

### 12.3 Credential stuffing

Credential stuffing uses usernames and passwords exposed in other breaches.

Password hashing does not prevent credential stuffing when users reuse passwords.

Mitigations include:

- Unique passwords for every service.
- Compromised-password screening.
- Multi-factor authentication.
- Rate limiting.
- Suspicious-login detection.

### 12.4 Timing attacks

Ordinary comparison functions may stop when they encounter the first differing byte.

This can reveal information about comparison results through timing differences.

The implementations use constant-time comparison functions where available.

Constant-time comparison does not eliminate every possible timing side channel in the surrounding authentication workflow.

## 13. Security Limitations and Production Considerations

| Area | Demonstration limitation | Production consideration |
|---|---|---|
| Password hashing | Example parameters | Benchmark and periodically review work factors |
| Algorithm choice | scrypt, PBKDF2, bcrypt | Prefer Argon2id where suitable |
| Common passwords | Small blocklists | Use a maintained compromised-password screening process |
| Rate limiting | Account-level failure counters | Add distributed IP, device, and account-based limits |
| Account locking | Simple temporary lock | Prevent denial-of-service through targeted lockouts |
| Audit | In-memory or database events | Centralize protected and tamper-resistant logs |
| Salt generation | Platform-dependent C++ example | Use an audited CSPRNG |
| Password history | Limited demonstration | Use durable, transactional storage |
| MFA | Not implemented | Add another independent authentication factor |
| Recovery | Not implemented | Use protected account recovery procedures |
| Pepper | Not implemented | Store any pepper outside the credential database |
| Transport security | Not implemented | Use TLS for authentication traffic |

### Database security

The PostgreSQL implementation demonstrates relational password management, not a complete production identity provider.

A production database should:

- Restrict access to password verifiers.
- Grant applications only the required function permissions.
- Avoid exposing credential columns through general-purpose views.
- Prevent plaintext passwords from appearing in SQL logs.
- Protect backups and replicas.
- Use encrypted connections.
- Restrict administrative privileges.
- Monitor unusual authentication activity.

The SQL functions use database-side password processing for demonstration. Production deployments should carefully review function privileges, ownership, `search_path` configuration, connection logging, and application access boundaries.

### Resource management

Password derivation consumes CPU and, for scrypt, substantial memory.

Concurrent authentication requests can exhaust application resources.

Production systems should use:

- Bounded authentication concurrency.
- Request timeouts.
- Admission control.
- Resource monitoring.
- Load testing.
- Carefully benchmarked derivation parameters.

## 14. Execution Requirements

| File | Runtime or requirement |
|---|---|
| Python | Python 3.10+ |
| JavaScript | Node.js 18+ |
| C++17 | C++17-compatible compiler |
| Java | Java 17 |
| PostgreSQL | PostgreSQL 15+ with `pgcrypto` |

### Python

Run the script directly with Python.

It executes the demonstration and its unit tests.

### JavaScript

Run the JavaScript file with Node.js.

It uses native Node.js modules and does not require npm dependencies.

### C++17

Compile using a C++17-compatible compiler.

The program performs PBKDF2 derivation and SHA-256 validation.

### Java 17

Compile and run the `PasswordSecurity` class using Java 17.

The implementation uses standard Java cryptographic APIs.

### PostgreSQL

Execute the SQL script using a PostgreSQL connection with sufficient permissions to create extensions, schemas, tables, functions, and views.

The `pgcrypto` extension must be available.

The script creates demonstration accounts and runs the password security workflows inside a transaction.

## 15. Core Terminology

| Term | Definition |
|---|---|
| Password verifier | Stored derived value used to verify a submitted password |
| Salt | Unique random input used during password derivation |
| Key stretching | Repeated computation that increases password-guessing cost |
| Memory hardness | Property that makes password guessing require significant memory |
| Work factor | Configured computational cost of password derivation |
| Pepper | Additional secret maintained separately from password records |
| PBKDF2 | Password-based key derivation function using repeated pseudorandom operations |
| scrypt | Memory-hard password-based key derivation function |
| bcrypt | Adaptive password hashing algorithm |
| HMAC | Keyed construction based on a cryptographic hash function |
| SHA-256 | Cryptographic hash function producing a 256-bit digest |
| Constant-time comparison | Comparison designed to avoid data-dependent early termination |
| Credential stuffing | Automated use of previously exposed credentials |
| Password rotation | Replacement of an existing password with a new password |
| Account lockout | Temporary or permanent restriction following authentication failures |
| Password history | Retained previous password verifiers used to restrict reuse |
| Multi-factor authentication | Authentication using multiple independent factor categories |

## 16. Educational Outcomes

The five implementations demonstrate different engineering perspectives on the same security problem.

- Python emphasizes modular password hashing, validation, serialization, and unit testing.
- JavaScript emphasizes asynchronous cryptographic operations and event-driven authentication.
- C++17 demonstrates the internal construction of SHA-256, HMAC, and PBKDF2.
- Java 17 models enterprise account state, password history, validation, and security auditing.
- PostgreSQL demonstrates database-backed credential management, integrity constraints, transactional password rotation, and security reporting.

The central security principle is that passwords should be stored as deliberately expensive, salted password verifiers rather than plaintext or fast general-purpose hashes.
