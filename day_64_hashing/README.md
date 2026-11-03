# Cryptographic Hashing: SHA-2, SHA-3, Collision Resistance and Integrity Verification

## 1. Scope and implemented workflow

Cryptographic hashing transforms an input of arbitrary length into a fixed-length digest. The input can be a file, message, document, software package, configuration, model artifact or database export.

This project implements two cryptographic hash families:

- **SHA-2:** SHA-256 and SHA-512.
- **SHA-3:** SHA3-256 and SHA3-512.

It also implements integrity verification and HMAC-based message authentication. The five source files approach the same subject through different engineering perspectives:

| Deliverable | Engineering perspective | Main implementation |
|---|---|---|
| Python | General-purpose hashing and automation | Streaming file hashing, manifests, digest validation and HMAC |
| JavaScript | Event-driven integrity monitoring | Asynchronous file processing, event emission and manifest registration |
| C++17 | Cryptographic algorithm mechanics | Self-contained SHA-256, SHA3-256 and HMAC-SHA-256 |
| Java 17 | Enterprise release management | JCA-based digest service, immutable records, policy enforcement and audit history |
| PostgreSQL | Relational integrity management | Algorithm policy, artifact versions, digest triggers and verification records |

The workflow is:

Artifact
  |
  v
Select approved hash algorithm
  |
  v
Calculate digest
  |
  v
Store trusted digest metadata
  |
  v
Receive or retrieve artifact
  |
  v
Calculate digest again
  |
  v
Compare expected and observed values
  |
  +---- Match ------> Integrity check passed
  |
  +---- Mismatch ---> Integrity check failed

A successful comparison establishes that the observed bytes produce the expected digest. It does not independently establish who created the artifact or whether the stored expected digest is trustworthy.

## 2. Cryptographic hash functions

A cryptographic hash function accepts an input message and produces a fixed-size output:

\[
H : \{0,1\}^{*} \rightarrow \{0,1\}^{n}
\]

Where:

- \(H\) is the hash function.
- The input can contain any finite number of bits.
- \(n\) is the fixed output length.
- The output is commonly represented as hexadecimal characters.

For a given algorithm, the same input always produces the same digest. A one-bit change in the input is expected to produce a substantially different output.

A cryptographic hash function is designed to provide three important security properties.

### 2.1 Preimage resistance

Given a digest \(d\), finding an input \(m\) satisfying the following relationship should be computationally infeasible:

\[
H(m)=d
\]

This property prevents an attacker from efficiently reconstructing an original message from its digest.

### 2.2 Second-preimage resistance

Given an existing message \(m_1\), finding a different message \(m_2\) satisfying the following relationship should be computationally infeasible:

\[
H(m_1)=H(m_2)
\]

This property is important when a trusted digest has already been recorded for a particular artifact.

### 2.3 Collision resistance

Collision resistance concerns finding any two distinct inputs that produce the same digest:

\[
m_1 \ne m_2
\]

\[
H(m_1)=H(m_2)
\]

An attacker is free to choose both inputs. This differs from second-preimage resistance, where one original input is already fixed.

Collision resistance is essential for digital signatures, software distribution, document fingerprinting and other systems that rely on cryptographic digests.

## 3. SHA-2

SHA-2 is a family of cryptographic hash algorithms standardized in the Secure Hash Standard.

This project implements SHA-256 and SHA-512 through standard cryptographic libraries in Python, JavaScript and Java. The C++ implementation directly implements SHA-256.

| Property | SHA-256 | SHA-512 |
|---|---:|---:|
| Digest length | 256 bits | 512 bits |
| Digest bytes | 32 | 64 |
| Block size | 512 bits | 1024 bits |
| Internal word size | 32 bits | 64 bits |
| Main construction | Merkle-Damgård | Merkle-Damgård |

### 3.1 SHA-256 processing

SHA-256 processes input through the following stages:

1. Convert the input into a bit sequence.
2. Append a single one bit.
3. Append zero bits until the message length satisfies the block-padding requirement.
4. Append the original message length as a 64-bit value.
5. Divide the padded message into 512-bit blocks.
6. Expand each block into a message schedule.
7. Apply 64 compression rounds.
8. Combine the working variables with the current hash state.
9. Produce eight 32-bit output words.

The message schedule uses bitwise rotations, shifts and modular addition. The compression process applies logical functions such as choice and majority.

The C++ implementation makes these operations visible through the SHA-256 compression function and its 64 round constants.

### 3.2 SHA-512

SHA-512 follows a similar high-level construction but uses:

- 1024-bit message blocks.
- 64-bit working words.
- 80 compression rounds.
- A 512-bit final digest.

SHA-512 produces twice as many digest bits as SHA-256. Its larger internal state and digest length change the security and performance characteristics.

## 4. SHA-3

SHA-3 is a separate cryptographic hash family based on the Keccak sponge construction.

SHA-3 is not simply a later version of SHA-2. Its internal construction is fundamentally different.

| Property | SHA-2 | SHA-3 |
|---|---|---|
| Construction | Merkle-Damgård-based compression | Sponge construction |
| Core mechanism | Iterative compression function | Keccak permutation |
| Primary processing | Message blocks and chaining state | Absorption and squeezing |
| Digest examples | SHA-256, SHA-512 | SHA3-256, SHA3-512 |

### 4.1 Sponge construction

The sponge construction maintains an internal state divided conceptually into two regions:

- **Rate:** the portion used to absorb message data and produce output.
- **Capacity:** the remaining state used to provide security strength.

Its processing occurs in two stages.

**Absorbing**

The input is padded and divided into blocks. Each block is combined with the rate portion of the internal state. The Keccak permutation transforms the complete state after each block.

**Squeezing**

The function extracts output bytes from the transformed state. Additional permutations are performed when a requested output requires more data than the rate provides.

### 4.2 SHA3-256 parameters

SHA3-256 uses:

| Parameter | Value |
|---|---:|
| Internal state | 1600 bits |
| Rate | 1088 bits |
| Capacity | 512 bits |
| Output | 256 bits |
| Rate bytes | 136 |

The Keccak-f[1600] permutation performs 24 rounds. Each round includes five transformations:

- Theta
- Rho
- Pi
- Chi
- Iota

The C++ implementation explicitly represents the 25 lanes of the 1600-bit state and applies these transformations.

SHA3-256 and SHA-256 both produce 256-bit digests, but they do not produce interchangeable outputs. They use different constructions and padding rules.

## 5. Collision resistance and security strength

An ideal \(n\)-bit cryptographic hash has a digest space containing:

\[
2^n
\]

possible outputs.

For a generic preimage search, the approximate work factor is:

\[
2^n
\]

For a generic collision search, the birthday bound gives an approximate work factor of:

\[
2^{n/2}
\]

This distinction has important implications.

| Algorithm | Digest size | Generic collision work factor |
|---|---:|---:|
| SHA-256 | 256 bits | Approximately \(2^{128}\) |
| SHA-512 | 512 bits | Approximately \(2^{256}\) |
| SHA3-256 | 256 bits | Approximately \(2^{128}\) |
| SHA3-512 | 512 bits | Approximately \(2^{256}\) |

These values describe generic theoretical attack complexity under idealized assumptions. They do not prove that every implementation or deployment has the same effective security.

An algorithm may have a large digest while still being unsuitable if it contains known cryptographic weaknesses, is incorrectly implemented or is used in an insecure workflow.

This project does not attempt to create an actual collision. Instead, it validates known test vectors and demonstrates that modifying an artifact changes its digest.

## 6. Integrity verification

Integrity verification compares a newly calculated digest with a previously trusted digest.

Let:

\[
d_e = \text{Expected digest}
\]

\[
d_o = \text{Observed digest}
\]

The verification decision is:

\[
\text{Integrity}(m)=
\begin{cases}
\text{PASS} & d_e=d_o \\
\text{FAIL} & d_e\ne d_o
\end{cases}
\]

A practical verification workflow has four requirements:

1. The artifact must be read consistently.
2. The same approved algorithm must be used during registration and verification.
3. The expected digest must come from a trusted record.
4. The comparison must reject malformed or incorrectly sized digest values.

### 6.1 File hashing

Large files should be processed incrementally rather than loaded entirely into memory.

The Python, JavaScript and Java implementations use streaming or fixed-size buffers.

For a file of size \(N\) and a processing buffer of size \(B\):

- Hashing time is approximately \(O(N)\).
- Additional buffer memory is \(O(B)\).
- The digest state remains fixed in size for the selected algorithm.

The C++ implementation uses an in-memory byte vector for clarity. This is appropriate for learning and moderate test inputs but is not a streaming implementation for very large files.

### 6.2 Integrity manifests

An integrity manifest records metadata needed to verify an artifact later.

The Python implementation defines an immutable manifest containing:

| Field | Purpose |
|---|---|
| `file_name` | Identifies the artifact |
| `algorithm` | Identifies the digest algorithm |
| `digest` | Records the expected hexadecimal digest |
| `byte_count` | Records the original file length |
| `created_at` | Records when the manifest was created |

The manifest can be serialized to JSON and loaded again. Its fields and digest format are validated before verification.

A manifest is useful only when its expected digest is protected. An attacker who can replace both an artifact and its manifest may be able to make a modified artifact appear valid.

A manifest distributed with an artifact through the same untrusted channel does not provide independent protection.

## 7. HMAC and authenticated integrity

An ordinary hash does not require a secret key.

An attacker who can modify a file may also calculate a new ordinary digest. Consequently, an unkeyed digest alone does not authenticate the source of the file.

HMAC addresses this limitation by combining a cryptographic hash function with a secret key.

For a hash function \(H\), a key \(K\), and a message \(m\):

\[
\operatorname{HMAC}(K,m)
=
H\left(
(K' \oplus opad)
\parallel
H((K' \oplus ipad)\parallel m)
\right)
\]

Where:

- \(K'\) is the key processed to the hash block size.
- \(ipad\) is the inner padding value.
- \(opad\) is the outer padding value.
- \(\oplus\) represents XOR.
- \(\parallel\) represents concatenation.

The implementations include HMAC-SHA-256.

| Mechanism | Uses secret key | Primary purpose |
|---|---|---|
| SHA-256 | No | Digest calculation |
| SHA3-256 | No | Digest calculation |
| HMAC-SHA-256 | Yes | Keyed message authentication |

HMAC verification requires the correct secret key. The key must be protected independently from the message and its digest.

The Python, JavaScript and Java implementations reject HMAC keys shorter than 32 bytes as an application-level policy. The C++ and PostgreSQL examples apply the same minimum-length rule.

This rule is an implementation policy, not a universal requirement of the HMAC construction.

The PostgreSQL function accepts a caller-provided key and does not create a key-storage table. Production systems should retrieve secrets from an approved secrets-management system.

## 8. Python implementation

The Python file uses the `hashlib` and `hmac` standard-library modules.

### Main components

| Component | Responsibility |
|---|---|
| `HashAlgorithm` | Defines the supported SHA-2 and SHA-3 algorithms |
| `HashResult` | Stores digest metadata |
| `IntegrityManifest` | Serializes and validates file integrity metadata |
| `hash_bytes()` | Hashes an in-memory byte sequence |
| `hash_stream()` | Hashes a binary stream incrementally |
| `hash_file()` | Calculates a file digest |
| `verify_bytes()` | Verifies an in-memory input |
| `verify_file()` | Verifies a file against an expected digest |
| `create_hmac()` | Calculates a keyed authentication value |
| `verify_hmac()` | Verifies an HMAC |
| `run_self_tests()` | Executes known-answer and integrity tests |

### Implementation decisions

The `HashAlgorithm` enum prevents arbitrary algorithm names from entering the public interface.

`validate_digest()` checks hexadecimal representation and the required output length before comparison.

`hash_stream()` processes the input in fixed-size chunks. Its memory use does not increase proportionally with file size.

The HMAC implementation uses `hmac.new()` and applies a minimum key-length policy.

The manifest uses a temporary file followed by replacement, reducing the risk of leaving a partially written manifest after a normal file-write failure.

### Executable examples

- Running the script without arguments executes its demonstration and tests.
- The `hash` command calculates a selected file digest.
- The `verify` command compares a selected file against a supplied digest.
- A failed verification returns a nonzero process exit code.

The implementation also tests the empty-input and `abc` test vectors for SHA-256 and SHA3-256.

## 9. JavaScript implementation

The JavaScript file uses Node.js built-in modules.

### Main components

| Component | Responsibility |
|---|---|
| `ALGORITHMS` | Defines supported algorithms and digest lengths |
| `normalizeAlgorithm()` | Validates algorithm selection |
| `hashBuffer()` | Hashes an in-memory Buffer |
| `hashFile()` | Hashes a file asynchronously |
| `validateDigest()` | Validates digest syntax and length |
| `verifyFile()` | Compares a file digest against an expected value |
| `createHmac()` | Produces an HMAC |
| `IntegrityMonitor` | Maintains registered manifests and verification events |

### Event-driven monitoring

`IntegrityMonitor` extends Node.js `EventEmitter`.

It emits three events:

| Event | Meaning |
|---|---|
| `registered` | A new artifact manifest was created |
| `verified` | The current artifact matches the registered value |
| `mismatch` | The current artifact does not match the registered value |

This separates digest computation from the application logic that reacts to verification results.

The manifest registry uses a `Map` keyed by UUID. Registered manifests are immutable objects.

The asynchronous file-hashing function reads data through a stream and propagates filesystem errors through its returned promise.

`crypto.timingSafeEqual()` compares equal-length digest buffers. The implementation checks and validates their lengths before using the function.

### Demonstration workflow

The program:

1. Runs known-answer tests.
2. Calculates SHA-2 and SHA-3 digests.
3. Creates a temporary release artifact.
4. Registers an integrity manifest.
5. Verifies the unchanged file.
6. Modifies the file.
7. Verifies it again and emits a mismatch event.
8. Demonstrates HMAC generation and verification.
9. Removes the temporary files.

## 10. C++17 implementation

The C++ file provides a low-level implementation of SHA-256, SHA3-256 and HMAC-SHA-256 without external libraries.

### SHA-256 components

The implementation uses:

- Fixed-width unsigned integer types.
- The 64 SHA-256 round constants.
- Message padding and length encoding.
- A 64-word message schedule.
- Eight working state variables.
- Bitwise rotation, choice and majority functions.
- Modular 32-bit arithmetic.

Unsigned integer operations provide the wraparound behavior required by SHA-256.

The implementation converts words to big-endian output bytes.

### SHA3-256 components

The SHA3-256 implementation uses:

- A 1600-bit Keccak state.
- Twenty-five 64-bit lanes.
- A 136-byte rate.
- A 512-bit capacity.
- SHA-3 domain-separation padding.
- Twenty-four Keccak-f[1600] rounds.

The permutation explicitly applies Theta, Rho, Pi, Chi and Iota.

The implementation absorbs each message block into the state using little-endian lane representation and then extracts the first 32 output bytes.

### HMAC-SHA-256

The HMAC function:

1. Validates the minimum key length.
2. Hashes keys longer than the SHA-256 block size.
3. Pads the processed key to 64 bytes.
4. Calculates the inner digest.
5. Calculates the outer digest.
6. Returns the resulting authentication tag.

The demonstration compares the generated HMAC against the same data and key, then tests a modified message.

### Design limitations

The C++ program retains input data in a byte vector. Its memory use therefore grows with input size.

The implementation is designed to expose algorithm mechanics rather than replace a maintained cryptographic library. It does not claim to provide hardened constant-time processing, formal verification, side-channel protection or a production-grade cryptographic API.

For production software, a maintained cryptographic library should normally be preferred.

## 11. Java 17 enterprise implementation

The Java file models release-artifact registration and verification.

It uses the Java Cryptography Architecture (JCA) and `MessageDigest` rather than implementing the algorithms manually.

### Domain model

| Type | Responsibility |
|---|---|
| `HashAlgorithm` | Identifies approved SHA-2 and SHA-3 algorithms |
| `DigestResult` | Represents a calculated digest |
| `ArtifactManifest` | Records trusted release metadata |
| `VerificationResult` | Captures the outcome of a verification |
| `VerificationStatus` | Defines match, mismatch and missing-manifest states |
| `DigestPolicy` | Enforces approved algorithm selection |
| `DigestEngine` | Calculates and verifies digests |
| `ArtifactCatalog` | Registers and retrieves artifacts |
| `IntegrityVerificationService` | Evaluates integrity and records audit results |

### Algorithm policy

The default policy permits SHA-256, SHA-512, SHA3-256 and SHA3-512.

The design centralizes algorithm eligibility in `DigestPolicy`. This prevents separate application services from independently introducing unsupported algorithms.

### Immutable release manifests

`ArtifactManifest` is a Java record.

It captures:

- Artifact identifier.
- File name.
- Algorithm.
- Expected digest.
- Original byte count.
- Registration timestamp.
- Revision number.

Immutable records reduce accidental modification of registered integrity metadata.

### Concurrent registry and audit records

`ArtifactCatalog` uses `ConcurrentHashMap` for concurrent manifest access.

The revision counter uses `AtomicLong`.

`IntegrityVerificationService` maintains verification outcomes using a concurrent queue. The audit entries distinguish successful verification, changed content and missing registration.

The service calculates the current digest from the file rather than trusting metadata supplied by the requesting caller.

### Failure states

| Condition | Verification result |
|---|---|
| Current bytes match the manifest | `MATCH` |
| Digest or file size differs | `MISMATCH` |
| Artifact identifier is unknown | `MANIFEST_NOT_FOUND` |
| File cannot be read | IOException |
| Algorithm is not approved | Hashing exception |
| Malformed digest | Illegal argument exception |

## 12. PostgreSQL implementation

The PostgreSQL file models artifact integrity as a relational workflow.

It uses the `pgcrypto` extension for cryptographic operations.

### Relational structure

algorithm_policy
    |
    v
artifact
    |
    v
artifact_version
    |
    +---- content
    |
    +---- algorithm_name
    |
    +---- content_digest
    |
    v
verification_event

The main tables are:

| Table | Purpose |
|---|---|
| `algorithm_policy` | Defines approved digest algorithms |
| `artifact` | Stores artifact ownership and classification |
| `artifact_version` | Stores versioned content and calculated digests |
| `verification_event` | Records integrity verification outcomes |

### Algorithm policy table

The `algorithm_policy` table restricts the supported algorithms to SHA-256, SHA-512, SHA3-256 and SHA3-512.

The policy includes:

- Algorithm family.
- Output length.
- Enabled status.
- Approval status.

The `calculate_digest()` function uses this table before invoking the underlying `pgcrypto` digest function.

This provides a central database-level algorithm policy rather than allowing application queries to select arbitrary digest names.

### Digest trigger

A `BEFORE INSERT OR UPDATE` trigger calculates the digest from the supplied content.

The trigger also sets the byte count using `octet_length()`.

This makes the database-calculated digest the authoritative value for a newly inserted or updated artifact version. A caller cannot insert an arbitrary digest value and have it retained by the trigger.

### Verification function

`verify_artifact_version()` accepts:

- A registered version identifier.
- Candidate content.
- The identity of the verifier.

It retrieves the registered version, calculates a digest over the candidate content and compares it with the stored digest.

Three outcomes are recorded:

| Status | Meaning |
|---|---|
| `MATCH` | Candidate content matches the registered version |
| `MISMATCH` | Candidate digest differs |
| `SIZE_MISMATCH` | Candidate byte count differs |

Every completed comparison inserts a row into `verification_event`.

The function obtains a shared lock on the target version while reading the registered values, keeping the verification operation consistent with concurrent database activity.

### Reporting and evaluation

The schema provides two reporting views.

`v_artifact_integrity` exposes registered artifact versions, algorithms, digest values and byte counts.

`v_latest_verification` returns the latest verification event for each version.

The example queries demonstrate:

- Artifact and version retrieval.
- Latest verification retrieval.
- Verification aggregation by algorithm and outcome.
- Identification of versions without a successful latest verification.
- CTE-based compliance reporting.
- Algorithm eligibility evaluation.
- Recalculation of stored digests.
- HMAC generation with a caller-provided key.

The script uses transaction boundaries around its sample verification workflow. If any statement in that transaction fails, the transaction can be rolled back rather than leaving only part of the sample workflow committed.

## 13. Digest comparison and secure implementation rules

A digest comparison must operate on validated values.

The source files reject malformed hexadecimal input and incorrect digest lengths. Python uses `hmac.compare_digest()`, JavaScript uses `crypto.timingSafeEqual()` and Java uses `MessageDigest.isEqual()`.

The C++ example includes a fixed-length byte comparison, but it is not a substitute for a vetted cryptographic library's hardened comparison primitive.

The PostgreSQL example compares digest values used for integrity records. It does not use an ordinary digest comparison to authenticate secrets.

### Important security boundaries

**A hash is not encryption.**

Hashing does not provide a reversible transformation. It does not conceal the original content in the same way that encryption does.

**A hash is not a digital signature.**

A digest alone does not establish the identity of its creator. Digital signatures require an asymmetric signing and verification mechanism.

**A hash is not automatically authentication.**

An attacker who can replace both a file and its expected digest may be able to create a consistent but unauthorized pair. HMAC or digital signatures can provide authentication when implemented with appropriate key management.

**A hash is not password storage.**

Fast general-purpose hash functions such as SHA-256 and SHA3-256 are not appropriate for password storage. Password authentication should use a dedicated password-hashing scheme with salts and configurable work factors.

**A successful digest comparison is not proof of benign content.**

A verified file may still contain malware, unsafe configuration or incorrect application behavior. Integrity verification establishes correspondence with trusted bytes, not whether those bytes are safe.

## 14. Performance and operational considerations

| Factor | Engineering consideration |
|---|---|
| File size | Use streaming and fixed-size buffers |
| Digest size | Larger output increases metadata size |
| Algorithm choice | Use an approved SHA-2 or SHA-3 variant |
| CPU utilization | Hashing requires processing the complete input |
| Concurrent verification | Avoid shared mutable digest state |
| Storage | Store algorithm identifiers with digest values |
| Metadata integrity | Protect manifests and expected digests |
| HMAC | Protect and rotate keys independently |
| Failure handling | Record mismatches and filesystem errors distinctly |
| Reproducibility | Validate known-answer test vectors |
| Database performance | Index version identifiers, algorithms and verification timestamps |

Hash calculation has linear time complexity with respect to input length:

\[
T(N)=O(N)
\]

For a streaming implementation, temporary memory is bounded by the buffer size:

\[
M(N)=O(B)
\]

Where \(B\) is the configured buffer size.

For an implementation that holds the complete input in memory:

\[
M(N)=O(N)
\]

The C++ example uses the second approach, while the Python, JavaScript and Java file-processing implementations use bounded-buffer processing.

## 15. Validation scenarios

The source files exercise the following cases:

| Scenario | Expected behavior |
|---|---|
| Hash empty input | Produce the algorithm's defined empty-input digest |
| Hash the same content twice | Produce the same digest |
| Hash different content | Produce a different digest in normal operation |
| Verify unchanged content | Pass |
| Verify modified content | Fail |
| Verify a file with a different size | Fail |
| Supply malformed hexadecimal | Reject the input |
| Supply a digest of incorrect length | Reject the input |
| Request an unsupported algorithm | Reject the request |
| Use a short HMAC key | Reject the request |
| Verify with the correct HMAC key | Pass |
| Verify with modified content | Fail |
| Verify an unknown artifact identifier | Return a missing-record state |
| Read an unavailable file | Report an I/O error |
| Recalculate a database digest | Match the stored digest when content is unchanged |

Known-answer testing is important because two incorrect implementations can sometimes agree with each other while producing incorrect digests.

The empty-input and `abc` test vectors provide independent reference values for SHA-256 and SHA3-256. The C++, Python and JavaScript implementations also test HMAC or integrity-verification behavior.

## 16. Cross-language implementation comparison

| Technical concern | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| SHA-256 | `hashlib` | `crypto` | Direct implementation | JCA | `pgcrypto` |
| SHA-512 | `hashlib` | `crypto` | Not included | JCA | `pgcrypto` |
| SHA3-256 | `hashlib` | `crypto` | Direct implementation | JCA | `pgcrypto` |
| SHA3-512 | `hashlib` | `crypto` | Not included | JCA | `pgcrypto` |
| HMAC-SHA-256 | `hmac` | `createHmac` | Direct implementation | JCA `Mac` | `pgcrypto` |
| File processing | Binary streams | Asynchronous streams | In-memory byte vector | Buffered streams | Stored `BYTEA` content |
| Manifest model | Dataclass | Immutable object | Struct | Java record | Relational tables |
| Verification history | Function results | Event-driven monitor | Demonstration output | Concurrent audit queue | Verification table |
| Policy enforcement | Enum validation | Algorithm registry | Input validation | Policy object | Database policy table |

The implementations demonstrate that the same integrity objective can be addressed at different system layers. A general-purpose script can calculate and compare digests, an event-driven service can monitor release artifacts, a low-level implementation can expose cryptographic transformations, an enterprise service can enforce registration and audit rules, and a relational database can preserve integrity metadata and verification history.

The core security requirement remains consistent across all five implementations: a digest is useful only when the algorithm is appropriate, the calculation is correct and the expected value is obtained from a trusted source.
