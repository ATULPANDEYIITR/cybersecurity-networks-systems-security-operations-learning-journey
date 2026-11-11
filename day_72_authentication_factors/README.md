# Authentication Factors and Adaptive Authentication

## 1. Project Scope

This project implements an enterprise authentication model covering five connected technical areas:

- Password-based authentication.
- Multi-factor authentication (MFA).
- Hardware security tokens.
- Biometric authentication.
- Risk-based adaptive authentication.

The implementations demonstrate credential management, factor enrollment, verification evidence, authentication policy evaluation, account lockout, risk scoring, session creation and audit reporting.

The five source files use different engineering approaches:

| File | Engineering perspective | Main implementation |
|---|---|---|
| Python | Authentication workflow simulation | Credential management, TOTP, risk evaluation and testing |
| JavaScript | Event-driven authentication | Asynchronous credential operations, events and policy evaluation |
| C++17 | Authentication decision engine | Domain modeling, factor evidence and merge-like policy evaluation |
| Java 17 | Enterprise authentication services | Immutable records, interfaces, policy objects and state transitions |
| PostgreSQL | Relational authentication governance | Credential records, factor enrollment, policies, sessions and reporting |

The implementations are independent examples. They do not share an authentication server or database.

---

## 2. Authentication Fundamentals

Authentication establishes whether an entity is the person or system it claims to be.

The three fundamental authentication-factor categories are:

| Category | Meaning | Examples |
|---|---|---|
| Knowledge | Something the user knows | Password, PIN |
| Possession | Something the user has | Security key, authenticator device |
| Inherence | Something the user is | Fingerprint, facial biometric |

Two credentials do not automatically constitute MFA.

For example:

- Password plus PIN: two knowledge factors.
- Password plus TOTP: knowledge and possession.
- Password plus hardware security key: knowledge and possession.
- Password plus biometric verification: knowledge and inherence.

MFA requires independent factors from different categories.

The independence of factors matters because compromising one category should not automatically compromise the other.

### Authentication workflow

    User
      |
      v
    Submit identity and password
      |
      v
    Verify password credential
      |
      v
    Evaluate login context
      |
      v
    Determine required factors
      |
      v
    Verify additional factors
      |
      v
    Evaluate authentication result
      |
      +---- Rejected
      |
      +---- Additional verification required
      |
      +---- Successful authentication
                    |
                    v
                Issue session
                    |
                    v
                Record audit event

Authentication and authorization are separate.

Authentication verifies identity. Authorization determines which resources and operations that identity can access.

---

## 3. Password Authentication

### 3.1 Password storage

A password should never be stored as plaintext or encrypted using a reversible application-level encryption scheme merely to support login verification.

Instead, password storage uses a password-hashing algorithm.

The implementations demonstrate:

- Random salt generation.
- Password derivation.
- Credential verification.
- Constant-time comparison where supported.
- Password-length validation.
- Failed-attempt tracking.
- Account lockout.

A password credential consists of:

| Field | Purpose |
|---|---|
| Salt | Makes identical passwords produce different derived values |
| Password hash | Stores the derived password representation |
| Algorithm | Identifies the hashing mechanism |
| Failure count | Tracks unsuccessful verification attempts |
| Lock expiration | Controls temporary account lockout |

### 3.2 Password-hashing algorithms

| Algorithm | Characteristics |
|---|---|
| Argon2id | Memory-hard password hashing |
| scrypt | Memory-hard password hashing |
| PBKDF2 | Iterated password-based key derivation |

The Python implementation uses `hashlib.scrypt`.

The JavaScript implementation uses Node.js `crypto.scrypt`.

The Java implementation uses `PBKDF2WithHmacSHA256`.

The C++ example uses a deliberately simplified demonstration digest. It is not suitable for real credential storage because `std::hash` is not a password-hashing algorithm and does not provide a cryptographic security guarantee.

The PostgreSQL implementation stores encoded credential metadata but delegates actual password hashing to the application service.

### 3.3 Password security considerations

A production password service should implement:

- Unique cryptographically random salts.
- Appropriate memory and computational costs.
- Secure password reset procedures.
- Rate limiting.
- Credential-stuffing detection.
- Password breach screening.
- Secure credential transport.
- Protection against account enumeration.

Account lockout must be designed carefully. Permanent lockout after repeated failures can create a denial-of-service opportunity.

Temporary lockouts, progressive delays, IP-level rate limiting and risk-based controls provide more flexible protection.

---

## 4. Multi-Factor Authentication

MFA combines independently verifiable authentication factors.

The project models four factor types:

| Factor | Category | Verification mechanism |
|---|---|---|
| Password | Knowledge | Password hash verification |
| TOTP | Possession | Time-based one-time password |
| Hardware token | Possession | Challenge-response assertion |
| Biometric | Inherence | Trusted platform verification result |

### 4.1 Factor enrollment

Enrollment associates an authentication factor with a user account.

A typical enrollment workflow is:

1. Authenticate the existing account.
2. Register the additional factor.
3. Generate or establish factor-specific credentials.
4. Verify control of the factor.
5. Mark enrollment as verified.
6. Record the enrollment event.

Pending enrollment must not be treated as successful factor registration.

A revoked factor must not be accepted during authentication.

### 4.2 Factor verification

Each factor has a separate verification mechanism.

The authentication service should not treat a client-provided statement that a factor was verified as sufficient evidence without validating its authenticity.

The Java implementation demonstrates this separation through the `FactorVerifier` interface.

The Python implementation separates verification into dedicated service classes.

The JavaScript implementation uses individual factor managers.

The C++ implementation uses `FactorEvidence` and a policy engine.

The PostgreSQL implementation stores factor enrollment and verification states independently.

### 4.3 Authentication states

| State | Meaning |
|---|---|
| SUCCESS | Required factors were verified |
| REJECTED | Authentication evidence was invalid |
| MFA_REQUIRED | Additional MFA verification is required |
| STEP_UP_REQUIRED | Stronger authentication is required |
| LOCKED | Account access is temporarily blocked |
| DISABLED | Account cannot authenticate |
| EXPIRED | Relevant credential or session has expired |

A missing factor and an invalid factor are different operational conditions.

A missing factor may require an additional authentication challenge. Invalid evidence should result in rejection of that factor verification.

---

## 5. Time-Based One-Time Passwords

TOTP is a time-based extension of the HMAC-based one-time password mechanism.

It generates short-lived verification codes using a shared secret and a time counter.

The general relationship is:

    T = floor(Current Unix Time / Time Step)

    OTP = HOTP(Secret, T)

The project uses:

| Parameter | Demonstration setting |
|---|---|
| Algorithm | HMAC-SHA1 |
| Code length | 6 digits |
| Time step | 30 seconds |
| Clock-skew window | One interval before or after |

### 5.1 TOTP verification

The verifier calculates the expected code for the current time interval and a limited clock-skew window.

It compares the calculated value with the submitted value.

The verifier must reject:

- Incorrect code lengths.
- Non-numeric codes.
- Expired codes outside the accepted window.
- Incorrect secrets.
- Replayed authentication codes.

### 5.2 Replay protection

A valid TOTP code should not be accepted repeatedly for the same time counter where replay prevention is required.

The PostgreSQL schema includes `last_accepted_counter` in `totp_credentials`.

A production implementation should update this value atomically, ensuring that simultaneous authentication requests cannot both accept the same counter.

The demonstration implementations focus on generation and verification rather than a complete distributed replay-prevention service.

TOTP secrets must be encrypted at rest and protected against unauthorized access.

---

## 6. Hardware Security Tokens

Hardware tokens provide possession-based authentication.

FIDO2 and WebAuthn are important standards for phishing-resistant authentication.

### 6.1 Challenge-response authentication

A typical hardware-token workflow is:

    Server creates random challenge
              |
              v
    Client requests authenticator assertion
              |
              v
    Authenticator signs challenge
              |
              v
    Server verifies public-key signature
              |
              v
    Server validates origin and RP ID
              |
              v
    Server checks challenge and user presence
              |
              v
    Authentication decision

The server must verify:

- Challenge freshness.
- Challenge association with the authentication request.
- Cryptographic signature.
- Registered credential identifier.
- Expected relying-party identifier.
- Expected origin.
- User-presence requirements.
- User-verification requirements when required.
- Authenticator counter or other applicable credential-state information.

### 6.2 Public-key authentication

The PostgreSQL `hardware_tokens` table stores:

- Credential identifier.
- Public key.
- Relying-party identifier.
- Signature counter.
- Authenticator type.

The private key remains with the authenticator.

The Python and JavaScript implementations include HMAC-based challenge-response demonstrations to illustrate possession verification.

These demonstrations are not complete FIDO2 implementations.

The production design should use a maintained WebAuthn implementation with public-key signature verification.

### 6.3 Security advantages

Hardware-backed authentication can reduce exposure to:

- Phishing.
- Password reuse.
- Credential interception.
- Unauthorized authentication from unregistered devices.

Hardware authentication still requires careful credential enrollment, revocation and account recovery procedures.

---

## 7. Biometric Authentication

Biometric authentication evaluates physical or behavioral characteristics.

Common examples include:

- Fingerprint recognition.
- Facial recognition.
- Iris recognition.
- Voice recognition.

Biometric information differs from a password because it cannot generally be replaced in the same way after compromise.

### 7.1 Local biometric verification

The preferred architecture delegates biometric matching to a trusted operating-system or hardware security component.

The application receives an authenticated verification result instead of collecting raw biometric data.

The project models three conditions:

| Condition | Purpose |
|---|---|
| Verified | The biometric operation succeeded |
| User present | The user participated in the authentication |
| Trusted platform | The verification originated from an accepted platform |

All required conditions must be satisfied.

### 7.2 Biometric privacy

The database implementation deliberately avoids storing fingerprint images, facial images or biometric templates.

It records:

- Platform identity.
- Device reference.
- Attestation status.
- User-verification capability.
- Enrollment timestamp.

A platform assertion must be cryptographically and contextually validated before being accepted.

A boolean field supplied directly by an untrusted client is not adequate biometric authentication evidence.

### 7.3 Limitations

Biometric authentication can be affected by:

- False acceptance.
- False rejection.
- Environmental conditions.
- Sensor quality.
- Presentation attacks.
- Device compromise.
- Enrollment integrity.

Biometrics should be combined with secure device authentication and appropriate recovery procedures.

---

## 8. Adaptive Authentication

Adaptive authentication adjusts authentication requirements according to contextual risk.

Traditional authentication applies a relatively fixed factor policy.

Adaptive authentication evaluates contextual signals before determining whether additional verification is necessary.

### 8.1 Risk indicators

The implementations use four signals:

| Signal | Weight | Interpretation |
|---|---:|---|
| New device | 25 | Device has not been recognized |
| Impossible travel | 55 | Location history indicates suspicious travel |
| Unusual time | 15 | Login occurs outside expected patterns |
| Sensitive action | 20 | Requested operation requires stronger assurance |

The demonstration calculates:

    Risk Score =
        New Device Weight
        + Impossible Travel Weight
        + Unusual Time Weight
        + Sensitive Action Weight

The score is mapped to a risk level.

| Score | Risk level |
|---:|---|
| 0–19 | Low |
| 20–44 | Medium |
| 45–69 | High |
| 70 and above | Critical |

### 8.2 Adaptive policy behavior

The implemented policy follows these rules:

- Password authentication is mandatory.
- TOTP is required when registered.
- High or critical risk requires an additional hardware-token or biometric factor when available.
- Hardware tokens receive priority over biometrics in the demonstrated elevated-risk policy.
- Sensitive operations require biometric verification when that factor is registered.
- Missing or invalid additional evidence prevents successful authentication.

### 8.3 Example scenarios

| Scenario | Score | Risk | Expected behavior |
|---|---:|---|---|
| Recognized device | 0 | Low | Standard authentication |
| New device | 25 | Medium | Enhanced monitoring |
| Unusual time | 15 | Low | Standard authentication |
| New device and unusual time | 40 | Medium | Enhanced monitoring |
| Impossible travel | 55 | High | Additional factor |
| New device and impossible travel | 80 | Critical | Strong step-up authentication |
| Sensitive action | 20 | Medium | Additional biometric verification if registered |

The weights are illustrative policy values, not universal security thresholds.

A production risk engine should account for signal reliability, historical behavior, false positives, false negatives and the impact of the protected operation.

### 8.4 Risk-based authentication architecture

    Authentication Request
             |
             v
       Context Collection
             |
             v
        Risk Engine
             |
             v
       Policy Evaluation
             |
       +-----+------+
       |            |
    Standard      Step-up
    Factors       Factors
       |            |
       +-----+------+
             |
             v
       Authentication
          Decision
             |
       +-----+------+
       |            |
    Rejected      Success
                    |
                    v
               Session Issue

Risk assessment is not equivalent to factor verification.

A low-risk score does not prove identity. It determines which authentication requirements should apply.

---

## 9. Authentication Policy and Factor Eligibility

Factor registration and factor eligibility are different concepts.

A registered factor may be:

- Pending verification.
- Verified.
- Failed.
- Revoked.

Only an eligible, verified and non-revoked factor should participate in authentication policy evaluation.

The PostgreSQL function `required_authentication_factors` calculates required factors from registered factor states and contextual risk.

The Java `AuthenticationPolicy` class provides an equivalent domain-level policy decision.

The Python and JavaScript implementations construct the required-factor list dynamically.

The C++ implementation separates the policy calculation from the authentication engine.

This separation allows factor requirements to change without rewriting individual verification mechanisms.

### Policy conflict examples

| Condition | Policy behavior |
|---|---|
| Password is missing | Reject registration |
| TOTP enrollment is pending | Do not count it as verified MFA |
| Hardware token is revoked | Reject its assertion |
| High risk without an additional factor | Do not grant authentication |
| Sensitive action without registered biometric | Do not claim biometric verification |
| Account is disabled | Reject authentication |
| Account is temporarily locked | Enforce lock expiration |

A production policy should explicitly define recovery behavior when users lose their registered authenticators.

---

## 10. Account Lockout and Failure Handling

Repeated unsuccessful authentication attempts can indicate credential attacks.

The implementations demonstrate a maximum of five consecutive password failures.

The Python and JavaScript implementations apply a five-minute temporary lockout.

The Java implementation models account states and lock expiration.

The C++ implementation demonstrates failure-count tracking and account lockout.

The database stores failure counts and lock expiration timestamps.

### Failure handling requirements

| Failure | Required response |
|---|---|
| Incorrect password | Reject authentication |
| Repeated incorrect passwords | Apply lockout or progressive delay |
| Missing TOTP | Request MFA |
| Incorrect TOTP | Reject factor verification |
| Invalid hardware assertion | Require a valid assertion |
| Untrusted biometric evidence | Reject verification |
| Unknown user | Return a generic authentication failure |
| Disabled account | Deny authentication |
| Expired session | Require reauthentication |

Production systems should also implement IP-based and account-based rate limits.

The authentication response should avoid exposing whether an account exists.

---

## 11. Session Management

Successful authentication can establish a session.

A session is not the same as an authentication attempt.

An authentication attempt records an identity-verification operation. A session represents an authenticated interaction period.

The PostgreSQL implementation models sessions through `authenticated_sessions`.

Important attributes include:

- User identity.
- Authentication attempt.
- Session token hash.
- Issue timestamp.
- Expiration timestamp.
- Revocation timestamp.

The session-creation trigger checks:

1. The authentication attempt exists.
2. The attempt was successful.
3. The user associated with the attempt matches the session user.
4. The user account is active.

### Session lifecycle

    Authentication Success
             |
             v
       Session Creation
             |
             v
       Active Session
             |
       +-----+------+
       |            |
    Expiration    Revocation
       |            |
       +-----+------+
             |
             v
       Reauthentication

Production session management should also support secure cookies, session rotation, CSRF protection where applicable, token revocation, concurrent-session policy and secure logout.

The database sample uses demonstration token hashes and should not be interpreted as a deployed session-management service.

---

## 12. Audit and Authentication Monitoring

Authentication auditing records security-relevant events.

The project records events such as:

- Account registration.
- Password failures.
- Unknown-user attempts.
- Authentication success.
- Risk assessments.
- Additional-factor requirements.
- Session issuance.

Sensitive credentials must never appear in audit logs.

The PostgreSQL implementation stores structured event details using `JSONB`.

Indexes support queries by user, timestamp and event type.

The Python implementation exports audit records as JSON.

The JavaScript implementation uses an event-driven audit logger.

The Java implementation maintains an audit service.

The C++ implementation uses a simple event collection.

### Useful monitoring indicators

| Indicator | Operational purpose |
|---|---|
| Failed login rate | Detect password attacks |
| MFA failure rate | Identify factor-related attacks |
| Lockout frequency | Detect suspicious activity |
| New-device authentication | Monitor device changes |
| High-risk authentication | Prioritize security investigation |
| Factor enrollment changes | Detect account takeover attempts |
| Session revocation | Monitor incident response |

Audit storage should be access-controlled, protected against modification and retained according to applicable organizational requirements.

---

## 13. PostgreSQL Relational Design

The database separates account identity, credentials, authentication factors, contextual evidence and session state.

### Entity relationships

    users
      |
      +---- password_credentials
      |
      +---- authentication_factors
      |          |
      |          +---- totp_credentials
      |          |
      |          +---- hardware_tokens
      |          |
      |          +---- biometric_credentials
      |
      +---- trusted_devices
      |
      +---- login_contexts
                 |
                 +---- risk_assessments
                 |
                 +---- authentication_attempts
                              |
                              +---- attempt_factors
                              |
                              +---- authenticated_sessions
                              |
                              +---- authentication_audit

### Database integrity

The SQL implementation includes:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enum types.
- Partial indexes.
- Reporting views.
- Risk calculation functions.
- Factor eligibility functions.
- Triggers.
- Transaction handling.

### Performance decisions

The database indexes support common access patterns:

- Factor lookup by user and verification state.
- Login history by user and timestamp.
- Failed authentication monitoring.
- Session expiration checks.
- Audit retrieval by user and event type.

Indexes should be selected according to actual query patterns and table size.

Excessive indexes increase write cost and storage requirements.

### Transaction integrity

Session creation is tied to a successful authentication attempt.

The trigger validates the attempt and account state before allowing session insertion.

The transaction demonstration uses a savepoint to isolate an expected failure without interrupting the complete SQL script.

---

## 14. Implementation Comparison

### Python

Python provides a modular simulation.

Its principal components are:

| Component | Responsibility |
|---|---|
| `PasswordService` | Password derivation and verification |
| `TOTPService` | Time-based code generation and verification |
| `HardwareTokenService` | Demonstration challenge-response |
| `BiometricService` | Trusted platform evidence validation |
| `AdaptiveRiskEngine` | Contextual risk calculation |
| `AuthenticationEngine` | Authentication workflow |
| `AuthenticationTests` | Functional verification |

Python demonstrates executable authentication logic using standard-library modules.

### JavaScript

JavaScript emphasizes asynchronous execution and event-driven operations.

The main components are:

- `PasswordManager`
- `TotpManager`
- `HardwareTokenManager`
- `BiometricManager`
- `AdaptiveRiskEngine`
- `AuditLogger`
- `AuthenticationService`

`EventEmitter` provides events for account registration and successful authentication.

`Map` stores user accounts, while `Set` represents registered factors.

Asynchronous password derivation prevents the service interface from assuming synchronous credential operations.

### C++17

C++ provides an explicit domain model.

The implementation separates:

- `User`
- `LoginContext`
- `FactorEvidence`
- `RiskAssessment`
- `AuthResult`
- `PasswordPolicy`
- `RiskEngine`
- `AuthenticationPolicy`
- `AuthenticationEngine`

STL containers represent registered users, factor sets and authentication evidence.

The program demonstrates validation, deterministic policy evaluation, state management and failure handling.

Its password digest is intentionally educational rather than production-safe.

### Java 17

Java emphasizes enterprise-oriented service boundaries.

The implementation uses:

- Records for immutable data.
- Enums for domain states.
- Interfaces for factor verification.
- Classes for credential and account management.
- `EnumSet` for registered factors.
- `Map` for user accounts and verifiers.
- Custom exceptions for authentication failures.
- `MessageDigest.isEqual` for credential comparison.

`AuthenticationPolicy` and `RiskEngine` isolate decision-making from account operations.

### PostgreSQL

PostgreSQL provides persistent relational modeling.

It handles:

- Account and credential relationships.
- Factor enrollment.
- Hardware-token registration.
- Biometric registration metadata.
- Login context.
- Risk assessment.
- Authentication attempts.
- Factor verification evidence.
- Sessions.
- Audit events.

The SQL implementation focuses on data integrity and reporting rather than implementing cryptographic verification inside the database.

---

## 15. Security Limitations and Production Considerations

The implementations are educational authentication models, not complete identity-provider products.

Important production requirements include:

| Area | Production requirement |
|---|---|
| Passwords | Argon2id or another maintained password-hashing implementation |
| TOTP | Encrypted secrets and replay prevention |
| Hardware tokens | Complete FIDO2/WebAuthn public-key verification |
| Biometrics | Trusted platform assertions and privacy protection |
| Adaptive risk | Calibrated risk models and monitored thresholds |
| Lockout | Distributed rate limiting and abuse-resistant recovery |
| Sessions | Secure token issuance, rotation and revocation |
| Auditing | Protected, append-only security records |
| Database | Least privilege, encryption and appropriate row-level controls |
| Recovery | Secure account recovery and authenticator replacement |
| Transport | TLS and secure credential transmission |
| Operations | Monitoring, incident response and security testing |

### Important implementation limitations

1. The Python and JavaScript hardware-token implementations use HMAC demonstration secrets rather than complete WebAuthn public-key verification.
2. The biometric implementations validate trusted verification evidence but do not perform fingerprint or facial matching.
3. The C++ password demonstration uses `std::hash` and must not be used for production password storage.
4. The Java implementation uses PBKDF2 with a fixed demonstration configuration that requires deployment-specific calibration.
5. The SQL sample includes non-authenticating demonstration password hashes and a demonstration session-token hash.
6. The adaptive risk model uses fixed weights and does not perform statistical anomaly detection.
7. The Python and JavaScript examples use in-memory user and audit collections.
8. The Java and C++ implementations use in-memory state rather than a distributed account store.
9. Production implementations require concurrency controls for lockouts, credential counters and replay prevention.
10. Authentication recovery must be secured independently from normal authentication.

---

## 16. Testing Scenarios

The source implementations include executable assertions and test scenarios.

The following cases define the expected behavior of the authentication model.

| Test case | Expected result |
|---|---|
| Valid password and valid required TOTP | Success |
| Incorrect password | Rejected |
| Missing TOTP | MFA required |
| Invalid hardware assertion | Step-up required |
| Untrusted biometric evidence | Step-up required |
| New device | Medium risk |
| Impossible travel | High risk |
| New device and impossible travel | Critical risk |
| Repeated password failures | Account locked |
| Pending factor enrollment | Not eligible for verified-factor policy |
| Revoked authenticator | Verification rejected |
| Disabled account | Authentication denied |
| Invalid session creation | Transaction rejected |

### Complexity considerations

Let:

- \(U\) represent the number of users.
- \(F\) represent the number of registered factors per user.
- \(A\) represent the number of authentication audit records.

| Operation | Expected complexity |
|---|---|
| In-memory username lookup | Average \(O(1)\) |
| Factor-set membership | Average \(O(1)\) |
| Policy evaluation | \(O(F)\) |
| Risk calculation | \(O(1)\) |
| TOTP generation | \(O(1)\) |
| Password verification | Depends on configured hashing cost |
| Indexed user retrieval | Approximately \(O(\log U)\) |
| Indexed audit retrieval | Depends on index selectivity and result count |

Password verification is intentionally computationally expensive. It should be protected by request rate limits and resource controls.

---

## 17. Practical Applications

The modeled authentication architecture is applicable to:

- Enterprise workforce identity systems.
- Banking and financial applications.
- Privileged administrator access.
- Cloud infrastructure access.
- Secure development environments.
- Remote workforce authentication.
- Sensitive transaction approval.
- Healthcare information systems.
- Government digital services.
- Device-based identity verification.

Different operations should receive different assurance requirements.

A routine read-only operation may require standard authentication.

A privileged administrative action may require phishing-resistant MFA and recent user verification.

A sensitive financial operation may require additional transaction-specific confirmation.

The authentication policy should reflect the security impact of the requested operation rather than treating every login as an identical event.

---

## 18. Execution

| Implementation | Execution |
|---|---|
| Python | `python authentication_factors.py` |
| JavaScript | `node authentication_factors.js` |
| C++17 | `g++ -std=c++17 -O2 authentication_factors.cpp -o authentication_factors` followed by `./authentication_factors` |
| Java 17 | `javac AuthenticationFactors.java` followed by `java AuthenticationFactors` |
| PostgreSQL | Execute the SQL file using `psql` against a PostgreSQL 15+ database |

The Python, JavaScript, C++17 and Java 17 programs use standard-library functionality.

The PostgreSQL implementation requires permission to create a schema, tables, functions, types, triggers and indexes. It also uses PostgreSQL's `pgcrypto` extension functionality through `gen_random_uuid()`.

The database script is designed for a dedicated learning database because it creates persistent schema objects.

---

## 19. Conceptual Distinctions

The following distinctions are central to understanding the complete authentication architecture.

| Concept | Primary responsibility |
|---|---|
| Password authentication | Verify knowledge of a secret |
| MFA | Combine independent authentication factors |
| TOTP | Verify possession through a time-based code |
| Hardware token | Verify possession through cryptographic authentication |
| Biometrics | Verify an inherence characteristic through a trusted platform |
| Adaptive authentication | Adjust authentication requirements according to contextual risk |
| Authentication policy | Determine which factors are required |
| Factor verification | Establish whether supplied factor evidence is valid |
| Authentication decision | Determine whether identity verification succeeded |
| Session management | Maintain and terminate authenticated access |
| Audit monitoring | Preserve and analyze authentication-related events |

These mechanisms address different security problems.

MFA increases authentication assurance through factor independence.

Hardware-backed authentication can improve resistance to phishing.

Biometric verification can provide convenient local user verification.

Adaptive authentication adjusts assurance requirements according to risk.

Session governance controls authenticated access after identity verification.

The complete model connects these mechanisms without treating them as interchangeable security controls.
