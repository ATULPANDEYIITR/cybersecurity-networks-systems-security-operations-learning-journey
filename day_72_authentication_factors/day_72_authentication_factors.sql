-- ============================================================
-- AUTHENTICATION FACTORS AND ADAPTIVE ACCESS GOVERNANCE
-- PostgreSQL 15+
--
-- Passwords, MFA, TOTP, Hardware Tokens, Biometrics,
-- Adaptive Authentication, Audit and Session Governance.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS auth;
SET search_path TO auth, public;

-- ------------------------------------------------------------
-- 1. DOMAIN TYPES
-- ------------------------------------------------------------

CREATE TYPE factor_type AS ENUM (
    'password',
    'totp',
    'hardware_token',
    'biometric'
);

CREATE TYPE credential_state AS ENUM (
    'active',
    'locked',
    'disabled',
    'expired'
);

CREATE TYPE risk_level AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE authentication_status AS ENUM (
    'success',
    'rejected',
    'mfa_required',
    'step_up_required',
    'locked',
    'expired'
);

CREATE TYPE verification_status AS ENUM (
    'pending',
    'verified',
    'failed',
    'revoked'
);

-- ------------------------------------------------------------
-- 2. USERS AND CREDENTIALS
-- ------------------------------------------------------------

CREATE TABLE users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    account_state credential_state NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ,
    CHECK (length(username) >= 3),
    CHECK (position('@' IN email) > 1)
);

CREATE TABLE password_credentials (
    credential_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE REFERENCES users(user_id)
        ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    hashing_algorithm VARCHAR(30) NOT NULL DEFAULT 'argon2id',
    password_version INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (failed_attempts >= 0),
    CHECK (password_version > 0),
    CHECK (hashing_algorithm IN ('argon2id', 'scrypt', 'pbkdf2'))
);

-- ------------------------------------------------------------
-- 3. REGISTERED AUTHENTICATION FACTORS
-- ------------------------------------------------------------

CREATE TABLE authentication_factors (
    factor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id)
        ON DELETE CASCADE,
    factor factor_type NOT NULL,
    factor_name VARCHAR(120) NOT NULL,
    verification verification_status NOT NULL DEFAULT 'pending',
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    UNIQUE (user_id, factor_id),
    UNIQUE (user_id, factor, factor_name),
    CHECK (
        (verification = 'verified' AND verified_at IS NOT NULL)
        OR verification <> 'verified'
    )
);

CREATE INDEX idx_factors_user_verified
ON authentication_factors(user_id, factor)
WHERE verification = 'verified';

-- ------------------------------------------------------------
-- 4. TOTP CONFIGURATION
-- ------------------------------------------------------------

CREATE TABLE totp_credentials (
    factor_id BIGINT PRIMARY KEY
        REFERENCES authentication_factors(factor_id)
        ON DELETE CASCADE,
    encrypted_secret BYTEA NOT NULL,
    algorithm VARCHAR(10) NOT NULL DEFAULT 'SHA1',
    digits SMALLINT NOT NULL DEFAULT 6,
    period_seconds SMALLINT NOT NULL DEFAULT 30,
    last_accepted_counter BIGINT NOT NULL DEFAULT -1,
    CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512')),
    CHECK (digits BETWEEN 6 AND 8),
    CHECK (period_seconds BETWEEN 15 AND 120)
);

-- Store an encrypted TOTP secret, never the plaintext secret.
-- Encryption and key management belong to the application/KMS layer.

-- ------------------------------------------------------------
-- 5. HARDWARE TOKENS
-- ------------------------------------------------------------

CREATE TABLE hardware_tokens (
    factor_id BIGINT PRIMARY KEY
        REFERENCES authentication_factors(factor_id)
        ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    relying_party_id VARCHAR(255) NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    authenticator_type VARCHAR(30) NOT NULL DEFAULT 'platform',
    backed_up BOOLEAN NOT NULL DEFAULT false,
    last_assertion_at TIMESTAMPTZ,
    CHECK (sign_count >= 0),
    CHECK (authenticator_type IN ('platform', 'cross_platform'))
);

-- Public keys are stored rather than private token secrets.
-- WebAuthn verification must validate the signature, origin,
-- RP ID, challenge, user presence and applicable user verification.

-- ------------------------------------------------------------
-- 6. BIOMETRIC CREDENTIALS
-- ------------------------------------------------------------

CREATE TABLE biometric_credentials (
    factor_id BIGINT PRIMARY KEY
        REFERENCES authentication_factors(factor_id)
        ON DELETE CASCADE,
    platform_name VARCHAR(100) NOT NULL,
    device_reference VARCHAR(255) NOT NULL,
    attestation_verified BOOLEAN NOT NULL DEFAULT false,
    user_verification_supported BOOLEAN NOT NULL DEFAULT false,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No raw fingerprint, facial image or biometric template is stored.
-- The trusted platform performs biometric matching locally.

-- ------------------------------------------------------------
-- 7. DEVICES AND LOGIN CONTEXT
-- ------------------------------------------------------------

CREATE TABLE trusted_devices (
    device_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(user_id)
        ON DELETE CASCADE,
    device_fingerprint_hash TEXT NOT NULL,
    device_name VARCHAR(150),
    trusted BOOLEAN NOT NULL DEFAULT false,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, device_fingerprint_hash)
);

CREATE TABLE login_contexts (
    context_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id)
        ON DELETE SET NULL,
    device_id BIGINT REFERENCES trusted_devices(device_id)
        ON DELETE SET NULL,
    ip_address INET NOT NULL,
    country_code CHAR(2),
    new_device BOOLEAN NOT NULL DEFAULT false,
    impossible_travel BOOLEAN NOT NULL DEFAULT false,
    unusual_time BOOLEAN NOT NULL DEFAULT false,
    sensitive_action BOOLEAN NOT NULL DEFAULT false,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_login_context_user_time
ON login_contexts(user_id, observed_at DESC);

CREATE INDEX idx_login_context_ip
ON login_contexts(ip_address);

-- ------------------------------------------------------------
-- 8. RISK POLICIES
-- ------------------------------------------------------------

CREATE TABLE risk_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_name VARCHAR(120) NOT NULL UNIQUE,
    new_device_weight INTEGER NOT NULL DEFAULT 25,
    impossible_travel_weight INTEGER NOT NULL DEFAULT 55,
    unusual_time_weight INTEGER NOT NULL DEFAULT 15,
    sensitive_action_weight INTEGER NOT NULL DEFAULT 20,
    medium_threshold INTEGER NOT NULL DEFAULT 20,
    high_threshold INTEGER NOT NULL DEFAULT 45,
    critical_threshold INTEGER NOT NULL DEFAULT 70,
    active BOOLEAN NOT NULL DEFAULT true,
    CHECK (new_device_weight >= 0),
    CHECK (impossible_travel_weight >= 0),
    CHECK (unusual_time_weight >= 0),
    CHECK (sensitive_action_weight >= 0),
    CHECK (
        medium_threshold < high_threshold
        AND high_threshold < critical_threshold
    )
);

INSERT INTO risk_policies (
    policy_name
)
VALUES ('enterprise-default');

CREATE TABLE risk_assessments (
    assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    context_id BIGINT NOT NULL REFERENCES login_contexts(context_id),
    policy_id BIGINT NOT NULL REFERENCES risk_policies(policy_id),
    risk_score INTEGER NOT NULL,
    risk risk_level NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (risk_score >= 0)
);

-- ------------------------------------------------------------
-- 9. AUTHENTICATION SESSIONS AND EVENTS
-- ------------------------------------------------------------

CREATE TABLE authentication_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id)
        ON DELETE SET NULL,
    context_id BIGINT REFERENCES login_contexts(context_id)
        ON DELETE SET NULL,
    assessment_id BIGINT REFERENCES risk_assessments(assessment_id)
        ON DELETE SET NULL,
    status authentication_status NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    failure_reason VARCHAR(255),
    CHECK (
        completed_at IS NULL
        OR completed_at >= attempted_at
    )
);

CREATE INDEX idx_attempt_user_time
ON authentication_attempts(user_id, attempted_at DESC);

CREATE INDEX idx_attempt_failures
ON authentication_attempts(attempted_at DESC)
WHERE status IN ('rejected', 'locked');

CREATE TABLE attempt_factors (
    attempt_id BIGINT NOT NULL REFERENCES authentication_attempts(attempt_id)
        ON DELETE CASCADE,
    factor_id BIGINT REFERENCES authentication_factors(factor_id)
        ON DELETE SET NULL,
    factor factor_type NOT NULL,
    verification_status verification_status NOT NULL,
    verified_at TIMESTAMPTZ,
    PRIMARY KEY (attempt_id, factor)
);

CREATE TABLE authenticated_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id BIGINT NOT NULL REFERENCES users(user_id),
    attempt_id BIGINT NOT NULL UNIQUE
        REFERENCES authentication_attempts(attempt_id),
    session_token_hash TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE INDEX idx_sessions_active
ON authenticated_sessions(user_id, expires_at)
WHERE revoked_at IS NULL;

-- ------------------------------------------------------------
-- 10. AUDIT LOG
-- ------------------------------------------------------------

CREATE TABLE authentication_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT REFERENCES users(user_id)
        ON DELETE SET NULL,
    attempt_id BIGINT REFERENCES authentication_attempts(attempt_id)
        ON DELETE SET NULL,
    event_type VARCHAR(80) NOT NULL,
    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_user_time
ON authentication_audit(user_id, occurred_at DESC);

CREATE INDEX idx_audit_event_type
ON authentication_audit(event_type, occurred_at DESC);

-- ------------------------------------------------------------
-- 11. RISK CALCULATION FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION calculate_risk(
    p_new_device BOOLEAN,
    p_impossible_travel BOOLEAN,
    p_unusual_time BOOLEAN,
    p_sensitive_action BOOLEAN,
    p_policy_id BIGINT DEFAULT 1
)
RETURNS TABLE (
    risk_score INTEGER,
    risk risk_level
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    policy risk_policies%ROWTYPE;
    score INTEGER := 0;
BEGIN
    SELECT *
    INTO policy
    FROM risk_policies
    WHERE policy_id = p_policy_id
      AND active = true;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active risk policy not found: %', p_policy_id;
    END IF;

    IF p_new_device THEN
        score := score + policy.new_device_weight;
    END IF;

    IF p_impossible_travel THEN
        score := score + policy.impossible_travel_weight;
    END IF;

    IF p_unusual_time THEN
        score := score + policy.unusual_time_weight;
    END IF;

    IF p_sensitive_action THEN
        score := score + policy.sensitive_action_weight;
    END IF;

    risk_score := score;

    IF score >= policy.critical_threshold THEN
        risk := 'critical';
    ELSIF score >= policy.high_threshold THEN
        risk := 'high';
    ELSIF score >= policy.medium_threshold THEN
        risk := 'medium';
    ELSE
        risk := 'low';
    END IF;

    RETURN NEXT;
END;
$$;

-- ------------------------------------------------------------
-- 12. REQUIRED FACTOR DETERMINATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION required_authentication_factors(
    p_user_id BIGINT,
    p_risk risk_level,
    p_sensitive_action BOOLEAN
)
RETURNS TABLE (factor factor_type)
LANGUAGE sql
STABLE
AS $$
    WITH registered AS (
        SELECT af.factor
        FROM authentication_factors af
        WHERE af.user_id = p_user_id
          AND af.verification = 'verified'
          AND af.revoked_at IS NULL
    ),
    base_factors AS (
        SELECT 'password'::factor_type AS factor
        UNION ALL
        SELECT factor
        FROM registered
        WHERE factor = 'totp'
    ),
    elevated AS (
        SELECT factor
        FROM registered
        WHERE (
            p_risk IN ('high', 'critical')
            AND factor IN ('hardware_token', 'biometric')
        )
        OR (
            p_sensitive_action
            AND factor = 'biometric'
        )
    )
    SELECT DISTINCT factor
    FROM (
        SELECT factor FROM base_factors
        UNION ALL
        SELECT factor FROM elevated
    ) AS required
    ORDER BY factor;
$$;

-- ------------------------------------------------------------
-- 13. FACTOR VERIFICATION INTEGRITY
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_factor_verification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.verification = 'verified' AND NEW.verified_at IS NULL THEN
        NEW.verified_at := now();
    END IF;

    IF NEW.verification = 'revoked' AND NEW.revoked_at IS NULL THEN
        NEW.revoked_at := now();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_factor_verification
BEFORE INSERT OR UPDATE ON authentication_factors
FOR EACH ROW
EXECUTE FUNCTION validate_factor_verification();

-- ------------------------------------------------------------
-- 14. SESSION CREATION VALIDATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_session_creation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    attempt authentication_attempts%ROWTYPE;
    account credential_state;
BEGIN
    SELECT *
    INTO attempt
    FROM authentication_attempts
    WHERE attempt_id = NEW.attempt_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Authentication attempt does not exist.';
    END IF;

    IF attempt.status <> 'success' THEN
        RAISE EXCEPTION 'A successful authentication is required.';
    END IF;

    IF attempt.user_id <> NEW.user_id THEN
        RAISE EXCEPTION 'Session and attempt user IDs do not match.';
    END IF;

    SELECT account_state
    INTO account
    FROM users
    WHERE user_id = NEW.user_id;

    IF account <> 'active' THEN
        RAISE EXCEPTION 'User account is not active.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_session_creation
BEFORE INSERT ON authenticated_sessions
FOR EACH ROW
EXECUTE FUNCTION validate_session_creation();

-- ------------------------------------------------------------
-- 15. AUTHENTICATION ELIGIBILITY VIEW
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW authentication_attempt_report AS
SELECT
    a.attempt_id,
    u.username,
    a.status,
    a.attempted_at,
    lc.ip_address,
    lc.country_code,
    ra.risk_score,
    ra.risk,
    COUNT(af.factor) AS factors_recorded,
    COUNT(af.factor) FILTER (
        WHERE af.verification_status = 'verified'
    ) AS factors_verified
FROM authentication_attempts a
LEFT JOIN users u
    ON u.user_id = a.user_id
LEFT JOIN login_contexts lc
    ON lc.context_id = a.context_id
LEFT JOIN risk_assessments ra
    ON ra.assessment_id = a.assessment_id
LEFT JOIN attempt_factors af
    ON af.attempt_id = a.attempt_id
GROUP BY
    a.attempt_id,
    u.username,
    a.status,
    a.attempted_at,
    lc.ip_address,
    lc.country_code,
    ra.risk_score,
    ra.risk;

-- ------------------------------------------------------------
-- 16. SAMPLE ENTERPRISE USERS
-- ------------------------------------------------------------

INSERT INTO users (username, email)
VALUES
    ('security_admin', 'security@example.com'),
    ('developer01', 'developer@example.com'),
    ('analyst01', 'analyst@example.com');

INSERT INTO password_credentials (
    user_id,
    password_hash,
    salt,
    hashing_algorithm
)
SELECT
    user_id,
    '$argon2id$example_encoded_hash_for_admin',
    'sample_salt_admin',
    'argon2id'
FROM users
WHERE username = 'security_admin';

INSERT INTO password_credentials (
    user_id,
    password_hash,
    salt,
    hashing_algorithm
)
SELECT
    user_id,
    '$argon2id$example_encoded_hash_for_developer',
    'sample_salt_developer',
    'argon2id'
FROM users
WHERE username = 'developer01';

INSERT INTO password_credentials (
    user_id,
    password_hash,
    salt,
    hashing_algorithm
)
SELECT
    user_id,
    '$argon2id$example_encoded_hash_for_analyst',
    'sample_salt_analyst',
    'argon2id'
FROM users
WHERE username = 'analyst01';

-- The encoded sample hashes are non-authenticating demonstration data.
-- Production hashes must be generated by a password-hashing library.

INSERT INTO authentication_factors (
    user_id,
    factor,
    factor_name,
    verification,
    verified_at
)
SELECT
    u.user_id,
    f.factor,
    f.factor_name,
    'verified',
    now()
FROM users u
CROSS JOIN (
    VALUES
        ('password'::factor_type, 'Primary password'),
        ('totp'::factor_type, 'Authenticator application'),
        ('hardware_token'::factor_type, 'FIDO2 security key'),
        ('biometric'::factor_type, 'Platform biometric')
) AS f(factor, factor_name)
WHERE u.username = 'security_admin';

INSERT INTO authentication_factors (
    user_id,
    factor,
    factor_name,
    verification,
    verified_at
)
SELECT
    u.user_id,
    f.factor,
    f.factor_name,
    'verified',
    now()
FROM users u
CROSS JOIN (
    VALUES
        ('password'::factor_type, 'Primary password'),
        ('totp'::factor_type, 'Authenticator application')
) AS f(factor, factor_name)
WHERE u.username = 'developer01';

INSERT INTO authentication_factors (
    user_id,
    factor,
    factor_name,
    verification
)
SELECT
    user_id,
    'totp',
    'Pending authenticator enrollment',
    'pending'
FROM users
WHERE username = 'analyst01';

-- ------------------------------------------------------------
-- 17. SAMPLE HARDWARE TOKEN
-- ------------------------------------------------------------

INSERT INTO hardware_tokens (
    factor_id,
    credential_id,
    public_key,
    relying_party_id,
    sign_count,
    authenticator_type
)
SELECT
    factor_id,
    decode('00112233445566778899aabbccddeeff', 'hex'),
    decode('aabbccddeeff00112233445566778899', 'hex'),
    'enterprise.example.com',
    12,
    'cross_platform'
FROM authentication_factors
WHERE factor_name = 'FIDO2 security key';

-- ------------------------------------------------------------
-- 18. SAMPLE BIOMETRIC REGISTRATION
-- ------------------------------------------------------------

INSERT INTO biometric_credentials (
    factor_id,
    platform_name,
    device_reference,
    attestation_verified,
    user_verification_supported
)
SELECT
    factor_id,
    'Enterprise Trusted Platform',
    'device-reference-001',
    true,
    true
FROM authentication_factors
WHERE factor_name = 'Platform biometric';

-- ------------------------------------------------------------
-- 19. SAMPLE DEVICES AND CONTEXTS
-- ------------------------------------------------------------

INSERT INTO trusted_devices (
    user_id,
    device_fingerprint_hash,
    device_name,
    trusted
)
SELECT
    user_id,
    'sha256:example-device-fingerprint',
    'Corporate Workstation',
    true
FROM users
WHERE username = 'security_admin';

INSERT INTO login_contexts (
    user_id,
    device_id,
    ip_address,
    country_code,
    new_device,
    impossible_travel,
    unusual_time,
    sensitive_action
)
SELECT
    u.user_id,
    d.device_id,
    '192.0.2.10'::inet,
    'IN',
    false,
    false,
    false,
    false
FROM users u
JOIN trusted_devices d
    ON d.user_id = u.user_id
WHERE u.username = 'security_admin';

INSERT INTO login_contexts (
    user_id,
    ip_address,
    country_code,
    new_device,
    impossible_travel,
    unusual_time,
    sensitive_action
)
SELECT
    user_id,
    '198.51.100.25'::inet,
    'US',
    true,
    true,
    false,
    true
FROM users
WHERE username = 'security_admin';

-- ------------------------------------------------------------
-- 20. SAMPLE RISK ASSESSMENTS
-- ------------------------------------------------------------

INSERT INTO risk_assessments (
    context_id,
    policy_id,
    risk_score,
    risk
)
SELECT
    lc.context_id,
    1,
    result.risk_score,
    result.risk
FROM login_contexts lc
CROSS JOIN LATERAL calculate_risk(
    lc.new_device,
    lc.impossible_travel,
    lc.unusual_time,
    lc.sensitive_action,
    1
) AS result;

-- ------------------------------------------------------------
-- 21. SAMPLE AUTHENTICATION ATTEMPTS
-- ------------------------------------------------------------

INSERT INTO authentication_attempts (
    user_id,
    context_id,
    assessment_id,
    status,
    completed_at,
    failure_reason
)
SELECT
    lc.user_id,
    lc.context_id,
    ra.assessment_id,
    CASE
        WHEN ra.risk = 'low' THEN 'success'::authentication_status
        ELSE 'step_up_required'::authentication_status
    END,
    now(),
    CASE
        WHEN ra.risk = 'low' THEN NULL
        ELSE 'Additional verification required'
    END
FROM login_contexts lc
JOIN risk_assessments ra
    ON ra.context_id = lc.context_id
WHERE lc.user_id IS NOT NULL;

-- ------------------------------------------------------------
-- 22. FACTOR EVIDENCE RECORDS
-- ------------------------------------------------------------

INSERT INTO attempt_factors (
    attempt_id,
    factor_id,
    factor,
    verification_status,
    verified_at
)
SELECT
    a.attempt_id,
    af.factor_id,
    af.factor,
    CASE
        WHEN a.status = 'success'
             AND af.factor IN ('password', 'totp')
        THEN 'verified'::verification_status
        ELSE 'pending'::verification_status
    END,
    CASE
        WHEN a.status = 'success'
             AND af.factor IN ('password', 'totp')
        THEN now()
        ELSE NULL
    END
FROM authentication_attempts a
JOIN authentication_factors af
    ON af.user_id = a.user_id
WHERE af.verification = 'verified';

-- ------------------------------------------------------------
-- 23. AUDIT RECORDS
-- ------------------------------------------------------------

INSERT INTO authentication_audit (
    user_id,
    attempt_id,
    event_type,
    event_details
)
SELECT
    a.user_id,
    a.attempt_id,
    'authentication_attempt',
    jsonb_build_object(
        'status', a.status,
        'source', 'enterprise_login'
    )
FROM authentication_attempts a;

-- ------------------------------------------------------------
-- 24. REPORTING AND VALIDATION QUERIES
-- ------------------------------------------------------------

-- Query 1: Registered factors per user.
SELECT
    u.username,
    af.factor,
    af.verification,
    af.registered_at
FROM users u
LEFT JOIN authentication_factors af
    ON af.user_id = u.user_id
ORDER BY u.username, af.factor;

-- Query 2: Account eligibility and verified MFA enrollment.
SELECT
    u.username,
    u.account_state,
    COUNT(af.factor_id) FILTER (
        WHERE af.verification = 'verified'
        AND af.factor <> 'password'
    ) AS verified_additional_factors,
    COUNT(af.factor_id) FILTER (
        WHERE af.verification = 'pending'
    ) AS pending_factors,
    CASE
        WHEN u.account_state <> 'active' THEN 'INELIGIBLE'
        WHEN COUNT(af.factor_id) FILTER (
            WHERE af.verification = 'verified'
            AND af.factor <> 'password'
        ) = 0 THEN 'MFA_ENROLLMENT_REQUIRED'
        ELSE 'MFA_ENROLLED'
    END AS eligibility
FROM users u
LEFT JOIN authentication_factors af
    ON af.user_id = u.user_id
GROUP BY u.user_id, u.username, u.account_state;

-- Query 3: Risk assessment distribution.
SELECT
    risk,
    COUNT(*) AS assessment_count,
    ROUND(AVG(risk_score), 2) AS average_score,
    MAX(risk_score) AS maximum_score
FROM risk_assessments
GROUP BY risk
ORDER BY average_score DESC;

-- Query 4: Failed authentication monitoring.
SELECT
    u.username,
    COUNT(*) AS failed_attempts,
    MAX(a.attempted_at) AS last_failure
FROM authentication_attempts a
JOIN users u
    ON u.user_id = a.user_id
WHERE a.status IN ('rejected', 'locked')
GROUP BY u.username
ORDER BY failed_attempts DESC;

-- Query 5: Adaptive policy evaluation.
SELECT
    lc.context_id,
    lc.ip_address,
    lc.country_code,
    result.risk_score,
    result.risk,
    CASE
        WHEN result.risk IN ('high', 'critical')
        THEN 'STEP_UP_REQUIRED'
        WHEN result.risk = 'medium'
        THEN 'ENHANCED_MONITORING'
        ELSE 'STANDARD_AUTHENTICATION'
    END AS recommended_action
FROM login_contexts lc
CROSS JOIN LATERAL calculate_risk(
    lc.new_device,
    lc.impossible_travel,
    lc.unusual_time,
    lc.sensitive_action,
    1
) AS result;

-- Query 6: Factor-level success rates.
SELECT
    factor,
    COUNT(*) AS total_checks,
    COUNT(*) FILTER (
        WHERE verification_status = 'verified'
    ) AS successful_checks,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE verification_status = 'verified'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS success_percentage
FROM attempt_factors
GROUP BY factor
ORDER BY factor;

-- Query 7: Authentication reporting view.
SELECT *
FROM authentication_attempt_report
ORDER BY attempted_at DESC;

-- Query 8: Determine factors required for the administrator.
SELECT factor
FROM required_authentication_factors(
    (
        SELECT user_id
        FROM users
        WHERE username = 'security_admin'
    ),
    'critical',
    true
);

-- ------------------------------------------------------------
-- 25. TRANSACTIONAL SESSION CREATION
-- ------------------------------------------------------------

-- Session creation is permitted only after a successful attempt.
-- The trigger validates account state and user ownership.

DO $$
DECLARE
    successful_attempt BIGINT;
    target_user BIGINT;
BEGIN
    SELECT attempt_id, user_id
    INTO successful_attempt, target_user
    FROM authentication_attempts
    WHERE status = 'success'
    ORDER BY attempted_at DESC
    LIMIT 1;

    IF successful_attempt IS NOT NULL THEN
        INSERT INTO authenticated_sessions (
            user_id,
            attempt_id,
            session_token_hash,
            expires_at
        )
        VALUES (
            target_user,
            successful_attempt,
            'sha256:demonstration-session-token-hash',
            now() + INTERVAL '8 hours'
        )
        ON CONFLICT (attempt_id) DO NOTHING;
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- 26. SECURITY AND SESSION REPORTING
-- ------------------------------------------------------------

SELECT
    s.session_id,
    u.username,
    s.issued_at,
    s.expires_at,
    CASE
        WHEN s.revoked_at IS NOT NULL THEN 'REVOKED'
        WHEN s.expires_at <= now() THEN 'EXPIRED'
        ELSE 'ACTIVE'
    END AS session_state
FROM authenticated_sessions s
JOIN users u
    ON u.user_id = s.user_id
ORDER BY s.issued_at DESC;

-- Demonstration of transactional rollback for invalid sessions.
-- The savepoint ensures the main script remains executable.

SAVEPOINT session_validation_test;

DO $$
BEGIN
    BEGIN
        INSERT INTO authenticated_sessions (
            user_id,
            attempt_id,
            session_token_hash,
            expires_at
        )
        SELECT
            a.user_id,
            a.attempt_id,
            'invalid-demonstration-token',
            now() + INTERVAL '1 hour'
        FROM authentication_attempts a
        WHERE a.status <> 'success'
        LIMIT 1;

    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'Expected session validation failure: %', SQLERRM;
    END;
END;
$$;

ROLLBACK TO SAVEPOINT session_validation_test;
RELEASE SAVEPOINT session_validation_test;

COMMIT;

-- ------------------------------------------------------------
-- PRODUCTION SECURITY NOTES
-- ------------------------------------------------------------
-- 1. Password hashing must be performed by a maintained
--    Argon2id, scrypt or PBKDF2 implementation.
-- 2. TOTP secrets must be encrypted using managed keys.
-- 3. TOTP counter replay prevention must use atomic updates.
-- 4. Hardware tokens require complete WebAuthn validation.
-- 5. Biometric matching must remain on the trusted platform.
-- 6. Session tokens must be generated with a CSPRNG.
-- 7. Store only a cryptographic hash of session tokens.
-- 8. Apply row-level security and least-privilege database roles.
-- 9. Rate-limit authentication requests at the service boundary.
-- 10. Audit events should be append-only and access-controlled.
