-- ============================================================
-- TLS Deep Dive: PostgreSQL TLS Security Governance Database
-- ============================================================
--
-- Models:
--   TLS endpoints
--   TLS protocol policies
--   Cipher suite inventory
--   X.509 certificate inventory
--   Certificate chains
--   Handshake assessments
--   Session metadata
--   Security findings
--   Certificate renewal workflow
--
-- Session secrets, private keys, resumption tickets and raw
-- traffic secrets must NEVER be stored in this database.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS tls_governance;

SET search_path TO tls_governance, public;

-- ------------------------------------------------------------
-- Enumerated domain states
-- ------------------------------------------------------------

CREATE TYPE protocol_version AS ENUM (
    'TLS_1_2',
    'TLS_1_3'
);

CREATE TYPE endpoint_status AS ENUM (
    'ACTIVE',
    'MAINTENANCE',
    'DISABLED'
);

CREATE TYPE certificate_status AS ENUM (
    'PENDING',
    'VALID',
    'EXPIRING',
    'EXPIRED',
    'REVOKED',
    'REJECTED'
);

CREATE TYPE handshake_status AS ENUM (
    'INITIATED',
    'ESTABLISHED',
    'FAILED',
    'TIMED_OUT'
);

CREATE TYPE finding_severity AS ENUM (
    'INFO',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TYPE finding_status AS ENUM (
    'OPEN',
    'ACKNOWLEDGED',
    'RESOLVED',
    'ACCEPTED_RISK'
);

CREATE TYPE session_status AS ENUM (
    'ACTIVE',
    'EXPIRED',
    'REVOKED'
);

-- ------------------------------------------------------------
-- Organizational ownership
-- ------------------------------------------------------------

CREATE TABLE security_teams (
    team_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    team_name VARCHAR(120) NOT NULL UNIQUE,
    owner_email VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE tls_endpoints (
    endpoint_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    team_id BIGINT NOT NULL
        REFERENCES security_teams(team_id),

    hostname VARCHAR(253) NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,

    environment VARCHAR(30) NOT NULL
        CHECK (
            environment IN (
                'DEVELOPMENT',
                'TEST',
                'STAGING',
                'PRODUCTION'
            )
        ),

    status endpoint_status NOT NULL DEFAULT 'ACTIVE',

    expected_protocol protocol_version NOT NULL
        DEFAULT 'TLS_1_3',

    last_assessed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT endpoint_port_check
        CHECK (port BETWEEN 1 AND 65535),

    CONSTRAINT endpoint_hostname_not_empty
        CHECK (LENGTH(TRIM(hostname)) > 0),

    UNIQUE (hostname, port, environment)
);

CREATE INDEX idx_endpoints_team
    ON tls_endpoints(team_id);

CREATE INDEX idx_endpoints_active
    ON tls_endpoints(status, environment)
    WHERE status = 'ACTIVE';

-- ------------------------------------------------------------
-- Cipher suite governance
-- ------------------------------------------------------------

CREATE TABLE cipher_suites (
    cipher_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    cipher_name VARCHAR(160) NOT NULL UNIQUE,

    protocol protocol_version NOT NULL,

    encryption_algorithm VARCHAR(80) NOT NULL,
    authentication_algorithm VARCHAR(80),
    key_exchange_algorithm VARCHAR(80),
    hash_algorithm VARCHAR(40) NOT NULL,

    key_bits INTEGER NOT NULL
        CHECK (key_bits > 0),

    authenticated_encryption BOOLEAN NOT NULL,

    forward_secrecy BOOLEAN NOT NULL,

    approved BOOLEAN NOT NULL DEFAULT FALSE,

    security_notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cipher_approved
    ON cipher_suites(protocol, cipher_name)
    WHERE approved = TRUE;

-- TLS 1.3 cipher suites do not encode key exchange or
-- authentication algorithms in their names.
INSERT INTO cipher_suites (
    cipher_name,
    protocol,
    encryption_algorithm,
    authentication_algorithm,
    key_exchange_algorithm,
    hash_algorithm,
    key_bits,
    authenticated_encryption,
    forward_secrecy,
    approved
)
VALUES
(
    'TLS_AES_128_GCM_SHA256',
    'TLS_1_3',
    'AES-128-GCM',
    NULL,
    NULL,
    'SHA-256',
    128,
    TRUE,
    TRUE,
    TRUE
),
(
    'TLS_AES_256_GCM_SHA384',
    'TLS_1_3',
    'AES-256-GCM',
    NULL,
    NULL,
    'SHA-384',
    256,
    TRUE,
    TRUE,
    TRUE
),
(
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_1_3',
    'ChaCha20-Poly1305',
    NULL,
    NULL,
    'SHA-256',
    256,
    TRUE,
    TRUE,
    TRUE
),
(
    'ECDHE-RSA-AES128-GCM-SHA256',
    'TLS_1_2',
    'AES-128-GCM',
    'RSA',
    'ECDHE',
    'SHA-256',
    128,
    TRUE,
    TRUE,
    TRUE
),
(
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'TLS_1_2',
    'AES-256-GCM',
    'ECDSA',
    'ECDHE',
    'SHA-384',
    256,
    TRUE,
    TRUE,
    TRUE
),
(
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_1_2',
    'AES-128-CBC',
    'RSA',
    'RSA',
    'SHA-1',
    128,
    FALSE,
    FALSE,
    FALSE
);

-- ------------------------------------------------------------
-- Endpoint cipher compatibility
-- ------------------------------------------------------------

CREATE TABLE endpoint_cipher_preferences (
    endpoint_id BIGINT NOT NULL
        REFERENCES tls_endpoints(endpoint_id)
        ON DELETE CASCADE,

    cipher_id BIGINT NOT NULL
        REFERENCES cipher_suites(cipher_id),

    preference_order INTEGER NOT NULL
        CHECK (preference_order > 0),

    PRIMARY KEY (endpoint_id, cipher_id),

    UNIQUE (endpoint_id, preference_order)
);

-- ------------------------------------------------------------
-- Certificate inventory
-- ------------------------------------------------------------

CREATE TABLE certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES tls_endpoints(endpoint_id),

    common_name VARCHAR(253) NOT NULL,

    issuer VARCHAR(500) NOT NULL,

    serial_number VARCHAR(160) NOT NULL,

    public_key_algorithm VARCHAR(40) NOT NULL,

    public_key_bits INTEGER NOT NULL
        CHECK (public_key_bits > 0),

    signature_algorithm VARCHAR(100) NOT NULL,

    sha256_fingerprint VARCHAR(64) NOT NULL UNIQUE
        CHECK (sha256_fingerprint ~ '^[0-9a-fA-F]{64}$'),

    not_before TIMESTAMPTZ NOT NULL,

    not_after TIMESTAMPTZ NOT NULL,

    status certificate_status NOT NULL DEFAULT 'PENDING',

    is_ca BOOLEAN NOT NULL DEFAULT FALSE,

    server_auth_allowed BOOLEAN NOT NULL DEFAULT TRUE,

    hostname_verified BOOLEAN NOT NULL DEFAULT FALSE,

    chain_verified BOOLEAN NOT NULL DEFAULT FALSE,

    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (not_after > not_before),

    CHECK (
        status <> 'REVOKED'
        OR revoked_at IS NOT NULL
    )
);

CREATE INDEX idx_certificate_endpoint
    ON certificates(endpoint_id, status);

CREATE INDEX idx_certificate_expiry
    ON certificates(not_after)
    WHERE status IN ('VALID', 'EXPIRING');

-- ------------------------------------------------------------
-- Certificate chain relationships
-- ------------------------------------------------------------

CREATE TABLE certificate_chain (
    child_certificate_id BIGINT NOT NULL
        REFERENCES certificates(certificate_id)
        ON DELETE CASCADE,

    issuer_certificate_id BIGINT NOT NULL
        REFERENCES certificates(certificate_id),

    chain_order INTEGER NOT NULL
        CHECK (chain_order > 0),

    PRIMARY KEY (
        child_certificate_id,
        issuer_certificate_id
    ),

    UNIQUE (
        child_certificate_id,
        chain_order
    ),

    CHECK (
        child_certificate_id <> issuer_certificate_id
    )
);

-- ------------------------------------------------------------
-- TLS security policies
-- ------------------------------------------------------------

CREATE TABLE tls_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    minimum_protocol protocol_version NOT NULL,

    maximum_protocol protocol_version NOT NULL,

    require_valid_certificate BOOLEAN NOT NULL DEFAULT TRUE,

    require_hostname_verification BOOLEAN NOT NULL DEFAULT TRUE,

    require_forward_secrecy BOOLEAN NOT NULL DEFAULT TRUE,

    require_aead BOOLEAN NOT NULL DEFAULT TRUE,

    allow_session_resumption BOOLEAN NOT NULL DEFAULT TRUE,

    maximum_certificate_lifetime_days INTEGER NOT NULL
        CHECK (maximum_certificate_lifetime_days > 0),

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (
        minimum_protocol <> 'TLS_1_3'
        OR maximum_protocol = 'TLS_1_3'
    )
);

CREATE TABLE endpoint_policies (
    endpoint_id BIGINT PRIMARY KEY
        REFERENCES tls_endpoints(endpoint_id)
        ON DELETE CASCADE,

    policy_id BIGINT NOT NULL
        REFERENCES tls_policies(policy_id),

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------
-- Handshake assessments
-- ------------------------------------------------------------

CREATE TABLE handshake_assessments (
    assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES tls_endpoints(endpoint_id),

    certificate_id BIGINT
        REFERENCES certificates(certificate_id),

    cipher_id BIGINT
        REFERENCES cipher_suites(cipher_id),

    negotiated_protocol protocol_version,

    status handshake_status NOT NULL,

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    duration_ms NUMERIC(12, 3),

    session_reused BOOLEAN NOT NULL DEFAULT FALSE,

    certificate_verified BOOLEAN NOT NULL DEFAULT FALSE,

    hostname_verified BOOLEAN NOT NULL DEFAULT FALSE,

    transcript_verified BOOLEAN NOT NULL DEFAULT FALSE,

    failure_code VARCHAR(100),

    failure_description TEXT,

    CHECK (
        completed_at IS NULL
        OR completed_at >= started_at
    ),

    CHECK (
        duration_ms IS NULL
        OR duration_ms >= 0
    ),

    CHECK (
        status <> 'ESTABLISHED'
        OR (
            negotiated_protocol IS NOT NULL
            AND cipher_id IS NOT NULL
            AND certificate_verified
            AND hostname_verified
            AND transcript_verified
        )
    ),

    CHECK (
        status NOT IN ('FAILED', 'TIMED_OUT')
        OR failure_code IS NOT NULL
    )
);

CREATE INDEX idx_handshake_endpoint_time
    ON handshake_assessments(
        endpoint_id,
        started_at DESC
    );

CREATE INDEX idx_handshake_failures
    ON handshake_assessments(status, started_at DESC)
    WHERE status IN ('FAILED', 'TIMED_OUT');

-- ------------------------------------------------------------
-- Session metadata
-- ------------------------------------------------------------

-- Deliberately excludes raw tickets, traffic secrets,
-- session keys and resumable PSK material.
CREATE TABLE tls_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES tls_endpoints(endpoint_id),

    assessment_id BIGINT NOT NULL
        REFERENCES handshake_assessments(assessment_id),

    session_reference_hash VARCHAR(64) NOT NULL UNIQUE
        CHECK (
            session_reference_hash ~ '^[0-9a-fA-F]{64}$'
        ),

    protocol protocol_version NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    status session_status NOT NULL DEFAULT 'ACTIVE',

    revoked_at TIMESTAMPTZ,

    CHECK (expires_at > created_at),

    CHECK (
        status <> 'REVOKED'
        OR revoked_at IS NOT NULL
    )
);

CREATE INDEX idx_sessions_expiry
    ON tls_sessions(expires_at)
    WHERE status = 'ACTIVE';

-- ------------------------------------------------------------
-- Security findings
-- ------------------------------------------------------------

CREATE TABLE security_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES tls_endpoints(endpoint_id),

    assessment_id BIGINT
        REFERENCES handshake_assessments(assessment_id),

    severity finding_severity NOT NULL,

    status finding_status NOT NULL DEFAULT 'OPEN',

    finding_code VARCHAR(100) NOT NULL,

    description TEXT NOT NULL,

    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    resolved_at TIMESTAMPTZ,

    CHECK (
        status <> 'RESOLVED'
        OR resolved_at IS NOT NULL
    )
);

CREATE INDEX idx_open_findings
    ON security_findings(
        severity,
        detected_at DESC
    )
    WHERE status = 'OPEN';

-- ------------------------------------------------------------
-- Audit events
-- ------------------------------------------------------------

CREATE TABLE tls_audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    entity_type VARCHAR(80) NOT NULL,

    entity_id BIGINT NOT NULL,

    event_type VARCHAR(100) NOT NULL,

    event_description TEXT NOT NULL,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    actor VARCHAR(255) NOT NULL DEFAULT CURRENT_USER
);

CREATE INDEX idx_audit_entity
    ON tls_audit_events(entity_type, entity_id, occurred_at DESC);

-- ------------------------------------------------------------
-- Certificate validity trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_certificate_record()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.not_after <= NEW.not_before THEN
        RAISE EXCEPTION
            'Certificate expiration must follow its validity start.';
    END IF;

    IF NEW.status = 'VALID' THEN
        IF NOT NEW.hostname_verified THEN
            RAISE EXCEPTION
                'A valid certificate must pass hostname verification.';
        END IF;

        IF NOT NEW.chain_verified THEN
            RAISE EXCEPTION
                'A valid certificate must have a verified chain.';
        END IF;

        IF NOT NEW.server_auth_allowed THEN
            RAISE EXCEPTION
                'Certificate is not permitted for server authentication.';
        END IF;

        IF NEW.is_ca THEN
            RAISE EXCEPTION
                'A CA certificate cannot be registered as a server leaf certificate.';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_certificate
BEFORE INSERT OR UPDATE ON certificates
FOR EACH ROW
EXECUTE FUNCTION validate_certificate_record();

-- ------------------------------------------------------------
-- Handshake protocol and cipher consistency trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_handshake_cipher()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    selected_protocol protocol_version;
    selected_approved BOOLEAN;
    selected_aead BOOLEAN;
    selected_forward_secrecy BOOLEAN;
BEGIN
    IF NEW.cipher_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT
        protocol,
        approved,
        authenticated_encryption,
        forward_secrecy
    INTO
        selected_protocol,
        selected_approved,
        selected_aead,
        selected_forward_secrecy
    FROM cipher_suites
    WHERE cipher_id = NEW.cipher_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown cipher suite.';
    END IF;

    IF NEW.negotiated_protocol IS DISTINCT FROM selected_protocol THEN
        RAISE EXCEPTION
            'Negotiated protocol does not match cipher suite protocol.';
    END IF;

    IF NEW.status = 'ESTABLISHED' AND NOT selected_approved THEN
        RAISE EXCEPTION
            'Unapproved cipher cannot establish a compliant handshake.';
    END IF;

    IF NEW.status = 'ESTABLISHED' AND
       NOT selected_aead THEN
        RAISE EXCEPTION
            'Approved handshake requires authenticated encryption.';
    END IF;

    IF NEW.status = 'ESTABLISHED' AND
       NOT selected_forward_secrecy THEN
        RAISE EXCEPTION
            'Approved handshake requires forward secrecy.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_handshake_cipher
BEFORE INSERT OR UPDATE ON handshake_assessments
FOR EACH ROW
EXECUTE FUNCTION validate_handshake_cipher();

-- ------------------------------------------------------------
-- Audit trigger for handshake events
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_handshake_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO tls_audit_events (
        entity_type,
        entity_id,
        event_type,
        event_description
    )
    VALUES (
        'HANDSHAKE',
        NEW.assessment_id,
        NEW.status::TEXT,
        'Handshake assessment state: ' || NEW.status::TEXT
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_handshake
AFTER INSERT OR UPDATE OF status ON handshake_assessments
FOR EACH ROW
EXECUTE FUNCTION audit_handshake_event();

-- ------------------------------------------------------------
-- Certificate expiration maintenance
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION refresh_certificate_statuses()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected INTEGER;
BEGIN
    UPDATE certificates
    SET status = CASE
        WHEN not_after <= NOW() THEN 'EXPIRED'::certificate_status
        WHEN not_after <= NOW() + INTERVAL '30 days'
            THEN 'EXPIRING'::certificate_status
        ELSE 'VALID'::certificate_status
    END
    WHERE status IN ('VALID', 'EXPIRING', 'EXPIRED')
      AND status <> 'REVOKED';

    GET DIAGNOSTICS affected = ROW_COUNT;

    RETURN affected;
END;
$$;

-- ------------------------------------------------------------
-- Handshake eligibility function
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION is_handshake_compliant(
    p_assessment_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    compliant BOOLEAN;
BEGIN
    SELECT
        h.status = 'ESTABLISHED'
        AND h.certificate_verified
        AND h.hostname_verified
        AND h.transcript_verified
        AND c.approved
        AND c.authenticated_encryption
        AND c.forward_secrecy
        AND p.active
        AND h.negotiated_protocol IN (
            p.minimum_protocol,
            p.maximum_protocol
        )
    INTO compliant
    FROM handshake_assessments h
    JOIN cipher_suites c
        ON c.cipher_id = h.cipher_id
    JOIN tls_endpoints e
        ON e.endpoint_id = h.endpoint_id
    JOIN endpoint_policies ep
        ON ep.endpoint_id = e.endpoint_id
    JOIN tls_policies p
        ON p.policy_id = ep.policy_id
    WHERE h.assessment_id = p_assessment_id;

    RETURN COALESCE(compliant, FALSE);
END;
$$;

-- ------------------------------------------------------------
-- Certificate renewal procedure
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE create_certificate_renewal_finding(
    p_endpoint_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    expiring_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO expiring_count
    FROM certificates
    WHERE endpoint_id = p_endpoint_id
      AND status IN ('VALID', 'EXPIRING')
      AND not_after <= NOW() + INTERVAL '30 days';

    IF expiring_count > 0 THEN
        INSERT INTO security_findings (
            endpoint_id,
            severity,
            finding_code,
            description
        )
        VALUES (
            p_endpoint_id,
            'HIGH',
            'CERTIFICATE_RENEWAL_REQUIRED',
            'One or more endpoint certificates expire within 30 days.'
        );
    END IF;
END;
$$;

-- ------------------------------------------------------------
-- Reporting views
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW v_endpoint_tls_posture AS
SELECT
    e.endpoint_id,
    e.hostname,
    e.port,
    e.environment,
    e.status AS endpoint_status,
    COUNT(DISTINCT h.assessment_id) AS assessment_count,
    COUNT(DISTINCT h.assessment_id)
        FILTER (WHERE h.status = 'ESTABLISHED')
        AS successful_handshakes,
    COUNT(DISTINCT h.assessment_id)
        FILTER (WHERE h.status IN ('FAILED', 'TIMED_OUT'))
        AS failed_handshakes,
    MAX(h.started_at) AS last_handshake,
    COUNT(DISTINCT f.finding_id)
        FILTER (WHERE f.status = 'OPEN')
        AS open_findings
FROM tls_endpoints e
LEFT JOIN handshake_assessments h
    ON h.endpoint_id = e.endpoint_id
LEFT JOIN security_findings f
    ON f.endpoint_id = e.endpoint_id
GROUP BY
    e.endpoint_id,
    e.hostname,
    e.port,
    e.environment,
    e.status;

CREATE OR REPLACE VIEW v_certificate_expiry_report AS
SELECT
    c.certificate_id,
    e.hostname,
    c.common_name,
    c.issuer,
    c.status,
    c.not_after,
    EXTRACT(
        DAY FROM c.not_after - NOW()
    )::INTEGER AS days_remaining
FROM certificates c
JOIN tls_endpoints e
    ON e.endpoint_id = c.endpoint_id
WHERE c.status IN ('VALID', 'EXPIRING', 'EXPIRED');

CREATE OR REPLACE VIEW v_cipher_usage AS
SELECT
    cs.cipher_name,
    cs.protocol,
    cs.approved,
    COUNT(h.assessment_id) AS handshake_count,
    COUNT(h.assessment_id)
        FILTER (WHERE h.status = 'ESTABLISHED')
        AS successful_count
FROM cipher_suites cs
LEFT JOIN handshake_assessments h
    ON h.cipher_id = cs.cipher_id
GROUP BY
    cs.cipher_id,
    cs.cipher_name,
    cs.protocol,
    cs.approved;

-- ------------------------------------------------------------
-- Sample records
-- ------------------------------------------------------------

INSERT INTO security_teams (
    team_name,
    owner_email
)
VALUES
(
    'Platform Security',
    'platform-security@example.com'
),
(
    'Infrastructure Security',
    'infrastructure@example.com'
);

INSERT INTO tls_endpoints (
    team_id,
    hostname,
    port,
    environment,
    expected_protocol
)
VALUES
(
    1,
    'api.example.com',
    443,
    'PRODUCTION',
    'TLS_1_3'
),
(
    1,
    'payments.example.com',
    443,
    'PRODUCTION',
    'TLS_1_3'
),
(
    2,
    'staging.example.com',
    443,
    'STAGING',
    'TLS_1_2'
);

INSERT INTO tls_policies (
    policy_name,
    minimum_protocol,
    maximum_protocol,
    require_valid_certificate,
    require_hostname_verification,
    require_forward_secrecy,
    require_aead,
    maximum_certificate_lifetime_days
)
VALUES
(
    'Production TLS Strict',
    'TLS_1_3',
    'TLS_1_3',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    398
),
(
    'Staging TLS Compatible',
    'TLS_1_2',
    'TLS_1_3',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    398
);

INSERT INTO endpoint_policies (
    endpoint_id,
    policy_id
)
VALUES
(1, 1),
(2, 1),
(3, 2);

INSERT INTO endpoint_cipher_preferences (
    endpoint_id,
    cipher_id,
    preference_order
)
SELECT
    1,
    cipher_id,
    ROW_NUMBER() OVER (
        ORDER BY cipher_name
    )::INTEGER
FROM cipher_suites
WHERE protocol = 'TLS_1_3'
  AND approved = TRUE;

INSERT INTO certificates (
    endpoint_id,
    common_name,
    issuer,
    serial_number,
    public_key_algorithm,
    public_key_bits,
    signature_algorithm,
    sha256_fingerprint,
    not_before,
    not_after,
    status,
    hostname_verified,
    chain_verified,
    server_auth_allowed
)
VALUES
(
    1,
    'api.example.com',
    'Example Intermediate CA',
    '100001',
    'RSA',
    3072,
    'SHA256withRSA',
    REPEAT('a', 64),
    NOW() - INTERVAL '30 days',
    NOW() + INTERVAL '300 days',
    'VALID',
    TRUE,
    TRUE,
    TRUE
),
(
    2,
    'payments.example.com',
    'Example Intermediate CA',
    '100002',
    'EC',
    256,
    'ECDSA-SHA256',
    REPEAT('b', 64),
    NOW() - INTERVAL '30 days',
    NOW() + INTERVAL '15 days',
    'EXPIRING',
    TRUE,
    TRUE,
    TRUE
),
(
    3,
    'staging.example.com',
    'Example Intermediate CA',
    '100003',
    'RSA',
    2048,
    'SHA256withRSA',
    REPEAT('c', 64),
    NOW() - INTERVAL '10 days',
    NOW() + INTERVAL '200 days',
    'VALID',
    TRUE,
    TRUE,
    TRUE
);

INSERT INTO handshake_assessments (
    endpoint_id,
    certificate_id,
    cipher_id,
    negotiated_protocol,
    status,
    started_at,
    completed_at,
    duration_ms,
    certificate_verified,
    hostname_verified,
    transcript_verified
)
SELECT
    1,
    1,
    c.cipher_id,
    'TLS_1_3',
    'ESTABLISHED',
    NOW() - INTERVAL '10 minutes',
    NOW() - INTERVAL '9 minutes 59 seconds',
    32.5,
    TRUE,
    TRUE,
    TRUE
FROM cipher_suites c
WHERE c.cipher_name = 'TLS_AES_128_GCM_SHA256';

INSERT INTO handshake_assessments (
    endpoint_id,
    certificate_id,
    negotiated_protocol,
    status,
    started_at,
    completed_at,
    failure_code,
    failure_description
)
VALUES
(
    2,
    2,
    NULL,
    'FAILED',
    NOW() - INTERVAL '5 minutes',
    NOW() - INTERVAL '5 minutes',
    'CERTIFICATE_VALIDATION_FAILED',
    'Certificate validation failed during the TLS handshake.'
);

INSERT INTO handshake_assessments (
    endpoint_id,
    certificate_id,
    cipher_id,
    negotiated_protocol,
    status,
    started_at,
    completed_at,
    duration_ms,
    certificate_verified,
    hostname_verified,
    transcript_verified
)
SELECT
    3,
    3,
    c.cipher_id,
    'TLS_1_2',
    'ESTABLISHED',
    NOW() - INTERVAL '2 minutes',
    NOW() - INTERVAL '119 seconds',
    65.2,
    TRUE,
    TRUE,
    TRUE
FROM cipher_suites c
WHERE c.cipher_name =
    'ECDHE-RSA-AES128-GCM-SHA256';

INSERT INTO tls_sessions (
    endpoint_id,
    assessment_id,
    session_reference_hash,
    protocol,
    expires_at
)
VALUES
(
    1,
    1,
    REPEAT('d', 64),
    'TLS_1_3',
    NOW() + INTERVAL '1 hour'
);

INSERT INTO security_findings (
    endpoint_id,
    assessment_id,
    severity,
    finding_code,
    description
)
VALUES
(
    2,
    2,
    'HIGH',
    'CERTIFICATE_EXPIRING',
    'Production certificate expires within 30 days.'
),
(
    2,
    2,
    'HIGH',
    'HANDSHAKE_FAILURE',
    'TLS connection failed because certificate validation failed.'
);

COMMIT;

-- ============================================================
-- Operational queries
-- ============================================================

-- 1. Retrieve active endpoints and their expected protocol.

SELECT
    hostname,
    port,
    environment,
    expected_protocol
FROM tls_endpoints
WHERE status = 'ACTIVE'
ORDER BY hostname;

-- 2. Inspect approved and prohibited cipher suites.

SELECT
    cipher_name,
    protocol,
    encryption_algorithm,
    hash_algorithm,
    approved,
    forward_secrecy
FROM cipher_suites
ORDER BY protocol, approved DESC, cipher_name;

-- 3. Find certificate renewal candidates.

SELECT *
FROM v_certificate_expiry_report
WHERE days_remaining <= 30
ORDER BY days_remaining;

-- 4. Assess handshake success and failure.

SELECT
    e.hostname,
    h.status,
    h.negotiated_protocol,
    h.duration_ms,
    h.failure_code
FROM handshake_assessments h
JOIN tls_endpoints e
    ON e.endpoint_id = h.endpoint_id
ORDER BY h.started_at DESC;

-- 5. Evaluate successful handshake compliance.

SELECT
    h.assessment_id,
    e.hostname,
    h.negotiated_protocol,
    is_handshake_compliant(h.assessment_id) AS compliant
FROM handshake_assessments h
JOIN tls_endpoints e
    ON e.endpoint_id = h.endpoint_id;

-- 6. Aggregate cipher usage.

SELECT *
FROM v_cipher_usage
ORDER BY handshake_count DESC, cipher_name;

-- 7. Endpoint security posture.

SELECT *
FROM v_endpoint_tls_posture
ORDER BY failed_handshakes DESC;

-- 8. Find open critical and high-severity findings.

SELECT
    e.hostname,
    f.severity,
    f.finding_code,
    f.description,
    f.detected_at
FROM security_findings f
JOIN tls_endpoints e
    ON e.endpoint_id = f.endpoint_id
WHERE f.status = 'OPEN'
  AND f.severity IN ('HIGH', 'CRITICAL')
ORDER BY f.detected_at DESC;

-- 9. Find active sessions approaching expiration.

SELECT
    e.hostname,
    s.session_id,
    s.protocol,
    s.expires_at
FROM tls_sessions s
JOIN tls_endpoints e
    ON e.endpoint_id = s.endpoint_id
WHERE s.status = 'ACTIVE'
  AND s.expires_at <= NOW() + INTERVAL '15 minutes';

-- 10. Common table expression for endpoint compliance.

WITH latest_assessments AS (
    SELECT DISTINCT ON (endpoint_id)
        endpoint_id,
        assessment_id,
        status,
        negotiated_protocol,
        started_at
    FROM handshake_assessments
    ORDER BY endpoint_id, started_at DESC
)
SELECT
    e.hostname,
    l.status,
    l.negotiated_protocol,
    CASE
        WHEN l.status = 'ESTABLISHED'
         AND is_handshake_compliant(l.assessment_id)
        THEN 'COMPLIANT'
        ELSE 'NON_COMPLIANT'
    END AS security_status
FROM tls_endpoints e
LEFT JOIN latest_assessments l
    ON l.endpoint_id = e.endpoint_id;

-- 11. Find unapproved cipher suites that have been observed.
SELECT
    c.cipher_name,
    COUNT(*) AS observed_handshakes
FROM handshake_assessments h
JOIN cipher_suites c
    ON c.cipher_id = h.cipher_id
WHERE c.approved = FALSE
GROUP BY c.cipher_name;

-- 12. Certificate expiry status maintenance.
SELECT refresh_certificate_statuses();

-- 13. Create a renewal finding for an endpoint.
CALL create_certificate_renewal_finding(2);

-- 14. Revoke a session without exposing session secrets.
BEGIN;

UPDATE tls_sessions
SET
    status = 'REVOKED',
    revoked_at = NOW()
WHERE session_id = 1
  AND status = 'ACTIVE';

INSERT INTO tls_audit_events (
    entity_type,
    entity_id,
    event_type,
    event_description
)
VALUES (
    'SESSION',
    1,
    'SESSION_REVOKED',
    'Session reference revoked by security administration.'
);

COMMIT;

-- ============================================================
-- End of TLS governance database
-- ============================================================
