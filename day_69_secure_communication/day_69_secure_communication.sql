-- ============================================================
-- SECURE COMMUNICATIONS MANAGEMENT DATABASE
-- PostgreSQL 15+
--
-- Covers:
-- SSH, HTTPS, TLS, VPN, SFTP, endpoint governance,
-- connection lifecycle, security policies, file integrity,
-- transfer auditing, and operational reporting.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS secure_comms;

SET search_path TO secure_comms, public;

-- ------------------------------------------------------------
-- 1. Enumerated domain types
-- ------------------------------------------------------------

CREATE TYPE communication_protocol AS ENUM (
    'SSH',
    'HTTPS',
    'VPN',
    'SFTP'
);

CREATE TYPE connection_state AS ENUM (
    'DISCONNECTED',
    'CONNECTING',
    'CONNECTED',
    'FAILED'
);

CREATE TYPE transfer_state AS ENUM (
    'PENDING',
    'IN_PROGRESS',
    'COMPLETED',
    'FAILED',
    'REJECTED'
);

CREATE TYPE certificate_state AS ENUM (
    'VALID',
    'EXPIRED',
    'REVOKED',
    'PENDING'
);

CREATE TYPE vpn_state AS ENUM (
    'INACTIVE',
    'CONNECTING',
    'ACTIVE',
    'FAILED'
);

CREATE TYPE audit_severity AS ENUM (
    'INFO',
    'WARNING',
    'CRITICAL'
);

-- ------------------------------------------------------------
-- 2. Enterprise users and roles
-- ------------------------------------------------------------

CREATE TABLE communication_users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(80) NOT NULL UNIQUE,

    email VARCHAR(254) NOT NULL UNIQUE,

    role_name VARCHAR(30) NOT NULL
        CHECK (
            role_name IN (
                'ADMIN',
                'SECURITY_ENGINEER',
                'OPERATOR',
                'AUDITOR'
            )
        ),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------
-- 3. Security policies
-- ------------------------------------------------------------

CREATE TABLE security_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(120) NOT NULL UNIQUE,

    minimum_tls_version VARCHAR(10) NOT NULL
        CHECK (
            minimum_tls_version IN ('TLSv1.2', 'TLSv1.3')
        ),

    certificate_verification_required BOOLEAN NOT NULL DEFAULT TRUE,

    hostname_verification_required BOOLEAN NOT NULL DEFAULT TRUE,

    strict_ssh_host_checking BOOLEAN NOT NULL DEFAULT TRUE,

    agent_forwarding_allowed BOOLEAN NOT NULL DEFAULT FALSE,

    weak_algorithms_allowed BOOLEAN NOT NULL DEFAULT FALSE,

    maximum_transfer_bytes BIGINT NOT NULL
        CHECK (maximum_transfer_bytes > 0),

    require_vpn_for_private_networks BOOLEAN NOT NULL DEFAULT TRUE,

    direct_public_ssh_allowed BOOLEAN NOT NULL DEFAULT FALSE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (
        certificate_verification_required = TRUE
    ),

    CHECK (
        hostname_verification_required = TRUE
    ),

    CHECK (
        strict_ssh_host_checking = TRUE
    ),

    CHECK (
        weak_algorithms_allowed = FALSE
    ),

    CHECK (
        agent_forwarding_allowed = FALSE
    )
);

INSERT INTO security_policies (
    policy_name,
    minimum_tls_version,
    maximum_transfer_bytes,
    require_vpn_for_private_networks
)
VALUES (
    'Enterprise Default',
    'TLSv1.2',
    52428800,
    TRUE
);

-- ------------------------------------------------------------
-- 4. Approved communication endpoints
-- ------------------------------------------------------------

CREATE TABLE endpoints (
    endpoint_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_name VARCHAR(120) NOT NULL,

    hostname VARCHAR(253) NOT NULL,

    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),

    protocol communication_protocol NOT NULL,

    is_private BOOLEAN NOT NULL DEFAULT FALSE,

    approved BOOLEAN NOT NULL DEFAULT FALSE,

    policy_id BIGINT NOT NULL
        REFERENCES security_policies(policy_id),

    created_by BIGINT
        REFERENCES communication_users(user_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (hostname, port, protocol)
);

CREATE INDEX idx_endpoints_protocol_approved
ON endpoints(protocol, approved);

CREATE INDEX idx_endpoints_policy
ON endpoints(policy_id);

-- ------------------------------------------------------------
-- 5. TLS certificates
-- ------------------------------------------------------------

CREATE TABLE tls_certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,

    common_name VARCHAR(253) NOT NULL,

    issuer VARCHAR(253) NOT NULL,

    serial_number VARCHAR(128) NOT NULL UNIQUE,

    fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE
        CHECK (fingerprint_sha256 ~ '^[0-9a-fA-F]{64}$'),

    valid_from TIMESTAMPTZ NOT NULL,

    valid_until TIMESTAMPTZ NOT NULL,

    certificate_status certificate_state NOT NULL DEFAULT 'PENDING',

    last_verified_at TIMESTAMPTZ,

    CHECK (valid_until > valid_from)
);

CREATE INDEX idx_certificates_endpoint_status
ON tls_certificates(endpoint_id, certificate_status);

-- ------------------------------------------------------------
-- 6. SSH host keys
-- ------------------------------------------------------------

CREATE TABLE ssh_host_keys (
    host_key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,

    key_algorithm VARCHAR(30) NOT NULL
        CHECK (
            key_algorithm IN ('ED25519', 'ECDSA', 'RSA')
        ),

    fingerprint_sha256 VARCHAR(64) NOT NULL
        CHECK (fingerprint_sha256 ~ '^[0-9a-fA-F]{64}$'),

    verified BOOLEAN NOT NULL DEFAULT FALSE,

    verified_by BIGINT REFERENCES communication_users(user_id),

    verified_at TIMESTAMPTZ,

    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    UNIQUE(endpoint_id, fingerprint_sha256),

    CHECK (
        NOT verified OR
        (verified_by IS NOT NULL AND verified_at IS NOT NULL)
    )
);

CREATE INDEX idx_ssh_host_keys_endpoint
ON ssh_host_keys(endpoint_id, verified, revoked);

-- ------------------------------------------------------------
-- 7. VPN profiles and network routes
-- ------------------------------------------------------------

CREATE TABLE vpn_profiles (
    vpn_profile_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL UNIQUE
        REFERENCES endpoints(endpoint_id),

    vpn_protocol VARCHAR(20) NOT NULL
        CHECK (vpn_protocol IN ('WireGuard', 'IPsec')),

    interface_name VARCHAR(15) NOT NULL,

    tunnel_state vpn_state NOT NULL DEFAULT 'INACTIVE',

    encryption_required BOOLEAN NOT NULL DEFAULT TRUE,

    peer_public_key_fingerprint VARCHAR(64)
        CHECK (
            peer_public_key_fingerprint IS NULL OR
            peer_public_key_fingerprint ~ '^[0-9a-fA-F]{64}$'
        ),

    last_handshake_at TIMESTAMPTZ,

    CHECK (encryption_required = TRUE)
);

CREATE TABLE vpn_routes (
    route_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    vpn_profile_id BIGINT NOT NULL
        REFERENCES vpn_profiles(vpn_profile_id) ON DELETE CASCADE,

    destination_cidr CIDR NOT NULL,

    route_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE(vpn_profile_id, destination_cidr)
);

CREATE INDEX idx_vpn_routes_enabled
ON vpn_routes(vpn_profile_id)
WHERE route_enabled = TRUE;

-- ------------------------------------------------------------
-- 8. SSH identities
-- ------------------------------------------------------------

CREATE TABLE ssh_identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES communication_users(user_id),

    endpoint_id BIGINT NOT NULL
        REFERENCES endpoints(endpoint_id),

    public_key_fingerprint VARCHAR(64) NOT NULL
        CHECK (
            public_key_fingerprint ~ '^[0-9a-fA-F]{64}$'
        ),

    key_algorithm VARCHAR(30) NOT NULL
        CHECK (
            key_algorithm IN ('ED25519', 'ECDSA', 'RSA')
        ),

    identity_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(user_id, endpoint_id, public_key_fingerprint)
);

-- Private keys are deliberately not stored in this database.

-- ------------------------------------------------------------
-- 9. Communication sessions
-- ------------------------------------------------------------

CREATE TABLE communication_sessions (
    session_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    endpoint_id BIGINT NOT NULL
        REFERENCES endpoints(endpoint_id),

    user_id BIGINT NOT NULL
        REFERENCES communication_users(user_id),

    state connection_state NOT NULL DEFAULT 'DISCONNECTED',

    connected_at TIMESTAMPTZ,

    disconnected_at TIMESTAMPTZ,

    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (
        disconnected_at IS NULL OR connected_at IS NOT NULL
    )
);

CREATE INDEX idx_sessions_endpoint_state
ON communication_sessions(endpoint_id, state);

CREATE INDEX idx_sessions_user_created
ON communication_sessions(user_id, created_at DESC);

-- ------------------------------------------------------------
-- 10. State transition enforcement
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_session_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.state <> OLD.state THEN

        IF NOT (
            (OLD.state = 'DISCONNECTED' AND NEW.state = 'CONNECTING')
            OR
            (OLD.state = 'CONNECTING' AND NEW.state IN ('CONNECTED', 'FAILED'))
            OR
            (OLD.state = 'CONNECTED' AND NEW.state IN ('DISCONNECTED', 'FAILED'))
            OR
            (OLD.state = 'FAILED' AND NEW.state = 'DISCONNECTED')
        ) THEN
            RAISE EXCEPTION
                'Invalid session transition: % -> %',
                OLD.state,
                NEW.state;
        END IF;

    END IF;

    IF NEW.state = 'CONNECTED' AND
       NEW.connected_at IS NULL THEN
        NEW.connected_at := NOW();
    END IF;

    IF NEW.state = 'DISCONNECTED' AND
       OLD.state = 'CONNECTED' THEN
        NEW.disconnected_at := NOW();
    END IF;

    IF NEW.state = 'FAILED' AND
       NEW.failure_reason IS NULL THEN
        NEW.failure_reason := 'Connection failure recorded.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_session_transition
BEFORE UPDATE OF state
ON communication_sessions
FOR EACH ROW
EXECUTE FUNCTION validate_session_transition();

-- ------------------------------------------------------------
-- 11. Secure file transfers
-- ------------------------------------------------------------

CREATE TABLE file_transfers (
    transfer_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    source_endpoint_id BIGINT
        REFERENCES endpoints(endpoint_id),

    destination_endpoint_id BIGINT NOT NULL
        REFERENCES endpoints(endpoint_id),

    initiated_by BIGINT NOT NULL
        REFERENCES communication_users(user_id),

    file_name VARCHAR(255) NOT NULL,

    file_size_bytes BIGINT NOT NULL
        CHECK (file_size_bytes >= 0),

    sha256_hash VARCHAR(64) NOT NULL
        CHECK (sha256_hash ~ '^[0-9a-fA-F]{64}$'),

    transfer_protocol communication_protocol NOT NULL
        DEFAULT 'SFTP'
        CHECK (transfer_protocol = 'SFTP'),

    remote_path TEXT NOT NULL,

    state transfer_state NOT NULL DEFAULT 'PENDING',

    started_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (file_name <> ''),

    CHECK (remote_path LIKE '/%'),

    CHECK (
        completed_at IS NULL OR started_at IS NOT NULL
    )
);

CREATE INDEX idx_transfers_state_created
ON file_transfers(state, created_at DESC);

CREATE INDEX idx_transfers_destination
ON file_transfers(destination_endpoint_id, created_at DESC);

CREATE INDEX idx_transfers_user
ON file_transfers(initiated_by, created_at DESC);

-- ------------------------------------------------------------
-- 12. Transfer integrity verification
-- ------------------------------------------------------------

CREATE TABLE transfer_verifications (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    transfer_id BIGINT NOT NULL
        REFERENCES file_transfers(transfer_id) ON DELETE CASCADE,

    expected_sha256 VARCHAR(64) NOT NULL
        CHECK (expected_sha256 ~ '^[0-9a-fA-F]{64}$'),

    received_sha256 VARCHAR(64)
        CHECK (
            received_sha256 IS NULL OR
            received_sha256 ~ '^[0-9a-fA-F]{64}$'
        ),

    integrity_verified BOOLEAN NOT NULL DEFAULT FALSE,

    verified_at TIMESTAMPTZ,

    CHECK (
        NOT integrity_verified OR
        (
            received_sha256 IS NOT NULL
            AND LOWER(expected_sha256) = LOWER(received_sha256)
            AND verified_at IS NOT NULL
        )
    )
);

-- ------------------------------------------------------------
-- 13. Security audit events
-- ------------------------------------------------------------

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT REFERENCES communication_users(user_id),

    session_id BIGINT REFERENCES communication_sessions(session_id),

    transfer_id BIGINT REFERENCES file_transfers(transfer_id),

    event_type VARCHAR(80) NOT NULL,

    severity audit_severity NOT NULL DEFAULT 'INFO',

    event_description TEXT NOT NULL,

    source_ip INET,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_created
ON security_audit(created_at DESC);

CREATE INDEX idx_audit_severity
ON security_audit(severity, created_at DESC);

-- ------------------------------------------------------------
-- 14. Transfer eligibility function
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION evaluate_transfer_eligibility(
    p_user_id BIGINT,
    p_endpoint_id BIGINT,
    p_file_size BIGINT
)
RETURNS TABLE (
    eligible BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_user_active BOOLEAN;
    v_endpoint_approved BOOLEAN;
    v_protocol communication_protocol;
    v_policy_id BIGINT;
    v_max_size BIGINT;
    v_private BOOLEAN;
    v_vpn_required BOOLEAN;
BEGIN
    SELECT u.is_active
    INTO v_user_active
    FROM communication_users u
    WHERE u.user_id = p_user_id;

    IF NOT FOUND OR NOT v_user_active THEN
        RETURN QUERY
        SELECT FALSE, 'User is missing or inactive';
        RETURN;
    END IF;

    SELECT
        e.approved,
        e.protocol,
        e.policy_id,
        e.is_private,
        p.maximum_transfer_bytes,
        p.require_vpn_for_private_networks
    INTO
        v_endpoint_approved,
        v_protocol,
        v_policy_id,
        v_private,
        v_max_size,
        v_vpn_required
    FROM endpoints e
    JOIN security_policies p
        ON p.policy_id = e.policy_id
    WHERE e.endpoint_id = p_endpoint_id
      AND p.enabled = TRUE;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT FALSE, 'Endpoint or enabled policy does not exist';
        RETURN;
    END IF;

    IF NOT v_endpoint_approved THEN
        RETURN QUERY
        SELECT FALSE, 'Endpoint is not approved';
        RETURN;
    END IF;

    IF v_protocol <> 'SFTP' THEN
        RETURN QUERY
        SELECT FALSE, 'Destination does not support SFTP';
        RETURN;
    END IF;

    IF p_file_size < 0 OR p_file_size > v_max_size THEN
        RETURN QUERY
        SELECT FALSE, 'File size violates transfer policy';
        RETURN;
    END IF;

    IF v_private AND v_vpn_required AND NOT EXISTS (
        SELECT 1
        FROM endpoints vpn_endpoint
        JOIN vpn_profiles vp
            ON vp.endpoint_id = vpn_endpoint.endpoint_id
        WHERE vpn_endpoint.approved = TRUE
          AND vp.tunnel_state = 'ACTIVE'
    ) THEN
        RETURN QUERY
        SELECT FALSE, 'Active approved VPN tunnel is required';
        RETURN;
    END IF;

    RETURN QUERY
    SELECT TRUE, 'Transfer meets configured policy';
END;
$$;

-- ------------------------------------------------------------
-- 15. Transfer validation trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION enforce_transfer_policy()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_eligible BOOLEAN;
    v_reason TEXT;
BEGIN
    IF TG_OP = 'INSERT' OR
       (
           TG_OP = 'UPDATE'
           AND (
               NEW.state = 'IN_PROGRESS'
               OR NEW.state = 'COMPLETED'
           )
       ) THEN

        SELECT eligible, reason
        INTO v_eligible, v_reason
        FROM evaluate_transfer_eligibility(
            NEW.initiated_by,
            NEW.destination_endpoint_id,
            NEW.file_size_bytes
        );

        IF NOT v_eligible THEN
            RAISE EXCEPTION 'Transfer rejected: %', v_reason;
        END IF;

    END IF;

    IF NEW.state = 'IN_PROGRESS' AND NEW.started_at IS NULL THEN
        NEW.started_at := NOW();
    END IF;

    IF NEW.state = 'COMPLETED' AND NEW.completed_at IS NULL THEN
        NEW.completed_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_enforce_transfer_policy
BEFORE INSERT OR UPDATE OF state
ON file_transfers
FOR EACH ROW
EXECUTE FUNCTION enforce_transfer_policy();

-- ------------------------------------------------------------
-- 16. Audit trigger
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_session_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO security_audit (
            user_id,
            session_id,
            event_type,
            severity,
            event_description
        )
        VALUES (
            NEW.user_id,
            NEW.session_id,
            'SESSION_STATE_CHANGED',
            CASE
                WHEN NEW.state = 'FAILED' THEN 'WARNING'
                ELSE 'INFO'
            END,
            OLD.state::TEXT || ' -> ' || NEW.state::TEXT
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_session_changes
AFTER UPDATE OF state
ON communication_sessions
FOR EACH ROW
EXECUTE FUNCTION audit_session_changes();

-- ------------------------------------------------------------
-- 17. Enterprise monitoring views
-- ------------------------------------------------------------

CREATE VIEW active_communication_sessions AS
SELECT
    s.session_id,
    u.username,
    e.endpoint_name,
    e.hostname,
    e.port,
    e.protocol,
    s.state,
    s.connected_at
FROM communication_sessions s
JOIN communication_users u
    ON u.user_id = s.user_id
JOIN endpoints e
    ON e.endpoint_id = s.endpoint_id
WHERE s.state = 'CONNECTED';

CREATE VIEW expiring_tls_certificates AS
SELECT
    e.endpoint_name,
    e.hostname,
    c.common_name,
    c.valid_until,
    c.certificate_status,
    c.valid_until - NOW() AS remaining_validity
FROM tls_certificates c
JOIN endpoints e
    ON e.endpoint_id = c.endpoint_id
WHERE c.valid_until <= NOW() + INTERVAL '30 days'
  AND c.certificate_status = 'VALID';

CREATE VIEW transfer_reporting AS
SELECT
    u.username,
    e.endpoint_name,
    COUNT(*) AS total_transfers,
    COUNT(*) FILTER (
        WHERE f.state = 'COMPLETED'
    ) AS completed_transfers,
    COUNT(*) FILTER (
        WHERE f.state IN ('FAILED', 'REJECTED')
    ) AS unsuccessful_transfers,
    COALESCE(SUM(f.file_size_bytes), 0) AS total_bytes
FROM file_transfers f
JOIN communication_users u
    ON u.user_id = f.initiated_by
JOIN endpoints e
    ON e.endpoint_id = f.destination_endpoint_id
GROUP BY u.username, e.endpoint_name;

-- ------------------------------------------------------------
-- 18. Sample enterprise records
-- ------------------------------------------------------------

INSERT INTO communication_users (
    username,
    email,
    role_name
)
VALUES
    ('security_admin', 'admin@example.com', 'ADMIN'),
    ('network_engineer', 'network@example.com', 'SECURITY_ENGINEER'),
    ('transfer_operator', 'operator@example.com', 'OPERATOR'),
    ('security_auditor', 'auditor@example.com', 'AUDITOR');

INSERT INTO endpoints (
    endpoint_name,
    hostname,
    port,
    protocol,
    is_private,
    approved,
    policy_id,
    created_by
)
SELECT
    v.endpoint_name,
    v.hostname,
    v.port,
    v.protocol::communication_protocol,
    v.is_private,
    v.approved,
    p.policy_id,
    u.user_id
FROM (
    VALUES
        ('Public Web Service', 'example.com', 443, 'HTTPS', FALSE, TRUE),
        ('Enterprise SSH Server', 'ssh.example.com', 22, 'SSH', TRUE, TRUE),
        ('Enterprise SFTP Server', 'sftp.example.com', 22, 'SFTP', TRUE, TRUE),
        ('Corporate VPN Gateway', 'vpn.example.com', 51820, 'VPN', FALSE, TRUE),
        ('Unapproved Transfer Server', 'untrusted.example.com', 22, 'SFTP', TRUE, FALSE)
) AS v(endpoint_name, hostname, port, protocol, is_private, approved)
CROSS JOIN security_policies p
CROSS JOIN communication_users u
WHERE p.policy_name = 'Enterprise Default'
  AND u.username = 'security_admin';

INSERT INTO tls_certificates (
    endpoint_id,
    common_name,
    issuer,
    serial_number,
    fingerprint_sha256,
    valid_from,
    valid_until,
    certificate_status
)
SELECT
    endpoint_id,
    hostname,
    'Enterprise Trusted CA',
    'CERT-' || endpoint_id,
    repeat('a', 64),
    NOW() - INTERVAL '10 days',
    NOW() + INTERVAL '90 days',
    'VALID'
FROM endpoints
WHERE protocol = 'HTTPS';

INSERT INTO ssh_host_keys (
    endpoint_id,
    key_algorithm,
    fingerprint_sha256,
    verified,
    verified_by,
    verified_at
)
SELECT
    e.endpoint_id,
    'ED25519',
    repeat('b', 64),
    TRUE,
    u.user_id,
    NOW()
FROM endpoints e
CROSS JOIN communication_users u
WHERE e.protocol = 'SSH'
  AND u.username = 'security_admin';

INSERT INTO vpn_profiles (
    endpoint_id,
    vpn_protocol,
    interface_name,
    tunnel_state,
    encryption_required,
    peer_public_key_fingerprint
)
SELECT
    endpoint_id,
    'WireGuard',
    'wg0',
    'ACTIVE',
    TRUE,
    repeat('c', 64)
FROM endpoints
WHERE protocol = 'VPN';

INSERT INTO vpn_routes (
    vpn_profile_id,
    destination_cidr
)
SELECT
    vpn_profile_id,
    v.network::CIDR
FROM vpn_profiles
CROSS JOIN (
    VALUES
        ('10.20.0.0/16'),
        ('192.168.50.0/24')
) AS v(network);

INSERT INTO ssh_identities (
    user_id,
    endpoint_id,
    public_key_fingerprint,
    key_algorithm
)
SELECT
    u.user_id,
    e.endpoint_id,
    repeat('d', 64),
    'ED25519'
FROM communication_users u
JOIN endpoints e ON e.protocol = 'SFTP'
WHERE u.username = 'transfer_operator';

-- ------------------------------------------------------------
-- 19. Connection lifecycle sample
-- ------------------------------------------------------------

INSERT INTO communication_sessions (
    endpoint_id,
    user_id,
    state
)
SELECT
    e.endpoint_id,
    u.user_id,
    'DISCONNECTED'
FROM endpoints e
CROSS JOIN communication_users u
WHERE e.protocol = 'HTTPS'
  AND u.username = 'network_engineer';

UPDATE communication_sessions
SET state = 'CONNECTING'
WHERE state = 'DISCONNECTED';

UPDATE communication_sessions
SET state = 'CONNECTED'
WHERE state = 'CONNECTING';

UPDATE communication_sessions
SET state = 'DISCONNECTED'
WHERE state = 'CONNECTED';

-- ------------------------------------------------------------
-- 20. Successful SFTP transfer sample
-- ------------------------------------------------------------

INSERT INTO file_transfers (
    destination_endpoint_id,
    initiated_by,
    file_name,
    file_size_bytes,
    sha256_hash,
    remote_path,
    state
)
SELECT
    e.endpoint_id,
    u.user_id,
    'network-report.csv',
    10240,
    repeat('e', 64),
    '/incoming/network-report.csv',
    'PENDING'
FROM endpoints e
CROSS JOIN communication_users u
WHERE e.protocol = 'SFTP'
  AND e.approved = TRUE
  AND u.username = 'transfer_operator';

UPDATE file_transfers
SET state = 'IN_PROGRESS'
WHERE file_name = 'network-report.csv';

UPDATE file_transfers
SET state = 'COMPLETED'
WHERE file_name = 'network-report.csv';

INSERT INTO transfer_verifications (
    transfer_id,
    expected_sha256,
    received_sha256,
    integrity_verified,
    verified_at
)
SELECT
    transfer_id,
    sha256_hash,
    sha256_hash,
    TRUE,
    NOW()
FROM file_transfers
WHERE file_name = 'network-report.csv';

-- ------------------------------------------------------------
-- 21. Transactional failure demonstration
-- The invalid transfer is rolled back without damaging
-- the valid enterprise sample records.
-- ------------------------------------------------------------

DO $$
DECLARE
    v_endpoint_id BIGINT;
    v_user_id BIGINT;
BEGIN
    SELECT endpoint_id
    INTO v_endpoint_id
    FROM endpoints
    WHERE hostname = 'untrusted.example.com';

    SELECT user_id
    INTO v_user_id
    FROM communication_users
    WHERE username = 'transfer_operator';

    BEGIN
        INSERT INTO file_transfers (
            destination_endpoint_id,
            initiated_by,
            file_name,
            file_size_bytes,
            sha256_hash,
            remote_path
        )
        VALUES (
            v_endpoint_id,
            v_user_id,
            'unauthorized.dat',
            2048,
            repeat('f', 64),
            '/incoming/unauthorized.dat'
        );

        RAISE NOTICE 'Unexpected transfer acceptance.';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE 'Expected transfer rejection: %', SQLERRM;
    END;
END;
$$;

-- ------------------------------------------------------------
-- 22. Retrieval queries
-- ------------------------------------------------------------

SELECT
    endpoint_name,
    hostname,
    port,
    protocol,
    approved
FROM endpoints
ORDER BY protocol, endpoint_name;

SELECT
    username,
    role_name,
    is_active
FROM communication_users
ORDER BY username;

-- ------------------------------------------------------------
-- 23. Eligibility evaluation
-- ------------------------------------------------------------

SELECT
    e.endpoint_name,
    eligibility.eligible,
    eligibility.reason
FROM endpoints e
CROSS JOIN LATERAL evaluate_transfer_eligibility(
    (
        SELECT user_id
        FROM communication_users
        WHERE username = 'transfer_operator'
    ),
    e.endpoint_id,
    10240
) AS eligibility
WHERE e.protocol = 'SFTP'
ORDER BY e.endpoint_name;

-- ------------------------------------------------------------
-- 24. VPN and network reporting
-- ------------------------------------------------------------

SELECT
    e.endpoint_name,
    vp.vpn_protocol,
    vp.interface_name,
    vp.tunnel_state,
    vr.destination_cidr
FROM vpn_profiles vp
JOIN endpoints e
    ON e.endpoint_id = vp.endpoint_id
LEFT JOIN vpn_routes vr
    ON vr.vpn_profile_id = vp.vpn_profile_id
ORDER BY e.endpoint_name, vr.destination_cidr;

-- ------------------------------------------------------------
-- 25. Certificate health evaluation
-- ------------------------------------------------------------

SELECT
    endpoint_name,
    hostname,
    common_name,
    valid_until,
    CASE
        WHEN valid_until < NOW() THEN 'EXPIRED'
        WHEN valid_until < NOW() + INTERVAL '30 days' THEN 'EXPIRING'
        ELSE 'HEALTHY'
    END AS certificate_health
FROM expiring_tls_certificates;

-- ------------------------------------------------------------
-- 26. Transfer aggregation
-- ------------------------------------------------------------

SELECT *
FROM transfer_reporting
ORDER BY total_transfers DESC;

-- ------------------------------------------------------------
-- 27. CTE-based security monitoring
-- ------------------------------------------------------------

WITH endpoint_risk AS (
    SELECT
        e.endpoint_id,
        e.endpoint_name,
        e.protocol,
        e.approved,
        COUNT(s.session_id) FILTER (
            WHERE s.state = 'FAILED'
        ) AS failed_sessions,
        COUNT(s.session_id) FILTER (
            WHERE s.state = 'CONNECTED'
        ) AS active_sessions
    FROM endpoints e
    LEFT JOIN communication_sessions s
        ON s.endpoint_id = e.endpoint_id
    GROUP BY
        e.endpoint_id,
        e.endpoint_name,
        e.protocol,
        e.approved
)
SELECT
    endpoint_name,
    protocol,
    failed_sessions,
    active_sessions,
    CASE
        WHEN NOT approved THEN 'HIGH'
        WHEN failed_sessions >= 5 THEN 'HIGH'
        WHEN failed_sessions >= 2 THEN 'MEDIUM'
        ELSE 'LOW'
    END AS risk_level
FROM endpoint_risk
ORDER BY failed_sessions DESC, endpoint_name;

-- ------------------------------------------------------------
-- 28. Security audit report
-- ------------------------------------------------------------

SELECT
    audit_id,
    event_type,
    severity,
    event_description,
    created_at
FROM security_audit
ORDER BY created_at DESC;

-- ------------------------------------------------------------
-- 29. Operational stored procedure
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE disconnect_idle_sessions(
    p_idle_minutes INTEGER DEFAULT 60
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    IF p_idle_minutes <= 0 THEN
        RAISE EXCEPTION 'Idle minutes must be positive.';
    END IF;

    UPDATE communication_sessions
    SET
        state = 'DISCONNECTED',
        disconnected_at = NOW()
    WHERE state = 'CONNECTED'
      AND connected_at < NOW() - MAKE_INTERVAL(mins => p_idle_minutes);

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RAISE NOTICE 'Disconnected % idle sessions.', v_count;
END;
$$;

-- ------------------------------------------------------------
-- 30. Database integrity verification
-- ------------------------------------------------------------

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM endpoints e
        JOIN security_policies p
            ON p.policy_id = e.policy_id
        WHERE p.enabled = TRUE
          AND (
              p.certificate_verification_required = FALSE
              OR p.hostname_verification_required = FALSE
              OR p.strict_ssh_host_checking = FALSE
              OR p.weak_algorithms_allowed = TRUE
          )
    ) THEN
        RAISE EXCEPTION 'Insecure endpoint policy detected.';
    END IF;

    RAISE NOTICE 'Security policy integrity validation passed.';
END;
$$;

COMMIT;

-- ============================================================
-- END OF SECURE COMMUNICATIONS DATABASE
-- ============================================================
