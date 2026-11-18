-- ============================================================
-- ZERO TRUST SECURITY GOVERNANCE DATABASE
-- PostgreSQL 15+
--
-- Core principles:
-- 1. Verify explicitly.
-- 2. Enforce least privilege.
-- 3. Continuously evaluate access.
-- 4. Segment resources and networks.
-- 5. Deny access by default.
-- 6. Maintain security audit records.
--
-- This script models authorization decisions and session
-- governance. It does not implement cryptographic authentication,
-- an MFA provider, or an actual network enforcement gateway.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS zero_trust;

SET search_path TO zero_trust, public;

-- ============================================================
-- 1. DOMAIN TYPES
-- ============================================================

CREATE TYPE decision_type AS ENUM (
    'ALLOW',
    'DENY',
    'REVOKE'
);

CREATE TYPE trust_level AS ENUM (
    'UNTRUSTED',
    'VERIFIED',
    'HIGH'
);

CREATE TYPE resource_zone AS ENUM (
    'PUBLIC',
    'INTERNAL',
    'RESTRICTED',
    'CRITICAL'
);

CREATE TYPE session_state AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE access_action AS ENUM (
    'READ',
    'WRITE',
    'DELETE',
    'ADMIN'
);

-- ============================================================
-- 2. IDENTITY AND ROLE MANAGEMENT
-- ============================================================

CREATE TABLE identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(100) NOT NULL UNIQUE,

    email VARCHAR(255) NOT NULL UNIQUE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (username <> ''),
    CHECK (email <> '')
);

CREATE TABLE roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    role_name VARCHAR(80) NOT NULL UNIQUE,

    description TEXT NOT NULL DEFAULT '',

    CHECK (role_name <> '')
);

CREATE TABLE identity_roles (
    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id) ON DELETE CASCADE,

    role_id BIGINT NOT NULL
        REFERENCES roles(role_id) ON DELETE RESTRICT,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (identity_id, role_id)
);

-- ============================================================
-- 3. DEVICE INVENTORY AND POSTURE
-- ============================================================

CREATE TABLE devices (
    device_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    device_identifier VARCHAR(120) NOT NULL UNIQUE,

    owner_identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id) ON DELETE RESTRICT,

    managed BOOLEAN NOT NULL DEFAULT FALSE,

    encrypted BOOLEAN NOT NULL DEFAULT FALSE,

    patched BOOLEAN NOT NULL DEFAULT FALSE,

    endpoint_protected BOOLEAN NOT NULL DEFAULT FALSE,

    risk_score INTEGER NOT NULL DEFAULT 100,

    posture_version BIGINT NOT NULL DEFAULT 1,

    last_assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (risk_score BETWEEN 0 AND 100),

    CHECK (posture_version >= 1)
);

CREATE INDEX idx_devices_owner
    ON devices(owner_identity_id);

CREATE INDEX idx_devices_posture
    ON devices(risk_score, last_assessed_at);

-- ============================================================
-- 4. NETWORK SEGMENTATION
-- ============================================================

CREATE TABLE network_segments (
    segment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    segment_name VARCHAR(80) NOT NULL UNIQUE,

    zone resource_zone NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    description TEXT NOT NULL DEFAULT ''
);

-- ============================================================
-- 5. RESOURCE INVENTORY
-- ============================================================

CREATE TABLE resources (
    resource_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    resource_name VARCHAR(150) NOT NULL UNIQUE,

    zone resource_zone NOT NULL,

    network_segment_id BIGINT NOT NULL
        REFERENCES network_segments(segment_id) ON DELETE RESTRICT,

    minimum_trust trust_level NOT NULL DEFAULT 'VERIFIED',

    require_mfa BOOLEAN NOT NULL DEFAULT TRUE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_resources_zone
    ON resources(zone, enabled);

CREATE TABLE resource_role_permissions (
    resource_id BIGINT NOT NULL
        REFERENCES resources(resource_id) ON DELETE CASCADE,

    role_id BIGINT NOT NULL
        REFERENCES roles(role_id) ON DELETE RESTRICT,

    action access_action NOT NULL,

    PRIMARY KEY (resource_id, role_id, action)
);

CREATE INDEX idx_resource_permissions_role
    ON resource_role_permissions(role_id, resource_id);

-- ============================================================
-- 6. ZERO TRUST POLICY DEFINITIONS
-- ============================================================

CREATE TABLE access_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(120) NOT NULL UNIQUE,

    minimum_trust trust_level NOT NULL,

    maximum_device_risk INTEGER NOT NULL,

    maximum_context_risk INTEGER NOT NULL,

    require_mfa BOOLEAN NOT NULL DEFAULT TRUE,

    require_managed_device BOOLEAN NOT NULL DEFAULT TRUE,

    require_encryption BOOLEAN NOT NULL DEFAULT TRUE,

    require_patch_compliance BOOLEAN NOT NULL DEFAULT TRUE,

    require_endpoint_protection BOOLEAN NOT NULL DEFAULT TRUE,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (maximum_device_risk BETWEEN 0 AND 100),

    CHECK (maximum_context_risk BETWEEN 0 AND 100)
);

CREATE TABLE resource_policy_assignments (
    resource_id BIGINT NOT NULL
        REFERENCES resources(resource_id) ON DELETE CASCADE,

    policy_id BIGINT NOT NULL
        REFERENCES access_policies(policy_id) ON DELETE RESTRICT,

    PRIMARY KEY (resource_id, policy_id)
);

-- ============================================================
-- 7. ACCESS REQUESTS
-- ============================================================

CREATE TABLE access_requests (
    request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id) ON DELETE RESTRICT,

    device_id BIGINT NOT NULL
        REFERENCES devices(device_id) ON DELETE RESTRICT,

    resource_id BIGINT NOT NULL
        REFERENCES resources(resource_id) ON DELETE RESTRICT,

    requested_action access_action NOT NULL,

    source_ip INET NOT NULL,

    network_segment_id BIGINT NOT NULL
        REFERENCES network_segments(segment_id) ON DELETE RESTRICT,

    context_risk INTEGER NOT NULL,

    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (context_risk BETWEEN 0 AND 100)
);

CREATE INDEX idx_access_requests_identity_time
    ON access_requests(identity_id, requested_at DESC);

CREATE INDEX idx_access_requests_resource_time
    ON access_requests(resource_id, requested_at DESC);

-- ============================================================
-- 8. ACCESS DECISIONS
-- ============================================================

CREATE TABLE access_decisions (
    decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL UNIQUE
        REFERENCES access_requests(request_id) ON DELETE RESTRICT,

    decision decision_type NOT NULL,

    assessed_trust trust_level NOT NULL,

    reason TEXT NOT NULL,

    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (reason <> '')
);

CREATE INDEX idx_access_decisions_result
    ON access_decisions(decision, evaluated_at DESC);

-- ============================================================
-- 9. SESSION MANAGEMENT
-- ============================================================

CREATE TABLE security_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    request_id BIGINT NOT NULL UNIQUE
        REFERENCES access_requests(request_id) ON DELETE RESTRICT,

    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id) ON DELETE RESTRICT,

    device_id BIGINT NOT NULL
        REFERENCES devices(device_id) ON DELETE RESTRICT,

    resource_id BIGINT NOT NULL
        REFERENCES resources(resource_id) ON DELETE RESTRICT,

    device_posture_version BIGINT NOT NULL,

    state session_state NOT NULL DEFAULT 'ACTIVE',

    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    last_evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    revoked_at TIMESTAMPTZ,

    CHECK (expires_at > issued_at),

    CHECK (
        (state = 'REVOKED' AND revoked_at IS NOT NULL)
        OR
        (state <> 'REVOKED' AND revoked_at IS NULL)
    )
);

CREATE INDEX idx_sessions_active
    ON security_sessions(identity_id, expires_at)
    WHERE state = 'ACTIVE';

CREATE INDEX idx_sessions_resource
    ON security_sessions(resource_id, state);

CREATE INDEX idx_sessions_device
    ON security_sessions(device_id, state);

-- ============================================================
-- 10. AUDIT LOG
-- ============================================================

CREATE TABLE security_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    identity_id BIGINT
        REFERENCES identities(identity_id) ON DELETE SET NULL,

    request_id BIGINT
        REFERENCES access_requests(request_id) ON DELETE SET NULL,

    session_id UUID
        REFERENCES security_sessions(session_id) ON DELETE SET NULL,

    resource_id BIGINT
        REFERENCES resources(resource_id) ON DELETE SET NULL,

    decision decision_type NOT NULL,

    reason TEXT NOT NULL,

    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (reason <> '')
);

CREATE INDEX idx_audit_identity_time
    ON security_audit(identity_id, event_time DESC);

CREATE INDEX idx_audit_decision_time
    ON security_audit(decision, event_time DESC);

-- ============================================================
-- 11. DEVICE POSTURE VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION device_is_compliant(
    p_device_id BIGINT
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
AS $$
    SELECT COALESCE(
        managed
        AND encrypted
        AND patched
        AND endpoint_protected
        AND risk_score <= 30,
        FALSE
    )
    FROM devices
    WHERE device_id = p_device_id;
$$;

-- ============================================================
-- 12. TRUST EVALUATION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_device_trust(
    p_identity_id BIGINT,
    p_device_id BIGINT
)
RETURNS trust_level
LANGUAGE PLPGSQL
STABLE
AS $$
DECLARE
    v_device devices%ROWTYPE;
    v_identity identities%ROWTYPE;
BEGIN
    SELECT *
    INTO v_identity
    FROM identities
    WHERE identity_id = p_identity_id;

    SELECT *
    INTO v_device
    FROM devices
    WHERE device_id = p_device_id;

    IF NOT FOUND THEN
        RETURN 'UNTRUSTED';
    END IF;

    IF v_identity.identity_id IS NULL
       OR NOT v_identity.enabled
       OR v_device.owner_identity_id <> p_identity_id
       OR NOT device_is_compliant(p_device_id) THEN

        RETURN 'UNTRUSTED';
    END IF;

    IF v_identity.mfa_verified AND v_device.risk_score <= 10 THEN
        RETURN 'HIGH';
    END IF;

    RETURN 'VERIFIED';
END;
$$;

-- ============================================================
-- 13. CENTRAL ACCESS EVALUATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_access(
    p_identity_id BIGINT,
    p_device_id BIGINT,
    p_resource_id BIGINT,
    p_action access_action,
    p_network_segment_id BIGINT,
    p_context_risk INTEGER
)
RETURNS TABLE (
    allowed BOOLEAN,
    assessed_trust trust_level,
    reason TEXT
)
LANGUAGE PLPGSQL
AS $$
DECLARE
    v_identity identities%ROWTYPE;
    v_device devices%ROWTYPE;
    v_resource resources%ROWTYPE;
    v_segment network_segments%ROWTYPE;
    v_policy access_policies%ROWTYPE;

    v_trust trust_level;
    v_role_allowed BOOLEAN;
    v_action_allowed BOOLEAN;
BEGIN
    IF p_context_risk NOT BETWEEN 0 AND 100 THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Invalid context risk.';
        RETURN;
    END IF;

    SELECT *
    INTO v_identity
    FROM identities
    WHERE identity_id = p_identity_id;

    IF NOT FOUND OR NOT v_identity.enabled THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Identity is missing or disabled.';
        RETURN;
    END IF;

    SELECT *
    INTO v_device
    FROM devices
    WHERE device_id = p_device_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Device not found.';
        RETURN;
    END IF;

    IF v_device.owner_identity_id <> p_identity_id THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Device ownership mismatch.';
        RETURN;
    END IF;

    SELECT *
    INTO v_resource
    FROM resources
    WHERE resource_id = p_resource_id;

    IF NOT FOUND OR NOT v_resource.enabled THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Resource missing or disabled.';
        RETURN;
    END IF;

    SELECT *
    INTO v_segment
    FROM network_segments
    WHERE segment_id = p_network_segment_id;

    IF NOT FOUND OR NOT v_segment.enabled THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Network segment missing or disabled.';
        RETURN;
    END IF;

    -- Resource and network boundaries must agree.
    IF v_resource.network_segment_id <> p_network_segment_id THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Resource network segmentation mismatch.';
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM resource_role_permissions rp
        JOIN identity_roles ir
            ON ir.role_id = rp.role_id
        WHERE rp.resource_id = p_resource_id
          AND ir.identity_id = p_identity_id
          AND rp.action = p_action
    ) THEN
        RETURN QUERY SELECT
            FALSE,
            'UNTRUSTED'::trust_level,
            'Least-privilege permission denied.';
        RETURN;
    END IF;

    v_trust := evaluate_device_trust(
        p_identity_id,
        p_device_id
    );

    IF v_trust = 'UNTRUSTED' THEN
        RETURN QUERY SELECT
            FALSE,
            v_trust,
            'Device posture is noncompliant.';
        RETURN;
    END IF;

    IF v_resource.require_mfa AND NOT v_identity.mfa_verified THEN
        RETURN QUERY SELECT
            FALSE,
            v_trust,
            'MFA verification required.';
        RETURN;
    END IF;

    IF p_context_risk >= 80 THEN
        RETURN QUERY SELECT
            FALSE,
            v_trust,
            'Contextual risk threshold exceeded.';
        RETURN;
    END IF;

    -- Evaluate each assigned policy.
    FOR v_policy IN
        SELECT ap.*
        FROM access_policies ap
        JOIN resource_policy_assignments rpa
            ON rpa.policy_id = ap.policy_id
        WHERE rpa.resource_id = p_resource_id
          AND ap.enabled
    LOOP
        IF v_trust::TEXT = 'UNTRUSTED'
           OR (
               CASE v_trust
                   WHEN 'UNTRUSTED' THEN 0
                   WHEN 'VERIFIED' THEN 1
                   WHEN 'HIGH' THEN 2
               END
           ) < (
               CASE v_policy.minimum_trust
                   WHEN 'UNTRUSTED' THEN 0
                   WHEN 'VERIFIED' THEN 1
                   WHEN 'HIGH' THEN 2
               END
           ) THEN

            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Policy minimum trust requirement failed.';
            RETURN;
        END IF;

        IF v_device.risk_score > v_policy.maximum_device_risk
           OR p_context_risk > v_policy.maximum_context_risk THEN

            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Policy risk threshold exceeded.';
            RETURN;
        END IF;

        IF v_policy.require_mfa AND NOT v_identity.mfa_verified THEN
            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Policy requires MFA.';
            RETURN;
        END IF;

        IF v_policy.require_managed_device AND NOT v_device.managed THEN
            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Managed device required.';
            RETURN;
        END IF;

        IF v_policy.require_encryption AND NOT v_device.encrypted THEN
            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Device encryption required.';
            RETURN;
        END IF;

        IF v_policy.require_patch_compliance AND NOT v_device.patched THEN
            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Device patch compliance required.';
            RETURN;
        END IF;

        IF v_policy.require_endpoint_protection
           AND NOT v_device.endpoint_protected THEN

            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Endpoint protection required.';
            RETURN;
        END IF;
    END LOOP;

    IF v_resource.zone = 'RESTRICTED'
       AND v_segment.segment_name NOT IN ('CORPORATE', 'VPN') THEN

        RETURN QUERY SELECT
            FALSE,
            v_trust,
            'Restricted resource network violation.';
        RETURN;
    END IF;

    IF v_resource.zone = 'CRITICAL' THEN
        IF v_segment.segment_name <> 'CORPORATE'
           OR p_context_risk > 10
           OR v_trust <> 'HIGH' THEN

            RETURN QUERY SELECT
                FALSE,
                v_trust,
                'Critical resource policy failed.';
            RETURN;
        END IF;
    END IF;

    RETURN QUERY SELECT
        TRUE,
        v_trust,
        'All Zero Trust policies satisfied.';
END;
$$;

-- ============================================================
-- 14. AUDIT INSERTION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION write_security_audit(
    p_identity_id BIGINT,
    p_request_id BIGINT,
    p_session_id UUID,
    p_resource_id BIGINT,
    p_decision decision_type,
    p_reason TEXT
)
RETURNS BIGINT
LANGUAGE PLPGSQL
AS $$
DECLARE
    v_audit_id BIGINT;
BEGIN
    INSERT INTO security_audit (
        identity_id,
        request_id,
        session_id,
        resource_id,
        decision,
        reason
    )
    VALUES (
        p_identity_id,
        p_request_id,
        p_session_id,
        p_resource_id,
        p_decision,
        p_reason
    )
    RETURNING audit_id INTO v_audit_id;

    RETURN v_audit_id;
END;
$$;

-- ============================================================
-- 15. ACCESS REQUEST PROCESSING PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE process_access_request(
    p_request_id BIGINT
)
LANGUAGE PLPGSQL
AS $$
DECLARE
    v_request access_requests%ROWTYPE;
    v_allowed BOOLEAN;
    v_trust trust_level;
    v_reason TEXT;
    v_decision decision_type;
    v_session_id UUID;
BEGIN
    SELECT *
    INTO v_request
    FROM access_requests
    WHERE request_id = p_request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Access request % not found.', p_request_id;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM access_decisions
        WHERE request_id = p_request_id
    ) THEN
        RAISE EXCEPTION
            'Request % has already been evaluated.',
            p_request_id;
    END IF;

    SELECT e.allowed, e.assessed_trust, e.reason
    INTO v_allowed, v_trust, v_reason
    FROM evaluate_access(
        v_request.identity_id,
        v_request.device_id,
        v_request.resource_id,
        v_request.requested_action,
        v_request.network_segment_id,
        v_request.context_risk
    ) AS e;

    v_decision := CASE
        WHEN v_allowed THEN 'ALLOW'::decision_type
        ELSE 'DENY'::decision_type
    END;

    INSERT INTO access_decisions (
        request_id,
        decision,
        assessed_trust,
        reason
    )
    VALUES (
        p_request_id,
        v_decision,
        v_trust,
        v_reason
    );

    IF v_allowed THEN
        INSERT INTO security_sessions (
            request_id,
            identity_id,
            device_id,
            resource_id,
            device_posture_version,
            state,
            issued_at,
            expires_at
        )
        VALUES (
            p_request_id,
            v_request.identity_id,
            v_request.device_id,
            v_request.resource_id,
            (
                SELECT posture_version
                FROM devices
                WHERE device_id = v_request.device_id
            ),
            'ACTIVE',
            NOW(),
            NOW() + INTERVAL '15 minutes'
        )
        RETURNING session_id INTO v_session_id;
    END IF;

    PERFORM write_security_audit(
        v_request.identity_id,
        p_request_id,
        v_session_id,
        v_request.resource_id,
        v_decision,
        v_reason
    );
END;
$$;

-- ============================================================
-- 16. SESSION CONTINUOUS EVALUATION
-- ============================================================

CREATE OR REPLACE FUNCTION reevaluate_session(
    p_session_id UUID,
    p_context_risk INTEGER,
    p_network_segment_id BIGINT
)
RETURNS decision_type
LANGUAGE PLPGSQL
AS $$
DECLARE
    v_session security_sessions%ROWTYPE;
    v_request access_requests%ROWTYPE;

    v_allowed BOOLEAN;
    v_trust trust_level;
    v_reason TEXT;

    v_decision decision_type;
BEGIN
    IF p_context_risk NOT BETWEEN 0 AND 100 THEN
        RAISE EXCEPTION 'Invalid contextual risk.';
    END IF;

    SELECT *
    INTO v_session
    FROM security_sessions
    WHERE session_id = p_session_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown session.';
    END IF;

    IF v_session.state <> 'ACTIVE' THEN
        RETURN 'REVOKE';
    END IF;

    IF NOW() >= v_session.expires_at THEN
        UPDATE security_sessions
        SET state = 'EXPIRED',
            last_evaluated_at = NOW()
        WHERE session_id = p_session_id;

        PERFORM write_security_audit(
            v_session.identity_id,
            v_session.request_id,
            p_session_id,
            v_session.resource_id,
            'REVOKE',
            'Session expired.'
        );

        RETURN 'REVOKE';
    END IF;

    SELECT *
    INTO v_request
    FROM access_requests
    WHERE request_id = v_session.request_id;

    SELECT e.allowed, e.assessed_trust, e.reason
    INTO v_allowed, v_trust, v_reason
    FROM evaluate_access(
        v_session.identity_id,
        v_session.device_id,
        v_session.resource_id,
        v_request.requested_action,
        p_network_segment_id,
        p_context_risk
    ) AS e;

    IF NOT v_allowed OR
       v_session.device_posture_version <> (
           SELECT posture_version
           FROM devices
           WHERE device_id = v_session.device_id
       ) THEN

        UPDATE security_sessions
        SET state = 'REVOKED',
            revoked_at = NOW(),
            last_evaluated_at = NOW()
        WHERE session_id = p_session_id;

        v_decision := 'REVOKE';

        IF v_allowed THEN
            v_reason := 'Device posture changed.';
        END IF;

    ELSE
        UPDATE security_sessions
        SET last_evaluated_at = NOW()
        WHERE session_id = p_session_id;

        v_decision := 'ALLOW';
        v_reason := 'Continuous verification passed.';
    END IF;

    PERFORM write_security_audit(
        v_session.identity_id,
        v_session.request_id,
        p_session_id,
        v_session.resource_id,
        v_decision,
        v_reason
    );

    RETURN v_decision;
END;
$$;

-- ============================================================
-- 17. AUTOMATIC SESSION REVOCATION ON DEVICE POSTURE CHANGE
-- ============================================================

CREATE OR REPLACE FUNCTION revoke_sessions_on_posture_change()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
BEGIN
    IF (
        OLD.managed,
        OLD.encrypted,
        OLD.patched,
        OLD.endpoint_protected,
        OLD.risk_score
    ) IS DISTINCT FROM (
        NEW.managed,
        NEW.encrypted,
        NEW.patched,
        NEW.endpoint_protected,
        NEW.risk_score
    ) THEN

        NEW.posture_version := OLD.posture_version + 1;
        NEW.last_assessed_at := NOW();

        UPDATE security_sessions
        SET state = 'REVOKED',
            revoked_at = NOW(),
            last_evaluated_at = NOW()
        WHERE device_id = NEW.device_id
          AND state = 'ACTIVE';

        INSERT INTO security_audit (
            identity_id,
            resource_id,
            decision,
            reason
        )
        VALUES (
            NEW.owner_identity_id,
            NULL,
            'REVOKE',
            'Device posture changed; active sessions invalidated.'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_device_posture_session_revocation
BEFORE UPDATE OF
    managed,
    encrypted,
    patched,
    endpoint_protected,
    risk_score
ON devices
FOR EACH ROW
EXECUTE FUNCTION revoke_sessions_on_posture_change();

-- ============================================================
-- 18. EXPIRED SESSION MAINTENANCE
-- ============================================================

CREATE OR REPLACE PROCEDURE expire_sessions()
LANGUAGE PLPGSQL
AS $$
BEGIN
    UPDATE security_sessions
    SET state = 'EXPIRED',
        last_evaluated_at = NOW()
    WHERE state = 'ACTIVE'
      AND expires_at <= NOW();
END;
$$;

-- ============================================================
-- 19. AUDIT PROTECTION
-- ============================================================

CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
BEGIN
    RAISE EXCEPTION
        'Security audit records cannot be modified or deleted.';
END;
$$;

CREATE TRIGGER trg_prevent_audit_update
BEFORE UPDATE OR DELETE ON security_audit
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_mutation();

-- ============================================================
-- 20. OPERATIONAL VIEWS
-- ============================================================

CREATE VIEW active_session_report AS
SELECT
    s.session_id,
    i.username,
    d.device_identifier,
    r.resource_name,
    r.zone,
    s.issued_at,
    s.expires_at,
    s.last_evaluated_at,
    d.risk_score,
    d.posture_version
FROM security_sessions s
JOIN identities i
    ON i.identity_id = s.identity_id
JOIN devices d
    ON d.device_id = s.device_id
JOIN resources r
    ON r.resource_id = s.resource_id
WHERE s.state = 'ACTIVE'
  AND s.expires_at > NOW();

CREATE VIEW security_decision_summary AS
SELECT
    decision,
    COUNT(*) AS total_events,
    MAX(event_time) AS latest_event
FROM security_audit
GROUP BY decision;

CREATE VIEW resource_access_summary AS
SELECT
    r.resource_name,
    r.zone,
    COUNT(a.audit_id) AS total_requests,
    COUNT(a.audit_id) FILTER (
        WHERE a.decision = 'ALLOW'
    ) AS allowed_requests,
    COUNT(a.audit_id) FILTER (
        WHERE a.decision = 'DENY'
    ) AS denied_requests,
    COUNT(a.audit_id) FILTER (
        WHERE a.decision = 'REVOKE'
    ) AS revoked_sessions
FROM resources r
LEFT JOIN security_audit a
    ON a.resource_id = r.resource_id
GROUP BY r.resource_id, r.resource_name, r.zone;

-- ============================================================
-- 21. SAMPLE ROLES
-- ============================================================

INSERT INTO roles (role_name, description)
VALUES
    ('SECURITY_ANALYST', 'Read-only security monitoring access'),
    ('SECURITY_ADMIN', 'Restricted security administration'),
    ('DATABASE_ADMIN', 'Database administration'),
    ('EMPLOYEE', 'Standard employee access');

-- ============================================================
-- 22. SAMPLE IDENTITIES
-- ============================================================

INSERT INTO identities (
    username,
    email,
    enabled,
    mfa_verified
)
VALUES
    ('analyst_01', 'analyst@example.com', TRUE, TRUE),
    ('admin_01', 'admin@example.com', TRUE, TRUE),
    ('employee_01', 'employee@example.com', TRUE, FALSE),
    ('disabled_01', 'disabled@example.com', FALSE, TRUE);

INSERT INTO identity_roles (identity_id, role_id)
SELECT i.identity_id, r.role_id
FROM (
    VALUES
        ('analyst_01', 'SECURITY_ANALYST'),
        ('admin_01', 'SECURITY_ADMIN'),
        ('employee_01', 'EMPLOYEE'),
        ('disabled_01', 'SECURITY_ANALYST')
) AS mapping(username, role_name)
JOIN identities i
    ON i.username = mapping.username
JOIN roles r
    ON r.role_name = mapping.role_name;

-- ============================================================
-- 23. SAMPLE NETWORK SEGMENTS
-- ============================================================

INSERT INTO network_segments (
    segment_name,
    zone,
    description
)
VALUES
    ('PUBLIC', 'PUBLIC', 'Untrusted external network'),
    ('INTERNAL', 'INTERNAL', 'Internal business network'),
    ('VPN', 'RESTRICTED', 'Authenticated remote access'),
    ('CORPORATE', 'CRITICAL', 'Controlled corporate network');

-- ============================================================
-- 24. SAMPLE DEVICES
-- ============================================================

INSERT INTO devices (
    device_identifier,
    owner_identity_id,
    managed,
    encrypted,
    patched,
    endpoint_protected,
    risk_score
)
SELECT
    v.device_identifier,
    i.identity_id,
    v.managed,
    v.encrypted,
    v.patched,
    v.endpoint_protected,
    v.risk_score
FROM (
    VALUES
        ('ANALYST-LAPTOP', 'analyst_01', TRUE, TRUE, TRUE, TRUE, 5),
        ('ADMIN-WORKSTATION', 'admin_01', TRUE, TRUE, TRUE, TRUE, 3),
        ('EMPLOYEE-BYOD', 'employee_01', FALSE, FALSE, TRUE, FALSE, 65),
        ('DISABLED-DEVICE', 'disabled_01', TRUE, TRUE, TRUE, TRUE, 5)
) AS v(
    device_identifier,
    username,
    managed,
    encrypted,
    patched,
    endpoint_protected,
    risk_score
)
JOIN identities i
    ON i.username = v.username;

-- ============================================================
-- 25. SAMPLE RESOURCES
-- ============================================================

INSERT INTO resources (
    resource_name,
    zone,
    network_segment_id,
    minimum_trust,
    require_mfa
)
SELECT
    v.resource_name,
    v.zone::resource_zone,
    n.segment_id,
    v.minimum_trust::trust_level,
    v.require_mfa
FROM (
    VALUES
        (
            'Security Dashboard',
            'RESTRICTED',
            'VPN',
            'VERIFIED',
            TRUE
        ),
        (
            'Production Control Plane',
            'CRITICAL',
            'CORPORATE',
            'HIGH',
            TRUE
        ),
        (
            'Employee Portal',
            'INTERNAL',
            'INTERNAL',
            'VERIFIED',
            FALSE
        )
) AS v(
    resource_name,
    zone,
    segment_name,
    minimum_trust,
    require_mfa
)
JOIN network_segments n
    ON n.segment_name = v.segment_name;

-- ============================================================
-- 26. LEAST-PRIVILEGE PERMISSIONS
-- ============================================================

INSERT INTO resource_role_permissions (
    resource_id,
    role_id,
    action
)
SELECT r.resource_id, role.role_id, permission.action
FROM (
    VALUES
        ('Security Dashboard', 'SECURITY_ANALYST', 'READ'),
        ('Production Control Plane', 'SECURITY_ADMIN', 'ADMIN'),
        ('Employee Portal', 'EMPLOYEE', 'READ')
) AS permission(resource_name, role_name, action)
JOIN resources r
    ON r.resource_name = permission.resource_name
JOIN roles role
    ON role.role_name = permission.role_name;

-- ============================================================
-- 27. SAMPLE ACCESS POLICIES
-- ============================================================

INSERT INTO access_policies (
    policy_name,
    minimum_trust,
    maximum_device_risk,
    maximum_context_risk,
    require_mfa,
    require_managed_device,
    require_encryption,
    require_patch_compliance,
    require_endpoint_protection
)
VALUES
(
    'Restricted Resource Policy',
    'VERIFIED',
    30,
    50,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE
),
(
    'Critical Resource Policy',
    'HIGH',
    10,
    10,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE
),
(
    'Employee Portal Policy',
    'VERIFIED',
    30,
    60,
    FALSE,
    TRUE,
    TRUE,
    TRUE,
    TRUE
);

INSERT INTO resource_policy_assignments (
    resource_id,
    policy_id
)
SELECT r.resource_id, p.policy_id
FROM (
    VALUES
        ('Security Dashboard', 'Restricted Resource Policy'),
        ('Production Control Plane', 'Critical Resource Policy'),
        ('Employee Portal', 'Employee Portal Policy')
) AS mapping(resource_name, policy_name)
JOIN resources r
    ON r.resource_name = mapping.resource_name
JOIN access_policies p
    ON p.policy_name = mapping.policy_name;

-- ============================================================
-- 28. SAMPLE ACCESS REQUESTS
-- ============================================================

INSERT INTO access_requests (
    identity_id,
    device_id,
    resource_id,
    requested_action,
    source_ip,
    network_segment_id,
    context_risk
)
SELECT
    i.identity_id,
    d.device_id,
    r.resource_id,
    v.requested_action::access_action,
    v.source_ip::inet,
    n.segment_id,
    v.context_risk
FROM (
    VALUES
        (
            'analyst_01',
            'ANALYST-LAPTOP',
            'Security Dashboard',
            'READ',
            '10.10.0.25',
            'VPN',
            5
        ),
        (
            'analyst_01',
            'ANALYST-LAPTOP',
            'Security Dashboard',
            'DELETE',
            '10.10.0.25',
            'VPN',
            5
        ),
        (
            'employee_01',
            'EMPLOYEE-BYOD',
            'Security Dashboard',
            'READ',
            '10.10.0.45',
            'VPN',
            20
        ),
        (
            'disabled_01',
            'DISABLED-DEVICE',
            'Security Dashboard',
            'READ',
            '10.10.0.55',
            'VPN',
            5
        ),
        (
            'admin_01',
            'ADMIN-WORKSTATION',
            'Production Control Plane',
            'ADMIN',
            '10.20.0.10',
            'CORPORATE',
            5
        )
) AS v(
    username,
    device_identifier,
    resource_name,
    requested_action,
    source_ip,
    segment_name,
    context_risk
)
JOIN identities i
    ON i.username = v.username
JOIN devices d
    ON d.device_identifier = v.device_identifier
JOIN resources r
    ON r.resource_name = v.resource_name
JOIN network_segments n
    ON n.segment_name = v.segment_name;

-- ============================================================
-- 29. PROCESS REQUESTS TRANSACTIONALLY
-- ============================================================

DO $$
DECLARE
    v_request RECORD;
BEGIN
    FOR v_request IN
        SELECT request_id
        FROM access_requests
        ORDER BY request_id
    LOOP
        CALL process_access_request(v_request.request_id);
    END LOOP;
END;
$$;

-- ============================================================
-- 30. RETRIEVAL QUERIES
-- ============================================================

-- All identity roles.
SELECT
    i.username,
    r.role_name,
    i.enabled,
    i.mfa_verified
FROM identities i
JOIN identity_roles ir
    ON ir.identity_id = i.identity_id
JOIN roles r
    ON r.role_id = ir.role_id
ORDER BY i.username, r.role_name;

-- Device posture.
SELECT
    device_identifier,
    managed,
    encrypted,
    patched,
    endpoint_protected,
    risk_score,
    device_is_compliant(device_id) AS compliant
FROM devices
ORDER BY device_identifier;

-- ============================================================
-- 31. VALIDATION QUERIES
-- ============================================================

-- Requests and their authorization outcomes.
SELECT
    ar.request_id,
    i.username,
    r.resource_name,
    ar.requested_action,
    ad.decision,
    ad.assessed_trust,
    ad.reason
FROM access_requests ar
JOIN identities i
    ON i.identity_id = ar.identity_id
JOIN resources r
    ON r.resource_id = ar.resource_id
LEFT JOIN access_decisions ad
    ON ad.request_id = ar.request_id
ORDER BY ar.request_id;

-- ============================================================
-- 32. AGGREGATION QUERIES
-- ============================================================

SELECT
    decision,
    COUNT(*) AS total_decisions
FROM access_decisions
GROUP BY decision
ORDER BY decision;

SELECT
    r.zone,
    COUNT(ad.decision_id) AS total_decisions,
    COUNT(*) FILTER (
        WHERE ad.decision = 'ALLOW'
    ) AS allowed,
    COUNT(*) FILTER (
        WHERE ad.decision = 'DENY'
    ) AS denied
FROM resources r
LEFT JOIN access_requests ar
    ON ar.resource_id = r.resource_id
LEFT JOIN access_decisions ad
    ON ad.request_id = ar.request_id
GROUP BY r.zone
ORDER BY r.zone;

-- ============================================================
-- 33. ELIGIBILITY DETERMINATION
-- ============================================================

SELECT
    ar.request_id,
    i.username,
    r.resource_name,
    evaluate_device_trust(
        ar.identity_id,
        ar.device_id
    ) AS device_trust,
    ad.decision,
    CASE
        WHEN ad.decision = 'ALLOW' THEN TRUE
        ELSE FALSE
    END AS eligible_at_evaluation
FROM access_requests ar
JOIN identities i
    ON i.identity_id = ar.identity_id
JOIN resources r
    ON r.resource_id = ar.resource_id
JOIN access_decisions ad
    ON ad.request_id = ar.request_id
ORDER BY ar.request_id;

-- ============================================================
-- 34. CONTINUOUS EVALUATION DEMONSTRATION
-- ============================================================

-- Obtain an active analyst session.
SELECT *
FROM active_session_report;

-- Simulate a device risk increase.
-- The trigger automatically revokes existing active sessions.
UPDATE devices
SET risk_score = 95
WHERE device_identifier = 'ANALYST-LAPTOP';

-- Confirm device posture and session revocation.
SELECT
    device_identifier,
    risk_score,
    posture_version,
    device_is_compliant(device_id) AS compliant
FROM devices
WHERE device_identifier = 'ANALYST-LAPTOP';

SELECT
    session_id,
    state,
    revoked_at
FROM security_sessions
WHERE device_id = (
    SELECT device_id
    FROM devices
    WHERE device_identifier = 'ANALYST-LAPTOP'
);

-- ============================================================
-- 35. SESSION EXPIRATION WORKFLOW
-- ============================================================

CALL expire_sessions();

SELECT
    state,
    COUNT(*) AS total_sessions
FROM security_sessions
GROUP BY state
ORDER BY state;

-- ============================================================
-- 36. AUDIT REPORTING
-- ============================================================

SELECT
    audit_id,
    identity_id,
    resource_id,
    decision,
    reason,
    event_time
FROM security_audit
ORDER BY event_time DESC, audit_id DESC;

SELECT *
FROM security_decision_summary;

SELECT *
FROM resource_access_summary
ORDER BY resource_name;

-- ============================================================
-- 37. OPERATIONAL VALIDATION
-- ============================================================

DO $$
DECLARE
    v_allowed BIGINT;
    v_denied BIGINT;
BEGIN
    SELECT COUNT(*)
    INTO v_allowed
    FROM access_decisions
    WHERE decision = 'ALLOW';

    SELECT COUNT(*)
    INTO v_denied
    FROM access_decisions
    WHERE decision = 'DENY';

    IF v_allowed < 1 THEN
        RAISE EXCEPTION 'Expected at least one permitted request.';
    END IF;

    IF v_denied < 1 THEN
        RAISE EXCEPTION 'Expected at least one denied request.';
    END IF;

    RAISE NOTICE
        'Validation passed. Allowed: %, Denied: %',
        v_allowed,
        v_denied;
END;
$$;

-- ============================================================
-- 38. TRANSACTION COMPLETION
-- ============================================================

COMMIT;
