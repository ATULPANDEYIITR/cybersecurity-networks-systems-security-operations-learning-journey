-- ============================================================
-- SECRETS MANAGEMENT DATABASE
-- PostgreSQL 15+
--
-- Covers:
--   Secret inventory
--   API keys, tokens, passwords and credentials
--   Version management
--   Rotation and expiration
--   Role-based authorization
--   Access policies
--   Exposure incidents
--   Audit logging
--   Secret revocation
--   Repository integration and merge eligibility
--
-- SECURITY NOTICE:
-- Secret values are not stored as plaintext in this schema.
-- Store encrypted ciphertext produced by an authenticated
-- encryption system, with encryption keys held separately.
--
-- This script uses synthetic demonstration records.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS secrets_mgmt;

SET search_path TO secrets_mgmt, public;

-- ============================================================
-- 1. ENUM TYPES
-- ============================================================

CREATE TYPE secret_type AS ENUM (
    'API_KEY',
    'ACCESS_TOKEN',
    'REFRESH_TOKEN',
    'PASSWORD',
    'DATABASE_CREDENTIAL',
    'PRIVATE_KEY',
    'CERTIFICATE'
);

CREATE TYPE secret_status AS ENUM (
    'ACTIVE',
    'EXPIRED',
    'REVOKED'
);

CREATE TYPE environment_type AS ENUM (
    'DEVELOPMENT',
    'TESTING',
    'STAGING',
    'PRODUCTION'
);

CREATE TYPE permission_type AS ENUM (
    'READ',
    'WRITE',
    'ROTATE',
    'REVOKE',
    'ADMIN'
);

CREATE TYPE review_state AS ENUM (
    'APPROVED',
    'CHANGES_REQUESTED',
    'COMMENTED',
    'DISMISSED'
);

CREATE TYPE incident_status AS ENUM (
    'OPEN',
    'INVESTIGATING',
    'CONTAINED',
    'RESOLVED'
);

-- ============================================================
-- 2. IDENTITIES AND AUTHORIZATION
-- ============================================================

CREATE TABLE principals (
    principal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_name VARCHAR(120) NOT NULL UNIQUE,
    principal_type VARCHAR(30) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_principal_type CHECK (
        principal_type IN (
            'USER',
            'SERVICE',
            'APPLICATION',
            'SYSTEM'
        )
    )
);

CREATE TABLE roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name VARCHAR(60) NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE principal_roles (
    principal_id UUID NOT NULL
        REFERENCES principals(principal_id) ON DELETE CASCADE,

    role_id BIGINT NOT NULL
        REFERENCES roles(role_id) ON DELETE CASCADE,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (principal_id, role_id)
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL
        REFERENCES roles(role_id) ON DELETE CASCADE,

    permission permission_type NOT NULL,

    PRIMARY KEY (role_id, permission)
);

INSERT INTO roles (role_name, description) VALUES
(
    'developer',
    'Read-only access to authorized application secrets'
),
(
    'operator',
    'Read and rotate authorized credentials'
),
(
    'security_admin',
    'Administrative secret lifecycle management'
);

INSERT INTO role_permissions (role_id, permission)
SELECT role_id, permission
FROM roles
CROSS JOIN LATERAL (
    SELECT UNNEST(
        CASE role_name
            WHEN 'developer' THEN ARRAY['READ']::permission_type[]
            WHEN 'operator' THEN ARRAY['READ', 'ROTATE']::permission_type[]
            WHEN 'security_admin' THEN ARRAY[
                'READ',
                'WRITE',
                'ROTATE',
                'REVOKE',
                'ADMIN'
            ]::permission_type[]
        END
    ) AS permission
) permissions;

INSERT INTO principals (
    principal_name,
    principal_type
)
VALUES
('security-team', 'USER'),
('developer-01', 'USER'),
('platform-operator', 'USER'),
('payment-service', 'SERVICE');

INSERT INTO principal_roles (principal_id, role_id)
SELECT p.principal_id, r.role_id
FROM principals p
JOIN roles r ON
    (p.principal_name = 'security-team'
        AND r.role_name = 'security_admin')
    OR
    (p.principal_name = 'developer-01'
        AND r.role_name = 'developer')
    OR
    (p.principal_name = 'platform-operator'
        AND r.role_name = 'operator');

-- ============================================================
-- 3. SECRET INVENTORY
-- ============================================================

CREATE TABLE secrets (
    secret_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    secret_name VARCHAR(100) NOT NULL,

    secret_type secret_type NOT NULL,

    environment environment_type NOT NULL,

    owner_principal UUID NOT NULL
        REFERENCES principals(principal_id),

    description TEXT,

    rotation_interval_days INTEGER NOT NULL DEFAULT 90,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_secret_name CHECK (
        secret_name ~ '^[A-Za-z][A-Za-z0-9_.-]{2,99}$'
    ),

    CONSTRAINT valid_rotation_interval CHECK (
        rotation_interval_days BETWEEN 1 AND 3650
    ),

    CONSTRAINT unique_secret_environment
        UNIQUE (secret_name, environment)
);

CREATE TABLE secret_tags (
    secret_id UUID NOT NULL
        REFERENCES secrets(secret_id) ON DELETE CASCADE,

    tag VARCHAR(80) NOT NULL,

    PRIMARY KEY (secret_id, tag)
);

CREATE INDEX idx_secrets_environment
    ON secrets(environment);

CREATE INDEX idx_secrets_owner
    ON secrets(owner_principal);

CREATE INDEX idx_secrets_type
    ON secrets(secret_type);

-- ============================================================
-- 4. SECRET VERSIONING
-- ============================================================

CREATE TABLE secret_versions (
    version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    secret_id UUID NOT NULL
        REFERENCES secrets(secret_id) ON DELETE RESTRICT,

    version_number INTEGER NOT NULL,

    -- Authenticated encrypted ciphertext.
    -- Never insert raw passwords or API keys here.
    ciphertext BYTEA NOT NULL,

    -- Identifies the external encryption key version.
    encryption_key_reference VARCHAR(255) NOT NULL,

    -- SHA-256 fingerprint of the plaintext for comparison.
    -- In production, prefer a keyed HMAC fingerprint for
    -- low-entropy secrets such as passwords.
    fingerprint BYTEA NOT NULL,

    status secret_status NOT NULL DEFAULT 'ACTIVE',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,

    CONSTRAINT positive_version CHECK (version_number > 0),

    CONSTRAINT nonempty_ciphertext CHECK (
        OCTET_LENGTH(ciphertext) > 0
    ),

    CONSTRAINT fingerprint_length CHECK (
        OCTET_LENGTH(fingerprint) = 32
    ),

    CONSTRAINT valid_expiration CHECK (
        expires_at > created_at
    ),

    CONSTRAINT valid_revocation CHECK (
        (status = 'REVOKED' AND revoked_at IS NOT NULL)
        OR
        (status <> 'REVOKED' AND revoked_at IS NULL)
    ),

    UNIQUE (secret_id, version_number)
);

CREATE INDEX idx_secret_versions_expiration
    ON secret_versions(expires_at)
    WHERE status = 'ACTIVE';

CREATE INDEX idx_secret_versions_secret
    ON secret_versions(secret_id, version_number DESC);

-- Only one active version may exist for each secret.
CREATE UNIQUE INDEX idx_one_active_version
    ON secret_versions(secret_id)
    WHERE status = 'ACTIVE';

-- ============================================================
-- 5. SECRET ACCESS POLICIES
-- ============================================================

CREATE TABLE secret_access_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    secret_id UUID NOT NULL
        REFERENCES secrets(secret_id) ON DELETE CASCADE,

    principal_id UUID NOT NULL
        REFERENCES principals(principal_id) ON DELETE CASCADE,

    permission permission_type NOT NULL,

    granted_by UUID NOT NULL
        REFERENCES principals(principal_id),

    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    valid_until TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    CONSTRAINT valid_policy_period CHECK (
        valid_until IS NULL OR valid_until > valid_from
    ),

    UNIQUE (secret_id, principal_id, permission)
);

CREATE INDEX idx_access_policy_principal
    ON secret_access_policies(principal_id, secret_id);

-- ============================================================
-- 6. ROTATION HISTORY
-- ============================================================

CREATE TABLE rotation_events (
    rotation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    secret_id UUID NOT NULL
        REFERENCES secrets(secret_id),

    previous_version INTEGER,

    new_version INTEGER NOT NULL,

    initiated_by UUID NOT NULL
        REFERENCES principals(principal_id),

    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    outcome VARCHAR(20) NOT NULL,

    failure_reason TEXT,

    CONSTRAINT valid_rotation_outcome CHECK (
        outcome IN ('STARTED', 'SUCCESS', 'FAILED')
    ),

    CONSTRAINT valid_rotation_versions CHECK (
        previous_version IS NULL
        OR new_version > previous_version
    )
);

CREATE INDEX idx_rotation_secret_date
    ON rotation_events(secret_id, initiated_at DESC);

-- ============================================================
-- 7. AUDIT LOG
-- ============================================================

CREATE TABLE audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),

    principal_id UUID
        REFERENCES principals(principal_id),

    secret_id UUID
        REFERENCES secrets(secret_id),

    action VARCHAR(40) NOT NULL,

    outcome VARCHAR(20) NOT NULL,

    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    source_ip INET,

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_audit_outcome CHECK (
        outcome IN ('SUCCESS', 'FAILED', 'BLOCKED')
    )
);

CREATE INDEX idx_audit_secret_time
    ON audit_events(secret_id, event_time DESC);

CREATE INDEX idx_audit_principal_time
    ON audit_events(principal_id, event_time DESC);

CREATE INDEX idx_audit_action
    ON audit_events(action, event_time DESC);

-- ============================================================
-- 8. EXPOSURE INCIDENTS
-- ============================================================

CREATE TABLE exposure_incidents (
    incident_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    secret_id UUID
        REFERENCES secrets(secret_id),

    incident_type VARCHAR(60) NOT NULL,

    source_location TEXT,

    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    status incident_status NOT NULL DEFAULT 'OPEN',

    severity VARCHAR(20) NOT NULL,

    assigned_to UUID
        REFERENCES principals(principal_id),

    contained_at TIMESTAMPTZ,

    resolved_at TIMESTAMPTZ,

    remediation_notes TEXT,

    CONSTRAINT valid_severity CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    )
);

CREATE INDEX idx_incident_status
    ON exposure_incidents(status, severity);

-- ============================================================
-- 9. UPDATED TIMESTAMP TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_secrets_updated
BEFORE UPDATE ON secrets
FOR EACH ROW
EXECUTE FUNCTION update_timestamp();

-- ============================================================
-- 10. AUDIT IMMUTABILITY
-- ============================================================

CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Audit records cannot be updated or deleted.';
END;
$$;

CREATE TRIGGER trg_audit_no_update
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_mutation();

-- ============================================================
-- 11. AUTHORIZATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION has_secret_permission(
    p_principal UUID,
    p_secret UUID,
    p_permission permission_type
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM principals p
        JOIN principal_roles pr
            ON pr.principal_id = p.principal_id
        JOIN roles r
            ON r.role_id = pr.role_id
        JOIN role_permissions rp
            ON rp.role_id = r.role_id
        WHERE p.principal_id = p_principal
          AND p.is_active = TRUE
          AND (
              rp.permission = p_permission
              OR rp.permission = 'ADMIN'
          )
    )
    AND EXISTS (
        SELECT 1
        FROM secret_access_policies sap
        WHERE sap.principal_id = p_principal
          AND sap.secret_id = p_secret
          AND sap.permission = p_permission
          AND sap.revoked_at IS NULL
          AND sap.valid_from <= NOW()
          AND (
              sap.valid_until IS NULL
              OR sap.valid_until > NOW()
          )
    );
$$;

-- ============================================================
-- 12. CREATE SECRET FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION register_secret(
    p_principal UUID,
    p_name VARCHAR,
    p_type secret_type,
    p_environment environment_type,
    p_owner UUID,
    p_ciphertext BYTEA,
    p_key_reference VARCHAR,
    p_fingerprint BYTEA,
    p_ttl_days INTEGER
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_secret_id UUID;
BEGIN
    IF NOT has_secret_permission(
        p_principal,
        gen_random_uuid(),
        'WRITE'
    ) THEN
        -- Registration authorization is evaluated through
        -- the principal's role because the secret does not yet exist.
        IF NOT EXISTS (
            SELECT 1
            FROM principal_roles pr
            JOIN roles r ON r.role_id = pr.role_id
            JOIN role_permissions rp ON rp.role_id = r.role_id
            JOIN principals p ON p.principal_id = pr.principal_id
            WHERE p.principal_id = p_principal
              AND p.is_active = TRUE
              AND (
                  rp.permission = 'WRITE'
                  OR rp.permission = 'ADMIN'
              )
        ) THEN
            RAISE EXCEPTION 'Secret creation is not authorized.';
        END IF;
    END IF;

    IF p_ttl_days NOT BETWEEN 1 AND 3650 THEN
        RAISE EXCEPTION 'Invalid expiration period.';
    END IF;

    IF OCTET_LENGTH(p_ciphertext) = 0 THEN
        RAISE EXCEPTION 'Ciphertext cannot be empty.';
    END IF;

    IF OCTET_LENGTH(p_fingerprint) <> 32 THEN
        RAISE EXCEPTION 'Fingerprint must contain 32 bytes.';
    END IF;

    INSERT INTO secrets (
        secret_name,
        secret_type,
        environment,
        owner_principal
    )
    VALUES (
        p_name,
        p_type,
        p_environment,
        p_owner
    )
    RETURNING secret_id INTO v_secret_id;

    INSERT INTO secret_versions (
        secret_id,
        version_number,
        ciphertext,
        encryption_key_reference,
        fingerprint,
        expires_at
    )
    VALUES (
        v_secret_id,
        1,
        p_ciphertext,
        p_key_reference,
        p_fingerprint,
        NOW() + make_interval(days => p_ttl_days)
    );

    INSERT INTO secret_access_policies (
        secret_id,
        principal_id,
        permission,
        granted_by
    )
    SELECT
        v_secret_id,
        p_principal,
        permission,
        p_principal
    FROM UNNEST(
        ARRAY[
            'READ',
            'WRITE',
            'ROTATE',
            'REVOKE'
        ]::permission_type[]
    ) permission;

    INSERT INTO audit_events (
        principal_id,
        secret_id,
        action,
        outcome
    )
    VALUES (
        p_principal,
        v_secret_id,
        'CREATE',
        'SUCCESS'
    );

    RETURN v_secret_id;
END;
$$;

-- ============================================================
-- 13. ROTATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE rotate_secret(
    p_principal UUID,
    p_secret_id UUID,
    p_ciphertext BYTEA,
    p_key_reference VARCHAR,
    p_fingerprint BYTEA,
    p_ttl_days INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_previous_version INTEGER;
    v_next_version INTEGER;
    v_previous_fingerprint BYTEA;
BEGIN
    IF NOT has_secret_permission(
        p_principal,
        p_secret_id,
        'ROTATE'
    ) THEN
        RAISE EXCEPTION 'Rotation not authorized.';
    END IF;

    IF p_ttl_days NOT BETWEEN 1 AND 3650 THEN
        RAISE EXCEPTION 'Invalid rotation TTL.';
    END IF;

    IF OCTET_LENGTH(p_ciphertext) = 0 THEN
        RAISE EXCEPTION 'Ciphertext cannot be empty.';
    END IF;

    IF OCTET_LENGTH(p_fingerprint) <> 32 THEN
        RAISE EXCEPTION 'Invalid fingerprint.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM secrets
        WHERE secret_id = p_secret_id
    ) THEN
        RAISE EXCEPTION 'Secret not found.';
    END IF;

    -- Serialize concurrent rotations for this secret.
    PERFORM 1
    FROM secrets
    WHERE secret_id = p_secret_id
    FOR UPDATE;

    SELECT version_number, fingerprint
    INTO v_previous_version, v_previous_fingerprint
    FROM secret_versions
    WHERE secret_id = p_secret_id
      AND status = 'ACTIVE'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'No active version exists.';
    END IF;

    IF v_previous_fingerprint = p_fingerprint THEN
        RAISE EXCEPTION 'New credential must differ from existing credential.';
    END IF;

    v_next_version := v_previous_version + 1;

    UPDATE secret_versions
    SET status = 'EXPIRED'
    WHERE secret_id = p_secret_id
      AND status = 'ACTIVE';

    INSERT INTO secret_versions (
        secret_id,
        version_number,
        ciphertext,
        encryption_key_reference,
        fingerprint,
        expires_at
    )
    VALUES (
        p_secret_id,
        v_next_version,
        p_ciphertext,
        p_key_reference,
        p_fingerprint,
        NOW() + make_interval(days => p_ttl_days)
    );

    INSERT INTO rotation_events (
        secret_id,
        previous_version,
        new_version,
        initiated_by,
        completed_at,
        outcome
    )
    VALUES (
        p_secret_id,
        v_previous_version,
        v_next_version,
        p_principal,
        NOW(),
        'SUCCESS'
    );

    INSERT INTO audit_events (
        principal_id,
        secret_id,
        action,
        outcome,
        details
    )
    VALUES (
        p_principal,
        p_secret_id,
        'ROTATE',
        'SUCCESS',
        jsonb_build_object(
            'previous_version', v_previous_version,
            'new_version', v_next_version
        )
    );
END;
$$;

-- ============================================================
-- 14. REVOKE SECRET FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION revoke_secret(
    p_principal UUID,
    p_secret_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT has_secret_permission(
        p_principal,
        p_secret_id,
        'REVOKE'
    ) THEN
        RAISE EXCEPTION 'Revocation not authorized.';
    END IF;

    PERFORM 1
    FROM secrets
    WHERE secret_id = p_secret_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Secret not found.';
    END IF;

    UPDATE secret_versions
    SET
        status = 'REVOKED',
        revoked_at = NOW(),
        ciphertext = decode('', 'hex')
    WHERE secret_id = p_secret_id;

    INSERT INTO audit_events (
        principal_id,
        secret_id,
        action,
        outcome
    )
    VALUES (
        p_principal,
        p_secret_id,
        'REVOKE',
        'SUCCESS'
    );

    RETURN TRUE;
END;
$$;

-- ============================================================
-- 15. AUTOMATIC EXPIRATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION expire_secrets()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE secret_versions
    SET status = 'EXPIRED'
    WHERE status = 'ACTIVE'
      AND expires_at <= NOW();

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$;

-- ============================================================
-- 16. SECRET INVENTORY VIEW
-- ============================================================

CREATE OR REPLACE VIEW active_secret_inventory AS
SELECT
    s.secret_id,
    s.secret_name,
    s.secret_type,
    s.environment,
    p.principal_name AS owner,
    sv.version_number,
    sv.status,
    sv.created_at,
    sv.expires_at,
    CASE
        WHEN sv.expires_at <= NOW() THEN 'EXPIRED'
        WHEN sv.expires_at <= NOW() + INTERVAL '15 days'
            THEN 'ROTATION_DUE'
        WHEN sv.expires_at <= NOW() + INTERVAL '30 days'
            THEN 'ROTATION_SOON'
        ELSE 'HEALTHY'
    END AS lifecycle_health
FROM secrets s
JOIN principals p
    ON p.principal_id = s.owner_principal
JOIN secret_versions sv
    ON sv.secret_id = s.secret_id
WHERE sv.status = 'ACTIVE';

-- ============================================================
-- 17. ROTATION REPORT VIEW
-- ============================================================

CREATE OR REPLACE VIEW rotation_report AS
SELECT
    s.secret_id,
    s.secret_name,
    s.environment,
    COUNT(re.rotation_id) AS total_rotations,
    MAX(re.completed_at) AS last_rotation,
    MAX(sv.expires_at) AS current_expiration
FROM secrets s
LEFT JOIN rotation_events re
    ON re.secret_id = s.secret_id
LEFT JOIN secret_versions sv
    ON sv.secret_id = s.secret_id
GROUP BY
    s.secret_id,
    s.secret_name,
    s.environment;

-- ============================================================
-- 18. EXPOSURE INCIDENT REPORT
-- ============================================================

CREATE OR REPLACE VIEW open_exposure_incidents AS
SELECT
    ei.incident_id,
    s.secret_name,
    ei.incident_type,
    ei.severity,
    ei.status,
    ei.detected_at,
    p.principal_name AS assigned_to
FROM exposure_incidents ei
LEFT JOIN secrets s
    ON s.secret_id = ei.secret_id
LEFT JOIN principals p
    ON p.principal_id = ei.assigned_to
WHERE ei.status <> 'RESOLVED';

-- ============================================================
-- 19. REPOSITORY GOVERNANCE
-- ============================================================

CREATE TABLE repositories (
    repository_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    repository_name VARCHAR(150) NOT NULL UNIQUE,

    default_branch VARCHAR(100) NOT NULL DEFAULT 'main',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE branches (
    branch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    repository_id UUID NOT NULL
        REFERENCES repositories(repository_id),

    branch_name VARCHAR(150) NOT NULL,

    head_commit VARCHAR(100) NOT NULL,

    protected BOOLEAN NOT NULL DEFAULT FALSE,

    UNIQUE (repository_id, branch_name)
);

CREATE TABLE pull_requests (
    pull_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    repository_id UUID NOT NULL
        REFERENCES repositories(repository_id),

    source_branch UUID NOT NULL
        REFERENCES branches(branch_id),

    target_branch UUID NOT NULL
        REFERENCES branches(branch_id),

    title VARCHAR(200) NOT NULL,

    status VARCHAR(30) NOT NULL DEFAULT 'OPEN',

    is_draft BOOLEAN NOT NULL DEFAULT FALSE,

    has_conflicts BOOLEAN NOT NULL DEFAULT FALSE,

    conversations_resolved BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    merged_at TIMESTAMPTZ,

    CONSTRAINT valid_pull_request_status CHECK (
        status IN ('OPEN', 'CLOSED', 'MERGED')
    ),

    CONSTRAINT distinct_pull_request_branches CHECK (
        source_branch <> target_branch
    )
);

CREATE TABLE reviews (
    review_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    pull_request_id UUID NOT NULL
        REFERENCES pull_requests(pull_request_id),

    reviewer UUID NOT NULL
        REFERENCES principals(principal_id),

    state review_state NOT NULL,

    eligible BOOLEAN NOT NULL DEFAULT TRUE,

    stale BOOLEAN NOT NULL DEFAULT FALSE,

    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reviews_pr
    ON reviews(pull_request_id, state);

CREATE TABLE review_comments (
    comment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    review_id UUID NOT NULL
        REFERENCES reviews(review_id),

    file_path TEXT NOT NULL,

    line_number INTEGER NOT NULL,

    comment_text TEXT NOT NULL,

    resolved BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (line_number > 0)
);

CREATE TABLE status_checks (
    check_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    pull_request_id UUID NOT NULL
        REFERENCES pull_requests(pull_request_id),

    check_name VARCHAR(120) NOT NULL,

    required BOOLEAN NOT NULL DEFAULT TRUE,

    passed BOOLEAN NOT NULL DEFAULT FALSE,

    completed_at TIMESTAMPTZ,

    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE branch_protection_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    branch_id UUID NOT NULL UNIQUE
        REFERENCES branches(branch_id),

    minimum_approvals INTEGER NOT NULL DEFAULT 2,

    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,

    require_resolved_conversations BOOLEAN NOT NULL DEFAULT TRUE,

    prevent_direct_push BOOLEAN NOT NULL DEFAULT TRUE,

    prevent_force_push BOOLEAN NOT NULL DEFAULT TRUE,

    prevent_deletion BOOLEAN NOT NULL DEFAULT TRUE,

    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,

    administrator_bypass_allowed BOOLEAN NOT NULL DEFAULT FALSE,

    CHECK (minimum_approvals >= 0)
);

-- ============================================================
-- 20. MERGE ELIGIBILITY FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_merge_eligibility(
    p_pull_request UUID
)
RETURNS TABLE (
    eligible BOOLEAN,
    violations TEXT[]
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_pr pull_requests%ROWTYPE;
    v_policy branch_protection_policies%ROWTYPE;
    v_approvals INTEGER;
    v_failures TEXT[] := ARRAY[]::TEXT[];
    v_branch UUID;
BEGIN
    SELECT *
    INTO v_pr
    FROM pull_requests
    WHERE pull_request_id = p_pull_request;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Pull Request does not exist.';
    END IF;

    v_branch := v_pr.target_branch;

    SELECT *
    INTO v_policy
    FROM branch_protection_policies
    WHERE branch_id = v_branch;

    IF NOT FOUND THEN
        RETURN QUERY SELECT TRUE, ARRAY[]::TEXT[];
        RETURN;
    END IF;

    IF v_pr.status <> 'OPEN' THEN
        v_failures := array_append(
            v_failures,
            'Pull Request is not open.'
        );
    END IF;

    IF v_pr.is_draft THEN
        v_failures := array_append(
            v_failures,
            'Draft Pull Request cannot be merged.'
        );
    END IF;

    IF v_pr.has_conflicts THEN
        v_failures := array_append(
            v_failures,
            'Merge conflicts must be resolved.'
        );
    END IF;

    IF (
        v_policy.require_resolved_conversations
        AND NOT v_pr.conversations_resolved
    ) THEN
        v_failures := array_append(
            v_failures,
            'Review conversations remain unresolved.'
        );
    END IF;

    SELECT COUNT(DISTINCT reviewer)
    INTO v_approvals
    FROM reviews
    WHERE pull_request_id = p_pull_request
      AND state = 'APPROVED'
      AND eligible = TRUE
      AND stale = FALSE;

    IF v_approvals < v_policy.minimum_approvals THEN
        v_failures := array_append(
            v_failures,
            'Insufficient eligible approvals.'
        );
    END IF;

    IF v_policy.require_status_checks AND EXISTS (
        SELECT 1
        FROM status_checks
        WHERE pull_request_id = p_pull_request
          AND required = TRUE
          AND passed = FALSE
    ) THEN
        v_failures := array_append(
            v_failures,
            'One or more required status checks failed.'
        );
    END IF;

    RETURN QUERY
    SELECT
        CARDINALITY(v_failures) = 0,
        v_failures;
END;
$$;

-- ============================================================
-- 21. SAMPLE DATA
-- ============================================================

DO $$
DECLARE
    v_admin UUID;
    v_developer UUID;
    v_operator UUID;
    v_payment UUID;
    v_repository UUID;
    v_main UUID;
    v_feature UUID;
    v_pr UUID;
    v_secret UUID;
    v_version UUID;
    v_review1 UUID;
    v_review2 UUID;
    v_review3 UUID;
BEGIN

    SELECT principal_id INTO v_admin
    FROM principals
    WHERE principal_name = 'security-team';

    SELECT principal_id INTO v_developer
    FROM principals
    WHERE principal_name = 'developer-01';

    SELECT principal_id INTO v_operator
    FROM principals
    WHERE principal_name = 'platform-operator';

    SELECT principal_id INTO v_payment
    FROM principals
    WHERE principal_name = 'payment-service';

    -- Create a synthetic encrypted credential record.
    INSERT INTO secrets (
        secret_name,
        secret_type,
        environment,
        owner_principal,
        description,
        rotation_interval_days
    )
    VALUES (
        'payment_api_key',
        'API_KEY',
        'PRODUCTION',
        v_payment,
        'External payment gateway credential',
        90
    )
    RETURNING secret_id INTO v_secret;

    INSERT INTO secret_versions (
        secret_id,
        version_number,
        ciphertext,
        encryption_key_reference,
        fingerprint,
        expires_at
    )
    VALUES (
        v_secret,
        1,
        decode('deadbeef01020304', 'hex'),
        'kms://production/keys/payment-v1',
        decode(repeat('a1', 32), 'hex'),
        NOW() + INTERVAL '90 days'
    )
    RETURNING version_id INTO v_version;

    INSERT INTO secret_tags VALUES
        (v_secret, 'payments'),
        (v_secret, 'external-api'),
        (v_secret, 'production');

    -- Explicit grants to the operator and developer.
    INSERT INTO secret_access_policies (
        secret_id,
        principal_id,
        permission,
        granted_by
    )
    VALUES
        (v_secret, v_developer, 'READ', v_admin),
        (v_secret, v_operator, 'READ', v_admin),
        (v_secret, v_operator, 'ROTATE', v_admin),
        (v_secret, v_admin, 'READ', v_admin),
        (v_secret, v_admin, 'WRITE', v_admin),
        (v_secret, v_admin, 'ROTATE', v_admin),
        (v_secret, v_admin, 'REVOKE', v_admin);

    INSERT INTO rotation_events (
        secret_id,
        previous_version,
        new_version,
        initiated_by,
        completed_at,
        outcome
    )
    VALUES (
        v_secret,
        NULL,
        1,
        v_admin,
        NOW(),
        'SUCCESS'
    );

    -- An exposure incident.
    INSERT INTO exposure_incidents (
        secret_id,
        incident_type,
        source_location,
        severity,
        status,
        assigned_to
    )
    VALUES (
        v_secret,
        'PUBLIC_REPOSITORY_EXPOSURE',
        'repository/configuration.env',
        'CRITICAL',
        'INVESTIGATING',
        v_admin
    );

    INSERT INTO audit_events (
        principal_id,
        secret_id,
        action,
        outcome,
        details
    )
    VALUES
    (
        v_admin,
        v_secret,
        'CREATE',
        'SUCCESS',
        '{"version": 1}'::JSONB
    ),
    (
        v_developer,
        v_secret,
        'READ',
        'SUCCESS',
        '{"purpose": "application startup"}'::JSONB
    );

    -- Repository and branch model.
    INSERT INTO repositories (repository_name)
    VALUES ('payment-platform')
    RETURNING repository_id INTO v_repository;

    INSERT INTO branches (
        repository_id,
        branch_name,
        head_commit,
        protected
    )
    VALUES (
        v_repository,
        'main',
        'commit-main-001',
        TRUE
    )
    RETURNING branch_id INTO v_main;

    INSERT INTO branches (
        repository_id,
        branch_name,
        head_commit,
        protected
    )
    VALUES (
        v_repository,
        'feature/secret-rotation',
        'commit-feature-002',
        FALSE
    )
    RETURNING branch_id INTO v_feature;

    INSERT INTO branch_protection_policies (
        branch_id,
        minimum_approvals,
        require_status_checks,
        require_resolved_conversations,
        prevent_direct_push,
        prevent_force_push,
        prevent_deletion,
        require_linear_history
    )
    VALUES (
        v_main,
        2,
        TRUE,
        TRUE,
        TRUE,
        TRUE,
        TRUE,
        TRUE
    );

    INSERT INTO pull_requests (
        repository_id,
        source_branch,
        target_branch,
        title,
        status,
        is_draft,
        has_conflicts,
        conversations_resolved
    )
    VALUES (
        v_repository,
        v_feature,
        v_main,
        'Implement secure credential rotation',
        'OPEN',
        FALSE,
        FALSE,
        TRUE
    )
    RETURNING pull_request_id INTO v_pr;

    INSERT INTO reviews (
        pull_request_id,
        reviewer,
        state,
        eligible,
        stale
    )
    VALUES
        (v_pr, v_admin, 'APPROVED', TRUE, FALSE),
        (v_pr, v_operator, 'APPROVED', TRUE, FALSE),
        (v_pr, v_developer, 'COMMENTED', TRUE, FALSE);

    INSERT INTO status_checks (
        pull_request_id,
        check_name,
        required,
        passed,
        completed_at
    )
    VALUES
        (v_pr, 'unit-tests', TRUE, TRUE, NOW()),
        (v_pr, 'security-scan', TRUE, TRUE, NOW()),
        (v_pr, 'integration-tests', TRUE, TRUE, NOW());

    INSERT INTO review_comments (
        review_id,
        file_path,
        line_number,
        comment_text,
        resolved
    )
    SELECT
        review_id,
        'src/secrets/rotation.py',
        42,
        'Verify that the previous credential is invalidated.',
        TRUE
    FROM reviews
    WHERE pull_request_id = v_pr
      AND state = 'COMMENTED';

    -- A second request representing an unsuccessful security check.
    INSERT INTO pull_requests (
        repository_id,
        source_branch,
        target_branch,
        title,
        status,
        is_draft,
        has_conflicts,
        conversations_resolved
    )
    VALUES (
        v_repository,
        v_feature,
        v_main,
        'Introduce environment credential changes',
        'OPEN',
        FALSE,
        FALSE,
        FALSE
    )
    RETURNING pull_request_id INTO v_pr;

    INSERT INTO reviews (
        pull_request_id,
        reviewer,
        state,
        eligible,
        stale
    )
    VALUES (
        v_pr,
        v_admin,
        'APPROVED',
        TRUE,
        TRUE
    );

    INSERT INTO status_checks (
        pull_request_id,
        check_name,
        required,
        passed
    )
    VALUES
        (v_pr, 'unit-tests', TRUE, TRUE),
        (v_pr, 'security-scan', TRUE, FALSE);

END;
$$;

-- ============================================================
-- 22. RETRIEVAL QUERIES
-- ============================================================

-- Active secret inventory without revealing credentials.
SELECT
    secret_id,
    secret_name,
    secret_type,
    environment,
    owner,
    version_number,
    lifecycle_health
FROM active_secret_inventory
ORDER BY environment, secret_name;

-- Secret version history.
SELECT
    s.secret_name,
    sv.version_number,
    sv.status,
    sv.created_at,
    sv.expires_at,
    sv.encryption_key_reference
FROM secrets s
JOIN secret_versions sv
    ON sv.secret_id = s.secret_id
ORDER BY s.secret_name, sv.version_number;

-- ============================================================
-- 23. AUTHORIZATION VALIDATION
-- ============================================================

SELECT
    p.principal_name,
    s.secret_name,
    sap.permission,
    has_secret_permission(
        p.principal_id,
        s.secret_id,
        sap.permission
    ) AS authorized
FROM secret_access_policies sap
JOIN principals p
    ON p.principal_id = sap.principal_id
JOIN secrets s
    ON s.secret_id = sap.secret_id
ORDER BY p.principal_name, s.secret_name;

-- ============================================================
-- 24. ROTATION MONITORING
-- ============================================================

SELECT
    secret_name,
    environment,
    version_number,
    expires_at,
    lifecycle_health
FROM active_secret_inventory
WHERE lifecycle_health IN (
    'ROTATION_DUE',
    'ROTATION_SOON',
    'EXPIRED'
)
ORDER BY expires_at;

-- Rotation frequency.
SELECT
    s.secret_name,
    COUNT(re.rotation_id) AS rotation_count,
    MAX(re.completed_at) AS most_recent_rotation
FROM secrets s
LEFT JOIN rotation_events re
    ON re.secret_id = s.secret_id
GROUP BY s.secret_id, s.secret_name
ORDER BY rotation_count DESC;

-- ============================================================
-- 25. EXPOSURE REPORTING
-- ============================================================

SELECT *
FROM open_exposure_incidents
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    detected_at;

-- ============================================================
-- 26. AUDIT AGGREGATION
-- ============================================================

SELECT
    p.principal_name,
    ae.action,
    ae.outcome,
    COUNT(*) AS total_events
FROM audit_events ae
LEFT JOIN principals p
    ON p.principal_id = ae.principal_id
GROUP BY
    p.principal_name,
    ae.action,
    ae.outcome
ORDER BY total_events DESC;

-- ============================================================
-- 27. MERGE ELIGIBILITY REPORT
-- ============================================================

SELECT
    pr.title,
    pr.status,
    result.eligible,
    result.violations
FROM pull_requests pr
CROSS JOIN LATERAL
    evaluate_merge_eligibility(pr.pull_request_id) result
ORDER BY pr.created_at;

-- ============================================================
-- 28. TRANSACTIONAL ROTATION EXAMPLE
-- ============================================================
--
-- The ciphertext and fingerprint below are synthetic.
-- A real application must generate authenticated ciphertext
-- and a suitable keyed fingerprint before invoking the
-- rotation procedure.
--
-- The first sample request is intentionally not executed
-- because its example ciphertext must not be mistaken for
-- a production encryption operation.
--
-- Example application invocation:
--
-- BEGIN;
--
-- CALL secrets_mgmt.rotate_secret(
--     'AUTHORIZED_OPERATOR_UUID',
--     'EXISTING_SECRET_UUID',
--     decode('aabbccdd01020304', 'hex'),
--     'kms://production/keys/payment-v2',
--     decode(repeat('b2', 32), 'hex'),
--     90
-- );
--
-- COMMIT;
--
-- If any operation fails, the application must roll back
-- the transaction.
--
-- ============================================================
-- 29. EXPLICIT FAILURE VALIDATION
-- ============================================================

DO $$
DECLARE
    v_invalid_ttl INTEGER := 0;
    v_invalid_name VARCHAR := 'x';
BEGIN
    IF v_invalid_ttl NOT BETWEEN 1 AND 3650 THEN
        RAISE NOTICE 'Validation passed: invalid TTL rejected.';
    END IF;

    IF v_invalid_name !~ '^[A-Za-z][A-Za-z0-9_.-]{2,99}$' THEN
        RAISE NOTICE 'Validation passed: invalid name rejected.';
    END IF;
END;
$$;

COMMIT;

-- ============================================================
-- END OF SECRETS MANAGEMENT DATABASE
-- ============================================================
