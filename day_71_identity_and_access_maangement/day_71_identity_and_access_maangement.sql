-- ============================================================
-- IDENTITY AND ACCESS MANAGEMENT
-- Authentication, Authorization, Accounting and Lifecycle
-- PostgreSQL 14+
-- ============================================================

DROP SCHEMA IF EXISTS iam CASCADE;
CREATE SCHEMA iam;

SET search_path TO iam, public;

-- ============================================================
-- 1. DOMAIN TYPES
-- ============================================================

CREATE TYPE identity_status AS ENUM (
    'PENDING',
    'ACTIVE',
    'SUSPENDED',
    'DISABLED',
    'TERMINATED'
);

CREATE TYPE event_type AS ENUM (
    'IDENTITY_CREATED',
    'IDENTITY_ACTIVATED',
    'IDENTITY_SUSPENDED',
    'IDENTITY_DISABLED',
    'IDENTITY_TERMINATED',
    'ROLE_ASSIGNED',
    'ROLE_REMOVED',
    'LOGIN_SUCCESS',
    'LOGIN_FAILURE',
    'ACCESS_GRANTED',
    'ACCESS_DENIED',
    'SESSION_REVOKED',
    'PASSWORD_CHANGED'
);

CREATE TYPE decision_type AS ENUM (
    'ALLOW',
    'DENY'
);

-- ============================================================
-- 2. ORGANIZATIONAL AND IDENTITY MODEL
-- ============================================================

CREATE TABLE departments (
    department_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    department_name VARCHAR(120) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE identities (
    identity_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    full_name VARCHAR(150) NOT NULL,
    department_id BIGINT REFERENCES departments(department_id),
    status identity_status NOT NULL DEFAULT 'PENDING',
    credential_reference VARCHAR(255) NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (length(trim(username)) >= 3),
    CHECK (length(trim(full_name)) > 0),
    CHECK (failed_attempts >= 0),
    CHECK (version > 0)
);

CREATE INDEX idx_identities_department
ON identities(department_id);

CREATE INDEX idx_identities_active
ON identities(status, username)
WHERE status = 'ACTIVE';

-- ============================================================
-- 3. RBAC MODEL
-- ============================================================

CREATE TABLE roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name VARCHAR(80) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    privileged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE permissions (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    permission_code VARCHAR(120) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(permission_id)
        ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE identity_roles (
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    role_id BIGINT NOT NULL REFERENCES roles(role_id),
    assigned_by UUID REFERENCES identities(identity_id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (identity_id, role_id),
    CHECK (expires_at IS NULL OR expires_at > assigned_at)
);

CREATE INDEX idx_identity_roles_role
ON identity_roles(role_id, identity_id);

CREATE INDEX idx_identity_roles_expiry
ON identity_roles(expires_at)
WHERE expires_at IS NOT NULL;

-- ============================================================
-- 4. AUTHENTICATION AND SESSION MANAGEMENT
-- ============================================================

CREATE TABLE authentication_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identity_id UUID REFERENCES identities(identity_id),
    attempted_username VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(120),
    source_ip INET,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_authentication_identity_time
ON authentication_attempts(identity_id, attempted_at DESC);

CREATE INDEX idx_authentication_failure_time
ON authentication_attempts(attempted_at DESC)
WHERE success = FALSE;

CREATE TABLE sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (
        (revoked = FALSE AND revoked_at IS NULL)
        OR
        (revoked = TRUE AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX idx_sessions_identity
ON sessions(identity_id, created_at DESC);

CREATE INDEX idx_sessions_valid
ON sessions(expires_at)
WHERE revoked = FALSE;

-- ============================================================
-- 5. AUTHORIZATION POLICY AND ACCESS DECISIONS
-- ============================================================

CREATE TABLE resources (
    resource_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    resource_name VARCHAR(200) NOT NULL UNIQUE,
    resource_type VARCHAR(100) NOT NULL,
    classification VARCHAR(30) NOT NULL DEFAULT 'INTERNAL',
    CHECK (
        classification IN (
            'PUBLIC',
            'INTERNAL',
            'CONFIDENTIAL',
            'RESTRICTED'
        )
    )
);

CREATE TABLE access_decisions (
    decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identity_id UUID REFERENCES identities(identity_id),
    session_id UUID REFERENCES sessions(session_id),
    resource_id BIGINT REFERENCES resources(resource_id),
    permission_id BIGINT REFERENCES permissions(permission_id),
    decision decision_type NOT NULL,
    reason VARCHAR(200) NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_identity_time
ON access_decisions(identity_id, evaluated_at DESC);

CREATE INDEX idx_access_denials
ON access_decisions(evaluated_at DESC)
WHERE decision = 'DENY';

-- ============================================================
-- 6. ACCOUNTING AND AUDIT
-- ============================================================

CREATE TABLE audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identity_id UUID REFERENCES identities(identity_id),
    event event_type NOT NULL,
    resource VARCHAR(255) NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX idx_audit_identity_time
ON audit_events(identity_id, occurred_at DESC);

CREATE INDEX idx_audit_event_time
ON audit_events(event, occurred_at DESC);

CREATE INDEX idx_audit_details
ON audit_events USING GIN(details);

-- Prevent application-level modification of historical audit records.
CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Audit events are append-only';
END;
$$;

CREATE TRIGGER trg_audit_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_mutation();

-- ============================================================
-- 7. LIFECYCLE MANAGEMENT
-- ============================================================

CREATE OR REPLACE FUNCTION validate_identity_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'PENDING'
       AND NEW.status = 'ACTIVE' THEN
        NULL;

    ELSIF OLD.status = 'ACTIVE'
       AND NEW.status IN ('SUSPENDED', 'DISABLED', 'TERMINATED') THEN
        NULL;

    ELSIF OLD.status = 'SUSPENDED'
       AND NEW.status IN ('ACTIVE', 'DISABLED', 'TERMINATED') THEN
        NULL;

    ELSIF OLD.status = 'DISABLED'
       AND NEW.status = 'TERMINATED' THEN
        NULL;

    ELSE
        RAISE EXCEPTION
            'Invalid identity transition: % -> %',
            OLD.status,
            NEW.status;
    END IF;

    NEW.version := OLD.version + 1;
    NEW.updated_at := CURRENT_TIMESTAMP;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_identity_transition
BEFORE UPDATE OF status ON identities
FOR EACH ROW
EXECUTE FUNCTION validate_identity_transition();

CREATE OR REPLACE FUNCTION record_identity_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_event event_type;
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO audit_events(
            identity_id, event, resource, details
        )
        VALUES (
            NEW.identity_id,
            'IDENTITY_CREATED',
            'identity',
            jsonb_build_object('username', NEW.username)
        );

        RETURN NEW;
    END IF;

    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    v_event := CASE NEW.status
        WHEN 'ACTIVE' THEN 'IDENTITY_ACTIVATED'::event_type
        WHEN 'SUSPENDED' THEN 'IDENTITY_SUSPENDED'::event_type
        WHEN 'DISABLED' THEN 'IDENTITY_DISABLED'::event_type
        WHEN 'TERMINATED' THEN 'IDENTITY_TERMINATED'::event_type
        ELSE 'IDENTITY_CREATED'::event_type
    END;

    INSERT INTO audit_events(
        identity_id, event, resource, details
    )
    VALUES (
        NEW.identity_id,
        v_event,
        'identity',
        jsonb_build_object(
            'previous_status', OLD.status,
            'new_status', NEW.status,
            'version', NEW.version
        )
    );

    -- Lifecycle changes revoke existing sessions atomically.
    IF NEW.status IN ('SUSPENDED', 'DISABLED', 'TERMINATED') THEN
        UPDATE sessions
        SET revoked = TRUE,
            revoked_at = CURRENT_TIMESTAMP
        WHERE identity_id = NEW.identity_id
          AND revoked = FALSE;

        INSERT INTO audit_events(
            identity_id, event, resource, details
        )
        VALUES (
            NEW.identity_id,
            'SESSION_REVOKED',
            'session',
            jsonb_build_object(
                'reason', 'identity_lifecycle_change'
            )
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_identity_audit_insert
AFTER INSERT ON identities
FOR EACH ROW
EXECUTE FUNCTION record_identity_lifecycle();

CREATE TRIGGER trg_identity_audit_update
AFTER UPDATE OF status ON identities
FOR EACH ROW
EXECUTE FUNCTION record_identity_lifecycle();

-- ============================================================
-- 8. ROLE ASSIGNMENT AUDIT
-- ============================================================

CREATE OR REPLACE FUNCTION record_role_assignment()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO audit_events(
        identity_id, event, resource, details
    )
    VALUES (
        NEW.identity_id,
        'ROLE_ASSIGNED',
        'identity_roles',
        jsonb_build_object(
            'role_id', NEW.role_id,
            'assigned_by', NEW.assigned_by,
            'expires_at', NEW.expires_at
        )
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_role_assignment_audit
AFTER INSERT ON identity_roles
FOR EACH ROW
EXECUTE FUNCTION record_role_assignment();

CREATE OR REPLACE FUNCTION record_role_removal()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO audit_events(
        identity_id, event, resource, details
    )
    VALUES (
        OLD.identity_id,
        'ROLE_REMOVED',
        'identity_roles',
        jsonb_build_object('role_id', OLD.role_id)
    );

    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_role_removal_audit
AFTER DELETE ON identity_roles
FOR EACH ROW
EXECUTE FUNCTION record_role_removal();

-- ============================================================
-- 9. RBAC AUTHORIZATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION check_access(
    p_identity_id UUID,
    p_permission_code VARCHAR,
    p_resource_name VARCHAR
)
RETURNS TABLE (
    allowed BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_status identity_status;
    v_allowed BOOLEAN;
BEGIN
    SELECT status
    INTO v_status
    FROM identities
    WHERE identity_id = p_identity_id;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT FALSE, 'IDENTITY_NOT_FOUND'::TEXT;
        RETURN;
    END IF;

    IF v_status <> 'ACTIVE' THEN
        RETURN QUERY
        SELECT FALSE, 'IDENTITY_NOT_ACTIVE'::TEXT;
        RETURN;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM identity_roles ir
        JOIN role_permissions rp
            ON rp.role_id = ir.role_id
        JOIN permissions p
            ON p.permission_id = rp.permission_id
        WHERE ir.identity_id = p_identity_id
          AND p.permission_code = p_permission_code
          AND (
              ir.expires_at IS NULL
              OR ir.expires_at > CURRENT_TIMESTAMP
          )
    )
    INTO v_allowed;

    RETURN QUERY
    SELECT
        v_allowed,
        CASE
            WHEN v_allowed THEN 'ROLE_PERMISSION_MATCH'
            ELSE 'PERMISSION_NOT_GRANTED'
        END::TEXT;
END;
$$;

-- ============================================================
-- 10. SESSION VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_session(
    p_session_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_valid BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM sessions s
        JOIN identities i
            ON i.identity_id = s.identity_id
        WHERE s.session_id = p_session_id
          AND s.revoked = FALSE
          AND s.expires_at > CURRENT_TIMESTAMP
          AND i.status = 'ACTIVE'
    )
    INTO v_valid;

    RETURN v_valid;
END;
$$;

-- ============================================================
-- 11. ACCESS DECISION RECORDING
-- ============================================================

CREATE OR REPLACE FUNCTION record_access_decision(
    p_identity_id UUID,
    p_session_id UUID,
    p_resource_id BIGINT,
    p_permission_id BIGINT
)
RETURNS decision_type
LANGUAGE plpgsql
AS $$
DECLARE
    v_allowed BOOLEAN;
    v_reason TEXT;
    v_decision decision_type;
    v_permission VARCHAR;
    v_resource VARCHAR;
BEGIN
    SELECT permission_code
    INTO v_permission
    FROM permissions
    WHERE permission_id = p_permission_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Permission does not exist';
    END IF;

    SELECT resource_name
    INTO v_resource
    FROM resources
    WHERE resource_id = p_resource_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Resource does not exist';
    END IF;

    IF NOT validate_session(p_session_id) THEN
        v_allowed := FALSE;
        v_reason := 'INVALID_SESSION';
    ELSE
        IF NOT EXISTS (
            SELECT 1
            FROM sessions
            WHERE session_id = p_session_id
              AND identity_id = p_identity_id
        ) THEN
            v_allowed := FALSE;
            v_reason := 'SESSION_IDENTITY_MISMATCH';
        ELSE
            SELECT ca.allowed, ca.reason
            INTO v_allowed, v_reason
            FROM check_access(
                p_identity_id,
                v_permission,
                v_resource
            ) ca;
        END IF;
    END IF;

    v_decision := CASE
        WHEN v_allowed THEN 'ALLOW'::decision_type
        ELSE 'DENY'::decision_type
    END;

    INSERT INTO access_decisions(
        identity_id,
        session_id,
        resource_id,
        permission_id,
        decision,
        reason
    )
    VALUES (
        p_identity_id,
        p_session_id,
        p_resource_id,
        p_permission_id,
        v_decision,
        v_reason
    );

    INSERT INTO audit_events(
        identity_id,
        event,
        resource,
        details
    )
    VALUES (
        p_identity_id,
        CASE
            WHEN v_allowed THEN 'ACCESS_GRANTED'::event_type
            ELSE 'ACCESS_DENIED'::event_type
        END,
        v_resource,
        jsonb_build_object(
            'permission', v_permission,
            'decision', v_decision,
            'reason', v_reason
        )
    );

    RETURN v_decision;
END;
$$;

-- ============================================================
-- 12. IDENTITY LIFECYCLE PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE change_identity_status(
    p_identity_id UUID,
    p_new_status identity_status
)
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE identities
    SET status = p_new_status
    WHERE identity_id = p_identity_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Identity not found';
    END IF;
END;
$$;

-- ============================================================
-- 13. SEED DATA
-- ============================================================

INSERT INTO departments(department_name)
VALUES
    ('Engineering'),
    ('Information Security'),
    ('Finance'),
    ('Internal Audit');

INSERT INTO roles(role_name, description, privileged)
VALUES
    ('EMPLOYEE', 'Standard organizational employee', FALSE),
    ('MANAGER', 'Department management privileges', FALSE),
    ('SECURITY_ADMIN', 'Privileged security administration', TRUE),
    ('AUDITOR', 'Read-only compliance auditing', FALSE);

INSERT INTO permissions(permission_code, description)
VALUES
    ('document:read', 'Read organizational documents'),
    ('document:write', 'Create and update documents'),
    ('document:delete', 'Delete organizational documents'),
    ('users:manage', 'Manage identity records'),
    ('roles:manage', 'Manage role assignments'),
    ('audit:read', 'Read audit records');

-- Employee permissions.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'EMPLOYEE'
  AND p.permission_code IN (
      'document:read',
      'document:write'
  );

-- Manager permissions.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'MANAGER'
  AND p.permission_code IN (
      'document:read',
      'document:write',
      'document:delete'
  );

-- Security administrator permissions.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'SECURITY_ADMIN';

-- Auditor permissions.
INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE r.role_name = 'AUDITOR'
  AND p.permission_code IN (
      'document:read',
      'audit:read'
  );

INSERT INTO identities(
    username,
    email,
    full_name,
    department_id,
    status,
    credential_reference,
    mfa_enabled
)
SELECT
    'alice',
    'alice@example.org',
    'Alice Employee',
    department_id,
    'ACTIVE',
    'external-vault-reference-1001',
    TRUE
FROM departments
WHERE department_name = 'Engineering';

INSERT INTO identities(
    username,
    email,
    full_name,
    department_id,
    status,
    credential_reference
)
SELECT
    'bob',
    'bob@example.org',
    'Bob Manager',
    department_id,
    'ACTIVE',
    'external-vault-reference-1002'
FROM departments
WHERE department_name = 'Engineering';

INSERT INTO identities(
    username,
    email,
    full_name,
    department_id,
    status,
    credential_reference
)
SELECT
    'charlie',
    'charlie@example.org',
    'Charlie Auditor',
    department_id,
    'ACTIVE',
    'external-vault-reference-1003'
FROM departments
WHERE department_name = 'Internal Audit';

INSERT INTO identities(
    username,
    email,
    full_name,
    status,
    credential_reference
)
VALUES (
    'pending_user',
    'pending@example.org',
    'Pending User',
    'PENDING',
    'external-vault-reference-1004'
);

-- Assign roles.
INSERT INTO identity_roles(
    identity_id,
    role_id,
    assigned_by
)
SELECT
    i.identity_id,
    r.role_id,
    NULL
FROM identities i
CROSS JOIN roles r
WHERE i.username = 'alice'
  AND r.role_name = 'EMPLOYEE';

INSERT INTO identity_roles(
    identity_id,
    role_id
)
SELECT
    i.identity_id,
    r.role_id
FROM identities i
CROSS JOIN roles r
WHERE i.username = 'bob'
  AND r.role_name = 'MANAGER';

INSERT INTO identity_roles(
    identity_id,
    role_id
)
SELECT
    i.identity_id,
    r.role_id
FROM identities i
CROSS JOIN roles r
WHERE i.username = 'charlie'
  AND r.role_name = 'AUDITOR';

-- Resources.
INSERT INTO resources(
    resource_name,
    resource_type,
    classification
)
VALUES
    ('engineering-report', 'DOCUMENT', 'INTERNAL'),
    ('financial-report', 'DOCUMENT', 'CONFIDENTIAL'),
    ('security-audit', 'DOCUMENT', 'RESTRICTED');

-- ============================================================
-- 14. DEMONSTRATE AUTHENTICATION ACCOUNTING
-- ============================================================

INSERT INTO authentication_attempts(
    identity_id,
    attempted_username,
    success,
    failure_reason,
    source_ip
)
SELECT
    identity_id,
    username,
    TRUE,
    NULL,
    '192.0.2.10'
FROM identities
WHERE username = 'alice';

INSERT INTO authentication_attempts(
    identity_id,
    attempted_username,
    success,
    failure_reason,
    source_ip
)
SELECT
    identity_id,
    username,
    FALSE,
    'INVALID_CREDENTIALS',
    '192.0.2.11'
FROM identities
WHERE username = 'alice';

-- Session token hashes are supplied by the authentication service.
-- Raw bearer tokens must never be stored in the database.

INSERT INTO sessions(
    identity_id,
    token_hash,
    expires_at
)
SELECT
    identity_id,
    digest('demo-session-alice', 'sha256'),
    CURRENT_TIMESTAMP + INTERVAL '30 minutes'
FROM identities
WHERE username = 'alice';

INSERT INTO sessions(
    identity_id,
    token_hash,
    expires_at
)
SELECT
    identity_id,
    digest('demo-session-bob', 'sha256'),
    CURRENT_TIMESTAMP + INTERVAL '30 minutes'
FROM identities
WHERE username = 'bob';

-- ============================================================
-- 15. ACCESS EVALUATION
-- ============================================================

SELECT
    i.username,
    r.resource_name,
    p.permission_code,
    ca.allowed,
    ca.reason
FROM identities i
CROSS JOIN resources r
CROSS JOIN permissions p
CROSS JOIN LATERAL check_access(
    i.identity_id,
    p.permission_code,
    r.resource_name
) ca
WHERE i.username = 'alice'
  AND r.resource_name = 'engineering-report'
  AND p.permission_code IN (
      'document:read',
      'document:delete'
  )
ORDER BY p.permission_code;

-- Record a successful read decision.
SELECT record_access_decision(
    i.identity_id,
    s.session_id,
    r.resource_id,
    p.permission_id
)
FROM identities i
JOIN sessions s ON s.identity_id = i.identity_id
JOIN resources r ON r.resource_name = 'engineering-report'
JOIN permissions p ON p.permission_code = 'document:read'
WHERE i.username = 'alice'
  AND s.revoked = FALSE
LIMIT 1;

-- ============================================================
-- 16. VIEWS
-- ============================================================

CREATE VIEW active_identity_directory AS
SELECT
    i.identity_id,
    i.username,
    i.email,
    i.full_name,
    d.department_name,
    i.mfa_enabled,
    i.created_at
FROM identities i
LEFT JOIN departments d
    ON d.department_id = i.department_id
WHERE i.status = 'ACTIVE';

CREATE VIEW identity_effective_permissions AS
SELECT DISTINCT
    i.identity_id,
    i.username,
    r.role_name,
    p.permission_code,
    ir.expires_at
FROM identities i
JOIN identity_roles ir
    ON ir.identity_id = i.identity_id
JOIN roles r
    ON r.role_id = ir.role_id
JOIN role_permissions rp
    ON rp.role_id = r.role_id
JOIN permissions p
    ON p.permission_id = rp.permission_id
WHERE i.status = 'ACTIVE'
  AND (
      ir.expires_at IS NULL
      OR ir.expires_at > CURRENT_TIMESTAMP
  );

CREATE VIEW identity_session_summary AS
SELECT
    i.identity_id,
    i.username,
    COUNT(s.session_id) FILTER (
        WHERE s.revoked = FALSE
          AND s.expires_at > CURRENT_TIMESTAMP
    ) AS active_sessions,
    COUNT(s.session_id) AS total_sessions
FROM identities i
LEFT JOIN sessions s
    ON s.identity_id = i.identity_id
GROUP BY i.identity_id, i.username;

-- ============================================================
-- 17. REPORTING AND AGGREGATION
-- ============================================================

-- Identities by lifecycle state.
SELECT
    status,
    COUNT(*) AS identity_count
FROM identities
GROUP BY status
ORDER BY status;

-- Role distribution.
SELECT
    r.role_name,
    COUNT(ir.identity_id) AS assigned_identities
FROM roles r
LEFT JOIN identity_roles ir
    ON ir.role_id = r.role_id
GROUP BY r.role_id, r.role_name
ORDER BY assigned_identities DESC;

-- Authentication failure monitoring.
SELECT
    attempted_username,
    COUNT(*) AS failed_attempts,
    MAX(attempted_at) AS latest_failure
FROM authentication_attempts
WHERE success = FALSE
  AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'
GROUP BY attempted_username
ORDER BY failed_attempts DESC;

-- Access denial reporting.
SELECT
    identity_id,
    COUNT(*) AS denied_requests
FROM access_decisions
WHERE decision = 'DENY'
GROUP BY identity_id
ORDER BY denied_requests DESC;

-- Accounting event distribution.
SELECT
    event,
    COUNT(*) AS event_count,
    MIN(occurred_at) AS first_occurrence,
    MAX(occurred_at) AS last_occurrence
FROM audit_events
GROUP BY event
ORDER BY event_count DESC;

-- ============================================================
-- 18. CTE: EFFECTIVE ACCESS EVALUATION
-- ============================================================

WITH effective_access AS (
    SELECT DISTINCT
        i.username,
        r.role_name,
        p.permission_code
    FROM identities i
    JOIN identity_roles ir
        ON ir.identity_id = i.identity_id
    JOIN roles r
        ON r.role_id = ir.role_id
    JOIN role_permissions rp
        ON rp.role_id = r.role_id
    JOIN permissions p
        ON p.permission_id = rp.permission_id
    WHERE i.status = 'ACTIVE'
      AND (
          ir.expires_at IS NULL
          OR ir.expires_at > CURRENT_TIMESTAMP
      )
)
SELECT
    username,
    ARRAY_AGG(
        DISTINCT permission_code
        ORDER BY permission_code
    ) AS effective_permissions
FROM effective_access
GROUP BY username
ORDER BY username;

-- ============================================================
-- 19. ELIGIBILITY AND POLICY VALIDATION
-- ============================================================

-- Find active privileged identities without MFA.
SELECT
    i.username,
    r.role_name,
    i.mfa_enabled
FROM identities i
JOIN identity_roles ir
    ON ir.identity_id = i.identity_id
JOIN roles r
    ON r.role_id = ir.role_id
WHERE i.status = 'ACTIVE'
  AND r.privileged = TRUE
  AND i.mfa_enabled = FALSE;

-- Detect expired role assignments.
SELECT
    i.username,
    r.role_name,
    ir.expires_at
FROM identity_roles ir
JOIN identities i ON i.identity_id = ir.identity_id
JOIN roles r ON r.role_id = ir.role_id
WHERE ir.expires_at <= CURRENT_TIMESTAMP;

-- Detect identities with no assigned roles.
SELECT
    i.identity_id,
    i.username,
    i.status
FROM identities i
LEFT JOIN identity_roles ir
    ON ir.identity_id = i.identity_id
WHERE i.status = 'ACTIVE'
GROUP BY i.identity_id, i.username, i.status
HAVING COUNT(ir.role_id) = 0;

-- ============================================================
-- 20. ROLE EXPIRATION WORKFLOW
-- ============================================================

CREATE OR REPLACE PROCEDURE remove_expired_roles()
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM identity_roles
    WHERE expires_at IS NOT NULL
      AND expires_at <= CURRENT_TIMESTAMP;
END;
$$;

-- ============================================================
-- 21. TRANSACTIONAL OFFBOARDING
-- ============================================================

BEGIN;

-- The procedure updates lifecycle state and revokes sessions
-- within the same transaction.

CALL change_identity_status(
    (SELECT identity_id FROM identities WHERE username = 'bob'),
    'SUSPENDED'
);

COMMIT;

-- ============================================================
-- 22. VALIDATION AND FINAL REPORTING
-- ============================================================

-- Current identity directory.
SELECT *
FROM active_identity_directory
ORDER BY username;

-- Current permission directory.
SELECT *
FROM identity_effective_permissions
ORDER BY username, permission_code;

-- Session state.
SELECT *
FROM identity_session_summary
ORDER BY username;

-- Audit trail.
SELECT
    event_id,
    identity_id,
    event,
    resource,
    details,
    occurred_at
FROM audit_events
ORDER BY event_id;

-- Verify that suspended identities have no valid sessions.
SELECT
    i.username,
    COUNT(s.session_id) AS invalid_active_sessions
FROM identities i
JOIN sessions s
    ON s.identity_id = i.identity_id
WHERE i.status <> 'ACTIVE'
  AND s.revoked = FALSE
  AND s.expires_at > CURRENT_TIMESTAMP
GROUP BY i.username;

-- ============================================================
-- 23. DATABASE SECURITY CONSIDERATIONS
-- ============================================================

-- Password hashing, MFA verification, credential validation,
-- token generation and token hashing belong in the trusted
-- authentication service.
--
-- Production deployments should:
--
-- 1. Use separate database roles for authentication services,
--    identity administration and read-only auditing.
-- 2. Restrict direct UPDATE/DELETE access to audit_events.
-- 3. Apply least-privilege grants to application roles.
-- 4. Use TLS for database connections.
-- 5. Keep credential references outside ordinary application logs.
-- 6. Use transaction boundaries for lifecycle changes.
-- 7. Configure audit retention and archival.
-- 8. Use row-level security where tenant isolation is required.
--
-- Example restricted reporting role:
--
-- CREATE ROLE iam_auditor NOLOGIN;
-- GRANT USAGE ON SCHEMA iam TO iam_auditor;
-- GRANT SELECT ON audit_events TO iam_auditor;
-- GRANT SELECT ON active_identity_directory TO iam_auditor;
--
-- Example application permissions should be granted separately
-- by a database administrator after reviewing deployment roles.
