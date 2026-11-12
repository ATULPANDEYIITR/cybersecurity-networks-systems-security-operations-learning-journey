/*
===============================================================================
AUTHORIZATION GOVERNANCE DATABASE
===============================================================================

Authorization mechanisms:
    1. RBAC - Role-Based Access Control
    2. ABAC - Attribute-Based Access Control
    3. ACL  - Access Control Lists
    4. DAC  - Discretionary Access Control
    5. MAC  - Mandatory Access Control
    6. Least privilege

PostgreSQL 15+

Execution:
    psql -U postgres -d authorization_db -f authorization_models.sql

The script creates an isolated schema named authorization.
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS authorization;

SET search_path TO authorization, public;

-- ============================================================================
-- DOMAIN TYPES
-- ============================================================================

CREATE TYPE classification_level AS ENUM (
    'PUBLIC',
    'INTERNAL',
    'CONFIDENTIAL',
    'SECRET',
    'TOP_SECRET'
);

CREATE TYPE permission_type AS ENUM (
    'READ',
    'WRITE',
    'DELETE',
    'EXECUTE',
    'SHARE',
    'ADMIN'
);

CREATE TYPE access_decision AS ENUM (
    'ALLOW',
    'DENY'
);

CREATE TYPE access_purpose AS ENUM (
    'BUSINESS',
    'RESEARCH',
    'MAINTENANCE',
    'COMPLIANCE'
);

CREATE TYPE principal_type AS ENUM (
    'USER',
    'ROLE'
);

-- ============================================================================
-- IDENTITY AND ORGANIZATION
-- ============================================================================

CREATE TABLE departments (
    department_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    department_name VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(128) NOT NULL UNIQUE,

    department_id BIGINT NOT NULL
        REFERENCES departments(department_id),

    location VARCHAR(100) NOT NULL,

    clearance classification_level NOT NULL DEFAULT 'PUBLIC',

    active BOOLEAN NOT NULL DEFAULT TRUE,

    suspended BOOLEAN NOT NULL DEFAULT FALSE,

    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,

    privileged_admin BOOLEAN NOT NULL DEFAULT FALSE,

    delete_authorized BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_username
        CHECK (length(trim(username)) > 0),

    CONSTRAINT suspended_user_inactive
        CHECK (NOT suspended OR NOT active)
);

-- ============================================================================
-- RBAC
-- ============================================================================

CREATE TABLE roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    role_name VARCHAR(100) NOT NULL UNIQUE,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (length(trim(role_name)) > 0)
);

CREATE TABLE permissions (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    permission_name permission_type NOT NULL UNIQUE,

    description TEXT
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE CASCADE,

    permission_id BIGINT NOT NULL REFERENCES permissions(permission_id)
        ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL REFERENCES users(user_id)
        ON DELETE CASCADE,

    role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE CASCADE,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    assigned_by BIGINT REFERENCES users(user_id),

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_role
    ON user_roles(role_id, user_id);

CREATE INDEX idx_role_permissions_permission
    ON role_permissions(permission_id, role_id);

-- ============================================================================
-- RESOURCES AND CLASSIFICATION
-- ============================================================================

CREATE TABLE resources (
    resource_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    resource_name VARCHAR(150) NOT NULL UNIQUE,

    owner_id BIGINT NOT NULL REFERENCES users(user_id),

    department_id BIGINT NOT NULL
        REFERENCES departments(department_id),

    classification classification_level NOT NULL DEFAULT 'PUBLIC',

    require_mfa BOOLEAN NOT NULL DEFAULT TRUE,

    deletion_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (length(trim(resource_name)) > 0)
);

CREATE INDEX idx_resources_owner
    ON resources(owner_id);

CREATE INDEX idx_resources_department_classification
    ON resources(department_id, classification);

-- ============================================================================
-- ABAC RESOURCE ATTRIBUTES
-- ============================================================================

CREATE TABLE resource_attributes (
    resource_id BIGINT NOT NULL
        REFERENCES resources(resource_id)
        ON DELETE CASCADE,

    attribute_name VARCHAR(100) NOT NULL,

    attribute_value JSONB NOT NULL,

    PRIMARY KEY (resource_id, attribute_name),

    CHECK (length(trim(attribute_name)) > 0)
);

CREATE INDEX idx_resource_attributes_gin
    ON resource_attributes USING GIN(attribute_value);

-- ============================================================================
-- ACL AND DAC
-- ============================================================================

CREATE TABLE access_control_entries (
    acl_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    resource_id BIGINT NOT NULL
        REFERENCES resources(resource_id)
        ON DELETE CASCADE,

    principal_kind principal_type NOT NULL,

    user_id BIGINT REFERENCES users(user_id)
        ON DELETE CASCADE,

    role_id BIGINT REFERENCES roles(role_id)
        ON DELETE CASCADE,

    permission_id BIGINT NOT NULL
        REFERENCES permissions(permission_id),

    granted_by BIGINT NOT NULL REFERENCES users(user_id),

    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_acl_principal CHECK (
        (
            principal_kind = 'USER'
            AND user_id IS NOT NULL
            AND role_id IS NULL
        )
        OR
        (
            principal_kind = 'ROLE'
            AND role_id IS NOT NULL
            AND user_id IS NULL
        )
    ),

    CONSTRAINT unique_user_acl UNIQUE (
        resource_id,
        user_id,
        permission_id
    ),

    CONSTRAINT unique_role_acl UNIQUE (
        resource_id,
        role_id,
        permission_id
    )
);

CREATE INDEX idx_acl_resource_permission
    ON access_control_entries(resource_id, permission_id);

CREATE INDEX idx_acl_user
    ON access_control_entries(user_id)
    WHERE user_id IS NOT NULL;

CREATE INDEX idx_acl_role
    ON access_control_entries(role_id)
    WHERE role_id IS NOT NULL;

-- ============================================================================
-- ABAC POLICY DEFINITIONS
-- ============================================================================

CREATE TABLE authorization_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    policy_category VARCHAR(20) NOT NULL,

    description TEXT NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        policy_category IN (
            'ABAC',
            'MAC',
            'LEAST_PRIVILEGE',
            'DENY'
        )
    )
);

-- Explicit deny rules override ordinary grants.

CREATE TABLE explicit_deny_rules (
    deny_rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT REFERENCES users(user_id)
        ON DELETE CASCADE,

    department_id BIGINT REFERENCES departments(department_id)
        ON DELETE CASCADE,

    resource_id BIGINT REFERENCES resources(resource_id)
        ON DELETE CASCADE,

    permission_id BIGINT REFERENCES permissions(permission_id)
        ON DELETE CASCADE,

    reason TEXT NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        user_id IS NOT NULL
        OR department_id IS NOT NULL
        OR resource_id IS NOT NULL
    )
);

CREATE INDEX idx_explicit_deny_user
    ON explicit_deny_rules(user_id)
    WHERE enabled = TRUE;

-- ============================================================================
-- ACCESS REQUESTS
-- ============================================================================

CREATE TABLE access_requests (
    request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    user_id BIGINT NOT NULL REFERENCES users(user_id),

    resource_id BIGINT NOT NULL REFERENCES resources(resource_id),

    permission_id BIGINT NOT NULL
        REFERENCES permissions(permission_id),

    purpose access_purpose NOT NULL,

    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    decision access_decision,

    decision_reason TEXT,

    decided_at TIMESTAMPTZ,

    CONSTRAINT valid_decision_timestamp CHECK (
        (
            decision IS NULL
            AND decided_at IS NULL
        )
        OR
        (
            decision IS NOT NULL
            AND decided_at IS NOT NULL
        )
    )
);

CREATE INDEX idx_access_requests_user_time
    ON access_requests(user_id, requested_at DESC);

CREATE INDEX idx_access_requests_resource_decision
    ON access_requests(resource_id, decision);

-- ============================================================================
-- AUDIT LOG
-- ============================================================================

CREATE TABLE authorization_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT REFERENCES access_requests(request_id),

    user_id BIGINT REFERENCES users(user_id),

    resource_id BIGINT REFERENCES resources(resource_id),

    permission_id BIGINT REFERENCES permissions(permission_id),

    decision access_decision NOT NULL,

    reason TEXT NOT NULL,

    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    transaction_id BIGINT DEFAULT txid_current()
);

CREATE INDEX idx_authorization_audit_time
    ON authorization_audit(evaluated_at DESC);

CREATE INDEX idx_authorization_audit_denials
    ON authorization_audit(evaluated_at DESC)
    WHERE decision = 'DENY';

-- ============================================================================
-- CLASSIFICATION ORDERING
-- ============================================================================

CREATE FUNCTION classification_rank(
    p_level classification_level
)
RETURNS INTEGER
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT CASE p_level
        WHEN 'PUBLIC' THEN 0
        WHEN 'INTERNAL' THEN 1
        WHEN 'CONFIDENTIAL' THEN 2
        WHEN 'SECRET' THEN 3
        WHEN 'TOP_SECRET' THEN 4
    END;
$$;

-- ============================================================================
-- DAC OWNERSHIP VALIDATION
-- ============================================================================
-- A resource owner may grant ACL entries for that resource.
-- A separate privileged database role should administer global policy.

CREATE FUNCTION validate_acl_owner()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_owner_id BIGINT;
BEGIN
    SELECT owner_id
    INTO v_owner_id
    FROM resources
    WHERE resource_id = NEW.resource_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Resource does not exist';
    END IF;

    IF v_owner_id <> NEW.granted_by THEN
        RAISE EXCEPTION
            'Only the resource owner may issue DAC grants';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_acl_owner
BEFORE INSERT OR UPDATE ON access_control_entries
FOR EACH ROW
EXECUTE FUNCTION validate_acl_owner();

-- ============================================================================
-- AUDIT IMMUTABILITY
-- ============================================================================

CREATE FUNCTION prevent_audit_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'Authorization audit records are immutable';
END;
$$;

CREATE TRIGGER trg_audit_no_update
BEFORE UPDATE OR DELETE ON authorization_audit
FOR EACH ROW
EXECUTE FUNCTION prevent_audit_modification();

-- ============================================================================
-- SAMPLE DEPARTMENTS, USERS, ROLES, AND PERMISSIONS
-- ============================================================================

INSERT INTO departments(department_name)
VALUES
    ('Engineering'),
    ('Finance'),
    ('Security'),
    ('Compliance');

INSERT INTO users (
    username,
    department_id,
    location,
    clearance,
    active,
    suspended,
    mfa_verified,
    privileged_admin,
    delete_authorized
)
VALUES
    (
        'alice',
        (SELECT department_id FROM departments
         WHERE department_name = 'Engineering'),
        'India',
        'CONFIDENTIAL',
        TRUE,
        FALSE,
        TRUE,
        FALSE,
        FALSE
    ),
    (
        'bob',
        (SELECT department_id FROM departments
         WHERE department_name = 'Finance'),
        'India',
        'SECRET',
        TRUE,
        FALSE,
        TRUE,
        TRUE,
        TRUE
    ),
    (
        'charlie',
        (SELECT department_id FROM departments
         WHERE department_name = 'Engineering'),
        'India',
        'PUBLIC',
        FALSE,
        FALSE,
        FALSE,
        FALSE,
        FALSE
    ),
    (
        'diana',
        (SELECT department_id FROM departments
         WHERE department_name = 'Security'),
        'United States',
        'TOP_SECRET',
        TRUE,
        FALSE,
        TRUE,
        TRUE,
        TRUE
    );

INSERT INTO roles(role_name, description)
VALUES
    ('developer', 'Engineering development permissions'),
    ('security_admin', 'Privileged security administration'),
    ('auditor', 'Read access for compliance audits'),
    ('analyst', 'Restricted business analysis');

INSERT INTO permissions(permission_name, description)
VALUES
    ('READ', 'Read resource content'),
    ('WRITE', 'Modify resource content'),
    ('DELETE', 'Delete resource'),
    ('EXECUTE', 'Execute resource'),
    ('SHARE', 'Share resource'),
    ('ADMIN', 'Administer resource');

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
CROSS JOIN permissions p
WHERE (
    r.role_name = 'developer'
    AND p.permission_name IN ('READ', 'WRITE')
)
OR (
    r.role_name = 'security_admin'
    AND p.permission_name IN ('READ', 'ADMIN')
)
OR (
    r.role_name = 'auditor'
    AND p.permission_name = 'READ'
)
OR (
    r.role_name = 'analyst'
    AND p.permission_name = 'READ'
);

INSERT INTO user_roles(user_id, role_id, assigned_by)
SELECT u.user_id, r.role_id, u.user_id
FROM (
    VALUES
        ('alice', 'developer'),
        ('bob', 'security_admin'),
        ('diana', 'auditor')
) AS assignment(username, role_name)
JOIN users u ON u.username = assignment.username
JOIN roles r ON r.role_name = assignment.role_name;

-- ============================================================================
-- SAMPLE RESOURCES
-- ============================================================================

INSERT INTO resources (
    resource_name,
    owner_id,
    department_id,
    classification,
    require_mfa,
    deletion_enabled
)
VALUES
    (
        'source-code',
        (SELECT user_id FROM users WHERE username = 'alice'),
        (SELECT department_id FROM departments
         WHERE department_name = 'Engineering'),
        'CONFIDENTIAL',
        TRUE,
        FALSE
    ),
    (
        'financial-report',
        (SELECT user_id FROM users WHERE username = 'bob'),
        (SELECT department_id FROM departments
         WHERE department_name = 'Finance'),
        'SECRET',
        TRUE,
        TRUE
    ),
    (
        'public-document',
        (SELECT user_id FROM users WHERE username = 'alice'),
        (SELECT department_id FROM departments
         WHERE department_name = 'Engineering'),
        'PUBLIC',
        FALSE,
        FALSE
    );

INSERT INTO resource_attributes(
    resource_id,
    attribute_name,
    attribute_value
)
VALUES
    (
        (SELECT resource_id FROM resources
         WHERE resource_name = 'source-code'),
        'allowed_locations',
        '["India"]'::jsonb
    ),
    (
        (SELECT resource_id FROM resources
         WHERE resource_name = 'financial-report'),
        'allowed_locations',
        '["India"]'::jsonb
    ),
    (
        (SELECT resource_id FROM resources
         WHERE resource_name = 'source-code'),
        'business_unit',
        '"Engineering"'::jsonb
    );

-- ============================================================================
-- SAMPLE ACL ENTRIES
-- ============================================================================

INSERT INTO access_control_entries(
    resource_id,
    principal_kind,
    user_id,
    role_id,
    permission_id,
    granted_by
)
SELECT
    res.resource_id,
    'USER',
    target.user_id,
    NULL,
    perm.permission_id,
    owner.user_id
FROM resources res
JOIN users owner ON owner.user_id = res.owner_id
JOIN users target ON target.username = 'alice'
JOIN permissions perm ON perm.permission_name = 'READ'
WHERE res.resource_name = 'financial-report';

-- ============================================================================
-- SAMPLE POLICY DEFINITIONS
-- ============================================================================

INSERT INTO authorization_policies(
    policy_name,
    policy_category,
    description
)
VALUES
    (
        'department_access',
        'ABAC',
        'Restrict ordinary access to the resource department'
    ),
    (
        'classification_clearance',
        'MAC',
        'User clearance must dominate resource classification'
    ),
    (
        'least_privilege_delete',
        'LEAST_PRIVILEGE',
        'Deletion requires explicit user and resource authorization'
    ),
    (
        'explicit_suspension',
        'DENY',
        'Suspended accounts cannot access resources'
    );

-- ============================================================================
-- ACCESS CONTROL EVALUATION FUNCTION
-- ============================================================================
-- Grant logic:
--   RBAC OR ACL OR DAC
--
-- Mandatory conditions:
--   Active account AND MAC AND ABAC AND least privilege
--
-- Explicit deny:
--   Overrides all grant mechanisms.

CREATE FUNCTION evaluate_access(
    p_user_id BIGINT,
    p_resource_id BIGINT,
    p_permission permission_type,
    p_purpose access_purpose
)
RETURNS TABLE (
    decision access_decision,
    explanation TEXT,
    rbac_granted BOOLEAN,
    acl_granted BOOLEAN,
    dac_granted BOOLEAN,
    mac_passed BOOLEAN,
    abac_passed BOOLEAN,
    least_privilege_passed BOOLEAN
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_user users%ROWTYPE;
    v_resource resources%ROWTYPE;

    v_permission_id BIGINT;

    v_rbac BOOLEAN := FALSE;
    v_acl BOOLEAN := FALSE;
    v_dac BOOLEAN := FALSE;

    v_mac BOOLEAN := FALSE;
    v_abac BOOLEAN := FALSE;
    v_least BOOLEAN := FALSE;

    v_deny BOOLEAN := FALSE;
    v_grant BOOLEAN := FALSE;

    v_explanation TEXT := '';
BEGIN
    SELECT *
    INTO v_user
    FROM users
    WHERE user_id = p_user_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown user ID: %', p_user_id;
    END IF;

    SELECT *
    INTO v_resource
    FROM resources
    WHERE resource_id = p_resource_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown resource ID: %', p_resource_id;
    END IF;

    SELECT permission_id
    INTO v_permission_id
    FROM permissions
    WHERE permission_name = p_permission;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown permission';
    END IF;

    -- Explicit deny rules have precedence over grants.
    SELECT EXISTS (
        SELECT 1
        FROM explicit_deny_rules d
        WHERE d.enabled = TRUE
          AND (
              d.user_id IS NULL
              OR d.user_id = p_user_id
          )
          AND (
              d.department_id IS NULL
              OR d.department_id = v_user.department_id
          )
          AND (
              d.resource_id IS NULL
              OR d.resource_id = p_resource_id
          )
          AND (
              d.permission_id IS NULL
              OR d.permission_id = v_permission_id
          )
    )
    INTO v_deny;

    IF v_deny THEN
        RETURN QUERY SELECT
            'DENY'::access_decision,
            'Explicit deny rule matched'::TEXT,
            FALSE, FALSE, FALSE, FALSE, FALSE, FALSE;

        RETURN;
    END IF;

    IF NOT v_user.active OR v_user.suspended THEN
        RETURN QUERY SELECT
            'DENY'::access_decision,
            'Inactive or suspended account'::TEXT,
            FALSE, FALSE, FALSE, FALSE, FALSE, FALSE;

        RETURN;
    END IF;

    IF NOT v_resource.active THEN
        RETURN QUERY SELECT
            'DENY'::access_decision,
            'Resource is inactive'::TEXT,
            FALSE, FALSE, FALSE, FALSE, FALSE, FALSE;

        RETURN;
    END IF;

    -- RBAC: any assigned role can supply the requested permission.
    SELECT EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        WHERE ur.user_id = p_user_id
          AND rp.permission_id = v_permission_id
    )
    INTO v_rbac;

    -- ACL: direct user or assigned role entry.
    SELECT EXISTS (
        SELECT 1
        FROM access_control_entries ace
        WHERE ace.resource_id = p_resource_id
          AND ace.permission_id = v_permission_id
          AND (
              (
                  ace.principal_kind = 'USER'
                  AND ace.user_id = p_user_id
              )
              OR
              (
                  ace.principal_kind = 'ROLE'
                  AND ace.role_id IN (
                      SELECT role_id
                      FROM user_roles
                      WHERE user_id = p_user_id
                  )
              )
          )
    )
    INTO v_acl;

    -- DAC: resource owner receives limited ownership permissions.
    v_dac :=
        v_resource.owner_id = p_user_id
        AND p_permission IN ('READ', 'WRITE', 'SHARE');

    -- MAC: clearance must dominate classification.
    v_mac :=
        classification_rank(v_user.clearance)
        >= classification_rank(v_resource.classification);

    -- ABAC: department, location, purpose, and MFA.
    v_abac :=
        (
            v_user.department_id = v_resource.department_id
            OR p_purpose = 'COMPLIANCE'
        )
        AND (
            NOT EXISTS (
                SELECT 1
                FROM resource_attributes ra
                WHERE ra.resource_id = p_resource_id
                  AND ra.attribute_name = 'allowed_locations'
            )
            OR EXISTS (
                SELECT 1
                FROM resource_attributes ra
                WHERE ra.resource_id = p_resource_id
                  AND ra.attribute_name = 'allowed_locations'
                  AND ra.attribute_value ? v_user.location
            )
        )
        AND (
            NOT v_resource.require_mfa
            OR v_user.mfa_verified
        );

    -- Least privilege: destructive and administrative permissions
    -- require specific user-level authorization.
    v_least :=
        CASE
            WHEN p_permission = 'ADMIN'
                THEN v_user.privileged_admin
            WHEN p_permission = 'DELETE'
                THEN v_user.delete_authorized
                     AND v_resource.deletion_enabled
            ELSE TRUE
        END;

    v_grant := v_rbac OR v_acl OR v_dac;

    IF NOT v_grant THEN
        v_explanation := 'No RBAC, ACL, or DAC grant';
    ELSIF NOT v_mac THEN
        v_explanation := 'MAC clearance failure';
    ELSIF NOT v_abac THEN
        v_explanation := 'ABAC attribute failure';
    ELSIF NOT v_least THEN
        v_explanation := 'Least-privilege restriction';
    ELSE
        v_explanation := 'All mandatory conditions and grant checks passed';
    END IF;

    RETURN QUERY SELECT
        CASE
            WHEN v_grant AND v_mac AND v_abac AND v_least
                THEN 'ALLOW'::access_decision
            ELSE 'DENY'::access_decision
        END,
        v_explanation,
        v_rbac,
        v_acl,
        v_dac,
        v_mac,
        v_abac,
        v_least;
END;
$$;

-- ============================================================================
-- WORKFLOW PROCEDURE
-- ============================================================================
-- Every evaluation creates a request and an immutable audit event.

CREATE PROCEDURE process_access_request(
    p_username VARCHAR(128),
    p_resource_name VARCHAR(150),
    p_permission permission_type,
    p_purpose access_purpose
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id BIGINT;
    v_resource_id BIGINT;
    v_permission_id BIGINT;
    v_request_id BIGINT;

    v_decision access_decision;
    v_explanation TEXT;
BEGIN
    SELECT user_id
    INTO v_user_id
    FROM users
    WHERE username = p_username;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown username: %', p_username;
    END IF;

    SELECT resource_id
    INTO v_resource_id
    FROM resources
    WHERE resource_name = p_resource_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown resource: %', p_resource_name;
    END IF;

    SELECT permission_id
    INTO v_permission_id
    FROM permissions
    WHERE permission_name = p_permission;

    INSERT INTO access_requests(
        user_id,
        resource_id,
        permission_id,
        purpose
    )
    VALUES (
        v_user_id,
        v_resource_id,
        v_permission_id,
        p_purpose
    )
    RETURNING request_id INTO v_request_id;

    SELECT
        e.decision,
        e.explanation
    INTO
        v_decision,
        v_explanation
    FROM evaluate_access(
        v_user_id,
        v_resource_id,
        p_permission,
        p_purpose
    ) e;

    UPDATE access_requests
    SET decision = v_decision,
        decision_reason = v_explanation,
        decided_at = CURRENT_TIMESTAMP
    WHERE request_id = v_request_id;

    INSERT INTO authorization_audit(
        request_id,
        user_id,
        resource_id,
        permission_id,
        decision,
        reason
    )
    VALUES (
        v_request_id,
        v_user_id,
        v_resource_id,
        v_permission_id,
        v_decision,
        v_explanation
    );
END;
$$;

-- ============================================================================
-- VIEWS
-- ============================================================================

CREATE VIEW v_user_effective_roles AS
SELECT
    u.username,
    r.role_name,
    p.permission_name,
    ur.assigned_at
FROM users u
JOIN user_roles ur ON ur.user_id = u.user_id
JOIN roles r ON r.role_id = ur.role_id
JOIN role_permissions rp ON rp.role_id = r.role_id
JOIN permissions p ON p.permission_id = rp.permission_id;

CREATE VIEW v_resource_ownership AS
SELECT
    res.resource_name,
    owner.username AS owner,
    d.department_name,
    res.classification,
    res.require_mfa,
    res.deletion_enabled
FROM resources res
JOIN users owner ON owner.user_id = res.owner_id
JOIN departments d ON d.department_id = res.department_id;

CREATE VIEW v_access_decision_report AS
SELECT
    ar.request_id,
    u.username,
    res.resource_name,
    p.permission_name,
    ar.purpose,
    ar.decision,
    ar.decision_reason,
    ar.requested_at,
    ar.decided_at
FROM access_requests ar
JOIN users u ON u.user_id = ar.user_id
JOIN resources res ON res.resource_id = ar.resource_id
JOIN permissions p ON p.permission_id = ar.permission_id;

-- ============================================================================
-- WORKFLOW EXECUTION
-- ============================================================================

-- Valid RBAC request.
CALL process_access_request(
    'alice',
    'source-code',
    'READ',
    'BUSINESS'
);

-- ACL grant exists, but MAC prevents access to SECRET data.
CALL process_access_request(
    'alice',
    'financial-report',
    'READ',
    'COMPLIANCE'
);

-- Alice cannot modify the financial report.
CALL process_access_request(
    'alice',
    'financial-report',
    'WRITE',
    'COMPLIANCE'
);

-- Bob can access his classified report.
CALL process_access_request(
    'bob',
    'financial-report',
    'READ',
    'BUSINESS'
);

-- Least privilege prevents unauthorized deletion.
CALL process_access_request(
    'alice',
    'source-code',
    'DELETE',
    'MAINTENANCE'
);

-- Inactive account is denied.
CALL process_access_request(
    'charlie',
    'source-code',
    'READ',
    'BUSINESS'
);

-- ============================================================================
-- EXPLICIT DENY SCENARIO
-- ============================================================================

INSERT INTO explicit_deny_rules(
    user_id,
    reason
)
SELECT user_id, 'Temporary account suspension'
FROM users
WHERE username = 'alice';

CALL process_access_request(
    'alice',
    'source-code',
    'READ',
    'BUSINESS'
);

-- ============================================================================
-- RETRIEVAL QUERIES
-- ============================================================================

-- Users and their assigned permissions.
SELECT *
FROM v_user_effective_roles
ORDER BY username, role_name, permission_name;

-- Resource ownership and classifications.
SELECT *
FROM v_resource_ownership
ORDER BY resource_name;

-- Complete access history.
SELECT *
FROM v_access_decision_report
ORDER BY requested_at DESC;

-- ============================================================================
-- VALIDATION QUERIES
-- ============================================================================

-- Check that every active role assignment has a valid role.
SELECT
    u.username,
    r.role_name
FROM user_roles ur
JOIN users u ON u.user_id = ur.user_id
JOIN roles r ON r.role_id = ur.role_id;

-- Identify users with clearance below a resource classification.
SELECT
    u.username,
    res.resource_name,
    u.clearance,
    res.classification
FROM users u
CROSS JOIN resources res
WHERE classification_rank(u.clearance)
    < classification_rank(res.classification);

-- Identify resources that permit deletion.
SELECT
    resource_name,
    owner_id,
    classification
FROM resources
WHERE deletion_enabled = TRUE;

-- ============================================================================
-- AGGREGATION AND REPORTING
-- ============================================================================

-- Allow and deny counts.
SELECT
    decision,
    COUNT(*) AS total_requests
FROM authorization_audit
GROUP BY decision
ORDER BY decision;

-- Decisions by user.
SELECT
    u.username,
    COUNT(*) AS total_requests,
    COUNT(*) FILTER (
        WHERE a.decision = 'ALLOW'
    ) AS allowed,
    COUNT(*) FILTER (
        WHERE a.decision = 'DENY'
    ) AS denied
FROM authorization_audit a
JOIN users u ON u.user_id = a.user_id
GROUP BY u.username
ORDER BY total_requests DESC;

-- Most frequently accessed resources.
SELECT
    res.resource_name,
    COUNT(*) AS request_count
FROM authorization_audit a
JOIN resources res ON res.resource_id = a.resource_id
GROUP BY res.resource_name
ORDER BY request_count DESC;

-- Denial rate by resource.
SELECT
    res.resource_name,
    COUNT(*) AS total,
    COUNT(*) FILTER (
        WHERE a.decision = 'DENY'
    ) AS denied,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE a.decision = 'DENY'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS denial_percentage
FROM authorization_audit a
JOIN resources res ON res.resource_id = a.resource_id
GROUP BY res.resource_name;

-- ============================================================================
-- CTE: EFFECTIVE RBAC PERMISSIONS
-- ============================================================================

WITH effective_permissions AS (
    SELECT DISTINCT
        u.user_id,
        u.username,
        p.permission_name
    FROM users u
    JOIN user_roles ur ON ur.user_id = u.user_id
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    JOIN permissions p ON p.permission_id = rp.permission_id
)
SELECT
    username,
    COUNT(*) AS permission_count,
    STRING_AGG(
        permission_name::TEXT,
        ', ' ORDER BY permission_name
    ) AS permissions
FROM effective_permissions
GROUP BY username
ORDER BY username;

-- ============================================================================
-- CTE: RESOURCE ACCESS REVIEW
-- ============================================================================

WITH resource_grants AS (
    SELECT
        ace.resource_id,
        COUNT(*) AS acl_grant_count
    FROM access_control_entries ace
    GROUP BY ace.resource_id
),
role_grants AS (
    SELECT
        res.resource_id,
        COUNT(*) AS role_grant_count
    FROM resources res
    JOIN user_roles ur ON TRUE
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    WHERE EXISTS (
        SELECT 1
        FROM users u
        WHERE u.user_id = ur.user_id
          AND u.department_id = res.department_id
    )
    GROUP BY res.resource_id
)
SELECT
    res.resource_name,
    COALESCE(rg.acl_grant_count, 0) AS acl_grants,
    COALESCE(ro.role_grant_count, 0) AS role_grants
FROM resources res
LEFT JOIN resource_grants rg
    ON rg.resource_id = res.resource_id
LEFT JOIN role_grants ro
    ON ro.resource_id = res.resource_id
ORDER BY res.resource_name;

-- ============================================================================
-- ELIGIBILITY DETERMINATION
-- ============================================================================

SELECT
    u.username,
    res.resource_name,
    p.permission_name,
    e.decision,
    e.explanation,
    e.rbac_granted,
    e.acl_granted,
    e.dac_granted,
    e.mac_passed,
    e.abac_passed,
    e.least_privilege_passed
FROM users u
CROSS JOIN resources res
CROSS JOIN permissions p
CROSS JOIN LATERAL evaluate_access(
    u.user_id,
    res.resource_id,
    p.permission_name,
    'BUSINESS'
) e
WHERE u.username IN ('alice', 'bob')
  AND res.resource_name IN (
      'source-code',
      'financial-report'
  )
ORDER BY u.username, res.resource_name, p.permission_name;

-- ============================================================================
-- TRANSACTIONAL ROLE REVOCATION
-- ============================================================================
-- Demonstrates atomic removal of an assignment.
-- The rollback leaves the sample assignment unchanged.

SAVEPOINT before_role_revocation;

DELETE FROM user_roles
WHERE user_id = (
    SELECT user_id FROM users WHERE username = 'alice'
)
AND role_id = (
    SELECT role_id FROM roles WHERE role_name = 'developer'
);

ROLLBACK TO SAVEPOINT before_role_revocation;

RELEASE SAVEPOINT before_role_revocation;

-- ============================================================================
-- FINAL SECURITY REPORT
-- ============================================================================

SELECT
    COUNT(*) AS total_access_requests,
    COUNT(*) FILTER (
        WHERE decision = 'ALLOW'
    ) AS successful_requests,
    COUNT(*) FILTER (
        WHERE decision = 'DENY'
    ) AS rejected_requests
FROM authorization_audit;

COMMIT;
