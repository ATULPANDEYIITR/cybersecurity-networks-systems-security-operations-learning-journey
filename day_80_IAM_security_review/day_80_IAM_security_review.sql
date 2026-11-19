/*
===============================================================================
IAM SECURITY REVIEW
Identity Attack Surface, Privilege Escalation, and Access Reviews
PostgreSQL 14+

Relational implementation covering:
- Identity inventory
- RBAC and inherited permissions
- Privilege escalation exposure
- Role conflicts and separation of duties
- Access certification
- Review decisions
- Identity lifecycle
- Privileged account governance
- Audit events
- Risk assessment
- Remediation tracking
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS iam;

SET search_path TO iam, public;

-- ============================================================================
-- ENUMERATED DOMAIN STATES
-- ============================================================================

CREATE TYPE identity_type AS ENUM (
    'human',
    'service',
    'application',
    'external'
);

CREATE TYPE identity_status AS ENUM (
    'active',
    'suspended',
    'disabled'
);

CREATE TYPE review_decision AS ENUM (
    'approve',
    'revoke',
    'reduce',
    'escalate',
    'pending'
);

CREATE TYPE finding_severity AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE review_status AS ENUM (
    'open',
    'completed',
    'cancelled'
);

-- ============================================================================
-- IDENTITY INVENTORY
-- ============================================================================

CREATE TABLE identities (
    identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_id VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(200) NOT NULL,
    identity_kind identity_type NOT NULL,
    status identity_status NOT NULL DEFAULT 'active',
    owner_id VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    email VARCHAR(254),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    credential_rotation_at TIMESTAMPTZ,
    service_expiry_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_identity_name
        CHECK (length(trim(display_name)) > 0),

    CONSTRAINT valid_owner
        CHECK (length(trim(owner_id)) > 0),

    CONSTRAINT valid_metadata
        CHECK (jsonb_typeof(metadata) = 'object'),

    CONSTRAINT valid_login_timestamp
        CHECK (last_login_at IS NULL OR last_login_at >= created_at)
);

CREATE INDEX idx_identity_status
    ON identities(status);

CREATE INDEX idx_identity_owner
    ON identities(owner_id);

CREATE INDEX idx_identity_department
    ON identities(department);

CREATE INDEX idx_identity_last_login
    ON identities(last_login_at)
    WHERE status = 'active';

CREATE INDEX idx_identity_service_expiry
    ON identities(service_expiry_at)
    WHERE identity_kind = 'service';

-- ============================================================================
-- ROLE AND PERMISSION CATALOG
-- ============================================================================

CREATE TABLE roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_code VARCHAR(100) NOT NULL UNIQUE,
    role_name VARCHAR(200) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_privileged BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE permissions (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    resource_name VARCHAR(150) NOT NULL,
    action_name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    sensitivity VARCHAR(20) NOT NULL DEFAULT 'normal',

    CONSTRAINT unique_resource_action
        UNIQUE(resource_name, action_name),

    CONSTRAINT valid_sensitivity
        CHECK (sensitivity IN (
            'normal', 'sensitive', 'critical'
        ))
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(permission_id)
        ON DELETE RESTRICT,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(role_id, permission_id)
);

CREATE TABLE role_inheritance (
    child_role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE CASCADE,
    parent_role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY(child_role_id, parent_role_id),

    CONSTRAINT no_direct_self_inheritance
        CHECK(child_role_id <> parent_role_id)
);

CREATE TABLE identity_roles (
    identity_id BIGINT NOT NULL REFERENCES identities(identity_id)
        ON DELETE CASCADE,
    role_id BIGINT NOT NULL REFERENCES roles(role_id)
        ON DELETE RESTRICT,
    assigned_by VARCHAR(100) NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    assignment_reason TEXT NOT NULL,

    PRIMARY KEY(identity_id, role_id),

    CONSTRAINT valid_assignment_expiry
        CHECK(expires_at IS NULL OR expires_at > assigned_at)
);

CREATE INDEX idx_identity_roles_role
    ON identity_roles(role_id);

CREATE INDEX idx_role_inheritance_parent
    ON role_inheritance(parent_role_id);

CREATE TABLE direct_permissions (
    identity_id BIGINT NOT NULL REFERENCES identities(identity_id)
        ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions(permission_id)
        ON DELETE RESTRICT,
    granted_by VARCHAR(100) NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    justification TEXT NOT NULL,

    PRIMARY KEY(identity_id, permission_id),

    CONSTRAINT valid_direct_permission_expiry
        CHECK(expires_at IS NULL OR expires_at > granted_at)
);

-- ============================================================================
-- SEPARATION OF DUTIES
-- ============================================================================

CREATE TABLE role_conflicts (
    conflict_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_a BIGINT NOT NULL REFERENCES roles(role_id),
    role_b BIGINT NOT NULL REFERENCES roles(role_id),
    description TEXT NOT NULL,
    severity finding_severity NOT NULL DEFAULT 'critical',

    CONSTRAINT distinct_conflicting_roles
        CHECK(role_a <> role_b),

    CONSTRAINT unique_role_conflict
        UNIQUE(role_a, role_b)
);

-- ============================================================================
-- ACCESS REVIEW WORKFLOW
-- ============================================================================

CREATE TABLE access_review_campaigns (
    campaign_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_name VARCHAR(200) NOT NULL,
    scope_description TEXT NOT NULL,
    start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    due_date TIMESTAMPTZ NOT NULL,
    status review_status NOT NULL DEFAULT 'open',
    created_by VARCHAR(100) NOT NULL,

    CONSTRAINT valid_campaign_period
        CHECK(due_date > start_date)
);

CREATE TABLE access_reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    campaign_id BIGINT NOT NULL
        REFERENCES access_review_campaigns(campaign_id),
    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),
    reviewer_id VARCHAR(100) NOT NULL,
    decision review_decision NOT NULL DEFAULT 'pending',
    justification TEXT NOT NULL DEFAULT '',
    reviewed_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    previous_status identity_status,
    version_number INTEGER NOT NULL DEFAULT 1,

    CONSTRAINT unique_campaign_identity
        UNIQUE(campaign_id, identity_id),

    CONSTRAINT valid_review_version
        CHECK(version_number > 0),

    CONSTRAINT valid_completed_review
        CHECK(
            (decision = 'pending' AND completed_at IS NULL)
            OR
            (decision <> 'pending' AND completed_at IS NOT NULL)
        )
);

CREATE INDEX idx_reviews_pending
    ON access_reviews(campaign_id, decision)
    WHERE decision = 'pending';

CREATE INDEX idx_reviews_identity
    ON access_reviews(identity_id, completed_at DESC);

-- ============================================================================
-- REVIEWED ACCESS OBJECTS
-- ============================================================================

CREATE TABLE review_scope (
    review_scope_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    review_id BIGINT NOT NULL
        REFERENCES access_reviews(review_id) ON DELETE CASCADE,
    object_type VARCHAR(20) NOT NULL,
    object_id BIGINT NOT NULL,
    original_decision review_decision NOT NULL DEFAULT 'pending',
    final_decision review_decision NOT NULL DEFAULT 'pending',
    reason TEXT NOT NULL DEFAULT '',

    CONSTRAINT valid_review_object_type
        CHECK(object_type IN ('role', 'permission')),

    CONSTRAINT unique_review_object
        UNIQUE(review_id, object_type, object_id)
);

-- ============================================================================
-- SECURITY FINDINGS
-- ============================================================================

CREATE TABLE security_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    identity_id BIGINT NOT NULL
        REFERENCES identities(identity_id),
    category VARCHAR(100) NOT NULL,
    severity finding_severity NOT NULL,
    risk_score INTEGER NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::JSONB,
    recommendation TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    is_open BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT valid_risk_score
        CHECK(risk_score BETWEEN 0 AND 100),

    CONSTRAINT valid_finding_evidence
        CHECK(jsonb_typeof(evidence) = 'object'),

    CONSTRAINT valid_resolution_state
        CHECK(
            (is_open = TRUE AND resolved_at IS NULL)
            OR
            (is_open = FALSE AND resolved_at IS NOT NULL)
        )
);

CREATE INDEX idx_findings_open_risk
    ON security_findings(risk_score DESC, severity)
    WHERE is_open = TRUE;

CREATE INDEX idx_findings_identity
    ON security_findings(identity_id, detected_at DESC);

-- ============================================================================
-- SECURITY AUDIT TRAIL
-- ============================================================================

CREATE TABLE audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100) NOT NULL,
    entity_reference VARCHAR(150) NOT NULL,
    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_address INET,

    CONSTRAINT valid_event_details
        CHECK(jsonb_typeof(event_details) = 'object')
);

CREATE INDEX idx_audit_entity
    ON audit_events(entity_type, entity_reference, event_timestamp DESC);

CREATE INDEX idx_audit_actor
    ON audit_events(actor_id, event_timestamp DESC);

-- ============================================================================
-- TRIGGER: PROTECT AUDIT HISTORY FROM MODIFICATION
-- ============================================================================

CREATE FUNCTION reject_audit_modification()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION
        'Audit events are append-only and cannot be modified or deleted';
END;
$$;

CREATE TRIGGER trg_audit_immutable
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW
EXECUTE FUNCTION reject_audit_modification();

-- ============================================================================
-- TRIGGER: VALIDATE ROLE INHERITANCE CYCLES
-- ============================================================================

CREATE FUNCTION validate_role_inheritance()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        WITH RECURSIVE ancestry(role_id, path, cycle) AS (
            SELECT
                NEW.parent_role_id,
                ARRAY[NEW.child_role_id, NEW.parent_role_id],
                NEW.parent_role_id = NEW.child_role_id

            UNION ALL

            SELECT
                ri.parent_role_id,
                a.path || ri.parent_role_id,
                ri.parent_role_id = ANY(a.path)
            FROM ancestry a
            JOIN role_inheritance ri
                ON ri.child_role_id = a.role_id
            WHERE NOT a.cycle
        )
        SELECT 1
        FROM ancestry
        WHERE cycle
    ) THEN
        RAISE EXCEPTION
            'Role inheritance would introduce a circular dependency';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_role_inheritance
BEFORE INSERT OR UPDATE ON role_inheritance
FOR EACH ROW
EXECUTE FUNCTION validate_role_inheritance();

-- ============================================================================
-- TRIGGER: ACCESS REVIEW COMPLETION VALIDATION
-- ============================================================================

CREATE FUNCTION validate_access_review()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.decision <> 'pending' THEN
        IF length(trim(NEW.reviewer_id)) = 0 THEN
            RAISE EXCEPTION 'Reviewer is required';
        END IF;

        IF length(trim(NEW.justification)) < 10 THEN
            RAISE EXCEPTION
                'Completed review requires at least 10 characters of justification';
        END IF;

        IF NEW.completed_at IS NULL THEN
            NEW.completed_at := NOW();
        END IF;

        IF NEW.reviewed_at IS NULL THEN
            NEW.reviewed_at := NOW();
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_access_review
BEFORE INSERT OR UPDATE ON access_reviews
FOR EACH ROW
EXECUTE FUNCTION validate_access_review();

-- ============================================================================
-- FUNCTION: EFFECTIVE PERMISSIONS
-- ============================================================================

CREATE FUNCTION get_effective_permissions(
    p_identity_id BIGINT,
    p_as_of TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
    permission_id BIGINT,
    resource_name VARCHAR,
    action_name VARCHAR,
    grant_source TEXT
)
LANGUAGE sql
STABLE
AS $$
    WITH RECURSIVE assigned_roles(role_id) AS (
        SELECT ir.role_id
        FROM identity_roles ir
        JOIN identities i
            ON i.identity_id = ir.identity_id
        WHERE ir.identity_id = p_identity_id
          AND i.status = 'active'
          AND ir.assigned_at <= p_as_of
          AND (ir.expires_at IS NULL OR ir.expires_at > p_as_of)

        UNION

        SELECT ri.parent_role_id
        FROM role_inheritance ri
        JOIN assigned_roles ar
            ON ri.child_role_id = ar.role_id
        JOIN roles r
            ON r.role_id = ri.parent_role_id
        WHERE r.is_active = TRUE
    ),
    role_grants AS (
        SELECT
            rp.permission_id,
            'role'::TEXT AS grant_source
        FROM assigned_roles ar
        JOIN roles r
            ON r.role_id = ar.role_id
        JOIN role_permissions rp
            ON rp.role_id = r.role_id
        WHERE r.is_active = TRUE
    ),
    direct_grants AS (
        SELECT
            dp.permission_id,
            'direct'::TEXT AS grant_source
        FROM direct_permissions dp
        JOIN identities i
            ON i.identity_id = dp.identity_id
        WHERE dp.identity_id = p_identity_id
          AND i.status = 'active'
          AND dp.granted_at <= p_as_of
          AND (dp.expires_at IS NULL OR dp.expires_at > p_as_of)
    ),
    all_grants AS (
        SELECT permission_id, grant_source
        FROM role_grants

        UNION ALL

        SELECT permission_id, grant_source
        FROM direct_grants
    )
    SELECT DISTINCT
        p.permission_id,
        p.resource_name::VARCHAR,
        p.action_name::VARCHAR,
        ag.grant_source
    FROM all_grants ag
    JOIN permissions p
        ON p.permission_id = ag.permission_id;
$$;

-- ============================================================================
-- FUNCTION: PRIVILEGE ESCALATION EXPOSURE
-- ============================================================================

CREATE FUNCTION detect_privilege_exposure()
RETURNS TABLE (
    identity_id BIGINT,
    external_id VARCHAR,
    sensitive_permissions BIGINT,
    privileged_roles BIGINT,
    risk_score INTEGER
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        i.identity_id,
        i.external_id,
        COUNT(DISTINCT ep.permission_id)
            FILTER (
                WHERE p.sensitivity = 'critical'
                   OR p.action_name IN (
                       'admin',
                       'manage_roles',
                       'manage_policies',
                       'manage_credentials',
                       'configure_security'
                   )
            ) AS sensitive_permissions,

        COUNT(DISTINCT ir.role_id)
            FILTER (WHERE r.is_privileged = TRUE) AS privileged_roles,

        LEAST(
            100,
            50
            + 15 * COUNT(DISTINCT ep.permission_id)
                FILTER (
                    WHERE p.sensitivity = 'critical'
                       OR p.action_name IN (
                           'admin',
                           'manage_roles',
                           'manage_policies',
                           'manage_credentials'
                       )
                )
            + 20 * COUNT(DISTINCT ir.role_id)
                FILTER (WHERE r.is_privileged = TRUE)
        )::INTEGER AS risk_score

    FROM identities i

    LEFT JOIN identity_roles ir
        ON ir.identity_id = i.identity_id
       AND ir.assigned_at <= NOW()
       AND (ir.expires_at IS NULL OR ir.expires_at > NOW())

    LEFT JOIN roles r
        ON r.role_id = ir.role_id

    LEFT JOIN LATERAL get_effective_permissions(
        i.identity_id,
        NOW()
    ) ep ON TRUE

    LEFT JOIN permissions p
        ON p.permission_id = ep.permission_id

    WHERE i.status = 'active'

    GROUP BY i.identity_id, i.external_id
    HAVING
        COUNT(DISTINCT ep.permission_id)
            FILTER (
                WHERE p.sensitivity = 'critical'
                   OR p.action_name IN (
                       'admin',
                       'manage_roles',
                       'manage_policies',
                       'manage_credentials',
                       'configure_security'
                   )
            ) > 0
        OR
        COUNT(DISTINCT ir.role_id)
            FILTER (WHERE r.is_privileged = TRUE) > 0;
$$;

-- ============================================================================
-- VIEW: IDENTITY ATTACK SURFACE
-- ============================================================================

CREATE VIEW identity_attack_surface AS
SELECT
    i.identity_id,
    i.external_id,
    i.display_name,
    i.identity_kind,
    i.status,
    i.owner_id,
    i.department,
    i.mfa_enabled,
    i.last_login_at,
    COUNT(DISTINCT ep.permission_id) AS effective_permission_count,
    COUNT(DISTINCT ep.permission_id)
        FILTER (
            WHERE p.sensitivity IN ('sensitive', 'critical')
        ) AS sensitive_permission_count,
    COUNT(DISTINCT ir.role_id) AS directly_assigned_roles,
    BOOL_OR(COALESCE(r.is_privileged, FALSE)) AS has_privileged_role

FROM identities i

LEFT JOIN identity_roles ir
    ON ir.identity_id = i.identity_id
   AND ir.assigned_at <= NOW()
   AND (ir.expires_at IS NULL OR ir.expires_at > NOW())

LEFT JOIN roles r
    ON r.role_id = ir.role_id

LEFT JOIN LATERAL get_effective_permissions(
    i.identity_id,
    NOW()
) ep ON TRUE

LEFT JOIN permissions p
    ON p.permission_id = ep.permission_id

GROUP BY i.identity_id;

-- ============================================================================
-- FUNCTION: SEPARATION OF DUTIES VIOLATIONS
-- ============================================================================

CREATE FUNCTION find_separation_of_duties_violations()
RETURNS TABLE (
    identity_id BIGINT,
    external_id VARCHAR,
    role_a VARCHAR,
    role_b VARCHAR,
    violation_description TEXT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        i.identity_id,
        i.external_id,
        ra.role_code,
        rb.role_code,
        rc.description
    FROM identities i
    JOIN identity_roles ira
        ON ira.identity_id = i.identity_id
    JOIN identity_roles irb
        ON irb.identity_id = i.identity_id
    JOIN role_conflicts rc
        ON (
            rc.role_a = ira.role_id
            AND rc.role_b = irb.role_id
        )
        OR (
            rc.role_a = irb.role_id
            AND rc.role_b = ira.role_id
        )
    JOIN roles ra
        ON ra.role_id = ira.role_id
    JOIN roles rb
        ON rb.role_id = irb.role_id
    WHERE i.status = 'active'
      AND ira.assigned_at <= NOW()
      AND (ira.expires_at IS NULL OR ira.expires_at > NOW())
      AND irb.assigned_at <= NOW()
      AND (irb.expires_at IS NULL OR irb.expires_at > NOW());
$$;

-- ============================================================================
-- PROCEDURE: RECORD ASSESSMENT FINDINGS
-- ============================================================================

CREATE PROCEDURE run_iam_assessment()
LANGUAGE plpgsql
AS $$
BEGIN
    -- Retain historical findings and mark resolved findings separately.
    INSERT INTO security_findings (
        identity_id,
        category,
        severity,
        risk_score,
        evidence,
        recommendation
    )
    SELECT
        i.identity_id,
        'PRIVILEGE_ESCALATION_EXPOSURE',
        'critical',
        LEAST(100, d.risk_score),
        jsonb_build_object(
            'sensitive_permissions', d.sensitive_permissions,
            'privileged_roles', d.privileged_roles
        ),
        'Review sensitive permissions and privileged role assignments.'
    FROM detect_privilege_exposure() d
    JOIN identities i
        ON i.identity_id = d.identity_id;

    INSERT INTO security_findings (
        identity_id,
        category,
        severity,
        risk_score,
        evidence,
        recommendation
    )
    SELECT
        i.identity_id,
        'MISSING_MFA',
        'critical',
        95,
        jsonb_build_object(
            'identity_type', i.identity_kind,
            'owner', i.owner_id
        ),
        'Enable MFA for active privileged and sensitive identities.'
    FROM identities i
    WHERE i.status = 'active'
      AND i.mfa_enabled = FALSE
      AND (
          EXISTS (
              SELECT 1
              FROM identity_roles ir
              JOIN roles r ON r.role_id = ir.role_id
              WHERE ir.identity_id = i.identity_id
                AND r.is_privileged = TRUE
                AND ir.assigned_at <= NOW()
                AND (ir.expires_at IS NULL OR ir.expires_at > NOW())
          )
          OR EXISTS (
              SELECT 1
              FROM get_effective_permissions(i.identity_id) ep
              JOIN permissions p
                  ON p.permission_id = ep.permission_id
              WHERE p.sensitivity = 'critical'
          )
      );

    INSERT INTO security_findings (
        identity_id,
        category,
        severity,
        risk_score,
        evidence,
        recommendation
    )
    SELECT
        identity_id,
        'DORMANT_IDENTITY',
        CASE
            WHEN identity_kind IN ('service', 'application')
                THEN 'critical'::finding_severity
            ELSE 'high'::finding_severity
        END,
        CASE
            WHEN identity_kind IN ('service', 'application') THEN 90
            ELSE 75
        END,
        jsonb_build_object(
            'last_login_at', last_login_at,
            'identity_type', identity_kind
        ),
        'Verify ownership and disable unused identities.'
    FROM identities
    WHERE status = 'active'
      AND (
          last_login_at IS NULL
          OR last_login_at < NOW() - INTERVAL '90 days'
      );

    INSERT INTO security_findings (
        identity_id,
        category,
        severity,
        risk_score,
        evidence,
        recommendation
    )
    SELECT
        identity_id,
        'SEPARATION_OF_DUTIES',
        'critical',
        95,
        jsonb_build_object(
            'role_a', role_a,
            'role_b', role_b,
            'violation', violation_description
        ),
        'Remove conflicting access or establish an independent control.'
    FROM find_separation_of_duties_violations();

    INSERT INTO audit_events (
        actor_id,
        event_type,
        entity_type,
        entity_reference,
        event_details
    )
    VALUES (
        'system',
        'IAM_ASSESSMENT_COMPLETED',
        'security_assessment',
        'full_inventory',
        jsonb_build_object(
            'assessment_time', NOW(),
            'finding_count', (
                SELECT COUNT(*)
                FROM security_findings
                WHERE detected_at >= NOW() - INTERVAL '1 minute'
            )
        )
    );
END;
$$;

-- ============================================================================
-- PROCEDURE: PROCESS ACCESS REVIEW
-- ============================================================================

CREATE PROCEDURE process_access_review(
    p_review_id BIGINT,
    p_reviewer VARCHAR,
    p_decision review_decision,
    p_justification TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_identity_id BIGINT;
    v_current_status identity_status;
    v_campaign_status review_status;
BEGIN
    SELECT
        ar.identity_id,
        i.status,
        c.status
    INTO
        v_identity_id,
        v_current_status,
        v_campaign_status
    FROM access_reviews ar
    JOIN identities i
        ON i.identity_id = ar.identity_id
    JOIN access_review_campaigns c
        ON c.campaign_id = ar.campaign_id
    WHERE ar.review_id = p_review_id
    FOR UPDATE OF ar, i;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Access review % not found', p_review_id;
    END IF;

    IF v_campaign_status <> 'open' THEN
        RAISE EXCEPTION 'Access review campaign is not open';
    END IF;

    IF p_decision = 'pending' THEN
        RAISE EXCEPTION 'A pending decision cannot be processed';
    END IF;

    IF p_reviewer IS NULL OR length(trim(p_reviewer)) = 0 THEN
        RAISE EXCEPTION 'Reviewer is required';
    END IF;

    IF p_justification IS NULL
       OR length(trim(p_justification)) < 10 THEN
        RAISE EXCEPTION 'Review justification is insufficient';
    END IF;

    UPDATE access_reviews
    SET reviewer_id = p_reviewer,
        decision = p_decision,
        justification = p_justification,
        reviewed_at = NOW(),
        completed_at = NOW(),
        previous_status = v_current_status,
        version_number = version_number + 1
    WHERE review_id = p_review_id;

    IF p_decision = 'revoke' THEN
        UPDATE identities
        SET status = 'disabled'
        WHERE identity_id = v_identity_id;

        DELETE FROM identity_roles
        WHERE identity_id = v_identity_id;

        DELETE FROM direct_permissions
        WHERE identity_id = v_identity_id;

    ELSIF p_decision = 'reduce' THEN
        -- Reductions must be specified in review_scope.
        -- This operation removes explicitly selected direct grants.
        DELETE FROM direct_permissions dp
        USING review_scope rs, permissions p
        WHERE rs.review_id = p_review_id
          AND rs.object_type = 'permission'
          AND rs.final_decision = 'reduce'
          AND rs.object_id = p.permission_id
          AND dp.permission_id = p.permission_id
          AND dp.identity_id = v_identity_id;

        -- Role-based reductions are handled through role assignment
        -- removal, not mutation of shared role permissions.
        DELETE FROM identity_roles ir
        USING review_scope rs
        WHERE rs.review_id = p_review_id
          AND rs.object_type = 'role'
          AND rs.final_decision = 'reduce'
          AND rs.object_id = ir.role_id
          AND ir.identity_id = v_identity_id;
    END IF;

    INSERT INTO audit_events (
        actor_id,
        event_type,
        entity_type,
        entity_reference,
        event_details
    )
    VALUES (
        p_reviewer,
        'ACCESS_REVIEW_PROCESSED',
        'identity',
        v_identity_id::TEXT,
        jsonb_build_object(
            'review_id', p_review_id,
            'decision', p_decision,
            'justification', p_justification
        )
    );
END;
$$;

-- ============================================================================
-- SAMPLE ROLES
-- ============================================================================

INSERT INTO roles (
    role_code, role_name, description, is_privileged
)
VALUES
(
    'employee',
    'Standard Employee',
    'Standard business access',
    FALSE
),
(
    'developer',
    'Software Developer',
    'Source code and deployment access',
    FALSE
),
(
    'security_admin',
    'Security Administrator',
    'IAM and security administration',
    TRUE
),
(
    'finance_approver',
    'Finance Approver',
    'Payment approval capability',
    FALSE
),
(
    'payment_creator',
    'Payment Creator',
    'Payment creation capability',
    FALSE
),
(
    'audit_reviewer',
    'Audit Reviewer',
    'Independent audit review',
    FALSE
);

INSERT INTO permissions (
    resource_name, action_name, description, sensitivity
)
VALUES
('documents', 'read', 'Read business documents', 'normal'),
('source_code', 'read', 'Read source code', 'normal'),
('source_code', 'write', 'Modify source code', 'sensitive'),
('deployment', 'read', 'View deployments', 'normal'),
('iam', 'manage_roles', 'Create or modify IAM roles', 'critical'),
('iam', 'manage_policies', 'Modify access policies', 'critical'),
('security', 'configure_security', 'Change security controls', 'critical'),
('secrets', 'manage_credentials', 'Manage protected credentials', 'critical'),
('payments', 'approve', 'Approve payments', 'sensitive'),
('payments', 'create', 'Create payments', 'sensitive'),
('audit', 'read', 'Read audit records', 'sensitive');

-- ============================================================================
-- ROLE PERMISSION ASSIGNMENTS
-- ============================================================================

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r
JOIN permissions p ON
    (r.role_code = 'employee'
        AND p.resource_name = 'documents'
        AND p.action_name = 'read')
    OR
    (r.role_code = 'developer'
        AND p.resource_name IN ('source_code', 'deployment'))
    OR
    (r.role_code = 'security_admin'
        AND p.sensitivity = 'critical')
    OR
    (r.role_code = 'finance_approver'
        AND p.resource_name = 'payments'
        AND p.action_name = 'approve')
    OR
    (r.role_code = 'payment_creator'
        AND p.resource_name = 'payments'
        AND p.action_name = 'create')
    OR
    (r.role_code = 'audit_reviewer'
        AND p.resource_name = 'audit');

-- ============================================================================
-- ROLE INHERITANCE
-- ============================================================================

INSERT INTO role_inheritance(child_role_id, parent_role_id)
SELECT child.role_id, parent.role_id
FROM roles child
CROSS JOIN roles parent
WHERE child.role_code = 'developer'
  AND parent.role_code = 'employee';

-- ============================================================================
-- ROLE CONFLICT POLICIES
-- ============================================================================

INSERT INTO role_conflicts(role_a, role_b, description)
SELECT a.role_id, b.role_id,
       'Payment creator must not approve the same payment workflow'
FROM roles a
CROSS JOIN roles b
WHERE a.role_code = 'finance_approver'
  AND b.role_code = 'payment_creator';

INSERT INTO role_conflicts(role_a, role_b, description)
SELECT a.role_id, b.role_id,
       'Security administration must be separated from independent audit'
FROM roles a
CROSS JOIN roles b
WHERE a.role_code = 'security_admin'
  AND b.role_code = 'audit_reviewer';

-- ============================================================================
-- SAMPLE IDENTITIES
-- ============================================================================

INSERT INTO identities (
    external_id,
    display_name,
    identity_kind,
    status,
    owner_id,
    department,
    email,
    mfa_enabled,
    created_at,
    last_login_at,
    credential_rotation_at
)
VALUES
(
    'USR-401',
    'Software Developer',
    'human',
    'active',
    'engineering_manager',
    'engineering',
    'developer@example.org',
    TRUE,
    NOW() - INTERVAL '300 days',
    NOW() - INTERVAL '2 days',
    NOW() - INTERVAL '30 days'
),
(
    'USR-402',
    'Privileged Operator',
    'human',
    'active',
    'security_director',
    'security',
    'operator@example.org',
    FALSE,
    NOW() - INTERVAL '400 days',
    NOW() - INTERVAL '120 days',
    NOW() - INTERVAL '180 days'
),
(
    'USR-403',
    'Finance Operator',
    'human',
    'active',
    'finance_director',
    'finance',
    'finance@example.org',
    TRUE,
    NOW() - INTERVAL '200 days',
    NOW() - INTERVAL '1 day',
    NOW() - INTERVAL '20 days'
),
(
    'SVC-401',
    'Legacy Integration',
    'service',
    'active',
    'integration_team',
    'platform',
    NULL,
    FALSE,
    NOW() - INTERVAL '700 days',
    NULL,
    NOW() - INTERVAL '250 days'
),
(
    'EXT-401',
    'Suspended Contractor',
    'external',
    'suspended',
    'vendor_manager',
    'external',
    'contractor@example.org',
    FALSE,
    NOW() - INTERVAL '100 days',
    NOW() - INTERVAL '50 days',
    NULL
);

-- ============================================================================
-- SAMPLE ROLE ASSIGNMENTS
-- ============================================================================

INSERT INTO identity_roles (
    identity_id,
    role_id,
    assigned_by,
    assigned_at,
    assignment_reason
)
SELECT i.identity_id, r.role_id, 'identity_governance',
       NOW() - INTERVAL '30 days',
       'Approved business access assignment'
FROM identities i
JOIN roles r ON
    (i.external_id = 'USR-401' AND r.role_code = 'developer')
    OR
    (i.external_id = 'USR-402' AND r.role_code = 'security_admin')
    OR
    (i.external_id = 'USR-403'
        AND r.role_code IN ('finance_approver', 'payment_creator'))
    OR
    (i.external_id = 'SVC-401' AND r.role_code = 'security_admin')
    OR
    (i.external_id = 'EXT-401' AND r.role_code = 'employee');

-- ============================================================================
-- ACCESS REVIEW CAMPAIGN
-- ============================================================================

INSERT INTO access_review_campaigns (
    campaign_name,
    scope_description,
    start_date,
    due_date,
    created_by
)
VALUES (
    'Q4 2026 IAM Certification',
    'Review human, service, and privileged identities.',
    NOW(),
    NOW() + INTERVAL '30 days',
    'security_director'
);

INSERT INTO access_reviews (
    campaign_id,
    identity_id,
    reviewer_id,
    decision,
    justification
)
SELECT
    c.campaign_id,
    i.identity_id,
    CASE
        WHEN i.department = 'security'
            THEN 'security_director'
        WHEN i.department = 'finance'
            THEN 'finance_director'
        ELSE 'engineering_manager'
    END,
    'pending',
    ''
FROM access_review_campaigns c
CROSS JOIN identities i
WHERE c.campaign_name = 'Q4 2026 IAM Certification';

-- ============================================================================
-- EXAMPLE QUERIES
-- ============================================================================

-- 1. Identity inventory and assigned role information.

SELECT
    i.external_id,
    i.display_name,
    i.identity_kind,
    i.status,
    i.owner_id,
    r.role_code,
    r.is_privileged
FROM identities i
LEFT JOIN identity_roles ir
    ON ir.identity_id = i.identity_id
LEFT JOIN roles r
    ON r.role_id = ir.role_id
ORDER BY i.external_id, r.role_code;

-- 2. Effective permissions for an identity.

SELECT
    resource_name,
    action_name,
    grant_source
FROM get_effective_permissions(
    (SELECT identity_id
     FROM identities
     WHERE external_id = 'USR-401')
)
ORDER BY resource_name, action_name;

-- 3. Privilege escalation exposure.

SELECT *
FROM detect_privilege_exposure()
ORDER BY risk_score DESC;

-- 4. Dormant identities.

SELECT
    external_id,
    display_name,
    identity_kind,
    owner_id,
    last_login_at,
    NOW() - last_login_at AS inactivity_period
FROM identities
WHERE status = 'active'
  AND (
      last_login_at IS NULL
      OR last_login_at < NOW() - INTERVAL '90 days'
  )
ORDER BY last_login_at NULLS FIRST;

-- 5. Identities without MFA.

SELECT
    external_id,
    display_name,
    identity_kind,
    owner_id
FROM identities
WHERE status = 'active'
  AND mfa_enabled = FALSE;

-- 6. Separation of duties violations.

SELECT *
FROM find_separation_of_duties_violations();

-- 7. Aggregated identity attack surface.

SELECT
    identity_kind,
    COUNT(*) AS identity_count,
    COUNT(*) FILTER (
        WHERE mfa_enabled = FALSE
    ) AS without_mfa,
    COUNT(*) FILTER (
        WHERE last_login_at IS NULL
           OR last_login_at < NOW() - INTERVAL '90 days'
    ) AS dormant_count
FROM identities
WHERE status = 'active'
GROUP BY identity_kind
ORDER BY identity_kind;

-- 8. Access review completion status.

SELECT
    c.campaign_name,
    COUNT(ar.review_id) AS total_reviews,
    COUNT(*) FILTER (
        WHERE ar.decision = 'pending'
    ) AS pending_reviews,
    COUNT(*) FILTER (
        WHERE ar.decision = 'approve'
    ) AS approved_reviews,
    COUNT(*) FILTER (
        WHERE ar.decision = 'revoke'
    ) AS revoked_reviews,
    COUNT(*) FILTER (
        WHERE ar.decision = 'reduce'
    ) AS reduced_reviews
FROM access_review_campaigns c
LEFT JOIN access_reviews ar
    ON ar.campaign_id = c.campaign_id
GROUP BY c.campaign_id, c.campaign_name;

-- ============================================================================
-- SAMPLE ASSESSMENT EXECUTION
-- ============================================================================

CALL run_iam_assessment();

-- 9. Prioritized security findings.

SELECT
    sf.finding_id,
    i.external_id,
    sf.category,
    sf.severity,
    sf.risk_score,
    sf.evidence,
    sf.recommendation
FROM security_findings sf
JOIN identities i
    ON i.identity_id = sf.identity_id
WHERE sf.is_open = TRUE
ORDER BY
    sf.risk_score DESC,
    sf.detected_at DESC;

-- 10. Review campaign completion percentage.

SELECT
    c.campaign_name,
    COUNT(ar.review_id) AS total_reviews,
    COUNT(ar.review_id) FILTER (
        WHERE ar.decision <> 'pending'
    ) AS completed_reviews,
    ROUND(
        100.0 * COUNT(ar.review_id) FILTER (
            WHERE ar.decision <> 'pending'
        ) / NULLIF(COUNT(ar.review_id), 0),
        2
    ) AS completion_percentage
FROM access_review_campaigns c
LEFT JOIN access_reviews ar
    ON ar.campaign_id = c.campaign_id
GROUP BY c.campaign_id, c.campaign_name;

-- ============================================================================
-- SAMPLE TRANSACTION: REVOKE A DORMANT PRIVILEGED IDENTITY
-- ============================================================================

DO $$
DECLARE
    v_review_id BIGINT;
BEGIN
    SELECT ar.review_id
    INTO v_review_id
    FROM access_reviews ar
    JOIN identities i
        ON i.identity_id = ar.identity_id
    JOIN access_review_campaigns c
        ON c.campaign_id = ar.campaign_id
    WHERE i.external_id = 'USR-402'
      AND c.campaign_name = 'Q4 2026 IAM Certification'
      AND ar.decision = 'pending'
      AND c.status = 'open'
    FOR UPDATE OF ar;

    IF v_review_id IS NOT NULL THEN
        CALL process_access_review(
            v_review_id,
            'security_director',
            'revoke',
            'Dormant privileged account without MFA. Access revoked after certification.'
        );
    END IF;
END;
$$;

-- 11. Verify identity remediation.

SELECT
    external_id,
    display_name,
    status,
    mfa_enabled
FROM identities
WHERE external_id = 'USR-402';

-- 12. Verify audit events.

SELECT
    actor_id,
    event_type,
    entity_type,
    entity_reference,
    event_details,
    event_timestamp
FROM audit_events
ORDER BY event_timestamp DESC;

-- 13. Final identity attack surface.

SELECT *
FROM identity_attack_surface
ORDER BY sensitive_permission_count DESC,
         effective_permission_count DESC;

-- ============================================================================
-- TRANSACTION COMPLETION
-- ============================================================================

COMMIT;
