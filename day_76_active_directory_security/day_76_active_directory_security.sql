/*
===============================================================================
ACTIVE DIRECTORY SECURITY GOVERNANCE DATABASE
PostgreSQL 15+

Domain areas:
1. Privileged accounts and administrative tiers
2. Service account governance
3. Kerberos delegation
4. Cross-domain trusts
5. Security relationships and attack-path analysis
6. Findings and remediation
7. Governance policies and security reporting

This database stores normalized security inventory and audit evidence.
It does not connect to or modify a live Active Directory deployment.
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS ad_security;

SET search_path TO ad_security, public;

-- ============================================================================
-- ENUMERATED DOMAIN TYPES
-- ============================================================================

CREATE TYPE account_type AS ENUM (
    'user',
    'administrator',
    'service',
    'managed_service'
);

CREATE TYPE security_tier AS ENUM (
    'tier_0',
    'tier_1',
    'tier_2'
);

CREATE TYPE delegation_type AS ENUM (
    'none',
    'unconstrained',
    'constrained',
    'resource_based'
);

CREATE TYPE trust_type AS ENUM (
    'external',
    'forest',
    'parent_child'
);

CREATE TYPE trust_direction AS ENUM (
    'inbound',
    'outbound',
    'bidirectional'
);

CREATE TYPE finding_severity AS ENUM (
    'critical',
    'high',
    'medium',
    'low'
);

CREATE TYPE finding_status AS ENUM (
    'open',
    'mitigated',
    'accepted'
);

CREATE TYPE audit_run_status AS ENUM (
    'running',
    'completed',
    'failed'
);

-- ============================================================================
-- DOMAIN AND REPOSITORY INVENTORY
-- ============================================================================

CREATE TABLE domains (
    domain_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_name VARCHAR(253) NOT NULL UNIQUE,
    forest_name VARCHAR(253) NOT NULL,
    functional_level VARCHAR(40) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_domain_name
        CHECK (
            domain_name = LOWER(domain_name)
            AND POSITION(' ' IN domain_name) = 0
        )
);

CREATE TABLE directory_accounts (
    account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    domain_id BIGINT NOT NULL
        REFERENCES domains(domain_id) ON DELETE RESTRICT,

    sam_account_name VARCHAR(64) NOT NULL,
    display_name VARCHAR(150) NOT NULL,
    account_type account_type NOT NULL,
    security_tier security_tier NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    privileged BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    password_never_expires BOOLEAN NOT NULL DEFAULT FALSE,
    password_age_days INTEGER NOT NULL DEFAULT 0,

    interactive_logon_allowed BOOLEAN NOT NULL DEFAULT TRUE,
    managed_password BOOLEAN NOT NULL DEFAULT FALSE,

    spn_count INTEGER NOT NULL DEFAULT 0,

    delegation delegation_type NOT NULL DEFAULT 'none',
    trusted_to_authenticate BOOLEAN NOT NULL DEFAULT FALSE,

    last_logon_at TIMESTAMPTZ,
    last_password_change TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_domain_account
        UNIQUE(domain_id, sam_account_name),

    CONSTRAINT valid_account_name
        CHECK (
            sam_account_name ~ '^[A-Za-z0-9_.-]{1,64}$'
        ),

    CONSTRAINT nonnegative_password_age
        CHECK (password_age_days >= 0),

    CONSTRAINT nonnegative_spn_count
        CHECK (spn_count >= 0)
);

CREATE TABLE security_groups (
    group_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    domain_id BIGINT NOT NULL
        REFERENCES domains(domain_id) ON DELETE RESTRICT,

    group_name VARCHAR(150) NOT NULL,
    description TEXT,

    privileged BOOLEAN NOT NULL DEFAULT FALSE,
    security_tier security_tier NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(domain_id, group_name)
);

CREATE TABLE group_memberships (
    membership_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    group_id BIGINT NOT NULL
        REFERENCES security_groups(group_id) ON DELETE CASCADE,

    account_id BIGINT NOT NULL
        REFERENCES directory_accounts(account_id) ON DELETE CASCADE,

    membership_source VARCHAR(50) NOT NULL DEFAULT 'direct',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(group_id, account_id),

    CHECK (
        membership_source IN (
            'direct',
            'nested',
            'imported'
        )
    )
);

-- ============================================================================
-- SERVICE ACCOUNT INVENTORY
-- ============================================================================

CREATE TABLE service_accounts (
    service_account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id BIGINT NOT NULL UNIQUE
        REFERENCES directory_accounts(account_id) ON DELETE CASCADE,

    service_name VARCHAR(150) NOT NULL,
    service_owner VARCHAR(150) NOT NULL,

    environment VARCHAR(30) NOT NULL,
    managed_identity BOOLEAN NOT NULL DEFAULT FALSE,

    credential_rotation_days INTEGER NOT NULL DEFAULT 90,
    last_rotation_at TIMESTAMPTZ,

    business_justification TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (
        environment IN (
            'production',
            'staging',
            'development',
            'testing'
        )
    ),

    CHECK (credential_rotation_days > 0)
);

-- ============================================================================
-- DOMAIN TRUST INVENTORY
-- ============================================================================

CREATE TABLE domain_trusts (
    trust_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    source_domain_id BIGINT NOT NULL
        REFERENCES domains(domain_id) ON DELETE RESTRICT,

    target_domain_id BIGINT NOT NULL
        REFERENCES domains(domain_id) ON DELETE RESTRICT,

    trust_type trust_type NOT NULL,
    direction trust_direction NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    sid_filtering BOOLEAN NOT NULL DEFAULT TRUE,
    selective_authentication BOOLEAN NOT NULL DEFAULT TRUE,

    forest_transitive BOOLEAN NOT NULL DEFAULT FALSE,
    quarantine_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    reviewed_at TIMESTAMPTZ,
    review_due_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(source_domain_id, target_domain_id),

    CHECK (source_domain_id <> target_domain_id),

    CHECK (
        review_due_at IS NULL
        OR reviewed_at IS NULL
        OR review_due_at >= reviewed_at
    )
);

-- ============================================================================
-- DOCUMENTED SECURITY RELATIONSHIPS
-- ============================================================================

CREATE TABLE security_relationships (
    relationship_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    source_account_id BIGINT
        REFERENCES directory_accounts(account_id) ON DELETE CASCADE,

    target_account_id BIGINT
        REFERENCES directory_accounts(account_id) ON DELETE CASCADE,

    source_group_id BIGINT
        REFERENCES security_groups(group_id) ON DELETE CASCADE,

    target_group_id BIGINT
        REFERENCES security_groups(group_id) ON DELETE CASCADE,

    relationship_type VARCHAR(60) NOT NULL,
    permission_name VARCHAR(150) NOT NULL,

    evidence_reference VARCHAR(255),
    validated BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (
        source_account_id IS NOT NULL
        OR source_group_id IS NOT NULL
    ),

    CHECK (
        target_account_id IS NOT NULL
        OR target_group_id IS NOT NULL
    ),

    CHECK (
        source_account_id IS NULL
        OR target_account_id IS NULL
        OR source_account_id <> target_account_id
    ),

    CHECK (
        relationship_type IN (
            'group_membership',
            'administrative_access',
            'service_dependency',
            'delegation_exposure',
            'remote_access',
            'resource_access',
            'privileged_dependency'
        )
    )
);

-- ============================================================================
-- GOVERNANCE POLICY
-- ============================================================================

CREATE TABLE governance_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    require_privileged_mfa BOOLEAN NOT NULL DEFAULT TRUE,
    prohibit_unconstrained_delegation BOOLEAN NOT NULL DEFAULT TRUE,
    require_managed_service_passwords BOOLEAN NOT NULL DEFAULT TRUE,

    require_sid_filtering BOOLEAN NOT NULL DEFAULT TRUE,
    require_selective_authentication BOOLEAN NOT NULL DEFAULT TRUE,

    maximum_service_password_age INTEGER NOT NULL DEFAULT 180,
    maximum_trust_review_age_days INTEGER NOT NULL DEFAULT 365,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (maximum_service_password_age >= 0),
    CHECK (maximum_trust_review_age_days > 0)
);

INSERT INTO governance_policies (
    policy_name,
    require_privileged_mfa,
    prohibit_unconstrained_delegation,
    require_managed_service_passwords,
    require_sid_filtering,
    require_selective_authentication,
    maximum_service_password_age,
    maximum_trust_review_age_days
)
VALUES (
    'Corporate AD Baseline',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    180,
    365
);

-- ============================================================================
-- AUDIT RUNS AND FINDINGS
-- ============================================================================

CREATE TABLE audit_runs (
    audit_run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    domain_id BIGINT NOT NULL
        REFERENCES domains(domain_id) ON DELETE RESTRICT,

    policy_id BIGINT NOT NULL
        REFERENCES governance_policies(policy_id) ON DELETE RESTRICT,

    status audit_run_status NOT NULL DEFAULT 'running',

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,

    accounts_examined INTEGER NOT NULL DEFAULT 0,
    trusts_examined INTEGER NOT NULL DEFAULT 0,

    CHECK (accounts_examined >= 0),
    CHECK (trusts_examined >= 0),

    CHECK (
        completed_at IS NULL
        OR completed_at >= started_at
    )
);

CREATE TABLE security_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    audit_run_id BIGINT NOT NULL
        REFERENCES audit_runs(audit_run_id) ON DELETE CASCADE,

    account_id BIGINT
        REFERENCES directory_accounts(account_id) ON DELETE SET NULL,

    trust_id BIGINT
        REFERENCES domain_trusts(trust_id) ON DELETE SET NULL,

    category VARCHAR(80) NOT NULL,
    severity finding_severity NOT NULL,

    subject VARCHAR(150) NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,

    status finding_status NOT NULL DEFAULT 'open',

    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    accepted_by VARCHAR(150),
    resolution_notes TEXT,

    CONSTRAINT valid_resolution_time
        CHECK (
            resolved_at IS NULL
            OR resolved_at >= discovered_at
        ),

    CONSTRAINT resolution_requires_identity
        CHECK (
            status <> 'accepted'
            OR accepted_by IS NOT NULL
        )
);

CREATE TABLE remediation_history (
    remediation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    finding_id BIGINT NOT NULL
        REFERENCES security_findings(finding_id) ON DELETE CASCADE,

    action_taken VARCHAR(150) NOT NULL,
    performed_by VARCHAR(150) NOT NULL,
    evidence_reference VARCHAR(255),

    performed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX idx_accounts_domain_enabled
    ON directory_accounts(domain_id, enabled);

CREATE INDEX idx_accounts_privileged
    ON directory_accounts(domain_id, privileged)
    WHERE privileged = TRUE AND enabled = TRUE;

CREATE INDEX idx_accounts_delegation
    ON directory_accounts(delegation)
    WHERE delegation <> 'none';

CREATE INDEX idx_service_password_age
    ON directory_accounts(password_age_days)
    WHERE spn_count > 0;

CREATE INDEX idx_group_memberships_account
    ON group_memberships(account_id);

CREATE INDEX idx_relationship_source
    ON security_relationships(source_account_id);

CREATE INDEX idx_relationship_target
    ON security_relationships(target_account_id);

CREATE INDEX idx_trust_security
    ON domain_trusts(enabled, sid_filtering, selective_authentication);

CREATE INDEX idx_findings_open_severity
    ON security_findings(severity, discovered_at)
    WHERE status = 'open';

CREATE INDEX idx_findings_audit
    ON security_findings(audit_run_id);

CREATE INDEX idx_remediation_finding
    ON remediation_history(finding_id, performed_at DESC);

-- ============================================================================
-- AUTOMATIC UPDATED_AT MANAGEMENT
-- ============================================================================

CREATE OR REPLACE FUNCTION update_modified_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_updated
BEFORE UPDATE ON directory_accounts
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

-- ============================================================================
-- AUDIT FINDING CREATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION create_security_finding(
    p_audit_run_id BIGINT,
    p_account_id BIGINT,
    p_trust_id BIGINT,
    p_category VARCHAR,
    p_severity finding_severity,
    p_subject VARCHAR,
    p_description TEXT,
    p_recommendation TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_finding_id BIGINT;
BEGIN
    INSERT INTO security_findings (
        audit_run_id,
        account_id,
        trust_id,
        category,
        severity,
        subject,
        description,
        recommendation
    )
    VALUES (
        p_audit_run_id,
        p_account_id,
        p_trust_id,
        p_category,
        p_severity,
        p_subject,
        p_description,
        p_recommendation
    )
    RETURNING finding_id INTO v_finding_id;

    RETURN v_finding_id;
END;
$$;

-- ============================================================================
-- ACCOUNT SECURITY AUDIT FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION audit_directory_accounts(
    p_audit_run_id BIGINT
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy governance_policies%ROWTYPE;
    v_account RECORD;
    v_count INTEGER := 0;
BEGIN
    SELECT gp.*
    INTO STRICT v_policy
    FROM audit_runs ar
    JOIN governance_policies gp
      ON gp.policy_id = ar.policy_id
    WHERE ar.audit_run_id = p_audit_run_id
      AND gp.active = TRUE
      AND ar.status = 'running';

    FOR v_account IN
        SELECT *
        FROM directory_accounts
        WHERE domain_id = (
            SELECT domain_id
            FROM audit_runs
            WHERE audit_run_id = p_audit_run_id
        )
        AND enabled = TRUE
    LOOP

        IF
            v_policy.require_privileged_mfa
            AND v_account.privileged
            AND NOT v_account.mfa_enabled
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'PRIVILEGED_MFA',
                'critical',
                v_account.sam_account_name,
                'Privileged account does not have MFA enabled.',
                'Enforce strong MFA for privileged authentication.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_account.privileged
            AND v_account.password_never_expires
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'PASSWORD_LIFECYCLE',
                'high',
                v_account.sam_account_name,
                'Privileged account has a non-expiring password.',
                'Adopt managed credentials and lifecycle controls.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_account.account_type = 'administrator'
            AND v_account.privileged
            AND v_account.security_tier <> 'tier_0'
            AND v_account.interactive_logon_allowed
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'TIER_SEPARATION',
                'high',
                v_account.sam_account_name,
                'Administrative tier and logon scope require review.',
                'Separate administrative identities by tier.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_policy.prohibit_unconstrained_delegation
            AND v_account.delegation = 'unconstrained'
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'UNCONSTRAINED_DELEGATION',
                'critical',
                v_account.sam_account_name,
                'Unconstrained Kerberos delegation is enabled.',
                'Remove unnecessary unconstrained delegation.'
            );

            v_count := v_count + 1;
        END IF;

        IF v_account.trusted_to_authenticate THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'PROTOCOL_TRANSITION',
                'high',
                v_account.sam_account_name,
                'Protocol transition is configured.',
                'Review delegation necessity and permitted targets.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_account.account_type IN ('service', 'managed_service')
            AND v_account.interactive_logon_allowed
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'INTERACTIVE_SERVICE_LOGON',
                'medium',
                v_account.sam_account_name,
                'Service identity allows interactive logon.',
                'Restrict interactive logon where feasible.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_account.account_type = 'service'
            AND v_policy.require_managed_service_passwords
            AND NOT v_account.managed_password
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'SERVICE_CREDENTIALS',
                'high',
                v_account.sam_account_name,
                'Service account does not use managed credentials.',
                'Evaluate migration to a group Managed Service Account.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_account.account_type = 'service'
            AND v_account.spn_count > 0
            AND v_account.password_age_days >
                v_policy.maximum_service_password_age
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                v_account.account_id,
                NULL,
                'SERVICE_PASSWORD_AGE',
                'high',
                v_account.sam_account_name,
                'SPN-bearing service account has an old password.',
                'Rotate credentials or migrate to managed credentials.'
            );

            v_count := v_count + 1;
        END IF;

    END LOOP;

    RETURN v_count;
END;
$$;

-- ============================================================================
-- TRUST SECURITY AUDIT FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION audit_domain_trusts(
    p_audit_run_id BIGINT
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy governance_policies%ROWTYPE;
    v_trust RECORD;
    v_count INTEGER := 0;
BEGIN
    SELECT gp.*
    INTO STRICT v_policy
    FROM audit_runs ar
    JOIN governance_policies gp
      ON gp.policy_id = ar.policy_id
    WHERE ar.audit_run_id = p_audit_run_id
      AND gp.active = TRUE
      AND ar.status = 'running';

    FOR v_trust IN
        SELECT dt.*
        FROM domain_trusts dt
        JOIN domains d
          ON d.domain_id = dt.source_domain_id
        JOIN audit_runs ar
          ON ar.domain_id = d.domain_id
        WHERE ar.audit_run_id = p_audit_run_id
          AND dt.enabled = TRUE
    LOOP

        IF
            v_policy.require_sid_filtering
            AND NOT v_trust.sid_filtering
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                NULL,
                v_trust.trust_id,
                'TRUST_SID_FILTERING',
                'critical',
                'TRUST-' || v_trust.trust_id,
                'Trust does not enforce SID filtering.',
                'Enable appropriate SID filtering.'
            );

            v_count := v_count + 1;
        END IF;

        IF
            v_policy.require_selective_authentication
            AND NOT v_trust.selective_authentication
        THEN
            PERFORM create_security_finding(
                p_audit_run_id,
                NULL,
                v_trust.trust_id,
                'TRUST_SELECTIVE_AUTHENTICATION',
                'high',
                'TRUST-' || v_trust.trust_id,
                'Selective authentication is disabled.',
                'Restrict cross-domain authentication.'
            );

            v_count := v_count + 1;
        END IF;

    END LOOP;

    RETURN v_count;
END;
$$;

-- ============================================================================
-- AUDIT PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE execute_security_audit(
    p_domain_id BIGINT,
    p_policy_id BIGINT,
    INOUT p_audit_run_id BIGINT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_accounts INTEGER;
    v_trusts INTEGER;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM domains
        WHERE domain_id = p_domain_id
    ) THEN
        RAISE EXCEPTION 'Domain does not exist';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM governance_policies
        WHERE policy_id = p_policy_id
          AND active = TRUE
    ) THEN
        RAISE EXCEPTION 'Active policy does not exist';
    END IF;

    INSERT INTO audit_runs (
        domain_id,
        policy_id,
        status
    )
    VALUES (
        p_domain_id,
        p_policy_id,
        'running'
    )
    RETURNING audit_run_id INTO p_audit_run_id;

    v_accounts := audit_directory_accounts(p_audit_run_id);
    v_trusts := audit_domain_trusts(p_audit_run_id);

    UPDATE audit_runs
    SET status = 'completed',
        completed_at = NOW(),
        accounts_examined = (
            SELECT COUNT(*)
            FROM directory_accounts
            WHERE domain_id = p_domain_id
              AND enabled = TRUE
        ),
        trusts_examined = (
            SELECT COUNT(*)
            FROM domain_trusts
            WHERE source_domain_id = p_domain_id
              AND enabled = TRUE
        )
    WHERE audit_run_id = p_audit_run_id;

    RAISE NOTICE
        'Audit % completed. Account findings: %, trust findings: %',
        p_audit_run_id,
        v_accounts,
        v_trusts;
END;
$$;

-- ============================================================================
-- FINDING STATUS TRANSITION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_finding_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = 'mitigated'
       AND NEW.status = 'open'
    THEN
        RAISE EXCEPTION
            'A mitigated finding cannot be reopened through this transition';
    END IF;

    IF NEW.status = 'mitigated' AND NEW.resolved_at IS NULL THEN
        NEW.resolved_at = NOW();
    END IF;

    IF NEW.status = 'accepted' AND NEW.accepted_by IS NULL THEN
        RAISE EXCEPTION
            'Accepted findings require an accountable identity';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_finding_transition
BEFORE UPDATE OF status ON security_findings
FOR EACH ROW
EXECUTE FUNCTION validate_finding_transition();

-- ============================================================================
-- VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW privileged_account_inventory AS
SELECT
    a.account_id,
    d.domain_name,
    a.sam_account_name,
    a.security_tier,
    a.mfa_enabled,
    a.password_never_expires,
    a.enabled,
    a.delegation,
    a.last_logon_at
FROM directory_accounts a
JOIN domains d
    ON d.domain_id = a.domain_id
WHERE a.privileged = TRUE;

CREATE OR REPLACE VIEW service_account_risk_inventory AS
SELECT
    a.account_id,
    d.domain_name,
    a.sam_account_name,
    sa.service_name,
    sa.service_owner,
    a.spn_count,
    a.password_age_days,
    a.managed_password,
    a.interactive_logon_allowed,
    a.delegation
FROM directory_accounts a
JOIN domains d
    ON d.domain_id = a.domain_id
JOIN service_accounts sa
    ON sa.account_id = a.account_id;

CREATE OR REPLACE VIEW open_security_findings AS
SELECT
    f.finding_id,
    ar.audit_run_id,
    d.domain_name,
    f.category,
    f.severity,
    f.subject,
    f.description,
    f.recommendation,
    f.discovered_at
FROM security_findings f
JOIN audit_runs ar
    ON ar.audit_run_id = f.audit_run_id
JOIN domains d
    ON d.domain_id = ar.domain_id
WHERE f.status = 'open';

CREATE OR REPLACE VIEW security_risk_summary AS
SELECT
    ar.audit_run_id,
    d.domain_name,
    COUNT(f.finding_id) AS total_findings,

    COUNT(*) FILTER (
        WHERE f.severity = 'critical'
    ) AS critical_findings,

    COUNT(*) FILTER (
        WHERE f.severity = 'high'
    ) AS high_findings,

    COUNT(*) FILTER (
        WHERE f.severity = 'medium'
    ) AS medium_findings,

    COUNT(*) FILTER (
        WHERE f.severity = 'low'
    ) AS low_findings

FROM audit_runs ar
JOIN domains d
    ON d.domain_id = ar.domain_id
LEFT JOIN security_findings f
    ON f.audit_run_id = ar.audit_run_id
GROUP BY ar.audit_run_id, d.domain_name;

-- ============================================================================
-- RECURSIVE DEFENSIVE ATTACK-PATH ANALYSIS
-- ============================================================================

CREATE OR REPLACE FUNCTION find_security_paths(
    p_start_account_id BIGINT,
    p_target_account_id BIGINT,
    p_max_depth INTEGER DEFAULT 8
)
RETURNS TABLE (
    path_account_ids BIGINT[],
    path_depth INTEGER
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_max_depth < 1 OR p_max_depth > 32 THEN
        RAISE EXCEPTION 'Maximum depth must be between 1 and 32';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM directory_accounts
        WHERE account_id = p_start_account_id
    ) OR NOT EXISTS (
        SELECT 1 FROM directory_accounts
        WHERE account_id = p_target_account_id
    ) THEN
        RAISE EXCEPTION 'Start or target account does not exist';
    END IF;

    RETURN QUERY
    WITH RECURSIVE paths AS (
        SELECT
            p_start_account_id AS current_id,
            ARRAY[p_start_account_id]::BIGINT[] AS path,
            0 AS depth

        UNION ALL

        SELECT
            r.target_account_id,
            p.path || r.target_account_id,
            p.depth + 1

        FROM paths p
        JOIN security_relationships r
            ON r.source_account_id = p.current_id

        WHERE r.target_account_id IS NOT NULL
          AND r.validated = TRUE
          AND p.depth < p_max_depth
          AND NOT r.target_account_id = ANY(p.path)
    )

    SELECT
        p.path,
        p.depth
    FROM paths p
    WHERE p.current_id = p_target_account_id
    ORDER BY p.depth, p.path;
END;
$$;

-- ============================================================================
-- SAMPLE DOMAIN DATA
-- ============================================================================

INSERT INTO domains (
    domain_name,
    forest_name,
    functional_level
)
VALUES
    ('corp.example.com', 'example.com', 'Windows Server 2022'),
    ('partner.example.net', 'partner.example.net', 'Windows Server 2019');

INSERT INTO directory_accounts (
    domain_id,
    sam_account_name,
    display_name,
    account_type,
    security_tier,
    enabled,
    privileged,
    mfa_enabled,
    password_never_expires,
    password_age_days,
    interactive_logon_allowed,
    managed_password,
    spn_count,
    delegation,
    trusted_to_authenticate
)
SELECT
    d.domain_id,
    sample.sam_account_name,
    sample.display_name,
    sample.account_type::account_type,
    sample.security_tier::security_tier,
    sample.enabled,
    sample.privileged,
    sample.mfa_enabled,
    sample.password_never_expires,
    sample.password_age_days,
    sample.interactive_logon_allowed,
    sample.managed_password,
    sample.spn_count,
    sample.delegation::delegation_type,
    sample.trusted_to_authenticate
FROM domains d
CROSS JOIN (
    VALUES
    (
        'domain_admin',
        'Domain Administrator',
        'administrator',
        'tier_0',
        TRUE, TRUE, TRUE, FALSE,
        20, FALSE, FALSE, 0, 'none', FALSE
    ),
    (
        'helpdesk_admin',
        'Helpdesk Administrator',
        'administrator',
        'tier_2',
        TRUE, TRUE, FALSE, TRUE,
        120, TRUE, FALSE, 0, 'none', FALSE
    ),
    (
        'sql_service',
        'SQL Service Identity',
        'service',
        'tier_1',
        TRUE, FALSE, FALSE, TRUE,
        240, TRUE, FALSE, 2, 'none', FALSE
    ),
    (
        'legacy_web',
        'Legacy Web Service',
        'service',
        'tier_1',
        TRUE, FALSE, FALSE, TRUE,
        300, TRUE, FALSE, 1, 'unconstrained', TRUE
    ),
    (
        'web_gmsa',
        'Managed Web Service',
        'managed_service',
        'tier_1',
        TRUE, FALSE, FALSE, FALSE,
        5, FALSE, TRUE, 1, 'none', FALSE
    ),
    (
        'employee01',
        'Employee One',
        'user',
        'tier_2',
        TRUE, FALSE, TRUE, FALSE,
        60, TRUE, FALSE, 0, 'none', FALSE
    ),
    (
        'disabled_admin',
        'Disabled Administrator',
        'administrator',
        'tier_0',
        FALSE, TRUE, FALSE, TRUE,
        400, FALSE, FALSE, 0, 'none', FALSE
    )
) AS sample(
    sam_account_name,
    display_name,
    account_type,
    security_tier,
    enabled,
    privileged,
    mfa_enabled,
    password_never_expires,
    password_age_days,
    interactive_logon_allowed,
    managed_password,
    spn_count,
    delegation,
    trusted_to_authenticate
)
WHERE d.domain_name = 'corp.example.com';

INSERT INTO service_accounts (
    account_id,
    service_name,
    service_owner,
    environment,
    managed_identity,
    credential_rotation_days,
    last_rotation_at,
    business_justification
)
SELECT
    a.account_id,
    sample.service_name,
    sample.service_owner,
    sample.environment,
    sample.managed_identity,
    sample.rotation_days,
    NOW() - INTERVAL '240 days',
    sample.justification
FROM directory_accounts a
JOIN domains d
    ON d.domain_id = a.domain_id
JOIN (
    VALUES
    (
        'sql_service',
        'SQL Database Service',
        'Database Operations',
        'production',
        FALSE,
        90,
        'Application database processing'
    ),
    (
        'legacy_web',
        'Legacy Web Application',
        'Application Operations',
        'production',
        FALSE,
        90,
        'Legacy application hosting'
    ),
    (
        'web_gmsa',
        'Managed Web Application',
        'Platform Operations',
        'production',
        TRUE,
        30,
        'Managed web application execution'
    )
) AS sample(
    account_name,
    service_name,
    service_owner,
    environment,
    managed_identity,
    rotation_days,
    justification
)
    ON sample.account_name = a.sam_account_name
WHERE d.domain_name = 'corp.example.com';

INSERT INTO security_groups (
    domain_id,
    group_name,
    description,
    privileged,
    security_tier
)
SELECT
    domain_id,
    'Domain Admins',
    'Tier 0 domain administration group',
    TRUE,
    'tier_0'
FROM domains
WHERE domain_name = 'corp.example.com';

INSERT INTO group_memberships (
    group_id,
    account_id
)
SELECT
    g.group_id,
    a.account_id
FROM security_groups g
JOIN directory_accounts a
    ON a.sam_account_name = 'domain_admin'
JOIN domains d
    ON d.domain_id = g.domain_id
WHERE g.group_name = 'Domain Admins'
  AND d.domain_name = 'corp.example.com';

INSERT INTO domain_trusts (
    source_domain_id,
    target_domain_id,
    trust_type,
    direction,
    enabled,
    sid_filtering,
    selective_authentication,
    forest_transitive,
    quarantine_enabled,
    reviewed_at,
    review_due_at
)
SELECT
    source.domain_id,
    target.domain_id,
    'external',
    'bidirectional',
    TRUE,
    FALSE,
    FALSE,
    FALSE,
    FALSE,
    NOW() - INTERVAL '400 days',
    NOW() - INTERVAL '35 days'
FROM domains source
CROSS JOIN domains target
WHERE source.domain_name = 'corp.example.com'
  AND target.domain_name = 'partner.example.net';

-- ============================================================================
-- DOCUMENTED RELATIONSHIP GRAPH
-- ============================================================================

INSERT INTO security_relationships (
    source_account_id,
    target_account_id,
    relationship_type,
    permission_name,
    evidence_reference,
    validated
)
SELECT
    source.account_id,
    target.account_id,
    relation.relationship_type,
    relation.permission_name,
    relation.evidence_reference,
    TRUE
FROM (
    VALUES
    (
        'employee01',
        'helpdesk_admin',
        'group_membership',
        'Documented group relationship',
        'INVENTORY-001'
    ),
    (
        'helpdesk_admin',
        'sql_service',
        'administrative_access',
        'Documented service administration',
        'INVENTORY-002'
    ),
    (
        'sql_service',
        'legacy_web',
        'service_dependency',
        'Documented service dependency',
        'INVENTORY-003'
    ),
    (
        'legacy_web',
        'domain_admin',
        'delegation_exposure',
        'Delegation-related exposure requiring review',
        'INVENTORY-004'
    ),
    (
        'employee01',
        'web_gmsa',
        'resource_access',
        'Documented application access',
        'INVENTORY-005'
    ),
    (
        'web_gmsa',
        'domain_admin',
        'privileged_dependency',
        'Documented dependency requiring validation',
        'INVENTORY-006'
    )
) AS relation(
    source_name,
    target_name,
    relationship_type,
    permission_name,
    evidence_reference
)
JOIN directory_accounts source
    ON source.sam_account_name = relation.source_name
JOIN directory_accounts target
    ON target.sam_account_name = relation.target_name
JOIN domains d
    ON d.domain_id = source.domain_id
   AND d.domain_id = target.domain_id
WHERE d.domain_name = 'corp.example.com';

-- ============================================================================
-- EXECUTE AN AUDIT TRANSACTION
-- ============================================================================

DO $$
DECLARE
    v_domain_id BIGINT;
    v_policy_id BIGINT;
    v_audit_run_id BIGINT;
BEGIN
    SELECT domain_id
    INTO STRICT v_domain_id
    FROM domains
    WHERE domain_name = 'corp.example.com';

    SELECT policy_id
    INTO STRICT v_policy_id
    FROM governance_policies
    WHERE policy_name = 'Corporate AD Baseline'
      AND active = TRUE;

    CALL execute_security_audit(
        v_domain_id,
        v_policy_id,
        v_audit_run_id
    );

    RAISE NOTICE 'Created audit run: %', v_audit_run_id;
END;
$$;

COMMIT;

-- ============================================================================
-- RETRIEVAL: PRIVILEGED ACCOUNT INVENTORY
-- ============================================================================

SELECT
    domain_name,
    sam_account_name,
    security_tier,
    mfa_enabled,
    password_never_expires,
    enabled
FROM privileged_account_inventory
ORDER BY security_tier, sam_account_name;

-- ============================================================================
-- RETRIEVAL: SERVICE ACCOUNT SECURITY
-- ============================================================================

SELECT
    sam_account_name,
    service_name,
    service_owner,
    spn_count,
    password_age_days,
    managed_password,
    delegation
FROM service_account_risk_inventory
ORDER BY password_age_days DESC;

-- ============================================================================
-- VALIDATION: HIGH-RISK CONFIGURATION
-- ============================================================================

SELECT
    sam_account_name,
    delegation,
    privileged,
    mfa_enabled,
    password_never_expires
FROM directory_accounts
WHERE enabled = TRUE
  AND (
      delegation = 'unconstrained'
      OR (privileged AND NOT mfa_enabled)
      OR (privileged AND password_never_expires)
  );

-- ============================================================================
-- TRUST SECURITY REVIEW
-- ============================================================================

SELECT
    source.domain_name AS source_domain,
    target.domain_name AS target_domain,
    t.trust_type,
    t.direction,
    t.sid_filtering,
    t.selective_authentication,
    t.review_due_at
FROM domain_trusts t
JOIN domains source
    ON source.domain_id = t.source_domain_id
JOIN domains target
    ON target.domain_id = t.target_domain_id
WHERE t.enabled = TRUE;

-- ============================================================================
-- AGGREGATION: AUDIT RISK DISTRIBUTION
-- ============================================================================

SELECT *
FROM security_risk_summary
ORDER BY audit_run_id DESC;

-- ============================================================================
-- REPORTING: OPEN FINDINGS
-- ============================================================================

SELECT
    finding_id,
    category,
    severity,
    subject,
    description,
    recommendation,
    discovered_at
FROM open_security_findings
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        ELSE 4
    END,
    discovered_at;

-- ============================================================================
-- EVALUATION: SERVICE ACCOUNT PASSWORD AGE
-- ============================================================================

SELECT
    sam_account_name,
    spn_count,
    password_age_days,
    CASE
        WHEN managed_password THEN 'MANAGED'
        WHEN password_age_days > 180 THEN 'REVIEW_REQUIRED'
        ELSE 'WITHIN_THRESHOLD'
    END AS credential_assessment
FROM directory_accounts
WHERE account_type = 'service'
  AND enabled = TRUE
ORDER BY password_age_days DESC;

-- ============================================================================
-- DEFENSIVE ATTACK-PATH ANALYSIS
-- ============================================================================

SELECT
    path_account_ids,
    path_depth,
    ARRAY(
        SELECT a.sam_account_name
        FROM unnest(path_account_ids) WITH ORDINALITY p(id, position)
        JOIN directory_accounts a
            ON a.account_id = p.id
        ORDER BY p.position
    ) AS account_path
FROM find_security_paths(
    (
        SELECT account_id
        FROM directory_accounts
        WHERE sam_account_name = 'employee01'
    ),
    (
        SELECT account_id
        FROM directory_accounts
        WHERE sam_account_name = 'domain_admin'
    ),
    8
);

-- ============================================================================
-- WORKFLOW: REMEDIATE A FINDING
-- ============================================================================
-- This example records remediation evidence and changes finding status
-- atomically. The finding must exist in the latest audit.

BEGIN;

DO $$
DECLARE
    v_finding_id BIGINT;
BEGIN
    SELECT finding_id
    INTO v_finding_id
    FROM security_findings
    WHERE category = 'UNCONSTRAINED_DELEGATION'
      AND status = 'open'
    ORDER BY discovered_at DESC
    LIMIT 1;

    IF v_finding_id IS NOT NULL THEN

        INSERT INTO remediation_history (
            finding_id,
            action_taken,
            performed_by,
            evidence_reference
        )
        VALUES (
            v_finding_id,
            'Delegation configuration reviewed and mitigation recorded',
            'security.operations',
            'CHANGE-REQUEST-001'
        );

        UPDATE security_findings
        SET status = 'mitigated',
            resolution_notes =
                'Mitigation evidence recorded and configuration review completed'
        WHERE finding_id = v_finding_id;

    END IF;
END;
$$;

COMMIT;

-- ============================================================================
-- FINAL GOVERNANCE DASHBOARD
-- ============================================================================

SELECT
    d.domain_name,

    COUNT(DISTINCT a.account_id) AS total_accounts,

    COUNT(DISTINCT a.account_id) FILTER (
        WHERE a.privileged AND a.enabled
    ) AS active_privileged_accounts,

    COUNT(DISTINCT a.account_id) FILTER (
        WHERE a.delegation = 'unconstrained'
          AND a.enabled
    ) AS unconstrained_delegation_accounts,

    COUNT(DISTINCT t.trust_id) FILTER (
        WHERE t.enabled
          AND (
              NOT t.sid_filtering
              OR NOT t.selective_authentication
          )
    ) AS insecure_trusts,

    COUNT(DISTINCT f.finding_id) FILTER (
        WHERE f.status = 'open'
          AND f.severity = 'critical'
    ) AS open_critical_findings

FROM domains d

LEFT JOIN directory_accounts a
    ON a.domain_id = d.domain_id

LEFT JOIN domain_trusts t
    ON t.source_domain_id = d.domain_id

LEFT JOIN audit_runs ar
    ON ar.domain_id = d.domain_id

LEFT JOIN security_findings f
    ON f.audit_run_id = ar.audit_run_id

GROUP BY d.domain_name
ORDER BY d.domain_name;
