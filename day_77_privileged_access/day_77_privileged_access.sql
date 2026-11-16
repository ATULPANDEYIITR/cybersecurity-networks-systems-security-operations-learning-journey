-- ============================================================
-- PRIVILEGED ACCESS MANAGEMENT (PAM)
-- PostgreSQL 15+
--
-- Domain:
-- Administrative accounts
-- Privileged groups
-- Credential isolation
-- Access requests
-- Approval workflows
-- Separation of duties
-- Just-in-time sessions
-- Security checks
-- Session revocation
-- Credential rotation
-- Branch-like governance enforcement
-- Audit and reporting
--
-- The credential table stores opaque vault references.
-- Actual passwords and private keys must remain outside
-- the relational database.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS pam;

SET search_path TO pam, public;


-- ============================================================
-- 1. ENUMERATIONS
-- ============================================================

CREATE TYPE privilege_level AS ENUM (
    'STANDARD',
    'ELEVATED',
    'ADMIN',
    'SUPER_ADMIN'
);

CREATE TYPE account_status AS ENUM (
    'ACTIVE',
    'DISABLED',
    'LOCKED'
);

CREATE TYPE request_status AS ENUM (
    'PENDING',
    'APPROVED',
    'DENIED',
    'ACTIVE',
    'EXPIRED',
    'REVOKED'
);

CREATE TYPE review_decision AS ENUM (
    'APPROVE',
    'DENY'
);

CREATE TYPE check_status AS ENUM (
    'PENDING',
    'PASSED',
    'FAILED'
);

CREATE TYPE session_status AS ENUM (
    'ACTIVE',
    'TERMINATED',
    'EXPIRED',
    'REVOKED'
);

CREATE TYPE audit_severity AS ENUM (
    'INFO',
    'WARNING',
    'CRITICAL'
);


-- ============================================================
-- 2. IDENTITY MANAGEMENT
-- ============================================================

CREATE TABLE pam.users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(100) NOT NULL UNIQUE,

    department VARCHAR(100) NOT NULL,

    email VARCHAR(255) NOT NULL UNIQUE,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_username
        CHECK (length(trim(username)) >= 3)
);


CREATE TABLE pam.roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    role_name VARCHAR(80) NOT NULL UNIQUE,

    description TEXT NOT NULL
);


CREATE TABLE pam.user_roles (
    user_id BIGINT NOT NULL
        REFERENCES pam.users(user_id) ON DELETE RESTRICT,

    role_id BIGINT NOT NULL
        REFERENCES pam.roles(role_id) ON DELETE RESTRICT,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    assigned_by BIGINT
        REFERENCES pam.users(user_id) ON DELETE SET NULL,

    PRIMARY KEY (user_id, role_id)
);


-- ============================================================
-- 3. PRIVILEGED GROUPS
-- ============================================================

CREATE TABLE pam.privileged_groups (
    group_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    group_name VARCHAR(150) NOT NULL UNIQUE,

    privilege privilege_level NOT NULL,

    approval_required BOOLEAN NOT NULL DEFAULT TRUE,

    maximum_session_minutes INTEGER NOT NULL DEFAULT 60,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_group_session_duration
        CHECK (maximum_session_minutes BETWEEN 1 AND 1440)
);


CREATE TABLE pam.group_memberships (
    group_id BIGINT NOT NULL
        REFERENCES pam.privileged_groups(group_id)
        ON DELETE RESTRICT,

    user_id BIGINT NOT NULL
        REFERENCES pam.users(user_id)
        ON DELETE RESTRICT,

    assigned_by BIGINT
        REFERENCES pam.users(user_id)
        ON DELETE SET NULL,

    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    valid_until TIMESTAMPTZ,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    PRIMARY KEY (group_id, user_id),

    CONSTRAINT valid_membership_period
        CHECK (
            valid_until IS NULL
            OR valid_until > valid_from
        )
);


-- ============================================================
-- 4. PRIVILEGED ACCOUNT INVENTORY
-- ============================================================

CREATE TABLE pam.privileged_accounts (
    account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    username VARCHAR(150) NOT NULL,

    system_name VARCHAR(150) NOT NULL,

    privilege privilege_level NOT NULL,

    status account_status NOT NULL DEFAULT 'ACTIVE',

    rotation_interval_days INTEGER NOT NULL DEFAULT 30,

    last_rotated_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_by BIGINT
        REFERENCES pam.users(user_id)
        ON DELETE SET NULL,

    CONSTRAINT unique_system_account
        UNIQUE (system_name, username),

    CONSTRAINT valid_rotation_interval
        CHECK (rotation_interval_days BETWEEN 1 AND 3650)
);


CREATE TABLE pam.account_group_assignments (
    account_id BIGINT NOT NULL
        REFERENCES pam.privileged_accounts(account_id)
        ON DELETE RESTRICT,

    group_id BIGINT NOT NULL
        REFERENCES pam.privileged_groups(group_id)
        ON DELETE RESTRICT,

    PRIMARY KEY (account_id, group_id)
);


-- ============================================================
-- 5. CREDENTIAL ISOLATION
-- ============================================================

CREATE TABLE pam.vault_references (
    vault_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id BIGINT NOT NULL UNIQUE
        REFERENCES pam.privileged_accounts(account_id)
        ON DELETE RESTRICT,

    vault_provider VARCHAR(100) NOT NULL,

    secret_reference VARCHAR(255) NOT NULL UNIQUE,

    credential_version INTEGER NOT NULL DEFAULT 1,

    last_verified_at TIMESTAMPTZ,

    provisioned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    is_available BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT valid_credential_version
        CHECK (credential_version > 0)
);


CREATE TABLE pam.credential_rotations (
    rotation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id BIGINT NOT NULL
        REFERENCES pam.privileged_accounts(account_id)
        ON DELETE RESTRICT,

    old_version INTEGER NOT NULL,

    new_version INTEGER NOT NULL,

    initiated_by BIGINT
        REFERENCES pam.users(user_id)
        ON DELETE SET NULL,

    rotation_status VARCHAR(20) NOT NULL,

    initiated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    CONSTRAINT valid_rotation_status
        CHECK (
            rotation_status IN (
                'PENDING',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT increasing_credential_version
        CHECK (new_version > old_version)
);


-- ============================================================
-- 6. APPROVAL POLICY
-- ============================================================

CREATE TABLE pam.approval_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    minimum_approvals INTEGER NOT NULL DEFAULT 1,

    prohibit_self_approval BOOLEAN NOT NULL DEFAULT TRUE,

    require_mfa BOOLEAN NOT NULL DEFAULT TRUE,

    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,

    require_session_recording BOOLEAN NOT NULL DEFAULT TRUE,

    prohibit_concurrent_sessions BOOLEAN NOT NULL DEFAULT TRUE,

    maximum_session_minutes INTEGER NOT NULL DEFAULT 60,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT valid_approval_count
        CHECK (minimum_approvals BETWEEN 1 AND 10),

    CONSTRAINT valid_policy_duration
        CHECK (maximum_session_minutes BETWEEN 1 AND 1440)
);


CREATE TABLE pam.group_approval_policies (
    group_id BIGINT NOT NULL
        REFERENCES pam.privileged_groups(group_id)
        ON DELETE RESTRICT,

    policy_id BIGINT NOT NULL
        REFERENCES pam.approval_policies(policy_id)
        ON DELETE RESTRICT,

    PRIMARY KEY (group_id, policy_id)
);


-- ============================================================
-- 7. PRIVILEGED ACCESS REQUESTS
-- ============================================================

CREATE TABLE pam.access_requests (
    request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    requester_id BIGINT NOT NULL
        REFERENCES pam.users(user_id)
        ON DELETE RESTRICT,

    account_id BIGINT NOT NULL
        REFERENCES pam.privileged_accounts(account_id)
        ON DELETE RESTRICT,

    justification TEXT NOT NULL,

    requested_minutes INTEGER NOT NULL,

    status request_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    reviewed_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    CONSTRAINT valid_requested_duration
        CHECK (requested_minutes BETWEEN 1 AND 1440),

    CONSTRAINT nonempty_justification
        CHECK (length(trim(justification)) >= 10)
);


CREATE TABLE pam.access_request_policies (
    request_id BIGINT NOT NULL
        REFERENCES pam.access_requests(request_id)
        ON DELETE RESTRICT,

    policy_id BIGINT NOT NULL
        REFERENCES pam.approval_policies(policy_id)
        ON DELETE RESTRICT,

    PRIMARY KEY (request_id, policy_id)
);


-- ============================================================
-- 8. APPROVAL DECISIONS
-- ============================================================

CREATE TABLE pam.approvals (
    approval_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL
        REFERENCES pam.access_requests(request_id)
        ON DELETE RESTRICT,

    approver_id BIGINT NOT NULL
        REFERENCES pam.users(user_id)
        ON DELETE RESTRICT,

    decision review_decision NOT NULL,

    comments TEXT,

    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (request_id, approver_id)
);


-- ============================================================
-- 9. AUTOMATED SECURITY CHECKS
-- ============================================================

CREATE TABLE pam.security_checks (
    check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    request_id BIGINT NOT NULL
        REFERENCES pam.access_requests(request_id)
        ON DELETE RESTRICT,

    check_name VARCHAR(100) NOT NULL,

    status check_status NOT NULL DEFAULT 'PENDING',

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    checked_at TIMESTAMPTZ,

    UNIQUE (request_id, check_name)
);


-- ============================================================
-- 10. PRIVILEGED SESSIONS
-- ============================================================

CREATE TABLE pam.privileged_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    request_id BIGINT NOT NULL UNIQUE
        REFERENCES pam.access_requests(request_id)
        ON DELETE RESTRICT,

    user_id BIGINT NOT NULL
        REFERENCES pam.users(user_id)
        ON DELETE RESTRICT,

    account_id BIGINT NOT NULL
        REFERENCES pam.privileged_accounts(account_id)
        ON DELETE RESTRICT,

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL,

    terminated_at TIMESTAMPTZ,

    status session_status NOT NULL DEFAULT 'ACTIVE',

    recording_enabled BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT valid_session_period
        CHECK (expires_at > started_at),

    CONSTRAINT valid_termination_time
        CHECK (
            terminated_at IS NULL
            OR terminated_at >= started_at
        )
);


-- ============================================================
-- 11. SESSION RECORDING METADATA
-- ============================================================

CREATE TABLE pam.session_recordings (
    recording_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id UUID NOT NULL UNIQUE
        REFERENCES pam.privileged_sessions(session_id)
        ON DELETE RESTRICT,

    storage_reference VARCHAR(255) NOT NULL,

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    recording_status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',

    CONSTRAINT valid_recording_status
        CHECK (
            recording_status IN (
                'ACTIVE',
                'COMPLETED',
                'FAILED'
            )
        )
);


-- ============================================================
-- 12. AUDIT EVENTS
-- ============================================================

CREATE TABLE pam.audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    actor_id BIGINT
        REFERENCES pam.users(user_id)
        ON DELETE SET NULL,

    action VARCHAR(100) NOT NULL,

    resource_type VARCHAR(100) NOT NULL,

    resource_id VARCHAR(100) NOT NULL,

    severity audit_severity NOT NULL DEFAULT 'INFO',

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 13. INDEXES
-- ============================================================

CREATE INDEX idx_access_requests_requester
    ON pam.access_requests(requester_id, created_at DESC);

CREATE INDEX idx_access_requests_status
    ON pam.access_requests(status, created_at DESC);

CREATE INDEX idx_approvals_request
    ON pam.approvals(request_id, decision);

CREATE INDEX idx_security_checks_status
    ON pam.security_checks(request_id, status);

CREATE INDEX idx_active_memberships
    ON pam.group_memberships(user_id, group_id)
    WHERE is_active = TRUE;

CREATE INDEX idx_active_sessions_expiration
    ON pam.privileged_sessions(expires_at)
    WHERE status = 'ACTIVE';

CREATE INDEX idx_sessions_account
    ON pam.privileged_sessions(account_id, started_at DESC);

CREATE INDEX idx_audit_resource
    ON pam.audit_events(resource_type, resource_id);

CREATE INDEX idx_audit_timestamp
    ON pam.audit_events(event_time DESC);

CREATE INDEX idx_audit_details
    ON pam.audit_events USING GIN(details);


-- ============================================================
-- 14. AUDIT TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION pam.log_request_status_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN

        INSERT INTO pam.audit_events (
            action,
            resource_type,
            resource_id,
            severity,
            details
        )
        VALUES (
            'REQUEST_STATUS_CHANGED',
            'ACCESS_REQUEST',
            NEW.request_id::TEXT,
            CASE
                WHEN NEW.status IN ('DENIED', 'REVOKED')
                    THEN 'WARNING'::pam.audit_severity
                ELSE 'INFO'::pam.audit_severity
            END,
            jsonb_build_object(
                'previous_status', OLD.status,
                'new_status', NEW.status
            )
        );

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_request_status_audit
AFTER UPDATE OF status
ON pam.access_requests
FOR EACH ROW
EXECUTE FUNCTION pam.log_request_status_change();


-- ============================================================
-- 15. SEPARATION OF DUTIES TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION pam.prevent_self_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    requester BIGINT;
    prohibit_self BOOLEAN;
BEGIN

    SELECT ar.requester_id
    INTO requester
    FROM pam.access_requests ar
    WHERE ar.request_id = NEW.request_id;

    SELECT COALESCE(
        bool_or(p.prohibit_self_approval),
        TRUE
    )
    INTO prohibit_self
    FROM pam.access_request_policies arp
    JOIN pam.approval_policies p
        ON p.policy_id = arp.policy_id
    WHERE arp.request_id = NEW.request_id
      AND p.is_active = TRUE;

    IF prohibit_self AND requester = NEW.approver_id THEN
        RAISE EXCEPTION
            'Self-approval is prohibited for request %',
            NEW.request_id;
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_prevent_self_approval
BEFORE INSERT ON pam.approvals
FOR EACH ROW
EXECUTE FUNCTION pam.prevent_self_approval();


-- ============================================================
-- 16. APPROVER ELIGIBILITY TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION pam.validate_approver()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    eligible BOOLEAN;
BEGIN

    SELECT
        u.is_active
        AND u.mfa_enabled
        AND EXISTS (
            SELECT 1
            FROM pam.user_roles ur
            JOIN pam.roles r
                ON r.role_id = ur.role_id
            WHERE ur.user_id = u.user_id
              AND r.role_name = 'pam_approver'
        )
    INTO eligible
    FROM pam.users u
    WHERE u.user_id = NEW.approver_id;

    IF COALESCE(eligible, FALSE) = FALSE THEN
        RAISE EXCEPTION
            'Approver is inactive, lacks MFA, or lacks PAM approver role';
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_validate_approver
BEFORE INSERT ON pam.approvals
FOR EACH ROW
EXECUTE FUNCTION pam.validate_approver();


-- ============================================================
-- 17. APPROVAL POLICY EVALUATION
-- ============================================================

CREATE OR REPLACE FUNCTION pam.evaluate_request(
    p_request_id BIGINT
)
RETURNS TABLE (
    eligible BOOLEAN,
    reason TEXT,
    approval_count BIGINT,
    required_approvals INTEGER,
    failed_checks BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    current_request pam.access_requests%ROWTYPE;
    required_count INTEGER;
    current_approvals BIGINT;
    failed_count BIGINT;
    policy_exists BOOLEAN;
BEGIN

    SELECT *
    INTO current_request
    FROM pam.access_requests
    WHERE request_id = p_request_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            FALSE,
            'REQUEST_NOT_FOUND'::TEXT,
            0::BIGINT,
            0,
            0::BIGINT;
        RETURN;
    END IF;

    SELECT
        COALESCE(MAX(p.minimum_approvals), 1),
        COALESCE(bool_or(p.is_active), FALSE)
    INTO required_count, policy_exists
    FROM pam.access_request_policies arp
    JOIN pam.approval_policies p
        ON p.policy_id = arp.policy_id
    WHERE arp.request_id = p_request_id;

    IF NOT policy_exists THEN
        required_count := 1;
    END IF;

    SELECT COUNT(DISTINCT a.approver_id)
    INTO current_approvals
    FROM pam.approvals a
    JOIN pam.users u
        ON u.user_id = a.approver_id
    WHERE a.request_id = p_request_id
      AND a.decision = 'APPROVE'
      AND u.is_active = TRUE
      AND u.mfa_enabled = TRUE
      AND EXISTS (
          SELECT 1
          FROM pam.user_roles ur
          JOIN pam.roles r
            ON r.role_id = ur.role_id
          WHERE ur.user_id = u.user_id
            AND r.role_name = 'pam_approver'
      );

    SELECT COUNT(*)
    INTO failed_count
    FROM pam.security_checks
    WHERE request_id = p_request_id
      AND status <> 'PASSED';

    eligible :=
        current_request.status = 'APPROVED'
        AND current_approvals >= required_count
        AND failed_count = 0;

    approval_count := current_approvals;
    required_approvals := required_count;
    failed_checks := failed_count;

    reason := CASE
        WHEN current_request.status <> 'APPROVED'
            THEN 'REQUEST_NOT_APPROVED'
        WHEN current_approvals < required_count
            THEN 'INSUFFICIENT_APPROVALS'
        WHEN failed_count > 0
            THEN 'SECURITY_CHECKS_INCOMPLETE'
        ELSE 'ELIGIBLE'
    END;

    RETURN NEXT;
END;
$$;


-- ============================================================
-- 18. JUST-IN-TIME SESSION CREATION
-- ============================================================

CREATE OR REPLACE PROCEDURE pam.activate_access(
    p_request_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    req pam.access_requests%ROWTYPE;
    account_state pam.account_status;
    policy_maximum INTEGER;
    group_maximum INTEGER;
    maximum_duration INTEGER;
    eligibility RECORD;
    membership_exists BOOLEAN;
    user_mfa BOOLEAN;
BEGIN

    SELECT *
    INTO req
    FROM pam.access_requests
    WHERE request_id = p_request_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Access request not found';
    END IF;

    IF req.status <> 'APPROVED' THEN
        RAISE EXCEPTION 'Request must be approved';
    END IF;

    SELECT
        a.status,
        u.mfa_enabled
    INTO account_state, user_mfa
    FROM pam.privileged_accounts a
    JOIN pam.users u
        ON u.user_id = req.requester_id
    WHERE a.account_id = req.account_id
      AND u.is_active = TRUE
    FOR UPDATE OF a;

    IF NOT FOUND OR account_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'User or privileged account unavailable';
    END IF;

    IF NOT user_mfa THEN
        RAISE EXCEPTION 'MFA is required';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM pam.account_group_assignments aga
        JOIN pam.group_memberships gm
            ON gm.group_id = aga.group_id
        JOIN pam.privileged_groups pg
            ON pg.group_id = aga.group_id
        WHERE aga.account_id = req.account_id
          AND gm.user_id = req.requester_id
          AND gm.is_active = TRUE
          AND gm.valid_from <= NOW()
          AND (
              gm.valid_until IS NULL
              OR gm.valid_until > NOW()
          )
          AND pg.is_active = TRUE
    )
    INTO membership_exists;

    IF NOT membership_exists THEN
        RAISE EXCEPTION 'No valid privileged group membership';
    END IF;

    SELECT COALESCE(MAX(p.maximum_session_minutes), 60)
    INTO policy_maximum
    FROM pam.access_request_policies arp
    JOIN pam.approval_policies p
        ON p.policy_id = arp.policy_id
    WHERE arp.request_id = p_request_id
      AND p.is_active = TRUE;

    SELECT MIN(pg.maximum_session_minutes)
    INTO group_maximum
    FROM pam.account_group_assignments aga
    JOIN pam.group_memberships gm
        ON gm.group_id = aga.group_id
    JOIN pam.privileged_groups pg
        ON pg.group_id = aga.group_id
    WHERE aga.account_id = req.account_id
      AND gm.user_id = req.requester_id
      AND gm.is_active = TRUE
      AND pg.is_active = TRUE
      AND gm.valid_from <= NOW()
      AND (
          gm.valid_until IS NULL
          OR gm.valid_until > NOW()
      );

    maximum_duration := LEAST(
        COALESCE(policy_maximum, 60),
        COALESCE(group_maximum, 0)
    );

    IF req.requested_minutes > maximum_duration THEN
        RAISE EXCEPTION 'Requested duration exceeds policy';
    END IF;

    SELECT *
    INTO eligibility
    FROM pam.evaluate_request(p_request_id);

    IF NOT eligibility.eligible THEN
        RAISE EXCEPTION
            'Access eligibility failed: %',
            eligibility.reason;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pam.privileged_sessions s
        JOIN pam.approval_policies p
            ON p.is_active = TRUE
        JOIN pam.access_request_policies arp
            ON arp.policy_id = p.policy_id
        WHERE s.user_id = req.requester_id
          AND s.account_id = req.account_id
          AND s.status = 'ACTIVE'
          AND s.expires_at > NOW()
          AND arp.request_id = p_request_id
          AND p.prohibit_concurrent_sessions = TRUE
    ) THEN
        RAISE EXCEPTION 'Concurrent session prohibited';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pam.vault_references
        WHERE account_id = req.account_id
          AND is_available = TRUE
    ) THEN
        RAISE EXCEPTION 'Credential vault unavailable';
    END IF;

    INSERT INTO pam.privileged_sessions (
        request_id,
        user_id,
        account_id,
        started_at,
        expires_at,
        status,
        recording_enabled
    )
    VALUES (
        req.request_id,
        req.requester_id,
        req.account_id,
        NOW(),
        NOW() + make_interval(
            mins => req.requested_minutes
        ),
        'ACTIVE',
        TRUE
    );

    UPDATE pam.access_requests
    SET status = 'ACTIVE'
    WHERE request_id = p_request_id;

    INSERT INTO pam.audit_events (
        actor_id,
        action,
        resource_type,
        resource_id,
        details
    )
    VALUES (
        req.requester_id,
        'SESSION_STARTED',
        'ACCESS_REQUEST',
        p_request_id::TEXT,
        jsonb_build_object(
            'account_id', req.account_id,
            'duration_minutes', req.requested_minutes
        )
    );

END;
$$;


-- ============================================================
-- 19. SESSION EXPIRATION
-- ============================================================

CREATE OR REPLACE PROCEDURE pam.expire_sessions()
LANGUAGE plpgsql
AS $$
BEGIN

    UPDATE pam.privileged_sessions
    SET
        status = 'EXPIRED',
        terminated_at = NOW()
    WHERE status = 'ACTIVE'
      AND expires_at <= NOW();

    UPDATE pam.access_requests ar
    SET
        status = 'EXPIRED',
        completed_at = NOW()
    FROM pam.privileged_sessions s
    WHERE s.request_id = ar.request_id
      AND s.status = 'EXPIRED'
      AND ar.status = 'ACTIVE';

END;
$$;


-- ============================================================
-- 20. ACCOUNT DISABLEMENT AND REVOCATION
-- ============================================================

CREATE OR REPLACE PROCEDURE pam.disable_account(
    p_account_id BIGINT,
    p_actor_id BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN

    UPDATE pam.privileged_accounts
    SET status = 'DISABLED'
    WHERE account_id = p_account_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Privileged account not found';
    END IF;

    UPDATE pam.privileged_sessions
    SET
        status = 'REVOKED',
        terminated_at = NOW()
    WHERE account_id = p_account_id
      AND status = 'ACTIVE';

    UPDATE pam.access_requests ar
    SET
        status = 'REVOKED',
        completed_at = NOW()
    FROM pam.privileged_sessions s
    WHERE s.request_id = ar.request_id
      AND s.account_id = p_account_id
      AND s.status = 'REVOKED'
      AND ar.status = 'ACTIVE';

    INSERT INTO pam.audit_events (
        actor_id,
        action,
        resource_type,
        resource_id,
        severity
    )
    VALUES (
        p_actor_id,
        'ACCOUNT_DISABLED',
        'PRIVILEGED_ACCOUNT',
        p_account_id::TEXT,
        'CRITICAL'
    );

END;
$$;


-- ============================================================
-- 21. ACCOUNT ROTATION DUE VIEW
-- ============================================================

CREATE OR REPLACE VIEW pam.v_rotation_due AS
SELECT
    a.account_id,
    a.username,
    a.system_name,
    a.privilege,
    a.last_rotated_at,
    a.rotation_interval_days,
    a.last_rotated_at
        + make_interval(days => a.rotation_interval_days)
        AS rotation_due_at
FROM pam.privileged_accounts a
WHERE a.status = 'ACTIVE'
  AND (
      a.last_rotated_at IS NULL
      OR a.last_rotated_at
          + make_interval(days => a.rotation_interval_days)
          <= NOW()
  );


-- ============================================================
-- 22. PRIVILEGED SESSION MONITORING VIEW
-- ============================================================

CREATE OR REPLACE VIEW pam.v_active_sessions AS
SELECT
    s.session_id,
    u.username,
    a.username AS privileged_username,
    a.system_name,
    a.privilege,
    s.started_at,
    s.expires_at,
    s.recording_enabled,
    EXTRACT(
        EPOCH FROM (s.expires_at - NOW())
    ) / 60 AS remaining_minutes
FROM pam.privileged_sessions s
JOIN pam.users u
    ON u.user_id = s.user_id
JOIN pam.privileged_accounts a
    ON a.account_id = s.account_id
WHERE s.status = 'ACTIVE'
  AND s.expires_at > NOW();


-- ============================================================
-- 23. ACCESS REQUEST REPORTING VIEW
-- ============================================================

CREATE OR REPLACE VIEW pam.v_access_request_report AS
SELECT
    ar.request_id,
    u.username AS requester,
    a.username AS privileged_account,
    a.system_name,
    ar.justification,
    ar.requested_minutes,
    ar.status,
    COUNT(
        DISTINCT ap.approver_id
    ) FILTER (
        WHERE ap.decision = 'APPROVE'
    ) AS approval_count,
    COUNT(
        DISTINCT sc.check_id
    ) FILTER (
        WHERE sc.status <> 'PASSED'
    ) AS incomplete_checks,
    ar.created_at
FROM pam.access_requests ar
JOIN pam.users u
    ON u.user_id = ar.requester_id
JOIN pam.privileged_accounts a
    ON a.account_id = ar.account_id
LEFT JOIN pam.approvals ap
    ON ap.request_id = ar.request_id
LEFT JOIN pam.security_checks sc
    ON sc.request_id = ar.request_id
GROUP BY
    ar.request_id,
    u.username,
    a.username,
    a.system_name,
    ar.justification,
    ar.requested_minutes,
    ar.status,
    ar.created_at;


-- ============================================================
-- 24. AUDIT SUMMARY VIEW
-- ============================================================

CREATE OR REPLACE VIEW pam.v_audit_summary AS
SELECT
    action,
    severity,
    COUNT(*) AS event_count,
    MAX(event_time) AS latest_event
FROM pam.audit_events
GROUP BY action, severity;


-- ============================================================
-- 25. SAMPLE MASTER DATA
-- ============================================================

INSERT INTO pam.users (
    username,
    department,
    email,
    is_active,
    mfa_enabled
)
VALUES
(
    'rahul.operator',
    'Infrastructure',
    'rahul.operator@example.org',
    TRUE,
    TRUE
),
(
    'neha.security',
    'Security',
    'neha.security@example.org',
    TRUE,
    TRUE
),
(
    'amit.auditor',
    'Internal Audit',
    'amit.auditor@example.org',
    TRUE,
    TRUE
),
(
    'inactive.operator',
    'Infrastructure',
    'inactive.operator@example.org',
    FALSE,
    FALSE
);


INSERT INTO pam.roles (role_name, description)
VALUES
(
    'system_operator',
    'Authorized infrastructure operator'
),
(
    'pam_approver',
    'Authorized privileged access approver'
),
(
    'security_admin',
    'Privileged security administrator'
),
(
    'auditor',
    'Read-only security audit reviewer'
);


INSERT INTO pam.user_roles (
    user_id,
    role_id
)
SELECT u.user_id, r.role_id
FROM pam.users u
CROSS JOIN pam.roles r
WHERE
    (u.username = 'rahul.operator'
        AND r.role_name = 'system_operator')
    OR
    (u.username = 'neha.security'
        AND r.role_name IN (
            'pam_approver',
            'security_admin'
        ))
    OR
    (u.username = 'amit.auditor'
        AND r.role_name = 'auditor');


INSERT INTO pam.privileged_groups (
    group_name,
    privilege,
    approval_required,
    maximum_session_minutes
)
VALUES
(
    'Production DBA Administrators',
    'ADMIN',
    TRUE,
    45
),
(
    'Cloud Infrastructure Administrators',
    'SUPER_ADMIN',
    TRUE,
    30
),
(
    'Development Database Operators',
    'ELEVATED',
    FALSE,
    120
);


INSERT INTO pam.group_memberships (
    group_id,
    user_id,
    assigned_by,
    is_active
)
SELECT
    g.group_id,
    u.user_id,
    (
        SELECT user_id
        FROM pam.users
        WHERE username = 'neha.security'
    ),
    TRUE
FROM pam.privileged_groups g
CROSS JOIN pam.users u
WHERE g.group_name = 'Production DBA Administrators'
  AND u.username = 'rahul.operator';


INSERT INTO pam.privileged_accounts (
    username,
    system_name,
    privilege,
    rotation_interval_days,
    last_rotated_at
)
VALUES
(
    'production_dba',
    'production-postgresql',
    'ADMIN',
    30,
    NOW() - INTERVAL '10 days'
),
(
    'cloud_root',
    'production-cloud',
    'SUPER_ADMIN',
    15,
    NOW() - INTERVAL '20 days'
),
(
    'development_dba',
    'development-postgresql',
    'ELEVATED',
    60,
    NOW() - INTERVAL '5 days'
);


INSERT INTO pam.account_group_assignments (
    account_id,
    group_id
)
SELECT a.account_id, g.group_id
FROM pam.privileged_accounts a
JOIN pam.privileged_groups g
ON (
    (
        a.username = 'production_dba'
        AND g.group_name = 'Production DBA Administrators'
    )
    OR
    (
        a.username = 'cloud_root'
        AND g.group_name = 'Cloud Infrastructure Administrators'
    )
    OR
    (
        a.username = 'development_dba'
        AND g.group_name = 'Development Database Operators'
    )
);


-- Opaque references only. No real secrets are inserted.
INSERT INTO pam.vault_references (
    account_id,
    vault_provider,
    secret_reference,
    credential_version
)
SELECT
    account_id,
    'Enterprise Secret Manager',
    'vault://production/account/' || account_id,
    1
FROM pam.privileged_accounts;


INSERT INTO pam.approval_policies (
    policy_name,
    minimum_approvals,
    prohibit_self_approval,
    require_mfa,
    require_status_checks,
    require_session_recording,
    prohibit_concurrent_sessions,
    maximum_session_minutes
)
VALUES
(
    'Production Critical Access',
    1,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    60
),
(
    'Super Administrator Access',
    2,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    30
),
(
    'Development Elevated Access',
    1,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TRUE,
    120
);


INSERT INTO pam.group_approval_policies (
    group_id,
    policy_id
)
SELECT g.group_id, p.policy_id
FROM pam.privileged_groups g
JOIN pam.approval_policies p
ON (
    (
        g.group_name = 'Production DBA Administrators'
        AND p.policy_name = 'Production Critical Access'
    )
    OR
    (
        g.group_name = 'Cloud Infrastructure Administrators'
        AND p.policy_name = 'Super Administrator Access'
    )
    OR
    (
        g.group_name = 'Development Database Operators'
        AND p.policy_name = 'Development Elevated Access'
    )
);


-- ============================================================
-- 26. SAMPLE ACCESS REQUESTS
-- ============================================================

INSERT INTO pam.access_requests (
    requester_id,
    account_id,
    justification,
    requested_minutes,
    status
)
SELECT
    u.user_id,
    a.account_id,
    'Investigate production database latency incident.',
    30,
    'PENDING'
FROM pam.users u
CROSS JOIN pam.privileged_accounts a
WHERE u.username = 'rahul.operator'
  AND a.username = 'production_dba';


INSERT INTO pam.access_request_policies (
    request_id,
    policy_id
)
SELECT ar.request_id, p.policy_id
FROM pam.access_requests ar
JOIN pam.approval_policies p
    ON p.policy_name = 'Production Critical Access';


-- ============================================================
-- 27. SAMPLE SECURITY CHECKS
-- ============================================================

INSERT INTO pam.security_checks (
    request_id,
    check_name,
    status,
    details,
    checked_at
)
SELECT
    request_id,
    checks.check_name,
    'PASSED',
    jsonb_build_object(
        'source', 'Automated PAM validation',
        'result', 'Successful'
    ),
    NOW()
FROM pam.access_requests
CROSS JOIN (
    VALUES
        ('identity'),
        ('mfa'),
        ('group_membership'),
        ('account_status'),
        ('credential_availability')
) AS checks(check_name);


-- ============================================================
-- 28. SAMPLE APPROVAL
-- ============================================================

INSERT INTO pam.approvals (
    request_id,
    approver_id,
    decision,
    comments
)
SELECT
    ar.request_id,
    u.user_id,
    'APPROVE',
    'Production incident verified.'
FROM pam.access_requests ar
CROSS JOIN pam.users u
WHERE u.username = 'neha.security';


UPDATE pam.access_requests
SET
    status = 'APPROVED',
    reviewed_at = NOW()
WHERE status = 'PENDING';


-- ============================================================
-- 29. SAMPLE AUDIT DATA
-- ============================================================

INSERT INTO pam.audit_events (
    actor_id,
    action,
    resource_type,
    resource_id,
    severity,
    details
)
SELECT
    user_id,
    'PRIVILEGED_ACCOUNT_REVIEWED',
    'PRIVILEGED_ACCOUNT',
    '1',
    'INFO',
    jsonb_build_object(
        'review_type', 'Periodic access review'
    )
FROM pam.users
WHERE username = 'amit.auditor';


INSERT INTO pam.audit_events (
    action,
    resource_type,
    resource_id,
    severity,
    details
)
VALUES
(
    'UNUSUAL_ADMIN_LOGIN',
    'PRIVILEGED_ACCOUNT',
    'cloud_root',
    'WARNING',
    '{"source":"Unrecognized network location"}'::JSONB
),
(
    'CREDENTIAL_ROTATION_FAILURE',
    'PRIVILEGED_ACCOUNT',
    'cloud_root',
    'CRITICAL',
    '{"reason":"External vault synchronization failed"}'::JSONB
);


COMMIT;


-- ============================================================
-- 30. RETRIEVAL QUERIES
-- ============================================================

-- Active privileged accounts.

SELECT
    account_id,
    username,
    system_name,
    privilege,
    status
FROM pam.privileged_accounts
WHERE status = 'ACTIVE'
ORDER BY privilege DESC;


-- Privileged group membership.

SELECT
    pg.group_name,
    u.username,
    pg.privilege,
    gm.valid_from,
    gm.valid_until
FROM pam.group_memberships gm
JOIN pam.privileged_groups pg
    ON pg.group_id = gm.group_id
JOIN pam.users u
    ON u.user_id = gm.user_id
WHERE gm.is_active = TRUE
ORDER BY pg.group_name, u.username;


-- ============================================================
-- 31. VALIDATION QUERIES
-- ============================================================

-- Detect privileged accounts without vault references.

SELECT
    a.account_id,
    a.username,
    a.system_name
FROM pam.privileged_accounts a
LEFT JOIN pam.vault_references v
    ON v.account_id = a.account_id
WHERE v.vault_id IS NULL
   OR v.is_available = FALSE;


-- Detect privileged groups without active members.

SELECT
    g.group_id,
    g.group_name
FROM pam.privileged_groups g
LEFT JOIN pam.group_memberships gm
    ON gm.group_id = g.group_id
   AND gm.is_active = TRUE
WHERE gm.user_id IS NULL;


-- Identify inactive users with privileged memberships.

SELECT
    u.username,
    g.group_name
FROM pam.group_memberships gm
JOIN pam.users u
    ON u.user_id = gm.user_id
JOIN pam.privileged_groups g
    ON g.group_id = gm.group_id
WHERE u.is_active = FALSE
  AND gm.is_active = TRUE;


-- ============================================================
-- 32. APPROVAL EVALUATION
-- ============================================================

SELECT *
FROM pam.evaluate_request(1);


-- Approval counts by request.

SELECT
    ar.request_id,
    ar.status,
    COUNT(DISTINCT ap.approver_id) FILTER (
        WHERE ap.decision = 'APPROVE'
    ) AS approvals,
    COUNT(DISTINCT ap.approver_id) FILTER (
        WHERE ap.decision = 'DENY'
    ) AS denials
FROM pam.access_requests ar
LEFT JOIN pam.approvals ap
    ON ap.request_id = ar.request_id
GROUP BY ar.request_id, ar.status;


-- ============================================================
-- 33. WORKFLOW PROCESSING
-- ============================================================

-- Execute only after validating approvals and security checks.
-- This call is atomic within its transaction.

BEGIN;

CALL pam.activate_access(1);

COMMIT;


-- ============================================================
-- 34. SESSION REPORTING
-- ============================================================

SELECT *
FROM pam.v_active_sessions;


-- ============================================================
-- 35. CREDENTIAL ROTATION REPORTING
-- ============================================================

SELECT *
FROM pam.v_rotation_due;


-- ============================================================
-- 36. AGGREGATION AND SECURITY REPORTING
-- ============================================================

SELECT
    status,
    COUNT(*) AS request_count,
    AVG(requested_minutes) AS average_requested_minutes
FROM pam.access_requests
GROUP BY status
ORDER BY status;


SELECT
    severity,
    COUNT(*) AS event_count
FROM pam.audit_events
GROUP BY severity
ORDER BY severity;


SELECT *
FROM pam.v_audit_summary
ORDER BY event_count DESC;


-- ============================================================
-- 37. ACCOUNT AND SESSION RISK REPORT
-- ============================================================

SELECT
    a.username,
    a.system_name,
    a.privilege,
    COUNT(s.session_id) AS total_sessions,
    COUNT(*) FILTER (
        WHERE s.status = 'ACTIVE'
    ) AS active_sessions,
    MAX(s.started_at) AS latest_session
FROM pam.privileged_accounts a
LEFT JOIN pam.privileged_sessions s
    ON s.account_id = a.account_id
GROUP BY
    a.account_id,
    a.username,
    a.system_name,
    a.privilege
ORDER BY a.privilege DESC;


-- ============================================================
-- 38. CTE: PRIVILEGED ACCESS RISK CLASSIFICATION
-- ============================================================

WITH account_risk AS (
    SELECT
        a.account_id,
        a.username,
        a.system_name,
        a.privilege,
        a.status,

        CASE
            WHEN a.privilege = 'SUPER_ADMIN'
                THEN 4
            WHEN a.privilege = 'ADMIN'
                THEN 3
            WHEN a.privilege = 'ELEVATED'
                THEN 2
            ELSE 1
        END AS privilege_score,

        CASE
            WHEN v.vault_id IS NULL
                OR v.is_available = FALSE
                THEN 5
            ELSE 0
        END AS vault_risk,

        CASE
            WHEN a.last_rotated_at IS NULL
                OR a.last_rotated_at
                    + make_interval(
                        days => a.rotation_interval_days
                    ) < NOW()
                THEN 3
            ELSE 0
        END AS rotation_risk

    FROM pam.privileged_accounts a
    LEFT JOIN pam.vault_references v
        ON v.account_id = a.account_id
)
SELECT
    *,
    privilege_score + vault_risk + rotation_risk
        AS total_risk_score
FROM account_risk
ORDER BY total_risk_score DESC;


-- ============================================================
-- 39. EXAMPLE: SESSION EXPIRATION
-- ============================================================

CALL pam.expire_sessions();


-- ============================================================
-- 40. SECURITY GOVERNANCE PRINCIPLES
-- ============================================================

-- Application/database role design:
--
-- Runtime role:
--   SELECT required inventory and policy information.
--   INSERT access requests and security checks.
--   EXECUTE approved workflow procedures.
--   No direct access to secret material.
--
-- Approver role:
--   Review requests and record approval decisions.
--   Cannot approve its own requests.
--
-- Auditor role:
--   SELECT reporting views and permitted audit records.
--   No UPDATE or DELETE on audit history.
--
-- Database owner:
--   Controls DDL, procedures, and security policies.
--
-- Production deployments should create separate LOGIN roles,
-- grant only required permissions, enforce TLS, protect
-- procedure execution privileges, and apply row-level security
-- where tenant or department isolation is necessary.
--
-- Audit retention and tamper resistance require separate
-- immutable or externally protected storage.
--
-- The database cannot itself prove that a remote vault
-- actually terminated an underlying operating-system or
-- database session. External session brokers must enforce it.
