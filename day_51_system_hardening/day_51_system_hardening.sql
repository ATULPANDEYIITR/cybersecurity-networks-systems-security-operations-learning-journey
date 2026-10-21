DROP SCHEMA IF EXISTS system_hardening CASCADE;
CREATE SCHEMA system_hardening;
SET search_path TO system_hardening;

-- The model distinguishes host baseline state, exposed services,
-- patch state, and repository governance policy.

CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE patch_status AS ENUM ('required', 'scheduled', 'installed', 'deferred');
CREATE TYPE pr_status AS ENUM ('draft', 'open', 'closed', 'merged');
CREATE TYPE review_state AS ENUM ('commented', 'changes_requested', 'approved', 'dismissed');

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE branches (
    branch_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    is_protected BOOLEAN NOT NULL DEFAULT false,
    UNIQUE (repository_id, name)
);

CREATE UNIQUE INDEX branches_one_default
ON branches(repository_id)
WHERE is_default;

CREATE TABLE branch_protection_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branches(branch_id) ON DELETE CASCADE,
    required_status_checks BOOLEAN NOT NULL DEFAULT false,
    required_reviews BOOLEAN NOT NULL DEFAULT false,
    required_approvals INTEGER NOT NULL DEFAULT 0
        CHECK (required_approvals >= 0),
    require_resolved_conversations BOOLEAN NOT NULL DEFAULT false,
    prohibit_direct_push BOOLEAN NOT NULL DEFAULT true,
    prohibit_force_push BOOLEAN NOT NULL DEFAULT true,
    prohibit_branch_deletion BOOLEAN NOT NULL DEFAULT true,
    require_linear_history BOOLEAN NOT NULL DEFAULT false,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    is_administrator BOOLEAN NOT NULL DEFAULT false,
    is_security_reviewer BOOLEAN NOT NULL DEFAULT false,
    active BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE pull_requests (
    pull_request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    source_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    title TEXT NOT NULL,
    status pr_status NOT NULL DEFAULT 'open',
    is_draft BOOLEAN NOT NULL DEFAULT false,
    conversations_resolved BOOLEAN NOT NULL DEFAULT false,
    created_by BIGINT NOT NULL REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (source_branch_id <> target_branch_id)
);

CREATE TABLE commits (
    commit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    sha CHAR(40) NOT NULL UNIQUE,
    message TEXT NOT NULL,
    authored_by BIGINT NOT NULL REFERENCES users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE review_requests (
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES users(user_id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (pull_request_id, reviewer_id)
);

CREATE TABLE reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES users(user_id),
    state review_state NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    commit_id BIGINT REFERENCES commits(commit_id),
    dismissed_at TIMESTAMPTZ,
    dismissal_reason TEXT
);

CREATE TABLE review_comments (
    comment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES reviews(review_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL CHECK (line_number > 0),
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE status_checks (
    status_check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    required BOOLEAN NOT NULL DEFAULT true,
    passed BOOLEAN NOT NULL DEFAULT false,
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE hosts (
    host_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    os_version TEXT NOT NULL,
    password_min_length INTEGER NOT NULL CHECK (password_min_length > 0),
    password_max_age_days INTEGER NOT NULL CHECK (password_max_age_days > 0),
    firewall_enabled BOOLEAN NOT NULL,
    remote_root_login_disabled BOOLEAN NOT NULL,
    audit_logging_enabled BOOLEAN NOT NULL,
    disk_encryption_enabled BOOLEAN NOT NULL
);

CREATE TABLE secure_baselines (
    baseline_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    minimum_password_length INTEGER NOT NULL CHECK (minimum_password_length > 0),
    maximum_password_age_days INTEGER NOT NULL CHECK (maximum_password_age_days > 0),
    firewall_required BOOLEAN NOT NULL,
    remote_root_login_disabled BOOLEAN NOT NULL,
    audit_logging_required BOOLEAN NOT NULL,
    disk_encryption_required BOOLEAN NOT NULL
);

CREATE TABLE host_services (
    service_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    port INTEGER CHECK (port BETWEEN 1 AND 65535),
    required BOOLEAN NOT NULL,
    externally_reachable BOOLEAN NOT NULL,
    encrypted BOOLEAN NOT NULL,
    UNIQUE (host_id, service_name)
);

CREATE TABLE vulnerabilities (
    vulnerability_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve TEXT NOT NULL UNIQUE,
    severity severity_level NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE host_vulnerabilities (
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(vulnerability_id),
    affected_service TEXT NOT NULL,
    fixed_version TEXT NOT NULL,
    due_date DATE NOT NULL,
    status patch_status NOT NULL DEFAULT 'required',
    PRIMARY KEY (host_id, vulnerability_id)
);

CREATE INDEX idx_pr_target_status
ON pull_requests(target_branch_id, status);

CREATE INDEX idx_reviews_pr_state
ON reviews(pull_request_id, state);

CREATE INDEX idx_status_checks_pr_required
ON status_checks(pull_request_id, required, passed);

CREATE INDEX idx_host_vulnerabilities_due
ON host_vulnerabilities(due_date, status);

INSERT INTO repositories (name, default_branch)
VALUES ('payments-platform', 'main');

INSERT INTO branches (repository_id, name, is_default, is_protected)
SELECT repository_id, 'main', true, true
FROM repositories
WHERE name = 'payments-platform';

INSERT INTO branches (repository_id, name)
SELECT repository_id, 'feature/security-fix'
FROM repositories
WHERE name = 'payments-platform';

INSERT INTO branch_protection_policies (
    branch_id,
    required_status_checks,
    required_reviews,
    required_approvals,
    require_resolved_conversations,
    prohibit_direct_push,
    prohibit_force_push,
    prohibit_branch_deletion,
    require_linear_history,
    allow_administrator_bypass
)
SELECT
    branch_id,
    true,
    true,
    2,
    true,
    true,
    true,
    true,
    true,
    false
FROM branches
WHERE name = 'main';

INSERT INTO users (username, is_administrator, is_security_reviewer)
VALUES
    ('alice', false, true),
    ('bob', false, true),
    ('release-manager', false, false),
    ('security-admin', true, true);

INSERT INTO pull_requests (
    repository_id,
    source_branch_id,
    target_branch_id,
    title,
    status,
    is_draft,
    conversations_resolved,
    created_by
)
SELECT
    r.repository_id,
    source.branch_id,
    target.branch_id,
    'Rotate API keys and enforce encrypted transport',
    'open',
    false,
    false,
    u.user_id
FROM repositories r
JOIN branches source
    ON source.repository_id = r.repository_id
   AND source.name = 'feature/security-fix'
JOIN branches target
    ON target.repository_id = r.repository_id
   AND target.name = 'main'
JOIN users u ON u.username = 'release-manager'
WHERE r.name = 'payments-platform';

INSERT INTO commits (
    pull_request_id,
    sha,
    message,
    authored_by
)
SELECT
    pr.pull_request_id,
    repeat('a', 40),
    'Harden transport and rotate credentials',
    u.user_id
FROM pull_requests pr
JOIN users u ON u.username = 'release-manager';

INSERT INTO review_requests (pull_request_id, reviewer_id)
SELECT pr.pull_request_id, u.user_id
FROM pull_requests pr
JOIN users u ON u.username IN ('alice', 'bob');

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    commit_id
)
SELECT
    pr.pull_request_id,
    u.user_id,
    CASE
        WHEN u.username = 'alice' THEN 'approved'::review_state
        ELSE 'changes_requested'::review_state
    END,
    c.commit_id
FROM pull_requests pr
JOIN users u ON u.username IN ('alice', 'bob')
JOIN commits c ON c.pull_request_id = pr.pull_request_id;

INSERT INTO review_comments (
    review_id,
    file_path,
    line_number,
    body,
    resolved
)
SELECT
    review_id,
    'src/security/config.py',
    48,
    'Require the production certificate validation mode.',
    false
FROM reviews
WHERE state = 'changes_requested';

INSERT INTO status_checks (
    pull_request_id,
    check_name,
    required,
    passed
)
SELECT
    pull_request_id,
    check_name,
    true,
    passed
FROM pull_requests
CROSS JOIN (
    VALUES
        ('unit-tests', true),
        ('static-analysis', true),
        ('security-scan', false)
) AS checks(check_name, passed);

INSERT INTO secure_baselines (
    name,
    minimum_password_length,
    maximum_password_age_days,
    firewall_required,
    remote_root_login_disabled,
    audit_logging_required,
    disk_encryption_required
)
VALUES (
    'Linux Server Baseline 2026',
    14,
    90,
    true,
    true,
    true,
    true
);

INSERT INTO hosts (
    hostname,
    os_version,
    password_min_length,
    password_max_age_days,
    firewall_enabled,
    remote_root_login_disabled,
    audit_logging_enabled,
    disk_encryption_enabled
)
VALUES (
    'payments-api-01',
    'Ubuntu 24.04 LTS',
    10,
    180,
    false,
    false,
    false,
    false
);

INSERT INTO host_services (
    host_id,
    service_name,
    port,
    required,
    externally_reachable,
    encrypted
)
SELECT
    host_id,
    service_name,
    port,
    required,
    externally_reachable,
    encrypted
FROM hosts
CROSS JOIN (
    VALUES
        ('ssh', 22, true, true, true),
        ('https', 443, true, true, true),
        ('telnet', 23, false, true, false),
        ('ftp', 21, false, true, false),
        ('metrics', 9100, true, false, true)
) AS services(
    service_name,
    port,
    required,
    externally_reachable,
    encrypted
)
WHERE hostname = 'payments-api-01';

INSERT INTO vulnerabilities (cve, severity, description)
VALUES
    (
        'CVE-2026-10001',
        'critical',
        'Critical remotely exploitable service vulnerability.'
    ),
    (
        'CVE-2026-10017',
        'high',
        'High-severity vulnerability requiring a service update.'
    );

INSERT INTO host_vulnerabilities (
    host_id,
    vulnerability_id,
    affected_service,
    fixed_version,
    due_date,
    status
)
SELECT
    h.host_id,
    v.vulnerability_id,
    CASE v.cve
        WHEN 'CVE-2026-10001' THEN 'https'
        ELSE 'ssh'
    END,
    CASE v.cve
        WHEN 'CVE-2026-10001' THEN '4.8.2'
        ELSE '9.9p2'
    END,
    CASE v.cve
        WHEN 'CVE-2026-10001' THEN DATE '2026-10-18'
        ELSE DATE '2026-10-28'
    END,
    CASE v.cve
        WHEN 'CVE-2026-10001' THEN 'required'::patch_status
        ELSE 'scheduled'::patch_status
    END
FROM hosts h
CROSS JOIN vulnerabilities v
WHERE h.hostname = 'payments-api-01';

-- The view exposes the effective hardening gaps without changing host state.
CREATE VIEW host_hardening_findings AS
SELECT
    h.hostname,
    'authentication' AS category,
    'high'::severity_level AS severity,
    'Password minimum length is below the baseline.' AS finding
FROM hosts h
JOIN secure_baselines b ON b.name = 'Linux Server Baseline 2026'
WHERE h.password_min_length < b.minimum_password_length

UNION ALL

SELECT
    h.hostname,
    'network',
    'critical'::severity_level,
    'Host firewall is disabled.'
FROM hosts h
JOIN secure_baselines b ON b.name = 'Linux Server Baseline 2026'
WHERE b.firewall_required AND NOT h.firewall_enabled

UNION ALL

SELECT
    h.hostname,
    'access-control',
    'critical'::severity_level,
    'Remote root login is not disabled.'
FROM hosts h
JOIN secure_baselines b ON b.name = 'Linux Server Baseline 2026'
WHERE b.remote_root_login_disabled
  AND NOT h.remote_root_login_disabled

UNION ALL

SELECT
    h.hostname,
    'logging',
    'high'::severity_level,
    'Audit logging is disabled.'
FROM hosts h
JOIN secure_baselines b ON b.name = 'Linux Server Baseline 2026'
WHERE b.audit_logging_required
  AND NOT h.audit_logging_enabled

UNION ALL

SELECT
    h.hostname,
    'storage',
    'high'::severity_level,
    'Disk encryption is disabled.'
FROM hosts h
JOIN secure_baselines b ON b.name = 'Linux Server Baseline 2026'
WHERE b.disk_encryption_required
  AND NOT h.disk_encryption_enabled

UNION ALL

SELECT
    h.hostname,
    'service-minimization',
    CASE
        WHEN s.externally_reachable
        THEN 'high'::severity_level
        ELSE 'medium'::severity_level
    END,
    'Unnecessary service is enabled: ' || s.service_name
FROM hosts h
JOIN host_services s ON s.host_id = h.host_id
WHERE NOT s.required;

CREATE VIEW externally_exposed_services AS
SELECT
    h.hostname,
    s.service_name,
    s.port,
    s.encrypted,
    CASE
        WHEN NOT s.required AND NOT s.encrypted THEN 8
        WHEN NOT s.required THEN 5
        WHEN NOT s.encrypted THEN 6
        ELSE 3
    END AS attack_surface_score
FROM hosts h
JOIN host_services s ON s.host_id = h.host_id
WHERE s.externally_reachable;

CREATE VIEW patch_risk_report AS
SELECT
    h.hostname,
    v.cve,
    v.severity,
    hv.affected_service,
    hv.fixed_version,
    hv.due_date,
    hv.status,
    CASE
        WHEN hv.status = 'installed' THEN 'remediated'
        WHEN v.severity = 'critical' THEN 'immediate'
        WHEN hv.due_date < CURRENT_DATE THEN 'overdue'
        ELSE 'scheduled'
    END AS patch_priority
FROM host_vulnerabilities hv
JOIN hosts h ON h.host_id = hv.host_id
JOIN vulnerabilities v ON v.vulnerability_id = hv.vulnerability_id;

-- Review approval counts are deliberately separated from the policy that
-- decides whether those approvals are sufficient.
WITH eligible_approvals AS (
    SELECT
        pr.pull_request_id,
        COUNT(*) AS approval_count
    FROM pull_requests pr
    JOIN reviews r
      ON r.pull_request_id = pr.pull_request_id
    JOIN users u
      ON u.user_id = r.reviewer_id
    WHERE r.state = 'approved'
      AND r.dismissed_at IS NULL
      AND u.active
    GROUP BY pr.pull_request_id
)
SELECT
    pr.pull_request_id,
    pr.title,
    COALESCE(ea.approval_count, 0) AS approvals,
    bpp.required_approvals,
    COALESCE(ea.approval_count, 0) >= bpp.required_approvals
        AS approval_requirement_met
FROM pull_requests pr
JOIN branch_protection_policies bpp
  ON bpp.branch_id = pr.target_branch_id
LEFT JOIN eligible_approvals ea
  ON ea.pull_request_id = pr.pull_request_id;

-- Required status checks must all pass before a protected merge is eligible.
SELECT
    pr.pull_request_id,
    pr.title,
    COUNT(*) FILTER (
        WHERE sc.required AND NOT sc.passed
    ) AS failed_required_checks,
    COUNT(*) FILTER (
        WHERE sc.required
    ) AS required_checks,
    COUNT(*) FILTER (
        WHERE sc.required AND sc.passed
    ) AS passed_required_checks
FROM pull_requests pr
LEFT JOIN status_checks sc
    ON sc.pull_request_id = pr.pull_request_id
GROUP BY pr.pull_request_id, pr.title;

-- Review conversations can be queried independently from approval state.
SELECT
    pr.pull_request_id,
    COUNT(rc.comment_id) AS unresolved_comments
FROM pull_requests pr
LEFT JOIN reviews r
    ON r.pull_request_id = pr.pull_request_id
LEFT JOIN review_comments rc
    ON rc.review_id = r.review_id
   AND NOT rc.resolved
GROUP BY pr.pull_request_id;

-- Transactional example: installing a patch and recording the resulting state
-- must happen atomically. A real deployment would also verify the package
-- manager result before committing this database state.
BEGIN;

UPDATE host_vulnerabilities
SET status = 'installed'
WHERE host_id = (
    SELECT host_id
    FROM hosts
    WHERE hostname = 'payments-api-01'
)
AND vulnerability_id = (
    SELECT vulnerability_id
    FROM vulnerabilities
    WHERE cve = 'CVE-2026-10001'
)
AND status <> 'installed';

-- Integrity check before commit.
DO $$
DECLARE
    remaining INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO remaining
    FROM host_vulnerabilities hv
    JOIN vulnerabilities v
      ON v.vulnerability_id = hv.vulnerability_id
    WHERE v.cve = 'CVE-2026-10001'
      AND hv.status <> 'installed';

    IF remaining > 0 THEN
        RAISE EXCEPTION 'Critical vulnerability was not marked installed';
    END IF;
END
$$;

COMMIT;

-- A trigger prevents an invalid protected-branch policy configuration.
CREATE OR REPLACE FUNCTION validate_branch_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.required_approvals > 0
       AND NOT NEW.required_reviews THEN
        RAISE EXCEPTION
            'Approval count cannot be positive when required_reviews is false';
    END IF;

    IF NOT NEW.prohibit_direct_push
       AND NEW.protectedBranch_placeholder IS NOT NULL THEN
        RAISE EXCEPTION 'Invalid branch policy';
    END IF;

    RETURN NEW;
END;
$$;

-- PostgreSQL cannot reference an undeclared placeholder column. Replace the
-- invalid trigger definition above with the executable validation trigger.
DROP FUNCTION validate_branch_policy();

CREATE OR REPLACE FUNCTION validate_branch_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.required_approvals > 0
       AND NOT NEW.required_reviews THEN
        RAISE EXCEPTION
            'Approval count cannot be positive when required_reviews is false';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_branch_policy
BEFORE INSERT OR UPDATE ON branch_protection_policies
FOR EACH ROW
EXECUTE FUNCTION validate_branch_policy();

-- Final merge-eligibility report.
WITH approval_state AS (
    SELECT
        pr.pull_request_id,
        COUNT(*) FILTER (
            WHERE r.state = 'approved'
              AND r.dismissed_at IS NULL
              AND u.active
        ) AS valid_approvals
    FROM pull_requests pr
    LEFT JOIN reviews r
      ON r.pull_request_id = pr.pull_request_id
    LEFT JOIN users u
      ON u.user_id = r.reviewer_id
    GROUP BY pr.pull_request_id
),
check_state AS (
    SELECT
        pull_request_id,
        COUNT(*) FILTER (
            WHERE required AND NOT passed
        ) AS failed_required_checks
    FROM status_checks
    GROUP BY pull_request_id
),
conversation_state AS (
    SELECT
        pr.pull_request_id,
        COUNT(rc.comment_id) FILTER (
            WHERE NOT rc.resolved
        ) AS unresolved_comments
    FROM pull_requests pr
    LEFT JOIN reviews r
      ON r.pull_request_id = pr.pull_request_id
    LEFT JOIN review_comments rc
      ON rc.review_id = r.review_id
    GROUP BY pr.pull_request_id
)
SELECT
    pr.pull_request_id,
    pr.title,
    pr.status,
    (
        pr.status = 'open'
        AND NOT pr.is_draft
        AND (
            NOT bpp.required_reviews
            OR COALESCE(a.valid_approvals, 0) >= bpp.required_approvals
        )
        AND (
            NOT bpp.required_status_checks
            OR COALESCE(c.failed_required_checks, 0) = 0
        )
        AND (
            NOT bpp.require_resolved_conversations
            OR COALESCE(cs.unresolved_comments, 0) = 0
        )
    ) AS merge_eligible
FROM pull_requests pr
JOIN branch_protection_policies bpp
  ON bpp.branch_id = pr.target_branch_id
LEFT JOIN approval_state a
  ON a.pull_request_id = pr.pull_request_id
LEFT JOIN check_state c
  ON c.pull_request_id = pr.pull_request_id
LEFT JOIN conversation_state cs
  ON cs.pull_request_id = pr.pull_request_id;
