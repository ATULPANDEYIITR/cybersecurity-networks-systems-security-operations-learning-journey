DROP SCHEMA IF EXISTS config_governance CASCADE;
CREATE SCHEMA config_governance;

SET search_path = config_governance, public;

CREATE TYPE pr_state AS ENUM ('draft', 'open', 'closed', 'merged');
CREATE TYPE review_state AS ENUM ('commented', 'approved', 'changes_requested', 'dismissed');
CREATE TYPE change_state AS ENUM ('proposed', 'approved', 'rejected', 'applied');

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE branches (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    head_commit_sha TEXT,
    UNIQUE (repository_id, name)
);

CREATE TABLE commits (
    commit_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    sha TEXT NOT NULL UNIQUE,
    message TEXT NOT NULL,
    author_id BIGINT REFERENCES users(user_id),
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    author_id BIGINT NOT NULL REFERENCES users(user_id),
    title TEXT NOT NULL,
    state pr_state NOT NULL DEFAULT 'draft',
    merge_conflict BOOLEAN NOT NULL DEFAULT FALSE,
    conversations_resolved BOOLEAN NOT NULL DEFAULT TRUE,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    commit_id BIGINT NOT NULL REFERENCES commits(commit_id),
    position INTEGER NOT NULL CHECK (position > 0),
    PRIMARY KEY (pull_request_id, commit_id),
    UNIQUE (pull_request_id, position)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES users(user_id),
    state review_state NOT NULL,
    eligible BOOLEAN NOT NULL DEFAULT FALSE,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    dismissed_at TIMESTAMPTZ
);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES reviews(review_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL CHECK (line_number > 0),
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE status_checks (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    passed BOOLEAN NOT NULL DEFAULT FALSE,
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name)
);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branches(branch_id) ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL CHECK (required_approvals >= 0),
    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_force_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_deletion BOOLEAN NOT NULL DEFAULT TRUE,
    require_resolved_conversations BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE approval_requirements (
    requirement_id BIGSERIAL PRIMARY KEY,
    policy_id BIGINT NOT NULL REFERENCES branch_protection_policies(policy_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES users(user_id),
    UNIQUE (policy_id, reviewer_id)
);

CREATE TABLE configuration_baselines (
    baseline_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    checksum TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (repository_id, name, version)
);

CREATE TABLE baseline_items (
    baseline_item_id BIGSERIAL PRIMARY KEY,
    baseline_id BIGINT NOT NULL REFERENCES configuration_baselines(baseline_id) ON DELETE CASCADE,
    config_key TEXT NOT NULL,
    expected_value TEXT,
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (baseline_id, config_key)
);

CREATE TABLE configuration_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    baseline_id BIGINT NOT NULL REFERENCES configuration_baselines(baseline_id),
    environment_name TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (baseline_id, environment_name, captured_at)
);

CREATE TABLE configuration_values (
    snapshot_id BIGINT NOT NULL REFERENCES configuration_snapshots(snapshot_id) ON DELETE CASCADE,
    config_key TEXT NOT NULL,
    actual_value TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (snapshot_id, config_key)
);

CREATE TABLE configuration_changes (
    change_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT REFERENCES pull_requests(pull_request_id),
    baseline_id BIGINT NOT NULL REFERENCES configuration_baselines(baseline_id),
    proposed_by BIGINT NOT NULL REFERENCES users(user_id),
    state change_state NOT NULL DEFAULT 'proposed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    applied_at TIMESTAMPTZ
);

CREATE TABLE audit_events (
    audit_event_id BIGSERIAL PRIMARY KEY,
    actor_id BIGINT REFERENCES users(user_id),
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id BIGINT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pr_target_state
    ON pull_requests(target_branch_id, state);

CREATE INDEX idx_reviews_pr_state
    ON reviews(pull_request_id, state, eligible);

CREATE INDEX idx_status_checks_pr
    ON status_checks(pull_request_id, required, passed);

CREATE INDEX idx_config_values_key
    ON configuration_values(config_key);

CREATE INDEX idx_audit_entity
    ON audit_events(entity_type, entity_id, created_at DESC);

-- Sample repository and identities.
INSERT INTO repositories(name, default_branch)
VALUES ('secure-config-platform', 'main');

INSERT INTO users(username) VALUES
    ('alice'),
    ('security-reviewer'),
    ('platform-reviewer'),
    ('release-manager'),
    ('untrusted-reviewer'),
    ('deployment-service');

INSERT INTO branches(repository_id, name, protected, head_commit_sha)
SELECT repository_id, 'main', TRUE, 'sha-main-002'
FROM repositories
WHERE name = 'secure-config-platform';

INSERT INTO branches(repository_id, name, protected, head_commit_sha)
SELECT repository_id, 'feature/hardened-config', FALSE, 'sha-feature-003'
FROM repositories
WHERE name = 'secure-config-platform';

INSERT INTO commits(repository_id, sha, message, author_id)
SELECT r.repository_id, v.sha, v.message, u.user_id
FROM repositories r
JOIN users u ON u.username = 'alice'
CROSS JOIN (
    VALUES
        ('sha-main-002', 'Harden production configuration baseline'),
        ('sha-feature-001', 'Add drift detection'),
        ('sha-feature-002', 'Add compliance rules'),
        ('sha-feature-003', 'Add remediation workflow')
) AS v(sha, message)
WHERE r.name = 'secure-config-platform';

INSERT INTO branch_protection_policies(
    branch_id,
    required_approvals,
    require_status_checks,
    restrict_direct_push,
    restrict_force_push,
    restrict_deletion,
    require_resolved_conversations,
    require_linear_history,
    administrator_bypass
)
SELECT branch_id, 2, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE
FROM branches
WHERE name = 'main';

INSERT INTO approval_requirements(policy_id, reviewer_id)
SELECT p.policy_id, u.user_id
FROM branch_protection_policies p
CROSS JOIN users u
WHERE u.username IN ('security-reviewer', 'platform-reviewer')
  AND p.branch_id = (SELECT branch_id FROM branches WHERE name = 'main');

INSERT INTO configuration_baselines(
    repository_id, name, version, checksum
)
SELECT repository_id,
       'production-linux-web',
       7,
       encode(
           digest(
               'production-linux-web:7:root-login-disabled:firewall-enabled:tls1.2',
               'sha256'
           ),
           'hex'
       )
FROM repositories
WHERE name = 'secure-config-platform';

INSERT INTO baseline_items(
    baseline_id, config_key, expected_value, is_secret, required
)
SELECT b.baseline_id, x.config_key, x.expected_value, x.is_secret, x.required
FROM configuration_baselines b
CROSS JOIN (
    VALUES
        ('ssh.root_login', 'false', FALSE, TRUE),
        ('ssh.password_authentication', 'false', FALSE, TRUE),
        ('firewall.enabled', 'true', FALSE, TRUE),
        ('tls.minimum_version', 'TLS1.2', FALSE, TRUE),
        ('audit.enabled', 'true', FALSE, TRUE),
        ('backup.retention_days', '30', FALSE, TRUE),
        ('service.https_port', '443', FALSE, TRUE),
        ('database.password', NULL, TRUE, TRUE)
) AS x(config_key, expected_value, is_secret, required)
WHERE b.name = 'production-linux-web' AND b.version = 7;

INSERT INTO pull_requests(
    repository_id,
    source_branch_id,
    target_branch_id,
    author_id,
    title,
    state,
    merge_conflict,
    conversations_resolved
)
SELECT r.repository_id,
       src.branch_id,
       target.branch_id,
       author.user_id,
       'Harden production configuration',
       'open',
       FALSE,
       TRUE
FROM repositories r
JOIN branches src ON src.repository_id = r.repository_id
                 AND src.name = 'feature/hardened-config'
JOIN branches target ON target.repository_id = r.repository_id
                     AND target.name = 'main'
JOIN users author ON author.username = 'alice'
WHERE r.name = 'secure-config-platform';

INSERT INTO pull_request_commits(pull_request_id, commit_id, position)
SELECT pr.pull_request_id, c.commit_id,
       CASE c.sha
           WHEN 'sha-feature-001' THEN 1
           WHEN 'sha-feature-002' THEN 2
           WHEN 'sha-feature-003' THEN 3
       END
FROM pull_requests pr
JOIN commits c ON c.sha IN ('sha-feature-001', 'sha-feature-002', 'sha-feature-003');

INSERT INTO reviews(
    pull_request_id, reviewer_id, state, eligible
)
SELECT pr.pull_request_id, u.user_id, 'approved', TRUE
FROM pull_requests pr
JOIN users u ON u.username IN ('security-reviewer', 'platform-reviewer');

INSERT INTO reviews(
    pull_request_id, reviewer_id, state, eligible
)
SELECT pr.pull_request_id, u.user_id, 'approved', FALSE
FROM pull_requests pr
JOIN users u ON u.username = 'untrusted-reviewer';

INSERT INTO review_comments(review_id, file_path, line_number, body, resolved)
SELECT review_id,
       'config/baseline.yaml',
       42,
       'Verify that secret material is not committed to the repository.',
       TRUE
FROM reviews
WHERE reviewer_id = (
    SELECT user_id FROM users WHERE username = 'security-reviewer'
);

INSERT INTO status_checks(
    pull_request_id, check_name, required, passed, completed_at
)
SELECT pr.pull_request_id, v.name, v.required, v.passed, now()
FROM pull_requests pr
CROSS JOIN (
    VALUES
        ('unit-tests', TRUE, TRUE),
        ('security-scan', TRUE, TRUE),
        ('configuration-policy', TRUE, TRUE),
        ('documentation-check', FALSE, FALSE)
) AS v(name, required, passed);

INSERT INTO configuration_snapshots(baseline_id, environment_name)
SELECT baseline_id, 'production'
FROM configuration_baselines
WHERE name = 'production-linux-web' AND version = 7;

INSERT INTO configuration_values(snapshot_id, config_key, actual_value)
SELECT s.snapshot_id, x.config_key, x.actual_value
FROM configuration_snapshots s
CROSS JOIN (
    VALUES
        ('ssh.root_login', 'false'),
        ('ssh.password_authentication', 'true'),
        ('firewall.enabled', 'true'),
        ('tls.minimum_version', 'TLS1.2'),
        ('audit.enabled', 'true'),
        ('backup.retention_days', '30'),
        ('service.https_port', '443'),
        ('database.password', 'REDACTED'),
        ('debug.enabled', 'true')
) AS x(config_key, actual_value)
WHERE s.environment_name = 'production';

-- Secret values are represented as REDACTED in the relational observation layer.
CREATE VIEW configuration_drift AS
SELECT
    s.snapshot_id,
    s.environment_name,
    b.config_key,
    CASE
        WHEN b.is_secret THEN '<SECRET>'
        ELSE b.expected_value
    END AS expected_value,
    CASE
        WHEN b.is_secret THEN '<SECRET>'
        ELSE cv.actual_value
    END AS actual_value,
    CASE
        WHEN cv.config_key IS NULL AND b.required THEN 'missing'
        WHEN cv.config_key IS NULL THEN 'optional_missing'
        WHEN b.is_secret THEN
            CASE WHEN cv.actual_value IS DISTINCT FROM 'REDACTED'
                 THEN 'drifted' ELSE 'observed' END
        WHEN cv.actual_value IS DISTINCT FROM b.expected_value THEN 'drifted'
        ELSE 'compliant'
    END AS status
FROM configuration_snapshots s
JOIN configuration_baselines cb ON cb.baseline_id = s.baseline_id
JOIN baseline_items b ON b.baseline_id = cb.baseline_id
LEFT JOIN configuration_values cv
       ON cv.snapshot_id = s.snapshot_id
      AND cv.config_key = b.config_key;

CREATE VIEW unauthorized_configuration_keys AS
SELECT
    s.snapshot_id,
    s.environment_name,
    cv.config_key,
    cv.actual_value
FROM configuration_snapshots s
JOIN configuration_values cv ON cv.snapshot_id = s.snapshot_id
LEFT JOIN baseline_items b
       ON b.baseline_id = s.baseline_id
      AND b.config_key = cv.config_key
WHERE b.baseline_item_id IS NULL
  AND cv.config_key NOT LIKE '%password%';

CREATE FUNCTION count_eligible_approvals(p_pr BIGINT)
RETURNS INTEGER
LANGUAGE SQL
STABLE
AS $$
    SELECT COUNT(DISTINCT r.reviewer_id)::INTEGER
    FROM reviews r
    JOIN pull_requests pr ON pr.pull_request_id = r.pull_request_id
    JOIN approval_requirements ar
      ON ar.reviewer_id = r.reviewer_id
    JOIN branch_protection_policies bp
      ON bp.policy_id = ar.policy_id
     AND bp.branch_id = pr.target_branch_id
    WHERE r.pull_request_id = p_pr
      AND r.state = 'approved'
      AND r.eligible = TRUE;
$$;

CREATE FUNCTION merge_eligibility(p_pr BIGINT)
RETURNS TABLE (
    eligible BOOLEAN,
    blocker TEXT
)
LANGUAGE SQL
STABLE
AS $$
    WITH pr AS (
        SELECT *
        FROM pull_requests
        WHERE pull_request_id = p_pr
    ),
    policy AS (
        SELECT bp.*
        FROM branch_protection_policies bp
        JOIN pr ON pr.target_branch_id = bp.branch_id
    ),
    check_failures AS (
        SELECT string_agg(sc.check_name, ', ' ORDER BY sc.check_name) AS failed
        FROM status_checks sc
        WHERE sc.pull_request_id = p_pr
          AND sc.required = TRUE
          AND sc.passed = FALSE
    )
    SELECT
        NOT (
            pr.state <> 'open'
            OR pr.merge_conflict
            OR count_eligible_approvals(p_pr) < policy.required_approvals
            OR (
                policy.require_status_checks
                AND EXISTS (
                    SELECT 1
                    FROM status_checks sc
                    WHERE sc.pull_request_id = p_pr
                      AND sc.required = TRUE
                      AND sc.passed = FALSE
                )
            )
            OR (
                policy.require_resolved_conversations
                AND NOT pr.conversations_resolved
            )
        ) AS eligible,
        CASE
            WHEN pr.state <> 'open' THEN 'Pull Request is not open'
            WHEN pr.merge_conflict THEN 'Merge conflict exists'
            WHEN count_eligible_approvals(p_pr) < policy.required_approvals
                THEN 'Required approvals are missing'
            WHEN EXISTS (
                SELECT 1
                FROM status_checks sc
                WHERE sc.pull_request_id = p_pr
                  AND sc.required = TRUE
                  AND sc.passed = FALSE
            ) THEN 'Required status check failed'
            WHEN policy.require_resolved_conversations
                 AND NOT pr.conversations_resolved
                THEN 'Unresolved conversations remain'
            ELSE NULL
        END AS blocker
    FROM pr
    JOIN policy ON TRUE;
$$;

CREATE FUNCTION prevent_protected_direct_push()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    protected_branch BOOLEAN;
BEGIN
    SELECT b.protected
    INTO protected_branch
    FROM branches b
    WHERE b.branch_id = NEW.target_branch_id;

    IF protected_branch AND NEW.state = 'merged' THEN
        IF count_eligible_approvals(NEW.pull_request_id) = 0 THEN
            RAISE EXCEPTION
                'Protected branch cannot accept a merge without eligible approval';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protected_merge_guard
BEFORE UPDATE OF state ON pull_requests
FOR EACH ROW
WHEN (NEW.state = 'merged')
EXECUTE FUNCTION prevent_protected_direct_push();

-- Pull Request retrieval.
SELECT
    pr.pull_request_id,
    r.name AS repository,
    src.name AS source_branch,
    target.name AS target_branch,
    pr.title,
    pr.state
FROM pull_requests pr
JOIN repositories r ON r.repository_id = pr.repository_id
JOIN branches src ON src.branch_id = pr.source_branch_id
JOIN branches target ON target.branch_id = pr.target_branch_id;

-- Configuration drift report.
SELECT *
FROM configuration_drift
WHERE status IN ('drifted', 'missing')
ORDER BY config_key;

-- Unauthorized configuration report.
SELECT *
FROM unauthorized_configuration_keys
ORDER BY config_key;

-- Approval evaluation.
SELECT
    pr.pull_request_id,
    count_eligible_approvals(pr.pull_request_id) AS eligible_approvals,
    bp.required_approvals
FROM pull_requests pr
JOIN branch_protection_policies bp
  ON bp.branch_id = pr.target_branch_id;

-- Status-check evaluation.
SELECT
    pr.pull_request_id,
    sc.check_name,
    sc.required,
    sc.passed,
    CASE
        WHEN sc.required AND NOT sc.passed THEN 'BLOCKED'
        WHEN sc.required THEN 'PASSED'
        ELSE 'OPTIONAL'
    END AS evaluation
FROM pull_requests pr
JOIN status_checks sc ON sc.pull_request_id = pr.pull_request_id
ORDER BY pr.pull_request_id, sc.check_name;

-- Merge eligibility.
SELECT *
FROM merge_eligibility(
    (SELECT pull_request_id FROM pull_requests LIMIT 1)
);

-- Compliance aggregation.
SELECT
    environment_name,
    COUNT(*) FILTER (WHERE status = 'compliant') AS compliant_items,
    COUNT(*) FILTER (WHERE status IN ('drifted', 'missing')) AS drifted_items,
    COUNT(*) AS baseline_items
FROM configuration_drift
GROUP BY environment_name;

-- Transactional example: an approval is only recorded when the reviewer
-- belongs to the policy's eligible reviewer set.
BEGIN;

WITH selected AS (
    SELECT
        pr.pull_request_id,
        u.user_id,
        bp.policy_id
    FROM pull_requests pr
    JOIN branches b ON b.branch_id = pr.target_branch_id
    JOIN branch_protection_policies bp ON bp.branch_id = b.branch_id
    JOIN users u ON u.username = 'release-manager'
    WHERE pr.state = 'open'
)
INSERT INTO approval_requirements(policy_id, reviewer_id)
SELECT policy_id, user_id
FROM selected
ON CONFLICT (policy_id, reviewer_id) DO NOTHING;

INSERT INTO audit_events(actor_id, event_type, entity_type, entity_id, details)
SELECT
    u.user_id,
    'POLICY_REVIEWED',
    'pull_request',
    pr.pull_request_id,
    jsonb_build_object(
        'required_approvals',
        bp.required_approvals,
        'eligible_approvals',
        count_eligible_approvals(pr.pull_request_id)
    )
FROM pull_requests pr
JOIN branches b ON b.branch_id = pr.target_branch_id
JOIN branch_protection_policies bp ON bp.branch_id = b.branch_id
JOIN users u ON u.username = 'release-manager'
WHERE pr.state = 'open';

COMMIT;

-- Final governance report.
SELECT
    pr.pull_request_id,
    pr.title,
    pr.state,
    count_eligible_approvals(pr.pull_request_id) AS eligible_approvals,
    bp.required_approvals,
    CASE
        WHEN EXISTS (
            SELECT 1
            FROM merge_eligibility(pr.pull_request_id) m
            WHERE m.eligible = FALSE
        ) THEN 'BLOCKED'
        ELSE 'ELIGIBLE'
    END AS merge_status
FROM pull_requests pr
JOIN branch_protection_policies bp
  ON bp.branch_id = pr.target_branch_id
ORDER BY pr.pull_request_id;
