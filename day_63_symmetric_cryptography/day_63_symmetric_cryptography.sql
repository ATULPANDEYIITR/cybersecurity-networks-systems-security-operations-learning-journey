DROP SCHEMA IF EXISTS asymmetric_crypto CASCADE;
CREATE SCHEMA asymmetric_crypto;
SET search_path TO asymmetric_crypto;

CREATE TYPE key_algorithm AS ENUM ('RSA', 'ECC');
CREATE TYPE key_usage AS ENUM ('ENCRYPTION', 'SIGNING');
CREATE TYPE pr_state AS ENUM ('DRAFT', 'OPEN', 'CLOSED', 'MERGED');
CREATE TYPE review_state AS ENUM ('PENDING', 'APPROVED', 'CHANGES_REQUESTED', 'REJECTED');
CREATE TYPE check_state AS ENUM ('PENDING', 'PASSED', 'FAILED');

CREATE TABLE repository (
    repository_id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    owner_team TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE repository_key (
    key_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repository(repository_id) ON DELETE CASCADE,
    key_algorithm key_algorithm NOT NULL,
    key_usage key_usage NOT NULL,
    key_fingerprint TEXT NOT NULL UNIQUE,
    public_key_pem TEXT NOT NULL,
    private_key_reference TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at TIMESTAMPTZ,
    CHECK (length(key_fingerprint) >= 32),
    CHECK (
        (key_usage = 'ENCRYPTION' AND private_key_reference IS NOT NULL)
        OR
        (key_usage = 'SIGNING')
    )
);

CREATE TABLE branch (
    branch_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repository(repository_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    protected BOOLEAN NOT NULL DEFAULT FALSE,
    head_commit TEXT NOT NULL,
    UNIQUE(repository_id, name)
);

CREATE TABLE commit_record (
    commit_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repository(repository_id) ON DELETE CASCADE,
    sha TEXT NOT NULL,
    author TEXT NOT NULL,
    message TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(repository_id, sha)
);

CREATE TABLE pull_request (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repository(repository_id) ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL REFERENCES branch(branch_id),
    target_branch_id BIGINT NOT NULL REFERENCES branch(branch_id),
    title TEXT NOT NULL,
    state pr_state NOT NULL DEFAULT 'OPEN',
    is_draft BOOLEAN NOT NULL DEFAULT FALSE,
    mergeable BOOLEAN NOT NULL DEFAULT TRUE,
    unresolved_conversations INTEGER NOT NULL DEFAULT 0,
    opened_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    merged_at TIMESTAMPTZ,
    CHECK (unresolved_conversations >= 0),
    CHECK (source_branch_id <> target_branch_id)
);

CREATE TABLE pull_request_commit (
    pull_request_id BIGINT NOT NULL REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    commit_id BIGINT NOT NULL REFERENCES commit_record(commit_id),
    PRIMARY KEY (pull_request_id, commit_id)
);

CREATE TABLE reviewer (
    reviewer_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    team TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE review (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES reviewer(reviewer_id),
    state review_state NOT NULL,
    body TEXT,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(pull_request_id, reviewer_id)
);

CREATE TABLE review_comment (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES review(review_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER NOT NULL,
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (line_number > 0)
);

CREATE TABLE status_check (
    status_check_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_request(pull_request_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    state check_state NOT NULL,
    completed_at TIMESTAMPTZ,
    UNIQUE(pull_request_id, name)
);

CREATE TABLE branch_protection (
    protection_id BIGSERIAL PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branch(branch_id) ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL DEFAULT 0,
    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_resolved_conversations BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_force_push BOOLEAN NOT NULL DEFAULT TRUE,
    restrict_branch_deletion BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (required_approvals >= 0)
);

CREATE TABLE required_status_check (
    protection_id BIGINT NOT NULL REFERENCES branch_protection(protection_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    PRIMARY KEY (protection_id, check_name)
);

CREATE TABLE approval_requirement (
    protection_id BIGINT NOT NULL REFERENCES branch_protection(protection_id) ON DELETE CASCADE,
    team_name TEXT NOT NULL,
    minimum_approvals INTEGER NOT NULL,
    PRIMARY KEY (protection_id, team_name),
    CHECK (minimum_approvals > 0)
);

CREATE TABLE merge_record (
    merge_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL UNIQUE REFERENCES pull_request(pull_request_id),
    merged_by TEXT NOT NULL,
    merge_method TEXT NOT NULL CHECK (merge_method IN ('MERGE', 'SQUASH', 'REBASE')),
    merge_commit_sha TEXT NOT NULL,
    merged_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pr_repository_state
    ON pull_request(repository_id, state);

CREATE INDEX idx_review_pr_state
    ON review(pull_request_id, state);

CREATE INDEX idx_status_pr_state
    ON status_check(pull_request_id, state);

CREATE INDEX idx_commit_repository_sha
    ON commit_record(repository_id, sha);

CREATE OR REPLACE FUNCTION prevent_invalid_pr_merge()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'MERGED' AND OLD.state <> 'MERGED' THEN
        IF NEW.is_draft THEN
            RAISE EXCEPTION 'Draft Pull Request cannot be merged';
        END IF;

        IF NOT NEW.mergeable THEN
            RAISE EXCEPTION 'Pull Request has merge conflicts';
        END IF;

        IF NEW.unresolved_conversations > 0 THEN
            RAISE EXCEPTION 'Pull Request has unresolved conversations';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_pr_merge
BEFORE UPDATE OF state ON pull_request
FOR EACH ROW
EXECUTE FUNCTION prevent_invalid_pr_merge();

CREATE OR REPLACE FUNCTION evaluate_merge_eligibility(p_pr BIGINT)
RETURNS TABLE (
    eligible BOOLEAN,
    approval_count BIGINT,
    failed_checks BIGINT,
    unresolved_conversations INTEGER,
    reasons TEXT[]
)
LANGUAGE sql
AS $$
WITH pr AS (
    SELECT
        p.*,
        bp.protection_id,
        bp.required_approvals,
        bp.require_status_checks,
        bp.require_resolved_conversations
    FROM pull_request p
    LEFT JOIN branch_protection bp
        ON bp.branch_id = p.target_branch_id
    WHERE p.pull_request_id = p_pr
),
approvals AS (
    SELECT
        r.pull_request_id,
        COUNT(*) FILTER (
            WHERE r.state = 'APPROVED'
              AND rv.active
        ) AS approval_count
    FROM review r
    JOIN reviewer rv ON rv.reviewer_id = r.reviewer_id
    WHERE r.pull_request_id = p_pr
    GROUP BY r.pull_request_id
),
checks AS (
    SELECT
        p_pr AS pull_request_id,
        COUNT(*) FILTER (WHERE sc.state = 'FAILED') AS failed_checks,
        COUNT(*) FILTER (WHERE sc.state = 'PENDING') AS pending_checks
    FROM status_check sc
    WHERE sc.pull_request_id = p_pr
),
required_checks AS (
    SELECT
        COUNT(*) AS required_count,
        COUNT(*) FILTER (
            WHERE sc.state = 'PASSED'
        ) AS passed_required_count
    FROM pull_request p
    JOIN branch_protection bp
        ON bp.branch_id = p.target_branch_id
    JOIN required_status_check rsc
        ON rsc.protection_id = bp.protection_id
    LEFT JOIN status_check sc
        ON sc.pull_request_id = p.pull_request_id
       AND sc.name = rsc.check_name
    WHERE p.pull_request_id = p_pr
)
SELECT
    (
        pr.state = 'OPEN'
        AND NOT pr.is_draft
        AND pr.mergeable
        AND COALESCE(a.approval_count, 0) >= COALESCE(pr.required_approvals, 0)
        AND (
            NOT COALESCE(pr.require_status_checks, FALSE)
            OR (
                COALESCE(rc.required_count, 0) =
                COALESCE(rc.passed_required_count, 0)
            )
        )
        AND (
            NOT COALESCE(pr.require_resolved_conversations, FALSE)
            OR pr.unresolved_conversations = 0
        )
    ) AS eligible,
    COALESCE(a.approval_count, 0),
    COALESCE(c.failed_checks, 0),
    pr.unresolved_conversations,
    ARRAY_REMOVE(ARRAY[
        CASE WHEN pr.state <> 'OPEN'
            THEN 'Pull Request is not open' END,
        CASE WHEN pr.is_draft
            THEN 'Pull Request is a draft' END,
        CASE WHEN NOT pr.mergeable
            THEN 'Pull Request is not mergeable' END,
        CASE WHEN COALESCE(a.approval_count, 0) <
                  COALESCE(pr.required_approvals, 0)
            THEN 'Required approvals are missing' END,
        CASE WHEN COALESCE(c.failed_checks, 0) > 0
            THEN 'One or more status checks failed' END,
        CASE WHEN COALESCE(pr.require_resolved_conversations, FALSE)
                  AND pr.unresolved_conversations > 0
            THEN 'Unresolved conversations exist' END
    ], NULL)
FROM pr
LEFT JOIN approvals a ON a.pull_request_id = pr.pull_request_id
LEFT JOIN checks c ON c.pull_request_id = pr.pull_request_id
CROSS JOIN required_checks rc;
$$;

CREATE OR REPLACE PROCEDURE merge_pull_request(
    p_pr BIGINT,
    p_merged_by TEXT,
    p_method TEXT,
    p_merge_sha TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    decision RECORD;
BEGIN
    IF p_method NOT IN ('MERGE', 'SQUASH', 'REBASE') THEN
        RAISE EXCEPTION 'Unsupported merge method: %', p_method;
    END IF;

    SELECT *
    INTO decision
    FROM evaluate_merge_eligibility(p_pr);

    IF NOT decision.eligible THEN
        RAISE EXCEPTION 'Pull Request % is not eligible: %',
            p_pr, array_to_string(decision.reasons, '; ');
    END IF;

    UPDATE pull_request
    SET state = 'MERGED',
        merged_at = now()
    WHERE pull_request_id = p_pr
      AND state = 'OPEN';

    INSERT INTO merge_record (
        pull_request_id,
        merged_by,
        merge_method,
        merge_commit_sha
    )
    VALUES (
        p_pr,
        p_merged_by,
        p_method,
        p_merge_sha
    );
END;
$$;

INSERT INTO repository(name, owner_team)
VALUES ('payments-platform', 'platform-security');

INSERT INTO branch(repository_id, name, protected, head_commit)
SELECT repository_id, 'main', TRUE, 'main-001'
FROM repository
WHERE name = 'payments-platform';

INSERT INTO branch(repository_id, name, protected, head_commit)
SELECT repository_id, 'feature/release-signing', FALSE, 'feature-004'
FROM repository
WHERE name = 'payments-platform';

INSERT INTO commit_record(repository_id, sha, author, message)
SELECT repository_id, 'abc123', 'atul', 'Add release manifest'
FROM repository
WHERE name = 'payments-platform';

INSERT INTO commit_record(repository_id, sha, author, message)
SELECT repository_id, 'def456', 'atul', 'Add signature verification'
FROM repository
WHERE name = 'payments-platform';

INSERT INTO pull_request(
    repository_id,
    source_branch_id,
    target_branch_id,
    title,
    opened_by
)
SELECT
    r.repository_id,
    source.branch_id,
    target.branch_id,
    'Add signed production release manifest',
    'atul'
FROM repository r
JOIN branch source
    ON source.repository_id = r.repository_id
   AND source.name = 'feature/release-signing'
JOIN branch target
    ON target.repository_id = r.repository_id
   AND target.name = 'main'
WHERE r.name = 'payments-platform';

INSERT INTO pull_request_commit(pull_request_id, commit_id)
SELECT p.pull_request_id, c.commit_id
FROM pull_request p
JOIN commit_record c ON c.sha IN ('abc123', 'def456')
WHERE p.title = 'Add signed production release manifest';

INSERT INTO reviewer(username, team)
VALUES
    ('security-reviewer', 'security'),
    ('platform-reviewer', 'platform'),
    ('release-author', 'authors');

INSERT INTO review(pull_request_id, reviewer_id, state, body)
SELECT
    p.pull_request_id,
    r.reviewer_id,
    'APPROVED',
    CASE r.username
        WHEN 'security-reviewer' THEN 'Cryptographic design reviewed'
        WHEN 'platform-reviewer' THEN 'Deployment impact reviewed'
        ELSE 'Self approval is not counted by policy'
    END
FROM pull_request p
CROSS JOIN reviewer r
WHERE p.title = 'Add signed production release manifest';

UPDATE review
SET state = 'APPROVED'
WHERE reviewer_id = (
    SELECT reviewer_id
    FROM reviewer
    WHERE username = 'release-author'
);

INSERT INTO status_check(pull_request_id, name, state)
SELECT
    p.pull_request_id,
    checks.name,
    'PASSED'
FROM pull_request p
CROSS JOIN (
    VALUES
        ('unit-tests'),
        ('security-scan'),
        ('integration-tests')
) AS checks(name)
WHERE p.title = 'Add signed production release manifest';

INSERT INTO branch_protection(
    branch_id,
    required_approvals,
    require_status_checks,
    require_resolved_conversations,
    restrict_direct_push,
    restrict_force_push,
    restrict_branch_deletion,
    require_linear_history,
    allow_administrator_bypass
)
SELECT
    branch_id,
    2,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE
FROM branch
WHERE name = 'main';

INSERT INTO required_status_check(protection_id, check_name)
SELECT protection_id, check_name
FROM branch_protection
CROSS JOIN (
    VALUES
        ('unit-tests'),
        ('security-scan'),
        ('integration-tests')
) AS checks(check_name);

INSERT INTO approval_requirement(
    protection_id,
    team_name,
    minimum_approvals
)
SELECT protection_id, 'security', 1
FROM branch_protection;

INSERT INTO approval_requirement(
    protection_id,
    team_name,
    minimum_approvals
)
SELECT protection_id, 'platform', 1
FROM branch_protection;

CREATE VIEW pull_request_governance_report AS
SELECT
    p.pull_request_id,
    r.name AS repository,
    p.title,
    p.state,
    p.is_draft,
    p.mergeable,
    p.unresolved_conversations,
    COUNT(DISTINCT rv.review_id)
        FILTER (WHERE rv.state = 'APPROVED') AS approvals,
    COUNT(DISTINCT sc.status_check_id)
        FILTER (WHERE sc.state = 'FAILED') AS failed_checks
FROM pull_request p
JOIN repository r
    ON r.repository_id = p.repository_id
LEFT JOIN review rv
    ON rv.pull_request_id = p.pull_request_id
LEFT JOIN status_check sc
    ON sc.pull_request_id = p.pull_request_id
GROUP BY
    p.pull_request_id,
    r.name,
    p.title,
    p.state,
    p.is_draft,
    p.mergeable,
    p.unresolved_conversations;

-- Retrieval.
SELECT *
FROM pull_request_governance_report
ORDER BY pull_request_id;

-- Eligibility evaluation.
SELECT *
FROM evaluate_merge_eligibility(1);

-- CTE-based reviewer analysis.
WITH reviewer_activity AS (
    SELECT
        rv.team,
        COUNT(*) AS review_count,
        COUNT(*) FILTER (WHERE r.state = 'APPROVED') AS approvals
    FROM review r
    JOIN reviewer rv ON rv.reviewer_id = r.reviewer_id
    GROUP BY rv.team
)
SELECT *
FROM reviewer_activity
ORDER BY approvals DESC, team;

-- Validation of cryptographic key inventory.
SELECT
    repository_id,
    key_algorithm,
    key_usage,
    COUNT(*) AS active_keys
FROM repository_key
WHERE active
GROUP BY repository_id, key_algorithm, key_usage;

-- Transactional merge attempt. The procedure rejects the transaction if
-- any branch-protection condition is violated.
BEGIN;
CALL merge_pull_request(
    1,
    'release-manager',
    'SQUASH',
    'release-0042'
);
COMMIT;

-- Final workflow state.
SELECT
    p.pull_request_id,
    p.state,
    m.merged_by,
    m.merge_method,
    m.merge_commit_sha
FROM pull_request p
LEFT JOIN merge_record m
    ON m.pull_request_id = p.pull_request_id
ORDER BY p.pull_request_id;
