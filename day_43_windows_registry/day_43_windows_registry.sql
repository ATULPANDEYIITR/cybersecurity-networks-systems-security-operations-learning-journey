-- PostgreSQL 14+
-- Repository governance: pull requests, code reviews, approvals, and branch protection.
-- Run in a disposable learning database because the script recreates its schema.

BEGIN;

DROP SCHEMA IF EXISTS repository_governance CASCADE;
CREATE SCHEMA repository_governance;
SET search_path TO repository_governance, public;

CREATE TYPE request_state AS ENUM ('draft', 'open', 'closed', 'merged');
CREATE TYPE review_state AS ENUM ('approved', 'changes_requested', 'commented');
CREATE TYPE check_state AS ENUM ('pending', 'success', 'failure');
CREATE TYPE merge_method AS ENUM ('merge_commit', 'squash', 'rebase');

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    owner_name TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_name, repository_name),
    CHECK (length(trim(owner_name)) > 0),
    CHECK (length(trim(repository_name)) > 0)
);

CREATE TABLE repository_users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    is_administrator BOOLEAN NOT NULL DEFAULT FALSE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (length(trim(username)) > 0)
);

CREATE TABLE branches (
    branch_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    branch_name TEXT NOT NULL,
    head_sha CHAR(40),
    revision BIGINT NOT NULL DEFAULT 1,
    deleted_at TIMESTAMPTZ,
    UNIQUE (repository_id, branch_name),
    CHECK (revision > 0),
    CHECK (head_sha IS NULL OR head_sha ~ '^[0-9a-fA-F]{40}$')
);

CREATE TABLE branch_protection (
    protection_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_id BIGINT NOT NULL UNIQUE REFERENCES branches(branch_id)
        ON DELETE CASCADE,
    required_approvals INTEGER NOT NULL DEFAULT 1,
    require_resolved_discussions BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    restrict_direct_push BOOLEAN NOT NULL DEFAULT TRUE,
    prohibit_force_push BOOLEAN NOT NULL DEFAULT TRUE,
    prohibit_deletion BOOLEAN NOT NULL DEFAULT TRUE,
    administrators_must_comply BOOLEAN NOT NULL DEFAULT TRUE,
    allow_merge_commit BOOLEAN NOT NULL DEFAULT TRUE,
    allow_squash BOOLEAN NOT NULL DEFAULT TRUE,
    allow_rebase BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (required_approvals >= 0),
    CHECK (allow_merge_commit OR allow_squash OR allow_rebase)
);

CREATE TABLE protected_required_checks (
    protection_id BIGINT NOT NULL REFERENCES branch_protection(protection_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    PRIMARY KEY (protection_id, check_name),
    CHECK (length(trim(check_name)) > 0)
);

CREATE TABLE pull_requests (
    pull_request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    source_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    target_branch_id BIGINT NOT NULL REFERENCES branches(branch_id),
    author_id BIGINT NOT NULL REFERENCES repository_users(user_id),
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state request_state NOT NULL DEFAULT 'open',
    is_draft BOOLEAN NOT NULL DEFAULT FALSE,
    merge_conflict BOOLEAN NOT NULL DEFAULT FALSE,
    source_revision BIGINT NOT NULL DEFAULT 1,
    target_revision_at_review BIGINT,
    merge_strategy merge_method,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ,
    merged_at TIMESTAMPTZ,
    CHECK (source_branch_id <> target_branch_id),
    CHECK (length(trim(title)) > 0),
    CHECK (source_revision > 0),
    CHECK (
        (state = 'merged' AND merged_at IS NOT NULL)
        OR (state <> 'merged' AND merged_at IS NULL)
    ),
    CHECK (state <> 'merged' OR merge_strategy IS NOT NULL)
);

CREATE TABLE commits (
    commit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_id BIGINT NOT NULL REFERENCES branches(branch_id) ON DELETE CASCADE,
    commit_sha CHAR(40) NOT NULL,
    message TEXT NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (branch_id, commit_sha),
    CHECK (commit_sha ~ '^[0-9a-fA-F]{40}$'),
    CHECK (length(trim(message)) > 0)
);

CREATE TABLE pull_request_commits (
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    commit_id BIGINT NOT NULL REFERENCES commits(commit_id),
    sequence_number INTEGER NOT NULL,
    PRIMARY KEY (pull_request_id, commit_id),
    UNIQUE (pull_request_id, sequence_number),
    CHECK (sequence_number > 0)
);

CREATE TABLE reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES repository_users(user_id),
    reviewed_head_sha CHAR(40) NOT NULL,
    state review_state NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    dismissed_at TIMESTAMPTZ,
    dismissal_reason TEXT,
    UNIQUE (review_id, pull_request_id),
    CHECK (reviewed_head_sha ~ '^[0-9a-fA-F]{40}$'),
    CHECK (dismissed_at IS NULL OR dismissal_reason IS NOT NULL)
);

CREATE TABLE review_comments (
    comment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES reviews(review_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER,
    comment_body TEXT NOT NULL,
    is_inline BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(trim(file_path)) > 0),
    CHECK (line_number IS NULL OR line_number > 0),
    CHECK (length(trim(comment_body)) > 0)
);

CREATE TABLE review_discussions (
    discussion_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    comment_id BIGINT REFERENCES review_comments(comment_id) ON DELETE SET NULL,
    opened_by BIGINT NOT NULL REFERENCES repository_users(user_id),
    resolved_by BIGINT REFERENCES repository_users(user_id),
    resolved_at TIMESTAMPTZ,
    CHECK (
        (resolved_at IS NULL AND resolved_by IS NULL)
        OR (resolved_at IS NOT NULL AND resolved_by IS NOT NULL)
    )
);

CREATE TABLE status_checks (
    status_check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    head_sha CHAR(40) NOT NULL,
    state check_state NOT NULL DEFAULT 'pending',
    completed_at TIMESTAMPTZ,
    UNIQUE (pull_request_id, check_name, head_sha),
    CHECK (length(trim(check_name)) > 0),
    CHECK (head_sha ~ '^[0-9a-fA-F]{40}$'),
    CHECK (
        (state = 'pending' AND completed_at IS NULL)
        OR (state <> 'pending' AND completed_at IS NOT NULL)
    )
);

CREATE TABLE merge_events (
    merge_event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pull_request_id BIGINT NOT NULL UNIQUE
        REFERENCES pull_requests(pull_request_id),
    merged_by BIGINT NOT NULL REFERENCES repository_users(user_id),
    strategy merge_method NOT NULL,
    merge_sha CHAR(40) NOT NULL,
    merged_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (merge_sha ~ '^[0-9a-fA-F]{40}$')
);

CREATE TABLE governance_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    actor_id BIGINT REFERENCES repository_users(user_id),
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied')),
    justification TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pull_requests_target_state
    ON pull_requests(target_branch_id, state);

CREATE INDEX idx_reviews_current_candidates
    ON reviews(pull_request_id, reviewer_id)
    WHERE dismissed_at IS NULL;

CREATE INDEX idx_status_checks_by_request_head
    ON status_checks(pull_request_id, head_sha, check_name);

CREATE INDEX idx_open_discussions
    ON review_discussions(pull_request_id)
    WHERE resolved_at IS NULL;

CREATE INDEX idx_audit_repository_time
    ON governance_audit(repository_id, occurred_at DESC);

-- A review can be recorded only by a user other than the author.
CREATE FUNCTION prevent_self_review()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    request_author BIGINT;
BEGIN
    SELECT author_id INTO request_author
    FROM pull_requests
    WHERE pull_request_id = NEW.pull_request_id;

    IF request_author IS NULL THEN
        RAISE EXCEPTION 'Pull request does not exist';
    END IF;

    IF request_author = NEW.reviewer_id THEN
        RAISE EXCEPTION 'Authors cannot review their own pull requests';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_prevent_self_review
BEFORE INSERT OR UPDATE ON reviews
FOR EACH ROW EXECUTE FUNCTION prevent_self_review();

-- A closed discussion remains part of the record; resolving it does not erase history.
CREATE FUNCTION resolve_discussion(
    p_discussion_id BIGINT,
    p_resolver_id BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE review_discussions
    SET resolved_by = p_resolver_id,
        resolved_at = now()
    WHERE discussion_id = p_discussion_id
      AND resolved_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Discussion not found or already resolved';
    END IF;
END;
$$;

-- Seed a repository, users, and branches.
INSERT INTO repositories(owner_name, repository_name, default_branch)
VALUES ('ExampleEngineering', 'registry-security-agent', 'main');

INSERT INTO repository_users(username, is_administrator)
VALUES
    ('developer-asha', FALSE),
    ('reviewer-ravi', FALSE),
    ('reviewer-meera', FALSE),
    ('release-admin', TRUE);

INSERT INTO branches(repository_id, branch_name, head_sha)
SELECT repository_id, 'main', repeat('a', 40)
FROM repositories;

INSERT INTO branches(repository_id, branch_name, head_sha)
SELECT repository_id, 'feature/registry-audit', repeat('b', 40)
FROM repositories;

INSERT INTO branch_protection(
    branch_id, required_approvals, require_resolved_discussions,
    require_linear_history, restrict_direct_push, prohibit_force_push,
    prohibit_deletion, administrators_must_comply,
    allow_merge_commit, allow_squash, allow_rebase
)
SELECT branch_id, 2, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, FALSE, TRUE, TRUE
FROM branches
WHERE branch_name = 'main';

INSERT INTO protected_required_checks(protection_id, check_name)
SELECT protection_id, 'unit-tests'
FROM branch_protection;

INSERT INTO protected_required_checks(protection_id, check_name)
SELECT protection_id, 'security-scan'
FROM branch_protection;

INSERT INTO commits(branch_id, commit_sha, message)
SELECT branch_id, repeat('b', 40), 'Add registry configuration audit'
FROM branches
WHERE branch_name = 'feature/registry-audit';

INSERT INTO pull_requests(
    repository_id, source_branch_id, target_branch_id, author_id,
    title, description, state, is_draft, source_revision, target_revision_at_review
)
SELECT r.repository_id, source.branch_id, target.branch_id, author.user_id,
       'Add registry configuration audit',
       'Validate typed settings and record security-relevant changes.',
       'open', FALSE, 1, target.revision
FROM repositories r
JOIN branches source ON source.repository_id = r.repository_id
    AND source.branch_name = 'feature/registry-audit'
JOIN branches target ON target.repository_id = r.repository_id
    AND target.branch_name = 'main'
JOIN repository_users author ON author.username = 'developer-asha';

INSERT INTO pull_request_commits(pull_request_id, commit_id, sequence_number)
SELECT pr.pull_request_id, c.commit_id, 1
FROM pull_requests pr
JOIN branches b ON b.branch_id = pr.source_branch_id
JOIN commits c ON c.branch_id = b.branch_id
WHERE pr.title = 'Add registry configuration audit';

INSERT INTO reviews(
    pull_request_id, reviewer_id, reviewed_head_sha, state, body
)
SELECT pr.pull_request_id, reviewer.user_id, repeat('b', 40),
       'approved', 'Configuration validation and access boundaries reviewed.'
FROM pull_requests pr
CROSS JOIN repository_users reviewer
WHERE reviewer.username IN ('reviewer-ravi', 'reviewer-meera');

INSERT INTO review_comments(review_id, file_path, line_number, comment_body)
SELECT review_id, 'registry/configuration.py', 48,
       'Confirm the registry view used on 64-bit Windows.'
FROM reviews
WHERE state = 'approved'
ORDER BY review_id
LIMIT 1;

INSERT INTO review_discussions(pull_request_id, comment_id, opened_by)
SELECT pr.pull_request_id, rc.comment_id, reviewer.user_id
FROM pull_requests pr
JOIN review_comments rc ON rc.file_path = 'registry/configuration.py'
JOIN repository_users reviewer ON reviewer.username = 'reviewer-ravi';

INSERT INTO status_checks(
    pull_request_id, check_name, head_sha, state, completed_at
)
SELECT pr.pull_request_id, required.check_name, repeat('b', 40),
       'success', now()
FROM pull_requests pr
JOIN branch_protection bp ON bp.branch_id = pr.target_branch_id
JOIN protected_required_checks required ON required.protection_id = bp.protection_id;

-- Current-head approvals exclude dismissed reviews and reviews of older commits.
CREATE VIEW current_approval_counts AS
SELECT
    pr.pull_request_id,
    COUNT(DISTINCT rv.reviewer_id) FILTER (
        WHERE rv.state = 'approved'
          AND rv.dismissed_at IS NULL
          AND rv.reviewed_head_sha = latest.commit_sha
    ) AS approval_count,
    BOOL_OR(
        rv.state = 'changes_requested'
        AND rv.dismissed_at IS NULL
        AND rv.reviewed_head_sha = latest.commit_sha
    ) AS has_changes_requested
FROM pull_requests pr
LEFT JOIN LATERAL (
    SELECT c.commit_sha
    FROM pull_request_commits pc
    JOIN commits c ON c.commit_id = pc.commit_id
    WHERE pc.pull_request_id = pr.pull_request_id
    ORDER BY pc.sequence_number DESC
    LIMIT 1
) latest ON TRUE
LEFT JOIN reviews rv ON rv.pull_request_id = pr.pull_request_id
GROUP BY pr.pull_request_id;

-- This view reports eligibility; it does not perform a merge or replace API-side
-- authorization. Production merge operations must lock rows and recheck policy.
CREATE VIEW merge_eligibility AS
SELECT
    pr.pull_request_id,
    repo.repository_name,
    target.branch_name AS target_branch,
    pr.state,
    COALESCE(approvals.approval_count, 0) AS approval_count,
    bp.required_approvals,
    COALESCE(approvals.has_changes_requested, FALSE) AS has_changes_requested,
    pr.merge_conflict,
    (
        pr.state = 'open'
        AND NOT pr.is_draft
        AND NOT pr.merge_conflict
        AND COALESCE(approvals.approval_count, 0) >= bp.required_approvals
        AND NOT COALESCE(approvals.has_changes_requested, FALSE)
        AND NOT (
            bp.require_resolved_discussions
            AND EXISTS (
                SELECT 1
                FROM review_discussions d
                WHERE d.pull_request_id = pr.pull_request_id
                  AND d.resolved_at IS NULL
            )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM protected_required_checks required
            WHERE required.protection_id = bp.protection_id
              AND NOT EXISTS (
                  SELECT 1
                  FROM status_checks sc
                  WHERE sc.pull_request_id = pr.pull_request_id
                    AND sc.check_name = required.check_name
                    AND sc.head_sha = (
                        SELECT c.commit_sha
                        FROM pull_request_commits pc
                        JOIN commits c ON c.commit_id = pc.commit_id
                        WHERE pc.pull_request_id = pr.pull_request_id
                        ORDER BY pc.sequence_number DESC
                        LIMIT 1
                    )
                    AND sc.state = 'success'
              )
        )
    ) AS eligible_before_strategy_check
FROM pull_requests pr
JOIN repositories repo ON repo.repository_id = pr.repository_id
JOIN branches target ON target.branch_id = pr.target_branch_id
JOIN branch_protection bp ON bp.branch_id = target.branch_id
LEFT JOIN current_approval_counts approvals
    ON approvals.pull_request_id = pr.pull_request_id;

-- Inspect policy results before performing any merge.
SELECT * FROM merge_eligibility;

-- Direct pushes are denied unless an explicit, audited bypass applies.
INSERT INTO governance_audit(
    repository_id, actor_id, action, target, outcome, justification
)
SELECT repo.repository_id, actor.user_id, 'direct_push', 'refs/heads/main',
       'denied', 'Protected branches accept changes through reviewed pull requests.'
FROM repositories repo
JOIN repository_users actor ON actor.username = 'developer-asha';

-- Resolve the review discussion while retaining its original history.
SELECT resolve_discussion(d.discussion_id, resolver.user_id)
FROM review_discussions d
JOIN pull_requests pr ON pr.pull_request_id = d.pull_request_id
JOIN repository_users resolver ON resolver.username = 'reviewer-ravi'
WHERE pr.title = 'Add registry configuration audit'
  AND d.resolved_at IS NULL;

SELECT pull_request_id, eligible_before_strategy_check
FROM merge_eligibility;

-- Demonstrate stale approval invalidation when the target branch advances.
UPDATE branches
SET revision = revision + 1,
    head_sha = repeat('c', 40)
WHERE branch_name = 'main';

UPDATE pull_requests pr
SET target_revision_at_review = NULL
FROM branches target
WHERE pr.target_branch_id = target.branch_id
  AND target.branch_name = 'main'
  AND target.revision > COALESCE(pr.target_revision_at_review, 0);

-- Explicitly dismiss old approvals after a changeset update.
UPDATE reviews
SET dismissed_at = now(),
    dismissal_reason = 'Target branch advanced; fresh review required.'
WHERE pull_request_id = (
    SELECT pull_request_id
    FROM pull_requests
    WHERE title = 'Add registry configuration audit'
)
AND dismissed_at IS NULL;

SELECT * FROM current_approval_counts;

-- Example negative test: self-review must raise an exception.
-- Execute independently when testing the trigger:
-- INSERT INTO reviews(pull_request_id, reviewer_id, reviewed_head_sha, state)
-- SELECT pr.pull_request_id, pr.author_id, repeat('b', 40), 'approved'
-- FROM pull_requests pr WHERE pr.title = 'Add registry configuration audit';

COMMIT;
