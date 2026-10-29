DROP SCHEMA IF EXISTS host_firewall CASCADE;
CREATE SCHEMA host_firewall;

SET search_path = host_firewall, public;

CREATE TYPE direction AS ENUM ('inbound', 'outbound');
CREATE TYPE protocol AS ENUM ('tcp', 'udp', 'icmp', 'any');
CREATE TYPE firewall_action AS ENUM ('allow', 'deny');
CREATE TYPE rule_log_level AS ENUM ('none', 'denied', 'all');
CREATE TYPE pr_status AS ENUM ('draft', 'open', 'closed', 'merged');

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    owner_name TEXT NOT NULL,
    UNIQUE (owner_name, name)
);

CREATE TABLE hosts (
    host_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    hostname TEXT NOT NULL,
    ipv4 INET NOT NULL,
    operating_system TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (repository_id, hostname),
    UNIQUE (ipv4)
);

CREATE TABLE applications (
    application_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    executable_path TEXT NOT NULL,
    trusted BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (host_id, name)
);

CREATE TABLE firewall_rules (
    rule_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    direction direction NOT NULL,
    action firewall_action NOT NULL,
    protocol protocol NOT NULL DEFAULT 'any',
    source_network CIDR NOT NULL DEFAULT '0.0.0.0/0',
    destination_network CIDR NOT NULL DEFAULT '0.0.0.0/0',
    destination_port INTEGER,
    application_pattern TEXT NOT NULL DEFAULT '*',
    priority INTEGER NOT NULL CHECK (priority > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    log_level rule_log_level NOT NULL DEFAULT 'denied',
    description TEXT NOT NULL,
    UNIQUE (host_id, rule_name),
    CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535)
);

CREATE INDEX idx_firewall_rules_host_priority
    ON firewall_rules (host_id, priority)
    WHERE enabled = TRUE;

CREATE TABLE firewall_connections (
    connection_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    direction direction NOT NULL,
    protocol protocol NOT NULL,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    application_id BIGINT REFERENCES applications(application_id),
    username TEXT,
    CHECK (source_port IS NULL OR source_port BETWEEN 1 AND 65535),
    CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535)
);

CREATE INDEX idx_connections_host_time
    ON firewall_connections (host_id, occurred_at DESC);

CREATE TABLE firewall_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    connection_id BIGINT NOT NULL REFERENCES firewall_connections(connection_id)
        ON DELETE CASCADE,
    rule_id BIGINT REFERENCES firewall_rules(rule_id),
    action firewall_action NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL,
    logged BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_decisions_action_time
    ON firewall_decisions (action, decided_at DESC);

CREATE TABLE branch_protection_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    policy_name TEXT NOT NULL,
    protected_branch TEXT NOT NULL,
    require_status_checks BOOLEAN NOT NULL DEFAULT TRUE,
    require_reviews BOOLEAN NOT NULL DEFAULT TRUE,
    required_reviews INTEGER NOT NULL DEFAULT 1
        CHECK (required_reviews >= 0),
    allow_direct_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_force_push BOOLEAN NOT NULL DEFAULT FALSE,
    allow_branch_deletion BOOLEAN NOT NULL DEFAULT FALSE,
    require_conversation_resolution BOOLEAN NOT NULL DEFAULT TRUE,
    require_linear_history BOOLEAN NOT NULL DEFAULT FALSE,
    allow_administrator_bypass BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (repository_id, protected_branch)
);

CREATE TABLE status_checks (
    check_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (repository_id, check_name)
);

CREATE TABLE pull_requests (
    pull_request_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    title TEXT NOT NULL,
    source_branch TEXT NOT NULL,
    target_branch TEXT NOT NULL,
    status pr_status NOT NULL DEFAULT 'open',
    source_commit TEXT NOT NULL,
    base_commit TEXT NOT NULL,
    draft BOOLEAN NOT NULL DEFAULT FALSE,
    merge_commit TEXT,
    opened_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    closed_at TIMESTAMPTZ,
    CHECK (source_branch <> target_branch)
);

CREATE INDEX idx_pull_requests_repository_target
    ON pull_requests (repository_id, target_branch, status);

CREATE TABLE pull_request_statuses (
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    check_id BIGINT NOT NULL REFERENCES status_checks(check_id)
        ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'success', 'failure')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (pull_request_id, check_id)
);

CREATE TABLE reviewers (
    reviewer_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE review_policies (
    policy_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES reviewers(reviewer_id),
    eligible BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (repository_id, reviewer_id)
);

CREATE TABLE reviews (
    review_id BIGSERIAL PRIMARY KEY,
    pull_request_id BIGINT NOT NULL REFERENCES pull_requests(pull_request_id)
        ON DELETE CASCADE,
    reviewer_id BIGINT NOT NULL REFERENCES reviewers(reviewer_id),
    state TEXT NOT NULL CHECK (
        state IN ('commented', 'approved', 'changes_requested', 'dismissed')
    ),
    commit_sha TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    dismissed_at TIMESTAMPTZ
);

CREATE INDEX idx_reviews_pr_state
    ON reviews (pull_request_id, state);

CREATE TABLE review_comments (
    comment_id BIGSERIAL PRIMARY KEY,
    review_id BIGINT NOT NULL REFERENCES reviews(review_id)
        ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_number INTEGER CHECK (line_number > 0),
    body TEXT NOT NULL,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX idx_review_comments_unresolved
    ON review_comments (review_id)
    WHERE resolved = FALSE;

CREATE OR REPLACE FUNCTION prevent_invalid_review()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = 'approved' AND NEW.commit_sha IS NULL THEN
        RAISE EXCEPTION 'An approval must reference a commit';
    END IF;

    IF NEW.state = 'dismissed' AND NEW.dismissed_at IS NULL THEN
        NEW.dismissed_at := clock_timestamp();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_review
BEFORE INSERT OR UPDATE ON reviews
FOR EACH ROW
EXECUTE FUNCTION prevent_invalid_review();

CREATE OR REPLACE FUNCTION evaluate_pull_request(p_pr_id BIGINT)
RETURNS TABLE (
    eligible BOOLEAN,
    reason TEXT,
    approval_count BIGINT,
    unresolved_comments BIGINT,
    failed_required_checks BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_repository BIGINT;
    v_target TEXT;
    v_required_reviews INTEGER;
    v_require_checks BOOLEAN;
    v_require_conversations BOOLEAN;
    v_draft BOOLEAN;
    v_status pr_status;
BEGIN
    SELECT
        pr.repository_id,
        pr.target_branch,
        pr.draft,
        pr.status,
        bp.required_reviews,
        bp.require_status_checks,
        bp.require_conversation_resolution
    INTO
        v_repository,
        v_target,
        v_draft,
        v_status,
        v_required_reviews,
        v_require_checks,
        v_require_conversations
    FROM pull_requests pr
    LEFT JOIN branch_protection_policies bp
      ON bp.repository_id = pr.repository_id
     AND bp.protected_branch = pr.target_branch
    WHERE pr.pull_request_id = p_pr_id;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT FALSE, 'Pull Request does not exist', 0::BIGINT, 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_status <> 'open' THEN
        RETURN QUERY
        SELECT FALSE, 'Pull Request is not open', 0::BIGINT, 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    IF v_draft THEN
        RETURN QUERY
        SELECT FALSE, 'Draft Pull Request cannot be merged', 0::BIGINT, 0::BIGINT, 0::BIGINT;
        RETURN;
    END IF;

    SELECT
        COUNT(DISTINCT r.reviewer_id)
    INTO approval_count
    FROM reviews r
    JOIN review_policies rp
      ON rp.reviewer_id = r.reviewer_id
     AND rp.repository_id = v_repository
     AND rp.eligible = TRUE
    WHERE r.pull_request_id = p_pr_id
      AND r.state = 'approved'
      AND r.dismissed_at IS NULL
      AND r.commit_sha = (
          SELECT source_commit
          FROM pull_requests
          WHERE pull_request_id = p_pr_id
      );

    SELECT COUNT(*)
    INTO unresolved_comments
    FROM review_comments rc
    JOIN reviews r ON r.review_id = rc.review_id
    WHERE r.pull_request_id = p_pr_id
      AND rc.resolved = FALSE;

    SELECT COUNT(*)
    INTO failed_required_checks
    FROM pull_request_statuses prs
    JOIN status_checks sc ON sc.check_id = prs.check_id
    WHERE prs.pull_request_id = p_pr_id
      AND sc.required = TRUE
      AND prs.status <> 'success';

    IF COALESCE(v_require_checks, FALSE)
       AND failed_required_checks > 0 THEN
        eligible := FALSE;
        reason := 'Required status checks are not successful';
    ELSIF COALESCE(v_require_conversations, FALSE)
          AND unresolved_comments > 0 THEN
        eligible := FALSE;
        reason := 'Unresolved review conversations remain';
    ELSIF COALESCE(v_required_reviews, 0) > approval_count THEN
        eligible := FALSE;
        reason := 'Required approvals are missing';
    ELSE
        eligible := TRUE;
        reason := 'All applicable merge conditions are satisfied';
    END IF;

    RETURN NEXT;
END;
$$;

CREATE OR REPLACE VIEW merge_eligibility_report AS
SELECT
    pr.pull_request_id,
    r.owner_name || '/' || r.name AS repository,
    pr.title,
    pr.source_branch,
    pr.target_branch,
    pr.status,
    result.eligible,
    result.reason,
    result.approval_count,
    result.unresolved_comments,
    result.failed_required_checks
FROM pull_requests pr
JOIN repositories r ON r.repository_id = pr.repository_id
CROSS JOIN LATERAL evaluate_pull_request(pr.pull_request_id) result;

BEGIN;

INSERT INTO repositories (name, owner_name)
VALUES ('secure-host-platform', 'security-team');

INSERT INTO hosts (
    repository_id,
    hostname,
    ipv4,
    operating_system
)
SELECT repository_id, 'workstation-01', '10.20.0.10', 'Linux'
FROM repositories
WHERE owner_name = 'security-team'
  AND name = 'secure-host-platform';

INSERT INTO applications (
    host_id,
    name,
    executable_path,
    trusted
)
SELECT h.host_id, data.name, data.path, data.trusted
FROM hosts h
CROSS JOIN (
    VALUES
        ('sshd', '/usr/sbin/sshd', TRUE),
        ('resolver', '/usr/bin/resolver', TRUE),
        ('browser', '/usr/bin/browser', TRUE),
        ('unknown', '/tmp/unknown', FALSE)
) AS data(name, path, trusted)
WHERE h.hostname = 'workstation-01';

INSERT INTO firewall_rules (
    host_id,
    rule_name,
    direction,
    action,
    protocol,
    source_network,
    destination_network,
    destination_port,
    application_pattern,
    priority,
    log_level,
    description
)
SELECT
    h.host_id,
    data.rule_name,
    data.direction::direction,
    data.action::firewall_action,
    data.protocol::protocol,
    data.source_network::CIDR,
    data.destination_network::CIDR,
    data.destination_port,
    data.application_pattern,
    data.priority,
    data.log_level::rule_log_level,
    data.description
FROM hosts h
CROSS JOIN (
    VALUES
    (
        'ALLOW-SSH-MGMT',
        'inbound',
        'allow',
        'tcp',
        '10.20.0.0/24',
        '10.20.0.10/32',
        22,
        'sshd',
        10,
        'all',
        'Administrative SSH from management network'
    ),
    (
        'DENY-INBOUND-APP',
        'inbound',
        'deny',
        'tcp',
        '0.0.0.0/0',
        '0.0.0.0/0',
        8080,
        '*',
        20,
        'denied',
        'Unapproved inbound application service'
    ),
    (
        'ALLOW-DNS',
        'outbound',
        'allow',
        'udp',
        '10.20.0.10/32',
        '10.20.0.53/32',
        53,
        'resolver',
        30,
        'all',
        'Approved DNS resolver'
    ),
    (
        'ALLOW-HTTPS',
        'outbound',
        'allow',
        'tcp',
        '10.20.0.10/32',
        '0.0.0.0/0',
        443,
        'browser%',
        40,
        'all',
        'Approved browser HTTPS traffic'
    ),
    (
        'DENY-UNKNOWN-OUTBOUND',
        'outbound',
        'deny',
        'any',
        '0.0.0.0/0',
        '0.0.0.0/0',
        NULL,
        '*',
        90,
        'denied',
        'Outbound traffic without an explicit allow rule'
    )
) AS data(
    rule_name,
    direction,
    action,
    protocol,
    source_network,
    destination_network,
    destination_port,
    application_pattern,
    priority,
    log_level,
    description
)
WHERE h.hostname = 'workstation-01';

INSERT INTO branch_protection_policies (
    repository_id,
    policy_name,
    protected_branch,
    require_status_checks,
    require_reviews,
    required_reviews,
    allow_direct_push,
    allow_force_push,
    allow_branch_deletion,
    require_conversation_resolution,
    require_linear_history,
    allow_administrator_bypass
)
SELECT
    repository_id,
    'main-protection',
    'main',
    TRUE,
    TRUE,
    2,
    FALSE,
    FALSE,
    FALSE,
    TRUE,
    TRUE,
    FALSE
FROM repositories
WHERE name = 'secure-host-platform';

INSERT INTO status_checks (repository_id, check_name, required)
SELECT repository_id, check_name, TRUE
FROM repositories
CROSS JOIN (
    VALUES ('unit-tests'), ('firewall-policy-validation')
) AS checks(check_name)
WHERE name = 'secure-host-platform';

INSERT INTO reviewers (username)
VALUES ('reviewer-alpha'), ('reviewer-beta');

INSERT INTO review_policies (repository_id, reviewer_id, eligible)
SELECT r.repository_id, rv.reviewer_id, TRUE
FROM repositories r
CROSS JOIN reviewers rv
WHERE r.name = 'secure-host-platform';

INSERT INTO pull_requests (
    repository_id,
    title,
    source_branch,
    target_branch,
    status,
    source_commit,
    base_commit,
    draft
)
SELECT
    repository_id,
    'Restrict workstation network egress',
    'feature/egress-policy',
    'main',
    'open',
    'abc123',
    'base001',
    FALSE
FROM repositories
WHERE name = 'secure-host-platform';

INSERT INTO pull_request_statuses (pull_request_id, check_id, status)
SELECT pr.pull_request_id, sc.check_id, 'success'
FROM pull_requests pr
JOIN status_checks sc
  ON sc.repository_id = pr.repository_id;

INSERT INTO reviews (
    pull_request_id,
    reviewer_id,
    state,
    commit_sha
)
SELECT
    pr.pull_request_id,
    rv.reviewer_id,
    'approved',
    'abc123'
FROM pull_requests pr
JOIN reviewers rv
  ON rv.username IN ('reviewer-alpha', 'reviewer-beta');

COMMIT;

-- Connection-level firewall decisions can be generated from actual traffic.
WITH traffic AS (
    SELECT
        fc.connection_id,
        fc.direction,
        fc.protocol,
        fc.source_ip,
        fc.destination_ip,
        fc.destination_port,
        a.name AS application,
        fr.rule_id,
        fr.action,
        fr.description,
        fr.priority,
        ROW_NUMBER() OVER (
            PARTITION BY fc.connection_id
            ORDER BY fr.priority
        ) AS rule_order
    FROM firewall_connections fc
    LEFT JOIN applications a
      ON a.application_id = fc.application_id
    JOIN firewall_rules fr
      ON fr.host_id = fc.host_id
     AND fr.enabled = TRUE
     AND fr.direction = fc.direction
     AND (fr.protocol = 'any' OR fr.protocol = fc.protocol)
     AND fc.source_ip <<= fr.source_network
     AND fc.destination_ip <<= fr.destination_network
     AND (
         fr.destination_port IS NULL
         OR fr.destination_port = fc.destination_port
     )
)
SELECT *
FROM traffic
WHERE rule_order = 1
ORDER BY connection_id;

-- Example operational report.
SELECT *
FROM merge_eligibility_report
ORDER BY pull_request_id;

-- Example approval validation: approvals tied to an older commit are stale.
SELECT
    pr.pull_request_id,
    rv.username,
    rvw.commit_sha,
    pr.source_commit,
    (rvw.commit_sha = pr.source_commit) AS approval_is_current
FROM pull_requests pr
JOIN reviews rvw
  ON rvw.pull_request_id = pr.pull_request_id
JOIN reviewers rv
  ON rv.reviewer_id = rvw.reviewer_id
WHERE rvw.state = 'approved'
  AND rvw.dismissed_at IS NULL;

-- Example aggregation of denied host traffic.
SELECT
    h.hostname,
    COUNT(*) AS denied_events,
    MIN(fd.decided_at) AS first_denial,
    MAX(fd.decided_at) AS last_denial
FROM firewall_decisions fd
JOIN firewall_connections fc
  ON fc.connection_id = fd.connection_id
JOIN hosts h
  ON h.host_id = fc.host_id
WHERE fd.action = 'deny'
GROUP BY h.hostname
ORDER BY denied_events DESC;

-- Transactional example: record one connection and its selected decision atomically.
BEGIN;

WITH inserted_connection AS (
    INSERT INTO firewall_connections (
        host_id,
        direction,
        protocol,
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        application_id,
        username
    )
    SELECT
        h.host_id,
        'outbound',
        'tcp',
        '10.20.0.10',
        '198.51.100.20',
        52000,
        443,
        a.application_id,
        'operator'
    FROM hosts h
    JOIN applications a
      ON a.host_id = h.host_id
     AND a.name = 'browser'
    WHERE h.hostname = 'workstation-01'
    RETURNING *
)
INSERT INTO firewall_decisions (
    connection_id,
    rule_id,
    action,
    reason,
    logged
)
SELECT
    ic.connection_id,
    fr.rule_id,
    fr.action,
    fr.description,
    fr.log_level IN ('all', 'denied')
FROM inserted_connection ic
JOIN firewall_rules fr
  ON fr.host_id = ic.host_id
 AND fr.enabled
 AND fr.direction = ic.direction
 AND (fr.protocol = 'any' OR fr.protocol = ic.protocol)
 AND ic.source_ip <<= fr.source_network
 AND ic.destination_ip <<= fr.destination_network
 AND (
     fr.destination_port IS NULL
     OR fr.destination_port = ic.destination_port
 )
ORDER BY fr.priority
LIMIT 1;

COMMIT;
