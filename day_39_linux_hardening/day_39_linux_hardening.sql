-- Linux hardening governance laboratory
-- PostgreSQL 15+ compatible.
--
-- The database records assessed evidence and remediation state. It does not
-- execute privileged host changes. Run in a disposable training database.
--
-- The transaction resets this example schema so the script is repeatable.

BEGIN;

DROP SCHEMA IF EXISTS linux_hardening CASCADE;
CREATE SCHEMA linux_hardening;
SET LOCAL search_path = linux_hardening, public;

CREATE TYPE control_family AS ENUM (
    'account_security',
    'ssh_hardening',
    'firewalling',
    'patching',
    'auditing'
);

CREATE TYPE finding_severity AS ENUM (
    'critical', 'high', 'medium', 'low', 'info'
);

CREATE TYPE remediation_status AS ENUM (
    'open', 'accepted', 'deferred', 'resolved', 'not_applicable'
);

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    environment TEXT NOT NULL CHECK (
        environment IN ('development', 'staging', 'production')
    ),
    distribution TEXT NOT NULL CHECK (btrim(distribution) <> ''),
    distribution_version TEXT NOT NULL,
    owner_team TEXT NOT NULL CHECK (btrim(owner_team) <> ''),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE assessments (
    assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    assessor TEXT NOT NULL CHECK (btrim(assessor) <> ''),
    scanner_version TEXT NOT NULL,
    scope TEXT NOT NULL CHECK (btrim(scope) <> ''),
    completed BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE accounts (
    account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    username TEXT NOT NULL CHECK (
        username ~ '^[a-z_][a-z0-9_-]{0,31}\$?$'
    ),
    uid INTEGER NOT NULL CHECK (uid >= 0),
    shell TEXT NOT NULL,
    password_locked BOOLEAN NOT NULL,
    interactive BOOLEAN NOT NULL,
    sudo_access BOOLEAN NOT NULL DEFAULT FALSE,
    service_account BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    UNIQUE (repository_id, username),
    UNIQUE (repository_id, uid),
    CHECK (NOT (sudo_access AND service_account))
);

-- UID uniqueness is intentionally scoped to a host. Linux UID identity and
-- file ownership are local to the system, not globally unique across servers.

CREATE TABLE account_groups (
    account_id BIGINT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    group_name TEXT NOT NULL CHECK (btrim(group_name) <> ''),
    PRIMARY KEY (account_id, group_name)
);

CREATE TABLE ssh_policies (
    ssh_policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    permit_root_login TEXT NOT NULL CHECK (
        permit_root_login IN ('yes', 'no', 'prohibit-password', 'forced-commands-only')
    ),
    password_authentication BOOLEAN NOT NULL,
    public_key_authentication BOOLEAN NOT NULL,
    max_auth_tries INTEGER NOT NULL CHECK (max_auth_tries BETWEEN 1 AND 100),
    max_sessions INTEGER NOT NULL CHECK (max_sessions BETWEEN 1 AND 1000),
    login_grace_seconds INTEGER NOT NULL CHECK (login_grace_seconds BETWEEN 1 AND 3600),
    tcp_forwarding BOOLEAN NOT NULL,
    x11_forwarding BOOLEAN NOT NULL,
    effective_config_verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE ssh_allowed_users (
    ssh_policy_id BIGINT NOT NULL REFERENCES ssh_policies(ssh_policy_id)
        ON DELETE CASCADE,
    username TEXT NOT NULL,
    PRIMARY KEY (ssh_policy_id, username)
);

CREATE TABLE firewall_policies (
    firewall_policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    inbound_default TEXT NOT NULL CHECK (
        inbound_default IN ('allow', 'deny', 'reject')
    ),
    outbound_default TEXT NOT NULL CHECK (
        outbound_default IN ('allow', 'deny', 'reject')
    ),
    forward_default TEXT NOT NULL CHECK (
        forward_default IN ('allow', 'deny', 'reject')
    ),
    backend TEXT NOT NULL CHECK (
        backend IN ('nftables', 'iptables', 'ufw', 'firewalld', 'other')
    ),
    active_rules_verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE firewall_rules (
    firewall_rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    firewall_policy_id BIGINT NOT NULL REFERENCES firewall_policies(firewall_policy_id)
        ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (
        direction IN ('inbound', 'outbound', 'forward')
    ),
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'reject')),
    protocol TEXT NOT NULL CHECK (
        protocol IN ('tcp', 'udp', 'icmp', 'any')
    ),
    port_start INTEGER,
    port_end INTEGER,
    source_cidr CIDR,
    destination_cidr CIDR,
    service_name TEXT NOT NULL,
    rule_order INTEGER NOT NULL CHECK (rule_order >= 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (
        (protocol IN ('tcp', 'udp') AND
         port_start BETWEEN 1 AND 65535 AND
         port_end BETWEEN port_start AND 65535)
        OR
        (protocol IN ('icmp', 'any') AND
         port_start IS NULL AND port_end IS NULL)
    ),
    UNIQUE (firewall_policy_id, rule_order)
);

CREATE TABLE patch_assessments (
    patch_assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    security_updates_pending INTEGER NOT NULL CHECK (security_updates_pending >= 0),
    critical_updates_pending INTEGER NOT NULL CHECK (critical_updates_pending >= 0),
    days_since_successful_update INTEGER NOT NULL
        CHECK (days_since_successful_update >= 0),
    reboot_required BOOLEAN NOT NULL,
    unattended_security_updates BOOLEAN NOT NULL,
    package_manager TEXT NOT NULL CHECK (
        package_manager IN ('apt', 'dnf', 'yum', 'zypper', 'other')
    ),
    repository_metadata_fresh BOOLEAN NOT NULL
);

CREATE TABLE audit_controls (
    audit_control_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    auditd_enabled BOOLEAN NOT NULL,
    persistent_rules BOOLEAN NOT NULL,
    authentication_logging BOOLEAN NOT NULL,
    time_synchronization BOOLEAN NOT NULL,
    file_integrity_monitoring BOOLEAN NOT NULL,
    log_retention_days INTEGER NOT NULL CHECK (log_retention_days >= 0),
    central_log_collection BOOLEAN NOT NULL,
    last_log_delivery_at TIMESTAMPTZ
);

CREATE TABLE file_permission_evidence (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    file_path TEXT NOT NULL CHECK (file_path LIKE '/%'),
    owner_name TEXT NOT NULL,
    group_name TEXT NOT NULL,
    mode_octal TEXT NOT NULL CHECK (mode_octal ~ '^0?[0-7]{3,4}$'),
    world_writable BOOLEAN GENERATED ALWAYS AS (
        (('x' || lpad(mode_octal, 4, '0'))::bit(12) & B'000000000010') <> B'000000000000'
    ) STORED,
    UNIQUE (repository_id, file_path, assessed_at)
);

CREATE TABLE hardening_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES assessments(assessment_id)
        ON DELETE CASCADE,
    family control_family NOT NULL,
    control_id TEXT NOT NULL,
    severity finding_severity NOT NULL,
    title TEXT NOT NULL CHECK (btrim(title) <> ''),
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    remediation TEXT NOT NULL CHECK (btrim(remediation) <> ''),
    status remediation_status NOT NULL DEFAULT 'open',
    assigned_team TEXT,
    due_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    UNIQUE (assessment_id, control_id),
    CHECK (
        (status = 'resolved' AND resolved_at IS NOT NULL)
        OR
        (status <> 'resolved' AND resolved_at IS NULL)
    )
);

CREATE TABLE remediation_events (
    remediation_event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES hardening_findings(finding_id)
        ON DELETE CASCADE,
    actor TEXT NOT NULL CHECK (btrim(actor) <> ''),
    previous_status remediation_status,
    new_status remediation_status NOT NULL,
    event_note TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE maintenance_changes (
    change_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id),
    change_reference TEXT NOT NULL UNIQUE,
    change_type TEXT NOT NULL CHECK (
        change_type IN ('ssh', 'firewall', 'patching', 'account', 'audit')
    ),
    owner_team TEXT NOT NULL,
    approved_by TEXT,
    scheduled_at TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    state TEXT NOT NULL CHECK (
        state IN ('proposed', 'approved', 'scheduled', 'executing',
                  'verified', 'failed', 'rolled_back')
    ),
    rollback_plan TEXT NOT NULL CHECK (btrim(rollback_plan) <> ''),
    CHECK (approved_by IS NOT NULL OR state = 'proposed'),
    CHECK (verified_at IS NULL OR state = 'verified')
);

CREATE INDEX idx_assessments_repository_time
    ON assessments(repository_id, assessed_at DESC);

CREATE INDEX idx_findings_open_severity
    ON hardening_findings(severity, due_at)
    WHERE status = 'open';

CREATE INDEX idx_findings_assessment_family
    ON hardening_findings(assessment_id, family, severity);

CREATE INDEX idx_firewall_enabled_order
    ON firewall_rules(firewall_policy_id, rule_order)
    WHERE enabled;

CREATE INDEX idx_patch_latest
    ON patch_assessments(repository_id, assessed_at DESC);

CREATE INDEX idx_audit_latest
    ON audit_controls(repository_id, assessed_at DESC);

CREATE INDEX idx_findings_evidence
    ON hardening_findings USING GIN(evidence);

-- Ensure remediation state changes leave an audit trail.
CREATE FUNCTION record_remediation_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO remediation_events (
            finding_id, actor, previous_status, new_status, event_note
        )
        VALUES (
            NEW.finding_id,
            COALESCE(NEW.assigned_team, 'system'),
            OLD.status,
            NEW.status,
            'Status changed through hardening finding update'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_remediation_status_audit
AFTER UPDATE OF status ON hardening_findings
FOR EACH ROW
EXECUTE FUNCTION record_remediation_event();

-- Resolve the latest record of each control family for each host. This avoids
-- counting stale inventory as if it were current evidence.
CREATE VIEW latest_host_assessment AS
SELECT DISTINCT ON (a.repository_id)
    a.repository_id,
    a.assessment_id,
    a.assessed_at,
    a.assessor,
    a.completed
FROM assessments AS a
ORDER BY a.repository_id, a.assessed_at DESC, a.assessment_id DESC;

INSERT INTO repositories (
    hostname, environment, distribution, distribution_version, owner_team
)
VALUES
    ('api-prod-01', 'production', 'Ubuntu', '24.04', 'platform-security'),
    ('worker-stage-01', 'staging', 'Debian', '12', 'data-platform');

INSERT INTO assessments (
    repository_id, assessed_at, assessor, scanner_version, scope, completed
)
SELECT repository_id, now() - interval '2 hours', 'security-audit',
       '2.4.0', 'account, SSH, firewall, patching, audit', TRUE
FROM repositories
WHERE hostname = 'api-prod-01';

INSERT INTO assessments (
    repository_id, assessed_at, assessor, scanner_version, scope, completed
)
SELECT repository_id, now() - interval '1 day', 'platform-ops',
       '2.4.0', 'account, SSH, firewall, patching, audit', TRUE
FROM repositories
WHERE hostname = 'worker-stage-01';

INSERT INTO accounts (
    repository_id, username, uid, shell, password_locked,
    interactive, sudo_access, service_account
)
SELECT repository_id, 'root', 0, '/bin/bash', TRUE, TRUE, TRUE, FALSE
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO accounts (
    repository_id, username, uid, shell, password_locked,
    interactive, sudo_access, service_account
)
SELECT repository_id, 'platform', 1000, '/bin/bash', FALSE, TRUE, TRUE, FALSE
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO accounts (
    repository_id, username, uid, shell, password_locked,
    interactive, sudo_access, service_account
)
SELECT repository_id, 'deploy', 1001, '/usr/sbin/nologin',
       TRUE, FALSE, FALSE, TRUE
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO account_groups(account_id, group_name)
SELECT account_id, 'sudo' FROM accounts WHERE username = 'platform';

INSERT INTO ssh_policies (
    repository_id, permit_root_login, password_authentication,
    public_key_authentication, max_auth_tries, max_sessions,
    login_grace_seconds, tcp_forwarding, x11_forwarding,
    effective_config_verified
)
SELECT repository_id, 'no', TRUE, TRUE, 6, 10, 90, TRUE, TRUE, FALSE
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO ssh_allowed_users(ssh_policy_id, username)
SELECT ssh_policy_id, 'platform' FROM ssh_policies;

INSERT INTO ssh_allowed_users(ssh_policy_id, username)
SELECT ssh_policy_id, 'deploy' FROM ssh_policies;

INSERT INTO firewall_policies (
    repository_id, inbound_default, outbound_default, forward_default,
    backend, active_rules_verified
)
SELECT repository_id, 'allow', 'allow', 'deny', 'nftables', FALSE
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO firewall_rules (
    firewall_policy_id, direction, action, protocol,
    port_start, port_end, source_cidr, service_name, rule_order, enabled
)
SELECT firewall_policy_id, 'inbound', 'allow', 'tcp', 22, 22,
       '0.0.0.0/0'::cidr, 'ssh', 10, TRUE
FROM firewall_policies;

INSERT INTO firewall_rules (
    firewall_policy_id, direction, action, protocol,
    port_start, port_end, source_cidr, service_name, rule_order, enabled
)
SELECT firewall_policy_id, 'inbound', 'allow', 'tcp', 443, 443,
       '0.0.0.0/0'::cidr, 'https', 20, TRUE
FROM firewall_policies;

INSERT INTO patch_assessments (
    repository_id, security_updates_pending, critical_updates_pending,
    days_since_successful_update, reboot_required,
    unattended_security_updates, package_manager, repository_metadata_fresh
)
SELECT repository_id, 12, 2, 38, TRUE, FALSE, 'apt', TRUE
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO audit_controls (
    repository_id, auditd_enabled, persistent_rules, authentication_logging,
    time_synchronization, file_integrity_monitoring, log_retention_days,
    central_log_collection, last_log_delivery_at
)
SELECT repository_id, FALSE, FALSE, TRUE, TRUE, FALSE, 14,
       TRUE, now() - interval '10 minutes'
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO file_permission_evidence (
    repository_id, file_path, owner_name, group_name, mode_octal, assessed_at
)
SELECT repository_id, '/etc/shadow', 'root', 'shadow', '0640', now()
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO file_permission_evidence (
    repository_id, file_path, owner_name, group_name, mode_octal, assessed_at
)
SELECT repository_id, '/etc/ssh/sshd_config', 'root', 'root', '0666', now()
FROM repositories WHERE hostname = 'api-prod-01';

INSERT INTO hardening_findings (
    assessment_id, family, control_id, severity, title, evidence,
    remediation, status, assigned_team, due_at
)
SELECT a.assessment_id, 'ssh_hardening', 'SSH-ROOT', 'high',
       'SSH password authentication is enabled',
       '{"directive":"PasswordAuthentication","effective_value":true}'::jsonb,
       'Disable password authentication after testing approved administrative access.',
       'open', 'platform-security', now() + interval '2 days'
FROM assessments a
JOIN repositories r USING (repository_id)
WHERE r.hostname = 'api-prod-01';

INSERT INTO hardening_findings (
    assessment_id, family, control_id, severity, title, evidence,
    remediation, status, assigned_team, due_at
)
SELECT a.assessment_id, 'firewalling', 'FW-DEFAULT-IN', 'critical',
       'Inbound firewall policy is permissive',
       '{"default_policy":"allow","backend":"nftables"}'::jsonb,
       'Switch to deny-by-default and allow only approved application services.',
       'open', 'network-security', now() + interval '1 day'
FROM assessments a
JOIN repositories r USING (repository_id)
WHERE r.hostname = 'api-prod-01';

INSERT INTO hardening_findings (
    assessment_id, family, control_id, severity, title, evidence,
    remediation, status, assigned_team, due_at
)
SELECT a.assessment_id, 'patching', 'PATCH-CRITICAL', 'critical',
       'Critical package updates are pending',
       '{"critical_pending":2,"security_pending":12,"reboot_required":true}'::jsonb,
       'Assess applicability, apply validated fixes, reboot in a controlled window, and verify health.',
       'open', 'platform-ops', now() + interval '1 day'
FROM assessments a
JOIN repositories r USING (repository_id)
WHERE r.hostname = 'api-prod-01';

INSERT INTO hardening_findings (
    assessment_id, family, control_id, severity, title, evidence,
    remediation, status, assigned_team, due_at
)
SELECT a.assessment_id, 'auditing', 'AUDIT-RULES', 'high',
       'Audit daemon or persistent audit rules are disabled',
       '{"auditd_enabled":false,"persistent_rules":false}'::jsonb,
       'Enable supported audit collection and persist reviewed rules.',
       'open', 'platform-security', now() + interval '7 days'
FROM assessments a
JOIN repositories r USING (repository_id)
WHERE r.hostname = 'api-prod-01';

-- Control evaluation combines current inventories with explicit SQL predicates.
WITH ssh_latest AS (
    SELECT DISTINCT ON (repository_id) *
    FROM ssh_policies
    ORDER BY repository_id, assessed_at DESC, ssh_policy_id DESC
),
firewall_latest AS (
    SELECT DISTINCT ON (repository_id) *
    FROM firewall_policies
    ORDER BY repository_id, assessed_at DESC, firewall_policy_id DESC
),
patch_latest AS (
    SELECT DISTINCT ON (repository_id) *
    FROM patch_assessments
    ORDER BY repository_id, assessed_at DESC, patch_assessment_id DESC
),
audit_latest AS (
    SELECT DISTINCT ON (repository_id) *
    FROM audit_controls
    ORDER BY repository_id, assessed_at DESC, audit_control_id DESC
)
SELECT
    r.hostname,
    CASE WHEN s.permit_root_login <> 'no'
         THEN 'HIGH' END AS root_ssh_risk,
    CASE WHEN s.password_authentication
         THEN 'HIGH' END AS ssh_password_risk,
    CASE WHEN f.inbound_default = 'allow'
         THEN 'CRITICAL' END AS inbound_firewall_risk,
    CASE WHEN p.critical_updates_pending > 0
         THEN 'CRITICAL' END AS critical_patch_risk,
    CASE WHEN p.days_since_successful_update > 30
         THEN 'HIGH' END AS stale_patch_risk,
    CASE WHEN NOT a.auditd_enabled OR NOT a.persistent_rules
         THEN 'HIGH' END AS audit_collection_risk
FROM repositories r
LEFT JOIN ssh_latest s USING (repository_id)
LEFT JOIN firewall_latest f USING (repository_id)
LEFT JOIN patch_latest p USING (repository_id)
LEFT JOIN audit_latest a USING (repository_id)
ORDER BY r.hostname;

-- Detect sensitive ports exposed to every source. CIDR is a native PostgreSQL
-- type, so comparisons are explicit rather than substring-based.
SELECT
    r.hostname,
    fr.service_name,
    fr.protocol,
    fr.port_start,
    fr.source_cidr,
    fr.rule_order
FROM firewall_rules fr
JOIN firewall_policies fp USING (firewall_policy_id)
JOIN repositories r USING (repository_id)
WHERE fr.enabled
  AND fr.direction = 'inbound'
  AND fr.action = 'allow'
  AND fr.protocol = 'tcp'
  AND fr.port_start IN (22, 23, 445, 3389)
  AND (
      fr.source_cidr IS NULL
      OR fr.source_cidr = '0.0.0.0/0'::cidr
      OR fr.source_cidr = '::/0'::cidr
  )
ORDER BY r.hostname, fr.port_start;

-- Detect service identities that still have an interactive shell or privilege.
SELECT r.hostname, a.username, a.uid, a.shell, a.sudo_access
FROM accounts a
JOIN repositories r USING (repository_id)
WHERE a.service_account
  AND (a.interactive OR a.sudo_access OR a.shell NOT LIKE '%nologin')
ORDER BY r.hostname, a.username;

-- File mode analysis: credential and authentication configuration files need
-- restrictive permissions. This query highlights world-writable evidence.
SELECT hostname, file_path, owner_name, group_name, mode_octal, world_writable
FROM file_permission_evidence e
JOIN repositories r USING (repository_id)
WHERE e.world_writable
   OR (
       e.file_path IN ('/etc/shadow', '/etc/gshadow')
       AND (('x' || lpad(e.mode_octal, 4, '0'))::bit(12) & B'000000001111') <>
           B'000000000000'
   )
ORDER BY hostname, file_path;

-- Prioritize work using explicit severity ordering and due dates.
SELECT
    r.hostname,
    f.control_id,
    f.family,
    f.severity,
    f.title,
    f.status,
    f.assigned_team,
    f.due_at
FROM hardening_findings f
JOIN assessments a USING (assessment_id)
JOIN repositories r USING (repository_id)
WHERE f.status = 'open'
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 0
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END,
    f.due_at NULLS LAST;

-- Demonstrate a transactional remediation status update. The trigger records
-- the previous and new status in remediation_events.
BEGIN;

UPDATE hardening_findings
SET status = 'accepted',
    assigned_team = 'platform-security'
WHERE control_id = 'SSH-ROOT'
  AND status = 'open';

SELECT finding_id, control_id, status, assigned_team
FROM hardening_findings
WHERE control_id = 'SSH-ROOT';

SELECT finding_id, previous_status, new_status, actor, occurred_at
FROM remediation_events
ORDER BY remediation_event_id DESC;

COMMIT;

-- A deliberately invalid row would be rejected by CHECK:
-- INSERT INTO firewall_rules (
--   firewall_policy_id, direction, action, protocol,
--   port_start, port_end, service_name, rule_order
-- ) VALUES (1, 'sideways', 'allow', 'tcp', 22, 22, 'ssh', 99);
--
-- A duplicate UID on the same host is rejected by UNIQUE(repository_id, uid).
-- A finding marked resolved must have resolved_at set. These integrity rules
-- prevent invalid records even when the application has a defect.

COMMIT;
