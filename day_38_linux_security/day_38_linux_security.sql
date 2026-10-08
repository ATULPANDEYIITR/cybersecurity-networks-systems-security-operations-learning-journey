-- Linux Security Governance Lab
-- PostgreSQL-compatible SQL
--
-- The schema separates:
--   SSH access policy
--   sudo authorization
--   filesystem permissions
--   secure host configuration
--   service minimization
--
-- These controls interact operationally but represent different security
-- boundaries and therefore receive separate relational structures.

DROP SCHEMA IF EXISTS linux_security_lab CASCADE;
CREATE SCHEMA linux_security_lab;
SET search_path TO linux_security_lab;

CREATE TYPE account_state AS ENUM ('active', 'locked', 'disabled');
CREATE TYPE authentication_method AS ENUM (
    'password',
    'public_key',
    'certificate'
);
CREATE TYPE review_severity AS ENUM (
    'info',
    'low',
    'medium',
    'high',
    'critical'
);
CREATE TYPE access_action AS ENUM ('read', 'write', 'execute');

CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    is_root BOOLEAN NOT NULL DEFAULT FALSE,
    state account_state NOT NULL DEFAULT 'active',
    public_key_configured BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (username <> '')
);

CREATE TABLE groups (
    group_id BIGSERIAL PRIMARY KEY,
    group_name TEXT NOT NULL UNIQUE,
    CHECK (group_name <> '')
);

CREATE TABLE user_groups (
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE ssh_policies (
    ssh_policy_id BIGSERIAL PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    permit_root_login BOOLEAN NOT NULL DEFAULT FALSE,
    password_authentication BOOLEAN NOT NULL DEFAULT FALSE,
    public_key_authentication BOOLEAN NOT NULL DEFAULT TRUE,
    max_auth_tries INTEGER NOT NULL DEFAULT 3,
    x11_forwarding BOOLEAN NOT NULL DEFAULT FALSE,
    agent_forwarding BOOLEAN NOT NULL DEFAULT FALSE,
    tcp_forwarding BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (max_auth_tries BETWEEN 1 AND 10)
);

CREATE TABLE ssh_allowed_users (
    ssh_policy_id BIGINT NOT NULL
        REFERENCES ssh_policies(ssh_policy_id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    PRIMARY KEY (ssh_policy_id, user_id)
);

CREATE TABLE ssh_allowed_groups (
    ssh_policy_id BIGINT NOT NULL
        REFERENCES ssh_policies(ssh_policy_id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    PRIMARY KEY (ssh_policy_id, group_id)
);

CREATE TABLE ssh_attempts (
    attempt_id BIGSERIAL PRIMARY KEY,
    ssh_policy_id BIGINT NOT NULL
        REFERENCES ssh_policies(ssh_policy_id),
    user_id BIGINT REFERENCES users(user_id),
    authentication_method authentication_method NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    credential_valid BOOLEAN NOT NULL DEFAULT FALSE,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (attempt_count > 0)
);

CREATE TABLE sudo_rules (
    sudo_rule_id BIGSERIAL PRIMARY KEY,
    rule_name TEXT NOT NULL UNIQUE,
    require_password BOOLEAN NOT NULL DEFAULT TRUE,
    noexec BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE sudo_rule_users (
    sudo_rule_id BIGINT NOT NULL
        REFERENCES sudo_rules(sudo_rule_id) ON DELETE CASCADE,
    user_id BIGINT REFERENCES users(user_id) ON DELETE CASCADE,
    all_users BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (
        (user_id IS NOT NULL AND all_users = FALSE)
        OR
        (user_id IS NULL AND all_users = TRUE)
    )
);

CREATE TABLE sudo_rule_commands (
    sudo_rule_id BIGINT NOT NULL
        REFERENCES sudo_rules(sudo_rule_id) ON DELETE CASCADE,
    command_path TEXT,
    all_commands BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (sudo_rule_id, command_path),
    CHECK (
        (command_path IS NOT NULL AND all_commands = FALSE)
        OR
        (command_path IS NULL AND all_commands = TRUE)
    )
);

CREATE TABLE filesystem_objects (
    object_id BIGSERIAL PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    owner_user_id BIGINT NOT NULL REFERENCES users(user_id),
    group_id BIGINT NOT NULL REFERENCES groups(group_id),
    mode INTEGER NOT NULL,
    is_directory BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (mode BETWEEN 0 AND 65535)
);

CREATE TABLE security_configuration (
    configuration_id BIGSERIAL PRIMARY KEY,
    host_name TEXT NOT NULL UNIQUE,
    firewall_enabled BOOLEAN NOT NULL,
    automatic_security_updates BOOLEAN NOT NULL,
    audit_logging BOOLEAN NOT NULL,
    time_synchronization BOOLEAN NOT NULL,
    core_dumps_restricted BOOLEAN NOT NULL,
    kernel_modules_restricted BOOLEAN NOT NULL,
    file_integrity_monitoring BOOLEAN NOT NULL,
    secure_boot BOOLEAN NOT NULL
);

CREATE TABLE services (
    service_id BIGSERIAL PRIMARY KEY,
    service_name TEXT NOT NULL UNIQUE,
    enabled_at_boot BOOLEAN NOT NULL DEFAULT FALSE,
    business_required BOOLEAN NOT NULL DEFAULT FALSE,
    remotely_reachable BOOLEAN NOT NULL DEFAULT FALSE,
    running BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE service_listeners (
    listener_id BIGSERIAL PRIMARY KEY,
    service_id BIGINT NOT NULL
        REFERENCES services(service_id) ON DELETE CASCADE,
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    bind_address INET,
    UNIQUE (service_id, protocol, port)
);

-- -------------------------------------------------------------------------
-- Sample identities and groups
-- -------------------------------------------------------------------------

INSERT INTO groups (group_name)
VALUES
    ('root'),
    ('shadow'),
    ('linux-admins'),
    ('developers'),
    ('app'),
    ('legacy-users');

INSERT INTO users (
    username,
    is_root,
    state,
    public_key_configured
)
VALUES
    ('root', TRUE, 'active', TRUE),
    ('opsadmin', FALSE, 'active', TRUE),
    ('developer', FALSE, 'active', TRUE),
    ('legacy', FALSE, 'active', FALSE),
    ('deploy', FALSE, 'active', TRUE);

INSERT INTO user_groups (user_id, group_id)
SELECT u.user_id, g.group_id
FROM users u
JOIN groups g ON
    (u.username = 'root' AND g.group_name = 'root')
    OR
    (u.username = 'opsadmin' AND g.group_name = 'linux-admins')
    OR
    (u.username = 'developer' AND g.group_name = 'developers')
    OR
    (u.username = 'legacy' AND g.group_name = 'legacy-users')
    OR
    (u.username = 'deploy' AND g.group_name = 'app');

-- -------------------------------------------------------------------------
-- SSH policy
-- -------------------------------------------------------------------------

INSERT INTO ssh_policies (
    policy_name,
    permit_root_login,
    password_authentication,
    public_key_authentication,
    max_auth_tries,
    x11_forwarding,
    agent_forwarding,
    tcp_forwarding
)
VALUES (
    'production-ssh',
    FALSE,
    FALSE,
    TRUE,
    3,
    FALSE,
    FALSE,
    FALSE
);

INSERT INTO ssh_allowed_users (ssh_policy_id, user_id)
SELECT p.ssh_policy_id, u.user_id
FROM ssh_policies p
JOIN users u
    ON u.username IN ('opsadmin', 'developer')
WHERE p.policy_name = 'production-ssh';

INSERT INTO ssh_allowed_groups (ssh_policy_id, group_id)
SELECT p.ssh_policy_id, g.group_id
FROM ssh_policies p
JOIN groups g ON g.group_name = 'linux-admins'
WHERE p.policy_name = 'production-ssh';

-- -------------------------------------------------------------------------
-- sudo policy
-- -------------------------------------------------------------------------

INSERT INTO sudo_rules (
    rule_name,
    require_password,
    noexec
)
VALUES
    ('opsadmin-nginx-control', TRUE, TRUE),
    ('developer-log-reading', TRUE, TRUE),
    ('unsafe-example', FALSE, FALSE);

INSERT INTO sudo_rule_users (sudo_rule_id, user_id)
SELECT r.sudo_rule_id, u.user_id
FROM sudo_rules r
JOIN users u
    ON (r.rule_name = 'opsadmin-nginx-control'
        AND u.username = 'opsadmin')
    OR
       (r.rule_name = 'developer-log-reading'
        AND u.username = 'developer');

INSERT INTO sudo_rule_users (
    sudo_rule_id,
    user_id,
    all_users
)
SELECT sudo_rule_id, NULL, TRUE
FROM sudo_rules
WHERE rule_name = 'unsafe-example';

INSERT INTO sudo_rule_commands (
    sudo_rule_id,
    command_path,
    all_commands
)
SELECT sudo_rule_id, '/usr/bin/systemctl restart nginx', FALSE
FROM sudo_rules
WHERE rule_name = 'opsadmin-nginx-control';

INSERT INTO sudo_rule_commands (
    sudo_rule_id,
    command_path,
    all_commands
)
SELECT sudo_rule_id, '/usr/bin/systemctl status nginx', FALSE
FROM sudo_rules
WHERE rule_name = 'opsadmin-nginx-control';

INSERT INTO sudo_rule_commands (
    sudo_rule_id,
    command_path,
    all_commands
)
SELECT sudo_rule_id, '/usr/bin/journalctl', FALSE
FROM sudo_rules
WHERE rule_name = 'developer-log-reading';

INSERT INTO sudo_rule_commands (
    sudo_rule_id,
    command_path,
    all_commands
)
SELECT sudo_rule_id, NULL, TRUE
FROM sudo_rules
WHERE rule_name = 'unsafe-example';

-- -------------------------------------------------------------------------
-- Filesystem permissions
-- -------------------------------------------------------------------------

INSERT INTO filesystem_objects (
    path,
    owner_user_id,
    group_id,
    mode,
    is_directory
)
SELECT
    '/etc/ssh/sshd_config',
    u.user_id,
    g.group_id,
    384,
    FALSE
FROM users u
JOIN groups g ON g.group_name = 'root'
WHERE u.username = 'root';

INSERT INTO filesystem_objects (
    path,
    owner_user_id,
    group_id,
    mode,
    is_directory
)
SELECT
    '/etc/shadow',
    u.user_id,
    g.group_id,
    416,
    FALSE
FROM users u
JOIN groups g ON g.group_name = 'shadow'
WHERE u.username = 'root';

INSERT INTO filesystem_objects (
    path,
    owner_user_id,
    group_id,
    mode,
    is_directory
)
SELECT
    '/srv/application',
    owner.user_id,
    app_group.group_id,
    488,
    TRUE
FROM users owner
JOIN groups app_group ON app_group.group_name = 'app'
WHERE owner.username = 'deploy';

-- Deliberately insecure example: 0777.
INSERT INTO filesystem_objects (
    path,
    owner_user_id,
    group_id,
    mode,
    is_directory
)
SELECT
    '/tmp/application-upload',
    owner.user_id,
    app_group.group_id,
    511,
    TRUE
FROM users owner
JOIN groups app_group ON app_group.group_name = 'app'
WHERE owner.username = 'deploy';

-- Deliberately sensitive privileged executable: 04755.
INSERT INTO filesystem_objects (
    path,
    owner_user_id,
    group_id,
    mode,
    is_directory
)
SELECT
    '/usr/local/bin/privileged-helper',
    owner.user_id,
    root_group.group_id,
    2541,
    FALSE
FROM users owner
JOIN groups root_group ON root_group.group_name = 'root'
WHERE owner.username = 'root';

-- -------------------------------------------------------------------------
-- Host configuration
-- -------------------------------------------------------------------------

INSERT INTO security_configuration (
    host_name,
    firewall_enabled,
    automatic_security_updates,
    audit_logging,
    time_synchronization,
    core_dumps_restricted,
    kernel_modules_restricted,
    file_integrity_monitoring,
    secure_boot
)
VALUES (
    'prod-app-01',
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    TRUE,
    FALSE,
    TRUE
);

-- -------------------------------------------------------------------------
-- Service inventory
-- -------------------------------------------------------------------------

INSERT INTO services (
    service_name,
    enabled_at_boot,
    business_required,
    remotely_reachable,
    running
)
VALUES
    ('sshd', TRUE, TRUE, TRUE, TRUE),
    ('nginx', TRUE, TRUE, TRUE, TRUE),
    ('telnet', TRUE, FALSE, TRUE, TRUE),
    ('cups', TRUE, FALSE, FALSE, TRUE);

INSERT INTO service_listeners (
    service_id,
    protocol,
    port,
    bind_address
)
SELECT
    s.service_id,
    'tcp',
    22,
    '0.0.0.0/0'
FROM services s
WHERE s.service_name = 'sshd';

INSERT INTO service_listeners (
    service_id,
    protocol,
    port,
    bind_address
)
SELECT
    s.service_id,
    'tcp',
    443,
    '0.0.0.0/0'
FROM services s
WHERE s.service_name = 'nginx';

INSERT INTO service_listeners (
    service_id,
    protocol,
    port,
    bind_address
)
SELECT
    s.service_id,
    'tcp',
    23,
    '0.0.0.0/0'
FROM services s
WHERE s.service_name = 'telnet';

INSERT INTO service_listeners (
    service_id,
    protocol,
    port,
    bind_address
)
SELECT
    s.service_id,
    'tcp',
    631,
    '127.0.0.1/32'
FROM services s
WHERE s.service_name = 'cups';

-- -------------------------------------------------------------------------
-- Indexes
-- -------------------------------------------------------------------------

CREATE INDEX idx_user_groups_group
    ON user_groups(group_id);

CREATE INDEX idx_ssh_attempts_timestamp
    ON ssh_attempts(attempted_at DESC);

CREATE INDEX idx_sudo_rule_commands_path
    ON sudo_rule_commands(command_path);

CREATE INDEX idx_filesystem_owner
    ON filesystem_objects(owner_user_id);

CREATE INDEX idx_service_listeners_port
    ON service_listeners(port);

-- -------------------------------------------------------------------------
-- SSH access evaluation
-- -------------------------------------------------------------------------

WITH policy AS (
    SELECT *
    FROM ssh_policies
    WHERE policy_name = 'production-ssh'
),
account AS (
    SELECT
        u.*,
        EXISTS (
            SELECT 1
            FROM ssh_allowed_users au
            WHERE au.ssh_policy_id = policy.ssh_policy_id
              AND au.user_id = u.user_id
        ) AS explicitly_allowed,
        EXISTS (
            SELECT 1
            FROM ssh_allowed_groups ag
            JOIN user_groups ug
                ON ug.group_id = ag.group_id
            WHERE ag.ssh_policy_id = policy.ssh_policy_id
              AND ug.user_id = u.user_id
        ) AS allowed_group
    FROM users u
    CROSS JOIN policy
)
SELECT
    username,
    CASE
        WHEN state <> 'active'
            THEN 'DENY: account is not active'
        WHEN is_root AND NOT permit_root_login
            THEN 'DENY: direct root SSH disabled'
        WHEN NOT password_authentication
             AND username = 'legacy'
            THEN 'DENY: password authentication disabled'
        WHEN public_key_configured = FALSE
            THEN 'DENY: no public key configured'
        WHEN NOT explicitly_allowed AND NOT allowed_group
            THEN 'DENY: SSH allow policy does not include account'
        ELSE 'ALLOW'
    END AS decision
FROM account
CROSS JOIN policy
WHERE username IN ('opsadmin', 'developer', 'legacy', 'root');

-- -------------------------------------------------------------------------
-- sudo least-privilege evaluation
-- -------------------------------------------------------------------------

SELECT
    u.username,
    r.rule_name,
    c.command_path,
    r.require_password,
    r.noexec,
    CASE
        WHEN c.all_commands THEN 'BROAD'
        ELSE 'SPECIFIC'
    END AS authorization_scope
FROM sudo_rules r
JOIN sudo_rule_users ru
    ON ru.sudo_rule_id = r.sudo_rule_id
LEFT JOIN users u
    ON u.user_id = ru.user_id
CROSS JOIN LATERAL (
    SELECT
        src.command_path,
        src.all_commands
    FROM sudo_rule_commands src
    WHERE src.sudo_rule_id = r.sudo_rule_id
) c
WHERE r.enabled = TRUE
ORDER BY r.rule_name, u.username NULLS FIRST;

-- Identify unrestricted sudo rules.
SELECT
    r.rule_name,
    r.require_password,
    r.noexec
FROM sudo_rules r
JOIN sudo_rule_users ru
    ON ru.sudo_rule_id = r.sudo_rule_id
JOIN sudo_rule_commands rc
    ON rc.sudo_rule_id = r.sudo_rule_id
WHERE ru.all_users = TRUE
  AND rc.all_commands = TRUE;

-- -------------------------------------------------------------------------
-- Filesystem permission audit
-- -------------------------------------------------------------------------

SELECT
    f.path,
    u.username AS owner,
    g.group_name AS owning_group,
    to_char(f.mode, 'FM9999') AS numeric_mode,
    CASE
        WHEN (f.mode & 2) <> 0 THEN 'WORLD_WRITABLE'
        WHEN (f.mode & 4) <> 0 AND NOT f.is_directory
            THEN 'WORLD_READABLE'
        WHEN (f.mode & 2048) <> 0
            THEN 'SETUID_PRESENT'
        ELSE 'NO_SELECTED_FINDING'
    END AS permission_finding
FROM filesystem_objects f
JOIN users u ON u.user_id = f.owner_user_id
JOIN groups g ON g.group_id = f.group_id
ORDER BY f.path;

-- Sensitive files should not be world-readable.
SELECT
    path,
    mode
FROM filesystem_objects
WHERE NOT is_directory
  AND (mode & 4) <> 0;

-- World-writable objects are high-priority findings.
SELECT
    path,
    mode
FROM filesystem_objects
WHERE (mode & 2) <> 0;

-- -------------------------------------------------------------------------
-- Secure configuration audit
-- -------------------------------------------------------------------------

SELECT
    host_name,
    CASE
        WHEN firewall_enabled THEN 'PASS'
        ELSE 'FAIL'
    END AS firewall,
    CASE
        WHEN automatic_security_updates THEN 'PASS'
        ELSE 'FAIL'
    END AS patching,
    CASE
        WHEN audit_logging THEN 'PASS'
        ELSE 'FAIL'
    END AS audit_logging,
    CASE
        WHEN time_synchronization THEN 'PASS'
        ELSE 'FAIL'
    END AS time_sync,
    CASE
        WHEN core_dumps_restricted THEN 'PASS'
        ELSE 'FAIL'
    END AS core_dump_policy,
    CASE
        WHEN kernel_modules_restricted THEN 'PASS'
        ELSE 'FAIL'
    END AS kernel_module_policy,
    CASE
        WHEN file_integrity_monitoring THEN 'PASS'
        ELSE 'FAIL'
    END AS file_integrity,
    CASE
        WHEN secure_boot THEN 'PASS'
        ELSE 'FAIL'
    END AS secure_boot
FROM security_configuration;

-- -------------------------------------------------------------------------
-- Service minimization audit
-- -------------------------------------------------------------------------

SELECT
    s.service_name,
    s.enabled_at_boot,
    s.business_required,
    s.remotely_reachable,
    s.running,
    COUNT(sl.listener_id) AS listener_count,
    CASE
        WHEN NOT s.business_required
             AND COUNT(sl.listener_id) > 0
            THEN 'HIGH: unnecessary listener'
        WHEN NOT s.business_required
             AND s.enabled_at_boot
            THEN 'HIGH: unnecessary enabled service'
        WHEN s.remotely_reachable
             AND COUNT(sl.listener_id) > 0
            THEN 'MEDIUM: remote exposure'
        ELSE 'NO_SELECTED_FINDING'
    END AS finding
FROM services s
LEFT JOIN service_listeners sl
    ON sl.service_id = s.service_id
GROUP BY
    s.service_id,
    s.service_name,
    s.enabled_at_boot,
    s.business_required,
    s.remotely_reachable,
    s.running
ORDER BY finding DESC, s.service_name;

-- -------------------------------------------------------------------------
-- Integrated host security score
-- -------------------------------------------------------------------------

WITH findings AS (
    SELECT
        'SSH' AS area,
        'CRITICAL' AS severity
    FROM ssh_policies
    WHERE permit_root_login

    UNION ALL

    SELECT
        'SSH',
        'HIGH'
    FROM ssh_policies
    WHERE password_authentication

    UNION ALL

    SELECT
        'sudo',
        'CRITICAL'
    FROM sudo_rules r
    JOIN sudo_rule_users ru
        ON ru.sudo_rule_id = r.sudo_rule_id
    JOIN sudo_rule_commands rc
        ON rc.sudo_rule_id = r.sudo_rule_id
    WHERE ru.all_users
      AND rc.all_commands
      AND r.enabled

    UNION ALL

    SELECT
        'Permissions',
        'HIGH'
    FROM filesystem_objects
    WHERE (mode & 2) <> 0

    UNION ALL

    SELECT
        'Permissions',
        'HIGH'
    FROM filesystem_objects
    WHERE (mode & 2048) <> 0

    UNION ALL

    SELECT
        'Configuration',
        'HIGH'
    FROM security_configuration
    WHERE NOT firewall_enabled

    UNION ALL

    SELECT
        'Configuration',
        'HIGH'
    FROM security_configuration
    WHERE NOT audit_logging

    UNION ALL

    SELECT
        'Configuration',
        'MEDIUM'
    FROM security_configuration
    WHERE NOT file_integrity_monitoring

    UNION ALL

    SELECT
        'Services',
        'HIGH'
    FROM services s
    WHERE NOT business_required
      AND enabled_at_boot

    UNION ALL

    SELECT
        'Services',
        'HIGH'
    FROM services s
    JOIN service_listeners sl
        ON sl.service_id = s.service_id
    WHERE NOT business_required
)
SELECT
    COUNT(*) AS finding_count,
    100
    - COALESCE(
        SUM(
            CASE severity
                WHEN 'CRITICAL' THEN 20
                WHEN 'HIGH' THEN 10
                WHEN 'MEDIUM' THEN 5
                WHEN 'LOW' THEN 2
                ELSE 0
            END
        ),
        0
    ) AS posture_score
FROM findings;

-- -------------------------------------------------------------------------
-- Transactional example
-- -------------------------------------------------------------------------

-- A service-minimization change should be treated as an intentional
-- configuration transaction. The transaction demonstrates database
-- consistency; the actual systemd operation would occur separately under
-- controlled deployment automation.

BEGIN;

UPDATE services
SET enabled_at_boot = FALSE,
    running = FALSE
WHERE service_name = 'telnet'
  AND business_required = FALSE;

DELETE FROM service_listeners
WHERE service_id = (
    SELECT service_id
    FROM services
    WHERE service_name = 'telnet'
);

COMMIT;

-- Verify the resulting state.
SELECT
    s.service_name,
    s.enabled_at_boot,
    s.running,
    COUNT(sl.listener_id) AS listener_count
FROM services s
LEFT JOIN service_listeners sl
    ON sl.service_id = s.service_id
WHERE s.service_name = 'telnet'
GROUP BY
    s.service_id,
    s.service_name,
    s.enabled_at_boot,
    s.running;

-- -------------------------------------------------------------------------
-- Useful operational view
-- -------------------------------------------------------------------------

CREATE VIEW host_security_findings AS
SELECT
    'service' AS category,
    s.service_name AS resource,
    'Unnecessary enabled service' AS finding,
    'high'::review_severity AS severity
FROM services s
WHERE NOT s.business_required
  AND s.enabled_at_boot

UNION ALL

SELECT
    'service',
    s.service_name,
    'Unnecessary network listener',
    'high'::review_severity
FROM services s
JOIN service_listeners sl
    ON sl.service_id = s.service_id
WHERE NOT s.business_required

UNION ALL

SELECT
    'filesystem',
    f.path,
    'World-writable object',
    'high'::review_severity
FROM filesystem_objects f
WHERE (f.mode & 2) <> 0

UNION ALL

SELECT
    'configuration',
    c.host_name,
    'File integrity monitoring disabled',
    'medium'::review_severity
FROM security_configuration c
WHERE NOT c.file_integrity_monitoring

UNION ALL

SELECT
    'sudo',
    r.rule_name,
    'Unrestricted command authorization',
    'critical'::review_severity
FROM sudo_rules r
JOIN sudo_rule_users ru
    ON ru.sudo_rule_id = r.sudo_rule_id
JOIN sudo_rule_commands rc
    ON rc.sudo_rule_id = r.sudo_rule_id
WHERE ru.all_users
  AND rc.all_commands
  AND r.enabled;

SELECT *
FROM host_security_findings
ORDER BY severity DESC, category, resource;
