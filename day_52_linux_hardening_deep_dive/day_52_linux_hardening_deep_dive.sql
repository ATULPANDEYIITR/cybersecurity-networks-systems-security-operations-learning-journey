DROP SCHEMA IF EXISTS linux_hardening CASCADE;
CREATE SCHEMA linux_hardening;

SET search_path = linux_hardening, public;

-- A host is the unit on which hardening evidence is collected.
CREATE TABLE hosts (
    host_id          BIGSERIAL PRIMARY KEY,
    hostname         TEXT NOT NULL UNIQUE,
    distribution     TEXT NOT NULL,
    distribution_version TEXT NOT NULL,
    environment      TEXT NOT NULL CHECK (environment IN ('development', 'staging', 'production')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE administrators (
    administrator_id BIGSERIAL PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE,
    role_name        TEXT NOT NULL CHECK (
        role_name IN ('security_admin', 'system_admin', 'auditor', 'operator')
    ),
    active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE ssh_policies (
    ssh_policy_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    permit_root_login TEXT NOT NULL CHECK (
        permit_root_login IN ('yes', 'no', 'prohibit-password', 'forced-commands-only')
    ),
    password_authentication BOOLEAN NOT NULL,
    permit_empty_passwords BOOLEAN NOT NULL,
    x11_forwarding BOOLEAN NOT NULL,
    max_auth_tries INTEGER NOT NULL CHECK (max_auth_tries BETWEEN 1 AND 20),
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sudo_rules (
    sudo_rule_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    subject_name TEXT NOT NULL,
    run_as_user TEXT NOT NULL DEFAULT 'root',
    command_pattern TEXT NOT NULL,
    password_required BOOLEAN NOT NULL,
    source_file TEXT NOT NULL DEFAULT '/etc/sudoers',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (length(trim(subject_name)) > 0),
    CHECK (length(trim(command_pattern)) > 0)
);

CREATE TABLE filesystem_objects (
    filesystem_object_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    object_type TEXT NOT NULL CHECK (
        object_type IN ('file', 'directory', 'symlink', 'device')
    ),
    owner_name TEXT NOT NULL,
    group_name TEXT NOT NULL,
    mode_octal CHAR(4) NOT NULL CHECK (mode_octal ~ '^[0-7]{4}$'),
    world_read BOOLEAN NOT NULL,
    world_write BOOLEAN NOT NULL,
    world_execute BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, path)
);

CREATE TABLE kernel_controls (
    kernel_control_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    control_name TEXT NOT NULL,
    observed_value TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_id, control_name)
);

CREATE TABLE audit_configuration (
    audit_configuration_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    audit_enabled BOOLEAN NOT NULL,
    persistent_rules_loaded BOOLEAN NOT NULL,
    log_directory TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_rules (
    audit_rule_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    syscall_name TEXT,
    path TEXT,
    permission_mask TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (host_id, rule_name)
);

CREATE TABLE hardening_findings (
    finding_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (
        category IN ('SSH', 'sudo', 'filesystem', 'kernel', 'auditing')
    ),
    control_name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('PASS', 'REVIEW', 'FAIL', 'UNKNOWN')
    ),
    severity TEXT NOT NULL CHECK (
        severity IN ('info', 'low', 'medium', 'high', 'critical')
    ),
    evidence TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_host_status
    ON hardening_findings (host_id, status);

CREATE INDEX idx_findings_category
    ON hardening_findings (category, severity);

CREATE INDEX idx_kernel_controls_host
    ON kernel_controls (host_id, control_name);

CREATE INDEX idx_filesystem_world_write
    ON filesystem_objects (host_id)
    WHERE world_write = TRUE;

INSERT INTO hosts
    (hostname, distribution, distribution_version, environment)
VALUES
    ('web-prod-01', 'Ubuntu', '24.04', 'production'),
    ('app-staging-01', 'Debian', '13', 'staging');

INSERT INTO administrators (username, role_name)
VALUES
    ('security-admin', 'security_admin'),
    ('platform-admin', 'system_admin'),
    ('audit-reader', 'auditor');

INSERT INTO ssh_policies
    (host_id, permit_root_login, password_authentication,
     permit_empty_passwords, x11_forwarding, max_auth_tries)
VALUES
    (1, 'no', FALSE, FALSE, FALSE, 4),
    (2, 'prohibit-password', TRUE, FALSE, TRUE, 6);

INSERT INTO sudo_rules
    (host_id, subject_name, run_as_user, command_pattern, password_required)
VALUES
    (1, '%platform-admins', 'root', '/usr/bin/systemctl restart nginx', TRUE),
    (1, 'deploy', 'root', '/usr/bin/systemctl restart application.service', FALSE),
    (2, '%developers', 'root', 'ALL', TRUE);

INSERT INTO filesystem_objects
    (host_id, path, object_type, owner_name, group_name, mode_octal,
     world_read, world_write, world_execute)
VALUES
    (1, '/etc/passwd', 'file', 'root', 'root', '0644', TRUE, FALSE, FALSE),
    (1, '/etc/shadow', 'file', 'root', 'shadow', '0640', FALSE, FALSE, FALSE),
    (1, '/etc/sudoers', 'file', 'root', 'root', '0440', FALSE, FALSE, FALSE),
    (2, '/etc/shadow', 'file', 'root', 'root', '0644', TRUE, FALSE, FALSE);

INSERT INTO kernel_controls
    (host_id, control_name, observed_value, expected_value)
VALUES
    (1, 'kernel.randomize_va_space', '2', '2'),
    (1, 'fs.protected_hardlinks', '1', '1'),
    (1, 'fs.protected_symlinks', '1', '1'),
    (2, 'kernel.randomize_va_space', '0', '2'),
    (2, 'fs.protected_hardlinks', '1', '1'),
    (2, 'fs.protected_symlinks', '0', '1');

INSERT INTO audit_configuration
    (host_id, audit_enabled, persistent_rules_loaded, log_directory)
VALUES
    (1, TRUE, TRUE, '/var/log/audit'),
    (2, TRUE, FALSE, '/var/log/audit');

INSERT INTO audit_rules
    (host_id, rule_name, syscall_name, path, permission_mask)
VALUES
    (1, 'identity-files', NULL, '/etc/passwd', 'wa'),
    (1, 'shadow-file', NULL, '/etc/shadow', 'wa'),
    (1, 'privilege-changes', 'setuid', NULL, NULL),
    (2, 'identity-files', NULL, '/etc/passwd', 'w');

CREATE OR REPLACE FUNCTION evaluate_host_hardening(p_host_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    ssh RECORD;
    fs RECORD;
    kernel RECORD;
    audit RECORD;
    sudo_record RECORD;
BEGIN
    SELECT *
    INTO ssh
    FROM ssh_policies
    WHERE host_id = p_host_id
    ORDER BY captured_at DESC
    LIMIT 1;

    IF NOT FOUND THEN
        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'SSH',
                'configuration',
                'UNKNOWN',
                'medium',
                'No SSH policy evidence is recorded.',
                'Collect an authoritative sshd configuration snapshot.'
            );
    ELSE
        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'SSH',
                'root-login',
                CASE
                    WHEN ssh.permit_root_login IN ('no', 'prohibit-password')
                    THEN 'PASS'
                    ELSE 'FAIL'
                END,
                CASE
                    WHEN ssh.permit_root_login IN ('no', 'prohibit-password')
                    THEN 'info'
                    ELSE 'high'
                END,
                'PermitRootLogin=' || ssh.permit_root_login,
                'Disable direct root SSH login unless a documented exception exists.'
            );

        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'SSH',
                'password-authentication',
                CASE WHEN NOT ssh.password_authentication THEN 'PASS' ELSE 'FAIL' END,
                CASE WHEN NOT ssh.password_authentication THEN 'info' ELSE 'high' END,
                'PasswordAuthentication=' || ssh.password_authentication,
                'Prefer strong key-based authentication where operationally appropriate.'
            );

        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'SSH',
                'empty-passwords',
                CASE WHEN NOT ssh.permit_empty_passwords THEN 'PASS' ELSE 'FAIL' END,
                CASE WHEN NOT ssh.permit_empty_passwords THEN 'info' ELSE 'critical' END,
                'PermitEmptyPasswords=' || ssh.permit_empty_passwords,
                'Disable authentication using empty passwords.'
            );

        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'SSH',
                'x11-forwarding',
                CASE WHEN NOT ssh.x11_forwarding THEN 'PASS' ELSE 'REVIEW' END,
                CASE WHEN NOT ssh.x11_forwarding THEN 'info' ELSE 'medium' END,
                'X11Forwarding=' || ssh.x11_forwarding,
                'Disable X11 forwarding unless it is operationally required.'
            );
    END IF;

    FOR fs IN
        SELECT *
        FROM filesystem_objects
        WHERE host_id = p_host_id
    LOOP
        IF fs.world_write OR (fs.object_type = 'file' AND fs.path = '/etc/shadow'
                              AND fs.world_read) THEN
            INSERT INTO hardening_findings
                (host_id, category, control_name, status, severity, evidence, recommendation)
            VALUES
                (
                    p_host_id,
                    'filesystem',
                    fs.path,
                    'FAIL',
                    'high',
                    'Mode=' || fs.mode_octal ||
                    ', world_read=' || fs.world_read ||
                    ', world_write=' || fs.world_write,
                    'Remove unnecessary world permissions and verify ownership.'
                );
        ELSE
            INSERT INTO hardening_findings
                (host_id, category, control_name, status, severity, evidence, recommendation)
            VALUES
                (
                    p_host_id,
                    'filesystem',
                    fs.path,
                    'PASS',
                    'info',
                    'Mode=' || fs.mode_octal,
                    'No recorded excessive permission was detected.'
                );
        END IF;
    END LOOP;

    FOR kernel IN
        SELECT *
        FROM kernel_controls
        WHERE host_id = p_host_id
    LOOP
        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'kernel',
                kernel.control_name,
                CASE
                    WHEN kernel.observed_value = kernel.expected_value
                    THEN 'PASS'
                    ELSE 'FAIL'
                END,
                CASE
                    WHEN kernel.observed_value = kernel.expected_value
                    THEN 'info'
                    ELSE 'high'
                END,
                'Observed=' || kernel.observed_value ||
                ', expected=' || kernel.expected_value,
                'Review the control and make persistent changes only through an approved system configuration process.'
            );
    END LOOP;

    SELECT *
    INTO audit
    FROM audit_configuration
    WHERE host_id = p_host_id
    ORDER BY observed_at DESC
    LIMIT 1;

    IF NOT FOUND OR NOT audit.audit_enabled OR NOT audit.persistent_rules_loaded THEN
        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'auditing',
                'audit-configuration',
                'FAIL',
                'high',
                CASE
                    WHEN NOT FOUND THEN 'No audit configuration evidence.'
                    ELSE 'audit_enabled=' || audit.audit_enabled ||
                         ', persistent_rules_loaded=' || audit.persistent_rules_loaded
                END,
                'Enable auditing and ensure required rules persist across reboot.'
            );
    ELSE
        INSERT INTO hardening_findings
            (host_id, category, control_name, status, severity, evidence, recommendation)
        VALUES
            (
                p_host_id,
                'auditing',
                'audit-configuration',
                'PASS',
                'info',
                'Audit interface and persistent rules are recorded as enabled.',
                'Monitor audit logs and validate rule coverage regularly.'
            );
    END IF;

    FOR sudo_record IN
        SELECT *
        FROM sudo_rules
        WHERE host_id = p_host_id
          AND enabled
    LOOP
        IF sudo_record.command_pattern = 'ALL'
           AND sudo_record.password_required THEN
            INSERT INTO hardening_findings
                (host_id, category, control_name, status, severity, evidence, recommendation)
            VALUES
                (
                    p_host_id,
                    'sudo',
                    'broad-command-grant',
                    'REVIEW',
                    'high',
                    sudo_record.subject_name || ' can execute ALL as ' ||
                    sudo_record.run_as_user,
                    'Replace unrestricted sudo access with narrowly scoped administrative commands.'
                );
        ELSIF NOT sudo_record.password_required THEN
            INSERT INTO hardening_findings
                (host_id, category, control_name, status, severity, evidence, recommendation)
            VALUES
                (
                    p_host_id,
                    'sudo',
                    'passwordless-command',
                    'REVIEW',
                    'medium',
                    sudo_record.subject_name || ' -> ' ||
                    sudo_record.command_pattern,
                    'Verify that passwordless elevation is necessary and tightly constrained.'
                );
        END IF;
    END LOOP;
END;
$$;

CREATE OR REPLACE VIEW host_hardening_summary AS
SELECT
    h.host_id,
    h.hostname,
    h.environment,
    COUNT(f.finding_id) AS finding_count,
    COUNT(*) FILTER (WHERE f.status = 'PASS') AS pass_count,
    COUNT(*) FILTER (WHERE f.status = 'REVIEW') AS review_count,
    COUNT(*) FILTER (WHERE f.status = 'FAIL') AS fail_count,
    COUNT(*) FILTER (WHERE f.status = 'UNKNOWN') AS unknown_count,
    MAX(f.detected_at) AS last_evaluation
FROM hosts h
LEFT JOIN hardening_findings f
    ON f.host_id = h.host_id
GROUP BY h.host_id, h.hostname, h.environment;

CREATE OR REPLACE VIEW failed_controls AS
SELECT
    h.hostname,
    f.category,
    f.control_name,
    f.severity,
    f.evidence,
    f.recommendation,
    f.detected_at
FROM hardening_findings f
JOIN hosts h ON h.host_id = f.host_id
WHERE f.status = 'FAIL'
ORDER BY
    CASE f.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
        ELSE 5
    END,
    f.detected_at DESC;

-- Transactionally evaluate the recorded host state.
BEGIN;

DELETE FROM hardening_findings
WHERE host_id IN (1, 2);

SELECT evaluate_host_hardening(1);
SELECT evaluate_host_hardening(2);

COMMIT;

-- Aggregate hardening posture by host.
SELECT *
FROM host_hardening_summary
ORDER BY fail_count DESC, review_count DESC, hostname;

-- Identify controls that require remediation or investigation.
SELECT
    hostname,
    category,
    control_name,
    severity,
    evidence,
    recommendation
FROM failed_controls;

-- Find potentially dangerous sudo grants.
SELECT
    h.hostname,
    s.subject_name,
    s.run_as_user,
    s.command_pattern,
    s.password_required
FROM sudo_rules s
JOIN hosts h ON h.host_id = s.host_id
WHERE s.enabled
  AND (
      s.command_pattern = 'ALL'
      OR NOT s.password_required
  )
ORDER BY h.hostname, s.subject_name;

-- Verify kernel controls against their expected values.
SELECT
    h.hostname,
    k.control_name,
    k.observed_value,
    k.expected_value,
    k.observed_value = k.expected_value AS compliant
FROM kernel_controls k
JOIN hosts h ON h.host_id = k.host_id
ORDER BY h.hostname, k.control_name;

-- Identify filesystem objects with dangerous world-write permissions.
SELECT
    h.hostname,
    f.path,
    f.mode_octal,
    f.owner_name,
    f.group_name
FROM filesystem_objects f
JOIN hosts h ON h.host_id = f.host_id
WHERE f.world_write
ORDER BY h.hostname, f.path;

-- Verify that audit configurations have persistent rules.
SELECT
    h.hostname,
    a.audit_enabled,
    a.persistent_rules_loaded,
    a.log_directory,
    COUNT(r.audit_rule_id) AS enabled_rule_count
FROM audit_configuration a
JOIN hosts h ON h.host_id = a.host_id
LEFT JOIN audit_rules r
    ON r.host_id = h.host_id
   AND r.enabled
GROUP BY
    h.hostname,
    a.audit_enabled,
    a.persistent_rules_loaded,
    a.log_directory
ORDER BY h.hostname;

-- Transactional example: reject an unsafe shadow-file permission update.
BEGIN;

UPDATE filesystem_objects
SET
    mode_octal = '0644',
    world_read = TRUE
WHERE host_id = 1
  AND path = '/etc/shadow';

-- Detect the unsafe state before committing it.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM filesystem_objects
        WHERE host_id = 1
          AND path = '/etc/shadow'
          AND world_read
    ) THEN
        RAISE EXCEPTION
            'Security policy violation: /etc/shadow must not be world-readable';
    END IF;
END;
$$;

COMMIT;
