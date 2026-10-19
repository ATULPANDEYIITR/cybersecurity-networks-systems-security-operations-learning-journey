-- PostgreSQL model for Windows Event Log security monitoring.
-- The schema distinguishes Security, System, Application and PowerShell
-- channels while retaining authentication, reviewable evidence and
-- database-enforced integrity rules.

DROP SCHEMA IF EXISTS windows_event_monitor CASCADE;
CREATE SCHEMA windows_event_monitor;

SET search_path TO windows_event_monitor;

CREATE TYPE event_channel AS ENUM (
    'Security',
    'System',
    'Application',
    'PowerShell'
);

CREATE TYPE event_severity AS ENUM (
    'Informational',
    'Warning',
    'Critical'
);

CREATE TABLE computers (
    computer_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    operating_system TEXT NOT NULL,
    environment TEXT NOT NULL CHECK (
        environment IN ('Production', 'Development', 'Test')
    )
);

CREATE TABLE users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    account_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    service_account BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE windows_events (
    event_pk BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    record_id BIGINT NOT NULL,
    computer_id BIGINT NOT NULL REFERENCES computers(computer_id),
    user_id BIGINT REFERENCES users(user_id),
    channel event_channel NOT NULL,
    provider TEXT NOT NULL,
    event_id INTEGER NOT NULL CHECK (event_id >= 0),
    severity event_severity NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    source_ip INET,
    message TEXT NOT NULL,
    event_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (computer_id, channel, record_id),

    -- Failed authentication without a source address is deliberately
    -- rejected because source correlation is a required investigation field.
    CHECK (
        event_id <> 4625
        OR source_ip IS NOT NULL
    ),

    -- Authentication events need an associated account when the normalized
    -- record is stored.
    CHECK (
        event_id NOT IN (4624, 4625, 4672)
        OR user_id IS NOT NULL
    )
);

CREATE TABLE authentication_events (
    event_pk BIGINT PRIMARY KEY
        REFERENCES windows_events(event_pk) ON DELETE CASCADE,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('Success', 'Failure', 'PrivilegeAssignment')
    ),
    logon_type TEXT,
    authentication_package TEXT,
    status_code TEXT
);

CREATE TABLE powershell_events (
    event_pk BIGINT PRIMARY KEY
        REFERENCES windows_events(event_pk) ON DELETE CASCADE,
    script_block_text TEXT,
    command_name TEXT,
    engine_version TEXT
);

CREATE TABLE security_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_pk BIGINT REFERENCES windows_events(event_pk),
    rule_name TEXT NOT NULL,
    severity event_severity NOT NULL,
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX idx_events_time
    ON windows_events (event_time DESC);

CREATE INDEX idx_events_channel_event
    ON windows_events (channel, event_id, event_time DESC);

CREATE INDEX idx_events_source_ip
    ON windows_events (source_ip, event_time DESC)
    WHERE source_ip IS NOT NULL;

CREATE INDEX idx_events_user_auth
    ON windows_events (user_id, event_id, event_time DESC)
    WHERE event_id IN (4624, 4625, 4672);

CREATE INDEX idx_powershell_script_blocks
    ON powershell_events (event_pk)
    WHERE script_block_text IS NOT NULL;

INSERT INTO computers (hostname, operating_system, environment)
VALUES
    ('WS-101', 'Windows 11 Enterprise', 'Production'),
    ('APP-201', 'Windows Server 2022', 'Production');

INSERT INTO users (username, account_enabled, service_account)
VALUES
    ('alice', TRUE, FALSE),
    ('administrator', TRUE, FALSE),
    ('svc_inventory', TRUE, TRUE),
    ('SYSTEM', TRUE, TRUE);

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1001,
    c.computer_id,
    u.user_id,
    'Security',
    'Microsoft-Windows-Security-Auditing',
    4624,
    'Informational',
    '2026-10-19 05:00:00+00',
    '10.10.20.50',
    'Successful interactive authentication',
    '{"LogonType":"10","AuthenticationPackage":"Negotiate"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'alice';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1002,
    c.computer_id,
    u.user_id,
    'Security',
    'Microsoft-Windows-Security-Auditing',
    4625,
    'Warning',
    '2026-10-19 05:01:00+00',
    '10.10.20.88',
    'Failed authentication',
    '{"Status":"0xC000006D","LogonType":"3"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'administrator';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1003,
    c.computer_id,
    u.user_id,
    'Security',
    'Microsoft-Windows-Security-Auditing',
    4625,
    'Warning',
    '2026-10-19 05:01:20+00',
    '10.10.20.88',
    'Failed authentication',
    '{"Status":"0xC000006D","LogonType":"3"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'administrator';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1004,
    c.computer_id,
    u.user_id,
    'Security',
    'Microsoft-Windows-Security-Auditing',
    4625,
    'Warning',
    '2026-10-19 05:01:40+00',
    '10.10.20.88',
    'Failed authentication',
    '{"Status":"0xC000006D","LogonType":"3"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'administrator';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1005,
    c.computer_id,
    u.user_id,
    'Security',
    'Microsoft-Windows-Security-Auditing',
    1102,
    'Critical',
    '2026-10-19 05:03:00+00',
    NULL,
    'Security audit log was cleared',
    '{"Action":"AuditLogCleared"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'administrator';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1006,
    c.computer_id,
    u.user_id,
    'System',
    'Service Control Manager',
    7045,
    'Critical',
    '2026-10-19 05:04:00+00',
    NULL,
    'RemoteSupport service installed',
    '{"ServiceName":"RemoteSupport","ImagePath":"C:\\ProgramData\\support.exe"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'SYSTEM';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1007,
    c.computer_id,
    u.user_id,
    'PowerShell',
    'Microsoft-Windows-PowerShell',
    4104,
    'Informational',
    '2026-10-19 05:05:00+00',
    NULL,
    'PowerShell script block recorded',
    '{"Command":"Get-Process; Get-Service"}'
FROM computers c, users u
WHERE c.hostname = 'WS-101'
  AND u.username = 'alice';

INSERT INTO windows_events (
    record_id, computer_id, user_id, channel, provider, event_id,
    severity, event_time, source_ip, message, event_data
)
SELECT
    1008,
    c.computer_id,
    u.user_id,
    'Application',
    'Windows Error Reporting',
    1001,
    'Warning',
    '2026-10-19 05:06:00+00',
    NULL,
    'Application crash: inventory.exe',
    '{"Application":"inventory.exe","FaultModule":"inventory.dll"}'
FROM computers c, users u
WHERE c.hostname = 'APP-201'
  AND u.username = 'svc_inventory';

INSERT INTO authentication_events (
    event_pk, outcome, logon_type, authentication_package, status_code
)
SELECT
    event_pk,
    CASE event_id
        WHEN 4624 THEN 'Success'
        WHEN 4625 THEN 'Failure'
        WHEN 4672 THEN 'PrivilegeAssignment'
    END,
    event_data->>'LogonType',
    event_data->>'AuthenticationPackage',
    event_data->>'Status'
FROM windows_events
WHERE event_id IN (4624, 4625, 4672);

INSERT INTO powershell_events (
    event_pk, script_block_text, command_name, engine_version
)
SELECT
    event_pk,
    event_data->>'Command',
    NULL,
    NULL
FROM windows_events
WHERE channel = 'PowerShell'
  AND event_id = 4104;

-- Authentication concentration by account and source.
WITH failures AS (
    SELECT
        u.username,
        e.source_ip,
        COUNT(*) AS failure_count,
        MIN(e.event_time) AS first_failure,
        MAX(e.event_time) AS last_failure
    FROM windows_events e
    JOIN users u ON u.user_id = e.user_id
    WHERE e.event_id = 4625
    GROUP BY u.username, e.source_ip
)
SELECT
    username,
    source_ip,
    failure_count,
    first_failure,
    last_failure,
    CASE
        WHEN failure_count >= 3 THEN 'Investigate'
        ELSE 'Normal'
    END AS assessment
FROM failures
ORDER BY failure_count DESC;

-- Security events whose presence changes the integrity of the audit trail.
SELECT
    e.event_time,
    c.hostname,
    u.username,
    e.event_id,
    e.message
FROM windows_events e
JOIN computers c ON c.computer_id = e.computer_id
LEFT JOIN users u ON u.user_id = e.user_id
WHERE e.channel = 'Security'
  AND e.event_id = 1102
ORDER BY e.event_time DESC;

-- PowerShell script-block telemetry is retained separately so analysts can
-- query execution evidence without treating every PowerShell event as hostile.
SELECT
    e.event_time,
    c.hostname,
    u.username,
    p.script_block_text
FROM powershell_events p
JOIN windows_events e ON e.event_pk = p.event_pk
JOIN computers c ON c.computer_id = e.computer_id
LEFT JOIN users u ON u.user_id = e.user_id
ORDER BY e.event_time DESC;

-- Cross-channel incident view.
SELECT
    e.event_time,
    c.hostname,
    e.channel,
    e.event_id,
    e.severity,
    u.username,
    e.source_ip,
    e.message
FROM windows_events e
JOIN computers c ON c.computer_id = e.computer_id
LEFT JOIN users u ON u.user_id = e.user_id
WHERE e.event_time >= '2026-10-19 05:00:00+00'
ORDER BY e.event_time;

-- Transactional finding creation demonstrates that a detection result and
-- its evidence can be committed atomically.
BEGIN;

INSERT INTO security_findings (
    event_pk,
    rule_name,
    severity,
    evidence
)
SELECT
    e.event_pk,
    'Security audit log cleared',
    'Critical',
    jsonb_build_object(
        'record_id', e.record_id,
        'username', u.username,
        'event_id', e.event_id
    )
FROM windows_events e
LEFT JOIN users u ON u.user_id = e.user_id
WHERE e.event_id = 1102;

COMMIT;

-- Database-enforced validation can be demonstrated safely with a transaction.
-- The statement below is intentionally not executed because it would violate
-- the 4625 source-IP CHECK constraint. An application can test the same rule
-- by attempting the INSERT and handling SQLSTATE 23514.
--
-- INSERT INTO windows_events (
--     record_id, computer_id, user_id, channel, provider, event_id,
--     severity, event_time, message
-- )
-- SELECT
--     9999, computer_id, user_id, 'Security',
--     'Microsoft-Windows-Security-Auditing', 4625,
--     'Warning', clock_timestamp(), 'Invalid authentication record'
-- FROM computers c, users u
-- WHERE c.hostname = 'WS-101' AND u.username = 'administrator';
