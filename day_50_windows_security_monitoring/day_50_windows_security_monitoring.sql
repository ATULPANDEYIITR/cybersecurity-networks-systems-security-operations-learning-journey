DROP SCHEMA IF EXISTS windows_security_monitor CASCADE;
CREATE SCHEMA windows_security_monitor;
SET search_path TO windows_security_monitor;

-- The model stores normalized security telemetry rather than raw localized
-- Windows event messages. This keeps detection rules deterministic.

CREATE TABLE computers (
    computer_id      BIGSERIAL PRIMARY KEY,
    hostname         TEXT NOT NULL UNIQUE,
    domain_name      TEXT,
    operating_system TEXT NOT NULL DEFAULT 'Windows',
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE accounts (
    account_id       BIGSERIAL PRIMARY KEY,
    username         TEXT NOT NULL,
    domain_name      TEXT,
    account_type     TEXT NOT NULL CHECK (
        account_type IN ('user', 'service', 'computer', 'system')
    ),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    privileged       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (domain_name, username)
);

CREATE TABLE security_events (
    event_id         BIGSERIAL PRIMARY KEY,
    windows_event_id INTEGER NOT NULL CHECK (windows_event_id > 0),
    computer_id      BIGINT NOT NULL REFERENCES computers(computer_id),
    subject_account  BIGINT REFERENCES accounts(account_id),
    target_account   BIGINT REFERENCES accounts(account_id),
    event_time       TIMESTAMPTZ NOT NULL,
    source_ip        INET,
    process_name     TEXT,
    process_id       INTEGER CHECK (process_id IS NULL OR process_id > 0),
    logon_type       INTEGER CHECK (logon_type IS NULL OR logon_type >= 0),
    privilege_name   TEXT,
    message          TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE account_activity (
    activity_id      BIGSERIAL PRIMARY KEY,
    event_id         BIGINT NOT NULL UNIQUE
                     REFERENCES security_events(event_id),
    action           TEXT NOT NULL CHECK (
        action IN (
            'created',
            'enabled',
            'disabled',
            'deleted',
            'changed',
            'locked'
        )
    ),
    target_account   BIGINT REFERENCES accounts(account_id)
);

CREATE TABLE status_checks (
    status_check_id  BIGSERIAL PRIMARY KEY,
    event_id         BIGINT REFERENCES security_events(event_id),
    check_name       TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (
        status IN ('success', 'failure', 'unknown')
    ),
    observed_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE detection_rules (
    rule_id          BIGSERIAL PRIMARY KEY,
    rule_name        TEXT NOT NULL UNIQUE,
    severity         TEXT NOT NULL CHECK (
        severity IN ('low', 'medium', 'high')
    ),
    enabled          BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE alerts (
    alert_id         BIGSERIAL PRIMARY KEY,
    rule_id          BIGINT NOT NULL REFERENCES detection_rules(rule_id),
    event_id         BIGINT REFERENCES security_events(event_id),
    computer_id      BIGINT REFERENCES computers(computer_id),
    account_id       BIGINT REFERENCES accounts(account_id),
    severity         TEXT NOT NULL CHECK (
        severity IN ('low', 'medium', 'high')
    ),
    evidence         TEXT NOT NULL,
    detected_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at      TIMESTAMPTZ
);

CREATE INDEX idx_security_events_time
    ON security_events (event_time DESC);

CREATE INDEX idx_security_events_event_time
    ON security_events (windows_event_id, event_time DESC);

CREATE INDEX idx_security_events_target_time
    ON security_events (target_account, event_time DESC)
    WHERE target_account IS NOT NULL;

CREATE INDEX idx_security_events_source_time
    ON security_events (source_ip, event_time DESC)
    WHERE source_ip IS NOT NULL;

CREATE INDEX idx_alerts_open
    ON alerts (detected_at DESC)
    WHERE resolved_at IS NULL;

INSERT INTO computers (hostname, domain_name)
VALUES
    ('WS-01', 'CORP'),
    ('DC-01', 'CORP');

INSERT INTO accounts (
    username, domain_name, account_type, enabled, privileged
)
VALUES
    ('SYSTEM', 'NT AUTHORITY', 'system', TRUE, TRUE),
    ('alice', 'CORP', 'user', TRUE, FALSE),
    ('scanner', 'CORP', 'service', TRUE, FALSE),
    ('administrator', 'CORP', 'user', TRUE, TRUE),
    ('admin', 'CORP', 'user', TRUE, TRUE),
    ('backupsvc', 'CORP', 'service', TRUE, FALSE);

INSERT INTO detection_rules (rule_name, severity)
VALUES
    ('failed_logon_burst', 'high'),
    ('special_privilege_assignment', 'medium'),
    ('script_interpreter_process', 'medium'),
    ('privileged_interactive_logon', 'high'),
    ('account_activity', 'medium');

CREATE OR REPLACE FUNCTION validate_security_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.windows_event_id IN (4624, 4625)
       AND NEW.target_account IS NULL THEN
        RAISE EXCEPTION
            'Logon event % requires target_account',
            NEW.windows_event_id;
    END IF;

    IF NEW.windows_event_id = 4688
       AND NEW.process_name IS NULL THEN
        RAISE EXCEPTION
            'Process creation event requires process_name';
    END IF;

    IF NEW.windows_event_id = 4672
       AND NEW.privilege_name IS NULL THEN
        RAISE EXCEPTION
            'Privilege event requires privilege_name';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_security_event
BEFORE INSERT OR UPDATE ON security_events
FOR EACH ROW
EXECUTE FUNCTION validate_security_event();

CREATE OR REPLACE FUNCTION record_account_activity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    activity_action TEXT;
BEGIN
    activity_action := CASE NEW.windows_event_id
        WHEN 4720 THEN 'created'
        WHEN 4722 THEN 'enabled'
        WHEN 4725 THEN 'disabled'
        WHEN 4726 THEN 'deleted'
        WHEN 4738 THEN 'changed'
        WHEN 4740 THEN 'locked'
        ELSE NULL
    END;

    IF activity_action IS NOT NULL THEN
        INSERT INTO account_activity (
            event_id, action, target_account
        )
        VALUES (
            NEW.event_id,
            activity_action,
            NEW.target_account
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_record_account_activity
AFTER INSERT ON security_events
FOR EACH ROW
EXECUTE FUNCTION record_account_activity();

CREATE OR REPLACE VIEW v_security_event_detail AS
SELECT
    e.event_id,
    e.windows_event_id,
    e.event_time,
    c.hostname,
    sa.username AS subject_user,
    ta.username AS target_user,
    e.source_ip,
    e.process_name,
    e.process_id,
    e.logon_type,
    e.privilege_name,
    e.message
FROM security_events e
JOIN computers c
  ON c.computer_id = e.computer_id
LEFT JOIN accounts sa
  ON sa.account_id = e.subject_account
LEFT JOIN accounts ta
  ON ta.account_id = e.target_account;

CREATE OR REPLACE VIEW v_open_alerts AS
SELECT
    a.alert_id,
    r.rule_name,
    a.severity,
    a.detected_at,
    c.hostname,
    acc.username,
    a.evidence
FROM alerts a
JOIN detection_rules r
  ON r.rule_id = a.rule_id
LEFT JOIN computers c
  ON c.computer_id = a.computer_id
LEFT JOIN accounts acc
  ON acc.account_id = a.account_id
WHERE a.resolved_at IS NULL;

BEGIN;

-- Successful interactive logon.
INSERT INTO security_events (
    windows_event_id,
    computer_id,
    subject_account,
    target_account,
    event_time,
    source_ip,
    logon_type
)
SELECT
    4624,
    c.computer_id,
    subject.account_id,
    target.account_id,
    '2026-10-20 05:00:00+00',
    '10.10.1.20',
    2
FROM computers c
JOIN accounts subject
  ON subject.username = 'SYSTEM'
 AND subject.domain_name = 'NT AUTHORITY'
JOIN accounts target
  ON target.username = 'alice'
 AND target.domain_name = 'CORP'
WHERE c.hostname = 'WS-01';

-- Special privilege assignment.
INSERT INTO security_events (
    windows_event_id,
    computer_id,
    subject_account,
    event_time,
    privilege_name
)
SELECT
    4672,
    c.computer_id,
    a.account_id,
    '2026-10-20 05:02:00+00',
    'SeDebugPrivilege'
FROM computers c
JOIN accounts a
  ON a.username = 'alice'
 AND a.domain_name = 'CORP'
WHERE c.hostname = 'WS-01';

-- Process creation immediately after privilege assignment.
INSERT INTO security_events (
    windows_event_id,
    computer_id,
    subject_account,
    event_time,
    process_name,
    process_id
)
SELECT
    4688,
    c.computer_id,
    a.account_id,
    '2026-10-20 05:02:30+00',
    'powershell.exe',
    2120
FROM computers c
JOIN accounts a
  ON a.username = 'alice'
 AND a.domain_name = 'CORP'
WHERE c.hostname = 'WS-01';

-- Three failed remote logons within five minutes.
INSERT INTO security_events (
    windows_event_id,
    computer_id,
    subject_account,
    target_account,
    event_time,
    source_ip,
    logon_type
)
SELECT
    4625,
    c.computer_id,
    scanner.account_id,
    admin.account_id,
    sample.event_time,
    '10.10.1.90',
    10
FROM computers c
JOIN accounts scanner
  ON scanner.username = 'scanner'
 AND scanner.domain_name = 'CORP'
JOIN accounts admin
  ON admin.username = 'administrator'
 AND admin.domain_name = 'CORP'
CROSS JOIN (
    VALUES
        ('2026-10-20 05:03:00+00'::timestamptz),
        ('2026-10-20 05:04:00+00'::timestamptz),
        ('2026-10-20 05:05:00+00'::timestamptz)
) AS sample(event_time)
WHERE c.hostname = 'WS-01';

-- Account creation and enablement.
INSERT INTO security_events (
    windows_event_id,
    computer_id,
    subject_account,
    target_account,
    event_time,
    message
)
SELECT
    4720,
    c.computer_id,
    admin.account_id,
    backup.account_id,
    '2026-10-20 05:07:00+00',
    'Service account created'
FROM computers c
JOIN accounts admin
  ON admin.username = 'admin'
 AND admin.domain_name = 'CORP'
JOIN accounts backup
  ON backup.username = 'backupsvc'
 AND backup.domain_name = 'CORP'
WHERE c.hostname = 'DC-01';

INSERT INTO security_events (
    windows_event_id,
    computer_id,
    subject_account,
    target_account,
    event_time
)
SELECT
    4722,
    c.computer_id,
    admin.account_id,
    backup.account_id,
    '2026-10-20 05:08:00+00'
FROM computers c
JOIN accounts admin
  ON admin.username = 'admin'
 AND admin.domain_name = 'CORP'
JOIN accounts backup
  ON backup.username = 'backupsvc'
 AND backup.domain_name = 'CORP'
WHERE c.hostname = 'DC-01';

COMMIT;

-- Failed-logon burst detection uses a window function rather than assuming
-- that every failed logon is malicious.
WITH failed AS (
    SELECT
        e.event_id,
        e.event_time,
        e.computer_id,
        e.target_account,
        e.source_ip,
        COUNT(*) OVER (
            PARTITION BY e.target_account
            ORDER BY e.event_time
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING
                  AND CURRENT ROW
        ) AS failures_in_window
    FROM security_events e
    WHERE e.windows_event_id = 4625
)
SELECT
    event_id,
    event_time,
    target_account,
    source_ip,
    failures_in_window
FROM failed
WHERE failures_in_window >= 3
ORDER BY event_time;

-- Identify high-risk privilege assignments.
SELECT
    e.event_id,
    e.event_time,
    c.hostname,
    a.username,
    e.privilege_name
FROM security_events e
JOIN computers c
  ON c.computer_id = e.computer_id
JOIN accounts a
  ON a.account_id = e.subject_account
WHERE e.windows_event_id = 4672
  AND lower(e.privilege_name) LIKE '%debug%'
ORDER BY e.event_time DESC;

-- Find script interpreters started by users after special-privilege events.
SELECT
    process_event.event_time AS process_time,
    c.hostname,
    account.username,
    process_event.process_name,
    privilege_event.event_time AS privilege_time,
    privilege_event.privilege_name
FROM security_events process_event
JOIN security_events privilege_event
  ON privilege_event.computer_id = process_event.computer_id
 AND privilege_event.subject_account = process_event.subject_account
 AND privilege_event.windows_event_id = 4672
 AND process_event.event_time >= privilege_event.event_time
 AND process_event.event_time <=
     privilege_event.event_time + INTERVAL '1 minute'
JOIN computers c
  ON c.computer_id = process_event.computer_id
JOIN accounts account
  ON account.account_id = process_event.subject_account
WHERE process_event.windows_event_id = 4688
  AND lower(process_event.process_name) IN (
      'powershell.exe',
      'cmd.exe',
      'wscript.exe',
      'cscript.exe',
      'mshta.exe',
      'rundll32.exe',
      'regsvr32.exe',
      'certutil.exe'
  )
ORDER BY process_event.event_time;

-- Detect privileged interactive logons.
SELECT
    e.event_id,
    e.event_time,
    c.hostname,
    account.username,
    e.logon_type,
    e.source_ip
FROM security_events e
JOIN computers c
  ON c.computer_id = e.computer_id
JOIN accounts account
  ON account.account_id = e.target_account
WHERE e.windows_event_id = 4624
  AND e.logon_type IN (2, 10, 11)
  AND account.privileged = TRUE
ORDER BY e.event_time DESC;

-- Aggregate account activity for an operational dashboard.
SELECT
    c.hostname,
    aa.action,
    COUNT(*) AS activity_count,
    MAX(e.event_time) AS latest_event
FROM account_activity aa
JOIN security_events e
  ON e.event_id = aa.event_id
JOIN computers c
  ON c.computer_id = e.computer_id
GROUP BY c.hostname, aa.action
ORDER BY latest_event DESC;

-- Transactional alert creation keeps the detection decision and evidence
-- insertion atomic.
BEGIN;

INSERT INTO alerts (
    rule_id,
    event_id,
    computer_id,
    account_id,
    severity,
    evidence
)
SELECT
    r.rule_id,
    f.event_id,
    f.computer_id,
    f.target_account,
    r.severity,
    f.failures_in_window ||
        ' failed logons within five minutes from source ' ||
        f.source_ip::text
FROM (
    SELECT
        e.*,
        COUNT(*) OVER (
            PARTITION BY e.target_account
            ORDER BY e.event_time
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING
                  AND CURRENT ROW
        ) AS failures_in_window
    FROM security_events e
    WHERE e.windows_event_id = 4625
) f
JOIN detection_rules r
  ON r.rule_name = 'failed_logon_burst'
 AND r.enabled
WHERE f.failures_in_window >= 3
  AND NOT EXISTS (
      SELECT 1
      FROM alerts existing
      WHERE existing.rule_id = r.rule_id
        AND existing.event_id = f.event_id
  );

COMMIT;

SELECT *
FROM v_security_event_detail
ORDER BY event_time;

SELECT *
FROM v_open_alerts
ORDER BY detected_at DESC;
