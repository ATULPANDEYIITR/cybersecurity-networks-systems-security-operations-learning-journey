-- PostgreSQL-compatible Linux logging laboratory.
--
-- The model deliberately separates:
--   * syslog classification
--   * authentication evidence
--   * kernel events
--   * application events
--   * journal entries
--
-- Database constraints protect relationships and data quality. Analytical
-- views and queries then evaluate operational and security conditions.

DROP SCHEMA IF EXISTS linux_logging_lab CASCADE;
CREATE SCHEMA linux_logging_lab;

SET search_path TO linux_logging_lab;

CREATE TYPE log_severity AS ENUM (
    'emerg',
    'alert',
    'crit',
    'err',
    'warning',
    'notice',
    'info',
    'debug'
);

CREATE TYPE log_facility AS ENUM (
    'kern',
    'user',
    'daemon',
    'auth',
    'syslog',
    'cron',
    'authpriv',
    'local0',
    'local1',
    'local2',
    'local3',
    'local4',
    'local5',
    'local6',
    'local7'
);

CREATE TYPE log_source_type AS ENUM (
    'syslog',
    'journald',
    'authentication',
    'kernel',
    'application'
);

CREATE TYPE authentication_result AS ENUM (
    'success',
    'failure',
    'invalid_user',
    'session_closed'
);

CREATE TABLE hosts (
    host_id BIGSERIAL PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    environment TEXT NOT NULL
        CHECK (environment IN ('development', 'staging', 'production')),
    operating_system TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE services (
    service_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id),
    service_name TEXT NOT NULL,
    service_type TEXT NOT NULL
        CHECK (
            service_type IN (
                'system',
                'authentication',
                'kernel',
                'application'
            )
        ),
    UNIQUE (host_id, service_name)
);

CREATE TABLE log_events (
    event_id BIGSERIAL PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id),
    service_id BIGINT REFERENCES services(service_id),
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_type log_source_type NOT NULL,
    facility log_facility NOT NULL,
    severity log_severity NOT NULL,
    process_id INTEGER CHECK (process_id IS NULL OR process_id > 0),
    message TEXT NOT NULL CHECK (length(trim(message)) > 0),
    source_file TEXT,
    journal_cursor TEXT UNIQUE,
    structured_data JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE authentication_events (
    authentication_event_id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL UNIQUE REFERENCES log_events(event_id)
        ON DELETE CASCADE,
    username TEXT,
    source_ip INET,
    result authentication_result NOT NULL,
    authentication_method TEXT,
    ssh_port INTEGER CHECK (
        ssh_port IS NULL OR ssh_port BETWEEN 1 AND 65535
    )
);

CREATE TABLE kernel_events (
    kernel_event_id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL UNIQUE REFERENCES log_events(event_id)
        ON DELETE CASCADE,
    subsystem TEXT,
    event_category TEXT NOT NULL
        CHECK (
            event_category IN (
                'memory',
                'storage',
                'network',
                'hardware',
                'security',
                'other'
            )
        )
);

CREATE TABLE application_events (
    application_event_id BIGSERIAL PRIMARY KEY,
    event_id BIGINT NOT NULL UNIQUE REFERENCES log_events(event_id)
        ON DELETE CASCADE,
    request_id TEXT,
    route TEXT,
    http_method TEXT,
    http_status INTEGER CHECK (
        http_status IS NULL OR http_status BETWEEN 100 AND 599
    ),
    application_error_code TEXT
);

CREATE INDEX idx_log_events_occurred_at
    ON log_events (occurred_at DESC);

CREATE INDEX idx_log_events_source_severity
    ON log_events (source_type, severity);

CREATE INDEX idx_log_events_service_time
    ON log_events (service_id, occurred_at DESC);

CREATE INDEX idx_authentication_source_ip_time
    ON authentication_events (source_ip, event_id);

CREATE INDEX idx_kernel_category
    ON kernel_events (event_category, event_id);

CREATE INDEX idx_application_request
    ON application_events (request_id)
    WHERE request_id IS NOT NULL;

CREATE INDEX idx_log_events_structured_data
    ON log_events USING GIN (structured_data);

-- PostgreSQL does not store syslog's facility/severity priority as a native
-- field. This generated column makes the standard numeric calculation
-- queryable without duplicating the value in application code.
ALTER TABLE log_events
ADD COLUMN syslog_priority INTEGER GENERATED ALWAYS AS (
    CASE facility
        WHEN 'kern' THEN 0
        WHEN 'user' THEN 1
        WHEN 'daemon' THEN 3
        WHEN 'auth' THEN 4
        WHEN 'syslog' THEN 5
        WHEN 'cron' THEN 9
        WHEN 'authpriv' THEN 10
        WHEN 'local0' THEN 16
        WHEN 'local1' THEN 17
        WHEN 'local2' THEN 18
        WHEN 'local3' THEN 19
        WHEN 'local4' THEN 20
        WHEN 'local5' THEN 21
        WHEN 'local6' THEN 22
        WHEN 'local7' THEN 23
    END * 8
    +
    CASE severity
        WHEN 'emerg' THEN 0
        WHEN 'alert' THEN 1
        WHEN 'crit' THEN 2
        WHEN 'err' THEN 3
        WHEN 'warning' THEN 4
        WHEN 'notice' THEN 5
        WHEN 'info' THEN 6
        WHEN 'debug' THEN 7
    END
) STORED;

INSERT INTO hosts (hostname, environment, operating_system)
VALUES
    ('prod-web-01', 'production', 'Ubuntu Linux'),
    ('prod-db-01', 'production', 'Ubuntu Linux'),
    ('stage-api-01', 'staging', 'Debian Linux');

INSERT INTO services (host_id, service_name, service_type)
SELECT host_id, 'sshd', 'authentication'
FROM hosts
WHERE hostname IN ('prod-web-01', 'prod-db-01');

INSERT INTO services (host_id, service_name, service_type)
SELECT host_id, 'kernel', 'kernel'
FROM hosts;

INSERT INTO services (host_id, service_name, service_type)
SELECT host_id, 'inventory-api', 'application'
FROM hosts
WHERE hostname IN ('prod-web-01', 'stage-api-01');

INSERT INTO services (host_id, service_name, service_type)
SELECT host_id, 'postgres', 'application'
FROM hosts
WHERE hostname = 'prod-db-01';

BEGIN;

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    message,
    source_file,
    structured_data
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:00:00+00:00',
    'authentication',
    'authpriv',
    'warning',
    'Failed password for invalid user admin from 203.0.113.42',
    '/var/log/auth.log',
    jsonb_build_object(
        'program', 'sshd',
        'event', 'authentication_failure'
    )
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'sshd'
WHERE h.hostname = 'prod-web-01';

INSERT INTO authentication_events (
    event_id,
    username,
    source_ip,
    result,
    authentication_method,
    ssh_port
)
VALUES (
    currval('log_events_event_id_seq'),
    'admin',
    '203.0.113.42',
    'invalid_user',
    'password',
    40001
);

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    message,
    source_file,
    structured_data
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:00:10+00:00',
    'authentication',
    'authpriv',
    'warning',
    'Failed password for root from 203.0.113.42',
    '/var/log/auth.log',
    jsonb_build_object(
        'program', 'sshd',
        'event', 'authentication_failure'
    )
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'sshd'
WHERE h.hostname = 'prod-web-01';

INSERT INTO authentication_events (
    event_id,
    username,
    source_ip,
    result,
    authentication_method,
    ssh_port
)
VALUES (
    currval('log_events_event_id_seq'),
    'root',
    '203.0.113.42',
    'failure',
    'password',
    40002
);

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    message,
    source_file,
    structured_data
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:00:20+00:00',
    'authentication',
    'authpriv',
    'info',
    'Accepted publickey for deploy from 10.10.20.15',
    '/var/log/auth.log',
    jsonb_build_object(
        'program', 'sshd',
        'event', 'authentication_success'
    )
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'sshd'
WHERE h.hostname = 'prod-web-01';

INSERT INTO authentication_events (
    event_id,
    username,
    source_ip,
    result,
    authentication_method
)
VALUES (
    currval('log_events_event_id_seq'),
    'deploy',
    '10.10.20.15',
    'success',
    'publickey'
);

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    message,
    source_file
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:01:00+00:00',
    'kernel',
    'kern',
    'err',
    'nvme0: I/O error, aborting command',
    '/var/log/kern.log'
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'kernel'
WHERE h.hostname = 'prod-db-01';

INSERT INTO kernel_events (
    event_id,
    subsystem,
    event_category
)
VALUES (
    currval('log_events_event_id_seq'),
    'nvme',
    'storage'
);

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    process_id,
    message,
    source_file
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:01:10+00:00',
    'kernel',
    'kern',
    'warning',
    8121,
    'Out of memory: Kill process 8121 (postgres)',
    '/var/log/kern.log'
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'kernel'
WHERE h.hostname = 'prod-db-01';

INSERT INTO kernel_events (
    event_id,
    subsystem,
    event_category
)
VALUES (
    currval('log_events_event_id_seq'),
    'memory',
    'memory'
);

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    process_id,
    message,
    source_file,
    structured_data
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:01:30+00:00',
    'application',
    'local0',
    'err',
    9021,
    'database connection pool exhausted',
    '/var/log/inventory-api.json',
    jsonb_build_object(
        'component', 'database',
        'pool_size', 20
    )
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'inventory-api'
WHERE h.hostname = 'prod-web-01';

INSERT INTO application_events (
    event_id,
    request_id,
    route,
    http_method,
    http_status,
    application_error_code
)
VALUES (
    currval('log_events_event_id_seq'),
    'req-8f13',
    '/orders',
    'POST',
    503,
    'DB_POOL_EXHAUSTED'
);

INSERT INTO log_events (
    host_id,
    service_id,
    occurred_at,
    source_type,
    facility,
    severity,
    process_id,
    message,
    source_file,
    structured_data
)
SELECT
    h.host_id,
    s.service_id,
    '2026-10-07T16:02:00+00:00',
    'application',
    'local0',
    'info',
    9021,
    'request completed status=200 route=/health',
    '/var/log/inventory-api.json',
    jsonb_build_object(
        'route', '/health',
        'http_status', 200
    )
FROM hosts h
JOIN services s
    ON s.host_id = h.host_id
   AND s.service_name = 'inventory-api'
WHERE h.hostname = 'prod-web-01';

INSERT INTO application_events (
    event_id,
    request_id,
    route,
    http_method,
    http_status
)
VALUES (
    currval('log_events_event_id_seq'),
    'req-health-01',
    '/health',
    'GET',
    200
);

COMMIT;

-- The authentication view isolates security evidence from general logs.
CREATE VIEW authentication_log_view AS
SELECT
    e.event_id,
    e.occurred_at,
    h.hostname,
    e.severity,
    a.username,
    a.source_ip,
    a.result,
    a.authentication_method,
    a.ssh_port,
    e.message
FROM log_events e
JOIN hosts h ON h.host_id = e.host_id
JOIN authentication_events a ON a.event_id = e.event_id;

-- The kernel view exposes host-level faults without treating application
-- errors as kernel events.
CREATE VIEW kernel_log_view AS
SELECT
    e.event_id,
    e.occurred_at,
    h.hostname,
    k.subsystem,
    k.event_category,
    e.severity,
    e.message
FROM log_events e
JOIN hosts h ON h.host_id = e.host_id
JOIN kernel_events k ON k.event_id = e.event_id;

-- The application view joins operational request information with the
-- originating log record.
CREATE VIEW application_log_view AS
SELECT
    e.event_id,
    e.occurred_at,
    h.hostname,
    s.service_name,
    e.severity,
    a.request_id,
    a.route,
    a.http_method,
    a.http_status,
    a.application_error_code,
    e.message
FROM log_events e
JOIN hosts h ON h.host_id = e.host_id
JOIN services s ON s.service_id = e.service_id
JOIN application_events a ON a.event_id = e.event_id;

-- Authentication source analysis: repeated failures from the same source.
SELECT
    source_ip,
    count(*) AS failed_attempts,
    min(event_id) AS first_event,
    max(event_id) AS last_event
FROM authentication_log_view
WHERE result IN ('failure', 'invalid_user')
GROUP BY source_ip
HAVING count(*) >= 2
ORDER BY failed_attempts DESC;

-- Kernel health analysis identifies storage and memory conditions.
SELECT
    hostname,
    event_category,
    count(*) AS event_count,
    min(occurred_at) AS first_seen,
    max(occurred_at) AS last_seen
FROM kernel_log_view
GROUP BY hostname, event_category
ORDER BY event_count DESC;

-- Application availability analysis identifies non-success HTTP responses.
SELECT
    hostname,
    service_name,
    count(*) FILTER (
        WHERE http_status >= 500
    ) AS server_errors,
    count(*) FILTER (
        WHERE http_status BETWEEN 200 AND 399
    ) AS successful_responses
FROM application_log_view
GROUP BY hostname, service_name
ORDER BY server_errors DESC;

-- Syslog severity/facility analysis.
SELECT
    facility,
    severity,
    syslog_priority,
    count(*) AS event_count
FROM log_events
GROUP BY facility, severity, syslog_priority
ORDER BY syslog_priority ASC;

-- Structured application data can be queried without changing the relational
-- schema for every optional application attribute.
SELECT
    event_id,
    service_id,
    structured_data ->> 'component' AS component,
    structured_data ->> 'pool_size' AS pool_size
FROM log_events
WHERE source_type = 'application'
  AND structured_data ? 'component';

-- Cross-source correlation: an authentication failure followed by an
-- application event from the same source IP within five minutes.
--
-- PostgreSQL's range of timestamp operators makes the temporal relationship
-- explicit rather than treating events as unrelated rows.
SELECT
    a.source_ip,
    a.occurred_at AS authentication_time,
    a.message AS authentication_message,
    e.occurred_at AS application_time,
    e.message AS application_message
FROM authentication_log_view a
JOIN log_events e
    ON e.occurred_at BETWEEN
        a.occurred_at AND
        a.occurred_at + INTERVAL '5 minutes'
JOIN application_events ae
    ON ae.event_id = e.event_id
WHERE a.result IN ('failure', 'invalid_user')
ORDER BY a.occurred_at;

-- A transaction demonstrates that an event and its specialized record should
-- be committed together. If the specialized insert fails, both inserts can
-- be rolled back.
BEGIN;

WITH inserted_event AS (
    INSERT INTO log_events (
        host_id,
        service_id,
        occurred_at,
        source_type,
        facility,
        severity,
        message,
        source_file
    )
    SELECT
        h.host_id,
        s.service_id,
        now(),
        'authentication',
        'authpriv',
        'warning',
        'Failed password for test-user from 192.0.2.200',
        '/var/log/auth.log'
    FROM hosts h
    JOIN services s
        ON s.host_id = h.host_id
       AND s.service_name = 'sshd'
    WHERE h.hostname = 'prod-web-01'
    RETURNING event_id
)
INSERT INTO authentication_events (
    event_id,
    username,
    source_ip,
    result,
    authentication_method
)
SELECT
    event_id,
    'test-user',
    '192.0.2.200',
    'failure',
    'password'
FROM inserted_event;

COMMIT;

-- Retention preview. Real deployments normally apply retention according to
-- operational, legal, and security requirements rather than deleting logs
-- solely because they are old.
SELECT
    count(*) AS events_older_than_30_days
FROM log_events
WHERE occurred_at < now() - INTERVAL '30 days';

-- A practical query for high-priority operational events.
SELECT
    e.event_id,
    h.hostname,
    e.occurred_at,
    e.source_type,
    e.facility,
    e.severity,
    e.syslog_priority,
    e.message
FROM log_events e
JOIN hosts h ON h.host_id = e.host_id
WHERE e.severity IN ('emerg', 'alert', 'crit', 'err')
ORDER BY e.occurred_at DESC;

-- Demonstration of database-level integrity: this statement is intentionally
-- commented because executing it would violate the positive PID constraint.
--
-- INSERT INTO log_events (
--     host_id, occurred_at, source_type, facility, severity,
--     process_id, message
-- )
-- VALUES (
--     1, now(), 'application', 'local0', 'info',
--     -42, 'invalid process identifier'
-- );
--
-- PostgreSQL rejects the row through CHECK (process_id IS NULL OR process_id > 0).

-- Another integrity rule: authentication data cannot point at a nonexistent
-- log event because authentication_events.event_id is a foreign key.
--
-- INSERT INTO authentication_events (
--     event_id, username, source_ip, result
-- )
-- VALUES (
--     999999999, 'ghost', '192.0.2.9', 'failure'
-- );
--
-- The foreign key prevents orphan authentication records.
