/*
    SIEM QUERYING AND SECURITY ANALYTICS
    PostgreSQL 15+

    Scope:
    1. Event ingestion and validation
    2. Indexed security-event retrieval
    3. Filtering and aggregation
    4. Timeline analysis
    5. Field analysis
    6. Failed-login detection
    7. Detection alert management
    8. Reporting and query optimization

    Execute as a database owner in a dedicated learning database.
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS siem;

SET search_path TO siem, public;

-- ============================================================
-- 1. DOMAIN TYPES
-- ============================================================

DO $$
BEGIN
    CREATE TYPE event_severity AS ENUM (
        'INFO',
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    CREATE TYPE alert_status AS ENUM (
        'OPEN',
        'INVESTIGATING',
        'CONFIRMED',
        'FALSE_POSITIVE',
        'CLOSED'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- ============================================================
-- 2. EVENT SOURCE REGISTRY
-- ============================================================

CREATE TABLE IF NOT EXISTS event_sources (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name VARCHAR(100) NOT NULL UNIQUE,
    source_type VARCHAR(50) NOT NULL,
    environment VARCHAR(30) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_source_type
        CHECK (source_type IN (
            'FIREWALL',
            'IDS',
            'ENDPOINT',
            'AUTHENTICATION',
            'APPLICATION',
            'CLOUD'
        ))
);

-- ============================================================
-- 3. SECURITY EVENTS
-- ============================================================

CREATE TABLE IF NOT EXISTS security_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    external_event_id VARCHAR(128) NOT NULL UNIQUE,

    event_timestamp TIMESTAMPTZ NOT NULL,

    ingestion_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,

    username VARCHAR(255) NOT NULL,

    event_type VARCHAR(80) NOT NULL,

    severity event_severity NOT NULL,

    action VARCHAR(80) NOT NULL,

    source_id BIGINT NOT NULL
        REFERENCES event_sources(source_id),

    raw_fields JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_username
        CHECK (LENGTH(TRIM(username)) > 0),

    CONSTRAINT valid_event_type
        CHECK (LENGTH(TRIM(event_type)) > 0),

    CONSTRAINT valid_action
        CHECK (LENGTH(TRIM(action)) > 0),

    CONSTRAINT valid_raw_fields
        CHECK (jsonb_typeof(raw_fields) = 'object')
);

-- ============================================================
-- 4. INDEXING
-- ============================================================

-- Efficient timestamp range scans.
CREATE INDEX IF NOT EXISTS idx_events_timestamp
    ON security_events(event_timestamp DESC);

-- Common investigation filters.
CREATE INDEX IF NOT EXISTS idx_events_severity_timestamp
    ON security_events(severity, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_source_ip_timestamp
    ON security_events(source_ip, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_username_timestamp
    ON security_events(username, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_type_timestamp
    ON security_events(event_type, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_source_action
    ON security_events(source_id, action);

-- JSONB containment and key-existence queries.
CREATE INDEX IF NOT EXISTS idx_events_raw_fields
    ON security_events USING GIN(raw_fields);

-- Partial index for failed authentication investigations.
CREATE INDEX IF NOT EXISTS idx_failed_authentication
    ON security_events(
        source_ip,
        username,
        event_timestamp
    )
    WHERE event_type = 'authentication'
      AND action = 'failure';

-- ============================================================
-- 5. DETECTION RULES
-- ============================================================

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_name VARCHAR(150) NOT NULL UNIQUE,

    event_type VARCHAR(80) NOT NULL,

    threshold_count INTEGER NOT NULL,

    window_seconds INTEGER NOT NULL,

    minimum_severity event_severity NOT NULL DEFAULT 'HIGH',

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_threshold
        CHECK (threshold_count > 0),

    CONSTRAINT valid_window
        CHECK (window_seconds > 0)
);

-- ============================================================
-- 6. DETECTION ALERTS
-- ============================================================

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_id BIGINT NOT NULL
        REFERENCES detection_rules(rule_id),

    source_ip INET NOT NULL,

    username VARCHAR(255) NOT NULL,

    attempt_count INTEGER NOT NULL,

    first_seen TIMESTAMPTZ NOT NULL,

    last_seen TIMESTAMPTZ NOT NULL,

    severity event_severity NOT NULL,

    status alert_status NOT NULL DEFAULT 'OPEN',

    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    assigned_to VARCHAR(100),

    analyst_notes TEXT NOT NULL DEFAULT '',

    CONSTRAINT valid_attempt_count
        CHECK (attempt_count > 0),

    CONSTRAINT valid_alert_window
        CHECK (first_seen <= last_seen)
);

CREATE INDEX IF NOT EXISTS idx_alert_status
    ON security_alerts(status, severity, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_alert_identity
    ON security_alerts(source_ip, username);

-- ============================================================
-- 7. EVENT VALIDATION TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION validate_security_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM event_sources
        WHERE source_id = NEW.source_id
          AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION
            'Event source % does not exist or is disabled',
            NEW.source_id;
    END IF;

    IF NEW.ingestion_timestamp < NEW.event_timestamp
       - INTERVAL '30 days' THEN
        RAISE EXCEPTION
            'Event timestamp exceeds allowed historical range';
    END IF;

    IF NEW.event_timestamp > NEW.ingestion_timestamp
       + INTERVAL '5 minutes' THEN
        RAISE EXCEPTION
            'Event timestamp exceeds permitted future tolerance';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_security_event
ON security_events;

CREATE TRIGGER trg_validate_security_event
BEFORE INSERT OR UPDATE ON security_events
FOR EACH ROW
EXECUTE FUNCTION validate_security_event();

-- ============================================================
-- 8. EVENT INGESTION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION ingest_security_event(
    p_external_event_id VARCHAR,
    p_event_timestamp TIMESTAMPTZ,
    p_source_ip INET,
    p_destination_ip INET,
    p_username VARCHAR,
    p_event_type VARCHAR,
    p_severity event_severity,
    p_action VARCHAR,
    p_source_id BIGINT,
    p_raw_fields JSONB DEFAULT '{}'::JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    inserted_id BIGINT;
BEGIN
    INSERT INTO security_events (
        external_event_id,
        event_timestamp,
        source_ip,
        destination_ip,
        username,
        event_type,
        severity,
        action,
        source_id,
        raw_fields
    )
    VALUES (
        p_external_event_id,
        p_event_timestamp,
        p_source_ip,
        p_destination_ip,
        p_username,
        p_event_type,
        p_severity,
        p_action,
        p_source_id,
        COALESCE(p_raw_fields, '{}'::JSONB)
    )
    RETURNING event_id INTO inserted_id;

    RETURN inserted_id;
END;
$$;

-- ============================================================
-- 9. SAMPLE EVENT SOURCES AND DETECTION RULE
-- ============================================================

INSERT INTO event_sources (
    source_name,
    source_type,
    environment
)
VALUES
    ('Corporate Firewall', 'FIREWALL', 'PRODUCTION'),
    ('Network IDS', 'IDS', 'PRODUCTION'),
    ('Endpoint Monitor', 'ENDPOINT', 'PRODUCTION')
ON CONFLICT (source_name) DO NOTHING;

INSERT INTO detection_rules (
    rule_name,
    event_type,
    threshold_count,
    window_seconds,
    minimum_severity
)
VALUES (
    'Repeated Failed Authentication',
    'authentication',
    5,
    600,
    'HIGH'
)
ON CONFLICT (rule_name) DO NOTHING;

-- ============================================================
-- 10. SAMPLE SECURITY EVENTS
-- ============================================================

DO $$
DECLARE
    firewall_id BIGINT;
    ids_id BIGINT;
    endpoint_id BIGINT;
    base_time TIMESTAMPTZ := '2026-11-25 02:30:00+00';
BEGIN
    SELECT source_id INTO firewall_id
    FROM event_sources
    WHERE source_name = 'Corporate Firewall';

    SELECT source_id INTO ids_id
    FROM event_sources
    WHERE source_name = 'Network IDS';

    SELECT source_id INTO endpoint_id
    FROM event_sources
    WHERE source_name = 'Endpoint Monitor';

    INSERT INTO security_events (
        external_event_id,
        event_timestamp,
        source_ip,
        destination_ip,
        username,
        event_type,
        severity,
        action,
        source_id,
        raw_fields
    )
    VALUES
    (
        'E001', base_time,
        '192.168.1.10', '10.0.0.5',
        'admin', 'authentication', 'HIGH',
        'failure', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    ),
    (
        'E002', base_time + INTERVAL '1 minute',
        '192.168.1.10', '10.0.0.5',
        'admin', 'authentication', 'HIGH',
        'failure', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    ),
    (
        'E003', base_time + INTERVAL '2 minutes',
        '192.168.1.10', '10.0.0.5',
        'admin', 'authentication', 'HIGH',
        'failure', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    ),
    (
        'E004', base_time + INTERVAL '3 minutes',
        '192.168.1.10', '10.0.0.5',
        'admin', 'authentication', 'HIGH',
        'failure', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    ),
    (
        'E005', base_time + INTERVAL '4 minutes',
        '192.168.1.10', '10.0.0.5',
        'admin', 'authentication', 'HIGH',
        'failure', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    ),
    (
        'E006', base_time + INTERVAL '5 minutes',
        '192.168.1.10', '10.0.0.5',
        'admin', 'authentication', 'INFO',
        'success', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    ),
    (
        'E007', base_time + INTERVAL '6 minutes',
        '10.10.1.20', '10.0.0.8',
        'analyst', 'network', 'MEDIUM',
        'blocked', ids_id,
        '{"protocol":"TCP","port":443}'::JSONB
    ),
    (
        'E008', base_time + INTERVAL '7 minutes',
        '10.10.1.20', '10.0.0.8',
        'analyst', 'network', 'CRITICAL',
        'blocked', ids_id,
        '{"protocol":"TCP","port":443}'::JSONB
    ),
    (
        'E009', base_time + INTERVAL '8 minutes',
        '172.16.0.25', '10.0.0.9',
        'service_account', 'process', 'LOW',
        'executed', endpoint_id,
        '{"process":"powershell.exe"}'::JSONB
    ),
    (
        'E010', base_time + INTERVAL '12 minutes',
        '192.168.1.15', '10.0.0.5',
        'user01', 'authentication', 'INFO',
        'success', firewall_id,
        '{"protocol":"SSH","port":22}'::JSONB
    )
    ON CONFLICT (external_event_id) DO NOTHING;
END;
$$;

-- ============================================================
-- 11. FILTERING AND RETRIEVAL
-- ============================================================

-- Retrieve high and critical events.
SELECT
    external_event_id,
    event_timestamp,
    source_ip,
    username,
    event_type,
    severity,
    action
FROM security_events
WHERE severity IN ('HIGH', 'CRITICAL')
ORDER BY event_timestamp DESC;

-- Filter by source IP and action.
SELECT
    external_event_id,
    event_timestamp,
    username,
    action
FROM security_events
WHERE source_ip = '192.168.1.10'
  AND action = 'failure'
ORDER BY event_timestamp;

-- Retrieve a specific event-time window.
SELECT *
FROM security_events
WHERE event_timestamp >= '2026-11-25 02:30:00+00'
  AND event_timestamp < '2026-11-25 02:45:00+00'
ORDER BY event_timestamp;

-- Filter using JSONB fields.
SELECT
    external_event_id,
    raw_fields
FROM security_events
WHERE raw_fields @> '{"protocol":"SSH"}'::JSONB;

-- ============================================================
-- 12. AGGREGATION
-- ============================================================

-- Severity distribution.
SELECT
    severity,
    COUNT(*) AS event_count
FROM security_events
GROUP BY severity
ORDER BY COUNT(*) DESC;

-- Most active source IP addresses.
SELECT
    source_ip,
    COUNT(*) AS event_count,
    COUNT(DISTINCT username) AS affected_accounts
FROM security_events
GROUP BY source_ip
ORDER BY event_count DESC;

-- Event type and action distribution.
SELECT
    event_type,
    action,
    COUNT(*) AS total
FROM security_events
GROUP BY event_type, action
ORDER BY total DESC;

-- Source-level reporting.
SELECT
    s.source_name,
    s.source_type,
    COUNT(e.event_id) AS total_events,
    COUNT(*) FILTER (
        WHERE e.severity IN ('HIGH', 'CRITICAL')
    ) AS serious_events
FROM event_sources s
LEFT JOIN security_events e
    ON e.source_id = s.source_id
GROUP BY s.source_id, s.source_name, s.source_type
ORDER BY total_events DESC;

-- ============================================================
-- 13. TIMELINE ANALYSIS
-- ============================================================

-- Five-minute event histogram.
SELECT
    date_bin(
        INTERVAL '5 minutes',
        event_timestamp,
        TIMESTAMPTZ '2000-01-01 00:00:00+00'
    ) AS time_bucket,
    COUNT(*) AS event_count,
    COUNT(*) FILTER (
        WHERE severity IN ('HIGH', 'CRITICAL')
    ) AS serious_events
FROM security_events
GROUP BY time_bucket
ORDER BY time_bucket;

-- ============================================================
-- 14. FIELD ANALYSIS
-- ============================================================

-- Distinct source addresses.
SELECT
    COUNT(DISTINCT source_ip) AS unique_source_ips,
    COUNT(DISTINCT destination_ip) AS unique_destination_ips,
    COUNT(DISTINCT username) AS unique_users,
    COUNT(DISTINCT event_type) AS unique_event_types
FROM security_events;

-- Top usernames.
SELECT
    username,
    COUNT(*) AS event_count
FROM security_events
GROUP BY username
ORDER BY event_count DESC
LIMIT 10;

-- JSONB key analysis.
SELECT
    jsonb_object_keys(raw_fields) AS field_name,
    COUNT(*) AS occurrence_count
FROM security_events
GROUP BY field_name
ORDER BY occurrence_count DESC;

-- ============================================================
-- 15. BRUTE-FORCE DETECTION
-- ============================================================

CREATE OR REPLACE FUNCTION detect_failed_login_bursts(
    p_threshold INTEGER DEFAULT 5,
    p_window_seconds INTEGER DEFAULT 600
)
RETURNS TABLE (
    detected_source INET,
    detected_username VARCHAR,
    attempt_count BIGINT,
    first_attempt TIMESTAMPTZ,
    last_attempt TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_threshold < 1 OR p_window_seconds < 1 THEN
        RAISE EXCEPTION
            'Threshold and window must be positive';
    END IF;

    RETURN QUERY
    WITH failed_events AS (
        SELECT
            e.source_ip,
            e.username,
            e.event_timestamp
        FROM security_events e
        WHERE e.event_type = 'authentication'
          AND e.action = 'failure'
    ),
    ordered_events AS (
        SELECT
            f.*,
            COUNT(*) OVER (
                PARTITION BY f.source_ip, f.username
                ORDER BY f.event_timestamp
                RANGE BETWEEN
                    (p_window_seconds * INTERVAL '1 second')
                    PRECEDING
                    AND CURRENT ROW
            ) AS attempts,
            MIN(f.event_timestamp) OVER (
                PARTITION BY f.source_ip, f.username
                ORDER BY f.event_timestamp
                RANGE BETWEEN
                    (p_window_seconds * INTERVAL '1 second')
                    PRECEDING
                    AND CURRENT ROW
            ) AS first_seen
        FROM failed_events f
    )
    SELECT
        o.source_ip,
        o.username,
        MAX(o.attempts),
        MIN(o.first_seen),
        MAX(o.event_timestamp)
    FROM ordered_events o
    WHERE o.attempts >= p_threshold
    GROUP BY o.source_ip, o.username
    ORDER BY MAX(o.attempts) DESC;
END;
$$;

-- Execute the detection query.
SELECT *
FROM detect_failed_login_bursts(5, 600);

-- ============================================================
-- 16. ALERT GENERATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE process_failed_login_alerts()
LANGUAGE plpgsql
AS $$
DECLARE
    rule_record RECORD;
    detection RECORD;
BEGIN
    SELECT *
    INTO rule_record
    FROM detection_rules
    WHERE rule_name = 'Repeated Failed Authentication'
      AND enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Enabled detection rule not found';
    END IF;

    FOR detection IN
        SELECT *
        FROM detect_failed_login_bursts(
            rule_record.threshold_count,
            rule_record.window_seconds
        )
    LOOP
        INSERT INTO security_alerts (
            rule_id,
            source_ip,
            username,
            attempt_count,
            first_seen,
            last_seen,
            severity
        )
        VALUES (
            rule_record.rule_id,
            detection.detected_source,
            detection.detected_username,
            detection.attempt_count::INTEGER,
            detection.first_attempt,
            detection.last_attempt,
            rule_record.minimum_severity
        )
        ON CONFLICT DO NOTHING;
    END LOOP;
END;
$$;

-- ============================================================
-- 17. ALERT REPORTING VIEW
-- ============================================================

CREATE OR REPLACE VIEW alert_investigation_report AS
SELECT
    a.alert_id,
    r.rule_name,
    a.source_ip,
    a.username,
    a.attempt_count,
    a.first_seen,
    a.last_seen,
    a.severity,
    a.status,
    a.assigned_to,
    a.detected_at,
    EXTRACT(
        EPOCH FROM (a.last_seen - a.first_seen)
    ) AS attack_duration_seconds
FROM security_alerts a
JOIN detection_rules r
    ON r.rule_id = a.rule_id;

-- ============================================================
-- 18. EVENT INVESTIGATION VIEW
-- ============================================================

CREATE OR REPLACE VIEW security_event_report AS
SELECT
    e.external_event_id,
    e.event_timestamp,
    e.source_ip,
    e.destination_ip,
    e.username,
    e.event_type,
    e.severity,
    e.action,
    s.source_name,
    s.source_type,
    e.raw_fields
FROM security_events e
JOIN event_sources s
    ON s.source_id = e.source_id;

-- ============================================================
-- 19. WORKFLOW TRANSACTION
-- ============================================================

-- Alert generation and subsequent investigation are transactional.
COMMIT;

BEGIN;

CALL process_failed_login_alerts();

-- Review open alerts.
SELECT *
FROM alert_investigation_report
WHERE status = 'OPEN'
ORDER BY severity DESC, attempt_count DESC;

-- Example analyst workflow transition.
UPDATE security_alerts
SET
    status = 'INVESTIGATING',
    assigned_to = 'security_analyst_01',
    analyst_notes = 'Reviewing repeated authentication failures'
WHERE source_ip = '192.168.1.10'
  AND username = 'admin'
  AND status = 'OPEN';

-- Verify the changed state.
SELECT
    alert_id,
    source_ip,
    username,
    status,
    assigned_to
FROM security_alerts
ORDER BY detected_at DESC;

COMMIT;

-- ============================================================
-- 20. DATA QUALITY VALIDATION
-- ============================================================

-- Detect records with unusual ingestion delay.
SELECT
    external_event_id,
    event_timestamp,
    ingestion_timestamp,
    EXTRACT(
        EPOCH FROM (ingestion_timestamp - event_timestamp)
    ) AS ingestion_delay_seconds
FROM security_events
WHERE ingestion_timestamp - event_timestamp
      > INTERVAL '5 minutes'
ORDER BY ingestion_delay_seconds DESC;

-- Identify source addresses generating diverse event types.
SELECT
    source_ip,
    COUNT(*) AS total_events,
    COUNT(DISTINCT event_type) AS event_type_diversity,
    COUNT(DISTINCT destination_ip) AS destination_diversity
FROM security_events
GROUP BY source_ip
HAVING COUNT(*) >= 2
ORDER BY event_type_diversity DESC;

-- Check event source availability.
SELECT
    source_name,
    enabled,
    COUNT(e.event_id) AS event_count
FROM event_sources s
LEFT JOIN security_events e
    ON e.source_id = s.source_id
GROUP BY s.source_id, s.source_name, s.enabled
ORDER BY source_name;

-- ============================================================
-- 21. QUERY PERFORMANCE INSPECTION
-- ============================================================

EXPLAIN (ANALYZE, BUFFERS)
SELECT
    external_event_id,
    event_timestamp,
    source_ip,
    severity
FROM security_events
WHERE severity IN ('HIGH', 'CRITICAL')
  AND event_timestamp >= '2026-11-25 02:30:00+00'
ORDER BY event_timestamp DESC;

-- ============================================================
-- 22. OPERATIONAL SECURITY NOTES
-- ============================================================

-- Production deployment should:
-- 1. Assign separate ingestion and analyst database roles.
-- 2. Restrict raw event access using grants and row-level security.
-- 3. Use TLS for database connections.
-- 4. Use parameterized queries in application code.
-- 5. Define retention and archival policies.
-- 6. Partition high-volume event tables by event_timestamp.
-- 7. Monitor ingestion delay, index growth, and query latency.
-- 8. Audit changes to alerts and detection rules.
-- 9. Restrict EXECUTE permissions on ingestion functions.
-- 10. Avoid storing passwords, tokens, and unnecessary PII in raw_fields.
