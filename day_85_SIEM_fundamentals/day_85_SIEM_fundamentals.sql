/*
===============================================================================
SIEM FUNDAMENTALS
===============================================================================

PostgreSQL 15+

Domain:
    Security events
    Structured fields
    Event indexing
    Search
    Correlation rules
    Correlation execution
    Security alerts
    Alert lifecycle
    Monitoring and reporting

The script creates an independent siem schema.
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS siem;

SET search_path TO siem, public;

-- ============================================================================
-- ENUMERATIONS
-- ============================================================================

CREATE TYPE siem.event_category AS ENUM (
    'authentication',
    'network',
    'endpoint',
    'firewall',
    'dns',
    'application'
);

CREATE TYPE siem.severity AS ENUM (
    'INFO',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TYPE siem.alert_status AS ENUM (
    'NEW',
    'ACKNOWLEDGED',
    'INVESTIGATING',
    'RESOLVED',
    'FALSE_POSITIVE'
);

CREATE TYPE siem.event_result AS ENUM (
    'SUCCESS',
    'FAILURE',
    'BLOCKED',
    'UNKNOWN'
);

-- ============================================================================
-- DATA SOURCES
-- ============================================================================

CREATE TABLE siem.data_sources (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name VARCHAR(100) NOT NULL UNIQUE,
    source_type VARCHAR(50) NOT NULL,
    hostname VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_source_name
        CHECK (length(trim(source_name)) > 0),

    CONSTRAINT valid_source_type
        CHECK (length(trim(source_type)) > 0)
);

-- ============================================================================
-- SECURITY EVENTS
-- ============================================================================

CREATE TABLE siem.security_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    external_event_id VARCHAR(128) NOT NULL UNIQUE,

    source_id BIGINT NOT NULL
        REFERENCES siem.data_sources(source_id),

    event_timestamp TIMESTAMPTZ NOT NULL,

    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    category siem.event_category NOT NULL,

    event_type VARCHAR(100) NOT NULL,

    severity siem.severity NOT NULL DEFAULT 'INFO',

    src_ip INET,
    dst_ip INET,

    username VARCHAR(150),
    hostname VARCHAR(255),

    destination_port INTEGER,

    result siem.event_result NOT NULL DEFAULT 'UNKNOWN',

    message TEXT,

    fields JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_event_type
        CHECK (length(trim(event_type)) > 0),

    CONSTRAINT valid_destination_port
        CHECK (
            destination_port IS NULL OR
            destination_port BETWEEN 1 AND 65535
        ),

    CONSTRAINT valid_fields_object
        CHECK (jsonb_typeof(fields) = 'object'),

    CONSTRAINT valid_event_message
        CHECK (
            message IS NULL OR
            length(message) <= 10000
        )
);

-- Time-oriented searches and retention operations.
CREATE INDEX idx_events_timestamp
    ON siem.security_events (event_timestamp DESC);

-- Common SOC investigations.
CREATE INDEX idx_events_source_time
    ON siem.security_events (source_id, event_timestamp DESC);

CREATE INDEX idx_events_category_severity_time
    ON siem.security_events (
        category,
        severity,
        event_timestamp DESC
    );

CREATE INDEX idx_events_source_ip_time
    ON siem.security_events (src_ip, event_timestamp DESC)
    WHERE src_ip IS NOT NULL;

CREATE INDEX idx_events_username_time
    ON siem.security_events (username, event_timestamp DESC)
    WHERE username IS NOT NULL;

CREATE INDEX idx_events_type_time
    ON siem.security_events (event_type, event_timestamp DESC);

-- GIN supports JSONB containment and key-oriented investigations.
CREATE INDEX idx_events_fields_gin
    ON siem.security_events USING GIN (fields);

-- ============================================================================
-- EVENT NORMALIZATION
-- ============================================================================

CREATE TABLE siem.event_field_definitions (
    field_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    field_name VARCHAR(100) NOT NULL UNIQUE,
    field_description TEXT NOT NULL,
    field_type VARCHAR(30) NOT NULL,
    is_searchable BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT valid_field_type
        CHECK (
            field_type IN (
                'TEXT',
                'INTEGER',
                'BOOLEAN',
                'TIMESTAMP',
                'IP_ADDRESS',
                'JSON'
            )
        )
);

INSERT INTO siem.event_field_definitions
    (field_name, field_description, field_type)
VALUES
    ('src_ip', 'Source network address', 'IP_ADDRESS'),
    ('dst_ip', 'Destination network address', 'IP_ADDRESS'),
    ('username', 'Account involved in the event', 'TEXT'),
    ('hostname', 'Originating endpoint hostname', 'TEXT'),
    ('event_type', 'Normalized event classification', 'TEXT'),
    ('severity', 'Normalized event severity', 'TEXT'),
    ('protocol', 'Network protocol', 'TEXT'),
    ('process', 'Endpoint process name', 'TEXT'),
    ('domain', 'DNS domain name', 'TEXT'),
    ('action', 'Security control action', 'TEXT')
ON CONFLICT (field_name) DO NOTHING;

-- ============================================================================
-- ANALYSTS AND SECURITY ROLES
-- ============================================================================

CREATE TABLE siem.analysts (
    analyst_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    role_name VARCHAR(50) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_analyst_role
        CHECK (
            role_name IN (
                'SOC_ANALYST',
                'SOC_LEAD',
                'SECURITY_ENGINEER',
                'SECURITY_ADMIN',
                'AUDITOR'
            )
        )
);

-- ============================================================================
-- CORRELATION RULES
-- ============================================================================

CREATE TABLE siem.correlation_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_code VARCHAR(80) NOT NULL UNIQUE,

    rule_name VARCHAR(200) NOT NULL,

    description TEXT NOT NULL,

    event_type VARCHAR(100) NOT NULL,

    group_field VARCHAR(100) NOT NULL,

    window_seconds INTEGER NOT NULL,

    threshold_count INTEGER NOT NULL,

    alert_severity siem.severity NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT positive_rule_window
        CHECK (window_seconds BETWEEN 1 AND 86400),

    CONSTRAINT positive_rule_threshold
        CHECK (threshold_count BETWEEN 1 AND 100000),

    CONSTRAINT valid_rule_name
        CHECK (length(trim(rule_name)) > 0)
);

INSERT INTO siem.correlation_rules (
    rule_code,
    rule_name,
    description,
    event_type,
    group_field,
    window_seconds,
    threshold_count,
    alert_severity
)
VALUES (
    'SSH-BRUTE-FORCE',
    'SSH Brute Force Detection',
    'Detect repeated failed SSH authentication attempts from one source address.',
    'failed_login',
    'src_ip',
    300,
    5,
    'CRITICAL'
);

-- ============================================================================
-- CORRELATION EXECUTIONS
-- ============================================================================

CREATE TABLE siem.correlation_runs (
    run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_id BIGINT NOT NULL
        REFERENCES siem.correlation_rules(rule_id),

    window_start TIMESTAMPTZ NOT NULL,

    window_end TIMESTAMPTZ NOT NULL,

    execution_status VARCHAR(20) NOT NULL DEFAULT 'RUNNING',

    matching_event_count INTEGER NOT NULL DEFAULT 0,

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    CONSTRAINT valid_correlation_window
        CHECK (window_start < window_end),

    CONSTRAINT valid_execution_status
        CHECK (
            execution_status IN (
                'RUNNING',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT unique_rule_window
        UNIQUE (rule_id, window_start, window_end)
);

-- ============================================================================
-- SECURITY ALERTS
-- ============================================================================

CREATE TABLE siem.alerts (
    alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    alert_fingerprint VARCHAR(128) NOT NULL UNIQUE,

    rule_id BIGINT NOT NULL
        REFERENCES siem.correlation_rules(rule_id),

    run_id BIGINT
        REFERENCES siem.correlation_runs(run_id),

    title VARCHAR(200) NOT NULL,

    description TEXT NOT NULL,

    severity siem.severity NOT NULL,

    status siem.alert_status NOT NULL DEFAULT 'NEW',

    group_value TEXT,

    first_event_at TIMESTAMPTZ NOT NULL,

    last_event_at TIMESTAMPTZ NOT NULL,

    event_count INTEGER NOT NULL,

    assigned_analyst BIGINT
        REFERENCES siem.analysts(analyst_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT positive_alert_event_count
        CHECK (event_count > 0),

    CONSTRAINT valid_alert_time
        CHECK (first_event_at <= last_event_at)
);

CREATE INDEX idx_alerts_status_severity
    ON siem.alerts (status, severity, created_at DESC);

CREATE INDEX idx_alerts_assigned_analyst
    ON siem.alerts (assigned_analyst, status);

CREATE INDEX idx_alerts_created_at
    ON siem.alerts (created_at DESC);

-- ============================================================================
-- ALERT EVENT RELATIONSHIP
-- ============================================================================

CREATE TABLE siem.alert_events (
    alert_id BIGINT NOT NULL
        REFERENCES siem.alerts(alert_id)
        ON DELETE CASCADE,

    event_id BIGINT NOT NULL
        REFERENCES siem.security_events(event_id),

    relationship_type VARCHAR(30) NOT NULL DEFAULT 'CORRELATED',

    PRIMARY KEY (alert_id, event_id),

    CONSTRAINT valid_relationship_type
        CHECK (
            relationship_type IN (
                'CORRELATED',
                'TRIGGERING',
                'SUPPORTING'
            )
        )
);

CREATE INDEX idx_alert_events_event
    ON siem.alert_events(event_id);

-- ============================================================================
-- ALERT AUDIT HISTORY
-- ============================================================================

CREATE TABLE siem.alert_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    alert_id BIGINT NOT NULL
        REFERENCES siem.alerts(alert_id),

    analyst_id BIGINT
        REFERENCES siem.analysts(analyst_id),

    previous_status siem.alert_status,

    new_status siem.alert_status NOT NULL,

    comment TEXT,

    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- STATUS CHECKS
-- ============================================================================

CREATE TABLE siem.status_checks (
    check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    check_name VARCHAR(150) NOT NULL,

    check_type VARCHAR(50) NOT NULL,

    check_status VARCHAR(20) NOT NULL,

    execution_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    source_id BIGINT
        REFERENCES siem.data_sources(source_id),

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_check_status
        CHECK (
            check_status IN (
                'PASS',
                'FAIL',
                'WARNING',
                'ERROR'
            )
        ),

    CONSTRAINT valid_check_details
        CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX idx_status_checks_execution
    ON siem.status_checks (execution_time DESC, check_status);

-- ============================================================================
-- UPDATE TIMESTAMP TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_alert_updated_at
BEFORE UPDATE ON siem.alerts
FOR EACH ROW
EXECUTE FUNCTION siem.set_updated_at();

-- ============================================================================
-- ALERT STATUS TRANSITION VALIDATION
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.validate_alert_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF OLD.status = 'NEW'
       AND NEW.status NOT IN (
           'ACKNOWLEDGED',
           'FALSE_POSITIVE'
       ) THEN
        RAISE EXCEPTION
            'Invalid transition from % to %',
            OLD.status,
            NEW.status;
    END IF;

    IF OLD.status = 'ACKNOWLEDGED'
       AND NEW.status NOT IN (
           'INVESTIGATING',
           'RESOLVED',
           'FALSE_POSITIVE'
       ) THEN
        RAISE EXCEPTION
            'Invalid transition from % to %',
            OLD.status,
            NEW.status;
    END IF;

    IF OLD.status = 'INVESTIGATING'
       AND NEW.status NOT IN (
           'RESOLVED',
           'FALSE_POSITIVE'
       ) THEN
        RAISE EXCEPTION
            'Invalid transition from % to %',
            OLD.status,
            NEW.status;
    END IF;

    IF OLD.status IN ('RESOLVED', 'FALSE_POSITIVE') THEN
        RAISE EXCEPTION
            'Terminal alert state cannot be changed';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_alert_transition
BEFORE UPDATE OF status ON siem.alerts
FOR EACH ROW
EXECUTE FUNCTION siem.validate_alert_transition();

-- ============================================================================
-- AUDIT HISTORY TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.record_alert_history()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN
        INSERT INTO siem.alert_history (
            alert_id,
            previous_status,
            new_status,
            comment
        )
        VALUES (
            NEW.alert_id,
            OLD.status,
            NEW.status,
            'Alert state changed'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_alert_history
AFTER UPDATE OF status ON siem.alerts
FOR EACH ROW
EXECUTE FUNCTION siem.record_alert_history();

-- ============================================================================
-- EVENT INGESTION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.ingest_event(
    p_external_event_id VARCHAR,
    p_source_name VARCHAR,
    p_timestamp TIMESTAMPTZ,
    p_category siem.event_category,
    p_event_type VARCHAR,
    p_severity siem.severity,
    p_src_ip INET,
    p_dst_ip INET,
    p_username VARCHAR,
    p_hostname VARCHAR,
    p_result siem.event_result,
    p_fields JSONB
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_source_id BIGINT;
    v_event_id BIGINT;
BEGIN
    IF p_timestamp IS NULL THEN
        RAISE EXCEPTION 'Event timestamp is required';
    END IF;

    IF p_external_event_id IS NULL
       OR length(trim(p_external_event_id)) = 0 THEN
        RAISE EXCEPTION 'External event identifier is required';
    END IF;

    IF p_fields IS NULL
       OR jsonb_typeof(p_fields) <> 'object' THEN
        RAISE EXCEPTION 'Event fields must be a JSON object';
    END IF;

    SELECT source_id
    INTO v_source_id
    FROM siem.data_sources
    WHERE source_name = p_source_name
      AND enabled = TRUE;

    IF v_source_id IS NULL THEN
        RAISE EXCEPTION
            'Unknown or disabled event source: %',
            p_source_name;
    END IF;

    INSERT INTO siem.security_events (
        external_event_id,
        source_id,
        event_timestamp,
        category,
        event_type,
        severity,
        src_ip,
        dst_ip,
        username,
        hostname,
        result,
        fields
    )
    VALUES (
        p_external_event_id,
        v_source_id,
        p_timestamp,
        p_category,
        p_event_type,
        p_severity,
        p_src_ip,
        p_dst_ip,
        p_username,
        p_hostname,
        p_result,
        p_fields
    )
    ON CONFLICT (external_event_id) DO NOTHING
    RETURNING event_id INTO v_event_id;

    UPDATE siem.data_sources
    SET last_seen_at = GREATEST(
        COALESCE(last_seen_at, p_timestamp),
        p_timestamp
    )
    WHERE source_id = v_source_id;

    RETURN v_event_id;
END;
$$;

-- ============================================================================
-- CORRELATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.evaluate_rule(
    p_rule_code VARCHAR,
    p_window_end TIMESTAMPTZ DEFAULT NOW()
)
RETURNS TABLE (
    generated_alert_id BIGINT,
    matching_group TEXT,
    matching_count BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule siem.correlation_rules%ROWTYPE;
    v_window_start TIMESTAMPTZ;
    v_run_id BIGINT;
    v_group RECORD;
    v_alert_id BIGINT;
    v_fingerprint TEXT;
    v_first_event TIMESTAMPTZ;
    v_last_event TIMESTAMPTZ;
BEGIN
    SELECT *
    INTO STRICT v_rule
    FROM siem.correlation_rules
    WHERE rule_code = p_rule_code
      AND enabled = TRUE;

    v_window_start :=
        p_window_end -
        make_interval(secs => v_rule.window_seconds);

    -- One transaction-safe execution per rule and exact time window.
    INSERT INTO siem.correlation_runs (
        rule_id,
        window_start,
        window_end,
        execution_status
    )
    VALUES (
        v_rule.rule_id,
        v_window_start,
        p_window_end,
        'RUNNING'
    )
    ON CONFLICT (rule_id, window_start, window_end)
    DO NOTHING
    RETURNING run_id INTO v_run_id;

    IF v_run_id IS NULL THEN
        RETURN;
    END IF;

    FOR v_group IN
        SELECT
            CASE v_rule.group_field
                WHEN 'src_ip' THEN src_ip::TEXT
                WHEN 'dst_ip' THEN dst_ip::TEXT
                WHEN 'username' THEN username
                WHEN 'hostname' THEN hostname
                ELSE fields ->> v_rule.group_field
            END AS group_value,

            COUNT(*) AS total_events,

            MIN(event_timestamp) AS first_event,
            MAX(event_timestamp) AS last_event,

            ARRAY_AGG(event_id ORDER BY event_id) AS event_ids

        FROM siem.security_events

        WHERE event_type = v_rule.event_type
          AND event_timestamp >= v_window_start
          AND event_timestamp <= p_window_end

        GROUP BY 1

        HAVING COUNT(*) >= v_rule.threshold_count
           AND CASE v_rule.group_field
                WHEN 'src_ip' THEN src_ip::TEXT
                WHEN 'dst_ip' THEN dst_ip::TEXT
                WHEN 'username' THEN username
                WHEN 'hostname' THEN hostname
                ELSE fields ->> v_rule.group_field
              END IS NOT NULL
    LOOP
        v_fingerprint := md5(
            p_rule_code || '|' ||
            v_group.group_value || '|' ||
            v_window_start::TEXT || '|' ||
            p_window_end::TEXT
        );

        INSERT INTO siem.alerts (
            alert_fingerprint,
            rule_id,
            run_id,
            title,
            description,
            severity,
            group_value,
            first_event_at,
            last_event_at,
            event_count
        )
        VALUES (
            v_fingerprint,
            v_rule.rule_id,
            v_run_id,
            v_rule.rule_name,
            v_group.total_events ||
                ' matching events for ' ||
                v_rule.group_field || '=' ||
                v_group.group_value,
            v_rule.alert_severity,
            v_group.group_value,
            v_group.first_event,
            v_group.last_event,
            v_group.total_events
        )
        ON CONFLICT (alert_fingerprint) DO NOTHING
        RETURNING alert_id INTO v_alert_id;

        IF v_alert_id IS NOT NULL THEN
            INSERT INTO siem.alert_events (
                alert_id,
                event_id,
                relationship_type
            )
            SELECT
                v_alert_id,
                unnest(v_group.event_ids),
                'TRIGGERING';

            generated_alert_id := v_alert_id;
            matching_group := v_group.group_value;
            matching_count := v_group.total_events;

            RETURN NEXT;
        END IF;
    END LOOP;

    UPDATE siem.correlation_runs
    SET execution_status = 'COMPLETED',
        matching_event_count = (
            SELECT COUNT(*)
            FROM siem.security_events
            WHERE event_type = v_rule.event_type
              AND event_timestamp >= v_window_start
              AND event_timestamp <= p_window_end
        ),
        completed_at = NOW()
    WHERE run_id = v_run_id;

    RETURN;
EXCEPTION
    WHEN OTHERS THEN
        IF v_run_id IS NOT NULL THEN
            UPDATE siem.correlation_runs
            SET execution_status = 'FAILED',
                completed_at = NOW()
            WHERE run_id = v_run_id;
        END IF;

        RAISE;
END;
$$;

-- ============================================================================
-- ALERT WORKFLOW FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.update_alert_status(
    p_alert_id BIGINT,
    p_new_status siem.alert_status,
    p_analyst_id BIGINT,
    p_comment TEXT DEFAULT NULL
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM siem.analysts
        WHERE analyst_id = p_analyst_id
          AND active = TRUE
          AND role_name IN (
              'SOC_ANALYST',
              'SOC_LEAD',
              'SECURITY_ADMIN'
          )
    ) THEN
        RAISE EXCEPTION
            'Analyst is not authorized to update alerts';
    END IF;

    UPDATE siem.alerts
    SET status = p_new_status,
        assigned_analyst = p_analyst_id
    WHERE alert_id = p_alert_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Alert does not exist';
    END IF;

    UPDATE siem.alert_history
    SET analyst_id = p_analyst_id,
        comment = COALESCE(p_comment, comment)
    WHERE history_id = (
        SELECT MAX(history_id)
        FROM siem.alert_history
        WHERE alert_id = p_alert_id
    );
END;
$$;

-- ============================================================================
-- SEARCH FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION siem.search_events(
    p_event_type VARCHAR DEFAULT NULL,
    p_src_ip INET DEFAULT NULL,
    p_severity siem.severity DEFAULT NULL,
    p_start TIMESTAMPTZ DEFAULT NULL,
    p_end TIMESTAMPTZ DEFAULT NULL,
    p_limit INTEGER DEFAULT 100
)
RETURNS SETOF siem.security_events
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION 'Search limit must be between 1 and 10000';
    END IF;

    IF p_start IS NOT NULL
       AND p_end IS NOT NULL
       AND p_start > p_end THEN
        RAISE EXCEPTION 'Invalid search time range';
    END IF;

    RETURN QUERY
    SELECT e.*
    FROM siem.security_events e
    WHERE (p_event_type IS NULL OR e.event_type = p_event_type)
      AND (p_src_ip IS NULL OR e.src_ip = p_src_ip)
      AND (p_severity IS NULL OR e.severity = p_severity)
      AND (p_start IS NULL OR e.event_timestamp >= p_start)
      AND (p_end IS NULL OR e.event_timestamp <= p_end)
    ORDER BY e.event_timestamp DESC, e.event_id DESC
    LIMIT p_limit;
END;
$$;

-- ============================================================================
-- REPORTING VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW siem.event_summary AS
SELECT
    category,
    severity,
    event_type,
    COUNT(*) AS event_count,
    MIN(event_timestamp) AS first_observed,
    MAX(event_timestamp) AS last_observed
FROM siem.security_events
GROUP BY category, severity, event_type;

CREATE OR REPLACE VIEW siem.alert_summary AS
SELECT
    a.alert_id,
    a.title,
    a.severity,
    a.status,
    a.group_value,
    a.event_count,
    a.first_event_at,
    a.last_event_at,
    d.display_name AS assigned_analyst,
    r.rule_code
FROM siem.alerts a
JOIN siem.correlation_rules r
    ON r.rule_id = a.rule_id
LEFT JOIN siem.analysts d
    ON d.analyst_id = a.assigned_analyst;

CREATE OR REPLACE VIEW siem.source_health AS
SELECT
    ds.source_id,
    ds.source_name,
    ds.source_type,
    ds.enabled,
    ds.last_seen_at,
    COUNT(e.event_id) AS total_events,
    MAX(e.ingested_at) AS last_ingestion
FROM siem.data_sources ds
LEFT JOIN siem.security_events e
    ON e.source_id = ds.source_id
GROUP BY
    ds.source_id,
    ds.source_name,
    ds.source_type,
    ds.enabled,
    ds.last_seen_at;

-- ============================================================================
-- SAMPLE DATA SOURCES
-- ============================================================================

INSERT INTO siem.data_sources (
    source_name,
    source_type,
    hostname
)
VALUES
    ('linux-auth-01', 'LINUX_AUTH', 'server-01'),
    ('firewall-01', 'FIREWALL', 'edge-firewall'),
    ('dns-01', 'DNS', 'dns-server-01'),
    ('edr-01', 'ENDPOINT', 'edr-agent-01')
ON CONFLICT (source_name) DO NOTHING;

INSERT INTO siem.analysts (
    username,
    display_name,
    role_name
)
VALUES
    ('soc.analyst01', 'SOC Analyst One', 'SOC_ANALYST'),
    ('soc.lead01', 'SOC Team Lead', 'SOC_LEAD'),
    ('security.auditor', 'Security Auditor', 'AUDITOR')
ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- SAMPLE EVENT INGESTION
-- ============================================================================

DO $$
DECLARE
    i INTEGER;
BEGIN
    FOR i IN 1..6 LOOP
        PERFORM siem.ingest_event(
            'AUTH-' || i,
            'linux-auth-01',
            TIMESTAMPTZ '2026-11-24 06:00:00+00'
                + make_interval(secs => i * 5),
            'authentication',
            'failed_login',
            'MEDIUM',
            '203.0.113.45'::INET,
            NULL,
            'admin',
            'server-01',
            'FAILURE',
            jsonb_build_object(
                'src_ip', '203.0.113.45',
                'username', 'admin',
                'protocol', 'ssh',
                'result', 'failure'
            )
        );
    END LOOP;
END;
$$;

SELECT siem.ingest_event(
    'FW-001',
    'firewall-01',
    '2026-11-24 06:00:30+00',
    'firewall',
    'blocked_connection',
    'HIGH',
    '203.0.113.45'::INET,
    '10.0.0.10'::INET,
    NULL,
    'edge-firewall',
    'BLOCKED',
    '{"dst_port":22,"action":"blocked"}'::JSONB
);

SELECT siem.ingest_event(
    'DNS-001',
    'dns-01',
    '2026-11-24 06:00:40+00',
    'dns',
    'dns_query',
    'INFO',
    '10.0.0.15'::INET,
    NULL,
    NULL,
    'dns-server-01',
    'SUCCESS',
    '{"domain":"example.internal","query_type":"A"}'::JSONB
);

SELECT siem.ingest_event(
    'EDR-001',
    'edr-01',
    '2026-11-24 06:00:50+00',
    'endpoint',
    'suspicious_process',
    'HIGH',
    '10.0.0.20'::INET,
    NULL,
    'employee01',
    'workstation-04',
    'UNKNOWN',
    '{"process":"powershell.exe","action":"suspicious_execution"}'::JSONB
);

-- ============================================================================
-- EVENT SEARCH EXAMPLES
-- ============================================================================

-- Authentication events from one source address.
SELECT
    external_event_id,
    event_timestamp,
    event_type,
    severity,
    src_ip,
    username,
    fields
FROM siem.search_events(
    p_event_type => 'failed_login',
    p_src_ip => '203.0.113.45'::INET,
    p_start => '2026-11-24 05:55:00+00',
    p_end => '2026-11-24 06:10:00+00',
    p_limit => 100
);

-- High-severity events.
SELECT
    external_event_id,
    category,
    event_type,
    severity,
    event_timestamp
FROM siem.search_events(
    p_severity => 'HIGH',
    p_limit => 100
);

-- Search a normalized JSON field.
SELECT
    external_event_id,
    fields ->> 'protocol' AS protocol,
    fields ->> 'username' AS username
FROM siem.security_events
WHERE fields @> '{"protocol":"ssh"}'::JSONB;

-- ============================================================================
-- CORRELATION EXECUTION
-- ============================================================================

-- A five-event threshold identifies the simulated brute-force activity.
SELECT *
FROM siem.evaluate_rule(
    'SSH-BRUTE-FORCE',
    '2026-11-24 06:01:00+00'
);

-- Repeating the same exact window does not create another execution.
SELECT *
FROM siem.evaluate_rule(
    'SSH-BRUTE-FORCE',
    '2026-11-24 06:01:00+00'
);

-- ============================================================================
-- ALERT ASSIGNMENT AND WORKFLOW
-- ============================================================================

DO $$
DECLARE
    v_alert_id BIGINT;
    v_analyst_id BIGINT;
BEGIN
    SELECT alert_id
    INTO v_alert_id
    FROM siem.alerts
    WHERE alert_fingerprint IS NOT NULL
    ORDER BY alert_id DESC
    LIMIT 1;

    SELECT analyst_id
    INTO v_analyst_id
    FROM siem.analysts
    WHERE username = 'soc.analyst01';

    IF v_alert_id IS NOT NULL THEN
        PERFORM siem.update_alert_status(
            v_alert_id,
            'ACKNOWLEDGED',
            v_analyst_id,
            'Initial review completed'
        );

        PERFORM siem.update_alert_status(
            v_alert_id,
            'INVESTIGATING',
            v_analyst_id,
            'Investigating repeated SSH authentication failures'
        );
    END IF;
END;
$$;

-- ============================================================================
-- REPORTING AND EVALUATION
-- ============================================================================

-- Event volume by category and severity.
SELECT
    category,
    severity,
    COUNT(*) AS total_events
FROM siem.security_events
GROUP BY category, severity
ORDER BY category, severity;

-- Top source IP addresses by event volume.
SELECT
    src_ip,
    COUNT(*) AS total_events,
    COUNT(*) FILTER (
        WHERE severity IN ('HIGH', 'CRITICAL')
    ) AS high_severity_events
FROM siem.security_events
WHERE src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY total_events DESC;

-- Alert status and severity distribution.
SELECT
    severity,
    status,
    COUNT(*) AS alert_count
FROM siem.alerts
GROUP BY severity, status
ORDER BY severity, status;

-- Alerts assigned to analysts.
SELECT *
FROM siem.alert_summary
ORDER BY first_event_at DESC;

-- Data source health.
SELECT *
FROM siem.source_health
ORDER BY total_events DESC;

-- Correlation execution history.
SELECT
    r.rule_code,
    cr.window_start,
    cr.window_end,
    cr.execution_status,
    cr.matching_event_count,
    cr.completed_at
FROM siem.correlation_runs cr
JOIN siem.correlation_rules r
    ON r.rule_id = cr.rule_id
ORDER BY cr.started_at DESC;

-- Audit trail.
SELECT
    h.alert_id,
    h.previous_status,
    h.new_status,
    h.comment,
    a.username AS analyst,
    h.changed_at
FROM siem.alert_history h
LEFT JOIN siem.analysts a
    ON a.analyst_id = h.analyst_id
ORDER BY h.changed_at DESC;

-- ============================================================================
-- VALIDATION QUERIES
-- ============================================================================

-- Detect duplicate external identifiers.
SELECT
    external_event_id,
    COUNT(*)
FROM siem.security_events
GROUP BY external_event_id
HAVING COUNT(*) > 1;

-- Identify events without a usable source IP.
SELECT
    event_id,
    external_event_id,
    category,
    event_type
FROM siem.security_events
WHERE category = 'authentication'
  AND src_ip IS NULL;

-- Identify events with missing normalized usernames.
SELECT
    event_id,
    external_event_id
FROM siem.security_events
WHERE category = 'authentication'
  AND username IS NULL;

-- Identify old unassigned alerts.
SELECT
    alert_id,
    title,
    severity,
    created_at
FROM siem.alerts
WHERE status = 'NEW'
  AND assigned_analyst IS NULL
  AND created_at < NOW() - INTERVAL '15 minutes';

-- ============================================================================
-- ELIGIBILITY DETERMINATION
-- ============================================================================

-- Alert investigation eligibility is separate from event detection.
SELECT
    a.alert_id,
    a.title,
    a.severity,
    a.status,

    CASE
        WHEN a.status IN ('RESOLVED', 'FALSE_POSITIVE')
            THEN 'TERMINAL'

        WHEN a.severity IN ('HIGH', 'CRITICAL')
             AND a.status = 'NEW'
            THEN 'PRIORITY_INVESTIGATION'

        WHEN a.status = 'ACKNOWLEDGED'
            THEN 'READY_FOR_INVESTIGATION'

        WHEN a.status = 'INVESTIGATING'
            THEN 'INVESTIGATION_IN_PROGRESS'

        ELSE 'STANDARD_QUEUE'
    END AS investigation_classification

FROM siem.alerts a
ORDER BY
    CASE a.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END,
    a.created_at;

-- ============================================================================
-- TRANSACTIONAL FAILURE HANDLING
-- ============================================================================

-- An invalid status transition must fail without corrupting alert state.
-- Run independently when testing failure behavior.
--
-- BEGIN;
-- UPDATE siem.alerts
-- SET status = 'NEW'
-- WHERE status = 'INVESTIGATING';
-- ROLLBACK;

-- ============================================================================
-- SECURITY AND OPERATIONAL NOTES
-- ============================================================================

-- Application roles should receive only required privileges.
-- Do not grant unrestricted schema ownership to ingestion services.
--
-- Example privilege boundaries:
--
-- GRANT USAGE ON SCHEMA siem TO siem_ingestor;
-- GRANT INSERT, SELECT ON siem.security_events TO siem_ingestor;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA siem
--     TO siem_ingestor;
--
-- GRANT SELECT ON siem.event_summary TO siem_auditor;
-- GRANT SELECT ON siem.alert_summary TO siem_auditor;
--
-- Database authentication, TLS, secret management, retention,
-- encryption, backup, and privileged role management must be
-- configured at the deployment level.
--
-- For high-volume production ingestion, consider time partitioning,
-- controlled retention, batched inserts, and a dedicated message queue.
--
-- JSONB GIN indexes accelerate flexible searches but increase
-- storage and write overhead.

COMMIT;
