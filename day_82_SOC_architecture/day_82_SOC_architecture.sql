/*
===============================================================================
SOC ARCHITECTURE
===============================================================================

PostgreSQL 15+

Models:
    1. Data sources
    2. Collectors and ingestion
    3. Raw security events
    4. Normalized security events
    5. Event storage and indexing
    6. Correlation rules
    7. Correlation executions
    8. Security alerts
    9. Alert evidence
   10. Analyst assignments and workflow
   11. Dashboard reporting

The script is designed as a repeatable demonstration.
It creates a dedicated schema and replaces that schema when rerun.
===============================================================================
*/

BEGIN;

DROP SCHEMA IF EXISTS soc CASCADE;
CREATE SCHEMA soc;

SET search_path TO soc, public;

-- ============================================================================
-- 1. ENUMERATED DOMAIN TYPES
-- ============================================================================

CREATE TYPE source_status AS ENUM (
    'ACTIVE',
    'DISABLED',
    'DEGRADED'
);

CREATE TYPE event_category AS ENUM (
    'AUTHENTICATION',
    'NETWORK',
    'ENDPOINT',
    'APPLICATION',
    'CLOUD'
);

CREATE TYPE event_severity AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TYPE alert_status AS ENUM (
    'OPEN',
    'INVESTIGATING',
    'RESOLVED',
    'CLOSED'
);

CREATE TYPE collector_status AS ENUM (
    'RUNNING',
    'STOPPED',
    'DEGRADED'
);

-- ============================================================================
-- 2. DATA SOURCES
-- ============================================================================

CREATE TABLE data_sources (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    source_code VARCHAR(80) NOT NULL UNIQUE,

    source_name VARCHAR(200) NOT NULL,

    source_type VARCHAR(80) NOT NULL,

    environment VARCHAR(40) NOT NULL,

    status source_status NOT NULL DEFAULT 'ACTIVE',

    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    last_seen_at TIMESTAMPTZ,

    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_source_code
        CHECK (source_code ~ '^[A-Za-z0-9_-]+$'),

    CONSTRAINT valid_environment
        CHECK (
            environment IN (
                'PRODUCTION',
                'STAGING',
                'DEVELOPMENT',
                'TEST'
            )
        )
);

COMMENT ON TABLE data_sources IS
'Inventory of systems that generate security telemetry.';

-- ============================================================================
-- 3. COLLECTORS
-- ============================================================================

CREATE TABLE collectors (
    collector_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    collector_code VARCHAR(80) NOT NULL UNIQUE,

    source_id BIGINT NOT NULL
        REFERENCES data_sources(source_id),

    collector_type VARCHAR(80) NOT NULL,

    status collector_status NOT NULL DEFAULT 'RUNNING',

    started_at TIMESTAMPTZ,

    last_heartbeat_at TIMESTAMPTZ,

    events_received BIGINT NOT NULL DEFAULT 0,

    events_dropped BIGINT NOT NULL DEFAULT 0,

    CONSTRAINT valid_collector_counters
        CHECK (
            events_received >= 0
            AND events_dropped >= 0
        )
);

CREATE INDEX idx_collectors_source
    ON collectors(source_id);

-- ============================================================================
-- 4. RAW EVENTS
-- ============================================================================

CREATE TABLE raw_events (
    raw_event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    collector_id BIGINT NOT NULL
        REFERENCES collectors(collector_id),

    source_id BIGINT NOT NULL
        REFERENCES data_sources(source_id),

    payload JSONB NOT NULL,

    payload_hash CHAR(64) NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    processing_status VARCHAR(20) NOT NULL DEFAULT 'PENDING',

    processing_error TEXT,

    CONSTRAINT valid_processing_status
        CHECK (
            processing_status IN (
                'PENDING',
                'PROCESSED',
                'REJECTED',
                'DUPLICATE'
            )
        ),

    CONSTRAINT valid_raw_payload
        CHECK (jsonb_typeof(payload) = 'object'),

    CONSTRAINT valid_payload_hash
        CHECK (payload_hash ~ '^[a-f0-9]{64}$')
);

CREATE INDEX idx_raw_events_pending
    ON raw_events(received_at)
    WHERE processing_status = 'PENDING';

CREATE INDEX idx_raw_events_source_time
    ON raw_events(source_id, received_at DESC);

CREATE INDEX idx_raw_events_payload
    ON raw_events USING GIN(payload);

-- ============================================================================
-- 5. NORMALIZED SECURITY EVENTS
-- ============================================================================

CREATE TABLE security_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_uuid UUID NOT NULL UNIQUE,

    raw_event_id BIGINT UNIQUE
        REFERENCES raw_events(raw_event_id),

    source_id BIGINT NOT NULL
        REFERENCES data_sources(source_id),

    event_timestamp TIMESTAMPTZ NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    category event_category NOT NULL,

    severity event_severity NOT NULL,

    event_type VARCHAR(120) NOT NULL,

    source_ip INET,

    destination_ip INET,

    username VARCHAR(255),

    hostname VARCHAR(255),

    message TEXT NOT NULL DEFAULT '',

    attributes JSONB NOT NULL DEFAULT '{}'::JSONB,

    CONSTRAINT valid_event_type
        CHECK (length(trim(event_type)) > 0),

    CONSTRAINT valid_attributes
        CHECK (jsonb_typeof(attributes) = 'object')
);

COMMENT ON TABLE security_events IS
'Normalized, queryable security telemetry.';

CREATE INDEX idx_events_timestamp
    ON security_events(event_timestamp DESC);

CREATE INDEX idx_events_source_timestamp
    ON security_events(source_id, event_timestamp DESC);

CREATE INDEX idx_events_severity_timestamp
    ON security_events(severity, event_timestamp DESC);

CREATE INDEX idx_events_category_timestamp
    ON security_events(category, event_timestamp DESC);

CREATE INDEX idx_events_username_timestamp
    ON security_events(username, event_timestamp DESC)
    WHERE username IS NOT NULL;

CREATE INDEX idx_events_source_ip
    ON security_events(source_ip)
    WHERE source_ip IS NOT NULL;

CREATE INDEX idx_events_attributes
    ON security_events USING GIN(attributes);

-- ============================================================================
-- 6. CORRELATION RULES
-- ============================================================================

CREATE TABLE correlation_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_code VARCHAR(80) NOT NULL UNIQUE,

    rule_name VARCHAR(200) NOT NULL,

    description TEXT NOT NULL,

    category event_category NOT NULL,

    event_type VARCHAR(120) NOT NULL,

    threshold_count INTEGER NOT NULL,

    window_seconds INTEGER NOT NULL,

    grouping_fields TEXT[] NOT NULL,

    alert_severity event_severity NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_rule_threshold
        CHECK (threshold_count >= 2),

    CONSTRAINT valid_rule_window
        CHECK (window_seconds > 0),

    CONSTRAINT valid_grouping_fields
        CHECK (cardinality(grouping_fields) > 0)
);

-- ============================================================================
-- 7. CORRELATION EXECUTIONS
-- ============================================================================

CREATE TABLE correlation_executions (
    execution_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_id BIGINT NOT NULL
        REFERENCES correlation_rules(rule_id),

    execution_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    execution_finished_at TIMESTAMPTZ,

    events_examined BIGINT NOT NULL DEFAULT 0,

    alerts_created BIGINT NOT NULL DEFAULT 0,

    execution_status VARCHAR(20) NOT NULL DEFAULT 'RUNNING',

    error_message TEXT,

    CONSTRAINT valid_execution_status
        CHECK (
            execution_status IN (
                'RUNNING',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT valid_execution_counters
        CHECK (
            events_examined >= 0
            AND alerts_created >= 0
        )
);

-- ============================================================================
-- 8. ALERTS
-- ============================================================================

CREATE TABLE security_alerts (
    alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    alert_uuid UUID NOT NULL UNIQUE,

    rule_id BIGINT
        REFERENCES correlation_rules(rule_id),

    title VARCHAR(250) NOT NULL,

    description TEXT NOT NULL,

    severity event_severity NOT NULL,

    status alert_status NOT NULL DEFAULT 'OPEN',

    first_observed_at TIMESTAMPTZ NOT NULL,

    last_observed_at TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    assigned_to VARCHAR(150),

    resolution_notes TEXT,

    CONSTRAINT valid_alert_title
        CHECK (length(trim(title)) > 0),

    CONSTRAINT valid_alert_times
        CHECK (last_observed_at >= first_observed_at)
);

CREATE INDEX idx_alerts_status_severity
    ON security_alerts(status, severity, created_at DESC);

CREATE INDEX idx_alerts_assignee
    ON security_alerts(assigned_to, status);

CREATE INDEX idx_alerts_rule
    ON security_alerts(rule_id, created_at DESC);

-- ============================================================================
-- 9. ALERT EVIDENCE
-- ============================================================================

CREATE TABLE alert_evidence (
    alert_id BIGINT NOT NULL
        REFERENCES security_alerts(alert_id)
        ON DELETE CASCADE,

    event_id BIGINT NOT NULL
        REFERENCES security_events(event_id),

    evidence_role VARCHAR(40) NOT NULL DEFAULT 'CORRELATED',

    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY(alert_id, event_id)
);

CREATE INDEX idx_alert_evidence_event
    ON alert_evidence(event_id);

-- ============================================================================
-- 10. ANALYST ACTIONS
-- ============================================================================

CREATE TABLE analyst_actions (
    action_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    alert_id BIGINT NOT NULL
        REFERENCES security_alerts(alert_id),

    analyst_id VARCHAR(150) NOT NULL,

    action_type VARCHAR(40) NOT NULL,

    previous_status alert_status,

    new_status alert_status,

    action_notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_action_type
        CHECK (
            action_type IN (
                'ASSIGNED',
                'INVESTIGATED',
                'REOPENED',
                'RESOLVED',
                'CLOSED',
                'NOTE_ADDED'
            )
        )
);

CREATE INDEX idx_analyst_actions_alert
    ON analyst_actions(alert_id, created_at DESC);

-- ============================================================================
-- 11. EVENT INGESTION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION ingest_raw_event(
    p_collector_id BIGINT,
    p_source_id BIGINT,
    p_payload JSONB,
    p_payload_hash CHAR(64)
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_status source_status;
    v_id BIGINT;
BEGIN
    SELECT status
    INTO v_status
    FROM data_sources
    WHERE source_id = p_source_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown data source: %', p_source_id;
    END IF;

    IF v_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'Data source is not active';
    END IF;

    IF jsonb_typeof(p_payload) <> 'object' THEN
        RAISE EXCEPTION 'Payload must be a JSON object';
    END IF;

    IF p_payload_hash !~ '^[a-f0-9]{64}$' THEN
        RAISE EXCEPTION 'Invalid SHA-256 payload hash';
    END IF;

    INSERT INTO raw_events (
        collector_id,
        source_id,
        payload,
        payload_hash
    )
    VALUES (
        p_collector_id,
        p_source_id,
        p_payload,
        p_payload_hash
    )
    RETURNING raw_event_id INTO v_id;

    UPDATE collectors
    SET events_received = events_received + 1,
        last_heartbeat_at = NOW()
    WHERE collector_id = p_collector_id
      AND source_id = p_source_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Collector does not belong to the specified source';
    END IF;

    RETURN v_id;
END;
$$;

-- ============================================================================
-- 12. EVENT NORMALIZATION FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION normalize_raw_event(
    p_raw_event_id BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_raw raw_events%ROWTYPE;
    v_event_id BIGINT;
    v_payload JSONB;
    v_timestamp TIMESTAMPTZ;
    v_category event_category;
    v_severity event_severity;
    v_source_ip INET;
    v_destination_ip INET;
    v_reserved TEXT[] := ARRAY[
        'timestamp',
        'category',
        'severity',
        'event_type',
        'source_ip',
        'destination_ip',
        'username',
        'hostname',
        'message'
    ];
    v_attributes JSONB;
BEGIN
    SELECT *
    INTO v_raw
    FROM raw_events
    WHERE raw_event_id = p_raw_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Raw event does not exist';
    END IF;

    IF v_raw.processing_status <> 'PENDING' THEN
        RAISE EXCEPTION
            'Raw event is not pending: %',
            v_raw.processing_status;
    END IF;

    v_payload := v_raw.payload;

    IF NOT (
        v_payload ?& ARRAY[
            'timestamp',
            'category',
            'severity',
            'event_type'
        ]
    ) THEN
        RAISE EXCEPTION 'Required fields are missing';
    END IF;

    v_timestamp := (v_payload->>'timestamp')::TIMESTAMPTZ;

    v_category := upper(
        v_payload->>'category'
    )::event_category;

    v_severity := upper(
        v_payload->>'severity'
    )::event_severity;

    IF NULLIF(trim(v_payload->>'event_type'), '') IS NULL THEN
        RAISE EXCEPTION 'Event type cannot be empty';
    END IF;

    v_source_ip := NULLIF(
        v_payload->>'source_ip',
        ''
    )::INET;

    v_destination_ip := NULLIF(
        v_payload->>'destination_ip',
        ''
    )::INET;

    SELECT COALESCE(
        jsonb_object_agg(key, value),
        '{}'::JSONB
    )
    INTO v_attributes
    FROM jsonb_each(v_payload)
    WHERE NOT (key = ANY(v_reserved));

    INSERT INTO security_events (
        event_uuid,
        raw_event_id,
        source_id,
        event_timestamp,
        category,
        severity,
        event_type,
        source_ip,
        destination_ip,
        username,
        hostname,
        message,
        attributes
    )
    VALUES (
        gen_random_uuid(),
        p_raw_event_id,
        v_raw.source_id,
        v_timestamp,
        v_category,
        v_severity,
        trim(v_payload->>'event_type'),
        v_source_ip,
        v_destination_ip,
        NULLIF(v_payload->>'username', ''),
        NULLIF(v_payload->>'hostname', ''),
        COALESCE(v_payload->>'message', ''),
        v_attributes
    )
    RETURNING event_id INTO v_event_id;

    UPDATE raw_events
    SET processing_status = 'PROCESSED',
        processing_error = NULL
    WHERE raw_event_id = p_raw_event_id;

    RETURN v_event_id;

EXCEPTION
    WHEN unique_violation THEN
        UPDATE raw_events
        SET processing_status = 'DUPLICATE',
            processing_error = SQLERRM
        WHERE raw_event_id = p_raw_event_id;

        RETURN NULL;

    WHEN OTHERS THEN
        UPDATE raw_events
        SET processing_status = 'REJECTED',
            processing_error = SQLERRM
        WHERE raw_event_id = p_raw_event_id;

        RAISE;
END;
$$;

-- ============================================================================
-- 13. ALERT STATUS TRANSITION ENFORCEMENT
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_alert_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.status = 'OPEN'
            AND NEW.status IN ('INVESTIGATING', 'RESOLVED'))
        OR
        (OLD.status = 'INVESTIGATING'
            AND NEW.status IN ('OPEN', 'RESOLVED'))
        OR
        (OLD.status = 'RESOLVED'
            AND NEW.status = 'OPEN')
        OR
        (OLD.status = 'CLOSED'
            AND NEW.status = 'OPEN')
        OR
        (OLD.status = 'RESOLVED'
            AND NEW.status = 'CLOSED')
    ) THEN
        RAISE EXCEPTION
            'Invalid alert transition: % -> %',
            OLD.status,
            NEW.status;
    END IF;

    NEW.updated_at := NOW();

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_alert_transition
BEFORE UPDATE OF status
ON security_alerts
FOR EACH ROW
EXECUTE FUNCTION validate_alert_transition();

-- ============================================================================
-- 14. ALERT AUDIT TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION audit_alert_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.status IS DISTINCT FROM NEW.status THEN

        INSERT INTO analyst_actions (
            alert_id,
            analyst_id,
            action_type,
            previous_status,
            new_status,
            action_notes
        )
        VALUES (
            NEW.alert_id,
            COALESCE(NEW.assigned_to, 'SYSTEM'),
            CASE NEW.status
                WHEN 'INVESTIGATING' THEN 'INVESTIGATED'
                WHEN 'RESOLVED' THEN 'RESOLVED'
                WHEN 'CLOSED' THEN 'CLOSED'
                WHEN 'OPEN' THEN 'REOPENED'
            END,
            OLD.status,
            NEW.status,
            'Automatic alert lifecycle audit'
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_alert_transition
AFTER UPDATE OF status
ON security_alerts
FOR EACH ROW
EXECUTE FUNCTION audit_alert_transition();

-- ============================================================================
-- 15. CORRELATION PROCESSING FUNCTION
-- ============================================================================

CREATE OR REPLACE FUNCTION execute_correlation_rule(
    p_rule_id BIGINT,
    p_reference_time TIMESTAMPTZ DEFAULT NOW()
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_rule correlation_rules%ROWTYPE;
    v_execution_id BIGINT;
    v_events_examined BIGINT := 0;
    v_alerts_created BIGINT := 0;
    v_group RECORD;
    v_alert_id BIGINT;
    v_first TIMESTAMPTZ;
    v_last TIMESTAMPTZ;
    v_event_ids BIGINT[];
    v_count INTEGER;
BEGIN
    SELECT *
    INTO v_rule
    FROM correlation_rules
    WHERE rule_id = p_rule_id
      AND enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active correlation rule not found';
    END IF;

    INSERT INTO correlation_executions(rule_id)
    VALUES (p_rule_id)
    RETURNING execution_id INTO v_execution_id;

    SELECT COUNT(*)
    INTO v_events_examined
    FROM security_events
    WHERE category = v_rule.category
      AND event_type = v_rule.event_type
      AND event_timestamp <= p_reference_time
      AND event_timestamp >=
          p_reference_time -
          make_interval(secs => v_rule.window_seconds);

    /*
       This demonstration rule supports two explicit grouping
       fields: source_ip and username.
       Other rule types require their own typed implementation.
    */

    IF v_rule.grouping_fields <> ARRAY['source_ip', 'username'] THEN
        RAISE EXCEPTION
            'Unsupported grouping configuration for this function';
    END IF;

    FOR v_group IN
        SELECT
            source_ip,
            username,
            COUNT(*) AS event_count,
            MIN(event_timestamp) AS first_seen,
            MAX(event_timestamp) AS last_seen,
            ARRAY_AGG(event_id ORDER BY event_timestamp) AS event_ids
        FROM security_events
        WHERE category = v_rule.category
          AND event_type = v_rule.event_type
          AND source_ip IS NOT NULL
          AND username IS NOT NULL
          AND event_timestamp <= p_reference_time
          AND event_timestamp >=
              p_reference_time -
              make_interval(secs => v_rule.window_seconds)
        GROUP BY source_ip, username
        HAVING COUNT(*) >= v_rule.threshold_count
    LOOP
        v_count := v_group.event_count;
        v_first := v_group.first_seen;
        v_last := v_group.last_seen;
        v_event_ids := v_group.event_ids;

        /*
           Alert creation and evidence insertion occur in one
           transaction. The advisory lock serializes the same
           rule and grouping key during concurrent execution.
        */

        PERFORM pg_advisory_xact_lock(
            p_rule_id,
            hashtext(
                v_group.source_ip::TEXT ||
                '|' ||
                v_group.username
            )
        );

        INSERT INTO security_alerts (
            alert_uuid,
            rule_id,
            title,
            description,
            severity,
            first_observed_at,
            last_observed_at
        )
        SELECT
            gen_random_uuid(),
            v_rule.rule_id,
            v_rule.rule_name,
            format(
                '%s matching events from %s for user %s',
                v_count,
                v_group.source_ip,
                v_group.username
            ),
            v_rule.alert_severity,
            v_first,
            v_last
        WHERE NOT EXISTS (
            SELECT 1
            FROM security_alerts a
            JOIN alert_evidence ae
                ON ae.alert_id = a.alert_id
            WHERE a.rule_id = v_rule.rule_id
              AND a.status <> 'CLOSED'
              AND ae.event_id = ANY(v_event_ids)
        )
        RETURNING alert_id INTO v_alert_id;

        IF v_alert_id IS NOT NULL THEN
            INSERT INTO alert_evidence (
                alert_id,
                event_id,
                evidence_role
            )
            SELECT
                v_alert_id,
                event_id,
                'BRUTE_FORCE_ATTEMPT'
            FROM unnest(v_event_ids) AS event_id;

            v_alerts_created := v_alerts_created + 1;
        END IF;

        v_alert_id := NULL;
    END LOOP;

    UPDATE correlation_executions
    SET execution_finished_at = NOW(),
        events_examined = v_events_examined,
        alerts_created = v_alerts_created,
        execution_status = 'COMPLETED'
    WHERE execution_id = v_execution_id;

    RETURN v_execution_id;

EXCEPTION
    WHEN OTHERS THEN
        UPDATE correlation_executions
        SET execution_finished_at = NOW(),
            execution_status = 'FAILED',
            error_message = SQLERRM
        WHERE execution_id = v_execution_id;

        RAISE;
END;
$$;

-- ============================================================================
-- 16. CRITICAL EVENT CORRELATION
-- ============================================================================

CREATE OR REPLACE FUNCTION generate_critical_alerts(
    p_since TIMESTAMPTZ
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER := 0;
    v_event RECORD;
BEGIN
    FOR v_event IN
        SELECT *
        FROM security_events
        WHERE severity = 'CRITICAL'
          AND event_timestamp >= p_since
    LOOP
        INSERT INTO security_alerts (
            alert_uuid,
            rule_id,
            title,
            description,
            severity,
            first_observed_at,
            last_observed_at
        )
        SELECT
            gen_random_uuid(),
            NULL,
            'Critical security event',
            v_event.message,
            'CRITICAL',
            v_event.event_timestamp,
            v_event.event_timestamp
        WHERE NOT EXISTS (
            SELECT 1
            FROM alert_evidence ae
            JOIN security_alerts a
                ON a.alert_id = ae.alert_id
            WHERE ae.event_id = v_event.event_id
              AND a.rule_id IS NULL
        )
        RETURNING alert_id INTO v_count;

        IF v_count IS NOT NULL THEN
            INSERT INTO alert_evidence (
                alert_id,
                event_id,
                evidence_role
            )
            SELECT
                a.alert_id,
                v_event.event_id,
                'CRITICAL_EVENT'
            FROM security_alerts a
            WHERE a.alert_id = v_count;

            v_count := 1;
        ELSE
            v_count := 0;
        END IF;

        -- Accumulate the number of newly created alerts.
        IF v_count = 1 THEN
            v_count := 0;
        END IF;
    END LOOP;

    RETURN v_count;
END;
$$;

-- ============================================================================
-- 17. REPORTING VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW event_severity_summary AS
SELECT
    severity,
    COUNT(*) AS event_count,
    COUNT(DISTINCT source_id) AS contributing_sources,
    MIN(event_timestamp) AS first_observed,
    MAX(event_timestamp) AS last_observed
FROM security_events
GROUP BY severity;

CREATE OR REPLACE VIEW event_category_summary AS
SELECT
    category,
    COUNT(*) AS event_count,
    COUNT(DISTINCT source_id) AS contributing_sources
FROM security_events
GROUP BY category;

CREATE OR REPLACE VIEW source_health_summary AS
SELECT
    ds.source_code,
    ds.source_name,
    ds.status AS source_status,
    COUNT(DISTINCT c.collector_id) AS collector_count,
    COALESCE(SUM(c.events_received), 0) AS received_count,
    COALESCE(SUM(c.events_dropped), 0) AS dropped_count,
    MAX(c.last_heartbeat_at) AS last_heartbeat
FROM data_sources ds
LEFT JOIN collectors c
    ON c.source_id = ds.source_id
GROUP BY
    ds.source_id,
    ds.source_code,
    ds.source_name,
    ds.status;

CREATE OR REPLACE VIEW alert_dashboard AS
SELECT
    a.alert_id,
    a.title,
    a.severity,
    a.status,
    a.assigned_to,
    a.created_at,
    COUNT(ae.event_id) AS evidence_count,
    MIN(e.event_timestamp) AS first_evidence,
    MAX(e.event_timestamp) AS last_evidence
FROM security_alerts a
LEFT JOIN alert_evidence ae
    ON ae.alert_id = a.alert_id
LEFT JOIN security_events e
    ON e.event_id = ae.event_id
GROUP BY a.alert_id;

CREATE OR REPLACE VIEW soc_operational_dashboard AS
SELECT
    (SELECT COUNT(*) FROM security_events) AS total_events,

    (SELECT COUNT(*) FROM raw_events) AS raw_events_received,

    (
        SELECT COUNT(*)
        FROM raw_events
        WHERE processing_status = 'PENDING'
    ) AS pending_events,

    (
        SELECT COUNT(*)
        FROM raw_events
        WHERE processing_status = 'REJECTED'
    ) AS rejected_events,

    (
        SELECT COUNT(*)
        FROM security_alerts
    ) AS total_alerts,

    (
        SELECT COUNT(*)
        FROM security_alerts
        WHERE status = 'OPEN'
    ) AS open_alerts,

    (
        SELECT COUNT(*)
        FROM security_alerts
        WHERE status = 'INVESTIGATING'
    ) AS investigating_alerts,

    (
        SELECT COUNT(*)
        FROM security_alerts
        WHERE status = 'RESOLVED'
    ) AS resolved_alerts;

-- ============================================================================
-- 18. SAMPLE DATA SOURCES
-- ============================================================================

INSERT INTO data_sources (
    source_code,
    source_name,
    source_type,
    environment
)
VALUES
(
    'firewall-01',
    'Enterprise Firewall',
    'NETWORK',
    'PRODUCTION'
),
(
    'edr-01',
    'Endpoint Detection Platform',
    'ENDPOINT',
    'PRODUCTION'
),
(
    'identity-01',
    'Identity and Authentication Service',
    'IDENTITY',
    'PRODUCTION'
),
(
    'cloud-01',
    'Cloud Audit Service',
    'CLOUD',
    'PRODUCTION'
),
(
    'test-source',
    'Disabled Test Source',
    'APPLICATION',
    'TEST'
);

UPDATE data_sources
SET status = 'DISABLED'
WHERE source_code = 'test-source';

-- ============================================================================
-- 19. SAMPLE COLLECTORS
-- ============================================================================

INSERT INTO collectors (
    collector_code,
    source_id,
    collector_type,
    status,
    started_at,
    last_heartbeat_at
)
SELECT
    'collector-firewall',
    source_id,
    'SYSLOG',
    'RUNNING',
    NOW() - INTERVAL '2 days',
    NOW()
FROM data_sources
WHERE source_code = 'firewall-01';

INSERT INTO collectors (
    collector_code,
    source_id,
    collector_type,
    status,
    started_at,
    last_heartbeat_at
)
SELECT
    'collector-edr',
    source_id,
    'API',
    'RUNNING',
    NOW() - INTERVAL '2 days',
    NOW()
FROM data_sources
WHERE source_code = 'edr-01';

INSERT INTO collectors (
    collector_code,
    source_id,
    collector_type,
    status,
    started_at,
    last_heartbeat_at
)
SELECT
    'collector-identity',
    source_id,
    'AGENT',
    'RUNNING',
    NOW() - INTERVAL '2 days',
    NOW()
FROM data_sources
WHERE source_code = 'identity-01';

-- ============================================================================
-- 20. SAMPLE CORRELATION POLICY
-- ============================================================================

INSERT INTO correlation_rules (
    rule_code,
    rule_name,
    description,
    category,
    event_type,
    threshold_count,
    window_seconds,
    grouping_fields,
    alert_severity
)
VALUES
(
    'AUTH-BRUTE-FORCE',
    'Possible Brute-Force Attack',
    'Detects repeated authentication failures from one IP against one user.',
    'AUTHENTICATION',
    'LOGIN_FAILURE',
    5,
    300,
    ARRAY['source_ip', 'username'],
    'HIGH'
),
(
    'ENDPOINT-MALWARE',
    'Critical Endpoint Malware',
    'Identifies endpoint malware detections.',
    'ENDPOINT',
    'MALWARE_DETECTED',
    2,
    300,
    ARRAY['source_ip', 'username'],
    'CRITICAL'
);

-- ============================================================================
-- 21. SAMPLE RAW EVENT INGESTION
-- ============================================================================

DO $$
DECLARE
    v_firewall_collector BIGINT;
    v_edr_collector BIGINT;
    v_firewall_source BIGINT;
    v_edr_source BIGINT;
    v_raw_id BIGINT;
    v_payload JSONB;
    v_hash TEXT;
    v_timestamp TIMESTAMPTZ;
    i INTEGER;
BEGIN
    SELECT c.collector_id, c.source_id
    INTO v_firewall_collector, v_firewall_source
    FROM collectors c
    JOIN data_sources d USING (source_id)
    WHERE d.source_code = 'firewall-01';

    SELECT c.collector_id, c.source_id
    INTO v_edr_collector, v_edr_source
    FROM collectors c
    JOIN data_sources d USING (source_id)
    WHERE d.source_code = 'edr-01';

    -- Six authentication failures within the correlation window.
    FOR i IN 1..6 LOOP
        v_timestamp := NOW() - INTERVAL '3 minutes'
                       + make_interval(secs => i * 20);

        v_payload := jsonb_build_object(
            'timestamp', v_timestamp,
            'category', 'AUTHENTICATION',
            'severity', 'MEDIUM',
            'event_type', 'LOGIN_FAILURE',
            'source_ip', '203.0.113.45',
            'username', 'admin',
            'hostname', 'identity-server-01',
            'message', 'Authentication failure',
            'authentication_method', 'PASSWORD'
        );

        v_hash := encode(
            sha256(convert_to(v_payload::TEXT, 'UTF8')),
            'hex'
        );

        v_raw_id := ingest_raw_event(
            v_firewall_collector,
            v_firewall_source,
            v_payload,
            v_hash::CHAR(64)
        );

        PERFORM normalize_raw_event(v_raw_id);
    END LOOP;

    -- Critical endpoint event.
    v_payload := jsonb_build_object(
        'timestamp', NOW(),
        'category', 'ENDPOINT',
        'severity', 'CRITICAL',
        'event_type', 'MALWARE_DETECTED',
        'source_ip', '192.0.2.10',
        'username', 'analyst',
        'hostname', 'endpoint-01',
        'message', 'Suspicious executable detected',
        'detection_engine', 'EDR'
    );

    v_hash := encode(
        sha256(convert_to(v_payload::TEXT, 'UTF8')),
        'hex'
    );

    v_raw_id := ingest_raw_event(
        v_edr_collector,
        v_edr_source,
        v_payload,
        v_hash::CHAR(64)
    );

    PERFORM normalize_raw_event(v_raw_id);

    -- Normal network event.
    v_payload := jsonb_build_object(
        'timestamp', NOW(),
        'category', 'NETWORK',
        'severity', 'LOW',
        'event_type', 'CONNECTION_ALLOWED',
        'source_ip', '192.0.2.20',
        'destination_ip', '198.51.100.10',
        'hostname', 'gateway-01',
        'message', 'Permitted network connection'
    );

    v_hash := encode(
        sha256(convert_to(v_payload::TEXT, 'UTF8')),
        'hex'
    );

    v_raw_id := ingest_raw_event(
        v_firewall_collector,
        v_firewall_source,
        v_payload,
        v_hash::CHAR(64)
    );

    PERFORM normalize_raw_event(v_raw_id);
END;
$$;

-- ============================================================================
-- 22. CORRELATION EXECUTION
-- ============================================================================

SELECT execute_correlation_rule(
    rule_id,
    NOW()
)
FROM correlation_rules
WHERE rule_code = 'AUTH-BRUTE-FORCE';

SELECT generate_critical_alerts(
    NOW() - INTERVAL '1 hour'
);

-- ============================================================================
-- 23. ANALYST WORKFLOW
-- ============================================================================

DO $$
DECLARE
    v_alert_id BIGINT;
BEGIN
    SELECT alert_id
    INTO v_alert_id
    FROM security_alerts
    WHERE status = 'OPEN'
    ORDER BY severity DESC, created_at
    LIMIT 1;

    IF v_alert_id IS NOT NULL THEN

        UPDATE security_alerts
        SET assigned_to = 'analyst-01',
            status = 'INVESTIGATING'
        WHERE alert_id = v_alert_id;

        UPDATE security_alerts
        SET status = 'RESOLVED',
            resolution_notes = 'Investigation completed; evidence reviewed.'
        WHERE alert_id = v_alert_id;
    END IF;
END;
$$;

-- ============================================================================
-- 24. RETRIEVAL QUERIES
-- ============================================================================

-- Latest normalized events.
SELECT
    event_id,
    event_timestamp,
    source_id,
    category,
    severity,
    event_type,
    source_ip,
    username,
    hostname
FROM security_events
ORDER BY event_timestamp DESC
LIMIT 50;

-- Authentication failures grouped by user and source IP.
SELECT
    source_ip,
    username,
    COUNT(*) AS failure_count,
    MIN(event_timestamp) AS first_failure,
    MAX(event_timestamp) AS last_failure
FROM security_events
WHERE category = 'AUTHENTICATION'
  AND event_type = 'LOGIN_FAILURE'
GROUP BY source_ip, username
ORDER BY failure_count DESC;

-- High and critical endpoint events.
SELECT *
FROM security_events
WHERE category = 'ENDPOINT'
  AND severity IN ('HIGH', 'CRITICAL')
ORDER BY event_timestamp DESC;

-- ============================================================================
-- 25. VALIDATION QUERIES
-- ============================================================================

-- Events that failed parsing.
SELECT
    raw_event_id,
    source_id,
    processing_status,
    processing_error
FROM raw_events
WHERE processing_status IN ('REJECTED', 'DUPLICATE');

-- Sources without active collectors.
SELECT
    ds.source_code,
    ds.source_name,
    ds.status
FROM data_sources ds
WHERE ds.status = 'ACTIVE'
  AND NOT EXISTS (
      SELECT 1
      FROM collectors c
      WHERE c.source_id = ds.source_id
        AND c.status = 'RUNNING'
  );

-- Collector ingestion loss.
SELECT
    collector_code,
    events_received,
    events_dropped,
    CASE
        WHEN events_received = 0 THEN 0
        ELSE ROUND(
            100.0 * events_dropped /
            (events_received + events_dropped),
            2
        )
    END AS drop_percentage
FROM collectors;

-- ============================================================================
-- 26. AGGREGATION AND EVALUATION
-- ============================================================================

SELECT * FROM event_severity_summary;

SELECT * FROM event_category_summary;

SELECT * FROM source_health_summary;

-- Correlation execution history.
SELECT
    r.rule_code,
    r.rule_name,
    e.execution_started_at,
    e.execution_status,
    e.events_examined,
    e.alerts_created,
    e.error_message
FROM correlation_executions e
JOIN correlation_rules r USING (rule_id)
ORDER BY e.execution_started_at DESC;

-- ============================================================================
-- 27. ALERT ELIGIBILITY AND INVESTIGATION REPORTING
-- ============================================================================

-- Alerts requiring analyst attention.
SELECT
    alert_id,
    title,
    severity,
    status,
    assigned_to,
    created_at
FROM security_alerts
WHERE status IN ('OPEN', 'INVESTIGATING')
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    created_at;

-- Alerts without an assigned analyst.
SELECT
    alert_id,
    title,
    severity,
    created_at
FROM security_alerts
WHERE status = 'OPEN'
  AND assigned_to IS NULL;

-- Evidence supporting every alert.
SELECT
    a.alert_id,
    a.title,
    e.event_id,
    e.event_type,
    e.event_timestamp,
    e.source_ip,
    e.username,
    ae.evidence_role
FROM security_alerts a
JOIN alert_evidence ae USING (alert_id)
JOIN security_events e USING (event_id)
ORDER BY a.alert_id, e.event_timestamp;

-- ============================================================================
-- 28. WINDOW-BASED CORRELATION QUERY
-- ============================================================================

WITH ordered_failures AS (
    SELECT
        event_id,
        source_ip,
        username,
        event_timestamp,

        COUNT(*) OVER (
            PARTITION BY source_ip, username
            ORDER BY event_timestamp
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING
                      AND CURRENT ROW
        ) AS failures_in_window

    FROM security_events
    WHERE category = 'AUTHENTICATION'
      AND event_type = 'LOGIN_FAILURE'
      AND source_ip IS NOT NULL
      AND username IS NOT NULL
)
SELECT
    source_ip,
    username,
    event_timestamp,
    failures_in_window
FROM ordered_failures
WHERE failures_in_window >= 5
ORDER BY event_timestamp;

-- ============================================================================
-- 29. OPERATIONAL DASHBOARD
-- ============================================================================

SELECT * FROM soc_operational_dashboard;

SELECT * FROM alert_dashboard;

-- ============================================================================
-- 30. TRANSACTIONAL VALIDATION
-- ============================================================================

SAVEPOINT before_test;

-- Demonstrate a valid alert transition.
DO $$
DECLARE
    v_alert_id BIGINT;
BEGIN
    SELECT alert_id
    INTO v_alert_id
    FROM security_alerts
    WHERE status = 'OPEN'
    LIMIT 1;

    IF v_alert_id IS NOT NULL THEN
        UPDATE security_alerts
        SET status = 'INVESTIGATING'
        WHERE alert_id = v_alert_id;
    END IF;
END;
$$;

-- Demonstrate rollback of an intentional invalid operation.
SAVEPOINT invalid_transition_test;

DO $$
DECLARE
    v_alert_id BIGINT;
BEGIN
    SELECT alert_id
    INTO v_alert_id
    FROM security_alerts
    WHERE status = 'INVESTIGATING'
    LIMIT 1;

    IF v_alert_id IS NOT NULL THEN
        -- INVESTIGATING -> CLOSED is not an allowed transition.
        UPDATE security_alerts
        SET status = 'CLOSED'
        WHERE alert_id = v_alert_id;
    END IF;
END;
$$;

-- If the previous demonstration is executed interactively,
-- PostgreSQL reports the trigger exception. Roll back to the
-- savepoint to recover the transaction.
-- The following statement is intended for execution after
-- catching that error in a transaction-capable client.
--
-- ROLLBACK TO SAVEPOINT invalid_transition_test;

-- ============================================================================
-- 31. FINAL INTEGRITY REPORT
-- ============================================================================

SELECT
    (SELECT COUNT(*) FROM data_sources) AS data_sources,
    (SELECT COUNT(*) FROM collectors) AS collectors,
    (SELECT COUNT(*) FROM raw_events) AS raw_events,
    (SELECT COUNT(*) FROM security_events) AS normalized_events,
    (SELECT COUNT(*) FROM correlation_rules) AS correlation_rules,
    (SELECT COUNT(*) FROM security_alerts) AS alerts,
    (SELECT COUNT(*) FROM alert_evidence) AS evidence_records,
    (SELECT COUNT(*) FROM analyst_actions) AS analyst_actions;

COMMIT;

/*
Operational notes:

1. Raw payloads and normalized events are separate records.
2. Raw JSONB is retained for parsing investigation and audit.
3. INET provides native IP validation and indexing.
4. Event UUIDs provide external event identifiers.
5. Correlation policies separate detection conditions from storage.
6. Alert evidence preserves event-to-alert relationships.
7. Alert triggers validate transitions and record audit actions.
8. Dashboard views provide reusable reporting queries.
9. The demonstration correlation function supports source_ip and
   username grouping. More complex rules require dedicated
   typed correlation implementations.
10. Production ingestion should use controlled database roles,
    encrypted connections, partitioned event tables, retention
    policies, queue-based processing, and explicit transaction
    retry handling.
11. For large deployments, use time-based partitioning and
    retention-aware indexes rather than unlimited event storage.
12. Application-level authentication, authorization, and
    database privilege separation remain necessary.
*/
