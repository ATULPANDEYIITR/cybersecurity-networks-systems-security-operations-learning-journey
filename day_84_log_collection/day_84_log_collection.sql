/*
===============================================================================
DISTRIBUTED LOG COLLECTION PLATFORM
PostgreSQL 15+

Database capabilities:
- Agent registration and source configuration
- Collection batches
- Raw log ingestion
- Normalized events
- Timestamp normalization
- Severity classification
- Deduplication
- Forwarding attempts
- Destination management
- Dead-letter processing
- Retention and archival
- Operational metrics
- Collection and governance reporting

All timestamps are stored as TIMESTAMPTZ.
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS log_platform;

SET search_path TO log_platform, public;

-- ============================================================================
-- DOMAIN TYPES
-- ============================================================================

CREATE TYPE source_type AS ENUM (
    'JSON',
    'SYSLOG',
    'APPLICATION',
    'SYSTEM',
    'NETWORK'
);

CREATE TYPE severity_level AS ENUM (
    'DEBUG',
    'INFO',
    'WARNING',
    'ERROR',
    'CRITICAL'
);

CREATE TYPE event_state AS ENUM (
    'COLLECTED',
    'NORMALIZED',
    'QUEUED',
    'FORWARDED',
    'FAILED',
    'ARCHIVED'
);

CREATE TYPE agent_status AS ENUM (
    'ACTIVE',
    'DISABLED',
    'REVOKED'
);

CREATE TYPE batch_status AS ENUM (
    'OPEN',
    'PROCESSING',
    'COMPLETED',
    'FAILED'
);

CREATE TYPE delivery_status AS ENUM (
    'PENDING',
    'DELIVERED',
    'RETRYING',
    'FAILED',
    'DEAD_LETTERED'
);

-- ============================================================================
-- AGENTS
-- ============================================================================

CREATE TABLE collection_agents (
    agent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    agent_name VARCHAR(150) NOT NULL UNIQUE,

    hostname VARCHAR(255) NOT NULL,

    environment VARCHAR(50) NOT NULL,

    source source_type NOT NULL,

    status agent_status NOT NULL DEFAULT 'ACTIVE',

    agent_version VARCHAR(50),

    last_heartbeat TIMESTAMPTZ,

    registered_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_agent_name
        CHECK (length(trim(agent_name)) > 0),

    CONSTRAINT valid_hostname
        CHECK (length(trim(hostname)) > 0)
);

CREATE INDEX idx_agents_status
    ON collection_agents(status);

CREATE INDEX idx_agents_environment
    ON collection_agents(environment);

-- ============================================================================
-- COLLECTION BATCHES
-- ============================================================================

CREATE TABLE collection_batches (
    batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    agent_id UUID NOT NULL
        REFERENCES collection_agents(agent_id),

    batch_number BIGINT NOT NULL,

    status batch_status NOT NULL DEFAULT 'OPEN',

    received_count INTEGER NOT NULL DEFAULT 0,

    accepted_count INTEGER NOT NULL DEFAULT 0,

    rejected_count INTEGER NOT NULL DEFAULT 0,

    started_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CONSTRAINT unique_agent_batch
        UNIQUE(agent_id, batch_number),

    CONSTRAINT valid_batch_counts
        CHECK (
            received_count >= 0
            AND accepted_count >= 0
            AND rejected_count >= 0
            AND accepted_count + rejected_count <= received_count
        )
);

CREATE INDEX idx_batches_status
    ON collection_batches(status, started_at DESC);

-- ============================================================================
-- LOG DESTINATIONS
-- ============================================================================

CREATE TABLE log_destinations (
    destination_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    destination_name VARCHAR(150) NOT NULL UNIQUE,

    destination_type VARCHAR(50) NOT NULL,

    endpoint_reference TEXT,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    max_batch_size INTEGER NOT NULL DEFAULT 500,

    connection_timeout_seconds INTEGER NOT NULL DEFAULT 10,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_batch_size
        CHECK (max_batch_size BETWEEN 1 AND 10000),

    CONSTRAINT valid_timeout
        CHECK (connection_timeout_seconds BETWEEN 1 AND 300)
);

-- ============================================================================
-- RAW LOG EVENTS
-- ============================================================================

CREATE TABLE raw_log_events (
    raw_event_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    event_uuid UUID NOT NULL DEFAULT gen_random_uuid(),

    agent_id UUID NOT NULL
        REFERENCES collection_agents(agent_id),

    batch_id UUID
        REFERENCES collection_batches(batch_id),

    raw_payload TEXT NOT NULL,

    source_timestamp TEXT,

    received_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    parsing_error TEXT,

    processed BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT unique_raw_event
        UNIQUE(event_uuid),

    CONSTRAINT valid_raw_payload
        CHECK (
            length(raw_payload) > 0
            AND octet_length(raw_payload) <= 1048576
        )
);

CREATE INDEX idx_raw_events_agent_received
    ON raw_log_events(agent_id, received_at DESC);

CREATE INDEX idx_raw_events_unprocessed
    ON raw_log_events(received)
    WHERE processed = FALSE;

-- ============================================================================
-- NORMALIZED EVENTS
-- ============================================================================

CREATE TABLE normalized_log_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    raw_event_id BIGINT UNIQUE
        REFERENCES raw_log_events(raw_event_id),

    event_uuid UUID NOT NULL UNIQUE,

    agent_id UUID NOT NULL
        REFERENCES collection_agents(agent_id),

    hostname VARCHAR(255) NOT NULL,

    environment VARCHAR(50) NOT NULL,

    source source_type NOT NULL,

    event_timestamp TIMESTAMPTZ NOT NULL,

    received_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    severity severity_level NOT NULL,

    message TEXT NOT NULL,

    attributes JSONB NOT NULL DEFAULT '{}'::JSONB,

    fingerprint CHAR(64) NOT NULL UNIQUE,

    state event_state NOT NULL DEFAULT 'NORMALIZED',

    CONSTRAINT valid_message_length
        CHECK (length(message) <= 10000),

    CONSTRAINT attributes_must_be_object
        CHECK (jsonb_typeof(attributes) = 'object'),

    CONSTRAINT valid_fingerprint
        CHECK (fingerprint ~ '^[a-f0-9]{64}$')
);

CREATE INDEX idx_events_timestamp
    ON normalized_log_events(event_timestamp DESC);

CREATE INDEX idx_events_agent_timestamp
    ON normalized_log_events(agent_id, event_timestamp DESC);

CREATE INDEX idx_events_severity_timestamp
    ON normalized_log_events(severity, event_timestamp DESC);

CREATE INDEX idx_events_environment
    ON normalized_log_events(environment);

CREATE INDEX idx_events_attributes
    ON normalized_log_events USING GIN(attributes);

CREATE INDEX idx_events_message_search
    ON normalized_log_events USING GIN(
        to_tsvector('english', message)
    );

CREATE INDEX idx_events_forwarding_queue
    ON normalized_log_events(event_id)
    WHERE state = 'QUEUED';

-- ============================================================================
-- RETENTION POLICIES
-- ============================================================================

CREATE TABLE retention_policies (
    policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    environment VARCHAR(50),

    hot_retention_days INTEGER NOT NULL,

    archive_retention_days INTEGER NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_retention_periods
        CHECK (
            hot_retention_days > 0
            AND archive_retention_days > hot_retention_days
        )
);

INSERT INTO retention_policies (
    policy_name,
    environment,
    hot_retention_days,
    archive_retention_days
)
VALUES
(
    'Production Standard',
    'production',
    30,
    365
),
(
    'Development Standard',
    'development',
    7,
    30
),
(
    'Security Audit',
    'security',
    90,
    730
);

-- ============================================================================
-- ARCHIVED EVENTS
-- ============================================================================

CREATE TABLE archived_log_events (
    archive_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    original_event_id BIGINT NOT NULL UNIQUE,

    event_uuid UUID NOT NULL,

    agent_id UUID NOT NULL,

    hostname VARCHAR(255) NOT NULL,

    environment VARCHAR(50) NOT NULL,

    source source_type NOT NULL,

    event_timestamp TIMESTAMPTZ NOT NULL,

    severity severity_level NOT NULL,

    message TEXT NOT NULL,

    attributes JSONB NOT NULL,

    fingerprint CHAR(64) NOT NULL UNIQUE,

    archived_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_archive_timestamp
    ON archived_log_events(event_timestamp DESC);

CREATE INDEX idx_archive_environment
    ON archived_log_events(environment);

-- ============================================================================
-- DELIVERY ATTEMPTS
-- ============================================================================

CREATE TABLE delivery_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    event_id BIGINT NOT NULL
        REFERENCES normalized_log_events(event_id),

    destination_id UUID NOT NULL
        REFERENCES log_destinations(destination_id),

    attempt_number INTEGER NOT NULL,

    status delivery_status NOT NULL DEFAULT 'PENDING',

    attempted_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    error_message TEXT,

    external_reference TEXT,

    CONSTRAINT unique_delivery_attempt
        UNIQUE(event_id, destination_id, attempt_number),

    CONSTRAINT valid_attempt_number
        CHECK (attempt_number > 0)
);

CREATE INDEX idx_delivery_pending
    ON delivery_attempts(status, attempted_at)
    WHERE status IN ('PENDING', 'RETRYING');

CREATE INDEX idx_delivery_event
    ON delivery_attempts(event_id, destination_id);

-- ============================================================================
-- DEAD LETTER EVENTS
-- ============================================================================

CREATE TABLE dead_letter_events (
    dead_letter_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    event_id BIGINT NOT NULL
        REFERENCES normalized_log_events(event_id),

    destination_id UUID NOT NULL
        REFERENCES log_destinations(destination_id),

    failure_reason TEXT NOT NULL,

    total_attempts INTEGER NOT NULL,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP,

    replayed_at TIMESTAMPTZ,

    CONSTRAINT valid_failure_attempts
        CHECK (total_attempts > 0),

    CONSTRAINT unique_dead_letter
        UNIQUE(event_id, destination_id)
);

-- ============================================================================
-- OPERATIONAL METRICS
-- ============================================================================

CREATE TABLE collection_metrics (
    metric_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    agent_id UUID
        REFERENCES collection_agents(agent_id),

    metric_name VARCHAR(100) NOT NULL,

    metric_value NUMERIC(20, 4) NOT NULL,

    recorded_at TIMESTAMPTZ NOT NULL
        DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_metrics_name_time
    ON collection_metrics(metric_name, recorded_at DESC);

-- ============================================================================
-- TIMESTAMP NORMALIZATION
-- ============================================================================

CREATE OR REPLACE FUNCTION normalize_log_timestamp(
    p_timestamp TEXT
)
RETURNS TIMESTAMPTZ
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result TIMESTAMPTZ;
BEGIN
    IF length(trim(p_timestamp)) = 0 THEN
        RAISE EXCEPTION 'Timestamp cannot be empty';
    END IF;

    BEGIN
        result := p_timestamp::TIMESTAMPTZ;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE EXCEPTION
                'Invalid timestamp: %',
                p_timestamp;
    END;

    RETURN result;
END;
$$;

-- ============================================================================
-- SEVERITY NORMALIZATION
-- ============================================================================

CREATE OR REPLACE FUNCTION normalize_severity(
    p_severity TEXT
)
RETURNS severity_level
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    normalized TEXT;
BEGIN
    normalized := lower(trim(p_severity));

    RETURN CASE normalized
        WHEN 'trace' THEN 'DEBUG'::severity_level
        WHEN 'debug' THEN 'DEBUG'::severity_level
        WHEN 'info' THEN 'INFO'::severity_level
        WHEN 'notice' THEN 'INFO'::severity_level
        WHEN 'warn' THEN 'WARNING'::severity_level
        WHEN 'warning' THEN 'WARNING'::severity_level
        WHEN 'error' THEN 'ERROR'::severity_level
        WHEN 'critical' THEN 'CRITICAL'::severity_level
        WHEN 'fatal' THEN 'CRITICAL'::severity_level
        WHEN 'emergency' THEN 'CRITICAL'::severity_level
        ELSE NULL
    END;

    IF normalize_severity IS NULL THEN
        RAISE EXCEPTION 'Unsupported severity: %', p_severity;
    END IF;
END;
$$;

-- ============================================================================
-- SENSITIVE DATA REDACTION
-- ============================================================================

CREATE OR REPLACE FUNCTION redact_log_message(
    p_message TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    result TEXT;
BEGIN
    result := regexp_replace(
        p_message,
        '(password|passwd|token|secret|api_key)[[:space:]]*[=:][[:space:]]*[^,[:space:]]+',
        '\1=[REDACTED]',
        'gi'
    );

    result := regexp_replace(
        result,
        '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        '[EMAIL_REDACTED]',
        'g'
    );

    RETURN result;
END;
$$;

-- ============================================================================
-- EVENT VALIDATION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_normalized_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF length(trim(NEW.hostname)) = 0 THEN
        RAISE EXCEPTION 'Hostname is required';
    END IF;

    IF length(NEW.message) > 10000 THEN
        RAISE EXCEPTION 'Message exceeds maximum size';
    END IF;

    IF jsonb_typeof(NEW.attributes) <> 'object' THEN
        RAISE EXCEPTION 'Attributes must be a JSON object';
    END IF;

    NEW.message := redact_log_message(NEW.message);

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_normalized_event
BEFORE INSERT OR UPDATE
ON normalized_log_events
FOR EACH ROW
EXECUTE FUNCTION validate_normalized_event();

-- ============================================================================
-- COLLECTION BATCH COUNTERS
-- ============================================================================

CREATE OR REPLACE FUNCTION update_batch_counters()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.batch_id IS NOT NULL THEN
        UPDATE collection_batches
        SET
            received_count = received_count + 1,
            accepted_count = accepted_count + 1
        WHERE batch_id = NEW.batch_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_raw_event_batch_counter
AFTER INSERT
ON raw_log_events
FOR EACH ROW
EXECUTE FUNCTION update_batch_counters();

-- ============================================================================
-- IDEMPOTENT NORMALIZED EVENT INSERTION
-- ============================================================================

CREATE OR REPLACE FUNCTION insert_normalized_event(
    p_raw_event_id BIGINT,
    p_event_uuid UUID,
    p_agent_id UUID,
    p_hostname VARCHAR,
    p_environment VARCHAR,
    p_source source_type,
    p_timestamp TEXT,
    p_severity TEXT,
    p_message TEXT,
    p_attributes JSONB,
    p_fingerprint CHAR(64)
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    inserted_id BIGINT;
    normalized_level severity_level;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM raw_log_events
        WHERE raw_event_id = p_raw_event_id
          AND agent_id = p_agent_id
    ) THEN
        RAISE EXCEPTION 'Raw event does not belong to agent';
    END IF;

    normalized_level :=
        normalize_severity(p_severity);

    INSERT INTO normalized_log_events (
        raw_event_id,
        event_uuid,
        agent_id,
        hostname,
        environment,
        source,
        event_timestamp,
        severity,
        message,
        attributes,
        fingerprint,
        state
    )
    VALUES (
        p_raw_event_id,
        p_event_uuid,
        p_agent_id,
        p_hostname,
        p_environment,
        p_source,
        normalize_log_timestamp(p_timestamp),
        normalized_level,
        redact_log_message(p_message),
        COALESCE(p_attributes, '{}'::JSONB),
        p_fingerprint,
        'QUEUED'
    )
    ON CONFLICT (fingerprint)
    DO NOTHING
    RETURNING event_id INTO inserted_id;

    IF inserted_id IS NOT NULL THEN
        UPDATE raw_log_events
        SET processed = TRUE
        WHERE raw_event_id = p_raw_event_id;
    END IF;

    RETURN inserted_id;
END;
$$;

-- ============================================================================
-- FORWARDING ELIGIBILITY
-- ============================================================================

CREATE OR REPLACE FUNCTION is_event_deliverable(
    p_event_id BIGINT,
    p_destination_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM normalized_log_events e
        JOIN log_destinations d
            ON d.destination_id = p_destination_id
        WHERE e.event_id = p_event_id
          AND e.state IN ('QUEUED', 'FAILED')
          AND d.enabled = TRUE
          AND NOT EXISTS (
              SELECT 1
              FROM delivery_attempts a
              WHERE a.event_id = e.event_id
                AND a.destination_id = d.destination_id
                AND a.status = 'DELIVERED'
          )
    );
$$;

-- ============================================================================
-- FORWARDING PROCESSING PROCEDURE
-- ============================================================================

CREATE OR REPLACE PROCEDURE process_delivery_attempt(
    p_event_id BIGINT,
    p_destination_id UUID,
    p_success BOOLEAN,
    p_error TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    next_attempt INTEGER;
BEGIN
    IF NOT is_event_deliverable(
        p_event_id,
        p_destination_id
    ) THEN
        RAISE EXCEPTION 'Event is not eligible for delivery';
    END IF;

    SELECT COALESCE(MAX(attempt_number), 0) + 1
    INTO next_attempt
    FROM delivery_attempts
    WHERE event_id = p_event_id
      AND destination_id = p_destination_id;

    INSERT INTO delivery_attempts (
        event_id,
        destination_id,
        attempt_number,
        status,
        completed_at,
        error_message
    )
    VALUES (
        p_event_id,
        p_destination_id,
        next_attempt,
        CASE
            WHEN p_success THEN 'DELIVERED'
            ELSE 'FAILED'
        END,
        CURRENT_TIMESTAMP,
        p_error
    );

    IF p_success THEN
        UPDATE normalized_log_events
        SET state = 'FORWARDED'
        WHERE event_id = p_event_id;

    ELSIF next_attempt >= 3 THEN
        UPDATE normalized_log_events
        SET state = 'FAILED'
        WHERE event_id = p_event_id;

        INSERT INTO dead_letter_events (
            event_id,
            destination_id,
            failure_reason,
            total_attempts
        )
        VALUES (
            p_event_id,
            p_destination_id,
            COALESCE(
                p_error,
                'Maximum attempts exceeded'
            ),
            next_attempt
        )
        ON CONFLICT (event_id, destination_id)
        DO NOTHING;

    ELSE
        UPDATE normalized_log_events
        SET state = 'QUEUED'
        WHERE event_id = p_event_id;
    END IF;
END;
$$;

-- ============================================================================
-- RETENTION PROCESSING
-- ============================================================================

CREATE OR REPLACE PROCEDURE apply_log_retention(
    p_reference_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
)
LANGUAGE plpgsql
AS $$
DECLARE
    policy RECORD;
BEGIN
    FOR policy IN
        SELECT *
        FROM retention_policies
        WHERE enabled = TRUE
    LOOP
        -- Archive records after hot retention.
        WITH moved AS (
            DELETE FROM normalized_log_events e
            WHERE e.environment = policy.environment
              AND e.event_timestamp <
                  p_reference_time
                  - make_interval(
                      days => policy.hot_retention_days
                  )
              AND e.event_timestamp >=
                  p_reference_time
                  - make_interval(
                      days => policy.archive_retention_days
                  )
            RETURNING e.*
        )
        INSERT INTO archived_log_events (
            original_event_id,
            event_uuid,
            agent_id,
            hostname,
            environment,
            source,
            event_timestamp,
            severity,
            message,
            attributes,
            fingerprint
        )
        SELECT
            event_id,
            event_uuid,
            agent_id,
            hostname,
            environment,
            source,
            event_timestamp,
            severity,
            message,
            attributes,
            fingerprint
        FROM moved
        ON CONFLICT (original_event_id)
        DO NOTHING;

        -- Remove events older than the archive period.
        DELETE FROM normalized_log_events
        WHERE environment = policy.environment
          AND event_timestamp <
              p_reference_time
              - make_interval(
                  days => policy.archive_retention_days
              );
    END LOOP;
END;
$$;

-- ============================================================================
-- REPORTING VIEWS
-- ============================================================================

CREATE OR REPLACE VIEW v_collection_overview AS
SELECT
    a.agent_id,
    a.agent_name,
    a.hostname,
    a.environment,
    a.source,
    a.status,
    COUNT(e.event_id) AS normalized_events,
    COUNT(e.event_id) FILTER (
        WHERE e.state = 'QUEUED'
    ) AS queued_events,
    COUNT(e.event_id) FILTER (
        WHERE e.state = 'FORWARDED'
    ) AS forwarded_events,
    COUNT(e.event_id) FILTER (
        WHERE e.state = 'FAILED'
    ) AS failed_events,
    MAX(e.received_at) AS last_event_received
FROM collection_agents a
LEFT JOIN normalized_log_events e
    ON e.agent_id = a.agent_id
GROUP BY
    a.agent_id,
    a.agent_name,
    a.hostname,
    a.environment,
    a.source,
    a.status;

CREATE OR REPLACE VIEW v_severity_distribution AS
SELECT
    environment,
    severity,
    COUNT(*) AS event_count
FROM normalized_log_events
GROUP BY
    environment,
    severity;

CREATE OR REPLACE VIEW v_destination_health AS
SELECT
    d.destination_id,
    d.destination_name,
    d.enabled,
    COUNT(a.attempt_id) AS attempts,
    COUNT(*) FILTER (
        WHERE a.status = 'DELIVERED'
    ) AS successful_attempts,
    COUNT(*) FILTER (
        WHERE a.status = 'FAILED'
    ) AS failed_attempts
FROM log_destinations d
LEFT JOIN delivery_attempts a
    ON a.destination_id = d.destination_id
GROUP BY
    d.destination_id,
    d.destination_name,
    d.enabled;

-- ============================================================================
-- SAMPLE DATA
-- ============================================================================

INSERT INTO collection_agents (
    agent_name,
    hostname,
    environment,
    source,
    agent_version
)
VALUES
(
    'web-agent-01',
    'web-server-01',
    'production',
    'JSON',
    '2.1.0'
),
(
    'database-agent-01',
    'database-01',
    'production',
    'SYSLOG',
    '2.1.0'
),
(
    'development-agent-01',
    'dev-server-01',
    'development',
    'JSON',
    '1.8.0'
);

INSERT INTO log_destinations (
    destination_name,
    destination_type,
    endpoint_reference,
    max_batch_size
)
VALUES
(
    'Primary Log Store',
    'DATABASE',
    'primary-log-store',
    500
),
(
    'Security Analytics',
    'ANALYTICS',
    'security-analytics',
    200
);

INSERT INTO collection_batches (
    agent_id,
    batch_number,
    status
)
SELECT
    agent_id,
    1,
    'OPEN'
FROM collection_agents
WHERE agent_name = 'web-agent-01';

-- ============================================================================
-- RAW EVENT INGESTION
-- ============================================================================

INSERT INTO raw_log_events (
    agent_id,
    batch_id,
    raw_payload,
    source_timestamp
)
SELECT
    a.agent_id,
    b.batch_id,
    payload.raw_payload,
    payload.event_timestamp
FROM collection_agents a
JOIN collection_batches b
    ON b.agent_id = a.agent_id
CROSS JOIN (
    VALUES
    (
        '{"timestamp":"2026-11-23T04:00:00Z","severity":"INFO","message":"Login successful"}',
        '2026-11-23T04:00:00Z'
    ),
    (
        '{"timestamp":"2026-11-23T04:01:00+05:30","severity":"ERROR","message":"password=secret123 database unavailable"}',
        '2026-11-23T04:01:00+05:30'
    ),
    (
        '{"timestamp":"2026-11-23T04:03:00Z","severity":"WARNING","message":"High CPU utilization"}',
        '2026-11-23T04:03:00Z'
    )
) AS payload(raw_payload, event_timestamp)
WHERE a.agent_name = 'web-agent-01'
  AND b.batch_number = 1;

-- ============================================================================
-- NORMALIZATION AND EVENT CREATION
-- ============================================================================

DO $$
DECLARE
    raw RECORD;
    normalized_payload JSONB;
    generated_fingerprint TEXT;
BEGIN
    FOR raw IN
        SELECT
            r.*,
            a.hostname,
            a.environment,
            a.source
        FROM raw_log_events r
        JOIN collection_agents a
            ON a.agent_id = r.agent_id
        WHERE r.processed = FALSE
        ORDER BY r.raw_event_id
    LOOP
        BEGIN
            normalized_payload :=
                raw.raw_payload::JSONB;

            generated_fingerprint :=
                encode(
                    digest(
                        raw.agent_id::TEXT
                        || '|'
                        || raw.hostname
                        || '|'
                        || normalize_log_timestamp(
                            normalized_payload->>'timestamp'
                        )::TEXT
                        || '|'
                        || redact_log_message(
                            normalized_payload->>'message'
                        ),
                        'sha256'
                    ),
                    'hex'
                );

            PERFORM insert_normalized_event(
                raw.raw_event_id,
                gen_random_uuid(),
                raw.agent_id,
                raw.hostname,
                raw.environment,
                raw.source,
                normalized_payload->>'timestamp',
                normalized_payload->>'severity',
                normalized_payload->>'message',
                normalized_payload - ARRAY[
                    'timestamp',
                    'severity',
                    'message'
                ],
                generated_fingerprint
            );

        EXCEPTION WHEN OTHERS THEN
            UPDATE raw_log_events
            SET parsing_error = SQLERRM
            WHERE raw_event_id = raw.raw_event_id;
        END;
    END LOOP;
END;
$$;

-- ============================================================================
-- SAMPLE INVALID EVENT
-- ============================================================================

INSERT INTO raw_log_events (
    agent_id,
    raw_payload
)
SELECT
    agent_id,
    '{"timestamp":"invalid-time","severity":"UNKNOWN","message":"Invalid sample"}'
FROM collection_agents
WHERE agent_name = 'web-agent-01';

-- ============================================================================
-- SAMPLE DELIVERY TRANSACTION
-- ============================================================================

DO $$
DECLARE
    destination UUID;
    event RECORD;
BEGIN
    SELECT destination_id
    INTO destination
    FROM log_destinations
    WHERE destination_name = 'Primary Log Store';

    FOR event IN
        SELECT event_id
        FROM normalized_log_events
        WHERE state = 'QUEUED'
        ORDER BY event_id
    LOOP
        CALL process_delivery_attempt(
            event.event_id,
            destination,
            TRUE,
            NULL
        );
    END LOOP;
END;
$$;

-- ============================================================================
-- RETRIEVAL QUERIES
-- ============================================================================

-- Latest events.
SELECT
    event_id,
    hostname,
    environment,
    event_timestamp,
    severity,
    message,
    state
FROM normalized_log_events
ORDER BY event_timestamp DESC
LIMIT 100;

-- Search events by severity.
SELECT
    event_id,
    event_timestamp,
    hostname,
    message
FROM normalized_log_events
WHERE severity IN ('ERROR', 'CRITICAL')
ORDER BY event_timestamp DESC;

-- Search JSONB attributes.
SELECT
    event_id,
    attributes
FROM normalized_log_events
WHERE attributes @> '{"service":"identity"}'::JSONB;

-- Full-text search.
SELECT
    event_id,
    message
FROM normalized_log_events
WHERE to_tsvector('english', message)
      @@ plainto_tsquery('english', 'database connection');

-- ============================================================================
-- AGGREGATION AND EVALUATION
-- ============================================================================

-- Event counts by agent.
SELECT
    agent_id,
    COUNT(*) AS total_events,
    COUNT(*) FILTER (
        WHERE severity = 'ERROR'
    ) AS errors,
    COUNT(*) FILTER (
        WHERE severity = 'CRITICAL'
    ) AS critical_events
FROM normalized_log_events
GROUP BY agent_id;

-- Hourly collection volume.
SELECT
    date_trunc('hour', event_timestamp) AS hour,
    environment,
    COUNT(*) AS event_count
FROM normalized_log_events
GROUP BY
    date_trunc('hour', event_timestamp),
    environment
ORDER BY hour;

-- Delivery success rates.
SELECT
    destination_id,
    COUNT(*) AS total_attempts,
    COUNT(*) FILTER (
        WHERE status = 'DELIVERED'
    ) AS successful_attempts,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE status = 'DELIVERED'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS success_percentage
FROM delivery_attempts
GROUP BY destination_id;

-- ============================================================================
-- VALIDATION QUERIES
-- ============================================================================

-- Agents without recent heartbeat.
SELECT
    agent_id,
    agent_name,
    last_heartbeat
FROM collection_agents
WHERE status = 'ACTIVE'
  AND (
      last_heartbeat IS NULL
      OR last_heartbeat <
          CURRENT_TIMESTAMP - INTERVAL '5 minutes'
  );

-- Raw records with parsing failures.
SELECT
    raw_event_id,
    agent_id,
    parsing_error
FROM raw_log_events
WHERE parsing_error IS NOT NULL;

-- Events with no successful delivery.
SELECT
    e.event_id,
    e.hostname,
    e.severity,
    e.state
FROM normalized_log_events e
WHERE NOT EXISTS (
    SELECT 1
    FROM delivery_attempts d
    WHERE d.event_id = e.event_id
      AND d.status = 'DELIVERED'
);

-- ============================================================================
-- RETENTION EXECUTION
-- ============================================================================
-- This procedure performs real data movement and deletion.
-- The demonstration uses a transaction and rollback to preserve
-- the sample data.

SAVEPOINT retention_demo;

CALL apply_log_retention(CURRENT_TIMESTAMP);

ROLLBACK TO SAVEPOINT retention_demo;

-- ============================================================================
-- CTE: COLLECTION PIPELINE HEALTH
-- ============================================================================

WITH event_counts AS (
    SELECT
        agent_id,
        COUNT(*) AS total_events,
        COUNT(*) FILTER (
            WHERE state = 'FORWARDED'
        ) AS forwarded,
        COUNT(*) FILTER (
            WHERE state = 'FAILED'
        ) AS failed
    FROM normalized_log_events
    GROUP BY agent_id
),
agent_health AS (
    SELECT
        a.agent_name,
        COALESCE(c.total_events, 0) AS total_events,
        COALESCE(c.forwarded, 0) AS forwarded,
        COALESCE(c.failed, 0) AS failed
    FROM collection_agents a
    LEFT JOIN event_counts c
        ON c.agent_id = a.agent_id
)
SELECT
    agent_name,
    total_events,
    forwarded,
    failed,
    CASE
        WHEN total_events = 0 THEN 'NO_DATA'
        WHEN failed > 0 THEN 'ATTENTION_REQUIRED'
        WHEN forwarded = total_events THEN 'HEALTHY'
        ELSE 'PENDING'
    END AS pipeline_status
FROM agent_health;

-- ============================================================================
-- FINAL REPORTS
-- ============================================================================

SELECT *
FROM v_collection_overview
ORDER BY agent_name;

SELECT *
FROM v_severity_distribution
ORDER BY environment, severity;

SELECT *
FROM v_destination_health
ORDER BY destination_name;

SELECT
    COUNT(*) AS raw_events,
    COUNT(*) FILTER (
        WHERE processed
    ) AS processed_events,
    COUNT(*) FILTER (
        WHERE parsing_error IS NOT NULL
    ) AS rejected_events
FROM raw_log_events;

COMMIT;
