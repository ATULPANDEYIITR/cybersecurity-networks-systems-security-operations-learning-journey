-- PostgreSQL 15+
-- Endpoint security: antivirus, EDR, HIDS, behavioral detection, telemetry.
-- The script creates an isolated schema and deterministic synthetic records.
-- It does not collect host telemetry or execute endpoint response actions.

BEGIN;

CREATE SCHEMA IF NOT EXISTS endpoint_security;
SET LOCAL search_path TO endpoint_security, public;

CREATE TYPE sensor_type AS ENUM ('antivirus', 'edr', 'hids', 'behavioral');
CREATE TYPE severity_level AS ENUM ('low', 'medium', 'high', 'critical');
CREATE TYPE incident_state AS ENUM (
    'new', 'triaged', 'contained', 'investigating', 'resolved'
);
CREATE TYPE endpoint_state AS ENUM (
    'healthy', 'monitoring', 'isolated', 'review_required'
);

CREATE TABLE IF NOT EXISTS repositories_placeholder_guard (
    guard_id integer PRIMARY KEY CHECK (guard_id = 1)
);
DROP TABLE repositories_placeholder_guard;

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id text PRIMARY KEY,
    hostname text NOT NULL UNIQUE,
    operating_system text NOT NULL,
    environment text NOT NULL CHECK (
        environment IN ('production', 'staging', 'development')
    ),
    state endpoint_state NOT NULL DEFAULT 'monitoring',
    last_seen_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(endpoint_id) BETWEEN 1 AND 128),
    CHECK (length(hostname) BETWEEN 1 AND 255)
);

CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id text PRIMARY KEY,
    endpoint_id text NOT NULL REFERENCES endpoints(endpoint_id),
    occurred_at timestamptz NOT NULL,
    sensor sensor_type NOT NULL,
    event_type text NOT NULL,
    severity severity_level NOT NULL,
    process_name text NOT NULL,
    user_name text NOT NULL DEFAULT 'unknown',
    file_sha256 text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    CHECK (length(event_id) BETWEEN 1 AND 128),
    CHECK (length(event_type) BETWEEN 1 AND 128),
    CHECK (length(process_name) BETWEEN 1 AND 128),
    CHECK (length(user_name) BETWEEN 1 AND 128),
    CHECK (
        file_sha256 IS NULL OR file_sha256 ~ '^[0-9A-Fa-f]{64}$'
    ),
    CHECK (jsonb_typeof(details) = 'object'),
    CHECK (octet_length(details::text) <= 16384)
);

CREATE INDEX IF NOT EXISTS telemetry_endpoint_time_idx
    ON telemetry_events(endpoint_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS telemetry_sensor_type_time_idx
    ON telemetry_events(sensor, event_type, occurred_at DESC);

CREATE INDEX IF NOT EXISTS telemetry_severity_time_idx
    ON telemetry_events(severity, occurred_at DESC);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_code text NOT NULL UNIQUE,
    sensor sensor_type NOT NULL,
    event_type text NOT NULL,
    minimum_severity severity_level NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    description text NOT NULL,
    CHECK (length(rule_code) BETWEEN 1 AND 100)
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id text NOT NULL REFERENCES endpoints(endpoint_id),
    severity severity_level NOT NULL,
    state incident_state NOT NULL DEFAULT 'new',
    title text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    CHECK (length(title) BETWEEN 1 AND 250),
    CHECK (
        (state = 'resolved' AND resolved_at IS NOT NULL)
        OR (state <> 'resolved' AND resolved_at IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS incidents_endpoint_state_idx
    ON incidents(endpoint_id, state, created_at DESC);

CREATE INDEX IF NOT EXISTS incidents_severity_open_idx
    ON incidents(severity, created_at DESC)
    WHERE state <> 'resolved';

CREATE TABLE IF NOT EXISTS incident_evidence (
    incident_id bigint NOT NULL REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    event_id text NOT NULL REFERENCES telemetry_events(event_id),
    reason text NOT NULL,
    PRIMARY KEY (incident_id, event_id, reason)
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id bigint NOT NULL REFERENCES incidents(incident_id),
    action_type text NOT NULL CHECK (
        action_type IN (
            'isolation_requested',
            'isolation_confirmed',
            'scan_requested',
            'credential_reset_requested',
            'manual_review'
        )
    ),
    requested_by text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending', 'succeeded', 'failed', 'cancelled')
    ),
    requested_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    CHECK (
        (status = 'pending' AND completed_at IS NULL)
        OR (status <> 'pending')
    )
);

CREATE INDEX IF NOT EXISTS response_actions_pending_idx
    ON response_actions(status, requested_at)
    WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS detection_exceptions (
    exception_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    file_sha256 text NOT NULL UNIQUE
        CHECK (file_sha256 ~ '^[0-9A-Fa-f]{64}$'),
    justification text NOT NULL,
    approved_by text NOT NULL,
    expires_at timestamptz NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    CHECK (length(justification) BETWEEN 10 AND 1000)
);

CREATE TABLE IF NOT EXISTS endpoint_policy (
    policy_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_name text NOT NULL UNIQUE,
    minimum_isolation_severity severity_level NOT NULL DEFAULT 'critical',
    require_hids boolean NOT NULL DEFAULT true,
    require_antivirus boolean NOT NULL DEFAULT true,
    require_edr boolean NOT NULL DEFAULT true,
    auto_containment_enabled boolean NOT NULL DEFAULT false,
    policy_version integer NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approval_requirements (
    requirement_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id bigint NOT NULL REFERENCES endpoint_policy(policy_id)
        ON DELETE CASCADE,
    action_type text NOT NULL,
    minimum_approvals integer NOT NULL CHECK (minimum_approvals >= 0),
    UNIQUE (policy_id, action_type)
);

CREATE TABLE IF NOT EXISTS security_approvals (
    approval_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id bigint NOT NULL REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    reviewer text NOT NULL,
    decision text NOT NULL CHECK (
        decision IN ('approved', 'rejected')
    ),
    decided_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (incident_id, reviewer)
);

CREATE TABLE IF NOT EXISTS status_check_runs (
    check_run_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id text NOT NULL REFERENCES endpoints(endpoint_id),
    check_name text NOT NULL,
    status text NOT NULL CHECK (
        status IN ('queued', 'running', 'passed', 'failed', 'error')
    ),
    started_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    CHECK (
        (status IN ('queued', 'running') AND completed_at IS NULL)
        OR (status IN ('passed', 'failed', 'error'))
    )
);

CREATE OR REPLACE FUNCTION enforce_incident_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = OLD.state THEN
        NEW.updated_at := now();
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.state = 'new' AND NEW.state = 'triaged')
        OR (OLD.state = 'triaged' AND NEW.state IN ('contained', 'investigating'))
        OR (OLD.state = 'contained' AND NEW.state = 'investigating')
        OR (OLD.state = 'investigating' AND NEW.state IN ('contained', 'resolved'))
    ) THEN
        RAISE EXCEPTION 'Invalid incident transition: % -> %',
            OLD.state, NEW.state;
    END IF;

    IF NEW.state = 'resolved' THEN
        NEW.resolved_at := COALESCE(NEW.resolved_at, now());
    ELSE
        NEW.resolved_at := NULL;
    END IF;

    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS incident_transition_guard ON incidents;
CREATE TRIGGER incident_transition_guard
BEFORE UPDATE OF state ON incidents
FOR EACH ROW
EXECUTE FUNCTION enforce_incident_transition();

CREATE OR REPLACE FUNCTION validate_response_action()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_state incident_state;
BEGIN
    SELECT state INTO current_state
    FROM incidents
    WHERE incident_id = NEW.incident_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident % does not exist', NEW.incident_id;
    END IF;

    IF NEW.action_type = 'isolation_confirmed'
       AND current_state NOT IN ('triaged', 'contained', 'investigating') THEN
        RAISE EXCEPTION 'Isolation cannot be confirmed from incident state %',
            current_state;
    END IF;

    IF NEW.status IN ('succeeded', 'failed', 'cancelled')
       AND NEW.completed_at IS NULL THEN
        NEW.completed_at := now();
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS response_action_guard ON response_actions;
CREATE TRIGGER response_action_guard
BEFORE INSERT OR UPDATE ON response_actions
FOR EACH ROW
EXECUTE FUNCTION validate_response_action();

CREATE OR REPLACE FUNCTION ingest_event(
    p_event_id text,
    p_endpoint_id text,
    p_occurred_at timestamptz,
    p_sensor sensor_type,
    p_event_type text,
    p_severity severity_level,
    p_process_name text,
    p_user_name text DEFAULT 'unknown',
    p_file_sha256 text DEFAULT NULL,
    p_details jsonb DEFAULT '{}'::jsonb
)
RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
    inserted_count integer;
BEGIN
    INSERT INTO telemetry_events (
        event_id, endpoint_id, occurred_at, sensor, event_type,
        severity, process_name, user_name, file_sha256, details
    )
    VALUES (
        p_event_id, p_endpoint_id, p_occurred_at, p_sensor, p_event_type,
        p_severity, p_process_name, p_user_name, p_file_sha256,
        COALESCE(p_details, '{}'::jsonb)
    )
    ON CONFLICT (event_id) DO NOTHING;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;

    IF inserted_count = 0 THEN
        IF NOT EXISTS (
            SELECT 1
            FROM telemetry_events
            WHERE event_id = p_event_id
              AND endpoint_id = p_endpoint_id
              AND occurred_at = p_occurred_at
              AND sensor = p_sensor
              AND event_type = p_event_type
              AND severity = p_severity
              AND process_name = p_process_name
              AND user_name = p_user_name
              AND file_sha256 IS NOT DISTINCT FROM p_file_sha256
              AND details = COALESCE(p_details, '{}'::jsonb)
        ) THEN
            RAISE EXCEPTION 'Conflicting duplicate event ID: %', p_event_id;
        END IF;
        RETURN false;
    END IF;

    UPDATE endpoints
    SET last_seen_at = GREATEST(
        COALESCE(last_seen_at, p_occurred_at), p_occurred_at
    )
    WHERE endpoint_id = p_endpoint_id;

    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION evaluate_endpoint_security(
    p_endpoint_id text
)
RETURNS bigint
LANGUAGE plpgsql
AS $$
DECLARE
    v_incident_id bigint;
    v_severity severity_level;
    v_title text;
    v_event_ids text[];
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM endpoints WHERE endpoint_id = p_endpoint_id
    ) THEN
        RAISE EXCEPTION 'Unknown endpoint: %', p_endpoint_id;
    END IF;

    WITH ordered_events AS (
        SELECT e.*,
               min(occurred_at) FILTER (
                   WHERE sensor = 'edr'
                     AND event_type IN ('suspicious_process', 'credential_access')
               ) OVER (PARTITION BY endpoint_id) AS first_suspicious_at,
               count(*) FILTER (
                   WHERE sensor = 'behavioral'
                     AND event_type = 'authentication_failure'
               ) OVER (
                   PARTITION BY endpoint_id, user_name
                   ORDER BY occurred_at
                   ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
               ) AS authentication_failures
        FROM telemetry_events e
        WHERE e.endpoint_id = p_endpoint_id
    ),
    scored AS (
        SELECT *,
            CASE
                WHEN sensor = 'edr'
                 AND event_type = 'unusual_outbound_connection'
                 AND occurred_at >= first_suspicious_at
                 AND occurred_at <= first_suspicious_at + interval '5 minutes'
                    THEN 'critical'::severity_level
                WHEN sensor = 'antivirus' AND event_type = 'malware_detected'
                    THEN severity
                WHEN sensor = 'antivirus' AND event_type = 'quarantine_failed'
                    THEN 'high'::severity_level
                WHEN sensor = 'hids' AND event_type = 'integrity_violation'
                    THEN severity
                WHEN sensor = 'edr'
                 AND event_type IN ('suspicious_process', 'credential_access')
                    THEN severity
                WHEN sensor = 'behavioral'
                 AND event_type = 'authentication_success'
                 AND authentication_failures >= 5
                    THEN 'high'::severity_level
                ELSE NULL
            END AS detected_severity,
            CASE
                WHEN sensor = 'antivirus' AND event_type = 'malware_detected'
                    THEN 'Antivirus malware detection'
                WHEN sensor = 'antivirus' AND event_type = 'quarantine_failed'
                    THEN 'Antivirus quarantine failed'
                WHEN sensor = 'hids' AND event_type = 'integrity_violation'
                    THEN 'Protected-file integrity violation'
                WHEN sensor = 'edr'
                 AND event_type IN ('suspicious_process', 'credential_access')
                    THEN 'EDR suspicious execution'
                WHEN sensor = 'edr'
                 AND event_type = 'unusual_outbound_connection'
                 AND occurred_at >= first_suspicious_at
                 AND occurred_at <= first_suspicious_at + interval '5 minutes'
                    THEN 'Suspicious execution correlated with outbound activity'
                WHEN sensor = 'behavioral'
                 AND event_type = 'authentication_success'
                 AND authentication_failures >= 5
                    THEN 'Repeated authentication failures followed by success'
                ELSE NULL
            END AS detection_reason
        FROM ordered_events
    )
    SELECT max(detected_severity::text)::severity_level,
           array_agg(event_id ORDER BY occurred_at),
           string_agg(DISTINCT detection_reason, '; ')
    INTO v_severity, v_event_ids, v_title
    FROM scored
    WHERE detected_severity IS NOT NULL;

    IF v_severity IS NULL THEN
        RETURN NULL;
    END IF;

    -- Severity ordering is explicit; text ordering is not severity ordering.
    SELECT detected_severity
    INTO v_severity
    FROM (
        SELECT CASE detected_severity
            WHEN 'low' THEN 1
            WHEN 'medium' THEN 2
            WHEN 'high' THEN 3
            WHEN 'critical' THEN 4
        END AS severity_rank,
        detected_severity
        FROM (
            SELECT CASE
                WHEN sensor = 'edr'
                 AND event_type = 'unusual_outbound_connection'
                 AND EXISTS (
                     SELECT 1 FROM telemetry_events s
                     WHERE s.endpoint_id = p_endpoint_id
                       AND s.sensor = 'edr'
                       AND s.event_type IN ('suspicious_process', 'credential_access')
                       AND s.occurred_at <= telemetry_events.occurred_at
                       AND telemetry_events.occurred_at <= s.occurred_at + interval '5 minutes'
                 ) THEN 'critical'::severity_level
                WHEN sensor = 'antivirus' AND event_type = 'malware_detected'
                    THEN severity
                WHEN sensor = 'antivirus' AND event_type = 'quarantine_failed'
                    THEN 'high'::severity_level
                WHEN sensor = 'hids' AND event_type = 'integrity_violation'
                    THEN severity
                WHEN sensor = 'edr' AND event_type IN ('suspicious_process', 'credential_access')
                    THEN severity
                WHEN sensor = 'behavioral' AND event_type = 'authentication_success'
                    AND (
                        SELECT count(*)
                        FROM telemetry_events f
                        WHERE f.endpoint_id = p_endpoint_id
                          AND f.sensor = 'behavioral'
                          AND f.event_type = 'authentication_failure'
                          AND f.user_name = telemetry_events.user_name
                          AND f.occurred_at <= telemetry_events.occurred_at
                    ) >= 5 THEN 'high'::severity_level
            END AS detected_severity
            FROM telemetry_events
            WHERE endpoint_id = p_endpoint_id
        ) candidates
        WHERE detected_severity IS NOT NULL
    ) ranked
    ORDER BY severity_rank DESC
    LIMIT 1;

    INSERT INTO incidents (endpoint_id, severity, title)
    VALUES (
        p_endpoint_id,
        v_severity,
        left(COALESCE(v_title, 'Endpoint security detection'), 250)
    )
    RETURNING incident_id INTO v_incident_id;

    WITH evidence AS (
        SELECT DISTINCT e.event_id,
            CASE
                WHEN e.sensor = 'antivirus' AND e.event_type = 'malware_detected'
                    THEN 'Antivirus malware detection'
                WHEN e.sensor = 'antivirus' AND e.event_type = 'quarantine_failed'
                    THEN 'Antivirus quarantine failed'
                WHEN e.sensor = 'hids' AND e.event_type = 'integrity_violation'
                    THEN 'Protected-file integrity violation'
                WHEN e.sensor = 'edr' AND e.event_type IN ('suspicious_process', 'credential_access')
                    THEN 'EDR suspicious execution'
                WHEN e.sensor = 'edr' AND e.event_type = 'unusual_outbound_connection'
                    THEN 'Outbound activity requiring correlation review'
                WHEN e.sensor = 'behavioral' AND e.event_type = 'authentication_success'
                    THEN 'Authentication success requiring behavioral review'
                ELSE 'Detection evidence'
            END AS reason
        FROM telemetry_events e
        WHERE e.endpoint_id = p_endpoint_id
          AND (
              (e.sensor = 'antivirus' AND e.event_type IN ('malware_detected', 'quarantine_failed'))
              OR (e.sensor = 'hids' AND e.event_type = 'integrity_violation')
              OR (e.sensor = 'edr' AND e.event_type IN (
                  'suspicious_process', 'credential_access', 'unusual_outbound_connection'
              ))
              OR (e.sensor = 'behavioral' AND e.event_type = 'authentication_success')
          )
    )
    INSERT INTO incident_evidence (incident_id, event_id, reason)
    SELECT v_incident_id, event_id, reason FROM evidence
    ON CONFLICT DO NOTHING;

    RETURN v_incident_id;
END;
$$;

CREATE OR REPLACE VIEW endpoint_security_dashboard AS
SELECT
    e.endpoint_id,
    e.hostname,
    e.environment,
    e.state AS endpoint_state,
    count(DISTINCT t.event_id) AS telemetry_count,
    count(DISTINCT i.incident_id) FILTER (
        WHERE i.state <> 'resolved'
    ) AS open_incidents,
    count(DISTINCT i.incident_id) FILTER (
        WHERE i.severity = 'critical' AND i.state <> 'resolved'
    ) AS critical_open_incidents,
    max(t.occurred_at) AS latest_event_at
FROM endpoints e
LEFT JOIN telemetry_events t ON t.endpoint_id = e.endpoint_id
LEFT JOIN incidents i ON i.endpoint_id = e.endpoint_id
GROUP BY e.endpoint_id, e.hostname, e.environment, e.state;

CREATE OR REPLACE VIEW sensor_coverage AS
SELECT
    e.endpoint_id,
    e.hostname,
    bool_or(t.sensor = 'antivirus') AS antivirus_seen,
    bool_or(t.sensor = 'edr') AS edr_seen,
    bool_or(t.sensor = 'hids') AS hids_seen,
    bool_or(t.sensor = 'behavioral') AS behavioral_telemetry_seen
FROM endpoints e
LEFT JOIN telemetry_events t ON t.endpoint_id = e.endpoint_id
GROUP BY e.endpoint_id, e.hostname;

INSERT INTO endpoints (
    endpoint_id, hostname, operating_system, environment, state
)
VALUES
    ('WS-101', 'finance-ws-101', 'Windows 11', 'production', 'monitoring'),
    ('WS-202', 'linux-server-202', 'Ubuntu 24.04', 'production', 'monitoring'),
    ('WS-303', 'engineering-ws-303', 'Windows 11', 'staging', 'monitoring'),
    ('WS-404', 'identity-server-404', 'Ubuntu 24.04', 'production', 'monitoring'),
    ('WS-505', 'office-ws-505', 'Windows 11', 'development', 'healthy')
ON CONFLICT (endpoint_id) DO NOTHING;

INSERT INTO detection_rules (
    rule_code, sensor, event_type, minimum_severity, description
)
VALUES
    ('AV-MALWARE', 'antivirus', 'malware_detected', 'high',
     'Known malware signature detected'),
    ('AV-QUARANTINE', 'antivirus', 'quarantine_failed', 'high',
     'Antivirus could not quarantine a detected object'),
    ('EDR-PROCESS', 'edr', 'suspicious_process', 'high',
     'Process behavior requires investigation'),
    ('HIDS-INTEGRITY', 'hids', 'integrity_violation', 'high',
     'Protected file integrity changed unexpectedly'),
    ('BEHAVIOR-AUTH', 'behavioral', 'authentication_success', 'high',
     'Successful login following repeated authentication failures')
ON CONFLICT (rule_code) DO NOTHING;

INSERT INTO endpoint_policy (
    policy_name, minimum_isolation_severity, require_hids,
    require_antivirus, require_edr, auto_containment_enabled
)
VALUES (
    'production-endpoint-baseline', 'critical', true, true, true, false
)
ON CONFLICT (policy_name) DO NOTHING;

INSERT INTO approval_requirements (
    policy_id, action_type, minimum_approvals
)
SELECT policy_id, 'isolation_confirmed', 1
FROM endpoint_policy
WHERE policy_name = 'production-endpoint-baseline'
ON CONFLICT (policy_id, action_type) DO NOTHING;

INSERT INTO telemetry_events (
    event_id, endpoint_id, occurred_at, sensor, event_type,
    severity, process_name, user_name, details
)
VALUES
    ('EV-001', 'WS-101', '2026-10-24 04:00:00+00',
     'antivirus', 'malware_detected', 'high', 'invoice.exe', 'employee',
     '{"signature":"TEST-MALWARE-001","action":"quarantined"}'),
    ('EV-002', 'WS-202', '2026-10-24 04:00:01+00',
     'hids', 'integrity_violation', 'high', 'sshd', 'root',
     '{"path":"/etc/ssh/sshd_config"}'),
    ('EV-003', 'WS-303', '2026-10-24 04:00:02+00',
     'edr', 'suspicious_process', 'high', 'powershell.exe', 'employee',
     '{"parent_process":"winword.exe"}'),
    ('EV-004', 'WS-303', '2026-10-24 04:00:30+00',
     'edr', 'unusual_outbound_connection', 'medium', 'powershell.exe', 'employee',
     '{"destination_class":"unusual_external_host"}'),
    ('AUTH-1', 'WS-404', '2026-10-24 04:00:01+00',
     'behavioral', 'authentication_failure', 'medium', 'login_service', 'svc-backup',
     '{"source":"internal"}'),
    ('AUTH-2', 'WS-404', '2026-10-24 04:00:02+00',
     'behavioral', 'authentication_failure', 'medium', 'login_service', 'svc-backup',
     '{"source":"internal"}'),
    ('AUTH-3', 'WS-404', '2026-10-24 04:00:03+00',
     'behavioral', 'authentication_failure', 'medium', 'login_service', 'svc-backup',
     '{"source":"internal"}'),
    ('AUTH-4', 'WS-404', '2026-10-24 04:00:04+00',
     'behavioral', 'authentication_failure', 'medium', 'login_service', 'svc-backup',
     '{"source":"internal"}'),
    ('AUTH-5', 'WS-404', '2026-10-24 04:00:05+00',
     'behavioral', 'authentication_failure', 'medium', 'login_service', 'svc-backup',
     '{"source":"internal"}'),
    ('AUTH-6', 'WS-404', '2026-10-24 04:00:10+00',
     'behavioral', 'authentication_success', 'medium', 'login_service', 'svc-backup',
     '{"source":"internal"}'),
    ('EV-005', 'WS-505', '2026-10-24 04:00:06+00',
     'edr', 'process_started', 'low', 'notepad.exe', 'employee',
     '{"classification":"ordinary_activity"}')
ON CONFLICT (event_id) DO NOTHING;

-- An identical replay is idempotent; a conflicting replay raises an exception.
SELECT ingest_event(
    'EV-001', 'WS-101', '2026-10-24 04:00:00+00',
    'antivirus', 'malware_detected', 'high', 'invoice.exe', 'employee',
    NULL, '{"signature":"TEST-MALWARE-001","action":"quarantined"}'
) AS duplicate_inserted;

-- Evaluate each endpoint independently.
SELECT evaluate_endpoint_security(endpoint_id)
FROM endpoints
WHERE endpoint_id IN ('WS-101', 'WS-202', 'WS-303', 'WS-404', 'WS-505')
ORDER BY endpoint_id;

-- Correlation reporting: process execution followed by outbound activity.
WITH suspicious AS (
    SELECT endpoint_id, min(occurred_at) AS first_suspicious_at
    FROM telemetry_events
    WHERE sensor = 'edr'
      AND event_type IN ('suspicious_process', 'credential_access')
    GROUP BY endpoint_id
)
SELECT e.endpoint_id,
       s.first_suspicious_at,
       e.event_id AS outbound_event_id,
       e.occurred_at AS outbound_at,
       e.occurred_at - s.first_suspicious_at AS elapsed
FROM suspicious s
JOIN telemetry_events e ON e.endpoint_id = s.endpoint_id
WHERE e.sensor = 'edr'
  AND e.event_type = 'unusual_outbound_connection'
  AND e.occurred_at >= s.first_suspicious_at
  AND e.occurred_at <= s.first_suspicious_at + interval '5 minutes'
ORDER BY e.endpoint_id, e.occurred_at;

-- Sensor coverage makes missing telemetry visible; absence of events does
-- not prove a sensor is disabled unless deployment inventory is also verified.
SELECT * FROM sensor_coverage ORDER BY endpoint_id;

-- Operational dashboard with open and critical incident counts.
SELECT * FROM endpoint_security_dashboard ORDER BY endpoint_id;

-- Incident evidence retrieval.
SELECT i.incident_id, i.endpoint_id, i.severity, i.state,
       ev.event_id, ev.sensor, ev.event_type, ev.occurred_at, ie.reason
FROM incidents i
JOIN incident_evidence ie ON ie.incident_id = i.incident_id
JOIN telemetry_events ev ON ev.event_id = ie.event_id
ORDER BY i.incident_id, ev.occurred_at;

-- Transactional incident response example.
-- The action is a request record, not a real network isolation command.
DO $$
DECLARE
    v_incident_id bigint;
BEGIN
    SELECT incident_id INTO v_incident_id
    FROM incidents
    WHERE endpoint_id = 'WS-303'
    ORDER BY created_at DESC
    LIMIT 1;

    IF v_incident_id IS NOT NULL THEN
        UPDATE incidents
        SET state = 'triaged'
        WHERE incident_id = v_incident_id AND state = 'new';

        INSERT INTO response_actions (
            incident_id, action_type, requested_by, status, details
        )
        SELECT v_incident_id, 'isolation_requested', 'security-analyst',
               'pending', '{"reason":"critical correlated EDR telemetry"}'
        WHERE EXISTS (
            SELECT 1 FROM incidents
            WHERE incident_id = v_incident_id
              AND severity = 'critical'
              AND state = 'triaged'
        );
    END IF;
END;
$$;

-- Eligibility query: whether a proposed response action has sufficient
-- approvals under the active policy. This is separate from detection severity.
WITH required AS (
    SELECT ar.action_type, ar.minimum_approvals
    FROM approval_requirements ar
    JOIN endpoint_policy p ON p.policy_id = ar.policy_id
    WHERE p.policy_name = 'production-endpoint-baseline'
),
counts AS (
    SELECT action_type,
           count(*) FILTER (WHERE decision = 'approved') AS approved_count,
           count(*) FILTER (WHERE decision = 'rejected') AS rejected_count
    FROM security_approvals
    GROUP BY action_type
)
SELECT r.action_type,
       r.minimum_approvals,
       COALESCE(c.approved_count, 0) AS approved_count,
       COALESCE(c.rejected_count, 0) AS rejected_count,
       COALESCE(c.approved_count, 0) >= r.minimum_approvals
           AND COALESCE(c.rejected_count, 0) = 0 AS approval_eligible
FROM required r
LEFT JOIN counts c USING (action_type)
ORDER BY r.action_type;

-- Validation demonstration: an invalid transition is rejected by the trigger.
-- A nested exception block keeps the main transaction executable.
DO $$
DECLARE
    v_incident_id bigint;
BEGIN
    SELECT incident_id INTO v_incident_id
    FROM incidents
    ORDER BY incident_id
    LIMIT 1;

    IF v_incident_id IS NOT NULL THEN
        BEGIN
            UPDATE incidents
            SET state = 'resolved'
            WHERE incident_id = v_incident_id AND state = 'new';
        EXCEPTION WHEN raise_exception THEN
            RAISE NOTICE 'Invalid incident transition rejected as expected';
        END;
    END IF;
END;
$$;

COMMIT;
