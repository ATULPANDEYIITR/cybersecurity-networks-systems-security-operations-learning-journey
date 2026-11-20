-- =========================================================
-- SECURITY OPERATIONS FUNDAMENTALS
-- PostgreSQL SOC monitoring and incident management system.
--
-- Models:
-- Repositories are not involved in this workflow.
-- Security events -> Alerts -> Analysts -> Incidents
-- -> Escalation -> Containment -> Resolution -> Reporting.
--
-- Compatible with PostgreSQL 14+.
-- =========================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS soc;

SET search_path TO soc, public;

-- ---------------------------------------------------------
-- 1. Enumerated domain types
-- ---------------------------------------------------------

CREATE TYPE severity_level AS ENUM (
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TYPE soc_tier AS ENUM (
    'TIER_1',
    'TIER_2',
    'TIER_3'
);

CREATE TYPE incident_type AS ENUM (
    'BRUTE_FORCE',
    'MALWARE',
    'PHISHING',
    'DATA_EXFILTRATION',
    'UNAUTHORIZED_ACCESS',
    'NETWORK_INTRUSION'
);

CREATE TYPE alert_status AS ENUM (
    'NEW',
    'TRIAGED',
    'INVESTIGATING',
    'ESCALATED',
    'CONTAINED',
    'RESOLVED',
    'CLOSED',
    'FALSE_POSITIVE'
);

CREATE TYPE review_decision AS ENUM (
    'CONFIRMED',
    'SUSPECTED',
    'FALSE_POSITIVE'
);

-- ---------------------------------------------------------
-- 2. Reference tables
-- ---------------------------------------------------------

CREATE TABLE soc_roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

INSERT INTO soc_roles (role_name, description)
VALUES
(
    'L1_ANALYST',
    'First-line alert monitoring and initial triage'
),
(
    'L2_RESPONDER',
    'Incident investigation and response coordination'
),
(
    'L3_THREAT_HUNTER',
    'Advanced threat hunting, malware analysis and forensics'
),
(
    'SOC_MANAGER',
    'SOC governance, reporting and operational oversight'
),
(
    'SYSTEM',
    'Automated security monitoring and detection service'
);

-- ---------------------------------------------------------
-- 3. SOC analysts
-- ---------------------------------------------------------

CREATE TABLE analysts (
    analyst_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    employee_code VARCHAR(30) NOT NULL UNIQUE,

    analyst_name VARCHAR(120) NOT NULL,

    role_id BIGINT NOT NULL
        REFERENCES soc_roles(role_id),

    tier soc_tier NOT NULL,

    email VARCHAR(255) NOT NULL UNIQUE,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    max_assignments INTEGER NOT NULL DEFAULT 5
        CHECK (max_assignments BETWEEN 1 AND 100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (analyst_name = BTRIM(analyst_name)),
    CHECK (email = LOWER(email))
);

-- ---------------------------------------------------------
-- 4. Analyst skills
-- ---------------------------------------------------------

CREATE TABLE analyst_skills (
    analyst_id BIGINT NOT NULL
        REFERENCES analysts(analyst_id) ON DELETE CASCADE,

    skill incident_type NOT NULL,

    proficiency SMALLINT NOT NULL
        CHECK (proficiency BETWEEN 1 AND 5),

    PRIMARY KEY (analyst_id, skill)
);

CREATE INDEX idx_analyst_skills_type
    ON analyst_skills(skill, proficiency DESC);

-- ---------------------------------------------------------
-- 5. Security monitoring sources
-- ---------------------------------------------------------

CREATE TABLE monitoring_sources (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    source_name VARCHAR(100) NOT NULL UNIQUE,

    source_type VARCHAR(50) NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    last_heartbeat TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO monitoring_sources (
    source_name,
    source_type,
    last_heartbeat
)
VALUES
('Corporate Firewall', 'NETWORK', NOW()),
('Endpoint EDR', 'ENDPOINT', NOW()),
('Identity Provider', 'IDENTITY', NOW()),
('Email Gateway', 'EMAIL', NOW()),
('Cloud Audit Platform', 'CLOUD', NOW()),
('DNS Monitoring', 'NETWORK', NOW());

-- ---------------------------------------------------------
-- 6. Security events
-- ---------------------------------------------------------

CREATE TABLE security_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    external_event_id VARCHAR(100) NOT NULL UNIQUE,

    source_id BIGINT NOT NULL
        REFERENCES monitoring_sources(source_id),

    event_type VARCHAR(100) NOT NULL,

    source_ip INET,

    destination VARCHAR(255),

    description TEXT NOT NULL,

    failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempts >= 0),

    transferred_mb NUMERIC(14, 2) NOT NULL DEFAULT 0
        CHECK (transferred_mb >= 0),

    affected_users INTEGER NOT NULL DEFAULT 1
        CHECK (affected_users >= 1),

    event_time TIMESTAMPTZ NOT NULL,

    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    raw_metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    CHECK (jsonb_typeof(raw_metadata) = 'object')
);

CREATE INDEX idx_security_events_time
    ON security_events(event_time DESC);

CREATE INDEX idx_security_events_source_time
    ON security_events(source_id, event_time DESC);

CREATE INDEX idx_security_events_ip
    ON security_events(source_ip);

CREATE INDEX idx_security_events_metadata
    ON security_events USING GIN(raw_metadata);

-- ---------------------------------------------------------
-- 7. Detection rules
-- ---------------------------------------------------------

CREATE TABLE detection_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    rule_code VARCHAR(50) NOT NULL UNIQUE,

    rule_name VARCHAR(150) NOT NULL,

    incident incident_type NOT NULL,

    severity severity_level NOT NULL,

    threshold_value NUMERIC(14, 2) NOT NULL
        CHECK (threshold_value > 0),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    description TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO detection_rules (
    rule_code,
    rule_name,
    incident,
    severity,
    threshold_value,
    description
)
VALUES
(
    'AUTH-001',
    'Repeated Authentication Failures',
    'BRUTE_FORCE',
    'HIGH',
    10,
    'Detect repeated authentication failures'
),
(
    'AUTH-002',
    'Critical Authentication Failures',
    'BRUTE_FORCE',
    'CRITICAL',
    25,
    'Detect severe authentication attack activity'
),
(
    'ENDP-001',
    'Malware Detection',
    'MALWARE',
    'HIGH',
    1,
    'Endpoint malware detection'
),
(
    'MAIL-001',
    'Reported Phishing',
    'PHISHING',
    'MEDIUM',
    1,
    'User-reported suspicious email'
),
(
    'DATA-001',
    'Large Outbound Transfer',
    'DATA_EXFILTRATION',
    'CRITICAL',
    500,
    'Detect unusually large outbound transfer'
);

-- ---------------------------------------------------------
-- 8. Security alerts
-- ---------------------------------------------------------

CREATE TABLE alerts (
    alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_id BIGINT NOT NULL UNIQUE
        REFERENCES security_events(event_id),

    rule_id BIGINT NOT NULL
        REFERENCES detection_rules(rule_id),

    incident incident_type NOT NULL,

    severity severity_level NOT NULL,

    confidence NUMERIC(5, 4) NOT NULL
        CHECK (confidence BETWEEN 0 AND 1),

    status alert_status NOT NULL DEFAULT 'NEW',

    assigned_tier soc_tier NOT NULL DEFAULT 'TIER_1',

    assigned_analyst BIGINT
        REFERENCES analysts(analyst_id),

    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    closed_at TIMESTAMPTZ,

    CHECK (
        (status = 'CLOSED' AND closed_at IS NOT NULL)
        OR
        (status <> 'CLOSED' AND closed_at IS NULL)
    )
);

CREATE INDEX idx_alerts_status_severity
    ON alerts(status, severity, detected_at DESC);

CREATE INDEX idx_alerts_analyst
    ON alerts(assigned_analyst, status);

CREATE INDEX idx_alerts_active
    ON alerts(detected_at DESC)
    WHERE status NOT IN ('CLOSED', 'FALSE_POSITIVE');

-- ---------------------------------------------------------
-- 9. Alert evidence
-- ---------------------------------------------------------

CREATE TABLE alert_evidence (
    evidence_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    alert_id BIGINT NOT NULL
        REFERENCES alerts(alert_id) ON DELETE CASCADE,

    evidence_type VARCHAR(60) NOT NULL,

    evidence_description TEXT NOT NULL,

    evidence_reference VARCHAR(500),

    collected_by BIGINT
        REFERENCES analysts(analyst_id),

    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    integrity_hash VARCHAR(128)
);

CREATE INDEX idx_evidence_alert
    ON alert_evidence(alert_id, collected_at);

-- ---------------------------------------------------------
-- 10. Incident records
-- ---------------------------------------------------------

CREATE TABLE incidents (
    incident_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    incident_number VARCHAR(40) NOT NULL UNIQUE,

    alert_id BIGINT NOT NULL UNIQUE
        REFERENCES alerts(alert_id),

    incident_title VARCHAR(200) NOT NULL,

    incident_description TEXT NOT NULL,

    severity severity_level NOT NULL,

    status alert_status NOT NULL DEFAULT 'NEW',

    incident_owner BIGINT
        REFERENCES analysts(analyst_id),

    detected_at TIMESTAMPTZ NOT NULL,

    acknowledged_at TIMESTAMPTZ,

    contained_at TIMESTAMPTZ,

    resolved_at TIMESTAMPTZ,

    closed_at TIMESTAMPTZ,

    root_cause TEXT,

    impact_assessment TEXT,

    CHECK (
        contained_at IS NULL OR
        acknowledged_at IS NOT NULL
    ),

    CHECK (
        resolved_at IS NULL OR
        contained_at IS NOT NULL
    ),

    CHECK (
        closed_at IS NULL OR
        resolved_at IS NOT NULL
    )
);

CREATE INDEX idx_incidents_status_severity
    ON incidents(status, severity, detected_at DESC);

-- ---------------------------------------------------------
-- 11. Incident audit history
-- ---------------------------------------------------------

CREATE TABLE incident_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    incident_id BIGINT NOT NULL
        REFERENCES incidents(incident_id),

    previous_status alert_status,

    new_status alert_status NOT NULL,

    changed_by VARCHAR(120) NOT NULL,

    reason TEXT NOT NULL,

    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incident_history
    ON incident_history(incident_id, changed_at);

-- ---------------------------------------------------------
-- 12. Escalation records
-- ---------------------------------------------------------

CREATE TABLE escalations (
    escalation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    incident_id BIGINT NOT NULL
        REFERENCES incidents(incident_id),

    from_tier soc_tier NOT NULL,

    to_tier soc_tier NOT NULL,

    assigned_to BIGINT
        REFERENCES analysts(analyst_id),

    escalation_reason TEXT NOT NULL,

    escalated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    acknowledged_at TIMESTAMPTZ,

    CHECK (
        from_tier <> to_tier
    ),

    CHECK (
        acknowledged_at IS NULL OR
        acknowledged_at >= escalated_at
    )
);

CREATE INDEX idx_escalations_incident
    ON escalations(incident_id, escalated_at DESC);

-- ---------------------------------------------------------
-- 13. Response actions
-- ---------------------------------------------------------

CREATE TABLE response_actions (
    action_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    incident_id BIGINT NOT NULL
        REFERENCES incidents(incident_id),

    action_type VARCHAR(80) NOT NULL,

    action_description TEXT NOT NULL,

    executed_by BIGINT
        REFERENCES analysts(analyst_id),

    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,

    approved_by BIGINT
        REFERENCES analysts(analyst_id),

    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    outcome VARCHAR(50) NOT NULL,

    CHECK (
        NOT requires_approval OR approved_by IS NOT NULL
    )
);

CREATE INDEX idx_response_actions_incident
    ON response_actions(incident_id, executed_at DESC);

-- ---------------------------------------------------------
-- 14. Monitoring and escalation policies
-- ---------------------------------------------------------

CREATE TABLE escalation_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(120) NOT NULL UNIQUE,

    severity severity_level NOT NULL,

    minimum_tier soc_tier NOT NULL,

    response_target_minutes INTEGER NOT NULL
        CHECK (response_target_minutes > 0),

    escalation_target_minutes INTEGER NOT NULL
        CHECK (escalation_target_minutes >= response_target_minutes),

    active BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO escalation_policies (
    policy_name,
    severity,
    minimum_tier,
    response_target_minutes,
    escalation_target_minutes
)
VALUES
('Low Severity', 'LOW', 'TIER_1', 60, 240),
('Medium Severity', 'MEDIUM', 'TIER_1', 30, 120),
('High Severity', 'HIGH', 'TIER_2', 15, 45),
('Critical Severity', 'CRITICAL', 'TIER_3', 5, 15);

-- ---------------------------------------------------------
-- 15. Status checks for monitoring infrastructure
-- ---------------------------------------------------------

CREATE TABLE monitoring_health (
    health_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    source_id BIGINT NOT NULL
        REFERENCES monitoring_sources(source_id),

    check_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    operational BOOLEAN NOT NULL,

    ingestion_delay_seconds INTEGER NOT NULL
        CHECK (ingestion_delay_seconds >= 0),

    error_message TEXT,

    UNIQUE (source_id, check_time)
);

CREATE INDEX idx_monitoring_health_time
    ON monitoring_health(source_id, check_time DESC);

-- ---------------------------------------------------------
-- 16. Incident state transition enforcement
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_incident_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.status = 'NEW' AND NEW.status IN (
            'TRIAGED', 'ESCALATED', 'FALSE_POSITIVE'
        ))
        OR
        (OLD.status = 'TRIAGED' AND NEW.status IN (
            'INVESTIGATING', 'ESCALATED', 'FALSE_POSITIVE'
        ))
        OR
        (OLD.status = 'INVESTIGATING' AND NEW.status IN (
            'ESCALATED', 'CONTAINED', 'FALSE_POSITIVE'
        ))
        OR
        (OLD.status = 'ESCALATED' AND NEW.status IN (
            'INVESTIGATING', 'CONTAINED'
        ))
        OR
        (OLD.status = 'CONTAINED' AND NEW.status = 'RESOLVED')
        OR
        (OLD.status = 'RESOLVED' AND NEW.status = 'CLOSED')
        OR
        (OLD.status = 'FALSE_POSITIVE' AND NEW.status = 'CLOSED')
    ) THEN
        RAISE EXCEPTION
            'Invalid incident transition: % -> %',
            OLD.status, NEW.status;
    END IF;

    IF NEW.status = 'CONTAINED' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM alert_evidence e
            JOIN incidents i ON i.alert_id = e.alert_id
            WHERE i.incident_id = NEW.incident_id
        ) THEN
            RAISE EXCEPTION
                'Containment requires recorded evidence';
        END IF;
    END IF;

    IF NEW.status = 'CLOSED' THEN
        NEW.closed_at = NOW();
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_incident_transition
BEFORE UPDATE OF status ON incidents
FOR EACH ROW
EXECUTE FUNCTION validate_incident_transition();

-- ---------------------------------------------------------
-- 17. Audit trigger
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION audit_incident_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO incident_history (
            incident_id,
            previous_status,
            new_status,
            changed_by,
            reason
        )
        VALUES (
            NEW.incident_id,
            OLD.status,
            NEW.status,
            COALESCE(
                NULLIF(current_setting(
                    'soc.actor',
                    TRUE
                ), ''),
                CURRENT_USER
            ),
            COALESCE(
                NULLIF(current_setting(
                    'soc.reason',
                    TRUE
                ), ''),
                'Recorded status transition'
            )
        );
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_incident_status
AFTER UPDATE OF status ON incidents
FOR EACH ROW
EXECUTE FUNCTION audit_incident_status();

-- ---------------------------------------------------------
-- 18. Automatic alert timestamp management
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION update_alert_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();

    IF NEW.status = 'CLOSED' THEN
        NEW.closed_at = COALESCE(NEW.closed_at, NOW());
    ELSE
        NEW.closed_at = NULL;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_alert_timestamp
BEFORE UPDATE ON alerts
FOR EACH ROW
EXECUTE FUNCTION update_alert_timestamp();

-- ---------------------------------------------------------
-- 19. Analyst workload function
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION analyst_workload(
    p_analyst_id BIGINT
)
RETURNS INTEGER
LANGUAGE sql
STABLE
AS $$
    SELECT COUNT(*)::INTEGER
    FROM alerts
    WHERE assigned_analyst = p_analyst_id
      AND status NOT IN ('CLOSED', 'FALSE_POSITIVE');
$$;

-- ---------------------------------------------------------
-- 20. Analyst eligibility function
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION find_eligible_analyst(
    p_incident incident_type,
    p_minimum_tier soc_tier
)
RETURNS TABLE (
    analyst_id BIGINT,
    analyst_name VARCHAR,
    tier soc_tier,
    active_workload INTEGER
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        a.analyst_id,
        a.analyst_name,
        a.tier,
        COUNT(al.alert_id)::INTEGER
    FROM analysts a
    JOIN analyst_skills s
      ON s.analyst_id = a.analyst_id
    LEFT JOIN alerts al
      ON al.assigned_analyst = a.analyst_id
     AND al.status NOT IN ('CLOSED', 'FALSE_POSITIVE')
    WHERE a.active = TRUE
      AND s.skill = p_incident
      AND s.proficiency >= 3
      AND (
          CASE a.tier
              WHEN 'TIER_1' THEN 1
              WHEN 'TIER_2' THEN 2
              WHEN 'TIER_3' THEN 3
          END
      ) >= (
          CASE p_minimum_tier
              WHEN 'TIER_1' THEN 1
              WHEN 'TIER_2' THEN 2
              WHEN 'TIER_3' THEN 3
          END
      )
    GROUP BY a.analyst_id, a.analyst_name, a.tier,
             a.max_assignments
    HAVING COUNT(al.alert_id) < a.max_assignments
    ORDER BY
        CASE a.tier
            WHEN 'TIER_1' THEN 1
            WHEN 'TIER_2' THEN 2
            WHEN 'TIER_3' THEN 3
        END,
        COUNT(al.alert_id),
        a.analyst_id
    LIMIT 1;
$$;

-- ---------------------------------------------------------
-- 21. SOC alert ingestion procedure
-- ---------------------------------------------------------

CREATE OR REPLACE PROCEDURE ingest_security_event(
    p_external_id VARCHAR,
    p_source_name VARCHAR,
    p_event_type VARCHAR,
    p_source_ip INET,
    p_destination VARCHAR,
    p_description TEXT,
    p_failed_attempts INTEGER,
    p_transferred_mb NUMERIC,
    p_event_time TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_source_id BIGINT;
    v_event_id BIGINT;
    v_rule_id BIGINT;
    v_incident incident_type;
    v_severity severity_level;
    v_confidence NUMERIC(5,4);
    v_alert_id BIGINT;
BEGIN
    IF p_external_id IS NULL OR BTRIM(p_external_id) = '' THEN
        RAISE EXCEPTION 'External event ID required';
    END IF;

    IF p_failed_attempts < 0 OR p_transferred_mb < 0 THEN
        RAISE EXCEPTION 'Invalid event measurements';
    END IF;

    SELECT source_id
    INTO v_source_id
    FROM monitoring_sources
    WHERE source_name = p_source_name
      AND enabled = TRUE;

    IF v_source_id IS NULL THEN
        RAISE EXCEPTION 'Monitoring source unavailable: %',
            p_source_name;
    END IF;

    INSERT INTO security_events (
        external_event_id,
        source_id,
        event_type,
        source_ip,
        destination,
        description,
        failed_attempts,
        transferred_mb,
        event_time
    )
    VALUES (
        p_external_id,
        v_source_id,
        p_event_type,
        p_source_ip,
        p_destination,
        p_description,
        p_failed_attempts,
        p_transferred_mb,
        p_event_time
    )
    ON CONFLICT (external_event_id) DO NOTHING
    RETURNING event_id INTO v_event_id;

    IF v_event_id IS NULL THEN
        RAISE EXCEPTION 'Duplicate event rejected: %',
            p_external_id;
    END IF;

    -- Determine detection outcome.
    IF p_failed_attempts >= 25 THEN
        v_incident := 'BRUTE_FORCE';
        v_severity := 'CRITICAL';
        v_confidence := 0.98;
        SELECT rule_id INTO v_rule_id
        FROM detection_rules
        WHERE rule_code = 'AUTH-002' AND enabled;

    ELSIF p_failed_attempts >= 10 THEN
        v_incident := 'BRUTE_FORCE';
        v_severity := 'HIGH';
        v_confidence := 0.90;
        SELECT rule_id INTO v_rule_id
        FROM detection_rules
        WHERE rule_code = 'AUTH-001' AND enabled;

    ELSIF p_event_type = 'malware_detected' THEN
        v_incident := 'MALWARE';
        v_severity := 'HIGH';
        v_confidence := 0.95;
        SELECT rule_id INTO v_rule_id
        FROM detection_rules
        WHERE rule_code = 'ENDP-001' AND enabled;

    ELSIF p_event_type = 'phishing_report' THEN
        v_incident := 'PHISHING';
        v_severity := 'MEDIUM';
        v_confidence := 0.85;
        SELECT rule_id INTO v_rule_id
        FROM detection_rules
        WHERE rule_code = 'MAIL-001' AND enabled;

    ELSIF p_event_type = 'unauthorized_access' THEN
        v_incident := 'UNAUTHORIZED_ACCESS';
        v_severity := 'HIGH';
        v_confidence := 0.90;
        SELECT rule_id INTO v_rule_id
        FROM detection_rules
        WHERE enabled
          AND incident = 'UNAUTHORIZED_ACCESS'
        ORDER BY rule_id
        LIMIT 1;

    ELSIF p_event_type = 'outbound_transfer'
          AND p_transferred_mb >= 500 THEN
        v_incident := 'DATA_EXFILTRATION';
        v_severity := 'CRITICAL';
        v_confidence := 0.95;
        SELECT rule_id INTO v_rule_id
        FROM detection_rules
        WHERE rule_code = 'DATA-001' AND enabled;

    ELSE
        RETURN;
    END IF;

    IF v_rule_id IS NULL THEN
        RAISE EXCEPTION 'No enabled detection rule for event';
    END IF;

    INSERT INTO alerts (
        event_id,
        rule_id,
        incident,
        severity,
        confidence
    )
    VALUES (
        v_event_id,
        v_rule_id,
        v_incident,
        v_severity,
        v_confidence
    )
    RETURNING alert_id INTO v_alert_id;

    INSERT INTO incidents (
        incident_number,
        alert_id,
        incident_title,
        incident_description,
        severity,
        status,
        detected_at
    )
    VALUES (
        'INC-' || LPAD(v_alert_id::TEXT, 8, '0'),
        v_alert_id,
        v_incident::TEXT,
        p_description,
        v_severity,
        'NEW',
        p_event_time
    );

    INSERT INTO alert_evidence (
        alert_id,
        evidence_type,
        evidence_description
    )
    VALUES (
        v_alert_id,
        'AUTOMATED_DETECTION',
        'Detection rule matched: ' || v_incident::TEXT
    );
END;
$$;

-- ---------------------------------------------------------
-- 22. Incident assignment procedure
-- ---------------------------------------------------------

CREATE OR REPLACE PROCEDURE assign_incident(
    p_incident_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_incident incident_type;
    v_severity severity_level;
    v_minimum_tier soc_tier;
    v_analyst_id BIGINT;
    v_alert_id BIGINT;
BEGIN
    SELECT
        i.severity,
        a.incident,
        i.alert_id
    INTO
        v_severity,
        v_incident,
        v_alert_id
    FROM incidents i
    JOIN alerts a ON a.alert_id = i.alert_id
    WHERE i.incident_id = p_incident_id
    FOR UPDATE OF i, a;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident not found';
    END IF;

    v_minimum_tier := CASE
        WHEN v_severity = 'CRITICAL' THEN 'TIER_3'
        WHEN v_severity = 'HIGH' THEN 'TIER_2'
        ELSE 'TIER_1'
    END;

    SELECT e.analyst_id
    INTO v_analyst_id
    FROM find_eligible_analyst(
        v_incident,
        v_minimum_tier
    ) e;

    IF v_analyst_id IS NULL THEN
        PERFORM set_config(
            'soc.actor', 'SYSTEM', TRUE
        );

        PERFORM set_config(
            'soc.reason', 'No qualified analyst available', TRUE
        );

        UPDATE incidents
        SET status = 'ESCALATED'
        WHERE incident_id = p_incident_id;

        UPDATE alerts
        SET status = 'ESCALATED'
        WHERE alert_id = v_alert_id;

        RETURN;
    END IF;

    PERFORM set_config('soc.actor', 'SYSTEM', TRUE);
    PERFORM set_config(
        'soc.reason', 'Initial analyst assignment', TRUE
    );

    UPDATE incidents
    SET
        status = 'TRIAGED',
        incident_owner = v_analyst_id,
        acknowledged_at = NOW()
    WHERE incident_id = p_incident_id;

    UPDATE alerts
    SET
        status = 'TRIAGED',
        assigned_analyst = v_analyst_id,
        assigned_tier = v_minimum_tier
    WHERE alert_id = v_alert_id;
END;
$$;

-- ---------------------------------------------------------
-- 23. Transactional incident transition procedure
-- ---------------------------------------------------------

CREATE OR REPLACE PROCEDURE transition_incident(
    p_incident_id BIGINT,
    p_new_status alert_status,
    p_actor VARCHAR,
    p_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_alert_id BIGINT;
BEGIN
    IF p_actor IS NULL OR BTRIM(p_actor) = '' THEN
        RAISE EXCEPTION 'Actor is required';
    END IF;

    IF p_reason IS NULL OR BTRIM(p_reason) = '' THEN
        RAISE EXCEPTION 'Transition reason is required';
    END IF;

    SELECT alert_id
    INTO v_alert_id
    FROM incidents
    WHERE incident_id = p_incident_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident not found';
    END IF;

    PERFORM set_config('soc.actor', p_actor, TRUE);
    PERFORM set_config('soc.reason', p_reason, TRUE);

    UPDATE incidents
    SET
        status = p_new_status,
        contained_at = CASE
            WHEN p_new_status = 'CONTAINED'
                THEN NOW()
            ELSE contained_at
        END,
        resolved_at = CASE
            WHEN p_new_status = 'RESOLVED'
                THEN NOW()
            ELSE resolved_at
        END,
        root_cause = CASE
            WHEN p_new_status = 'RESOLVED'
                THEN COALESCE(root_cause, p_reason)
            ELSE root_cause
        END
    WHERE incident_id = p_incident_id;

    UPDATE alerts
    SET
        status = p_new_status,
        closed_at = CASE
            WHEN p_new_status = 'CLOSED'
                THEN NOW()
            ELSE NULL
        END
    WHERE alert_id = v_alert_id;
END;
$$;

-- ---------------------------------------------------------
-- 24. Escalation procedure
-- ---------------------------------------------------------

CREATE OR REPLACE PROCEDURE escalate_incident(
    p_incident_id BIGINT,
    p_target_tier soc_tier,
    p_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_owner BIGINT;
    v_current_tier soc_tier;
    v_alert_id BIGINT;
BEGIN
    SELECT
        incident_owner,
        alert_id
    INTO
        v_owner,
        v_alert_id
    FROM incidents
    WHERE incident_id = p_incident_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Incident not found';
    END IF;

    SELECT assigned_tier
    INTO v_current_tier
    FROM alerts
    WHERE alert_id = v_alert_id
    FOR UPDATE;

    IF v_current_tier = p_target_tier THEN
        RAISE EXCEPTION 'Incident already assigned to target tier';
    END IF;

    INSERT INTO escalations (
        incident_id,
        from_tier,
        to_tier,
        assigned_to,
        escalation_reason
    )
    VALUES (
        p_incident_id,
        v_current_tier,
        p_target_tier,
        NULL,
        p_reason
    );

    PERFORM set_config('soc.actor', 'SYSTEM', TRUE);
    PERFORM set_config(
        'soc.reason',
        p_reason,
        TRUE
    );

    UPDATE incidents
    SET status = 'ESCALATED'
    WHERE incident_id = p_incident_id;

    UPDATE alerts
    SET
        status = 'ESCALATED',
        assigned_tier = p_target_tier,
        assigned_analyst = NULL
    WHERE alert_id = v_alert_id;
END;
$$;

-- ---------------------------------------------------------
-- 25. Seed analysts
-- ---------------------------------------------------------

INSERT INTO analysts (
    employee_code,
    analyst_name,
    role_id,
    tier,
    email,
    max_assignments
)
SELECT
    'SOC-001',
    'SOC L1 Analyst',
    role_id,
    'TIER_1',
    'l1@example.org',
    5
FROM soc_roles
WHERE role_name = 'L1_ANALYST';

INSERT INTO analysts (
    employee_code,
    analyst_name,
    role_id,
    tier,
    email,
    max_assignments
)
SELECT
    'SOC-002',
    'SOC L2 Responder',
    role_id,
    'TIER_2',
    'l2@example.org',
    5
FROM soc_roles
WHERE role_name = 'L2_RESPONDER';

INSERT INTO analysts (
    employee_code,
    analyst_name,
    role_id,
    tier,
    email,
    max_assignments
)
SELECT
    'SOC-003',
    'SOC L3 Threat Hunter',
    role_id,
    'TIER_3',
    'l3@example.org',
    5
FROM soc_roles
WHERE role_name = 'L3_THREAT_HUNTER';

INSERT INTO analysts (
    employee_code,
    analyst_name,
    role_id,
    tier,
    email,
    max_assignments
)
SELECT
    'SOC-004',
    'SOC Operations Manager',
    role_id,
    'TIER_3',
    'manager@example.org',
    10
FROM soc_roles
WHERE role_name = 'SOC_MANAGER';

-- ---------------------------------------------------------
-- 26. Seed analyst skills
-- ---------------------------------------------------------

INSERT INTO analyst_skills (
    analyst_id,
    skill,
    proficiency
)
SELECT analyst_id, skill::incident_type, proficiency
FROM (
    VALUES
    ('SOC-001', 'BRUTE_FORCE', 3),
    ('SOC-001', 'PHISHING', 4),
    ('SOC-002', 'MALWARE', 4),
    ('SOC-002', 'UNAUTHORIZED_ACCESS', 4),
    ('SOC-003', 'BRUTE_FORCE', 5),
    ('SOC-003', 'DATA_EXFILTRATION', 5),
    ('SOC-003', 'NETWORK_INTRUSION', 5)
) AS skills(employee_code, skill, proficiency)
JOIN analysts USING (employee_code);

-- ---------------------------------------------------------
-- 27. Seed monitoring health
-- ---------------------------------------------------------

INSERT INTO monitoring_health (
    source_id,
    operational,
    ingestion_delay_seconds,
    error_message
)
SELECT
    source_id,
    TRUE,
    2,
    NULL
FROM monitoring_sources;

-- ---------------------------------------------------------
-- 28. Ingest realistic security events
-- ---------------------------------------------------------

CALL ingest_security_event(
    'EVT-001',
    'Corporate Firewall',
    'authentication_failure',
    '203.0.113.45'::INET,
    'VPN Gateway',
    'Thirty failed VPN authentication attempts',
    30,
    0,
    NOW() - INTERVAL '5 minutes'
);

CALL ingest_security_event(
    'EVT-002',
    'Endpoint EDR',
    'malware_detected',
    '198.51.100.20'::INET,
    'Workstation-17',
    'Suspicious executable detected',
    0,
    0,
    NOW() - INTERVAL '4 minutes'
);

CALL ingest_security_event(
    'EVT-003',
    'Email Gateway',
    'phishing_report',
    '192.0.2.15'::INET,
    'Mail Server',
    'User reported suspicious attachment',
    0,
    0,
    NOW() - INTERVAL '3 minutes'
);

CALL ingest_security_event(
    'EVT-004',
    'Corporate Firewall',
    'outbound_transfer',
    '198.51.100.80'::INET,
    'External Endpoint',
    'Large outbound data transfer',
    0,
    850,
    NOW() - INTERVAL '2 minutes'
);

CALL ingest_security_event(
    'EVT-005',
    'Identity Provider',
    'normal_login',
    '192.0.2.40'::INET,
    'Identity Service',
    'Normal authentication',
    0,
    0,
    NOW()
);

-- ---------------------------------------------------------
-- 29. Automatically assign generated incidents
-- ---------------------------------------------------------

DO $$
DECLARE
    v_incident RECORD;
BEGIN
    FOR v_incident IN
        SELECT incident_id
        FROM incidents
        WHERE status = 'NEW'
        ORDER BY incident_id
    LOOP
        CALL assign_incident(v_incident.incident_id);
    END LOOP;
END;
$$;

-- ---------------------------------------------------------
-- 30. Complete a representative incident lifecycle
-- ---------------------------------------------------------

DO $$
DECLARE
    v_incident_id BIGINT;
    v_evidence_exists BOOLEAN;
BEGIN
    SELECT i.incident_id
    INTO v_incident_id
    FROM incidents i
    JOIN alerts a ON a.alert_id = i.alert_id
    WHERE a.incident = 'BRUTE_FORCE'
    ORDER BY i.incident_id
    LIMIT 1;

    IF v_incident_id IS NOT NULL THEN

        SELECT EXISTS (
            SELECT 1
            FROM incidents i
            JOIN alert_evidence e ON e.alert_id = i.alert_id
            WHERE i.incident_id = v_incident_id
        )
        INTO v_evidence_exists;

        IF v_evidence_exists THEN
            CALL transition_incident(
                v_incident_id,
                'INVESTIGATING',
                'SOC-003',
                'Correlating identity and firewall telemetry'
            );

            CALL transition_incident(
                v_incident_id,
                'CONTAINED',
                'SOC-003',
                'Suspicious source blocked'
            );

            CALL transition_incident(
                v_incident_id,
                'RESOLVED',
                'SOC-003',
                'Authentication controls restored'
            );

            CALL transition_incident(
                v_incident_id,
                'CLOSED',
                'SOC-004',
                'Incident evidence documented'
            );
        END IF;
    END IF;
END;
$$;

-- ---------------------------------------------------------
-- 31. View: operational alert dashboard
-- ---------------------------------------------------------

CREATE OR REPLACE VIEW v_soc_alert_dashboard AS
SELECT
    a.alert_id,
    e.external_event_id,
    a.incident,
    a.severity,
    a.status,
    a.confidence,
    an.analyst_name,
    a.assigned_tier,
    e.source_ip,
    e.source_name,
    e.event_time,
    a.detected_at,
    i.incident_number,
    i.acknowledged_at,
    i.contained_at,
    i.resolved_at,
    i.closed_at
FROM alerts a
JOIN security_events e
    ON e.event_id = a.event_id
JOIN monitoring_sources ms
    ON ms.source_id = e.source_id
LEFT JOIN analysts an
    ON an.analyst_id = a.assigned_analyst
LEFT JOIN incidents i
    ON i.alert_id = a.alert_id;

-- ---------------------------------------------------------
-- 32. View: SOC analyst workload
-- ---------------------------------------------------------

CREATE OR REPLACE VIEW v_analyst_workload AS
SELECT
    a.analyst_id,
    a.employee_code,
    a.analyst_name,
    a.tier,
    a.active,
    a.max_assignments,
    COUNT(al.alert_id) FILTER (
        WHERE al.status NOT IN ('CLOSED', 'FALSE_POSITIVE')
    ) AS active_assignments,
    COUNT(al.alert_id) AS historical_assignments
FROM analysts a
LEFT JOIN alerts al
    ON al.assigned_analyst = a.analyst_id
GROUP BY
    a.analyst_id,
    a.employee_code,
    a.analyst_name,
    a.tier,
    a.active,
    a.max_assignments;

-- ---------------------------------------------------------
-- 33. View: monitoring infrastructure health
-- ---------------------------------------------------------

CREATE OR REPLACE VIEW v_monitoring_health AS
SELECT DISTINCT ON (ms.source_id)
    ms.source_id,
    ms.source_name,
    ms.source_type,
    ms.enabled,
    mh.operational,
    mh.ingestion_delay_seconds,
    mh.check_time,
    mh.error_message
FROM monitoring_sources ms
LEFT JOIN monitoring_health mh
    ON mh.source_id = ms.source_id
ORDER BY ms.source_id, mh.check_time DESC NULLS LAST;

-- ---------------------------------------------------------
-- 34. Query: incident retrieval
-- ---------------------------------------------------------

SELECT *
FROM v_soc_alert_dashboard
ORDER BY detected_at DESC;

-- ---------------------------------------------------------
-- 35. Query: severity distribution
-- ---------------------------------------------------------

SELECT
    severity,
    COUNT(*) AS total_alerts,
    COUNT(*) FILTER (
        WHERE status NOT IN ('CLOSED', 'FALSE_POSITIVE')
    ) AS active_alerts
FROM alerts
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END;

-- ---------------------------------------------------------
-- 36. Query: incident lifecycle performance
-- ---------------------------------------------------------

SELECT
    incident_number,
    severity,
    status,
    EXTRACT(
        EPOCH FROM (acknowledged_at - detected_at)
    ) / 60 AS acknowledgement_minutes,
    EXTRACT(
        EPOCH FROM (contained_at - detected_at)
    ) / 60 AS containment_minutes,
    EXTRACT(
        EPOCH FROM (resolved_at - detected_at)
    ) / 60 AS resolution_minutes
FROM incidents
WHERE acknowledged_at IS NOT NULL
ORDER BY detected_at DESC;

-- ---------------------------------------------------------
-- 37. Query: escalation analysis
-- ---------------------------------------------------------

SELECT
    from_tier,
    to_tier,
    COUNT(*) AS escalation_count,
    AVG(
        EXTRACT(
            EPOCH FROM (acknowledged_at - escalated_at)
        ) / 60
    ) AS average_acknowledgement_minutes
FROM escalations
GROUP BY from_tier, to_tier;

-- ---------------------------------------------------------
-- 38. Query: analyst workload evaluation
-- ---------------------------------------------------------

SELECT *
FROM v_analyst_workload
ORDER BY active_assignments DESC, analyst_name;

-- ---------------------------------------------------------
-- 39. Query: detection effectiveness
-- ---------------------------------------------------------

SELECT
    dr.rule_code,
    dr.rule_name,
    COUNT(a.alert_id) AS generated_alerts,
    COUNT(a.alert_id) FILTER (
        WHERE a.status = 'FALSE_POSITIVE'
    ) AS false_positive_alerts,
    ROUND(
        100.0 * COUNT(a.alert_id) FILTER (
            WHERE a.status = 'FALSE_POSITIVE'
        ) / NULLIF(COUNT(a.alert_id), 0),
        2
    ) AS false_positive_percentage
FROM detection_rules dr
LEFT JOIN alerts a
    ON a.rule_id = dr.rule_id
GROUP BY dr.rule_id, dr.rule_code, dr.rule_name
ORDER BY generated_alerts DESC;

-- ---------------------------------------------------------
-- 40. Query: CTE-based SOC executive reporting
-- ---------------------------------------------------------

WITH severity_summary AS (
    SELECT
        severity,
        COUNT(*) AS total
    FROM alerts
    GROUP BY severity
),
status_summary AS (
    SELECT
        status,
        COUNT(*) AS total
    FROM incidents
    GROUP BY status
),
response_summary AS (
    SELECT
        COUNT(*) AS total_incidents,
        AVG(
            EXTRACT(
                EPOCH FROM (resolved_at - detected_at)
            ) / 60
        ) AS average_resolution_minutes
    FROM incidents
    WHERE resolved_at IS NOT NULL
)
SELECT
    (SELECT JSONB_OBJECT_AGG(
        severity::TEXT, total
    ) FROM severity_summary) AS severity_distribution,

    (SELECT JSONB_OBJECT_AGG(
        status::TEXT, total
    ) FROM status_summary) AS incident_status_distribution,

    response_summary.total_incidents,
    response_summary.average_resolution_minutes
FROM response_summary;

-- ---------------------------------------------------------
-- 41. Query: eligible analyst for a critical incident
-- ---------------------------------------------------------

SELECT *
FROM find_eligible_analyst(
    'BRUTE_FORCE',
    'TIER_3'
);

-- ---------------------------------------------------------
-- 42. Query: overdue response detection
-- ---------------------------------------------------------

SELECT
    i.incident_number,
    i.severity,
    i.status,
    p.response_target_minutes,
    EXTRACT(
        EPOCH FROM (NOW() - i.detected_at)
    ) / 60 AS elapsed_minutes
FROM incidents i
JOIN escalation_policies p
    ON p.severity = i.severity
   AND p.active
WHERE i.acknowledged_at IS NULL
  AND i.status NOT IN ('CLOSED', 'FALSE_POSITIVE')
  AND NOW() >
      i.detected_at +
      MAKE_INTERVAL(mins => p.response_target_minutes)
ORDER BY i.detected_at;

-- ---------------------------------------------------------
-- 43. Query: unmonitored or unhealthy sources
-- ---------------------------------------------------------

SELECT *
FROM v_monitoring_health
WHERE enabled = FALSE
   OR operational = FALSE
   OR ingestion_delay_seconds > 60
   OR check_time IS NULL;

-- ---------------------------------------------------------
-- 44. Query: event correlation by source IP
-- ---------------------------------------------------------

SELECT
    source_ip,
    COUNT(*) AS event_count,
    COUNT(DISTINCT source_id) AS distinct_sources,
    SUM(failed_attempts) AS total_failed_attempts,
    MAX(event_time) AS latest_event
FROM security_events
WHERE event_time >= NOW() - INTERVAL '24 hours'
GROUP BY source_ip
HAVING COUNT(*) >= 2
ORDER BY event_count DESC;

-- ---------------------------------------------------------
-- 45. Query: unresolved incidents
-- ---------------------------------------------------------

SELECT
    incident_number,
    incident_title,
    severity,
    status,
    incident_owner,
    detected_at
FROM incidents
WHERE status NOT IN ('CLOSED', 'FALSE_POSITIVE')
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END,
    detected_at;

-- ---------------------------------------------------------
-- 46. Demonstrate transaction rollback on invalid transition
-- ---------------------------------------------------------

DO $$
DECLARE
    v_incident_id BIGINT;
BEGIN
    SELECT incident_id
    INTO v_incident_id
    FROM incidents
    WHERE status = 'NEW'
    LIMIT 1;

    IF v_incident_id IS NOT NULL THEN
        BEGIN
            CALL transition_incident(
                v_incident_id,
                'CLOSED',
                'SOC-004',
                'Attempted invalid direct closure'
            );
        EXCEPTION
            WHEN OTHERS THEN
                RAISE NOTICE
                    'Invalid transition rejected safely: %',
                    SQLERRM;
        END;
    END IF;
END;
$$;

-- ---------------------------------------------------------
-- 47. Query: incident audit trail
-- ---------------------------------------------------------

SELECT
    i.incident_number,
    h.previous_status,
    h.new_status,
    h.changed_by,
    h.reason,
    h.changed_at
FROM incident_history h
JOIN incidents i
    ON i.incident_id = h.incident_id
ORDER BY h.changed_at DESC;

-- ---------------------------------------------------------
-- 48. Data integrity verification
-- ---------------------------------------------------------

SELECT
    'Alerts without incidents' AS validation,
    COUNT(*) AS failure_count
FROM alerts a
LEFT JOIN incidents i
    ON i.alert_id = a.alert_id
WHERE i.incident_id IS NULL

UNION ALL

SELECT
    'Incidents without alerts',
    COUNT(*)
FROM incidents i
LEFT JOIN alerts a
    ON a.alert_id = i.alert_id
WHERE a.alert_id IS NULL

UNION ALL

SELECT
    'Unassigned active alerts',
    COUNT(*)
FROM alerts
WHERE assigned_analyst IS NULL
  AND status NOT IN ('CLOSED', 'FALSE_POSITIVE');

COMMIT;
