/*
====================================================================
ALERT TRIAGE AND SECURITY OPERATIONS DATABASE
====================================================================

Platform: PostgreSQL 14+

Domain:
- Alert ingestion
- Severity and detection confidence
- Asset and threat enrichment
- Evidence management
- False-positive classification
- Risk scoring
- Analyst assignment
- Investigation workflow
- Escalation and resolution
- Audit history
- Operational reporting

The script is self-contained and creates a dedicated schema.
It can be executed as a database administrator or a role with
CREATE SCHEMA and object-creation permissions.

The sample data represents a fictional security operations center.
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS alert_ops;

SET search_path TO alert_ops, public;

-- ============================================================
-- 1. ENUMERATED DOMAIN TYPES
-- ============================================================

CREATE TYPE severity_level AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'informational'
);

CREATE TYPE alert_status AS ENUM (
    'new',
    'enriching',
    'triaged',
    'assigned',
    'investigating',
    'escalated',
    'resolved',
    'closed'
);

CREATE TYPE alert_verdict AS ENUM (
    'true_positive',
    'false_positive',
    'benign_true_positive',
    'undetermined'
);

CREATE TYPE analyst_tier AS ENUM (
    'tier_1',
    'tier_2',
    'tier_3'
);

CREATE TYPE evidence_type AS ENUM (
    'malware_detection',
    'confirmed_c2',
    'unauthorized_access',
    'approved_activity',
    'authorized_scanner',
    'maintenance_window',
    'verified_business_process',
    'other'
);

CREATE TYPE audit_action AS ENUM (
    'ingested',
    'enriched',
    'triaged',
    'assigned',
    'investigation_started',
    'investigation_updated',
    'escalated',
    'resolved',
    'closed',
    'status_transition',
    'evidence_added'
);


-- ============================================================
-- 2. REFERENCE TABLES
-- ============================================================

CREATE TABLE security_assets (
    asset_id VARCHAR(64) PRIMARY KEY,

    asset_name VARCHAR(150) NOT NULL,

    asset_type VARCHAR(60) NOT NULL,

    asset_owner VARCHAR(120) NOT NULL,

    business_context TEXT NOT NULL,

    criticality NUMERIC(5,4) NOT NULL
        CHECK (criticality BETWEEN 0 AND 1),

    privileged_asset BOOLEAN NOT NULL DEFAULT FALSE,

    environment VARCHAR(30) NOT NULL DEFAULT 'production'
        CHECK (
            environment IN (
                'production',
                'staging',
                'development',
                'testing'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE threat_indicators (
    indicator_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    indicator_value VARCHAR(255) NOT NULL,

    indicator_type VARCHAR(50) NOT NULL,

    threat_score NUMERIC(5,4) NOT NULL
        CHECK (threat_score BETWEEN 0 AND 1),

    confirmed_malicious BOOLEAN NOT NULL DEFAULT FALSE,

    intelligence_source VARCHAR(120) NOT NULL,

    first_seen_at TIMESTAMPTZ,

    last_seen_at TIMESTAMPTZ,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE (indicator_value, indicator_type)
);


CREATE TABLE analysts (
    analyst_id VARCHAR(40) PRIMARY KEY,

    analyst_name VARCHAR(120) NOT NULL,

    email VARCHAR(255) NOT NULL UNIQUE,

    tier analyst_tier NOT NULL,

    max_active_cases INTEGER NOT NULL
        CHECK (max_active_cases > 0),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE analyst_specialties (
    analyst_id VARCHAR(40) NOT NULL
        REFERENCES analysts(analyst_id),

    specialty VARCHAR(80) NOT NULL,

    PRIMARY KEY (analyst_id, specialty)
);


-- ============================================================
-- 3. ALERT INGESTION
-- ============================================================

CREATE TABLE alerts (
    alert_id VARCHAR(64) PRIMARY KEY,

    title VARCHAR(200) NOT NULL,

    description TEXT NOT NULL,

    source VARCHAR(80) NOT NULL,

    category VARCHAR(80) NOT NULL,

    asset_id VARCHAR(64) NOT NULL
        REFERENCES security_assets(asset_id),

    severity severity_level NOT NULL,

    confidence NUMERIC(5,4) NOT NULL
        CHECK (confidence BETWEEN 0 AND 1),

    status alert_status NOT NULL DEFAULT 'new',

    verdict alert_verdict NOT NULL DEFAULT 'undetermined',

    risk_score NUMERIC(5,4)
        CHECK (
            risk_score IS NULL
            OR risk_score BETWEEN 0 AND 1
        ),

    priority VARCHAR(2)
        CHECK (
            priority IS NULL
            OR priority IN ('P1', 'P2', 'P3', 'P4')
        ),

    assigned_analyst_id VARCHAR(40)
        REFERENCES analysts(analyst_id),

    observed_at TIMESTAMPTZ NOT NULL,

    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    resolved_at TIMESTAMPTZ,

    closed_at TIMESTAMPTZ,

    version INTEGER NOT NULL DEFAULT 1
        CHECK (version > 0),

    CHECK (
        closed_at IS NULL
        OR resolved_at IS NOT NULL
    )
);


-- ============================================================
-- 4. ALERT ENRICHMENT
-- ============================================================

CREATE TABLE alert_enrichment (
    alert_id VARCHAR(64) PRIMARY KEY
        REFERENCES alerts(alert_id) ON DELETE CASCADE,

    asset_criticality NUMERIC(5,4) NOT NULL
        CHECK (asset_criticality BETWEEN 0 AND 1),

    threat_score NUMERIC(5,4) NOT NULL
        CHECK (threat_score BETWEEN 0 AND 1),

    malicious_indicator BOOLEAN NOT NULL DEFAULT FALSE,

    privileged_asset BOOLEAN NOT NULL DEFAULT FALSE,

    historical_alert_count INTEGER NOT NULL DEFAULT 0
        CHECK (historical_alert_count >= 0),

    asset_owner VARCHAR(120) NOT NULL,

    business_context TEXT NOT NULL,

    enrichment_provider VARCHAR(100) NOT NULL,

    enriched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE alert_indicator_matches (
    alert_id VARCHAR(64) NOT NULL
        REFERENCES alerts(alert_id) ON DELETE CASCADE,

    indicator_id BIGINT NOT NULL
        REFERENCES threat_indicators(indicator_id),

    match_confidence NUMERIC(5,4) NOT NULL
        CHECK (match_confidence BETWEEN 0 AND 1),

    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (alert_id, indicator_id)
);


-- ============================================================
-- 5. EVIDENCE MANAGEMENT
-- ============================================================

CREATE TABLE alert_evidence (
    evidence_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    alert_id VARCHAR(64) NOT NULL
        REFERENCES alerts(alert_id) ON DELETE CASCADE,

    evidence_type evidence_type NOT NULL,

    description TEXT NOT NULL,

    evidence_source VARCHAR(120) NOT NULL,

    reliability NUMERIC(5,4) NOT NULL
        CHECK (reliability BETWEEN 0 AND 1),

    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    submitted_by VARCHAR(40),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 6. INVESTIGATION AND ASSIGNMENT
-- ============================================================

CREATE TABLE investigations (
    investigation_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    alert_id VARCHAR(64) NOT NULL
        REFERENCES alerts(alert_id),

    analyst_id VARCHAR(40) NOT NULL
        REFERENCES analysts(analyst_id),

    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    completed_at TIMESTAMPTZ,

    findings TEXT,

    resolution_notes TEXT,

    outcome alert_verdict,

    CHECK (
        completed_at IS NULL
        OR completed_at >= started_at
    ),

    CHECK (
        completed_at IS NULL
        OR outcome IS NOT NULL
    )
);


CREATE TABLE investigation_notes (
    note_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    investigation_id BIGINT NOT NULL
        REFERENCES investigations(investigation_id)
        ON DELETE CASCADE,

    analyst_id VARCHAR(40) NOT NULL
        REFERENCES analysts(analyst_id),

    note_text TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE alert_escalations (
    escalation_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    alert_id VARCHAR(64) NOT NULL
        REFERENCES alerts(alert_id),

    escalated_by VARCHAR(40)
        REFERENCES analysts(analyst_id),

    reason TEXT NOT NULL,

    escalation_level analyst_tier NOT NULL,

    escalated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    acknowledged_at TIMESTAMPTZ
);


-- ============================================================
-- 7. AUDIT LOG
-- ============================================================

CREATE TABLE alert_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    alert_id VARCHAR(64) NOT NULL
        REFERENCES alerts(alert_id),

    action audit_action NOT NULL,

    actor VARCHAR(120) NOT NULL,

    previous_status alert_status,

    new_status alert_status,

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ============================================================
-- 8. TRIAGE POLICY CONFIGURATION
-- ============================================================

CREATE TABLE triage_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    policy_name VARCHAR(120) NOT NULL UNIQUE,

    critical_threshold NUMERIC(5,4) NOT NULL
        CHECK (critical_threshold BETWEEN 0 AND 1),

    high_threshold NUMERIC(5,4) NOT NULL
        CHECK (high_threshold BETWEEN 0 AND 1),

    medium_threshold NUMERIC(5,4) NOT NULL
        CHECK (medium_threshold BETWEEN 0 AND 1),

    malicious_evidence_threshold NUMERIC(5,4) NOT NULL
        CHECK (
            malicious_evidence_threshold BETWEEN 0 AND 1
        ),

    benign_evidence_threshold NUMERIC(5,4) NOT NULL
        CHECK (
            benign_evidence_threshold BETWEEN 0 AND 1
        ),

    minimum_tier_for_critical analyst_tier NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (critical_threshold >= high_threshold),

    CHECK (high_threshold >= medium_threshold)
);


-- ============================================================
-- 9. PERFORMANCE INDEXES
-- ============================================================

CREATE INDEX idx_alerts_status_severity
    ON alerts(status, severity);

CREATE INDEX idx_alerts_priority
    ON alerts(priority, risk_score DESC)
    WHERE status NOT IN ('resolved', 'closed');

CREATE INDEX idx_alerts_observed_at
    ON alerts(observed_at DESC);

CREATE INDEX idx_alerts_asset
    ON alerts(asset_id, observed_at DESC);

CREATE INDEX idx_alerts_assigned_analyst
    ON alerts(assigned_analyst_id)
    WHERE assigned_analyst_id IS NOT NULL;

CREATE INDEX idx_evidence_alert_type
    ON alert_evidence(alert_id, evidence_type);

CREATE INDEX idx_investigations_analyst
    ON investigations(analyst_id, started_at DESC);

CREATE INDEX idx_audit_alert_time
    ON alert_audit(alert_id, created_at DESC);

CREATE INDEX idx_audit_details
    ON alert_audit USING GIN(details);

CREATE INDEX idx_threat_active_score
    ON threat_indicators(threat_score DESC)
    WHERE active = TRUE;


-- ============================================================
-- 10. STATUS TRANSITION VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_alert_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    allowed BOOLEAN := FALSE;
BEGIN

    IF OLD.status = NEW.status THEN
        RETURN NEW;
    END IF;

    allowed := CASE OLD.status

        WHEN 'new' THEN
            NEW.status IN ('enriching', 'closed')

        WHEN 'enriching' THEN
            NEW.status IN ('triaged', 'escalated')

        WHEN 'triaged' THEN
            NEW.status IN ('assigned', 'escalated', 'closed')

        WHEN 'assigned' THEN
            NEW.status IN ('investigating', 'escalated')

        WHEN 'investigating' THEN
            NEW.status IN ('escalated', 'resolved')

        WHEN 'escalated' THEN
            NEW.status IN ('investigating', 'resolved')

        WHEN 'resolved' THEN
            NEW.status = 'closed'

        WHEN 'closed' THEN
            FALSE

        ELSE FALSE

    END;

    IF NOT allowed THEN
        RAISE EXCEPTION
            'Invalid alert transition: % -> %',
            OLD.status,
            NEW.status;
    END IF;

    NEW.version := OLD.version + 1;
    NEW.updated_at := NOW();

    IF NEW.status = 'resolved' THEN
        NEW.resolved_at := NOW();
    END IF;

    IF NEW.status = 'closed' THEN
        NEW.closed_at := NOW();
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_validate_alert_transition
BEFORE UPDATE OF status ON alerts
FOR EACH ROW
EXECUTE FUNCTION validate_alert_transition();


-- ============================================================
-- 11. AUTOMATIC AUDIT RECORDING
-- ============================================================

CREATE OR REPLACE FUNCTION audit_alert_changes()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    IF TG_OP = 'INSERT' THEN

        INSERT INTO alert_audit (
            alert_id,
            action,
            actor,
            new_status,
            details
        )
        VALUES (
            NEW.alert_id,
            'ingested',
            COALESCE(
                current_setting('app.actor', TRUE),
                'system'
            ),
            NEW.status,
            jsonb_build_object(
                'source', NEW.source,
                'severity', NEW.severity
            )
        );

        RETURN NEW;
    END IF;

    IF OLD.status IS DISTINCT FROM NEW.status THEN

        INSERT INTO alert_audit (
            alert_id,
            action,
            actor,
            previous_status,
            new_status,
            details
        )
        VALUES (
            NEW.alert_id,
            'status_transition',
            COALESCE(
                current_setting('app.actor', TRUE),
                'system'
            ),
            OLD.status,
            NEW.status,
            jsonb_build_object(
                'version', NEW.version
            )
        );

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_alert_audit
AFTER INSERT OR UPDATE OF status ON alerts
FOR EACH ROW
EXECUTE FUNCTION audit_alert_changes();


-- ============================================================
-- 12. ENRICHMENT VALIDATION
-- ============================================================

CREATE OR REPLACE FUNCTION validate_enrichment()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM alerts a
        WHERE a.alert_id = NEW.alert_id
          AND a.status IN ('new', 'enriching')
    ) THEN
        RAISE EXCEPTION
            'Enrichment is allowed only for new or enriching alerts';
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_validate_enrichment
BEFORE INSERT OR UPDATE ON alert_enrichment
FOR EACH ROW
EXECUTE FUNCTION validate_enrichment();


-- ============================================================
-- 13. EVIDENCE VALIDATION AND AUDITING
-- ============================================================

CREATE OR REPLACE FUNCTION audit_evidence_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    INSERT INTO alert_audit (
        alert_id,
        action,
        actor,
        details
    )
    VALUES (
        NEW.alert_id,
        'evidence_added',
        COALESCE(
            NEW.submitted_by,
            'evidence_service'
        ),
        jsonb_build_object(
            'evidence_id', NEW.evidence_id,
            'evidence_type', NEW.evidence_type,
            'reliability', NEW.reliability
        )
    );

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_audit_evidence
AFTER INSERT ON alert_evidence
FOR EACH ROW
EXECUTE FUNCTION audit_evidence_insert();


-- ============================================================
-- 14. RISK CALCULATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION calculate_alert_risk(
    p_alert_id VARCHAR,
    p_policy_id BIGINT
)
RETURNS NUMERIC(5,4)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE

    v_severity NUMERIC;

    v_confidence NUMERIC;

    v_asset NUMERIC;

    v_threat NUMERIC;

    v_privileged BOOLEAN;

    v_malicious BOOLEAN;

    v_history INTEGER;

    v_score NUMERIC;

BEGIN

    SELECT
        CASE a.severity
            WHEN 'critical' THEN 1.00
            WHEN 'high' THEN 0.80
            WHEN 'medium' THEN 0.55
            WHEN 'low' THEN 0.30
            WHEN 'informational' THEN 0.10
        END,
        a.confidence,
        e.asset_criticality,
        e.threat_score,
        e.privileged_asset,
        e.malicious_indicator,
        e.historical_alert_count

    INTO
        v_severity,
        v_confidence,
        v_asset,
        v_threat,
        v_privileged,
        v_malicious,
        v_history

    FROM alerts a

    JOIN alert_enrichment e
      ON e.alert_id = a.alert_id

    WHERE a.alert_id = p_alert_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Alert or enrichment record not found: %',
            p_alert_id;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM triage_policies
        WHERE policy_id = p_policy_id
          AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION
            'Enabled triage policy not found';
    END IF;

    v_score :=
        0.30 * v_severity
        + 0.25 * v_confidence
        + 0.20 * v_threat
        + 0.25 * v_asset
        + CASE WHEN v_privileged THEN 0.10 ELSE 0 END
        + CASE WHEN v_malicious THEN 0.15 ELSE 0 END
        + LEAST(v_history * 0.01, 0.10);

    RETURN LEAST(v_score, 1.0)::NUMERIC(5,4);

END;
$$;


-- ============================================================
-- 15. PRIORITY CALCULATION
-- ============================================================

CREATE OR REPLACE FUNCTION determine_alert_priority(
    p_risk NUMERIC,
    p_policy_id BIGINT
)
RETURNS VARCHAR(2)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_policy triage_policies%ROWTYPE;
BEGIN

    SELECT *
    INTO v_policy
    FROM triage_policies
    WHERE policy_id = p_policy_id
      AND enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Enabled policy not found';
    END IF;

    RETURN CASE
        WHEN p_risk >= v_policy.critical_threshold THEN 'P1'
        WHEN p_risk >= v_policy.high_threshold THEN 'P2'
        WHEN p_risk >= v_policy.medium_threshold THEN 'P3'
        ELSE 'P4'
    END;

END;
$$;


-- ============================================================
-- 16. FALSE-POSITIVE EVALUATION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_alert_verdict(
    p_alert_id VARCHAR,
    p_policy_id BIGINT
)
RETURNS alert_verdict
LANGUAGE plpgsql
STABLE
AS $$
DECLARE

    v_malicious BOOLEAN;

    v_benign BOOLEAN;

    v_confidence NUMERIC;

    v_indicator BOOLEAN;

    v_malicious_threshold NUMERIC;

    v_benign_threshold NUMERIC;

BEGIN

    SELECT
        p.malicious_evidence_threshold,
        p.benign_evidence_threshold

    INTO
        v_malicious_threshold,
        v_benign_threshold

    FROM triage_policies p

    WHERE p.policy_id = p_policy_id
      AND p.enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Enabled policy not found';
    END IF;

    SELECT
        a.confidence,
        e.malicious_indicator

    INTO
        v_confidence,
        v_indicator

    FROM alerts a

    JOIN alert_enrichment e
      ON e.alert_id = a.alert_id

    WHERE a.alert_id = p_alert_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Alert enrichment not found';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM alert_evidence e
        WHERE e.alert_id = p_alert_id
          AND e.evidence_type IN (
              'malware_detection',
              'confirmed_c2',
              'unauthorized_access'
          )
          AND e.reliability >= v_malicious_threshold
    )
    INTO v_malicious;

    SELECT EXISTS (
        SELECT 1
        FROM alert_evidence e
        WHERE e.alert_id = p_alert_id
          AND e.evidence_type IN (
              'approved_activity',
              'authorized_scanner',
              'maintenance_window',
              'verified_business_process'
          )
          AND e.reliability >= v_benign_threshold
    )
    INTO v_benign;

    IF v_malicious THEN
        RETURN 'true_positive';
    END IF;

    IF v_benign THEN
        RETURN 'false_positive';
    END IF;

    IF v_confidence >= 0.90 AND v_indicator THEN
        RETURN 'true_positive';
    END IF;

    RETURN 'undetermined';

END;
$$;


-- ============================================================
-- 17. TRIAGE PROCESSING PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE process_alert_triage(
    p_alert_id VARCHAR,
    p_policy_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE

    v_risk NUMERIC(5,4);

    v_priority VARCHAR(2);

    v_verdict alert_verdict;

BEGIN

    -- The alert row is locked to prevent concurrent triage
    -- operations from overwriting one another.

    PERFORM 1
    FROM alerts
    WHERE alert_id = p_alert_id
      AND status = 'enriching'
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Alert must be enriching before triage';
    END IF;

    v_risk := calculate_alert_risk(
        p_alert_id,
        p_policy_id
    );

    v_priority := determine_alert_priority(
        v_risk,
        p_policy_id
    );

    v_verdict := evaluate_alert_verdict(
        p_alert_id,
        p_policy_id
    );

    UPDATE alerts
    SET
        risk_score = v_risk,
        priority = v_priority,
        verdict = v_verdict,
        status = 'triaged'
    WHERE alert_id = p_alert_id;

    INSERT INTO alert_audit (
        alert_id,
        action,
        actor,
        details
    )
    VALUES (
        p_alert_id,
        'triaged',
        'triage_engine',
        jsonb_build_object(
            'risk_score', v_risk,
            'priority', v_priority,
            'verdict', v_verdict
        )
    );

END;
$$;


-- ============================================================
-- 18. ANALYST CAPACITY AND ASSIGNMENT
-- ============================================================

CREATE OR REPLACE FUNCTION assign_alert(
    p_alert_id VARCHAR,
    p_analyst_id VARCHAR
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE

    v_alert alerts%ROWTYPE;

    v_analyst analysts%ROWTYPE;

    v_required_tier INTEGER;

    v_current_load INTEGER;

    v_investigation_id BIGINT;

BEGIN

    SELECT *
    INTO v_alert
    FROM alerts
    WHERE alert_id = p_alert_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Alert not found';
    END IF;

    IF v_alert.status <> 'triaged' THEN
        RAISE EXCEPTION 'Alert must be triaged';
    END IF;

    IF v_alert.verdict = 'false_positive' THEN
        RAISE EXCEPTION
            'False-positive alert cannot be assigned';
    END IF;

    v_required_tier := CASE
        WHEN v_alert.risk_score >= 0.85 THEN 3
        WHEN v_alert.risk_score >= 0.65 THEN 2
        ELSE 1
    END;

    SELECT *
    INTO v_analyst
    FROM analysts
    WHERE analyst_id = p_analyst_id
      AND enabled = TRUE
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Analyst not found or disabled';
    END IF;

    SELECT CASE v_analyst.tier
        WHEN 'tier_1' THEN 1
        WHEN 'tier_2' THEN 2
        WHEN 'tier_3' THEN 3
    END
    INTO v_current_load;

    IF v_current_load < v_required_tier THEN
        RAISE EXCEPTION
            'Analyst tier is insufficient';
    END IF;

    SELECT COUNT(*)
    INTO v_current_load
    FROM alerts
    WHERE assigned_analyst_id = p_analyst_id
      AND status IN (
          'assigned',
          'investigating',
          'escalated'
      );

    IF v_current_load >= v_analyst.max_active_cases THEN
        RAISE EXCEPTION
            'Analyst capacity exhausted';
    END IF;

    UPDATE alerts
    SET
        assigned_analyst_id = p_analyst_id,
        status = 'assigned'
    WHERE alert_id = p_alert_id;

    INSERT INTO investigations (
        alert_id,
        analyst_id
    )
    VALUES (
        p_alert_id,
        p_analyst_id
    )
    RETURNING investigation_id
    INTO v_investigation_id;

    INSERT INTO alert_audit (
        alert_id,
        action,
        actor,
        details
    )
    VALUES (
        p_alert_id,
        'assigned',
        p_analyst_id,
        jsonb_build_object(
            'investigation_id', v_investigation_id
        )
    );

    RETURN v_investigation_id;

END;
$$;


-- ============================================================
-- 19. INVESTIGATION UPDATE PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE record_investigation_finding(
    p_investigation_id BIGINT,
    p_analyst_id VARCHAR,
    p_finding TEXT,
    p_evidence_type evidence_type DEFAULT NULL,
    p_evidence_description TEXT DEFAULT NULL,
    p_evidence_reliability NUMERIC DEFAULT NULL,
    p_evidence_source VARCHAR DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE

    v_alert_id VARCHAR;

    v_current_analyst VARCHAR;

BEGIN

    IF p_finding IS NULL OR LENGTH(TRIM(p_finding)) = 0 THEN
        RAISE EXCEPTION 'Investigation finding is required';
    END IF;

    SELECT
        i.alert_id,
        i.analyst_id

    INTO
        v_alert_id,
        v_current_analyst

    FROM investigations i

    JOIN alerts a
      ON a.alert_id = i.alert_id

    WHERE i.investigation_id = p_investigation_id
      AND i.completed_at IS NULL
      AND a.status IN ('assigned', 'investigating')
    FOR UPDATE OF i, a;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Active investigation not found';
    END IF;

    IF v_current_analyst <> p_analyst_id THEN
        RAISE EXCEPTION
            'Only the assigned analyst may update this investigation';
    END IF;

    INSERT INTO investigation_notes (
        investigation_id,
        analyst_id,
        note_text
    )
    VALUES (
        p_investigation_id,
        p_analyst_id,
        p_finding
    );

    UPDATE alerts
    SET status = 'investigating'
    WHERE alert_id = v_alert_id
      AND status = 'assigned';

    IF p_evidence_type IS NOT NULL THEN

        IF
            p_evidence_description IS NULL
            OR p_evidence_source IS NULL
            OR p_evidence_reliability IS NULL
        THEN
            RAISE EXCEPTION
                'Complete evidence information is required';
        END IF;

        INSERT INTO alert_evidence (
            alert_id,
            evidence_type,
            description,
            evidence_source,
            reliability,
            submitted_by
        )
        VALUES (
            v_alert_id,
            p_evidence_type,
            p_evidence_description,
            p_evidence_source,
            p_evidence_reliability,
            p_analyst_id
        );

    END IF;

    INSERT INTO alert_audit (
        alert_id,
        action,
        actor,
        details
    )
    VALUES (
        v_alert_id,
        'investigation_updated',
        p_analyst_id,
        jsonb_build_object(
            'investigation_id', p_investigation_id
        )
    );

END;
$$;


-- ============================================================
-- 20. RESOLUTION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE resolve_investigation(
    p_investigation_id BIGINT,
    p_analyst_id VARCHAR,
    p_verdict alert_verdict,
    p_resolution_notes TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE

    v_alert_id VARCHAR;

BEGIN

    IF p_verdict = 'undetermined' THEN
        RAISE EXCEPTION
            'Undetermined alerts cannot be resolved';
    END IF;

    IF
        p_resolution_notes IS NULL
        OR LENGTH(TRIM(p_resolution_notes)) = 0
    THEN
        RAISE EXCEPTION
            'Resolution notes are required';
    END IF;

    SELECT i.alert_id
    INTO v_alert_id

    FROM investigations i

    JOIN alerts a
      ON a.alert_id = i.alert_id

    WHERE i.investigation_id = p_investigation_id
      AND i.analyst_id = p_analyst_id
      AND i.completed_at IS NULL
      AND a.status IN ('investigating', 'escalated')
    FOR UPDATE OF i, a;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Investigation cannot be resolved by this analyst';
    END IF;

    UPDATE investigations
    SET
        completed_at = NOW(),
        outcome = p_verdict,
        resolution_notes = p_resolution_notes
    WHERE investigation_id = p_investigation_id;

    UPDATE alerts
    SET
        verdict = p_verdict,
        status = 'resolved',
        resolved_at = NOW()
    WHERE alert_id = v_alert_id;

    INSERT INTO alert_audit (
        alert_id,
        action,
        actor,
        details
    )
    VALUES (
        v_alert_id,
        'resolved',
        p_analyst_id,
        jsonb_build_object(
            'verdict', p_verdict,
            'investigation_id', p_investigation_id
        )
    );

END;
$$;


-- ============================================================
-- 21. OPERATIONAL VIEWS
-- ============================================================

CREATE VIEW active_alert_dashboard AS
SELECT
    a.alert_id,
    a.title,
    a.source,
    a.category,
    a.severity,
    a.confidence,
    a.risk_score,
    a.priority,
    a.verdict,
    a.status,
    a.observed_at,
    sa.asset_name,
    sa.asset_owner,
    sa.criticality AS asset_criticality,
    an.analyst_name AS assigned_analyst

FROM alerts a

JOIN security_assets sa
  ON sa.asset_id = a.asset_id

LEFT JOIN analysts an
  ON an.analyst_id = a.assigned_analyst_id

WHERE a.status NOT IN ('resolved', 'closed');


CREATE VIEW analyst_workload AS
SELECT
    an.analyst_id,
    an.analyst_name,
    an.tier,
    an.max_active_cases,

    COUNT(a.alert_id) FILTER (
        WHERE a.status IN (
            'assigned',
            'investigating',
            'escalated'
        )
    ) AS active_cases,

    an.max_active_cases
    -
    COUNT(a.alert_id) FILTER (
        WHERE a.status IN (
            'assigned',
            'investigating',
            'escalated'
        )
    ) AS remaining_capacity

FROM analysts an

LEFT JOIN alerts a
  ON a.assigned_analyst_id = an.analyst_id

GROUP BY
    an.analyst_id,
    an.analyst_name,
    an.tier,
    an.max_active_cases;


CREATE VIEW alert_verdict_metrics AS
SELECT
    severity,
    COUNT(*) AS total_alerts,

    COUNT(*) FILTER (
        WHERE verdict = 'true_positive'
    ) AS true_positives,

    COUNT(*) FILTER (
        WHERE verdict = 'false_positive'
    ) AS false_positives,

    COUNT(*) FILTER (
        WHERE verdict = 'undetermined'
    ) AS undetermined,

    ROUND(
        COUNT(*) FILTER (
            WHERE verdict = 'false_positive'
        )::NUMERIC
        / NULLIF(COUNT(*), 0),
        4
    ) AS false_positive_rate

FROM alerts

GROUP BY severity;


-- ============================================================
-- 22. SAMPLE REFERENCE DATA
-- ============================================================

INSERT INTO security_assets (
    asset_id,
    asset_name,
    asset_type,
    asset_owner,
    business_context,
    criticality,
    privileged_asset,
    environment
)
VALUES
(
    'SRV-001',
    'Production Identity Server',
    'server',
    'Infrastructure Security',
    'Enterprise identity and authentication services',
    0.98,
    TRUE,
    'production'
),
(
    'WS-102',
    'Employee Workstation',
    'workstation',
    'End User Computing',
    'Standard employee endpoint',
    0.45,
    FALSE,
    'production'
),
(
    'SRV-003',
    'Security Scanning Server',
    'server',
    'Security Engineering',
    'Authorized vulnerability assessment infrastructure',
    0.70,
    FALSE,
    'production'
),
(
    'DB-004',
    'Financial Database',
    'database',
    'Database Operations',
    'Critical financial transaction database',
    0.95,
    TRUE,
    'production'
);


INSERT INTO threat_indicators (
    indicator_value,
    indicator_type,
    threat_score,
    confirmed_malicious,
    intelligence_source,
    first_seen_at,
    last_seen_at
)
VALUES
(
    '198.51.100.44',
    'ip',
    0.95,
    TRUE,
    'Threat Intelligence Feed',
    NOW() - INTERVAL '3 days',
    NOW()
),
(
    'suspicious-domain.example',
    'domain',
    0.82,
    TRUE,
    'Threat Intelligence Feed',
    NOW() - INTERVAL '2 days',
    NOW()
),
(
    '192.0.2.15',
    'ip',
    0.10,
    FALSE,
    'Internal Network Inventory',
    NOW() - INTERVAL '10 days',
    NOW()
);


INSERT INTO analysts (
    analyst_id,
    analyst_name,
    email,
    tier,
    max_active_cases
)
VALUES
(
    'AN-01',
    'Analyst One',
    'analyst1@example.org',
    'tier_1',
    4
),
(
    'AN-02',
    'Analyst Two',
    'analyst2@example.org',
    'tier_2',
    5
),
(
    'AN-03',
    'Analyst Three',
    'analyst3@example.org',
    'tier_3',
    5
);


INSERT INTO analyst_specialties (
    analyst_id,
    specialty
)
VALUES
('AN-01', 'authentication'),
('AN-02', 'endpoint'),
('AN-02', 'network'),
('AN-03', 'identity'),
('AN-03', 'forensics');


INSERT INTO triage_policies (
    policy_name,
    critical_threshold,
    high_threshold,
    medium_threshold,
    malicious_evidence_threshold,
    benign_evidence_threshold,
    minimum_tier_for_critical
)
VALUES
(
    'Standard SOC Policy',
    0.85,
    0.70,
    0.45,
    0.70,
    0.90,
    'tier_3'
);


-- ============================================================
-- 23. SAMPLE ALERTS
-- ============================================================

INSERT INTO alerts (
    alert_id,
    title,
    description,
    source,
    category,
    asset_id,
    severity,
    confidence,
    observed_at
)
VALUES
(
    'ALT-5001',
    'Suspicious privileged login',
    'Administrator login from unusual location',
    'SIEM',
    'identity',
    'SRV-001',
    'critical',
    0.96,
    NOW() - INTERVAL '8 minutes'
),
(
    'ALT-5002',
    'Repeated authentication failures',
    'Multiple failed authentication attempts',
    'SIEM',
    'authentication',
    'WS-102',
    'medium',
    0.75,
    NOW() - INTERVAL '20 minutes'
),
(
    'ALT-5003',
    'Authorized vulnerability scan',
    'Scheduled internal vulnerability assessment',
    'EDR',
    'network',
    'SRV-003',
    'high',
    0.92,
    NOW() - INTERVAL '35 minutes'
),
(
    'ALT-5004',
    'Suspicious database access',
    'Unusual privileged database access',
    'Database Monitoring',
    'database',
    'DB-004',
    'high',
    0.87,
    NOW() - INTERVAL '12 minutes'
);


-- ============================================================
-- 24. SAMPLE ENRICHMENT
-- ============================================================

UPDATE alerts
SET status = 'enriching'
WHERE alert_id IN (
    'ALT-5001',
    'ALT-5002',
    'ALT-5003',
    'ALT-5004'
);


INSERT INTO alert_enrichment (
    alert_id,
    asset_criticality,
    threat_score,
    malicious_indicator,
    privileged_asset,
    historical_alert_count,
    asset_owner,
    business_context,
    enrichment_provider
)
VALUES
(
    'ALT-5001',
    0.98,
    0.95,
    TRUE,
    TRUE,
    4,
    'Infrastructure Security',
    'Production identity server',
    'Asset Inventory and Threat Intelligence'
),
(
    'ALT-5002',
    0.45,
    0.35,
    FALSE,
    FALSE,
    2,
    'End User Computing',
    'Employee workstation',
    'Asset Inventory and Threat Intelligence'
),
(
    'ALT-5003',
    0.70,
    0.05,
    FALSE,
    FALSE,
    0,
    'Security Engineering',
    'Authorized scanning infrastructure',
    'Asset Inventory and Threat Intelligence'
),
(
    'ALT-5004',
    0.95,
    0.80,
    TRUE,
    TRUE,
    3,
    'Database Operations',
    'Critical financial database',
    'Asset Inventory and Threat Intelligence'
);


-- ============================================================
-- 25. SAMPLE EVIDENCE
-- ============================================================

INSERT INTO alert_evidence (
    alert_id,
    evidence_type,
    description,
    evidence_source,
    reliability,
    submitted_by
)
VALUES
(
    'ALT-5001',
    'unauthorized_access',
    'Privileged access from an unrecognized location',
    'Identity Monitoring',
    0.95,
    'security_monitor'
),
(
    'ALT-5003',
    'authorized_scanner',
    'Scheduled scan confirmed in approved change window',
    'Change Management',
    0.98,
    'change_management'
),
(
    'ALT-5004',
    'malware_detection',
    'Malicious database access payload identified',
    'Database Security Monitoring',
    0.91,
    'security_monitor'
);


INSERT INTO alert_indicator_matches (
    alert_id,
    indicator_id,
    match_confidence
)
SELECT
    'ALT-5001',
    indicator_id,
    0.96
FROM threat_indicators
WHERE indicator_value = '198.51.100.44';


-- ============================================================
-- 26. TRIAGE ALL SAMPLE ALERTS
-- ============================================================

CALL process_alert_triage(
    'ALT-5001',
    1
);

CALL process_alert_triage(
    'ALT-5002',
    1
);

CALL process_alert_triage(
    'ALT-5003',
    1
);

CALL process_alert_triage(
    'ALT-5004',
    1
);


-- ============================================================
-- 27. VALIDATED INVESTIGATION WORKFLOW
-- ============================================================

-- Each assignment and its investigation creation is atomic.

DO $$
DECLARE
    v_investigation_id BIGINT;
BEGIN

    v_investigation_id := assign_alert(
        'ALT-5001',
        'AN-03'
    );

    CALL record_investigation_finding(
        v_investigation_id,
        'AN-03',
        'Authentication records confirm unauthorized privileged access.'
    );

    CALL resolve_investigation(
        v_investigation_id,
        'AN-03',
        'true_positive',
        'Unauthorized administrator access confirmed.'
    );

    UPDATE alerts
    SET status = 'closed'
    WHERE alert_id = 'ALT-5001';

END;
$$;


-- Assign the medium-risk alert to an eligible analyst.

DO $$
DECLARE
    v_investigation_id BIGINT;
BEGIN

    v_investigation_id := assign_alert(
        'ALT-5002',
        'AN-01'
    );

    CALL record_investigation_finding(
        v_investigation_id,
        'AN-01',
        'Authentication patterns require additional review.'
    );

END;
$$;


-- Escalate the second investigation because evidence is incomplete.

UPDATE alerts
SET status = 'escalated'
WHERE alert_id = 'ALT-5002'
  AND status = 'investigating';


INSERT INTO alert_escalations (
    alert_id,
    escalated_by,
    reason,
    escalation_level
)
VALUES (
    'ALT-5002',
    'AN-01',
    'Unresolved authentication behavior requires senior investigation.',
    'tier_2'
);


-- The authorized vulnerability scan is classified as a false positive
-- and does not receive an analyst assignment.

-- The database alert is classified as a true positive but remains
-- unassigned for demonstration of a pending high-priority case.


-- ============================================================
-- 28. RETRIEVAL QUERIES
-- ============================================================

-- Active alerts ordered by risk.

SELECT *
FROM active_alert_dashboard
ORDER BY
    risk_score DESC NULLS LAST,
    observed_at ASC;


-- Retrieve evidence for a particular alert.

SELECT
    evidence_id,
    evidence_type,
    description,
    reliability,
    evidence_source,
    observed_at
FROM alert_evidence
WHERE alert_id = 'ALT-5001'
ORDER BY observed_at DESC;


-- Retrieve the complete investigation history.

SELECT
    i.investigation_id,
    i.alert_id,
    an.analyst_name,
    i.started_at,
    i.completed_at,
    i.outcome,
    n.note_text,
    n.created_at AS note_created_at
FROM investigations i
JOIN analysts an
    ON an.analyst_id = i.analyst_id
LEFT JOIN investigation_notes n
    ON n.investigation_id = i.investigation_id
ORDER BY i.started_at DESC;


-- ============================================================
-- 29. VALIDATION QUERIES
-- ============================================================

-- Alerts without enrichment.

SELECT a.alert_id, a.title
FROM alerts a
LEFT JOIN alert_enrichment e
    ON e.alert_id = a.alert_id
WHERE e.alert_id IS NULL;


-- Active alerts with no assigned analyst.

SELECT
    alert_id,
    title,
    severity,
    risk_score,
    priority
FROM alerts
WHERE status IN (
    'assigned',
    'investigating',
    'escalated'
)
AND assigned_analyst_id IS NULL;


-- Analysts with workload exceeding their configured capacity.

SELECT *
FROM analyst_workload
WHERE active_cases > max_active_cases;


-- Completed investigations without resolution outcomes.

SELECT investigation_id, alert_id
FROM investigations
WHERE completed_at IS NOT NULL
  AND outcome IS NULL;


-- Alerts with conflicting evidence.

SELECT
    a.alert_id,
    COUNT(*) FILTER (
        WHERE e.evidence_type IN (
            'malware_detection',
            'confirmed_c2',
            'unauthorized_access'
        )
    ) AS malicious_evidence_count,

    COUNT(*) FILTER (
        WHERE e.evidence_type IN (
            'approved_activity',
            'authorized_scanner',
            'maintenance_window',
            'verified_business_process'
        )
    ) AS benign_evidence_count

FROM alerts a
JOIN alert_evidence e
    ON e.alert_id = a.alert_id

GROUP BY a.alert_id

HAVING
    COUNT(*) FILTER (
        WHERE e.evidence_type IN (
            'malware_detection',
            'confirmed_c2',
            'unauthorized_access'
        )
    ) > 0

    AND

    COUNT(*) FILTER (
        WHERE e.evidence_type IN (
            'approved_activity',
            'authorized_scanner',
            'maintenance_window',
            'verified_business_process'
        )
    ) > 0;


-- ============================================================
-- 30. AGGREGATION AND REPORTING
-- ============================================================

SELECT *
FROM alert_verdict_metrics
ORDER BY severity;


-- Overall alert distribution.

SELECT
    status,
    COUNT(*) AS alert_count,
    ROUND(AVG(confidence), 4) AS average_confidence,
    ROUND(AVG(risk_score), 4) AS average_risk
FROM alerts
GROUP BY status
ORDER BY alert_count DESC;


-- Priority distribution.

SELECT
    priority,
    COUNT(*) AS total_alerts,
    ROUND(AVG(risk_score), 4) AS average_risk
FROM alerts
GROUP BY priority
ORDER BY priority;


-- Analyst workload report.

SELECT *
FROM analyst_workload
ORDER BY
    active_cases DESC,
    remaining_capacity ASC;


-- Mean time to resolution in minutes.

SELECT
    ROUND(
        AVG(
            EXTRACT(
                EPOCH FROM (resolved_at - ingested_at)
            ) / 60
        ),
        2
    ) AS average_resolution_minutes
FROM alerts
WHERE resolved_at IS NOT NULL;


-- ============================================================
-- 31. CTE-BASED RISK ANALYSIS
-- ============================================================

WITH alert_ranking AS (
    SELECT
        a.alert_id,
        a.title,
        a.severity,
        a.confidence,
        a.risk_score,
        a.priority,
        a.status,

        ROW_NUMBER() OVER (
            ORDER BY
                a.risk_score DESC NULLS LAST,
                a.observed_at ASC
        ) AS processing_rank

    FROM alerts a

    WHERE a.status NOT IN ('resolved', 'closed')
)

SELECT *
FROM alert_ranking
ORDER BY processing_rank;


-- ============================================================
-- 32. ENRICHMENT-BASED ELIGIBILITY DETERMINATION
-- ============================================================

WITH eligibility AS (

    SELECT
        a.alert_id,
        a.risk_score,
        a.verdict,
        a.status,

        CASE
            WHEN a.verdict = 'false_positive'
                THEN 'exclude_from_investigation'

            WHEN a.risk_score >= 0.85
                THEN 'tier_3_required'

            WHEN a.risk_score >= 0.65
                THEN 'tier_2_required'

            ELSE 'tier_1_required'
        END AS assignment_requirement

    FROM alerts a

    WHERE a.status = 'triaged'
)

SELECT *
FROM eligibility
ORDER BY risk_score DESC;


-- ============================================================
-- 33. INVESTIGATION FAILURE CASE: INVALID TRANSITION
-- ============================================================

-- The following statement intentionally demonstrates an invalid
-- transition. It is not executed because it would abort the script.
--
-- UPDATE alerts
-- SET status = 'closed'
-- WHERE alert_id = 'ALT-5002';
--
-- An investigating alert cannot be closed directly.
-- It must first transition to resolved.


-- ============================================================
-- 34. TRANSACTIONAL PROCESSING EXAMPLE
-- ============================================================

-- Example of atomic enrichment for an additional alert.
-- The savepoint permits local rollback without losing the transaction.

SAVEPOINT enrichment_example;

DO $$
DECLARE
    v_alert_id VARCHAR := 'ALT-5004';
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM alerts
        WHERE alert_id = v_alert_id
          AND status IN ('new', 'enriching')
    ) THEN
        RAISE EXCEPTION
            'Alert is not eligible for enrichment';
    END IF;

    UPDATE alerts
    SET status = 'enriching'
    WHERE alert_id = v_alert_id
      AND status = 'new';

    -- The alert is already enriched and triaged in the sample workflow.
    -- This block intentionally verifies state rather than repeating
    -- enrichment or modifying an existing triage decision.

END;
$$;

RELEASE SAVEPOINT enrichment_example;


-- ============================================================
-- 35. AUDIT REVIEW
-- ============================================================

SELECT
    audit_id,
    alert_id,
    action,
    actor,
    previous_status,
    new_status,
    details,
    created_at
FROM alert_audit
ORDER BY created_at DESC, audit_id DESC;


-- ============================================================
-- 36. FINAL INTEGRITY CHECKS
-- ============================================================

DO $$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM alerts
        WHERE alert_id = 'ALT-5001'
          AND status = 'closed'
          AND verdict = 'true_positive'
    ) THEN
        RAISE EXCEPTION
            'Critical alert workflow assertion failed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM alerts
        WHERE alert_id = 'ALT-5003'
          AND verdict = 'false_positive'
    ) THEN
        RAISE EXCEPTION
            'False-positive assertion failed';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM alerts
        WHERE alert_id = 'ALT-5004'
          AND verdict = 'true_positive'
    ) THEN
        RAISE EXCEPTION
            'Database alert classification assertion failed';
    END IF;

    RAISE NOTICE
        'Alert triage database integrity assertions passed';

END;
$$;


COMMIT;
