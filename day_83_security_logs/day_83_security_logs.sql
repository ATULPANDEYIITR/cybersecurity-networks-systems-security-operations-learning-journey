/*
===============================================================================
SECURITY LOG MANAGEMENT AND THREAT DETECTION PLATFORM
PostgreSQL 15+

Domains:
    Windows security logs
    Linux authentication logs
    Firewall telemetry
    DNS telemetry
    Proxy logs
    Application telemetry

Capabilities:
    Normalized event storage
    Event-source management
    Event validation
    Duplicate prevention
    Authentication anomaly detection
    Network scanning detection
    DNS anomaly detection
    Proxy threat detection
    Security findings
    Incident lifecycle management
    Risk scoring
    Branch-independent governance of security alerts

Execution:
    psql -U postgres -d security_database -f security_logs.sql

The script recreates its own schema.
===============================================================================
*/

BEGIN;

DROP SCHEMA IF EXISTS security_logs CASCADE;

CREATE SCHEMA security_logs;

SET search_path TO security_logs, public;


-- ============================================================================
-- 1. DOMAIN TYPES
-- ============================================================================

CREATE TYPE telemetry_source AS ENUM (
    'windows',
    'linux',
    'firewall',
    'dns',
    'proxy',
    'authentication',
    'application'
);

CREATE TYPE security_event_type AS ENUM (
    'login_success',
    'login_failure',
    'privilege_change',
    'process_execution',
    'network_connection',
    'firewall_block',
    'firewall_allow',
    'dns_query',
    'http_request',
    'application_error',
    'file_access'
);

CREATE TYPE finding_severity AS ENUM (
    'INFO',
    'LOW',
    'MEDIUM',
    'HIGH',
    'CRITICAL'
);

CREATE TYPE incident_status AS ENUM (
    'OPEN',
    'INVESTIGATING',
    'CONTAINED',
    'RESOLVED',
    'CLOSED'
);

CREATE TYPE alert_status AS ENUM (
    'NEW',
    'ACKNOWLEDGED',
    'SUPPRESSED',
    'ESCALATED'
);


-- ============================================================================
-- 2. ORGANIZATIONAL AND TELEMETRY SOURCE MANAGEMENT
-- ============================================================================

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_name VARCHAR(150) NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE telemetry_sources (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    source_name VARCHAR(150) NOT NULL,

    source_type telemetry_source NOT NULL,

    hostname VARCHAR(255),

    environment VARCHAR(30) NOT NULL DEFAULT 'production'
        CHECK (
            environment IN (
                'production',
                'staging',
                'development',
                'testing'
            )
        ),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    last_seen_at TIMESTAMPTZ,

    UNIQUE (organization_id, source_name)
);


-- ============================================================================
-- 3. SECURITY EVENT STORAGE
-- ============================================================================

CREATE TABLE security_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    source_id BIGINT NOT NULL
        REFERENCES telemetry_sources(source_id),

    external_event_id VARCHAR(128) NOT NULL,

    event_timestamp TIMESTAMPTZ NOT NULL,

    ingestion_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    event_type security_event_type NOT NULL,

    source_ip INET,

    destination_ip INET,

    username VARCHAR(255),

    hostname VARCHAR(255),

    destination_port INTEGER
        CHECK (
            destination_port IS NULL OR
            destination_port BETWEEN 1 AND 65535
        ),

    protocol VARCHAR(20),

    action VARCHAR(50),

    resource TEXT,

    message TEXT,

    attributes JSONB NOT NULL DEFAULT '{}'::JSONB
        CHECK (
            jsonb_typeof(attributes) = 'object'
        ),

    UNIQUE (source_id, external_event_id),

    CHECK (
        source_ip IS NULL OR
        family(source_ip) IN (4, 6)
    ),

    CHECK (
        destination_ip IS NULL OR
        family(destination_ip) IN (4, 6)
    ),

    CHECK (
        message IS NULL OR
        length(message) <= 8192
    )
);


-- ============================================================================
-- 4. PERFORMANCE INDEXES
-- ============================================================================

CREATE INDEX idx_events_org_timestamp
    ON security_events (
        organization_id,
        event_timestamp DESC
    );

CREATE INDEX idx_events_type_timestamp
    ON security_events (
        event_type,
        event_timestamp DESC
    );

CREATE INDEX idx_events_source_ip_timestamp
    ON security_events (
        source_ip,
        event_timestamp DESC
    )
    WHERE source_ip IS NOT NULL;

CREATE INDEX idx_events_username_timestamp
    ON security_events (
        username,
        event_timestamp DESC
    )
    WHERE username IS NOT NULL;

CREATE INDEX idx_events_destination_port
    ON security_events (
        destination_port,
        event_timestamp DESC
    )
    WHERE destination_port IS NOT NULL;

CREATE INDEX idx_events_attributes_gin
    ON security_events
    USING GIN (attributes);

CREATE INDEX idx_events_ingestion_timestamp
    ON security_events (ingestion_timestamp DESC);


-- ============================================================================
-- 5. DETECTION RULE MANAGEMENT
-- ============================================================================

CREATE TABLE detection_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    rule_code VARCHAR(50) NOT NULL UNIQUE,

    rule_name VARCHAR(200) NOT NULL,

    description TEXT NOT NULL,

    severity finding_severity NOT NULL,

    threshold_value INTEGER
        CHECK (
            threshold_value IS NULL OR threshold_value > 0
        ),

    window_seconds INTEGER
        CHECK (
            window_seconds IS NULL OR window_seconds > 0
        ),

    confidence NUMERIC(4,3) NOT NULL
        CHECK (confidence BETWEEN 0 AND 1),

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


INSERT INTO detection_rules (
    rule_code,
    rule_name,
    description,
    severity,
    threshold_value,
    window_seconds,
    confidence
)
VALUES
(
    'AUTH-001',
    'Repeated authentication failures',
    'Multiple failed logins from one source and account.',
    'HIGH',
    5,
    300,
    0.950
),
(
    'NET-001',
    'Potential port scan',
    'One source contacts multiple destination ports.',
    'HIGH',
    10,
    300,
    0.900
),
(
    'DNS-001',
    'Suspicious DNS query',
    'DNS queries containing unusually long labels.',
    'MEDIUM',
    50,
    NULL,
    0.850
),
(
    'PROXY-001',
    'Executable download',
    'Proxy request accesses a suspicious executable extension.',
    'MEDIUM',
    NULL,
    NULL,
    0.800
),
(
    'AUTH-002',
    'Privilege change',
    'An account receives elevated privileges.',
    'MEDIUM',
    NULL,
    NULL,
    0.850
);


-- ============================================================================
-- 6. SECURITY FINDINGS
-- ============================================================================

CREATE TABLE security_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    rule_id BIGINT NOT NULL
        REFERENCES detection_rules(rule_id),

    entity VARCHAR(255) NOT NULL,

    severity finding_severity NOT NULL,

    confidence NUMERIC(4,3) NOT NULL
        CHECK (confidence BETWEEN 0 AND 1),

    risk_score INTEGER NOT NULL
        CHECK (risk_score BETWEEN 0 AND 100),

    description TEXT NOT NULL,

    evidence JSONB NOT NULL DEFAULT '{}'::JSONB
        CHECK (jsonb_typeof(evidence) = 'object'),

    first_seen TIMESTAMPTZ NOT NULL,

    last_seen TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (last_seen >= first_seen)
);

CREATE INDEX idx_findings_org_risk
    ON security_findings (
        organization_id,
        risk_score DESC,
        last_seen DESC
    );

CREATE INDEX idx_findings_rule
    ON security_findings (rule_id, last_seen DESC);

CREATE TABLE finding_events (
    finding_id BIGINT NOT NULL
        REFERENCES security_findings(finding_id)
        ON DELETE CASCADE,

    event_id BIGINT NOT NULL
        REFERENCES security_events(event_id),

    PRIMARY KEY (finding_id, event_id)
);


-- ============================================================================
-- 7. INCIDENT MANAGEMENT
-- ============================================================================

CREATE TABLE security_incidents (
    incident_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    finding_id BIGINT NOT NULL
        REFERENCES security_findings(finding_id),

    status incident_status NOT NULL DEFAULT 'OPEN',

    assigned_to VARCHAR(255),

    opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    resolved_at TIMESTAMPTZ,

    resolution_notes TEXT,

    CHECK (
        resolved_at IS NULL OR
        resolved_at >= opened_at
    )
);

CREATE TABLE incident_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,

    incident_id BIGINT NOT NULL
        REFERENCES security_incidents(incident_id)
        ON DELETE CASCADE,

    previous_status incident_status,

    new_status incident_status NOT NULL,

    changed_by VARCHAR(255) NOT NULL,

    change_reason TEXT,

    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_status
    ON security_incidents (status, opened_at DESC);


-- ============================================================================
-- 8. EVENT VALIDATION TRIGGER
-- ============================================================================

CREATE OR REPLACE FUNCTION validate_security_event()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    source_organization BIGINT;
    source_active BOOLEAN;
BEGIN
    SELECT organization_id, is_active
    INTO source_organization, source_active
    FROM telemetry_sources
    WHERE source_id = NEW.source_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Telemetry source % does not exist',
            NEW.source_id;
    END IF;

    IF source_organization <> NEW.organization_id THEN
        RAISE EXCEPTION
            'Event organization does not match telemetry source';
    END IF;

    IF NOT source_active THEN
        RAISE EXCEPTION
            'Inactive telemetry source cannot submit events';
    END IF;

    IF NEW.ingestion_timestamp < NEW.event_timestamp
       - INTERVAL '365 days' THEN
        RAISE EXCEPTION
            'Event timestamp exceeds allowed historical range';
    END IF;

    UPDATE telemetry_sources
    SET last_seen_at = GREATEST(
        COALESCE(last_seen_at, NEW.ingestion_timestamp),
        NEW.ingestion_timestamp
    )
    WHERE source_id = NEW.source_id;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_security_event
BEFORE INSERT ON security_events
FOR EACH ROW
EXECUTE FUNCTION validate_security_event();


-- ============================================================================
-- 9. INCIDENT STATE TRANSITION ENFORCEMENT
-- ============================================================================

CREATE OR REPLACE FUNCTION enforce_incident_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    allowed BOOLEAN := FALSE;
BEGIN
    IF NEW.status = OLD.status THEN
        RETURN NEW;
    END IF;

    allowed := CASE OLD.status
        WHEN 'OPEN' THEN
            NEW.status IN ('INVESTIGATING', 'CLOSED')

        WHEN 'INVESTIGATING' THEN
            NEW.status IN ('CONTAINED', 'RESOLVED')

        WHEN 'CONTAINED' THEN
            NEW.status IN ('INVESTIGATING', 'RESOLVED')

        WHEN 'RESOLVED' THEN
            NEW.status IN ('CLOSED', 'INVESTIGATING')

        WHEN 'CLOSED' THEN
            FALSE

        ELSE FALSE
    END;

    IF NOT allowed THEN
        RAISE EXCEPTION
            'Invalid incident transition: % -> %',
            OLD.status,
            NEW.status;
    END IF;

    NEW.updated_at := NOW();

    IF NEW.status IN ('RESOLVED', 'CLOSED') THEN
        NEW.resolved_at := NOW();
    ELSE
        NEW.resolved_at := NULL;
    END IF;

    INSERT INTO incident_history (
        incident_id,
        previous_status,
        new_status,
        changed_by,
        change_reason
    )
    VALUES (
        OLD.incident_id,
        OLD.status,
        NEW.status,
        COALESCE(
            current_setting('app.user', TRUE),
            SESSION_USER
        ),
        'Incident status transition'
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_incident_transition
BEFORE UPDATE OF status ON security_incidents
FOR EACH ROW
EXECUTE FUNCTION enforce_incident_transition();


-- ============================================================================
-- 10. RISK CALCULATION
-- ============================================================================

CREATE OR REPLACE FUNCTION calculate_risk_score(
    p_severity finding_severity,
    p_confidence NUMERIC
)
RETURNS INTEGER
LANGUAGE SQL
IMMUTABLE
STRICT
AS $$
    SELECT LEAST(
        100,
        ROUND(
            (
                CASE p_severity
                    WHEN 'INFO' THEN 0
                    WHEN 'LOW' THEN 10
                    WHEN 'MEDIUM' THEN 25
                    WHEN 'HIGH' THEN 45
                    WHEN 'CRITICAL' THEN 70
                END
            ) * p_confidence
        )::INTEGER
    );
$$;


-- ============================================================================
-- 11. BRUTE-FORCE DETECTION
-- ============================================================================

CREATE OR REPLACE FUNCTION detect_brute_force(
    p_organization_id BIGINT,
    p_threshold INTEGER DEFAULT 5,
    p_window_seconds INTEGER DEFAULT 300
)
RETURNS TABLE (
    source_ip INET,
    username VARCHAR,
    attempts BIGINT,
    first_attempt TIMESTAMPTZ,
    last_attempt TIMESTAMPTZ
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_threshold < 1 OR p_window_seconds < 1 THEN
        RAISE EXCEPTION 'Invalid detection parameters';
    END IF;

    RETURN QUERY
    SELECT
        e.source_ip,
        e.username,
        COUNT(*) AS attempts,
        MIN(e.event_timestamp),
        MAX(e.event_timestamp)
    FROM security_events e
    WHERE
        e.organization_id = p_organization_id
        AND e.event_type = 'login_failure'
        AND e.source_ip IS NOT NULL
        AND e.event_timestamp >= NOW()
            - make_interval(secs => p_window_seconds)
    GROUP BY
        e.source_ip,
        e.username
    HAVING COUNT(*) >= p_threshold;
END;
$$;


-- ============================================================================
-- 12. PORT SCAN DETECTION
-- ============================================================================

CREATE OR REPLACE FUNCTION detect_port_scans(
    p_organization_id BIGINT,
    p_threshold INTEGER DEFAULT 10,
    p_window_seconds INTEGER DEFAULT 300
)
RETURNS TABLE (
    source_ip INET,
    unique_ports BIGINT,
    connection_count BIGINT
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_threshold < 1 OR p_window_seconds < 1 THEN
        RAISE EXCEPTION 'Invalid detection parameters';
    END IF;

    RETURN QUERY
    SELECT
        e.source_ip,
        COUNT(DISTINCT e.destination_port),
        COUNT(*)
    FROM security_events e
    WHERE
        e.organization_id = p_organization_id
        AND e.event_type = 'network_connection'
        AND e.source_ip IS NOT NULL
        AND e.destination_port IS NOT NULL
        AND e.event_timestamp >= NOW()
            - make_interval(secs => p_window_seconds)
    GROUP BY e.source_ip
    HAVING COUNT(DISTINCT e.destination_port) >= p_threshold;
END;
$$;


-- ============================================================================
-- 13. DNS ANOMALY DETECTION
-- ============================================================================

CREATE OR REPLACE FUNCTION detect_dns_anomalies(
    p_organization_id BIGINT,
    p_label_threshold INTEGER DEFAULT 50
)
RETURNS TABLE (
    event_id BIGINT,
    source_ip INET,
    domain TEXT,
    longest_label INTEGER
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_label_threshold < 1 THEN
        RAISE EXCEPTION 'DNS label threshold must be positive';
    END IF;

    RETURN QUERY
    SELECT
        e.event_id,
        e.source_ip,
        e.attributes ->> 'query',
        (
            SELECT MAX(length(label))
            FROM unnest(
                string_to_array(
                    COALESCE(
                        e.attributes ->> 'query',
                        ''
                    ),
                    '.'
                )
            ) AS label
        )::INTEGER
    FROM security_events e
    WHERE
        e.organization_id = p_organization_id
        AND e.event_type = 'dns_query'
        AND EXISTS (
            SELECT 1
            FROM unnest(
                string_to_array(
                    COALESCE(
                        e.attributes ->> 'query',
                        ''
                    ),
                    '.'
                )
            ) AS label
            WHERE length(label) >= p_label_threshold
        );
END;
$$;


-- ============================================================================
-- 14. PROXY EXECUTABLE DOWNLOAD DETECTION
-- ============================================================================

CREATE OR REPLACE VIEW suspicious_proxy_requests AS
SELECT
    event_id,
    organization_id,
    source_ip,
    username,
    resource,
    event_timestamp
FROM security_events
WHERE
    event_type = 'http_request'
    AND LOWER(
        SPLIT_PART(
            SPLIT_PART(
                COALESCE(resource, ''),
                '?',
                1
            ),
            '#',
            1
        )
    ) ~ '\.(exe|dll|ps1|bat|scr|vbs)$';


-- ============================================================================
-- 15. PRIVILEGE CHANGE MONITORING
-- ============================================================================

CREATE OR REPLACE VIEW privilege_change_events AS
SELECT
    event_id,
    organization_id,
    username,
    hostname,
    source_ip,
    event_timestamp,
    attributes
FROM security_events
WHERE event_type = 'privilege_change';


-- ============================================================================
-- 16. ORGANIZATION SECURITY DASHBOARD
-- ============================================================================

CREATE OR REPLACE VIEW security_dashboard AS
SELECT
    o.organization_id,
    o.organization_name,

    COUNT(DISTINCT e.event_id) AS total_events,

    COUNT(DISTINCT e.event_id) FILTER (
        WHERE e.event_type = 'login_failure'
    ) AS failed_logins,

    COUNT(DISTINCT e.event_id) FILTER (
        WHERE e.event_type = 'firewall_block'
    ) AS firewall_blocks,

    COUNT(DISTINCT e.event_id) FILTER (
        WHERE e.event_type = 'dns_query'
    ) AS dns_queries,

    COUNT(DISTINCT f.finding_id) AS total_findings,

    COUNT(DISTINCT f.finding_id) FILTER (
        WHERE f.severity IN ('HIGH', 'CRITICAL')
    ) AS high_risk_findings,

    COUNT(DISTINCT i.incident_id) FILTER (
        WHERE i.status IN ('OPEN', 'INVESTIGATING')
    ) AS active_incidents

FROM organizations o

LEFT JOIN security_events e
    ON e.organization_id = o.organization_id

LEFT JOIN security_findings f
    ON f.organization_id = o.organization_id

LEFT JOIN security_incidents i
    ON i.finding_id = f.finding_id

GROUP BY
    o.organization_id,
    o.organization_name;


-- ============================================================================
-- 17. SAMPLE ORGANIZATION AND SOURCES
-- ============================================================================

INSERT INTO organizations (organization_name)
VALUES ('Enterprise Security Operations');

INSERT INTO telemetry_sources (
    organization_id,
    source_name,
    source_type,
    hostname
)
SELECT
    organization_id,
    source_name,
    source_type,
    hostname
FROM organizations
CROSS JOIN (
    VALUES
        (
            'windows-server-01',
            'windows'::telemetry_source,
            'WIN-SERVER-01'
        ),
        (
            'linux-server-01',
            'linux'::telemetry_source,
            'LINUX-SERVER-01'
        ),
        (
            'perimeter-firewall',
            'firewall'::telemetry_source,
            'FW-EDGE-01'
        ),
        (
            'enterprise-dns',
            'dns'::telemetry_source,
            'DNS-01'
        ),
        (
            'web-proxy',
            'proxy'::telemetry_source,
            'PROXY-01'
        ),
        (
            'identity-service',
            'authentication'::telemetry_source,
            'IAM-01'
        ),
        (
            'application-server',
            'application'::telemetry_source,
            'APP-01'
        )
) AS s(source_name, source_type, hostname);


-- ============================================================================
-- 18. SAMPLE SECURITY EVENTS
-- ============================================================================

INSERT INTO security_events (
    organization_id,
    source_id,
    external_event_id,
    event_timestamp,
    event_type,
    source_ip,
    username,
    hostname,
    message,
    attributes
)
SELECT
    o.organization_id,
    s.source_id,
    'auth-failure-' || n,
    NOW() - make_interval(secs => 60 - n * 5),
    'login_failure',
    '203.0.113.50'::INET,
    'administrator',
    'WIN-SERVER-01',
    'Authentication failed',
    jsonb_build_object(
        'logon_type',
        3,
        'authentication_method',
        'password'
    )
FROM organizations o
JOIN telemetry_sources s
    ON s.organization_id = o.organization_id
WHERE s.source_name = 'identity-service'
CROSS JOIN generate_series(1, 7) AS n;


INSERT INTO security_events (
    organization_id,
    source_id,
    external_event_id,
    event_timestamp,
    event_type,
    source_ip,
    destination_ip,
    destination_port,
    protocol,
    action,
    message
)
SELECT
    o.organization_id,
    s.source_id,
    'network-' || n,
    NOW() - make_interval(secs => 40 - n),
    'network_connection',
    '198.51.100.20'::INET,
    '10.0.0.10'::INET,
    1000 + n,
    'TCP',
    'ALLOW',
    'Outbound connection'
FROM organizations o
JOIN telemetry_sources s
    ON s.organization_id = o.organization_id
CROSS JOIN generate_series(1, 12) AS n
WHERE s.source_name = 'perimeter-firewall';


INSERT INTO security_events (
    organization_id,
    source_id,
    external_event_id,
    event_timestamp,
    event_type,
    source_ip,
    attributes,
    message
)
SELECT
    o.organization_id,
    s.source_id,
    'dns-001',
    NOW(),
    'dns_query',
    '10.0.0.15'::INET,
    jsonb_build_object(
        'query',
        repeat('a', 65) || '.example.com',
        'record_type',
        'TXT'
    ),
    'DNS query received'
FROM organizations o
JOIN telemetry_sources s
    ON s.organization_id = o.organization_id
WHERE s.source_name = 'enterprise-dns';


INSERT INTO security_events (
    organization_id,
    source_id,
    external_event_id,
    event_timestamp,
    event_type,
    source_ip,
    username,
    resource,
    message
)
SELECT
    o.organization_id,
    s.source_id,
    'proxy-001',
    NOW(),
    'http_request',
    '10.0.0.15'::INET,
    'employee01',
    'https://example.com/payload.exe',
    'Proxy request recorded'
FROM organizations o
JOIN telemetry_sources s
    ON s.organization_id = o.organization_id
WHERE s.source_name = 'web-proxy';


INSERT INTO security_events (
    organization_id,
    source_id,
    external_event_id,
    event_timestamp,
    event_type,
    username,
    hostname,
    attributes,
    message
)
SELECT
    o.organization_id,
    s.source_id,
    'priv-001',
    NOW(),
    'privilege_change',
    'administrator',
    'WIN-SERVER-01',
    jsonb_build_object(
        'privilege',
        'SeDebugPrivilege'
    ),
    'Special privileges assigned'
FROM organizations o
JOIN telemetry_sources s
    ON s.organization_id = o.organization_id
WHERE s.source_name = 'windows-server-01';


-- ============================================================================
-- 19. DETECTION RESULTS AND FINDING CREATION
-- ============================================================================

CREATE OR REPLACE PROCEDURE process_security_detections(
    p_organization_id BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    rule_record RECORD;
    detection RECORD;
    new_finding_id BIGINT;
    severity_weight INTEGER;
    calculated_risk INTEGER;
BEGIN
    -- Brute-force detection.
    SELECT * INTO rule_record
    FROM detection_rules
    WHERE rule_code = 'AUTH-001'
      AND enabled = TRUE;

    IF FOUND THEN
        FOR detection IN
            SELECT *
            FROM detect_brute_force(
                p_organization_id,
                rule_record.threshold_value,
                rule_record.window_seconds
            )
        LOOP
            calculated_risk := calculate_risk_score(
                rule_record.severity,
                rule_record.confidence
            );

            INSERT INTO security_findings (
                organization_id,
                rule_id,
                entity,
                severity,
                confidence,
                risk_score,
                description,
                evidence,
                first_seen,
                last_seen
            )
            VALUES (
                p_organization_id,
                rule_record.rule_id,
                detection.source_ip::TEXT,
                rule_record.severity,
                rule_record.confidence,
                calculated_risk,
                rule_record.description,
                jsonb_build_object(
                    'username', detection.username,
                    'attempts', detection.attempts
                ),
                detection.first_attempt,
                detection.last_attempt
            )
            RETURNING finding_id INTO new_finding_id;

            INSERT INTO finding_events (
                finding_id,
                event_id
            )
            SELECT
                new_finding_id,
                e.event_id
            FROM security_events e
            WHERE
                e.organization_id = p_organization_id
                AND e.event_type = 'login_failure'
                AND e.source_ip = detection.source_ip
                AND e.username IS NOT DISTINCT FROM
                    detection.username
                AND e.event_timestamp BETWEEN
                    detection.first_attempt
                    AND detection.last_attempt;
        END LOOP;
    END IF;

    -- Port scanning detection.
    SELECT * INTO rule_record
    FROM detection_rules
    WHERE rule_code = 'NET-001'
      AND enabled = TRUE;

    IF FOUND THEN
        FOR detection IN
            SELECT *
            FROM detect_port_scans(
                p_organization_id,
                rule_record.threshold_value,
                rule_record.window_seconds
            )
        LOOP
            INSERT INTO security_findings (
                organization_id,
                rule_id,
                entity,
                severity,
                confidence,
                risk_score,
                description,
                evidence,
                first_seen,
                last_seen
            )
            VALUES (
                p_organization_id,
                rule_record.rule_id,
                detection.source_ip::TEXT,
                rule_record.severity,
                rule_record.confidence,
                calculate_risk_score(
                    rule_record.severity,
                    rule_record.confidence
                ),
                rule_record.description,
                jsonb_build_object(
                    'unique_ports',
                    detection.unique_ports,
                    'connection_count',
                    detection.connection_count
                ),
                NOW() - make_interval(
                    secs => rule_record.window_seconds
                ),
                NOW()
            );
        END LOOP;
    END IF;

    -- DNS anomalies.
    SELECT * INTO rule_record
    FROM detection_rules
    WHERE rule_code = 'DNS-001'
      AND enabled = TRUE;

    IF FOUND THEN
        FOR detection IN
            SELECT *
            FROM detect_dns_anomalies(
                p_organization_id,
                rule_record.threshold_value
            )
        LOOP
            INSERT INTO security_findings (
                organization_id,
                rule_id,
                entity,
                severity,
                confidence,
                risk_score,
                description,
                evidence,
                first_seen,
                last_seen
            )
            VALUES (
                p_organization_id,
                rule_record.rule_id,
                COALESCE(
                    detection.source_ip::TEXT,
                    'unknown'
                ),
                rule_record.severity,
                rule_record.confidence,
                calculate_risk_score(
                    rule_record.severity,
                    rule_record.confidence
                ),
                rule_record.description,
                jsonb_build_object(
                    'domain',
                    detection.domain,
                    'longest_label',
                    detection.longest_label
                ),
                NOW(),
                NOW()
            )
            RETURNING finding_id INTO new_finding_id;

            INSERT INTO finding_events (
                finding_id,
                event_id
            )
            VALUES (
                new_finding_id,
                detection.event_id
            );
        END LOOP;
    END IF;

    -- Proxy executable downloads.
    SELECT * INTO rule_record
    FROM detection_rules
    WHERE rule_code = 'PROXY-001'
      AND enabled = TRUE;

    IF FOUND THEN
        INSERT INTO security_findings (
            organization_id,
            rule_id,
            entity,
            severity,
            confidence,
            risk_score,
            description,
            evidence,
            first_seen,
            last_seen
        )
        SELECT
            p_organization_id,
            rule_record.rule_id,
            COALESCE(source_ip::TEXT, 'unknown'),
            rule_record.severity,
            rule_record.confidence,
            calculate_risk_score(
                rule_record.severity,
                rule_record.confidence
            ),
            rule_record.description,
            jsonb_build_object(
                'resource',
                resource,
                'username',
                username
            ),
            event_timestamp,
            event_timestamp
        FROM suspicious_proxy_requests
        WHERE organization_id = p_organization_id;
    END IF;

    -- Privilege changes.
    SELECT * INTO rule_record
    FROM detection_rules
    WHERE rule_code = 'AUTH-002'
      AND enabled = TRUE;

    IF FOUND THEN
        INSERT INTO security_findings (
            organization_id,
            rule_id,
            entity,
            severity,
            confidence,
            risk_score,
            description,
            evidence,
            first_seen,
            last_seen
        )
        SELECT
            p_organization_id,
            rule_record.rule_id,
            COALESCE(username, 'unknown'),
            rule_record.severity,
            rule_record.confidence,
            calculate_risk_score(
                rule_record.severity,
                rule_record.confidence
            ),
            rule_record.description,
            jsonb_build_object(
                'hostname',
                hostname,
                'source_ip',
                source_ip::TEXT
            ),
            event_timestamp,
            event_timestamp
        FROM privilege_change_events
        WHERE organization_id = p_organization_id;
    END IF;

END;
$$;


-- ============================================================================
-- 20. PROCESS DETECTIONS
-- ============================================================================

CALL process_security_detections(1);


-- ============================================================================
-- 21. CREATE INCIDENTS FROM HIGH-RISK FINDINGS
-- ============================================================================

INSERT INTO security_incidents (finding_id)
SELECT finding_id
FROM security_findings
WHERE
    organization_id = 1
    AND risk_score >= 40;


-- ============================================================================
-- 22. REPORTING QUERIES
-- ============================================================================

-- A. Telemetry ingestion by source.

SELECT
    ts.source_name,
    ts.source_type,
    COUNT(e.event_id) AS total_events,
    MAX(e.event_timestamp) AS latest_event
FROM telemetry_sources ts
LEFT JOIN security_events e
    ON e.source_id = ts.source_id
GROUP BY
    ts.source_id,
    ts.source_name,
    ts.source_type
ORDER BY total_events DESC;


-- B. Authentication failures by source and account.

SELECT
    source_ip,
    username,
    COUNT(*) AS failed_attempts,
    MIN(event_timestamp) AS first_attempt,
    MAX(event_timestamp) AS last_attempt
FROM security_events
WHERE event_type = 'login_failure'
GROUP BY source_ip, username
ORDER BY failed_attempts DESC;


-- C. Firewall activity.

SELECT
    action,
    protocol,
    COUNT(*) AS connection_count,
    COUNT(DISTINCT source_ip) AS distinct_sources
FROM security_events
WHERE source_id IN (
    SELECT source_id
    FROM telemetry_sources
    WHERE source_type = 'firewall'
)
GROUP BY action, protocol
ORDER BY connection_count DESC;


-- D. DNS query distribution.

SELECT
    attributes ->> 'record_type' AS record_type,
    COUNT(*) AS query_count
FROM security_events
WHERE event_type = 'dns_query'
GROUP BY attributes ->> 'record_type'
ORDER BY query_count DESC;


-- E. Proxy executable downloads.

SELECT *
FROM suspicious_proxy_requests
ORDER BY event_timestamp DESC;


-- F. Security findings by severity.

SELECT
    severity,
    COUNT(*) AS findings,
    ROUND(AVG(risk_score), 2) AS average_risk,
    MAX(risk_score) AS maximum_risk
FROM security_findings
GROUP BY severity
ORDER BY MAX(risk_score) DESC;


-- G. Top risk entities.

SELECT
    entity,
    COUNT(*) AS finding_count,
    MAX(risk_score) AS highest_risk,
    SUM(risk_score) AS cumulative_risk
FROM security_findings
GROUP BY entity
ORDER BY cumulative_risk DESC
LIMIT 20;


-- H. Incident status report.

SELECT
    status,
    COUNT(*) AS incident_count
FROM security_incidents
GROUP BY status
ORDER BY incident_count DESC;


-- I. Cross-source event correlation.

WITH authentication AS (
    SELECT
        source_ip,
        username,
        COUNT(*) AS failed_logins,
        MIN(event_timestamp) AS first_seen,
        MAX(event_timestamp) AS last_seen
    FROM security_events
    WHERE event_type = 'login_failure'
    GROUP BY source_ip, username
),
network AS (
    SELECT
        source_ip,
        COUNT(DISTINCT destination_port) AS unique_ports
    FROM security_events
    WHERE event_type = 'network_connection'
    GROUP BY source_ip
)
SELECT
    a.source_ip,
    a.username,
    a.failed_logins,
    COALESCE(n.unique_ports, 0) AS unique_ports,
    CASE
        WHEN a.failed_logins >= 5
         AND COALESCE(n.unique_ports, 0) >= 10
            THEN 'HIGH_CORRELATION'
        WHEN a.failed_logins >= 5
            THEN 'AUTHENTICATION_ANOMALY'
        WHEN COALESCE(n.unique_ports, 0) >= 10
            THEN 'NETWORK_ANOMALY'
        ELSE 'NORMAL'
    END AS assessment
FROM authentication a
LEFT JOIN network n
    ON n.source_ip = a.source_ip
ORDER BY
    a.failed_logins DESC;


-- J. Organization dashboard.

SELECT *
FROM security_dashboard;


-- ============================================================================
-- 23. ELIGIBILITY AND VALIDATION QUERIES
-- ============================================================================

-- Events with missing usernames for authentication events.

SELECT
    event_id,
    event_timestamp,
    source_ip,
    event_type
FROM security_events
WHERE
    event_type IN (
        'login_failure',
        'login_success'
    )
    AND username IS NULL;


-- Events with unusually high ingestion delay.

SELECT
    event_id,
    event_type,
    event_timestamp,
    ingestion_timestamp,
    ingestion_timestamp - event_timestamp AS ingestion_delay
FROM security_events
WHERE
    ingestion_timestamp - event_timestamp >
    INTERVAL '5 minutes'
ORDER BY ingestion_delay DESC;


-- Active detection rules.

SELECT
    rule_code,
    rule_name,
    severity,
    threshold_value,
    window_seconds
FROM detection_rules
WHERE enabled = TRUE
ORDER BY rule_code;


-- ============================================================================
-- 24. INCIDENT WORKFLOW EXAMPLE
-- ============================================================================

-- Move the first open incident into investigation.

UPDATE security_incidents
SET status = 'INVESTIGATING',
    assigned_to = 'soc-analyst-01'
WHERE incident_id = (
    SELECT incident_id
    FROM security_incidents
    WHERE status = 'OPEN'
    ORDER BY opened_at
    LIMIT 1
);


-- Review incident transition history.

SELECT
    incident_id,
    previous_status,
    new_status,
    changed_by,
    change_reason,
    changed_at
FROM incident_history
ORDER BY changed_at DESC;


-- ============================================================================
-- 25. ANALYTICS AND DATA RETENTION
-- ============================================================================

-- Query recent event volume by hourly interval.

SELECT
    date_trunc('hour', event_timestamp) AS event_hour,
    source_id,
    COUNT(*) AS event_count
FROM security_events
WHERE event_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY
    date_trunc('hour', event_timestamp),
    source_id
ORDER BY event_hour DESC;


-- Data-retention eligibility.
-- This SELECT does not delete data.

SELECT
    COUNT(*) AS eligible_for_archival
FROM security_events
WHERE event_timestamp < NOW() - INTERVAL '90 days';


-- ============================================================================
-- 26. EXECUTION VALIDATION
-- ============================================================================

DO $$
DECLARE
    event_count BIGINT;
    finding_count BIGINT;
BEGIN
    SELECT COUNT(*) INTO event_count
    FROM security_events;

    SELECT COUNT(*) INTO finding_count
    FROM security_findings;

    IF event_count = 0 THEN
        RAISE EXCEPTION 'Sample event ingestion failed';
    END IF;

    IF finding_count = 0 THEN
        RAISE EXCEPTION 'Detection processing produced no findings';
    END IF;

    RAISE NOTICE
        'Security log database initialized: % events, % findings',
        event_count,
        finding_count;
END;
$$;


COMMIT;
