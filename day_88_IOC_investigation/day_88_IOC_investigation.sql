/*
===============================================================================
IOC INVESTIGATION AND THREAT INTELLIGENCE MANAGEMENT
PostgreSQL 15+

Functional areas:
1. IOC registration and normalization
2. IP, domain, hash, URL, filename and registry indicators
3. Threat intelligence provenance
4. Security event ingestion
5. IOC-to-event correlation
6. Allowlist management
7. Indicator expiration and lifecycle
8. Confidence and severity evaluation
9. Investigation case management
10. Analyst assignments
11. Investigation notes
12. Audit records
13. Threat reporting and aggregation
14. Transaction-safe correlation

Sample IP ranges use RFC 5737 documentation addresses.
Sample domains use reserved example domains.
===============================================================================
*/

BEGIN;

CREATE SCHEMA IF NOT EXISTS threat_intel;

SET search_path TO threat_intel, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------------
-- DOMAIN TYPES
-- ---------------------------------------------------------------------------

CREATE TYPE ioc_type AS ENUM (
    'ip',
    'domain',
    'hash',
    'url',
    'filename',
    'registry'
);

CREATE TYPE threat_severity AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE case_status AS ENUM (
    'open',
    'investigating',
    'contained',
    'closed'
);

CREATE TYPE event_source AS ENUM (
    'firewall',
    'dns',
    'endpoint',
    'proxy',
    'filesystem',
    'registry'
);

CREATE TYPE case_action AS ENUM (
    'create',
    'assign',
    'investigate',
    'contain',
    'close',
    'reopen_investigation'
);

-- ---------------------------------------------------------------------------
-- SOURCE ORGANIZATIONS AND THREAT INTELLIGENCE FEEDS
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_name VARCHAR(200) NOT NULL UNIQUE,
    organization_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (length(trim(organization_name)) > 0)
);

CREATE TABLE threat_feeds (
    feed_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    feed_name VARCHAR(200) NOT NULL,
    feed_reference VARCHAR(200) NOT NULL UNIQUE,
    reliability_score SMALLINT NOT NULL DEFAULT 50,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (reliability_score BETWEEN 0 AND 100),
    UNIQUE (organization_id, feed_name)
);

-- ---------------------------------------------------------------------------
-- USERS AND ANALYST IDENTITIES
-- ---------------------------------------------------------------------------

CREATE TABLE analysts (
    analyst_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    full_name VARCHAR(200) NOT NULL,
    role_name VARCHAR(50) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (role_name IN (
        'analyst',
        'senior_analyst',
        'incident_responder',
        'administrator'
    ))
);

-- ---------------------------------------------------------------------------
-- IOC NORMALIZATION
-- ---------------------------------------------------------------------------

CREATE FUNCTION normalize_ioc(
    p_type ioc_type,
    p_value TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    v TEXT;
BEGIN
    v := btrim(p_value);

    IF length(v) = 0 OR length(v) > 4096 THEN
        RAISE EXCEPTION 'Invalid IOC length';
    END IF;

    CASE p_type

        WHEN 'ip' THEN
            BEGIN
                RETURN host(v::inet);
            EXCEPTION WHEN OTHERS THEN
                RAISE EXCEPTION 'Invalid IP address: %', v;
            END;

        WHEN 'domain' THEN
            v := lower(regexp_replace(v, '\.$', ''));

            IF length(v) > 253
               OR v !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'
               OR v !~ '\.'
               OR v ~ '\.\.'
            THEN
                RAISE EXCEPTION 'Invalid domain: %', v;
            END IF;

            IF EXISTS (
                SELECT 1
                FROM regexp_split_to_table(v, '\.') AS labels(label)
                WHERE length(label) > 63
                   OR label !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
            ) THEN
                RAISE EXCEPTION 'Invalid domain label: %', v;
            END IF;

            RETURN v;

        WHEN 'hash' THEN
            v := lower(v);

            IF v !~ '^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$' THEN
                RAISE EXCEPTION 'Unsupported cryptographic hash';
            END IF;

            RETURN v;

        WHEN 'url' THEN
            IF v !~* '^https?://' THEN
                RAISE EXCEPTION 'Only HTTP and HTTPS URLs are supported';
            END IF;

            IF v ~ '@' THEN
                RAISE EXCEPTION 'Credential-bearing URL rejected';
            END IF;

            RETURN regexp_replace(
                v,
                '^(HTTP|HTTPS)://',
                lower(substring(v FROM '^[^:]+')) || '://',
                'i'
            );

        WHEN 'filename' THEN
            IF length(v) > 255
               OR v ~ '[/\\\r\n]'
            THEN
                RAISE EXCEPTION 'Invalid filename';
            END IF;

            RETURN lower(v);

        WHEN 'registry' THEN
            v := regexp_replace(
                v,
                '^HKEY_LOCAL_MACHINE',
                'HKLM',
                'i'
            );

            v := regexp_replace(
                v,
                '^HKEY_CURRENT_USER',
                'HKCU',
                'i'
            );

            v := regexp_replace(
                v,
                '^HKEY_CLASSES_ROOT',
                'HKCR',
                'i'
            );

            v := regexp_replace(
                v,
                '^HKEY_USERS',
                'HKU',
                'i'
            );

            IF v !~* '^HK(LM|CU|CR|U)\\' THEN
                RAISE EXCEPTION 'Unsupported registry root';
            END IF;

            RETURN lower(v);

    END CASE;

    RAISE EXCEPTION 'Unsupported IOC type';
END;
$$;

-- ---------------------------------------------------------------------------
-- IOC REGISTRY
-- ---------------------------------------------------------------------------

CREATE TABLE indicators (
    indicator_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    indicator_type ioc_type NOT NULL,
    indicator_value TEXT NOT NULL,

    source_feed_id BIGINT NOT NULL
        REFERENCES threat_feeds(feed_id),

    confidence SMALLINT NOT NULL,
    severity threat_severity NOT NULL,

    description TEXT NOT NULL DEFAULT '',
    tags TEXT[] NOT NULL DEFAULT '{}',

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    normalized_value TEXT GENERATED ALWAYS AS (
        normalize_ioc(indicator_type, indicator_value)
    ) STORED,

    CHECK (confidence BETWEEN 0 AND 100),
    CHECK (
        expires_at IS NULL OR expires_at > created_at
    ),

    UNIQUE (indicator_type, normalized_value)
);

CREATE INDEX idx_indicators_active
    ON indicators(active, indicator_type);

CREATE INDEX idx_indicators_severity
    ON indicators(severity, confidence DESC);

CREATE INDEX idx_indicators_expiry
    ON indicators(expires_at)
    WHERE active = TRUE AND expires_at IS NOT NULL;

CREATE INDEX idx_indicators_tags
    ON indicators USING GIN(tags);

-- ---------------------------------------------------------------------------
-- ALLOWLIST
-- ---------------------------------------------------------------------------

CREATE TABLE indicator_allowlist (
    allowlist_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    indicator_type ioc_type NOT NULL,
    indicator_value TEXT NOT NULL,

    normalized_value TEXT GENERATED ALWAYS AS (
        normalize_ioc(indicator_type, indicator_value)
    ) STORED,

    justification TEXT NOT NULL,
    approved_by BIGINT NOT NULL REFERENCES analysts(analyst_id),

    expires_at TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (length(trim(justification)) > 0),

    UNIQUE(indicator_type, normalized_value)
);

CREATE INDEX idx_allowlist_active
    ON indicator_allowlist(indicator_type, normalized_value)
    WHERE active = TRUE;

-- ---------------------------------------------------------------------------
-- SECURITY EVENTS
-- ---------------------------------------------------------------------------

CREATE TABLE security_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    external_event_id VARCHAR(150) NOT NULL UNIQUE,

    source event_source NOT NULL,
    indicator_type ioc_type NOT NULL,
    observed_value TEXT NOT NULL,

    normalized_value TEXT GENERATED ALWAYS AS (
        normalize_ioc(indicator_type, observed_value)
    ) STORED,

    asset_name VARCHAR(200) NOT NULL,
    tenant_id VARCHAR(100) NOT NULL,

    event_timestamp TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    event_metadata JSONB NOT NULL DEFAULT '{}'::JSONB,

    CHECK (length(trim(asset_name)) > 0),
    CHECK (jsonb_typeof(event_metadata) = 'object')
);

CREATE INDEX idx_events_lookup
    ON security_events(
        indicator_type,
        normalized_value,
        event_timestamp DESC
    );

CREATE INDEX idx_events_asset
    ON security_events(asset_name, event_timestamp DESC);

CREATE INDEX idx_events_tenant
    ON security_events(tenant_id, event_timestamp DESC);

CREATE INDEX idx_events_metadata
    ON security_events USING GIN(event_metadata);

-- ---------------------------------------------------------------------------
-- INVESTIGATION CASES
-- ---------------------------------------------------------------------------

CREATE TABLE investigation_cases (
    case_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    case_reference VARCHAR(50) NOT NULL UNIQUE,
    title VARCHAR(250) NOT NULL,
    description TEXT NOT NULL DEFAULT '',

    status case_status NOT NULL DEFAULT 'open',
    priority SMALLINT NOT NULL DEFAULT 50,

    tenant_id VARCHAR(100) NOT NULL,

    assigned_analyst_id BIGINT REFERENCES analysts(analyst_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at TIMESTAMPTZ,

    CHECK (priority BETWEEN 0 AND 100),
    CHECK (length(trim(title)) > 0),
    CHECK (
        (status = 'closed' AND closed_at IS NOT NULL)
        OR
        (status <> 'closed' AND closed_at IS NULL)
    )
);

CREATE INDEX idx_cases_status_priority
    ON investigation_cases(status, priority DESC);

CREATE INDEX idx_cases_assignee
    ON investigation_cases(assigned_analyst_id, status);

CREATE INDEX idx_cases_tenant
    ON investigation_cases(tenant_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- MATCHED INDICATORS
-- ---------------------------------------------------------------------------

CREATE TABLE event_indicator_matches (
    match_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_id UUID NOT NULL
        REFERENCES security_events(event_id),

    indicator_id UUID NOT NULL
        REFERENCES indicators(indicator_id),

    case_id UUID
        REFERENCES investigation_cases(case_id),

    confidence SMALLINT NOT NULL,
    severity threat_severity NOT NULL,

    matched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (confidence BETWEEN 0 AND 100),

    UNIQUE(event_id, indicator_id)
);

CREATE INDEX idx_matches_case
    ON event_indicator_matches(case_id, matched_at DESC);

CREATE INDEX idx_matches_indicator
    ON event_indicator_matches(indicator_id, matched_at DESC);

-- ---------------------------------------------------------------------------
-- INVESTIGATION NOTES AND CASE ACTIONS
-- ---------------------------------------------------------------------------

CREATE TABLE investigation_notes (
    note_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    case_id UUID NOT NULL
        REFERENCES investigation_cases(case_id),

    analyst_id BIGINT NOT NULL
        REFERENCES analysts(analyst_id),

    note_content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (length(trim(note_content)) > 0)
);

CREATE INDEX idx_notes_case
    ON investigation_notes(case_id, created_at DESC);

CREATE TABLE case_actions (
    action_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    case_id UUID NOT NULL
        REFERENCES investigation_cases(case_id),

    analyst_id BIGINT NOT NULL
        REFERENCES analysts(analyst_id),

    action case_action NOT NULL,
    previous_status case_status,
    new_status case_status,

    action_details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_actions_case
    ON case_actions(case_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- AUDIT LOG
-- ---------------------------------------------------------------------------

CREATE TABLE audit_log (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    actor VARCHAR(150) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(150) NOT NULL,

    details JSONB NOT NULL DEFAULT '{}'::JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_resource
    ON audit_log(resource_type, resource_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- AUDIT TRIGGER
-- ---------------------------------------------------------------------------

CREATE FUNCTION audit_indicator_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO audit_log (
        actor,
        action,
        resource_type,
        resource_id,
        details
    )
    VALUES (
        current_user,
        TG_OP,
        'indicator',
        COALESCE(NEW.indicator_id, OLD.indicator_id)::TEXT,
        jsonb_build_object(
            'indicator_type',
            COALESCE(NEW.indicator_type, OLD.indicator_type),
            'severity',
            COALESCE(NEW.severity, OLD.severity),
            'operation',
            TG_OP
        )
    );

    RETURN COALESCE(NEW, OLD);
END;
$$;

CREATE TRIGGER trg_indicator_audit
AFTER INSERT OR UPDATE OR DELETE
ON indicators
FOR EACH ROW
EXECUTE FUNCTION audit_indicator_change();

-- ---------------------------------------------------------------------------
-- CASE STATE TRANSITION ENFORCEMENT
-- ---------------------------------------------------------------------------

CREATE FUNCTION enforce_case_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status <> OLD.status THEN

        IF NOT (
            (OLD.status = 'open'
                AND NEW.status IN ('investigating', 'closed'))
            OR
            (OLD.status = 'investigating'
                AND NEW.status IN ('contained', 'closed'))
            OR
            (OLD.status = 'contained'
                AND NEW.status IN ('investigating', 'closed'))
        ) THEN
            RAISE EXCEPTION
                'Invalid case transition: % -> %',
                OLD.status,
                NEW.status;
        END IF;

        NEW.updated_at := NOW();

        IF NEW.status = 'closed' THEN
            NEW.closed_at := NOW();
        ELSE
            NEW.closed_at := NULL;
        END IF;

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_case_transition
BEFORE UPDATE OF status
ON investigation_cases
FOR EACH ROW
EXECUTE FUNCTION enforce_case_transition();

-- ---------------------------------------------------------------------------
-- CASE ELIGIBILITY FUNCTION
-- ---------------------------------------------------------------------------

CREATE FUNCTION evaluate_case_priority(
    p_case_id UUID
)
RETURNS SMALLINT
LANGUAGE sql
STABLE
AS $$
    SELECT COALESCE(
        MAX(
            ROUND(
                m.confidence::NUMERIC *
                CASE m.severity
                    WHEN 'low' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'high' THEN 3
                    WHEN 'critical' THEN 4
                END / 4
            )
        ),
        0
    )::SMALLINT
    FROM event_indicator_matches m
    WHERE m.case_id = p_case_id;
$$;

-- ---------------------------------------------------------------------------
-- IOC CORRELATION FUNCTION
-- ---------------------------------------------------------------------------

CREATE FUNCTION correlate_event(
    p_event_id UUID,
    p_case_id UUID DEFAULT NULL
)
RETURNS TABLE (
    matched_indicator UUID,
    matched_type ioc_type,
    matched_value TEXT,
    matched_severity threat_severity,
    matched_confidence SMALLINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_event security_events%ROWTYPE;
BEGIN
    SELECT *
    INTO v_event
    FROM security_events
    WHERE event_id = p_event_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Security event not found';
    END IF;

    IF p_case_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM investigation_cases
        WHERE case_id = p_case_id
          AND tenant_id = v_event.tenant_id
          AND status <> 'closed'
    ) THEN
        RAISE EXCEPTION
            'Case is missing, closed or belongs to another tenant';
    END IF;

    RETURN QUERY
    WITH candidates AS (
        SELECT
            i.indicator_id,
            i.indicator_type,
            i.normalized_value,
            i.severity,
            i.confidence
        FROM indicators i
        WHERE i.indicator_type = v_event.indicator_type
          AND i.normalized_value = v_event.normalized_value
          AND i.active = TRUE
          AND (
              i.expires_at IS NULL OR i.expires_at > NOW()
          )
          AND NOT EXISTS (
              SELECT 1
              FROM indicator_allowlist a
              WHERE a.indicator_type = i.indicator_type
                AND a.normalized_value = i.normalized_value
                AND a.active = TRUE
                AND (
                    a.expires_at IS NULL OR a.expires_at > NOW()
                )
          )
    ),
    inserted AS (
        INSERT INTO event_indicator_matches (
            event_id,
            indicator_id,
            case_id,
            confidence,
            severity
        )
        SELECT
            p_event_id,
            c.indicator_id,
            p_case_id,
            c.confidence,
            c.severity
        FROM candidates c
        ON CONFLICT (event_id, indicator_id)
        DO UPDATE SET
            case_id = COALESCE(
                event_indicator_matches.case_id,
                EXCLUDED.case_id
            )
        RETURNING indicator_id
    )
    SELECT
        c.indicator_id,
        c.indicator_type,
        c.normalized_value,
        c.severity,
        c.confidence
    FROM candidates c
    JOIN inserted x USING (indicator_id);
END;
$$;

-- ---------------------------------------------------------------------------
-- CASE CREATION PROCEDURE
-- ---------------------------------------------------------------------------

CREATE PROCEDURE create_investigation_case(
    p_reference VARCHAR(50),
    p_title VARCHAR(250),
    p_tenant VARCHAR(100),
    p_analyst BIGINT,
    p_case_id UUID
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_title IS NULL OR length(trim(p_title)) = 0 THEN
        RAISE EXCEPTION 'Case title is required';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM analysts
        WHERE analyst_id = p_analyst
          AND active = TRUE
    ) THEN
        RAISE EXCEPTION 'Active analyst required';
    END IF;

    INSERT INTO investigation_cases (
        case_id,
        case_reference,
        title,
        tenant_id,
        assigned_analyst_id
    )
    VALUES (
        p_case_id,
        p_reference,
        p_title,
        p_tenant,
        p_analyst
    );

    INSERT INTO case_actions (
        case_id,
        analyst_id,
        action,
        new_status
    )
    VALUES (
        p_case_id,
        p_analyst,
        'create',
        'open'
    );
END;
$$;

-- ---------------------------------------------------------------------------
-- VIEWS
-- ---------------------------------------------------------------------------

CREATE VIEW active_threat_indicators AS
SELECT
    i.indicator_id,
    i.indicator_type,
    i.normalized_value,
    i.confidence,
    i.severity,
    i.tags,
    f.feed_name,
    f.reliability_score,
    i.created_at,
    i.expires_at
FROM indicators i
JOIN threat_feeds f ON f.feed_id = i.source_feed_id
WHERE i.active = TRUE
  AND f.enabled = TRUE
  AND (i.expires_at IS NULL OR i.expires_at > NOW());

CREATE VIEW investigation_dashboard AS
SELECT
    c.case_id,
    c.case_reference,
    c.title,
    c.status,
    c.priority,
    c.tenant_id,
    a.username AS assigned_analyst,
    COUNT(DISTINCT m.match_id) AS matched_events,
    COUNT(DISTINCT m.indicator_id) AS distinct_indicators,
    c.created_at,
    c.updated_at
FROM investigation_cases c
LEFT JOIN analysts a
    ON a.analyst_id = c.assigned_analyst_id
LEFT JOIN event_indicator_matches m
    ON m.case_id = c.case_id
GROUP BY
    c.case_id,
    c.case_reference,
    c.title,
    c.status,
    c.priority,
    c.tenant_id,
    a.username,
    c.created_at,
    c.updated_at;

-- ---------------------------------------------------------------------------
-- SAMPLE DATA
-- ---------------------------------------------------------------------------

INSERT INTO organizations (
    organization_name,
    organization_type
)
VALUES
    ('Internal Security Operations', 'internal'),
    ('Threat Intelligence Provider A', 'external'),
    ('Threat Intelligence Provider B', 'external');

INSERT INTO threat_feeds (
    organization_id,
    feed_name,
    feed_reference,
    reliability_score
)
SELECT
    organization_id,
    'Primary Network Feed',
    'NETWORK-FEED-001',
    95
FROM organizations
WHERE organization_name = 'Threat Intelligence Provider A';

INSERT INTO threat_feeds (
    organization_id,
    feed_name,
    feed_reference,
    reliability_score
)
SELECT
    organization_id,
    'Endpoint Malware Feed',
    'ENDPOINT-FEED-001',
    90
FROM organizations
WHERE organization_name = 'Threat Intelligence Provider B';

INSERT INTO threat_feeds (
    organization_id,
    feed_name,
    feed_reference,
    reliability_score
)
SELECT
    organization_id,
    'DNS Intelligence Feed',
    'DNS-FEED-001',
    85
FROM organizations
WHERE organization_name = 'Internal Security Operations';

INSERT INTO analysts (
    username,
    full_name,
    role_name
)
VALUES
    ('analyst01', 'Primary SOC Analyst', 'analyst'),
    ('senior01', 'Senior Threat Analyst', 'senior_analyst'),
    ('admin01', 'Security Administrator', 'administrator'),
    ('responder01', 'Incident Responder', 'incident_responder');

-- ---------------------------------------------------------------------------
-- SAMPLE IOC REGISTRATION
-- ---------------------------------------------------------------------------

INSERT INTO indicators (
    indicator_type,
    indicator_value,
    source_feed_id,
    confidence,
    severity,
    description,
    tags
)
VALUES
(
    'ip',
    '203.0.113.45',
    (SELECT feed_id FROM threat_feeds
     WHERE feed_reference = 'NETWORK-FEED-001'),
    95,
    'critical',
    'Suspicious command and control endpoint',
    ARRAY['c2', 'network']
),
(
    'domain',
    'malware.example',
    (SELECT feed_id FROM threat_feeds
     WHERE feed_reference = 'DNS-FEED-001'),
    90,
    'high',
    'Suspicious domain',
    ARRAY['dns', 'malware']
),
(
    'hash',
    repeat('a', 64),
    (SELECT feed_id FROM threat_feeds
     WHERE feed_reference = 'ENDPOINT-FEED-001'),
    99,
    'critical',
    'Malicious executable SHA-256',
    ARRAY['malware', 'sha256']
),
(
    'url',
    'https://malware.example/payload',
    (SELECT feed_id FROM threat_feeds
     WHERE feed_reference = 'NETWORK-FEED-001'),
    92,
    'high',
    'Suspicious payload URL',
    ARRAY['payload']
),
(
    'filename',
    'suspicious.exe',
    (SELECT feed_id FROM threat_feeds
     WHERE feed_reference = 'ENDPOINT-FEED-001'),
    80,
    'medium',
    'Suspicious executable filename',
    ARRAY['executable']
),
(
    'registry',
    'HKEY_LOCAL_MACHINE\Software\BadActor\Persistence',
    (SELECT feed_id FROM threat_feeds
     WHERE feed_reference = 'ENDPOINT-FEED-001'),
    90,
    'high',
    'Suspicious persistence registry key',
    ARRAY['persistence', 'registry']
);

-- ---------------------------------------------------------------------------
-- ALLOWLIST DATA
-- ---------------------------------------------------------------------------

INSERT INTO indicator_allowlist (
    indicator_type,
    indicator_value,
    justification,
    approved_by
)
VALUES (
    'ip',
    '192.0.2.10',
    'Approved internal network test address',
    (SELECT analyst_id FROM analysts WHERE username = 'admin01')
);

-- ---------------------------------------------------------------------------
-- SAMPLE SECURITY EVENTS
-- ---------------------------------------------------------------------------

INSERT INTO security_events (
    external_event_id,
    source,
    indicator_type,
    observed_value,
    asset_name,
    tenant_id,
    event_timestamp,
    event_metadata
)
VALUES
(
    'EVT-001',
    'firewall',
    'ip',
    '203.0.113.45',
    'WORKSTATION-01',
    'TENANT-001',
    NOW(),
    '{"action":"outbound_connection","port":443}'
),
(
    'EVT-002',
    'dns',
    'domain',
    'MALWARE.EXAMPLE.',
    'WORKSTATION-02',
    'TENANT-001',
    NOW(),
    '{"query_type":"A","response":"203.0.113.45"}'
),
(
    'EVT-003',
    'endpoint',
    'hash',
    repeat('a', 64),
    'SERVER-01',
    'TENANT-001',
    NOW(),
    '{"process":"unknown.exe","detection":"file_hash"}'
),
(
    'EVT-004',
    'proxy',
    'url',
    'https://malware.example/payload',
    'WORKSTATION-03',
    'TENANT-001',
    NOW(),
    '{"method":"GET","response_code":200}'
),
(
    'EVT-005',
    'filesystem',
    'filename',
    'suspicious.exe',
    'WORKSTATION-04',
    'TENANT-001',
    NOW(),
    '{"directory":"C:\\Temp","operation":"created"}'
),
(
    'EVT-006',
    'registry',
    'registry',
    'HKLM\Software\BadActor\Persistence',
    'WORKSTATION-05',
    'TENANT-001',
    NOW(),
    '{"operation":"registry_set","hive":"HKLM"}'
),
(
    'EVT-007',
    'firewall',
    'ip',
    '192.0.2.10',
    'WORKSTATION-06',
    'TENANT-001',
    NOW(),
    '{"action":"approved_test_connection"}'
),
(
    'EVT-008',
    'dns',
    'domain',
    'normal.example',
    'WORKSTATION-07',
    'TENANT-001',
    NOW(),
    '{"query_type":"A"}'
);

-- ---------------------------------------------------------------------------
-- CASE CREATION
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    v_case UUID := gen_random_uuid();
    v_analyst BIGINT;
BEGIN
    SELECT analyst_id
    INTO v_analyst
    FROM analysts
    WHERE username = 'analyst01';

    CALL create_investigation_case(
        'CASE-2026-001',
        'Suspicious endpoint and network activity',
        'TENANT-001',
        v_analyst,
        v_case
    );
END;
$$;

-- ---------------------------------------------------------------------------
-- TRANSACTIONAL EVENT CORRELATION
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    v_case UUID;
    v_event RECORD;
BEGIN
    SELECT case_id
    INTO v_case
    FROM investigation_cases
    WHERE case_reference = 'CASE-2026-001';

    FOR v_event IN
        SELECT event_id
        FROM security_events
        WHERE tenant_id = 'TENANT-001'
        ORDER BY event_timestamp
    LOOP
        PERFORM *
        FROM correlate_event(v_event.event_id, v_case);
    END LOOP;

    UPDATE investigation_cases
    SET
        priority = evaluate_case_priority(v_case),
        status = 'investigating'
    WHERE case_id = v_case
      AND status = 'open';

    INSERT INTO case_actions (
        case_id,
        analyst_id,
        action,
        previous_status,
        new_status,
        action_details
    )
    SELECT
        v_case,
        analyst_id,
        'investigate',
        'open',
        'investigating',
        '{"reason":"IOC correlation completed"}'
    FROM analysts
    WHERE username = 'analyst01';
END;
$$;

-- ---------------------------------------------------------------------------
-- INVESTIGATION NOTE
-- ---------------------------------------------------------------------------

INSERT INTO investigation_notes (
    case_id,
    analyst_id,
    note_content
)
SELECT
    c.case_id,
    a.analyst_id,
    'Initial IOC correlation completed. Endpoint triage and network review required.'
FROM investigation_cases c
CROSS JOIN analysts a
WHERE c.case_reference = 'CASE-2026-001'
  AND a.username = 'analyst01';

-- ---------------------------------------------------------------------------
-- RETRIEVAL: ACTIVE IOC INVENTORY
-- ---------------------------------------------------------------------------

SELECT
    indicator_type,
    normalized_value,
    confidence,
    severity,
    feed_name
FROM active_threat_indicators
ORDER BY confidence DESC, severity DESC;

-- ---------------------------------------------------------------------------
-- RETRIEVAL: MATCHED EVENTS
-- ---------------------------------------------------------------------------

SELECT
    e.external_event_id,
    e.source,
    e.asset_name,
    i.indicator_type,
    i.normalized_value,
    m.confidence,
    m.severity,
    m.matched_at
FROM event_indicator_matches m
JOIN security_events e
    ON e.event_id = m.event_id
JOIN indicators i
    ON i.indicator_id = m.indicator_id
ORDER BY m.matched_at DESC;

-- ---------------------------------------------------------------------------
-- VALIDATION: INVALID HASH EXAMPLE
-- Run separately because the exception is expected.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    BEGIN
        PERFORM normalize_ioc('hash', 'INVALID-HASH');

        RAISE EXCEPTION
            'Validation failure: invalid hash was accepted';

    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE
                'Expected validation rejection: %',
                SQLERRM;
    END;
END;
$$;

-- ---------------------------------------------------------------------------
-- AGGREGATION: IOC DISTRIBUTION
-- ---------------------------------------------------------------------------

SELECT
    indicator_type,
    severity,
    COUNT(*) AS indicator_count,
    ROUND(AVG(confidence), 2) AS average_confidence
FROM indicators
GROUP BY indicator_type, severity
ORDER BY indicator_type, severity;

-- ---------------------------------------------------------------------------
-- AGGREGATION: EVENT SOURCE DISTRIBUTION
-- ---------------------------------------------------------------------------

SELECT
    source,
    COUNT(*) AS total_events,
    COUNT(DISTINCT asset_name) AS affected_assets
FROM security_events
GROUP BY source
ORDER BY total_events DESC;

-- ---------------------------------------------------------------------------
-- EVALUATION: ALLOWLIST EFFECT
-- ---------------------------------------------------------------------------

SELECT
    e.external_event_id,
    e.normalized_value,
    CASE
        WHEN EXISTS (
            SELECT 1
            FROM indicator_allowlist a
            WHERE a.indicator_type = e.indicator_type
              AND a.normalized_value = e.normalized_value
              AND a.active = TRUE
              AND (
                  a.expires_at IS NULL
                  OR a.expires_at > NOW()
              )
        )
        THEN 'ALLOWLISTED'
        WHEN EXISTS (
            SELECT 1
            FROM indicators i
            WHERE i.indicator_type = e.indicator_type
              AND i.normalized_value = e.normalized_value
              AND i.active = TRUE
              AND (
                  i.expires_at IS NULL
                  OR i.expires_at > NOW()
              )
        )
        THEN 'MATCH_CANDIDATE'
        ELSE 'NO_MATCH'
    END AS evaluation
FROM security_events e
ORDER BY e.external_event_id;

-- ---------------------------------------------------------------------------
-- REPORTING: INVESTIGATION DASHBOARD
-- ---------------------------------------------------------------------------

SELECT *
FROM investigation_dashboard
ORDER BY priority DESC, created_at DESC;

-- ---------------------------------------------------------------------------
-- REPORTING: ASSET EXPOSURE
-- ---------------------------------------------------------------------------

SELECT
    e.asset_name,
    e.tenant_id,
    COUNT(DISTINCT e.event_id) AS observed_events,
    COUNT(DISTINCT m.indicator_id) AS matched_indicators,
    MAX(m.confidence) AS maximum_confidence,
    COUNT(*) FILTER (
        WHERE m.severity = 'critical'
    ) AS critical_matches
FROM security_events e
LEFT JOIN event_indicator_matches m
    ON m.event_id = e.event_id
GROUP BY e.asset_name, e.tenant_id
ORDER BY critical_matches DESC, matched_indicators DESC;

-- ---------------------------------------------------------------------------
-- WORKFLOW PROCESSING: CASE STATE
-- ---------------------------------------------------------------------------

SELECT
    case_reference,
    status,
    priority,
    assigned_analyst,
    matched_events,
    distinct_indicators
FROM investigation_dashboard
WHERE status IN ('open', 'investigating', 'contained')
ORDER BY priority DESC;

-- ---------------------------------------------------------------------------
-- ELIGIBILITY: CASE CONTAINMENT READINESS
-- ---------------------------------------------------------------------------

WITH case_evaluation AS (
    SELECT
        c.case_id,
        c.case_reference,
        c.status,
        COUNT(m.match_id) AS match_count,
        COUNT(*) FILTER (
            WHERE m.severity IN ('high', 'critical')
        ) AS serious_matches,
        MAX(m.confidence) AS max_confidence
    FROM investigation_cases c
    LEFT JOIN event_indicator_matches m
        ON m.case_id = c.case_id
    GROUP BY c.case_id, c.case_reference, c.status
)
SELECT
    *,
    CASE
        WHEN status = 'closed'
            THEN 'NOT_ELIGIBLE_CLOSED'
        WHEN match_count = 0
            THEN 'INSUFFICIENT_EVIDENCE'
        WHEN serious_matches = 0
            THEN 'ANALYST_REVIEW_REQUIRED'
        WHEN max_confidence < 70
            THEN 'LOW_CONFIDENCE'
        ELSE 'READY_FOR_CONTAINMENT_REVIEW'
    END AS containment_eligibility
FROM case_evaluation;

-- ---------------------------------------------------------------------------
-- AUDIT REPORT
-- ---------------------------------------------------------------------------

SELECT
    actor,
    action,
    resource_type,
    resource_id,
    created_at,
    details
FROM audit_log
ORDER BY created_at DESC;

-- ---------------------------------------------------------------------------
-- TRANSACTIONAL CASE CLOSURE EXAMPLE
-- This example is intentionally not executed automatically.
-- ---------------------------------------------------------------------------

/*
BEGIN;

UPDATE investigation_cases
SET status = 'closed'
WHERE case_reference = 'CASE-2026-001'
  AND status IN ('investigating', 'contained');

INSERT INTO case_actions (
    case_id,
    analyst_id,
    action,
    previous_status,
    new_status,
    action_details
)
SELECT
    c.case_id,
    a.analyst_id,
    'close',
    'investigating',
    'closed',
    '{"reason":"Investigation completed"}'
FROM investigation_cases c
CROSS JOIN analysts a
WHERE c.case_reference = 'CASE-2026-001'
  AND a.username = 'analyst01';

COMMIT;
*/

COMMIT;
