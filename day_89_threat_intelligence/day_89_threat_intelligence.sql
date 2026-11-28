-- ============================================================
-- THREAT INTELLIGENCE MANAGEMENT DATABASE
-- PostgreSQL 15+
--
-- Covers:
-- 1. Strategic, operational and tactical intelligence
-- 2. Threat intelligence feeds and ingestion
-- 3. Indicators of Compromise
-- 4. Threat actors and campaigns
-- 5. TLP information-sharing classifications
-- 6. Confidence and severity assessment
-- 7. Indicator lifecycle and expiration
-- 8. Observable correlation
-- 9. Feed provenance and validation
-- 10. Intelligence reporting
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS threat_intel;

SET LOCAL search_path TO threat_intel, public;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ------------------------------------------------------------
-- ENUMERATIONS
-- ------------------------------------------------------------

CREATE TYPE intelligence_type AS ENUM (
    'strategic',
    'operational',
    'tactical'
);

CREATE TYPE indicator_type AS ENUM (
    'ipv4',
    'ipv6',
    'domain',
    'url',
    'md5',
    'sha1',
    'sha256',
    'email'
);

CREATE TYPE threat_severity AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE tlp_classification AS ENUM (
    'clear',
    'green',
    'amber',
    'amber+strict',
    'red'
);

CREATE TYPE indicator_status AS ENUM (
    'active',
    'expired',
    'false_positive',
    'revoked'
);

CREATE TYPE feed_status AS ENUM (
    'active',
    'disabled',
    'failed'
);

CREATE TYPE review_status AS ENUM (
    'pending',
    'accepted',
    'rejected'
);

-- ------------------------------------------------------------
-- ORGANIZATIONS AND RECIPIENT GROUPS
-- ------------------------------------------------------------

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_name VARCHAR(200) NOT NULL UNIQUE,
    organization_type VARCHAR(80) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE recipient_groups (
    group_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    group_name VARCHAR(100) NOT NULL UNIQUE,
    organization_id BIGINT REFERENCES organizations(organization_id),
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- ------------------------------------------------------------
-- INTELLIGENCE SOURCES AND FEEDS
-- ------------------------------------------------------------

CREATE TABLE intelligence_sources (
    source_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_name VARCHAR(200) NOT NULL UNIQUE,
    source_type VARCHAR(50) NOT NULL,
    reliability_score SMALLINT NOT NULL
        CHECK (reliability_score BETWEEN 0 AND 100),
    owner_organization_id BIGINT
        REFERENCES organizations(organization_id),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE intelligence_feeds (
    feed_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id BIGINT NOT NULL
        REFERENCES intelligence_sources(source_id),
    feed_name VARCHAR(200) NOT NULL,
    feed_format VARCHAR(30) NOT NULL,
    feed_status feed_status NOT NULL DEFAULT 'active',
    polling_interval_minutes INTEGER NOT NULL
        CHECK (polling_interval_minutes BETWEEN 1 AND 10080),
    last_successful_poll TIMESTAMPTZ,
    last_failed_poll TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_id, feed_name)
);

CREATE TABLE feed_ingestion_runs (
    ingestion_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    feed_id BIGINT NOT NULL
        REFERENCES intelligence_feeds(feed_id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    records_received INTEGER NOT NULL DEFAULT 0
        CHECK (records_received >= 0),
    records_accepted INTEGER NOT NULL DEFAULT 0
        CHECK (records_accepted >= 0),
    records_rejected INTEGER NOT NULL DEFAULT 0
        CHECK (records_rejected >= 0),
    status VARCHAR(20) NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed')),
    error_message TEXT,
    CHECK (
        records_received >= records_accepted + records_rejected
    ),
    CHECK (
        completed_at IS NULL OR completed_at >= started_at
    )
);

-- ------------------------------------------------------------
-- THREAT ACTORS
-- ------------------------------------------------------------

CREATE TABLE threat_actors (
    actor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_actor_id VARCHAR(100) UNIQUE,
    actor_name VARCHAR(200) NOT NULL UNIQUE,
    motivation VARCHAR(150),
    sophistication VARCHAR(50),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE threat_actor_aliases (
    alias_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id BIGINT NOT NULL
        REFERENCES threat_actors(actor_id) ON DELETE CASCADE,
    alias_name VARCHAR(200) NOT NULL,
    UNIQUE(actor_id, alias_name)
);

-- ------------------------------------------------------------
-- CAMPAIGNS AND STRATEGIC CONTEXT
-- ------------------------------------------------------------

CREATE TABLE threat_campaigns (
    campaign_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    external_campaign_id VARCHAR(100) UNIQUE,
    campaign_name VARCHAR(200) NOT NULL,
    actor_id BIGINT REFERENCES threat_actors(actor_id),
    objective TEXT NOT NULL,
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    campaign_status VARCHAR(30) NOT NULL DEFAULT 'active'
        CHECK (
            campaign_status IN (
                'active',
                'inactive',
                'completed',
                'unknown'
            )
        ),
    CHECK (
        end_date IS NULL OR start_date IS NULL OR end_date >= start_date
    )
);

CREATE TABLE targeted_sectors (
    sector_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sector_name VARCHAR(150) NOT NULL UNIQUE
);

CREATE TABLE campaign_targets (
    campaign_id BIGINT NOT NULL
        REFERENCES threat_campaigns(campaign_id) ON DELETE CASCADE,
    sector_id BIGINT NOT NULL
        REFERENCES targeted_sectors(sector_id),
    PRIMARY KEY(campaign_id, sector_id)
);

-- ------------------------------------------------------------
-- INTELLIGENCE PRODUCTS
-- ------------------------------------------------------------

CREATE TABLE intelligence_products (
    product_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_title VARCHAR(300) NOT NULL,
    intelligence_category intelligence_type NOT NULL,
    executive_summary TEXT NOT NULL,
    analytical_assessment TEXT,
    key_judgments JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence_level SMALLINT NOT NULL
        CHECK (confidence_level BETWEEN 0 AND 100),
    tlp tlp_classification NOT NULL DEFAULT 'amber',
    author_organization_id BIGINT
        REFERENCES organizations(organization_id),
    published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until TIMESTAMPTZ,
    CHECK (
        valid_until IS NULL OR valid_until > published_at
    ),
    CHECK (jsonb_typeof(key_judgments) = 'array')
);

CREATE TABLE product_campaigns (
    product_id BIGINT NOT NULL
        REFERENCES intelligence_products(product_id) ON DELETE CASCADE,
    campaign_id BIGINT NOT NULL
        REFERENCES threat_campaigns(campaign_id),
    PRIMARY KEY(product_id, campaign_id)
);

-- ------------------------------------------------------------
-- INDICATORS OF COMPROMISE
-- ------------------------------------------------------------

CREATE TABLE indicators (
    indicator_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_value VARCHAR(2048) NOT NULL,
    indicator_type indicator_type NOT NULL,
    normalized_value VARCHAR(2048) NOT NULL,
    source_id BIGINT NOT NULL
        REFERENCES intelligence_sources(source_id),
    confidence SMALLINT NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    severity threat_severity NOT NULL,
    tlp tlp_classification NOT NULL,
    intelligence_category intelligence_type NOT NULL,
    status indicator_status NOT NULL DEFAULT 'active',
    description TEXT,
    actor_id BIGINT REFERENCES threat_actors(actor_id),
    campaign_id BIGINT REFERENCES threat_campaigns(campaign_id),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (last_seen >= first_seen),
    CHECK (expires_at > first_seen),

    UNIQUE(indicator_type, normalized_value, source_id)
);

CREATE TABLE indicator_tags (
    indicator_id BIGINT NOT NULL
        REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    tag_name VARCHAR(100) NOT NULL,
    PRIMARY KEY(indicator_id, tag_name)
);

CREATE TABLE indicator_references (
    reference_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id BIGINT NOT NULL
        REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    source_id BIGINT NOT NULL
        REFERENCES intelligence_sources(source_id),
    external_reference TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(indicator_id, source_id, external_reference)
);

-- ------------------------------------------------------------
-- INDICATOR OBSERVATIONS AND PROVENANCE
-- ------------------------------------------------------------

CREATE TABLE indicator_observations (
    observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id BIGINT NOT NULL
        REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    feed_id BIGINT REFERENCES intelligence_feeds(feed_id),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confidence SMALLINT NOT NULL
        CHECK (confidence BETWEEN 0 AND 100),
    observation_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (jsonb_typeof(observation_context) = 'object')
);

CREATE TABLE indicator_reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id BIGINT NOT NULL
        REFERENCES indicators(indicator_id) ON DELETE CASCADE,
    reviewer_organization_id BIGINT
        REFERENCES organizations(organization_id),
    review_status review_status NOT NULL DEFAULT 'pending',
    reviewer_notes TEXT,
    reviewed_at TIMESTAMPTZ,
    CHECK (
        (review_status = 'pending' AND reviewed_at IS NULL)
        OR
        (review_status <> 'pending' AND reviewed_at IS NOT NULL)
    )
);

-- ------------------------------------------------------------
-- TLP SHARING POLICIES
-- ------------------------------------------------------------

CREATE TABLE tlp_sharing_rules (
    classification tlp_classification NOT NULL,
    recipient_group_id BIGINT NOT NULL
        REFERENCES recipient_groups(group_id) ON DELETE CASCADE,
    can_share BOOLEAN NOT NULL,
    PRIMARY KEY(classification, recipient_group_id)
);

CREATE TABLE intelligence_sharing_events (
    sharing_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    product_id BIGINT REFERENCES intelligence_products(product_id),
    indicator_id BIGINT REFERENCES indicators(indicator_id),
    recipient_group_id BIGINT NOT NULL
        REFERENCES recipient_groups(group_id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    permitted BOOLEAN NOT NULL,
    decision_reason TEXT NOT NULL,
    CHECK (
        (product_id IS NOT NULL AND indicator_id IS NULL)
        OR
        (product_id IS NULL AND indicator_id IS NOT NULL)
    )
);

-- ------------------------------------------------------------
-- PERFORMANCE INDEXES
-- ------------------------------------------------------------

CREATE INDEX idx_indicators_active_expiration
    ON indicators(expires_at)
    WHERE status = 'active';

CREATE INDEX idx_indicators_campaign
    ON indicators(campaign_id)
    WHERE campaign_id IS NOT NULL;

CREATE INDEX idx_indicators_actor
    ON indicators(actor_id)
    WHERE actor_id IS NOT NULL;

CREATE INDEX idx_indicators_severity
    ON indicators(severity, confidence DESC);

CREATE INDEX idx_indicators_category
    ON indicators(intelligence_category, status);

CREATE INDEX idx_indicators_observable
    ON indicators(indicator_type, normalized_value);

CREATE INDEX idx_indicator_observations_time
    ON indicator_observations(indicator_id, observed_at DESC);

CREATE INDEX idx_feed_runs_recent
    ON feed_ingestion_runs(feed_id, started_at DESC);

CREATE INDEX idx_products_category
    ON intelligence_products(intelligence_category, published_at DESC);

CREATE INDEX idx_products_judgments
    ON intelligence_products USING GIN(key_judgments);

-- ------------------------------------------------------------
-- AUTOMATIC UPDATED_AT MAINTENANCE
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_modified_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_indicator_updated_at
BEFORE UPDATE ON indicators
FOR EACH ROW
EXECUTE FUNCTION update_modified_timestamp();

-- ------------------------------------------------------------
-- AUTOMATIC INDICATOR EXPIRATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION expire_indicator()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.expires_at <= NOW()
       AND NEW.status = 'active' THEN
        NEW.status = 'expired';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_indicator_expiration
BEFORE INSERT OR UPDATE OF expires_at, status
ON indicators
FOR EACH ROW
EXECUTE FUNCTION expire_indicator();

-- ------------------------------------------------------------
-- VALIDATION FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_indicator_value(
    p_type indicator_type,
    p_value TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN

    IF p_value IS NULL OR LENGTH(TRIM(p_value)) = 0 THEN
        RETURN FALSE;
    END IF;

    IF LENGTH(p_value) > 2048 THEN
        RETURN FALSE;
    END IF;

    CASE p_type

        WHEN 'ipv4' THEN
            RETURN p_value ~
                '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'
                AND NOT EXISTS (
                    SELECT 1
                    FROM unnest(string_to_array(p_value, '.')) AS octet
                    WHERE octet::INTEGER > 255
                );

        WHEN 'ipv6' THEN
            BEGIN
                RETURN family(p_value::inet) = 6;
            EXCEPTION WHEN OTHERS THEN
                RETURN FALSE;
            END;

        WHEN 'domain' THEN
            RETURN LENGTH(p_value) <= 253
                AND p_value ~* (
                    '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
                    || '(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
                );

        WHEN 'md5' THEN
            RETURN p_value ~* '^[0-9a-f]{32}$';

        WHEN 'sha1' THEN
            RETURN p_value ~* '^[0-9a-f]{40}$';

        WHEN 'sha256' THEN
            RETURN p_value ~* '^[0-9a-f]{64}$';

        WHEN 'email' THEN
            RETURN p_value ~
                '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$';

        WHEN 'url' THEN
            RETURN p_value ~* '^https?://[^[:space:]/]+';

    END CASE;

    RETURN FALSE;
END;
$$;

-- ------------------------------------------------------------
-- SECURE INDICATOR INSERTION PROCEDURE
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE ingest_indicator(
    p_value VARCHAR,
    p_type indicator_type,
    p_source_id BIGINT,
    p_confidence SMALLINT,
    p_severity threat_severity,
    p_tlp tlp_classification,
    p_category intelligence_type,
    p_first_seen TIMESTAMPTZ,
    p_last_seen TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ,
    p_actor_id BIGINT DEFAULT NULL,
    p_campaign_id BIGINT DEFAULT NULL,
    p_description TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_normalized TEXT;
BEGIN

    IF NOT validate_indicator_value(p_type, p_value) THEN
        RAISE EXCEPTION 'Invalid indicator value for type %', p_type;
    END IF;

    IF p_confidence NOT BETWEEN 0 AND 100 THEN
        RAISE EXCEPTION 'Confidence must be between 0 and 100';
    END IF;

    IF p_last_seen < p_first_seen THEN
        RAISE EXCEPTION 'last_seen precedes first_seen';
    END IF;

    IF p_expires_at <= p_first_seen THEN
        RAISE EXCEPTION 'Invalid indicator expiration';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM intelligence_sources
        WHERE source_id = p_source_id
          AND enabled = TRUE
    ) THEN
        RAISE EXCEPTION 'Unknown or disabled intelligence source';
    END IF;

    IF p_actor_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM threat_actors
        WHERE actor_id = p_actor_id
    ) THEN
        RAISE EXCEPTION 'Unknown threat actor';
    END IF;

    IF p_campaign_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM threat_campaigns
        WHERE campaign_id = p_campaign_id
    ) THEN
        RAISE EXCEPTION 'Unknown threat campaign';
    END IF;

    v_normalized = CASE
        WHEN p_type IN ('domain', 'email', 'url')
            THEN LOWER(TRIM(p_value))
        ELSE LOWER(TRIM(p_value))
    END;

    INSERT INTO indicators (
        indicator_value,
        indicator_type,
        normalized_value,
        source_id,
        confidence,
        severity,
        tlp,
        intelligence_category,
        actor_id,
        campaign_id,
        first_seen,
        last_seen,
        expires_at,
        description
    )
    VALUES (
        p_value,
        p_type,
        v_normalized,
        p_source_id,
        p_confidence,
        p_severity,
        p_tlp,
        p_category,
        p_actor_id,
        p_campaign_id,
        p_first_seen,
        p_last_seen,
        p_expires_at,
        p_description
    )
    ON CONFLICT (
        indicator_type,
        normalized_value,
        source_id
    )
    DO UPDATE SET
        confidence = GREATEST(
            indicators.confidence,
            EXCLUDED.confidence
        ),
        severity = CASE
            WHEN CASE indicators.severity
                WHEN 'low' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'high' THEN 3
                WHEN 'critical' THEN 4
            END
            <
            CASE EXCLUDED.severity
                WHEN 'low' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'high' THEN 3
                WHEN 'critical' THEN 4
            END
            THEN EXCLUDED.severity
            ELSE indicators.severity
        END,
        last_seen = GREATEST(
            indicators.last_seen,
            EXCLUDED.last_seen
        ),
        expires_at = GREATEST(
            indicators.expires_at,
            EXCLUDED.expires_at
        ),
        description = COALESCE(
            EXCLUDED.description,
            indicators.description
        );

END;
$$;

-- ------------------------------------------------------------
-- TLP AUTHORIZATION FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION check_tlp_permission(
    p_classification tlp_classification,
    p_recipient_group BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_allowed BOOLEAN;
BEGIN

    SELECT can_share
    INTO v_allowed
    FROM tlp_sharing_rules
    WHERE classification = p_classification
      AND recipient_group_id = p_recipient_group;

    RETURN COALESCE(v_allowed, FALSE);
END;
$$;

-- ------------------------------------------------------------
-- INTELLIGENCE SHARING PROCEDURE
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE request_indicator_sharing(
    p_indicator_id BIGINT,
    p_recipient_group BIGINT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_tlp tlp_classification;
    v_allowed BOOLEAN;
    v_status indicator_status;
BEGIN

    SELECT tlp, status
    INTO v_tlp, v_status
    FROM indicators
    WHERE indicator_id = p_indicator_id
      AND expires_at > NOW();

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Indicator not found or expired';
    END IF;

    IF v_status <> 'active' THEN
        RAISE EXCEPTION 'Indicator is not active';
    END IF;

    v_allowed = check_tlp_permission(
        v_tlp,
        p_recipient_group
    );

    INSERT INTO intelligence_sharing_events (
        indicator_id,
        recipient_group_id,
        permitted,
        decision_reason
    )
    VALUES (
        p_indicator_id,
        p_recipient_group,
        v_allowed,
        CASE
            WHEN v_allowed THEN 'TLP policy permits sharing'
            ELSE 'TLP policy prohibits sharing'
        END
    );

END;
$$;

-- ------------------------------------------------------------
-- EXPIRATION PROCESSING
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION expire_old_indicators()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN

    UPDATE indicators
    SET status = 'expired'
    WHERE status = 'active'
      AND expires_at <= NOW();

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$;

-- ------------------------------------------------------------
-- RISK EVALUATION VIEW
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW active_indicator_risk AS
SELECT
    i.indicator_id,
    i.normalized_value,
    i.indicator_type,
    i.severity,
    i.confidence,
    i.tlp,
    i.intelligence_category,
    i.campaign_id,
    i.actor_id,
    i.source_id,
    i.last_seen,
    i.expires_at,

    ROUND(
        (
            i.confidence * 0.4
            +
            CASE i.severity
                WHEN 'low' THEN 25
                WHEN 'medium' THEN 50
                WHEN 'high' THEN 75
                WHEN 'critical' THEN 100
            END * 0.4
            +
            GREATEST(
                0,
                100 - (
                    EXTRACT(EPOCH FROM (NOW() - i.last_seen))
                    / 86400.0 * 5
                )
            ) * 0.2
        )::NUMERIC,
        2
    ) AS risk_score

FROM indicators i

WHERE i.status = 'active'
  AND i.expires_at > NOW();

-- ------------------------------------------------------------
-- INTELLIGENCE DISTRIBUTION REPORT
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW intelligence_distribution AS
SELECT
    intelligence_category,
    COUNT(*) AS indicator_count,
    AVG(confidence)::NUMERIC(5,2) AS average_confidence,
    COUNT(*) FILTER (
        WHERE severity = 'critical'
    ) AS critical_count,
    COUNT(*) FILTER (
        WHERE severity = 'high'
    ) AS high_count
FROM indicators
WHERE status = 'active'
  AND expires_at > NOW()
GROUP BY intelligence_category;

-- ------------------------------------------------------------
-- CAMPAIGN CORRELATION VIEW
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW campaign_intelligence AS
SELECT
    c.campaign_id,
    c.campaign_name,
    a.actor_name,
    COUNT(i.indicator_id) AS indicator_count,
    COUNT(DISTINCT i.source_id) AS source_count,
    COUNT(DISTINCT i.indicator_type) AS indicator_type_count,
    AVG(i.confidence)::NUMERIC(5,2) AS average_confidence,
    COUNT(*) FILTER (
        WHERE i.severity = 'critical'
    ) AS critical_indicators

FROM threat_campaigns c

LEFT JOIN threat_actors a
    ON a.actor_id = c.actor_id

LEFT JOIN indicators i
    ON i.campaign_id = c.campaign_id
   AND i.status = 'active'
   AND i.expires_at > NOW()

GROUP BY
    c.campaign_id,
    c.campaign_name,
    a.actor_name;

-- ------------------------------------------------------------
-- SAMPLE DATA
-- ------------------------------------------------------------

INSERT INTO organizations (
    organization_name,
    organization_type
)
VALUES
    ('National Security Operations', 'government'),
    ('Cyber Threat Research Unit', 'research'),
    ('Energy Infrastructure Security', 'critical_infrastructure');

INSERT INTO recipient_groups (
    group_name,
    organization_id
)
SELECT
    'public',
    NULL
UNION ALL
SELECT
    'community',
    organization_id
FROM organizations
WHERE organization_name = 'Cyber Threat Research Unit'
UNION ALL
SELECT
    'organization',
    organization_id
FROM organizations
WHERE organization_name = 'National Security Operations'
UNION ALL
SELECT
    'designated_group',
    organization_id
FROM organizations
WHERE organization_name = 'Energy Infrastructure Security'
UNION ALL
SELECT
    'internal',
    organization_id
FROM organizations
WHERE organization_name = 'National Security Operations';

INSERT INTO intelligence_sources (
    source_name,
    source_type,
    reliability_score,
    owner_organization_id
)
SELECT
    'Example Threat Feed',
    'commercial',
    95,
    organization_id
FROM organizations
WHERE organization_name = 'Cyber Threat Research Unit';

INSERT INTO intelligence_sources (
    source_name,
    source_type,
    reliability_score,
    owner_organization_id
)
SELECT
    'Open Source Intelligence',
    'osint',
    80,
    organization_id
FROM organizations
WHERE organization_name = 'Cyber Threat Research Unit';

INSERT INTO intelligence_feeds (
    source_id,
    feed_name,
    feed_format,
    polling_interval_minutes
)
SELECT
    source_id,
    'Primary IOC Feed',
    'json',
    60
FROM intelligence_sources
WHERE source_name = 'Example Threat Feed';

INSERT INTO threat_actors (
    external_actor_id,
    actor_name,
    motivation,
    sophistication,
    description
)
VALUES (
    'EXT-ACT-001',
    'Example APT',
    'Espionage',
    'Advanced',
    'Simulated persistent threat actor for analytical exercises.'
);

INSERT INTO threat_actor_aliases (
    actor_id,
    alias_name
)
SELECT
    actor_id,
    'EXAMPLE-APT'
FROM threat_actors
WHERE actor_name = 'Example APT';

INSERT INTO threat_campaigns (
    external_campaign_id,
    campaign_name,
    actor_id,
    objective
)
SELECT
    'EXT-CMP-001',
    'Northern Gateway',
    actor_id,
    'Credential theft and unauthorized data access'
FROM threat_actors
WHERE actor_name = 'Example APT';

INSERT INTO targeted_sectors (sector_name)
VALUES
    ('Government'),
    ('Energy'),
    ('Telecommunications');

INSERT INTO campaign_targets (
    campaign_id,
    sector_id
)
SELECT
    c.campaign_id,
    s.sector_id
FROM threat_campaigns c
CROSS JOIN targeted_sectors s
WHERE c.campaign_name = 'Northern Gateway'
  AND s.sector_name IN ('Government', 'Energy');

INSERT INTO tlp_sharing_rules (
    classification,
    recipient_group_id,
    can_share
)
SELECT
    labels.classification::tlp_classification,
    groups.group_id,
    CASE
        WHEN labels.classification = 'clear'
            THEN TRUE
        WHEN labels.classification = 'green'
            THEN groups.group_name <> 'public'
        WHEN labels.classification = 'amber'
            THEN groups.group_name IN (
                'organization',
                'designated_group',
                'internal'
            )
        WHEN labels.classification = 'amber+strict'
            THEN groups.group_name IN (
                'designated_group',
                'internal'
            )
        ELSE FALSE
    END
FROM (
    VALUES
        ('clear'),
        ('green'),
        ('amber'),
        ('amber+strict'),
        ('red')
) AS labels(classification)
CROSS JOIN recipient_groups groups;

-- ------------------------------------------------------------
-- TRANSACTIONAL FEED INGESTION
-- ------------------------------------------------------------

DO $$
DECLARE
    v_source_id BIGINT;
    v_actor_id BIGINT;
    v_campaign_id BIGINT;
    v_now TIMESTAMPTZ := NOW();
BEGIN

    SELECT source_id
    INTO v_source_id
    FROM intelligence_sources
    WHERE source_name = 'Example Threat Feed';

    SELECT actor_id
    INTO v_actor_id
    FROM threat_actors
    WHERE actor_name = 'Example APT';

    SELECT campaign_id
    INTO v_campaign_id
    FROM threat_campaigns
    WHERE campaign_name = 'Northern Gateway';

    INSERT INTO feed_ingestion_runs (
        feed_id,
        records_received,
        status
    )
    SELECT
        feed_id,
        3,
        'running'
    FROM intelligence_feeds
    WHERE feed_name = 'Primary IOC Feed';

    CALL ingest_indicator(
        '203.0.113.25',
        'ipv4',
        v_source_id,
        95,
        'critical',
        'amber',
        'tactical',
        v_now,
        v_now,
        v_now + INTERVAL '30 days',
        v_actor_id,
        v_campaign_id,
        'Simulated command-and-control address'
    );

    CALL ingest_indicator(
        'malicious-example.org',
        'domain',
        v_source_id,
        85,
        'high',
        'green',
        'operational',
        v_now,
        v_now,
        v_now + INTERVAL '15 days',
        v_actor_id,
        v_campaign_id,
        'Simulated phishing infrastructure'
    );

    CALL ingest_indicator(
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'sha256',
        v_source_id,
        90,
        'critical',
        'amber+strict',
        'tactical',
        v_now,
        v_now,
        v_now + INTERVAL '60 days',
        v_actor_id,
        v_campaign_id,
        'Simulated malware file hash'
    );

    UPDATE feed_ingestion_runs
    SET
        records_accepted = 3,
        completed_at = NOW(),
        status = 'completed'
    WHERE feed_id = (
        SELECT feed_id
        FROM intelligence_feeds
        WHERE feed_name = 'Primary IOC Feed'
    )
    AND status = 'running';

    UPDATE intelligence_feeds
    SET last_successful_poll = NOW()
    WHERE feed_name = 'Primary IOC Feed';

END;
$$;

-- ------------------------------------------------------------
-- INDICATOR TAGGING
-- ------------------------------------------------------------

INSERT INTO indicator_tags (
    indicator_id,
    tag_name
)
SELECT indicator_id, 'malware'
FROM indicators
WHERE indicator_type = 'ipv4';

INSERT INTO indicator_tags (
    indicator_id,
    tag_name
)
SELECT indicator_id, 'phishing'
FROM indicators
WHERE indicator_type = 'domain';

INSERT INTO indicator_tags (
    indicator_id,
    tag_name
)
SELECT indicator_id, 'file-hash'
FROM indicators
WHERE indicator_type = 'sha256';

-- ------------------------------------------------------------
-- INTELLIGENCE PRODUCT EXAMPLES
-- ------------------------------------------------------------

INSERT INTO intelligence_products (
    product_title,
    intelligence_category,
    executive_summary,
    analytical_assessment,
    key_judgments,
    confidence_level,
    tlp,
    author_organization_id
)
SELECT
    'Cyber Threat Strategic Assessment',
    'strategic',
    'Assessment of simulated cyber threats affecting critical sectors.',
    'Persistent threat activity requires coordinated monitoring.',
    '[
        {"judgment":"Government infrastructure is targeted","confidence":"high"},
        {"judgment":"Credential theft is an operational objective","confidence":"moderate"}
    ]'::jsonb,
    85,
    'amber',
    organization_id
FROM organizations
WHERE organization_name = 'National Security Operations';

-- ------------------------------------------------------------
-- QUERY 1: ACTIVE INDICATORS
-- ------------------------------------------------------------

SELECT
    indicator_id,
    normalized_value,
    indicator_type,
    severity,
    confidence,
    tlp,
    intelligence_category,
    expires_at
FROM indicators
WHERE status = 'active'
  AND expires_at > NOW()
ORDER BY confidence DESC;

-- ------------------------------------------------------------
-- QUERY 2: RISK PRIORITIZATION
-- ------------------------------------------------------------

SELECT *
FROM active_indicator_risk
ORDER BY risk_score DESC;

-- ------------------------------------------------------------
-- QUERY 3: STRATEGIC, OPERATIONAL AND TACTICAL DISTRIBUTION
-- ------------------------------------------------------------

SELECT *
FROM intelligence_distribution
ORDER BY intelligence_category;

-- ------------------------------------------------------------
-- QUERY 4: CAMPAIGN CORRELATION
-- ------------------------------------------------------------

SELECT *
FROM campaign_intelligence
ORDER BY indicator_count DESC;

-- ------------------------------------------------------------
-- QUERY 5: THREAT ACTOR INTELLIGENCE
-- ------------------------------------------------------------

SELECT
    a.actor_name,
    c.campaign_name,
    i.normalized_value,
    i.indicator_type,
    i.severity,
    i.confidence
FROM threat_actors a
LEFT JOIN threat_campaigns c
    ON c.actor_id = a.actor_id
LEFT JOIN indicators i
    ON i.actor_id = a.actor_id
WHERE i.status = 'active'
  AND i.expires_at > NOW()
ORDER BY a.actor_name, i.confidence DESC;

-- ------------------------------------------------------------
-- QUERY 6: TAG-BASED RETRIEVAL
-- ------------------------------------------------------------

SELECT
    i.normalized_value,
    i.indicator_type,
    t.tag_name
FROM indicators i
JOIN indicator_tags t
    ON t.indicator_id = i.indicator_id
WHERE t.tag_name = 'malware'
  AND i.status = 'active';

-- ------------------------------------------------------------
-- QUERY 7: FEED PERFORMANCE
-- ------------------------------------------------------------

SELECT
    f.feed_name,
    COUNT(r.ingestion_id) AS ingestion_runs,
    COALESCE(SUM(r.records_received), 0) AS received,
    COALESCE(SUM(r.records_accepted), 0) AS accepted,
    COALESCE(SUM(r.records_rejected), 0) AS rejected,
    ROUND(
        100.0 * COALESCE(SUM(r.records_accepted), 0)
        / NULLIF(SUM(r.records_received), 0),
        2
    ) AS acceptance_percentage
FROM intelligence_feeds f
LEFT JOIN feed_ingestion_runs r
    ON r.feed_id = f.feed_id
GROUP BY f.feed_id, f.feed_name;

-- ------------------------------------------------------------
-- QUERY 8: INDICATOR VALIDATION
-- ------------------------------------------------------------

SELECT
    indicator_value,
    indicator_type,
    validate_indicator_value(
        indicator_type,
        indicator_value
    ) AS valid
FROM indicators;

-- ------------------------------------------------------------
-- QUERY 9: OBSERVABLE MATCHING
-- ------------------------------------------------------------

SELECT
    indicator_id,
    normalized_value,
    severity,
    confidence,
    tlp
FROM indicators
WHERE indicator_type = 'ipv4'
  AND normalized_value = '203.0.113.25'
  AND status = 'active'
  AND expires_at > NOW();

-- ------------------------------------------------------------
-- QUERY 10: TLP SHARING ELIGIBILITY
-- ------------------------------------------------------------

SELECT
    i.normalized_value,
    i.tlp,
    g.group_name,
    check_tlp_permission(
        i.tlp,
        g.group_id
    ) AS permitted
FROM indicators i
CROSS JOIN recipient_groups g
WHERE i.normalized_value = '203.0.113.25';

-- ------------------------------------------------------------
-- QUERY 11: EXPIRED INDICATORS
-- ------------------------------------------------------------

SELECT
    indicator_id,
    normalized_value,
    expires_at
FROM indicators
WHERE expires_at <= NOW()
  AND status = 'active';

-- ------------------------------------------------------------
-- QUERY 12: JSONB INTELLIGENCE JUDGMENTS
-- ------------------------------------------------------------

SELECT
    product_title,
    judgment.value ->> 'judgment' AS judgment,
    judgment.value ->> 'confidence' AS confidence
FROM intelligence_products p
CROSS JOIN LATERAL jsonb_array_elements(
    p.key_judgments
) AS judgment(value);

-- ------------------------------------------------------------
-- QUERY 13: REVIEW QUEUE
-- ------------------------------------------------------------

SELECT
    r.review_id,
    i.normalized_value,
    i.severity,
    r.review_status,
    r.reviewer_notes
FROM indicator_reviews r
JOIN indicators i
    ON i.indicator_id = r.indicator_id
WHERE r.review_status = 'pending';

-- ------------------------------------------------------------
-- EXAMPLE SHARING TRANSACTION
-- ------------------------------------------------------------

DO $$
DECLARE
    v_indicator BIGINT;
    v_group BIGINT;
BEGIN

    SELECT indicator_id
    INTO v_indicator
    FROM indicators
    WHERE normalized_value = '203.0.113.25'
    LIMIT 1;

    SELECT group_id
    INTO v_group
    FROM recipient_groups
    WHERE group_name = 'organization';

    IF v_indicator IS NOT NULL AND v_group IS NOT NULL THEN
        CALL request_indicator_sharing(
            v_indicator,
            v_group
        );
    END IF;

END;
$$;

-- ------------------------------------------------------------
-- REPORTING: SHARING AUDIT
-- ------------------------------------------------------------

SELECT
    e.sharing_id,
    e.requested_at,
    i.normalized_value,
    g.group_name,
    i.tlp,
    e.permitted,
    e.decision_reason
FROM intelligence_sharing_events e
JOIN indicators i
    ON i.indicator_id = e.indicator_id
JOIN recipient_groups g
    ON g.group_id = e.recipient_group_id
ORDER BY e.requested_at DESC;

-- ------------------------------------------------------------
-- DATA QUALITY: POTENTIAL DUPLICATES ACROSS SOURCES
-- ------------------------------------------------------------

SELECT
    indicator_type,
    normalized_value,
    COUNT(DISTINCT source_id) AS source_count,
    AVG(confidence)::NUMERIC(5,2) AS average_confidence,
    MAX(confidence) AS highest_confidence
FROM indicators
GROUP BY indicator_type, normalized_value
HAVING COUNT(DISTINCT source_id) > 1
ORDER BY source_count DESC;

-- ------------------------------------------------------------
-- EXAMPLE FALSE-POSITIVE REVIEW
-- ------------------------------------------------------------

INSERT INTO indicator_reviews (
    indicator_id,
    reviewer_organization_id,
    review_status,
    reviewer_notes,
    reviewed_at
)
SELECT
    i.indicator_id,
    o.organization_id,
    'accepted',
    'Indicator reviewed and retained for monitoring.',
    NOW()
FROM indicators i
CROSS JOIN organizations o
WHERE i.indicator_type = 'domain'
  AND o.organization_name = 'National Security Operations'
LIMIT 1;

-- ------------------------------------------------------------
-- OPERATIONAL MAINTENANCE
-- ------------------------------------------------------------

SELECT expire_old_indicators();

COMMIT;
