/*
 * PostgreSQL Network Segmentation Governance System
 *
 * Covers:
 *   - VLANs and IPv4 network segments
 *   - Trust zones
 *   - DMZ boundary policies
 *   - Microsegmentation rules
 *   - East-west traffic
 *   - Policy revisions and approvals
 *   - Separation of duties
 *   - Policy activation and retirement
 *   - Traffic evaluation and audit records
 *
 * Execute:
 *     psql -v ON_ERROR_STOP=1 -f network_segmentation.sql
 *
 * The script recreates the network_security schema.
 */

BEGIN;

DROP SCHEMA IF EXISTS network_security CASCADE;

CREATE SCHEMA network_security;

SET search_path TO network_security, public;


/* ================================================================
   1. NETWORK INVENTORY
   ================================================================ */

CREATE TABLE segments (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    segment_key     VARCHAR(64) NOT NULL UNIQUE,
    name            VARCHAR(120) NOT NULL,
    vlan_id         INTEGER NOT NULL UNIQUE,
    network         CIDR NOT NULL UNIQUE,
    trust_zone      VARCHAR(24) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_vlan_id
        CHECK (vlan_id BETWEEN 1 AND 4094),

    CONSTRAINT ck_trust_zone
        CHECK (
            trust_zone IN (
                'USER',
                'DMZ',
                'APPLICATION',
                'DATA',
                'MANAGEMENT',
                'INTERNET'
            )
        )
);

/*
 * CIDR uniqueness alone does not prevent overlapping networks.
 * Prevent overlapping segment ranges to avoid ambiguous routing
 * and conflicting segment assignments.
 */

CREATE OR REPLACE FUNCTION prevent_segment_overlap()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM segments existing
        WHERE existing.id <> COALESCE(NEW.id, -1)
          AND existing.network && NEW.network
    ) THEN
        RAISE EXCEPTION
            'Network range % overlaps an existing segment.',
            NEW.network;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_prevent_segment_overlap
BEFORE INSERT OR UPDATE ON segments
FOR EACH ROW
EXECUTE FUNCTION prevent_segment_overlap();


CREATE TABLE endpoints (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_key    VARCHAR(80) NOT NULL UNIQUE,
    segment_id      BIGINT NOT NULL REFERENCES segments(id),
    hostname        VARCHAR(120) NOT NULL,
    ip_address      INET NOT NULL UNIQUE,
    labels          JSONB NOT NULL DEFAULT '{}'::JSONB,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT ck_endpoint_ipv4
        CHECK (family(ip_address) = 4),

    CONSTRAINT ck_endpoint_role
        CHECK (
            labels ? 'role'
            AND length(trim(labels ->> 'role')) > 0
        )
);

/*
 * An endpoint must be addressed from the subnet assigned to its VLAN.
 * Network membership is checked when the endpoint is inserted or moved.
 */

CREATE OR REPLACE FUNCTION validate_endpoint_network()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_network CIDR;
BEGIN
    SELECT network
    INTO v_network
    FROM segments
    WHERE id = NEW.segment_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown segment ID: %', NEW.segment_id;
    END IF;

    IF NOT (NEW.ip_address <<= v_network) THEN
        RAISE EXCEPTION
            'Endpoint address % is outside network %.',
            NEW.ip_address,
            v_network;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_endpoint_network
BEFORE INSERT OR UPDATE ON endpoints
FOR EACH ROW
EXECUTE FUNCTION validate_endpoint_network();


CREATE INDEX idx_endpoints_segment
    ON endpoints(segment_id);

CREATE INDEX idx_endpoints_role
    ON endpoints((labels ->> 'role'));


/* ================================================================
   2. POLICY REVISION AND GOVERNANCE
   ================================================================ */

CREATE TABLE policy_revisions (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_name     VARCHAR(120) NOT NULL,
    version         INTEGER NOT NULL,
    created_by      VARCHAR(120) NOT NULL,
    state           VARCHAR(16) NOT NULL DEFAULT 'DRAFT',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activated_at    TIMESTAMPTZ,

    CONSTRAINT uq_policy_version
        UNIQUE (policy_name, version),

    CONSTRAINT ck_policy_version
        CHECK (version >= 1),

    CONSTRAINT ck_policy_state
        CHECK (state IN ('DRAFT', 'ACTIVE', 'RETIRED')),

    CONSTRAINT ck_activation_timestamp
        CHECK (
            (state = 'DRAFT' AND activated_at IS NULL)
            OR
            (state IN ('ACTIVE', 'RETIRED') AND activated_at IS NOT NULL)
        )
);

/*
 * Only one active revision of a named policy can exist.
 * This avoids competing active configurations.
 */

CREATE UNIQUE INDEX uq_one_active_policy_revision
    ON policy_revisions(policy_name)
    WHERE state = 'ACTIVE';


CREATE TABLE approval_requirements (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    revision_id     BIGINT NOT NULL
                    REFERENCES policy_revisions(id) ON DELETE CASCADE,
    required_role   VARCHAR(40) NOT NULL,

    CONSTRAINT uq_required_role
        UNIQUE (revision_id, required_role),

    CONSTRAINT ck_required_role
        CHECK (
            required_role IN (
                'NETWORK_SECURITY',
                'PLATFORM_OPERATIONS'
            )
        )
);


CREATE TABLE policy_approvals (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    revision_id     BIGINT NOT NULL
                    REFERENCES policy_revisions(id) ON DELETE CASCADE,
    approver        VARCHAR(120) NOT NULL,
    approver_role   VARCHAR(40) NOT NULL,
    approved_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_revision_approver
        UNIQUE (revision_id, approver),

    CONSTRAINT ck_approver_role
        CHECK (
            approver_role IN (
                'NETWORK_SECURITY',
                'PLATFORM_OPERATIONS'
            )
        )
);


/*
 * Policy revisions have a limited state-transition graph:
 *
 * DRAFT  -> ACTIVE
 * ACTIVE -> RETIRED
 *
 * Direct transitions between other states are prohibited.
 */

CREATE OR REPLACE FUNCTION validate_policy_state_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.state = OLD.state THEN
        RETURN NEW;
    END IF;

    IF NOT (
        (OLD.state = 'DRAFT' AND NEW.state = 'ACTIVE')
        OR
        (OLD.state = 'ACTIVE' AND NEW.state = 'RETIRED')
    ) THEN
        RAISE EXCEPTION
            'Invalid policy transition: % -> %.',
            OLD.state,
            NEW.state;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_policy_state_transition
BEFORE UPDATE OF state ON policy_revisions
FOR EACH ROW
EXECUTE FUNCTION validate_policy_state_transition();


/*
 * Rule sets and approval records are mutable only while their revision
 * is in DRAFT state. Activated policies become immutable.
 */

CREATE OR REPLACE FUNCTION enforce_draft_policy_revision()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_revision_id BIGINT;
    v_state       VARCHAR(16);
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_revision_id := OLD.revision_id;
    ELSE
        v_revision_id := NEW.revision_id;
    END IF;

    SELECT state
    INTO v_state
    FROM policy_revisions
    WHERE id = v_revision_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Policy revision % does not exist.', v_revision_id;
    END IF;

    IF v_state <> 'DRAFT' THEN
        RAISE EXCEPTION
            'Policy revision % is %, not editable.',
            v_revision_id,
            v_state;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_draft_approval_requirement
BEFORE INSERT OR UPDATE OR DELETE ON approval_requirements
FOR EACH ROW
EXECUTE FUNCTION enforce_draft_policy_revision();


CREATE TRIGGER trg_draft_policy_approval
BEFORE INSERT OR UPDATE OR DELETE ON policy_approvals
FOR EACH ROW
EXECUTE FUNCTION enforce_draft_policy_revision();


/*
 * Approvers must satisfy a configured organizational role.
 * The revision creator cannot approve their own revision.
 */

CREATE OR REPLACE FUNCTION validate_policy_approval()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_created_by VARCHAR(120);
BEGIN
    SELECT created_by
    INTO v_created_by
    FROM policy_revisions
    WHERE id = NEW.revision_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Policy revision does not exist.';
    END IF;

    IF NEW.approver = v_created_by THEN
        RAISE EXCEPTION
            'Policy creator cannot approve their own revision.';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM approval_requirements
        WHERE revision_id = NEW.revision_id
          AND required_role = NEW.approver_role
    ) THEN
        RAISE EXCEPTION
            'Role % is not required for revision %.',
            NEW.approver_role,
            NEW.revision_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_policy_approval
BEFORE INSERT ON policy_approvals
FOR EACH ROW
EXECUTE FUNCTION validate_policy_approval();


/*
 * Activation is an explicit operation rather than an unrestricted UPDATE.
 * Every required role must have at least one independent approval.
 */

CREATE OR REPLACE FUNCTION activate_policy_revision(
    p_revision_id BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_state VARCHAR(16);
BEGIN
    SELECT state
    INTO v_state
    FROM policy_revisions
    WHERE id = p_revision_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Policy revision % not found.', p_revision_id;
    END IF;

    IF v_state <> 'DRAFT' THEN
        RAISE EXCEPTION
            'Only draft policies can be activated. Current state: %.',
            v_state;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM approval_requirements
        WHERE revision_id = p_revision_id
    ) THEN
        RAISE EXCEPTION
            'Policy revision has no configured approval requirements.';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM approval_requirements requirement
        WHERE requirement.revision_id = p_revision_id
          AND NOT EXISTS (
              SELECT 1
              FROM policy_approvals approval
              WHERE approval.revision_id = requirement.revision_id
                AND approval.approver_role = requirement.required_role
          )
    ) THEN
        RAISE EXCEPTION
            'Policy revision is missing required approvals.';
    END IF;

    UPDATE policy_revisions
    SET state = 'ACTIVE',
        activated_at = CURRENT_TIMESTAMP
    WHERE id = p_revision_id;
END;
$$;


/* ================================================================
   3. NETWORK-BOUNDARY POLICY
   ================================================================ */

CREATE TABLE network_rules (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    revision_id         BIGINT NOT NULL
                        REFERENCES policy_revisions(id) ON DELETE CASCADE,
    rule_key            VARCHAR(80) NOT NULL,
    priority            INTEGER NOT NULL,
    source_zone         VARCHAR(24) NOT NULL,
    destination_zone    VARCHAR(24) NOT NULL,
    protocol            VARCHAR(8) NOT NULL,
    port_from           INTEGER NOT NULL,
    port_to             INTEGER NOT NULL,
    action              VARCHAR(8) NOT NULL,
    description         TEXT NOT NULL,

    CONSTRAINT uq_network_rule_key
        UNIQUE (revision_id, rule_key),

    CONSTRAINT uq_network_rule_priority
        UNIQUE (revision_id, priority),

    CONSTRAINT ck_network_source_zone
        CHECK (
            source_zone IN (
                'USER',
                'DMZ',
                'APPLICATION',
                'DATA',
                'MANAGEMENT',
                'INTERNET'
            )
        ),

    CONSTRAINT ck_network_destination_zone
        CHECK (
            destination_zone IN (
                'USER',
                'DMZ',
                'APPLICATION',
                'DATA',
                'MANAGEMENT',
                'INTERNET'
            )
        ),

    CONSTRAINT ck_network_protocol
        CHECK (protocol IN ('TCP', 'UDP')),

    CONSTRAINT ck_network_ports
        CHECK (
            port_from BETWEEN 1 AND 65535
            AND port_to BETWEEN port_from AND 65535
        ),

    CONSTRAINT ck_network_action
        CHECK (action IN ('ALLOW', 'DENY'))
);


CREATE INDEX idx_network_rule_lookup
    ON network_rules(
        revision_id,
        source_zone,
        destination_zone,
        priority
    );


CREATE TRIGGER trg_draft_network_rule
BEFORE INSERT OR UPDATE OR DELETE ON network_rules
FOR EACH ROW
EXECUTE FUNCTION enforce_draft_policy_revision();


/* ================================================================
   4. WORKLOAD MICROSEGMENTATION POLICY
   ================================================================ */

CREATE TABLE micro_rules (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    revision_id         BIGINT NOT NULL
                        REFERENCES policy_revisions(id) ON DELETE CASCADE,
    rule_key            VARCHAR(80) NOT NULL,
    priority            INTEGER NOT NULL,
    source_role         VARCHAR(80) NOT NULL,
    destination_role    VARCHAR(80) NOT NULL,
    protocol            VARCHAR(8) NOT NULL,
    port_from           INTEGER NOT NULL,
    port_to             INTEGER NOT NULL,
    action              VARCHAR(8) NOT NULL,
    description         TEXT NOT NULL,

    CONSTRAINT uq_micro_rule_key
        UNIQUE (revision_id, rule_key),

    CONSTRAINT uq_micro_rule_priority
        UNIQUE (revision_id, priority),

    CONSTRAINT ck_micro_protocol
        CHECK (protocol IN ('TCP', 'UDP')),

    CONSTRAINT ck_micro_ports
        CHECK (
            port_from BETWEEN 1 AND 65535
            AND port_to BETWEEN port_from AND 65535
        ),

    CONSTRAINT ck_micro_action
        CHECK (action IN ('ALLOW', 'DENY'))
);


CREATE INDEX idx_micro_rule_lookup
    ON micro_rules(
        revision_id,
        source_role,
        destination_role,
        priority
    );


CREATE TRIGGER trg_draft_micro_rule
BEFORE INSERT OR UPDATE OR DELETE ON micro_rules
FOR EACH ROW
EXECUTE FUNCTION enforce_draft_policy_revision();


/* ================================================================
   5. TRAFFIC AUDIT MODEL
   ================================================================ */

CREATE TABLE flow_audit (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    revision_id         BIGINT NOT NULL
                        REFERENCES policy_revisions(id),
    flow_key            VARCHAR(100) NOT NULL,
    source_endpoint_id  BIGINT NOT NULL REFERENCES endpoints(id),
    destination_endpoint_id BIGINT NOT NULL REFERENCES endpoints(id),
    protocol            VARCHAR(8) NOT NULL,
    destination_port    INTEGER NOT NULL,
    traffic_class       VARCHAR(20) NOT NULL,
    network_result      VARCHAR(20) NOT NULL,
    micro_result        VARCHAR(8) NOT NULL,
    final_decision      VARCHAR(8) NOT NULL,
    decision_reason     VARCHAR(100) NOT NULL,
    evaluated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_flow_per_revision
        UNIQUE (revision_id, flow_key),

    CONSTRAINT ck_audit_protocol
        CHECK (protocol IN ('TCP', 'UDP')),

    CONSTRAINT ck_audit_port
        CHECK (destination_port BETWEEN 1 AND 65535),

    CONSTRAINT ck_traffic_class
        CHECK (
            traffic_class IN (
                'NORTH_SOUTH',
                'EAST_WEST',
                'INTRA_SEGMENT'
            )
        ),

    CONSTRAINT ck_network_result
        CHECK (
            network_result IN (
                'ALLOW',
                'DENY',
                'NOT_REQUIRED'
            )
        ),

    CONSTRAINT ck_micro_result
        CHECK (micro_result IN ('ALLOW', 'DENY')),

    CONSTRAINT ck_final_decision
        CHECK (final_decision IN ('ALLOW', 'DENY'))
);


CREATE INDEX idx_flow_audit_time
    ON flow_audit(evaluated_at DESC);

CREATE INDEX idx_flow_audit_decision
    ON flow_audit(final_decision, traffic_class);


/* ================================================================
   6. POLICY ACTIVATION AND TRAFFIC EVALUATION
   ================================================================ */

/*
 * Returns:
 *   traffic_class
 *   network_result
 *   micro_result
 *   final_decision
 *   decision_reason
 *
 * For traffic crossing VLAN boundaries:
 *   final decision = network boundary result AND microsegmentation result
 *
 * For traffic within one VLAN:
 *   network boundary filtering is not applicable, but workload-level
 *   microsegmentation remains mandatory.
 *
 * Missing rules result in DENY.
 */

CREATE OR REPLACE FUNCTION evaluate_flow(
    p_revision_id BIGINT,
    p_source_endpoint_id BIGINT,
    p_destination_endpoint_id BIGINT,
    p_protocol VARCHAR,
    p_destination_port INTEGER,
    p_flow_key VARCHAR
)
RETURNS TABLE (
    traffic_class TEXT,
    network_result TEXT,
    micro_result TEXT,
    final_decision TEXT,
    decision_reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_revision_state VARCHAR(16);

    v_source_segment BIGINT;
    v_destination_segment BIGINT;

    v_source_zone VARCHAR(24);
    v_destination_zone VARCHAR(24);

    v_source_role VARCHAR(80);
    v_destination_role VARCHAR(80);

    v_network_action VARCHAR(8);
    v_micro_action VARCHAR(8);

    v_traffic_class TEXT;
    v_network_result TEXT;
    v_micro_result TEXT;
    v_final_decision TEXT;
    v_decision_reason TEXT;

BEGIN
    IF p_protocol NOT IN ('TCP', 'UDP') THEN
        RAISE EXCEPTION 'Unsupported protocol: %.', p_protocol;
    END IF;

    IF p_destination_port NOT BETWEEN 1 AND 65535 THEN
        RAISE EXCEPTION 'Destination port must be between 1 and 65535.';
    END IF;

    IF p_flow_key IS NULL OR length(trim(p_flow_key)) = 0 THEN
        RAISE EXCEPTION 'Flow key is required.';
    END IF;

    SELECT state
    INTO v_revision_state
    FROM policy_revisions
    WHERE id = p_revision_id;

    IF NOT FOUND OR v_revision_state <> 'ACTIVE' THEN
        RAISE EXCEPTION 'An active policy revision is required.';
    END IF;

    SELECT
        endpoint.segment_id,
        segment.trust_zone,
        endpoint.labels ->> 'role'
    INTO
        v_source_segment,
        v_source_zone,
        v_source_role
    FROM endpoints endpoint
    JOIN segments segment
      ON segment.id = endpoint.segment_id
    WHERE endpoint.id = p_source_endpoint_id
      AND endpoint.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Source endpoint % does not exist or is inactive.',
            p_source_endpoint_id;
    END IF;

    SELECT
        endpoint.segment_id,
        segment.trust_zone,
        endpoint.labels ->> 'role'
    INTO
        v_destination_segment,
        v_destination_zone,
        v_destination_role
    FROM endpoints endpoint
    JOIN segments segment
      ON segment.id = endpoint.segment_id
    WHERE endpoint.id = p_destination_endpoint_id
      AND endpoint.active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Destination endpoint % does not exist or is inactive.',
            p_destination_endpoint_id;
    END IF;

    IF (
        v_source_zone = 'INTERNET'
        OR v_destination_zone = 'INTERNET'
    ) THEN
        v_traffic_class := 'NORTH_SOUTH';
    ELSIF v_source_segment = v_destination_segment THEN
        v_traffic_class := 'INTRA_SEGMENT';
    ELSE
        v_traffic_class := 'EAST_WEST';
    END IF;

    /*
     * First enforcement layer: inter-VLAN boundary control.
     */

    IF v_source_segment = v_destination_segment THEN
        v_network_action := 'ALLOW';
        v_network_result := 'NOT_REQUIRED';
    ELSE
        SELECT action
        INTO v_network_action
        FROM network_rules
        WHERE revision_id = p_revision_id
          AND source_zone = v_source_zone
          AND destination_zone = v_destination_zone
          AND protocol = p_protocol
          AND p_destination_port BETWEEN port_from AND port_to
        ORDER BY priority, id
        LIMIT 1;

        v_network_action := COALESCE(v_network_action, 'DENY');
        v_network_result := v_network_action;
    END IF;

    /*
     * Second enforcement layer: workload identity and service access.
     * Wildcard selectors are supported for deliberately broad rules.
     */

    SELECT action
    INTO v_micro_action
    FROM micro_rules
    WHERE revision_id = p_revision_id
      AND source_role IN (v_source_role, '*')
      AND destination_role IN (v_destination_role, '*')
      AND protocol = p_protocol
      AND p_destination_port BETWEEN port_from AND port_to
    ORDER BY priority, id
    LIMIT 1;

    v_micro_action := COALESCE(v_micro_action, 'DENY');
    v_micro_result := v_micro_action;

    IF (
        v_network_action = 'ALLOW'
        AND v_micro_action = 'ALLOW'
    ) THEN
        v_final_decision := 'ALLOW';
        v_decision_reason := 'BOTH_POLICY_LAYERS_ALLOW';
    ELSIF v_network_action = 'DENY' THEN
        v_final_decision := 'DENY';
        v_decision_reason := 'NETWORK_BOUNDARY_DENY';
    ELSE
        v_final_decision := 'DENY';
        v_decision_reason := 'MICROSEGMENTATION_DEFAULT_DENY';
    END IF;

    INSERT INTO flow_audit (
        revision_id,
        flow_key,
        source_endpoint_id,
        destination_endpoint_id,
        protocol,
        destination_port,
        traffic_class,
        network_result,
        micro_result,
        final_decision,
        decision_reason
    )
    VALUES (
        p_revision_id,
        p_flow_key,
        p_source_endpoint_id,
        p_destination_endpoint_id,
        p_protocol,
        p_destination_port,
        v_traffic_class,
        v_network_result,
        v_micro_result,
        v_final_decision,
        v_decision_reason
    );

    RETURN QUERY
    SELECT
        v_traffic_class,
        v_network_result,
        v_micro_result,
        v_final_decision,
        v_decision_reason;
END;
$$;


/* ================================================================
   7. OPERATIONAL AND SECURITY VIEWS
   ================================================================ */

CREATE OR REPLACE VIEW v_segment_inventory AS
SELECT
    segment.id,
    segment.segment_key,
    segment.name,
    segment.vlan_id,
    segment.network,
    segment.trust_zone,
    COUNT(endpoint.id) FILTER (
        WHERE endpoint.active = TRUE
    ) AS active_endpoint_count
FROM segments segment
LEFT JOIN endpoints endpoint
    ON endpoint.segment_id = segment.id
GROUP BY
    segment.id,
    segment.segment_key,
    segment.name,
    segment.vlan_id,
    segment.network,
    segment.trust_zone;


CREATE OR REPLACE VIEW v_active_policy_summary AS
SELECT
    revision.id AS revision_id,
    revision.policy_name,
    revision.version,
    revision.state,
    revision.created_by,
    revision.activated_at,
    COUNT(DISTINCT network_rule.id) AS network_rule_count,
    COUNT(DISTINCT micro_rule.id) AS micro_rule_count,
    COUNT(DISTINCT approval.id) AS approval_count
FROM policy_revisions revision
LEFT JOIN network_rules network_rule
    ON network_rule.revision_id = revision.id
LEFT JOIN micro_rules micro_rule
    ON micro_rule.revision_id = revision.id
LEFT JOIN policy_approvals approval
    ON approval.revision_id = revision.id
WHERE revision.state = 'ACTIVE'
GROUP BY
    revision.id,
    revision.policy_name,
    revision.version,
    revision.state,
    revision.created_by,
    revision.activated_at;


CREATE OR REPLACE VIEW v_flow_security_report AS
SELECT
    audit.flow_key,
    source.endpoint_key AS source_endpoint,
    source.labels ->> 'role' AS source_role,
    destination.endpoint_key AS destination_endpoint,
    destination.labels ->> 'role' AS destination_role,
    audit.protocol,
    audit.destination_port,
    audit.traffic_class,
    audit.network_result,
    audit.micro_result,
    audit.final_decision,
    audit.decision_reason,
    audit.evaluated_at
FROM flow_audit audit
JOIN endpoints source
    ON source.id = audit.source_endpoint_id
JOIN endpoints destination
    ON destination.id = audit.destination_endpoint_id;


/* ================================================================
   8. SAMPLE NETWORK INVENTORY
   ================================================================ */

INSERT INTO segments (
    segment_key,
    name,
    vlan_id,
    network,
    trust_zone
)
VALUES
    (
        'USERS',
        'Corporate User VLAN',
        10,
        '10.10.0.0/24',
        'USER'
    ),
    (
        'DMZ',
        'Public Application DMZ',
        20,
        '10.20.0.0/24',
        'DMZ'
    ),
    (
        'APPLICATIONS',
        'Application Workload VLAN',
        30,
        '10.30.0.0/24',
        'APPLICATION'
    ),
    (
        'DATABASES',
        'Restricted Database VLAN',
        40,
        '10.40.0.0/24',
        'DATA'
    ),
    (
        'MANAGEMENT',
        'Administrative Management VLAN',
        50,
        '10.50.0.0/24',
        'MANAGEMENT'
    ),
    (
        'EXTERNAL',
        'External Test Network',
        900,
        '198.51.100.0/24',
        'INTERNET'
    );


INSERT INTO endpoints (
    endpoint_key,
    segment_id,
    hostname,
    ip_address,
    labels
)
VALUES
    (
        'workstation-01',
        (SELECT id FROM segments WHERE segment_key = 'USERS'),
        'user-workstation-01',
        '10.10.0.10',
        '{"role": "employee", "environment": "production"}'
    ),
    (
        'web-01',
        (SELECT id FROM segments WHERE segment_key = 'DMZ'),
        'public-web-01',
        '10.20.0.10',
        '{"role": "web", "environment": "production"}'
    ),
    (
        'api-01',
        (SELECT id FROM segments WHERE segment_key = 'APPLICATIONS'),
        'application-api-01',
        '10.30.0.10',
        '{"role": "api", "environment": "production"}'
    ),
    (
        'api-02',
        (SELECT id FROM segments WHERE segment_key = 'APPLICATIONS'),
        'application-api-02',
        '10.30.0.11',
        '{"role": "api", "environment": "production"}'
    ),
    (
        'db-01',
        (SELECT id FROM segments WHERE segment_key = 'DATABASES'),
        'customer-db-01',
        '10.40.0.10',
        '{"role": "database", "environment": "production"}'
    ),
    (
        'admin-01',
        (SELECT id FROM segments WHERE segment_key = 'MANAGEMENT'),
        'management-admin-01',
        '10.50.0.10',
        '{"role": "administrator", "environment": "management"}'
    ),
    (
        'external-client',
        (SELECT id FROM segments WHERE segment_key = 'EXTERNAL'),
        'external-test-client',
        '198.51.100.10',
        '{"role": "internet-client", "environment": "external"}'
    );


/* ================================================================
   9. CREATE A DRAFT POLICY REVISION
   ================================================================ */

INSERT INTO policy_revisions (
    policy_name,
    version,
    created_by,
    state
)
VALUES (
    'PRODUCTION-NETWORK-SEGMENTATION',
    1,
    'release-bot',
    'DRAFT'
);


/* ================================================================
   10. CONFIGURE APPROVAL REQUIREMENTS
   ================================================================ */

INSERT INTO approval_requirements (
    revision_id,
    required_role
)
SELECT id, 'NETWORK_SECURITY'
FROM policy_revisions
WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND version = 1;


INSERT INTO approval_requirements (
    revision_id,
    required_role
)
SELECT id, 'PLATFORM_OPERATIONS'
FROM policy_revisions
WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND version = 1;


/* ================================================================
   11. CONFIGURE VLAN BOUNDARY RULES
   ================================================================ */

INSERT INTO network_rules (
    revision_id,
    rule_key,
    priority,
    source_zone,
    destination_zone,
    protocol,
    port_from,
    port_to,
    action,
    description
)
SELECT
    revision.id,
    rules.rule_key,
    rules.priority,
    rules.source_zone,
    rules.destination_zone,
    rules.protocol,
    rules.port_from,
    rules.port_to,
    rules.action,
    rules.description
FROM policy_revisions revision
CROSS JOIN (
    VALUES
        (
            'NET-001',
            10,
            'INTERNET',
            'DMZ',
            'TCP',
            443,
            443,
            'ALLOW',
            'External HTTPS access to the DMZ web tier'
        ),
        (
            'NET-002',
            20,
            'USER',
            'DMZ',
            'TCP',
            443,
            443,
            'ALLOW',
            'Corporate HTTPS access to the DMZ'
        ),
        (
            'NET-003',
            30,
            'DMZ',
            'APPLICATION',
            'TCP',
            8443,
            8443,
            'ALLOW',
            'DMZ web tier to application API'
        ),
        (
            'NET-004',
            40,
            'APPLICATION',
            'DATA',
            'TCP',
            5432,
            5432,
            'ALLOW',
            'Application database connectivity'
        ),
        (
            'NET-005',
            50,
            'MANAGEMENT',
            'APPLICATION',
            'TCP',
            22,
            22,
            'ALLOW',
            'Authorized administrative SSH access'
        )
) AS rules(
    rule_key,
    priority,
    source_zone,
    destination_zone,
    protocol,
    port_from,
    port_to,
    action,
    description
)
WHERE revision.policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND revision.version = 1;


/* ================================================================
   12. CONFIGURE WORKLOAD MICROSEGMENTATION
   ================================================================ */

INSERT INTO micro_rules (
    revision_id,
    rule_key,
    priority,
    source_role,
    destination_role,
    protocol,
    port_from,
    port_to,
    action,
    description
)
SELECT
    revision.id,
    rules.rule_key,
    rules.priority,
    rules.source_role,
    rules.destination_role,
    rules.protocol,
    rules.port_from,
    rules.port_to,
    rules.action,
    rules.description
FROM policy_revisions revision
CROSS JOIN (
    VALUES
        (
            'MICRO-001',
            10,
            'internet-client',
            'web',
            'TCP',
            443,
            443,
            'ALLOW',
            'External client to public web service'
        ),
        (
            'MICRO-002',
            20,
            'employee',
            'web',
            'TCP',
            443,
            443,
            'ALLOW',
            'Employee access to public web service'
        ),
        (
            'MICRO-003',
            30,
            'web',
            'api',
            'TCP',
            8443,
            8443,
            'ALLOW',
            'Web workload to application API'
        ),
        (
            'MICRO-004',
            40,
            'api',
            'database',
            'TCP',
            5432,
            5432,
            'ALLOW',
            'API workload to database service'
        ),
        (
            'MICRO-005',
            50,
            'administrator',
            'api',
            'TCP',
            22,
            22,
            'ALLOW',
            'Authorized administrator to application host'
        )
) AS rules(
    rule_key,
    priority,
    source_role,
    destination_role,
    protocol,
    port_from,
    port_to,
    action,
    description
)
WHERE revision.policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND revision.version = 1;


/* ================================================================
   13. APPROVAL WORKFLOW
   ================================================================ */

/*
 * Different principals approve the revision.
 * The revision creator is release-bot, not an approver.
 */

INSERT INTO policy_approvals (
    revision_id,
    approver,
    approver_role
)
SELECT id, 'security-reviewer', 'NETWORK_SECURITY'
FROM policy_revisions
WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND version = 1;


INSERT INTO policy_approvals (
    revision_id,
    approver,
    approver_role
)
SELECT id, 'operations-reviewer', 'PLATFORM_OPERATIONS'
FROM policy_revisions
WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND version = 1;


/*
 * Activation fails unless every configured organizational role
 * has supplied an approval.
 */

SELECT activate_policy_revision(id)
FROM policy_revisions
WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
  AND version = 1;


/* ================================================================
   14. EVALUATE REALISTIC TRAFFIC FLOWS
   ================================================================ */

/*
 * FLOW-001: External HTTPS to the public web server.
 * Expected: ALLOW
 */

SELECT
    'FLOW-001 external-to-web' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'external-client'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'web-01'),
    'TCP',
    443,
    'FLOW-001'
) AS result;


/*
 * FLOW-002: Corporate user to the public web server.
 * Expected: ALLOW
 */

SELECT
    'FLOW-002 user-to-web' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'workstation-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'web-01'),
    'TCP',
    443,
    'FLOW-002'
) AS result;


/*
 * FLOW-003: DMZ web server to the application API.
 * Expected: ALLOW
 */

SELECT
    'FLOW-003 web-to-api' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'web-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'api-01'),
    'TCP',
    8443,
    'FLOW-003'
) AS result;


/*
 * FLOW-004: Application API to its database.
 * Expected: ALLOW
 */

SELECT
    'FLOW-004 api-to-database' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'api-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'db-01'),
    'TCP',
    5432,
    'FLOW-004'
) AS result;


/*
 * FLOW-005: DMZ web server attempts direct database access.
 * Expected: DENY at the network boundary.
 */

SELECT
    'FLOW-005 web-to-database' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'web-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'db-01'),
    'TCP',
    5432,
    'FLOW-005'
) AS result;


/*
 * FLOW-006: One API workload attempts an unauthorized connection
 * to another API workload inside the same VLAN.
 *
 * There is no inter-VLAN filtering requirement because both endpoints
 * share a segment. Microsegmentation still denies the connection.
 *
 * Expected: DENY.
 */

SELECT
    'FLOW-006 intra-vlan-api' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'api-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'api-02'),
    'TCP',
    8080,
    'FLOW-006'
) AS result;


/*
 * FLOW-007: Authorized management endpoint uses SSH to reach an API host.
 * Expected: ALLOW
 */

SELECT
    'FLOW-007 management-to-api' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'admin-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'api-01'),
    'TCP',
    22,
    'FLOW-007'
) AS result;


/*
 * FLOW-008: Application API attempts database access on an
 * unauthorized service port.
 * Expected: DENY.
 */

SELECT
    'FLOW-008 api-to-database-wrong-port' AS scenario,
    result.*
FROM evaluate_flow(
    (SELECT id FROM policy_revisions
     WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
       AND version = 1),
    (SELECT id FROM endpoints WHERE endpoint_key = 'api-01'),
    (SELECT id FROM endpoints WHERE endpoint_key = 'db-01'),
    'TCP',
    443,
    'FLOW-008'
) AS result;


/* ================================================================
   15. RETRIEVAL AND INVENTORY REPORTING
   ================================================================ */

SELECT
    segment_key,
    name,
    vlan_id,
    network,
    trust_zone,
    active_endpoint_count
FROM v_segment_inventory
ORDER BY vlan_id;


/* Active policy and approval overview. */

SELECT
    revision_id,
    policy_name,
    version,
    state,
    created_by,
    network_rule_count,
    micro_rule_count,
    approval_count,
    activated_at
FROM v_active_policy_summary;


/* ================================================================
   16. VALIDATION AND POLICY CONFIGURATION REPORTING
   ================================================================ */

SELECT
    revision.policy_name,
    revision.version,
    requirement.required_role,
    COUNT(approval.id) AS received_approvals,
    CASE
        WHEN COUNT(approval.id) > 0 THEN 'SATISFIED'
        ELSE 'MISSING'
    END AS approval_status
FROM policy_revisions revision
JOIN approval_requirements requirement
    ON requirement.revision_id = revision.id
LEFT JOIN policy_approvals approval
    ON approval.revision_id = requirement.revision_id
   AND approval.approver_role = requirement.required_role
WHERE revision.policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
GROUP BY
    revision.policy_name,
    revision.version,
    requirement.required_role
ORDER BY requirement.required_role;


/* Retrieve network-boundary rules. */

SELECT
    rule_key,
    priority,
    source_zone,
    destination_zone,
    protocol,
    port_from,
    port_to,
    action,
    description
FROM network_rules
WHERE revision_id = (
    SELECT id
    FROM policy_revisions
    WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
      AND version = 1
)
ORDER BY priority;


/* Retrieve workload-level rules. */

SELECT
    rule_key,
    priority,
    source_role,
    destination_role,
    protocol,
    port_from,
    port_to,
    action,
    description
FROM micro_rules
WHERE revision_id = (
    SELECT id
    FROM policy_revisions
    WHERE policy_name = 'PRODUCTION-NETWORK-SEGMENTATION'
      AND version = 1
)
ORDER BY priority;


/* ================================================================
   17. FLOW ANALYSIS AND SECURITY AGGREGATION
   ================================================================ */

/* Allow/deny counts by traffic classification. */

SELECT
    traffic_class,
    COUNT(*) AS total_flows,
    COUNT(*) FILTER (
        WHERE final_decision = 'ALLOW'
    ) AS allowed_flows,
    COUNT(*) FILTER (
        WHERE final_decision = 'DENY'
    ) AS denied_flows
FROM flow_audit
GROUP BY traffic_class
ORDER BY traffic_class;


/* Inspect policy-denied traffic. */

SELECT
    flow_key,
    source_endpoint,
    source_role,
    destination_endpoint,
    destination_role,
    destination_port,
    traffic_class,
    network_result,
    micro_result,
    decision_reason,
    evaluated_at
FROM v_flow_security_report
WHERE final_decision = 'DENY'
ORDER BY evaluated_at;


/* Identify workloads generating repeated denied connections. */

SELECT
    source_endpoint,
    source_role,
    COUNT(*) AS denied_attempts
FROM v_flow_security_report
WHERE final_decision = 'DENY'
GROUP BY source_endpoint, source_role
ORDER BY denied_attempts DESC, source_endpoint;


/* ================================================================
   18. CTE-BASED SECURITY REPORTING
   ================================================================ */

WITH traffic_summary AS (
    SELECT
        traffic_class,
        COUNT(*) AS flow_count,
        COUNT(*) FILTER (
            WHERE final_decision = 'ALLOW'
        ) AS allowed_count,
        COUNT(*) FILTER (
            WHERE final_decision = 'DENY'
        ) AS denied_count
    FROM flow_audit
    GROUP BY traffic_class
),
security_metrics AS (
    SELECT
        SUM(flow_count) AS total_flows,
        SUM(allowed_count) AS allowed_flows,
        SUM(denied_count) AS denied_flows
    FROM traffic_summary
)
SELECT
    total_flows,
    allowed_flows,
    denied_flows,
    ROUND(
        100.0 * denied_flows / NULLIF(total_flows, 0),
        2
    ) AS denied_percentage
FROM security_metrics;


/* ================================================================
   19. FINAL POLICY AND AUDIT STATE
   ================================================================ */

SELECT
    revision.id AS revision_id,
    revision.policy_name,
    revision.version,
    revision.state,
    COUNT(DISTINCT network_rule.id) AS network_rules,
    COUNT(DISTINCT micro_rule.id) AS microsegmentation_rules,
    COUNT(DISTINCT approval.id) AS approvals,
    COUNT(DISTINCT audit.id) AS evaluated_flows
FROM policy_revisions revision
LEFT JOIN network_rules network_rule
    ON network_rule.revision_id = revision.id
LEFT JOIN micro_rules micro_rule
    ON micro_rule.revision_id = revision.id
LEFT JOIN policy_approvals approval
    ON approval.revision_id = revision.id
LEFT JOIN flow_audit audit
    ON audit.revision_id = revision.id
GROUP BY
    revision.id,
    revision.policy_name,
    revision.version,
    revision.state
ORDER BY revision.id;


COMMIT;
