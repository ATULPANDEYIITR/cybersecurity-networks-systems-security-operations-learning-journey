DROP SCHEMA IF EXISTS firewall_lab CASCADE;

CREATE SCHEMA firewall_lab;

SET search_path TO firewall_lab, public;

CREATE TYPE firewall_action AS ENUM ('ALLOW', 'DENY');
CREATE TYPE protocol_type AS ENUM ('TCP', 'UDP', 'ICMP');
CREATE TYPE direction_type AS ENUM ('INBOUND', 'OUTBOUND');
CREATE TYPE firewall_state AS ENUM ('NEW', 'ESTABLISHED');

CREATE TABLE repositories (
    repository_id BIGSERIAL PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE zones (
    zone_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    zone_name TEXT NOT NULL,
    trust_level SMALLINT NOT NULL,
    UNIQUE (repository_id, zone_name),
    CHECK (trust_level BETWEEN 0 AND 100)
);

CREATE TABLE networks (
    network_id BIGSERIAL PRIMARY KEY,
    zone_id BIGINT NOT NULL REFERENCES zones(zone_id)
        ON DELETE CASCADE,
    cidr CIDR NOT NULL,
    UNIQUE (zone_id, cidr)
);

CREATE TABLE firewall_rules (
    rule_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    rule_order INTEGER NOT NULL,
    action firewall_action NOT NULL,
    protocol protocol_type,
    source_network CIDR,
    destination_network CIDR,
    source_port INTEGER,
    destination_port INTEGER,
    direction direction_type,
    interface_name TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (repository_id, rule_name),
    UNIQUE (repository_id, rule_order),

    CHECK (rule_order > 0),
    CHECK (
        source_port IS NULL OR
        source_port BETWEEN 1 AND 65535
    ),
    CHECK (
        destination_port IS NULL OR
        destination_port BETWEEN 1 AND 65535
    ),
    CHECK (
        protocol IN ('TCP', 'UDP') OR
        (source_port IS NULL AND destination_port IS NULL)
    )
);

CREATE TABLE connections (
    connection_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    protocol protocol_type NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    state firewall_state NOT NULL DEFAULT 'NEW',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        protocol IN ('TCP', 'UDP') OR
        (source_port IS NULL AND destination_port IS NULL)
    ),
    CHECK (
        source_port IS NULL OR
        source_port BETWEEN 1 AND 65535
    ),
    CHECK (
        destination_port IS NULL OR
        destination_port BETWEEN 1 AND 65535
    )
);

CREATE TABLE packets (
    packet_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    connection_id BIGINT REFERENCES connections(connection_id)
        ON DELETE SET NULL,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    protocol protocol_type NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    direction direction_type NOT NULL,
    interface_name TEXT NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (
        protocol IN ('TCP', 'UDP') OR
        (source_port IS NULL AND destination_port IS NULL)
    ),
    CHECK (
        source_port IS NULL OR
        source_port BETWEEN 1 AND 65535
    ),
    CHECK (
        destination_port IS NULL OR
        destination_port BETWEEN 1 AND 65535
    )
);

CREATE TABLE packet_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    packet_id BIGINT NOT NULL REFERENCES packets(packet_id)
        ON DELETE CASCADE,
    rule_id BIGINT REFERENCES firewall_rules(rule_id)
        ON DELETE SET NULL,
    action firewall_action NOT NULL,
    reason TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE zone_policies (
    zone_policy_id BIGSERIAL PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    source_zone_id BIGINT NOT NULL REFERENCES zones(zone_id)
        ON DELETE CASCADE,
    destination_zone_id BIGINT NOT NULL REFERENCES zones(zone_id)
        ON DELETE CASCADE,
    action firewall_action NOT NULL,
    protocol protocol_type,
    destination_port INTEGER,

    CHECK (
        destination_port IS NULL OR
        destination_port BETWEEN 1 AND 65535
    )
);

CREATE INDEX idx_firewall_rules_repository_order
    ON firewall_rules(repository_id, rule_order)
    WHERE enabled = TRUE;

CREATE INDEX idx_packets_repository_time
    ON packets(repository_id, evaluated_at DESC);

CREATE INDEX idx_packet_decisions_packet
    ON packet_decisions(packet_id);

CREATE INDEX idx_connections_flow
    ON connections(
        repository_id,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port
    );

CREATE INDEX idx_networks_zone
    ON networks(zone_id);

INSERT INTO repositories (
    repository_name,
    description
)
VALUES (
    'edge-security',
    'Example enterprise perimeter and internal firewall policy'
);

INSERT INTO zones (
    repository_id,
    zone_name,
    trust_level
)
SELECT
    repository_id,
    zone_name,
    trust_level
FROM repositories
CROSS JOIN (
    VALUES
        ('INTERNET', 10),
        ('DMZ', 50),
        ('INTERNAL', 90)
) AS values_list(zone_name, trust_level)
WHERE repository_name = 'edge-security';

INSERT INTO networks (zone_id, cidr)
SELECT z.zone_id, values_list.cidr::CIDR
FROM zones z
JOIN repositories r
    ON r.repository_id = z.repository_id
JOIN (
    VALUES
        ('INTERNET', '0.0.0.0/1'),
        ('INTERNET', '128.0.0.0/1'),
        ('DMZ', '10.0.10.0/24'),
        ('INTERNAL', '10.0.20.0/24')
) AS values_list(zone_name, cidr)
    ON values_list.zone_name = z.zone_name
WHERE r.repository_name = 'edge-security';

INSERT INTO firewall_rules (
    repository_id,
    rule_name,
    rule_order,
    action,
    protocol,
    source_network,
    destination_network,
    source_port,
    destination_port,
    direction,
    interface_name
)
SELECT
    r.repository_id,
    rules.rule_name,
    rules.rule_order,
    rules.action::firewall_action,
    rules.protocol::protocol_type,
    rules.source_network::CIDR,
    rules.destination_network::CIDR,
    rules.source_port,
    rules.destination_port,
    rules.direction::direction_type,
    rules.interface_name
FROM repositories r
CROSS JOIN (
    VALUES
        (
            'ALLOW-HTTPS-INBOUND',
            10,
            'ALLOW',
            'TCP',
            NULL,
            '10.0.10.0/24',
            NULL,
            443,
            'INBOUND',
            'external'
        ),
        (
            'ALLOW-DNS-OUTBOUND',
            20,
            'ALLOW',
            'UDP',
            '10.0.20.0/24',
            NULL,
            NULL,
            53,
            'OUTBOUND',
            'internal'
        ),
        (
            'DENY-TELNET',
            30,
            'DENY',
            'TCP',
            NULL,
            NULL,
            NULL,
            23,
            NULL,
            NULL
        )
) AS rules(
    rule_name,
    rule_order,
    action,
    protocol,
    source_network,
    destination_network,
    source_port,
    destination_port,
    direction,
    interface_name
)
WHERE r.repository_name = 'edge-security';

INSERT INTO zone_policies (
    repository_id,
    source_zone_id,
    destination_zone_id,
    action,
    protocol,
    destination_port
)
SELECT
    r.repository_id,
    source_zone.zone_id,
    destination_zone.zone_id,
    policy.action::firewall_action,
    policy.protocol::protocol_type,
    policy.destination_port
FROM repositories r
CROSS JOIN (
    VALUES
        ('INTERNET', 'DMZ', 'ALLOW', 'TCP', 443),
        ('INTERNAL', 'INTERNET', 'ALLOW', 'TCP', 443),
        ('INTERNAL', 'INTERNET', 'ALLOW', 'UDP', 53)
) AS policy(
    source_zone,
    destination_zone,
    action,
    protocol,
    destination_port
)
JOIN zones source_zone
    ON source_zone.repository_id = r.repository_id
    AND source_zone.zone_name = policy.source_zone
JOIN zones destination_zone
    ON destination_zone.repository_id = r.repository_id
    AND destination_zone.zone_name = policy.destination_zone
WHERE r.repository_name = 'edge-security';

INSERT INTO connections (
    repository_id,
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    state
)
SELECT
    repository_id,
    '10.0.20.10',
    '198.51.100.20',
    'TCP',
    51000,
    443,
    'ESTABLISHED'
FROM repositories
WHERE repository_name = 'edge-security';

INSERT INTO packets (
    repository_id,
    connection_id,
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    direction,
    interface_name
)
SELECT
    r.repository_id,
    c.connection_id,
    packet.source_ip::INET,
    packet.destination_ip::INET,
    packet.protocol::protocol_type,
    packet.source_port,
    packet.destination_port,
    packet.direction::direction_type,
    packet.interface_name
FROM repositories r
JOIN connections c
    ON c.repository_id = r.repository_id
CROSS JOIN (
    VALUES
        (
            '203.0.113.10',
            '10.0.10.20',
            'TCP',
            45000,
            443,
            'INBOUND',
            'external'
        ),
        (
            '10.0.20.10',
            '198.51.100.20',
            'TCP',
            51000,
            443,
            'OUTBOUND',
            'internal'
        ),
        (
            '203.0.113.50',
            '10.0.20.25',
            'TCP',
            45001,
            22,
            'INBOUND',
            'external'
        ),
        (
            '203.0.113.50',
            '10.0.20.25',
            'TCP',
            45002,
            23,
            'INBOUND',
            'external'
        )
) AS packet(
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    direction,
    interface_name
)
WHERE r.repository_name = 'edge-security'
  AND (
      packet.source_ip::INET = c.source_ip
      OR packet.destination_ip::INET = c.destination_ip
      OR packet.destination_port = c.destination_port
  )
LIMIT 4;

CREATE OR REPLACE FUNCTION validate_packet_ports()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.protocol IN ('TCP', 'UDP') THEN
        IF NEW.source_port IS NULL OR NEW.destination_port IS NULL THEN
            RAISE EXCEPTION
                'TCP/UDP packets require source and destination ports';
        END IF;
    ELSE
        IF NEW.source_port IS NOT NULL OR NEW.destination_port IS NOT NULL THEN
            RAISE EXCEPTION
                'ICMP packets cannot contain ports';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_packet_ports
BEFORE INSERT OR UPDATE ON packets
FOR EACH ROW
EXECUTE FUNCTION validate_packet_ports();

CREATE OR REPLACE FUNCTION validate_connection_ports()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.protocol IN ('TCP', 'UDP') THEN
        IF NEW.source_port IS NULL OR NEW.destination_port IS NULL THEN
            RAISE EXCEPTION
                'TCP/UDP connections require ports';
        END IF;
    ELSE
        IF NEW.source_port IS NOT NULL OR NEW.destination_port IS NOT NULL THEN
            RAISE EXCEPTION
                'ICMP connections cannot contain ports';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_connection_ports
BEFORE INSERT OR UPDATE ON connections
FOR EACH ROW
EXECUTE FUNCTION validate_connection_ports();

CREATE OR REPLACE FUNCTION evaluate_packet(
    p_repository_id BIGINT,
    p_source_ip INET,
    p_destination_ip INET,
    p_protocol protocol_type,
    p_source_port INTEGER,
    p_destination_port INTEGER,
    p_direction direction_type,
    p_interface_name TEXT
)
RETURNS TABLE (
    decision firewall_action,
    matched_rule TEXT,
    reason TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        rule.action,
        rule.rule_name,
        'First matching rule'
    FROM firewall_rules rule
    WHERE rule.repository_id = p_repository_id
      AND rule.enabled
      AND (rule.protocol IS NULL OR rule.protocol = p_protocol)
      AND (
          rule.source_network IS NULL OR
          p_source_ip <<= rule.source_network
      )
      AND (
          rule.destination_network IS NULL OR
          p_destination_ip <<= rule.destination_network
      )
      AND (
          rule.source_port IS NULL OR
          rule.source_port = p_source_port
      )
      AND (
          rule.destination_port IS NULL OR
          rule.destination_port = p_destination_port
      )
      AND (
          rule.direction IS NULL OR
          rule.direction = p_direction
      )
      AND (
          rule.interface_name IS NULL OR
          rule.interface_name = p_interface_name
      )
    ORDER BY rule.rule_order
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN QUERY
        SELECT
            'DENY'::firewall_action,
            'DEFAULT-DENY'::TEXT,
            'No configured rule matched'::TEXT;
    END IF;
END;
$$;

CREATE OR REPLACE VIEW active_firewall_rules AS
SELECT
    r.repository_name,
    f.rule_order,
    f.rule_name,
    f.action,
    f.protocol,
    f.source_network,
    f.destination_network,
    f.destination_port,
    f.direction,
    f.interface_name
FROM firewall_rules f
JOIN repositories r
    ON r.repository_id = f.repository_id
WHERE f.enabled
ORDER BY
    r.repository_name,
    f.rule_order;

CREATE OR REPLACE VIEW firewall_decision_report AS
SELECT
    p.packet_id,
    r.repository_name,
    p.source_ip,
    p.destination_ip,
    p.protocol,
    p.source_port,
    p.destination_port,
    p.direction,
    d.action,
    COALESCE(fr.rule_name, 'DEFAULT-DENY') AS rule_name,
    d.reason,
    d.decided_at
FROM packet_decisions d
JOIN packets p
    ON p.packet_id = d.packet_id
JOIN repositories r
    ON r.repository_id = p.repository_id
LEFT JOIN firewall_rules fr
    ON fr.rule_id = d.rule_id;

-- Retrieve rules in evaluation order.
SELECT *
FROM active_firewall_rules
WHERE repository_name = 'edge-security';

-- Evaluate an explicitly permitted HTTPS packet.
SELECT *
FROM evaluate_packet(
    (
        SELECT repository_id
        FROM repositories
        WHERE repository_name = 'edge-security'
    ),
    '203.0.113.10',
    '10.0.10.20',
    'TCP',
    45000,
    443,
    'INBOUND',
    'external'
);

-- Evaluate an SSH packet that has no permit rule.
SELECT *
FROM evaluate_packet(
    (
        SELECT repository_id
        FROM repositories
        WHERE repository_name = 'edge-security'
    ),
    '203.0.113.10',
    '10.0.10.20',
    'TCP',
    45000,
    22,
    'INBOUND',
    'external'
);

-- Evaluate an explicitly denied Telnet packet.
SELECT *
FROM evaluate_packet(
    (
        SELECT repository_id
        FROM repositories
        WHERE repository_name = 'edge-security'
    ),
    '203.0.113.10',
    '10.0.10.20',
    'TCP',
    45000,
    23,
    'INBOUND',
    'external'
);

-- Show stateful connections.
SELECT
    repository_id,
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    state,
    last_seen
FROM connections
WHERE state = 'ESTABLISHED'
ORDER BY last_seen DESC;

-- Zone policy report.
SELECT
    repository_id,
    source_zone_id,
    destination_zone_id,
    action,
    protocol,
    destination_port
FROM zone_policies
ORDER BY
    repository_id,
    source_zone_id,
    destination_zone_id;

-- Aggregate current connection states.
SELECT
    repository_id,
    state,
    protocol,
    COUNT(*) AS connection_count
FROM connections
GROUP BY
    repository_id,
    state,
    protocol
ORDER BY
    repository_id,
    state,
    protocol;

-- Transactional example: disable a rule only after verifying its identity.
BEGIN;

UPDATE firewall_rules
SET enabled = FALSE
WHERE repository_id = (
    SELECT repository_id
    FROM repositories
    WHERE repository_name = 'edge-security'
)
AND rule_name = 'DENY-TELNET';

-- The transaction can be inspected before commit.
SELECT
    rule_name,
    enabled
FROM firewall_rules
WHERE rule_name = 'DENY-TELNET';

ROLLBACK;

-- The rollback preserves the original policy.
SELECT
    rule_name,
    enabled
FROM firewall_rules
WHERE rule_name = 'DENY-TELNET';

-- Database-level validation failure example.
-- This statement is intentionally not executed so the complete
-- operational dataset remains valid.
SELECT
    'TCP/UDP require ports; ICMP must not use ports' AS validation_rule;
