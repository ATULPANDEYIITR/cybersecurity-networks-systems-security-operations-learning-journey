-- Linux Networking relational model
-- PostgreSQL-compatible SQL
--
-- The schema models:
--   interfaces and addresses
--   routing entries
--   TCP/UDP sockets
--   DNS configuration
--   firewall chains and rules
--   firewall policy decisions
--
-- The database models networking state and policy. It does not attempt to
-- replace the Linux kernel, nftables, NetworkManager, or systemd-resolved.

DROP SCHEMA IF EXISTS linux_networking CASCADE;

CREATE SCHEMA linux_networking;

SET search_path TO linux_networking;

-- ---------------------------------------------------------------------------
-- Hosts and network interfaces
-- ---------------------------------------------------------------------------

CREATE TABLE hosts (
    host_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    environment TEXT NOT NULL
        CHECK (environment IN ('development', 'staging', 'production')),
    management_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE interfaces (
    interface_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    interface_name TEXT NOT NULL,
    mac_address MACADDR,
    mtu INTEGER NOT NULL DEFAULT 1500
        CHECK (mtu BETWEEN 576 AND 65535),
    admin_up BOOLEAN NOT NULL DEFAULT TRUE,
    link_up BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (host_id, interface_name)
);

CREATE TABLE interface_addresses (
    address_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    interface_id BIGINT NOT NULL
        REFERENCES interfaces(interface_id) ON DELETE CASCADE,
    address INET NOT NULL,
    prefix_length SMALLINT NOT NULL
        CHECK (prefix_length BETWEEN 0 AND 128),
    address_family SMALLINT NOT NULL
        CHECK (address_family IN (4, 6)),
    scope TEXT NOT NULL DEFAULT 'global'
        CHECK (scope IN ('host', 'link', 'global')),
    UNIQUE (interface_id, address)
);

CREATE INDEX idx_interface_addresses_address
    ON interface_addresses USING GIST (address inet_ops);

-- ---------------------------------------------------------------------------
-- Routing
-- ---------------------------------------------------------------------------

CREATE TABLE routes (
    route_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    destination CIDR NOT NULL,
    gateway INET,
    interface_id BIGINT REFERENCES interfaces(interface_id)
        ON DELETE SET NULL,
    metric INTEGER NOT NULL DEFAULT 100
        CHECK (metric >= 0),
    protocol TEXT NOT NULL
        CHECK (protocol IN ('kernel', 'static', 'dhcp', 'ra', 'dynamic')),
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_routes_destination
    ON routes USING GIST (destination inet_ops);

CREATE INDEX idx_routes_host_active
    ON routes(host_id, active);

-- ---------------------------------------------------------------------------
-- Sockets
-- ---------------------------------------------------------------------------

CREATE TABLE sockets (
    socket_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    protocol TEXT NOT NULL
        CHECK (protocol IN ('tcp', 'udp')),
    state TEXT NOT NULL,
    local_address INET NOT NULL,
    local_port INTEGER
        CHECK (local_port BETWEEN 1 AND 65535),
    peer_address INET,
    peer_port INTEGER
        CHECK (peer_port BETWEEN 1 AND 65535),
    process_name TEXT
);

CREATE INDEX idx_sockets_host_protocol
    ON sockets(host_id, protocol, state);

CREATE INDEX idx_sockets_local
    ON sockets(local_address, local_port);

-- ---------------------------------------------------------------------------
-- DNS configuration
-- ---------------------------------------------------------------------------

CREATE TABLE dns_configurations (
    dns_configuration_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    source TEXT NOT NULL
        CHECK (source IN (
            'resolv.conf',
            'systemd-resolved',
            'NetworkManager',
            'static'
        )),
    search_domain TEXT,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE(host_id, source, search_domain)
);

CREATE TABLE dns_nameservers (
    nameserver_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dns_configuration_id BIGINT NOT NULL
        REFERENCES dns_configurations(dns_configuration_id)
        ON DELETE CASCADE,
    nameserver INET NOT NULL,
    priority INTEGER NOT NULL
        CHECK (priority > 0),
    UNIQUE(dns_configuration_id, nameserver)
);

CREATE INDEX idx_dns_nameservers_priority
    ON dns_nameservers(dns_configuration_id, priority);

-- ---------------------------------------------------------------------------
-- Firewall configuration
-- ---------------------------------------------------------------------------

CREATE TABLE firewall_chains (
    chain_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    chain_name TEXT NOT NULL,
    family TEXT NOT NULL
        CHECK (family IN ('ip', 'ip6', 'inet')),
    hook TEXT,
    priority INTEGER,
    default_action TEXT NOT NULL DEFAULT 'drop'
        CHECK (default_action IN ('accept', 'drop')),
    UNIQUE(host_id, chain_name, family)
);

CREATE TABLE firewall_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    chain_id BIGINT NOT NULL
        REFERENCES firewall_chains(chain_id) ON DELETE CASCADE,
    rule_order INTEGER NOT NULL
        CHECK (rule_order > 0),
    protocol TEXT
        CHECK (protocol IS NULL OR protocol IN ('tcp', 'udp', 'icmp', 'icmpv6')),
    source_network CIDR,
    destination_network CIDR,
    source_port INTEGER
        CHECK (source_port IS NULL OR source_port BETWEEN 1 AND 65535),
    destination_port INTEGER
        CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
    action TEXT NOT NULL
        CHECK (action IN ('accept', 'drop', 'reject', 'log')),
    state_requirement TEXT,
    comment TEXT NOT NULL,
    UNIQUE(chain_id, rule_order)
);

CREATE INDEX idx_firewall_rules_chain_order
    ON firewall_rules(chain_id, rule_order);

CREATE INDEX idx_firewall_rules_source_network
    ON firewall_rules USING GIST (source_network inet_ops);

-- ---------------------------------------------------------------------------
-- Firewall decision audit
-- ---------------------------------------------------------------------------

CREATE TABLE firewall_decisions (
    decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_id BIGINT NOT NULL REFERENCES hosts(host_id) ON DELETE CASCADE,
    protocol TEXT NOT NULL
        CHECK (protocol IN ('tcp', 'udp', 'icmp', 'icmpv6')),
    source_address INET NOT NULL,
    source_port INTEGER
        CHECK (source_port IS NULL OR source_port BETWEEN 1 AND 65535),
    destination_address INET NOT NULL,
    destination_port INTEGER
        CHECK (destination_port IS NULL OR destination_port BETWEEN 1 AND 65535),
    selected_rule_id BIGINT REFERENCES firewall_rules(rule_id)
        ON DELETE SET NULL,
    decision TEXT NOT NULL
        CHECK (decision IN ('accept', 'drop', 'reject', 'no_match')),
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_firewall_decisions_host_time
    ON firewall_decisions(host_id, evaluated_at DESC);

-- ---------------------------------------------------------------------------
-- Seed realistic Linux hosts
-- ---------------------------------------------------------------------------

INSERT INTO hosts (
    hostname,
    environment,
    management_enabled
)
VALUES
    ('app-prod-01', 'production', TRUE),
    ('dns-prod-01', 'production', TRUE),
    ('dev-network-01', 'development', TRUE);

INSERT INTO interfaces (
    host_id,
    interface_name,
    mac_address,
    mtu,
    admin_up,
    link_up
)
SELECT
    host_id,
    'eth0',
    '02:42:ac:11:00:10',
    1500,
    TRUE,
    TRUE
FROM hosts
WHERE hostname = 'app-prod-01';

INSERT INTO interfaces (
    host_id,
    interface_name,
    mac_address,
    mtu,
    admin_up,
    link_up
)
SELECT
    host_id,
    'eth1',
    '02:42:ac:11:00:11',
    1500,
    TRUE,
    TRUE
FROM hosts
WHERE hostname = 'app-prod-01';

INSERT INTO interfaces (
    host_id,
    interface_name,
    mac_address,
    mtu,
    admin_up,
    link_up
)
SELECT
    host_id,
    'eth0',
    '02:42:ac:11:00:20',
    1500,
    TRUE,
    TRUE
FROM hosts
WHERE hostname = 'dns-prod-01';

-- ---------------------------------------------------------------------------
-- Interface addresses
-- ---------------------------------------------------------------------------

INSERT INTO interface_addresses (
    interface_id,
    address,
    prefix_length,
    address_family,
    scope
)
SELECT
    i.interface_id,
    '10.20.5.20',
    16,
    4,
    'global'
FROM interfaces i
JOIN hosts h ON h.host_id = i.host_id
WHERE h.hostname = 'app-prod-01'
  AND i.interface_name = 'eth0';

INSERT INTO interface_addresses (
    interface_id,
    address,
    prefix_length,
    address_family,
    scope
)
SELECT
    i.interface_id,
    '10.30.5.20',
    16,
    4,
    'global'
FROM interfaces i
JOIN hosts h ON h.host_id = i.host_id
WHERE h.hostname = 'app-prod-01'
  AND i.interface_name = 'eth1';

INSERT INTO interface_addresses (
    interface_id,
    address,
    prefix_length,
    address_family,
    scope
)
SELECT
    i.interface_id,
    '127.0.0.1',
    8,
    4,
    'host'
FROM interfaces i
JOIN hosts h ON h.host_id = i.host_id
WHERE h.hostname = 'app-prod-01'
  AND i.interface_name = 'eth0';

-- ---------------------------------------------------------------------------
-- Routes
-- ---------------------------------------------------------------------------

INSERT INTO routes (
    host_id,
    destination,
    gateway,
    interface_id,
    metric,
    protocol
)
SELECT
    h.host_id,
    '0.0.0.0/0',
    '10.20.0.1',
    i.interface_id,
    100,
    'static'
FROM hosts h
JOIN interfaces i
    ON i.host_id = h.host_id
   AND i.interface_name = 'eth0'
WHERE h.hostname = 'app-prod-01';

INSERT INTO routes (
    host_id,
    destination,
    gateway,
    interface_id,
    metric,
    protocol
)
SELECT
    h.host_id,
    '10.20.0.0/16',
    NULL,
    i.interface_id,
    0,
    'kernel'
FROM hosts h
JOIN interfaces i
    ON i.host_id = h.host_id
   AND i.interface_name = 'eth0'
WHERE h.hostname = 'app-prod-01';

INSERT INTO routes (
    host_id,
    destination,
    gateway,
    interface_id,
    metric,
    protocol
)
SELECT
    h.host_id,
    '10.30.0.0/16',
    NULL,
    i.interface_id,
    0,
    'kernel'
FROM hosts h
JOIN interfaces i
    ON i.host_id = h.host_id
   AND i.interface_name = 'eth1'
WHERE h.hostname = 'app-prod-01';

-- ---------------------------------------------------------------------------
-- Socket inventory
-- ---------------------------------------------------------------------------

INSERT INTO sockets (
    host_id,
    protocol,
    state,
    local_address,
    local_port,
    peer_address,
    peer_port,
    process_name
)
SELECT
    host_id,
    'tcp',
    'LISTEN',
    '0.0.0.0',
    443,
    NULL,
    NULL,
    'nginx'
FROM hosts
WHERE hostname = 'app-prod-01';

INSERT INTO sockets (
    host_id,
    protocol,
    state,
    local_address,
    local_port,
    peer_address,
    peer_port,
    process_name
)
SELECT
    host_id,
    'tcp',
    'ESTABLISHED',
    '10.20.5.20',
    443,
    '10.20.40.15',
    52144,
    'nginx'
FROM hosts
WHERE hostname = 'app-prod-01';

INSERT INTO sockets (
    host_id,
    protocol,
    state,
    local_address,
    local_port,
    peer_address,
    peer_port,
    process_name
)
SELECT
    host_id,
    'udp',
    'UNCONN',
    '10.20.5.20',
    53,
    NULL,
    NULL,
    'dns-service'
FROM hosts
WHERE hostname = 'dns-prod-01';

-- ---------------------------------------------------------------------------
-- DNS configuration
-- ---------------------------------------------------------------------------

INSERT INTO dns_configurations (
    host_id,
    source,
    search_domain
)
SELECT
    host_id,
    'systemd-resolved',
    'corp.example'
FROM hosts
WHERE hostname = 'app-prod-01';

INSERT INTO dns_nameservers (
    dns_configuration_id,
    nameserver,
    priority
)
SELECT
    dc.dns_configuration_id,
    '10.20.5.53',
    1
FROM dns_configurations dc
JOIN hosts h ON h.host_id = dc.host_id
WHERE h.hostname = 'app-prod-01';

INSERT INTO dns_nameservers (
    dns_configuration_id,
    nameserver,
    priority
)
SELECT
    dc.dns_configuration_id,
    '1.1.1.1',
    2
FROM dns_configurations dc
JOIN hosts h ON h.host_id = dc.host_id
WHERE h.hostname = 'app-prod-01';

-- ---------------------------------------------------------------------------
-- Firewall chains and policy
-- ---------------------------------------------------------------------------

INSERT INTO firewall_chains (
    host_id,
    chain_name,
    family,
    hook,
    priority,
    default_action
)
SELECT
    host_id,
    'input',
    'inet',
    'input',
    0,
    'drop'
FROM hosts
WHERE hostname = 'app-prod-01';

INSERT INTO firewall_rules (
    chain_id,
    rule_order,
    protocol,
    source_network,
    destination_port,
    action,
    state_requirement,
    comment
)
SELECT
    fc.chain_id,
    10,
    'tcp',
    '10.20.0.0/16',
    22,
    'accept',
    'established,related',
    'Management SSH access'
FROM firewall_chains fc
JOIN hosts h ON h.host_id = fc.host_id
WHERE h.hostname = 'app-prod-01'
  AND fc.chain_name = 'input';

INSERT INTO firewall_rules (
    chain_id,
    rule_order,
    protocol,
    source_network,
    destination_port,
    action,
    state_requirement,
    comment
)
SELECT
    fc.chain_id,
    20,
    'tcp',
    NULL,
    443,
    'accept',
    'new,established',
    'Public HTTPS service'
FROM firewall_chains fc
JOIN hosts h ON h.host_id = fc.host_id
WHERE h.hostname = 'app-prod-01'
  AND fc.chain_name = 'input';

INSERT INTO firewall_rules (
    chain_id,
    rule_order,
    protocol,
    source_network,
    destination_port,
    action,
    state_requirement,
    comment
)
SELECT
    fc.chain_id,
    30,
    'udp',
    '10.20.0.0/16',
    53,
    'accept',
    'new',
    'Internal DNS traffic'
FROM firewall_chains fc
JOIN hosts h ON h.host_id = fc.host_id
WHERE h.hostname = 'app-prod-01'
  AND fc.chain_name = 'input';

-- ---------------------------------------------------------------------------
-- Views
-- ---------------------------------------------------------------------------

CREATE VIEW active_interface_addresses AS
SELECT
    h.hostname,
    i.interface_name,
    ia.address,
    ia.prefix_length,
    ia.scope,
    i.admin_up,
    i.link_up
FROM hosts h
JOIN interfaces i ON i.host_id = h.host_id
JOIN interface_addresses ia ON ia.interface_id = i.interface_id
WHERE i.admin_up = TRUE
  AND i.link_up = TRUE;

CREATE VIEW listening_sockets AS
SELECT
    h.hostname,
    s.protocol,
    s.local_address,
    s.local_port,
    s.process_name
FROM sockets s
JOIN hosts h ON h.host_id = s.host_id
WHERE s.state = 'LISTEN'
   OR s.state = 'UNCONN';

CREATE VIEW firewall_policy AS
SELECT
    h.hostname,
    fc.chain_name,
    fr.rule_order,
    fr.protocol,
    fr.source_network,
    fr.destination_port,
    fr.action,
    fr.state_requirement,
    fr.comment
FROM firewall_rules fr
JOIN firewall_chains fc ON fc.chain_id = fr.chain_id
JOIN hosts h ON h.host_id = fc.host_id
ORDER BY h.hostname, fc.chain_name, fr.rule_order;

-- ---------------------------------------------------------------------------
-- Route lookup using PostgreSQL inet containment
-- ---------------------------------------------------------------------------

-- PostgreSQL's << operator checks whether the address on the left belongs to
-- the network on the right. Ordering by prefix length implements a simplified
-- longest-prefix lookup.

SELECT
    h.hostname,
    r.destination,
    r.gateway,
    i.interface_name,
    r.metric,
    r.protocol
FROM routes r
JOIN hosts h ON h.host_id = r.host_id
LEFT JOIN interfaces i ON i.interface_id = r.interface_id
WHERE h.hostname = 'app-prod-01'
  AND '10.20.55.10'::inet <<= r.destination
  AND r.active = TRUE
ORDER BY masklen(r.destination) DESC, r.metric ASC
LIMIT 1;

-- ---------------------------------------------------------------------------
-- Find exposed listening services
-- ---------------------------------------------------------------------------

SELECT
    hostname,
    protocol,
    local_address,
    local_port,
    process_name
FROM listening_sockets
WHERE local_address = '0.0.0.0'
   OR local_address = '::';

-- ---------------------------------------------------------------------------
-- DNS configuration report
-- ---------------------------------------------------------------------------

SELECT
    h.hostname,
    dc.source,
    dc.search_domain,
    dn.nameserver,
    dn.priority
FROM hosts h
JOIN dns_configurations dc ON dc.host_id = h.host_id
JOIN dns_nameservers dn
    ON dn.dns_configuration_id = dc.dns_configuration_id
WHERE dc.active = TRUE
ORDER BY h.hostname, dn.priority;

-- ---------------------------------------------------------------------------
-- Firewall decision simulation
-- ---------------------------------------------------------------------------

-- This query demonstrates how a packet can be compared with ordered rules.
-- The application would normally supply packet values as parameters.

WITH packet AS (
    SELECT
        'tcp'::TEXT AS protocol,
        '10.20.45.10'::inet AS source_address,
        '10.20.5.20'::inet AS destination_address,
        55000::INTEGER AS source_port,
        22::INTEGER AS destination_port
),
candidate_rules AS (
    SELECT
        fr.rule_id,
        fr.rule_order,
        fr.action,
        fr.comment,
        fc.default_action,
        packet.*
    FROM firewall_rules fr
    JOIN firewall_chains fc ON fc.chain_id = fr.chain_id
    JOIN hosts h ON h.host_id = fc.host_id
    CROSS JOIN packet
    WHERE h.hostname = 'app-prod-01'
      AND fc.chain_name = 'input'
      AND (fr.protocol IS NULL OR fr.protocol = packet.protocol)
      AND (
          fr.source_network IS NULL
          OR packet.source_address <<= fr.source_network
      )
      AND (
          fr.destination_network IS NULL
          OR packet.destination_address <<= fr.destination_network
      )
      AND (
          fr.source_port IS NULL
          OR fr.source_port = packet.source_port
      )
      AND (
          fr.destination_port IS NULL
          OR fr.destination_port = packet.destination_port
      )
)
SELECT
    rule_id,
    rule_order,
    action,
    comment
FROM candidate_rules
ORDER BY rule_order
LIMIT 1;

-- ---------------------------------------------------------------------------
-- Transactional integrity example
-- ---------------------------------------------------------------------------

BEGIN;

-- A network configuration change should be treated atomically when multiple
-- related records must change together.

INSERT INTO routes (
    host_id,
    destination,
    gateway,
    interface_id,
    metric,
    protocol
)
SELECT
    h.host_id,
    '10.40.0.0/16',
    '10.20.0.254',
    i.interface_id,
    120,
    'static'
FROM hosts h
JOIN interfaces i
    ON i.host_id = h.host_id
   AND i.interface_name = 'eth0'
WHERE h.hostname = 'app-prod-01';

-- Verify the newly staged route before committing.
SELECT
    h.hostname,
    r.destination,
    r.gateway,
    r.metric,
    r.protocol
FROM routes r
JOIN hosts h ON h.host_id = r.host_id
WHERE h.hostname = 'app-prod-01'
  AND r.destination = '10.40.0.0/16';

COMMIT;

-- ---------------------------------------------------------------------------
-- Constraint demonstrations
-- ---------------------------------------------------------------------------

-- The following statements are intentionally commented out because they are
-- invalid and would terminate the transaction if executed:
--
-- INSERT INTO sockets (
--     host_id, protocol, state, local_address, local_port
-- )
-- VALUES (
--     1, 'tcp', 'LISTEN', '10.20.5.20', 70000
-- );
--
-- The CHECK constraint rejects port 70000.
--
-- A duplicate interface name on the same host is also rejected by:
-- UNIQUE(host_id, interface_name).
--
-- A firewall rule referencing a non-existent chain is rejected by the
-- foreign-key constraint.
