-- PostgreSQL 15+
-- Windows networking service inventory, endpoint exposure, and firewall policy.
--
-- This schema models reviewed policy rather than querying a live Windows host.
-- TCP 135 is the RPC endpoint mapper; dynamic RPC endpoints are not enumerated
-- by this standard-port reference model.

BEGIN;

DROP VIEW IF EXISTS windows_networking_assessment;
DROP TABLE IF EXISTS firewall_rules CASCADE;
DROP TABLE IF EXISTS service_requirements CASCADE;
DROP TABLE IF EXISTS network_observations CASCADE;
DROP TABLE IF EXISTS service_endpoints CASCADE;
DROP TABLE IF EXISTS windows_services CASCADE;
DROP TABLE IF EXISTS network_assets CASCADE;

CREATE TABLE network_assets (
    asset_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    environment TEXT NOT NULL
        CHECK (environment IN ('production', 'corporate', 'test')),
    owner_team TEXT NOT NULL CHECK (length(trim(owner_team)) > 0),
    firewall_profile TEXT NOT NULL
        CHECK (firewall_profile IN ('Domain', 'Private', 'Public')),
    lifecycle_state TEXT NOT NULL DEFAULT 'active'
        CHECK (lifecycle_state IN ('active', 'under_review', 'retired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE windows_services (
    service_id SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_code TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    security_guidance TEXT NOT NULL,
    CHECK (service_code IN ('SMB', 'RDP', 'WinRM', 'RPC'))
);

CREATE TABLE service_endpoints (
    endpoint_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_id SMALLINT NOT NULL
        REFERENCES windows_services(service_id) ON DELETE RESTRICT,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    transport TEXT NOT NULL CHECK (transport IN ('TCP', 'UDP')),
    endpoint_description TEXT NOT NULL,
    UNIQUE (service_id, port, transport)
);

CREATE TABLE service_requirements (
    asset_id BIGINT NOT NULL
        REFERENCES network_assets(asset_id) ON DELETE CASCADE,
    service_id SMALLINT NOT NULL
        REFERENCES windows_services(service_id) ON DELETE RESTRICT,
    business_reason TEXT NOT NULL CHECK (length(trim(business_reason)) > 0),
    approved_by TEXT NOT NULL CHECK (length(trim(approved_by)) > 0),
    approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, service_id)
);

CREATE TABLE network_observations (
    observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id BIGINT NOT NULL
        REFERENCES network_assets(asset_id) ON DELETE CASCADE,
    endpoint_id BIGINT NOT NULL
        REFERENCES service_endpoints(endpoint_id) ON DELETE RESTRICT,
    observed_from INET NOT NULL,
    result TEXT NOT NULL
        CHECK (result IN ('reachable', 'unreachable', 'not_tested', 'error')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    latency_ms NUMERIC(10, 2)
        CHECK (latency_ms IS NULL OR latency_ms >= 0),
    details TEXT,
    -- Prevent impossible latency values for tests that never completed.
    CHECK (
        result = 'reachable'
        OR latency_ms IS NULL
    )
);

CREATE TABLE firewall_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_name TEXT NOT NULL UNIQUE,
    asset_id BIGINT REFERENCES network_assets(asset_id) ON DELETE CASCADE,
    service_id SMALLINT NOT NULL
        REFERENCES windows_services(service_id) ON DELETE RESTRICT,
    endpoint_id BIGINT NOT NULL
        REFERENCES service_endpoints(endpoint_id) ON DELETE RESTRICT,
    profile TEXT NOT NULL
        CHECK (profile IN ('Domain', 'Private', 'Public')),
    action TEXT NOT NULL CHECK (action IN ('Allow', 'Block')),
    source_network CIDR,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    change_ticket TEXT,
    reviewed_by TEXT NOT NULL CHECK (length(trim(reviewed_by)) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_observations_asset_time
    ON network_observations (asset_id, observed_at DESC);

CREATE INDEX idx_firewall_rules_policy_lookup
    ON firewall_rules (asset_id, profile, service_id, endpoint_id)
    WHERE enabled = TRUE;

CREATE INDEX idx_requirements_service
    ON service_requirements (service_id, asset_id);

INSERT INTO windows_services
    (service_code, purpose, security_guidance)
VALUES
    (
        'SMB',
        'Windows file and printer sharing',
        'Restrict TCP 445 to approved networks; use SMB 3.x, appropriate '
        'signing, encryption where required, and least-privilege share ACLs.'
    ),
    (
        'RDP',
        'Interactive remote desktop sessions',
        'Restrict TCP 3389, require NLA where supported, use strong '
        'authentication, and prefer a controlled VPN or gateway.'
    ),
    (
        'WinRM',
        'PowerShell remoting and Windows remote management',
        'Restrict management sources; prefer correctly configured HTTPS '
        'on TCP 5986 and carefully scoped administrative permissions.'
    ),
    (
        'RPC',
        'Remote procedure calls and endpoint discovery',
        'TCP 135 is the endpoint mapper; required RPC services may use '
        'additional dynamic ports that need separate policy review.'
    );

INSERT INTO service_endpoints
    (service_id, port, transport, endpoint_description)
SELECT service_id, endpoint.port, 'TCP', endpoint.description
FROM windows_services AS service
CROSS JOIN (
    VALUES
        ('SMB', 445, 'SMB over TCP'),
        ('RDP', 3389, 'Remote Desktop Protocol endpoint'),
        ('WinRM', 5985, 'WinRM HTTP listener when configured'),
        ('WinRM', 5986, 'WinRM HTTPS listener when configured'),
        ('RPC', 135, 'RPC endpoint mapper')
) AS endpoint(service_code, port, description)
WHERE service.service_code = endpoint.service_code;

INSERT INTO network_assets
    (hostname, environment, owner_team, firewall_profile, lifecycle_state)
VALUES
    ('fileserver-01', 'production', 'Infrastructure', 'Domain', 'active'),
    ('admin-workstation-01', 'corporate', 'Endpoint Engineering', 'Domain', 'active'),
    ('test-host-01', 'test', 'Quality Engineering', 'Private', 'under_review');

INSERT INTO service_requirements
    (asset_id, service_id, business_reason, approved_by)
SELECT asset.asset_id, service.service_id, requirement.reason, 'Network Governance'
FROM (
    VALUES
        ('fileserver-01', 'SMB', 'Approved departmental file shares'),
        ('fileserver-01', 'RPC', 'Required Windows management operations'),
        ('admin-workstation-01', 'RDP', 'Controlled administrative desktop access'),
        ('admin-workstation-01', 'WinRM', 'Remote PowerShell administration'),
        ('admin-workstation-01', 'RPC', 'Required Windows management operations')
) AS requirement(hostname, service_code, reason)
JOIN network_assets AS asset
    ON asset.hostname = requirement.hostname
JOIN windows_services AS service
    ON service.service_code = requirement.service_code;

INSERT INTO firewall_rules
    (
        rule_name, asset_id, service_id, endpoint_id, profile,
        action, source_network, reviewed_by, change_ticket
    )
SELECT
    policy.rule_name,
    asset.asset_id,
    service.service_id,
    endpoint.endpoint_id,
    policy.profile,
    policy.action,
    policy.source_network::CIDR,
    'Security Engineering',
    policy.change_ticket
FROM (
    VALUES
        (
            'Allow approved file-server SMB',
            'fileserver-01', 'SMB', 445, 'Domain', 'Allow',
            '192.168.20.0/24', 'NET-204'
        ),
        (
            'Block public SMB',
            NULL, 'SMB', 445, 'Public', 'Block',
            NULL, 'SEC-101'
        ),
        (
            'Allow management RDP',
            'admin-workstation-01', 'RDP', 3389, 'Domain', 'Allow',
            '192.168.20.15/32', 'NET-205'
        ),
        (
            'Allow management WinRM HTTPS',
            'admin-workstation-01', 'WinRM', 5986, 'Domain', 'Allow',
            '192.168.20.15/32', 'NET-206'
        ),
        (
            'Block management WinRM HTTP',
            'admin-workstation-01', 'WinRM', 5985, 'Domain', 'Block',
            NULL, 'SEC-102'
        )
) AS policy(
    rule_name, hostname, service_code, port, profile,
    action, source_network, change_ticket
)
LEFT JOIN network_assets AS asset
    ON asset.hostname = policy.hostname
JOIN windows_services AS service
    ON service.service_code = policy.service_code
JOIN service_endpoints AS endpoint
    ON endpoint.service_id = service.service_id
   AND endpoint.port = policy.port
   AND endpoint.transport = 'TCP';

INSERT INTO network_observations
    (asset_id, endpoint_id, observed_from, result, latency_ms, details)
SELECT
    asset.asset_id,
    endpoint.endpoint_id,
    observation.source_ip::INET,
    observation.result,
    observation.latency_ms,
    observation.details
FROM (
    VALUES
        (
            'fileserver-01', 'SMB', 445, '192.168.20.15',
            'reachable', 8.50::NUMERIC, 'TCP connection succeeded'
        ),
        (
            'fileserver-01', 'RDP', 3389, '192.168.20.15',
            'unreachable', NULL::NUMERIC, 'No TCP connection established'
        ),
        (
            'admin-workstation-01', 'WinRM', 5986, '192.168.20.15',
            'reachable', 12.10::NUMERIC, 'TCP connection succeeded'
        ),
        (
            'admin-workstation-01', 'WinRM', 5985, '192.168.20.15',
            'not_tested', NULL::NUMERIC, 'Not included in the test window'
        )
) AS observation(
    hostname, service_code, port, source_ip,
    result, latency_ms, details
)
JOIN network_assets AS asset
    ON asset.hostname = observation.hostname
JOIN windows_services AS service
    ON service.service_code = observation.service_code
JOIN service_endpoints AS endpoint
    ON endpoint.service_id = service.service_id
   AND endpoint.port = observation.port
   AND endpoint.transport = 'TCP';

-- Latest observed endpoint state per asset and endpoint.
CREATE VIEW windows_networking_assessment AS
WITH latest_observation AS (
    SELECT DISTINCT ON (observation.asset_id, observation.endpoint_id)
        observation.asset_id,
        observation.endpoint_id,
        observation.result,
        observation.observed_from,
        observation.observed_at,
        observation.latency_ms,
        observation.details
    FROM network_observations AS observation
    ORDER BY
        observation.asset_id,
        observation.endpoint_id,
        observation.observed_at DESC,
        observation.observation_id DESC
)
SELECT
    asset.hostname,
    asset.environment,
    asset.owner_team,
    asset.firewall_profile,
    service.service_code,
    endpoint.port,
    endpoint.transport,
    EXISTS (
        SELECT 1
        FROM service_requirements AS requirement
        WHERE requirement.asset_id = asset.asset_id
          AND requirement.service_id = service.service_id
    ) AS service_required,
    observation.result AS latest_observation,
    observation.observed_from,
    observation.observed_at,
    observation.latency_ms,
    observation.details
FROM network_assets AS asset
CROSS JOIN windows_services AS service
JOIN service_endpoints AS endpoint
    ON endpoint.service_id = service.service_id
LEFT JOIN latest_observation AS observation
    ON observation.asset_id = asset.asset_id
   AND observation.endpoint_id = endpoint.endpoint_id
WHERE asset.lifecycle_state <> 'retired';

-- Review endpoint requirements and observed availability.
SELECT
    hostname,
    service_code,
    port,
    service_required,
    latest_observation,
    latency_ms
FROM windows_networking_assessment
ORDER BY hostname, service_code, port;

-- Find endpoints that are reachable even though the service is not required.
SELECT
    hostname,
    service_code,
    port,
    observed_from,
    observed_at
FROM windows_networking_assessment
WHERE latest_observation = 'reachable'
  AND service_required = FALSE
ORDER BY hostname, service_code, port;

-- List enabled firewall rules relevant to each asset or global profile.
SELECT
    COALESCE(asset.hostname, '[all assets]') AS target,
    service.service_code,
    endpoint.port,
    rule.profile,
    rule.action,
    rule.source_network,
    rule.rule_name
FROM firewall_rules AS rule
LEFT JOIN network_assets AS asset
    ON asset.asset_id = rule.asset_id
JOIN windows_services AS service
    ON service.service_id = rule.service_id
JOIN service_endpoints AS endpoint
    ON endpoint.endpoint_id = rule.endpoint_id
WHERE rule.enabled
ORDER BY target, service.service_code, endpoint.port;

-- Evaluate whether an observation indicates a dependency outage.
SELECT
    assessment.hostname,
    assessment.service_code,
    assessment.port,
    assessment.latest_observation,
    assessment.service_required,
    CASE
        WHEN assessment.service_required
         AND assessment.latest_observation = 'unreachable'
            THEN 'Investigate required endpoint outage'
        WHEN assessment.service_required
         AND assessment.latest_observation IS NULL
            THEN 'Required endpoint has not been observed'
        WHEN NOT assessment.service_required
         AND assessment.latest_observation = 'reachable'
            THEN 'Review unnecessary exposure'
        ELSE 'No finding from available observations'
    END AS finding
FROM windows_networking_assessment AS assessment
ORDER BY assessment.hostname, assessment.service_code, assessment.port;

-- Demonstrate transaction rollback: invalid port violates the table constraint.
SAVEPOINT before_invalid_endpoint;
DO $$
BEGIN
    BEGIN
        INSERT INTO service_endpoints
            (service_id, port, transport, endpoint_description)
        SELECT service_id, 70000, 'TCP', 'Invalid endpoint'
        FROM windows_services
        WHERE service_code = 'RDP';
    EXCEPTION
        WHEN check_violation THEN
            RAISE NOTICE 'Rejected invalid endpoint port as expected.';
    END;
END;
$$;
ROLLBACK TO SAVEPOINT before_invalid_endpoint;
RELEASE SAVEPOINT before_invalid_endpoint;

COMMIT;

-- The model records reviewed rules and sampled observations. It does not
-- calculate the complete Windows Firewall effective policy. Real deployments
-- must account for Windows policy precedence, local/domain policy, rule
-- merging, profile selection, IPv4/IPv6, service identity, and dynamic RPC.
