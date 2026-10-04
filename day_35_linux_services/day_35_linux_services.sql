-- PostgreSQL-compatible Linux service-management learning model.
-- The schema models systemd-oriented service configuration, daemon state,
-- dependencies, startup enablement, service events, and operational health.
--
-- It intentionally separates:
--   service configuration from runtime state
--   startup enablement from dependency ordering
--   daemon failures from ordinary service configuration
--
-- No operating-system service is modified by this SQL script.

DROP SCHEMA IF EXISTS linux_services CASCADE;
CREATE SCHEMA linux_services;

SET search_path TO linux_services;

CREATE TYPE service_state AS ENUM (
    'inactive',
    'activating',
    'active',
    'deactivating',
    'failed'
);

CREATE TYPE startup_policy AS ENUM (
    'disabled',
    'enabled',
    'static'
);

CREATE TYPE restart_policy AS ENUM (
    'no',
    'on-failure',
    'always'
);

CREATE TABLE service_units (
    service_id BIGSERIAL PRIMARY KEY,
    unit_name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    exec_start TEXT NOT NULL,
    service_user TEXT NOT NULL,
    working_directory TEXT,
    restart_policy restart_policy NOT NULL DEFAULT 'no',
    restart_seconds INTEGER NOT NULL DEFAULT 1,
    wanted_by TEXT,
    CONSTRAINT service_unit_suffix_chk
        CHECK (unit_name ~ '\.service$'),
    CONSTRAINT exec_start_not_blank_chk
        CHECK (length(btrim(exec_start)) > 0),
    CONSTRAINT service_user_not_blank_chk
        CHECK (length(btrim(service_user)) > 0),
    CONSTRAINT restart_seconds_chk
        CHECK (restart_seconds >= 0)
);

CREATE TABLE service_environment (
    service_id BIGINT NOT NULL REFERENCES service_units(service_id)
        ON DELETE CASCADE,
    variable_name TEXT NOT NULL,
    variable_value TEXT NOT NULL,
    PRIMARY KEY (service_id, variable_name),
    CONSTRAINT environment_name_chk
        CHECK (variable_name ~ '^[A-Za-z_][A-Za-z0-9_]*$')
);

CREATE TABLE service_dependencies (
    service_id BIGINT NOT NULL REFERENCES service_units(service_id)
        ON DELETE CASCADE,
    dependency_unit_name TEXT NOT NULL,
    PRIMARY KEY (service_id, dependency_unit_name),
    CONSTRAINT dependency_not_self_chk
        CHECK (dependency_unit_name <> '')
);

CREATE TABLE service_startup (
    service_id BIGINT PRIMARY KEY REFERENCES service_units(service_id)
        ON DELETE CASCADE,
    policy startup_policy NOT NULL,
    target_name TEXT,
    CONSTRAINT enabled_requires_target_chk
        CHECK (
            policy <> 'enabled'
            OR length(btrim(COALESCE(target_name, ''))) > 0
        )
);

CREATE TABLE service_runtime (
    service_id BIGINT PRIMARY KEY REFERENCES service_units(service_id)
        ON DELETE CASCADE,
    state service_state NOT NULL DEFAULT 'inactive',
    restart_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_state_change TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT restart_count_chk
        CHECK (restart_count >= 0)
);

CREATE TABLE service_events (
    event_id BIGSERIAL PRIMARY KEY,
    service_id BIGINT NOT NULL REFERENCES service_units(service_id)
        ON DELETE CASCADE,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    state service_state,
    message TEXT NOT NULL
);

CREATE TABLE service_health_checks (
    health_check_id BIGSERIAL PRIMARY KEY,
    service_id BIGINT NOT NULL REFERENCES service_units(service_id)
        ON DELETE CASCADE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    healthy BOOLEAN NOT NULL,
    detail TEXT NOT NULL
);

CREATE INDEX service_events_service_time_idx
    ON service_events(service_id, event_time DESC);

CREATE INDEX service_health_service_time_idx
    ON service_health_checks(service_id, checked_at DESC);

CREATE INDEX service_startup_policy_idx
    ON service_startup(policy);

CREATE INDEX service_dependencies_dependency_idx
    ON service_dependencies(dependency_unit_name);

INSERT INTO service_units
    (unit_name, description, exec_start, service_user, working_directory,
     restart_policy, restart_seconds, wanted_by)
VALUES
    (
        'network-online.target.service',
        'Network availability target',
        '/bin/true',
        'root',
        NULL,
        'no',
        0,
        'multi-user.target'
    ),
    (
        'metrics-agent.service',
        'Host metrics collection daemon',
        '/opt/metrics/bin/agent --config /etc/metrics/agent.conf',
        'metrics',
        '/opt/metrics',
        'always',
        3,
        'multi-user.target'
    ),
    (
        'orders-api.service',
        'Orders API daemon',
        '/opt/orders/bin/server --port 8080',
        'orders',
        '/opt/orders',
        'on-failure',
        5,
        'multi-user.target'
    ),
    (
        'billing-worker.service',
        'Billing background worker',
        'FAIL --config /etc/billing/worker.conf',
        'billing',
        '/opt/billing',
        'on-failure',
        10,
        'multi-user.target'
    );

INSERT INTO service_environment(service_id, variable_name, variable_value)
SELECT service_id, 'APP_ENV', 'production'
FROM service_units
WHERE unit_name IN (
    'metrics-agent.service',
    'orders-api.service',
    'billing-worker.service'
);

INSERT INTO service_environment(service_id, variable_name, variable_value)
SELECT service_id, 'LOG_LEVEL', 'info'
FROM service_units
WHERE unit_name IN (
    'metrics-agent.service',
    'orders-api.service'
);

INSERT INTO service_dependencies(service_id, dependency_unit_name)
SELECT service_id, 'network-online.target.service'
FROM service_units
WHERE unit_name IN (
    'metrics-agent.service',
    'orders-api.service'
);

INSERT INTO service_dependencies(service_id, dependency_unit_name)
SELECT service_id, 'metrics-agent.service'
FROM service_units
WHERE unit_name = 'orders-api.service';

INSERT INTO service_startup(service_id, policy, target_name)
SELECT service_id, 'static', NULL
FROM service_units
WHERE unit_name = 'network-online.target.service';

INSERT INTO service_startup(service_id, policy, target_name)
SELECT service_id, 'enabled', 'multi-user.target'
FROM service_units
WHERE unit_name IN (
    'metrics-agent.service',
    'orders-api.service',
    'billing-worker.service'
);

INSERT INTO service_runtime(service_id, state, restart_count, last_error)
SELECT service_id, 'inactive', 0, NULL
FROM service_units;

-- Simulate dependency activation followed by application activation.
UPDATE service_runtime
SET state = 'active',
    last_state_change = now()
WHERE service_id = (
    SELECT service_id
    FROM service_units
    WHERE unit_name = 'network-online.target.service'
);

INSERT INTO service_events(service_id, state, message)
SELECT service_id, 'active', 'network target reached'
FROM service_units
WHERE unit_name = 'network-online.target.service';

UPDATE service_runtime
SET state = 'active',
    last_state_change = now()
WHERE service_id = (
    SELECT service_id
    FROM service_units
    WHERE unit_name = 'metrics-agent.service'
);

INSERT INTO service_events(service_id, state, message)
SELECT service_id, 'active', 'metrics daemon started after network dependency'
FROM service_units
WHERE unit_name = 'metrics-agent.service';

UPDATE service_runtime
SET state = 'active',
    last_state_change = now()
WHERE service_id = (
    SELECT service_id
    FROM service_units
    WHERE unit_name = 'orders-api.service'
);

INSERT INTO service_events(service_id, state, message)
SELECT service_id, 'active', 'orders API started after required dependencies'
FROM service_units
WHERE unit_name = 'orders-api.service';

-- The billing daemon contains a deliberately failing executable name.
UPDATE service_runtime
SET state = 'failed',
    last_error = 'ExecStart returned failure',
    restart_count = restart_count + 1,
    last_state_change = now()
WHERE service_id = (
    SELECT service_id
    FROM service_units
    WHERE unit_name = 'billing-worker.service'
);

INSERT INTO service_events(service_id, state, message)
SELECT service_id, 'failed', 'ExecStart returned failure'
FROM service_units
WHERE unit_name = 'billing-worker.service';

INSERT INTO service_health_checks(service_id, healthy, detail)
SELECT service_id,
       state = 'active',
       CASE
           WHEN state = 'active' THEN 'service is active'
           ELSE COALESCE(last_error, 'service is not active')
       END
FROM service_runtime;

-- Show the service configuration and current runtime state.
SELECT
    u.unit_name,
    u.description,
    u.restart_policy,
    u.restart_seconds,
    s.policy AS startup_policy,
    s.target_name,
    r.state,
    r.restart_count,
    r.last_error
FROM service_units u
JOIN service_startup s USING (service_id)
JOIN service_runtime r USING (service_id)
ORDER BY u.unit_name;

-- Resolve dependency relationships for operational inspection.
SELECT
    dependent.unit_name AS service,
    dependency.dependency_unit_name AS dependency,
    dependency_runtime.state AS dependency_state
FROM service_dependencies dependency
JOIN service_units dependent
    ON dependent.service_id = dependency.service_id
JOIN service_units dependency_unit
    ON dependency_unit.unit_name = dependency.dependency_unit_name
JOIN service_runtime dependency_runtime
    ON dependency_runtime.service_id = dependency_unit.service_id
ORDER BY dependent.unit_name, dependency.dependency_unit_name;

-- Identify enabled services that are not currently active.
SELECT
    u.unit_name,
    r.state,
    s.target_name,
    r.last_error
FROM service_units u
JOIN service_startup s USING (service_id)
JOIN service_runtime r USING (service_id)
WHERE s.policy = 'enabled'
  AND r.state <> 'active';

-- Produce a service-management view similar to a compact operational status.
CREATE VIEW service_status AS
SELECT
    u.unit_name,
    u.description,
    r.state,
    s.policy AS startup_policy,
    s.target_name,
    u.restart_policy,
    r.restart_count,
    r.last_error,
    r.last_state_change
FROM service_units u
JOIN service_runtime r USING (service_id)
JOIN service_startup s USING (service_id);

SELECT *
FROM service_status
ORDER BY unit_name;

-- Show environment settings associated with production daemons.
SELECT
    u.unit_name,
    e.variable_name,
    e.variable_value
FROM service_units u
JOIN service_environment e USING (service_id)
ORDER BY u.unit_name, e.variable_name;

-- Demonstrate the database-level transactional approach used when changing
-- runtime state and recording the corresponding event.
BEGIN;

UPDATE service_runtime
SET state = 'deactivating',
    last_state_change = now()
WHERE service_id = (
    SELECT service_id
    FROM service_units
    WHERE unit_name = 'orders-api.service'
)
AND state = 'active';

INSERT INTO service_events(service_id, state, message)
SELECT service_id,
       'deactivating',
       'controlled stop requested'
FROM service_units
WHERE unit_name = 'orders-api.service';

UPDATE service_runtime
SET state = 'inactive',
    last_state_change = now()
WHERE service_id = (
    SELECT service_id
    FROM service_units
    WHERE unit_name = 'orders-api.service'
)
AND state = 'deactivating';

INSERT INTO service_events(service_id, state, message)
SELECT service_id,
       'inactive',
       'service stopped successfully'
FROM service_units
WHERE unit_name = 'orders-api.service';

COMMIT;

-- Verify that the stop and its event were persisted together.
SELECT
    u.unit_name,
    r.state,
    event.state AS event_state,
    event.message,
    event.event_time
FROM service_units u
JOIN service_runtime r USING (service_id)
JOIN service_events event USING (service_id)
WHERE u.unit_name = 'orders-api.service'
ORDER BY event.event_time DESC
LIMIT 5;

-- Integrity test: this statement intentionally fails because the service
-- name does not have the required .service suffix.
-- INSERT INTO service_units
--     (unit_name, description, exec_start, service_user)
-- VALUES
--     ('bad-unit', 'Invalid unit', '/bin/true', 'service');

-- Integrity test: this statement intentionally fails because restart_seconds
-- cannot be negative.
-- INSERT INTO service_units
--     (unit_name, description, exec_start, service_user, restart_seconds)
-- VALUES
--     ('bad-restart.service', 'Invalid restart', '/bin/true', 'service', -1);

-- Startup policy query: static units are dependency-driven and are not
-- equivalent to enabled units.
SELECT
    u.unit_name,
    s.policy,
    s.target_name
FROM service_units u
JOIN service_startup s USING (service_id)
WHERE s.policy IN ('enabled', 'static')
ORDER BY s.policy, u.unit_name;

-- Failure-focused operational report.
SELECT
    u.unit_name,
    u.restart_policy,
    r.restart_count,
    r.last_error,
    MAX(h.checked_at) AS last_health_check,
    BOOL_AND(h.healthy) AS all_recorded_checks_healthy
FROM service_units u
JOIN service_runtime r USING (service_id)
LEFT JOIN service_health_checks h USING (service_id)
WHERE r.state = 'failed'
GROUP BY
    u.unit_name,
    u.restart_policy,
    r.restart_count,
    r.last_error;
