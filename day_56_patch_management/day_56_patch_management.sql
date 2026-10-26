DROP SCHEMA IF EXISTS patch_mgmt CASCADE;
CREATE SCHEMA patch_mgmt;

SET search_path = patch_mgmt, public;

CREATE TYPE environment_type AS ENUM (
    'development',
    'staging',
    'production'
);

CREATE TYPE severity_type AS ENUM (
    'low',
    'medium',
    'high',
    'critical'
);

CREATE TYPE patch_status AS ENUM (
    'planned',
    'deploying',
    'validating',
    'completed',
    'failed',
    'rolled_back'
);

CREATE TYPE deployment_type AS ENUM (
    'scheduled',
    'emergency'
);

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_name TEXT NOT NULL UNIQUE,
    owner_team TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (btrim(repository_name) <> ''),
    CHECK (btrim(owner_team) <> '')
);

CREATE TABLE servers (
    server_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT REFERENCES repositories(repository_id),
    hostname TEXT NOT NULL UNIQUE,
    environment environment_type NOT NULL,
    operating_system TEXT NOT NULL,
    online BOOLEAN NOT NULL DEFAULT TRUE,
    reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
    last_patched_at TIMESTAMPTZ,
    CHECK (btrim(hostname) <> ''),
    CHECK (btrim(operating_system) <> '')
);

CREATE TABLE components (
    component_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    component_name TEXT NOT NULL UNIQUE,
    vendor TEXT NOT NULL,
    current_stable_version TEXT NOT NULL,
    CHECK (btrim(component_name) <> ''),
    CHECK (btrim(vendor) <> ''),
    CHECK (current_stable_version ~ '^[0-9]+(\.[0-9]+){1,3}$')
);

CREATE TABLE server_components (
    server_id BIGINT NOT NULL REFERENCES servers(server_id) ON DELETE CASCADE,
    component_id BIGINT NOT NULL REFERENCES components(component_id),
    installed_version TEXT NOT NULL,
    PRIMARY KEY (server_id, component_id),
    CHECK (installed_version ~ '^[0-9]+(\.[0-9]+){1,3}$')
);

CREATE TABLE patches (
    patch_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    patch_code TEXT NOT NULL UNIQUE,
    component_id BIGINT NOT NULL REFERENCES components(component_id),
    title TEXT NOT NULL,
    version_before TEXT NOT NULL,
    version_after TEXT NOT NULL,
    severity severity_type NOT NULL,
    release_date DATE NOT NULL,
    requires_reboot BOOLEAN NOT NULL DEFAULT FALSE,
    package_sha256 CHAR(64) NOT NULL,
    deployment_type deployment_type NOT NULL DEFAULT 'scheduled',
    withdrawn BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (patch_code ~ '^P-[0-9]{4,}$'),
    CHECK (btrim(title) <> ''),
    CHECK (version_before ~ '^[0-9]+(\.[0-9]+){1,3}$'),
    CHECK (version_after ~ '^[0-9]+(\.[0-9]+){1,3}$'),
    CHECK (version_before <> version_after),
    CHECK (package_sha256 ~ '^[0-9a-fA-F]{64}$')
);

CREATE TABLE patch_windows (
    window_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    window_name TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    allowed_environment environment_type NOT NULL,
    CHECK (btrim(window_name) <> ''),
    CHECK (ends_at > starts_at)
);

CREATE TABLE deployments (
    deployment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    patch_id BIGINT NOT NULL REFERENCES patches(patch_id),
    server_id BIGINT NOT NULL REFERENCES servers(server_id),
    window_id BIGINT REFERENCES patch_windows(window_id),
    status patch_status NOT NULL DEFAULT 'planned',
    planned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    validation_message TEXT,
    UNIQUE (patch_id, server_id)
);

CREATE TABLE validation_checks (
    validation_check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id BIGINT NOT NULL REFERENCES deployments(deployment_id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    passed BOOLEAN NOT NULL,
    details TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (deployment_id, check_name),
    CHECK (btrim(check_name) <> '')
);

CREATE TABLE patch_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    environment environment_type NOT NULL,
    required_reviews INTEGER NOT NULL DEFAULT 0,
    emergency_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    direct_production_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    require_validation BOOLEAN NOT NULL DEFAULT TRUE,
    require_reboot_clear BOOLEAN NOT NULL DEFAULT TRUE,
    CHECK (required_reviews >= 0)
);

CREATE TABLE patch_policy_severities (
    policy_id BIGINT NOT NULL REFERENCES patch_policies(policy_id) ON DELETE CASCADE,
    severity severity_type NOT NULL,
    PRIMARY KEY (policy_id, severity)
);

CREATE INDEX idx_servers_environment
    ON servers(environment);

CREATE INDEX idx_patches_severity_release
    ON patches(severity, release_date)
    WHERE withdrawn = FALSE;

CREATE INDEX idx_deployments_status
    ON deployments(status);

CREATE INDEX idx_validation_checks_deployment
    ON validation_checks(deployment_id);

CREATE INDEX idx_server_components_component_version
    ON server_components(component_id, installed_version);

INSERT INTO repositories (repository_name, owner_team)
VALUES
    ('payments-platform', 'platform-security'),
    ('identity-service', 'identity-engineering');

INSERT INTO servers (
    repository_id,
    hostname,
    environment,
    operating_system
)
SELECT
    repository_id,
    'payments-prod-01',
    'production',
    'Ubuntu 24.04'
FROM repositories
WHERE repository_name = 'payments-platform';

INSERT INTO servers (
    repository_id,
    hostname,
    environment,
    operating_system
)
SELECT
    repository_id,
    'payments-stage-01',
    'staging',
    'Ubuntu 24.04'
FROM repositories
WHERE repository_name = 'payments-platform';

INSERT INTO servers (
    repository_id,
    hostname,
    environment,
    operating_system
)
SELECT
    repository_id,
    'identity-dev-01',
    'development',
    'Ubuntu 24.04'
FROM repositories
WHERE repository_name = 'identity-service';

INSERT INTO components (
    component_name,
    vendor,
    current_stable_version
)
VALUES
    ('openssl', 'OpenSSL Project', '3.0.17'),
    ('linux-kernel', 'Linux Foundation', '6.1.112'),
    ('nginx', 'F5', '1.26.3');

INSERT INTO server_components (server_id, component_id, installed_version)
SELECT s.server_id, c.component_id, x.installed_version
FROM (
    VALUES
        ('payments-prod-01', 'openssl', '3.0.12'),
        ('payments-prod-01', 'linux-kernel', '6.1.70'),
        ('payments-prod-01', 'nginx', '1.26.2'),
        ('payments-stage-01', 'openssl', '3.0.12'),
        ('payments-stage-01', 'linux-kernel', '6.1.70'),
        ('payments-stage-01', 'nginx', '1.26.2'),
        ('identity-dev-01', 'openssl', '3.0.17'),
        ('identity-dev-01', 'linux-kernel', '6.1.112'),
        ('identity-dev-01', 'nginx', '1.26.3')
) AS x(hostname, component_name, installed_version)
JOIN servers s ON s.hostname = x.hostname
JOIN components c ON c.component_name = x.component_name;

INSERT INTO patches (
    patch_code,
    component_id,
    title,
    version_before,
    version_after,
    severity,
    release_date,
    requires_reboot,
    package_sha256,
    deployment_type
)
SELECT
    'P-5001',
    component_id,
    'OpenSSL critical security update',
    '3.0.12',
    '3.0.17',
    'critical',
    CURRENT_DATE,
    FALSE,
    repeat('a', 64),
    'emergency'
FROM components
WHERE component_name = 'openssl';

INSERT INTO patches (
    patch_code,
    component_id,
    title,
    version_before,
    version_after,
    severity,
    release_date,
    requires_reboot,
    package_sha256,
    deployment_type
)
SELECT
    'P-5002',
    component_id,
    'Linux kernel security update',
    '6.1.70',
    '6.1.112',
    'high',
    CURRENT_DATE,
    TRUE,
    repeat('b', 64),
    'scheduled'
FROM components
WHERE component_name = 'linux-kernel';

INSERT INTO patches (
    patch_code,
    component_id,
    title,
    version_before,
    version_after,
    severity,
    release_date,
    requires_reboot,
    package_sha256,
    deployment_type
)
SELECT
    'P-5003',
    component_id,
    'Nginx maintenance update',
    '1.26.2',
    '1.26.3',
    'medium',
    CURRENT_DATE,
    FALSE,
    repeat('c', 64),
    'scheduled'
FROM components
WHERE component_name = 'nginx';

INSERT INTO patch_windows (
    window_name,
    starts_at,
    ends_at,
    allowed_environment
)
VALUES
    (
        'Production emergency window',
        now() - interval '15 minutes',
        now() + interval '2 hours',
        'production'
    ),
    (
        'Staging validation window',
        now() - interval '15 minutes',
        now() + interval '4 hours',
        'staging'
    );

INSERT INTO patch_policies (
    policy_name,
    environment,
    required_reviews,
    emergency_allowed,
    direct_production_allowed,
    require_validation,
    require_reboot_clear
)
VALUES
    (
        'Production security policy',
        'production',
        2,
        TRUE,
        FALSE,
        TRUE,
        TRUE
    ),
    (
        'Staging validation policy',
        'staging',
        1,
        TRUE,
        TRUE,
        TRUE,
        TRUE
    ),
    (
        'Development maintenance policy',
        'development',
        0,
        TRUE,
        TRUE,
        TRUE,
        FALSE
    );

INSERT INTO patch_policy_severities (policy_id, severity)
SELECT policy_id, 'critical'
FROM patch_policies
WHERE policy_name = 'Production security policy';

INSERT INTO patch_policy_severities (policy_id, severity)
SELECT policy_id, 'high'
FROM patch_policies
WHERE policy_name = 'Production security policy';

INSERT INTO patch_policy_severities (policy_id, severity)
SELECT policy_id, severity
FROM patch_policies
CROSS JOIN (
    VALUES
        ('low'::severity_type),
        ('medium'::severity_type),
        ('high'::severity_type),
        ('critical'::severity_type)
) AS allowed(severity)
WHERE patch_policies.policy_name IN (
    'Staging validation policy',
    'Development maintenance policy'
);

CREATE OR REPLACE FUNCTION validate_deployment_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    p patches%ROWTYPE;
    s servers%ROWTYPE;
    c_version TEXT;
    window_environment environment_type;
BEGIN
    SELECT *
    INTO p
    FROM patches
    WHERE patch_id = NEW.patch_id
      AND withdrawn = FALSE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Patch does not exist or is withdrawn';
    END IF;

    SELECT *
    INTO s
    FROM servers
    WHERE server_id = NEW.server_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Server does not exist';
    END IF;

    IF NOT s.online THEN
        RAISE EXCEPTION 'Cannot deploy patch to offline server %', s.hostname;
    END IF;

    SELECT installed_version
    INTO c_version
    FROM server_components
    WHERE server_id = s.server_id
      AND component_id = p.component_id;

    IF c_version IS NULL THEN
        RAISE EXCEPTION
            'Server % does not contain component %',
            s.hostname,
            p.component_id;
    END IF;

    IF c_version <> p.version_before THEN
        RAISE EXCEPTION
            'Version prerequisite failed for %. Expected %, found %',
            s.hostname,
            p.version_before,
            c_version;
    END IF;

    IF NEW.window_id IS NOT NULL THEN
        SELECT allowed_environment
        INTO window_environment
        FROM patch_windows
        WHERE window_id = NEW.window_id
          AND starts_at <= now()
          AND ends_at >= now();

        IF window_environment IS NULL THEN
            RAISE EXCEPTION 'Deployment window is missing or inactive';
        END IF;

        IF window_environment <> s.environment THEN
            RAISE EXCEPTION
                'Patch window environment % does not match server environment %',
                window_environment,
                s.environment;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_deployment_insert
BEFORE INSERT ON deployments
FOR EACH ROW
EXECUTE FUNCTION validate_deployment_insert();

CREATE OR REPLACE FUNCTION validate_deployment_completion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    p patches%ROWTYPE;
    s servers%ROWTYPE;
    installed TEXT;
    failed_checks INTEGER;
BEGIN
    IF NEW.status = 'completed'
       AND OLD.status <> 'completed' THEN

        SELECT *
        INTO p
        FROM patches
        WHERE patch_id = NEW.patch_id;

        SELECT *
        INTO s
        FROM servers
        WHERE server_id = NEW.server_id;

        SELECT installed_version
        INTO installed
        FROM server_components
        WHERE server_id = s.server_id
          AND component_id = p.component_id;

        SELECT count(*)
        INTO failed_checks
        FROM validation_checks
        WHERE deployment_id = NEW.deployment_id
          AND passed = FALSE;

        IF installed <> p.version_after THEN
            RAISE EXCEPTION
                'Cannot complete deployment: expected %, found %',
                p.version_after,
                installed;
        END IF;

        IF failed_checks > 0 THEN
            RAISE EXCEPTION
                'Cannot complete deployment: validation failures exist';
        END IF;

        UPDATE servers
        SET last_patched_at = now(),
            reboot_required = FALSE
        WHERE server_id = s.server_id;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_deployment_completion
BEFORE UPDATE OF status ON deployments
FOR EACH ROW
EXECUTE FUNCTION validate_deployment_completion();

CREATE OR REPLACE VIEW patch_eligibility AS
WITH current_versions AS (
    SELECT
        sc.server_id,
        sc.component_id,
        sc.installed_version
    FROM server_components sc
),
candidate AS (
    SELECT
        s.server_id,
        s.hostname,
        s.environment,
        p.patch_id,
        p.patch_code,
        p.title,
        p.severity,
        p.deployment_type,
        p.version_before,
        p.version_after,
        p.requires_reboot,
        cv.installed_version,
        CASE
            WHEN NOT s.online THEN FALSE
            WHEN p.withdrawn THEN FALSE
            WHEN cv.installed_version IS NULL THEN FALSE
            WHEN cv.installed_version <> p.version_before THEN FALSE
            WHEN p.deployment_type = 'emergency'
                 AND p.severity NOT IN ('high', 'critical')
                THEN FALSE
            ELSE TRUE
        END AS eligible
    FROM servers s
    CROSS JOIN patches p
    JOIN current_versions cv
      ON cv.server_id = s.server_id
     AND cv.component_id = p.component_id
)
SELECT *
FROM candidate;

CREATE OR REPLACE VIEW patch_compliance_report AS
SELECT
    s.hostname,
    s.environment,
    c.component_name,
    sc.installed_version,
    c.current_stable_version,
    CASE
        WHEN sc.installed_version = c.current_stable_version
            THEN 'current'
        WHEN sc.installed_version < c.current_stable_version
            THEN 'behind'
        ELSE 'nonstandard'
    END AS compliance_state,
    s.last_patched_at,
    s.reboot_required
FROM servers s
JOIN server_components sc
  ON sc.server_id = s.server_id
JOIN components c
  ON c.component_id = sc.component_id;

-- Transactional emergency deployment.
BEGIN;

INSERT INTO deployments (
    patch_id,
    server_id,
    window_id,
    status
)
SELECT
    p.patch_id,
    s.server_id,
    w.window_id,
    'planned'
FROM patches p
JOIN servers s
  ON s.hostname = 'payments-prod-01'
JOIN patch_windows w
  ON w.window_name = 'Production emergency window'
WHERE p.patch_code = 'P-5001';

UPDATE deployments
SET status = 'deploying',
    started_at = now()
WHERE deployment_id = (
    SELECT max(deployment_id)
    FROM deployments
    WHERE patch_id = (
        SELECT patch_id FROM patches WHERE patch_code = 'P-5001'
    )
    AND server_id = (
        SELECT server_id FROM servers WHERE hostname = 'payments-prod-01'
    )
);

UPDATE server_components
SET installed_version = (
    SELECT version_after
    FROM patches
    WHERE patch_code = 'P-5001'
)
WHERE server_id = (
    SELECT server_id FROM servers WHERE hostname = 'payments-prod-01'
)
AND component_id = (
    SELECT component_id
    FROM patches
    WHERE patch_code = 'P-5001'
);

INSERT INTO validation_checks (
    deployment_id,
    check_name,
    passed,
    details
)
SELECT
    d.deployment_id,
    'version_check',
    sc.installed_version = p.version_after,
    'Installed version must equal the approved target.'
FROM deployments d
JOIN patches p ON p.patch_id = d.patch_id
JOIN server_components sc
  ON sc.server_id = d.server_id
 AND sc.component_id = p.component_id
WHERE d.patch_id = (
    SELECT patch_id FROM patches WHERE patch_code = 'P-5001'
)
AND d.server_id = (
    SELECT server_id FROM servers WHERE hostname = 'payments-prod-01'
);

INSERT INTO validation_checks (
    deployment_id,
    check_name,
    passed,
    details
)
SELECT
    d.deployment_id,
    'host_online',
    s.online,
    'Production server must remain online.'
FROM deployments d
JOIN servers s ON s.server_id = d.server_id
WHERE d.patch_id = (
    SELECT patch_id FROM patches WHERE patch_code = 'P-5001'
)
AND d.server_id = (
    SELECT server_id FROM servers WHERE hostname = 'payments-prod-01'
);

UPDATE deployments
SET status = 'validating',
    validation_message = 'Automated version and availability checks completed.'
WHERE patch_id = (
    SELECT patch_id FROM patches WHERE patch_code = 'P-5001'
)
AND server_id = (
    SELECT server_id FROM servers WHERE hostname = 'payments-prod-01'
);

UPDATE deployments d
SET status = 'completed',
    completed_at = now(),
    validation_message = 'Emergency patch validated successfully.'
WHERE d.patch_id = (
    SELECT patch_id FROM patches WHERE patch_code = 'P-5001'
)
AND d.server_id = (
    SELECT server_id FROM servers WHERE hostname = 'payments-prod-01'
)
AND NOT EXISTS (
    SELECT 1
    FROM validation_checks vc
    WHERE vc.deployment_id = d.deployment_id
      AND vc.passed = FALSE
);

COMMIT;

-- Eligibility and validation queries.
SELECT
    patch_code,
    hostname,
    environment,
    severity,
    installed_version,
    version_after,
    eligible
FROM patch_eligibility
WHERE eligible
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        ELSE 4
    END,
    hostname;

SELECT
    environment,
    severity,
    count(*) AS patch_count
FROM patches
WHERE withdrawn = FALSE
GROUP BY environment, severity
ORDER BY environment, severity;

SELECT
    hostname,
    environment,
    count(*) FILTER (
        WHERE compliance_state = 'behind'
    ) AS components_behind,
    count(*) AS components_total
FROM patch_compliance_report
GROUP BY hostname, environment
ORDER BY hostname;

SELECT
    d.deployment_id,
    p.patch_code,
    s.hostname,
    s.environment,
    d.status,
    d.started_at,
    d.completed_at,
    d.validation_message
FROM deployments d
JOIN patches p ON p.patch_id = d.patch_id
JOIN servers s ON s.server_id = d.server_id
ORDER BY d.deployment_id;

SELECT
    d.deployment_id,
    p.patch_code,
    s.hostname,
    vc.check_name,
    vc.passed,
    vc.details,
    vc.checked_at
FROM validation_checks vc
JOIN deployments d ON d.deployment_id = vc.deployment_id
JOIN patches p ON p.patch_id = d.patch_id
JOIN servers s ON s.server_id = d.server_id
ORDER BY vc.checked_at, d.deployment_id;

-- Failure-case query: servers whose installed version does not satisfy a patch.
SELECT
    p.patch_code,
    p.title,
    s.hostname,
    c.component_name,
    sc.installed_version,
    p.version_before AS required_version
FROM patches p
JOIN components c ON c.component_id = p.component_id
JOIN server_components sc ON sc.component_id = p.component_id
JOIN servers s ON s.server_id = sc.server_id
WHERE sc.installed_version <> p.version_before
  AND p.withdrawn = FALSE
ORDER BY p.patch_code, s.hostname;

-- Emergency exposure report.
SELECT
    p.patch_code,
    p.title,
    p.severity,
    p.release_date,
    count(*) FILTER (
        WHERE sc.installed_version = p.version_before
    ) AS servers_still_on_vulnerable_version
FROM patches p
JOIN server_components sc
  ON sc.component_id = p.component_id
WHERE p.deployment_type = 'emergency'
  AND p.severity IN ('high', 'critical')
  AND p.withdrawn = FALSE
GROUP BY
    p.patch_code,
    p.title,
    p.severity,
    p.release_date
ORDER BY
    CASE p.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        ELSE 3
    END,
    p.release_date;
