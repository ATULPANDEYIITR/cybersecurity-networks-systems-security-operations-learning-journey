-- PostgreSQL 15+
-- Windows fundamentals: endpoint architecture, identities, services,
-- registry configuration, filesystem permissions, and security findings.
--
-- The schema represents a management inventory and policy assessment.
-- It does not query or modify a live Windows endpoint.
--
-- Run in a dedicated training database. DROP SCHEMA is intentionally avoided.

BEGIN;

CREATE SCHEMA IF NOT EXISTS windows_lab;

SET search_path TO windows_lab, public;

CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    windows_edition TEXT NOT NULL,
    os_build TEXT NOT NULL,
    os_architecture TEXT NOT NULL
        CHECK (os_architecture IN ('x86', 'x64', 'arm64')),
    secure_boot_enabled BOOLEAN,
    tpm_present BOOLEAN,
    last_inventory_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS principals (
    principal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    sid TEXT NOT NULL,
    account_name TEXT NOT NULL,
    principal_type TEXT NOT NULL
        CHECK (principal_type IN (
            'LOCAL_USER',
            'LOCAL_GROUP',
            'DOMAIN_USER',
            'DOMAIN_GROUP',
            'SERVICE_IDENTITY'
        )),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    is_builtin_administrator BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (endpoint_id, sid),
    UNIQUE (endpoint_id, account_name),
    CHECK (
        NOT is_builtin_administrator
        OR principal_type = 'LOCAL_USER'
    )
);

CREATE TABLE IF NOT EXISTS group_memberships (
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    member_principal_id BIGINT NOT NULL REFERENCES principals(principal_id)
        ON DELETE CASCADE,
    group_principal_id BIGINT NOT NULL REFERENCES principals(principal_id)
        ON DELETE CASCADE,
    membership_source TEXT NOT NULL DEFAULT 'LOCAL',
    PRIMARY KEY (member_principal_id, group_principal_id),
    CHECK (member_principal_id <> group_principal_id)
);

CREATE INDEX IF NOT EXISTS idx_principals_endpoint_type
    ON principals(endpoint_id, principal_type);

CREATE INDEX IF NOT EXISTS idx_group_memberships_group
    ON group_memberships(group_principal_id);

CREATE TABLE IF NOT EXISTS services (
    service_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    service_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    executable_path TEXT NOT NULL,
    run_as_principal_id BIGINT NOT NULL REFERENCES principals(principal_id),
    service_state TEXT NOT NULL
        CHECK (service_state IN ('RUNNING', 'STOPPED', 'DISABLED')),
    startup_type TEXT NOT NULL
        CHECK (startup_type IN ('AUTOMATIC', 'DELAYED_AUTOMATIC', 'MANUAL', 'DISABLED')),
    executable_writable_by_standard_users BOOLEAN NOT NULL DEFAULT FALSE,
    unquoted_path_with_spaces BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (endpoint_id, service_name)
);

CREATE INDEX IF NOT EXISTS idx_services_state
    ON services(endpoint_id, service_state, startup_type);

CREATE TABLE IF NOT EXISTS registry_settings (
    setting_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    root_hive TEXT NOT NULL
        CHECK (root_hive IN ('HKLM', 'HKCU', 'HKCR', 'HKU', 'HKCC')),
    key_path TEXT NOT NULL,
    value_name TEXT NOT NULL,
    value_type TEXT NOT NULL
        CHECK (value_type IN (
            'REG_SZ',
            'REG_EXPAND_SZ',
            'REG_DWORD',
            'REG_QWORD',
            'REG_BINARY',
            'REG_MULTI_SZ'
        )),
    value_text TEXT,
    owner_principal_id BIGINT REFERENCES principals(principal_id),
    machine_wide BOOLEAN NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (endpoint_id, root_hive, key_path, value_name)
);

CREATE INDEX IF NOT EXISTS idx_registry_settings_key
    ON registry_settings(endpoint_id, root_hive, key_path);

CREATE TABLE IF NOT EXISTS filesystem_objects (
    object_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    object_path TEXT NOT NULL,
    object_type TEXT NOT NULL
        CHECK (object_type IN ('FILE', 'DIRECTORY', 'REPARSE_POINT')),
    owner_principal_id BIGINT REFERENCES principals(principal_id),
    inheritance_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (endpoint_id, object_path)
);

CREATE TABLE IF NOT EXISTS filesystem_acl_entries (
    acl_entry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    object_id BIGINT NOT NULL REFERENCES filesystem_objects(object_id)
        ON DELETE CASCADE,
    principal_id BIGINT NOT NULL REFERENCES principals(principal_id),
    access_type TEXT NOT NULL CHECK (access_type IN ('ALLOW', 'DENY')),
    rights TEXT[] NOT NULL,
    inherited BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (cardinality(rights) > 0),
    CHECK (
        rights <@ ARRAY[
            'READ', 'WRITE', 'EXECUTE', 'DELETE',
            'CHANGE_PERMISSIONS', 'TAKE_OWNERSHIP', 'FULL_CONTROL'
        ]::TEXT[]
    )
);

CREATE INDEX IF NOT EXISTS idx_filesystem_acl_principal
    ON filesystem_acl_entries(principal_id, object_id);

CREATE TABLE IF NOT EXISTS audit_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    service_id BIGINT REFERENCES services(service_id) ON DELETE CASCADE,
    object_id BIGINT REFERENCES filesystem_objects(object_id) ON DELETE CASCADE,
    finding_code TEXT NOT NULL,
    severity TEXT NOT NULL
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'REMEDIATED', 'ACCEPTED_RISK')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (service_id IS NULL OR object_id IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_audit_findings_open
    ON audit_findings(endpoint_id, severity, observed_at DESC)
    WHERE status = 'OPEN';

-- The endpoint inventory represents a 64-bit Windows workstation.
INSERT INTO endpoints (
    hostname,
    windows_edition,
    os_build,
    os_architecture,
    secure_boot_enabled,
    tpm_present
)
VALUES (
    'OPS-WKS-014',
    'Windows 11 Enterprise',
    '26100',
    'x64',
    TRUE,
    TRUE
)
ON CONFLICT (hostname) DO NOTHING;

-- ON CONFLICT is used for repeatable training setup.
INSERT INTO principals (
    endpoint_id, sid, account_name, principal_type, enabled,
    is_builtin_administrator
)
SELECT e.endpoint_id, source.sid, source.account_name,
       source.principal_type, source.enabled, source.is_builtin_administrator
FROM endpoints e
CROSS JOIN (
    VALUES
    (
        'S-1-5-21-900-900-900-1001',
        'Riya',
        'LOCAL_USER',
        TRUE,
        FALSE
    ),
    (
        'S-1-5-21-900-900-900-1002',
        'InventorySvc',
        'SERVICE_IDENTITY',
        TRUE,
        FALSE
    ),
    (
        'S-1-5-21-900-900-900-500',
        'LocalAdmin',
        'LOCAL_USER',
        TRUE,
        TRUE
    ),
    (
        'S-1-5-32-544',
        'Administrators',
        'LOCAL_GROUP',
        TRUE,
        FALSE
    ),
    (
        'S-1-5-32-545',
        'Users',
        'LOCAL_GROUP',
        TRUE,
        FALSE
    )
) AS source(sid, account_name, principal_type, enabled, is_builtin_administrator)
WHERE e.hostname = 'OPS-WKS-014'
ON CONFLICT (endpoint_id, sid) DO NOTHING;

INSERT INTO group_memberships (
    endpoint_id, member_principal_id, group_principal_id, membership_source
)
SELECT e.endpoint_id, member.principal_id, grp.principal_id, 'LOCAL'
FROM endpoints e
JOIN principals member ON member.endpoint_id = e.endpoint_id
JOIN principals grp ON grp.endpoint_id = e.endpoint_id
WHERE e.hostname = 'OPS-WKS-014'
  AND (
      (member.account_name = 'InventorySvc'
       AND grp.account_name = 'Administrators')
      OR
      (member.account_name = 'Riya'
       AND grp.account_name = 'Users')
  )
ON CONFLICT DO NOTHING;

INSERT INTO services (
    endpoint_id,
    service_name,
    display_name,
    executable_path,
    run_as_principal_id,
    service_state,
    startup_type,
    executable_writable_by_standard_users,
    unquoted_path_with_spaces
)
SELECT e.endpoint_id,
       s.service_name,
       s.display_name,
       s.executable_path,
       p.principal_id,
       s.service_state,
       s.startup_type,
       s.executable_writable_by_standard_users,
       s.unquoted_path_with_spaces
FROM endpoints e
CROSS JOIN (
    VALUES
    (
        'InventoryAgent',
        'Inventory Collection Agent',
        'C:\Program Files\Contoso\Inventory\agent.exe',
        'InventorySvc',
        'RUNNING',
        'AUTOMATIC',
        TRUE,
        FALSE
    ),
    (
        'LegacyUpdater',
        'Legacy Software Updater',
        'C:\Program Files\Legacy Tools\update.exe',
        'LocalAdmin',
        'RUNNING',
        'AUTOMATIC',
        FALSE,
        TRUE
    ),
    (
        'DiagnosticAgent',
        'Diagnostic Agent',
        'C:\Windows\System32\diagnostic.exe',
        'InventorySvc',
        'DISABLED',
        'AUTOMATIC',
        FALSE,
        FALSE
    )
) AS s(
    service_name,
    display_name,
    executable_path,
    run_as_account,
    service_state,
    startup_type,
    executable_writable_by_standard_users,
    unquoted_path_with_spaces
)
JOIN principals p
  ON p.endpoint_id = e.endpoint_id
 AND p.account_name = s.run_as_account
WHERE e.hostname = 'OPS-WKS-014'
ON CONFLICT (endpoint_id, service_name) DO NOTHING;

INSERT INTO registry_settings (
    endpoint_id,
    root_hive,
    key_path,
    value_name,
    value_type,
    value_text,
    owner_principal_id,
    machine_wide
)
SELECT e.endpoint_id,
       r.root_hive,
       r.key_path,
       r.value_name,
       r.value_type,
       r.value_text,
       p.principal_id,
       r.machine_wide
FROM endpoints e
CROSS JOIN (
    VALUES
    (
        'HKLM',
        'SOFTWARE\Contoso\Inventory',
        'TelemetryEnabled',
        'REG_DWORD',
        '1',
        'LocalAdmin',
        TRUE
    ),
    (
        'HKCU',
        'Software\Contoso\Inventory',
        'LastWorkspace',
        'REG_SZ',
        'Operations',
        'Riya',
        FALSE
    )
) AS r(root_hive, key_path, value_name, value_type, value_text, owner_account, machine_wide)
JOIN principals p
  ON p.endpoint_id = e.endpoint_id
 AND p.account_name = r.owner_account
WHERE e.hostname = 'OPS-WKS-014'
ON CONFLICT (endpoint_id, root_hive, key_path, value_name) DO NOTHING;

INSERT INTO filesystem_objects (
    endpoint_id, object_path, object_type, owner_principal_id, inheritance_enabled
)
SELECT e.endpoint_id,
       'C:\ProgramData\Contoso\Inventory\settings.json',
       'FILE',
       p.principal_id,
       TRUE
FROM endpoints e
JOIN principals p
  ON p.endpoint_id = e.endpoint_id
 AND p.account_name = 'InventorySvc'
WHERE e.hostname = 'OPS-WKS-014'
ON CONFLICT (endpoint_id, object_path) DO NOTHING;

INSERT INTO filesystem_acl_entries (
    object_id, principal_id, access_type, rights, inherited
)
SELECT f.object_id, p.principal_id, a.access_type, a.rights, a.inherited
FROM endpoints e
JOIN filesystem_objects f
  ON f.endpoint_id = e.endpoint_id
 AND f.object_path = 'C:\ProgramData\Contoso\Inventory\settings.json'
CROSS JOIN (
    VALUES
    ('Riya', 'ALLOW', ARRAY['READ']::TEXT[], FALSE),
    ('Riya', 'DENY', ARRAY['WRITE']::TEXT[], FALSE),
    ('InventorySvc', 'ALLOW', ARRAY['READ', 'WRITE']::TEXT[], FALSE),
    ('LocalAdmin', 'ALLOW', ARRAY['FULL_CONTROL']::TEXT[], FALSE)
) AS a(account_name, access_type, rights, inherited)
JOIN principals p
  ON p.endpoint_id = e.endpoint_id
 AND p.account_name = a.account_name
WHERE e.hostname = 'OPS-WKS-014'
  AND NOT EXISTS (
      SELECT 1
      FROM filesystem_acl_entries existing
      WHERE existing.object_id = f.object_id
        AND existing.principal_id = p.principal_id
        AND existing.access_type = a.access_type
  );

-- View: identify service configurations that need investigation.
CREATE OR REPLACE VIEW service_risk_inventory AS
SELECT
    e.hostname,
    s.service_name,
    s.service_state,
    s.startup_type,
    p.account_name AS run_as_account,
    p.principal_type,
    s.executable_writable_by_standard_users,
    s.unquoted_path_with_spaces,
    CASE
        WHEN s.executable_writable_by_standard_users THEN 'CRITICAL'
        WHEN p.is_builtin_administrator
             AND s.service_state = 'RUNNING' THEN 'HIGH'
        WHEN s.unquoted_path_with_spaces THEN 'HIGH'
        WHEN s.service_state = 'DISABLED'
             AND s.startup_type IN ('AUTOMATIC', 'DELAYED_AUTOMATIC')
            THEN 'MEDIUM'
        ELSE 'LOW'
    END AS calculated_risk
FROM services s
JOIN endpoints e ON e.endpoint_id = s.endpoint_id
JOIN principals p ON p.principal_id = s.run_as_principal_id;

-- View: report machine-wide registry settings attributed to standard users.
CREATE OR REPLACE VIEW registry_ownership_review AS
SELECT
    e.hostname,
    r.root_hive,
    r.key_path,
    r.value_name,
    r.value_type,
    p.account_name AS recorded_owner,
    p.principal_type
FROM registry_settings r
JOIN endpoints e ON e.endpoint_id = r.endpoint_id
JOIN principals p ON p.principal_id = r.owner_principal_id
WHERE r.machine_wide
  AND p.principal_type IN ('LOCAL_USER', 'DOMAIN_USER');

-- Review services with the greatest modeled risk.
SELECT *
FROM service_risk_inventory
WHERE calculated_risk IN ('CRITICAL', 'HIGH', 'MEDIUM')
ORDER BY
    CASE calculated_risk
        WHEN 'CRITICAL' THEN 0
        WHEN 'HIGH' THEN 1
        ELSE 2
    END,
    hostname,
    service_name;

-- Group memberships show which accounts belong to sensitive local groups.
SELECT
    e.hostname,
    member.account_name AS member_name,
    grp.account_name AS group_name,
    member.principal_type,
    member.enabled
FROM group_memberships gm
JOIN endpoints e ON e.endpoint_id = gm.endpoint_id
JOIN principals member ON member.principal_id = gm.member_principal_id
JOIN principals grp ON grp.principal_id = gm.group_principal_id
WHERE grp.account_name = 'Administrators'
ORDER BY e.hostname, member.account_name;

-- Registry ownership review does not itself prove who can write a key.
-- Effective registry access depends on the actual key security descriptor.
SELECT *
FROM registry_ownership_review
ORDER BY hostname, root_hive, key_path;

-- Summarize the observed filesystem ACL records.
SELECT
    e.hostname,
    f.object_path,
    p.account_name,
    acl.access_type,
    unnest(acl.rights) AS right_name,
    acl.inherited
FROM filesystem_acl_entries acl
JOIN filesystem_objects f ON f.object_id = acl.object_id
JOIN endpoints e ON e.endpoint_id = f.endpoint_id
JOIN principals p ON p.principal_id = acl.principal_id
ORDER BY e.hostname, f.object_path, p.account_name, acl.access_type;

-- Create durable example findings without duplicating an existing finding.
INSERT INTO audit_findings (
    endpoint_id,
    service_id,
    finding_code,
    severity,
    description,
    remediation
)
SELECT e.endpoint_id,
       s.service_id,
       findings.finding_code,
       findings.severity,
       findings.description,
       findings.remediation
FROM endpoints e
JOIN services s ON s.endpoint_id = e.endpoint_id
CROSS JOIN (
    VALUES
    (
        'SERVICE_EXECUTABLE_WRITABLE',
        'CRITICAL',
        'Standard users can modify the InventoryAgent executable.',
        'Restrict executable and parent-directory write permissions.'
    ),
    (
        'SERVICE_ADMIN_IDENTITY',
        'HIGH',
        'LegacyUpdater runs under a built-in administrator identity.',
        'Use a dedicated least-privilege service identity.'
    )
) AS findings(finding_code, severity, description, remediation)
WHERE e.hostname = 'OPS-WKS-014'
  AND s.service_name = CASE findings.finding_code
      WHEN 'SERVICE_EXECUTABLE_WRITABLE' THEN 'InventoryAgent'
      WHEN 'SERVICE_ADMIN_IDENTITY' THEN 'LegacyUpdater'
  END
  AND NOT EXISTS (
      SELECT 1
      FROM audit_findings existing
      WHERE existing.endpoint_id = e.endpoint_id
        AND existing.service_id = s.service_id
        AND existing.finding_code = findings.finding_code
        AND existing.status = 'OPEN'
  );

SELECT
    e.hostname,
    f.finding_code,
    f.severity,
    f.status,
    f.description,
    f.remediation,
    f.observed_at
FROM audit_findings f
JOIN endpoints e ON e.endpoint_id = f.endpoint_id
WHERE f.status = 'OPEN'
ORDER BY
    CASE f.severity
        WHEN 'CRITICAL' THEN 0
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END,
    f.observed_at DESC;

-- Atomicity matters when recording a multi-table inventory snapshot.
-- This transaction succeeds only when the inserted observation is valid.
SAVEPOINT before_inventory_test;

INSERT INTO filesystem_objects (
    endpoint_id, object_path, object_type, inheritance_enabled
)
SELECT endpoint_id,
       'C:\ProgramData\Contoso\Inventory\logs',
       'DIRECTORY',
       TRUE
FROM endpoints
WHERE hostname = 'OPS-WKS-014'
ON CONFLICT (endpoint_id, object_path) DO NOTHING;

RELEASE SAVEPOINT before_inventory_test;

COMMIT;
