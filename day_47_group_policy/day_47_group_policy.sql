-- PostgreSQL 15+ Group Policy governance laboratory.
-- Models policy objects, scope links, workstation assignments, password
-- controls, reviewable settings, and effective configuration evaluation.
--
-- This schema is a governance simulation, not a Windows GPO backup format.
-- Run in a dedicated learning database because the script recreates its schema.

BEGIN;

DROP SCHEMA IF EXISTS group_policy_lab CASCADE;
CREATE SCHEMA group_policy_lab;
SET search_path TO group_policy_lab, public;

CREATE TYPE policy_category AS ENUM (
    'security',
    'password',
    'workstation'
);

CREATE TYPE policy_scope_type AS ENUM (
    'site',
    'domain',
    'ou'
);

CREATE TYPE policy_link_mode AS ENUM (
    'normal',
    'enforced'
);

CREATE TYPE setting_value_type AS ENUM (
    'boolean',
    'integer',
    'text'
);

CREATE TABLE repositories (
    repository_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    directory_name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (length(trim(directory_name)) > 0)
);

CREATE TABLE policy_scopes (
    scope_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    scope_type policy_scope_type NOT NULL,
    scope_name TEXT NOT NULL,
    parent_scope_id BIGINT REFERENCES policy_scopes(scope_id)
        ON DELETE RESTRICT,
    UNIQUE (repository_id, scope_type, scope_name),
    CHECK (length(trim(scope_name)) > 0),
    CHECK (parent_scope_id IS NULL OR parent_scope_id <> scope_id)
);

CREATE TABLE group_policy_objects (
    gpo_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    gpo_name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (repository_id, gpo_name),
    CHECK (length(trim(gpo_name)) > 0)
);

CREATE TABLE policy_settings (
    setting_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    gpo_id BIGINT NOT NULL REFERENCES group_policy_objects(gpo_id)
        ON DELETE CASCADE,
    setting_name TEXT NOT NULL,
    category policy_category NOT NULL,
    value_type setting_value_type NOT NULL,
    boolean_value BOOLEAN,
    integer_value INTEGER,
    text_value TEXT,
    UNIQUE (gpo_id, setting_name),
    CHECK (
        (value_type = 'boolean'
            AND boolean_value IS NOT NULL
            AND integer_value IS NULL
            AND text_value IS NULL)
        OR
        (value_type = 'integer'
            AND boolean_value IS NULL
            AND integer_value IS NOT NULL
            AND text_value IS NULL)
        OR
        (value_type = 'text'
            AND boolean_value IS NULL
            AND integer_value IS NULL
            AND text_value IS NOT NULL)
    ),
    CHECK (
        setting_name NOT IN (
            'minimum_password_length',
            'password_history_count',
            'maximum_password_age_days',
            'minimum_password_age_days'
        )
        OR category = 'password'
    ),
    CHECK (
        setting_name <> 'minimum_password_length'
        OR (
            value_type = 'integer'
            AND integer_value BETWEEN 8 AND 128
        )
    ),
    CHECK (
        setting_name <> 'password_history_count'
        OR (
            value_type = 'integer'
            AND integer_value BETWEEN 0 AND 50
        )
    ),
    CHECK (
        setting_name NOT IN (
            'maximum_password_age_days',
            'minimum_password_age_days'
        )
        OR (
            value_type = 'integer'
            AND integer_value BETWEEN 0 AND 365
        )
    ),
    CHECK (
        setting_name <> 'screen_lock_timeout_minutes'
        OR (
            category = 'workstation'
            AND value_type = 'integer'
            AND integer_value BETWEEN 1 AND 1440
        )
    )
);

CREATE TABLE policy_links (
    link_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    gpo_id BIGINT NOT NULL REFERENCES group_policy_objects(gpo_id)
        ON DELETE CASCADE,
    scope_id BIGINT NOT NULL REFERENCES policy_scopes(scope_id)
        ON DELETE CASCADE,
    link_order INTEGER NOT NULL CHECK (link_order > 0),
    mode policy_link_mode NOT NULL DEFAULT 'normal',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    block_inheritance BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (gpo_id, scope_id)
);

CREATE TABLE workstations (
    workstation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    site_scope_id BIGINT REFERENCES policy_scopes(scope_id),
    domain_scope_id BIGINT REFERENCES policy_scopes(scope_id),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (repository_id, hostname),
    CHECK (length(trim(hostname)) > 0)
);

CREATE TABLE workstation_ou_memberships (
    workstation_id BIGINT NOT NULL REFERENCES workstations(workstation_id)
        ON DELETE CASCADE,
    scope_id BIGINT NOT NULL REFERENCES policy_scopes(scope_id)
        ON DELETE CASCADE,
    membership_order INTEGER NOT NULL CHECK (membership_order > 0),
    PRIMARY KEY (workstation_id, scope_id),
    UNIQUE (workstation_id, membership_order)
);

CREATE TABLE directory_users (
    user_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    username TEXT NOT NULL,
    department TEXT NOT NULL,
    account_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (repository_id, username),
    CHECK (length(trim(username)) > 0)
);

CREATE TABLE security_groups (
    group_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories(repository_id)
        ON DELETE CASCADE,
    group_name TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE (repository_id, group_name)
);

CREATE TABLE user_group_memberships (
    user_id BIGINT NOT NULL REFERENCES directory_users(user_id)
        ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES security_groups(group_id)
        ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE policy_audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workstation_id BIGINT REFERENCES workstations(workstation_id)
        ON DELETE SET NULL,
    gpo_id BIGINT REFERENCES group_policy_objects(gpo_id)
        ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    event_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (length(trim(event_type)) > 0)
);

CREATE INDEX policy_links_scope_order_idx
    ON policy_links(scope_id, enabled, link_order);

CREATE INDEX policy_settings_name_category_idx
    ON policy_settings(setting_name, category);

CREATE INDEX workstation_ou_memberships_scope_idx
    ON workstation_ou_memberships(scope_id, workstation_id);

CREATE INDEX policy_audit_events_recorded_idx
    ON policy_audit_events(recorded_at DESC);

-- Prevent settings from using a category inconsistent with their meaning.
CREATE FUNCTION validate_policy_setting_category()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.setting_name IN (
        'minimum_password_length',
        'password_history_count',
        'maximum_password_age_days',
        'minimum_password_age_days',
        'password_complexity_enabled'
    ) AND NEW.category <> 'password' THEN
        RAISE EXCEPTION
            'Setting % must belong to the password category',
            NEW.setting_name;
    END IF;

    IF NEW.setting_name IN (
        'firewall_enabled',
        'usb_storage_blocked',
        'screen_lock_enabled',
        'screen_lock_timeout_minutes',
        'local_admin_installation_blocked',
        'removable_media_auditing'
    ) AND NEW.category <> 'workstation' THEN
        RAISE EXCEPTION
            'Setting % must belong to the workstation category',
            NEW.setting_name;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER policy_setting_category_guard
BEFORE INSERT OR UPDATE ON policy_settings
FOR EACH ROW
EXECUTE FUNCTION validate_policy_setting_category();

-- Sample directory and scope hierarchy.
INSERT INTO repositories (directory_name, description)
VALUES (
    'corp.example',
    'Corporate directory policy simulation for managed endpoints.'
);

INSERT INTO policy_scopes (
    repository_id, scope_type, scope_name, parent_scope_id
)
SELECT repository_id, 'site', 'North-Office', NULL
FROM repositories
WHERE directory_name = 'corp.example';

INSERT INTO policy_scopes (
    repository_id, scope_type, scope_name, parent_scope_id
)
SELECT r.repository_id, 'domain', 'corp.example', s.scope_id
FROM repositories r
JOIN policy_scopes s
    ON s.repository_id = r.repository_id
   AND s.scope_type = 'site'
   AND s.scope_name = 'North-Office'
WHERE r.directory_name = 'corp.example';

INSERT INTO policy_scopes (
    repository_id, scope_type, scope_name, parent_scope_id
)
SELECT r.repository_id, 'ou', 'Engineering', d.scope_id
FROM repositories r
JOIN policy_scopes d
    ON d.repository_id = r.repository_id
   AND d.scope_type = 'domain'
   AND d.scope_name = 'corp.example'
WHERE r.directory_name = 'corp.example';

INSERT INTO policy_scopes (
    repository_id, scope_type, scope_name, parent_scope_id
)
SELECT r.repository_id, 'ou', 'Research', d.scope_id
FROM repositories r
JOIN policy_scopes d
    ON d.repository_id = r.repository_id
   AND d.scope_type = 'domain'
   AND d.scope_name = 'corp.example'
WHERE r.directory_name = 'corp.example';

INSERT INTO group_policy_objects (
    repository_id, gpo_name, description
)
SELECT repository_id, 'Domain-Security-Baseline',
       'Enforced account security and baseline workstation protection.'
FROM repositories
WHERE directory_name = 'corp.example';

INSERT INTO group_policy_objects (
    repository_id, gpo_name, description
)
SELECT repository_id, 'Engineering-Workstations',
       'Restrictions for engineering workstation devices.'
FROM repositories
WHERE directory_name = 'corp.example';

INSERT INTO group_policy_objects (
    repository_id, gpo_name, description
)
SELECT repository_id, 'Legacy-Firewall-Exception',
       'Conflicting legacy setting used to test precedence.'
FROM repositories
WHERE directory_name = 'corp.example';

INSERT INTO policy_settings (
    gpo_id, setting_name, category, value_type,
    boolean_value, integer_value, text_value
)
SELECT g.gpo_id, v.setting_name, v.category::policy_category,
       v.value_type::setting_value_type, v.boolean_value,
       v.integer_value, v.text_value
FROM group_policy_objects g
CROSS JOIN (
    VALUES
        ('firewall_enabled', 'workstation', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT),
        ('interactive_logon_banner_enabled', 'security', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT),
        ('minimum_password_length', 'password', 'integer',
            NULL::BOOLEAN, 14, NULL::TEXT),
        ('password_history_count', 'password', 'integer',
            NULL::BOOLEAN, 24, NULL::TEXT),
        ('maximum_password_age_days', 'password', 'integer',
            NULL::BOOLEAN, 0, NULL::TEXT),
        ('minimum_password_age_days', 'password', 'integer',
            NULL::BOOLEAN, 1, NULL::TEXT),
        ('password_complexity_enabled', 'password', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT),
        ('lockout_threshold', 'security', 'integer',
            NULL::BOOLEAN, 10, NULL::TEXT)
) AS v(
    setting_name, category, value_type,
    boolean_value, integer_value, text_value
)
WHERE g.gpo_name = 'Domain-Security-Baseline';

INSERT INTO policy_settings (
    gpo_id, setting_name, category, value_type,
    boolean_value, integer_value, text_value
)
SELECT g.gpo_id, v.setting_name, v.category::policy_category,
       v.value_type::setting_value_type, v.boolean_value,
       v.integer_value, v.text_value
FROM group_policy_objects g
CROSS JOIN (
    VALUES
        ('usb_storage_blocked', 'workstation', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT),
        ('screen_lock_enabled', 'workstation', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT),
        ('screen_lock_timeout_minutes', 'workstation', 'integer',
            NULL::BOOLEAN, 10, NULL::TEXT),
        ('local_admin_installation_blocked', 'workstation', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT),
        ('removable_media_auditing', 'workstation', 'boolean',
            TRUE, NULL::INTEGER, NULL::TEXT)
) AS v(
    setting_name, category, value_type,
    boolean_value, integer_value, text_value
)
WHERE g.gpo_name = 'Engineering-Workstations';

INSERT INTO policy_settings (
    gpo_id, setting_name, category, value_type, boolean_value
)
SELECT gpo_id, 'firewall_enabled', 'workstation', 'boolean', FALSE
FROM group_policy_objects
WHERE gpo_name = 'Legacy-Firewall-Exception';

INSERT INTO policy_links (
    gpo_id, scope_id, link_order, mode, enabled
)
SELECT g.gpo_id, s.scope_id, 1, 'enforced', TRUE
FROM group_policy_objects g
JOIN policy_scopes s
    ON s.repository_id = g.repository_id
   AND s.scope_type = 'domain'
   AND s.scope_name = 'corp.example'
WHERE g.gpo_name = 'Domain-Security-Baseline';

INSERT INTO policy_links (
    gpo_id, scope_id, link_order, mode, enabled
)
SELECT g.gpo_id, s.scope_id, 1, 'normal', TRUE
FROM group_policy_objects g
JOIN policy_scopes s
    ON s.repository_id = g.repository_id
   AND s.scope_type = 'ou'
   AND s.scope_name = 'Engineering'
WHERE g.gpo_name = 'Engineering-Workstations';

INSERT INTO policy_links (
    gpo_id, scope_id, link_order, mode, enabled
)
SELECT g.gpo_id, s.scope_id, 2, 'normal', TRUE
FROM group_policy_objects g
JOIN policy_scopes s
    ON s.repository_id = g.repository_id
   AND s.scope_type = 'ou'
   AND s.scope_name = 'Engineering'
WHERE g.gpo_name = 'Legacy-Firewall-Exception';

INSERT INTO workstations (
    repository_id, hostname, site_scope_id, domain_scope_id
)
SELECT r.repository_id, 'ENG-WS-042', site.scope_id, domain.scope_id
FROM repositories r
JOIN policy_scopes site
    ON site.repository_id = r.repository_id
   AND site.scope_type = 'site'
   AND site.scope_name = 'North-Office'
JOIN policy_scopes domain
    ON domain.repository_id = r.repository_id
   AND domain.scope_type = 'domain'
   AND domain.scope_name = 'corp.example'
WHERE r.directory_name = 'corp.example';

INSERT INTO workstation_ou_memberships (
    workstation_id, scope_id, membership_order
)
SELECT w.workstation_id, ou.scope_id, 1
FROM workstations w
JOIN repositories r ON r.repository_id = w.repository_id
JOIN policy_scopes ou
    ON ou.repository_id = r.repository_id
   AND ou.scope_type = 'ou'
   AND ou.scope_name = 'Engineering'
WHERE w.hostname = 'ENG-WS-042';

INSERT INTO directory_users (repository_id, username, department)
SELECT repository_id, 'engineering.operator', 'Engineering'
FROM repositories
WHERE directory_name = 'corp.example';

INSERT INTO security_groups (repository_id, group_name, description)
SELECT repository_id, 'Standard-Users',
       'Users without workstation administration privileges.'
FROM repositories
WHERE directory_name = 'corp.example';

INSERT INTO user_group_memberships (user_id, group_id)
SELECT u.user_id, g.group_id
FROM directory_users u
JOIN security_groups g ON g.repository_id = u.repository_id
WHERE u.username = 'engineering.operator'
  AND g.group_name = 'Standard-Users';

INSERT INTO policy_audit_events (
    workstation_id, gpo_id, event_type, event_detail
)
SELECT w.workstation_id, g.gpo_id, 'policy_link_created',
       jsonb_build_object(
           'link_mode', 'enforced',
           'scope', 'corp.example',
           'purpose', 'protect baseline firewall configuration'
       )
FROM workstations w
JOIN group_policy_objects g
    ON g.repository_id = w.repository_id
WHERE w.hostname = 'ENG-WS-042'
  AND g.gpo_name = 'Domain-Security-Baseline';

-- Compute applicable links for one workstation. The effective-policy query
-- treats enforced settings as immutable against normal links and otherwise
-- lets later scope/link-order entries replace earlier values.
CREATE VIEW workstation_effective_policy AS
WITH applicable AS (
    SELECT
        w.workstation_id,
        w.hostname,
        l.link_id,
        l.gpo_id,
        g.gpo_name,
        l.mode,
        l.link_order,
        CASE s.scope_type
            WHEN 'site' THEN 0
            WHEN 'domain' THEN 1
            WHEN 'ou' THEN 2
        END AS scope_depth,
        ps.setting_name,
        ps.category,
        ps.value_type,
        ps.boolean_value,
        ps.integer_value,
        ps.text_value
    FROM workstations w
    JOIN policy_links l ON l.enabled
    JOIN group_policy_objects g
        ON g.gpo_id = l.gpo_id
       AND g.enabled
    JOIN policy_scopes s ON s.scope_id = l.scope_id
    JOIN policy_settings ps ON ps.gpo_id = g.gpo_id
    WHERE
        (s.scope_type = 'site' AND s.scope_id = w.site_scope_id)
        OR
        (s.scope_type = 'domain' AND s.scope_id = w.domain_scope_id)
        OR
        (
            s.scope_type = 'ou'
            AND EXISTS (
                SELECT 1
                FROM workstation_ou_memberships membership
                WHERE membership.workstation_id = w.workstation_id
                  AND membership.scope_id = s.scope_id
            )
        )
),
ranked AS (
    SELECT
        applicable.*,
        bool_or(mode = 'enforced') OVER (
            PARTITION BY workstation_id, setting_name
        ) AS has_enforced_value,
        first_value(gpo_name) OVER (
            PARTITION BY workstation_id, setting_name
            ORDER BY
                (mode = 'enforced') DESC,
                scope_depth DESC,
                link_order DESC,
                gpo_name DESC
        ) AS selected_gpo,
        row_number() OVER (
            PARTITION BY workstation_id, setting_name
            ORDER BY
                (mode = 'enforced') DESC,
                scope_depth DESC,
                link_order DESC,
                gpo_name DESC
        ) AS preference_rank
    FROM applicable
)
SELECT
    workstation_id,
    hostname,
    setting_name,
    category,
    value_type,
    boolean_value,
    integer_value,
    text_value,
    selected_gpo AS source_gpo
FROM ranked
WHERE preference_rank = 1;

-- Inspect the effective configuration and provenance.
SELECT
    hostname,
    setting_name,
    COALESCE(
        boolean_value::TEXT,
        integer_value::TEXT,
        text_value
    ) AS effective_value,
    source_gpo
FROM workstation_effective_policy
WHERE hostname = 'ENG-WS-042'
ORDER BY setting_name;

-- Password baseline audit: these rows identify weak effective settings.
SELECT
    hostname,
    setting_name,
    integer_value AS effective_integer,
    source_gpo,
    CASE
        WHEN setting_name = 'minimum_password_length'
             AND integer_value < 14
            THEN 'Password length below organizational baseline'
        WHEN setting_name = 'password_history_count'
             AND integer_value < 12
            THEN 'Password history below organizational baseline'
        WHEN setting_name = 'maximum_password_age_days'
             AND integer_value < 0
            THEN 'Invalid maximum password age'
    END AS finding
FROM workstation_effective_policy
WHERE setting_name IN (
    'minimum_password_length',
    'password_history_count',
    'maximum_password_age_days'
)
AND (
    (setting_name = 'minimum_password_length' AND integer_value < 14)
    OR
    (setting_name = 'password_history_count' AND integer_value < 12)
    OR
    (setting_name = 'maximum_password_age_days' AND integer_value < 0)
);

-- Endpoint compliance checks.
SELECT
    hostname,
    setting_name,
    boolean_value,
    source_gpo
FROM workstation_effective_policy
WHERE hostname = 'ENG-WS-042'
  AND setting_name IN (
      'firewall_enabled',
      'usb_storage_blocked',
      'screen_lock_enabled',
      'local_admin_installation_blocked',
      'removable_media_auditing'
  )
ORDER BY setting_name;

-- Inspect which links participate in workstation policy evaluation.
SELECT
    w.hostname,
    s.scope_type,
    s.scope_name,
    g.gpo_name,
    l.link_order,
    l.mode,
    l.enabled
FROM workstations w
JOIN policy_scopes s
    ON s.scope_id = w.site_scope_id
    OR s.scope_id = w.domain_scope_id
    OR EXISTS (
        SELECT 1
        FROM workstation_ou_memberships m
        WHERE m.workstation_id = w.workstation_id
          AND m.scope_id = s.scope_id
    )
JOIN policy_links l ON l.scope_id = s.scope_id
JOIN group_policy_objects g ON g.gpo_id = l.gpo_id
WHERE w.hostname = 'ENG-WS-042'
ORDER BY
    CASE s.scope_type
        WHEN 'site' THEN 0
        WHEN 'domain' THEN 1
        WHEN 'ou' THEN 2
    END,
    l.link_order;

-- Database-level rejection example. Uncomment to observe the CHECK failure:
-- INSERT INTO policy_settings (
--     gpo_id, setting_name, category, value_type, integer_value
-- )
-- SELECT gpo_id, 'minimum_password_length', 'password', 'integer', 4
-- FROM group_policy_objects
-- WHERE gpo_name = 'Domain-Security-Baseline';
--
-- The minimum length constraint rejects this row. Application validation
-- should complement, not replace, database integrity rules.

COMMIT;
