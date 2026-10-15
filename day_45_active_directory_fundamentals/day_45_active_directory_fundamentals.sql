-- Active Directory Fundamentals: PostgreSQL directory governance laboratory.
--
-- This relational model represents domain identities and administration.
-- PostgreSQL does not implement Active Directory, LDAP, Kerberos, or native
-- Windows Group Policy. The schema is an executable domain model for learning
-- identity structure, group nesting, policy links, and authorization evidence.

BEGIN;

DROP SCHEMA IF EXISTS ad_lab CASCADE;
CREATE SCHEMA ad_lab;
SET search_path = ad_lab, public;

CREATE TYPE directory_object_kind AS ENUM (
    'user', 'security_group', 'distribution_group', 'computer', 'organizational_unit'
);

CREATE TYPE group_scope AS ENUM ('global', 'domain_local', 'universal');

CREATE TYPE account_status AS ENUM ('enabled', 'disabled', 'locked');

CREATE TYPE controller_role AS ENUM (
    'schema_master',
    'domain_naming_master',
    'rid_master',
    'pdc_emulator',
    'infrastructure_master'
);

CREATE TABLE domains (
    domain_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dns_name text NOT NULL UNIQUE,
    netbios_name varchar(15) NOT NULL UNIQUE,
    domain_dn text NOT NULL UNIQUE,
    functional_level text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT domain_dns_shape CHECK (
        dns_name = lower(dns_name)
        AND dns_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    ),
    CONSTRAINT domain_netbios_shape CHECK (
        netbios_name ~ '^[A-Z0-9-]{1,15}$'
    )
);

CREATE TABLE organizational_units (
    ou_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    parent_ou_id bigint,
    ou_name text NOT NULL,
    distinguished_name text NOT NULL,
    protected_from_deletion boolean NOT NULL DEFAULT true,
    block_inheritance boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ou_name_nonempty CHECK (length(trim(ou_name)) > 0),
    CONSTRAINT ou_dn_unique UNIQUE (domain_id, distinguished_name),
    CONSTRAINT ou_parent_fk FOREIGN KEY (parent_ou_id)
        REFERENCES organizational_units(ou_id) ON DELETE RESTRICT,
    CONSTRAINT ou_not_own_parent CHECK (
        parent_ou_id IS NULL OR parent_ou_id <> ou_id
    ),
    UNIQUE (domain_id, parent_ou_id, ou_name)
);

CREATE TABLE domain_controllers (
    controller_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    hostname text NOT NULL,
    site_name text NOT NULL,
    writable boolean NOT NULL DEFAULT true,
    global_catalog boolean NOT NULL DEFAULT true,
    reachable boolean NOT NULL DEFAULT true,
    observed_revision bigint NOT NULL DEFAULT 0 CHECK (observed_revision >= 0),
    UNIQUE (domain_id, hostname)
);

CREATE TABLE controller_operations_roles (
    controller_id bigint NOT NULL
        REFERENCES domain_controllers(controller_id) ON DELETE CASCADE,
    role controller_role NOT NULL,
    PRIMARY KEY (controller_id, role)
);

CREATE TABLE directory_users (
    user_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    ou_id bigint NOT NULL REFERENCES organizational_units(ou_id) ON DELETE RESTRICT,
    display_name text NOT NULL,
    sam_account_name varchar(20) NOT NULL,
    user_principal_name text NOT NULL,
    department text NOT NULL,
    status account_status NOT NULL DEFAULT 'enabled',
    mfa_registered boolean NOT NULL DEFAULT false,
    failed_logons integer NOT NULL DEFAULT 0 CHECK (failed_logons >= 0),
    password_last_set timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_name_nonempty CHECK (length(trim(display_name)) > 0),
    CONSTRAINT user_sam_shape CHECK (
        sam_account_name ~ '^[A-Za-z0-9._-]{1,20}$'
    ),
    CONSTRAINT user_upn_nonempty CHECK (position('@' IN user_principal_name) > 1),
    UNIQUE (domain_id, sam_account_name),
    UNIQUE (domain_id, user_principal_name),
    UNIQUE (domain_id, ou_id, display_name)
);

CREATE TABLE directory_groups (
    group_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    ou_id bigint NOT NULL REFERENCES organizational_units(ou_id) ON DELETE RESTRICT,
    group_name text NOT NULL,
    distinguished_name text NOT NULL,
    scope group_scope NOT NULL,
    object_kind directory_object_kind NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT group_kind_valid CHECK (
        object_kind IN ('security_group', 'distribution_group')
    ),
    CONSTRAINT group_name_nonempty CHECK (length(trim(group_name)) > 0),
    UNIQUE (domain_id, distinguished_name),
    UNIQUE (domain_id, ou_id, group_name)
);

CREATE TABLE directory_computers (
    computer_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    ou_id bigint NOT NULL REFERENCES organizational_units(ou_id) ON DELETE RESTRICT,
    hostname text NOT NULL,
    operating_system text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    secure_channel_healthy boolean NOT NULL DEFAULT true,
    last_logon timestamptz,
    UNIQUE (domain_id, hostname)
);

-- A single membership relation supports user-to-group and nested-group edges.
-- A trigger validates object types and rejects cycles in the group graph.
CREATE TABLE group_memberships (
    group_id bigint NOT NULL
        REFERENCES directory_groups(group_id) ON DELETE CASCADE,
    member_user_id bigint REFERENCES directory_users(user_id) ON DELETE RESTRICT,
    member_group_id bigint REFERENCES directory_groups(group_id) ON DELETE RESTRICT,
    added_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT exactly_one_member_kind CHECK (
        (member_user_id IS NOT NULL AND member_group_id IS NULL)
        OR (member_user_id IS NULL AND member_group_id IS NOT NULL)
    ),
    CONSTRAINT no_direct_self_membership CHECK (
        member_group_id IS NULL OR member_group_id <> group_id
    )
);

CREATE UNIQUE INDEX membership_user_unique
    ON group_memberships(group_id, member_user_id)
    WHERE member_user_id IS NOT NULL;

CREATE UNIQUE INDEX membership_group_unique
    ON group_memberships(group_id, member_group_id)
    WHERE member_group_id IS NOT NULL;

CREATE TABLE group_policy_objects (
    gpo_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    gpo_name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    user_configuration_enabled boolean NOT NULL DEFAULT true,
    computer_configuration_enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (domain_id, gpo_name)
);

CREATE TABLE gpo_settings (
    gpo_id bigint NOT NULL
        REFERENCES group_policy_objects(gpo_id) ON DELETE CASCADE,
    setting_name text NOT NULL,
    setting_value jsonb NOT NULL,
    PRIMARY KEY (gpo_id, setting_name),
    CONSTRAINT supported_setting CHECK (
        setting_name IN (
            'password_min_length',
            'lockout_threshold',
            'require_mfa',
            'usb_storage_allowed',
            'screen_lock_minutes',
            'firewall_enabled'
        )
    ),
    CONSTRAINT valid_setting_value CHECK (
        CASE setting_name
            WHEN 'password_min_length' THEN
                jsonb_typeof(setting_value) = 'number'
                AND (setting_value #>> '{}')::numeric BETWEEN 8 AND 128
            WHEN 'lockout_threshold' THEN
                jsonb_typeof(setting_value) = 'number'
                AND (setting_value #>> '{}')::numeric BETWEEN 0 AND 20
            WHEN 'screen_lock_minutes' THEN
                jsonb_typeof(setting_value) = 'number'
                AND (setting_value #>> '{}')::numeric BETWEEN 1 AND 240
            WHEN 'require_mfa' THEN jsonb_typeof(setting_value) = 'boolean'
            WHEN 'usb_storage_allowed' THEN jsonb_typeof(setting_value) = 'boolean'
            WHEN 'firewall_enabled' THEN jsonb_typeof(setting_value) = 'boolean'
            ELSE false
        END
    )
);

CREATE TABLE gpo_links (
    link_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    gpo_id bigint NOT NULL
        REFERENCES group_policy_objects(gpo_id) ON DELETE CASCADE,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    target_ou_id bigint NOT NULL
        REFERENCES organizational_units(ou_id) ON DELETE RESTRICT,
    link_order integer NOT NULL DEFAULT 1 CHECK (link_order > 0),
    enforced boolean NOT NULL DEFAULT false,
    link_disabled boolean NOT NULL DEFAULT false,
    UNIQUE (gpo_id, target_ou_id)
);

CREATE INDEX gpo_links_target_order_idx
    ON gpo_links(target_ou_id, link_order DESC)
    WHERE link_disabled = false;

CREATE TABLE access_resources (
    resource_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    resource_name text NOT NULL,
    required_group_id bigint NOT NULL
        REFERENCES directory_groups(group_id) ON DELETE RESTRICT,
    description text NOT NULL,
    UNIQUE (domain_id, resource_name)
);

CREATE TABLE authentication_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    user_id bigint REFERENCES directory_users(user_id) ON DELETE SET NULL,
    account_name_attempted text NOT NULL,
    outcome text NOT NULL CHECK (
        outcome IN ('success', 'invalid_credentials', 'locked', 'disabled', 'mfa_required')
    ),
    controller_id bigint REFERENCES domain_controllers(controller_id) ON DELETE SET NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE directory_audit_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    domain_id bigint NOT NULL REFERENCES domains(domain_id) ON DELETE RESTRICT,
    actor text NOT NULL,
    action text NOT NULL,
    object_type text NOT NULL,
    object_reference text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX users_department_status_idx
    ON directory_users(domain_id, department, status);

CREATE INDEX memberships_member_user_idx
    ON group_memberships(member_user_id)
    WHERE member_user_id IS NOT NULL;

CREATE INDEX memberships_member_group_idx
    ON group_memberships(member_group_id)
    WHERE member_group_id IS NOT NULL;

CREATE INDEX audit_domain_time_idx
    ON directory_audit_events(domain_id, occurred_at DESC);

-- The recursive path prevents nested security-group cycles.
CREATE FUNCTION validate_group_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    target_domain bigint;
    member_domain bigint;
    target_kind directory_object_kind;
    member_kind directory_object_kind;
    creates_cycle boolean;
BEGIN
    SELECT domain_id, object_kind
      INTO target_domain, target_kind
      FROM directory_groups
     WHERE group_id = NEW.group_id;

    IF target_domain IS NULL THEN
        RAISE EXCEPTION 'Target group does not exist';
    END IF;

    IF target_kind <> 'security_group' THEN
        RAISE EXCEPTION 'Distribution groups cannot grant security access';
    END IF;

    IF NEW.member_user_id IS NOT NULL THEN
        SELECT domain_id INTO member_domain
          FROM directory_users WHERE user_id = NEW.member_user_id;

        IF member_domain IS NULL THEN
            RAISE EXCEPTION 'Member user does not exist';
        END IF;

        IF member_domain <> target_domain THEN
            RAISE EXCEPTION 'This laboratory restricts membership to one domain';
        END IF;
    ELSE
        SELECT domain_id, object_kind
          INTO member_domain, member_kind
          FROM directory_groups
         WHERE group_id = NEW.member_group_id;

        IF member_domain IS NULL THEN
            RAISE EXCEPTION 'Nested member group does not exist';
        END IF;

        IF member_domain <> target_domain THEN
            RAISE EXCEPTION 'This laboratory restricts nested membership to one domain';
        END IF;

        IF member_kind <> 'security_group' THEN
            RAISE EXCEPTION 'A distribution group cannot be nested as a security principal';
        END IF;

        WITH RECURSIVE descendants(group_id, path) AS (
            SELECT NEW.member_group_id,
                   ARRAY[NEW.member_group_id]::bigint[]
            UNION ALL
            SELECT gm.member_group_id,
                   d.path || gm.member_group_id
              FROM descendants d
              JOIN group_memberships gm
                ON gm.group_id = d.group_id
             WHERE gm.member_group_id IS NOT NULL
               AND NOT gm.member_group_id = ANY(d.path)
        )
        SELECT EXISTS (
            SELECT 1
              FROM descendants
             WHERE group_id = NEW.group_id
        )
        INTO creates_cycle;

        IF creates_cycle THEN
            RAISE EXCEPTION 'Nested group membership would create a cycle';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER group_membership_validation
BEFORE INSERT OR UPDATE ON group_memberships
FOR EACH ROW EXECUTE FUNCTION validate_group_membership();

-- Protected OUs cannot be deleted while the protection flag is set.
CREATE FUNCTION protect_organizational_unit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.protected_from_deletion THEN
        RAISE EXCEPTION 'OU % is protected from accidental deletion', OLD.ou_name;
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER organizational_unit_deletion_guard
BEFORE DELETE ON organizational_units
FOR EACH ROW EXECUTE FUNCTION protect_organizational_unit();

-- Sample domain and root OU.
INSERT INTO domains (
    dns_name, netbios_name, domain_dn, functional_level
) VALUES (
    'corp.example.com',
    'CORP',
    'DC=corp,DC=example,DC=com',
    'Windows Server 2016 or later'
);

INSERT INTO organizational_units (
    domain_id, parent_ou_id, ou_name, distinguished_name
)
SELECT domain_id, NULL, 'Domain Root', domain_dn
FROM domains
WHERE dns_name = 'corp.example.com';

INSERT INTO domain_controllers (
    domain_id, hostname, site_name, writable, global_catalog
)
SELECT domain_id, 'DC01', 'Lucknow', true, true
FROM domains WHERE dns_name = 'corp.example.com';

INSERT INTO domain_controllers (
    domain_id, hostname, site_name, writable, global_catalog
)
SELECT domain_id, 'DC02', 'Delhi', true, true
FROM domains WHERE dns_name = 'corp.example.com';

INSERT INTO controller_operations_roles(controller_id, role)
SELECT controller_id, 'pdc_emulator'
FROM domain_controllers WHERE hostname = 'DC01';

INSERT INTO controller_operations_roles(controller_id, role)
SELECT controller_id, 'rid_master'
FROM domain_controllers WHERE hostname = 'DC01';

INSERT INTO organizational_units (
    domain_id, parent_ou_id, ou_name, distinguished_name
)
SELECT d.domain_id, root.ou_id, 'Engineering',
       'OU=Engineering,' || d.domain_dn
FROM domains d
JOIN organizational_units root
  ON root.domain_id = d.domain_id AND root.parent_ou_id IS NULL;

INSERT INTO organizational_units (
    domain_id, parent_ou_id, ou_name, distinguished_name
)
SELECT d.domain_id, engineering.ou_id, 'Privileged',
       'OU=Privileged,OU=Engineering,' || d.domain_dn
FROM domains d
JOIN organizational_units engineering
  ON engineering.domain_id = d.domain_id
 AND engineering.ou_name = 'Engineering';

INSERT INTO organizational_units (
    domain_id, parent_ou_id, ou_name, distinguished_name
)
SELECT d.domain_id, root.ou_id, 'Employees',
       'OU=Employees,' || d.domain_dn
FROM domains d
JOIN organizational_units root
  ON root.domain_id = d.domain_id AND root.parent_ou_id IS NULL;

INSERT INTO directory_users (
    domain_id, ou_id, display_name, sam_account_name,
    user_principal_name, department, status, mfa_registered, password_last_set
)
SELECT d.domain_id, ou.ou_id, 'Riya Sharma', 'riya.sharma',
       'riya.sharma@corp.example.com', 'Engineering',
       'enabled', true, now()
FROM domains d
JOIN organizational_units ou
  ON ou.domain_id = d.domain_id AND ou.ou_name = 'Engineering';

INSERT INTO directory_users (
    domain_id, ou_id, display_name, sam_account_name,
    user_principal_name, department, status, mfa_registered, password_last_set
)
SELECT d.domain_id, ou.ou_id, 'Release Operator', 'release.operator',
       'release.operator@corp.example.com', 'IT',
       'enabled', true, now()
FROM domains d
JOIN organizational_units ou
  ON ou.domain_id = d.domain_id AND ou.ou_name = 'Privileged';

INSERT INTO directory_groups (
    domain_id, ou_id, group_name, distinguished_name, scope, object_kind
)
SELECT d.domain_id, ou.ou_id, 'Engineering-Developers',
       'CN=Engineering-Developers,OU=Engineering,' || d.domain_dn,
       'global', 'security_group'
FROM domains d
JOIN organizational_units ou
  ON ou.domain_id = d.domain_id AND ou.ou_name = 'Engineering';

INSERT INTO directory_groups (
    domain_id, ou_id, group_name, distinguished_name, scope, object_kind
)
SELECT d.domain_id, ou.ou_id, 'Production-Administrators',
       'CN=Production-Administrators,OU=Privileged,OU=Engineering,' || d.domain_dn,
       'domain_local', 'security_group'
FROM domains d
JOIN organizational_units ou
  ON ou.domain_id = d.domain_id AND ou.ou_name = 'Privileged';

INSERT INTO group_memberships(group_id, member_user_id)
SELECT g.group_id, u.user_id
FROM directory_groups g
JOIN directory_users u ON u.sam_account_name = 'riya.sharma'
WHERE g.group_name = 'Engineering-Developers';

INSERT INTO group_memberships(group_id, member_user_id)
SELECT g.group_id, u.user_id
FROM directory_groups g
JOIN directory_users u ON u.sam_account_name = 'release.operator'
WHERE g.group_name = 'Production-Administrators';

INSERT INTO group_memberships(group_id, member_group_id)
SELECT parent.group_id, child.group_id
FROM directory_groups parent
JOIN directory_groups child
  ON child.group_name = 'Engineering-Developers'
WHERE parent.group_name = 'Production-Administrators';

INSERT INTO group_policy_objects (
    domain_id, gpo_name, enabled, computer_configuration_enabled
)
SELECT domain_id, 'Corporate Security Baseline', true, true
FROM domains;

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'password_min_length', '14'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Corporate Security Baseline';

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'lockout_threshold', '5'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Corporate Security Baseline';

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'require_mfa', 'true'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Corporate Security Baseline';

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'usb_storage_allowed', 'false'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Corporate Security Baseline';

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'screen_lock_minutes', '10'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Corporate Security Baseline';

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'firewall_enabled', 'true'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Corporate Security Baseline';

INSERT INTO group_policy_objects (
    domain_id, gpo_name, enabled, computer_configuration_enabled
)
SELECT domain_id, 'Engineering Workstation Policy', true, true
FROM domains;

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'usb_storage_allowed', 'true'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Engineering Workstation Policy';

INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
SELECT gpo_id, 'screen_lock_minutes', '20'::jsonb
FROM group_policy_objects WHERE gpo_name = 'Engineering Workstation Policy';

-- Link the baseline to the domain root and the workstation policy to Engineering.
INSERT INTO gpo_links (
    gpo_id, domain_id, target_ou_id, link_order, enforced
)
SELECT g.gpo_id, d.domain_id, root.ou_id, 1, true
FROM group_policy_objects g
JOIN domains d ON d.domain_id = g.domain_id
JOIN organizational_units root
  ON root.domain_id = d.domain_id AND root.parent_ou_id IS NULL
WHERE g.gpo_name = 'Corporate Security Baseline';

INSERT INTO gpo_links (
    gpo_id, domain_id, target_ou_id, link_order, enforced
)
SELECT g.gpo_id, d.domain_id, ou.ou_id, 1, false
FROM group_policy_objects g
JOIN domains d ON d.domain_id = g.domain_id
JOIN organizational_units ou
  ON ou.domain_id = d.domain_id AND ou.ou_name = 'Engineering'
WHERE g.gpo_name = 'Engineering Workstation Policy';

INSERT INTO access_resources (
    domain_id, resource_name, required_group_id, description
)
SELECT d.domain_id, 'Production Deployment',
       g.group_id, 'Permission to deploy approved production releases'
FROM domains d
JOIN directory_groups g
  ON g.domain_id = d.domain_id
 AND g.group_name = 'Production-Administrators';

INSERT INTO authentication_events (
    domain_id, user_id, account_name_attempted, outcome
)
SELECT d.domain_id, u.user_id, u.sam_account_name, 'success'
FROM domains d
JOIN directory_users u ON u.sam_account_name = 'riya.sharma';

INSERT INTO directory_audit_events (
    domain_id, actor, action, object_type, object_reference, details
)
SELECT domain_id, 'directory-admin', 'create-user', 'user', 'riya.sharma',
       jsonb_build_object('department', 'Engineering', 'mfa_registered', true)
FROM domains;

-- Recursive membership query expands nested security groups for each user.
CREATE VIEW effective_user_security_groups AS
WITH RECURSIVE memberships(user_id, group_id, path) AS (
    SELECT gm.member_user_id, gm.group_id, ARRAY[gm.group_id]::bigint[]
    FROM group_memberships gm
    JOIN directory_groups g ON g.group_id = gm.group_id
    WHERE gm.member_user_id IS NOT NULL
      AND g.object_kind = 'security_group'
      AND g.enabled = true

    UNION ALL

    SELECT m.user_id, gm.group_id, m.path || gm.group_id
    FROM memberships m
    JOIN group_memberships gm ON gm.member_group_id = m.group_id
    JOIN directory_groups parent ON parent.group_id = gm.group_id
    WHERE parent.object_kind = 'security_group'
      AND parent.enabled = true
      AND NOT gm.group_id = ANY(m.path)
)
SELECT DISTINCT
    u.user_id,
    u.sam_account_name,
    g.group_id,
    g.group_name,
    g.scope
FROM memberships m
JOIN directory_users u ON u.user_id = m.user_id
JOIN directory_groups g ON g.group_id = m.group_id;

-- Effective computer policy for the Engineering OU.
-- The recursive ancestor chain identifies applicable OU scopes.
-- This query gives enforced links precedence over non-enforced values.
WITH RECURSIVE target_chain AS (
    SELECT ou.ou_id, ou.parent_ou_id, 0 AS depth
    FROM organizational_units ou
    WHERE ou.ou_name = 'Engineering'

    UNION ALL

    SELECT parent.ou_id, parent.parent_ou_id, child.depth + 1
    FROM target_chain child
    JOIN organizational_units parent ON parent.ou_id = child.parent_ou_id
),
applicable AS (
    SELECT
        s.setting_name,
        s.setting_value,
        l.enforced,
        l.link_order,
        chain.depth,
        g.gpo_name,
        row_number() OVER (
            PARTITION BY s.setting_name
            ORDER BY
                l.enforced DESC,
                chain.depth ASC,
                l.link_order ASC,
                l.link_id ASC
        ) AS precedence_rank
    FROM target_chain chain
    JOIN gpo_links l ON l.target_ou_id = chain.ou_id
    JOIN group_policy_objects g
      ON g.gpo_id = l.gpo_id
     AND g.enabled = true
     AND g.computer_configuration_enabled = true
    JOIN gpo_settings s ON s.gpo_id = g.gpo_id
    WHERE l.link_disabled = false
)
SELECT setting_name, setting_value, enforced, gpo_name
FROM applicable
WHERE precedence_rank = 1
ORDER BY setting_name;

-- Access decision uses effective nested membership, not OU placement.
SELECT
    r.resource_name,
    u.sam_account_name,
    CASE
        WHEN u.status <> 'enabled' THEN 'DENIED: account not enabled'
        WHEN EXISTS (
            SELECT 1
            FROM effective_user_security_groups e
            WHERE e.user_id = u.user_id
              AND e.group_id = r.required_group_id
        ) THEN 'GRANTED'
        ELSE 'DENIED: required security group absent'
    END AS authorization_decision
FROM access_resources r
JOIN directory_users u ON u.sam_account_name IN (
    'riya.sharma', 'release.operator'
)
ORDER BY r.resource_name, u.sam_account_name;

-- Domain controller observations are evidence of replication lag, not proof
-- that a production controller is healthy or that replication will converge.
SELECT
    hostname,
    site_name,
    reachable,
    observed_revision,
    greatest(
        0,
        (SELECT count(*) FROM directory_audit_events) - observed_revision
    ) AS illustrative_revision_lag
FROM domain_controllers
ORDER BY hostname;

-- Audit events support investigation of administrative changes.
SELECT occurred_at, actor, action, object_type, object_reference, details
FROM directory_audit_events
ORDER BY occurred_at DESC;

-- Demonstrate constraint enforcement with a transaction that is rolled back.
-- The invalid policy setting is rejected by the CHECK constraint.
DO $$
BEGIN
    BEGIN
        INSERT INTO gpo_settings(gpo_id, setting_name, setting_value)
        SELECT gpo_id, 'password_min_length', '3'::jsonb
        FROM group_policy_objects
        WHERE gpo_name = 'Corporate Security Baseline';

        RAISE EXCEPTION 'Invalid setting unexpectedly accepted';
    EXCEPTION
        WHEN check_violation THEN
            RAISE NOTICE 'Invalid password policy rejected by database constraint';
    END;
END;
$$;

COMMIT;
