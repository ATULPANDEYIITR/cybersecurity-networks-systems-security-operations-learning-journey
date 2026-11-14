-- ============================================================
-- LDAP DIRECTORY MANAGEMENT AND SECURITY
-- PostgreSQL 15+
--
-- Models:
-- Directory Information Tree
-- Entries and multivalued attributes
-- Distinguished Names
-- Authentication identities
-- Account lockout
-- Access control
-- Directory searches
-- Audit events
-- Identity lifecycle
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS ldap_directory;

SET search_path TO ldap_directory, public;

-- ------------------------------------------------------------
-- 1. ENUMERATED DOMAIN STATES
-- ------------------------------------------------------------

CREATE TYPE account_status AS ENUM (
    'active',
    'locked',
    'disabled',
    'pending'
);

CREATE TYPE directory_scope AS ENUM (
    'base',
    'one',
    'subtree'
);

CREATE TYPE audit_outcome AS ENUM (
    'success',
    'failure',
    'denied'
);

-- ------------------------------------------------------------
-- 2. ORGANIZATIONAL UNITS
-- ------------------------------------------------------------

CREATE TABLE organizational_units (
    unit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    unit_name VARCHAR(150) NOT NULL,
    unit_code VARCHAR(50) NOT NULL UNIQUE,
    parent_unit_id BIGINT REFERENCES organizational_units(unit_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (length(trim(unit_name)) > 0),
    CHECK (parent_unit_id IS NULL OR parent_unit_id <> unit_id)
);

-- ------------------------------------------------------------
-- 3. DIRECTORY ENTRIES
--
-- dn is the directory's logical identity.
-- parent_dn supports DIT hierarchy.
-- ------------------------------------------------------------

CREATE TABLE directory_entries (
    entry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    dn TEXT NOT NULL UNIQUE,

    parent_dn TEXT REFERENCES directory_entries(dn)
        ON DELETE RESTRICT,

    rdn TEXT NOT NULL,

    object_classes TEXT[] NOT NULL,

    status account_status NOT NULL DEFAULT 'active',

    version INTEGER NOT NULL DEFAULT 1,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_dn CHECK (
        length(trim(dn)) > 0
        AND position('= ' IN dn) = 0
    ),

    CONSTRAINT valid_rdn CHECK (
        length(trim(rdn)) > 0
    ),

    CONSTRAINT valid_object_classes CHECK (
        cardinality(object_classes) > 0
    ),

    CONSTRAINT valid_version CHECK (version > 0)
);

CREATE INDEX idx_directory_parent
    ON directory_entries(parent_dn);

CREATE INDEX idx_directory_status
    ON directory_entries(status);

CREATE INDEX idx_directory_object_classes
    ON directory_entries USING GIN(object_classes);

-- ------------------------------------------------------------
-- 4. DIRECTORY ATTRIBUTES
--
-- A separate relation supports multivalued LDAP attributes.
-- ------------------------------------------------------------

CREATE TABLE directory_attributes (
    attribute_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    entry_id BIGINT NOT NULL
        REFERENCES directory_entries(entry_id)
        ON DELETE CASCADE,

    attribute_name VARCHAR(128) NOT NULL,

    attribute_value TEXT NOT NULL,

    normalized_value TEXT GENERATED ALWAYS AS (
        lower(trim(attribute_value))
    ) STORED,

    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_attribute_name CHECK (
        attribute_name ~ '^[a-zA-Z][a-zA-Z0-9-]*$'
    ),

    CONSTRAINT nonempty_attribute_value CHECK (
        length(trim(attribute_value)) > 0
    )
);

CREATE INDEX idx_attributes_name_value
    ON directory_attributes(
        attribute_name,
        normalized_value
    );

CREATE INDEX idx_attributes_entry
    ON directory_attributes(entry_id);

-- ------------------------------------------------------------
-- 5. IDENTITY ACCOUNTS
--
-- Password verification is performed by the authentication
-- service. The database stores a password verifier, not plaintext.
-- ------------------------------------------------------------

CREATE TABLE identity_accounts (
    account_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    entry_id BIGINT NOT NULL UNIQUE
        REFERENCES directory_entries(entry_id)
        ON DELETE CASCADE,

    username VARCHAR(100) NOT NULL UNIQUE,

    password_verifier TEXT,

    verifier_algorithm VARCHAR(50),

    failed_attempts INTEGER NOT NULL DEFAULT 0,

    maximum_attempts INTEGER NOT NULL DEFAULT 5,

    locked_until TIMESTAMPTZ,

    password_changed_at TIMESTAMPTZ,

    last_login_at TIMESTAMPTZ,

    status account_status NOT NULL DEFAULT 'active',

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_failed_attempts CHECK (
        failed_attempts >= 0
    ),

    CONSTRAINT valid_maximum_attempts CHECK (
        maximum_attempts BETWEEN 1 AND 20
    ),

    CONSTRAINT valid_username CHECK (
        username ~ '^[A-Za-z0-9._-]{2,100}$'
    )
);

CREATE INDEX idx_identity_status
    ON identity_accounts(status);

-- ------------------------------------------------------------
-- 6. DIRECTORY ROLES
-- ------------------------------------------------------------

CREATE TABLE directory_roles (
    role_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    role_name VARCHAR(80) NOT NULL UNIQUE,

    description TEXT
);

CREATE TABLE directory_permissions (
    permission_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    permission_name VARCHAR(100) NOT NULL UNIQUE,

    description TEXT
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL
        REFERENCES directory_roles(role_id)
        ON DELETE CASCADE,

    permission_id BIGINT NOT NULL
        REFERENCES directory_permissions(permission_id)
        ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE account_roles (
    account_id BIGINT NOT NULL
        REFERENCES identity_accounts(account_id)
        ON DELETE CASCADE,

    role_id BIGINT NOT NULL
        REFERENCES directory_roles(role_id)
        ON DELETE CASCADE,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (account_id, role_id)
);

-- ------------------------------------------------------------
-- 7. AUTHENTICATION AND DIRECTORY AUDIT
-- ------------------------------------------------------------

CREATE TABLE directory_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    account_id BIGINT REFERENCES identity_accounts(account_id)
        ON DELETE SET NULL,

    operation VARCHAR(80) NOT NULL,

    target_dn TEXT,

    outcome audit_outcome NOT NULL,

    source_address INET,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_account_time
    ON directory_audit(account_id, created_at DESC);

CREATE INDEX idx_audit_operation_time
    ON directory_audit(operation, created_at DESC);

-- ------------------------------------------------------------
-- 8. DIRECTORY ENTRY UPDATE TRIGGER
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION update_entry_timestamp()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    NEW.version := OLD.version + 1;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_entry_updated
BEFORE UPDATE ON directory_entries
FOR EACH ROW
EXECUTE FUNCTION update_entry_timestamp();

-- ------------------------------------------------------------
-- 9. DIRECTORY HIERARCHY VALIDATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_directory_parent()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.parent_dn IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.parent_dn = NEW.dn THEN
        RAISE EXCEPTION 'An entry cannot be its own parent';
    END IF;

    IF NEW.dn LIKE '%,' || NEW.parent_dn ESCAPE '\' THEN
        NULL;
    ELSE
        RAISE EXCEPTION
            'Parent DN must be a suffix of the child DN';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM directory_entries
        WHERE dn = NEW.parent_dn
          AND entry_id = NEW.entry_id
    ) THEN
        RAISE EXCEPTION 'Circular directory relationship';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_directory_parent
BEFORE INSERT OR UPDATE OF dn, parent_dn
ON directory_entries
FOR EACH ROW
EXECUTE FUNCTION validate_directory_parent();

-- ------------------------------------------------------------
-- 10. AUTHENTICATION FAILURE PROCESSING
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION record_authentication_failure(
    p_username VARCHAR,
    p_source INET DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_account identity_accounts%ROWTYPE;
BEGIN
    SELECT *
    INTO v_account
    FROM identity_accounts
    WHERE username = p_username
    FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO directory_audit(
            operation,
            outcome,
            source_address,
            details
        )
        VALUES (
            'BIND',
            'failure',
            p_source,
            jsonb_build_object('reason', 'unknown_account')
        );

        RETURN FALSE;
    END IF;

    IF v_account.status <> 'active' THEN
        INSERT INTO directory_audit(
            account_id,
            operation,
            target_dn,
            outcome,
            source_address,
            details
        )
        SELECT
            v_account.account_id,
            'BIND',
            d.dn,
            'denied',
            p_source,
            jsonb_build_object('reason', 'account_unavailable')
        FROM directory_entries d
        WHERE d.entry_id = v_account.entry_id;

        RETURN FALSE;
    END IF;

    UPDATE identity_accounts
    SET
        failed_attempts = failed_attempts + 1,

        status = CASE
            WHEN failed_attempts + 1 >= maximum_attempts
            THEN 'locked'::account_status
            ELSE status
        END,

        locked_until = CASE
            WHEN failed_attempts + 1 >= maximum_attempts
            THEN CURRENT_TIMESTAMP + INTERVAL '15 minutes'
            ELSE locked_until
        END

    WHERE account_id = v_account.account_id;

    INSERT INTO directory_audit(
        account_id,
        operation,
        outcome,
        source_address,
        details
    )
    VALUES (
        v_account.account_id,
        'BIND',
        'failure',
        p_source,
        jsonb_build_object('reason', 'invalid_credentials')
    );

    RETURN TRUE;
END;
$$;

-- ------------------------------------------------------------
-- 11. AUTHENTICATION SUCCESS PROCESSING
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION record_authentication_success(
    p_username VARCHAR,
    p_source INET DEFAULT NULL
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    v_account identity_accounts%ROWTYPE;
BEGIN
    SELECT *
    INTO v_account
    FROM identity_accounts
    WHERE username = p_username
    FOR UPDATE;

    IF NOT FOUND OR v_account.status <> 'active' THEN
        RETURN FALSE;
    END IF;

    UPDATE identity_accounts
    SET
        failed_attempts = 0,
        locked_until = NULL,
        last_login_at = CURRENT_TIMESTAMP
    WHERE account_id = v_account.account_id;

    INSERT INTO directory_audit(
        account_id,
        operation,
        outcome,
        source_address,
        details
    )
    VALUES (
        v_account.account_id,
        'BIND',
        'success',
        p_source,
        '{"authentication":"successful"}'::jsonb
    );

    RETURN TRUE;
END;
$$;

-- ------------------------------------------------------------
-- 12. ACCOUNT LOCKOUT EXPIRATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION unlock_expired_accounts()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE identity_accounts
    SET
        status = 'active',
        failed_attempts = 0,
        locked_until = NULL
    WHERE status = 'locked'
      AND locked_until IS NOT NULL
      AND locked_until <= CURRENT_TIMESTAMP;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$;

-- ------------------------------------------------------------
-- 13. DIRECTORY SEARCH FUNCTION
--
-- The application supplies an attribute and an exact value.
-- User-provided SQL fragments are never executed dynamically.
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION search_directory(
    p_base_dn TEXT,
    p_scope directory_scope,
    p_attribute TEXT,
    p_value TEXT,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    result_dn TEXT,
    result_attribute TEXT,
    result_value TEXT
)
LANGUAGE plpgsql
STABLE
AS $$
BEGIN
    IF p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION 'Search limit must be between 1 and 1000';
    END IF;

    IF p_attribute !~ '^[a-zA-Z][a-zA-Z0-9-]*$' THEN
        RAISE EXCEPTION 'Invalid LDAP attribute name';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM directory_entries
        WHERE dn = p_base_dn
    ) THEN
        RAISE EXCEPTION 'Search base does not exist';
    END IF;

    RETURN QUERY
    SELECT
        d.dn,
        a.attribute_name,
        a.attribute_value
    FROM directory_entries d
    LEFT JOIN directory_attributes a
        ON a.entry_id = d.entry_id
    WHERE
        CASE p_scope
            WHEN 'base' THEN
                d.dn = p_base_dn

            WHEN 'one' THEN
                d.parent_dn = p_base_dn

            WHEN 'subtree' THEN
                d.dn = p_base_dn
                OR right(
                    d.dn,
                    length(p_base_dn) + 1
                ) = ',' || p_base_dn
        END
        AND (
            a.attribute_name = p_attribute
            AND lower(a.attribute_value) = lower(p_value)
        )
    ORDER BY d.dn
    LIMIT p_limit;
END;
$$;

-- ------------------------------------------------------------
-- 14. DIRECTORY ELIGIBILITY VIEW
-- ------------------------------------------------------------

CREATE VIEW active_directory_identities AS
SELECT
    ia.account_id,
    ia.username,
    ia.status AS account_status,
    de.dn,
    de.object_classes,
    de.status AS entry_status,
    ia.last_login_at,
    ia.failed_attempts
FROM identity_accounts ia
JOIN directory_entries de
    ON de.entry_id = ia.entry_id
WHERE ia.status = 'active'
  AND de.status = 'active';

-- ------------------------------------------------------------
-- 15. ROLE AND PERMISSION DATA
-- ------------------------------------------------------------

INSERT INTO directory_roles(role_name, description)
VALUES
    ('administrator', 'Full directory administration'),
    ('directory-manager', 'Directory entry management'),
    ('employee', 'Read-only directory access'),
    ('service-account', 'Restricted application access');

INSERT INTO directory_permissions(permission_name, description)
VALUES
    ('read', 'Read directory attributes'),
    ('search', 'Search directory entries'),
    ('write', 'Create and modify directory entries'),
    ('delete', 'Delete eligible directory entries');

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM directory_roles r
CROSS JOIN directory_permissions p
WHERE r.role_name = 'administrator';

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM directory_roles r
JOIN directory_permissions p
    ON p.permission_name IN ('read', 'search', 'write')
WHERE r.role_name = 'directory-manager';

INSERT INTO role_permissions(role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM directory_roles r
JOIN directory_permissions p
    ON p.permission_name IN ('read', 'search')
WHERE r.role_name IN ('employee', 'service-account');

-- ------------------------------------------------------------
-- 16. SAMPLE DIRECTORY TREE
-- ------------------------------------------------------------

INSERT INTO directory_entries(
    dn,
    parent_dn,
    rdn,
    object_classes
)
VALUES (
    'dc=example,dc=com',
    NULL,
    'dc=example',
    ARRAY['top', 'domain']
);

INSERT INTO directory_entries(
    dn,
    parent_dn,
    rdn,
    object_classes
)
VALUES
(
    'ou=people,dc=example,dc=com',
    'dc=example,dc=com',
    'ou=people',
    ARRAY['top', 'organizationalUnit']
),
(
    'ou=groups,dc=example,dc=com',
    'dc=example,dc=com',
    'ou=groups',
    ARRAY['top', 'organizationalUnit']
);

INSERT INTO directory_entries(
    dn,
    parent_dn,
    rdn,
    object_classes
)
VALUES
(
    'uid=alice,ou=people,dc=example,dc=com',
    'ou=people,dc=example,dc=com',
    'uid=alice',
    ARRAY['top', 'person', 'inetOrgPerson']
),
(
    'uid=bob,ou=people,dc=example,dc=com',
    'ou=people,dc=example,dc=com',
    'uid=bob',
    ARRAY['top', 'person', 'inetOrgPerson']
),
(
    'uid=carol,ou=people,dc=example,dc=com',
    'ou=people,dc=example,dc=com',
    'uid=carol',
    ARRAY['top', 'person', 'inetOrgPerson']
);

-- ------------------------------------------------------------
-- 17. SAMPLE DIRECTORY ATTRIBUTES
-- ------------------------------------------------------------

INSERT INTO directory_attributes(
    entry_id,
    attribute_name,
    attribute_value
)
SELECT d.entry_id, v.attribute_name, v.attribute_value
FROM directory_entries d
JOIN (
    VALUES
    (
        'uid=alice,ou=people,dc=example,dc=com',
        'uid', 'alice'
    ),
    (
        'uid=alice,ou=people,dc=example,dc=com',
        'cn', 'Alice Sharma'
    ),
    (
        'uid=alice,ou=people,dc=example,dc=com',
        'sn', 'Sharma'
    ),
    (
        'uid=alice,ou=people,dc=example,dc=com',
        'department', 'Engineering'
    ),
    (
        'uid=alice,ou=people,dc=example,dc=com',
        'mail', 'alice@example.com'
    ),
    (
        'uid=alice,ou=people,dc=example,dc=com',
        'active', 'true'
    ),
    (
        'uid=bob,ou=people,dc=example,dc=com',
        'uid', 'bob'
    ),
    (
        'uid=bob,ou=people,dc=example,dc=com',
        'cn', 'Bob Kumar'
    ),
    (
        'uid=bob,ou=people,dc=example,dc=com',
        'sn', 'Kumar'
    ),
    (
        'uid=bob,ou=people,dc=example,dc=com',
        'department', 'Security'
    ),
    (
        'uid=bob,ou=people,dc=example,dc=com',
        'mail', 'bob@example.com'
    ),
    (
        'uid=bob,ou=people,dc=example,dc=com',
        'active', 'true'
    ),
    (
        'uid=carol,ou=people,dc=example,dc=com',
        'uid', 'carol'
    ),
    (
        'uid=carol,ou=people,dc=example,dc=com',
        'cn', 'Carol Singh'
    ),
    (
        'uid=carol,ou=people,dc=example,dc=com',
        'sn', 'Singh'
    ),
    (
        'uid=carol,ou=people,dc=example,dc=com',
        'department', 'Engineering'
    ),
    (
        'uid=carol,ou=people,dc=example,dc=com',
        'mail', 'carol@example.com'
    ),
    (
        'uid=carol,ou=people,dc=example,dc=com',
        'active', 'true'
    )
) AS v(dn, attribute_name, attribute_value)
    ON d.dn = v.dn;

-- ------------------------------------------------------------
-- 18. SAMPLE IDENTITY ACCOUNTS
--
-- Verifier strings are intentionally nonfunctional examples.
-- The application authentication service must replace them.
-- ------------------------------------------------------------

INSERT INTO identity_accounts(
    entry_id,
    username,
    password_verifier,
    verifier_algorithm,
    password_changed_at
)
SELECT
    d.entry_id,
    v.username,
    v.verifier,
    'PBKDF2-SHA256',
    CURRENT_TIMESTAMP
FROM directory_entries d
JOIN (
    VALUES
    ('alice', 'REPLACE_WITH_REAL_PBKDF2_VERIFIER'),
    ('bob', 'REPLACE_WITH_REAL_PBKDF2_VERIFIER'),
    ('carol', 'REPLACE_WITH_REAL_PBKDF2_VERIFIER')
) AS v(username, verifier)
    ON d.dn = 'uid=' || v.username ||
       ',ou=people,dc=example,dc=com';

-- ------------------------------------------------------------
-- 19. ACCOUNT ROLE ASSIGNMENTS
-- ------------------------------------------------------------

INSERT INTO account_roles(account_id, role_id)
SELECT ia.account_id, r.role_id
FROM identity_accounts ia
JOIN directory_roles r
    ON r.role_name = CASE ia.username
        WHEN 'alice' THEN 'employee'
        WHEN 'bob' THEN 'directory-manager'
        ELSE 'employee'
    END;

-- ------------------------------------------------------------
-- 20. TRANSACTIONAL DIRECTORY MODIFICATION
-- ------------------------------------------------------------

SAVEPOINT before_directory_update;

UPDATE directory_attributes
SET attribute_value = '+91-9876543210'
WHERE attribute_name = 'telephoneNumber'
  AND entry_id = (
      SELECT entry_id
      FROM directory_entries
      WHERE dn = 'uid=alice,ou=people,dc=example,dc=com'
  );

INSERT INTO directory_attributes(
    entry_id,
    attribute_name,
    attribute_value
)
SELECT
    entry_id,
    'telephoneNumber',
    '+91-9876543210'
FROM directory_entries
WHERE dn = 'uid=alice,ou=people,dc=example,dc=com'
AND NOT EXISTS (
    SELECT 1
    FROM directory_attributes a
    WHERE a.entry_id = directory_entries.entry_id
      AND a.attribute_name = 'telephoneNumber'
);

RELEASE SAVEPOINT before_directory_update;

-- ------------------------------------------------------------
-- 21. DEMONSTRATE AUTHENTICATION FAILURES
-- ------------------------------------------------------------

SELECT record_authentication_failure(
    'alice',
    '192.0.2.10'::INET
);

SELECT record_authentication_failure(
    'alice',
    '192.0.2.10'::INET
);

-- ------------------------------------------------------------
-- 22. REPORTING: DIRECTORY TREE
-- ------------------------------------------------------------

WITH RECURSIVE directory_tree AS (
    SELECT
        entry_id,
        dn,
        parent_dn,
        0 AS depth
    FROM directory_entries
    WHERE parent_dn IS NULL

    UNION ALL

    SELECT
        child.entry_id,
        child.dn,
        child.parent_dn,
        parent.depth + 1
    FROM directory_entries child
    JOIN directory_tree parent
        ON child.parent_dn = parent.dn
)
SELECT
    repeat('  ', depth) || dn AS hierarchy,
    depth
FROM directory_tree
ORDER BY depth, dn;

-- ------------------------------------------------------------
-- 23. REPORTING: ATTRIBUTE COUNTS
-- ------------------------------------------------------------

SELECT
    attribute_name,
    COUNT(*) AS value_count,
    COUNT(DISTINCT entry_id) AS entry_count
FROM directory_attributes
GROUP BY attribute_name
ORDER BY attribute_name;

-- ------------------------------------------------------------
-- 24. QUERY: ENGINEERING DIRECTORY USERS
-- ------------------------------------------------------------

SELECT
    d.dn,
    ia.username,
    a.attribute_value AS common_name
FROM directory_entries d
JOIN identity_accounts ia
    ON ia.entry_id = d.entry_id
JOIN directory_attributes a
    ON a.entry_id = d.entry_id
WHERE a.attribute_name = 'cn'
  AND d.entry_id IN (
      SELECT entry_id
      FROM directory_attributes
      WHERE attribute_name = 'department'
        AND normalized_value = 'engineering'
  )
ORDER BY ia.username;

-- ------------------------------------------------------------
-- 25. QUERY: DIRECTORY SEARCH
-- ------------------------------------------------------------

SELECT *
FROM search_directory(
    'dc=example,dc=com',
    'subtree',
    'department',
    'Engineering',
    100
);

-- ------------------------------------------------------------
-- 26. QUERY: ACTIVE IDENTITY ACCOUNTS
-- ------------------------------------------------------------

SELECT *
FROM active_directory_identities
ORDER BY username;

-- ------------------------------------------------------------
-- 27. QUERY: ACCOUNT SECURITY STATUS
-- ------------------------------------------------------------

SELECT
    username,
    status,
    failed_attempts,
    maximum_attempts,
    locked_until,
    last_login_at
FROM identity_accounts
ORDER BY username;

-- ------------------------------------------------------------
-- 28. QUERY: ROLE AND PERMISSION MATRIX
-- ------------------------------------------------------------

SELECT
    r.role_name,
    p.permission_name
FROM role_permissions rp
JOIN directory_roles r
    ON r.role_id = rp.role_id
JOIN directory_permissions p
    ON p.permission_id = rp.permission_id
ORDER BY r.role_name, p.permission_name;

-- ------------------------------------------------------------
-- 29. QUERY: AUDIT REPORT
-- ------------------------------------------------------------

SELECT
    audit_id,
    username,
    operation,
    outcome,
    source_address,
    created_at
FROM directory_audit a
LEFT JOIN identity_accounts ia
    ON ia.account_id = a.account_id
ORDER BY a.created_at DESC;

-- ------------------------------------------------------------
-- 30. QUERY: FAILED AUTHENTICATION AGGREGATION
-- ------------------------------------------------------------

SELECT
    username,
    COUNT(*) AS failure_count,
    MAX(a.created_at) AS last_failure
FROM directory_audit a
JOIN identity_accounts ia
    ON ia.account_id = a.account_id
WHERE a.operation = 'BIND'
  AND a.outcome = 'failure'
GROUP BY username
ORDER BY failure_count DESC;

-- ------------------------------------------------------------
-- 31. VALIDATION: ORPHANED DIRECTORY REFERENCES
-- ------------------------------------------------------------

SELECT
    child.dn,
    child.parent_dn
FROM directory_entries child
LEFT JOIN directory_entries parent
    ON parent.dn = child.parent_dn
WHERE child.parent_dn IS NOT NULL
  AND parent.entry_id IS NULL;

-- ------------------------------------------------------------
-- 32. VALIDATION: DUPLICATE ATTRIBUTE VALUES
-- ------------------------------------------------------------

SELECT
    entry_id,
    attribute_name,
    normalized_value,
    COUNT(*) AS duplicates
FROM directory_attributes
GROUP BY
    entry_id,
    attribute_name,
    normalized_value
HAVING COUNT(*) > 1;

-- ------------------------------------------------------------
-- 33. PERMISSION EVALUATION
-- ------------------------------------------------------------

SELECT EXISTS (
    SELECT 1
    FROM account_roles ar
    JOIN role_permissions rp
        ON rp.role_id = ar.role_id
    JOIN directory_permissions dp
        ON dp.permission_id = rp.permission_id
    JOIN identity_accounts ia
        ON ia.account_id = ar.account_id
    WHERE ia.username = 'bob'
      AND dp.permission_name = 'write'
      AND ia.status = 'active'
) AS bob_can_write;

-- ------------------------------------------------------------
-- 34. ACCOUNT LOCKOUT EXPIRATION PROCESS
-- ------------------------------------------------------------

SELECT unlock_expired_accounts();

-- ------------------------------------------------------------
-- 35. TRANSACTIONAL SECURITY REPORT
-- ------------------------------------------------------------

COMMIT;

-- ============================================================
-- OPERATIONAL SECURITY NOTES
--
-- 1. The database does not implement the LDAP wire protocol.
-- 2. Bind password verification belongs in a trusted service.
-- 3. Password verifier values must be generated by a secure KDF.
-- 4. Use TLS for LDAP connections.
-- 5. Restrict database roles and function execution privileges.
-- 6. Apply network restrictions and audit retention policies.
-- 7. The simplified DN checks are not a complete RFC 4514 parser.
-- ============================================================
