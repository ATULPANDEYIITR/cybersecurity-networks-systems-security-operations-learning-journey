-- ============================================================
-- KERBEROS AUTHENTICATION DATABASE
-- PostgreSQL 15+
--
-- Models:
--   Realms
--   Principals
--   Service principals
--   Long-term key metadata
--   Authentication Server exchanges
--   Ticket Granting Tickets
--   Service tickets
--   Ticket relationships
--   Authentication attempts
--   Authenticators
--   Replay protection
--   Service access
--   KDC audit
--
-- This database stores ticket metadata and simulated signatures.
-- It does not implement Kerberos cryptographic ticket encryption.
-- Never store plaintext passwords or production secret keys here.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS kerberos;

SET search_path TO kerberos, public;

-- ------------------------------------------------------------
-- 1. DOMAIN TYPES
-- ------------------------------------------------------------

CREATE TYPE principal_type AS ENUM (
    'USER',
    'SERVICE',
    'KDC'
);

CREATE TYPE principal_status AS ENUM (
    'ACTIVE',
    'DISABLED',
    'LOCKED',
    'EXPIRED'
);

CREATE TYPE ticket_type AS ENUM (
    'TGT',
    'SERVICE'
);

CREATE TYPE ticket_status AS ENUM (
    'ISSUED',
    'REVOKED',
    'EXPIRED'
);

CREATE TYPE authentication_status AS ENUM (
    'PENDING',
    'SUCCESS',
    'FAILED',
    'REJECTED'
);

CREATE TYPE authentication_stage AS ENUM (
    'AS',
    'TGS',
    'SERVICE'
);

CREATE TYPE audit_severity AS ENUM (
    'INFO',
    'WARNING',
    'ERROR',
    'CRITICAL'
);

-- ------------------------------------------------------------
-- 2. REALMS
-- ------------------------------------------------------------

CREATE TABLE realms (
    realm_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    realm_name VARCHAR(255) NOT NULL UNIQUE,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (realm_name = UPPER(realm_name)),
    CHECK (realm_name ~ '^[A-Z0-9.-]+$')
);

-- ------------------------------------------------------------
-- 3. PRINCIPALS
-- ------------------------------------------------------------

CREATE TABLE principals (
    principal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    realm_id BIGINT NOT NULL REFERENCES realms(realm_id),

    principal_name VARCHAR(255) NOT NULL,

    principal_type principal_type NOT NULL,

    status principal_status NOT NULL DEFAULT 'ACTIVE',

    password_verifier TEXT,

    key_version INTEGER NOT NULL DEFAULT 1,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_authenticated_at TIMESTAMPTZ,

    UNIQUE (realm_id, principal_name),

    CHECK (key_version > 0),

    CHECK (
        principal_type <> 'USER'
        OR password_verifier IS NOT NULL
    )
);

CREATE INDEX idx_principals_status
ON principals(realm_id, status);

CREATE INDEX idx_principals_type
ON principals(principal_type);

-- ------------------------------------------------------------
-- 4. PRINCIPAL ROLES
-- ------------------------------------------------------------

CREATE TABLE principal_roles (
    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id) ON DELETE CASCADE,

    role_name VARCHAR(100) NOT NULL,

    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (principal_id, role_name)
);

-- ------------------------------------------------------------
-- 5. LONG-TERM KEY METADATA
-- ------------------------------------------------------------

CREATE TABLE principal_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    key_version INTEGER NOT NULL,

    encryption_type VARCHAR(50) NOT NULL,

    key_reference VARCHAR(500) NOT NULL,

    valid_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    valid_until TIMESTAMPTZ,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    UNIQUE (principal_id, key_version),

    CHECK (key_version > 0),

    CHECK (
        valid_until IS NULL
        OR valid_until > valid_from
    )
);

CREATE UNIQUE INDEX uq_active_principal_key
ON principal_keys(principal_id)
WHERE active = TRUE;

-- ------------------------------------------------------------
-- 6. SERVICE PRINCIPALS
-- ------------------------------------------------------------

CREATE TABLE service_principals (
    service_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    principal_id BIGINT NOT NULL UNIQUE
        REFERENCES principals(principal_id),

    service_name VARCHAR(255) NOT NULL UNIQUE,

    hostname VARCHAR(255) NOT NULL,

    service_category VARCHAR(100) NOT NULL,

    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (service_name ~ '^[a-zA-Z0-9_-]+/')
);

-- ------------------------------------------------------------
-- 7. AUTHENTICATION SESSIONS
-- ------------------------------------------------------------

CREATE TABLE authentication_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    client_address INET,

    client_identifier VARCHAR(255),

    status authentication_status NOT NULL DEFAULT 'PENDING',

    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    completed_at TIMESTAMPTZ,

    CHECK (
        completed_at IS NULL
        OR completed_at >= started_at
    )
);

CREATE INDEX idx_sessions_principal_time
ON authentication_sessions(principal_id, started_at DESC);

CREATE INDEX idx_sessions_status
ON authentication_sessions(status, started_at DESC);

-- ------------------------------------------------------------
-- 8. KERBEROS TICKETS
-- ------------------------------------------------------------

CREATE TABLE tickets (
    ticket_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    ticket_type ticket_type NOT NULL,

    client_principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    service_id BIGINT
        REFERENCES service_principals(service_id),

    session_id UUID NOT NULL
        REFERENCES authentication_sessions(session_id),

    parent_tgt_id UUID
        REFERENCES tickets(ticket_id),

    key_version INTEGER NOT NULL,

    ticket_signature TEXT NOT NULL,

    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    expires_at TIMESTAMPTZ NOT NULL,

    status ticket_status NOT NULL DEFAULT 'ISSUED',

    renewable_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (expires_at > issued_at),

    CHECK (key_version > 0),

    CHECK (
        renewable_until IS NULL
        OR renewable_until >= expires_at
    ),

    CHECK (
        (ticket_type = 'TGT' AND service_id IS NULL
         AND parent_tgt_id IS NULL)
        OR
        (ticket_type = 'SERVICE' AND service_id IS NOT NULL
         AND parent_tgt_id IS NOT NULL)
    )
);

CREATE INDEX idx_tickets_client
ON tickets(client_principal_id, issued_at DESC);

CREATE INDEX idx_tickets_expiry
ON tickets(expires_at)
WHERE status = 'ISSUED';

CREATE INDEX idx_tickets_service
ON tickets(service_id, status, expires_at);

CREATE INDEX idx_tickets_parent
ON tickets(parent_tgt_id)
WHERE parent_tgt_id IS NOT NULL;

-- ------------------------------------------------------------
-- 9. AUTHENTICATION ATTEMPTS
-- ------------------------------------------------------------

CREATE TABLE authentication_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    session_id UUID REFERENCES authentication_sessions(session_id),

    principal_id BIGINT REFERENCES principals(principal_id),

    stage authentication_stage NOT NULL,

    requested_service_id BIGINT
        REFERENCES service_principals(service_id),

    status authentication_status NOT NULL,

    failure_reason TEXT,

    source_address INET,

    attempted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_attempts_principal
ON authentication_attempts(principal_id, attempted_at DESC);

CREATE INDEX idx_attempts_failures
ON authentication_attempts(attempted_at DESC)
WHERE status IN ('FAILED', 'REJECTED');

CREATE INDEX idx_attempts_stage
ON authentication_attempts(stage, status);

-- ------------------------------------------------------------
-- 10. AUTHENTICATORS AND REPLAY DETECTION
-- ------------------------------------------------------------

CREATE TABLE authenticators (
    authenticator_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ticket_id UUID NOT NULL REFERENCES tickets(ticket_id),

    nonce VARCHAR(255) NOT NULL,

    authenticator_timestamp TIMESTAMPTZ NOT NULL,

    signature TEXT NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    accepted BOOLEAN NOT NULL DEFAULT FALSE,

    UNIQUE (ticket_id, nonce)
);

CREATE INDEX idx_authenticator_timestamp
ON authenticators(authenticator_timestamp);

-- ------------------------------------------------------------
-- 11. SERVICE ACCESS EVENTS
-- ------------------------------------------------------------

CREATE TABLE service_access_events (
    access_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ticket_id UUID NOT NULL REFERENCES tickets(ticket_id),

    service_id BIGINT NOT NULL
        REFERENCES service_principals(service_id),

    principal_id BIGINT NOT NULL
        REFERENCES principals(principal_id),

    authenticator_id BIGINT
        REFERENCES authenticators(authenticator_id),

    authenticated BOOLEAN NOT NULL DEFAULT FALSE,

    mutual_authentication BOOLEAN NOT NULL DEFAULT FALSE,

    accessed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    failure_reason TEXT
);

CREATE INDEX idx_service_access_principal
ON service_access_events(principal_id, accessed_at DESC);

CREATE INDEX idx_service_access_service
ON service_access_events(service_id, accessed_at DESC);

-- ------------------------------------------------------------
-- 12. KDC AUDIT LOG
-- ------------------------------------------------------------

CREATE TABLE kdc_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    principal_id BIGINT REFERENCES principals(principal_id),

    action VARCHAR(100) NOT NULL,

    severity audit_severity NOT NULL DEFAULT 'INFO',

    description TEXT,

    source_address INET,

    event_time TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_time
ON kdc_audit(event_time DESC);

CREATE INDEX idx_audit_severity
ON kdc_audit(severity, event_time DESC);

-- ------------------------------------------------------------
-- 13. TICKET INTEGRITY TRIGGER
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_ticket_relationship()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    parent_ticket tickets%ROWTYPE;
BEGIN
    IF NEW.expires_at <= NEW.issued_at THEN
        RAISE EXCEPTION 'Ticket expiration must follow issuance';
    END IF;

    IF NEW.ticket_type = 'SERVICE' THEN

        SELECT *
        INTO parent_ticket
        FROM tickets
        WHERE ticket_id = NEW.parent_tgt_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Parent TGT does not exist';
        END IF;

        IF parent_ticket.ticket_type <> 'TGT' THEN
            RAISE EXCEPTION 'Parent ticket must be a TGT';
        END IF;

        IF parent_ticket.client_principal_id
           <> NEW.client_principal_id THEN
            RAISE EXCEPTION 'Client principal mismatch';
        END IF;

        IF parent_ticket.session_id <> NEW.session_id THEN
            RAISE EXCEPTION 'Authentication session mismatch';
        END IF;

        IF NEW.issued_at < parent_ticket.issued_at
           OR NEW.expires_at > parent_ticket.expires_at THEN
            RAISE EXCEPTION
                'Service ticket cannot outlive its parent TGT';
        END IF;

        IF parent_ticket.status <> 'ISSUED' THEN
            RAISE EXCEPTION 'Parent TGT is not active';
        END IF;

    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_ticket_relationship
BEFORE INSERT ON tickets
FOR EACH ROW
EXECUTE FUNCTION validate_ticket_relationship();

-- ------------------------------------------------------------
-- 14. TICKET EXPIRATION FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION expire_tickets()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    affected INTEGER;
BEGIN
    UPDATE tickets
    SET status = 'EXPIRED'
    WHERE status = 'ISSUED'
      AND expires_at <= CURRENT_TIMESTAMP;

    GET DIAGNOSTICS affected = ROW_COUNT;

    RETURN affected;
END;
$$;

-- ------------------------------------------------------------
-- 15. AUTHENTICATION ATTEMPT VALIDATION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_authentication_attempt()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'FAILED'
       AND NEW.failure_reason IS NULL THEN
        RAISE EXCEPTION
            'Failed authentication requires a failure reason';
    END IF;

    IF NEW.stage = 'SERVICE'
       AND NEW.requested_service_id IS NULL THEN
        RAISE EXCEPTION
            'Service authentication requires a service principal';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_authentication_attempt
BEFORE INSERT OR UPDATE ON authentication_attempts
FOR EACH ROW
EXECUTE FUNCTION validate_authentication_attempt();

-- ------------------------------------------------------------
-- 16. AUTHENTICATOR REPLAY-PROTECTION FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION accept_authenticator(
    p_ticket_id UUID,
    p_nonce VARCHAR,
    p_timestamp TIMESTAMPTZ,
    p_signature TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
AS $$
DECLARE
    ticket_record tickets%ROWTYPE;
    inserted_id BIGINT;
BEGIN
    SELECT *
    INTO ticket_record
    FROM tickets
    WHERE ticket_id = p_ticket_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Unknown ticket';
    END IF;

    IF ticket_record.status <> 'ISSUED' THEN
        RAISE EXCEPTION 'Ticket is not active';
    END IF;

    IF ticket_record.expires_at <= CURRENT_TIMESTAMP THEN
        RAISE EXCEPTION 'Ticket expired';
    END IF;

    IF ABS(
        EXTRACT(
            EPOCH FROM (
                CURRENT_TIMESTAMP - p_timestamp
            )
        )
    ) > 60 THEN
        RAISE EXCEPTION 'Authenticator clock tolerance exceeded';
    END IF;

    IF p_nonce IS NULL OR LENGTH(p_nonce) < 16 THEN
        RAISE EXCEPTION 'Invalid authenticator nonce';
    END IF;

    IF p_signature IS NULL OR LENGTH(p_signature) < 16 THEN
        RAISE EXCEPTION 'Invalid authenticator signature';
    END IF;

    INSERT INTO authenticators (
        ticket_id,
        nonce,
        authenticator_timestamp,
        signature,
        accepted
    )
    VALUES (
        p_ticket_id,
        p_nonce,
        p_timestamp,
        p_signature,
        TRUE
    )
    ON CONFLICT (ticket_id, nonce) DO NOTHING
    RETURNING authenticator_id INTO inserted_id;

    IF inserted_id IS NULL THEN
        RAISE EXCEPTION 'Replay detected';
    END IF;

    RETURN TRUE;
END;
$$;

-- ------------------------------------------------------------
-- 17. SERVICE TICKET ELIGIBILITY FUNCTION
-- ------------------------------------------------------------

CREATE OR REPLACE FUNCTION service_ticket_eligibility(
    p_tgt_id UUID,
    p_service_id BIGINT
)
RETURNS TABLE (
    eligible BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    tgt tickets%ROWTYPE;
    client_status principal_status;
    service_enabled BOOLEAN;
BEGIN
    SELECT *
    INTO tgt
    FROM tickets
    WHERE ticket_id = p_tgt_id;

    IF NOT FOUND THEN
        RETURN QUERY SELECT FALSE, 'TGT_NOT_FOUND';
        RETURN;
    END IF;

    IF tgt.ticket_type <> 'TGT' THEN
        RETURN QUERY SELECT FALSE, 'NOT_A_TGT';
        RETURN;
    END IF;

    IF tgt.status <> 'ISSUED' THEN
        RETURN QUERY SELECT FALSE, 'TGT_NOT_ACTIVE';
        RETURN;
    END IF;

    IF tgt.expires_at <= CURRENT_TIMESTAMP THEN
        RETURN QUERY SELECT FALSE, 'TGT_EXPIRED';
        RETURN;
    END IF;

    SELECT status
    INTO client_status
    FROM principals
    WHERE principal_id = tgt.client_principal_id;

    IF client_status <> 'ACTIVE' THEN
        RETURN QUERY SELECT FALSE, 'PRINCIPAL_NOT_ACTIVE';
        RETURN;
    END IF;

    SELECT enabled
    INTO service_enabled
    FROM service_principals
    WHERE service_id = p_service_id;

    IF NOT FOUND OR NOT service_enabled THEN
        RETURN QUERY SELECT FALSE, 'SERVICE_NOT_ENABLED';
        RETURN;
    END IF;

    RETURN QUERY SELECT TRUE, 'ELIGIBLE';
END;
$$;

-- ------------------------------------------------------------
-- 18. SERVICE TICKET ISSUANCE PROCEDURE
-- ------------------------------------------------------------

CREATE OR REPLACE PROCEDURE issue_service_ticket(
    p_tgt_id UUID,
    p_service_id BIGINT,
    p_key_version INTEGER,
    p_ticket_signature TEXT,
    p_lifetime INTERVAL,
    INOUT p_new_ticket_id UUID DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
DECLARE
    tgt tickets%ROWTYPE;
    eligibility RECORD;
    now_time TIMESTAMPTZ := CURRENT_TIMESTAMP;
    expiry TIMESTAMPTZ;
BEGIN
    IF p_lifetime <= INTERVAL '0 seconds' THEN
        RAISE EXCEPTION 'Ticket lifetime must be positive';
    END IF;

    SELECT *
    INTO tgt
    FROM tickets
    WHERE ticket_id = p_tgt_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'TGT not found';
    END IF;

    SELECT *
    INTO eligibility
    FROM service_ticket_eligibility(
        p_tgt_id,
        p_service_id
    );

    IF NOT eligibility.eligible THEN
        RAISE EXCEPTION
            'Service ticket rejected: %',
            eligibility.reason;
    END IF;

    expiry := LEAST(
        now_time + p_lifetime,
        tgt.expires_at
    );

    INSERT INTO tickets (
        ticket_type,
        client_principal_id,
        service_id,
        session_id,
        parent_tgt_id,
        key_version,
        ticket_signature,
        issued_at,
        expires_at
    )
    VALUES (
        'SERVICE',
        tgt.client_principal_id,
        p_service_id,
        tgt.session_id,
        tgt.ticket_id,
        p_key_version,
        p_ticket_signature,
        now_time,
        expiry
    )
    RETURNING ticket_id INTO p_new_ticket_id;

    INSERT INTO kdc_audit (
        principal_id,
        action,
        severity,
        description
    )
    VALUES (
        tgt.client_principal_id,
        'SERVICE_TICKET_ISSUED',
        'INFO',
        'Service ticket issued by TGS'
    );
END;
$$;

-- ------------------------------------------------------------
-- 19. REPORTING VIEW
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW ticket_inventory AS
SELECT
    t.ticket_id,
    t.ticket_type,
    p.principal_name,
    p.principal_type,
    sp.service_name,
    t.issued_at,
    t.expires_at,
    t.status,
    CASE
        WHEN t.status <> 'ISSUED' THEN FALSE
        WHEN t.expires_at <= CURRENT_TIMESTAMP THEN FALSE
        ELSE TRUE
    END AS currently_valid
FROM tickets t
JOIN principals p
    ON p.principal_id = t.client_principal_id
LEFT JOIN service_principals sp
    ON sp.service_id = t.service_id;

-- ------------------------------------------------------------
-- 20. AUTHENTICATION PERFORMANCE VIEW
-- ------------------------------------------------------------

CREATE OR REPLACE VIEW authentication_performance AS
SELECT
    stage,
    status,
    COUNT(*) AS total_attempts,
    MIN(attempted_at) AS first_attempt,
    MAX(attempted_at) AS latest_attempt
FROM authentication_attempts
GROUP BY stage, status;

-- ------------------------------------------------------------
-- 21. SAMPLE DATA
-- ------------------------------------------------------------

INSERT INTO realms (
    realm_name,
    description
)
VALUES (
    'EXAMPLE.LOCAL',
    'Educational enterprise Kerberos realm'
);

INSERT INTO principals (
    realm_id,
    principal_name,
    principal_type,
    status,
    password_verifier
)
SELECT
    realm_id,
    'alice@EXAMPLE.LOCAL',
    'USER',
    'ACTIVE',
    'PBKDF2_VERIFIER_REFERENCE_ALICE'
FROM realms
WHERE realm_name = 'EXAMPLE.LOCAL';

INSERT INTO principals (
    realm_id,
    principal_name,
    principal_type,
    status
)
SELECT
    realm_id,
    'http/web.example.local',
    'SERVICE',
    'ACTIVE'
FROM realms
WHERE realm_name = 'EXAMPLE.LOCAL';

INSERT INTO principals (
    realm_id,
    principal_name,
    principal_type,
    status
)
SELECT
    realm_id,
    'postgres/db.example.local',
    'SERVICE',
    'ACTIVE'
FROM realms
WHERE realm_name = 'EXAMPLE.LOCAL';

INSERT INTO principal_roles (
    principal_id,
    role_name
)
SELECT
    principal_id,
    'DEVELOPER'
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

INSERT INTO principal_roles (
    principal_id,
    role_name
)
SELECT
    principal_id,
    'EMPLOYEE'
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

INSERT INTO principal_keys (
    principal_id,
    key_version,
    encryption_type,
    key_reference,
    active
)
SELECT
    principal_id,
    1,
    'AES256-CTS-HMAC-SHA1-96',
    'KMS://EXAMPLE/ALICE/V1',
    TRUE
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

INSERT INTO principal_keys (
    principal_id,
    key_version,
    encryption_type,
    key_reference,
    active
)
SELECT
    principal_id,
    1,
    'AES256-CTS-HMAC-SHA1-96',
    'KMS://EXAMPLE/HTTP/V1',
    TRUE
FROM principals
WHERE principal_name = 'http/web.example.local';

INSERT INTO principal_keys (
    principal_id,
    key_version,
    encryption_type,
    key_reference,
    active
)
SELECT
    principal_id,
    1,
    'AES256-CTS-HMAC-SHA1-96',
    'KMS://EXAMPLE/POSTGRES/V1',
    TRUE
FROM principals
WHERE principal_name = 'postgres/db.example.local';

INSERT INTO service_principals (
    principal_id,
    service_name,
    hostname,
    service_category
)
SELECT
    principal_id,
    'http/web.example.local',
    'web.example.local',
    'HTTP'
FROM principals
WHERE principal_name = 'http/web.example.local';

INSERT INTO service_principals (
    principal_id,
    service_name,
    hostname,
    service_category
)
SELECT
    principal_id,
    'postgres/db.example.local',
    'db.example.local',
    'DATABASE'
FROM principals
WHERE principal_name = 'postgres/db.example.local';

-- ------------------------------------------------------------
-- 22. VALID AUTHENTICATION SESSION
-- ------------------------------------------------------------

INSERT INTO authentication_sessions (
    session_id,
    principal_id,
    client_identifier,
    client_address,
    status,
    completed_at
)
SELECT
    '11111111-1111-4111-8111-111111111111',
    principal_id,
    'WORKSTATION-01',
    '192.168.1.25',
    'SUCCESS',
    CURRENT_TIMESTAMP
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

-- ------------------------------------------------------------
-- 23. ISSUE SAMPLE TGT
-- ------------------------------------------------------------

INSERT INTO tickets (
    ticket_id,
    ticket_type,
    client_principal_id,
    session_id,
    key_version,
    ticket_signature,
    issued_at,
    expires_at
)
SELECT
    '22222222-2222-4222-8222-222222222222',
    'TGT',
    p.principal_id,
    s.session_id,
    1,
    'EDUCATIONAL_TGT_SIGNATURE',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '10 minutes'
FROM principals p
JOIN authentication_sessions s
    ON s.principal_id = p.principal_id
WHERE p.principal_name = 'alice@EXAMPLE.LOCAL'
  AND s.session_id =
      '11111111-1111-4111-8111-111111111111';

-- ------------------------------------------------------------
-- 24. ISSUE SAMPLE SERVICE TICKET
-- ------------------------------------------------------------

INSERT INTO tickets (
    ticket_id,
    ticket_type,
    client_principal_id,
    service_id,
    session_id,
    parent_tgt_id,
    key_version,
    ticket_signature,
    issued_at,
    expires_at
)
SELECT
    '33333333-3333-4333-8333-333333333333',
    'SERVICE',
    tgt.client_principal_id,
    sp.service_id,
    tgt.session_id,
    tgt.ticket_id,
    1,
    'EDUCATIONAL_SERVICE_SIGNATURE',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '5 minutes'
FROM tickets tgt
JOIN service_principals sp
    ON sp.service_name = 'http/web.example.local'
WHERE tgt.ticket_id =
    '22222222-2222-4222-8222-222222222222';

-- ------------------------------------------------------------
-- 25. SUCCESSFUL AND FAILED AUTHENTICATION ATTEMPTS
-- ------------------------------------------------------------

INSERT INTO authentication_attempts (
    session_id,
    principal_id,
    stage,
    status,
    source_address
)
SELECT
    s.session_id,
    p.principal_id,
    'AS',
    'SUCCESS',
    '192.168.1.25'
FROM authentication_sessions s
JOIN principals p
    ON p.principal_id = s.principal_id
WHERE s.session_id =
    '11111111-1111-4111-8111-111111111111';

INSERT INTO authentication_attempts (
    session_id,
    principal_id,
    stage,
    status,
    failure_reason,
    source_address
)
SELECT
    s.session_id,
    p.principal_id,
    'AS',
    'FAILED',
    'INVALID_CREDENTIALS',
    '192.168.1.25'
FROM authentication_sessions s
JOIN principals p
    ON p.principal_id = s.principal_id
WHERE s.session_id =
    '11111111-1111-4111-8111-111111111111';

INSERT INTO authentication_attempts (
    session_id,
    principal_id,
    stage,
    requested_service_id,
    status,
    source_address
)
SELECT
    s.session_id,
    p.principal_id,
    'SERVICE',
    sp.service_id,
    'SUCCESS',
    '192.168.1.25'
FROM authentication_sessions s
JOIN principals p
    ON p.principal_id = s.principal_id
JOIN service_principals sp
    ON sp.service_name = 'http/web.example.local'
WHERE s.session_id =
    '11111111-1111-4111-8111-111111111111';

-- ------------------------------------------------------------
-- 26. AUTHENTICATOR RECORD
-- ------------------------------------------------------------

INSERT INTO authenticators (
    ticket_id,
    nonce,
    authenticator_timestamp,
    signature,
    accepted
)
VALUES (
    '33333333-3333-4333-8333-333333333333',
    'UNIQUE-EDUCATIONAL-NONCE-001',
    CURRENT_TIMESTAMP,
    'EDUCATIONAL_AUTHENTICATOR_SIGNATURE',
    TRUE
);

-- ------------------------------------------------------------
-- 27. SERVICE ACCESS RECORD
-- ------------------------------------------------------------

INSERT INTO service_access_events (
    ticket_id,
    service_id,
    principal_id,
    authenticator_id,
    authenticated,
    mutual_authentication
)
SELECT
    t.ticket_id,
    t.service_id,
    t.client_principal_id,
    a.authenticator_id,
    TRUE,
    TRUE
FROM tickets t
JOIN authenticators a
    ON a.ticket_id = t.ticket_id
WHERE t.ticket_id =
    '33333333-3333-4333-8333-333333333333';

-- ------------------------------------------------------------
-- 28. AUDIT RECORDS
-- ------------------------------------------------------------

INSERT INTO kdc_audit (
    principal_id,
    action,
    severity,
    description,
    source_address
)
SELECT
    principal_id,
    'TGT_ISSUED',
    'INFO',
    'Authentication Server issued a TGT',
    '192.168.1.25'
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

INSERT INTO kdc_audit (
    principal_id,
    action,
    severity,
    description,
    source_address
)
SELECT
    principal_id,
    'INVALID_CREDENTIALS',
    'WARNING',
    'Authentication attempt rejected',
    '192.168.1.25'
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

-- ------------------------------------------------------------
-- 29. RETRIEVAL: PRINCIPAL AND ROLE INFORMATION
-- ------------------------------------------------------------

SELECT
    p.principal_name,
    p.principal_type,
    p.status,
    r.realm_name,
    pr.role_name
FROM principals p
JOIN realms r
    ON r.realm_id = p.realm_id
LEFT JOIN principal_roles pr
    ON pr.principal_id = p.principal_id
ORDER BY p.principal_name, pr.role_name;

-- ------------------------------------------------------------
-- 30. RETRIEVAL: TGT AND SERVICE TICKET INVENTORY
-- ------------------------------------------------------------

SELECT *
FROM ticket_inventory
ORDER BY issued_at DESC;

-- ------------------------------------------------------------
-- 31. VALIDATION: SERVICE TICKET ELIGIBILITY
-- ------------------------------------------------------------

SELECT *
FROM service_ticket_eligibility(
    '22222222-2222-4222-8222-222222222222',
    (
        SELECT service_id
        FROM service_principals
        WHERE service_name = 'postgres/db.example.local'
    )
);

-- ------------------------------------------------------------
-- 32. VALIDATION: TICKET RELATIONSHIPS
-- ------------------------------------------------------------

SELECT
    child.ticket_id AS service_ticket,
    parent.ticket_id AS parent_tgt,
    child.client_principal_id,
    child.expires_at AS service_expiry,
    parent.expires_at AS tgt_expiry,
    child.expires_at <= parent.expires_at AS lifetime_valid
FROM tickets child
JOIN tickets parent
    ON parent.ticket_id = child.parent_tgt_id;

-- ------------------------------------------------------------
-- 33. AGGREGATION: AUTHENTICATION SUCCESS RATE
-- ------------------------------------------------------------

SELECT
    stage,
    COUNT(*) AS total_attempts,
    COUNT(*) FILTER (
        WHERE status = 'SUCCESS'
    ) AS successful_attempts,
    COUNT(*) FILTER (
        WHERE status IN ('FAILED', 'REJECTED')
    ) AS unsuccessful_attempts,
    ROUND(
        100.0 * COUNT(*) FILTER (
            WHERE status = 'SUCCESS'
        ) / NULLIF(COUNT(*), 0),
        2
    ) AS success_percentage
FROM authentication_attempts
GROUP BY stage
ORDER BY stage;

-- ------------------------------------------------------------
-- 34. EVALUATION: TICKETS APPROACHING EXPIRATION
-- ------------------------------------------------------------

SELECT
    ticket_id,
    ticket_type,
    expires_at,
    expires_at - CURRENT_TIMESTAMP AS remaining_lifetime
FROM tickets
WHERE status = 'ISSUED'
  AND expires_at BETWEEN
      CURRENT_TIMESTAMP
      AND CURRENT_TIMESTAMP + INTERVAL '2 minutes'
ORDER BY expires_at;

-- ------------------------------------------------------------
-- 35. REPORTING: SERVICE ACCESS BY PRINCIPAL
-- ------------------------------------------------------------

SELECT
    p.principal_name,
    sp.service_name,
    COUNT(*) AS total_accesses,
    COUNT(*) FILTER (
        WHERE sae.authenticated
    ) AS successful_accesses,
    COUNT(*) FILTER (
        WHERE sae.mutual_authentication
    ) AS mutually_authenticated
FROM service_access_events sae
JOIN principals p
    ON p.principal_id = sae.principal_id
JOIN service_principals sp
    ON sp.service_id = sae.service_id
GROUP BY
    p.principal_name,
    sp.service_name
ORDER BY total_accesses DESC;

-- ------------------------------------------------------------
-- 36. WORKFLOW: AUTHENTICATION EVENT TIMELINE
-- ------------------------------------------------------------

SELECT
    s.session_id,
    p.principal_name,
    s.started_at,
    aa.stage,
    aa.status,
    aa.failure_reason,
    aa.attempted_at
FROM authentication_sessions s
JOIN principals p
    ON p.principal_id = s.principal_id
LEFT JOIN authentication_attempts aa
    ON aa.session_id = s.session_id
ORDER BY s.started_at, aa.attempted_at;

-- ------------------------------------------------------------
-- 37. SECURITY REPORT: FAILED AUTHENTICATIONS
-- ------------------------------------------------------------

SELECT
    p.principal_name,
    aa.source_address,
    COUNT(*) AS failure_count,
    MAX(aa.attempted_at) AS latest_failure
FROM authentication_attempts aa
JOIN principals p
    ON p.principal_id = aa.principal_id
WHERE aa.status IN ('FAILED', 'REJECTED')
GROUP BY
    p.principal_name,
    aa.source_address
ORDER BY failure_count DESC;

-- ------------------------------------------------------------
-- 38. REPORT: KDC AUDIT EVENTS
-- ------------------------------------------------------------

SELECT
    a.audit_id,
    p.principal_name,
    a.action,
    a.severity,
    a.description,
    a.event_time
FROM kdc_audit a
LEFT JOIN principals p
    ON p.principal_id = a.principal_id
ORDER BY a.event_time DESC;

-- ------------------------------------------------------------
-- 39. REPORT: AUTHENTICATION PERFORMANCE
-- ------------------------------------------------------------

SELECT *
FROM authentication_performance
ORDER BY stage, status;

-- ------------------------------------------------------------
-- 40. WORKFLOW: EXPIRE TICKETS
-- ------------------------------------------------------------

SELECT expire_tickets() AS tickets_expired;

-- ------------------------------------------------------------
-- 41. TRANSACTION: ISSUE A SERVICE TICKET
-- ------------------------------------------------------------

BEGIN;

CALL issue_service_ticket(
    '22222222-2222-4222-8222-222222222222',
    (
        SELECT service_id
        FROM service_principals
        WHERE service_name = 'postgres/db.example.local'
    ),
    1,
    'DATABASE_SERVICE_TICKET_SIGNATURE',
    INTERVAL '5 minutes',
    NULL
);

COMMIT;

-- ------------------------------------------------------------
-- 42. VERIFY NEW SERVICE TICKET
-- ------------------------------------------------------------

SELECT
    ticket_id,
    ticket_type,
    status,
    issued_at,
    expires_at
FROM tickets
WHERE ticket_type = 'SERVICE'
ORDER BY issued_at DESC;

-- ------------------------------------------------------------
-- 43. TRANSACTION: DEMONSTRATE ROLLBACK
-- ------------------------------------------------------------

BEGIN;

UPDATE principals
SET status = 'DISABLED'
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

-- The update is deliberately rolled back.
ROLLBACK;

-- The principal remains ACTIVE.
SELECT
    principal_name,
    status
FROM principals
WHERE principal_name = 'alice@EXAMPLE.LOCAL';

COMMIT;

-- ------------------------------------------------------------
-- 44. FINAL DATABASE INVENTORY
-- ------------------------------------------------------------

SELECT
    'REALMS' AS entity,
    COUNT(*) AS record_count
FROM realms

UNION ALL

SELECT
    'PRINCIPALS',
    COUNT(*)
FROM principals

UNION ALL

SELECT
    'SERVICES',
    COUNT(*)
FROM service_principals

UNION ALL

SELECT
    'SESSIONS',
    COUNT(*)
FROM authentication_sessions

UNION ALL

SELECT
    'TICKETS',
    COUNT(*)
FROM tickets

UNION ALL

SELECT
    'AUTHENTICATION_ATTEMPTS',
    COUNT(*)
FROM authentication_attempts

UNION ALL

SELECT
    'AUTHENTICATORS',
    COUNT(*)
FROM authenticators

UNION ALL

SELECT
    'AUDIT_RECORDS',
    COUNT(*)
FROM kdc_audit;

COMMIT;
