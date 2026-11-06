-- ============================================================
-- PUBLIC KEY INFRASTRUCTURE (PKI)
-- Certificate Authorities, Trust Hierarchy and Lifecycle
-- PostgreSQL 15+
--
-- Models:
-- 1. Root certificate authorities
-- 2. Intermediate certificate authorities
-- 3. End-entity certificates
-- 4. Certificate issuance policies
-- 5. Certificate chains and trust anchors
-- 6. Renewal and replacement
-- 7. Revocation and CRL records
-- 8. Validation decisions
-- 9. Audit events
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS pki;

SET search_path TO pki, public;

-- ============================================================
-- ENUM TYPES
-- ============================================================

CREATE TYPE ca_type AS ENUM (
    'ROOT',
    'INTERMEDIATE',
    'END_ENTITY'
);

CREATE TYPE certificate_status AS ENUM (
    'ACTIVE',
    'EXPIRED',
    'REVOKED',
    'NOT_YET_VALID'
);

CREATE TYPE ca_status AS ENUM (
    'ACTIVE',
    'SUSPENDED',
    'RETIRED',
    'COMPROMISED'
);

CREATE TYPE revocation_reason AS ENUM (
    'KEY_COMPROMISE',
    'CA_COMPROMISE',
    'SUPERSEDED',
    'CESSATION_OF_OPERATION',
    'PRIVILEGE_WITHDRAWN',
    'CERTIFICATE_HOLD',
    'UNSPECIFIED'
);

CREATE TYPE validation_status AS ENUM (
    'VALID',
    'EXPIRED',
    'REVOKED',
    'NOT_YET_VALID',
    'UNTRUSTED_ROOT',
    'INVALID_CHAIN',
    'ISSUER_UNAVAILABLE',
    'POLICY_FAILURE'
);

CREATE TYPE lifecycle_event AS ENUM (
    'ROOT_CREATED',
    'INTERMEDIATE_CREATED',
    'CERTIFICATE_ISSUED',
    'CERTIFICATE_RENEWED',
    'CERTIFICATE_REVOKED',
    'CA_SUSPENDED',
    'CA_RETIRED',
    'VALIDATION_PERFORMED'
);

-- ============================================================
-- ORGANIZATIONS
-- ============================================================

CREATE TABLE organizations (
    organization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_name VARCHAR(200) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================
-- CERTIFICATE AUTHORITIES
-- ============================================================

CREATE TABLE certificate_authorities (
    ca_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    organization_id BIGINT NOT NULL
        REFERENCES organizations(organization_id),

    parent_ca_id BIGINT
        REFERENCES certificate_authorities(ca_id),

    ca_name VARCHAR(200) NOT NULL,

    ca_type ca_type NOT NULL
        CHECK (ca_type IN ('ROOT', 'INTERMEDIATE')),

    status ca_status NOT NULL DEFAULT 'ACTIVE',

    max_validity_days INTEGER NOT NULL
        CHECK (max_validity_days > 0),

    max_path_length INTEGER
        CHECK (max_path_length IS NULL OR max_path_length >= 0),

    certificate_id BIGINT UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT root_has_no_parent
        CHECK (
            (ca_type = 'ROOT' AND parent_ca_id IS NULL)
            OR
            (ca_type = 'INTERMEDIATE' AND parent_ca_id IS NOT NULL)
        ),

    CONSTRAINT unique_ca_name_per_organization
        UNIQUE (organization_id, ca_name)
);

CREATE INDEX idx_ca_parent
    ON certificate_authorities(parent_ca_id);

CREATE INDEX idx_ca_status
    ON certificate_authorities(status);

-- ============================================================
-- CERTIFICATES
-- ============================================================

CREATE TABLE certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    serial_number VARCHAR(64) NOT NULL UNIQUE,

    subject VARCHAR(500) NOT NULL,

    issuer_ca_id BIGINT
        REFERENCES certificate_authorities(ca_id),

    certificate_type ca_type NOT NULL,

    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,

    is_ca BOOLEAN NOT NULL DEFAULT FALSE,

    max_path_length INTEGER
        CHECK (max_path_length IS NULL OR max_path_length >= 0),

    subject_key_identifier VARCHAR(128) NOT NULL,

    authority_key_identifier VARCHAR(128),

    signature_algorithm VARCHAR(100) NOT NULL,

    public_key_algorithm VARCHAR(50) NOT NULL,

    key_usage TEXT[] NOT NULL,

    fingerprint_sha256 VARCHAR(64) NOT NULL UNIQUE,

    replacement_for BIGINT
        REFERENCES certificates(certificate_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_certificate_period
        CHECK (not_after > not_before),

    CONSTRAINT root_certificate_has_no_issuer
        CHECK (
            (certificate_type = 'ROOT' AND issuer_ca_id IS NULL)
            OR
            (certificate_type <> 'ROOT' AND issuer_ca_id IS NOT NULL)
        ),

    CONSTRAINT ca_type_consistency
        CHECK (
            (certificate_type IN ('ROOT', 'INTERMEDIATE') AND is_ca)
            OR
            (certificate_type = 'END_ENTITY' AND NOT is_ca)
        ),

    CONSTRAINT end_entity_has_no_ca_path_length
        CHECK (
            certificate_type <> 'END_ENTITY'
            OR max_path_length IS NULL
        ),

    CONSTRAINT non_empty_key_usage
        CHECK (cardinality(key_usage) > 0),

    CONSTRAINT no_self_replacement
        CHECK (
            replacement_for IS NULL
            OR replacement_for <> certificate_id
        )
);

CREATE INDEX idx_certificates_issuer
    ON certificates(issuer_ca_id);

CREATE INDEX idx_certificates_subject
    ON certificates(subject);

CREATE INDEX idx_certificates_validity
    ON certificates(not_before, not_after);

CREATE INDEX idx_certificates_replacement
    ON certificates(replacement_for);

CREATE INDEX idx_certificates_key_id
    ON certificates(subject_key_identifier);

-- ============================================================
-- CA CERTIFICATE ASSOCIATION
-- ============================================================

ALTER TABLE certificate_authorities
    ADD CONSTRAINT fk_ca_certificate
    FOREIGN KEY (certificate_id)
    REFERENCES certificates(certificate_id);

-- ============================================================
-- ISSUANCE POLICIES
-- ============================================================

CREATE TABLE issuance_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ca_id BIGINT NOT NULL
        REFERENCES certificate_authorities(ca_id),

    policy_name VARCHAR(150) NOT NULL,

    max_validity_days INTEGER NOT NULL
        CHECK (max_validity_days > 0),

    allowed_key_usages TEXT[] NOT NULL,

    allow_intermediate_ca BOOLEAN NOT NULL DEFAULT FALSE,

    require_subject_validation BOOLEAN NOT NULL DEFAULT TRUE,

    require_unique_serial BOOLEAN NOT NULL DEFAULT TRUE,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (ca_id, policy_name),

    CHECK (cardinality(allowed_key_usages) > 0)
);

CREATE INDEX idx_issuance_policies_active
    ON issuance_policies(ca_id, active);

-- ============================================================
-- TRUST ANCHORS
-- ============================================================

CREATE TABLE trust_anchors (
    trust_anchor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_id BIGINT NOT NULL UNIQUE
        REFERENCES certificates(certificate_id),

    trusted_by VARCHAR(200) NOT NULL,

    trust_purpose TEXT[] NOT NULL,

    trusted_from TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    trusted_until TIMESTAMPTZ,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    CHECK (
        trusted_until IS NULL
        OR trusted_until > trusted_from
    )
);

CREATE INDEX idx_trust_anchors_active
    ON trust_anchors(certificate_id)
    WHERE active = TRUE;

-- ============================================================
-- CERTIFICATE REVOCATION
-- ============================================================

CREATE TABLE certificate_revocations (
    revocation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_id BIGINT NOT NULL UNIQUE
        REFERENCES certificates(certificate_id),

    reason revocation_reason NOT NULL,

    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    revoked_by VARCHAR(150) NOT NULL,

    effective_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    remarks TEXT
);

CREATE INDEX idx_revocations_time
    ON certificate_revocations(revoked_at DESC);

-- CRL publication records.

CREATE TABLE crl_publications (
    crl_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    ca_id BIGINT NOT NULL
        REFERENCES certificate_authorities(ca_id),

    crl_number BIGINT NOT NULL CHECK (crl_number > 0),

    this_update TIMESTAMPTZ NOT NULL,

    next_update TIMESTAMPTZ NOT NULL,

    published_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    crl_fingerprint VARCHAR(64) NOT NULL UNIQUE,

    UNIQUE (ca_id, crl_number),

    CHECK (next_update > this_update)
);

CREATE TABLE crl_entries (
    crl_entry_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    crl_id BIGINT NOT NULL
        REFERENCES crl_publications(crl_id),

    certificate_id BIGINT NOT NULL
        REFERENCES certificate_revocations(certificate_id),

    UNIQUE (crl_id, certificate_id)
);

-- ============================================================
-- VALIDATION RECORDS
-- ============================================================

CREATE TABLE certificate_validations (
    validation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_id BIGINT NOT NULL
        REFERENCES certificates(certificate_id),

    validation_status validation_status NOT NULL,

    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    relying_party VARCHAR(200) NOT NULL,

    trust_anchor_id BIGINT
        REFERENCES trust_anchors(trust_anchor_id),

    validation_message TEXT NOT NULL,

    chain_depth INTEGER CHECK (chain_depth IS NULL OR chain_depth >= 0)
);

CREATE INDEX idx_validation_certificate_time
    ON certificate_validations(
        certificate_id,
        checked_at DESC
    );

CREATE INDEX idx_validation_status
    ON certificate_validations(validation_status, checked_at DESC);

-- ============================================================
-- AUDIT EVENTS
-- ============================================================

CREATE TABLE pki_audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    event_type lifecycle_event NOT NULL,

    certificate_id BIGINT
        REFERENCES certificates(certificate_id),

    ca_id BIGINT
        REFERENCES certificate_authorities(ca_id),

    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,

    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    actor VARCHAR(150) NOT NULL
);

CREATE INDEX idx_pki_audit_timestamp
    ON pki_audit_events(event_timestamp DESC);

CREATE INDEX idx_pki_audit_type
    ON pki_audit_events(event_type, event_timestamp DESC);

-- ============================================================
-- CERTIFICATE STATUS FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION get_certificate_status(
    p_certificate_id BIGINT,
    p_check_time TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
)
RETURNS certificate_status
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_cert certificates%ROWTYPE;
BEGIN
    SELECT *
    INTO v_cert
    FROM certificates
    WHERE certificate_id = p_certificate_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Certificate % does not exist',
            p_certificate_id;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM certificate_revocations
        WHERE certificate_id = p_certificate_id
    ) THEN
        RETURN 'REVOKED';
    END IF;

    IF p_check_time < v_cert.not_before THEN
        RETURN 'NOT_YET_VALID';
    END IF;

    IF p_check_time >= v_cert.not_after THEN
        RETURN 'EXPIRED';
    END IF;

    RETURN 'ACTIVE';
END;
$$;

-- ============================================================
-- VALIDATE CERTIFICATE ISSUANCE
-- ============================================================

CREATE OR REPLACE FUNCTION validate_certificate_issuance(
    p_ca_id BIGINT,
    p_subject TEXT,
    p_validity_days INTEGER,
    p_key_usage TEXT[]
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_ca certificate_authorities%ROWTYPE;
    v_policy issuance_policies%ROWTYPE;
    v_ca_cert certificates%ROWTYPE;
BEGIN
    SELECT *
    INTO v_ca
    FROM certificate_authorities
    WHERE ca_id = p_ca_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'CA not found';
    END IF;

    IF v_ca.status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'CA is not active';
    END IF;

    SELECT *
    INTO v_policy
    FROM issuance_policies
    WHERE ca_id = p_ca_id
      AND active = TRUE
    ORDER BY policy_id
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'No active issuance policy';
    END IF;

    SELECT *
    INTO v_ca_cert
    FROM certificates
    WHERE certificate_id = v_ca.certificate_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'CA certificate missing';
    END IF;

    IF get_certificate_status(
        v_ca.certificate_id
    ) <> 'ACTIVE' THEN
        RAISE EXCEPTION 'CA certificate is not valid';
    END IF;

    IF v_policy.max_validity_days > v_ca.max_validity_days
       OR p_validity_days > v_policy.max_validity_days
       OR p_validity_days > v_ca.max_validity_days THEN
        RAISE EXCEPTION 'Certificate lifetime violates CA policy';
    END IF;

    IF p_subject IS NULL OR length(trim(p_subject)) = 0 THEN
        RAISE EXCEPTION 'Subject cannot be empty';
    END IF;

    IF p_key_usage IS NULL OR cardinality(p_key_usage) = 0 THEN
        RAISE EXCEPTION 'Key usage cannot be empty';
    END IF;

    IF NOT (p_key_usage <@ v_policy.allowed_key_usages) THEN
        RAISE EXCEPTION 'Requested key usage violates issuance policy';
    END IF;

    RETURN TRUE;
END;
$$;

-- ============================================================
-- CERTIFICATE VALIDATION FUNCTION
--
-- Performs structural and lifecycle validation.
-- It does not cryptographically verify X.509 signatures.
-- ============================================================

CREATE OR REPLACE FUNCTION validate_certificate(
    p_certificate_id BIGINT,
    p_relying_party VARCHAR(200)
)
RETURNS validation_status
LANGUAGE plpgsql
AS $$
DECLARE
    v_current BIGINT := p_certificate_id;
    v_parent BIGINT;
    v_cert certificates%ROWTYPE;
    v_parent_cert certificates%ROWTYPE;
    v_root BIGINT;
    v_depth INTEGER := 0;
    v_subordinate_cas INTEGER;
    v_seen BIGINT[] := ARRAY[]::BIGINT[];
    v_result validation_status := 'VALID';
    v_anchor BIGINT;
BEGIN
    SELECT *
    INTO v_cert
    FROM certificates
    WHERE certificate_id = p_certificate_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Certificate not found';
    END IF;

    LOOP
        IF v_current = ANY(v_seen) THEN
            v_result := 'INVALID_CHAIN';
            EXIT;
        END IF;

        v_seen := array_append(v_seen, v_current);

        SELECT *
        INTO v_cert
        FROM certificates
        WHERE certificate_id = v_current;

        IF NOT FOUND THEN
            v_result := 'INVALID_CHAIN';
            EXIT;
        END IF;

        CASE get_certificate_status(v_current)
            WHEN 'REVOKED' THEN
                v_result := 'REVOKED';
                EXIT;
            WHEN 'EXPIRED' THEN
                v_result := 'EXPIRED';
                EXIT;
            WHEN 'NOT_YET_VALID' THEN
                v_result := 'NOT_YET_VALID';
                EXIT;
            ELSE
                NULL;
        END CASE;

        IF v_cert.issuer_ca_id IS NULL THEN
            IF v_cert.certificate_type <> 'ROOT' THEN
                v_result := 'INVALID_CHAIN';
            END IF;

            v_root := v_current;
            EXIT;
        END IF;

        v_parent := v_cert.issuer_ca_id;

        SELECT *
        INTO v_parent_cert
        FROM certificates
        WHERE certificate_id = (
            SELECT certificate_id
            FROM certificate_authorities
            WHERE ca_id = v_parent
        );

        IF NOT FOUND THEN
            v_result := 'ISSUER_UNAVAILABLE';
            EXIT;
        END IF;

        IF v_cert.authority_key_identifier <>
           v_parent_cert.subject_key_identifier THEN
            v_result := 'INVALID_CHAIN';
            EXIT;
        END IF;

        IF NOT v_parent_cert.is_ca
           OR NOT ('keyCertSign' = ANY(v_parent_cert.key_usage)) THEN
            v_result := 'INVALID_CHAIN';
            EXIT;
        END IF;

        IF EXISTS (
            SELECT 1
            FROM certificate_authorities
            WHERE ca_id = v_parent
              AND status <> 'ACTIVE'
        ) THEN
            v_result := 'ISSUER_UNAVAILABLE';
            EXIT;
        END IF;

        v_depth := v_depth + 1;
        v_current := v_parent_cert.certificate_id;

        IF v_depth > 10 THEN
            v_result := 'INVALID_CHAIN';
            EXIT;
        END IF;
    END LOOP;

    IF v_result = 'VALID' THEN
        SELECT trust_anchor_id
        INTO v_anchor
        FROM trust_anchors
        WHERE certificate_id = v_root
          AND active = TRUE
          AND trusted_from <= CURRENT_TIMESTAMP
          AND (
              trusted_until IS NULL
              OR trusted_until > CURRENT_TIMESTAMP
          )
        LIMIT 1;

        IF NOT FOUND THEN
            v_result := 'UNTRUSTED_ROOT';
        END IF;
    END IF;

    INSERT INTO certificate_validations (
        certificate_id,
        validation_status,
        relying_party,
        trust_anchor_id,
        validation_message,
        chain_depth
    )
    VALUES (
        p_certificate_id,
        v_result,
        p_relying_party,
        v_anchor,
        CASE v_result
            WHEN 'VALID' THEN 'Structural trust validation passed'
            ELSE 'Certificate validation failed: ' || v_result::TEXT
        END,
        v_depth
    );

    INSERT INTO pki_audit_events (
        event_type,
        certificate_id,
        event_details,
        actor
    )
    VALUES (
        'VALIDATION_PERFORMED',
        p_certificate_id,
        jsonb_build_object(
            'result', v_result,
            'relying_party', p_relying_party,
            'chain_depth', v_depth
        ),
        p_relying_party
    );

    RETURN v_result;
END;
$$;

-- ============================================================
-- CERTIFICATE REVOCATION PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE revoke_certificate(
    p_certificate_id BIGINT,
    p_reason revocation_reason,
    p_actor VARCHAR(150),
    p_remarks TEXT DEFAULT NULL
)
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM certificates
        WHERE certificate_id = p_certificate_id
    ) THEN
        RAISE EXCEPTION 'Certificate does not exist';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM certificate_revocations
        WHERE certificate_id = p_certificate_id
    ) THEN
        RAISE EXCEPTION 'Certificate is already revoked';
    END IF;

    INSERT INTO certificate_revocations (
        certificate_id,
        reason,
        revoked_by,
        remarks
    )
    VALUES (
        p_certificate_id,
        p_reason,
        p_actor,
        p_remarks
    );

    IF EXISTS (
        SELECT 1
        FROM certificates
        WHERE certificate_id = p_certificate_id
          AND is_ca = TRUE
    ) THEN
        UPDATE certificate_authorities
        SET status = 'COMPROMISED'
        WHERE certificate_id = p_certificate_id;
    END IF;

    INSERT INTO pki_audit_events (
        event_type,
        certificate_id,
        event_details,
        actor
    )
    VALUES (
        'CERTIFICATE_REVOKED',
        p_certificate_id,
        jsonb_build_object(
            'reason', p_reason,
            'remarks', p_remarks
        ),
        p_actor
    );
END;
$$;

-- ============================================================
-- AUDIT TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION audit_certificate_insertion()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO pki_audit_events (
        event_type,
        certificate_id,
        event_details,
        actor
    )
    VALUES (
        CASE NEW.certificate_type
            WHEN 'ROOT' THEN 'ROOT_CREATED'::lifecycle_event
            WHEN 'INTERMEDIATE' THEN 'INTERMEDIATE_CREATED'::lifecycle_event
            ELSE 'CERTIFICATE_ISSUED'::lifecycle_event
        END,
        NEW.certificate_id,
        jsonb_build_object(
            'subject', NEW.subject,
            'serial', NEW.serial_number,
            'type', NEW.certificate_type
        ),
        CURRENT_USER
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_certificate_audit
AFTER INSERT ON certificates
FOR EACH ROW
EXECUTE FUNCTION audit_certificate_insertion();

-- ============================================================
-- VIEWS
-- ============================================================

CREATE OR REPLACE VIEW certificate_inventory AS
SELECT
    c.certificate_id,
    c.serial_number,
    c.subject,
    c.certificate_type,
    c.issuer_ca_id,
    c.not_before,
    c.not_after,
    c.is_ca,
    c.fingerprint_sha256,
    CASE
        WHEN r.revocation_id IS NOT NULL THEN 'REVOKED'
        WHEN CURRENT_TIMESTAMP < c.not_before THEN 'NOT_YET_VALID'
        WHEN CURRENT_TIMESTAMP >= c.not_after THEN 'EXPIRED'
        ELSE 'ACTIVE'
    END AS current_status,
    c.replacement_for
FROM certificates c
LEFT JOIN certificate_revocations r
    ON r.certificate_id = c.certificate_id;

CREATE OR REPLACE VIEW ca_hierarchy AS
WITH RECURSIVE hierarchy AS (
    SELECT
        ca_id,
        ca_name,
        parent_ca_id,
        ca_type,
        0 AS depth,
        ARRAY[ca_id] AS path
    FROM certificate_authorities
    WHERE parent_ca_id IS NULL

    UNION ALL

    SELECT
        child.ca_id,
        child.ca_name,
        child.parent_ca_id,
        child.ca_type,
        parent.depth + 1,
        parent.path || child.ca_id
    FROM certificate_authorities child
    JOIN hierarchy parent
        ON child.parent_ca_id = parent.ca_id
    WHERE NOT child.ca_id = ANY(parent.path)
)
SELECT * FROM hierarchy;

CREATE OR REPLACE VIEW certificate_expiry_report AS
SELECT
    certificate_id,
    subject,
    certificate_type,
    not_after,
    not_after - CURRENT_TIMESTAMP AS remaining_validity
FROM certificates
WHERE not_after > CURRENT_TIMESTAMP
  AND not_after <= CURRENT_TIMESTAMP + INTERVAL '30 days';

-- ============================================================
-- SAMPLE DATA
-- ============================================================

INSERT INTO organizations (organization_name)
VALUES ('Example Enterprise');

-- Root CA metadata.

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    max_path_length,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256
)
VALUES (
    'ROOT-SERIAL-001',
    'CN=Example Enterprise Root CA',
    NULL,
    'ROOT',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '10 years',
    TRUE,
    2,
    'ROOT-KEY-001',
    NULL,
    'SHA256withRSA',
    'RSA-4096',
    ARRAY['keyCertSign', 'cRLSign'],
    repeat('a', 64)
);

INSERT INTO certificate_authorities (
    organization_id,
    parent_ca_id,
    ca_name,
    ca_type,
    status,
    max_validity_days,
    max_path_length,
    certificate_id
)
VALUES (
    1,
    NULL,
    'Enterprise Root CA',
    'ROOT',
    'ACTIVE',
    3650,
    2,
    1
);

INSERT INTO trust_anchors (
    certificate_id,
    trusted_by,
    trust_purpose
)
VALUES (
    1,
    'Enterprise Security Administration',
    ARRAY['TLS_SERVER', 'TLS_CLIENT', 'CODE_SIGNING']
);

INSERT INTO issuance_policies (
    ca_id,
    policy_name,
    max_validity_days,
    allowed_key_usages,
    allow_intermediate_ca
)
VALUES (
    1,
    'Root Issuance Policy',
    730,
    ARRAY[
        'digitalSignature',
        'keyEncipherment',
        'keyAgreement',
        'dataEncipherment',
        'contentCommitment'
    ],
    TRUE
);

-- Intermediate CA.

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    max_path_length,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256
)
VALUES (
    'INT-SERIAL-001',
    'CN=Enterprise Issuing CA',
    1,
    'INTERMEDIATE',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '2 years',
    TRUE,
    0,
    'INT-KEY-001',
    'ROOT-KEY-001',
    'SHA256withRSA',
    'RSA-3072',
    ARRAY['keyCertSign', 'cRLSign'],
    repeat('b', 64)
);

INSERT INTO certificate_authorities (
    organization_id,
    parent_ca_id,
    ca_name,
    ca_type,
    status,
    max_validity_days,
    max_path_length,
    certificate_id
)
VALUES (
    1,
    1,
    'Enterprise Issuing CA',
    'INTERMEDIATE',
    'ACTIVE',
    365,
    0,
    2
);

INSERT INTO issuance_policies (
    ca_id,
    policy_name,
    max_validity_days,
    allowed_key_usages,
    allow_intermediate_ca
)
VALUES (
    2,
    'Server and Client Certificate Policy',
    90,
    ARRAY[
        'digitalSignature',
        'keyEncipherment',
        'keyAgreement'
    ],
    FALSE
);

-- Server certificate.

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256
)
VALUES (
    'LEAF-SERIAL-001',
    'DNS=api.example.com',
    2,
    'END_ENTITY',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '90 days',
    FALSE,
    'SERVER-KEY-001',
    'INT-KEY-001',
    'SHA256withRSA',
    'RSA-2048',
    ARRAY['digitalSignature', 'keyEncipherment'],
    repeat('c', 64)
);

-- Client certificate.

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256
)
VALUES (
    'LEAF-SERIAL-002',
    'CN=enterprise-client',
    2,
    'END_ENTITY',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '60 days',
    FALSE,
    'CLIENT-KEY-001',
    'INT-KEY-001',
    'SHA256withRSA',
    'RSA-2048',
    ARRAY['digitalSignature'],
    repeat('d', 64)
);

-- Expired certificate for failure testing.

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256
)
VALUES (
    'LEAF-SERIAL-003',
    'DNS=expired.example.com',
    2,
    'END_ENTITY',
    CURRENT_TIMESTAMP - INTERVAL '100 days',
    CURRENT_TIMESTAMP - INTERVAL '10 days',
    FALSE,
    'EXPIRED-KEY-001',
    'INT-KEY-001',
    'SHA256withRSA',
    'RSA-2048',
    ARRAY['digitalSignature'],
    repeat('e', 64)
);

-- Revoked certificate.

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256
)
VALUES (
    'LEAF-SERIAL-004',
    'CN=compromised-client',
    2,
    'END_ENTITY',
    CURRENT_TIMESTAMP - INTERVAL '1 day',
    CURRENT_TIMESTAMP + INTERVAL '90 days',
    FALSE,
    'REVOKED-KEY-001',
    'INT-KEY-001',
    'SHA256withRSA',
    'RSA-2048',
    ARRAY['digitalSignature'],
    repeat('f', 64)
);

INSERT INTO certificate_revocations (
    certificate_id,
    reason,
    revoked_by,
    remarks
)
VALUES (
    6,
    'KEY_COMPROMISE',
    'security-admin',
    'Private key compromise reported'
);

-- ============================================================
-- SAMPLE CRL PUBLICATION
-- ============================================================

INSERT INTO crl_publications (
    ca_id,
    crl_number,
    this_update,
    next_update,
    crl_fingerprint
)
VALUES (
    2,
    1,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '24 hours',
    repeat('1', 64)
);

INSERT INTO crl_entries (
    crl_id,
    certificate_id
)
VALUES (
    1,
    6
);

-- ============================================================
-- SAMPLE RENEWAL
-- ============================================================

INSERT INTO certificates (
    serial_number,
    subject,
    issuer_ca_id,
    certificate_type,
    not_before,
    not_after,
    is_ca,
    subject_key_identifier,
    authority_key_identifier,
    signature_algorithm,
    public_key_algorithm,
    key_usage,
    fingerprint_sha256,
    replacement_for
)
VALUES (
    'LEAF-SERIAL-005',
    'DNS=api.example.com',
    2,
    'END_ENTITY',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP + INTERVAL '120 days',
    FALSE,
    'SERVER-KEY-002',
    'INT-KEY-001',
    'SHA256withRSA',
    'RSA-2048',
    ARRAY['digitalSignature', 'keyEncipherment'],
    repeat('2', 64),
    3
);

-- ============================================================
-- REPORTING AND RETRIEVAL QUERIES
-- ============================================================

-- 1. Full certificate inventory.

SELECT *
FROM certificate_inventory
ORDER BY certificate_id;

-- 2. CA hierarchy.

SELECT
    repeat('  ', depth) || ca_name AS hierarchy_name,
    ca_type,
    depth,
    path
FROM ca_hierarchy
ORDER BY path;

-- 3. Certificates approaching expiration.

SELECT *
FROM certificate_expiry_report
ORDER BY not_after;

-- 4. Revocation registry.

SELECT
    c.serial_number,
    c.subject,
    r.reason,
    r.revoked_at,
    r.revoked_by
FROM certificate_revocations r
JOIN certificates c
    ON c.certificate_id = r.certificate_id
ORDER BY r.revoked_at DESC;

-- 5. Certificate issuance statistics.

SELECT
    certificate_type,
    COUNT(*) AS certificate_count,
    COUNT(*) FILTER (
        WHERE not_after > CURRENT_TIMESTAMP
    ) AS unexpired_count
FROM certificates
GROUP BY certificate_type
ORDER BY certificate_type;

-- 6. CA issuance workload.

SELECT
    ca.ca_id,
    ca.ca_name,
    COUNT(c.certificate_id) AS issued_certificates
FROM certificate_authorities ca
LEFT JOIN certificates c
    ON c.issuer_ca_id = ca.ca_id
GROUP BY ca.ca_id, ca.ca_name
ORDER BY issued_certificates DESC;

-- 7. Renewal history.

SELECT
    old.certificate_id AS original_id,
    old.subject,
    replacement.certificate_id AS replacement_id,
    old.not_after AS old_expiry,
    replacement.not_after AS replacement_expiry
FROM certificates replacement
JOIN certificates old
    ON replacement.replacement_for = old.certificate_id;

-- 8. Certificate validation evaluation.

SELECT validate_certificate(
    3,
    'api.example.com'
);

SELECT validate_certificate(
    4,
    'enterprise-client'
);

SELECT validate_certificate(
    5,
    'expired.example.com'
);

SELECT validate_certificate(
    6,
    'compromised-client'
);

-- 9. Validation performance report.

SELECT
    validation_status,
    COUNT(*) AS total_checks,
    COUNT(DISTINCT certificate_id) AS distinct_certificates
FROM certificate_validations
GROUP BY validation_status
ORDER BY validation_status;

-- 10. Audit history.

SELECT
    event_timestamp,
    event_type,
    certificate_id,
    ca_id,
    actor,
    event_details
FROM pki_audit_events
ORDER BY event_timestamp DESC;

-- ============================================================
-- ISSUANCE VALIDATION FAILURE EXAMPLE
-- Execute separately when testing because the exception
-- intentionally aborts the current transaction block.
-- ============================================================

-- SELECT validate_certificate_issuance(
--     2,
--     'DNS=invalid.example.com',
--     500,
--     ARRAY['digitalSignature']
-- );

-- ============================================================
-- TRANSACTIONAL REVOCATION EXAMPLE
-- ============================================================

DO $$
BEGIN
    CALL revoke_certificate(
        4,
        'SUPERSEDED',
        'security-admin',
        'Certificate replaced during planned rotation'
    );
END;
$$;

-- Verify the revocation.

SELECT
    certificate_id,
    subject,
    get_certificate_status(certificate_id) AS current_status
FROM certificates
WHERE certificate_id = 4;

-- ============================================================
-- ELIGIBILITY DETERMINATION
-- ============================================================

SELECT
    c.certificate_id,
    c.subject,
    get_certificate_status(c.certificate_id) AS lifecycle_status,
    CASE
        WHEN get_certificate_status(c.certificate_id) <> 'ACTIVE'
            THEN FALSE
        WHEN c.certificate_type = 'ROOT'
            THEN EXISTS (
                SELECT 1
                FROM trust_anchors ta
                WHERE ta.certificate_id = c.certificate_id
                  AND ta.active = TRUE
            )
        ELSE EXISTS (
            SELECT 1
            FROM certificate_authorities ca
            WHERE ca.ca_id = c.issuer_ca_id
              AND ca.status = 'ACTIVE'
        )
    END AS basic_eligibility
FROM certificates c
ORDER BY c.certificate_id;

-- ============================================================
-- CLEAN TRANSACTION COMPLETION
-- ============================================================

COMMIT;
