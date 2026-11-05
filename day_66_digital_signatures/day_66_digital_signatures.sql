-- ==============================================================
-- DIGITAL SIGNATURE MANAGEMENT AND CERTIFICATE TRUST
-- PostgreSQL 15+
--
-- Models:
--   Certificate authorities and trust anchors
--   Subject certificates and revocation
--   Digital signatures and document integrity
--   Verification decisions and audit history
--
-- Cryptographic signing and signature verification must be
-- performed by a trusted application or cryptographic service.
-- PostgreSQL stores evidence and evaluates workflow eligibility.
-- ==============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS digital_trust;

SET search_path TO digital_trust, public;

-- --------------------------------------------------------------
-- Enumerated workflow states
-- --------------------------------------------------------------

CREATE TYPE certificate_status AS ENUM (
    'ACTIVE',
    'REVOKED',
    'EXPIRED',
    'SUSPENDED'
);

CREATE TYPE signature_status AS ENUM (
    'PENDING',
    'SIGNED',
    'VERIFIED',
    'INVALID',
    'REJECTED'
);

CREATE TYPE verification_result AS ENUM (
    'VALID',
    'INVALID',
    'EXPIRED',
    'NOT_YET_VALID',
    'REVOKED',
    'UNTRUSTED',
    'MISSING_CERTIFICATE'
);

-- --------------------------------------------------------------
-- Users who participate in document signing.
-- --------------------------------------------------------------

CREATE TABLE signers (
    signer_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_signer_email
        CHECK (POSITION('@' IN email) > 1),

    CONSTRAINT valid_display_name
        CHECK (LENGTH(TRIM(display_name)) > 0)
);

-- --------------------------------------------------------------
-- Certificate authorities.
--
-- Root authorities are explicitly configured as trust anchors.
-- Intermediate authorities can reference their parent.
-- --------------------------------------------------------------

CREATE TABLE certificate_authorities (
    authority_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    authority_name VARCHAR(200) NOT NULL UNIQUE,
    public_key_pem TEXT NOT NULL,
    public_key_fingerprint CHAR(64) NOT NULL UNIQUE,
    parent_authority_id BIGINT REFERENCES
        certificate_authorities(authority_id),
    is_trust_anchor BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_authority_fingerprint
        CHECK (public_key_fingerprint ~ '^[a-f0-9]{64}$'),

    CONSTRAINT nonempty_authority_key
        CHECK (LENGTH(TRIM(public_key_pem)) > 0),

    CONSTRAINT no_self_issued_parent
        CHECK (
            parent_authority_id IS NULL
            OR parent_authority_id <> authority_id
        )
);

-- --------------------------------------------------------------
-- Issued public-key certificates.
-- --------------------------------------------------------------

CREATE TABLE certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    serial_number VARCHAR(128) NOT NULL UNIQUE,

    signer_id BIGINT NOT NULL REFERENCES signers(signer_id),

    authority_id BIGINT NOT NULL REFERENCES
        certificate_authorities(authority_id),

    subject_public_key_pem TEXT NOT NULL,

    public_key_fingerprint CHAR(64) NOT NULL,

    signature_algorithm VARCHAR(50) NOT NULL,

    certificate_signature BYTEA NOT NULL,

    not_before TIMESTAMPTZ NOT NULL,

    not_after TIMESTAMPTZ NOT NULL,

    status certificate_status NOT NULL DEFAULT 'ACTIVE',

    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    revoked_at TIMESTAMPTZ,

    revocation_reason TEXT,

    CONSTRAINT valid_certificate_period
        CHECK (not_after > not_before),

    CONSTRAINT valid_public_key_fingerprint
        CHECK (public_key_fingerprint ~ '^[a-f0-9]{64}$'),

    CONSTRAINT supported_signature_algorithm
        CHECK (
            signature_algorithm IN (
                'Ed25519',
                'RSA-SHA256',
                'ECDSA-SHA256'
            )
        ),

    CONSTRAINT valid_revocation_state
        CHECK (
            (status = 'REVOKED' AND revoked_at IS NOT NULL)
            OR
            (status <> 'REVOKED' AND revoked_at IS NULL)
        ),

    CONSTRAINT certificate_key_present
        CHECK (LENGTH(TRIM(subject_public_key_pem)) > 0)
);

CREATE INDEX idx_certificates_signer
    ON certificates(signer_id, status);

CREATE INDEX idx_certificates_authority
    ON certificates(authority_id, status);

CREATE INDEX idx_certificates_expiration
    ON certificates(not_after)
    WHERE status = 'ACTIVE';

-- --------------------------------------------------------------
-- Documents submitted for electronic signing.
-- --------------------------------------------------------------

CREATE TABLE documents (
    document_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    external_reference VARCHAR(100) NOT NULL UNIQUE,

    document_name VARCHAR(255) NOT NULL,

    content_hash CHAR(64) NOT NULL,

    hash_algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256',

    content_location TEXT,

    owner_id BIGINT NOT NULL REFERENCES signers(signer_id),

    status signature_status NOT NULL DEFAULT 'PENDING',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_document_hash
        CHECK (content_hash ~ '^[a-f0-9]{64}$'),

    CONSTRAINT supported_hash_algorithm
        CHECK (hash_algorithm = 'SHA-256'),

    CONSTRAINT valid_document_name
        CHECK (LENGTH(TRIM(document_name)) > 0)
);

CREATE INDEX idx_documents_owner
    ON documents(owner_id, created_at DESC);

CREATE INDEX idx_documents_status
    ON documents(status, created_at DESC);

-- --------------------------------------------------------------
-- Signature records.
--
-- A signature is tied to a particular immutable document digest,
-- certificate, signer, and cryptographic algorithm.
-- --------------------------------------------------------------

CREATE TABLE digital_signatures (
    signature_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    document_id BIGINT NOT NULL REFERENCES documents(document_id),

    signer_id BIGINT NOT NULL REFERENCES signers(signer_id),

    certificate_id BIGINT NOT NULL REFERENCES
        certificates(certificate_id),

    signature_value BYTEA NOT NULL,

    signed_content_hash CHAR(64) NOT NULL,

    signature_algorithm VARCHAR(50) NOT NULL,

    signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    status signature_status NOT NULL DEFAULT 'SIGNED',

    CONSTRAINT valid_signed_hash
        CHECK (signed_content_hash ~ '^[a-f0-9]{64}$'),

    CONSTRAINT valid_signature_algorithm
        CHECK (
            signature_algorithm IN (
                'Ed25519',
                'RSA-SHA256',
                'ECDSA-SHA256'
            )
        ),

    CONSTRAINT nonempty_signature
        CHECK (OCTET_LENGTH(signature_value) > 0),

    CONSTRAINT unique_document_signer
        UNIQUE(document_id, signer_id, signed_content_hash)
);

CREATE INDEX idx_signatures_document
    ON digital_signatures(document_id, signed_at DESC);

CREATE INDEX idx_signatures_certificate
    ON digital_signatures(certificate_id);

-- --------------------------------------------------------------
-- Certificate verification history.
-- --------------------------------------------------------------

CREATE TABLE verification_audit (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    signature_id BIGINT REFERENCES
        digital_signatures(signature_id),

    certificate_id BIGINT REFERENCES
        certificates(certificate_id),

    verification_result verification_result NOT NULL,

    verifier_service VARCHAR(150) NOT NULL,

    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    document_hash_verified CHAR(64),

    certificate_chain_valid BOOLEAN NOT NULL DEFAULT FALSE,

    cryptographic_signature_valid BOOLEAN NOT NULL DEFAULT FALSE,

    details TEXT,

    CONSTRAINT valid_verified_hash
        CHECK (
            document_hash_verified IS NULL
            OR document_hash_verified ~ '^[a-f0-9]{64}$'
        )
);

CREATE INDEX idx_verification_signature
    ON verification_audit(signature_id, verified_at DESC);

CREATE INDEX idx_verification_result
    ON verification_audit(verification_result, verified_at DESC);

-- --------------------------------------------------------------
-- Trust evaluation function.
--
-- Checks stored certificate metadata and issuing authority trust.
-- This function does NOT perform cryptographic verification.
-- The external verification service must verify the actual
-- certificate signature and public-key signature.
-- --------------------------------------------------------------

CREATE OR REPLACE FUNCTION evaluate_certificate(
    p_certificate_id BIGINT,
    p_at TIMESTAMPTZ DEFAULT NOW()
)
RETURNS verification_result
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_certificate certificates%ROWTYPE;
    v_authority certificate_authorities%ROWTYPE;
BEGIN
    SELECT *
    INTO v_certificate
    FROM certificates
    WHERE certificate_id = p_certificate_id;

    IF NOT FOUND THEN
        RETURN 'MISSING_CERTIFICATE';
    END IF;

    IF v_certificate.status = 'REVOKED' THEN
        RETURN 'REVOKED';
    END IF;

    IF v_certificate.status = 'SUSPENDED' THEN
        RETURN 'UNTRUSTED';
    END IF;

    IF p_at < v_certificate.not_before THEN
        RETURN 'NOT_YET_VALID';
    END IF;

    IF p_at > v_certificate.not_after
       OR v_certificate.status = 'EXPIRED' THEN
        RETURN 'EXPIRED';
    END IF;

    SELECT *
    INTO v_authority
    FROM certificate_authorities
    WHERE authority_id = v_certificate.authority_id;

    IF NOT FOUND
       OR NOT v_authority.is_active
       OR NOT v_authority.is_trust_anchor THEN
        RETURN 'UNTRUSTED';
    END IF;

    RETURN 'VALID';
END;
$$;

-- --------------------------------------------------------------
-- Trigger: prevent modification of signed document content hashes.
-- A changed document must be registered as a new document version.
-- --------------------------------------------------------------

CREATE OR REPLACE FUNCTION protect_signed_document()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.content_hash <> OLD.content_hash
       AND EXISTS (
           SELECT 1
           FROM digital_signatures
           WHERE document_id = OLD.document_id
       ) THEN

        RAISE EXCEPTION
            'Cannot change the content hash of a signed document';
    END IF;

    NEW.updated_at = NOW();

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_protect_signed_document
BEFORE UPDATE ON documents
FOR EACH ROW
EXECUTE FUNCTION protect_signed_document();

-- --------------------------------------------------------------
-- Trigger: verify signer and certificate ownership.
-- --------------------------------------------------------------

CREATE OR REPLACE FUNCTION validate_signature_identity()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_certificate_signer BIGINT;
BEGIN
    SELECT signer_id
    INTO v_certificate_signer
    FROM certificates
    WHERE certificate_id = NEW.certificate_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Certificate does not exist';
    END IF;

    IF v_certificate_signer <> NEW.signer_id THEN
        RAISE EXCEPTION
            'Signature signer does not match certificate owner';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM documents
        WHERE document_id = NEW.document_id
          AND content_hash = NEW.signed_content_hash
    ) THEN
        RAISE EXCEPTION
            'Signed hash does not match registered document hash';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_signature_identity
BEFORE INSERT ON digital_signatures
FOR EACH ROW
EXECUTE FUNCTION validate_signature_identity();

-- --------------------------------------------------------------
-- Transactional signature verification recording.
--
-- Cryptographic validity is supplied by a trusted verifier.
-- A caller must not be granted unrestricted access to this
-- function merely because it accepts a boolean result.
-- --------------------------------------------------------------

CREATE OR REPLACE FUNCTION record_verification(
    p_signature_id BIGINT,
    p_result verification_result,
    p_service VARCHAR(150),
    p_hash CHAR(64),
    p_chain_valid BOOLEAN,
    p_crypto_valid BOOLEAN,
    p_details TEXT DEFAULT NULL
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_signature digital_signatures%ROWTYPE;
    v_id BIGINT;
BEGIN
    SELECT *
    INTO v_signature
    FROM digital_signatures
    WHERE signature_id = p_signature_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Signature record not found';
    END IF;

    IF p_service IS NULL OR LENGTH(TRIM(p_service)) = 0 THEN
        RAISE EXCEPTION 'Verifier identity is required';
    END IF;

    IF p_result = 'VALID'
       AND (
           NOT p_chain_valid
           OR NOT p_crypto_valid
           OR p_hash IS DISTINCT FROM v_signature.signed_content_hash
       ) THEN
        RAISE EXCEPTION
            'VALID result requires matching hash and successful checks';
    END IF;

    INSERT INTO verification_audit (
        signature_id,
        certificate_id,
        verification_result,
        verifier_service,
        document_hash_verified,
        certificate_chain_valid,
        cryptographic_signature_valid,
        details
    )
    VALUES (
        p_signature_id,
        v_signature.certificate_id,
        p_result,
        p_service,
        p_hash,
        p_chain_valid,
        p_crypto_valid,
        p_details
    )
    RETURNING verification_id INTO v_id;

    UPDATE digital_signatures
    SET status = CASE
        WHEN p_result = 'VALID' THEN 'VERIFIED'::signature_status
        WHEN p_result = 'INVALID' THEN 'INVALID'::signature_status
        ELSE 'SIGNED'::signature_status
    END
    WHERE signature_id = p_signature_id;

    RETURN v_id;
END;
$$;

-- --------------------------------------------------------------
-- View: certificate and signature operational status.
-- --------------------------------------------------------------

CREATE OR REPLACE VIEW signature_status_report AS
SELECT
    ds.signature_id,
    d.external_reference,
    d.document_name,
    s.email AS signer_email,
    c.serial_number,
    c.signature_algorithm,
    ds.status AS signature_status,
    evaluate_certificate(c.certificate_id) AS certificate_status,
    ds.signed_at
FROM digital_signatures ds
JOIN documents d
    ON d.document_id = ds.document_id
JOIN signers s
    ON s.signer_id = ds.signer_id
JOIN certificates c
    ON c.certificate_id = ds.certificate_id;

-- --------------------------------------------------------------
-- Sample data
-- --------------------------------------------------------------

INSERT INTO signers(email, display_name)
VALUES
    ('alice@example.com', 'Alice Sharma'),
    ('bob@example.com', 'Bob Verma'),
    ('carol@example.com', 'Carol Singh');

INSERT INTO certificate_authorities(
    authority_name,
    public_key_pem,
    public_key_fingerprint,
    is_trust_anchor
)
VALUES
(
    'Enterprise Root CA',
    '-----BEGIN PUBLIC KEY----- ENTERPRISE_ROOT_KEY -----END PUBLIC KEY-----',
    repeat('a', 64),
    TRUE
),
(
    'Unknown External CA',
    '-----BEGIN PUBLIC KEY----- EXTERNAL_KEY -----END PUBLIC KEY-----',
    repeat('b', 64),
    FALSE
);

INSERT INTO certificates(
    serial_number,
    signer_id,
    authority_id,
    subject_public_key_pem,
    public_key_fingerprint,
    signature_algorithm,
    certificate_signature,
    not_before,
    not_after,
    status
)
VALUES
(
    'CERT-ALICE-001',
    1,
    1,
    '-----BEGIN PUBLIC KEY----- ALICE_KEY -----END PUBLIC KEY-----',
    repeat('1', 64),
    'Ed25519',
    decode('aabbccdd', 'hex'),
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '365 days',
    'ACTIVE'
),
(
    'CERT-BOB-001',
    2,
    1,
    '-----BEGIN PUBLIC KEY----- BOB_KEY -----END PUBLIC KEY-----',
    repeat('2', 64),
    'Ed25519',
    decode('aabbccdd', 'hex'),
    NOW() - INTERVAL '365 days',
    NOW() - INTERVAL '1 day',
    'EXPIRED'
),
(
    'CERT-CAROL-001',
    3,
    2,
    '-----BEGIN PUBLIC KEY----- CAROL_KEY -----END PUBLIC KEY-----',
    repeat('3', 64),
    'Ed25519',
    decode('aabbccdd', 'hex'),
    NOW() - INTERVAL '1 day',
    NOW() + INTERVAL '365 days',
    'ACTIVE'
);

INSERT INTO documents(
    external_reference,
    document_name,
    content_hash,
    owner_id
)
VALUES
(
    'CONTRACT-1001',
    'Enterprise Service Agreement',
    repeat('c', 64),
    1
),
(
    'CONTRACT-1002',
    'Supplier Agreement',
    repeat('d', 64),
    2
),
(
    'CONTRACT-1003',
    'External Vendor Agreement',
    repeat('e', 64),
    3
);

INSERT INTO digital_signatures(
    document_id,
    signer_id,
    certificate_id,
    signature_value,
    signed_content_hash,
    signature_algorithm,
    status
)
VALUES
(
    1,
    1,
    1,
    decode('aabbccdd', 'hex'),
    repeat('c', 64),
    'Ed25519',
    'SIGNED'
),
(
    2,
    2,
    2,
    decode('11223344', 'hex'),
    repeat('d', 64),
    'Ed25519',
    'SIGNED'
),
(
    3,
    3,
    3,
    decode('55667788', 'hex'),
    repeat('e', 64),
    'Ed25519',
    'SIGNED'
);

-- --------------------------------------------------------------
-- Transaction: record valid verification for Alice.
-- In production, the verified flags and hash must originate
-- from an authenticated cryptographic verification service.
-- --------------------------------------------------------------

DO $$
BEGIN
    PERFORM record_verification(
        1,
        'VALID',
        'Enterprise Signature Verification Service',
        repeat('c', 64)::CHAR(64),
        TRUE,
        TRUE,
        'Certificate and document signature verified externally'
    );
END;
$$;

-- Record the expired certificate case.
DO $$
BEGIN
    PERFORM record_verification(
        2,
        'EXPIRED',
        'Enterprise Signature Verification Service',
        repeat('d', 64)::CHAR(64),
        FALSE,
        FALSE,
        'Certificate validity period has ended'
    );
END;
$$;

-- Record the unknown issuer case.
DO $$
BEGIN
    PERFORM record_verification(
        3,
        'UNTRUSTED',
        'Enterprise Signature Verification Service',
        repeat('e', 64)::CHAR(64),
        FALSE,
        FALSE,
        'Issuer is not configured as a trust anchor'
    );
END;
$$;

-- --------------------------------------------------------------
-- 1. Retrieval: documents and signatures.
-- --------------------------------------------------------------

SELECT
    d.external_reference,
    d.document_name,
    s.email,
    ds.status,
    ds.signed_at
FROM documents d
JOIN digital_signatures ds
    ON ds.document_id = d.document_id
JOIN signers s
    ON s.signer_id = ds.signer_id
ORDER BY ds.signed_at DESC;

-- --------------------------------------------------------------
-- 2. Certificate eligibility evaluation.
-- --------------------------------------------------------------

SELECT
    serial_number,
    evaluate_certificate(certificate_id) AS eligibility
FROM certificates
ORDER BY certificate_id;

-- --------------------------------------------------------------
-- 3. Verification aggregation.
-- --------------------------------------------------------------

SELECT
    verification_result,
    COUNT(*) AS verification_count
FROM verification_audit
GROUP BY verification_result
ORDER BY verification_result;

-- --------------------------------------------------------------
-- 4. Certificate expiration monitoring.
-- --------------------------------------------------------------

SELECT
    serial_number,
    not_after,
    not_after - NOW() AS remaining_validity
FROM certificates
WHERE status = 'ACTIVE'
  AND not_after <= NOW() + INTERVAL '30 days'
ORDER BY not_after;

-- --------------------------------------------------------------
-- 5. Full signature verification report.
-- --------------------------------------------------------------

SELECT *
FROM signature_status_report
ORDER BY signed_at DESC;

-- --------------------------------------------------------------
-- 6. CTE: determine currently eligible signatures.
--
-- Database eligibility is metadata-based. Actual cryptographic
-- verification must still be confirmed by the verification audit.
-- --------------------------------------------------------------

WITH latest_verification AS (
    SELECT DISTINCT ON (signature_id)
        signature_id,
        verification_result,
        verified_at
    FROM verification_audit
    ORDER BY signature_id, verified_at DESC
),
eligibility AS (
    SELECT
        ds.signature_id,
        d.external_reference,
        s.email,
        evaluate_certificate(c.certificate_id) AS certificate_result,
        lv.verification_result
    FROM digital_signatures ds
    JOIN documents d
        ON d.document_id = ds.document_id
    JOIN signers s
        ON s.signer_id = ds.signer_id
    JOIN certificates c
        ON c.certificate_id = ds.certificate_id
    LEFT JOIN latest_verification lv
        ON lv.signature_id = ds.signature_id
)
SELECT
    *,
    (
        certificate_result = 'VALID'
        AND verification_result = 'VALID'
    ) AS eligible
FROM eligibility
ORDER BY signature_id;

-- --------------------------------------------------------------
-- 7. Revoke a certificate transactionally.
-- --------------------------------------------------------------

BEGIN;

UPDATE certificates
SET
    status = 'REVOKED',
    revoked_at = NOW(),
    revocation_reason = 'Key compromise investigation'
WHERE serial_number = 'CERT-ALICE-001'
  AND status = 'ACTIVE';

COMMIT;

-- --------------------------------------------------------------
-- 8. Confirm revocation and subsequent eligibility.
-- --------------------------------------------------------------

SELECT
    serial_number,
    status,
    revoked_at,
    evaluate_certificate(certificate_id) AS current_trust
FROM certificates
WHERE serial_number = 'CERT-ALICE-001';

-- --------------------------------------------------------------
-- 9. Audit history.
-- --------------------------------------------------------------

SELECT
    va.verification_id,
    d.external_reference,
    va.verification_result,
    va.verifier_service,
    va.verified_at,
    va.details
FROM verification_audit va
JOIN digital_signatures ds
    ON ds.signature_id = va.signature_id
JOIN documents d
    ON d.document_id = ds.document_id
ORDER BY va.verified_at DESC;

COMMIT;
