BEGIN;

CREATE SCHEMA IF NOT EXISTS crypto_lab;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

SET search_path = crypto_lab, public;

DROP VIEW IF EXISTS encryption_operation_report;
DROP VIEW IF EXISTS key_inventory;
DROP TABLE IF EXISTS encryption_operations CASCADE;
DROP TABLE IF EXISTS cryptographic_keys CASCADE;

CREATE TABLE cryptographic_keys (
    key_id              BIGSERIAL PRIMARY KEY,
    key_name            TEXT NOT NULL UNIQUE,
    key_type            TEXT NOT NULL,
    algorithm           TEXT NOT NULL,
    key_purpose         TEXT NOT NULL,
    key_status          TEXT NOT NULL DEFAULT 'ACTIVE',
    key_version         INTEGER NOT NULL DEFAULT 1,
    key_fingerprint     TEXT NOT NULL UNIQUE,
    public_material     TEXT,
    encrypted_secret    BYTEA,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at          TIMESTAMPTZ,

    CONSTRAINT key_type_check
        CHECK (key_type IN ('SYMMETRIC', 'ASYMMETRIC_PUBLIC', 'ASYMMETRIC_PRIVATE')),

    CONSTRAINT algorithm_check
        CHECK (
            algorithm IN (
                'AES-256-GCM',
                'RSA-OAEP-SHA256',
                'HMAC-SHA256'
            )
        ),

    CONSTRAINT key_purpose_check
        CHECK (
            key_purpose IN (
                'ENCRYPTION',
                'DECRYPTION',
                'KEY_WRAPPING',
                'AUTHENTICATION'
            )
        ),

    CONSTRAINT key_status_check
        CHECK (
            key_status IN (
                'ACTIVE',
                'ROTATING',
                'REVOKED',
                'EXPIRED'
            )
        ),

    CONSTRAINT key_version_check
        CHECK (key_version > 0),

    CONSTRAINT expiry_check
        CHECK (expires_at IS NULL OR expires_at > created_at),

    CONSTRAINT asymmetric_public_material_check
        CHECK (
            key_type <> 'ASYMMETRIC_PUBLIC'
            OR public_material IS NOT NULL
        ),

    CONSTRAINT secret_material_check
        CHECK (
            key_type = 'ASYMMETRIC_PUBLIC'
            OR encrypted_secret IS NOT NULL
        )
);

CREATE TABLE encryption_operations (
    operation_id        BIGSERIAL PRIMARY KEY,
    operation_reference TEXT NOT NULL UNIQUE,
    key_id              BIGINT NOT NULL
        REFERENCES cryptographic_keys(key_id),
    operation_type      TEXT NOT NULL,
    plaintext_label     TEXT NOT NULL,
    ciphertext          BYTEA NOT NULL,
    authentication_tag  BYTEA,
    operation_status    TEXT NOT NULL DEFAULT 'COMPLETED',
    requested_by        TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT operation_type_check
        CHECK (
            operation_type IN (
                'SYMMETRIC_ENCRYPT',
                'SYMMETRIC_DECRYPT',
                'ASYMMETRIC_ENCRYPT',
                'KEY_WRAP',
                'HMAC'
            )
        ),

    CONSTRAINT operation_status_check
        CHECK (
            operation_status IN (
                'REQUESTED',
                'COMPLETED',
                'FAILED',
                'REJECTED'
            )
        ),

    CONSTRAINT plaintext_label_check
        CHECK (length(trim(plaintext_label)) > 0),

    CONSTRAINT ciphertext_check
        CHECK (length(ciphertext) > 0)
);

CREATE INDEX idx_keys_status_algorithm
    ON cryptographic_keys (key_status, algorithm);

CREATE INDEX idx_operations_key_created
    ON encryption_operations (key_id, created_at DESC);

CREATE INDEX idx_operations_status
    ON encryption_operations (operation_status);

CREATE OR REPLACE FUNCTION validate_encryption_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    key_state TEXT;
    key_algorithm TEXT;
BEGIN
    SELECT key_status, algorithm
    INTO key_state, key_algorithm
    FROM cryptographic_keys
    WHERE key_id = NEW.key_id;

    IF key_state IS NULL THEN
        RAISE EXCEPTION 'Cryptographic key % does not exist', NEW.key_id;
    END IF;

    IF key_state <> 'ACTIVE' THEN
        RAISE EXCEPTION
            'Key % cannot process operations because its status is %',
            NEW.key_id,
            key_state;
    END IF;

    IF NEW.operation_type = 'SYMMETRIC_ENCRYPT'
       AND key_algorithm <> 'AES-256-GCM' THEN
        RAISE EXCEPTION
            'Symmetric encryption requires AES-256-GCM, received %',
            key_algorithm;
    END IF;

    IF NEW.operation_type = 'HMAC'
       AND key_algorithm <> 'HMAC-SHA256' THEN
        RAISE EXCEPTION
            'HMAC operation requires HMAC-SHA256, received %',
            key_algorithm;
    END IF;

    IF NEW.operation_type IN ('ASYMMETRIC_ENCRYPT', 'KEY_WRAP')
       AND key_algorithm <> 'RSA-OAEP-SHA256' THEN
        RAISE EXCEPTION
            'Asymmetric operation requires RSA-OAEP-SHA256, received %',
            key_algorithm;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_encryption_key
BEFORE INSERT OR UPDATE ON encryption_operations
FOR EACH ROW
EXECUTE FUNCTION validate_encryption_key();

CREATE OR REPLACE FUNCTION reject_revoked_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.key_status = 'REVOKED' AND NEW.expires_at IS NULL THEN
        RAISE EXCEPTION
            'Revoked keys must record an expiration or retirement timestamp.';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_reject_invalid_revocation
BEFORE UPDATE ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION reject_revoked_key();

CREATE OR REPLACE FUNCTION key_fingerprint_from_material(
    material TEXT
)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT encode(
        digest(material, 'sha256'),
        'hex'
    );
$$;

INSERT INTO cryptographic_keys (
    key_name,
    key_type,
    algorithm,
    key_purpose,
    key_status,
    key_version,
    key_fingerprint,
    encrypted_secret
)
VALUES (
    'payments-aes-v1',
    'SYMMETRIC',
    'AES-256-GCM',
    'ENCRYPTION',
    'ACTIVE',
    1,
    key_fingerprint_from_material('payments-aes-v1-secret'),
    pgp_sym_encrypt(
        'demo-only-32-byte-secret',
        'database-demo-key'
    )
);

INSERT INTO cryptographic_keys (
    key_name,
    key_type,
    algorithm,
    key_purpose,
    key_status,
    key_version,
    key_fingerprint,
    encrypted_secret
)
VALUES (
    'payments-hmac-v1',
    'SYMMETRIC',
    'HMAC-SHA256',
    'AUTHENTICATION',
    'ACTIVE',
    1,
    key_fingerprint_from_material('payments-hmac-v1-secret'),
    pgp_sym_encrypt(
        'demo-hmac-secret',
        'database-demo-key'
    )
);

INSERT INTO cryptographic_keys (
    key_name,
    key_type,
    algorithm,
    key_purpose,
    key_status,
    key_version,
    key_fingerprint,
    public_material,
    encrypted_secret
)
VALUES (
    'payments-rsa-public-v1',
    'ASYMMETRIC_PUBLIC',
    'RSA-OAEP-SHA256',
    'KEY_WRAPPING',
    'ACTIVE',
    1,
    key_fingerprint_from_material('payments-rsa-public-v1'),
    '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
DEMO-REPLACE-WITH-REAL-PUBLIC-KEY-MATERIAL
-----END PUBLIC KEY-----',
    decode(
        'deadbeef',
        'hex'
    )
);

INSERT INTO encryption_operations (
    operation_reference,
    key_id,
    operation_type,
    plaintext_label,
    ciphertext,
    authentication_tag,
    operation_status,
    requested_by
)
SELECT
    'OP-1001',
    key_id,
    'SYMMETRIC_ENCRYPT',
    'customer-payment-instruction',
    pgp_sym_encrypt(
        'Transaction TX-2048: amount=12500; currency=INR',
        'database-demo-key'
    ),
    digest(
        'Transaction TX-2048: amount=12500; currency=INR',
        'sha256'
    ),
    'COMPLETED',
    'payments-service'
FROM cryptographic_keys
WHERE key_name = 'payments-aes-v1';

INSERT INTO encryption_operations (
    operation_reference,
    key_id,
    operation_type,
    plaintext_label,
    ciphertext,
    authentication_tag,
    operation_status,
    requested_by
)
SELECT
    'OP-1002',
    key_id,
    'HMAC',
    'customer-payment-instruction',
    digest(
        'Transaction TX-2048: amount=12500; currency=INR',
        'sha256'
    ),
    digest(
        'Transaction TX-2048: amount=12500; currency=INR',
        'sha256'
    ),
    'COMPLETED',
    'integrity-service'
FROM cryptographic_keys
WHERE key_name = 'payments-hmac-v1';

INSERT INTO encryption_operations (
    operation_reference,
    key_id,
    operation_type,
    plaintext_label,
    ciphertext,
    operation_status,
    requested_by
)
SELECT
    'OP-1003',
    key_id,
    'KEY_WRAP',
    'payments-aes-v1-key',
    decode(
        'aabbccdd',
        'hex'
    ),
    'COMPLETED',
    'key-service'
FROM cryptographic_keys
WHERE key_name = 'payments-rsa-public-v1';

CREATE OR REPLACE VIEW key_inventory AS
SELECT
    key_id,
    key_name,
    key_type,
    algorithm,
    key_purpose,
    key_status,
    key_version,
    key_fingerprint,
    created_at,
    expires_at,
    CASE
        WHEN key_status = 'ACTIVE' AND
             (expires_at IS NULL OR expires_at > clock_timestamp())
            THEN 'USABLE'
        WHEN key_status = 'REVOKED'
            THEN 'BLOCKED'
        WHEN expires_at IS NOT NULL AND expires_at <= clock_timestamp()
            THEN 'EXPIRED'
        ELSE 'UNAVAILABLE'
    END AS operational_state
FROM cryptographic_keys;

CREATE OR REPLACE VIEW encryption_operation_report AS
SELECT
    o.operation_reference,
    o.operation_type,
    o.plaintext_label,
    o.operation_status,
    o.requested_by,
    k.key_name,
    k.algorithm,
    k.key_status,
    length(o.ciphertext) AS ciphertext_bytes,
    CASE
        WHEN o.authentication_tag IS NULL THEN false
        ELSE true
    END AS has_authentication_tag,
    o.created_at
FROM encryption_operations o
JOIN cryptographic_keys k
    ON k.key_id = o.key_id;

-- Retrieval: active encryption keys.
SELECT
    key_name,
    algorithm,
    key_purpose,
    key_status,
    key_version
FROM key_inventory
WHERE operational_state = 'USABLE'
ORDER BY key_name;

-- Evaluation: operations whose keys are not currently usable.
SELECT
    operation_reference,
    operation_type,
    key_name,
    key_status,
    operation_status
FROM encryption_operation_report
WHERE key_status <> 'ACTIVE'
   OR operation_status <> 'COMPLETED'
ORDER BY created_at DESC;

-- Aggregation: cryptographic activity by algorithm.
SELECT
    algorithm,
    COUNT(*) AS operation_count,
    SUM(ciphertext_bytes) AS total_ciphertext_bytes
FROM encryption_operation_report
GROUP BY algorithm
ORDER BY operation_count DESC, algorithm;

-- Integrity evaluation: compare a deterministic digest with a known message.
SELECT
    encode(
        digest(
            'Transaction TX-2048: amount=12500; currency=INR',
            'sha256'
        ),
        'hex'
    ) AS sha256_digest;

-- Demonstration of symmetric encryption and decryption inside PostgreSQL.
WITH encrypted AS (
    SELECT pgp_sym_encrypt(
        'Database-level encrypted value',
        'database-demo-key'
    ) AS ciphertext
)
SELECT
    encode(ciphertext, 'base64') AS ciphertext_base64,
    pgp_sym_decrypt(
        ciphertext,
        'database-demo-key'
    ) AS recovered_plaintext
FROM encrypted;

-- Demonstration of an atomic workflow.
DO $$
DECLARE
    selected_key BIGINT;
    new_operation BIGINT;
BEGIN
    SELECT key_id
    INTO selected_key
    FROM cryptographic_keys
    WHERE key_name = 'payments-aes-v1'
      AND key_status = 'ACTIVE'
    FOR UPDATE;

    IF selected_key IS NULL THEN
        RAISE EXCEPTION 'No active AES encryption key is available.';
    END IF;

    INSERT INTO encryption_operations (
        operation_reference,
        key_id,
        operation_type,
        plaintext_label,
        ciphertext,
        authentication_tag,
        operation_status,
        requested_by
    )
    VALUES (
        'OP-TRANSACTIONAL-01',
        selected_key,
        'SYMMETRIC_ENCRYPT',
        'transactional-record',
        pgp_sym_encrypt(
            'Atomic database workflow record',
            'database-demo-key'
        ),
        digest(
            'Atomic database workflow record',
            'sha256'
        ),
        'COMPLETED',
        'transactional-service'
    )
    RETURNING operation_id INTO new_operation;

    RAISE NOTICE
        'Transactional encryption operation created: %',
        new_operation;
END;
$$;

-- Validation: duplicate key fingerprints are prevented by a UNIQUE constraint.
-- Validation: revoked or expired keys are excluded from normal operation selection.
-- Validation: operation algorithms must agree with the selected key algorithm.

COMMIT;
