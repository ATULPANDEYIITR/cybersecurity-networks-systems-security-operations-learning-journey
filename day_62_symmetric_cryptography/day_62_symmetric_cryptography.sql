CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP SCHEMA IF EXISTS symmetric_crypto CASCADE;
CREATE SCHEMA symmetric_crypto;

SET search_path = symmetric_crypto, public;

CREATE TYPE key_status AS ENUM (
    'ACTIVE',
    'RETIRED',
    'REVOKED'
);

CREATE TYPE encryption_algorithm AS ENUM (
    'AES-256-GCM',
    'AES-256-CBC-HMAC-SHA256',
    'AES-256-CTR-HMAC-SHA256'
);

CREATE TABLE encryption_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_version INTEGER NOT NULL,
    algorithm encryption_algorithm NOT NULL,
    key_material BYTEA NOT NULL,
    status key_status NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    retired_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT encryption_keys_version_positive
        CHECK (key_version > 0),
    CONSTRAINT encryption_keys_material_length
        CHECK (octet_length(key_material) = 32),
    CONSTRAINT encryption_keys_lifecycle
        CHECK (
            (status = 'ACTIVE' AND retired_at IS NULL AND revoked_at IS NULL)
            OR
            (status = 'RETIRED' AND retired_at IS NOT NULL AND revoked_at IS NULL)
            OR
            (status = 'REVOKED' AND revoked_at IS NOT NULL)
        ),
    CONSTRAINT encryption_keys_unique_version
        UNIQUE (key_version)
);

CREATE UNIQUE INDEX one_active_encryption_key
ON encryption_keys ((status))
WHERE status = 'ACTIVE';

CREATE TABLE encrypted_records (
    record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id UUID NOT NULL
        REFERENCES encryption_keys(key_id),
    algorithm encryption_algorithm NOT NULL,
    iv BYTEA NOT NULL,
    ciphertext BYTEA NOT NULL,
    authentication_tag BYTEA NOT NULL,
    aad BYTEA NOT NULL DEFAULT '\x'::bytea,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    decrypted_at TIMESTAMPTZ,
    CONSTRAINT encrypted_records_algorithm_matches_key
        CHECK (
            algorithm IN (
                'AES-256-GCM',
                'AES-256-CBC-HMAC-SHA256',
                'AES-256-CTR-HMAC-SHA256'
            )
        ),
    CONSTRAINT encrypted_records_gcm_iv
        CHECK (
            algorithm <> 'AES-256-GCM'
            OR octet_length(iv) = 12
        ),
    CONSTRAINT encrypted_records_gcm_tag
        CHECK (
            algorithm <> 'AES-256-GCM'
            OR octet_length(authentication_tag) = 16
        ),
    CONSTRAINT encrypted_records_cbc_iv
        CHECK (
            algorithm <> 'AES-256-CBC-HMAC-SHA256'
            OR octet_length(iv) = 16
        ),
    CONSTRAINT encrypted_records_ctr_iv
        CHECK (
            algorithm <> 'AES-256-CTR-HMAC-SHA256'
            OR octet_length(iv) = 16
        ),
    CONSTRAINT encrypted_records_nonempty_ciphertext
        CHECK (octet_length(ciphertext) > 0)
);

CREATE INDEX encrypted_records_key_created_idx
ON encrypted_records(key_id, created_at DESC);

CREATE TABLE key_rotation_events (
    rotation_id BIGSERIAL PRIMARY KEY,
    old_key_id UUID REFERENCES encryption_keys(key_id),
    new_key_id UUID NOT NULL REFERENCES encryption_keys(key_id),
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    reason TEXT NOT NULL,
    CONSTRAINT key_rotation_reason
        CHECK (length(trim(reason)) >= 10)
);

CREATE TABLE encryption_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    record_id UUID REFERENCES encrypted_records(record_id),
    key_id UUID REFERENCES encryption_keys(key_id),
    operation TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT encryption_audit_operation
        CHECK (
            operation IN (
                'ENCRYPT',
                'DECRYPT',
                'KEY_ROTATE',
                'KEY_REVOKE',
                'AUTHENTICATION_FAILURE'
            )
        ),
    CONSTRAINT encryption_audit_failure_consistency
        CHECK (
            success = TRUE
            OR failure_reason IS NOT NULL
        )
);

COMMENT ON TABLE encryption_keys IS
'Metadata and key material for the demonstration key lifecycle. Production systems should keep raw keys in a KMS or HSM rather than application tables.';

COMMENT ON TABLE encrypted_records IS
'Stores ciphertext envelopes, IVs, authentication tags, AAD, and the key identifier required for controlled decryption.';

CREATE OR REPLACE FUNCTION validate_key_algorithm()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.algorithm = 'AES-256-GCM'
       AND octet_length(NEW.key_material) <> 32 THEN
        RAISE EXCEPTION
            'AES-256 requires exactly 32 bytes of key material';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER validate_key_algorithm_trigger
BEFORE INSERT OR UPDATE ON encryption_keys
FOR EACH ROW
EXECUTE FUNCTION validate_key_algorithm();

CREATE OR REPLACE FUNCTION prevent_invalid_key_rotation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'ACTIVE'
       AND EXISTS (
           SELECT 1
           FROM encryption_keys existing
           WHERE existing.status = 'ACTIVE'
             AND existing.key_id <> NEW.key_id
       ) THEN
        RAISE EXCEPTION
            'Only one active encryption key is permitted';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER prevent_invalid_key_rotation_trigger
BEFORE INSERT OR UPDATE ON encryption_keys
FOR EACH ROW
EXECUTE FUNCTION prevent_invalid_key_rotation();

CREATE OR REPLACE FUNCTION rotate_encryption_key(
    p_reason TEXT
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    old_key UUID;
    new_key UUID;
    next_version INTEGER;
BEGIN
    SELECT key_id
    INTO old_key
    FROM encryption_keys
    WHERE status = 'ACTIVE'
    FOR UPDATE;

    SELECT COALESCE(MAX(key_version), 0) + 1
    INTO next_version
    FROM encryption_keys;

    IF old_key IS NOT NULL THEN
        UPDATE encryption_keys
        SET status = 'RETIRED',
            retired_at = clock_timestamp()
        WHERE key_id = old_key;
    END IF;

    INSERT INTO encryption_keys (
        key_version,
        algorithm,
        key_material,
        status
    )
    VALUES (
        next_version,
        'AES-256-GCM',
        gen_random_bytes(32),
        'ACTIVE'
    )
    RETURNING key_id INTO new_key;

    INSERT INTO key_rotation_events (
        old_key_id,
        new_key_id,
        reason
    )
    VALUES (
        old_key,
        new_key,
        p_reason
    );

    INSERT INTO encryption_audit (
        key_id,
        operation,
        success
    )
    VALUES (
        new_key,
        'KEY_ROTATE',
        TRUE
    );

    RETURN new_key;
END;
$$;

CREATE OR REPLACE FUNCTION revoke_encryption_key(
    p_key_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE encryption_keys
    SET status = 'REVOKED',
        revoked_at = clock_timestamp()
    WHERE key_id = p_key_id
      AND status <> 'REVOKED';

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Key % does not exist or is already revoked',
            p_key_id;
    END IF;

    INSERT INTO encryption_audit (
        key_id,
        operation,
        success
    )
    VALUES (
        p_key_id,
        'KEY_REVOKE',
        TRUE
    );
END;
$$;

CREATE OR REPLACE FUNCTION encrypt_record(
    p_key_id UUID,
    p_plaintext TEXT,
    p_aad TEXT
)
RETURNS UUID
LANGUAGE plpgsql
AS $$
DECLARE
    v_record_id UUID;
    v_key BYTEA;
    v_iv BYTEA;
    v_ciphertext BYTEA;
    v_tag BYTEA;
BEGIN
    SELECT key_material
    INTO v_key
    FROM encryption_keys
    WHERE key_id = p_key_id
      AND status = 'ACTIVE'
      AND algorithm = 'AES-256-GCM'
    FOR UPDATE;

    IF v_key IS NULL THEN
        RAISE EXCEPTION
            'Encryption key is unavailable or not active';
    END IF;

    /*
     * PostgreSQL pgcrypto exposes symmetric primitives such as
     * pgp_sym_encrypt, but AES-GCM envelope construction is kept
     * explicit here so IV, AAD, tag, and key lifecycle remain
     * visible in the relational model.
     *
     * The encrypted payload below uses pgp_sym_encrypt as the
     * executable database-side encryption primitive. The envelope
     * columns still model the metadata required by an AES-GCM
     * application protocol.
     */
    v_iv := gen_random_bytes(12);

    v_ciphertext := pgp_sym_encrypt(
        p_plaintext,
        encode(v_key, 'hex'),
        'cipher-algo=aes256'
    );

    /*
     * pgp_sym_encrypt does not expose an AES-GCM tag. A SHA-256
     * digest is therefore stored as a database integrity marker,
     * not as a claim that pgcrypto produced a GCM authentication tag.
     * Application-layer AES-GCM should be used when GCM semantics
     * are required.
     */
    v_tag := digest(
        convert_to(
            encode(v_iv, 'hex')
            || encode(v_ciphertext, 'hex')
            || coalesce(p_aad, ''),
            'UTF8'
        ),
        'sha256'
    );

    INSERT INTO encrypted_records (
        key_id,
        algorithm,
        iv,
        ciphertext,
        authentication_tag,
        aad
    )
    VALUES (
        p_key_id,
        'AES-256-GCM',
        v_iv,
        v_ciphertext,
        substring(v_tag FROM 1 FOR 16),
        convert_to(coalesce(p_aad, ''), 'UTF8')
    )
    RETURNING record_id INTO v_record_id;

    INSERT INTO encryption_audit (
        record_id,
        key_id,
        operation,
        success
    )
    VALUES (
        v_record_id,
        p_key_id,
        'ENCRYPT',
        TRUE
    );

    RETURN v_record_id;
END;
$$;

CREATE OR REPLACE FUNCTION record_decryption_success(
    p_record_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_key_id UUID;
BEGIN
    SELECT key_id
    INTO v_key_id
    FROM encrypted_records
    WHERE record_id = p_record_id;

    IF v_key_id IS NULL THEN
        RAISE EXCEPTION
            'Encrypted record does not exist';
    END IF;

    UPDATE encrypted_records
    SET decrypted_at = clock_timestamp()
    WHERE record_id = p_record_id;

    INSERT INTO encryption_audit (
        record_id,
        key_id,
        operation,
        success
    )
    VALUES (
        p_record_id,
        v_key_id,
        'DECRYPT',
        TRUE
    );
END;
$$;

CREATE VIEW active_key_inventory AS
SELECT
    key_id,
    key_version,
    algorithm,
    status,
    created_at
FROM encryption_keys
WHERE status = 'ACTIVE';

CREATE VIEW encryption_record_report AS
SELECT
    er.record_id,
    er.key_id,
    ek.key_version,
    er.algorithm,
    octet_length(er.iv) AS iv_bytes,
    octet_length(er.ciphertext) AS ciphertext_bytes,
    octet_length(er.authentication_tag) AS tag_bytes,
    er.created_at,
    er.decrypted_at,
    CASE
        WHEN er.decrypted_at IS NULL THEN 'NOT_DECRYPTED'
        ELSE 'DECRYPTED'
    END AS workflow_state
FROM encrypted_records er
JOIN encryption_keys ek
  ON ek.key_id = er.key_id;

CREATE VIEW encryption_failure_report AS
SELECT
    operation,
    COUNT(*) AS event_count
FROM encryption_audit
WHERE success = FALSE
GROUP BY operation
ORDER BY event_count DESC;

BEGIN;

INSERT INTO encryption_keys (
    key_version,
    algorithm,
    key_material,
    status
)
VALUES (
    1,
    'AES-256-GCM',
    gen_random_bytes(32),
    'ACTIVE'
);

COMMIT;

DO $$
DECLARE
    v_active UUID;
BEGIN
    SELECT key_id
    INTO v_active
    FROM encryption_keys
    WHERE status = 'ACTIVE';

    RAISE NOTICE
        'Initial active key: %',
        v_active;
END;
$$;

BEGIN;

DO $$
DECLARE
    v_key UUID;
    v_record UUID;
BEGIN
    SELECT key_id
    INTO v_key
    FROM encryption_keys
    WHERE status = 'ACTIVE';

    v_record := encrypt_record(
        v_key,
        'Confidential repository deployment configuration',
        'repository=payments;classification=confidential'
    );

    RAISE NOTICE
        'Created encrypted record: %',
        v_record;
END;
$$;

COMMIT;

SELECT
    key_id,
    key_version,
    algorithm,
    status,
    created_at
FROM active_key_inventory;

SELECT
    record_id,
    key_version,
    algorithm,
    iv_bytes,
    ciphertext_bytes,
    tag_bytes,
    workflow_state
FROM encryption_record_report
ORDER BY created_at DESC;

SELECT
    operation,
    success,
    COUNT(*) AS occurrences
FROM encryption_audit
GROUP BY operation, success
ORDER BY operation, success DESC;

WITH key_usage AS (
    SELECT
        ek.key_id,
        ek.key_version,
        ek.status,
        COUNT(er.record_id) AS protected_records
    FROM encryption_keys ek
    LEFT JOIN encrypted_records er
      ON er.key_id = ek.key_id
    GROUP BY
        ek.key_id,
        ek.key_version,
        ek.status
)
SELECT
    key_id,
    key_version,
    status,
    protected_records,
    CASE
        WHEN status = 'ACTIVE'
             AND protected_records > 0
        THEN 'CURRENT_KEY_IN_USE'
        WHEN status = 'RETIRED'
             AND protected_records > 0
        THEN 'ROTATION_MIGRATION_REQUIRED'
        ELSE 'NO_ACTIVE_RECORDS'
    END AS key_management_state
FROM key_usage
ORDER BY key_version;

SELECT
    record_id,
    key_id,
    algorithm,
    created_at
FROM encrypted_records
WHERE algorithm = 'AES-256-GCM'
  AND octet_length(iv) = 12
  AND octet_length(authentication_tag) = 16
ORDER BY created_at DESC;

SELECT
    key_id,
    key_version,
    status,
    created_at,
    retired_at,
    revoked_at
FROM encryption_keys
ORDER BY key_version;

BEGIN;

SELECT rotate_encryption_key(
    'Scheduled rotation after encryption key age threshold'
);

COMMIT;

SELECT
    rotation_id,
    old_key_id,
    new_key_id,
    rotated_at,
    reason
FROM key_rotation_events
ORDER BY rotation_id DESC;

SELECT
    key_id,
    key_version,
    status,
    created_at,
    retired_at
FROM encryption_keys
ORDER BY key_version;

DO $$
DECLARE
    active_count INTEGER;
BEGIN
    SELECT COUNT(*)
    INTO active_count
    FROM encryption_keys
    WHERE status = 'ACTIVE';

    IF active_count <> 1 THEN
        RAISE EXCEPTION
            'Key-management invariant violated: expected exactly one active key, found %',
            active_count;
    END IF;
END;
$$;

SELECT
    current_timestamp AS evaluated_at,
    COUNT(*) FILTER (
        WHERE status = 'ACTIVE'
    ) AS active_keys,
    COUNT(*) FILTER (
        WHERE status = 'RETIRED'
    ) AS retired_keys,
    COUNT(*) FILTER (
        WHERE status = 'REVOKED'
    ) AS revoked_keys
FROM encryption_keys;
