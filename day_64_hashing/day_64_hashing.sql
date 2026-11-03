/*
 * Cryptographic hashing and integrity verification database.
 *
 * Requirements:
 *   PostgreSQL with the pgcrypto extension available.
 *
 * The schema models:
 *   - Approved SHA-2 and SHA-3 algorithms
 *   - Registered artifacts and immutable versions
 *   - Database-calculated content digests
 *   - Integrity verification events
 *   - HMAC generation without persisting secret keys
 *   - Reporting and eligibility evaluation
 *
 * The content column is included to make the exercise reproducible.
 * Large production systems commonly keep artifact bytes in object storage
 * and store trusted digest metadata in the database.
 */

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS integrity_lab;

SET search_path TO integrity_lab, public;

-- ---------------------------------------------------------------------
-- 1. Algorithm policy
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS algorithm_policy (
    algorithm_name TEXT PRIMARY KEY,
    algorithm_family TEXT NOT NULL
        CHECK (algorithm_family IN ('SHA-2', 'SHA-3')),
    output_bytes INTEGER NOT NULL
        CHECK (output_bytes IN (32, 64)),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    approved_for_integrity BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT algorithm_name_supported CHECK (
        algorithm_name IN (
            'sha256',
            'sha512',
            'sha3-256',
            'sha3-512'
        )
    )
);

INSERT INTO algorithm_policy (
    algorithm_name,
    algorithm_family,
    output_bytes,
    enabled,
    approved_for_integrity
)
VALUES
    ('sha256', 'SHA-2', 32, TRUE, TRUE),
    ('sha512', 'SHA-2', 64, TRUE, TRUE),
    ('sha3-256', 'SHA-3', 32, TRUE, TRUE),
    ('sha3-512', 'SHA-3', 64, TRUE, TRUE)
ON CONFLICT (algorithm_name) DO NOTHING;

-- ---------------------------------------------------------------------
-- 2. Artifact ownership and version history
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS artifact (
    artifact_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_name TEXT NOT NULL UNIQUE,
    artifact_type TEXT NOT NULL
        CHECK (
            artifact_type IN (
                'RELEASE_PACKAGE',
                'DOCUMENT',
                'MODEL',
                'CONFIGURATION',
                'DATA_EXPORT'
            )
        ),
    owner_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT artifact_name_not_blank
        CHECK (length(trim(artifact_name)) > 0),

    CONSTRAINT artifact_owner_not_blank
        CHECK (length(trim(owner_name)) > 0)
);

CREATE TABLE IF NOT EXISTS artifact_version (
    version_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id BIGINT NOT NULL
        REFERENCES artifact(artifact_id)
        ON DELETE RESTRICT,
    version_number INTEGER NOT NULL
        CHECK (version_number > 0),
    content BYTEA NOT NULL,
    algorithm_name TEXT NOT NULL
        REFERENCES algorithm_policy(algorithm_name),
    content_digest BYTEA NOT NULL,
    byte_count BIGINT NOT NULL
        CHECK (byte_count >= 0),
    recorded_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT artifact_version_unique
        UNIQUE (artifact_id, version_number),

    CONSTRAINT artifact_version_digest_not_empty
        CHECK (octet_length(content_digest) > 0)
);

CREATE INDEX IF NOT EXISTS idx_artifact_version_artifact
    ON artifact_version (artifact_id, version_number DESC);

CREATE INDEX IF NOT EXISTS idx_artifact_version_algorithm
    ON artifact_version (algorithm_name, created_at DESC);

-- ---------------------------------------------------------------------
-- 3. Safe digest calculation
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION calculate_digest(
    p_content BYTEA,
    p_algorithm TEXT
)
RETURNS BYTEA
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_output_bytes INTEGER;
    v_digest BYTEA;
BEGIN
    IF p_content IS NULL THEN
        RAISE EXCEPTION 'Content cannot be NULL.';
    END IF;

    SELECT output_bytes
    INTO v_output_bytes
    FROM algorithm_policy
    WHERE algorithm_name = p_algorithm
      AND enabled = TRUE
      AND approved_for_integrity = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Algorithm % is not enabled by the integrity policy.',
            p_algorithm;
    END IF;

    v_digest := public.digest(p_content, p_algorithm);

    IF octet_length(v_digest) <> v_output_bytes THEN
        RAISE EXCEPTION
            'Digest length does not match policy for %.',
            p_algorithm;
    END IF;

    RETURN v_digest;
END;
$$;

-- ---------------------------------------------------------------------
-- 4. Automatically calculate digest and byte count
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_artifact_version_digest()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.content_digest := calculate_digest(
        NEW.content,
        NEW.algorithm_name
    );

    NEW.byte_count := octet_length(NEW.content);

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_set_artifact_version_digest
    ON artifact_version;

CREATE TRIGGER trg_set_artifact_version_digest
BEFORE INSERT OR UPDATE OF content, algorithm_name
ON artifact_version
FOR EACH ROW
EXECUTE FUNCTION set_artifact_version_digest();

-- ---------------------------------------------------------------------
-- 5. Verification audit records
-- ---------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS verification_event (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version_id BIGINT NOT NULL
        REFERENCES artifact_version(version_id)
        ON DELETE RESTRICT,
    algorithm_name TEXT NOT NULL
        REFERENCES algorithm_policy(algorithm_name),
    expected_digest BYTEA NOT NULL,
    observed_digest BYTEA NOT NULL,
    expected_bytes BIGINT NOT NULL CHECK (expected_bytes >= 0),
    observed_bytes BIGINT NOT NULL CHECK (observed_bytes >= 0),
    verification_status TEXT NOT NULL
        CHECK (
            verification_status IN (
                'MATCH',
                'MISMATCH',
                'SIZE_MISMATCH'
            )
        ),
    checked_by TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details TEXT,

    CONSTRAINT verification_actor_not_blank
        CHECK (length(trim(checked_by)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_verification_version_time
    ON verification_event (version_id, checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_verification_status_time
    ON verification_event (verification_status, checked_at DESC);

CREATE INDEX IF NOT EXISTS idx_verification_algorithm
    ON verification_event (algorithm_name, checked_at DESC);

-- ---------------------------------------------------------------------
-- 6. Verify candidate content against a registered version
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION verify_artifact_version(
    p_version_id BIGINT,
    p_candidate BYTEA,
    p_checked_by TEXT
)
RETURNS BIGINT
LANGUAGE plpgsql
AS $$
DECLARE
    v_version artifact_version%ROWTYPE;
    v_observed_digest BYTEA;
    v_observed_bytes BIGINT;
    v_status TEXT;
    v_verification_id BIGINT;
BEGIN
    IF p_candidate IS NULL THEN
        RAISE EXCEPTION 'Candidate content cannot be NULL.';
    END IF;

    IF p_checked_by IS NULL OR length(trim(p_checked_by)) = 0 THEN
        RAISE EXCEPTION 'Checker identity is required.';
    END IF;

    SELECT *
    INTO v_version
    FROM artifact_version
    WHERE version_id = p_version_id
    FOR SHARE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'Artifact version % does not exist.',
            p_version_id;
    END IF;

    v_observed_digest := calculate_digest(
        p_candidate,
        v_version.algorithm_name
    );

    v_observed_bytes := octet_length(p_candidate);

    IF v_observed_bytes <> v_version.byte_count THEN
        v_status := 'SIZE_MISMATCH';
    ELSIF v_observed_digest = v_version.content_digest THEN
        v_status := 'MATCH';
    ELSE
        v_status := 'MISMATCH';
    END IF;

    INSERT INTO verification_event (
        version_id,
        algorithm_name,
        expected_digest,
        observed_digest,
        expected_bytes,
        observed_bytes,
        verification_status,
        checked_by,
        details
    )
    VALUES (
        v_version.version_id,
        v_version.algorithm_name,
        v_version.content_digest,
        v_observed_digest,
        v_version.byte_count,
        v_observed_bytes,
        v_status,
        p_checked_by,
        CASE
            WHEN v_status = 'MATCH'
                THEN 'Candidate content matches the registered version.'
            WHEN v_status = 'SIZE_MISMATCH'
                THEN 'Candidate content length differs from the registered version.'
            ELSE
                'Candidate content digest differs from the registered version.'
        END
    )
    RETURNING verification_id INTO v_verification_id;

    RETURN v_verification_id;
END;
$$;

-- ---------------------------------------------------------------------
-- 7. HMAC calculation
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION calculate_hmac_sha256(
    p_content BYTEA,
    p_secret_key BYTEA
)
RETURNS BYTEA
LANGUAGE plpgsql
STRICT
AS $$
BEGIN
    IF octet_length(p_secret_key) < 32 THEN
        RAISE EXCEPTION
            'HMAC key must contain at least 32 bytes.';
    END IF;

    RETURN public.hmac(
        p_content,
        p_secret_key,
        'sha256'
    );
END;
$$;

-- The key is supplied by the caller and is not persisted in this schema.
-- Applications should retrieve it from an approved secrets-management
-- system and avoid exposing it in SQL logs or query histories.

-- ---------------------------------------------------------------------
-- 8. Reporting views
-- ---------------------------------------------------------------------

CREATE OR REPLACE VIEW v_artifact_integrity AS
SELECT
    a.artifact_id,
    a.artifact_name,
    a.artifact_type,
    a.owner_name,
    av.version_id,
    av.version_number,
    av.algorithm_name,
    encode(av.content_digest, 'hex') AS digest_hex,
    av.byte_count,
    av.recorded_by,
    av.created_at
FROM artifact AS a
JOIN artifact_version AS av
    ON av.artifact_id = a.artifact_id
WHERE a.active = TRUE;

CREATE OR REPLACE VIEW v_latest_verification AS
SELECT DISTINCT ON (ve.version_id)
    ve.version_id,
    ve.verification_id,
    ve.algorithm_name,
    ve.verification_status,
    ve.checked_by,
    ve.checked_at,
    encode(ve.expected_digest, 'hex') AS expected_digest_hex,
    encode(ve.observed_digest, 'hex') AS observed_digest_hex,
    ve.expected_bytes,
    ve.observed_bytes
FROM verification_event AS ve
ORDER BY ve.version_id, ve.checked_at DESC, ve.verification_id DESC;

-- ---------------------------------------------------------------------
-- 9. Sample artifact records and versions
-- ---------------------------------------------------------------------

INSERT INTO artifact (
    artifact_name,
    artifact_type,
    owner_name
)
VALUES
    (
        'payment-service-release',
        'RELEASE_PACKAGE',
        'release-engineering'
    ),
    (
        'security-policy-document',
        'DOCUMENT',
        'security-governance'
    ),
    (
        'fraud-detection-model',
        'MODEL',
        'data-platform'
    )
ON CONFLICT (artifact_name) DO NOTHING;

INSERT INTO artifact_version (
    artifact_id,
    version_number,
    content,
    algorithm_name,
    content_digest,
    byte_count,
    recorded_by
)
SELECT
    a.artifact_id,
    1,
    convert_to(
        'Release version 2.4.1; payment service; production',
        'UTF8'
    ),
    'sha256',
    '\x00'::BYTEA,
    0,
    'release-bot'
FROM artifact AS a
WHERE a.artifact_name = 'payment-service-release'
ON CONFLICT (artifact_id, version_number) DO NOTHING;

INSERT INTO artifact_version (
    artifact_id,
    version_number,
    content,
    algorithm_name,
    content_digest,
    byte_count,
    recorded_by
)
SELECT
    a.artifact_id,
    1,
    convert_to(
        'Access policy version 5.2; reviewed and approved',
        'UTF8'
    ),
    'sha3-256',
    '\x00'::BYTEA,
    0,
    'policy-service'
FROM artifact AS a
WHERE a.artifact_name = 'security-policy-document'
ON CONFLICT (artifact_id, version_number) DO NOTHING;

INSERT INTO artifact_version (
    artifact_id,
    version_number,
    content,
    algorithm_name,
    content_digest,
    byte_count,
    recorded_by
)
SELECT
    a.artifact_id,
    1,
    convert_to(
        'Model artifact version 8.0; evaluation package',
        'UTF8'
    ),
    'sha512',
    '\x00'::BYTEA,
    0,
    'model-registry'
FROM artifact AS a
WHERE a.artifact_name = 'fraud-detection-model'
ON CONFLICT (artifact_id, version_number) DO NOTHING;

-- ---------------------------------------------------------------------
-- 10. Transactional verification workflow
-- ---------------------------------------------------------------------

BEGIN;

-- Valid case: candidate is identical to the registered bytes.
SELECT verify_artifact_version(
    av.version_id,
    av.content,
    'integrity-verifier'
) AS valid_verification_id
FROM artifact_version AS av
JOIN artifact AS a
    ON a.artifact_id = av.artifact_id
WHERE a.artifact_name = 'payment-service-release'
  AND av.version_number = 1;

-- Failure case: candidate has the same length but different contents.
SELECT verify_artifact_version(
    av.version_id,
    convert_to(
        'Release version 2.4.1; payment service; altered',
        'UTF8'
    ),
    'integrity-verifier'
) AS altered_content_verification_id
FROM artifact_version AS av
JOIN artifact AS a
    ON a.artifact_id = av.artifact_id
WHERE a.artifact_name = 'payment-service-release'
  AND av.version_number = 1;

-- Failure case: candidate length differs from the registered version.
SELECT verify_artifact_version(
    av.version_id,
    convert_to('short', 'UTF8'),
    'integrity-verifier'
) AS size_failure_verification_id
FROM artifact_version AS av
JOIN artifact AS a
    ON a.artifact_id = av.artifact_id
WHERE a.artifact_name = 'security-policy-document'
  AND av.version_number = 1;

COMMIT;

-- ---------------------------------------------------------------------
-- 11. Retrieval and integrity evaluation queries
-- ---------------------------------------------------------------------

-- Retrieve registered versions and their stored digests.
SELECT
    artifact_name,
    artifact_type,
    version_number,
    algorithm_name,
    digest_hex,
    byte_count,
    recorded_by,
    created_at
FROM v_artifact_integrity
ORDER BY artifact_name, version_number;

-- Retrieve the latest verification decision for each version.
SELECT
    version_id,
    verification_id,
    algorithm_name,
    verification_status,
    expected_digest_hex,
    observed_digest_hex,
    expected_bytes,
    observed_bytes,
    checked_by,
    checked_at
FROM v_latest_verification
ORDER BY version_id;

-- Aggregate the number of verification outcomes by algorithm.
SELECT
    algorithm_name,
    verification_status,
    COUNT(*) AS verification_count
FROM verification_event
GROUP BY algorithm_name, verification_status
ORDER BY algorithm_name, verification_status;

-- Identify versions that do not have a successful latest verification.
SELECT
    av.version_id,
    a.artifact_name,
    av.version_number,
    av.algorithm_name,
    lv.verification_status,
    lv.checked_at
FROM artifact_version AS av
JOIN artifact AS a
    ON a.artifact_id = av.artifact_id
LEFT JOIN v_latest_verification AS lv
    ON lv.version_id = av.version_id
WHERE lv.verification_status IS DISTINCT FROM 'MATCH'
ORDER BY a.artifact_name, av.version_number;

-- CTE-based compliance report.
WITH latest_checks AS (
    SELECT DISTINCT ON (version_id)
        version_id,
        verification_status,
        checked_at
    FROM verification_event
    ORDER BY version_id, checked_at DESC, verification_id DESC
),
version_inventory AS (
    SELECT
        a.artifact_id,
        a.artifact_name,
        av.version_id,
        av.algorithm_name,
        av.byte_count
    FROM artifact AS a
    JOIN artifact_version AS av
        ON av.artifact_id = a.artifact_id
    WHERE a.active = TRUE
)
SELECT
    inventory.artifact_name,
    inventory.version_id,
    inventory.algorithm_name,
    inventory.byte_count,
    COALESCE(
        checks.verification_status,
        'NOT_CHECKED'
    ) AS latest_status,
    checks.checked_at
FROM version_inventory AS inventory
LEFT JOIN latest_checks AS checks
    ON checks.version_id = inventory.version_id
ORDER BY inventory.artifact_name, inventory.version_id;

-- Evaluate algorithm eligibility using the central policy table.
SELECT
    algorithm_name,
    algorithm_family,
    output_bytes,
    enabled,
    approved_for_integrity,
    (
        enabled = TRUE
        AND approved_for_integrity = TRUE
    ) AS eligible_for_integrity_work
FROM algorithm_policy
ORDER BY algorithm_family, algorithm_name;

-- HMAC demonstration using a caller-provided key.
-- This example key is only test data and must not be used in production.
SELECT encode(
    calculate_hmac_sha256(
        convert_to('authenticated release message', 'UTF8'),
        decode(
            '4242424242424242424242424242424242424242424242424242424242424242',
            'hex'
        )
    ),
    'hex'
) AS sample_hmac_sha256;

-- ---------------------------------------------------------------------
-- 12. Validation examples
-- ---------------------------------------------------------------------

-- This block demonstrates that a disabled algorithm is rejected without
-- terminating the remainder of the script.
DO $$
BEGIN
    BEGIN
        PERFORM calculate_digest(
            convert_to('test', 'UTF8'),
            'sha1'
        );

        RAISE EXCEPTION
            'Unexpected acceptance of an unsupported algorithm.';
    EXCEPTION
        WHEN OTHERS THEN
            RAISE NOTICE
                'Unsupported algorithm rejected: %',
                SQLERRM;
    END;
END;
$$;

-- Verify that stored digests and lengths remain consistent with content.
SELECT
    version_id,
    algorithm_name,
    byte_count,
    octet_length(content) AS actual_byte_count,
    encode(content_digest, 'hex') AS stored_digest,
    encode(
        calculate_digest(content, algorithm_name),
        'hex'
    ) AS recalculated_digest,
    (
        byte_count = octet_length(content)
        AND content_digest = calculate_digest(content, algorithm_name)
    ) AS stored_record_consistent
FROM artifact_version
ORDER BY version_id;
