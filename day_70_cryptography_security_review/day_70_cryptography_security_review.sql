-- ============================================================
-- CRYPTOGRAPHY SECURITY REVIEW
-- PostgreSQL 14+
--
-- Models:
--   Cryptographic asset inventory
--   Algorithm configurations
--   Key lifecycle and exposure
--   Certificates and trust validation
--   Security findings
--   Reviewers and review decisions
--   Remediation workflows
--   Security policies
--   Risk aggregation and reporting
--
-- The database stores key metadata only.
-- Raw private keys, passwords, symmetric keys, and secrets
-- must never be stored in these assessment tables.
-- ============================================================

BEGIN;

CREATE SCHEMA IF NOT EXISTS crypto_audit;

SET search_path TO crypto_audit, public;


-- ============================================================
-- 1. ENUMERATIONS
-- ============================================================

CREATE TYPE severity_level AS ENUM (
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW',
    'INFORMATIONAL'
);

CREATE TYPE finding_status AS ENUM (
    'OPEN',
    'IN_REVIEW',
    'REMEDIATED',
    'ACCEPTED_RISK',
    'FALSE_POSITIVE'
);

CREATE TYPE finding_category AS ENUM (
    'WEAK_ALGORITHM',
    'KEY_MANAGEMENT',
    'KEY_EXPOSURE',
    'CERTIFICATE',
    'TLS',
    'RANDOMNESS',
    'CONFIGURATION'
);

CREATE TYPE review_decision AS ENUM (
    'APPROVE_REMEDIATION',
    'REJECT_REMEDIATION',
    'ACCEPT_RISK'
);


-- ============================================================
-- 2. SECURITY POLICY
-- ============================================================

CREATE TABLE security_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    policy_name VARCHAR(150) NOT NULL UNIQUE,

    minimum_rsa_bits INTEGER NOT NULL DEFAULT 2048
        CHECK (minimum_rsa_bits >= 2048),

    maximum_key_age_days INTEGER NOT NULL DEFAULT 365
        CHECK (maximum_key_age_days > 0),

    certificate_warning_days INTEGER NOT NULL DEFAULT 30
        CHECK (certificate_warning_days > 0),

    minimum_approved_tls VARCHAR(10) NOT NULL DEFAULT 'TLS1.2'
        CHECK (minimum_approved_tls IN ('TLS1.2', 'TLS1.3')),

    require_authenticated_encryption BOOLEAN NOT NULL DEFAULT TRUE,

    require_hardware_key_protection BOOLEAN NOT NULL DEFAULT FALSE,

    reject_weak_hashes BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    enabled BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO security_policies (
    policy_name,
    minimum_rsa_bits,
    maximum_key_age_days,
    certificate_warning_days,
    minimum_approved_tls,
    require_authenticated_encryption,
    require_hardware_key_protection
)
VALUES (
    'Enterprise Cryptographic Security Policy',
    2048,
    365,
    30,
    'TLS1.2',
    TRUE,
    FALSE
);


-- ============================================================
-- 3. CRYPTOGRAPHIC ASSET INVENTORY
-- ============================================================

CREATE TABLE crypto_assets (
    asset_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    asset_code VARCHAR(80) NOT NULL UNIQUE,

    asset_name VARCHAR(200) NOT NULL,

    owner_team VARCHAR(120) NOT NULL,

    environment VARCHAR(30) NOT NULL
        CHECK (
            environment IN (
                'DEVELOPMENT',
                'TESTING',
                'STAGING',
                'PRODUCTION'
            )
        ),

    algorithm VARCHAR(80) NOT NULL,

    purpose VARCHAR(150) NOT NULL,

    key_bits INTEGER
        CHECK (key_bits IS NULL OR key_bits > 0),

    encryption_mode VARCHAR(50),

    authenticated_encryption BOOLEAN,

    tls_version VARCHAR(20),

    randomness_source VARCHAR(100),

    data_classification VARCHAR(30) NOT NULL DEFAULT 'INTERNAL'
        CHECK (
            data_classification IN (
                'PUBLIC',
                'INTERNAL',
                'CONFIDENTIAL',
                'RESTRICTED'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    active BOOLEAN NOT NULL DEFAULT TRUE
);


CREATE INDEX idx_crypto_assets_algorithm
    ON crypto_assets (UPPER(algorithm));

CREATE INDEX idx_crypto_assets_environment
    ON crypto_assets (environment, active);

CREATE INDEX idx_crypto_assets_owner
    ON crypto_assets (owner_team);


-- ============================================================
-- 4. KEY INVENTORY
-- ============================================================

CREATE TABLE cryptographic_keys (
    key_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    key_code VARCHAR(100) NOT NULL UNIQUE,

    asset_id BIGINT NOT NULL
        REFERENCES crypto_assets(asset_id),

    algorithm VARCHAR(80) NOT NULL,

    key_bits INTEGER NOT NULL
        CHECK (key_bits > 0),

    key_purpose VARCHAR(100) NOT NULL,

    storage_type VARCHAR(40) NOT NULL
        CHECK (
            storage_type IN (
                'HSM',
                'KMS',
                'VAULT',
                'ENCRYPTED_FILE',
                'LOCAL_FILE',
                'MEMORY',
                'EXTERNAL'
            )
        ),

    exportable BOOLEAN NOT NULL DEFAULT FALSE,

    exposed BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    last_rotated_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    CHECK (
        last_rotated_at IS NULL
        OR last_rotated_at >= created_at
    ),

    CHECK (
        revoked_at IS NULL
        OR revoked_at >= created_at
    )
);


CREATE INDEX idx_keys_asset
    ON cryptographic_keys(asset_id);

CREATE INDEX idx_keys_exposed
    ON cryptographic_keys(exposed)
    WHERE exposed = TRUE;

CREATE INDEX idx_keys_active_rotation
    ON cryptographic_keys(last_rotated_at)
    WHERE active = TRUE;


-- ============================================================
-- 5. CERTIFICATE INVENTORY
-- ============================================================

CREATE TABLE certificates (
    certificate_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    certificate_code VARCHAR(100) NOT NULL UNIQUE,

    asset_id BIGINT NOT NULL
        REFERENCES crypto_assets(asset_id),

    subject_name VARCHAR(255) NOT NULL,

    issuer_name VARCHAR(255) NOT NULL,

    hostname VARCHAR(255) NOT NULL,

    signature_algorithm VARCHAR(100) NOT NULL,

    public_key_algorithm VARCHAR(50) NOT NULL,

    public_key_bits INTEGER NOT NULL
        CHECK (public_key_bits > 0),

    not_before TIMESTAMPTZ NOT NULL,

    not_after TIMESTAMPTZ NOT NULL,

    trusted_issuer BOOLEAN NOT NULL DEFAULT FALSE,

    chain_valid BOOLEAN NOT NULL DEFAULT FALSE,

    revoked BOOLEAN NOT NULL DEFAULT FALSE,

    certificate_status VARCHAR(30) NOT NULL DEFAULT 'ACTIVE'
        CHECK (
            certificate_status IN (
                'ACTIVE',
                'EXPIRED',
                'REVOKED',
                'REPLACED'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (not_after > not_before)
);


CREATE INDEX idx_certificates_expiry
    ON certificates(not_after)
    WHERE certificate_status = 'ACTIVE';

CREATE INDEX idx_certificates_asset
    ON certificates(asset_id);

CREATE INDEX idx_certificates_hostname
    ON certificates(hostname);


-- ============================================================
-- 6. REVIEWER DIRECTORY
-- ============================================================

CREATE TABLE reviewers (
    reviewer_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    reviewer_code VARCHAR(80) NOT NULL UNIQUE,

    reviewer_name VARCHAR(150) NOT NULL,

    department VARCHAR(120) NOT NULL,

    active BOOLEAN NOT NULL DEFAULT TRUE,

    security_qualified BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE reviewer_specializations (
    specialization_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    reviewer_id BIGINT NOT NULL
        REFERENCES reviewers(reviewer_id),

    category finding_category NOT NULL,

    UNIQUE (reviewer_id, category)
);


-- ============================================================
-- 7. SECURITY FINDINGS
-- ============================================================

CREATE TABLE security_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    finding_code VARCHAR(100) NOT NULL UNIQUE,

    asset_id BIGINT NOT NULL
        REFERENCES crypto_assets(asset_id),

    key_id BIGINT
        REFERENCES cryptographic_keys(key_id),

    certificate_id BIGINT
        REFERENCES certificates(certificate_id),

    category finding_category NOT NULL,

    severity severity_level NOT NULL,

    title VARCHAR(250) NOT NULL,

    description TEXT NOT NULL,

    recommendation TEXT NOT NULL,

    status finding_status NOT NULL DEFAULT 'OPEN',

    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    remediation_due_at TIMESTAMPTZ,

    closed_at TIMESTAMPTZ,

    CHECK (
        key_id IS NULL OR certificate_id IS NULL
    )
);


CREATE INDEX idx_findings_status_severity
    ON security_findings(status, severity);

CREATE INDEX idx_findings_asset
    ON security_findings(asset_id);

CREATE INDEX idx_findings_open
    ON security_findings(detected_at)
    WHERE status = 'OPEN';

CREATE INDEX idx_findings_category
    ON security_findings(category, severity);


-- ============================================================
-- 8. FINDING STATUS HISTORY
-- ============================================================

CREATE TABLE finding_status_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    finding_id BIGINT NOT NULL
        REFERENCES security_findings(finding_id),

    previous_status finding_status,

    new_status finding_status NOT NULL,

    changed_by VARCHAR(150) NOT NULL,

    change_reason TEXT NOT NULL,

    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================
-- 9. REVIEW RECORDS
-- ============================================================

CREATE TABLE security_reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    finding_id BIGINT NOT NULL
        REFERENCES security_findings(finding_id),

    reviewer_id BIGINT NOT NULL
        REFERENCES reviewers(reviewer_id),

    decision review_decision NOT NULL,

    review_comments TEXT NOT NULL,

    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (finding_id, reviewer_id, reviewed_at)
);


CREATE INDEX idx_reviews_finding
    ON security_reviews(finding_id, reviewed_at DESC);


-- ============================================================
-- 10. STATUS CHECK RESULTS
-- ============================================================

CREATE TABLE security_status_checks (
    check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    asset_id BIGINT NOT NULL
        REFERENCES crypto_assets(asset_id),

    check_name VARCHAR(150) NOT NULL,

    check_category VARCHAR(80) NOT NULL,

    passed BOOLEAN NOT NULL,

    details TEXT,

    executed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (asset_id, check_name, executed_at)
);


CREATE INDEX idx_status_checks_asset
    ON security_status_checks(asset_id, passed);


-- ============================================================
-- 11. AUDIT EVENTS
-- ============================================================

CREATE TABLE audit_events (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    actor VARCHAR(150) NOT NULL,

    event_type VARCHAR(100) NOT NULL,

    entity_type VARCHAR(80) NOT NULL,

    entity_id BIGINT NOT NULL,

    event_details JSONB NOT NULL DEFAULT '{}'::JSONB,

    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


CREATE INDEX idx_audit_entity
    ON audit_events(entity_type, entity_id, occurred_at DESC);


-- ============================================================
-- 12. FINDING VALIDATION TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION validate_finding_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN

        IF NEW.status <> OLD.status THEN

            IF OLD.status = 'REMEDIATED'
               OR OLD.status = 'FALSE_POSITIVE' THEN

                RAISE EXCEPTION
                    'Terminal finding state cannot be reopened directly';
            END IF;

            IF NOT (
                (OLD.status = 'OPEN'
                    AND NEW.status IN (
                        'IN_REVIEW',
                        'REMEDIATED',
                        'ACCEPTED_RISK',
                        'FALSE_POSITIVE'
                    ))
                OR
                (OLD.status = 'IN_REVIEW'
                    AND NEW.status IN (
                        'OPEN',
                        'REMEDIATED',
                        'ACCEPTED_RISK',
                        'FALSE_POSITIVE'
                    ))
                OR
                (OLD.status = 'ACCEPTED_RISK'
                    AND NEW.status IN (
                        'OPEN',
                        'IN_REVIEW',
                        'REMEDIATED'
                    ))
            ) THEN
                RAISE EXCEPTION
                    'Invalid finding transition: % -> %',
                    OLD.status,
                    NEW.status;
            END IF;

            INSERT INTO finding_status_history (
                finding_id,
                previous_status,
                new_status,
                changed_by,
                change_reason
            )
            VALUES (
                OLD.finding_id,
                OLD.status,
                NEW.status,
                COALESCE(
                    NULLIF(current_setting('app.actor', TRUE), ''),
                    CURRENT_USER
                ),
                COALESCE(
                    NULLIF(current_setting('app.change_reason', TRUE), ''),
                    'Finding status updated'
                )
            );

            NEW.updated_at = CURRENT_TIMESTAMP;

            IF NEW.status IN (
                'REMEDIATED',
                'FALSE_POSITIVE'
            ) THEN
                NEW.closed_at = CURRENT_TIMESTAMP;
            ELSE
                NEW.closed_at = NULL;
            END IF;

        END IF;

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_finding_transition
BEFORE UPDATE OF status
ON security_findings
FOR EACH ROW
EXECUTE FUNCTION validate_finding_transition();


-- ============================================================
-- 13. AUDIT FINDING CREATION AND CHANGES
-- ============================================================

CREATE OR REPLACE FUNCTION audit_finding_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO audit_events (
        actor,
        event_type,
        entity_type,
        entity_id,
        event_details
    )
    VALUES (
        COALESCE(
            NULLIF(current_setting('app.actor', TRUE), ''),
            CURRENT_USER
        ),
        TG_OP,
        'SECURITY_FINDING',
        COALESCE(NEW.finding_id, OLD.finding_id),
        jsonb_build_object(
            'status',
            CASE
                WHEN TG_OP = 'DELETE' THEN OLD.status
                ELSE NEW.status
            END
        )
    );

    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;


CREATE TRIGGER trg_audit_finding
AFTER INSERT OR UPDATE OR DELETE
ON security_findings
FOR EACH ROW
EXECUTE FUNCTION audit_finding_change();


-- ============================================================
-- 14. REVIEWER ELIGIBILITY TRIGGER
-- ============================================================

CREATE OR REPLACE FUNCTION validate_reviewer_eligibility()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_category finding_category;
BEGIN
    SELECT category
    INTO target_category
    FROM security_findings
    WHERE finding_id = NEW.finding_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Finding does not exist';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM reviewers r
        JOIN reviewer_specializations s
            ON s.reviewer_id = r.reviewer_id
        WHERE r.reviewer_id = NEW.reviewer_id
          AND r.active = TRUE
          AND r.security_qualified = TRUE
          AND s.category = target_category
    ) THEN
        RAISE EXCEPTION
            'Reviewer is not qualified for this finding category';
    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_reviewer_eligibility
BEFORE INSERT ON security_reviews
FOR EACH ROW
EXECUTE FUNCTION validate_reviewer_eligibility();


-- ============================================================
-- 15. KEY EXPOSURE RESPONSE
-- ============================================================

CREATE OR REPLACE FUNCTION flag_exposed_key()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.exposed = TRUE AND OLD.exposed = FALSE THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            key_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'KEY-EXPOSURE-' || NEW.key_id,
            NEW.asset_id,
            NEW.key_id,
            'KEY_EXPOSURE',
            'CRITICAL',
            'Cryptographic key exposure',
            'The key has been reported as exposed and must be considered compromised.',
            'Revoke dependent credentials, rotate the key, and investigate exposure.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        INSERT INTO audit_events (
            actor,
            event_type,
            entity_type,
            entity_id,
            event_details
        )
        VALUES (
            CURRENT_USER,
            'KEY_EXPOSURE_DETECTED',
            'CRYPTOGRAPHIC_KEY',
            NEW.key_id,
            jsonb_build_object('exposed', TRUE)
        );

    END IF;

    RETURN NEW;
END;
$$;


CREATE TRIGGER trg_key_exposure
AFTER UPDATE OF exposed
ON cryptographic_keys
FOR EACH ROW
EXECUTE FUNCTION flag_exposed_key();


-- ============================================================
-- 16. ALGORITHM EVALUATION FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_asset(
    p_asset_id BIGINT,
    p_policy_id BIGINT
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    asset_record crypto_assets%ROWTYPE;
    policy_record security_policies%ROWTYPE;
    created_count INTEGER := 0;
    finding_severity severity_level;
BEGIN
    SELECT *
    INTO asset_record
    FROM crypto_assets
    WHERE asset_id = p_asset_id
      AND active = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Active asset not found: %', p_asset_id;
    END IF;

    SELECT *
    INTO policy_record
    FROM security_policies
    WHERE policy_id = p_policy_id
      AND enabled = TRUE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Enabled policy not found: %', p_policy_id;
    END IF;

    IF UPPER(asset_record.algorithm) IN ('MD5', 'SHA1', 'SHA-1')
       AND policy_record.reject_weak_hashes THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'WEAK-HASH-' || asset_record.asset_id,
            asset_record.asset_id,
            'WEAK_ALGORITHM',
            'HIGH',
            'Deprecated hash algorithm',
            'The asset uses ' || asset_record.algorithm,
            'Replace with SHA-256 or a stronger approved hash.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    IF UPPER(asset_record.algorithm) IN ('DES', '3DES', 'RC4') THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'WEAK-CIPHER-' || asset_record.asset_id,
            asset_record.asset_id,
            'WEAK_ALGORITHM',
            'CRITICAL',
            'Deprecated encryption cipher',
            'The configured encryption cipher is weak.',
            'Migrate to modern authenticated encryption.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    IF UPPER(asset_record.algorithm) = 'RSA'
       AND (
           asset_record.key_bits IS NULL
           OR asset_record.key_bits < policy_record.minimum_rsa_bits
       ) THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'WEAK-RSA-' || asset_record.asset_id,
            asset_record.asset_id,
            'WEAK_ALGORITHM',
            'HIGH',
            'RSA key strength insufficient',
            'RSA key size is missing or below policy.',
            'Use RSA keys meeting the configured minimum.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    IF UPPER(COALESCE(asset_record.encryption_mode, ''))
        IN ('ECB', 'CBC_WITHOUT_MAC') THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'UNSAFE-MODE-' || asset_record.asset_id,
            asset_record.asset_id,
            'CONFIGURATION',
            'HIGH',
            'Unsafe encryption mode',
            'The configured encryption mode does not provide authenticated protection.',
            'Use AES-GCM or another approved authenticated encryption construction.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    IF policy_record.require_authenticated_encryption
       AND asset_record.authenticated_encryption = FALSE THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'NO-AUTH-' || asset_record.asset_id,
            asset_record.asset_id,
            'CONFIGURATION',
            'HIGH',
            'Authenticated encryption missing',
            'The configured encryption does not authenticate ciphertext.',
            'Use an authenticated encryption construction.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    IF asset_record.tls_version IS NOT NULL
       AND asset_record.tls_version NOT IN ('TLS1.2', 'TLS1.3') THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'WEAK-TLS-' || asset_record.asset_id,
            asset_record.asset_id,
            'TLS',
            'HIGH',
            'Unsupported TLS version',
            'Configured TLS: ' || asset_record.tls_version,
            'Use TLS 1.2 or TLS 1.3.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    IF LOWER(COALESCE(asset_record.randomness_source, ''))
       IN ('math.random', 'random.random', 'static_seed', 'time') THEN

        INSERT INTO security_findings (
            finding_code,
            asset_id,
            category,
            severity,
            title,
            description,
            recommendation
        )
        VALUES (
            'WEAK-RNG-' || asset_record.asset_id,
            asset_record.asset_id,
            'RANDOMNESS',
            'CRITICAL',
            'Predictable randomness source',
            'The asset uses an insecure random number source.',
            'Use an operating-system cryptographically secure random generator.'
        )
        ON CONFLICT (finding_code) DO NOTHING;

        GET DIAGNOSTICS created_count = ROW_COUNT;
    END IF;

    RETURN created_count;
END;
$$;


-- ============================================================
-- 17. KEY LIFECYCLE EVALUATION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_key_lifecycle()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    key_record RECORD;
    created_count INTEGER := 0;
    affected INTEGER;
    reference_time TIMESTAMPTZ;
BEGIN
    FOR key_record IN
        SELECT k.*, p.maximum_key_age_days, p.minimum_rsa_bits
        FROM cryptographic_keys k
        JOIN crypto_assets a
            ON a.asset_id = k.asset_id
        JOIN security_policies p
            ON p.enabled = TRUE
        WHERE k.active = TRUE
          AND a.active = TRUE
    LOOP

        reference_time := COALESCE(
            key_record.last_rotated_at,
            key_record.created_at
        );

        IF (
            EXTRACT(EPOCH FROM (
                CURRENT_TIMESTAMP - reference_time
            )) / 86400
        ) > key_record.maximum_key_age_days THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                key_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'KEY-ROTATION-' || key_record.key_id,
                key_record.asset_id,
                key_record.key_id,
                'KEY_MANAGEMENT',
                'MEDIUM',
                'Key rotation overdue',
                'Key age exceeds the approved cryptoperiod.',
                'Rotate the key according to the approved lifecycle policy.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

        IF key_record.exportable
           AND key_record.storage_type <> 'HSM' THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                key_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'KEY-STORAGE-' || key_record.key_id,
                key_record.asset_id,
                key_record.key_id,
                'KEY_MANAGEMENT',
                'HIGH',
                'Unprotected exportable key',
                'The key is exportable outside the recorded HSM boundary.',
                'Use non-exportable keys or approved hardware protection.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

        IF UPPER(key_record.algorithm) = 'RSA'
           AND key_record.key_bits < key_record.minimum_rsa_bits THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                key_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'KEY-WEAK-RSA-' || key_record.key_id,
                key_record.asset_id,
                key_record.key_id,
                'WEAK_ALGORITHM',
                'HIGH',
                'Insufficient RSA key size',
                'RSA modulus is below the approved minimum.',
                'Replace with an adequately sized RSA key.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

    END LOOP;

    RETURN created_count;
END;
$$;


-- ============================================================
-- 18. CERTIFICATE EVALUATION
-- ============================================================

CREATE OR REPLACE FUNCTION evaluate_certificates()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    cert RECORD;
    created_count INTEGER := 0;
    affected INTEGER;
BEGIN
    FOR cert IN
        SELECT c.*, p.certificate_warning_days, p.minimum_rsa_bits
        FROM certificates c
        JOIN security_policies p
            ON p.enabled = TRUE
        WHERE c.certificate_status = 'ACTIVE'
    LOOP

        IF cert.not_after <= CURRENT_TIMESTAMP THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                certificate_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'CERT-EXPIRED-' || cert.certificate_id,
                cert.asset_id,
                cert.certificate_id,
                'CERTIFICATE',
                'CRITICAL',
                'Certificate expired',
                'Certificate validity period has ended.',
                'Renew and deploy a valid certificate.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;

        ELSIF cert.not_after <= (
            CURRENT_TIMESTAMP +
            cert.certificate_warning_days * INTERVAL '1 day'
        ) THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                certificate_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'CERT-EXPIRING-' || cert.certificate_id,
                cert.asset_id,
                cert.certificate_id,
                'CERTIFICATE',
                'MEDIUM',
                'Certificate expiring soon',
                'Certificate is approaching expiration.',
                'Schedule certificate renewal.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

        IF cert.revoked THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                certificate_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'CERT-REVOKED-' || cert.certificate_id,
                cert.asset_id,
                cert.certificate_id,
                'CERTIFICATE',
                'CRITICAL',
                'Certificate revoked',
                'Certificate is marked as revoked.',
                'Reject the certificate and investigate revocation.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

        IF NOT cert.trusted_issuer OR NOT cert.chain_valid THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                certificate_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'CERT-CHAIN-' || cert.certificate_id,
                cert.asset_id,
                cert.certificate_id,
                'CERTIFICATE',
                'HIGH',
                'Certificate chain validation failure',
                'Issuer trust or chain validation failed.',
                'Validate intermediates and trusted CA certificates.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

        IF UPPER(cert.signature_algorithm)
           IN ('MD5', 'SHA1', 'SHA-1', 'SHA1WITHRSA') THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                certificate_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'CERT-SIGNATURE-' || cert.certificate_id,
                cert.asset_id,
                cert.certificate_id,
                'CERTIFICATE',
                'HIGH',
                'Weak certificate signature',
                'Certificate uses a deprecated signature algorithm.',
                'Issue a certificate with an approved modern signature.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

        IF UPPER(cert.public_key_algorithm) = 'RSA'
           AND cert.public_key_bits < cert.minimum_rsa_bits THEN

            INSERT INTO security_findings (
                finding_code,
                asset_id,
                certificate_id,
                category,
                severity,
                title,
                description,
                recommendation
            )
            VALUES (
                'CERT-PUBLIC-KEY-' || cert.certificate_id,
                cert.asset_id,
                cert.certificate_id,
                'CERTIFICATE',
                'HIGH',
                'Weak certificate public key',
                'RSA public key is below the approved minimum.',
                'Replace with an adequately sized public key.'
            )
            ON CONFLICT (finding_code) DO NOTHING;

            GET DIAGNOSTICS affected = ROW_COUNT;
            created_count := created_count + affected;
        END IF;

    END LOOP;

    RETURN created_count;
END;
$$;


-- ============================================================
-- 19. ASSESSMENT PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE run_full_assessment()
LANGUAGE plpgsql
AS $$
DECLARE
    policy_record RECORD;
    asset_record RECORD;
    result_count INTEGER;
BEGIN
    SELECT policy_id
    INTO policy_record
    FROM security_policies
    WHERE enabled = TRUE
    ORDER BY policy_id
    LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'No enabled security policy exists.';
    END IF;

    FOR asset_record IN
        SELECT asset_id
        FROM crypto_assets
        WHERE active = TRUE
    LOOP
        result_count := evaluate_asset(
            asset_record.asset_id,
            policy_record.policy_id
        );
    END LOOP;

    PERFORM evaluate_key_lifecycle();
    PERFORM evaluate_certificates();

    INSERT INTO audit_events (
        actor,
        event_type,
        entity_type,
        entity_id,
        event_details
    )
    VALUES (
        CURRENT_USER,
        'FULL_ASSESSMENT_COMPLETED',
        'SECURITY_POLICY',
        policy_record.policy_id,
        jsonb_build_object(
            'execution_time',
            CURRENT_TIMESTAMP
        )
    );
END;
$$;


-- ============================================================
-- 20. REVIEW PROCESSING PROCEDURE
-- ============================================================

CREATE OR REPLACE PROCEDURE process_review(
    p_finding_id BIGINT,
    p_reviewer_id BIGINT,
    p_decision review_decision,
    p_comments TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    current_status finding_status;
BEGIN
    IF p_comments IS NULL OR LENGTH(TRIM(p_comments)) = 0 THEN
        RAISE EXCEPTION 'Review comments are required.';
    END IF;

    -- Lock the finding to avoid concurrent review transitions.
    SELECT status
    INTO current_status
    FROM security_findings
    WHERE finding_id = p_finding_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Finding does not exist.';
    END IF;

    INSERT INTO security_reviews (
        finding_id,
        reviewer_id,
        decision,
        review_comments
    )
    VALUES (
        p_finding_id,
        p_reviewer_id,
        p_decision,
        p_comments
    );

    CASE p_decision
        WHEN 'APPROVE_REMEDIATION' THEN
            UPDATE security_findings
            SET status = 'REMEDIATED'
            WHERE finding_id = p_finding_id;

        WHEN 'REJECT_REMEDIATION' THEN
            UPDATE security_findings
            SET status = 'IN_REVIEW'
            WHERE finding_id = p_finding_id;

        WHEN 'ACCEPT_RISK' THEN
            UPDATE security_findings
            SET status = 'ACCEPTED_RISK'
            WHERE finding_id = p_finding_id;
    END CASE;

END;
$$;


-- ============================================================
-- 21. MERGE-FREE RISK SCORING FUNCTION
-- ============================================================

CREATE OR REPLACE FUNCTION calculate_risk_score(
    p_asset_id BIGINT DEFAULT NULL
)
RETURNS INTEGER
LANGUAGE sql
STABLE
AS $$
    SELECT LEAST(
        100,
        COALESCE(
            SUM(
                CASE severity
                    WHEN 'CRITICAL' THEN 10
                    WHEN 'HIGH' THEN 7
                    WHEN 'MEDIUM' THEN 4
                    WHEN 'LOW' THEN 2
                    WHEN 'INFORMATIONAL' THEN 1
                END
            ),
            0
        )::INTEGER
    )
    FROM security_findings
    WHERE status = 'OPEN'
      AND (
          p_asset_id IS NULL
          OR asset_id = p_asset_id
      );
$$;


-- ============================================================
-- 22. REPORTING VIEWS
-- ============================================================

CREATE OR REPLACE VIEW v_security_findings AS
SELECT
    f.finding_id,
    f.finding_code,
    a.asset_code,
    a.asset_name,
    a.owner_team,
    a.environment,
    f.category,
    f.severity,
    f.title,
    f.status,
    f.detected_at,
    f.remediation_due_at,
    f.closed_at
FROM security_findings f
JOIN crypto_assets a
    ON a.asset_id = f.asset_id;


CREATE OR REPLACE VIEW v_key_lifecycle AS
SELECT
    k.key_id,
    k.key_code,
    a.asset_name,
    k.algorithm,
    k.key_bits,
    k.storage_type,
    k.exportable,
    k.exposed,
    k.active,
    k.last_rotated_at,
    EXTRACT(
        DAY FROM CURRENT_TIMESTAMP -
        COALESCE(k.last_rotated_at, k.created_at)
    )::INTEGER AS days_since_rotation
FROM cryptographic_keys k
JOIN crypto_assets a
    ON a.asset_id = k.asset_id;


CREATE OR REPLACE VIEW v_certificate_health AS
SELECT
    c.certificate_id,
    c.certificate_code,
    c.hostname,
    c.issuer_name,
    c.signature_algorithm,
    c.not_after,
    c.trusted_issuer,
    c.chain_valid,
    c.revoked,
    CASE
        WHEN c.revoked THEN 'REVOKED'
        WHEN c.not_after <= CURRENT_TIMESTAMP THEN 'EXPIRED'
        WHEN NOT c.trusted_issuer OR NOT c.chain_valid
            THEN 'TRUST_FAILURE'
        WHEN c.not_after <= CURRENT_TIMESTAMP + INTERVAL '30 days'
            THEN 'EXPIRING'
        ELSE 'VALID'
    END AS health_status
FROM certificates c;


CREATE OR REPLACE VIEW v_security_dashboard AS
SELECT
    severity,
    status,
    COUNT(*) AS finding_count
FROM security_findings
GROUP BY severity, status;


-- ============================================================
-- 23. SAMPLE ASSETS
-- ============================================================

INSERT INTO crypto_assets (
    asset_code,
    asset_name,
    owner_team,
    environment,
    algorithm,
    purpose,
    key_bits,
    encryption_mode,
    authenticated_encryption,
    tls_version,
    randomness_source,
    data_classification
)
VALUES
(
    'ASSET-001',
    'Legacy Authentication Service',
    'Identity Engineering',
    'PRODUCTION',
    'SHA1',
    'Integrity verification',
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    'RESTRICTED'
),
(
    'ASSET-002',
    'Payment Encryption Service',
    'Payment Engineering',
    'PRODUCTION',
    'AES',
    'Payment data encryption',
    256,
    'ECB',
    FALSE,
    'TLS1.2',
    'OS_CSPRNG',
    'RESTRICTED'
),
(
    'ASSET-003',
    'External API Gateway',
    'Platform Engineering',
    'PRODUCTION',
    'RSA',
    'Digital signatures',
    1024,
    NULL,
    NULL,
    'TLS1.0',
    NULL,
    'CONFIDENTIAL'
),
(
    'ASSET-004',
    'Session Token Service',
    'Identity Engineering',
    'STAGING',
    'AES-256',
    'Session protection',
    256,
    'GCM',
    TRUE,
    'TLS1.3',
    'MATH.RANDOM',
    'CONFIDENTIAL'
),
(
    'ASSET-005',
    'Secure Storage Service',
    'Infrastructure Security',
    'PRODUCTION',
    'AES-256',
    'Encrypted storage',
    256,
    'GCM',
    TRUE,
    'TLS1.3',
    'OS_CSPRNG',
    'RESTRICTED'
);


-- ============================================================
-- 24. SAMPLE KEYS
-- ============================================================

INSERT INTO cryptographic_keys (
    key_code,
    asset_id,
    algorithm,
    key_bits,
    key_purpose,
    storage_type,
    exportable,
    exposed,
    created_at,
    last_rotated_at
)
SELECT
    'KEY-001',
    asset_id,
    'RSA',
    1024,
    'Digital signatures',
    'LOCAL_FILE',
    TRUE,
    FALSE,
    CURRENT_TIMESTAMP - INTERVAL '600 days',
    CURRENT_TIMESTAMP - INTERVAL '500 days'
FROM crypto_assets
WHERE asset_code = 'ASSET-003';


INSERT INTO cryptographic_keys (
    key_code,
    asset_id,
    algorithm,
    key_bits,
    key_purpose,
    storage_type,
    exportable,
    exposed,
    created_at,
    last_rotated_at
)
SELECT
    'KEY-002',
    asset_id,
    'AES',
    256,
    'Storage encryption',
    'HSM',
    FALSE,
    FALSE,
    CURRENT_TIMESTAMP - INTERVAL '30 days',
    CURRENT_TIMESTAMP - INTERVAL '15 days'
FROM crypto_assets
WHERE asset_code = 'ASSET-005';


-- ============================================================
-- 25. SAMPLE CERTIFICATES
-- ============================================================

INSERT INTO certificates (
    certificate_code,
    asset_id,
    subject_name,
    issuer_name,
    hostname,
    signature_algorithm,
    public_key_algorithm,
    public_key_bits,
    not_before,
    not_after,
    trusted_issuer,
    chain_valid,
    revoked
)
SELECT
    'CERT-001',
    asset_id,
    'CN=old.example.com',
    'Unknown CA',
    'old.example.com',
    'SHA1WITHRSA',
    'RSA',
    1024,
    CURRENT_TIMESTAMP - INTERVAL '500 days',
    CURRENT_TIMESTAMP - INTERVAL '5 days',
    FALSE,
    FALSE,
    TRUE
FROM crypto_assets
WHERE asset_code = 'ASSET-003';


INSERT INTO certificates (
    certificate_code,
    asset_id,
    subject_name,
    issuer_name,
    hostname,
    signature_algorithm,
    public_key_algorithm,
    public_key_bits,
    not_before,
    not_after,
    trusted_issuer,
    chain_valid,
    revoked
)
SELECT
    'CERT-002',
    asset_id,
    'CN=storage.example.com',
    'Enterprise CA',
    'storage.example.com',
    'SHA256WITHRSA',
    'RSA',
    3072,
    CURRENT_TIMESTAMP - INTERVAL '20 days',
    CURRENT_TIMESTAMP + INTERVAL '200 days',
    TRUE,
    TRUE,
    FALSE
FROM crypto_assets
WHERE asset_code = 'ASSET-005';


-- ============================================================
-- 26. SAMPLE REVIEWERS
-- ============================================================

INSERT INTO reviewers (
    reviewer_code,
    reviewer_name,
    department,
    active,
    security_qualified
)
VALUES
(
    'REV-001',
    'Cryptography Security Team',
    'Information Security',
    TRUE,
    TRUE
),
(
    'REV-002',
    'Infrastructure Security Team',
    'Infrastructure Security',
    TRUE,
    TRUE
);


INSERT INTO reviewer_specializations (
    reviewer_id,
    category
)
SELECT r.reviewer_id, category
FROM reviewers r
CROSS JOIN unnest(
    ARRAY[
        'WEAK_ALGORITHM',
        'KEY_MANAGEMENT',
        'KEY_EXPOSURE',
        'CERTIFICATE',
        'TLS',
        'RANDOMNESS',
        'CONFIGURATION'
    ]::finding_category[]
) AS category
WHERE r.reviewer_code = 'REV-001';


INSERT INTO reviewer_specializations (
    reviewer_id,
    category
)
SELECT r.reviewer_id, category
FROM reviewers r
CROSS JOIN unnest(
    ARRAY[
        'KEY_MANAGEMENT',
        'CERTIFICATE',
        'TLS'
    ]::finding_category[]
) AS category
WHERE r.reviewer_code = 'REV-002';


-- ============================================================
-- 27. SAMPLE AUTOMATED STATUS CHECKS
-- ============================================================

INSERT INTO security_status_checks (
    asset_id,
    check_name,
    check_category,
    passed,
    details
)
SELECT
    asset_id,
    'TLS_VERSION_CHECK',
    'TLS',
    tls_version IN ('TLS1.2', 'TLS1.3'),
    'Protocol configuration inspection'
FROM crypto_assets;


INSERT INTO security_status_checks (
    asset_id,
    check_name,
    check_category,
    passed,
    details
)
SELECT
    asset_id,
    'AUTHENTICATED_ENCRYPTION_CHECK',
    'ENCRYPTION',
    COALESCE(authenticated_encryption, TRUE),
    'Encryption authentication configuration'
FROM crypto_assets;


-- ============================================================
-- 28. EXECUTE ASSESSMENT
-- ============================================================

CALL run_full_assessment();


-- ============================================================
-- 29. DEMONSTRATE KEY EXPOSURE DETECTION
-- ============================================================

-- The trigger creates a critical finding automatically.
UPDATE cryptographic_keys
SET exposed = TRUE
WHERE key_code = 'KEY-001';


-- ============================================================
-- 30. RETRIEVAL QUERIES
-- ============================================================

SELECT *
FROM v_security_findings
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END,
    detected_at DESC;


-- ============================================================
-- 31. VALIDATION QUERIES
-- ============================================================

-- Cryptographic assets using weak algorithms.
SELECT
    asset_code,
    asset_name,
    algorithm,
    key_bits
FROM crypto_assets
WHERE UPPER(algorithm) IN (
    'MD5',
    'SHA1',
    'SHA-1',
    'DES',
    '3DES',
    'RC4'
);


-- Insecure key storage.
SELECT
    key_code,
    algorithm,
    storage_type,
    exportable,
    exposed
FROM cryptographic_keys
WHERE exposed = TRUE
   OR (
       exportable = TRUE
       AND storage_type <> 'HSM'
   );


-- Certificate validation failures.
SELECT *
FROM v_certificate_health
WHERE health_status <> 'VALID';


-- ============================================================
-- 32. AGGREGATION QUERIES
-- ============================================================

SELECT
    category,
    severity,
    status,
    COUNT(*) AS total
FROM security_findings
GROUP BY category, severity, status
ORDER BY category, severity;


SELECT
    a.owner_team,
    COUNT(f.finding_id) AS total_findings,
    COUNT(*) FILTER (
        WHERE f.severity = 'CRITICAL'
    ) AS critical_findings,
    COUNT(*) FILTER (
        WHERE f.status = 'OPEN'
    ) AS open_findings
FROM crypto_assets a
LEFT JOIN security_findings f
    ON f.asset_id = a.asset_id
GROUP BY a.owner_team
ORDER BY open_findings DESC;


-- ============================================================
-- 33. EVALUATION AND RISK QUERIES
-- ============================================================

SELECT
    asset_id,
    asset_name,
    calculate_risk_score(asset_id) AS risk_score
FROM crypto_assets
ORDER BY risk_score DESC;


SELECT
    calculate_risk_score(NULL) AS enterprise_risk_score;


-- ============================================================
-- 34. WORKFLOW PROCESSING
-- ============================================================

-- Begin a separate transaction when processing a review.
-- The reviewer must be qualified for the finding category.

DO $$
DECLARE
    selected_finding BIGINT;
    selected_reviewer BIGINT;
BEGIN
    SELECT finding_id
    INTO selected_finding
    FROM security_findings
    WHERE status = 'OPEN'
    ORDER BY detected_at
    LIMIT 1;

    SELECT reviewer_id
    INTO selected_reviewer
    FROM reviewers
    WHERE reviewer_code = 'REV-001';

    IF selected_finding IS NOT NULL
       AND selected_reviewer IS NOT NULL THEN

        UPDATE security_findings
        SET status = 'IN_REVIEW'
        WHERE finding_id = selected_finding;
    END IF;
END;
$$;


-- ============================================================
-- 35. CTE-BASED MANAGEMENT REPORT
-- ============================================================

WITH finding_metrics AS (
    SELECT
        asset_id,
        COUNT(*) AS total_findings,
        COUNT(*) FILTER (
            WHERE status = 'OPEN'
        ) AS open_findings,
        COUNT(*) FILTER (
            WHERE severity = 'CRITICAL'
              AND status = 'OPEN'
        ) AS critical_open
    FROM security_findings
    GROUP BY asset_id
),
risk_metrics AS (
    SELECT
        asset_id,
        calculate_risk_score(asset_id) AS risk_score
    FROM crypto_assets
)
SELECT
    a.asset_code,
    a.asset_name,
    a.owner_team,
    COALESCE(f.total_findings, 0) AS total_findings,
    COALESCE(f.open_findings, 0) AS open_findings,
    COALESCE(f.critical_open, 0) AS critical_open,
    COALESCE(r.risk_score, 0) AS risk_score
FROM crypto_assets a
LEFT JOIN finding_metrics f
    ON f.asset_id = a.asset_id
LEFT JOIN risk_metrics r
    ON r.asset_id = a.asset_id
ORDER BY risk_score DESC;


-- ============================================================
-- 36. KEY ROTATION REPORT
-- ============================================================

SELECT
    key_code,
    asset_name,
    algorithm,
    storage_type,
    days_since_rotation,
    CASE
        WHEN exposed THEN 'COMPROMISED'
        WHEN days_since_rotation > 365 THEN 'ROTATION_OVERDUE'
        ELSE 'WITHIN_POLICY'
    END AS lifecycle_status
FROM v_key_lifecycle
ORDER BY days_since_rotation DESC NULLS LAST;


-- ============================================================
-- 37. SECURITY CHECK AGGREGATION
-- ============================================================

SELECT
    check_category,
    COUNT(*) AS checks_executed,
    COUNT(*) FILTER (
        WHERE passed
    ) AS passed,
    COUNT(*) FILTER (
        WHERE NOT passed
    ) AS failed,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE passed) /
        NULLIF(COUNT(*), 0),
        2
    ) AS pass_percentage
FROM security_status_checks
GROUP BY check_category;


-- ============================================================
-- 38. AUDIT HISTORY
-- ============================================================

SELECT
    actor,
    event_type,
    entity_type,
    entity_id,
    event_details,
    occurred_at
FROM audit_events
ORDER BY occurred_at DESC;


-- ============================================================
-- 39. REVIEW HISTORY
-- ============================================================

SELECT
    f.finding_code,
    r.reviewer_name,
    sr.decision,
    sr.review_comments,
    sr.reviewed_at
FROM security_reviews sr
JOIN security_findings f
    ON f.finding_id = sr.finding_id
JOIN reviewers r
    ON r.reviewer_id = sr.reviewer_id
ORDER BY sr.reviewed_at DESC;


-- ============================================================
-- 40. TRANSACTION HANDLING EXAMPLE
-- ============================================================

-- A valid remediation workflow must update the finding and
-- record its review atomically.

-- The following transaction is deliberately rolled back to
-- demonstrate failure isolation without modifying the sample
-- finding state.

SAVEPOINT remediation_example;

UPDATE security_findings
SET status = 'IN_REVIEW'
WHERE finding_code = 'WEAK-HASH-1'
  AND status = 'OPEN';

ROLLBACK TO SAVEPOINT remediation_example;


-- ============================================================
-- 41. OPERATIONAL NOTES
-- ============================================================

-- Database metadata is not a substitute for actual
-- cryptographic validation.
--
-- Certificate hostname matching, chain construction,
-- revocation checking, cryptographic signature verification,
-- nonce reuse detection, and cipher implementation analysis
-- must be performed by trusted security libraries or
-- dedicated assessment services.
--
-- Production access should use least-privilege roles.
-- Audit tables should be protected against unauthorized
-- modification and deletion.
--
-- The schema intentionally does not contain secret values.

COMMIT;
