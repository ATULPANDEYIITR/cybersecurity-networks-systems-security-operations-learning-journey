DROP SCHEMA IF EXISTS windows_hardening CASCADE;
CREATE SCHEMA windows_hardening;
SET search_path TO windows_hardening;

-- The relational model separates endpoint state from the hardening baseline.
-- This makes compliance historical and auditable rather than dependent on
-- one mutable configuration record.

CREATE TYPE firewall_profile AS ENUM ('DOMAIN', 'PRIVATE', 'PUBLIC');
CREATE TYPE enforcement_mode AS ENUM ('AUDIT', 'BLOCK', 'ALLOW', 'DISABLED');
CREATE TYPE severity_level AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');
CREATE TYPE assessment_status AS ENUM ('COMPLIANT', 'NON_COMPLIANT', 'UNKNOWN');

CREATE TABLE repositories_of_controls (
    control_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    control_family TEXT NOT NULL,
    control_name TEXT NOT NULL,
    description TEXT NOT NULL,
    UNIQUE (control_family, control_name)
);

CREATE TABLE endpoints (
    endpoint_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    operating_system TEXT NOT NULL DEFAULT 'Windows',
    domain_name TEXT,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (hostname ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$'),
    CHECK (operating_system = 'Windows')
);

CREATE TABLE defender_state (
    endpoint_id BIGINT PRIMARY KEY REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    realtime_monitoring BOOLEAN NOT NULL,
    behavior_monitoring BOOLEAN NOT NULL,
    ioav_protection BOOLEAN NOT NULL,
    cloud_protection BOOLEAN NOT NULL,
    tamper_protection BOOLEAN NOT NULL,
    signature_age_hours INTEGER NOT NULL CHECK (signature_age_hours >= 0),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE firewall_state (
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    profile firewall_profile NOT NULL,
    enabled BOOLEAN NOT NULL,
    default_inbound TEXT NOT NULL CHECK (default_inbound IN ('Allow', 'Block')),
    default_outbound TEXT NOT NULL CHECK (default_outbound IN ('Allow', 'Block')),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (endpoint_id, profile)
);

CREATE TABLE security_policy_state (
    endpoint_id BIGINT PRIMARY KEY REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    password_minimum_length INTEGER NOT NULL CHECK (
        password_minimum_length BETWEEN 1 AND 128
    ),
    lockout_threshold INTEGER NOT NULL CHECK (lockout_threshold >= 0),
    lockout_duration_minutes INTEGER NOT NULL CHECK (
        lockout_duration_minutes >= 0
    ),
    audit_logon_events BOOLEAN NOT NULL,
    audit_process_creation BOOLEAN NOT NULL,
    powershell_script_block_logging BOOLEAN NOT NULL,
    powershell_transcription BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE application_control_state (
    endpoint_id BIGINT PRIMARY KEY REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    mode enforcement_mode NOT NULL,
    publisher_rules BOOLEAN NOT NULL,
    path_rules BOOLEAN NOT NULL,
    unsigned_binary_blocking BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE asr_rules (
    asr_rule_id UUID PRIMARY KEY,
    rule_name TEXT NOT NULL UNIQUE,
    required_state enforcement_mode NOT NULL,
    severity severity_level NOT NULL
);

CREATE TABLE endpoint_asr_state (
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
    asr_rule_id UUID NOT NULL REFERENCES asr_rules(asr_rule_id) ON DELETE CASCADE,
    current_state enforcement_mode NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (endpoint_id, asr_rule_id)
);

CREATE TABLE hardening_baselines (
    baseline_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    baseline_name TEXT NOT NULL UNIQUE,
    max_signature_age_hours INTEGER NOT NULL CHECK (
        max_signature_age_hours >= 0
    ),
    minimum_password_length INTEGER NOT NULL CHECK (
        minimum_password_length BETWEEN 1 AND 128
    ),
    lockout_threshold INTEGER NOT NULL CHECK (
        lockout_threshold > 0
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE baseline_firewall_profiles (
    baseline_id BIGINT NOT NULL REFERENCES hardening_baselines(baseline_id)
        ON DELETE CASCADE,
    profile firewall_profile NOT NULL,
    required_enabled BOOLEAN NOT NULL,
    required_inbound TEXT NOT NULL CHECK (required_inbound IN ('Allow', 'Block')),
    required_outbound TEXT NOT NULL CHECK (required_outbound IN ('Allow', 'Block')),
    PRIMARY KEY (baseline_id, profile)
);

CREATE TABLE baseline_defender (
    baseline_id BIGINT PRIMARY KEY REFERENCES hardening_baselines(baseline_id)
        ON DELETE CASCADE,
    realtime_required BOOLEAN NOT NULL,
    behavior_required BOOLEAN NOT NULL,
    ioav_required BOOLEAN NOT NULL,
    cloud_required BOOLEAN NOT NULL,
    tamper_required BOOLEAN NOT NULL
);

CREATE TABLE baseline_security_policy (
    baseline_id BIGINT PRIMARY KEY REFERENCES hardening_baselines(baseline_id)
        ON DELETE CASCADE,
    audit_logon_required BOOLEAN NOT NULL,
    audit_process_creation_required BOOLEAN NOT NULL,
    powershell_script_block_required BOOLEAN NOT NULL,
    powershell_transcription_required BOOLEAN NOT NULL
);

CREATE TABLE baseline_application_control (
    baseline_id BIGINT PRIMARY KEY REFERENCES hardening_baselines(baseline_id)
        ON DELETE CASCADE,
    required_mode enforcement_mode NOT NULL,
    publisher_rules_required BOOLEAN NOT NULL,
    path_rules_required BOOLEAN NOT NULL,
    unsigned_binary_blocking_required BOOLEAN NOT NULL
);

CREATE TABLE hardening_assessments (
    assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    endpoint_id BIGINT NOT NULL REFERENCES endpoints(endpoint_id)
        ON DELETE CASCADE,
    baseline_id BIGINT NOT NULL REFERENCES hardening_baselines(baseline_id),
    status assessment_status NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hardening_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id BIGINT NOT NULL REFERENCES hardening_assessments(assessment_id)
        ON DELETE CASCADE,
    control_family TEXT NOT NULL,
    severity severity_level NOT NULL,
    finding_message TEXT NOT NULL,
    remediation TEXT NOT NULL,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_assessments_endpoint_time
    ON hardening_assessments(endpoint_id, assessed_at DESC);

CREATE INDEX idx_findings_open_severity
    ON hardening_findings(severity)
    WHERE resolved_at IS NULL;

INSERT INTO repositories_of_controls
    (control_family, control_name, description)
VALUES
    ('Microsoft Defender', 'Real-time monitoring',
     'Continuous malware and threat monitoring'),
    ('Windows Firewall', 'Default inbound blocking',
     'Block unsolicited inbound traffic unless an explicit rule allows it'),
    ('Security Policy', 'Process creation auditing',
     'Record process creation activity for security investigation'),
    ('Application Control', 'Publisher rules',
     'Use trusted publisher identity as an application-control condition'),
    ('Attack Surface Reduction', 'Office child-process blocking',
     'Reduce execution chains originating from Office applications');

INSERT INTO endpoints (hostname, domain_name)
VALUES
    ('WIN-OPS-311', 'CORP.EXAMPLE'),
    ('WIN-ENG-042', 'CORP.EXAMPLE');

INSERT INTO defender_state
    (endpoint_id, realtime_monitoring, behavior_monitoring, ioav_protection,
     cloud_protection, tamper_protection, signature_age_hours)
SELECT endpoint_id, TRUE, FALSE, TRUE, TRUE, FALSE, 41
FROM endpoints
WHERE hostname = 'WIN-OPS-311';

INSERT INTO defender_state
    (endpoint_id, realtime_monitoring, behavior_monitoring, ioav_protection,
     cloud_protection, tamper_protection, signature_age_hours)
SELECT endpoint_id, TRUE, TRUE, TRUE, TRUE, TRUE, 5
FROM endpoints
WHERE hostname = 'WIN-ENG-042';

INSERT INTO firewall_state
    (endpoint_id, profile, enabled, default_inbound, default_outbound)
SELECT endpoint_id, profile, TRUE, 'Block', 'Allow'
FROM endpoints
CROSS JOIN (
    VALUES
        ('DOMAIN'::firewall_profile),
        ('PRIVATE'::firewall_profile),
        ('PUBLIC'::firewall_profile)
) AS profiles(profile)
WHERE hostname = 'WIN-ENG-042';

INSERT INTO firewall_state
    (endpoint_id, profile, enabled, default_inbound, default_outbound)
SELECT endpoint_id, profile,
       CASE WHEN profile = 'PUBLIC' THEN FALSE ELSE TRUE END,
       CASE WHEN profile = 'PUBLIC' THEN 'Allow' ELSE 'Block' END,
       'Allow'
FROM endpoints
CROSS JOIN (
    VALUES
        ('DOMAIN'::firewall_profile),
        ('PRIVATE'::firewall_profile),
        ('PUBLIC'::firewall_profile)
) AS profiles(profile)
WHERE hostname = 'WIN-OPS-311';

INSERT INTO security_policy_state
    (endpoint_id, password_minimum_length, lockout_threshold,
     lockout_duration_minutes, audit_logon_events,
     audit_process_creation, powershell_script_block_logging,
     powershell_transcription)
SELECT endpoint_id, 11, 10, 10, TRUE, FALSE, TRUE, FALSE
FROM endpoints
WHERE hostname = 'WIN-OPS-311';

INSERT INTO security_policy_state
    (endpoint_id, password_minimum_length, lockout_threshold,
     lockout_duration_minutes, audit_logon_events,
     audit_process_creation, powershell_script_block_logging,
     powershell_transcription)
SELECT endpoint_id, 14, 5, 15, TRUE, TRUE, TRUE, TRUE
FROM endpoints
WHERE hostname = 'WIN-ENG-042';

INSERT INTO application_control_state
    (endpoint_id, mode, publisher_rules, path_rules, unsigned_binary_blocking)
SELECT endpoint_id, 'AUDIT', TRUE, FALSE, FALSE
FROM endpoints
WHERE hostname = 'WIN-OPS-311';

INSERT INTO application_control_state
    (endpoint_id, mode, publisher_rules, path_rules, unsigned_binary_blocking)
SELECT endpoint_id, 'BLOCK', TRUE, TRUE, TRUE
FROM endpoints
WHERE hostname = 'WIN-ENG-042';

INSERT INTO asr_rules
    (asr_rule_id, rule_name, required_state, severity)
VALUES
    ('d4f940ab-401b-4efc-aadc-ad5f3c50688a',
     'Block executable content from email client and webmail',
     'BLOCK', 'HIGH'),
    ('3b576869-a4ec-4529-8536-b80a7769e899',
     'Block Office applications from creating executable content',
     'BLOCK', 'HIGH'),
    ('75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
     'Block Office applications from injecting code into other processes',
     'BLOCK', 'HIGH'),
    ('26190899-1602-49e8-8b27-eb1d0a1ce869',
     'Block Office communication applications from creating child processes',
     'AUDIT', 'MEDIUM');

INSERT INTO endpoint_asr_state
    (endpoint_id, asr_rule_id, current_state)
SELECT
    e.endpoint_id,
    r.asr_rule_id,
    CASE
        WHEN e.hostname = 'WIN-OPS-311'
             AND r.rule_name LIKE 'Block executable content%'
            THEN 'BLOCK'::enforcement_mode
        WHEN e.hostname = 'WIN-OPS-311'
             AND r.rule_name LIKE 'Block Office applications from creating executable%'
            THEN 'AUDIT'::enforcement_mode
        WHEN e.hostname = 'WIN-ENG-042'
            THEN r.required_state
        ELSE 'DISABLED'::enforcement_mode
    END
FROM endpoints e
CROSS JOIN asr_rules r;

INSERT INTO hardening_baselines
    (baseline_name, max_signature_age_hours,
     minimum_password_length, lockout_threshold)
VALUES
    ('Windows Enterprise Hardened Baseline', 24, 14, 5);

INSERT INTO baseline_defender
    (baseline_id, realtime_required, behavior_required,
     ioav_required, cloud_required, tamper_required)
SELECT baseline_id, TRUE, TRUE, TRUE, TRUE, TRUE
FROM hardening_baselines
WHERE baseline_name = 'Windows Enterprise Hardened Baseline';

INSERT INTO baseline_firewall_profiles
    (baseline_id, profile, required_enabled,
     required_inbound, required_outbound)
SELECT baseline_id, profile, TRUE, 'Block', 'Allow'
FROM hardening_baselines
CROSS JOIN (
    VALUES
        ('DOMAIN'::firewall_profile),
        ('PRIVATE'::firewall_profile),
        ('PUBLIC'::firewall_profile)
) AS profiles(profile)
WHERE baseline_name = 'Windows Enterprise Hardened Baseline';

INSERT INTO baseline_security_policy
    (baseline_id, audit_logon_required,
     audit_process_creation_required,
     powershell_script_block_required,
     powershell_transcription_required)
SELECT baseline_id, TRUE, TRUE, TRUE, TRUE
FROM hardening_baselines
WHERE baseline_name = 'Windows Enterprise Hardened Baseline';

INSERT INTO baseline_application_control
    (baseline_id, required_mode, publisher_rules_required,
     path_rules_required, unsigned_binary_blocking_required)
SELECT baseline_id, 'BLOCK', TRUE, TRUE, TRUE
FROM hardening_baselines
WHERE baseline_name = 'Windows Enterprise Hardened Baseline';

-- This function evaluates an endpoint without modifying its configuration.
-- PostgreSQL arrays make the individual failed controls visible to callers.
CREATE OR REPLACE FUNCTION evaluate_endpoint(
    p_endpoint_id BIGINT,
    p_baseline_id BIGINT
)
RETURNS TABLE (
    control_family TEXT,
    severity severity_level,
    finding_message TEXT,
    remediation TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    d defender_state%ROWTYPE;
    s security_policy_state%ROWTYPE;
    a application_control_state%ROWTYPE;
    bd baseline_defender%ROWTYPE;
    bs baseline_security_policy%ROWTYPE;
    ba baseline_application_control%ROWTYPE;
    b hardening_baselines%ROWTYPE;
    f firewall_state%ROWTYPE;
    bf baseline_firewall_profiles%ROWTYPE;
    ar asr_rules%ROWTYPE;
    easr endpoint_asr_state%ROWTYPE;
BEGIN
    SELECT * INTO d
    FROM defender_state
    WHERE endpoint_id = p_endpoint_id;

    SELECT * INTO s
    FROM security_policy_state
    WHERE endpoint_id = p_endpoint_id;

    SELECT * INTO a
    FROM application_control_state
    WHERE endpoint_id = p_endpoint_id;

    SELECT * INTO b
    FROM hardening_baselines
    WHERE baseline_id = p_baseline_id;

    SELECT * INTO bd
    FROM baseline_defender
    WHERE baseline_id = p_baseline_id;

    SELECT * INTO bs
    FROM baseline_security_policy
    WHERE baseline_id = p_baseline_id;

    SELECT * INTO ba
    FROM baseline_application_control
    WHERE baseline_id = p_baseline_id;

    IF d.endpoint_id IS NULL OR s.endpoint_id IS NULL OR a.endpoint_id IS NULL THEN
        RAISE EXCEPTION 'Endpoint % lacks required security telemetry', p_endpoint_id;
    END IF;

    IF bd.realtime_required AND NOT d.realtime_monitoring THEN
        control_family := 'Microsoft Defender';
        severity := 'CRITICAL';
        finding_message := 'Real-time monitoring is disabled';
        remediation := 'Enable Defender real-time monitoring';
        RETURN NEXT;
    END IF;

    IF bd.behavior_required AND NOT d.behavior_monitoring THEN
        control_family := 'Microsoft Defender';
        severity := 'HIGH';
        finding_message := 'Behavior monitoring is disabled';
        remediation := 'Enable Defender behavior monitoring';
        RETURN NEXT;
    END IF;

    IF bd.ioav_required AND NOT d.ioav_protection THEN
        control_family := 'Microsoft Defender';
        severity := 'HIGH';
        finding_message := 'IOAV protection is disabled';
        remediation := 'Enable Defender IOAV protection';
        RETURN NEXT;
    END IF;

    IF bd.cloud_required AND NOT d.cloud_protection THEN
        control_family := 'Microsoft Defender';
        severity := 'HIGH';
        finding_message := 'Cloud protection is disabled';
        remediation := 'Enable Defender cloud protection';
        RETURN NEXT;
    END IF;

    IF bd.tamper_required AND NOT d.tamper_protection THEN
        control_family := 'Microsoft Defender';
        severity := 'CRITICAL';
        finding_message := 'Tamper protection is disabled';
        remediation := 'Enable Defender tamper protection';
        RETURN NEXT;
    END IF;

    IF d.signature_age_hours > b.max_signature_age_hours THEN
        control_family := 'Microsoft Defender';
        severity := 'HIGH';
        finding_message := 'Security intelligence is older than baseline';
        remediation := 'Update Defender security intelligence';
        RETURN NEXT;
    END IF;

    FOR bf IN
        SELECT *
        FROM baseline_firewall_profiles
        WHERE baseline_id = p_baseline_id
    LOOP
        SELECT * INTO f
        FROM firewall_state
        WHERE endpoint_id = p_endpoint_id
          AND profile = bf.profile;

        IF f.endpoint_id IS NULL THEN
            control_family := 'Windows Firewall';
            severity := 'CRITICAL';
            finding_message := bf.profile::TEXT || ' firewall telemetry is missing';
            remediation := 'Collect the missing firewall profile state';
            RETURN NEXT;
            CONTINUE;
        END IF;

        IF bf.required_enabled AND NOT f.enabled THEN
            control_family := 'Windows Firewall';
            severity := CASE
                WHEN bf.profile = 'PUBLIC' THEN 'CRITICAL'::severity_level
                ELSE 'HIGH'::severity_level
            END;
            finding_message := bf.profile::TEXT || ' firewall is disabled';
            remediation := 'Enable the ' || bf.profile::TEXT || ' firewall';
            RETURN NEXT;
        END IF;

        IF bf.required_inbound <> f.default_inbound THEN
            control_family := 'Windows Firewall';
            severity := 'HIGH';
            finding_message := bf.profile::TEXT ||
                ' inbound default is ' || f.default_inbound;
            remediation := 'Set inbound default action to ' ||
                bf.required_inbound;
            RETURN NEXT;
        END IF;
    END LOOP;

    IF s.password_minimum_length < b.minimum_password_length THEN
        control_family := 'Security Policy';
        severity := 'MEDIUM';
        finding_message := 'Password minimum length is below baseline';
        remediation := 'Set minimum password length to ' ||
            b.minimum_password_length;
        RETURN NEXT;
    END IF;

    IF s.lockout_threshold = 0
       OR s.lockout_threshold > b.lockout_threshold THEN
        control_family := 'Security Policy';
        severity := 'MEDIUM';
        finding_message := 'Account lockout threshold is too permissive';
        remediation := 'Set lockout threshold to ' || b.lockout_threshold;
        RETURN NEXT;
    END IF;

    IF bs.audit_logon_required AND NOT s.audit_logon_events THEN
        control_family := 'Security Policy';
        severity := 'MEDIUM';
        finding_message := 'Logon auditing is disabled';
        remediation := 'Enable logon auditing';
        RETURN NEXT;
    END IF;

    IF bs.audit_process_creation_required
       AND NOT s.audit_process_creation THEN
        control_family := 'Security Policy';
        severity := 'MEDIUM';
        finding_message := 'Process creation auditing is disabled';
        remediation := 'Enable process creation auditing';
        RETURN NEXT;
    END IF;

    IF bs.powershell_script_block_required
       AND NOT s.powershell_script_block_logging THEN
        control_family := 'Security Policy';
        severity := 'HIGH';
        finding_message := 'PowerShell script block logging is disabled';
        remediation := 'Enable PowerShell script block logging';
        RETURN NEXT;
    END IF;

    IF bs.powershell_transcription_required
       AND NOT s.powershell_transcription THEN
        control_family := 'Security Policy';
        severity := 'HIGH';
        finding_message := 'PowerShell transcription is disabled';
        remediation := 'Enable PowerShell transcription';
        RETURN NEXT;
    END IF;

    IF ba.required_mode <> a.mode THEN
        control_family := 'Application Control';
        severity := 'HIGH';
        finding_message := 'Application control mode is ' || a.mode::TEXT;
        remediation := 'Set application control mode to ' ||
            ba.required_mode::TEXT;
        RETURN NEXT;
    END IF;

    IF ba.publisher_rules_required AND NOT a.publisher_rules THEN
        control_family := 'Application Control';
        severity := 'HIGH';
        finding_message := 'Publisher rules are disabled';
        remediation := 'Enable publisher rules';
        RETURN NEXT;
    END IF;

    IF ba.path_rules_required AND NOT a.path_rules THEN
        control_family := 'Application Control';
        severity := 'HIGH';
        finding_message := 'Path rules are disabled';
        remediation := 'Enable path rules';
        RETURN NEXT;
    END IF;

    IF ba.unsigned_binary_blocking_required
       AND NOT a.unsigned_binary_blocking THEN
        control_family := 'Application Control';
        severity := 'HIGH';
        finding_message := 'Unsigned binary blocking is disabled';
        remediation := 'Enable unsigned binary blocking';
        RETURN NEXT;
    END IF;

    FOR ar IN SELECT * FROM asr_rules LOOP
        SELECT * INTO easr
        FROM endpoint_asr_state
        WHERE endpoint_id = p_endpoint_id
          AND asr_rule_id = ar.asr_rule_id;

        IF easr.endpoint_id IS NULL
           OR easr.current_state <> ar.required_state THEN
            control_family := 'Attack Surface Reduction';
            severity := ar.severity;
            finding_message := ar.rule_name || ' does not meet baseline';
            remediation := 'Set ASR rule ' || ar.asr_rule_id::TEXT ||
                ' to ' || ar.required_state::TEXT;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;

-- A trigger prevents a finding from being inserted with an invalid
-- remediation message. This keeps assessment records actionable.
CREATE OR REPLACE FUNCTION validate_finding()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF length(trim(NEW.finding_message)) < 5 THEN
        RAISE EXCEPTION 'Finding message is too short';
    END IF;

    IF length(trim(NEW.remediation)) < 5 THEN
        RAISE EXCEPTION 'Remediation is too short';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_finding
BEFORE INSERT ON hardening_findings
FOR EACH ROW
EXECUTE FUNCTION validate_finding();

-- Run the assessment inside a transaction so the assessment and all of its
-- findings become one atomic audit record.
BEGIN;

WITH selected_endpoint AS (
    SELECT endpoint_id
    FROM endpoints
    WHERE hostname = 'WIN-OPS-311'
),
selected_baseline AS (
    SELECT baseline_id
    FROM hardening_baselines
    WHERE baseline_name = 'Windows Enterprise Hardened Baseline'
),
assessment_insert AS (
    INSERT INTO hardening_assessments
        (endpoint_id, baseline_id, status)
    SELECT
        e.endpoint_id,
        b.baseline_id,
        'NON_COMPLIANT'
    FROM selected_endpoint e
    CROSS JOIN selected_baseline b
    RETURNING assessment_id, endpoint_id, baseline_id
)
INSERT INTO hardening_findings
    (assessment_id, control_family, severity,
     finding_message, remediation)
SELECT
    ai.assessment_id,
    evaluation.control_family,
    evaluation.severity,
    evaluation.finding_message,
    evaluation.remediation
FROM assessment_insert ai
CROSS JOIN LATERAL evaluate_endpoint(
    ai.endpoint_id,
    ai.baseline_id
) AS evaluation;

COMMIT;

-- Compliance report by control family.
SELECT
    a.assessment_id,
    e.hostname,
    hf.control_family,
    hf.severity,
    hf.finding_message,
    hf.remediation
FROM hardening_findings hf
JOIN hardening_assessments a
    ON a.assessment_id = hf.assessment_id
JOIN endpoints e
    ON e.endpoint_id = a.endpoint_id
ORDER BY
    e.hostname,
    CASE hf.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END,
    hf.control_family;

-- Aggregate open findings by severity.
SELECT
    severity,
    COUNT(*) AS open_findings
FROM hardening_findings
WHERE resolved_at IS NULL
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        ELSE 4
    END;

-- Identify endpoints with a disabled firewall profile.
SELECT
    e.hostname,
    f.profile,
    f.enabled,
    f.default_inbound
FROM endpoints e
JOIN firewall_state f
    ON f.endpoint_id = e.endpoint_id
WHERE NOT f.enabled
   OR f.default_inbound <> 'Block'
ORDER BY e.hostname, f.profile;

-- Identify endpoints whose application-control mode is not enforcing.
SELECT
    e.hostname,
    a.mode,
    a.publisher_rules,
    a.path_rules,
    a.unsigned_binary_blocking
FROM endpoints e
JOIN application_control_state a
    ON a.endpoint_id = e.endpoint_id
WHERE a.mode <> 'BLOCK'
   OR NOT a.publisher_rules
   OR NOT a.path_rules
   OR NOT a.unsigned_binary_blocking;

-- Show ASR rules that are not in their required state.
SELECT
    e.hostname,
    r.rule_name,
    r.required_state,
    COALESCE(s.current_state, 'DISABLED'::enforcement_mode) AS current_state,
    r.severity
FROM endpoints e
CROSS JOIN asr_rules r
LEFT JOIN endpoint_asr_state s
    ON s.endpoint_id = e.endpoint_id
   AND s.asr_rule_id = r.asr_rule_id
WHERE COALESCE(s.current_state, 'DISABLED'::enforcement_mode)
      <> r.required_state
ORDER BY e.hostname, r.severity, r.rule_name;

-- A CTE produces a compact endpoint-level compliance view.
WITH endpoint_findings AS (
    SELECT
        a.endpoint_id,
        COUNT(*) FILTER (WHERE hf.severity = 'CRITICAL') AS critical_count,
        COUNT(*) FILTER (WHERE hf.severity = 'HIGH') AS high_count,
        COUNT(*) FILTER (WHERE hf.severity = 'MEDIUM') AS medium_count,
        COUNT(*) AS total_findings
    FROM hardening_assessments a
    LEFT JOIN hardening_findings hf
        ON hf.assessment_id = a.assessment_id
       AND hf.resolved_at IS NULL
    GROUP BY a.endpoint_id
)
SELECT
    e.hostname,
    COALESCE(ef.critical_count, 0) AS critical_findings,
    COALESCE(ef.high_count, 0) AS high_findings,
    COALESCE(ef.medium_count, 0) AS medium_findings,
    COALESCE(ef.total_findings, 0) AS total_findings,
    CASE
        WHEN COALESCE(ef.critical_count, 0) > 0 THEN 'NON_COMPLIANT'
        WHEN COALESCE(ef.high_count, 0) > 0 THEN 'NON_COMPLIANT'
        WHEN COALESCE(ef.total_findings, 0) = 0 THEN 'COMPLIANT'
        ELSE 'NON_COMPLIANT'
    END AS derived_status
FROM endpoints e
LEFT JOIN endpoint_findings ef
    ON ef.endpoint_id = e.endpoint_id
ORDER BY e.hostname;
