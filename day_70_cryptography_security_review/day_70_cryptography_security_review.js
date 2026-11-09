"use strict";

/**
 * Cryptography Security Review
 *
 * Event-driven security assessment and remediation workflow.
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only.
 *
 * Features:
 * - Algorithm and cipher configuration inspection
 * - Key lifecycle and exposure evaluation
 * - Certificate metadata assessment
 * - TLS configuration checks
 * - Asynchronous asset processing
 * - Event-driven finding management
 * - Risk aggregation
 * - JSON reporting
 * - Automated validation tests
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const EventEmitter = require("node:events");
const assert = require("node:assert/strict");


/* ======================================================
   ENUMERATIONS AND CONSTANTS
====================================================== */

const Severity = Object.freeze({
    CRITICAL: "CRITICAL",
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
    INFORMATIONAL: "INFORMATIONAL"
});

const Category = Object.freeze({
    ALGORITHM: "WEAK_ALGORITHM",
    KEY: "KEY_MANAGEMENT",
    EXPOSURE: "KEY_EXPOSURE",
    CERTIFICATE: "CERTIFICATE",
    TLS: "TLS",
    RANDOMNESS: "RANDOMNESS",
    CONFIGURATION: "CONFIGURATION"
});

const Status = Object.freeze({
    OPEN: "OPEN",
    IN_REVIEW: "IN_REVIEW",
    REMEDIATED: "REMEDIATED",
    ACCEPTED_RISK: "ACCEPTED_RISK",
    FALSE_POSITIVE: "FALSE_POSITIVE"
});

const SEVERITY_WEIGHT = Object.freeze({
    CRITICAL: 10,
    HIGH: 7,
    MEDIUM: 4,
    LOW: 2,
    INFORMATIONAL: 1
});

const TERMINAL_STATES = new Set([
    Status.REMEDIATED,
    Status.FALSE_POSITIVE
]);

const VALID_TRANSITIONS = Object.freeze({
    OPEN: new Set([
        Status.IN_REVIEW,
        Status.REMEDIATED,
        Status.ACCEPTED_RISK,
        Status.FALSE_POSITIVE
    ]),
    IN_REVIEW: new Set([
        Status.OPEN,
        Status.REMEDIATED,
        Status.ACCEPTED_RISK,
        Status.FALSE_POSITIVE
    ]),
    ACCEPTED_RISK: new Set([
        Status.OPEN,
        Status.IN_REVIEW,
        Status.REMEDIATED
    ]),
    REMEDIATED: new Set(),
    FALSE_POSITIVE: new Set()
});


/* ======================================================
   ERRORS
====================================================== */

class SecurityReviewError extends Error {}

class ValidationError extends SecurityReviewError {}

class PolicyError extends SecurityReviewError {}


/* ======================================================
   VALIDATION
====================================================== */

function requireString(value, field) {
    if (
        typeof value !== "string" ||
        value.trim().length === 0
    ) {
        throw new ValidationError(
            `${field} must be a non-empty string.`
        );
    }
}

function requirePositiveInteger(value, field) {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new ValidationError(
            `${field} must be a positive integer.`
        );
    }
}

function normalizeAlgorithm(value) {
    requireString(value, "algorithm");

    return value
        .toUpperCase()
        .replaceAll("_", "-")
        .replaceAll(" ", "");
}

function parseDate(value, field) {
    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        throw new ValidationError(
            `${field} is not a valid date.`
        );
    }

    return date;
}


/* ======================================================
   POLICY ENGINE
====================================================== */

class SecurityPolicy {

    constructor() {
        this.deprecatedHashes = new Set([
            "MD5",
            "SHA1",
            "SHA-1"
        ]);

        this.weakCiphers = new Set([
            "DES",
            "3DES",
            "RC4"
        ]);

        this.minimumRsaBits = 2048;
        this.maximumKeyAgeDays = 365;
        this.approvedTls = new Set([
            "TLS1.2",
            "TLS1.3"
        ]);

        this.minimumCertificateWarningDays = 30;

        Object.freeze(this);
    }
}


/* ======================================================
   FINDING MODEL
====================================================== */

class SecurityFinding {

    constructor({
        id,
        assetId,
        category,
        severity,
        title,
        description,
        recommendation
    }) {
        requireString(id, "finding ID");
        requireString(assetId, "asset ID");
        requireString(title, "title");

        if (!Object.values(Severity).includes(severity)) {
            throw new ValidationError("Invalid severity.");
        }

        this.id = id;
        this.assetId = assetId;
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.recommendation = recommendation;

        this.status = Status.OPEN;
        this.detectedAt = new Date().toISOString();
        this.updatedAt = this.detectedAt;
    }

    transition(nextStatus) {
        if (!Object.values(Status).includes(nextStatus)) {
            throw new ValidationError(
                "Unknown finding status."
            );
        }

        if (!VALID_TRANSITIONS[this.status].has(nextStatus)) {
            throw new PolicyError(
                `Invalid transition: ${this.status} -> ${nextStatus}`
            );
        }

        this.status = nextStatus;
        this.updatedAt = new Date().toISOString();
    }
}


/* ======================================================
   ALGORITHM INSPECTOR
====================================================== */

class AlgorithmInspector {

    constructor(policy) {
        this.policy = policy;
    }

    inspect(asset) {
        requireString(asset.id, "asset ID");
        requireString(asset.algorithm, "algorithm");

        const algorithm = normalizeAlgorithm(asset.algorithm);
        const findings = [];

        const add = (category, severity, title, description, recommendation) => {
            findings.push({
                category,
                severity,
                title,
                description,
                recommendation
            });
        };

        if (this.policy.deprecatedHashes.has(algorithm)) {
            add(
                Category.ALGORITHM,
                Severity.HIGH,
                `Deprecated hash: ${algorithm}`,
                "The hash algorithm is unsuitable for modern collision-resistant security applications.",
                "Migrate to SHA-256 or a stronger approved hash."
            );
        }

        if (this.policy.weakCiphers.has(algorithm)) {
            add(
                Category.ALGORITHM,
                Severity.CRITICAL,
                `Weak cipher: ${algorithm}`,
                "The configured encryption algorithm is deprecated.",
                "Migrate to authenticated modern encryption."
            );
        }

        if (
            ["RSA", "RSA-PSS"].includes(algorithm)
        ) {
            if (asset.keyBits == null) {
                add(
                    Category.CONFIGURATION,
                    Severity.MEDIUM,
                    "RSA key size unavailable",
                    "The configured RSA modulus size cannot be verified.",
                    "Record and validate RSA key strength."
                );
            } else {
                requirePositiveInteger(asset.keyBits, "keyBits");

                if (asset.keyBits < this.policy.minimumRsaBits) {
                    add(
                        Category.ALGORITHM,
                        Severity.HIGH,
                        "Insufficient RSA key strength",
                        `Configured key size: ${asset.keyBits} bits.`,
                        "Use an RSA modulus of at least 2048 bits."
                    );
                }
            }
        }

        if (
            ["AES", "AES-128", "AES-256"].includes(algorithm)
        ) {
            if (
                asset.mode &&
                ["ECB", "CBC_WITHOUT_MAC"].includes(
                    asset.mode.toUpperCase()
                )
            ) {
                add(
                    Category.CONFIGURATION,
                    Severity.HIGH,
                    "Unauthenticated encryption mode",
                    `Configured AES mode: ${asset.mode}.`,
                    "Use AES-GCM with unique nonces."
                );
            }

            if (asset.authenticated === false) {
                add(
                    Category.CONFIGURATION,
                    Severity.HIGH,
                    "Encryption lacks authentication",
                    "Ciphertext integrity is not verified.",
                    "Use authenticated encryption and validate its tag."
                );
            }
        }

        if (
            asset.tlsVersion &&
            !this.policy.approvedTls.has(asset.tlsVersion.toUpperCase())
        ) {
            add(
                Category.TLS,
                Severity.HIGH,
                "Unsupported TLS version",
                `Detected protocol: ${asset.tlsVersion}.`,
                "Use TLS 1.2 or TLS 1.3."
            );
        }

        if (
            asset.randomnessSource &&
            ["math.random", "random.random", "static_seed", "time"].includes(
                asset.randomnessSource.toLowerCase()
            )
        ) {
            add(
                Category.RANDOMNESS,
                Severity.CRITICAL,
                "Predictable randomness",
                "The randomness source is unsuitable for cryptographic secrets.",
                "Use crypto.randomBytes or crypto.randomUUID as appropriate."
            );
        }

        return findings;
    }
}


/* ======================================================
   KEY LIFECYCLE INSPECTOR
====================================================== */

class KeyLifecycleInspector {

    constructor(policy) {
        this.policy = policy;
    }

    inspect(key) {
        requireString(key.id, "key ID");
        requireString(key.algorithm, "key algorithm");
        requireString(key.storage, "key storage");

        requirePositiveInteger(key.bits, "key bits");

        const created = parseDate(key.createdAt, "createdAt");

        const rotated = key.lastRotatedAt
            ? parseDate(key.lastRotatedAt, "lastRotatedAt")
            : created;

        if (rotated < created) {
            throw new ValidationError(
                "Key rotation date cannot precede creation."
            );
        }

        const findings = [];
        const now = Date.now();

        if (key.exposed) {
            findings.push({
                category: Category.EXPOSURE,
                severity: Severity.CRITICAL,
                title: "Key exposure detected",
                description: "The key must be treated as compromised.",
                recommendation:
                    "Revoke dependent credentials, rotate the key, and investigate exposure."
            });
        }

        if (key.exportable && key.storage !== "HSM") {
            findings.push({
                category: Category.KEY,
                severity: Severity.HIGH,
                title: "Unprotected exportable key",
                description:
                    "An exportable key is stored outside the recorded HSM boundary.",
                recommendation:
                    "Use controlled key custody and approved hardware protection."
            });
        }

        const ageDays = Math.floor(
            (now - rotated.getTime()) / 86400000
        );

        if (ageDays > this.policy.maximumKeyAgeDays) {
            findings.push({
                category: Category.KEY,
                severity: Severity.MEDIUM,
                title: "Key rotation overdue",
                description: `Key age: ${ageDays} days.`,
                recommendation:
                    "Rotate the key according to its approved cryptoperiod."
            });
        }

        if (
            normalizeAlgorithm(key.algorithm) === "RSA" &&
            key.bits < this.policy.minimumRsaBits
        ) {
            findings.push({
                category: Category.ALGORITHM,
                severity: Severity.HIGH,
                title: "Weak RSA key",
                description: `RSA modulus size is ${key.bits} bits.`,
                recommendation: "Replace with an appropriately sized RSA key."
            });
        }

        return findings;
    }
}


/* ======================================================
   CERTIFICATE INSPECTOR
====================================================== */

class CertificateInspector {

    constructor(policy) {
        this.policy = policy;
    }

    hostnameMatches(pattern, hostname) {
        pattern = pattern.toLowerCase().replace(/\.$/, "");
        hostname = hostname.toLowerCase().replace(/\.$/, "");

        if (pattern === hostname) {
            return true;
        }

        if (!pattern.startsWith("*.")) {
            return false;
        }

        const suffix = pattern.slice(2);

        if (!hostname.endsWith(`.${suffix}`)) {
            return false;
        }

        const prefix = hostname.slice(
            0,
            -(suffix.length + 1)
        );

        return prefix.length > 0 && !prefix.includes(".");
    }

    inspect(cert, expectedHostname) {
        requireString(cert.id, "certificate ID");
        requireString(expectedHostname, "expected hostname");

        const start = parseDate(cert.notBefore, "notBefore");
        const end = parseDate(cert.notAfter, "notAfter");

        if (end <= start) {
            throw new ValidationError(
                "Certificate validity period is invalid."
            );
        }

        const findings = [];
        const now = Date.now();

        const add = (severity, title, description, recommendation) => {
            findings.push({
                category: Category.CERTIFICATE,
                severity,
                title,
                description,
                recommendation
            });
        };

        if (now < start.getTime()) {
            add(
                Severity.HIGH,
                "Certificate not yet valid",
                "Current time precedes the validity start.",
                "Verify system clocks and certificate validity dates."
            );
        }

        if (now >= end.getTime()) {
            add(
                Severity.CRITICAL,
                "Expired certificate",
                "The certificate is outside its validity period.",
                "Renew and deploy a valid certificate."
            );
        } else if (
            end.getTime() - now <
            this.policy.minimumCertificateWarningDays * 86400000
        ) {
            add(
                Severity.MEDIUM,
                "Certificate expiring soon",
                "The certificate is approaching expiration.",
                "Schedule certificate renewal."
            );
        }

        if (cert.revoked) {
            add(
                Severity.CRITICAL,
                "Revoked certificate",
                "The certificate is marked revoked.",
                "Reject the certificate and investigate its revocation."
            );
        }

        if (!cert.chainValid || !cert.trustedIssuer) {
            add(
                Severity.HIGH,
                "Certificate trust validation failed",
                "The issuer or certificate chain is not trusted.",
                "Validate all intermediate certificates and trust anchors."
            );
        }

        if (
            !this.hostnameMatches(cert.hostname, expectedHostname)
        ) {
            add(
                Severity.HIGH,
                "Certificate hostname mismatch",
                `Expected ${expectedHostname}; received ${cert.hostname}.`,
                "Deploy a certificate with the correct SAN identity."
            );
        }

        if (
            ["SHA1", "SHA-1", "MD5", "SHA1WITHRSA"].includes(
                cert.signatureAlgorithm.toUpperCase()
            )
        ) {
            add(
                Severity.HIGH,
                "Weak certificate signature",
                "The certificate uses a deprecated signature algorithm.",
                "Issue a certificate with an approved modern signature."
            );
        }

        if (
            cert.publicKeyAlgorithm.toUpperCase() === "RSA" &&
            cert.publicKeyBits < this.policy.minimumRsaBits
        ) {
            add(
                Severity.HIGH,
                "Weak certificate public key",
                "RSA certificate key is below the configured minimum.",
                "Replace the certificate with an adequately sized public key."
            );
        }

        return findings;
    }
}


/* ======================================================
   SECURITY REVIEW SERVICE
====================================================== */

class SecurityReviewService extends EventEmitter {

    constructor(policy = new SecurityPolicy()) {
        super();

        this.policy = policy;

        this.assets = new Map();
        this.findings = new Map();
        this.sequence = 0;

        this.algorithmInspector = new AlgorithmInspector(policy);
        this.keyInspector = new KeyLifecycleInspector(policy);
        this.certificateInspector = new CertificateInspector(policy);
    }

    registerAsset(asset) {
        requireString(asset.id, "asset ID");

        if (this.assets.has(asset.id)) {
            throw new ValidationError(
                `Duplicate asset: ${asset.id}`
            );
        }

        this.assets.set(asset.id, Object.freeze({...asset}));

        this.emit("asset:registered", {
            assetId: asset.id
        });
    }

    addFindings(assetId, detected) {
        const created = [];

        for (const item of detected) {
            const id = `CRYPTO-${String(++this.sequence).padStart(5, "0")}`;

            const finding = new SecurityFinding({
                id,
                assetId,
                ...item
            });

            this.findings.set(id, finding);
            created.push(finding);

            this.emit("finding:created", {
                id,
                assetId,
                severity: finding.severity
            });
        }

        return created;
    }

    async assessAsset(assetId) {
        const asset = this.assets.get(assetId);

        if (!asset) {
            throw new ValidationError("Unknown asset.");
        }

        // Yield to the event loop so batch assessment remains cooperative.
        await new Promise(resolve => setImmediate(resolve));

        const findings = this.algorithmInspector.inspect(asset);

        return this.addFindings(assetId, findings);
    }

    assessKey(key) {
        const findings = this.keyInspector.inspect(key);

        return this.addFindings(key.id, findings);
    }

    assessCertificate(cert, hostname) {
        const findings = this.certificateInspector.inspect(
            cert,
            hostname
        );

        return this.addFindings(cert.id, findings);
    }

    updateFinding(id, nextStatus) {
        const finding = this.findings.get(id);

        if (!finding) {
            throw new ValidationError("Finding not found.");
        }

        const previous = finding.status;

        finding.transition(nextStatus);

        this.emit("finding:updated", {
            id,
            previous,
            current: finding.status
        });
    }

    riskScore() {
        let score = 0;

        for (const finding of this.findings.values()) {
            if (finding.status === Status.OPEN) {
                score += SEVERITY_WEIGHT[finding.severity];
            }
        }

        return Math.min(score, 100);
    }

    riskLevel(score = this.riskScore()) {
        if (score >= 30) return "CRITICAL";
        if (score >= 18) return "HIGH";
        if (score >= 8) return "MEDIUM";
        if (score > 0) return "LOW";

        return "NO_OPEN_FINDINGS";
    }

    report() {
        const findings = [...this.findings.values()];

        const countBy = (property) => {
            const result = {};

            for (const item of findings) {
                result[item[property]] =
                    (result[item[property]] || 0) + 1;
            }

            return result;
        };

        const score = this.riskScore();

        return {
            generatedAt: new Date().toISOString(),
            assetCount: this.assets.size,
            findingCount: findings.length,
            riskScore: score,
            riskLevel: this.riskLevel(score),
            severityDistribution: countBy("severity"),
            statusDistribution: countBy("status"),
            findings: findings.map(item => ({...item}))
        };
    }

    async exportReport(filename) {
        requireString(filename, "filename");

        const destination = path.resolve(filename);

        // Report data contains metadata only, never raw keys or passwords.
        await fs.writeFile(
            destination,
            JSON.stringify(this.report(), null, 2),
            {
                encoding: "utf8",
                mode: 0o600,
                flag: "w"
            }
        );

        return destination;
    }
}


/* ======================================================
   CONCURRENCY CONTROL
====================================================== */

async function assessInBatches(service, assetIds, concurrency = 4) {
    requirePositiveInteger(concurrency, "concurrency");

    const results = new Array(assetIds.length);
    let nextIndex = 0;

    async function worker() {
        while (true) {
            const index = nextIndex++;

            if (index >= assetIds.length) {
                return;
            }

            results[index] = await service.assessAsset(
                assetIds[index]
            );
        }
    }

    const workers = Array.from(
        {length: Math.min(concurrency, assetIds.length)},
        () => worker()
    );

    await Promise.all(workers);

    return results;
}


/* ======================================================
   DEMONSTRATION
====================================================== */

async function demonstration() {
    const service = new SecurityReviewService();

    service.on("finding:created", event => {
        console.log(
            `[EVENT] ${event.id}: ${event.severity}`
        );
    });

    service.on("finding:updated", event => {
        console.log(
            `[STATUS] ${event.id}: ${event.previous} -> ${event.current}`
        );
    });

    const assets = [
        {
            id: "ASSET-001",
            algorithm: "MD5"
        },
        {
            id: "ASSET-002",
            algorithm: "AES",
            mode: "ECB",
            authenticated: false,
            keyBits: 256
        },
        {
            id: "ASSET-003",
            algorithm: "RSA",
            keyBits: 1024,
            tlsVersion: "TLS1.0"
        },
        {
            id: "ASSET-004",
            algorithm: "AES-256",
            keyBits: 256,
            mode: "GCM",
            authenticated: true,
            randomnessSource: "math.random"
        },
        {
            id: "ASSET-005",
            algorithm: "AES-256",
            keyBits: 256,
            mode: "GCM",
            authenticated: true,
            randomnessSource: "crypto.randomBytes"
        }
    ];

    for (const asset of assets) {
        service.registerAsset(asset);
    }

    await assessInBatches(
        service,
        assets.map(asset => asset.id),
        3
    );

    const now = new Date();

    service.assessKey({
        id: "KEY-001",
        algorithm: "RSA",
        bits: 1024,
        createdAt: new Date(
            now.getTime() - 600 * 86400000
        ),
        lastRotatedAt: new Date(
            now.getTime() - 500 * 86400000
        ),
        storage: "LOCAL_FILE",
        exportable: true,
        exposed: true
    });

    service.assessCertificate({
        id: "CERT-001",
        notBefore: new Date(
            now.getTime() - 500 * 86400000
        ),
        notAfter: new Date(
            now.getTime() - 5 * 86400000
        ),
        hostname: "old.example.com",
        signatureAlgorithm: "SHA1WITHRSA",
        publicKeyAlgorithm: "RSA",
        publicKeyBits: 1024,
        trustedIssuer: false,
        chainValid: false,
        revoked: true
    }, "api.example.com");

    const firstFinding = service.findings.values().next().value;

    if (firstFinding) {
        service.updateFinding(
            firstFinding.id,
            Status.IN_REVIEW
        );
    }

    console.log("\nSECURITY ASSESSMENT REPORT");

    const report = service.report();

    console.log(JSON.stringify({
        assetCount: report.assetCount,
        findingCount: report.findingCount,
        riskScore: report.riskScore,
        riskLevel: report.riskLevel,
        severityDistribution: report.severityDistribution
    }, null, 2));

    const output = await service.exportReport(
        "./crypto-security-report.json"
    );

    console.log(`Report written to ${output}`);
}


/* ======================================================
   TESTS
====================================================== */

async function runTests() {
    const policy = new SecurityPolicy();
    const inspector = new AlgorithmInspector(policy);

    const weak = inspector.inspect({
        id: "TEST-001",
        algorithm: "MD5"
    });

    assert.equal(weak.length, 1);
    assert.equal(weak[0].severity, Severity.HIGH);

    const modern = inspector.inspect({
        id: "TEST-002",
        algorithm: "AES-256",
        mode: "GCM",
        authenticated: true,
        randomnessSource: "crypto.randomBytes"
    });

    assert.equal(modern.length, 0);

    const certificateInspector = new CertificateInspector(policy);

    assert.equal(
        certificateInspector.hostnameMatches(
            "*.example.com",
            "api.example.com"
        ),
        true
    );

    assert.equal(
        certificateInspector.hostnameMatches(
            "*.example.com",
            "a.b.example.com"
        ),
        false
    );

    const finding = new SecurityFinding({
        id: "F1",
        assetId: "A1",
        category: Category.ALGORITHM,
        severity: Severity.HIGH,
        title: "Weak algorithm",
        description: "Test",
        recommendation: "Replace algorithm"
    });

    finding.transition(Status.IN_REVIEW);
    finding.transition(Status.REMEDIATED);

    assert.throws(
        () => finding.transition(Status.OPEN),
        PolicyError
    );

    const keyInspector = new KeyLifecycleInspector(policy);

    assert.throws(
        () => keyInspector.inspect({
            id: "K1",
            algorithm: "RSA",
            bits: 2048,
            createdAt: "invalid",
            storage: "HSM",
            exportable: false
        }),
        ValidationError
    );

    console.log("All JavaScript tests passed.");
}


/* ======================================================
   ENTRY POINT
====================================================== */

if (require.main === module) {
    (async () => {
        try {
            await runTests();
            await demonstration();
        } catch (error) {
            console.error(
                "Security review failed:",
                error.message
            );

            process.exitCode = 1;
        }
    })();
}

module.exports = {
    SecurityPolicy,
    AlgorithmInspector,
    KeyLifecycleInspector,
    CertificateInspector,
    SecurityReviewService,
    SecurityFinding,
    Severity,
    Category,
    Status
};
