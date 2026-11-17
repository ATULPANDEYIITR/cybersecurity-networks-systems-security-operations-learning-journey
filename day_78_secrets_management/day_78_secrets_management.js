"use strict";

/*
 * Secrets Management Engine
 *
 * Event-driven secret lifecycle management using:
 * - Node.js cryptographic capabilities
 * - Asynchronous vault operations
 * - Map-based secret indexing
 * - Role-based access control
 * - Secret versioning and rotation
 * - Expiration monitoring
 * - Exposure scanning
 * - Event-driven audit records
 *
 * Run: node secrets-management.js
 *
 * This in-memory implementation is educational.
 * It does not provide encrypted persistent storage.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");

const SecretType = Object.freeze({
    API_KEY: "API_KEY",
    ACCESS_TOKEN: "ACCESS_TOKEN",
    REFRESH_TOKEN: "REFRESH_TOKEN",
    PASSWORD: "PASSWORD",
    DATABASE: "DATABASE",
    PRIVATE_KEY: "PRIVATE_KEY"
});

const SecretState = Object.freeze({
    ACTIVE: "ACTIVE",
    EXPIRED: "EXPIRED",
    REVOKED: "REVOKED"
});

const Permissions = Object.freeze({
    READ: "READ",
    WRITE: "WRITE",
    ROTATE: "ROTATE",
    REVOKE: "REVOKE",
    ADMIN: "ADMIN"
});

class SecretError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
    }
}

class AuthorizationError extends SecretError {}
class ValidationError extends SecretError {}
class NotFoundError extends SecretError {}
class RotationError extends SecretError {}
class ExpirationError extends SecretError {}

class SecretValidator {
    static validateName(name) {
        if (
            typeof name !== "string" ||
            !/^[a-zA-Z][a-zA-Z0-9_.-]{2,99}$/.test(name)
        ) {
            throw new ValidationError("Invalid secret name.");
        }
    }

    static validateValue(value) {
        if (
            typeof value !== "string" ||
            value.length === 0 ||
            value.length > 65536 ||
            value.includes("\0")
        ) {
            throw new ValidationError("Invalid secret value.");
        }
    }

    static validateEnvironment(environment) {
        const allowed = [
            "development",
            "testing",
            "staging",
            "production"
        ];

        if (!allowed.includes(environment)) {
            throw new ValidationError("Invalid environment.");
        }
    }

    static validateTTL(days) {
        if (!Number.isInteger(days) || days < 1 || days > 3650) {
            throw new ValidationError("TTL must be 1-3650 days.");
        }
    }
}

class Identity {
    constructor(id, roles) {
        if (!id || !Array.isArray(roles)) {
            throw new ValidationError("Invalid identity.");
        }

        this.id = id;
        this.roles = new Set(roles);
    }
}

class AccessControl {
    constructor() {
        this.rolePermissions = new Map([
            ["developer", new Set([Permissions.READ])],
            [
                "operator",
                new Set([Permissions.READ, Permissions.ROTATE])
            ],
            [
                "security_admin",
                new Set(Object.values(Permissions))
            ]
        ]);
    }

    authorize(identity, permission) {
        for (const role of identity.roles) {
            const permissions = this.rolePermissions.get(role);

            if (
                permissions &&
                (
                    permissions.has(Permissions.ADMIN) ||
                    permissions.has(permission)
                )
            ) {
                return true;
            }
        }

        return false;
    }

    require(identity, permission) {
        if (!this.authorize(identity, permission)) {
            throw new AuthorizationError(
                `${identity.id} cannot perform ${permission}.`
            );
        }
    }
}

class SecretGenerator {
    static generateAPIKey(bytes = 32) {
        if (!Number.isInteger(bytes) || bytes < 24 || bytes > 128) {
            throw new ValidationError("Invalid API key size.");
        }

        return crypto.randomBytes(bytes).toString("base64url");
    }

    static generatePassword(bytes = 32) {
        if (!Number.isInteger(bytes) || bytes < 16 || bytes > 128) {
            throw new ValidationError("Invalid password size.");
        }

        return crypto.randomBytes(bytes).toString("base64url");
    }

    static fingerprint(value) {
        return crypto
            .createHash("sha256")
            .update(value, "utf8")
            .digest("hex");
    }
}

class AuditLogger extends EventEmitter {
    constructor() {
        super();
        this.events = [];
    }

    record(event) {
        const safeEvent = Object.freeze({
            eventId: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            ...event
        });

        this.events.push(safeEvent);
        this.emit("audit", safeEvent);
    }

    getEvents() {
        return this.events.map(event => ({ ...event }));
    }

    async exportJSON(filePath) {
        if (!filePath.endsWith(".json")) {
            throw new ValidationError("Audit export must be JSON.");
        }

        const content = JSON.stringify(this.events, null, 2);

        await fs.writeFile(filePath, content, {
            encoding: "utf8",
            flag: "wx",
            mode: 0o600
        });
    }
}

class InMemoryVault {
    constructor(accessControl, auditLogger) {
        this.accessControl = accessControl;
        this.auditLogger = auditLogger;

        this.records = new Map();
        this.nameIndex = new Map();
    }

    audit(identity, action, secretId, outcome, details = "") {
        this.auditLogger.record({
            principal: identity.id,
            action,
            secretId,
            outcome,
            details
        });
    }

    async create(identity, input) {
        const secretId = crypto.randomUUID();

        try {
            this.accessControl.require(identity, Permissions.WRITE);

            SecretValidator.validateName(input.name);
            SecretValidator.validateValue(input.value);
            SecretValidator.validateEnvironment(input.environment);

            SecretValidator.validateTTL(input.ttlDays);

            if (!Object.values(SecretType).includes(input.type)) {
                throw new ValidationError("Unsupported secret type.");
            }

            if (!input.owner) {
                throw new ValidationError("Secret owner is required.");
            }

            const indexKey = `${input.environment}:${input.name}`;

            if (this.nameIndex.has(indexKey)) {
                throw new ValidationError(
                    "Secret already exists in this environment."
                );
            }

            const now = Date.now();

            const record = {
                id: secretId,
                name: input.name,
                type: input.type,
                environment: input.environment,
                owner: input.owner,
                tags: [...new Set(input.tags || [])],
                versions: [
                    {
                        version: 1,
                        value: input.value,
                        fingerprint: SecretGenerator.fingerprint(input.value),
                        createdAt: now,
                        expiresAt: now + input.ttlDays * 86400000,
                        state: SecretState.ACTIVE
                    }
                ]
            };

            this.records.set(secretId, record);
            this.nameIndex.set(indexKey, secretId);

            this.audit(identity, "CREATE", secretId, "SUCCESS");

            return secretId;

        } catch (error) {
            this.audit(
                identity,
                "CREATE",
                secretId,
                "FAILED",
                error.name
            );

            throw error;
        }
    }

    async retrieve(identity, secretId) {
        try {
            this.accessControl.require(identity, Permissions.READ);

            const record = this.records.get(secretId);

            if (!record) {
                throw new NotFoundError("Secret not found.");
            }

            const version = record.versions.at(-1);

            if (version.state === SecretState.REVOKED) {
                throw new SecretError("Secret is revoked.");
            }

            if (
                version.state === SecretState.EXPIRED ||
                Date.now() >= version.expiresAt
            ) {
                version.state = SecretState.EXPIRED;
                throw new ExpirationError("Secret has expired.");
            }

            this.audit(identity, "READ", secretId, "SUCCESS");

            return version.value;

        } catch (error) {
            this.audit(
                identity,
                "READ",
                secretId,
                "FAILED",
                error.name
            );

            throw error;
        }
    }

    async rotate(identity, secretId, newValue, ttlDays = 90) {
        try {
            this.accessControl.require(identity, Permissions.ROTATE);

            SecretValidator.validateValue(newValue);
            SecretValidator.validateTTL(ttlDays);

            const record = this.records.get(secretId);

            if (!record) {
                throw new NotFoundError("Secret not found.");
            }

            const previous = record.versions.at(-1);

            if (previous.state === SecretState.REVOKED) {
                throw new RotationError(
                    "Revoked secrets cannot be rotated."
                );
            }

            const fingerprint = SecretGenerator.fingerprint(newValue);

            if (
                crypto.timingSafeEqual(
                    Buffer.from(fingerprint, "hex"),
                    Buffer.from(previous.fingerprint, "hex")
                )
            ) {
                throw new RotationError(
                    "New secret must differ from the old secret."
                );
            }

            previous.state = SecretState.EXPIRED;

            const now = Date.now();

            const next = {
                version: previous.version + 1,
                value: newValue,
                fingerprint,
                createdAt: now,
                expiresAt: now + ttlDays * 86400000,
                state: SecretState.ACTIVE
            };

            record.versions.push(next);

            this.audit(
                identity,
                "ROTATE",
                secretId,
                "SUCCESS",
                `Version ${next.version}`
            );

            return next.version;

        } catch (error) {
            this.audit(
                identity,
                "ROTATE",
                secretId,
                "FAILED",
                error.name
            );

            throw error;
        }
    }

    async revoke(identity, secretId) {
        try {
            this.accessControl.require(identity, Permissions.REVOKE);

            const record = this.records.get(secretId);

            if (!record) {
                throw new NotFoundError("Secret not found.");
            }

            for (const version of record.versions) {
                version.state = SecretState.REVOKED;
                version.value = "";
            }

            this.audit(identity, "REVOKE", secretId, "SUCCESS");

        } catch (error) {
            this.audit(
                identity,
                "REVOKE",
                secretId,
                "FAILED",
                error.name
            );

            throw error;
        }
    }

    getMetadata(identity, secretId) {
        this.accessControl.require(identity, Permissions.READ);

        const record = this.records.get(secretId);

        if (!record) {
            throw new NotFoundError("Secret not found.");
        }

        const current = record.versions.at(-1);

        return {
            id: record.id,
            name: record.name,
            type: record.type,
            environment: record.environment,
            owner: record.owner,
            version: current.version,
            state: current.state,
            createdAt: new Date(current.createdAt).toISOString(),
            expiresAt: new Date(current.expiresAt).toISOString(),
            tags: [...record.tags]
        };
    }

    findExpiring(days = 15) {
        if (!Number.isInteger(days) || days < 0) {
            throw new ValidationError("Invalid monitoring period.");
        }

        const threshold = Date.now() + days * 86400000;

        return [...this.records.values()]
            .filter(record => {
                const current = record.versions.at(-1);

                return (
                    current.state === SecretState.ACTIVE &&
                    current.expiresAt <= threshold
                );
            })
            .map(record => record.id);
    }
}

class ExposureScanner {
    static patterns = [
        {
            name: "api_key",
            pattern: /api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9_-]{20,}/gi
        },
        {
            name: "password",
            pattern: /password\s*[:=]\s*["'][^"']{8,}["']/gi
        },
        {
            name: "bearer_token",
            pattern: /bearer\s+[A-Za-z0-9._~-]{20,}/gi
        },
        {
            name: "private_key",
            pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g
        }
    ];

    static scan(content) {
        if (typeof content !== "string") {
            throw new ValidationError("Content must be a string.");
        }

        const findings = [];

        for (const item of this.patterns) {
            for (const match of content.matchAll(item.pattern)) {
                findings.push({
                    category: item.name,
                    position: match.index,
                    severity: "HIGH"
                });
            }
        }

        return findings;
    }

    static redact(content) {
        let result = content;

        for (const item of this.patterns) {
            result = result.replace(item.pattern, "[REDACTED]");
        }

        return result;
    }
}

class RotationScheduler {
    constructor(vault, operator) {
        this.vault = vault;
        this.operator = operator;
    }

    async inspect(days = 15) {
        return this.vault.findExpiring(days);
    }

    async rotateWithGenerator(secretId, generator) {
        if (typeof generator !== "function") {
            throw new ValidationError("A secret generator is required.");
        }

        const newValue = generator();

        return this.vault.rotate(
            this.operator,
            secretId,
            newValue,
            90
        );
    }
}

async function main() {
    console.log("\nSECRETS MANAGEMENT ENGINE");
    console.log("=".repeat(55));

    const accessControl = new AccessControl();
    const audit = new AuditLogger();

    const vault = new InMemoryVault(accessControl, audit);

    audit.on("audit", event => {
        console.log(
            `[AUDIT] ${event.action}: ${event.outcome}`
        );
    });

    const admin = new Identity("security-team", ["security_admin"]);
    const developer = new Identity("developer-01", ["developer"]);
    const operator = new Identity("operator-01", ["operator"]);

    const secretId = await vault.create(admin, {
        name: "payment_api_key",
        value: SecretGenerator.generateAPIKey(),
        type: SecretType.API_KEY,
        environment: "production",
        owner: "payment-platform",
        ttlDays: 90,
        tags: ["payments", "external"]
    });

    console.log("\nCreated:", vault.getMetadata(admin, secretId));

    const retrieved = await vault.retrieve(developer, secretId);

    console.log(
        "\nRetrieved credential:",
        retrieved.slice(0, 5) + "********"
    );

    try {
        await vault.create(developer, {
            name: "unauthorized_secret",
            value: SecretGenerator.generateAPIKey(),
            type: SecretType.API_KEY,
            environment: "testing",
            owner: "developer",
            ttlDays: 90
        });
    } catch (error) {
        console.log("\nExpected authorization failure:", error.message);
    }

    const scheduler = new RotationScheduler(vault, operator);

    const newVersion = await scheduler.rotateWithGenerator(
        secretId,
        () => SecretGenerator.generateAPIKey()
    );

    console.log("\nRotated to version:", newVersion);

    const sample = [
        "api_key=example_api_key_12345678901234567890",
        "password='ExamplePassword123!'",
        "Authorization: Bearer example_token_12345678901234567890"
    ].join("\n");

    console.log("\nExposure findings:", ExposureScanner.scan(sample));
    console.log("\nRedacted content:\n", ExposureScanner.redact(sample));

    console.log(
        "\nExpiring credentials:",
        await scheduler.inspect(15)
    );

    console.log("\nMetadata:");
    console.log(vault.getMetadata(admin, secretId));

    await vault.revoke(admin, secretId);

    try {
        await vault.retrieve(developer, secretId);
    } catch (error) {
        console.log("\nRevoked retrieval blocked:", error.message);
    }

    console.log("\nAudit events:", audit.getEvents().length);

    if (vault.records.get(secretId).versions.length !== 2) {
        throw new Error("Versioning assertion failed.");
    }

    console.log("\nAll demonstration checks passed.");
}

main().catch(error => {
    console.error("Application failure:", error.message);
    process.exitCode = 1;
});
