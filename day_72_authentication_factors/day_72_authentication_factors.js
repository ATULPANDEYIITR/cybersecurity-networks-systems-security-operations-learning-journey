"use strict";

/*
 * Authentication Factors
 * Passwords, MFA, Hardware Tokens, Biometrics and Adaptive Authentication.
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const { EventEmitter } = require("node:events");

const Factor = Object.freeze({
    PASSWORD: "password",
    TOTP: "totp",
    HARDWARE: "hardware_token",
    BIOMETRIC: "biometric"
});

const Status = Object.freeze({
    SUCCESS: "success",
    REJECTED: "rejected",
    MFA_REQUIRED: "mfa_required",
    STEP_UP_REQUIRED: "step_up_required",
    LOCKED: "locked"
});

const Risk = Object.freeze({
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical"
});

class AuthenticationError extends Error {
    constructor(message) {
        super(message);
        this.name = "AuthenticationError";
    }
}

function constantTimeEqual(left, right) {
    const a = Buffer.from(String(left));
    const b = Buffer.from(String(right));

    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

class PasswordManager {
    static async create(password) {
        if (typeof password !== "string" ||
            password.length < 12 ||
            password.length > 1024) {
            throw new AuthenticationError(
                "Password must contain between 12 and 1024 characters."
            );
        }

        const salt = crypto.randomBytes(16);

        const hash = await new Promise((resolve, reject) => {
            crypto.scrypt(password, salt, 64, (error, derivedKey) => {
                if (error) reject(error);
                else resolve(derivedKey.toString("hex"));
            });
        });

        return {
            algorithm: "scrypt",
            salt: salt.toString("hex"),
            hash,
            failures: 0,
            lockedUntil: 0
        };
    }

    static async verify(password, credential) {
        if (!credential || credential.algorithm !== "scrypt") {
            throw new AuthenticationError("Unsupported credential.");
        }

        const candidate = await new Promise((resolve, reject) => {
            crypto.scrypt(
                password,
                Buffer.from(credential.salt, "hex"),
                64,
                (error, derivedKey) => {
                    if (error) reject(error);
                    else resolve(derivedKey.toString("hex"));
                }
            );
        });

        return constantTimeEqual(candidate, credential.hash);
    }
}

class TotpManager {
    static createSecret() {
        return crypto.randomBytes(20);
    }

    static generate(secret, timestamp = Date.now()) {
        const counter = BigInt(Math.floor(timestamp / 30000));

        const message = Buffer.alloc(8);
        message.writeBigUInt64BE(counter);

        const digest = crypto
            .createHmac("sha1", secret)
            .update(message)
            .digest();

        const offset = digest[digest.length - 1] & 0x0f;

        const binary = digest.readUInt32BE(offset) & 0x7fffffff;

        return String(binary % 1000000).padStart(6, "0");
    }

    static verify(secret, submitted, timestamp = Date.now()) {
        if (!/^\d{6}$/.test(String(submitted))) return false;

        for (let offset = -1; offset <= 1; offset++) {
            const expected = this.generate(
                secret,
                timestamp + offset * 30000
            );

            if (constantTimeEqual(expected, submitted)) return true;
        }

        return false;
    }
}

class HardwareTokenManager {
    static challenge() {
        return crypto.randomBytes(32).toString("hex");
    }

    // Demonstration only. Production should verify WebAuthn public-key assertions.
    static createDemoAssertion(secret, challenge) {
        return crypto
            .createHmac("sha256", secret)
            .update(challenge)
            .digest("hex");
    }

    static verify(secret, challenge, assertion) {
        if (!secret || !challenge || !assertion) return false;

        const expected = this.createDemoAssertion(secret, challenge);
        return constantTimeEqual(expected, assertion);
    }
}

class BiometricManager {
    // The platform performs biometric matching; this service checks its result.
    static verify(attestation) {
        return Boolean(
            attestation &&
            attestation.verified === true &&
            attestation.userPresent === true &&
            attestation.trustedPlatform === true
        );
    }
}

class AdaptiveRiskEngine {
    static evaluate(context) {
        const signals = new Map([
            ["newDevice", 25],
            ["impossibleTravel", 55],
            ["unusualTime", 15],
            ["sensitiveAction", 20]
        ]);

        let score = 0;

        for (const [signal, weight] of signals) {
            if (context[signal] === true) score += weight;
        }

        let level = Risk.LOW;

        if (score >= 70) level = Risk.CRITICAL;
        else if (score >= 45) level = Risk.HIGH;
        else if (score >= 20) level = Risk.MEDIUM;

        return Object.freeze({ score, level });
    }
}

class AuditLogger {
    constructor() {
        this.events = [];
    }

    record(username, event, details = {}) {
        // Never include credentials, secrets, codes or biometric templates.
        this.events.push(Object.freeze({
            timestamp: new Date().toISOString(),
            username,
            event,
            details: Object.freeze({ ...details })
        }));
    }

    async export(filename) {
        const safeName = String(filename);

        if (safeName !== require("node:path").basename(safeName)) {
            throw new AuthenticationError("Invalid audit filename.");
        }

        await fs.writeFile(
            safeName,
            JSON.stringify(this.events, null, 2),
            { encoding: "utf8", mode: 0o600 }
        );
    }
}

class AuthenticationService extends EventEmitter {
    constructor() {
        super();
        this.users = new Map();
        this.audit = new AuditLogger();
        this.maxFailures = 5;
        this.lockDuration = 300000;
    }

    async register(username, password, enabledFactors = [
        Factor.PASSWORD,
        Factor.TOTP
    ]) {
        if (typeof username !== "string" ||
            username.length < 3 ||
            username.length > 100) {
            throw new AuthenticationError("Invalid username.");
        }

        if (this.users.has(username)) {
            throw new AuthenticationError("User already exists.");
        }

        const factors = new Set(enabledFactors);

        if (!factors.has(Factor.PASSWORD)) {
            throw new AuthenticationError("Password is required.");
        }

        const supported = new Set(Object.values(Factor));

        for (const factor of factors) {
            if (!supported.has(factor)) {
                throw new AuthenticationError(`Unsupported factor: ${factor}`);
            }
        }

        const user = {
            id: crypto.randomUUID(),
            username,
            credential: await PasswordManager.create(password),
            factors,
            totpSecret: factors.has(Factor.TOTP)
                ? TotpManager.createSecret()
                : null,
            hardwareSecret: factors.has(Factor.HARDWARE)
                ? crypto.randomBytes(32)
                : null,
            biometricRegistered: factors.has(Factor.BIOMETRIC),
            lastLogin: null
        };

        this.users.set(username, user);

        this.emit("userRegistered", {
            username,
            factorCount: factors.size
        });

        return {
            id: user.id,
            username,
            factors: [...factors],
            totpSecret: user.totpSecret?.toString("hex") ?? null
        };
    }

    async authenticate(username, password, context, submitted = {}) {
        const user = this.users.get(username);

        if (!user) {
            this.audit.record(username, "unknown_user");
            return this.result(Status.REJECTED, "Invalid credentials.");
        }

        const now = Date.now();

        if (now < user.credential.lockedUntil) {
            return this.result(Status.LOCKED, "Account temporarily locked.");
        }

        const passwordValid = await PasswordManager.verify(
            password,
            user.credential
        );

        if (!passwordValid) {
            user.credential.failures++;

            if (user.credential.failures >= this.maxFailures) {
                user.credential.lockedUntil = now + this.lockDuration;
            }

            this.audit.record(username, "password_failure", {
                failures: user.credential.failures
            });

            return this.result(
                user.credential.lockedUntil > now
                    ? Status.LOCKED
                    : Status.REJECTED,
                "Invalid credentials."
            );
        }

        user.credential.failures = 0;

        const risk = AdaptiveRiskEngine.evaluate(context);

        const required = [Factor.PASSWORD];

        if (user.factors.has(Factor.TOTP)) {
            required.push(Factor.TOTP);
        }

        if ([Risk.HIGH, Risk.CRITICAL].includes(risk.level)) {
            if (user.factors.has(Factor.HARDWARE)) {
                required.push(Factor.HARDWARE);
            } else if (user.factors.has(Factor.BIOMETRIC)) {
                required.push(Factor.BIOMETRIC);
            }
        }

        if (context.sensitiveAction &&
            user.factors.has(Factor.BIOMETRIC) &&
            !required.includes(Factor.BIOMETRIC)) {
            required.push(Factor.BIOMETRIC);
        }

        const completed = [Factor.PASSWORD];

        if (required.includes(Factor.TOTP)) {
            if (!TotpManager.verify(user.totpSecret, submitted.totp)) {
                return this.result(
                    Status.MFA_REQUIRED,
                    "TOTP verification required.",
                    risk,
                    required,
                    completed
                );
            }

            completed.push(Factor.TOTP);
        }

        if (required.includes(Factor.HARDWARE)) {
            const valid = HardwareTokenManager.verify(
                user.hardwareSecret,
                submitted.challenge,
                submitted.assertion
            );

            if (!valid) {
                return this.result(
                    Status.STEP_UP_REQUIRED,
                    "Hardware-token verification required.",
                    risk,
                    required,
                    completed
                );
            }

            completed.push(Factor.HARDWARE);
        }

        if (required.includes(Factor.BIOMETRIC)) {
            if (!BiometricManager.verify(submitted.biometric)) {
                return this.result(
                    Status.STEP_UP_REQUIRED,
                    "Trusted biometric verification required.",
                    risk,
                    required,
                    completed
                );
            }

            completed.push(Factor.BIOMETRIC);
        }

        user.lastLogin = now;

        this.audit.record(username, "authentication_success", {
            riskScore: risk.score,
            riskLevel: risk.level,
            completed
        });

        this.emit("authenticated", {
            username,
            riskLevel: risk.level
        });

        return this.result(
            Status.SUCCESS,
            "Authentication successful.",
            risk,
            required,
            completed
        );
    }

    result(status, message, risk = { score: 0, level: Risk.LOW },
           required = [], completed = []) {
        return Object.freeze({
            status,
            message,
            risk,
            required,
            completed
        });
    }
}

async function runTests() {
    const assert = require("node:assert/strict");

    const password = await PasswordManager.create("SecurePassword!2026");

    assert.equal(
        await PasswordManager.verify("SecurePassword!2026", password),
        true
    );

    assert.equal(
        await PasswordManager.verify("IncorrectPassword", password),
        false
    );

    const secret = TotpManager.createSecret();
    const timestamp = 1800000000000;
    const code = TotpManager.generate(secret, timestamp);

    assert.equal(TotpManager.verify(secret, code, timestamp), true);
    assert.equal(TotpManager.verify(secret, "invalid", timestamp), false);

    const hardwareSecret = crypto.randomBytes(32);
    const challenge = HardwareTokenManager.challenge();

    const assertion = HardwareTokenManager.createDemoAssertion(
        hardwareSecret,
        challenge
    );

    assert.equal(
        HardwareTokenManager.verify(hardwareSecret, challenge, assertion),
        true
    );

    assert.equal(
        BiometricManager.verify({
            verified: true,
            userPresent: true,
            trustedPlatform: true
        }),
        true
    );

    assert.equal(
        BiometricManager.verify({
            verified: true,
            userPresent: true,
            trustedPlatform: false
        }),
        false
    );

    const highRisk = AdaptiveRiskEngine.evaluate({
        newDevice: true,
        impossibleTravel: true
    });

    assert.equal(highRisk.score, 80);
    assert.equal(highRisk.level, Risk.CRITICAL);

    const service = new AuthenticationService();

    let registered = false;

    service.on("userRegistered", () => {
        registered = true;
    });

    const user = await service.register(
        "admin@example.com",
        "SecurePassword!2026",
        [
            Factor.PASSWORD,
            Factor.TOTP,
            Factor.HARDWARE,
            Factor.BIOMETRIC
        ]
    );

    assert.equal(registered, true);

    const result = await service.authenticate(
        user.username,
        "SecurePassword!2026",
        {
            newDevice: false,
            impossibleTravel: false,
            unusualTime: false,
            sensitiveAction: false
        },
        {
            totp: TotpManager.generate(
                Buffer.from(user.totpSecret, "hex")
            )
        }
    );

    assert.equal(result.status, Status.SUCCESS);

    console.log("All authentication tests passed.");
    console.log(JSON.stringify(result, null, 2));
}

async function main() {
    const service = new AuthenticationService();

    service.on("authenticated", event => {
        console.log("Authentication event:", event);
    });

    const user = await service.register(
        "security@example.com",
        "EnterprisePassword!2026",
        [
            Factor.PASSWORD,
            Factor.TOTP,
            Factor.HARDWARE,
            Factor.BIOMETRIC
        ]
    );

    const result = await service.authenticate(
        user.username,
        "EnterprisePassword!2026",
        {
            newDevice: true,
            impossibleTravel: false,
            unusualTime: false,
            sensitiveAction: false
        },
        {
            totp: TotpManager.generate(
                Buffer.from(user.totpSecret, "hex")
            )
        }
    );

    console.log("\nAUTHENTICATION RESULT");
    console.log(JSON.stringify(result, null, 2));

    await runTests();
}

main().catch(error => {
    console.error("Authentication system failure:", error.message);
    process.exitCode = 1;
});
