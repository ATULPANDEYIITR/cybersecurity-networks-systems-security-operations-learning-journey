"use strict";

/*
 * Identity and Access Management
 * Event-driven authentication, authorization, accounting,
 * lifecycle policies, and session management.
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const EventEmitter = require("node:events");

const IdentityStatus = Object.freeze({
    PENDING: "PENDING",
    ACTIVE: "ACTIVE",
    SUSPENDED: "SUSPENDED",
    DISABLED: "DISABLED",
    TERMINATED: "TERMINATED"
});

const ReviewState = Object.freeze({
    ALLOW: "ALLOW",
    DENY: "DENY"
});

const Permissions = Object.freeze({
    READ: "document:read",
    WRITE: "document:write",
    DELETE: "document:delete",
    MANAGE_USERS: "users:manage",
    MANAGE_ROLES: "roles:manage",
    READ_AUDIT: "audit:read"
});

const RolePermissions = new Map([
    ["EMPLOYEE", new Set([
        Permissions.READ,
        Permissions.WRITE
    ])],
    ["MANAGER", new Set([
        Permissions.READ,
        Permissions.WRITE,
        Permissions.DELETE
    ])],
    ["SECURITY_ADMIN", new Set(Object.values(Permissions))],
    ["AUDITOR", new Set([
        Permissions.READ,
        Permissions.READ_AUDIT
    ])]
]);

class IAMError extends Error {}
class AuthenticationError extends IAMError {}
class AuthorizationError extends IAMError {}
class LifecycleError extends IAMError {}

function validateUsername(username) {
    if (typeof username !== "string") {
        throw new TypeError("Username must be a string");
    }

    const normalized = username.trim().toLowerCase();

    if (!/^[a-z0-9._-]{3,100}$/.test(normalized)) {
        throw new TypeError("Invalid username");
    }

    return normalized;
}

function validatePassword(password) {
    if (
        typeof password !== "string" ||
        password.length < 12 ||
        password.length > 1024
    ) {
        throw new TypeError("Password must contain 12 to 1024 characters");
    }
}

function derivePassword(password, salt) {
    return crypto.pbkdf2Sync(
        password,
        salt,
        310000,
        32,
        "sha256"
    );
}

function safeEqual(first, second) {
    return first.length === second.length &&
        crypto.timingSafeEqual(first, second);
}

class Identity {
    constructor({ id, username, email, salt, passwordHash }) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.salt = salt;
        this.passwordHash = passwordHash;
        this.status = IdentityStatus.PENDING;
        this.roles = new Set();
        this.mfaEnabled = false;
        this.failedAttempts = 0;
        this.version = 1;
        this.createdAt = new Date();
    }
}

class AuditLedger {
    constructor() {
        this.events = [];
        this.listeners = new EventEmitter();
    }

    record(type, identityId, details = {}) {
        const event = Object.freeze({
            eventId: crypto.randomUUID(),
            type,
            identityId: identityId ?? null,
            details: Object.freeze({ ...details }),
            timestamp: new Date().toISOString()
        });

        this.events.push(event);
        this.listeners.emit("audit", event);

        return event;
    }

    subscribe(callback) {
        this.listeners.on("audit", callback);

        return () => {
            this.listeners.off("audit", callback);
        };
    }

    report() {
        const counts = new Map();

        for (const event of this.events) {
            counts.set(
                event.type,
                (counts.get(event.type) || 0) + 1
            );
        }

        return Object.fromEntries(counts);
    }

    async export(filename) {
        await fs.writeFile(
            filename,
            JSON.stringify(this.events, null, 2),
            { encoding: "utf8", mode: 0o600 }
        );
    }
}

class AccessPolicy {
    constructor() {
        this.deniedIdentities = new Set();
    }

    evaluate(identity, permission, resource) {
        if (!identity || identity.status !== IdentityStatus.ACTIVE) {
            return {
                decision: ReviewState.DENY,
                reason: "IDENTITY_NOT_ACTIVE"
            };
        }

        if (this.deniedIdentities.has(identity.id)) {
            return {
                decision: ReviewState.DENY,
                reason: "EXPLICIT_DENY"
            };
        }

        if (
            typeof resource !== "string" ||
            resource.length === 0 ||
            resource.length > 500
        ) {
            return {
                decision: ReviewState.DENY,
                reason: "INVALID_RESOURCE"
            };
        }

        // Role permissions are combined as grants.
        const granted = [...identity.roles].some(role => {
            const permissions = RolePermissions.get(role);
            return permissions?.has(permission) ?? false;
        });

        return granted
            ? {
                decision: ReviewState.ALLOW,
                reason: "ROLE_PERMISSION_MATCH"
            }
            : {
                decision: ReviewState.DENY,
                reason: "PERMISSION_NOT_GRANTED"
            };
    }

    denyIdentity(identityId) {
        this.deniedIdentities.add(identityId);
    }

    restoreIdentity(identityId) {
        this.deniedIdentities.delete(identityId);
    }
}

class IAMService {
    constructor({
        maxAttempts = 5,
        sessionDurationMs = 30 * 60 * 1000,
        lockoutDurationMs = 15 * 60 * 1000
    } = {}) {
        if (
            !Number.isInteger(maxAttempts) ||
            maxAttempts < 1 ||
            sessionDurationMs <= 0 ||
            lockoutDurationMs <= 0
        ) {
            throw new RangeError("Invalid IAM configuration");
        }

        this.identities = new Map();
        this.usernameIndex = new Map();
        this.sessions = new Map();
        this.lockouts = new Map();

        this.maxAttempts = maxAttempts;
        this.sessionDurationMs = sessionDurationMs;
        this.lockoutDurationMs = lockoutDurationMs;

        this.audit = new AuditLedger();
        this.policy = new AccessPolicy();
    }

    createIdentity(username, email, password) {
        username = validateUsername(username);
        validatePassword(password);

        if (
            typeof email !== "string" ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        ) {
            throw new TypeError("Invalid email");
        }

        if (this.usernameIndex.has(username)) {
            throw new LifecycleError("Username already exists");
        }

        const salt = crypto.randomBytes(16);
        const passwordHash = derivePassword(password, salt);

        const identity = new Identity({
            id: crypto.randomUUID(),
            username,
            email: email.toLowerCase(),
            salt,
            passwordHash
        });

        this.identities.set(identity.id, identity);
        this.usernameIndex.set(username, identity.id);

        this.audit.record("IDENTITY_CREATED", identity.id);

        return identity.id;
    }

    getIdentity(id) {
        const identity = this.identities.get(id);

        if (!identity) {
            throw new LifecycleError("Identity not found");
        }

        return identity;
    }

    activate(id) {
        const identity = this.getIdentity(id);

        if (identity.status !== IdentityStatus.PENDING) {
            throw new LifecycleError("Invalid activation transition");
        }

        identity.status = IdentityStatus.ACTIVE;
        identity.version++;

        this.audit.record("IDENTITY_ACTIVATED", id);
    }

    assignRole(id, role) {
        const identity = this.getIdentity(id);

        if (identity.status !== IdentityStatus.ACTIVE) {
            throw new LifecycleError("Identity must be active");
        }

        if (!RolePermissions.has(role)) {
            throw new TypeError("Unknown role");
        }

        if (identity.roles.has(role)) {
            throw new LifecycleError("Role already assigned");
        }

        identity.roles.add(role);
        identity.version++;

        this.audit.record("ROLE_ASSIGNED", id, { role });
    }

    removeRole(id, role) {
        const identity = this.getIdentity(id);

        if (!identity.roles.has(role)) {
            throw new LifecycleError("Role not assigned");
        }

        identity.roles.delete(role);
        identity.version++;

        this.audit.record("ROLE_REMOVED", id, { role });
    }

    enableMFA(id) {
        const identity = this.getIdentity(id);

        if (identity.status !== IdentityStatus.ACTIVE) {
            throw new LifecycleError("Identity must be active");
        }

        identity.mfaEnabled = true;
        identity.version++;
    }

    async authenticate(username, password, mfaVerified = false) {
        username = validateUsername(username);

        const id = this.usernameIndex.get(username);

        if (!id) {
            this.audit.record("LOGIN_FAILURE", null, {
                username,
                reason: "UNKNOWN_IDENTITY"
            });

            throw new AuthenticationError("Invalid credentials");
        }

        const identity = this.getIdentity(id);
        const now = Date.now();

        const lockedUntil = this.lockouts.get(id);

        if (lockedUntil && now < lockedUntil) {
            throw new AuthenticationError("Account temporarily locked");
        }

        if (identity.status !== IdentityStatus.ACTIVE) {
            throw new AuthenticationError("Identity is not active");
        }

        const candidate = derivePassword(password, identity.salt);

        if (!safeEqual(candidate, identity.passwordHash)) {
            identity.failedAttempts++;

            this.audit.record("LOGIN_FAILURE", id, {
                reason: "INVALID_CREDENTIALS"
            });

            if (identity.failedAttempts >= this.maxAttempts) {
                this.lockouts.set(
                    id,
                    now + this.lockoutDurationMs
                );
            }

            throw new AuthenticationError("Invalid credentials");
        }

        if (identity.mfaEnabled && mfaVerified !== true) {
            this.audit.record("LOGIN_FAILURE", id, {
                reason: "MFA_REQUIRED"
            });

            throw new AuthenticationError("MFA verification required");
        }

        identity.failedAttempts = 0;
        this.lockouts.delete(id);

        const token = crypto.randomBytes(32).toString("base64url");

        const session = {
            token,
            identityId: id,
            createdAt: now,
            expiresAt: now + this.sessionDurationMs,
            revoked: false
        };

        this.sessions.set(token, session);

        this.audit.record("LOGIN_SUCCESS", id);

        return token;
    }

    authorize(token, permission, resource) {
        const session = this.sessions.get(token);

        if (!session || session.revoked) {
            throw new AuthorizationError("Invalid session");
        }

        if (Date.now() >= session.expiresAt) {
            session.revoked = true;

            this.audit.record("SESSION_EXPIRED", session.identityId);

            throw new AuthorizationError("Session expired");
        }

        const identity = this.getIdentity(session.identityId);

        const result = this.policy.evaluate(
            identity,
            permission,
            resource
        );

        this.audit.record(
            result.decision === ReviewState.ALLOW
                ? "ACCESS_GRANTED"
                : "ACCESS_DENIED",
            identity.id,
            {
                permission,
                resource,
                reason: result.reason
            }
        );

        return Object.freeze(result);
    }

    logout(token) {
        const session = this.sessions.get(token);

        if (!session || session.revoked) {
            return;
        }

        session.revoked = true;

        this.audit.record("LOGOUT", session.identityId);
    }

    revokeAllSessions(id) {
        for (const session of this.sessions.values()) {
            if (
                session.identityId === id &&
                !session.revoked
            ) {
                session.revoked = true;
            }
        }
    }

    suspend(id) {
        const identity = this.getIdentity(id);

        if (identity.status !== IdentityStatus.ACTIVE) {
            throw new LifecycleError("Invalid suspension transition");
        }

        identity.status = IdentityStatus.SUSPENDED;
        identity.version++;

        this.revokeAllSessions(id);

        this.audit.record("IDENTITY_SUSPENDED", id);
    }

    disable(id) {
        const identity = this.getIdentity(id);

        if (
            identity.status === IdentityStatus.DISABLED ||
            identity.status === IdentityStatus.TERMINATED
        ) {
            throw new LifecycleError("Identity cannot be disabled again");
        }

        identity.status = IdentityStatus.DISABLED;
        identity.version++;

        this.revokeAllSessions(id);

        this.audit.record("IDENTITY_DISABLED", id);
    }

    terminate(id) {
        const identity = this.getIdentity(id);

        if (
            identity.status === IdentityStatus.PENDING ||
            identity.status === IdentityStatus.TERMINATED
        ) {
            throw new LifecycleError("Invalid termination transition");
        }

        identity.status = IdentityStatus.TERMINATED;
        identity.roles.clear();
        identity.version++;

        this.revokeAllSessions(id);

        this.audit.record("IDENTITY_TERMINATED", id);
    }

    reactivate(id) {
        const identity = this.getIdentity(id);

        if (identity.status !== IdentityStatus.SUSPENDED) {
            throw new LifecycleError("Only suspended identities can reactivate");
        }

        identity.status = IdentityStatus.ACTIVE;
        identity.version++;

        this.audit.record("IDENTITY_REACTIVATED", id);
    }

    async accountingReport() {
        return {
            totalEvents: this.audit.events.length,
            eventsByType: this.audit.report(),
            identitiesByStatus: Object.fromEntries(
                Object.values(IdentityStatus).map(status => [
                    status,
                    [...this.identities.values()].filter(
                        identity => identity.status === status
                    ).length
                ])
            ),
            activeSessions: [...this.sessions.values()].filter(
                session =>
                    !session.revoked &&
                    session.expiresAt > Date.now()
            ).length
        };
    }
}

async function main() {
    const iam = new IAMService();

    iam.audit.subscribe(event => {
        console.log(
            `[AUDIT] ${event.type} identity=${event.identityId ?? "unknown"}`
        );
    });

    const aliceId = iam.createIdentity(
        "alice",
        "alice@example.org",
        "Alice-Strong-Password-2026"
    );

    iam.activate(aliceId);
    iam.assignRole(aliceId, "EMPLOYEE");
    iam.enableMFA(aliceId);

    const token = await iam.authenticate(
        "alice",
        "Alice-Strong-Password-2026",
        true
    );

    const allowed = iam.authorize(
        token,
        Permissions.READ,
        "documents/report.pdf"
    );

    console.log("Read decision:", allowed);

    try {
        iam.authorize(
            token,
            Permissions.DELETE,
            "documents/report.pdf"
        );
    } catch (error) {
        console.log(error.message);
    }

    // Role removal is immediately reflected by policy evaluation.
    iam.removeRole(aliceId, "EMPLOYEE");

    try {
        iam.authorize(
            token,
            Permissions.READ,
            "documents/report.pdf"
        );
    } catch (error) {
        console.log("Expected denial:", error.message);
    }

    iam.logout(token);

    iam.suspend(aliceId);
    iam.reactivate(aliceId);

    console.log(
        "Accounting:",
        JSON.stringify(await iam.accountingReport(), null, 2)
    );

    await iam.audit.export("iam_audit.json");
}

main().catch(error => {
    console.error("IAM execution failed:", error.message);
    process.exitCode = 1;
});
