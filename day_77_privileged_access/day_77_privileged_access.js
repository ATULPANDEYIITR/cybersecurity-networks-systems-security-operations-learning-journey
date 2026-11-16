"use strict";

/**
 * Privileged Access Management
 *
 * Event-driven PAM policy engine using Node.js built-in modules.
 *
 * Features:
 * - Privileged account inventory
 * - Group-based authorization
 * - Just-in-time access
 * - Approval workflows
 * - Separation of duties
 * - Credential isolation
 * - Session expiration and revocation
 * - Asynchronous audit events
 * - Policy evaluation
 *
 * Runtime: Node.js 18+
 *
 * The in-memory vault is a simulation, not a production
 * secrets-management implementation.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const EventEmitter = require("node:events");


const Privilege = Object.freeze({
    STANDARD: 1,
    ELEVATED: 2,
    ADMIN: 3,
    SUPER_ADMIN: 4
});

const AccountState = Object.freeze({
    ACTIVE: "ACTIVE",
    DISABLED: "DISABLED",
    LOCKED: "LOCKED"
});

const RequestState = Object.freeze({
    PENDING: "PENDING",
    APPROVED: "APPROVED",
    DENIED: "DENIED",
    ACTIVE: "ACTIVE",
    REVOKED: "REVOKED",
    EXPIRED: "EXPIRED"
});

const ReviewDecision = Object.freeze({
    APPROVE: "APPROVE",
    DENY: "DENY"
});


class PAMError extends Error {}
class ValidationError extends PAMError {}
class AuthorizationError extends PAMError {}
class WorkflowError extends PAMError {}
class NotFoundError extends PAMError {}


/**
 * Common validation functions.
 */
const validate = {

    required(value, field) {
        if (
            typeof value !== "string" ||
            value.trim().length === 0
        ) {
            throw new ValidationError(
                `${field} is required.`
            );
        }
    },

    duration(minutes, maximum) {
        if (
            !Number.isInteger(minutes) ||
            minutes < 1 ||
            minutes > maximum
        ) {
            throw new ValidationError(
                `Duration must be between 1 and ${maximum}.`
            );
        }
    },

    identifier(value, field) {
        this.required(value, field);

        if (!/^[A-Za-z0-9_-]{3,64}$/.test(value)) {
            throw new ValidationError(
                `Invalid ${field}.`
            );
        }
    }
};


/**
 * Credential isolation.
 *
 * No API exposes the stored secret.
 * The credential reference is a random opaque identifier.
 */
class CredentialVault {

    #records = new Map();

    provision(accountId, secret) {
        validate.required(accountId, "Account ID");

        if (
            typeof secret !== "string" ||
            Buffer.byteLength(secret, "utf8") < 16
        ) {
            throw new ValidationError(
                "Credential must contain at least 16 bytes."
            );
        }

        const reference = crypto.randomUUID();

        const fingerprint = crypto
            .createHash("sha256")
            .update(secret)
            .digest("hex");

        this.#records.set(accountId, {
            reference,
            fingerprint,
            provisionedAt: new Date().toISOString()
        });

        return reference;
    }

    getReference(accountId) {
        const record = this.#records.get(accountId);

        if (!record) {
            throw new PAMError(
                "Credential not available."
            );
        }

        return record.reference;
    }

    rotate(accountId, secret) {
        return this.provision(accountId, secret);
    }

    has(accountId) {
        return this.#records.has(accountId);
    }
}


/**
 * Immutable policy definition.
 */
class AccessPolicy {

    constructor({
        requireMFA = true,
        requireApproval = true,
        prohibitSelfApproval = true,
        maximumSessionMinutes = 60,
        requireJustification = true,
        requireActiveMembership = true
    } = {}) {

        if (
            !Number.isInteger(maximumSessionMinutes) ||
            maximumSessionMinutes < 1
        ) {
            throw new ValidationError(
                "Invalid maximum session duration."
            );
        }

        this.requireMFA = requireMFA;
        this.requireApproval = requireApproval;
        this.prohibitSelfApproval = prohibitSelfApproval;
        this.maximumSessionMinutes = maximumSessionMinutes;
        this.requireJustification = requireJustification;
        this.requireActiveMembership = requireActiveMembership;

        Object.freeze(this);
    }
}


/**
 * Event-driven policy and audit processing.
 */
class PAMEngine extends EventEmitter {

    #users = new Map();
    #groups = new Map();
    #accounts = new Map();
    #requests = new Map();
    #sessions = new Map();

    #vault = new CredentialVault();
    #policy;

    #mutex = Promise.resolve();

    constructor(policy = new AccessPolicy()) {
        super();
        this.#policy = policy;
    }

    /**
     * Serializes state-changing operations.
     *
     * A database implementation should use transactions,
     * row locks, or optimistic concurrency instead.
     */
    async #exclusive(operation) {
        const previous = this.#mutex;

        let release;

        this.#mutex = new Promise(resolve => {
            release = resolve;
        });

        await previous;

        try {
            return await operation();
        } finally {
            release();
        }
    }

    #emitAudit(action, actorId, resourceId, details = {}) {
        const event = Object.freeze({
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            action,
            actorId,
            resourceId,
            details
        });

        this.emit("audit", event);

        return event;
    }

    #user(id) {
        const user = this.#users.get(id);

        if (!user) {
            throw new NotFoundError("User not found.");
        }

        return user;
    }

    #account(id) {
        const account = this.#accounts.get(id);

        if (!account) {
            throw new NotFoundError("Account not found.");
        }

        return account;
    }

    #request(id) {
        const request = this.#requests.get(id);

        if (!request) {
            throw new NotFoundError("Request not found.");
        }

        return request;
    }

    #session(id) {
        const session = this.#sessions.get(id);

        if (!session) {
            throw new NotFoundError("Session not found.");
        }

        return session;
    }

    // --------------------------------------------------------
    // IDENTITY MANAGEMENT
    // --------------------------------------------------------

    async registerUser(user) {
        return this.#exclusive(async () => {
            validate.identifier(user.id, "user ID");
            validate.required(user.username, "Username");

            if (this.#users.has(user.id)) {
                throw new ValidationError(
                    "User already exists."
                );
            }

            const record = {
                id: user.id,
                username: user.username.trim(),
                department: user.department,
                active: user.active ?? true,
                mfaEnabled: user.mfaEnabled ?? false,
                roles: new Set(user.roles ?? [])
            };

            this.#users.set(record.id, record);

            this.#emitAudit(
                "USER_REGISTERED",
                record.id,
                record.id
            );
        });
    }

    async createGroup(group) {
        return this.#exclusive(async () => {
            validate.identifier(group.id, "group ID");
            validate.required(group.name, "Group name");

            if (this.#groups.has(group.id)) {
                throw new ValidationError(
                    "Group already exists."
                );
            }

            const record = {
                id: group.id,
                name: group.name,
                privilege: group.privilege,
                members: new Set(),
                maximumSessionMinutes:
                    group.maximumSessionMinutes ?? 60,
                approvalRequired:
                    group.approvalRequired ?? true
            };

            if (
                !Number.isInteger(record.maximumSessionMinutes) ||
                record.maximumSessionMinutes < 1
            ) {
                throw new ValidationError(
                    "Invalid session duration."
                );
            }

            this.#groups.set(record.id, record);
        });
    }

    async addMember(groupId, userId) {
        return this.#exclusive(async () => {
            const group = this.#groups.get(groupId);

            if (!group) {
                throw new NotFoundError("Group not found.");
            }

            const user = this.#user(userId);

            if (!user.active) {
                throw new AuthorizationError(
                    "Inactive users cannot join groups."
                );
            }

            group.members.add(userId);

            this.#emitAudit(
                "GROUP_MEMBER_ADDED",
                userId,
                groupId
            );
        });
    }

    // --------------------------------------------------------
    // PRIVILEGED ACCOUNT INVENTORY
    // --------------------------------------------------------

    async registerAccount(account, initialSecret) {
        return this.#exclusive(async () => {
            validate.identifier(account.id, "account ID");

            if (this.#accounts.has(account.id)) {
                throw new ValidationError(
                    "Account already exists."
                );
            }

            const groupIds = account.groupIds ?? [];

            for (const groupId of groupIds) {
                if (!this.#groups.has(groupId)) {
                    throw new NotFoundError(
                        `Unknown group: ${groupId}`
                    );
                }
            }

            this.#vault.provision(
                account.id,
                initialSecret
            );

            this.#accounts.set(account.id, {
                id: account.id,
                username: account.username,
                system: account.system,
                privilege: account.privilege,
                state: AccountState.ACTIVE,
                groupIds: new Set(groupIds),
                lastRotated: Date.now(),
                rotationIntervalDays:
                    account.rotationIntervalDays ?? 30
            });

            this.#emitAudit(
                "PRIVILEGED_ACCOUNT_CREATED",
                "SYSTEM",
                account.id
            );
        });
    }

    // --------------------------------------------------------
    // POLICY EVALUATION
    // --------------------------------------------------------

    #evaluateEligibility(user, account) {

        if (!user.active) {
            throw new AuthorizationError(
                "User account is inactive."
            );
        }

        if (
            this.#policy.requireMFA &&
            !user.mfaEnabled
        ) {
            throw new AuthorizationError(
                "MFA verification is required."
            );
        }

        if (account.state !== AccountState.ACTIVE) {
            throw new AuthorizationError(
                "Privileged account is unavailable."
            );
        }

        const memberships = [...account.groupIds]
            .map(id => this.#groups.get(id))
            .filter(group =>
                group &&
                group.members.has(user.id)
            );

        if (
            this.#policy.requireActiveMembership &&
            memberships.length === 0
        ) {
            throw new AuthorizationError(
                "No eligible privileged group membership."
            );
        }

        const maximum = Math.min(
            this.#policy.maximumSessionMinutes,
            ...memberships.map(
                group => group.maximumSessionMinutes
            )
        );

        return {
            memberships,
            maximum
        };
    }

    // --------------------------------------------------------
    // ACCESS REQUESTS
    // --------------------------------------------------------

    async requestAccess({
        userId,
        accountId,
        justification,
        durationMinutes
    }) {

        return this.#exclusive(async () => {
            const user = this.#user(userId);
            const account = this.#account(accountId);

            const eligibility = this.#evaluateEligibility(
                user,
                account
            );

            if (
                this.#policy.requireJustification &&
                (!justification || !justification.trim())
            ) {
                throw new ValidationError(
                    "Business justification is mandatory."
                );
            }

            validate.duration(
                durationMinutes,
                eligibility.maximum
            );

            const requiresApproval =
                this.#policy.requireApproval ||
                eligibility.memberships.some(
                    group => group.approvalRequired
                );

            const request = {
                id: crypto.randomUUID(),
                userId,
                accountId,
                justification: justification.trim(),
                durationMinutes,
                requiresApproval,
                state: requiresApproval
                    ? RequestState.PENDING
                    : RequestState.APPROVED,
                approverId: null,
                createdAt: new Date().toISOString()
            };

            this.#requests.set(request.id, request);

            this.#emitAudit(
                "ACCESS_REQUESTED",
                userId,
                request.id,
                { accountId, durationMinutes }
            );

            return { ...request };
        });
    }

    // --------------------------------------------------------
    // APPROVAL AND SEPARATION OF DUTIES
    // --------------------------------------------------------

    async reviewRequest(requestId, approverId, decision) {

        return this.#exclusive(async () => {
            const request = this.#request(requestId);
            const approver = this.#user(approverId);

            if (request.state !== RequestState.PENDING) {
                throw new WorkflowError(
                    "Request is not awaiting approval."
                );
            }

            if (!approver.active || !approver.mfaEnabled) {
                throw new AuthorizationError(
                    "Approver authentication failed."
                );
            }

            if (
                this.#policy.prohibitSelfApproval &&
                request.userId === approverId
            ) {
                throw new AuthorizationError(
                    "Self-approval is prohibited."
                );
            }

            if (!approver.roles.has("pam_approver")) {
                throw new AuthorizationError(
                    "Approver role is required."
                );
            }

            if (!Object.values(ReviewDecision).includes(decision)) {
                throw new ValidationError(
                    "Invalid review decision."
                );
            }

            if (decision === ReviewDecision.DENY) {
                request.state = RequestState.DENIED;
            } else {
                // Reevaluate identity, membership and account state.
                const user = this.#user(request.userId);
                const account = this.#account(request.accountId);

                const eligibility = this.#evaluateEligibility(
                    user,
                    account
                );

                validate.duration(
                    request.durationMinutes,
                    eligibility.maximum
                );

                request.state = RequestState.APPROVED;
            }

            request.approverId = approverId;
            request.reviewedAt = new Date().toISOString();

            this.#emitAudit(
                `REQUEST_${decision}`,
                approverId,
                requestId
            );

            return { ...request };
        });
    }

    // --------------------------------------------------------
    // JUST-IN-TIME SESSION CREATION
    // --------------------------------------------------------

    async startSession(requestId) {

        return this.#exclusive(async () => {
            const request = this.#request(requestId);

            if (request.state !== RequestState.APPROVED) {
                throw new WorkflowError(
                    "Request has not been approved."
                );
            }

            const user = this.#user(request.userId);
            const account = this.#account(request.accountId);

            const eligibility = this.#evaluateEligibility(
                user,
                account
            );

            validate.duration(
                request.durationMinutes,
                eligibility.maximum
            );

            if (!this.#vault.has(account.id)) {
                throw new PAMError(
                    "Credential vault is unavailable."
                );
            }

            const now = Date.now();

            const session = {
                id: crypto.randomUUID(),
                requestId,
                userId: user.id,
                accountId: account.id,
                startedAt: now,
                expiresAt:
                    now + request.durationMinutes * 60000,
                state: "ACTIVE",
                recordingEnabled: true
            };

            this.#sessions.set(session.id, session);
            request.state = RequestState.ACTIVE;

            this.#emitAudit(
                "SESSION_STARTED",
                user.id,
                session.id
            );

            return { ...session };
        });
    }

    // --------------------------------------------------------
    // CREDENTIAL ACCESS
    // --------------------------------------------------------

    async getVaultReference(sessionId, userId) {

        return this.#exclusive(async () => {
            const session = this.#session(sessionId);

            if (session.userId !== userId) {
                throw new AuthorizationError(
                    "Session ownership violation."
                );
            }

            if (session.state !== "ACTIVE") {
                throw new AuthorizationError(
                    "Session is not active."
                );
            }

            if (Date.now() >= session.expiresAt) {
                session.state = "EXPIRED";

                this.#request(
                    session.requestId
                ).state = RequestState.EXPIRED;

                throw new AuthorizationError(
                    "Session has expired."
                );
            }

            const account = this.#account(
                session.accountId
            );

            if (account.state !== AccountState.ACTIVE) {
                throw new AuthorizationError(
                    "Account access has been disabled."
                );
            }

            this.#emitAudit(
                "VAULT_REFERENCE_ACCESSED",
                userId,
                sessionId
            );

            return this.#vault.getReference(
                session.accountId
            );
        });
    }

    // --------------------------------------------------------
    // SESSION TERMINATION AND REVOCATION
    // --------------------------------------------------------

    async terminateSession(sessionId, actorId) {

        return this.#exclusive(async () => {
            const session = this.#session(sessionId);

            if (session.state !== "ACTIVE") {
                return false;
            }

            session.state = "TERMINATED";

            const request = this.#request(
                session.requestId
            );

            request.state = RequestState.EXPIRED;

            this.#emitAudit(
                "SESSION_TERMINATED",
                actorId,
                sessionId
            );

            return true;
        });
    }

    async revokeSession(sessionId, actorId) {

        return this.#exclusive(async () => {
            const session = this.#session(sessionId);

            if (session.state !== "ACTIVE") {
                return false;
            }

            session.state = "REVOKED";

            this.#request(
                session.requestId
            ).state = RequestState.REVOKED;

            this.#emitAudit(
                "SESSION_REVOKED",
                actorId,
                sessionId
            );

            return true;
        });
    }

    // --------------------------------------------------------
    // ACCOUNT CONTROL AND ROTATION
    // --------------------------------------------------------

    async disableAccount(accountId, actorId) {

        return this.#exclusive(async () => {
            const account = this.#account(accountId);

            account.state = AccountState.DISABLED;

            for (const session of this.#sessions.values()) {
                if (
                    session.accountId === accountId &&
                    session.state === "ACTIVE"
                ) {
                    session.state = "REVOKED";

                    this.#request(
                        session.requestId
                    ).state = RequestState.REVOKED;
                }
            }

            this.#emitAudit(
                "ACCOUNT_DISABLED",
                actorId,
                accountId
            );
        });
    }

    async rotateCredential(accountId, newSecret, actorId) {

        return this.#exclusive(async () => {
            const account = this.#account(accountId);

            if (account.state !== AccountState.ACTIVE) {
                throw new WorkflowError(
                    "Cannot rotate disabled account."
                );
            }

            this.#vault.rotate(accountId, newSecret);
            account.lastRotated = Date.now();

            this.#emitAudit(
                "CREDENTIAL_ROTATED",
                actorId,
                accountId
            );
        });
    }

    // --------------------------------------------------------
    // MONITORING AND REPORTING
    // --------------------------------------------------------

    getReport() {

        const sessions = [...this.#sessions.values()];
        const requests = [...this.#requests.values()];

        return {
            users: this.#users.size,
            privilegedGroups: this.#groups.size,
            privilegedAccounts: this.#accounts.size,
            pendingRequests: requests.filter(
                r => r.state === RequestState.PENDING
            ).length,
            activeSessions: sessions.filter(
                s => s.state === "ACTIVE"
            ).length,
            revokedSessions: sessions.filter(
                s => s.state === "REVOKED"
            ).length,
            expiredSessions: sessions.filter(
                s => s.state === "EXPIRED"
            ).length
        };
    }

    async exportAudit(events, filepath) {
        const safeEvents = events.map(event => ({
            ...event,
            details: event.details
        }));

        await fs.writeFile(
            filepath,
            JSON.stringify(safeEvents, null, 2),
            { encoding: "utf8", mode: 0o600 }
        );
    }
}


// ============================================================
// EXECUTABLE EVENT-DRIVEN SCENARIO
// ============================================================

async function main() {

    const pam = new PAMEngine(
        new AccessPolicy({
            requireMFA: true,
            requireApproval: true,
            prohibitSelfApproval: true,
            maximumSessionMinutes: 60
        })
    );

    const auditEvents = [];

    pam.on("audit", event => {
        auditEvents.push(event);

        console.log(
            `[AUDIT] ${event.action} | ${event.resourceId}`
        );
    });

    await pam.registerUser({
        id: "USR001",
        username: "database.operator",
        department: "Infrastructure",
        mfaEnabled: true,
        roles: ["operator"]
    });

    await pam.registerUser({
        id: "USR002",
        username: "security.approver",
        department: "Security",
        mfaEnabled: true,
        roles: ["pam_approver"]
    });

    await pam.createGroup({
        id: "GRP001",
        name: "Production Database Administrators",
        privilege: Privilege.ADMIN,
        maximumSessionMinutes: 45,
        approvalRequired: true
    });

    await pam.addMember("GRP001", "USR001");

    await pam.registerAccount({
        id: "ACC001",
        username: "production_dba",
        system: "production-postgresql",
        privilege: Privilege.ADMIN,
        groupIds: ["GRP001"],
        rotationIntervalDays: 30
    }, crypto.randomBytes(32).toString("hex"));

    const request = await pam.requestAccess({
        userId: "USR001",
        accountId: "ACC001",
        justification: "Investigate a production database incident.",
        durationMinutes: 30
    });

    console.log("\nRequest state:", request.state);

    await pam.reviewRequest(
        request.id,
        "USR002",
        ReviewDecision.APPROVE
    );

    const session = await pam.startSession(request.id);

    console.log("\nSession created:", session.id);

    const reference = await pam.getVaultReference(
        session.id,
        "USR001"
    );

    console.log("Credential reference:", reference);

    // Negative case: another user cannot retrieve this reference.
    try {
        await pam.getVaultReference(
            session.id,
            "USR002"
        );
    } catch (error) {
        console.log(
            "\nEXPECTED SECURITY DENIAL:",
            error.message
        );
    }

    await pam.terminateSession(
        session.id,
        "USR001"
    );

    console.log("\nPAM REPORT");
    console.log(
        JSON.stringify(pam.getReport(), null, 2)
    );

    await pam.exportAudit(
        auditEvents,
        "pam_audit_js.json"
    );

    console.log("\nAudit exported successfully.");
}


main().catch(error => {
    console.error("PAM execution failed:", error.message);
    process.exitCode = 1;
});
