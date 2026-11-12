"use strict";

/*
 * Authorization Models
 *
 * Event-driven authorization and policy evaluation using:
 * RBAC, ABAC, ACL, DAC, MAC, and least privilege.
 *
 * Runtime: Node.js 18+
 *
 * Run:
 * node authorization_models.js
 */

const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");

const Permission = Object.freeze({
    READ: "read",
    WRITE: "write",
    DELETE: "delete",
    EXECUTE: "execute",
    SHARE: "share",
    ADMIN: "admin"
});

const Classification = Object.freeze({
    PUBLIC: 0,
    INTERNAL: 1,
    CONFIDENTIAL: 2,
    SECRET: 3,
    TOP_SECRET: 4
});

const Decision = Object.freeze({
    ALLOW: "ALLOW",
    DENY: "DENY"
});

class AuthorizationError extends Error {
    constructor(message) {
        super(message);
        this.name = "AuthorizationError";
    }
}

class ValidationError extends AuthorizationError {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}

function requireIdentifier(value, label) {
    if (
        typeof value !== "string" ||
        value.trim().length === 0 ||
        value.length > 128
    ) {
        throw new ValidationError(`Invalid ${label}`);
    }
}

function requirePermission(permission) {
    if (!Object.values(Permission).includes(permission)) {
        throw new ValidationError("Unknown permission");
    }
}

class PolicyResult {
    constructor(allowed, reasons = []) {
        this.allowed = allowed;
        this.reasons = reasons;
    }
}

class AuthorizationPolicy {

    constructor() {
        this.rules = new Map();
    }

    register(name, evaluator) {
        requireIdentifier(name, "policy name");

        if (typeof evaluator !== "function") {
            throw new ValidationError("Evaluator must be a function");
        }

        if (this.rules.has(name)) {
            throw new ValidationError("Policy already registered");
        }

        this.rules.set(name, evaluator);
    }

    evaluate(name, context) {
        const evaluator = this.rules.get(name);

        if (!evaluator) {
            throw new AuthorizationError(`Unknown policy: ${name}`);
        }

        const result = evaluator(context);

        if (typeof result !== "boolean") {
            throw new AuthorizationError(
                `Policy ${name} returned an invalid result`
            );
        }

        return result;
    }
}

class AuthorizationEngine extends EventEmitter {

    constructor() {
        super();

        this.users = new Map();
        this.roles = new Map();
        this.userRoles = new Map();
        this.resources = new Map();

        this.explicitDenies = [];
        this.auditEvents = [];

        this.policy = new AuthorizationPolicy();

        this.registerPolicies();
    }

    registerPolicies() {

        this.policy.register("active-user", ({ user }) => {
            return user.active;
        });

        this.policy.register("mac", ({ user, resource }) => {
            return user.clearance >= resource.classification;
        });

        this.policy.register("abac", ({
            user,
            resource,
            request
        }) => {
            const allowedPurposes = new Set([
                "business",
                "research",
                "maintenance",
                "compliance"
            ]);

            if (!allowedPurposes.has(request.purpose)) {
                return false;
            }

            if (
                user.department !== resource.department &&
                request.purpose !== "compliance"
            ) {
                return false;
            }

            const locations = resource.attributes.allowedLocations;

            if (
                locations &&
                !locations.includes(user.location)
            ) {
                return false;
            }

            if (
                resource.attributes.requireMfa &&
                !user.attributes.mfaVerified
            ) {
                return false;
            }

            return true;
        });

        this.policy.register("least-privilege", ({
            user,
            resource,
            request
        }) => {
            if (request.permission === Permission.ADMIN) {
                return user.attributes.privilegedAdmin === true;
            }

            if (request.permission === Permission.DELETE) {
                return (
                    user.attributes.deleteAuthorized === true &&
                    resource.attributes.deletionEnabled === true
                );
            }

            return true;
        });
    }

    addUser(user) {
        requireIdentifier(user.id, "user ID");

        if (this.users.has(user.id)) {
            throw new ValidationError("Duplicate user");
        }

        if (
            !Number.isInteger(user.clearance) ||
            user.clearance < 0 ||
            user.clearance > 4
        ) {
            throw new ValidationError("Invalid clearance");
        }

        this.users.set(user.id, Object.freeze({
            ...user,
            attributes: Object.freeze({ ...user.attributes })
        }));

        this.userRoles.set(user.id, new Set());
    }

    addRole(name, permissions) {
        requireIdentifier(name, "role name");

        if (this.roles.has(name)) {
            throw new ValidationError("Duplicate role");
        }

        const validated = new Set(permissions);

        for (const permission of validated) {
            requirePermission(permission);
        }

        this.roles.set(name, validated);
    }

    assignRole(userId, roleName) {
        if (!this.users.has(userId) || !this.roles.has(roleName)) {
            throw new ValidationError("Unknown user or role");
        }

        this.userRoles.get(userId).add(roleName);
    }

    revokeRole(userId, roleName) {
        if (!this.userRoles.has(userId)) {
            throw new ValidationError("Unknown user");
        }

        this.userRoles.get(userId).delete(roleName);
    }

    addResource(resource) {
        requireIdentifier(resource.id, "resource ID");

        if (!this.users.has(resource.ownerId)) {
            throw new ValidationError("Resource owner does not exist");
        }

        if (this.resources.has(resource.id)) {
            throw new ValidationError("Duplicate resource");
        }

        if (
            !Number.isInteger(resource.classification) ||
            resource.classification < 0 ||
            resource.classification > 4
        ) {
            throw new ValidationError("Invalid classification");
        }

        this.resources.set(resource.id, {
            ...resource,
            attributes: { ...resource.attributes },
            acl: new Map()
        });
    }

    grantAcl(resourceId, principal, permissions) {
        const resource = this.resources.get(resourceId);

        if (!resource) {
            throw new ValidationError("Unknown resource");
        }

        if (
            !this.users.has(principal) &&
            !this.roles.has(principal)
        ) {
            throw new ValidationError("Unknown ACL principal");
        }

        const grants = new Set(permissions);

        for (const permission of grants) {
            requirePermission(permission);
        }

        const existing = resource.acl.get(principal) || new Set();

        for (const permission of grants) {
            existing.add(permission);
        }

        resource.acl.set(principal, existing);
    }

    revokeAcl(resourceId, principal) {
        const resource = this.resources.get(resourceId);

        if (!resource) {
            throw new ValidationError("Unknown resource");
        }

        resource.acl.delete(principal);
    }

    addExplicitDeny(attribute, expectedValue, permission = null) {
        requireIdentifier(attribute, "attribute");

        if (permission !== null) {
            requirePermission(permission);
        }

        this.explicitDenies.push({
            attribute,
            expectedValue,
            permission
        });
    }

    hasRbacGrant(userId, permission) {
        for (const roleName of this.userRoles.get(userId)) {
            if (this.roles.get(roleName).has(permission)) {
                return true;
            }
        }

        return false;
    }

    hasAclGrant(user, resource, permission) {
        if (resource.acl.get(user.id)?.has(permission)) {
            return true;
        }

        for (const roleName of this.userRoles.get(user.id)) {
            if (resource.acl.get(roleName)?.has(permission)) {
                return true;
            }
        }

        return false;
    }

    hasDacGrant(user, resource, permission) {
        return (
            user.id === resource.ownerId &&
            [
                Permission.READ,
                Permission.WRITE,
                Permission.SHARE
            ].includes(permission)
        );
    }

    evaluate(request) {
        requireIdentifier(request.userId, "user ID");
        requireIdentifier(request.resourceId, "resource ID");
        requirePermission(request.permission);

        const user = this.users.get(request.userId);
        const resource = this.resources.get(request.resourceId);

        if (!user || !resource) {
            throw new ValidationError("Unknown user or resource");
        }

        const reasons = [];

        for (const rule of this.explicitDenies) {
            if (
                user.attributes[rule.attribute] === rule.expectedValue &&
                (
                    rule.permission === null ||
                    rule.permission === request.permission
                )
            ) {
                return new PolicyResult(false, [
                    "Explicit deny policy matched"
                ]);
            }
        }

        const context = {
            user,
            resource,
            request
        };

        const mandatoryPolicies = [
            "active-user",
            "mac",
            "abac",
            "least-privilege"
        ];

        let mandatoryAllowed = true;

        for (const name of mandatoryPolicies) {
            const allowed = this.policy.evaluate(name, context);

            reasons.push(`${name}: ${allowed ? "PASS" : "FAIL"}`);

            if (!allowed) {
                mandatoryAllowed = false;
            }
        }

        const grants = {
            RBAC: this.hasRbacGrant(user.id, request.permission),
            ACL: this.hasAclGrant(user, resource, request.permission),
            DAC: this.hasDacGrant(user, resource, request.permission)
        };

        const grantFound = Object.values(grants).some(Boolean);

        reasons.push(
            `Grant evaluation: ${JSON.stringify(grants)}`
        );

        reasons.push(
            grantFound ? "Grant found" : "No grant found"
        );

        return new PolicyResult(
            mandatoryAllowed && grantFound,
            reasons
        );
    }

    async authorize(request) {
        const requestId = crypto.randomUUID();

        let result;

        try {
            result = this.evaluate(request);
        } catch (error) {
            result = new PolicyResult(false, [
                `Validation failure: ${error.message}`
            ]);

            this.record(requestId, request, result);

            throw error;
        }

        this.record(requestId, request, result);

        const event = {
            requestId,
            decision: result.allowed
                ? Decision.ALLOW
                : Decision.DENY,
            reasons: result.reasons
        };

        // Listeners receive a detached event object.
        this.emit("authorization", structuredClone(event));

        return event;
    }

    record(requestId, request, result) {
        const event = Object.freeze({
            requestId,
            userId: request.userId,
            resourceId: request.resourceId,
            permission: request.permission,
            decision: result.allowed
                ? Decision.ALLOW
                : Decision.DENY,
            reasons: [...result.reasons],
            timestamp: new Date().toISOString()
        });

        this.auditEvents.push(event);
    }

    async exportAudit(filePath) {
        const absolutePath = path.resolve(filePath);
        const temporaryPath = `${absolutePath}.${crypto.randomUUID()}.tmp`;

        try {
            await fs.writeFile(
                temporaryPath,
                JSON.stringify(this.auditEvents, null, 2),
                { encoding: "utf8", mode: 0o600, flag: "wx" }
            );

            await fs.rename(temporaryPath, absolutePath);

        } catch (error) {
            await fs.rm(temporaryPath, { force: true });
            throw error;
        }
    }
}

function createExample() {
    const engine = new AuthorizationEngine();

    engine.addUser({
        id: "alice",
        department: "engineering",
        clearance: Classification.CONFIDENTIAL,
        location: "India",
        active: true,
        attributes: {
            mfaVerified: true,
            deleteAuthorized: false
        }
    });

    engine.addUser({
        id: "bob",
        department: "finance",
        clearance: Classification.SECRET,
        location: "India",
        active: true,
        attributes: {
            mfaVerified: true,
            privilegedAdmin: true,
            deleteAuthorized: true
        }
    });

    engine.addUser({
        id: "charlie",
        department: "engineering",
        clearance: Classification.PUBLIC,
        location: "India",
        active: false,
        attributes: {}
    });

    engine.addRole("developer", [
        Permission.READ,
        Permission.WRITE
    ]);

    engine.addRole("security-admin", [
        Permission.READ,
        Permission.ADMIN
    ]);

    engine.assignRole("alice", "developer");
    engine.assignRole("bob", "security-admin");

    engine.addResource({
        id: "source-code",
        ownerId: "alice",
        department: "engineering",
        classification: Classification.CONFIDENTIAL,
        attributes: {
            allowedLocations: ["India"],
            requireMfa: true,
            deletionEnabled: false
        }
    });

    engine.addResource({
        id: "financial-report",
        ownerId: "bob",
        department: "finance",
        classification: Classification.SECRET,
        attributes: {
            allowedLocations: ["India"],
            requireMfa: true,
            deletionEnabled: true
        }
    });

    engine.grantAcl(
        "financial-report",
        "alice",
        [Permission.READ]
    );

    engine.addExplicitDeny("accountSuspended", true);

    return engine;
}

async function runTests(engine) {
    const assert = require("node:assert/strict");

    const cases = [
        {
            name: "RBAC read",
            request: {
                userId: "alice",
                resourceId: "source-code",
                permission: Permission.READ,
                purpose: "business"
            },
            expected: Decision.ALLOW
        },
        {
            name: "ACL cross-department compliance",
            request: {
                userId: "alice",
                resourceId: "financial-report",
                permission: Permission.READ,
                purpose: "compliance"
            },
            expected: Decision.ALLOW
        },
        {
            name: "MAC clearance denial",
            request: {
                userId: "alice",
                resourceId: "financial-report",
                permission: Permission.WRITE,
                purpose: "compliance"
            },
            expected: Decision.DENY
        },
        {
            name: "Inactive account",
            request: {
                userId: "charlie",
                resourceId: "source-code",
                permission: Permission.READ,
                purpose: "business"
            },
            expected: Decision.DENY
        },
        {
            name: "Least privilege",
            request: {
                userId: "alice",
                resourceId: "source-code",
                permission: Permission.DELETE,
                purpose: "business"
            },
            expected: Decision.DENY
        }
    ];

    for (const testCase of cases) {
        const result = await engine.authorize(testCase.request);

        assert.equal(result.decision, testCase.expected);

        console.log(
            `${testCase.name}: ${result.decision}`
        );
    }

    await assert.rejects(
        engine.authorize({
            userId: "unknown",
            resourceId: "source-code",
            permission: Permission.READ,
            purpose: "business"
        }),
        ValidationError
    );

    console.log("Unknown identity validation: PASS");
}

async function main() {
    const engine = createExample();

    engine.on("authorization", event => {
        console.log(
            `EVENT ${event.requestId}: ${event.decision}`
        );
    });

    await runTests(engine);

    await engine.exportAudit("authorization_audit.json");

    console.log(
        `Audit events recorded: ${engine.auditEvents.length}`
    );
}

main().catch(error => {
    console.error("Authorization system failure:", error.message);
    process.exitCode = 1;
});
