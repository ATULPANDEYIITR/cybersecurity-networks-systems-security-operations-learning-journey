"use strict";

/*
 * IAM SECURITY REVIEW
 * Event-driven identity risk and access certification engine.
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only.
 *
 * Focus:
 * - Identity attack surface
 * - Role inheritance
 * - Privilege escalation exposure
 * - Access certification
 * - Policy evaluation
 * - Separation of duties
 * - Risk-based remediation
 * - Audit event processing
 */

const fs = require("node:fs/promises");
const crypto = require("node:crypto");
const EventEmitter = require("node:events");

const IdentityStatus = Object.freeze({
    ACTIVE: "active",
    SUSPENDED: "suspended",
    DISABLED: "disabled"
});

const IdentityType = Object.freeze({
    HUMAN: "human",
    SERVICE: "service",
    APPLICATION: "application",
    EXTERNAL: "external"
});

const Decision = Object.freeze({
    APPROVE: "approve",
    REVOKE: "revoke",
    REDUCE: "reduce",
    ESCALATE: "escalate"
});

const Severity = Object.freeze({
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical"
});

class IAMError extends Error {}
class ValidationError extends IAMError {}
class PolicyError extends IAMError {}
class TransitionError extends IAMError {}

function requireString(value, field) {
    if (typeof value !== "string" || value.trim() === "") {
        throw new ValidationError(`${field} must be a non-empty string`);
    }
}

function permissionKey(permission) {
    requireString(permission.resource, "permission.resource");
    requireString(permission.action, "permission.action");

    return `${permission.resource}:${permission.action}`;
}

class Identity {
    constructor(data) {
        requireString(data.id, "identity.id");
        requireString(data.name, "identity.name");
        requireString(data.owner, "identity.owner");

        if (!Object.values(IdentityType).includes(data.type)) {
            throw new ValidationError("Invalid identity type");
        }

        if (!Object.values(IdentityStatus).includes(data.status)) {
            throw new ValidationError("Invalid identity status");
        }

        this.id = data.id;
        this.name = data.name;
        this.type = data.type;
        this.status = data.status;
        this.owner = data.owner;
        this.department = data.department ?? "unassigned";
        this.roles = new Set(data.roles ?? []);
        this.directPermissions = new Map(
            (data.permissions ?? []).map(p => [permissionKey(p), p])
        );
        this.mfaEnabled = Boolean(data.mfaEnabled);
        this.lastLogin = data.lastLogin ? new Date(data.lastLogin) : null;

        if (
            this.lastLogin &&
            Number.isNaN(this.lastLogin.getTime())
        ) {
            throw new ValidationError("Invalid lastLogin timestamp");
        }
    }
}

class Role {
    constructor(data) {
        requireString(data.id, "role.id");
        requireString(data.name, "role.name");

        this.id = data.id;
        this.name = data.name;
        this.privileged = Boolean(data.privileged);
        this.permissions = new Map(
            (data.permissions ?? []).map(p => [permissionKey(p), p])
        );
        this.inherits = new Set(data.inherits ?? []);
    }
}

class AuditEvent {
    constructor(type, actor, subject, details = {}) {
        this.id = crypto.randomUUID();
        this.type = type;
        this.actor = actor;
        this.subject = subject;
        this.details = structuredClone(details);
        this.timestamp = new Date().toISOString();
    }
}

class AccessReview {
    constructor({
        identityId,
        reviewer,
        decision,
        justification,
        removePermissions = []
    }) {
        requireString(identityId, "identityId");
        requireString(reviewer, "reviewer");
        requireString(justification, "justification");

        if (!Object.values(Decision).includes(decision)) {
            throw new ValidationError("Invalid review decision");
        }

        this.identityId = identityId;
        this.reviewer = reviewer;
        this.decision = decision;
        this.justification = justification;
        this.removePermissions = new Set(removePermissions);
        this.reviewedAt = new Date();
    }
}

class IAMRepository extends EventEmitter {
    constructor() {
        super();
        this.identities = new Map();
        this.roles = new Map();
        this.reviews = [];
        this.auditLog = [];
        this.findings = [];
        this.policies = {
            maximumPrivilegeAgeDays: 90,
            requireMFAForPrivileged: true,
            minimumReviewJustificationLength: 10,
            forbiddenRolePairs: [
                ["finance_approver", "payment_creator"],
                ["security_admin", "audit_reviewer"]
            ]
        };
    }

    recordEvent(event) {
        this.auditLog.push(event);
        this.emit("audit", event);
    }

    addRole(role) {
        if (!(role instanceof Role)) {
            throw new ValidationError("Expected a Role instance");
        }

        if (this.roles.has(role.id)) {
            throw new ValidationError(`Duplicate role ${role.id}`);
        }

        this.roles.set(role.id, role);
        this.recordEvent(
            new AuditEvent("ROLE_CREATED", "system", role.id)
        );
    }

    addIdentity(identity) {
        if (!(identity instanceof Identity)) {
            throw new ValidationError("Expected an Identity instance");
        }

        if (this.identities.has(identity.id)) {
            throw new ValidationError(`Duplicate identity ${identity.id}`);
        }

        for (const roleId of identity.roles) {
            if (!this.roles.has(roleId)) {
                throw new ValidationError(`Unknown role ${roleId}`);
            }
        }

        this.identities.set(identity.id, identity);

        this.recordEvent(
            new AuditEvent("IDENTITY_CREATED", "system", identity.id)
        );
    }

    validateRoleGraph() {
        const visiting = new Set();
        const visited = new Set();

        const visit = id => {
            if (!this.roles.has(id)) {
                throw new ValidationError(`Missing inherited role ${id}`);
            }

            if (visiting.has(id)) {
                throw new PolicyError(`Circular inheritance at ${id}`);
            }

            if (visited.has(id)) return;

            visiting.add(id);

            for (const parent of this.roles.get(id).inherits) {
                visit(parent);
            }

            visiting.delete(id);
            visited.add(id);
        };

        for (const id of this.roles.keys()) {
            visit(id);
        }
    }

    effectivePermissions(identityId) {
        const identity = this.identities.get(identityId);

        if (!identity) {
            throw new ValidationError(`Unknown identity ${identityId}`);
        }

        if (identity.status !== IdentityStatus.ACTIVE) {
            return new Map();
        }

        const result = new Map(identity.directPermissions);
        const visited = new Set();

        const collect = roleId => {
            if (visited.has(roleId)) return;
            visited.add(roleId);

            const role = this.roles.get(roleId);

            if (!role) {
                throw new ValidationError(`Unknown role ${roleId}`);
            }

            for (const [key, permission] of role.permissions) {
                result.set(key, permission);
            }

            for (const parent of role.inherits) {
                collect(parent);
            }
        };

        for (const roleId of identity.roles) {
            collect(roleId);
        }

        return result;
    }

    isPrivileged(identity) {
        for (const roleId of identity.roles) {
            if (this.roles.get(roleId)?.privileged) {
                return true;
            }
        }

        const sensitive = new Set([
            "iam:manage_roles",
            "iam:manage_policies",
            "security:configure_security",
            "secrets:manage_credentials"
        ]);

        return [...this.effectivePermissions(identity.id).keys()]
            .some(key => sensitive.has(key));
    }

    evaluateSeparationOfDuties(identity) {
        const violations = [];

        for (const [first, second] of this.policies.forbiddenRolePairs) {
            if (identity.roles.has(first) && identity.roles.has(second)) {
                violations.push(`${first} conflicts with ${second}`);
            }
        }

        return violations;
    }

    assessIdentity(identity, now = new Date()) {
        const findings = [];
        const permissions = this.effectivePermissions(identity.id);
        const privileged = this.isPrivileged(identity);

        const sensitiveActions = new Set([
            "admin",
            "manage_roles",
            "manage_policies",
            "manage_credentials",
            "configure_security",
            "delete"
        ]);

        const sensitive = [...permissions.values()].filter(permission =>
            sensitiveActions.has(permission.action)
        );

        if (sensitive.length > 0) {
            findings.push({
                category: "PRIVILEGE_ESCALATION_EXPOSURE",
                severity: Severity.CRITICAL,
                risk: 95,
                evidence: sensitive.map(permissionKey)
            });
        }

        if (permissions.size > 8) {
            findings.push({
                category: "EXCESSIVE_ACCESS",
                severity: Severity.MEDIUM,
                risk: 55,
                evidence: [`${permissions.size} effective permissions`]
            });
        }

        if (
            privileged &&
            this.policies.requireMFAForPrivileged &&
            !identity.mfaEnabled
        ) {
            findings.push({
                category: "PRIVILEGED_ACCOUNT_WITHOUT_MFA",
                severity: Severity.CRITICAL,
                risk: 98,
                evidence: ["Privileged identity has no MFA"]
            });
        }

        const inactiveDays = identity.lastLogin
            ? (now.getTime() - identity.lastLogin.getTime()) / 86400000
            : Infinity;

        if (inactiveDays > this.policies.maximumPrivilegeAgeDays) {
            findings.push({
                category: "DORMANT_IDENTITY",
                severity: privileged ? Severity.CRITICAL : Severity.HIGH,
                risk: privileged ? 95 : 75,
                evidence: [
                    Number.isFinite(inactiveDays)
                        ? `${Math.floor(inactiveDays)} days inactive`
                        : "No recorded login"
                ]
            });
        }

        const sodViolations = this.evaluateSeparationOfDuties(identity);

        if (sodViolations.length > 0) {
            findings.push({
                category: "SEPARATION_OF_DUTIES",
                severity: Severity.CRITICAL,
                risk: 95,
                evidence: sodViolations
            });
        }

        return findings.map(finding => ({
            identityId: identity.id,
            identityName: identity.name,
            ...finding
        }));
    }

    async assessAll(now = new Date()) {
        this.validateRoleGraph();

        const tasks = [...this.identities.values()]
            .map(async identity => this.assessIdentity(identity, now));

        const findings = (await Promise.all(tasks)).flat();

        findings.sort((a, b) => b.risk - a.risk);

        this.findings = findings;

        this.recordEvent(
            new AuditEvent(
                "IAM_ASSESSMENT_COMPLETED",
                "system",
                "repository",
                { findingCount: findings.length }
            )
        );

        return findings;
    }

    async processReview(review) {
        if (!(review instanceof AccessReview)) {
            throw new ValidationError("Expected AccessReview instance");
        }

        const identity = this.identities.get(review.identityId);

        if (!identity) {
            throw new ValidationError("Review target does not exist");
        }

        if (
            review.justification.length <
            this.policies.minimumReviewJustificationLength
        ) {
            throw new PolicyError("Review justification is insufficient");
        }

        // Validate before mutating the identity.
        if (review.decision === Decision.REDUCE) {
            for (const permission of review.removePermissions) {
                if (
                    !identity.directPermissions.has(permission) &&
                    ![...identity.roles].some(roleId =>
                        this.roles.get(roleId).permissions.has(permission)
                    )
                ) {
                    throw new ValidationError(
                        `Permission not assigned: ${permission}`
                    );
                }
            }
        }

        switch (review.decision) {
            case Decision.APPROVE:
                break;

            case Decision.REVOKE:
                identity.status = IdentityStatus.DISABLED;
                identity.roles.clear();
                identity.directPermissions.clear();
                break;

            case Decision.REDUCE:
                for (const permission of review.removePermissions) {
                    identity.directPermissions.delete(permission);
                }

                // Role-based permissions require a role-level change or
                // a narrower replacement role; they are not silently
                // removed from a shared role.
                break;

            case Decision.ESCALATE:
                this.recordEvent(
                    new AuditEvent(
                        "REVIEW_ESCALATED",
                        review.reviewer,
                        identity.id,
                        { justification: review.justification }
                    )
                );
                break;

            default:
                throw new TransitionError("Unsupported review transition");
        }

        this.reviews.push(review);

        this.recordEvent(
            new AuditEvent(
                "ACCESS_REVIEW_RECORDED",
                review.reviewer,
                identity.id,
                {
                    decision: review.decision,
                    justification: review.justification
                }
            )
        );

        return {
            identityId: identity.id,
            decision: review.decision,
            status: identity.status
        };
    }

    getReport() {
        return {
            generatedAt: new Date().toISOString(),
            identityCount: this.identities.size,
            roleCount: this.roles.size,
            reviewCount: this.reviews.length,
            findingCount: this.findings.length,
            findings: this.findings,
            auditEvents: this.auditLog.length
        };
    }
}

function createDemoRepository() {
    const repository = new IAMRepository();

    repository.on("audit", event => {
        console.log(
            `[AUDIT] ${event.type} | ${event.subject} | ${event.actor}`
        );
    });

    repository.addRole(new Role({
        id: "employee",
        name: "Employee",
        permissions: [
            { resource: "documents", action: "read" }
        ]
    }));

    repository.addRole(new Role({
        id: "developer",
        name: "Developer",
        inherits: ["employee"],
        permissions: [
            { resource: "source_code", action: "read" },
            { resource: "source_code", action: "write" },
            { resource: "deployment", action: "read" }
        ]
    }));

    repository.addRole(new Role({
        id: "security_admin",
        name: "Security Administrator",
        privileged: true,
        permissions: [
            { resource: "iam", action: "manage_roles" },
            { resource: "iam", action: "manage_policies" },
            { resource: "secrets", action: "manage_credentials" }
        ]
    }));

    repository.addRole(new Role({
        id: "finance_approver",
        name: "Finance Approver",
        permissions: [
            { resource: "payments", action: "approve" }
        ]
    }));

    repository.addRole(new Role({
        id: "payment_creator",
        name: "Payment Creator",
        permissions: [
            { resource: "payments", action: "create" }
        ]
    }));

    const now = Date.now();

    repository.addIdentity(new Identity({
        id: "USR-101",
        name: "Developer Account",
        type: IdentityType.HUMAN,
        status: IdentityStatus.ACTIVE,
        owner: "engineering_manager",
        roles: ["developer"],
        mfaEnabled: true,
        lastLogin: new Date(now - 86400000 * 2)
    }));

    repository.addIdentity(new Identity({
        id: "USR-102",
        name: "Privileged Operator",
        type: IdentityType.HUMAN,
        status: IdentityStatus.ACTIVE,
        owner: "security_director",
        roles: ["security_admin"],
        mfaEnabled: false,
        lastLogin: new Date(now - 86400000 * 120)
    }));

    repository.addIdentity(new Identity({
        id: "USR-103",
        name: "Finance Operator",
        type: IdentityType.HUMAN,
        status: IdentityStatus.ACTIVE,
        owner: "finance_director",
        roles: ["finance_approver", "payment_creator"],
        mfaEnabled: true,
        lastLogin: new Date(now - 86400000)
    }));

    repository.addIdentity(new Identity({
        id: "SVC-101",
        name: "Legacy Integration",
        type: IdentityType.SERVICE,
        status: IdentityStatus.ACTIVE,
        owner: "integration_team",
        roles: ["security_admin"],
        mfaEnabled: false,
        lastLogin: null
    }));

    return repository;
}

async function main() {
    const repository = createDemoRepository();

    console.log("\nIAM SECURITY REVIEW");
    console.log("==============================");

    const findings = await repository.assessAll();

    for (const finding of findings) {
        console.log(
            `${finding.identityId} | ${finding.severity} | ` +
            `${finding.category} | Risk ${finding.risk}`
        );

        for (const evidence of finding.evidence) {
            console.log(`  Evidence: ${evidence}`);
        }
    }

    console.log("\nACCESS CERTIFICATION");

    const result = await repository.processReview(
        new AccessReview({
            identityId: "USR-102",
            reviewer: "security_director",
            decision: Decision.REVOKE,
            justification:
                "Dormant privileged account without MFA protection."
        })
    );

    console.log("Review result:", result);

    const report = repository.getReport();

    // Write reports with restrictive file permissions.
    await fs.writeFile(
        "iam_security_report.json",
        JSON.stringify(report, null, 2),
        { encoding: "utf8", mode: 0o600 }
    );

    console.log("\nREPORT");
    console.log(JSON.stringify({
        identities: report.identityCount,
        roles: report.roleCount,
        findings: report.findingCount,
        reviews: report.reviewCount
    }, null, 2));
}

main().catch(error => {
    console.error("IAM assessment failed:", error.message);
    process.exitCode = 1;
});
