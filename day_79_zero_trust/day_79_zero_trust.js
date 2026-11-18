'use strict';

/**
 * Zero Trust Security Engine
 *
 * Event-driven authorization and continuous access evaluation.
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library.
 */

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const EventEmitter = require('node:events');

// ---------------------------------------------------------
// Domain definitions
// ---------------------------------------------------------

const Decision = Object.freeze({
    ALLOW: 'ALLOW',
    DENY: 'DENY',
    REVOKE: 'REVOKE'
});

const Zone = Object.freeze({
    PUBLIC: 'PUBLIC',
    INTERNAL: 'INTERNAL',
    RESTRICTED: 'RESTRICTED',
    CRITICAL: 'CRITICAL'
});

const Trust = Object.freeze({
    UNTRUSTED: 0,
    VERIFIED: 1,
    HIGH: 2
});

const SessionState = Object.freeze({
    ACTIVE: 'ACTIVE',
    REVOKED: 'REVOKED',
    EXPIRED: 'EXPIRED'
});

const VALID_ACTIONS = new Set([
    'READ',
    'WRITE',
    'DELETE',
    'ADMIN'
]);

const VALID_ZONES = new Set(Object.values(Zone));

// ---------------------------------------------------------
// Errors
// ---------------------------------------------------------

class SecurityError extends Error {}
class ValidationError extends SecurityError {}
class AuthenticationError extends SecurityError {}
class AuthorizationError extends SecurityError {}
class SessionError extends SecurityError {}

// ---------------------------------------------------------
// Input validation
// ---------------------------------------------------------

function requireString(value, field) {
    if (
        typeof value !== 'string' ||
        value.trim().length === 0
    ) {
        throw new ValidationError(`${field} is required.`);
    }

    return value.trim();
}

function validateRisk(value, field) {
    if (!Number.isInteger(value) || value < 0 || value > 100) {
        throw new ValidationError(
            `${field} must be an integer between 0 and 100.`
        );
    }
}

function validateIP(address) {
    if (typeof address !== 'string' || net.isIP(address) === 0) {
        throw new ValidationError('Invalid IP address.');
    }
}

function createIdentifier() {
    return crypto.randomBytes(24).toString('hex');
}

// ---------------------------------------------------------
// Identity registry
// ---------------------------------------------------------

class IdentityRegistry {

    #identities = new Map();

    register(identity) {
        const id = requireString(identity.id, 'Identity ID');

        if (this.#identities.has(id)) {
            throw new ValidationError('Identity already registered.');
        }

        if (!Array.isArray(identity.roles) || identity.roles.length === 0) {
            throw new ValidationError('At least one role is required.');
        }

        const normalized = Object.freeze({
            id,
            username: requireString(identity.username, 'Username'),
            roles: Object.freeze([...new Set(identity.roles)]),
            enabled: identity.enabled === true,
            mfaVerified: identity.mfaVerified === true
        });

        this.#identities.set(id, normalized);
        return normalized;
    }

    authenticate(id) {
        const identity = this.#identities.get(id);

        if (!identity || !identity.enabled) {
            throw new AuthenticationError(
                'Identity authentication failed.'
            );
        }

        return identity;
    }

    disable(id) {
        const identity = this.authenticate(id);

        this.#identities.set(id, Object.freeze({
            ...identity,
            enabled: false
        }));
    }
}

// ---------------------------------------------------------
// Device registry
// ---------------------------------------------------------

class DeviceRegistry {

    #devices = new Map();

    register(device) {
        const id = requireString(device.id, 'Device ID');

        if (this.#devices.has(id)) {
            throw new ValidationError('Duplicate device.');
        }

        validateRisk(device.riskScore, 'Device risk');

        const normalized = {
            id,
            ownerId: requireString(device.ownerId, 'Owner ID'),
            managed: device.managed === true,
            encrypted: device.encrypted === true,
            patched: device.patched === true,
            endpointProtected: device.endpointProtected === true,
            riskScore: device.riskScore,
            version: 1
        };

        this.#devices.set(id, normalized);
        return { ...normalized };
    }

    get(id) {
        const device = this.#devices.get(id);

        if (!device) {
            throw new AuthenticationError('Unknown device.');
        }

        return { ...device };
    }

    updatePosture(id, changes) {
        const current = this.#devices.get(id);

        if (!current) {
            throw new ValidationError('Unknown device.');
        }

        const next = { ...current, ...changes };

        validateRisk(next.riskScore, 'Device risk');

        next.version = current.version + 1;
        this.#devices.set(id, next);

        return { ...next };
    }

    isCompliant(device, identity) {
        return (
            device.ownerId === identity.id &&
            device.managed &&
            device.encrypted &&
            device.patched &&
            device.endpointProtected &&
            device.riskScore <= 30
        );
    }

    getTrust(device, identity) {
        if (!this.isCompliant(device, identity)) {
            return Trust.UNTRUSTED;
        }

        if (identity.mfaVerified && device.riskScore <= 10) {
            return Trust.HIGH;
        }

        return Trust.VERIFIED;
    }
}

// ---------------------------------------------------------
// Resource segmentation
// ---------------------------------------------------------

class ResourceRegistry {

    #resources = new Map();

    register(resource) {
        const id = requireString(resource.id, 'Resource ID');

        if (this.#resources.has(id)) {
            throw new ValidationError('Duplicate resource.');
        }

        if (!VALID_ZONES.has(resource.zone)) {
            throw new ValidationError('Invalid resource zone.');
        }

        if (!Array.isArray(resource.roles) || resource.roles.length === 0) {
            throw new ValidationError('Resource roles are required.');
        }

        if (
            !Array.isArray(resource.actions) ||
            resource.actions.length === 0 ||
            resource.actions.some(action => !VALID_ACTIONS.has(action))
        ) {
            throw new ValidationError('Invalid resource actions.');
        }

        const normalized = Object.freeze({
            id,
            name: requireString(resource.name, 'Resource name'),
            zone: resource.zone,
            roles: Object.freeze([...new Set(resource.roles)]),
            actions: Object.freeze([...new Set(resource.actions)]),
            minimumTrust: resource.minimumTrust,
            requireMFA: resource.requireMFA !== false
        });

        if (![0, 1, 2].includes(normalized.minimumTrust)) {
            throw new ValidationError('Invalid minimum trust level.');
        }

        this.#resources.set(id, normalized);
        return normalized;
    }

    get(id) {
        const resource = this.#resources.get(id);

        if (!resource) {
            throw new AuthorizationError('Unknown resource.');
        }

        return resource;
    }
}

// ---------------------------------------------------------
// Context-aware policy evaluation
// ---------------------------------------------------------

class AccessPolicy {

    constructor(deviceRegistry) {
        this.deviceRegistry = deviceRegistry;
    }

    evaluate(identity, device, resource, context) {

        validateIP(context.sourceIP);
        validateRisk(context.riskScore, 'Context risk');

        if (!VALID_ACTIONS.has(context.action)) {
            throw new ValidationError('Invalid requested action.');
        }

        if (!identity.enabled) {
            return { allowed: false, reason: 'Identity disabled.' };
        }

        if (!this.deviceRegistry.isCompliant(device, identity)) {
            return { allowed: false, reason: 'Device is noncompliant.' };
        }

        if (resource.requireMFA && !identity.mfaVerified) {
            return { allowed: false, reason: 'MFA required.' };
        }

        if (!resource.roles.some(role => identity.roles.includes(role))) {
            return { allowed: false, reason: 'Role mismatch.' };
        }

        if (!resource.actions.includes(context.action)) {
            return { allowed: false, reason: 'Action not authorized.' };
        }

        if (context.riskScore >= 80) {
            return { allowed: false, reason: 'Contextual risk too high.' };
        }

        const trust = this.deviceRegistry.getTrust(device, identity);

        if (trust < resource.minimumTrust) {
            return { allowed: false, reason: 'Insufficient device trust.' };
        }

        if (resource.zone === Zone.RESTRICTED) {
            if (!['CORPORATE', 'VPN'].includes(context.networkZone)) {
                return {
                    allowed: false,
                    reason: 'Restricted network boundary violated.'
                };
            }
        }

        if (resource.zone === Zone.CRITICAL) {
            if (
                context.networkZone !== 'CORPORATE' ||
                context.riskScore > 10 ||
                trust !== Trust.HIGH
            ) {
                return {
                    allowed: false,
                    reason: 'Critical resource security conditions failed.'
                };
            }
        }

        return {
            allowed: true,
            reason: 'All policy conditions satisfied.',
            trust
        };
    }
}

// ---------------------------------------------------------
// Event-driven audit service
// ---------------------------------------------------------

class SecurityEventBus extends EventEmitter {

    constructor() {
        super({ captureRejections: true });
        this.events = [];
    }

    publish(event) {
        const record = Object.freeze({
            id: createIdentifier(),
            timestamp: new Date().toISOString(),
            ...event
        });

        this.events.push(record);
        this.emit('security-event', record);

        return record;
    }

    async exportJSON(filename) {
        await fs.writeFile(
            filename,
            JSON.stringify(this.events, null, 2),
            { encoding: 'utf8', mode: 0o600, flag: 'w' }
        );
    }
}

// ---------------------------------------------------------
// Session manager
// ---------------------------------------------------------

class SessionManager {

    #sessions = new Map();

    constructor(lifetimeMs = 900000) {
        if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs <= 0) {
            throw new ValidationError('Invalid session lifetime.');
        }

        this.lifetimeMs = lifetimeMs;
    }

    create(identity, device, resource, now = Date.now()) {
        const session = {
            id: createIdentifier(),
            userId: identity.id,
            deviceId: device.id,
            resourceId: resource.id,
            deviceVersion: device.version,
            createdAt: now,
            expiresAt: now + this.lifetimeMs,
            state: SessionState.ACTIVE,
            lastEvaluatedAt: now
        };

        this.#sessions.set(session.id, session);

        return Object.freeze({ ...session });
    }

    get(id, now = Date.now()) {
        const session = this.#sessions.get(id);

        if (!session) {
            throw new SessionError('Unknown session.');
        }

        if (session.state !== SessionState.ACTIVE) {
            throw new SessionError('Session is not active.');
        }

        if (now >= session.expiresAt) {
            session.state = SessionState.EXPIRED;
            throw new SessionError('Session expired.');
        }

        return session;
    }

    revoke(id) {
        const session = this.#sessions.get(id);

        if (!session) {
            throw new SessionError('Unknown session.');
        }

        session.state = SessionState.REVOKED;
    }

    activeCount() {
        return [...this.#sessions.values()].filter(
            session => session.state === SessionState.ACTIVE
        ).length;
    }
}

// ---------------------------------------------------------
// Zero Trust orchestration
// ---------------------------------------------------------

class ZeroTrustEngine {

    constructor() {
        this.identities = new IdentityRegistry();
        this.devices = new DeviceRegistry();
        this.resources = new ResourceRegistry();
        this.policy = new AccessPolicy(this.devices);
        this.sessions = new SessionManager();
        this.events = new SecurityEventBus();

        this.events.on('security-event', event => {
            console.log(
                `[SECURITY EVENT] ${event.decision}: ${event.reason}`
            );
        });
    }

    async requestAccess(request) {
        let resourceId = request.resourceId || 'UNKNOWN';

        try {
            const identity = this.identities.authenticate(request.userId);
            const device = this.devices.get(request.deviceId);
            const resource = this.resources.get(request.resourceId);

            const result = this.policy.evaluate(
                identity,
                device,
                resource,
                request.context
            );

            if (!result.allowed) {
                this.events.publish({
                    decision: Decision.DENY,
                    userId: identity.id,
                    resourceId,
                    reason: result.reason
                });

                return { decision: Decision.DENY, session: null };
            }

            const session = this.sessions.create(
                identity,
                device,
                resource
            );

            this.events.publish({
                decision: Decision.ALLOW,
                userId: identity.id,
                resourceId,
                sessionId: session.id,
                reason: result.reason
            });

            return {
                decision: Decision.ALLOW,
                session
            };

        } catch (error) {
            if (!(error instanceof SecurityError)) {
                throw error;
            }

            this.events.publish({
                decision: Decision.DENY,
                userId: request.userId || 'UNKNOWN',
                resourceId,
                reason: error.message
            });

            return { decision: Decision.DENY, session: null };
        }
    }

    async reevaluateSession(sessionId, context) {
        let session;

        try {
            session = this.sessions.get(sessionId);

            const identity = this.identities.authenticate(session.userId);
            const device = this.devices.get(session.deviceId);
            const resource = this.resources.get(session.resourceId);

            const result = this.policy.evaluate(
                identity,
                device,
                resource,
                context
            );

            // Device posture changes invalidate the original session context.
            if (
                device.version !== session.deviceVersion ||
                !result.allowed
            ) {
                this.sessions.revoke(sessionId);

                this.events.publish({
                    decision: Decision.REVOKE,
                    userId: identity.id,
                    resourceId: resource.id,
                    sessionId,
                    reason: result.allowed
                        ? 'Device posture changed.'
                        : result.reason
                });

                return Decision.REVOKE;
            }

            session.lastEvaluatedAt = Date.now();

            this.events.publish({
                decision: Decision.ALLOW,
                userId: identity.id,
                resourceId: resource.id,
                sessionId,
                reason: 'Continuous verification passed.'
            });

            return Decision.ALLOW;

        } catch (error) {
            if (session) {
                try {
                    this.sessions.revoke(sessionId);
                } catch {
                    // Preserve the original failure.
                }
            }

            this.events.publish({
                decision: Decision.REVOKE,
                userId: session?.userId || 'UNKNOWN',
                resourceId: session?.resourceId || 'UNKNOWN',
                sessionId,
                reason: error.message
            });

            return Decision.REVOKE;
        }
    }
}

// ---------------------------------------------------------
// Demonstration
// ---------------------------------------------------------

async function main() {

    const engine = new ZeroTrustEngine();

    engine.identities.register({
        id: 'USR-100',
        username: 'security-analyst',
        roles: ['SECURITY_ANALYST'],
        enabled: true,
        mfaVerified: true
    });

    engine.devices.register({
        id: 'DEV-100',
        ownerId: 'USR-100',
        managed: true,
        encrypted: true,
        patched: true,
        endpointProtected: true,
        riskScore: 5
    });

    engine.resources.register({
        id: 'RES-100',
        name: 'Security Operations Dashboard',
        zone: Zone.RESTRICTED,
        roles: ['SECURITY_ANALYST'],
        actions: ['READ'],
        minimumTrust: Trust.VERIFIED,
        requireMFA: true
    });

    engine.resources.register({
        id: 'RES-200',
        name: 'Production Control Plane',
        zone: Zone.CRITICAL,
        roles: ['SECURITY_ADMIN'],
        actions: ['ADMIN'],
        minimumTrust: Trust.HIGH,
        requireMFA: true
    });

    const context = {
        sourceIP: '10.0.0.25',
        networkZone: 'VPN',
        action: 'READ',
        riskScore: 5
    };

    const result = await engine.requestAccess({
        userId: 'USR-100',
        deviceId: 'DEV-100',
        resourceId: 'RES-100',
        context
    });

    console.log('\nInitial authorization:', result.decision);

    if (result.decision !== Decision.ALLOW) {
        throw new Error('Expected access to be granted.');
    }

    // Simulate an endpoint security posture change.
    engine.devices.updatePosture('DEV-100', {
        riskScore: 95
    });

    const reevaluation = await engine.reevaluateSession(
        result.session.id,
        {
            ...context,
            riskScore: 5
        }
    );

    console.log('Continuous reevaluation:', reevaluation);

    if (reevaluation !== Decision.REVOKE) {
        throw new Error('Expected session revocation.');
    }

    const denied = await engine.requestAccess({
        userId: 'USR-100',
        deviceId: 'DEV-100',
        resourceId: 'RES-100',
        context
    });

    console.log('Noncompliant device request:', denied.decision);

    if (denied.decision !== Decision.DENY) {
        throw new Error('Expected access denial.');
    }

    await engine.events.exportJSON('zero-trust-events.json');

    console.log('\nAudit events:', engine.events.events.length);
    console.log('Active sessions:', engine.sessions.activeCount());
    console.log('All assertions passed.');
}

main().catch(error => {
    console.error('Security engine failure:', error.message);
    process.exitCode = 1;
});
