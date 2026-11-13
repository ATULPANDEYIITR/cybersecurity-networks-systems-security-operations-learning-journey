"use strict";

/*
 * KERBEROS AUTHENTICATION ENGINE
 *
 * Node.js implementation using:
 * - EventEmitter
 * - Promises and asynchronous authentication
 * - Maps and Sets
 * - HMAC-SHA256
 * - TGT and service tickets
 * - Ticket policy evaluation
 * - Replay protection
 * - Mutual authentication
 * - Authentication event monitoring
 *
 * Educational model. Ticket contents are signed, not encrypted.
 * Production Kerberos requires protocol-compatible encryption,
 * message formats, key management, and clock synchronization.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

class KerberosError extends Error {}
class InvalidCredentialsError extends KerberosError {}
class InvalidTicketError extends KerberosError {}
class ExpiredTicketError extends KerberosError {}
class ReplayDetectedError extends KerberosError {}
class UnknownPrincipalError extends KerberosError {}

const TicketType = Object.freeze({
    TGT: "TGT",
    SERVICE: "SERVICE"
});

const AuthenticationStatus = Object.freeze({
    PENDING: "PENDING",
    AUTHENTICATED: "AUTHENTICATED",
    DENIED: "DENIED"
});

function encode(value) {
    return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function decode(value) {
    try {
        return JSON.parse(
            Buffer.from(value, "base64url").toString("utf8")
        );
    } catch {
        throw new InvalidTicketError("Invalid ticket encoding");
    }
}

function sign(data, key) {
    return crypto
        .createHmac("sha256", key)
        .update(data)
        .digest("hex");
}

function constantTimeEqual(a, b) {
    const left = Buffer.from(String(a), "hex");
    const right = Buffer.from(String(b), "hex");

    return left.length === right.length &&
        crypto.timingSafeEqual(left, right);
}

function createTicket(payload, key) {
    const body = encode(payload);

    return {
        body,
        signature: sign(body, key)
    };
}

function validateTicket(ticket, key) {
    if (
        !ticket ||
        typeof ticket.body !== "string" ||
        typeof ticket.signature !== "string"
    ) {
        throw new InvalidTicketError("Malformed ticket");
    }

    const expected = sign(ticket.body, key);

    if (!constantTimeEqual(expected, ticket.signature)) {
        throw new InvalidTicketError("Ticket integrity failure");
    }

    return decode(ticket.body);
}

class Principal {
    constructor(name, salt, passwordVerifier, roles = []) {
        this.name = name;
        this.salt = salt;
        this.passwordVerifier = passwordVerifier;
        this.roles = new Set(roles);
        Object.freeze(this.roles);
    }
}

class TicketPolicy {
    constructor({
        ticketLifetimeMs = 300000,
        clockToleranceMs = 60000,
        maximumClockDriftMs = 30000
    } = {}) {
        if (
            ticketLifetimeMs <= 0 ||
            clockToleranceMs < 0 ||
            maximumClockDriftMs < 0
        ) {
            throw new RangeError("Invalid ticket policy");
        }

        this.ticketLifetimeMs = ticketLifetimeMs;
        this.clockToleranceMs = clockToleranceMs;
        this.maximumClockDriftMs = maximumClockDriftMs;
    }

    validateLifetime(ticket, now) {
        if (
            !Number.isFinite(ticket.issuedAt) ||
            !Number.isFinite(ticket.expiresAt) ||
            ticket.expiresAt <= ticket.issuedAt
        ) {
            throw new InvalidTicketError("Invalid ticket timestamps");
        }

        if (now >= ticket.expiresAt) {
            throw new ExpiredTicketError("Ticket expired");
        }

        if (ticket.issuedAt > now + this.maximumClockDriftMs) {
            throw new InvalidTicketError("Ticket issued in the future");
        }
    }

    validateAuthenticator(timestamp, now) {
        if (
            !Number.isFinite(timestamp) ||
            Math.abs(now - timestamp) > this.clockToleranceMs
        ) {
            throw new InvalidTicketError(
                "Authenticator outside clock tolerance"
            );
        }
    }
}

class ReplayProtection {
    constructor() {
        this.seen = new Map();
    }

    accept(ticketId, nonce, expiresAt, now) {
        for (const [key, expiry] of this.seen) {
            if (expiry <= now) {
                this.seen.delete(key);
            }
        }

        const key = `${ticketId}:${nonce}`;

        if (this.seen.has(key)) {
            throw new ReplayDetectedError("Duplicate authenticator");
        }

        this.seen.set(key, expiresAt);
    }
}

class KeyDistributionCenter extends EventEmitter {
    constructor(realm, policy = new TicketPolicy()) {
        super();

        if (!realm || !realm.includes(".")) {
            throw new TypeError("A valid Kerberos realm is required");
        }

        this.realm = realm.toUpperCase();
        this.policy = policy;

        this.principals = new Map();
        this.services = new Map();

        this.tgsKey = crypto.randomBytes(32);
        this.replayProtection = new ReplayProtection();

        this.audit = [];
    }

    record(event, details) {
        const entry = Object.freeze({
            event,
            timestamp: Date.now(),
            ...details
        });

        this.audit.push(entry);
        this.emit(event, entry);
        this.emit("audit", entry);
    }

    async registerPrincipal(name, password, roles = []) {
        if (
            typeof name !== "string" ||
            !name.includes("@") ||
            typeof password !== "string" ||
            password.length < 12
        ) {
            throw new TypeError("Invalid principal registration");
        }

        if (this.principals.has(name)) {
            throw new KerberosError("Principal already exists");
        }

        const salt = crypto.randomBytes(16);

        const verifier = await new Promise((resolve, reject) => {
            crypto.scrypt(password, salt, 32, (error, result) => {
                if (error) reject(error);
                else resolve(result);
            });
        });

        this.principals.set(
            name,
            new Principal(name, salt, verifier, roles)
        );

        this.record("principal.registered", { principal: name });
    }

    registerService(name) {
        if (
            typeof name !== "string" ||
            !name.includes("/") ||
            this.services.has(name)
        ) {
            throw new TypeError("Invalid or duplicate service");
        }

        this.services.set(name, crypto.randomBytes(32));

        this.record("service.registered", { service: name });
    }

    async authenticateAS(name, password) {
        const principal = this.principals.get(name);

        if (!principal) {
            throw new UnknownPrincipalError("Unknown principal");
        }

        const candidate = await new Promise((resolve, reject) => {
            crypto.scrypt(
                password,
                principal.salt,
                32,
                (error, result) => {
                    if (error) reject(error);
                    else resolve(result);
                }
            );
        });

        if (!crypto.timingSafeEqual(
            candidate,
            principal.passwordVerifier
        )) {
            this.record("as.denied", { principal: name });
            throw new InvalidCredentialsError("Invalid credentials");
        }

        const now = Date.now();

        const sessionKey = crypto.randomBytes(32);

        const payload = {
            type: TicketType.TGT,
            client: name,
            realm: this.realm,
            ticketId: crypto.randomUUID(),
            issuedAt: now,
            expiresAt: now + this.policy.ticketLifetimeMs,
            sessionKey: sessionKey.toString("base64")
        };

        const ticket = createTicket(payload, this.tgsKey);

        this.record("as.tgt.issued", { principal: name });

        return Object.freeze({
            ticket,
            sessionKey
        });
    }

    authenticateTGS(tgt, serviceName) {
        const serviceKey = this.services.get(serviceName);

        if (!serviceKey) {
            throw new UnknownPrincipalError("Unknown service");
        }

        const payload = validateTicket(tgt, this.tgsKey);

        if (
            payload.type !== TicketType.TGT ||
            payload.realm !== this.realm
        ) {
            throw new InvalidTicketError("Invalid TGT");
        }

        this.policy.validateLifetime(payload, Date.now());

        const now = Date.now();

        const serviceSessionKey = crypto.randomBytes(32);

        const serviceTicket = createTicket(
            {
                type: TicketType.SERVICE,
                client: payload.client,
                service: serviceName,
                ticketId: crypto.randomUUID(),
                issuedAt: now,
                expiresAt: Math.min(
                    now + this.policy.ticketLifetimeMs,
                    payload.expiresAt
                ),
                sessionKey: serviceSessionKey.toString("base64")
            },
            serviceKey
        );

        this.record("tgs.service.issued", {
            principal: payload.client,
            service: serviceName
        });

        return Object.freeze({
            ticket: serviceTicket,
            sessionKey: serviceSessionKey
        });
    }

    validateServiceAccess(ticket, serviceName, authenticator) {
        const serviceKey = this.services.get(serviceName);

        if (!serviceKey) {
            throw new UnknownPrincipalError("Unknown service");
        }

        const payload = validateTicket(ticket, serviceKey);

        if (
            payload.type !== TicketType.SERVICE ||
            payload.service !== serviceName
        ) {
            throw new InvalidTicketError("Service mismatch");
        }

        const now = Date.now();

        this.policy.validateLifetime(payload, now);

        const key = Buffer.from(payload.sessionKey, "base64");

        const {
            client,
            timestamp,
            nonce,
            signature
        } = authenticator || {};

        if (
            client !== payload.client ||
            typeof nonce !== "string" ||
            nonce.length < 16
        ) {
            throw new InvalidTicketError("Invalid authenticator fields");
        }

        this.policy.validateAuthenticator(timestamp, now);

        const message = `${client}|${serviceName}|${timestamp}|${nonce}`;

        const expected = sign(message, key);

        if (!constantTimeEqual(expected, signature)) {
            throw new InvalidTicketError("Authenticator signature invalid");
        }

        this.replayProtection.accept(
            payload.ticketId,
            nonce,
            payload.expiresAt,
            now
        );

        const serverProof = sign(
            `SERVER|${client}|${serviceName}|${nonce}`,
            key
        );

        this.record("service.authenticated", {
            principal: client,
            service: serviceName
        });

        return Object.freeze({
            authenticated: true,
            serverProof
        });
    }

    createAuthenticator(client, service, sessionKey) {
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(16).toString("hex");

        const message = `${client}|${service}|${timestamp}|${nonce}`;

        return Object.freeze({
            client,
            timestamp,
            nonce,
            signature: sign(message, sessionKey)
        });
    }

    verifyServerProof(
        client,
        service,
        nonce,
        sessionKey,
        serverProof
    ) {
        const expected = sign(
            `SERVER|${client}|${service}|${nonce}`,
            sessionKey
        );

        return constantTimeEqual(expected, serverProof);
    }
}

class KerberosClient {
    constructor(name, kdc) {
        this.name = name;
        this.kdc = kdc;
        this.status = AuthenticationStatus.PENDING;
        this.tgt = null;
        this.serviceSessions = new Map();
    }

    async login(password) {
        try {
            const response = await this.kdc.authenticateAS(
                this.name,
                password
            );

            this.tgt = response.ticket;
            this.status = AuthenticationStatus.AUTHENTICATED;

            return true;
        } catch (error) {
            this.status = AuthenticationStatus.DENIED;
            throw error;
        }
    }

    async accessService(serviceName) {
        if (!this.tgt) {
            throw new KerberosError("Client must authenticate first");
        }

        const response = this.kdc.authenticateTGS(
            this.tgt,
            serviceName
        );

        const authenticator = this.kdc.createAuthenticator(
            this.name,
            serviceName,
            response.sessionKey
        );

        const result = this.kdc.validateServiceAccess(
            response.ticket,
            serviceName,
            authenticator
        );

        if (!this.kdc.verifyServerProof(
            this.name,
            serviceName,
            authenticator.nonce,
            response.sessionKey,
            result.serverProof
        )) {
            throw new InvalidTicketError("Mutual authentication failed");
        }

        this.serviceSessions.set(serviceName, {
            ticket: response.ticket,
            sessionKey: response.sessionKey
        });

        this.status = AuthenticationStatus.AUTHENTICATED;

        return true;
    }
}

async function main() {
    const kdc = new KeyDistributionCenter(
        "EXAMPLE.LOCAL",
        new TicketPolicy({
            ticketLifetimeMs: 300000,
            clockToleranceMs: 60000
        })
    );

    kdc.on("audit", event => {
        console.log(
            `[AUDIT] ${event.event}`,
            event.principal || event.service || ""
        );
    });

    await kdc.registerPrincipal(
        "alice@EXAMPLE.LOCAL",
        "StrongPassword2026!",
        ["developer"]
    );

    kdc.registerService("http/web.example.local");
    kdc.registerService("postgres/db.example.local");

    const client = new KerberosClient("alice@EXAMPLE.LOCAL", kdc);

    console.log("\n1. Authentication Server");
    await client.login("StrongPassword2026!");
    console.log("TGT obtained:", client.status);

    console.log("\n2. Ticket Granting Server");
    await client.accessService("http/web.example.local");
    console.log("HTTP service authenticated");

    console.log("\n3. Database service");
    await client.accessService("postgres/db.example.local");
    console.log("Database service authenticated");

    console.log("\n4. Invalid credentials");

    try {
        await kdc.authenticateAS(
            "alice@EXAMPLE.LOCAL",
            "WrongPassword"
        );
    } catch (error) {
        console.log("Rejected:", error.message);
    }

    console.log("\n5. Authentication audit count");
    console.log(kdc.audit.length);

    console.log("\n6. Ticket replay protection");

    const response = kdc.authenticateTGS(
        client.tgt,
        "http/web.example.local"
    );

    const authenticator = kdc.createAuthenticator(
        client.name,
        "http/web.example.local",
        response.sessionKey
    );

    kdc.validateServiceAccess(
        response.ticket,
        "http/web.example.local",
        authenticator
    );

    try {
        kdc.validateServiceAccess(
            response.ticket,
            "http/web.example.local",
            authenticator
        );
    } catch (error) {
        console.log("Replay rejected:", error.message);
    }

    console.log("\nKerberos simulation completed.");
}

main().catch(error => {
    console.error("Authentication system failure:", error.message);
    process.exitCode = 1;
});
