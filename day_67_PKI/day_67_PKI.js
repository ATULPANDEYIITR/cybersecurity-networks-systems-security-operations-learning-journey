"use strict";

/*
 * Public Key Infrastructure (PKI)
 *
 * Event-driven certificate lifecycle and trust policy engine.
 *
 * Features:
 * - Root and intermediate CAs
 * - End-entity certificate issuance
 * - CA authorization and path constraints
 * - Certificate expiration
 * - Trust-chain construction
 * - Revocation registry
 * - Renewal and replacement
 * - Asynchronous lifecycle events
 * - Audit history
 *
 * This is a PKI lifecycle simulation, not an X.509 cryptographic
 * signature verification implementation.
 */

const crypto = require("node:crypto");
const EventEmitter = require("node:events");

const CAType = Object.freeze({
    ROOT: "ROOT",
    INTERMEDIATE: "INTERMEDIATE",
    END_ENTITY: "END_ENTITY"
});

const Status = Object.freeze({
    ACTIVE: "ACTIVE",
    EXPIRED: "EXPIRED",
    REVOKED: "REVOKED",
    NOT_YET_VALID: "NOT_YET_VALID"
});

const RevocationReason = Object.freeze({
    KEY_COMPROMISE: "KEY_COMPROMISE",
    CA_COMPROMISE: "CA_COMPROMISE",
    SUPERSEDED: "SUPERSEDED",
    CESSATION: "CESSATION_OF_OPERATION",
    PRIVILEGE_WITHDRAWN: "PRIVILEGE_WITHDRAWN"
});

class PKIError extends Error {}
class ValidationError extends PKIError {}
class IssuanceError extends PKIError {}
class RevocationError extends PKIError {}

function createIdentifier(prefix) {
    return `${prefix}-${crypto.randomBytes(12).toString("hex").toUpperCase()}`;
}

function fingerprint(subject, serial) {
    return crypto
        .createHash("sha256")
        .update(`${subject}:${serial}`)
        .digest("hex");
}

class Certificate {
    constructor({
        id,
        serial,
        subject,
        issuerId,
        type,
        notBefore,
        notAfter,
        isCA,
        pathLength,
        keyUsage,
        subjectKeyId,
        authorityKeyId
    }) {
        this.id = id;
        this.serial = serial;
        this.subject = subject;
        this.issuerId = issuerId;
        this.type = type;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.isCA = isCA;
        this.pathLength = pathLength;
        this.keyUsage = new Set(keyUsage);
        this.subjectKeyId = subjectKeyId;
        this.authorityKeyId = authorityKeyId;
        this.revokedAt = null;
        this.revocationReason = null;
        this.replacementId = null;
    }

    getStatus(now = new Date()) {
        if (this.revokedAt) return Status.REVOKED;
        if (now < this.notBefore) return Status.NOT_YET_VALID;
        if (now >= this.notAfter) return Status.EXPIRED;
        return Status.ACTIVE;
    }

    toJSON() {
        return {
            id: this.id,
            serial: this.serial,
            subject: this.subject,
            issuerId: this.issuerId,
            type: this.type,
            notBefore: this.notBefore.toISOString(),
            notAfter: this.notAfter.toISOString(),
            status: this.getStatus(),
            isCA: this.isCA,
            keyUsage: [...this.keyUsage],
            replacementId: this.replacementId
        };
    }
}

class PKIManager extends EventEmitter {
    #certificates = new Map();
    #authorities = new Map();
    #trustAnchors = new Set();
    #revocations = new Map();
    #audit = [];
    #queue = Promise.resolve();

    constructor(organization) {
        super();

        if (!organization?.trim()) {
            throw new ValidationError("Organization is required.");
        }

        this.organization = organization;
    }

    #record(action, certificateId, details) {
        const event = Object.freeze({
            timestamp: new Date().toISOString(),
            action,
            certificateId,
            details
        });

        this.#audit.push(event);
        this.emit("lifecycle", event);
    }

    #register(certificate) {
        if (this.#certificates.has(certificate.id)) {
            throw new PKIError("Duplicate certificate identifier.");
        }

        this.#certificates.set(certificate.id, certificate);
    }

    #getCA(id) {
        const ca = this.#authorities.get(id);

        if (!ca || !ca.active) {
            throw new IssuanceError("Unknown or inactive CA.");
        }

        return ca;
    }

    #validateCA(cert, now = new Date()) {
        if (!cert.isCA) {
            throw new ValidationError("Certificate is not a CA.");
        }

        if (cert.getStatus(now) !== Status.ACTIVE) {
            throw new ValidationError("CA certificate is not valid.");
        }

        if (!cert.keyUsage.has("keyCertSign")) {
            throw new ValidationError("CA cannot sign certificates.");
        }
    }

    createRootCA(subject, validityDays = 3650, pathLength = 2) {
        if (!subject?.trim() || validityDays <= 0 || pathLength < 0) {
            throw new ValidationError("Invalid root CA configuration.");
        }

        const now = new Date();
        const serial = crypto.randomBytes(16).toString("hex").toUpperCase();
        const id = createIdentifier("ROOT");

        const cert = new Certificate({
            id,
            serial,
            subject,
            issuerId: null,
            type: CAType.ROOT,
            notBefore: now,
            notAfter: new Date(now.getTime() + validityDays * 86400000),
            isCA: true,
            pathLength,
            keyUsage: ["keyCertSign", "cRLSign"],
            subjectKeyId: fingerprint(subject, serial),
            authorityKeyId: null
        });

        this.#register(cert);

        this.#authorities.set(id, {
            certificate: cert,
            maxValidityDays: validityDays,
            active: true,
            issued: new Set()
        });

        this.#trustAnchors.add(id);
        this.#record("ROOT_CREATED", id, subject);

        return cert;
    }

    createIntermediateCA(parentId, subject, validityDays = 730, pathLength = 0) {
        const parent = this.#getCA(parentId);
        const parentCert = parent.certificate;

        this.#validateCA(parentCert);

        if (!subject?.trim() || validityDays <= 0 || pathLength < 0) {
            throw new ValidationError("Invalid intermediate CA configuration.");
        }

        if (
            parentCert.pathLength !== null &&
            parentCert.pathLength <= 0
        ) {
            throw new IssuanceError("Parent CA path length exceeded.");
        }

        const now = new Date();
        const serial = crypto.randomBytes(16).toString("hex").toUpperCase();
        const id = createIdentifier("INT");

        const requestedExpiry = new Date(
            now.getTime() + validityDays * 86400000
        );

        const cert = new Certificate({
            id,
            serial,
            subject,
            issuerId: parentId,
            type: CAType.INTERMEDIATE,
            notBefore: now,
            notAfter: new Date(
                Math.min(requestedExpiry.getTime(), parentCert.notAfter.getTime())
            ),
            isCA: true,
            pathLength,
            keyUsage: ["keyCertSign", "cRLSign"],
            subjectKeyId: fingerprint(subject, serial),
            authorityKeyId: parentCert.subjectKeyId
        });

        if (cert.notAfter <= now) {
            throw new IssuanceError("Parent CA expires too soon.");
        }

        this.#register(cert);

        this.#authorities.set(id, {
            certificate: cert,
            maxValidityDays: validityDays,
            active: true,
            issued: new Set()
        });

        parent.issued.add(id);
        this.#record("INTERMEDIATE_CREATED", id, parentId);

        return cert;
    }

    issueCertificate(issuerId, subject, validityDays = 90, keyUsage = ["digitalSignature"]) {
        const issuer = this.#getCA(issuerId);
        const parent = issuer.certificate;

        this.#validateCA(parent);

        if (!subject?.trim() || validityDays <= 0) {
            throw new ValidationError("Invalid subject or validity period.");
        }

        if (validityDays > issuer.maxValidityDays) {
            throw new IssuanceError("Maximum certificate lifetime exceeded.");
        }

        const allowed = new Set([
            "digitalSignature",
            "keyEncipherment",
            "keyAgreement",
            "dataEncipherment",
            "contentCommitment"
        ]);

        if (
            !Array.isArray(keyUsage) ||
            keyUsage.length === 0 ||
            keyUsage.some(usage => !allowed.has(usage))
        ) {
            throw new ValidationError("Invalid end-entity key usage.");
        }

        const now = new Date();
        const serial = crypto.randomBytes(16).toString("hex").toUpperCase();
        const id = createIdentifier("LEAF");

        const requestedExpiry = new Date(
            now.getTime() + validityDays * 86400000
        );

        const cert = new Certificate({
            id,
            serial,
            subject,
            issuerId,
            type: CAType.END_ENTITY,
            notBefore: now,
            notAfter: new Date(
                Math.min(requestedExpiry.getTime(), parent.notAfter.getTime())
            ),
            isCA: false,
            pathLength: null,
            keyUsage,
            subjectKeyId: fingerprint(subject, serial),
            authorityKeyId: parent.subjectKeyId
        });

        if (cert.notAfter <= now) {
            throw new IssuanceError("Issuer expires too soon.");
        }

        this.#register(cert);
        issuer.issued.add(id);

        this.#record("CERTIFICATE_ISSUED", id, issuerId);

        return cert;
    }

    buildChain(certificateId) {
        const chain = [];
        const visited = new Set();
        let current = this.#certificates.get(certificateId);

        if (!current) {
            throw new ValidationError("Certificate not found.");
        }

        while (current) {
            if (visited.has(current.id)) {
                throw new ValidationError("Certificate chain cycle detected.");
            }

            visited.add(current.id);
            chain.push(current);

            if (current.issuerId === null) break;

            const parent = this.#certificates.get(current.issuerId);

            if (!parent) {
                throw new ValidationError("Issuer certificate is missing.");
            }

            if (current.authorityKeyId !== parent.subjectKeyId) {
                throw new ValidationError("Authority key identifier mismatch.");
            }

            current = parent;
        }

        return chain;
    }

    validateCertificate(certificateId, now = new Date()) {
        try {
            const chain = this.buildChain(certificateId);

            if (!this.#trustAnchors.has(chain.at(-1).id)) {
                throw new ValidationError("Untrusted root.");
            }

            for (let index = 0; index < chain.length; index++) {
                const cert = chain[index];

                if (cert.getStatus(now) !== Status.ACTIVE) {
                    throw new ValidationError(
                        `${cert.id} is ${cert.getStatus(now)}`
                    );
                }

                if (index > 0) {
                    const parent = chain[index - 1];

                    if (cert.issuerId !== parent.id) {
                        throw new ValidationError("Invalid issuer relationship.");
                    }

                    if (cert.isCA && !cert.keyUsage.has("keyCertSign")) {
                        throw new ValidationError("Invalid CA key usage.");
                    }

                    if (
                        parent.pathLength !== null &&
                        chain.slice(0, index).filter(item => item.isCA).length >
                        parent.pathLength
                    ) {
                        throw new ValidationError("Path length exceeded.");
                    }
                }
            }

            return {
                valid: true,
                chain: chain.map(cert => cert.id),
                message: "Structurally valid trusted certificate chain."
            };
        } catch (error) {
            return {
                valid: false,
                chain: [],
                message: error.message
            };
        }
    }

    revokeCertificate(id, reason) {
        const cert = this.#certificates.get(id);

        if (!cert) throw new RevocationError("Certificate not found.");

        if (cert.revokedAt) {
            throw new RevocationError("Certificate already revoked.");
        }

        if (!Object.values(RevocationReason).includes(reason)) {
            throw new RevocationError("Invalid revocation reason.");
        }

        cert.revokedAt = new Date();
        cert.revocationReason = reason;

        this.#revocations.set(id, {
            reason,
            revokedAt: cert.revokedAt
        });

        if (cert.isCA) {
            const authority = this.#authorities.get(id);
            if (authority) authority.active = false;
        }

        this.#record("CERTIFICATE_REVOKED", id, reason);

        return cert;
    }

    renewCertificate(id, validityDays = 90) {
        const old = this.#certificates.get(id);

        if (!old || old.type !== CAType.END_ENTITY) {
            throw new ValidationError("Invalid renewal target.");
        }

        if (old.getStatus() === Status.REVOKED) {
            throw new ValidationError("Revoked certificates cannot be renewed.");
        }

        const replacement = this.issueCertificate(
            old.issuerId,
            old.subject,
            validityDays,
            [...old.keyUsage]
        );

        old.replacementId = replacement.id;

        this.#record("CERTIFICATE_RENEWED", id, replacement.id);

        return replacement;
    }

    /*
     * Serializes lifecycle changes to avoid overlapping asynchronous
     * operations that update the same PKI registry.
     */
    enqueue(operation) {
        const task = this.#queue.then(() => operation());

        this.#queue = task.catch(() => undefined);

        return task;
    }

    get auditLog() {
        return this.#audit.map(event => ({ ...event }));
    }

    get inventory() {
        return [...this.#certificates.values()].map(cert => cert.toJSON());
    }

    get revocationRegistry() {
        return new Map(this.#revocations);
    }
}

async function main() {
    const pki = new PKIManager("Example Enterprise");

    pki.on("lifecycle", event => {
        console.log(
            `[AUDIT] ${event.action}: ${event.certificateId}`
        );
    });

    console.log("\nPUBLIC KEY INFRASTRUCTURE DEMONSTRATION");

    const root = pki.createRootCA(
        "CN=Enterprise Root CA",
        3650,
        2
    );

    const intermediate = pki.createIntermediateCA(
        root.id,
        "CN=Enterprise Issuing CA",
        730,
        0
    );

    const server = await pki.enqueue(() =>
        pki.issueCertificate(
            intermediate.id,
            "DNS=api.example.com",
            90,
            ["digitalSignature", "keyEncipherment"]
        )
    );

    const client = pki.issueCertificate(
        intermediate.id,
        "CN=application-client",
        60
    );

    console.log("\nISSUED CERTIFICATES");

    console.table([
        root.toJSON(),
        intermediate.toJSON(),
        server.toJSON(),
        client.toJSON()
    ]);

    console.log("\nTRUST VALIDATION");
    console.log(pki.validateCertificate(server.id));

    console.log("\nCERTIFICATE CHAIN");
    console.table(
        pki.buildChain(server.id).map(cert => ({
            id: cert.id,
            subject: cert.subject,
            type: cert.type
        }))
    );

    console.log("\nRENEWAL");

    const replacement = pki.renewCertificate(server.id, 120);

    console.log("Original:", server.id);
    console.log("Replacement:", replacement.id);

    console.log("\nREVOCATION");

    pki.revokeCertificate(
        client.id,
        RevocationReason.KEY_COMPROMISE
    );

    console.log(pki.validateCertificate(client.id));

    console.log("\nERROR HANDLING");

    try {
        pki.revokeCertificate(
            client.id,
            RevocationReason.KEY_COMPROMISE
        );
    } catch (error) {
        console.log("Expected:", error.message);
    }

    try {
        pki.issueCertificate(
            intermediate.id,
            "CN=invalid",
            5000
        );
    } catch (error) {
        console.log("Expected:", error.message);
    }

    console.log("\nFINAL INVENTORY");
    console.table(pki.inventory);

    console.log("\nAUDIT EVENT COUNT:", pki.auditLog.length);

    if (!pki.validateCertificate(replacement.id).valid) {
        throw new Error("Replacement certificate validation failed.");
    }

    if (pki.validateCertificate(client.id).valid) {
        throw new Error("Revoked certificate was incorrectly accepted.");
    }

    console.log("\nAll PKI lifecycle checks passed.");
}

main().catch(error => {
    console.error("PKI execution failed:", error.message);
    process.exitCode = 1;
});
