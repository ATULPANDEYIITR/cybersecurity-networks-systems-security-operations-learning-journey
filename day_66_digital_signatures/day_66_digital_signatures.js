"use strict";

/*
 * Digital Signatures
 * Node.js 20+ recommended.
 *
 * Demonstrates:
 * - Ed25519 signing and verification
 * - SHA-256 document fingerprints
 * - Certificate issuance and verification
 * - Trust anchors
 * - Certificate expiration and revocation
 * - Event-driven verification
 *
 * Uses only Node.js built-in modules.
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");

const SignatureStatus = Object.freeze({
    VALID: "VALID",
    INVALID: "INVALID",
    EXPIRED: "EXPIRED",
    REVOKED: "REVOKED",
    UNTRUSTED: "UNTRUSTED"
});

class SecurityError extends Error {}

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function canonicalize(value) {
    if (Array.isArray(value)) {
        return `[${value.map(canonicalize).join(",")}]`;
    }

    if (value !== null && typeof value === "object") {
        return `{${Object.keys(value)
            .sort()
            .map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`)
            .join(",")}}`;
    }

    return JSON.stringify(value);
}

function publicKeyFingerprint(publicKey) {
    return sha256(
        publicKey.export({
            type: "spki",
            format: "der"
        })
    );
}

class KeyIdentity {
    constructor(name) {
        if (typeof name !== "string" || !name.trim()) {
            throw new TypeError("Identity name is required");
        }

        this.name = name;

        const pair = crypto.generateKeyPairSync("ed25519");

        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;
    }

    sign(data) {
        const buffer = Buffer.from(data);

        if (buffer.length === 0) {
            throw new TypeError("Cannot sign an empty document");
        }

        return crypto.sign(null, buffer, this.privateKey);
    }

    exportPublicKey() {
        return this.publicKey.export({
            type: "spki",
            format: "pem"
        });
    }
}

class CertificateAuthority {
    constructor(name) {
        if (!name) {
            throw new TypeError("CA name is required");
        }

        this.name = name;

        const pair = crypto.generateKeyPairSync("ed25519");

        this.privateKey = pair.privateKey;
        this.publicKey = pair.publicKey;
    }

    issue(subject, publicKey, validityMs = 365 * 86400000) {
        if (!subject || !publicKey) {
            throw new TypeError("Subject and public key are required");
        }

        if (!Number.isFinite(validityMs) || validityMs <= 0) {
            throw new RangeError("Invalid certificate validity");
        }

        const now = Date.now();

        const certificate = {
            subject,
            issuer: this.name,
            publicKey: publicKey.export({
                type: "spki",
                format: "pem"
            }),
            serial: crypto.randomBytes(16).toString("hex"),
            notBefore: now,
            notAfter: now + validityMs
        };

        const payload = Buffer.from(canonicalize(certificate));

        return Object.freeze({
            ...certificate,
            signature: crypto.sign(
                null,
                payload,
                this.privateKey
            ).toString("base64")
        });
    }
}

class TrustStore {
    constructor() {
        this.trustedAuthorities = new Map();
        this.revokedSerials = new Set();
    }

    addAuthority(name, publicKey) {
        if (!name || !publicKey) {
            throw new TypeError("Invalid trust anchor");
        }

        this.trustedAuthorities.set(name, publicKey);
    }

    revoke(serial) {
        this.revokedSerials.add(serial);
    }

    verifyCertificate(certificate, now = Date.now()) {
        if (this.revokedSerials.has(certificate.serial)) {
            return SignatureStatus.REVOKED;
        }

        if (now < certificate.notBefore || now > certificate.notAfter) {
            return SignatureStatus.EXPIRED;
        }

        const issuerKey = this.trustedAuthorities.get(
            certificate.issuer
        );

        if (!issuerKey) {
            return SignatureStatus.UNTRUSTED;
        }

        const {
            signature,
            ...certificatePayload
        } = certificate;

        const valid = crypto.verify(
            null,
            Buffer.from(canonicalize(certificatePayload)),
            issuerKey,
            Buffer.from(signature, "base64")
        );

        return valid
            ? SignatureStatus.VALID
            : SignatureStatus.INVALID;
    }
}

class DocumentSignature {
    constructor({
        documentId,
        content,
        signer,
        certificate,
        signature
    }) {
        this.documentId = documentId;
        this.content = Buffer.from(content);
        this.signer = signer;
        this.certificate = certificate;
        this.signature = signature;
        this.digest = sha256(this.content);
        this.createdAt = new Date().toISOString();

        Object.freeze(this);
    }
}

class SignatureService extends EventEmitter {
    constructor(trustStore) {
        super();

        this.trustStore = trustStore;
        this.auditLog = [];
    }

    signDocument(documentId, content, identity, certificate) {
        if (!documentId || !content) {
            throw new TypeError("Document ID and content are required");
        }

        if (!(identity instanceof KeyIdentity)) {
            throw new TypeError("Invalid signer");
        }

        if (certificate.subject !== identity.name) {
            throw new SecurityError("Certificate identity mismatch");
        }

        const certifiedKey = crypto.createPublicKey(
            certificate.publicKey
        );

        if (
            publicKeyFingerprint(certifiedKey) !==
            publicKeyFingerprint(identity.publicKey)
        ) {
            throw new SecurityError("Certificate public key mismatch");
        }

        const signature = identity.sign(content);

        const signedDocument = new DocumentSignature({
            documentId,
            content,
            signer: identity.name,
            certificate,
            signature
        });

        this.emit("document:signed", {
            documentId,
            signer: identity.name,
            digest: signedDocument.digest
        });

        return signedDocument;
    }

    verifyDocument(signedDocument, now = Date.now()) {
        let status = this.trustStore.verifyCertificate(
            signedDocument.certificate,
            now
        );

        if (status === SignatureStatus.VALID) {
            const certificate = signedDocument.certificate;

            if (certificate.subject !== signedDocument.signer) {
                status = SignatureStatus.INVALID;
            } else if (
                sha256(signedDocument.content) !== signedDocument.digest
            ) {
                status = SignatureStatus.INVALID;
            } else {
                const publicKey = crypto.createPublicKey(
                    certificate.publicKey
                );

                const valid = crypto.verify(
                    null,
                    signedDocument.content,
                    publicKey,
                    signedDocument.signature
                );

                status = valid
                    ? SignatureStatus.VALID
                    : SignatureStatus.INVALID;
            }
        }

        const result = Object.freeze({
            documentId: signedDocument.documentId,
            signer: signedDocument.signer,
            status,
            verifiedAt: new Date(now).toISOString()
        });

        this.auditLog.push(result);
        this.emit("document:verified", result);

        return result;
    }
}

async function run() {
    const ca = new CertificateAuthority("Enterprise Root CA");

    const trustStore = new TrustStore();
    trustStore.addAuthority(ca.name, ca.publicKey);

    const alice = new KeyIdentity("alice@enterprise.example");

    const certificate = ca.issue(
        alice.name,
        alice.publicKey
    );

    const service = new SignatureService(trustStore);

    service.on("document:signed", event => {
        console.log("SIGN EVENT:", event);
    });

    service.on("document:verified", event => {
        console.log("VERIFICATION EVENT:", event);
    });

    const original = Buffer.from(
        "Contract ID: CT-2026-1001; Amount: INR 500000"
    );

    const signed = service.signDocument(
        "DOC-1001",
        original,
        alice,
        certificate
    );

    console.log("\nOriginal document:");
    console.log(service.verifyDocument(signed));

    const modified = new DocumentSignature({
        documentId: signed.documentId,
        content: Buffer.from(
            "Contract ID: CT-2026-1001; Amount: INR 900000"
        ),
        signer: signed.signer,
        certificate: signed.certificate,
        signature: signed.signature
    });

    console.log("\nModified document:");
    console.log(service.verifyDocument(modified));

    trustStore.revoke(certificate.serial);

    console.log("\nRevoked certificate:");
    console.log(service.verifyDocument(signed));

    const unknownStore = new TrustStore();

    console.log("\nUntrusted issuer:");
    console.log(
        unknownStore.verifyCertificate(certificate)
    );

    console.log("\nAudit records:", service.auditLog.length);

    // Promise-based verification can be integrated into asynchronous
    // document processing pipelines.
    const asynchronousResult = await Promise.resolve(
        service.verifyDocument(signed)
    );

    console.log("\nAsynchronous result:", asynchronousResult.status);
}

run().catch(error => {
    console.error("Digital signature processing failed:", error.message);
    process.exitCode = 1;
});
