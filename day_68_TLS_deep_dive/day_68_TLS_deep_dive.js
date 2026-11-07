"use strict";

/*
 * TLS Deep Dive: Node.js TLS diagnostics and security policy engine.
 *
 * Run:
 *   node tls_deep_dive.js
 *   node tls_deep_dive.js www.example.com 443
 *
 * Requires Node.js 18 or later.
 */

const tls = require("node:tls");
const net = require("node:net");
const crypto = require("node:crypto");
const { performance } = require("node:perf_hooks");
const { EventEmitter } = require("node:events");

const TLS_STATES = Object.freeze({
    CREATED: "CREATED",
    CONNECTING: "CONNECTING",
    ESTABLISHED: "ESTABLISHED",
    FAILED: "FAILED",
    CLOSED: "CLOSED"
});

const TLS_POLICY = Object.freeze({
    minimumVersion: "TLSv1.2",
    maximumVersion: "TLSv1.3",
    rejectUnauthorized: true,
    timeout: 8000,
    allowedTLS13: new Set([
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256"
    ]),
    allowedTLS12: new Set([
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-CHACHA20-POLY1305"
    ])
});

class TLSConfigurationError extends Error {
    constructor(message) {
        super(message);
        this.name = "TLSConfigurationError";
    }
}

class TLSHandshakeError extends Error {
    constructor(message, code = "TLS_HANDSHAKE_FAILED") {
        super(message);
        this.name = "TLSHandshakeError";
        this.code = code;
    }
}

class TLSConfiguration {
    constructor(options = {}) {
        this.minimumVersion =
            options.minimumVersion || TLS_POLICY.minimumVersion;

        this.maximumVersion =
            options.maximumVersion || TLS_POLICY.maximumVersion;

        this.timeout =
            options.timeout ?? TLS_POLICY.timeout;

        this.rejectUnauthorized =
            options.rejectUnauthorized ?? true;

        this.validate();
    }

    validate() {
        const supported = ["TLSv1.2", "TLSv1.3"];

        if (!supported.includes(this.minimumVersion)) {
            throw new TLSConfigurationError(
                "Unsupported minimum TLS version."
            );
        }

        if (!supported.includes(this.maximumVersion)) {
            throw new TLSConfigurationError(
                "Unsupported maximum TLS version."
            );
        }

        if (
            this.minimumVersion === "TLSv1.3" &&
            this.maximumVersion === "TLSv1.2"
        ) {
            throw new TLSConfigurationError(
                "Invalid TLS version range."
            );
        }

        if (!Number.isFinite(this.timeout) || this.timeout <= 0) {
            throw new TLSConfigurationError(
                "Timeout must be positive."
            );
        }

        if (typeof this.rejectUnauthorized !== "boolean") {
            throw new TLSConfigurationError(
                "Certificate verification must be boolean."
            );
        }
    }
}

class CipherPolicy {
    static evaluate(protocol, cipher) {
        const violations = [];

        if (protocol === "TLSv1.3") {
            if (!TLS_POLICY.allowedTLS13.has(cipher)) {
                violations.push("TLS 1.3 cipher is not approved.");
            }
        } else if (protocol === "TLSv1.2") {
            if (!TLS_POLICY.allowedTLS12.has(cipher)) {
                violations.push("TLS 1.2 cipher is not approved.");
            }
        } else {
            violations.push("Unsupported TLS protocol.");
        }

        return Object.freeze({
            accepted: violations.length === 0,
            violations
        });
    }
}

class TLSConnection extends EventEmitter {
    constructor(configuration = new TLSConfiguration()) {
        super();

        this.configuration = configuration;
        this.state = TLS_STATES.CREATED;
        this.socket = null;
        this.startedAt = null;
        this.report = null;
    }

    transition(nextState) {
        const allowed = {
            CREATED: ["CONNECTING"],
            CONNECTING: ["ESTABLISHED", "FAILED"],
            ESTABLISHED: ["CLOSED", "FAILED"],
            FAILED: ["CLOSED"],
            CLOSED: []
        };

        if (!allowed[this.state].includes(nextState)) {
            throw new Error(
                `Invalid state transition: ${this.state} -> ${nextState}`
            );
        }

        this.state = nextState;
        this.emit("stateChanged", nextState);
    }

    connect(host, port = 443) {
        return new Promise((resolve, reject) => {
            if (this.state !== TLS_STATES.CREATED) {
                reject(new TLSHandshakeError(
                    "Connection object cannot be reused.",
                    "INVALID_STATE"
                ));
                return;
            }

            if (
                typeof host !== "string" ||
                host.length === 0 ||
                net.isIP(host) === 0 &&
                !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(host)
            ) {
                reject(new TLSConfigurationError(
                    "Invalid hostname."
                ));
                return;
            }

            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                reject(new TLSConfigurationError(
                    "Invalid port."
                ));
                return;
            }

            this.startedAt = performance.now();
            this.transition(TLS_STATES.CONNECTING);

            const options = {
                host,
                port,
                servername: net.isIP(host) ? undefined : host,
                minVersion: this.configuration.minimumVersion,
                maxVersion: this.configuration.maximumVersion,
                rejectUnauthorized:
                    this.configuration.rejectUnauthorized,
                timeout: this.configuration.timeout
            };

            const socket = tls.connect(options);
            this.socket = socket;

            let completed = false;

            const finishFailure = (error) => {
                if (completed) return;

                completed = true;

                if (
                    this.state === TLS_STATES.CONNECTING ||
                    this.state === TLS_STATES.ESTABLISHED
                ) {
                    this.transition(TLS_STATES.FAILED);
                }

                socket.destroy();

                reject(new TLSHandshakeError(
                    error.message,
                    error.code || "TLS_ERROR"
                ));
            };

            socket.setTimeout(
                this.configuration.timeout,
                () => finishFailure(
                    new Error("TLS connection timed out.")
                )
            );

            socket.once("error", finishFailure);

            socket.once("secureConnect", () => {
                if (completed) return;

                completed = true;

                try {
                    const certificate = socket.getPeerCertificate(true);
                    const protocol = socket.getProtocol();
                    const cipher = socket.getCipher();

                    const policy = CipherPolicy.evaluate(
                        protocol,
                        cipher.name
                    );

                    if (!socket.authorized) {
                        throw new Error(
                            socket.authorizationError ||
                            "Certificate authorization failed."
                        );
                    }

                    if (!policy.accepted) {
                        throw new Error(
                            policy.violations.join("; ")
                        );
                    }

                    const certificateFingerprint =
                        certificate.raw
                            ? crypto.createHash("sha256")
                                .update(certificate.raw)
                                .digest("hex")
                            : null;

                    this.transition(TLS_STATES.ESTABLISHED);

                    this.report = Object.freeze({
                        host,
                        port,
                        state: this.state,
                        protocol,
                        cipher: cipher.name,
                        cipherVersion: cipher.version,
                        authorized: socket.authorized,
                        authorizationError: socket.authorizationError,
                        sessionReused: socket.isSessionReused(),
                        certificate: {
                            subject: certificate.subject,
                            issuer: certificate.issuer,
                            validFrom: certificate.valid_from,
                            validTo: certificate.valid_to,
                            fingerprintSHA256:
                                certificateFingerprint
                        },
                        elapsedMilliseconds: Number(
                            (performance.now() - this.startedAt).toFixed(2)
                        )
                    });

                    this.emit("secure", this.report);
                    resolve(this.report);

                } catch (error) {
                    finishFailure(error);
                }
            });
        });
    }

    close() {
        if (this.socket && !this.socket.destroyed) {
            this.socket.end();
        }

        if (
            this.state === TLS_STATES.ESTABLISHED ||
            this.state === TLS_STATES.FAILED
        ) {
            this.transition(TLS_STATES.CLOSED);
        }
    }
}

class TLSSessionManager {
    constructor() {
        this.sessions = new Map();
    }

    save(host, sessionBuffer) {
        if (!host || !Buffer.isBuffer(sessionBuffer)) {
            throw new TypeError("Invalid TLS session data.");
        }

        if (sessionBuffer.length === 0) {
            throw new TypeError("Empty TLS session.");
        }

        this.sessions.set(host, Buffer.from(sessionBuffer));
    }

    get(host) {
        const session = this.sessions.get(host);

        return session ? Buffer.from(session) : undefined;
    }

    remove(host) {
        this.sessions.delete(host);
    }

    clear() {
        this.sessions.clear();
    }

    get size() {
        return this.sessions.size;
    }
}

function displayTLSConcepts() {
    const concepts = new Map([
        ["ClientHello", "Client protocol versions, random, key shares and extensions."],
        ["ServerHello", "Server selects compatible parameters and key share."],
        ["Certificate", "Server presents its certificate chain."],
        ["CertificateVerify", "Server proves possession of its private key."],
        ["Finished", "Authenticates the handshake transcript."],
        ["Application Data", "Protected using derived directional traffic keys."]
    ]);

    console.log("\nTLS 1.3 Handshake Components");

    for (const [name, description] of concepts) {
        console.log(`${name}: ${description}`);
    }
}

async function main() {
    const host = process.argv[2] || "example.com";
    const port = Number(process.argv[3] || 443);

    const connection = new TLSConnection();

    connection.on("stateChanged", (state) => {
        console.log(`State: ${state}`);
    });

    connection.on("secure", (report) => {
        console.log("\nTLS Security Report");
        console.log(JSON.stringify(report, null, 2));
    });

    try {
        const report = await connection.connect(host, port);

        const sessions = new TLSSessionManager();

        const session = connection.socket.getSession();

        if (session) {
            sessions.save(host, session);
        }

        console.log(`\nStored sessions: ${sessions.size}`);
        console.log(
            `Negotiated cipher: ${report.cipher}`
        );

    } catch (error) {
        console.error(
            `${error.name}: ${error.message} (${error.code || "ERROR"})`
        );

        process.exitCode = 1;

    } finally {
        connection.close();
    }

    displayTLSConcepts();
}

if (require.main === module) {
    main().catch((error) => {
        console.error(error);
        process.exitCode = 1;
    });
}

module.exports = {
    TLSConfiguration,
    TLSConnection,
    CipherPolicy,
    TLSSessionManager,
    TLS_STATES
};
