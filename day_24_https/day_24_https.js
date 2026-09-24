/*
 * HTTPS and TLS: JavaScript Practical Study File
 *
 * This file complements the Python implementation by demonstrating:
 *
 * - HTTP versus HTTPS
 * - hashing and HMAC
 * - certificate concepts
 * - TLS handshake state
 * - TLS record framing
 * - asynchronous HTTPS connections
 * - hostname validation concepts
 * - certificate-chain modeling
 * - key derivation with Web Crypto
 * - TLS-related Node.js APIs
 * - error handling
 * - performance and security observations
 *
 * Run with:
 *   node https_tls_study.js
 *
 * No third-party npm packages are required.
 */

"use strict";

const https = require("https");
const tls = require("tls");
const crypto = require("crypto");
const os = require("os");


// ============================================================================
// 1. BASIC OUTPUT HELPERS
// ============================================================================

function title(text) {
    console.log("\n" + "=".repeat(78));
    console.log(text);
    console.log("=".repeat(78));
}

function subsection(text) {
    console.log("\n" + "-".repeat(78));
    console.log(text);
    console.log("-".repeat(78));
}


// ============================================================================
// 2. HTTP VERSUS HTTPS
// ============================================================================

function demonstrateHttpVsHttps() {
    title("1. HTTP versus HTTPS");

    const httpRequest =
        "GET /login HTTP/1.1\r\n" +
        "Host: example.com\r\n" +
        "Content-Type: application/x-www-form-urlencoded\r\n" +
        "\r\n" +
        "username=alice&password=example";

    console.log("HTTP is an application protocol.");
    console.log(httpRequest);

    console.log("\nHTTPS is conceptually:");
    console.log("HTTP + TLS + TCP + IP");

    console.log("\nTLS provides:");
    console.log("  confidentiality");
    console.log("  integrity");
    console.log("  server authentication");
    console.log("  secure key establishment");
}


// ============================================================================
// 3. HASHING
// ============================================================================

function sha256(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

function demonstrateHashing() {
    title("2. SHA-256 hashing");

    const message = Buffer.from("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    const originalHash = sha256(message);

    const modified = Buffer.from(
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    );
    const modifiedHash = sha256(modified);

    console.log("Original SHA-256:", originalHash);
    console.log("Modified SHA-256:", modifiedHash);

    console.log(
        "\nA hash detects changes but does not provide confidentiality."
    );
}


// ============================================================================
// 4. HMAC
// ============================================================================

function hmacSha256(key, message) {
    return crypto
        .createHmac("sha256", key)
        .update(message)
        .digest("hex");
}

function demonstrateHmac() {
    title("3. HMAC");

    const key = "demo-secret-key";
    const message = "amount=1000&account=42";

    const tag = hmacSha256(key, message);
    const validTag = hmacSha256(key, message);
    const tamperedTag = hmacSha256(key, "amount=9000&account=42");

    console.log("Message:", message);
    console.log("HMAC:", tag);
    console.log("Valid:", crypto.timingSafeEqual(
        Buffer.from(tag, "hex"),
        Buffer.from(validTag, "hex")
    ));
    console.log("Tampered:", crypto.timingSafeEqual(
        Buffer.from(tag, "hex"),
        Buffer.from(tamperedTag, "hex")
    ));
}


// ============================================================================
// 5. SYMMETRIC ENCRYPTION WITH AES-256-GCM
// ============================================================================

function encryptAesGcm(key, plaintext, additionalAuthenticatedData = "") {
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    if (additionalAuthenticatedData) {
        cipher.setAAD(Buffer.from(additionalAuthenticatedData));
    }

    const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(plaintext)),
        cipher.final()
    ]);

    const authTag = cipher.getAuthTag();

    return {
        iv,
        ciphertext,
        authTag
    };
}

function decryptAesGcm(
    key,
    encrypted,
    additionalAuthenticatedData = ""
) {
    const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        key,
        encrypted.iv
    );

    if (additionalAuthenticatedData) {
        decipher.setAAD(Buffer.from(additionalAuthenticatedData));
    }

    decipher.setAuthTag(encrypted.authTag);

    return Buffer.concat([
        decipher.update(encrypted.ciphertext),
        decipher.final()
    ]).toString("utf8");
}

function demonstrateAuthenticatedEncryption() {
    title("4. Authenticated symmetric encryption");

    const key = crypto.randomBytes(32);
    const plaintext = "HTTPS application data";
    const aad = "TLS-record-associated-data";

    const encrypted = encryptAesGcm(key, plaintext, aad);

    console.log("Ciphertext:", encrypted.ciphertext.toString("hex"));
    console.log("IV:", encrypted.iv.toString("hex"));
    console.log("Authentication tag:", encrypted.authTag.toString("hex"));

    const recovered = decryptAesGcm(key, encrypted, aad);

    console.log("Recovered:", recovered);

    // Changing authenticated data makes authentication fail.
    try {
        decryptAesGcm(key, encrypted, "tampered-associated-data");
    } catch (error) {
        console.log("Tampering detected:", error.message);
    }
}


// ============================================================================
// 6. HKDF
// ============================================================================

function demonstrateHkdf() {
    title("5. HKDF key derivation");

    const sharedSecret = crypto.randomBytes(32);
    const salt = crypto.randomBytes(32);

    const derived = crypto.hkdfSync(
        "sha256",
        sharedSecret,
        salt,
        Buffer.from("tls application traffic key"),
        32
    );

    const derivedBuffer = Buffer.from(derived);

    console.log("Shared secret:", sharedSecret.toString("hex"));
    console.log("Derived key:", derivedBuffer.toString("hex"));

    console.log(
        "\nTLS derives separate traffic secrets instead of treating a single "
        + "secret as a universal encryption key."
    );
}


// ============================================================================
// 7. CERTIFICATE MODEL
// ============================================================================

class CertificateModel {
    constructor({
        subject,
        issuer,
        dnsNames,
        isCA,
        publicKeyAlgorithm,
        signatureAlgorithm
    }) {
        this.subject = subject;
        this.issuer = issuer;
        this.dnsNames = dnsNames;
        this.isCA = isCA;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.signatureAlgorithm = signatureAlgorithm;
    }

    describe() {
        return {
            subject: this.subject,
            issuer: this.issuer,
            dnsNames: this.dnsNames,
            isCA: this.isCA,
            publicKeyAlgorithm: this.publicKeyAlgorithm,
            signatureAlgorithm: this.signatureAlgorithm
        };
    }
}

function demonstrateCertificateModel() {
    title("6. X.509 certificate model");

    const root = new CertificateModel({
        subject: "Example Root CA",
        issuer: "Example Root CA",
        dnsNames: [],
        isCA: true,
        publicKeyAlgorithm: "RSA-4096",
        signatureAlgorithm: "RSA-PSS-SHA256"
    });

    const intermediate = new CertificateModel({
        subject: "Example Intermediate CA",
        issuer: "Example Root CA",
        dnsNames: [],
        isCA: true,
        publicKeyAlgorithm: "RSA-3072",
        signatureAlgorithm: "RSA-PSS-SHA256"
    });

    const server = new CertificateModel({
        subject: "www.example.com",
        issuer: "Example Intermediate CA",
        dnsNames: ["www.example.com", "example.com"],
        isCA: false,
        publicKeyAlgorithm: "ECDSA-P256",
        signatureAlgorithm: "ECDSA-SHA256"
    });

    console.dir(root.describe(), { depth: null });
    console.dir(intermediate.describe(), { depth: null });
    console.dir(server.describe(), { depth: null });
}


// ============================================================================
// 8. CERTIFICATE CHAIN VALIDATION MODEL
// ============================================================================

function validateCertificateChain(chain, trustedRoots, hostname) {
    const errors = [];

    if (chain.length === 0) {
        errors.push("Certificate chain is empty.");
        return { valid: false, errors };
    }

    const leaf = chain[0];

    if (leaf.isCA) {
        errors.push("Leaf certificate should not be used as a CA.");
    }

    if (!leaf.dnsNames.includes(hostname)) {
        errors.push("Hostname is absent from the certificate SAN list.");
    }

    for (let index = 0; index < chain.length - 1; index++) {
        const current = chain[index];
        const issuer = chain[index + 1];

        if (current.issuer !== issuer.subject) {
            errors.push(
                `${current.subject} does not chain to ${issuer.subject}.`
            );
        }

        if (!issuer.isCA) {
            errors.push(`${issuer.subject} is not marked as a CA.`);
        }
    }

    const finalCertificate = chain[chain.length - 1];

    if (!trustedRoots.some(
        root => root.subject === finalCertificate.issuer ||
                root.subject === finalCertificate.subject
    )) {
        errors.push("Chain does not terminate at a trusted root.");
    }

    return {
        valid: errors.length === 0,
        errors
    };
}

function demonstrateCertificateValidation() {
    title("7. Certificate-chain validation");

    const root = new CertificateModel({
        subject: "Demo Root CA",
        issuer: "Demo Root CA",
        dnsNames: [],
        isCA: true,
        publicKeyAlgorithm: "RSA-4096",
        signatureAlgorithm: "RSA-PSS-SHA256"
    });

    const intermediate = new CertificateModel({
        subject: "Demo Intermediate CA",
        issuer: "Demo Root CA",
        dnsNames: [],
        isCA: true,
        publicKeyAlgorithm: "RSA-3072",
        signatureAlgorithm: "RSA-PSS-SHA256"
    });

    const server = new CertificateModel({
        subject: "api.example.com",
        issuer: "Demo Intermediate CA",
        dnsNames: ["api.example.com"],
        isCA: false,
        publicKeyAlgorithm: "ECDSA-P256",
        signatureAlgorithm: "ECDSA-SHA256"
    });

    const valid = validateCertificateChain(
        [server, intermediate],
        [root],
        "api.example.com"
    );

    console.log("Valid chain:", valid);

    const invalid = validateCertificateChain(
        [server, intermediate],
        [root],
        "attacker.example.com"
    );

    console.log("Wrong hostname:", invalid);
}


// ============================================================================
// 9. TLS HANDSHAKE STATE MACHINE
// ============================================================================

class TlsHandshakeStateMachine {
    constructor() {
        this.state = "START";

        this.transitions = {
            START: ["CLIENT_HELLO_SENT", "CLOSED"],
            CLIENT_HELLO_SENT: ["SERVER_HELLO_RECEIVED", "CLOSED"],
            SERVER_HELLO_RECEIVED: ["CERTIFICATE_VALIDATED", "CLOSED"],
            CERTIFICATE_VALIDATED: ["HANDSHAKE_KEYS_READY", "CLOSED"],
            HANDSHAKE_KEYS_READY: ["APPLICATION_KEYS_READY", "CLOSED"],
            APPLICATION_KEYS_READY: ["CONNECTED", "CLOSED"],
            CONNECTED: ["CLOSED"],
            CLOSED: []
        };
    }

    transition(nextState) {
        if (!this.transitions[this.state].includes(nextState)) {
            throw new Error(
                `Invalid TLS transition: ${this.state} -> ${nextState}`
            );
        }

        this.state = nextState;
    }
}

function demonstrateHandshakeStateMachine() {
    title("8. TLS handshake state machine");

    const machine = new TlsHandshakeStateMachine();

    const sequence = [
        "CLIENT_HELLO_SENT",
        "SERVER_HELLO_RECEIVED",
        "CERTIFICATE_VALIDATED",
        "HANDSHAKE_KEYS_READY",
        "APPLICATION_KEYS_READY",
        "CONNECTED",
        "CLOSED"
    ];

    for (const state of sequence) {
        machine.transition(state);
        console.log("State:", machine.state);
    }
}


// ============================================================================
// 10. TLS 1.3 HANDSHAKE MESSAGES
// ============================================================================

function demonstrateTls13Handshake() {
    title("9. TLS 1.3 handshake");

    const messages = [
        ["ClientHello", "Client -> Server", "Offers versions, extensions and key shares."],
        ["ServerHello", "Server -> Client", "Selects parameters and supplies a key share."],
        ["EncryptedExtensions", "Server -> Client", "Negotiated extensions after encryption begins."],
        ["Certificate", "Server -> Client", "Server certificate chain."],
        ["CertificateVerify", "Server -> Client", "Proof of private-key possession."],
        ["Finished", "Server -> Client", "Authenticates the handshake transcript."],
        ["Finished", "Client -> Server", "Client authenticates the transcript."]
    ];

    for (const [name, direction, purpose] of messages) {
        console.log(`${direction.padEnd(18)} ${name.padEnd(22)} ${purpose}`);
    }
}


// ============================================================================
// 11. TLS RECORD HEADER
// ============================================================================

const tlsContentTypes = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data"
};

function parseTlsRecordHeader(buffer) {
    if (buffer.length !== 5) {
        throw new Error("TLS record header must contain five bytes.");
    }

    const contentType = buffer.readUInt8(0);
    const major = buffer.readUInt8(1);
    const minor = buffer.readUInt8(2);
    const length = buffer.readUInt16BE(3);

    return {
        contentType: tlsContentTypes[contentType] || "Unknown",
        contentTypeCode: contentType,
        version: `${major}.${minor}`,
        length
    };
}

function demonstrateTlsRecord() {
    title("10. TLS record layer");

    const header = Buffer.alloc(5);
    header.writeUInt8(23, 0);
    header.writeUInt8(3, 1);
    header.writeUInt8(3, 2);
    header.writeUInt16BE(256, 3);

    console.log(parseTlsRecordHeader(header));

    console.log(
        "\nTLS records carry handshake, alert or protected application data."
    );
}


// ============================================================================
// 12. TRANSCRIPT HASH
// ============================================================================

function demonstrateTranscriptHash() {
    title("11. Handshake transcript");

    const transcript = Buffer.from(
        "ClientHello|ServerHello|EncryptedExtensions|Certificate|CertificateVerify"
    );

    console.log(
        "Transcript hash:",
        sha256(transcript)
    );

    console.log(
        "TLS uses transcript-dependent authentication to detect unauthorized "
        + "changes to handshake messages."
    );
}


// ============================================================================
// 13. HOSTNAME VALIDATION MODEL
// ============================================================================

function hostnameMatches(hostname, names) {
    const normalizedHostname = hostname.toLowerCase().replace(/\.$/, "");

    return names.some(pattern => {
        const normalizedPattern = pattern
            .toLowerCase()
            .replace(/\.$/, "");

        if (normalizedPattern === normalizedHostname) {
            return true;
        }

        if (normalizedPattern.startsWith("*.")) {
            const suffix = normalizedPattern.slice(1);

            // Simplified wildcard handling for educational purposes.
            return (
                normalizedHostname.endsWith(suffix) &&
                normalizedHostname.split(".").length ===
                    normalizedPattern.split(".").length
            );
        }

        return false;
    });
}

function demonstrateHostnameValidation() {
    title("12. Hostname verification");

    const names = ["example.com", "*.api.example.com"];

    for (const hostname of [
        "example.com",
        "www.example.com",
        "service.api.example.com",
        "api.example.com",
        "evil.example.net"
    ]) {
        console.log(
            hostname.padEnd(30),
            hostnameMatches(hostname, names)
        );
    }

    console.log(
        "\nA valid CA signature does not automatically make a certificate valid "
        + "for every hostname."
    );
}


// ============================================================================
// 14. NODE.JS TLS API
// ============================================================================

function demonstrateNodeTlsOptions() {
    title("13. Node.js TLS client configuration");

    const options = {
        host: "example.com",
        port: 443,
        servername: "example.com",
        minVersion: "TLSv1.2",
        rejectUnauthorized: true
    };

    console.log(options);

    console.log(
        "\nrejectUnauthorized: true preserves normal certificate validation."
    );
}


// ============================================================================
// 15. REAL TLS CONNECTION
// ============================================================================

function connectTls(hostname = "example.com", port = 443) {
    title("14. Real TLS connection");

    return new Promise((resolve) => {
        const socket = tls.connect({
            host: hostname,
            port,
            servername: hostname,
            minVersion: "TLSv1.2",
            rejectUnauthorized: true,
            timeout: 5000
        });

        socket.once("secureConnect", () => {
            console.log("TLS connection established.");
            console.log("Authorized:", socket.authorized);
            console.log("Authorization error:", socket.authorizationError || "none");
            console.log("TLS version:", socket.getProtocol());
            console.log("Cipher:", socket.getCipher());
            console.log("ALPN:", socket.alpnProtocol || "not negotiated");

            const certificate = socket.getPeerCertificate();

            console.log("Peer certificate subject:", certificate.subject);
            console.log("Peer certificate issuer:", certificate.issuer);
            console.log("Peer certificate valid from:", certificate.valid_from);
            console.log("Peer certificate valid to:", certificate.valid_to);

            socket.end();
            resolve();
        });

        socket.once("timeout", () => {
            console.log("TLS connection timed out.");
            socket.destroy();
            resolve();
        });

        socket.once("error", error => {
            console.log("TLS connection failed:", error.message);
            resolve();
        });
    });
}


// ============================================================================
// 16. REAL HTTPS REQUEST
// ============================================================================

function httpsGet(hostname = "example.com", path = "/") {
    title("15. HTTPS GET request");

    return new Promise((resolve) => {
        const request = https.request(
            {
                hostname,
                port: 443,
                path,
                method: "GET",
                minVersion: "TLSv1.2",
                rejectUnauthorized: true,
                headers: {
                    "User-Agent": "HTTPS-TLS-Study-Client/1.0",
                    "Accept": "*/*"
                }
            },
            response => {
                let body = "";

                console.log("HTTP status:", response.statusCode);
                console.log("TLS socket authorized:", response.socket.authorized);
                console.log("TLS protocol:", response.socket.getProtocol());

                response.setEncoding("utf8");

                response.on("data", chunk => {
                    body += chunk;
                });

                response.on("end", () => {
                    console.log("Received bytes:", Buffer.byteLength(body));
                    console.log("First 200 characters:");
                    console.log(body.slice(0, 200));
                    resolve();
                });
            }
        );

        request.setTimeout(5000, () => {
            console.log("HTTPS request timed out.");
            request.destroy();
            resolve();
        });

        request.on("error", error => {
            console.log("HTTPS request failed:", error.message);
            resolve();
        });

        request.end();
    });
}


// ============================================================================
// 17. ASYNCHRONOUS ERROR HANDLING
// ============================================================================

async function demonstrateAsyncErrorHandling() {
    title("16. Asynchronous TLS error handling");

    try {
        await connectTls("invalid.invalid", 443);
    } catch (error) {
        console.log("Caught unexpected failure:", error.message);
    }

    console.log(
        "Production network code should handle DNS errors, timeouts, "
        + "certificate errors, connection resets and protocol failures."
    );
}


// ============================================================================
// 18. PERFORMANCE
// ============================================================================

function demonstratePerformanceMeasurement() {
    title("17. Performance measurement");

    const data = Buffer.alloc(1024 * 1024, "A");
    const iterations = 50;

    const start = process.hrtime.bigint();

    for (let i = 0; i < iterations; i++) {
        crypto.createHash("sha256").update(data).digest();
    }

    const elapsedNanoseconds = process.hrtime.bigint() - start;
    const elapsedMilliseconds = Number(elapsedNanoseconds) / 1e6;

    console.log("Processed bytes:", data.length * iterations);
    console.log("Hash iterations:", iterations);
    console.log("Elapsed milliseconds:", elapsedMilliseconds.toFixed(2));

    console.log(
        "\nTLS performance is affected by CPU cost, handshake round trips, "
        + "connection reuse, certificate-chain size and network latency."
    );
}


// ============================================================================
// 19. SECURITY CHECKLIST
// ============================================================================

function securityChecklist() {
    title("18. Security checklist");

    const checks = [
        "Use TLS 1.3 when practical.",
        "Keep certificate validation enabled.",
        "Verify hostnames.",
        "Protect private keys.",
        "Use maintained Node.js releases.",
        "Do not disable rejectUnauthorized in production.",
        "Do not log secrets or session keys.",
        "Monitor certificate expiration.",
        "Use secure randomness.",
        "Handle certificate and protocol failures explicitly.",
        "Use connection reuse where appropriate.",
        "Treat TLS termination infrastructure as security-sensitive."
    ];

    checks.forEach(item => console.log("[ ] " + item));
}


// ============================================================================
// 20. OPENSSL COMMANDS
// ============================================================================

function printOpenSslCommands() {
    title("19. OpenSSL command reference");

    const commands = [
        "openssl version",
        "openssl x509 -in certificate.pem -text -noout",
        "openssl x509 -in certificate.pem -noout -dates",
        "openssl x509 -in certificate.pem -noout -ext subjectAltName",
        "openssl x509 -in certificate.pem -noout -fingerprint -sha256",
        "openssl s_client -connect example.com:443 -servername example.com",
        "openssl s_client -connect example.com:443 -servername example.com -tls1_3",
        "openssl s_client -connect example.com:443 -servername example.com -showcerts"
    ];

    commands.forEach(command => console.log(command));
}


// ============================================================================
// 21. WIRESHARK FILTERS
// ============================================================================

function printWiresharkFilters() {
    title("20. Wireshark filters");

    const filters = {
        "TLS": "tls",
        "TCP 443": "tcp.port == 443",
        "Handshake": "tls.handshake",
        "ClientHello": "tls.handshake.type == 1",
        "ServerHello": "tls.handshake.type == 2",
        "Certificate": "tls.handshake.type == 11",
        "Alerts": "tls.alert_message",
        "TCP retransmissions": "tcp.analysis.retransmission"
    };

    Object.entries(filters).forEach(([name, expression]) => {
        console.log(`${name.padEnd(22)} ${expression}`);
    });

    console.log(
        "\nWireshark can expose protocol metadata and handshake information, "
        + "while correctly encrypted application data remains protected."
    );
}


// ============================================================================
// 22. TLS 1.2 VERSUS TLS 1.3
// ============================================================================

function compareTlsVersions() {
    title("21. TLS 1.2 versus TLS 1.3");

    const rows = [
        ["Handshake", "More historical negotiation choices", "Reduced protocol complexity"],
        ["Forward secrecy", "Depends on negotiated method", "Ephemeral key exchange is standard"],
        ["Legacy algorithms", "Broader historical support", "Many obsolete choices removed"],
        ["Encrypted handshake", "Less extensive", "More handshake data is encrypted"],
        ["Latency", "Can require more round trips", "Designed to reduce handshake latency"]
    ];

    console.log("Aspect".padEnd(24) + "TLS 1.2".padEnd(35) + "TLS 1.3");

    rows.forEach(([aspect, oldValue, newValue]) => {
        console.log(
            aspect.padEnd(24) +
            oldValue.padEnd(35) +
            newValue
        );
    });
}


// ============================================================================
// 23. ADVANCED CONCEPTS
// ============================================================================

function advancedConcepts() {
    title("22. Advanced TLS concepts");

    const concepts = {
        SNI: "Identifies the intended hostname during TLS setup.",
        ALPN: "Negotiates application protocols such as HTTP/1.1 and HTTP/2.",
        "0-RTT": "Allows TLS 1.3 early data but introduces replay-related application concerns.",
        mTLS: "Authenticates both endpoints with certificates.",
        HSTS: "Tells compatible browsers to use HTTPS for a site.",
        OCSP: "Provides certificate revocation status information.",
        "Certificate Transparency": "Provides public logs for publicly trusted certificate issuance.",
        ECH: "Protects selected ClientHello information from network observers.",
        "Session Resumption": "Reduces cost of reconnecting to a previously authenticated server."
    };

    Object.entries(concepts).forEach(([name, explanation]) => {
        console.log(`\n${name}: ${explanation}`);
    });
}


// ============================================================================
// 24. ENVIRONMENT INFORMATION
// ============================================================================

function printEnvironment() {
    title("23. Runtime information");

    console.log("Node.js:", process.version);
    console.log("OpenSSL used by Node:", process.versions.openssl);
    console.log("Platform:", process.platform);
    console.log("Architecture:", process.arch);
    console.log("Operating system:", os.platform());
}


// ============================================================================
// 25. MAIN
// ============================================================================

async function main() {
    demonstrateHttpVsHttps();
    demonstrateHashing();
    demonstrateHmac();
    demonstrateAuthenticatedEncryption();
    demonstrateHkdf();
    demonstrateCertificateModel();
    demonstrateCertificateValidation();
    demonstrateHandshakeStateMachine();
    demonstrateTls13Handshake();
    demonstrateTlsRecord();
    demonstrateTranscriptHash();
    demonstrateHostnameValidation();
    demonstrateNodeTlsOptions();
    compareTlsVersions();
    advancedConcepts();
    printOpenSslCommands();
    printWiresharkFilters();
    demonstratePerformanceMeasurement();
    securityChecklist();
    printEnvironment();

    if (process.argv.includes("--network")) {
        await connectTls("example.com", 443);
        await httpsGet("example.com", "/");
        await demonstrateAsyncErrorHandling();
    } else {
        console.log(
            "\nNetwork examples were skipped. Run with --network to perform "
            + "real TLS/HTTPS connections."
        );
    }

    title("JavaScript TLS study complete");
}

main().catch(error => {
    console.error("Fatal error:", error);
    process.exitCode = 1;
});
