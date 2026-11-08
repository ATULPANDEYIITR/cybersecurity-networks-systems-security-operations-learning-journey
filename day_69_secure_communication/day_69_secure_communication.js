"use strict";

/*
 * Secure Communications Laboratory
 *
 * Node.js implementation:
 * - TLS and HTTPS connections
 * - SSH connection management
 * - SFTP transfer using OpenSSH
 * - VPN configuration validation
 * - Event-driven communication monitoring
 * - Security policy enforcement
 *
 * Requirements: Node.js 18+
 * No npm dependencies.
 */

const https = require("node:https");
const tls = require("node:tls");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawn } = require("node:child_process");
const { EventEmitter } = require("node:events");
const net = require("node:net");
const { pipeline } = require("node:stream/promises");

class SecurityError extends Error {
    constructor(message) {
        super(message);
        this.name = "SecurityError";
    }
}

class ValidationError extends SecurityError {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}

class CommunicationPolicy {
    constructor({
        minimumTLS = "TLSv1.2",
        verifyCertificates = true,
        verifyHostname = true,
        strictSSH = true,
        maximumFileSize = 50 * 1024 * 1024,
        timeout = 10000
    } = {}) {
        this.minimumTLS = minimumTLS;
        this.verifyCertificates = verifyCertificates;
        this.verifyHostname = verifyHostname;
        this.strictSSH = strictSSH;
        this.maximumFileSize = maximumFileSize;
        this.timeout = timeout;

        this.validate();
    }

    validate() {
        if (!["TLSv1.2", "TLSv1.3"].includes(this.minimumTLS)) {
            throw new ValidationError("Unsupported minimum TLS version.");
        }

        if (!this.verifyCertificates || !this.verifyHostname) {
            throw new ValidationError(
                "TLS certificate and hostname validation are mandatory."
            );
        }

        if (!this.strictSSH) {
            throw new ValidationError(
                "Strict SSH host-key verification is mandatory."
            );
        }

        if (!Number.isSafeInteger(this.maximumFileSize) ||
            this.maximumFileSize <= 0) {
            throw new ValidationError("Invalid maximum file size.");
        }

        if (!Number.isFinite(this.timeout) || this.timeout <= 0) {
            throw new ValidationError("Invalid timeout.");
        }
    }
}

class CommunicationMonitor extends EventEmitter {
    constructor() {
        super();
        this.connections = new Map();
        this.auditLog = [];
    }

    register(id, protocol, destination) {
        if (!id || this.connections.has(id)) {
            throw new ValidationError("Invalid or duplicate connection ID.");
        }

        const connection = {
            id,
            protocol,
            destination,
            state: "DISCONNECTED",
            createdAt: new Date().toISOString()
        };

        this.connections.set(id, connection);
        this.emit("registered", connection);

        return connection;
    }

    transition(id, nextState) {
        const connection = this.connections.get(id);

        if (!connection) {
            throw new ValidationError("Connection does not exist.");
        }

        const transitions = {
            DISCONNECTED: ["CONNECTING"],
            CONNECTING: ["CONNECTED", "FAILED"],
            CONNECTED: ["DISCONNECTED", "FAILED"],
            FAILED: ["DISCONNECTED"]
        };

        if (!transitions[connection.state].includes(nextState)) {
            throw new SecurityError(
                `Invalid state transition: ${connection.state} -> ${nextState}`
            );
        }

        const previousState = connection.state;
        connection.state = nextState;

        const event = {
            id,
            protocol: connection.protocol,
            previousState,
            nextState,
            timestamp: new Date().toISOString()
        };

        this.auditLog.push(event);
        this.emit("stateChanged", event);

        return event;
    }

    getActiveConnections() {
        return [...this.connections.values()].filter(
            connection => connection.state === "CONNECTED"
        );
    }
}

class HTTPSClient {
    constructor(policy) {
        this.policy = policy;
    }

    request(url) {
        const parsed = new URL(url);

        if (parsed.protocol !== "https:") {
            throw new ValidationError("HTTPS URL required.");
        }

        if (parsed.username || parsed.password) {
            throw new ValidationError(
                "Credentials in URLs are prohibited."
            );
        }

        return new Promise((resolve, reject) => {
            const request = https.request(parsed, {
                method: "GET",
                timeout: this.policy.timeout,
                minVersion: this.policy.minimumTLS,
                rejectUnauthorized: true,
                checkServerIdentity: (hostname, certificate) =>
                    tls.checkServerIdentity(hostname, certificate),
                headers: {
                    "User-Agent": "SecureCommunicationsLab/1.0"
                }
            }, response => {
                const chunks = [];
                let total = 0;
                const maximum = 1024 * 1024;

                response.on("data", chunk => {
                    total += chunk.length;

                    if (total > maximum) {
                        response.destroy(
                            new SecurityError("Response size limit exceeded.")
                        );
                        return;
                    }

                    chunks.push(chunk);
                });

                response.on("end", () => {
                    resolve({
                        status: response.statusCode,
                        headers: response.headers,
                        bodySize: total,
                        tlsVerified: true
                    });
                });

                response.on("error", reject);
            });

            request.on("timeout", () => {
                request.destroy(new Error("HTTPS request timed out."));
            });

            request.on("error", reject);
            request.end();
        });
    }
}

class OpenSSHClient {
    constructor({
        knownHosts = path.join(os.homedir(), ".ssh", "known_hosts"),
        identityFile = null,
        policy
    }) {
        this.knownHosts = path.resolve(knownHosts);
        this.identityFile = identityFile
            ? path.resolve(identityFile)
            : null;

        this.policy = policy;

        if (!fs.existsSync(this.knownHosts)) {
            throw new ValidationError("SSH known_hosts file is missing.");
        }

        if (this.identityFile &&
            !fs.statSync(this.identityFile).isFile()) {
            throw new ValidationError("SSH identity file is invalid.");
        }
    }

    validateDestination(username, host) {
        if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(username)) {
            throw new ValidationError("Invalid SSH username.");
        }

        if (!/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(host)) {
            throw new ValidationError("Invalid SSH hostname.");
        }
    }

    execute(program, args, timeout = 30000) {
        return new Promise((resolve, reject) => {
            const child = spawn(program, args, {
                shell: false,
                stdio: ["ignore", "pipe", "pipe"],
                windowsHide: true
            });

            let stdout = "";
            let stderr = "";
            let settled = false;

            const timer = setTimeout(() => {
                child.kill();
                finish(new Error(`${program} timed out.`));
            }, timeout);

            function finish(error, result) {
                if (settled) return;

                settled = true;
                clearTimeout(timer);

                if (error) {
                    reject(error);
                } else {
                    resolve(result);
                }
            }

            child.stdout.on("data", data => {
                stdout += data.toString();
            });

            child.stderr.on("data", data => {
                stderr += data.toString();
            });

            child.on("error", error => finish(error));

            child.on("close", code => {
                if (code !== 0) {
                    finish(new SecurityError(
                        `${program} failed: ${stderr.trim()}`
                    ));
                } else {
                    finish(null, { stdout, stderr, code });
                }
            });
        });
    }

    baseArguments() {
        const args = [
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ForwardAgent=no",
            "-o", `UserKnownHostsFile=${this.knownHosts}`
        ];

        if (this.identityFile) {
            args.push("-i", this.identityFile);
        }

        return args;
    }

    connect(username, host, remoteCommand = "id") {
        this.validateDestination(username, host);

        if (!remoteCommand ||
            /[\r\n\0]/.test(remoteCommand)) {
            throw new ValidationError("Invalid remote command.");
        }

        return this.execute(
            "ssh",
            [
                ...this.baseArguments(),
                `${username}@${host}`,
                remoteCommand
            ]
        );
    }

    upload(localFile, username, host, remotePath) {
        this.validateDestination(username, host);

        const resolved = path.resolve(localFile);

        if (!fs.existsSync(resolved) ||
            !fs.statSync(resolved).isFile()) {
            throw new ValidationError("Local file does not exist.");
        }

        if (fs.lstatSync(resolved).isSymbolicLink()) {
            throw new ValidationError("Symbolic links are not accepted.");
        }

        const stat = fs.statSync(resolved);

        if (stat.size > this.policy.maximumFileSize) {
            throw new ValidationError("File exceeds transfer size limit.");
        }

        if (!remotePath.startsWith("/") ||
            /[\s\r\n"'\\\0]/.test(remotePath) ||
            remotePath.split("/").some(part => part === "." || part === "..") ||
            remotePath.endsWith("/")) {
            throw new ValidationError("Unsafe remote file path.");
        }

        const remoteCommand = `put "${resolved}" "${remotePath}"`;

        const temporaryDirectory = fs.mkdtempSync(
            path.join(os.tmpdir(), "secure-sftp-")
        );

        const batchFile = path.join(temporaryDirectory, "batch.txt");

        try {
            fs.writeFileSync(
                batchFile,
                `${remoteCommand}\nls "${remotePath}"\nbye\n`,
                { mode: 0o600 }
            );

            return this.execute(
                "sftp",
                [
                    "-b", batchFile,
                    ...this.baseArguments(),
                    `${username}@${host}`
                ],
                120000
            ).then(result => {
                return {
                    destination: `${username}@${host}:${remotePath}`,
                    bytes: stat.size,
                    protocol: "SFTP over SSH",
                    result
                };
            }).finally(() => {
                fs.rmSync(temporaryDirectory, {
                    recursive: true,
                    force: true
                });
            });
        } catch (error) {
            fs.rmSync(temporaryDirectory, {
                recursive: true,
                force: true
            });

            throw error;
        }
    }
}

class VPNConfiguration {
    constructor({
        interfaceName,
        endpoint,
        port,
        allowedNetworks,
        protocol = "WireGuard"
    }) {
        if (!/^[A-Za-z0-9_.-]{1,15}$/.test(interfaceName)) {
            throw new ValidationError("Invalid VPN interface.");
        }

        if (net.isIP(endpoint) === 0 &&
            !/^(?=.{1,253}$)[A-Za-z0-9.-]+$/.test(endpoint)) {
            throw new ValidationError("Invalid VPN endpoint.");
        }

        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            throw new ValidationError("Invalid VPN port.");
        }

        if (!["WireGuard", "IPsec"].includes(protocol)) {
            throw new ValidationError("Unsupported VPN protocol.");
        }

        if (!Array.isArray(allowedNetworks) ||
            allowedNetworks.length === 0) {
            throw new ValidationError("VPN routes are required.");
        }

        this.interfaceName = interfaceName;
        this.endpoint = endpoint;
        this.port = port;
        this.allowedNetworks = allowedNetworks.map(
            VPNConfiguration.validateCIDR
        );
        this.protocol = protocol;
    }

    static validateCIDR(cidr) {
        if (typeof cidr !== "string") {
            throw new ValidationError("Network must be a string.");
        }

        const match = cidr.match(/^(.+)\/(\d+)$/);

        if (!match) {
            throw new ValidationError("Invalid CIDR notation.");
        }

        const address = match[1];
        const prefix = Number(match[2]);
        const version = net.isIP(address);

        if (version === 0 ||
            prefix < 0 ||
            prefix > (version === 4 ? 32 : 128)) {
            throw new ValidationError(`Invalid VPN network: ${cidr}`);
        }

        return cidr;
    }

    inspect() {
        return {
            interface: this.interfaceName,
            endpoint: `${this.endpoint}:${this.port}`,
            allowedNetworks: this.allowedNetworks,
            protocol: this.protocol,
            valid: true
        };
    }
}

class TransferIntegrity {
    static async calculateSHA256(file) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash("sha256");
            const stream = fs.createReadStream(file);

            stream.on("error", reject);
            stream.on("data", chunk => hash.update(chunk));
            stream.on("end", () => resolve(hash.digest("hex")));
        });
    }

    static async verify(file, expectedHash) {
        if (!/^[a-fA-F0-9]{64}$/.test(expectedHash)) {
            throw new ValidationError("Invalid SHA-256 digest.");
        }

        const actual = await this.calculateSHA256(file);

        return crypto.timingSafeEqual(
            Buffer.from(actual, "hex"),
            Buffer.from(expectedHash, "hex")
        );
    }
}

async function main() {
    const policy = new CommunicationPolicy();
    const monitor = new CommunicationMonitor();

    monitor.on("stateChanged", event => {
        console.log("AUDIT:", JSON.stringify(event));
    });

    monitor.on("registered", connection => {
        console.log("REGISTERED:", connection.id);
    });

    console.log("\n=== SECURE COMMUNICATIONS LAB ===");

    console.log("\n1. HTTPS and TLS");

    monitor.register(
        "HTTPS-001",
        "HTTPS",
        "https://example.com"
    );

    monitor.transition("HTTPS-001", "CONNECTING");

    try {
        const response = await new HTTPSClient(policy).request(
            "https://example.com"
        );

        monitor.transition("HTTPS-001", "CONNECTED");
        console.log(response);

        monitor.transition("HTTPS-001", "DISCONNECTED");
    } catch (error) {
        monitor.transition("HTTPS-001", "FAILED");
        console.error("HTTPS error:", error.message);
    }

    console.log("\n2. SSH security");

    const knownHosts = path.join(
        os.homedir(),
        ".ssh",
        "known_hosts"
    );

    console.log({
        knownHostsExists: fs.existsSync(knownHosts),
        strictHostChecking: policy.strictSSH,
        agentForwarding: false
    });

    console.log("SSH commands require explicit invocation.");

    console.log("\n3. VPN configuration");

    const vpn = new VPNConfiguration({
        interfaceName: "wg0",
        endpoint: "vpn.example.com",
        port: 51820,
        allowedNetworks: [
            "10.20.0.0/16",
            "192.168.50.0/24"
        ]
    });

    console.log(vpn.inspect());

    console.log("\n4. Secure file transfer integrity");

    const sample = path.join(
        os.tmpdir(),
        "secure-communications-sample.txt"
    );

    fs.writeFileSync(
        sample,
        "Confidential enterprise communication record."
    );

    try {
        const digest = await TransferIntegrity.calculateSHA256(sample);
        const verified = await TransferIntegrity.verify(sample, digest);

        console.log({
            file: path.basename(sample),
            sha256: digest,
            integrityVerified: verified,
            protocolForRemoteTransfer: "SFTP over SSH"
        });
    } finally {
        fs.rmSync(sample, { force: true });
    }

    console.log("\n5. SSH and SFTP operational requirements");

    if (fs.existsSync(knownHosts)) {
        console.log("Known-hosts database available.");
    } else {
        console.log("Configure trusted SSH host keys before connecting.");
    }

    console.log("SSH and SFTP use separate authenticated sessions.");
    console.log("VPN encryption protects network traffic at the tunnel layer.");

    console.log("\n6. Failure handling");

    try {
        new CommunicationPolicy({
            verifyCertificates: false
        });
    } catch (error) {
        console.log("Blocked insecure policy:", error.message);
    }

    try {
        new VPNConfiguration({
            interfaceName: "wg0",
            endpoint: "vpn.example.com",
            port: 51820,
            allowedNetworks: ["300.1.1.1/24"]
        });
    } catch (error) {
        console.log("Blocked invalid VPN route:", error.message);
    }

    console.log("\n7. Active communication sessions");

    console.log(monitor.getActiveConnections());

    console.log("\n8. Audit log");

    console.log(JSON.stringify(monitor.auditLog, null, 2));

    console.log("\nSecure communications demonstration completed.");
}

main().catch(error => {
    console.error("Fatal security error:", error.message);
    process.exitCode = 1;
});
