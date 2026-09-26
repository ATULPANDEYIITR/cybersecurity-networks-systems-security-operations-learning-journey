#!/usr/bin/env node

/**
 * Nmap Fundamentals in JavaScript
 *
 * Demonstrates:
 *   - TCP connect scanning
 *   - UDP probing
 *   - Port states
 *   - Lightweight service detection
 *   - Timeouts
 *   - Concurrency
 *   - Validation
 *   - Nmap command construction
 *   - OS detection concepts
 *
 * The default target is localhost.
 *
 * Network scanning should only be performed against systems for which
 * you have explicit authorization.
 *
 * Run:
 *   node nmap_fundamentals.js
 *
 * Examples:
 *   node nmap_fundamentals.js --target 127.0.0.1 --ports 22,80,443
 *   node nmap_fundamentals.js --mode tcp --ports 1-100
 *   node nmap_fundamentals.js --mode udp --ports 53,161
 *   node nmap_fundamentals.js --service-detection
 */

"use strict";

const net = require("net");
const dgram = require("dgram");
const os = require("os");

// -----------------------------------------------------------------------------
// 1. Fundamental terminology
// -----------------------------------------------------------------------------

function explainFundamentals() {
    console.log("=".repeat(78));
    console.log("NMAP FUNDAMENTALS - JAVASCRIPT");
    console.log("=".repeat(78));

    const concepts = [
        ["TCP", "Connection-oriented transport protocol."],
        ["UDP", "Connectionless transport protocol."],
        ["Port", "Numbered transport-layer endpoint."],
        ["Open", "An application is accepting traffic."],
        ["Closed", "The host responds, but no application accepts the port."],
        ["Filtered", "Filtering prevents a reliable state determination."],
        ["Service detection", "Attempts to identify the application behind a port."],
        ["OS detection", "Infers an operating-system family from network behavior."],
    ];

    for (const [name, meaning] of concepts) {
        console.log(`${name.padEnd(20)} ${meaning}`);
    }

    console.log();
}

// -----------------------------------------------------------------------------
// 2. Common services
// -----------------------------------------------------------------------------

const COMMON_SERVICES = new Map([
    [20, "ftp-data"],
    [21, "ftp"],
    [22, "ssh"],
    [23, "telnet"],
    [25, "smtp"],
    [53, "dns"],
    [67, "dhcp-server"],
    [68, "dhcp-client"],
    [80, "http"],
    [110, "pop3"],
    [111, "rpcbind"],
    [123, "ntp"],
    [135, "msrpc"],
    [137, "netbios-ns"],
    [138, "netbios-dgm"],
    [139, "netbios-ssn"],
    [143, "imap"],
    [161, "snmp"],
    [389, "ldap"],
    [443, "https"],
    [445, "microsoft-ds"],
    [465, "smtps"],
    [587, "submission"],
    [636, "ldaps"],
    [993, "imaps"],
    [995, "pop3s"],
    [1433, "mssql"],
    [1521, "oracle"],
    [2049, "nfs"],
    [3306, "mysql"],
    [3389, "rdp"],
    [5432, "postgresql"],
    [5900, "vnc"],
    [6379, "redis"],
    [8080, "http-alt"]
]);

function serviceName(port) {
    return COMMON_SERVICES.get(port) || "unknown";
}

// -----------------------------------------------------------------------------
// 3. Argument parsing
// -----------------------------------------------------------------------------

function parseArguments() {
    const args = process.argv.slice(2);

    const options = {
        target: "127.0.0.1",
        ports: "22,53,80,443,8080",
        mode: "both",
        timeout: 500,
        concurrency: 8,
        serviceDetection: false
    };

    for (let i = 0; i < args.length; i++) {
        const argument = args[i];

        switch (argument) {
            case "--target":
                options.target = args[++i];
                break;

            case "--ports":
                options.ports = args[++i];
                break;

            case "--mode":
                options.mode = args[++i];
                break;

            case "--timeout":
                options.timeout = Number(args[++i]);
                break;

            case "--concurrency":
                options.concurrency = Number(args[++i]);
                break;

            case "--service-detection":
                options.serviceDetection = true;
                break;

            case "--help":
                printUsage();
                process.exit(0);

            default:
                throw new Error(`Unknown argument: ${argument}`);
        }
    }

    return options;
}

function printUsage() {
    console.log(`
Usage:
  node nmap_fundamentals.js [options]

Options:
  --target <host>          Target host, default 127.0.0.1
  --ports <ports>          Example: 22,80,443 or 1-100
  --mode <mode>            tcp, udp, both
  --timeout <milliseconds> Socket timeout
  --concurrency <number>   Maximum simultaneous probes
  --service-detection      Perform lightweight service detection
  --help                   Display this help
`);
}

// -----------------------------------------------------------------------------
// 4. Port parsing and validation
// -----------------------------------------------------------------------------

function parsePorts(portText) {
    const ports = new Set();

    for (const rawPart of portText.split(",")) {
        const part = rawPart.trim();

        if (!part) {
            continue;
        }

        if (part.includes("-")) {
            const pieces = part.split("-");

            if (pieces.length !== 2) {
                throw new Error(`Invalid port range: ${part}`);
            }

            let start = Number(pieces[0]);
            let end = Number(pieces[1]);

            if (!Number.isInteger(start) || !Number.isInteger(end)) {
                throw new Error(`Invalid port range: ${part}`);
            }

            if (start > end) {
                [start, end] = [end, start];
            }

            for (let port = start; port <= end; port++) {
                ports.add(port);
            }
        } else {
            const port = Number(part);

            if (!Number.isInteger(port)) {
                throw new Error(`Invalid port: ${part}`);
            }

            ports.add(port);
        }
    }

    if (ports.size === 0) {
        throw new Error("No ports were supplied.");
    }

    for (const port of ports) {
        if (port < 1 || port > 65535) {
            throw new Error(`Port out of range: ${port}`);
        }
    }

    return [...ports].sort((a, b) => a - b);
}

// -----------------------------------------------------------------------------
// 5. Target validation
// -----------------------------------------------------------------------------

function validateTarget(target) {
    if (!target || target.length > 253) {
        throw new Error("Target is empty or too long.");
    }

    // Reject shell metacharacters. The target is used directly by Node's
    // networking APIs, but strict validation is still useful.
    if (!/^[A-Za-z0-9_.:-]+$/.test(target)) {
        throw new Error("Target contains unsupported characters.");
    }

    return target;
}

// -----------------------------------------------------------------------------
// 6. TCP connect scan
// -----------------------------------------------------------------------------

function tcpConnectScan(target, port, timeout) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        const started = process.hrtime.bigint();
        let settled = false;

        const finish = (result) => {
            if (settled) {
                return;
            }

            settled = true;
            socket.destroy();
            resolve(result);
        };

        socket.setTimeout(timeout);

        socket.once("connect", () => {
            const latency = Number(process.hrtime.bigint() - started) / 1e6;

            finish({
                port,
                protocol: "tcp",
                state: "open",
                service: serviceName(port),
                latencyMs: Number(latency.toFixed(2)),
                reason: "TCP connection succeeded",
                banner: ""
            });
        });

        socket.once("timeout", () => {
            const latency = Number(process.hrtime.bigint() - started) / 1e6;

            finish({
                port,
                protocol: "tcp",
                state: "filtered",
                service: serviceName(port),
                latencyMs: Number(latency.toFixed(2)),
                reason: "No TCP response before timeout",
                banner: ""
            });
        });

        socket.once("error", (error) => {
            const latency = Number(process.hrtime.bigint() - started) / 1e6;

            if (error.code === "ECONNREFUSED") {
                finish({
                    port,
                    protocol: "tcp",
                    state: "closed",
                    service: serviceName(port),
                    latencyMs: Number(latency.toFixed(2)),
                    reason: "Connection refused",
                    banner: ""
                });
            } else {
                finish({
                    port,
                    protocol: "tcp",
                    state: "error",
                    service: serviceName(port),
                    latencyMs: Number(latency.toFixed(2)),
                    reason: `${error.code || "network error"}: ${error.message}`,
                    banner: ""
                });
            }
        });

        socket.connect({
            host: target,
            port
        });
    });
}

// -----------------------------------------------------------------------------
// 7. Controlled concurrency
// -----------------------------------------------------------------------------

async function mapWithConcurrency(items, concurrency, worker) {
    const results = new Array(items.length);
    let nextIndex = 0;

    async function workerLoop() {
        while (true) {
            const index = nextIndex++;

            if (index >= items.length) {
                return;
            }

            results[index] = await worker(items[index]);
        }
    }

    const workers = [];

    for (let i = 0; i < Math.min(concurrency, items.length); i++) {
        workers.push(workerLoop());
    }

    await Promise.all(workers);
    return results;
}

// -----------------------------------------------------------------------------
// 8. HTTP service detection
// -----------------------------------------------------------------------------

function detectHttpService(target, port, timeout) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        let response = "";
        let settled = false;

        const finish = (value) => {
            if (settled) {
                return;
            }

            settled = true;
            socket.destroy();
            resolve(value);
        };

        socket.setTimeout(timeout);

        socket.once("connect", () => {
            const request =
                `HEAD / HTTP/1.0\r\n` +
                `Host: ${target}\r\n` +
                `Connection: close\r\n\r\n`;

            socket.write(request);
        });

        socket.on("data", (chunk) => {
            response += chunk.toString("utf8");

            // The first part normally contains the status line and headers.
            if (response.length >= 2048 || response.includes("\r\n\r\n")) {
                const lines = response.split(/\r?\n/);
                const status = lines[0] || "";

                const serverHeader =
                    lines.find((line) => /^server:/i.test(line)) || "";

                finish(
                    serverHeader
                        ? `${status}; ${serverHeader.trim()}`
                        : status
                );
            }
        });

        socket.once("timeout", () => finish(""));
        socket.once("error", () => finish(""));
        socket.once("close", () => finish(response.split(/\r?\n/)[0] || ""));

        socket.connect({
            host: target,
            port
        });
    });
}

// -----------------------------------------------------------------------------
// 9. Generic banner detection
// -----------------------------------------------------------------------------

function detectBanner(target, port, timeout) {
    if (port === 80 || port === 8080) {
        return detectHttpService(target, port, Math.max(timeout, 1000));
    }

    return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = "";
        let settled = false;

        const finish = (value) => {
            if (settled) {
                return;
            }

            settled = true;
            socket.destroy();
            resolve(value.trim().slice(0, 300));
        };

        socket.setTimeout(Math.max(timeout, 1000));

        socket.once("connect", () => {
            // Some protocols, notably SSH, send an identification string
            // immediately after connection.
        });

        socket.on("data", (chunk) => {
            data += chunk.toString("utf8");
            finish(data);
        });

        socket.once("timeout", () => finish(""));
        socket.once("error", () => finish(""));
        socket.once("close", () => finish(data));

        socket.connect({
            host: target,
            port
        });
    });
}

async function performServiceDetection(target, results, timeout) {
    const openTcp = results.filter(
        (result) => result.protocol === "tcp" && result.state === "open"
    );

    await mapWithConcurrency(openTcp, 4, async (result) => {
        const banner = await detectBanner(target, result.port, timeout);

        if (banner) {
            result.banner = banner;
            result.service = `${result.service} | ${banner}`;
        }

        return result;
    });
}

// -----------------------------------------------------------------------------
// 10. UDP scanning
// -----------------------------------------------------------------------------

function createDnsQuery() {
    // Minimal DNS query for the root name.
    return Buffer.from([
        0x12, 0x34,
        0x01, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
        0x00, 0x01,
        0x00, 0x01
    ]);
}

function udpProbe(target, port, timeout) {
    return new Promise((resolve) => {
        const socket = dgram.createSocket("udp4");
        const started = process.hrtime.bigint();
        let settled = false;

        const finish = (result) => {
            if (settled) {
                return;
            }

            settled = true;

            try {
                socket.close();
            } catch (_) {
                // Socket may already be closed.
            }

            resolve(result);
        };

        const timer = setTimeout(() => {
            const latency = Number(process.hrtime.bigint() - started) / 1e6;

            finish({
                port,
                protocol: "udp",
                state: "open|filtered",
                service: serviceName(port),
                latencyMs: Number(latency.toFixed(2)),
                reason:
                    "No UDP response; open and filtered cannot be distinguished",
                banner: ""
            });
        }, timeout);

        socket.once("message", (message) => {
            clearTimeout(timer);

            const latency = Number(process.hrtime.bigint() - started) / 1e6;

            finish({
                port,
                protocol: "udp",
                state: "open",
                service: serviceName(port),
                latencyMs: Number(latency.toFixed(2)),
                reason: "UDP response received",
                banner: message.subarray(0, 100).toString("hex")
            });
        });

        socket.once("error", (error) => {
            clearTimeout(timer);

            const latency = Number(process.hrtime.bigint() - started) / 1e6;

            finish({
                port,
                protocol: "udp",
                state:
                    error.code === "ECONNREFUSED"
                        ? "closed"
                        : "error",
                service: serviceName(port),
                latencyMs: Number(latency.toFixed(2)),
                reason: `${error.code || "UDP error"}: ${error.message}`,
                banner: ""
            });
        });

        const payload = port === 53 ? createDnsQuery() : Buffer.alloc(0);

        socket.send(payload, port, target, (error) => {
            if (error) {
                clearTimeout(timer);

                finish({
                    port,
                    protocol: "udp",
                    state: "error",
                    service: serviceName(port),
                    latencyMs: 0,
                    reason: error.message,
                    banner: ""
                });
            }
        });
    });
}

// -----------------------------------------------------------------------------
// 11. Result presentation
// -----------------------------------------------------------------------------

function printResults(results) {
    console.log("=".repeat(78));
    console.log("SCAN RESULTS");
    console.log("=".repeat(78));

    if (results.length === 0) {
        console.log("No results.");
        return;
    }

    console.log(
        `${"PORT".padStart(6)} ` +
        `${"PROTO".padEnd(6)} ` +
        `${"STATE".padEnd(16)} ` +
        `${"SERVICE".padEnd(30)} ` +
        `${"LATENCY".padStart(10)}`
    );

    console.log("-".repeat(78));

    const sorted = [...results].sort((a, b) => {
        if (a.protocol !== b.protocol) {
            return a.protocol.localeCompare(b.protocol);
        }

        return a.port - b.port;
    });

    for (const result of sorted) {
        const latency =
            result.latencyMs === undefined
                ? "-"
                : `${result.latencyMs.toFixed(2)} ms`;

        console.log(
            `${String(result.port).padStart(6)} ` +
            `${result.protocol.padEnd(6)} ` +
            `${result.state.padEnd(16)} ` +
            `${result.service.slice(0, 30).padEnd(30)} ` +
            `${latency.padStart(10)}`
        );

        console.log(`       reason: ${result.reason}`);

        if (result.banner) {
            console.log(`       probe:  ${result.banner.slice(0, 120)}`);
        }
    }

    console.log();
}

// -----------------------------------------------------------------------------
// 12. Nmap command reference
// -----------------------------------------------------------------------------

function printNmapReference(target, ports) {
    console.log("=".repeat(78));
    console.log("NMAP COMMAND REFERENCE");
    console.log("=".repeat(78));

    const commands = [
        [`nmap -sT -p ${ports} ${target}`, "TCP connect scan"],
        [`nmap -sU -p ${ports} ${target}`, "UDP scan"],
        [`nmap -sT -sV -p ${ports} ${target}`, "TCP service/version detection"],
        [`nmap -O -p ${ports} ${target}`, "OS detection"],
        [
            `nmap -sT -sV -O -p ${ports} ${target}`,
            "Combined TCP, service, and OS detection"
        ]
    ];

    for (const [command, explanation] of commands) {
        console.log(`${command}`);
        console.log(`  ${explanation}`);
    }

    console.log();
}

// -----------------------------------------------------------------------------
// 13. OS detection explanation
// -----------------------------------------------------------------------------

function explainOsDetection() {
    console.log("=".repeat(78));
    console.log("OS DETECTION");
    console.log("=".repeat(78));

    console.log(`
Nmap OS detection does not simply ask a remote machine for its OS name.

It can compare network fingerprints involving:
  - TCP options
  - TCP window behavior
  - packet sequencing
  - IP-level characteristics
  - ICMP responses
  - responses to carefully selected probes

The result is an inference from observable network behavior.

The local Node.js runtime can report its own host operating system:

  Node.js platform: ${process.platform}
  OS type:          ${os.type()}
  OS release:       ${os.release()}

These values describe the machine running this JavaScript process.
They are NOT remote OS fingerprinting.
`);
}

// -----------------------------------------------------------------------------
// 14. State explanation
// -----------------------------------------------------------------------------

function explainPortStates() {
    console.log("=".repeat(78));
    console.log("PORT STATES");
    console.log("=".repeat(78));

    const states = {
        open: "An application is accepting connections or protocol traffic.",
        closed: "The host is reachable, but the port has no listener.",
        filtered: "Filtering prevents a reliable determination.",
        "open|filtered":
            "UDP silence prevents distinguishing open from filtered.",
        "closed|filtered":
            "Evidence does not clearly separate closed from filtered."
    };

    for (const [state, meaning] of Object.entries(states)) {
        console.log(`${state.padEnd(18)} ${meaning}`);
    }

    console.log();
}

// -----------------------------------------------------------------------------
// 15. Main execution
// -----------------------------------------------------------------------------

async function main() {
    try {
        const options = parseArguments();

        validateTarget(options.target);

        if (!["tcp", "udp", "both"].includes(options.mode)) {
            throw new Error("Mode must be tcp, udp, or both.");
        }

        if (!Number.isFinite(options.timeout) || options.timeout <= 0) {
            throw new Error("Timeout must be greater than zero.");
        }

        if (
            !Number.isInteger(options.concurrency) ||
            options.concurrency < 1
        ) {
            throw new Error("Concurrency must be a positive integer.");
        }

        const ports = parsePorts(options.ports);

        explainFundamentals();
        explainPortStates();
        explainOsDetection();

        console.log(`Target: ${options.target}`);
        console.log(`Ports:  ${ports.join(", ")}`);
        console.log();

        const results = [];

        if (options.mode === "tcp" || options.mode === "both") {
            console.log("Running TCP connect probes...");

            const tcpResults = await mapWithConcurrency(
                ports,
                options.concurrency,
                (port) =>
                    tcpConnectScan(
                        options.target,
                        port,
                        options.timeout
                    )
            );

            results.push(...tcpResults);
        }

        if (options.mode === "udp" || options.mode === "both") {
            console.log("Running UDP probes...");

            const udpResults = await mapWithConcurrency(
                ports,
                Math.min(options.concurrency, 8),
                (port) =>
                    udpProbe(
                        options.target,
                        port,
                        Math.max(options.timeout, 500)
                    )
            );

            results.push(...udpResults);
        }

        if (options.serviceDetection) {
            console.log("Running lightweight service detection...");
            await performServiceDetection(
                options.target,
                results,
                Math.max(options.timeout, 1000)
            );
        }

        printResults(results);
        printNmapReference(options.target, options.ports);

        console.log("Important operational rule:");
        console.log(
            "Only scan systems and networks for which you have explicit authorization."
        );
    } catch (error) {
        console.error(`Error: ${error.message}`);
        process.exitCode = 1;
    }
}

main();
