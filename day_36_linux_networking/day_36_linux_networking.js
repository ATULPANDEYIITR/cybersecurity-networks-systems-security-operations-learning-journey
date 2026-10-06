#!/usr/bin/env node
"use strict";

/*
 * Linux Networking with Node.js
 *
 * This file uses Node's standard library to inspect interfaces, routes,
 * sockets, DNS behavior, and firewall configuration. It also models a
 * packet-routing and firewall decision path in memory.
 *
 * Diagnostic commands are read-only. The program never modifies firewall
 * rules because an unsafe firewall mutation can disconnect a remote host.
 */

const os = require("os");
const dns = require("dns").promises;
const net = require("net");
const fs = require("fs/promises");
const { execFile } = require("child_process");
const { promisify } = require("util");

const execFileAsync = promisify(execFile);


// ---------------------------------------------------------------------------
// Linux command execution
// ---------------------------------------------------------------------------

async function runCommand(command, args = [], timeout = 5000) {
    try {
        const { stdout, stderr } = await execFileAsync(command, args, {
            timeout,
            windowsHide: true,
            maxBuffer: 4 * 1024 * 1024,
        });

        return {
            stdout: stdout.trimEnd(),
            stderr: stderr.trimEnd(),
        };
    } catch (error) {
        const detail = error.stderr || error.message || "unknown command failure";
        throw new Error(`${command} ${args.join(" ")} failed: ${detail}`);
    }
}


// ---------------------------------------------------------------------------
// Interface inspection
// ---------------------------------------------------------------------------

function inspectInterfaces() {
    console.log("\n=== Network interfaces ===");

    const interfaces = os.networkInterfaces();

    for (const [name, addresses] of Object.entries(interfaces)) {
        console.log(`\n${name}`);

        for (const address of addresses || []) {
            console.log(
                `  ${address.family} ${address.address}/${address.netmask}` +
                ` ${address.internal ? "loopback/internal" : "host"}`
            );
        }
    }
}


// ---------------------------------------------------------------------------
// Linux routes
// ---------------------------------------------------------------------------

async function inspectRoutes() {
    console.log("\n=== IPv4 routes ===");

    try {
        const result = await runCommand("ip", ["-j", "route"]);
        const routes = JSON.parse(result.stdout);

        for (const route of routes) {
            console.log(
                `${route.dst || "default"} ` +
                `via=${route.gateway || "-"} ` +
                `dev=${route.dev || "-"} ` +
                `metric=${route.metric ?? "-"}`
            );
        }
    } catch (error) {
        console.error(`Route inspection failed: ${error.message}`);
    }

    console.log("\n=== IPv6 routes ===");

    try {
        const result = await runCommand("ip", ["-j", "-6", "route"]);
        const routes = JSON.parse(result.stdout);

        for (const route of routes) {
            console.log(
                `${route.dst || "default"} ` +
                `via=${route.gateway || "-"} ` +
                `dev=${route.dev || "-"} ` +
                `metric=${route.metric ?? "-"}`
            );
        }
    } catch (error) {
        console.error(`IPv6 route inspection failed: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// Socket inspection
// ---------------------------------------------------------------------------

async function inspectSockets() {
    console.log("\n=== TCP and UDP sockets ===");

    try {
        const { stdout } = await runCommand("ss", ["-H", "-tun"]);
        const lines = stdout.split(/\r?\n/).filter(Boolean);

        for (const line of lines.slice(0, 50)) {
            console.log(line);
        }

        if (lines.length > 50) {
            console.log(`... ${lines.length - 50} additional socket records omitted.`);
        }
    } catch (error) {
        console.error(`Socket inspection failed: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// DNS configuration
// ---------------------------------------------------------------------------

async function inspectDnsConfiguration() {
    console.log("\n=== DNS configuration ===");

    try {
        const content = await fs.readFile("/etc/resolv.conf", "utf8");

        for (const rawLine of content.split(/\r?\n/)) {
            const line = rawLine.trim();

            if (!line || line.startsWith("#")) {
                continue;
            }

            if (
                line.startsWith("nameserver ") ||
                line.startsWith("search ") ||
                line.startsWith("domain ")
            ) {
                console.log(line);
            }
        }
    } catch (error) {
        console.error(`Unable to read /etc/resolv.conf: ${error.message}`);
    }
}

async function resolveHostname(hostname) {
    if (!hostname || hostname.length > 253 || /\s/.test(hostname)) {
        throw new Error("Invalid hostname.");
    }

    const addresses = await dns.lookup(hostname, {
        all: true,
        verbatim: true,
    });

    return addresses;
}


// ---------------------------------------------------------------------------
// Firewall inspection
// ---------------------------------------------------------------------------

async function inspectFirewall() {
    console.log("\n=== Firewall configuration ===");

    const candidates = [
        ["nft", ["list", "ruleset"], "nftables"],
        ["ufw", ["status", "verbose"], "UFW"],
        ["iptables", ["-S"], "iptables"],
    ];

    for (const [command, args, label] of candidates) {
        try {
            const result = await runCommand(command, args);
            console.log(`\n${label}:`);
            console.log(result.stdout.split(/\r?\n/).slice(0, 80).join("\n"));
            return;
        } catch (_) {
            // A missing or inaccessible firewall command is not fatal.
        }
    }

    console.log("No supported firewall inspection command succeeded.");
}


// ---------------------------------------------------------------------------
// Route-selection model
// ---------------------------------------------------------------------------

function ipv4ToInteger(address) {
    const parts = address.split(".").map(Number);

    if (
        parts.length !== 4 ||
        parts.some(
            part => !Number.isInteger(part) || part < 0 || part > 255
        )
    ) {
        throw new Error(`Invalid IPv4 address: ${address}`);
    }

    return (
        ((parts[0] << 24) >>> 0) |
        (parts[1] << 16) |
        (parts[2] << 8) |
        parts[3]
    ) >>> 0;
}

function cidrContains(cidr, address) {
    const [network, prefixText] = cidr.split("/");
    const prefix = Number(prefixText);

    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
        throw new Error(`Invalid CIDR: ${cidr}`);
    }

    const ip = ipv4ToInteger(address);
    const networkValue = ipv4ToInteger(network);

    if (prefix === 0) {
        return true;
    }

    const mask = (0xffffffff << (32 - prefix)) >>> 0;

    return (ip & mask) === (networkValue & mask);
}

function selectRoute(routes, destination) {
    const candidates = routes.filter(route =>
        cidrContains(route.destination, destination)
    );

    if (candidates.length === 0) {
        return null;
    }

    return candidates.reduce((best, current) => {
        if (!best) {
            return current;
        }

        const currentPrefix = Number(current.destination.split("/")[1]);
        const bestPrefix = Number(best.destination.split("/")[1]);

        if (currentPrefix > bestPrefix) {
            return current;
        }

        if (
            currentPrefix === bestPrefix &&
            (current.metric ?? 0) < (best.metric ?? 0)
        ) {
            return current;
        }

        return best;
    }, null);
}


// ---------------------------------------------------------------------------
// Event-driven Pull Request-like network state model is deliberately avoided.
// The networking model below uses Node's event-driven socket API directly.
// ---------------------------------------------------------------------------

function tcpProbe(host, port, timeoutMs = 3000) {
    return new Promise(resolve => {
        const started = process.hrtime.bigint();
        let settled = false;

        const finish = result => {
            if (settled) {
                return;
            }

            settled = true;
            resolve(result);
        };

        const socket = net.createConnection({
            host,
            port,
            timeout: timeoutMs,
        });

        socket.once("connect", () => {
            const elapsedMs =
                Number(process.hrtime.bigint() - started) / 1_000_000;

            socket.end();

            finish({
                success: true,
                message: `TCP connection established in ${elapsedMs.toFixed(1)} ms`,
            });
        });

        socket.once("timeout", () => {
            socket.destroy();
            finish({
                success: false,
                message: `TCP connection timed out after ${timeoutMs} ms`,
            });
        });

        socket.once("error", error => {
            finish({
                success: false,
                message: `TCP connection failed: ${error.message}`,
            });
        });
    });
}


// ---------------------------------------------------------------------------
// Firewall policy model
// ---------------------------------------------------------------------------

class FirewallRule {
    constructor({
        action,
        protocol = null,
        sourceNetwork = null,
        destinationPort = null,
        description,
    }) {
        this.action = action;
        this.protocol = protocol;
        this.sourceNetwork = sourceNetwork;
        this.destinationPort = destinationPort;
        this.description = description;
    }

    matches(packet) {
        if (
            this.protocol &&
            packet.protocol.toLowerCase() !== this.protocol.toLowerCase()
        ) {
            return false;
        }

        if (
            this.sourceNetwork &&
            !cidrContains(this.sourceNetwork, packet.sourceIp)
        ) {
            return false;
        }

        if (
            this.destinationPort !== null &&
            packet.destinationPort !== this.destinationPort
        ) {
            return false;
        }

        return true;
    }
}

class FirewallPolicy {
    constructor(rules, defaultAction = "DROP") {
        this.rules = rules;
        this.defaultAction = defaultAction;
    }

    evaluate(packet) {
        for (const rule of this.rules) {
            if (rule.matches(packet)) {
                return {
                    action: rule.action,
                    reason: rule.description,
                };
            }
        }

        return {
            action: this.defaultAction,
            reason: "default policy",
        };
    }
}

function demonstrateModels() {
    console.log("\n=== Longest-prefix route selection ===");

    const routes = [
        {
            destination: "0.0.0.0/0",
            gateway: "192.0.2.1",
            device: "eth0",
            metric: 100,
        },
        {
            destination: "10.0.0.0/8",
            gateway: null,
            device: "eth1",
            metric: 100,
        },
        {
            destination: "10.20.0.0/16",
            gateway: "10.20.0.1",
            device: "eth2",
            metric: 50,
        },
    ];

    for (const destination of ["8.8.8.8", "10.50.1.10", "10.20.5.25"]) {
        const route = selectRoute(routes, destination);

        if (route) {
            console.log(
                `${destination} -> ${route.destination}, ` +
                `dev=${route.device}, gateway=${route.gateway || "-"}`
            );
        } else {
            console.log(`${destination} -> no route`);
        }
    }

    console.log("\n=== Firewall packet evaluation ===");

    const firewall = new FirewallPolicy([
        new FirewallRule({
            action: "ACCEPT",
            protocol: "tcp",
            sourceNetwork: "10.20.0.0/16",
            destinationPort: 22,
            description: "SSH allowed from management network",
        }),
        new FirewallRule({
            action: "ACCEPT",
            protocol: "tcp",
            destinationPort: 443,
            description: "HTTPS allowed",
        }),
    ]);

    const packets = [
        {
            protocol: "tcp",
            sourceIp: "10.20.5.10",
            destinationIp: "192.0.2.20",
            destinationPort: 22,
        },
        {
            protocol: "tcp",
            sourceIp: "198.51.100.5",
            destinationIp: "192.0.2.20",
            destinationPort: 22,
        },
        {
            protocol: "tcp",
            sourceIp: "198.51.100.5",
            destinationIp: "192.0.2.20",
            destinationPort: 443,
        },
    ];

    for (const packet of packets) {
        const decision = firewall.evaluate(packet);

        console.log(
            `${packet.protocol.toUpperCase()} ` +
            `${packet.sourceIp} -> ${packet.destinationIp}:${packet.destinationPort}: ` +
            `${decision.action} (${decision.reason})`
        );
    }
}


// ---------------------------------------------------------------------------
// Command-line interface
// ---------------------------------------------------------------------------

function parseArguments() {
    const args = process.argv.slice(2);

    return {
        all: args.includes("--all"),
        interfaces: args.includes("--interfaces"),
        routes: args.includes("--routes"),
        sockets: args.includes("--sockets"),
        dns: args.includes("--dns"),
        firewall: args.includes("--firewall"),
        models: args.includes("--models"),
        resolve: args.includes("--resolve")
            ? args[args.indexOf("--resolve") + 1]
            : null,
        tcpHost: args.includes("--tcp")
            ? args[args.indexOf("--tcp") + 1]
            : null,
        tcpPort: args.includes("--tcp")
            ? Number(args[args.indexOf("--tcp") + 2])
            : null,
    };
}

async function main() {
    const args = parseArguments();

    const noAction =
        !args.all &&
        !args.interfaces &&
        !args.routes &&
        !args.sockets &&
        !args.dns &&
        !args.firewall &&
        !args.models &&
        !args.resolve &&
        !args.tcpHost;

    if (noAction || args.all || args.interfaces) {
        inspectInterfaces();
    }

    if (args.all || args.routes) {
        await inspectRoutes();
    }

    if (args.all || args.sockets) {
        await inspectSockets();
    }

    if (args.all || args.dns) {
        await inspectDnsConfiguration();
    }

    if (args.all || args.firewall) {
        await inspectFirewall();
    }

    if (args.all || args.models || noAction) {
        demonstrateModels();
    }

    if (args.resolve) {
        console.log(`\n=== DNS resolution: ${args.resolve} ===`);

        try {
            const addresses = await resolveHostname(args.resolve);

            for (const address of addresses) {
                console.log(`${address.family}: ${address.address}`);
            }
        } catch (error) {
            console.error(`DNS resolution failed: ${error.message}`);
        }
    }

    if (args.tcpHost) {
        if (
            !args.tcpPort ||
            !Number.isInteger(args.tcpPort) ||
            args.tcpPort < 1 ||
            args.tcpPort > 65535
        ) {
            throw new Error("TCP port must be an integer between 1 and 65535.");
        }

        console.log(`\n=== TCP probe: ${args.tcpHost}:${args.tcpPort} ===`);
        const result = await tcpProbe(args.tcpHost, args.tcpPort);
        console.log(`${result.success ? "SUCCESS" : "FAILURE"}: ${result.message}`);
    }
}

main().catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
