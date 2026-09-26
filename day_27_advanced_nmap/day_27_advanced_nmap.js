#!/usr/bin/env node
"use strict";

/*
 * Advanced Nmap: NSE scripts, timing, output formats, scan interpretation,
 * and defensive scanning.
 *
 * This file complements the Python implementation by emphasizing:
 *   - JavaScript object modeling
 *   - XML parsing without external npm packages
 *   - child-process execution
 *   - asynchronous execution
 *   - inventory comparison
 *   - defensive reporting
 *
 * Live scans are restricted to loopback/private/link-local IPv4 targets.
 * Obtain authorization before scanning any system you do not own/control.
 *
 * Runtime:
 *   Node.js 18+
 *
 * Examples:
 *   node advanced_nmap.js
 *   node advanced_nmap.js --demo-scan
 *   node advanced_nmap.js --host 127.0.0.1 --demo-scan
 *   node advanced_nmap.js --xml scan.xml
 */

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const net = require("net");


function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}


function bullet(items) {
    for (const item of items) {
        console.log(`  • ${item}`);
    }
}


/*
 * JavaScript object modeling is useful when transforming Nmap's structured
 * output into application-level inventory objects.
 */
class PortObservation {
    constructor({
        port,
        protocol,
        state,
        service = "",
        product = "",
        version = "",
        extraInfo = "",
        scripts = {}
    }) {
        this.port = port;
        this.protocol = protocol;
        this.state = state;
        this.service = service;
        this.product = product;
        this.version = version;
        this.extraInfo = extraInfo;
        this.scripts = scripts;
    }
}


class HostObservation {
    constructor({
        address,
        hostname = "",
        status = "unknown",
        ports = []
    }) {
        this.address = address;
        this.hostname = hostname;
        this.status = status;
        this.ports = ports;
    }
}


/*
 * Numeric IPv4 validation is deliberately explicit. JavaScript's built-in
 * URL class is not an adequate security policy for arbitrary scan targets.
 */
function parseIPv4(value) {
    const parts = value.split(".");

    if (parts.length !== 4) {
        return null;
    }

    const numbers = parts.map(Number);

    if (
        numbers.some(
            (number) =>
                !Number.isInteger(number) ||
                number < 0 ||
                number > 255
        )
    ) {
        return null;
    }

    return numbers;
}


function isPrivateIPv4(address) {
    const parts = parseIPv4(address);

    if (!parts) {
        return false;
    }

    const [a, b] = parts;

    return (
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        a === 127 ||
        a === 169 && b === 254
    );
}


function validateTarget(target) {
    const value = target.trim();

    if (!value) {
        return { allowed: false, reason: "Target cannot be empty." };
    }

    if (value === "localhost" || isPrivateIPv4(value)) {
        return { allowed: true, normalized: value };
    }

    /*
     * Hostname resolution is handled asynchronously later. For this study
     * implementation, non-private hostnames are rejected before execution.
     */
    if (/^[A-Za-z0-9.-]+$/.test(value)) {
        return {
            allowed: false,
            reason:
                "Use localhost or an explicitly private/link-local IPv4 target."
        };
    }

    return {
        allowed: false,
        reason: "Target contains unsupported characters."
    };
}


/*
 * XML parsing with only the Node.js standard library.
 *
 * This parser handles common Nmap XML elements. It intentionally avoids
 * pretending that regular expressions constitute a complete XML parser.
 * For production systems handling arbitrary XML, a dedicated XML parser
 * with secure entity handling should be used.
 */
function decodeXml(value) {
    return value
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">")
        .replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'")
        .replace(/&amp;/g, "&");
}


function attributes(tag) {
    const result = {};
    const attributePattern =
        /([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*"([^"]*)"/g;

    let match;

    while ((match = attributePattern.exec(tag)) !== null) {
        result[match[1]] = decodeXml(match[2]);
    }

    return result;
}


function parseNmapXml(xml) {
    if (typeof xml !== "string" || xml.trim() === "") {
        throw new Error("Nmap XML is empty.");
    }

    /*
     * Reject DTD declarations in this small educational parser. This keeps
     * the parser from accepting external entity declarations.
     */
    if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml)) {
        throw new Error("DTD/entity declarations are not accepted.");
    }

    const hosts = [];

    const hostPattern = /<host\b[^>]*>([\s\S]*?)<\/host>/gi;
    let hostMatch;

    while ((hostMatch = hostPattern.exec(xml)) !== null) {
        const hostXml = hostMatch[1];

        const statusMatch = hostXml.match(
            /<status\b([^>]*)\/?>/i
        );
        const statusAttributes = statusMatch
            ? attributes(statusMatch[1])
            : {};

        const addressMatches = [
            ...hostXml.matchAll(/<address\b([^>]*)\/?>/gi)
        ];

        let address = "";

        for (const match of addressMatches) {
            const attr = attributes(match[1]);

            if (attr.addrtype === "ipv4" || attr.addrtype === "ipv6") {
                address = attr.addr || "";
                break;
            }
        }

        if (!address && addressMatches.length > 0) {
            address = attributes(addressMatches[0][1]).addr || "";
        }

        const hostnameMatch = hostXml.match(
            /<hostname\b([^>]*)\/?>/i
        );
        const hostname = hostnameMatch
            ? attributes(hostnameMatch[1]).name || ""
            : "";

        const ports = [];
        const portPattern = /<port\b([^>]*)>([\s\S]*?)<\/port>/gi;
        let portMatch;

        while ((portMatch = portPattern.exec(hostXml)) !== null) {
            const portAttributes = attributes(portMatch[1]);
            const portXml = portMatch[2];

            const stateMatch = portXml.match(
                /<state\b([^>]*)\/?>/i
            );
            const stateAttributes = stateMatch
                ? attributes(stateMatch[1])
                : {};

            const serviceMatch = portXml.match(
                /<service\b([^>]*)\/?>/i
            );
            const serviceAttributes = serviceMatch
                ? attributes(serviceMatch[1])
                : {};

            const scripts = {};
            const scriptPattern =
                /<script\b([^>]*)\/?>/gi;
            let scriptMatch;

            while ((scriptMatch = scriptPattern.exec(portXml)) !== null) {
                const scriptAttributes = attributes(scriptMatch[1]);
                if (scriptAttributes.id) {
                    scripts[scriptAttributes.id] =
                        scriptAttributes.output || "";
                }
            }

            const portNumber = Number.parseInt(
                portAttributes.portid,
                10
            );

            if (Number.isInteger(portNumber)) {
                ports.push(
                    new PortObservation({
                        port: portNumber,
                        protocol: portAttributes.protocol || "unknown",
                        state: stateAttributes.state || "unknown",
                        service: serviceAttributes.name || "",
                        product: serviceAttributes.product || "",
                        version: serviceAttributes.version || "",
                        extraInfo: serviceAttributes.extrainfo || "",
                        scripts
                    })
                );
            }
        }

        hosts.push(
            new HostObservation({
                address: address || "unknown",
                hostname,
                status: statusAttributes.state || "unknown",
                ports
            })
        );
    }

    return hosts;
}


function printObservations(hosts) {
    section("STRUCTURED NMAP INTERPRETATION");

    if (hosts.length === 0) {
        console.log("No hosts found.");
        return;
    }

    for (const host of hosts) {
        console.log(
            `\nHost: ${host.hostname || host.address}`
        );
        console.log(`Address: ${host.address}`);
        console.log(`Status: ${host.status}`);

        if (host.ports.length === 0) {
            console.log("  No port records.");
            continue;
        }

        for (const port of host.ports) {
            const serviceDetails = [
                port.service,
                port.product,
                port.version,
                port.extraInfo
            ]
                .filter(Boolean)
                .join(" ");

            console.log(
                `  ${port.port}/${port.protocol} ` +
                `${port.state.padEnd(14)} ` +
                `${serviceDetails}`
            );

            for (const [scriptId, output] of Object.entries(port.scripts)) {
                console.log(
                    `      NSE ${scriptId}: ${output}`
                );
            }
        }
    }
}


function explainFundamentals() {
    section("1. FUNDAMENTALS");

    bullet([
        "Nmap performs network discovery and security auditing.",
        "Port states describe evidence obtained through network probes.",
        "open means an application is accepting connections.",
        "closed means the port is reachable but no application is listening.",
        "filtered means filtering prevents a definitive state determination.",
        "Service detection identifies likely application protocols and software.",
        "NSE extends Nmap through Lua scripts."
    ]);

    console.log("\nCritical distinction:");
    console.log(
        "An exposed service is an inventory observation, not automatically a vulnerability."
    );
}


function explainNse() {
    section("2. NSE SCRIPTS");

    bullet([
        "NSE scripts are Lua programs executed by Nmap.",
        "The default category contains scripts selected for normal discovery.",
        "The safe category is useful when minimizing operational impact is important.",
        "Discovery scripts support information gathering.",
        "Version scripts can complement service detection.",
        "Vulnerability-oriented scripts should be used only within an authorized assessment.",
        "Script results are evidence and require context."
    ]);

    console.log("\nUseful commands:");
    console.log("  nmap --script-help=default");
    console.log("  nmap --script-help=safe");
    console.log("  nmap -sV --script=default TARGET");
    console.log("  nmap -sV --script=safe TARGET");
}


function explainTiming() {
    section("3. TIMING");

    const profiles = {
        "-T0": "extremely conservative",
        "-T1": "very conservative",
        "-T2": "polite",
        "-T3": "normal/default",
        "-T4": "aggressive",
        "-T5": "very aggressive"
    };

    for (const [profile, meaning] of Object.entries(profiles)) {
        console.log(`  ${profile.padEnd(4)} ${meaning}`);
    }

    console.log(
        "\nTiming affects more than elapsed time. Packet rate, parallelism,"
    );
    console.log(
        "retransmissions, latency assumptions, and reliability can change."
    );
}


function explainOutput() {
    section("4. OUTPUT FORMATS");

    const formats = [
        ["-oN", "normal human-readable output"],
        ["-oX", "XML structured output"],
        ["-oG", "grepable line-oriented output"],
        ["-oA", "normal + XML + grepable output"],
        ["-oS", "script-oriented output"]
    ];

    for (const [flag, purpose] of formats) {
        console.log(`  ${flag.padEnd(4)} ${purpose}`);
    }

    console.log(
        "\nXML is particularly useful when a defensive inventory must be"
    );
    console.log(
        "processed repeatedly without rescanning the network."
    );
}


function explainInterpretation() {
    section("5. SCAN INTERPRETATION");

    bullet([
        "Interpret port state before interpreting service identity.",
        "Interpret service identity before assessing configuration.",
        "Record uncertainty instead of converting inference into fact.",
        "Compare results against an approved service inventory.",
        "Treat unexpected exposure as a review item rather than proof of compromise.",
        "Record timestamps, target scope, options, and scanner version."
    ]);
}


function buildSafeNmapArguments(target) {
    /*
     * The live demonstration deliberately uses:
     *   -sV : service/version detection
     *   -sC : default NSE scripts
     *   -T3 : normal timing
     *   -oX - : XML to stdout
     *
     * It does not add exploit, brute-force, or intrusive script categories.
     */
    return [
        "-sV",
        "-sC",
        "-T3",
        "-oX",
        "-",
        target
    ];
}


function executeNmap(target) {
    return new Promise((resolve, reject) => {
        const validation = validateTarget(target);

        if (!validation.allowed) {
            reject(
                new Error(`Live scan refused: ${validation.reason}`)
            );
            return;
        }

        const args = buildSafeNmapArguments(target);
        const child = spawn("nmap", args, {
            stdio: ["ignore", "pipe", "pipe"]
        });

        let stdout = "";
        let stderr = "";
        let finished = false;

        const timeout = setTimeout(() => {
            if (!finished) {
                child.kill();
                reject(
                    new Error(
                        "Nmap exceeded the 180-second demonstration timeout."
                    )
                );
            }
        }, 180_000);

        child.stdout.setEncoding("utf8");
        child.stderr.setEncoding("utf8");

        child.stdout.on("data", chunk => {
            stdout += chunk;
        });

        child.stderr.on("data", chunk => {
            stderr += chunk;
        });

        child.on("error", error => {
            finished = true;
            clearTimeout(timeout);

            if (error.code === "ENOENT") {
                reject(
                    new Error(
                        "Nmap is not installed or is not available on PATH."
                    )
                );
            } else {
                reject(error);
            }
        });

        child.on("close", code => {
            finished = true;
            clearTimeout(timeout);

            if (code !== 0) {
                reject(
                    new Error(
                        `Nmap exited with code ${code}: ${stderr.trim()}`
                    )
                );
                return;
            }

            resolve(stdout);
        });
    });
}


/*
 * Inventory comparison demonstrates a practical defensive use of structured
 * scan output: detecting service changes between two approved baselines.
 */
function inventoryMap(hosts) {
    const map = new Map();

    for (const host of hosts) {
        for (const port of host.ports) {
            if (port.state !== "open") {
                continue;
            }

            const key =
                `${host.address}|${port.port}|${port.protocol}`;

            map.set(key, port.service || "unknown");
        }
    }

    return map;
}


function compareInventories(before, after) {
    section("6. DEFENSIVE INVENTORY DIFFERENCE");

    const oldMap = inventoryMap(before);
    const newMap = inventoryMap(after);

    const added = [];
    const removed = [];
    const changed = [];

    for (const [key, service] of newMap.entries()) {
        if (!oldMap.has(key)) {
            added.push([key, service]);
        } else if (oldMap.get(key) !== service) {
            changed.push([
                key,
                oldMap.get(key),
                service
            ]);
        }
    }

    for (const [key, service] of oldMap.entries()) {
        if (!newMap.has(key)) {
            removed.push([key, service]);
        }
    }

    console.log("New open services:");
    if (added.length === 0) {
        console.log("  None");
    } else {
        for (const [key, service] of added) {
            console.log(`  + ${key}: ${service}`);
        }
    }

    console.log("Removed open services:");
    if (removed.length === 0) {
        console.log("  None");
    } else {
        for (const [key, service] of removed) {
            console.log(`  - ${key}: ${service}`);
        }
    }

    console.log("Changed service identification:");
    if (changed.length === 0) {
        console.log("  None");
    } else {
        for (const [key, oldService, newService] of changed) {
            console.log(
                `  * ${key}: ${oldService} -> ${newService}`
            );
        }
    }
}


/*
 * A small asynchronous utility demonstrates why Node.js is suitable for
 * defensive inventory pipelines: I/O can be awaited without blocking the
 * entire event loop.
 */
async function loadXmlFile(filename) {
    const absolutePath = path.resolve(filename);
    const xml = await fs.promises.readFile(
        absolutePath,
        "utf8"
    );

    return {
        path: absolutePath,
        xml
    };
}


function reportDefensiveQuestions(hosts) {
    section("7. DEFENSIVE REVIEW QUESTIONS");

    for (const host of hosts) {
        const openPorts = host.ports.filter(
            port => port.state === "open"
        );

        console.log(`\n${host.address}`);

        if (openPorts.length === 0) {
            console.log("  No open services recorded.");
            continue;
        }

        for (const port of openPorts) {
            console.log(
                `  ${port.port}/${port.protocol}: ` +
                `${port.service || "unknown"}`
            );
        }

        console.log("  Review:");
        console.log("    - Is each service required?");
        console.log("    - Is its network exposure intentional?");
        console.log("    - Is access restricted to appropriate networks?");
        console.log("    - Is software supported and patched?");
        console.log("    - Does the observed service match the approved inventory?");
    }
}


function demonstrateJavaScriptConcepts() {
    section("8. JAVASCRIPT-SPECIFIC IMPLEMENTATION");

    const services = [
        new PortObservation({
            port: 22,
            protocol: "tcp",
            state: "open",
            service: "ssh"
        }),
        new PortObservation({
            port: 443,
            protocol: "tcp",
            state: "open",
            service: "https"
        })
    ];

    /*
     * Array methods make inventory processing concise while preserving
     * readable transformations.
     */
    const openServiceNames = services
        .filter(service => service.state === "open")
        .map(service => `${service.port}/${service.protocol}`);

    console.log(
        "Open service identifiers:",
        openServiceNames.join(", ")
    );

    /*
     * Map is useful for keyed inventory because lookup is explicit and
     * does not depend on object-property naming.
     */
    const inventory = new Map(
        services.map(service => [
            `${service.port}/${service.protocol}`,
            service.service
        ])
    );

    console.log("Inventory lookup for 443/tcp:", inventory.get("443/tcp"));

    /*
     * Set removes duplicates efficiently when collecting unique service
     * families.
     */
    const uniqueServices = new Set(
        services.map(service => service.service)
    );

    console.log(
        "Unique service families:",
        [...uniqueServices].join(", ")
    );
}


function explainOperationalModel() {
    section("9. DEFENSIVE OPERATIONAL MODEL");

    const phases = [
        "Define authorized scope.",
        "Select the smallest useful port/service scope.",
        "Pilot against a representative host.",
        "Select an appropriate timing profile.",
        "Choose narrowly scoped NSE categories.",
        "Save XML output.",
        "Parse and normalize the inventory.",
        "Compare against the approved baseline.",
        "Review unexpected exposure.",
        "Retest after authorized remediation."
    ];

    phases.forEach((phase, index) => {
        console.log(`${index + 1}. ${phase}`);
    });
}


function parseArguments() {
    const args = process.argv.slice(2);

    const options = {
        host: "127.0.0.1",
        demoScan: false,
        xmlFile: null
    };

    for (let index = 0; index < args.length; index += 1) {
        const argument = args[index];

        if (argument === "--demo-scan") {
            options.demoScan = true;
        } else if (argument === "--host") {
            options.host = args[index + 1];
            index += 1;
        } else if (argument === "--xml") {
            options.xmlFile = args[index + 1];
            index += 1;
        } else if (argument === "--help") {
            console.log(
                "Usage: node advanced_nmap.js " +
                "[--demo-scan] [--host 127.0.0.1] [--xml scan.xml]"
            );
            process.exit(0);
        }
    }

    return options;
}


async function main() {
    const options = parseArguments();

    console.log("ADVANCED NMAP DEFENSIVE SCANNING");
    console.log("Node.js:", process.version);
    console.log("Platform:", os.platform());
    console.log("Timestamp:", new Date().toISOString());

    explainFundamentals();
    explainNse();
    explainTiming();
    explainOutput();
    explainInterpretation();
    demonstrateJavaScriptConcepts();
    explainOperationalModel();

    if (options.xmlFile) {
        section("10. XML FILE ANALYSIS");

        try {
            const result = await loadXmlFile(options.xmlFile);
            const hosts = parseNmapXml(result.xml);

            console.log(`Loaded: ${result.path}`);
            printObservations(hosts);
            reportDefensiveQuestions(hosts);
        } catch (error) {
            console.error(
                "Could not analyze XML:",
                error.message
            );
            process.exitCode = 1;
        }
    }

    if (options.demoScan) {
        section("11. SAFE LIVE DEMONSTRATION");

        try {
            const xml = await executeNmap(options.host);
            const hosts = parseNmapXml(xml);

            console.log(
                `Completed constrained scan of ${options.host}.`
            );

            printObservations(hosts);
            reportDefensiveQuestions(hosts);
        } catch (error) {
            console.error(
                "Live scan failed:",
                error.message
            );
            process.exitCode = 1;
        }
    }

    section("12. CHECKLIST");

    bullet([
        "Explain open, closed, and filtered.",
        "Explain why service/version detection is probabilistic.",
        "Explain why NSE categories should be selected intentionally.",
        "Explain how timing affects load and reliability.",
        "Explain why XML is useful for automation.",
        "Separate exposed services from confirmed vulnerabilities.",
        "Use inventory differences to detect configuration drift.",
        "Record scope, timestamp, options, and scanner version."
    ]);
}


main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
