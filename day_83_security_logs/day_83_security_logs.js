"use strict";

/*
 * Multi-source Security Telemetry Correlation Engine
 *
 * Node.js 18+
 *
 * Engineering focus:
 * - Event-driven telemetry ingestion
 * - Asynchronous processing
 * - Sliding-window correlation
 * - Authentication abuse detection
 * - Firewall and network anomalies
 * - DNS and proxy threat indicators
 * - Application telemetry
 * - Alert deduplication
 * - Risk-based policy evaluation
 * - Bounded event retention
 *
 * Run:
 * node security_logs.js
 */

const { EventEmitter } = require("node:events");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");


const SOURCES = new Set([
    "windows",
    "linux",
    "firewall",
    "dns",
    "proxy",
    "authentication",
    "application"
]);

const EVENT_TYPES = new Set([
    "login_success",
    "login_failure",
    "privilege_change",
    "process_execution",
    "network_connection",
    "firewall_block",
    "firewall_allow",
    "dns_query",
    "http_request",
    "application_error",
    "file_access"
]);

const SEVERITY = Object.freeze({
    INFO: 0,
    LOW: 10,
    MEDIUM: 25,
    HIGH: 45,
    CRITICAL: 70
});


class SecurityError extends Error {
    constructor(message) {
        super(message);
        this.name = "SecurityError";
    }
}


function validIP(value) {
    if (typeof value !== "string") return false;

    const ipv4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

    if (ipv4.test(value)) return true;

    // Basic IPv6 validation, including compressed representations.
    if (!value.includes(":") || value.length > 45) return false;

    const groups = value.split(":");

    if (groups.length > 8) return false;

    if ((value.match(/::/g) || []).length > 1) return false;

    return groups.every(
        group => group === "" || /^[0-9a-fA-F]{1,4}$/.test(group)
    );
}


function normalizeEvent(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        throw new SecurityError("Event must be an object.");
    }

    const required = [
        "eventId",
        "timestamp",
        "source",
        "eventType"
    ];

    for (const field of required) {
        if (raw[field] === undefined || raw[field] === null) {
            throw new SecurityError(`Missing field: ${field}`);
        }
    }

    if (!SOURCES.has(raw.source)) {
        throw new SecurityError("Unsupported telemetry source.");
    }

    if (!EVENT_TYPES.has(raw.eventType)) {
        throw new SecurityError("Unsupported event type.");
    }

    if (typeof raw.eventId !== "string" ||
        raw.eventId.length === 0 ||
        raw.eventId.length > 128) {
        throw new SecurityError("Invalid event identifier.");
    }

    const timestamp = Date.parse(raw.timestamp);

    if (!Number.isFinite(timestamp)) {
        throw new SecurityError("Invalid event timestamp.");
    }

    for (const field of ["sourceIp", "destinationIp"]) {
        if (raw[field] !== undefined &&
            raw[field] !== null &&
            !validIP(raw[field])) {
            throw new SecurityError(`Invalid ${field}.`);
        }
    }

    if (raw.destinationPort !== undefined &&
        raw.destinationPort !== null) {
        if (!Number.isInteger(raw.destinationPort) ||
            raw.destinationPort < 1 ||
            raw.destinationPort > 65535) {
            throw new SecurityError("Invalid destination port.");
        }
    }

    if (raw.attributes !== undefined &&
        (!raw.attributes ||
         typeof raw.attributes !== "object" ||
         Array.isArray(raw.attributes))) {
        throw new SecurityError("Attributes must be an object.");
    }

    const message = String(raw.message ?? "");

    if (message.length > 8192) {
        throw new SecurityError("Message exceeds allowed length.");
    }

    return Object.freeze({
        eventId: raw.eventId,
        timestamp,
        source: raw.source,
        eventType: raw.eventType,
        sourceIp: raw.sourceIp ?? null,
        destinationIp: raw.destinationIp ?? null,
        username: raw.username ?? null,
        hostname: raw.hostname ?? null,
        destinationPort: raw.destinationPort ?? null,
        protocol: raw.protocol ?? null,
        action: raw.action ?? null,
        resource: raw.resource ?? null,
        message,
        attributes: Object.freeze({
            ...(raw.attributes ?? {})
        })
    });
}


class SlidingWindow {
    constructor(durationMs, maximumEvents = 100000) {
        if (durationMs <= 0 || maximumEvents <= 0) {
            throw new RangeError("Window configuration must be positive.");
        }

        this.durationMs = durationMs;
        this.maximumEvents = maximumEvents;
        this.events = [];
    }

    add(event) {
        this.events.push(event);

        if (this.events.length > this.maximumEvents) {
            this.events.shift();
        }

        this.prune(event.timestamp);
    }

    prune(referenceTime) {
        const threshold = referenceTime - this.durationMs;

        this.events = this.events.filter(
            event => event.timestamp >= threshold
        );
    }

    query(predicate) {
        return this.events.filter(predicate);
    }

    get size() {
        return this.events.length;
    }
}


class AlertDeduplicator {
    constructor(cooldownMs = 300000) {
        this.cooldownMs = cooldownMs;
        this.lastSeen = new Map();
    }

    shouldEmit(ruleId, entity, timestamp) {
        const key = `${ruleId}:${entity}`;
        const previous = this.lastSeen.get(key);

        if (previous !== undefined &&
            timestamp - previous < this.cooldownMs) {
            return false;
        }

        this.lastSeen.set(key, timestamp);

        return true;
    }

    cleanup(referenceTime) {
        for (const [key, timestamp] of this.lastSeen) {
            if (referenceTime - timestamp > this.cooldownMs * 2) {
                this.lastSeen.delete(key);
            }
        }
    }
}


class SecurityPolicy {
    constructor({
        failedLoginThreshold = 5,
        portScanThreshold = 10,
        windowMs = 300000,
        dnsLabelThreshold = 50,
        minimumRisk = 20
    } = {}) {
        if (
            failedLoginThreshold < 1 ||
            portScanThreshold < 1 ||
            windowMs <= 0 ||
            dnsLabelThreshold < 1
        ) {
            throw new RangeError("Invalid security policy.");
        }

        this.failedLoginThreshold = failedLoginThreshold;
        this.portScanThreshold = portScanThreshold;
        this.windowMs = windowMs;
        this.dnsLabelThreshold = dnsLabelThreshold;
        this.minimumRisk = minimumRisk;
    }

    evaluateBruteForce(events) {
        const groups = new Map();

        for (const event of events) {
            if (event.eventType !== "login_failure" ||
                !event.sourceIp) continue;

            const key = `${event.sourceIp}:${event.username ?? "unknown"}`;

            if (!groups.has(key)) groups.set(key, []);

            groups.get(key).push(event);
        }

        const findings = [];

        for (const [key, group] of groups) {
            group.sort((a, b) => a.timestamp - b.timestamp);

            let start = 0;

            for (let end = 0; end < group.length; end++) {
                while (
                    group[end].timestamp - group[start].timestamp >
                    this.windowMs
                ) {
                    start++;
                }

                const count = end - start + 1;

                if (count >= this.failedLoginThreshold) {
                    findings.push({
                        ruleId: "AUTH-001",
                        title: "Repeated authentication failures",
                        severity: "HIGH",
                        confidence: 0.95,
                        entity: key,
                        eventIds: group.slice(start, end + 1)
                            .map(e => e.eventId),
                        evidence: {
                            attempts: count,
                            windowMs: this.windowMs
                        }
                    });

                    break;
                }
            }
        }

        return findings;
    }

    evaluatePortScan(events) {
        const groups = new Map();

        for (const event of events) {
            if (event.eventType !== "network_connection" ||
                !event.sourceIp ||
                !event.destinationPort) continue;

            if (!groups.has(event.sourceIp)) {
                groups.set(event.sourceIp, []);
            }

            groups.get(event.sourceIp).push(event);
        }

        const findings = [];

        for (const [ip, group] of groups) {
            group.sort((a, b) => a.timestamp - b.timestamp);

            let start = 0;

            for (let end = 0; end < group.length; end++) {
                while (
                    group[end].timestamp - group[start].timestamp >
                    this.windowMs
                ) {
                    start++;
                }

                const windowEvents = group.slice(start, end + 1);

                const ports = new Set(
                    windowEvents.map(e => e.destinationPort)
                );

                if (ports.size >= this.portScanThreshold) {
                    findings.push({
                        ruleId: "NET-001",
                        title: "Potential port scanning",
                        severity: "HIGH",
                        confidence: 0.90,
                        entity: ip,
                        eventIds: windowEvents.map(e => e.eventId),
                        evidence: {
                            uniquePorts: ports.size,
                            ports: [...ports].sort((a, b) => a - b)
                        }
                    });

                    break;
                }
            }
        }

        return findings;
    }

    evaluateDns(events) {
        const findings = [];

        for (const event of events) {
            if (event.eventType !== "dns_query") continue;

            const domain = String(
                event.attributes.query ?? ""
            ).toLowerCase().replace(/\.$/, "");

            if (!domain) continue;

            const labels = domain.split(".");

            const longest = Math.max(
                ...labels.map(label => label.length)
            );

            const first = labels[0];

            const unique = new Set(first).size;

            const entropy = first.length === 0 ? 0 :
                [...new Set(first)].reduce((sum, character) => {
                    const count = [...first].filter(
                        c => c === character
                    ).length;

                    const probability = count / first.length;

                    return sum - probability *
                        Math.log2(probability);
                }, 0);

            if (
                longest >= this.dnsLabelThreshold ||
                (first.length >= 25 && unique >= 10 && entropy >= 3.5)
            ) {
                findings.push({
                    ruleId: "DNS-001",
                    title: "Suspicious DNS query",
                    severity: "MEDIUM",
                    confidence: 0.85,
                    entity: event.sourceIp ?? "unknown",
                    eventIds: [event.eventId],
                    evidence: {
                        domain,
                        longestLabel: longest,
                        entropy: Number(entropy.toFixed(3))
                    }
                });
            }
        }

        return findings;
    }

    evaluateProxy(events) {
        const extensions = new Set([
            ".exe", ".dll", ".ps1", ".bat", ".scr", ".vbs"
        ]);

        return events
            .filter(event => event.eventType === "http_request")
            .filter(event => {
                try {
                    const pathname = new URL(event.resource).pathname;
                    return [...extensions].some(
                        extension => pathname.toLowerCase().endsWith(extension)
                    );
                } catch {
                    return false;
                }
            })
            .map(event => ({
                ruleId: "PROXY-001",
                title: "Executable download detected",
                severity: "MEDIUM",
                confidence: 0.80,
                entity: event.sourceIp ?? "unknown",
                eventIds: [event.eventId],
                evidence: {
                    resource: event.resource
                }
            }));
    }

    evaluatePrivilegeChanges(events) {
        return events
            .filter(event => event.eventType === "privilege_change")
            .map(event => ({
                ruleId: "AUTH-002",
                title: "Privilege escalation event",
                severity: "MEDIUM",
                confidence: 0.85,
                entity: event.username ?? "unknown",
                eventIds: [event.eventId],
                evidence: {
                    hostname: event.hostname,
                    attributes: event.attributes
                }
            }));
    }

    calculateRisk(finding) {
        return Math.min(
            100,
            Math.round(
                SEVERITY[finding.severity] *
                finding.confidence
            )
        );
    }

    evaluate(events) {
        const findings = [
            ...this.evaluateBruteForce(events),
            ...this.evaluatePortScan(events),
            ...this.evaluateDns(events),
            ...this.evaluateProxy(events),
            ...this.evaluatePrivilegeChanges(events)
        ];

        return findings
            .map(finding => ({
                ...finding,
                riskScore: this.calculateRisk(finding)
            }))
            .filter(
                finding => finding.riskScore >= this.minimumRisk
            )
            .sort((a, b) => b.riskScore - a.riskScore);
    }
}


class SecurityTelemetryService extends EventEmitter {
    constructor(policy = new SecurityPolicy()) {
        super();

        this.policy = policy;
        this.window = new SlidingWindow(
            policy.windowMs,
            100000
        );

        this.deduplicator = new AlertDeduplicator();
        this.seenIds = new Set();
        this.eventCount = 0;
        this.rejectedCount = 0;
    }

    async ingest(raw) {
        let event;

        try {
            event = normalizeEvent(raw);

            if (this.seenIds.has(event.eventId)) {
                throw new SecurityError("Duplicate event.");
            }

            this.seenIds.add(event.eventId);
            this.window.add(event);
            this.eventCount++;

            this.emit("event", event);

            const findings = this.policy.evaluate(
                this.window.events
            );

            const emitted = [];

            for (const finding of findings) {
                const timestamp = Math.max(
                    ...this.window.events
                        .filter(e => finding.eventIds.includes(e.eventId))
                        .map(e => e.timestamp)
                );

                if (this.deduplicator.shouldEmit(
                    finding.ruleId,
                    finding.entity,
                    timestamp
                )) {
                    emitted.push(finding);
                    this.emit("alert", finding);
                }
            }

            this.deduplicator.cleanup(event.timestamp);

            return emitted;

        } catch (error) {
            this.rejectedCount++;

            this.emit("rejected", {
                message: error.message
            });

            throw error;
        }
    }

    async ingestBatch(records) {
        const results = [];

        for (const record of records) {
            try {
                const alerts = await this.ingest(record);

                results.push({
                    accepted: true,
                    eventId: record.eventId,
                    alerts
                });
            } catch (error) {
                results.push({
                    accepted: false,
                    eventId: record?.eventId ?? null,
                    error: error.message
                });
            }
        }

        return results;
    }

    statistics() {
        return {
            processed: this.eventCount,
            rejected: this.rejectedCount,
            retainedEvents: this.window.size,
            uniqueEventIds: this.seenIds.size
        };
    }
}


function createSampleEvents() {
    const now = Date.now();

    const events = [];

    for (let i = 0; i < 7; i++) {
        events.push({
            eventId: `auth-${i}`,
            timestamp: new Date(now - 60000 + i * 5000).toISOString(),
            source: "authentication",
            eventType: "login_failure",
            sourceIp: "203.0.113.50",
            username: "administrator"
        });
    }

    for (let i = 0; i < 12; i++) {
        events.push({
            eventId: `network-${i}`,
            timestamp: new Date(now - 40000 + i * 1000).toISOString(),
            source: "firewall",
            eventType: "network_connection",
            sourceIp: "198.51.100.20",
            destinationIp: "10.0.0.10",
            destinationPort: 1000 + i,
            protocol: "TCP"
        });
    }

    events.push({
        eventId: "dns-001",
        timestamp: new Date(now).toISOString(),
        source: "dns",
        eventType: "dns_query",
        sourceIp: "10.0.0.15",
        attributes: {
            query: "a".repeat(65) + ".example.com"
        }
    });

    events.push({
        eventId: "proxy-001",
        timestamp: new Date(now).toISOString(),
        source: "proxy",
        eventType: "http_request",
        sourceIp: "10.0.0.15",
        resource: "https://example.com/payload.exe"
    });

    events.push({
        eventId: "priv-001",
        timestamp: new Date(now).toISOString(),
        source: "windows",
        eventType: "privilege_change",
        username: "administrator",
        hostname: "server-01"
    });

    return events;
}


async function runTests() {
    const policy = new SecurityPolicy({
        failedLoginThreshold: 3,
        portScanThreshold: 5
    });

    const events = createSampleEvents().map(normalizeEvent);

    const findings = policy.evaluate(events);

    console.assert(
        findings.some(f => f.ruleId === "AUTH-001"),
        "Brute-force detection failed."
    );

    console.assert(
        findings.some(f => f.ruleId === "NET-001"),
        "Port-scan detection failed."
    );

    console.assert(
        findings.some(f => f.ruleId === "DNS-001"),
        "DNS anomaly detection failed."
    );

    console.assert(
        findings.some(f => f.ruleId === "PROXY-001"),
        "Proxy detection failed."
    );

    console.assert(
        validIP("127.0.0.1"),
        "IPv4 validation failed."
    );

    console.assert(
        !validIP("999.999.999.999"),
        "Invalid IPv4 address accepted."
    );

    console.log("All tests passed.");
}


async function main() {
    const service = new SecurityTelemetryService();

    service.on("alert", finding => {
        console.log(
            `[ALERT] ${finding.severity} ` +
            `${finding.ruleId}: ${finding.title}`
        );
    });

    service.on("rejected", event => {
        console.error("[REJECTED]", event.message);
    });

    const args = process.argv.slice(2);

    if (args.includes("--test")) {
        await runTests();
        return;
    }

    let records = createSampleEvents();

    const inputIndex = args.indexOf("--input");

    if (inputIndex !== -1) {
        const filename = args[inputIndex + 1];

        if (!filename) {
            throw new SecurityError("Input filename is required.");
        }

        const content = await fs.readFile(filename, "utf8");

        records = content
            .split(/\r?\n/)
            .filter(line => line.trim())
            .map(line => JSON.parse(line));
    }

    const results = await service.ingestBatch(records);

    const report = {
        generatedAt: new Date().toISOString(),
        statistics: service.statistics(),
        accepted: results.filter(r => r.accepted).length,
        rejected: results.filter(r => !r.accepted).length,
        findings: service.policy.evaluate(service.window.events)
    };

    await fs.writeFile(
        "security_report.json",
        JSON.stringify(report, null, 2),
        {
            encoding: "utf8",
            mode: 0o600
        }
    );

    console.log(JSON.stringify({
        statistics: report.statistics,
        findings: report.findings.length,
        report: "security_report.json"
    }, null, 2));
}


main().catch(error => {
    console.error("Processing failed:", error.message);
    process.exitCode = 1;
});
