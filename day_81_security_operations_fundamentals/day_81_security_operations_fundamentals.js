"use strict";

/*
 * SECURITY OPERATIONS FUNDAMENTALS
 * Event-driven SOC monitoring and incident orchestration.
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const path = require("node:path");
const EventEmitter = require("node:events");

// ---------------------------------------------------------
// 1. Domain constants
// ---------------------------------------------------------

const Severity = Object.freeze({
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
});

const Status = Object.freeze({
    NEW: "NEW",
    TRIAGED: "TRIAGED",
    INVESTIGATING: "INVESTIGATING",
    ESCALATED: "ESCALATED",
    CONTAINED: "CONTAINED",
    RESOLVED: "RESOLVED",
    CLOSED: "CLOSED",
    FALSE_POSITIVE: "FALSE_POSITIVE"
});

const Tier = Object.freeze({
    TIER_1: 1,
    TIER_2: 2,
    TIER_3: 3
});

const IncidentType = Object.freeze({
    BRUTE_FORCE: "brute_force",
    MALWARE: "malware",
    PHISHING: "phishing",
    DATA_EXFILTRATION: "data_exfiltration",
    UNAUTHORIZED_ACCESS: "unauthorized_access"
});

const TRANSITIONS = Object.freeze({
    NEW: [Status.TRIAGED, Status.ESCALATED, Status.FALSE_POSITIVE],
    TRIAGED: [
        Status.INVESTIGATING,
        Status.ESCALATED,
        Status.FALSE_POSITIVE
    ],
    INVESTIGATING: [
        Status.ESCALATED,
        Status.CONTAINED,
        Status.FALSE_POSITIVE
    ],
    ESCALATED: [
        Status.INVESTIGATING,
        Status.CONTAINED
    ],
    CONTAINED: [Status.RESOLVED],
    RESOLVED: [Status.CLOSED],
    FALSE_POSITIVE: [Status.CLOSED],
    CLOSED: []
});


// ---------------------------------------------------------
// 2. Input validation
// ---------------------------------------------------------

function validateEvent(event) {
    if (!event || typeof event !== "object") {
        throw new TypeError("Security event must be an object");
    }

    const required = [
        "source",
        "eventType",
        "sourceIp",
        "destination",
        "timestamp"
    ];

    for (const key of required) {
        if (
            typeof event[key] !== "string" ||
            event[key].trim() === ""
        ) {
            throw new TypeError(`Invalid event field: ${key}`);
        }
    }

    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

    if (!ipv4.test(event.sourceIp)) {
        throw new TypeError("Invalid IPv4 address");
    }

    const octets = event.sourceIp.split(".").map(Number);

    if (octets.some(value => value < 0 || value > 255)) {
        throw new TypeError("IPv4 octet outside valid range");
    }

    if (!Number.isInteger(event.failedAttempts ?? 0) ||
        (event.failedAttempts ?? 0) < 0) {
        throw new TypeError("Invalid failed attempt count");
    }

    const timestamp = Date.parse(event.timestamp);

    if (!Number.isFinite(timestamp)) {
        throw new TypeError("Invalid event timestamp");
    }

    return {
        ...event,
        failedAttempts: event.failedAttempts ?? 0,
        timestamp: new Date(timestamp).toISOString()
    };
}


// ---------------------------------------------------------
// 3. Detection rules
// ---------------------------------------------------------

class DetectionEngine {

    analyze(rawEvent) {
        const event = validateEvent(rawEvent);

        let type = null;
        let severity = Severity.LOW;
        let confidence = 0;

        if (event.failedAttempts >= 25) {
            type = IncidentType.BRUTE_FORCE;
            severity = Severity.CRITICAL;
            confidence = 0.98;
        } else if (event.failedAttempts >= 10) {
            type = IncidentType.BRUTE_FORCE;
            severity = Severity.HIGH;
            confidence = 0.90;
        } else if (event.eventType === "malware_detected") {
            type = IncidentType.MALWARE;
            severity = Severity.HIGH;
            confidence = 0.95;
        } else if (event.eventType === "phishing_report") {
            type = IncidentType.PHISHING;
            severity = Severity.MEDIUM;
            confidence = 0.85;
        } else if (event.eventType === "unauthorized_access") {
            type = IncidentType.UNAUTHORIZED_ACCESS;
            severity = Severity.HIGH;
            confidence = 0.90;
        } else if (
            event.eventType === "outbound_transfer" &&
            event.transferMb >= 500
        ) {
            type = IncidentType.DATA_EXFILTRATION;
            severity = Severity.CRITICAL;
            confidence = 0.95;
        }

        if (!type) return null;

        return {
            id: crypto.randomUUID(),
            event,
            type,
            severity,
            confidence,
            status: Status.NEW,
            tier: Tier.TIER_1,
            analystId: null,
            evidence: [`Detection rule: ${type}`],
            history: [{
                timestamp: new Date().toISOString(),
                action: "DETECTED"
            }]
        };
    }
}


// ---------------------------------------------------------
// 4. Analyst directory and assignment
// ---------------------------------------------------------

class AnalystDirectory {

    #analysts = new Map();
    #assignments = new Map();

    register(analyst) {
        if (!analyst.id || !analyst.name) {
            throw new TypeError("Analyst identity is required");
        }

        if (this.#analysts.has(analyst.id)) {
            throw new Error("Duplicate analyst identity");
        }

        if (![1, 2, 3].includes(analyst.tier)) {
            throw new Error("Invalid SOC tier");
        }

        this.#analysts.set(analyst.id, {
            ...analyst,
            skills: new Set(analyst.skills),
            active: analyst.active !== false
        });
    }

    assign(alert, preferredTier) {
        const candidates = [...this.#analysts.values()]
            .filter(analyst =>
                analyst.active &&
                analyst.tier >= preferredTier &&
                analyst.skills.has(alert.type)
            )
            .sort((a, b) =>
                a.tier - b.tier ||
                a.id.localeCompare(b.id)
            );

        const analyst = candidates.find(
            candidate => (this.#assignments.get(candidate.id) ?? 0) < 5
        );

        if (!analyst) {
            return null;
        }

        this.#assignments.set(
            analyst.id,
            (this.#assignments.get(analyst.id) ?? 0) + 1
        );

        return analyst;
    }

    release(analystId) {
        const current = this.#assignments.get(analystId) ?? 0;

        if (current > 0) {
            this.#assignments.set(analystId, current - 1);
        }
    }
}


// ---------------------------------------------------------
// 5. Incident state management
// ---------------------------------------------------------

class IncidentService {

    constructor(directory) {
        this.directory = directory;
        this.alerts = new Map();
    }

    add(alert) {
        if (this.alerts.has(alert.id)) {
            throw new Error("Duplicate alert");
        }

        this.alerts.set(alert.id, alert);
    }

    assign(alert) {
        const preferredTier =
            alert.severity >= Severity.CRITICAL ? Tier.TIER_3 :
            alert.severity >= Severity.HIGH ? Tier.TIER_2 :
            Tier.TIER_1;

        const analyst = this.directory.assign(
            alert,
            preferredTier
        );

        if (!analyst) {
            this.transition(
                alert,
                Status.ESCALATED,
                "SYSTEM",
                "No qualified analyst available"
            );
            return false;
        }

        alert.analystId = analyst.id;
        alert.tier = analyst.tier;

        this.transition(
            alert,
            Status.TRIAGED,
            "SYSTEM",
            `Assigned to ${analyst.name}`
        );

        return true;
    }

    transition(alert, nextStatus, actor, reason) {
        if (!TRANSITIONS[alert.status]?.includes(nextStatus)) {
            throw new Error(
                `Invalid transition ${alert.status} -> ${nextStatus}`
            );
        }

        if (!actor?.trim() || !reason?.trim()) {
            throw new Error("Actor and reason are required");
        }

        if (
            nextStatus === Status.CONTAINED &&
            alert.evidence.length === 0
        ) {
            throw new Error("Containment requires evidence");
        }

        const previousStatus = alert.status;
        alert.status = nextStatus;

        alert.history.push({
            timestamp: new Date().toISOString(),
            actor,
            action: nextStatus,
            previousStatus,
            reason
        });

        if (
            nextStatus === Status.CLOSED ||
            nextStatus === Status.FALSE_POSITIVE
        ) {
            if (alert.analystId) {
                this.directory.release(alert.analystId);
            }
        }
    }

    getMetrics() {
        const severity = new Map();
        const statuses = new Map();
        const tiers = new Map();

        for (const alert of this.alerts.values()) {
            severity.set(
                alert.severity,
                (severity.get(alert.severity) ?? 0) + 1
            );

            statuses.set(
                alert.status,
                (statuses.get(alert.status) ?? 0) + 1
            );

            tiers.set(
                alert.tier,
                (tiers.get(alert.tier) ?? 0) + 1
            );
        }

        return {
            total: this.alerts.size,
            severity: Object.fromEntries(severity),
            statuses: Object.fromEntries(statuses),
            tiers: Object.fromEntries(tiers)
        };
    }
}


// ---------------------------------------------------------
// 6. Event-driven SOC monitoring
// ---------------------------------------------------------

class SOCMonitoringSystem extends EventEmitter {

    constructor(incidentService, detectionEngine) {
        super();
        this.incidents = incidentService;
        this.detector = detectionEngine;
        this.processing = false;
        this.queue = [];
        this.maxQueueSize = 10000;
        this.on("alert", alert => {
            console.log(
                `[ALERT] ${alert.id.slice(0, 8)} | ` +
                `${alert.type} | Severity ${alert.severity}`
            );
        });
    }

    submit(event) {
        if (this.queue.length >= this.maxQueueSize) {
            throw new Error("Monitoring queue capacity exceeded");
        }

        this.queue.push(event);
    }

    async processQueue() {
        if (this.processing) return;

        this.processing = true;

        try {
            while (this.queue.length > 0) {
                const event = this.queue.shift();

                try {
                    const alert = this.detector.analyze(event);

                    if (!alert) continue;

                    this.incidents.add(alert);
                    this.incidents.assign(alert);
                    this.emit("alert", alert);

                } catch (error) {
                    console.error(
                        "Event processing failure:",
                        error.message
                    );
                }

                // Yield to the event loop during larger workloads.
                if (this.queue.length % 100 === 0) {
                    await new Promise(resolve => setImmediate(resolve));
                }
            }
        } finally {
            this.processing = false;
        }
    }
}


// ---------------------------------------------------------
// 7. Operational reporting
// ---------------------------------------------------------

function calculateMetrics(incidents) {
    const alerts = [...incidents.alerts.values()];

    const resolved = alerts.filter(
        alert => [
            Status.RESOLVED,
            Status.CLOSED
        ].includes(alert.status)
    ).length;

    const falsePositives = alerts.filter(
        alert => alert.status === Status.FALSE_POSITIVE
    ).length;

    const active = alerts.filter(
        alert => ![
            Status.CLOSED,
            Status.FALSE_POSITIVE
        ].includes(alert.status)
    ).length;

    return {
        ...incidents.getMetrics(),
        activeIncidents: active,
        resolvedIncidents: resolved,
        falsePositives,
        falsePositiveRate: alerts.length
            ? Number((falsePositives / alerts.length).toFixed(4))
            : 0
    };
}


// ---------------------------------------------------------
// 8. Secure report persistence
// ---------------------------------------------------------

async function saveReport(report, filename) {
    const destination = path.resolve(filename);

    if (path.extname(destination) !== ".json") {
        throw new Error("Only JSON report files are permitted");
    }

    const temporary = `${destination}.${crypto.randomUUID()}.tmp`;

    try {
        await fs.writeFile(
            temporary,
            JSON.stringify(report, null, 2),
            { flag: "wx", mode: 0o600 }
        );

        await fs.rename(temporary, destination);
    } catch (error) {
        await fs.rm(temporary, { force: true });
        throw error;
    }
}


// ---------------------------------------------------------
// 9. Test suite
// ---------------------------------------------------------

async function runTests() {
    const assert = require("node:assert/strict");

    const detector = new DetectionEngine();

    const event = {
        source: "VPN",
        eventType: "authentication_failure",
        sourceIp: "203.0.113.45",
        destination: "VPN Gateway",
        timestamp: new Date().toISOString(),
        failedAttempts: 30
    };

    const alert = detector.analyze(event);

    assert.equal(alert.severity, Severity.CRITICAL);
    assert.equal(alert.type, IncidentType.BRUTE_FORCE);

    assert.throws(
        () => detector.analyze({
            ...event,
            sourceIp: "999.999.999.999"
        })
    );

    assert.equal(detector.analyze({
        ...event,
        failedAttempts: 0
    }), null);

    const directory = new AnalystDirectory();

    directory.register({
        id: "A003",
        name: "Senior Responder",
        tier: 3,
        skills: ["brute_force"]
    });

    const service = new IncidentService(directory);
    service.add(alert);

    assert.equal(service.assign(alert), true);
    assert.equal(alert.status, Status.TRIAGED);

    service.transition(
        alert,
        Status.INVESTIGATING,
        "A003",
        "Investigation started"
    );

    service.transition(
        alert,
        Status.CONTAINED,
        "A003",
        "Malicious source blocked"
    );

    service.transition(
        alert,
        Status.RESOLVED,
        "A003",
        "Authentication controls restored"
    );

    service.transition(
        alert,
        Status.CLOSED,
        "A003",
        "Evidence archived"
    );

    assert.equal(alert.status, Status.CLOSED);

    assert.throws(() => {
        service.transition(
            alert,
            Status.INVESTIGATING,
            "A003",
            "Invalid reopening"
        );
    });

    console.log("All SOC validation tests passed.");
}


// ---------------------------------------------------------
// 10. Application entry point
// ---------------------------------------------------------

async function main() {
    const directory = new AnalystDirectory();

    directory.register({
        id: "A001",
        name: "SOC L1 Analyst",
        tier: 1,
        skills: ["phishing", "brute_force"]
    });

    directory.register({
        id: "A002",
        name: "SOC L2 Responder",
        tier: 2,
        skills: ["malware", "unauthorized_access"]
    });

    directory.register({
        id: "A003",
        name: "SOC L3 Threat Hunter",
        tier: 3,
        skills: ["brute_force", "data_exfiltration"]
    });

    const incidents = new IncidentService(directory);

    const monitoring = new SOCMonitoringSystem(
        incidents,
        new DetectionEngine()
    );

    const events = [
        {
            source: "Firewall",
            eventType: "authentication_failure",
            sourceIp: "203.0.113.45",
            destination: "VPN Gateway",
            timestamp: new Date().toISOString(),
            failedAttempts: 30
        },
        {
            source: "Endpoint EDR",
            eventType: "malware_detected",
            sourceIp: "198.51.100.25",
            destination: "Workstation-17",
            timestamp: new Date().toISOString()
        },
        {
            source: "Email Gateway",
            eventType: "phishing_report",
            sourceIp: "192.0.2.50",
            destination: "Mail Server",
            timestamp: new Date().toISOString()
        },
        {
            source: "Firewall",
            eventType: "normal_traffic",
            sourceIp: "192.0.2.80",
            destination: "Internal Server",
            timestamp: new Date().toISOString()
        }
    ];

    for (const event of events) {
        monitoring.submit(event);
    }

    await monitoring.processQueue();

    const report = calculateMetrics(incidents);

    console.log("\nSOC REPORT");
    console.log(JSON.stringify(report, null, 2));

    await saveReport(report, "soc_report.json");

    await runTests();
}

if (require.main === module) {
    main().catch(error => {
        console.error("SOC execution failed:", error);
        process.exitCode = 1;
    });
}

module.exports = {
    Severity,
    Status,
    Tier,
    DetectionEngine,
    AnalystDirectory,
    IncidentService,
    SOCMonitoringSystem,
    calculateMetrics
};
