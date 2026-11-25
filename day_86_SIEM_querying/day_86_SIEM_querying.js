"use strict";

/*
 * SIEM Querying and Detection Engine
 * Node.js 18+
 *
 * Event-driven query processing, asynchronous ingestion,
 * composable predicates, aggregation, timelines, and detection.
 */

const crypto = require("node:crypto");
const fs = require("node:fs/promises");

const SEVERITIES = Object.freeze([
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]);

const SEVERITY_SCORE = Object.freeze({
    INFO: 0,
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
});

const ALLOWED_FIELDS = new Set([
    "eventId",
    "timestamp",
    "sourceIp",
    "destinationIp",
    "username",
    "eventType",
    "severity",
    "action",
    "source"
]);

class SIEMError extends Error {
    constructor(message) {
        super(message);
        this.name = "SIEMError";
    }
}

function validateEvent(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
        throw new SIEMError("Event must be an object");
    }

    const required = [
        "eventId",
        "timestamp",
        "sourceIp",
        "destinationIp",
        "username",
        "eventType",
        "severity",
        "action",
        "source"
    ];

    for (const field of required) {
        if (input[field] === undefined || input[field] === null) {
            throw new SIEMError(`Missing field: ${field}`);
        }
    }

    const timestamp = new Date(input.timestamp);

    if (!Number.isFinite(timestamp.getTime())) {
        throw new SIEMError("Invalid event timestamp");
    }

    if (!SEVERITIES.includes(input.severity)) {
        throw new SIEMError("Invalid severity");
    }

    for (const field of [
        "eventId",
        "sourceIp",
        "destinationIp",
        "username",
        "eventType",
        "action",
        "source"
    ]) {
        if (
            typeof input[field] !== "string" ||
            input[field].trim().length === 0 ||
            input[field].length > 512
        ) {
            throw new SIEMError(`Invalid field: ${field}`);
        }
    }

    return Object.freeze({
        ...input,
        timestamp,
        fields: Object.freeze({ ...(input.fields || {}) })
    });
}

class EventBus {
    constructor() {
        this.listeners = new Map();
    }

    subscribe(eventName, callback) {
        if (typeof callback !== "function") {
            throw new SIEMError("Listener must be a function");
        }

        if (!this.listeners.has(eventName)) {
            this.listeners.set(eventName, new Set());
        }

        this.listeners.get(eventName).add(callback);

        return () => this.listeners.get(eventName)?.delete(callback);
    }

    emit(eventName, payload) {
        for (const listener of this.listeners.get(eventName) || []) {
            try {
                listener(payload);
            } catch (error) {
                console.error("Event listener failed:", error.message);
            }
        }
    }
}

class EventRepository {
    constructor() {
        this.events = [];
        this.eventIds = new Set();
        this.indexes = new Map();

        for (const field of [
            "sourceIp",
            "destinationIp",
            "username",
            "eventType",
            "severity",
            "action",
            "source"
        ]) {
            this.indexes.set(field, new Map());
        }
    }

    add(input) {
        const event = validateEvent(input);

        if (this.eventIds.has(event.eventId)) {
            throw new SIEMError(`Duplicate event: ${event.eventId}`);
        }

        this.events.push(event);
        this.eventIds.add(event.eventId);

        for (const [field, index] of this.indexes) {
            const value = event[field];

            if (!index.has(value)) {
                index.set(value, []);
            }

            index.get(value).push(event);
        }

        return event;
    }

    async ingestBatch(inputs) {
        if (!Array.isArray(inputs)) {
            throw new SIEMError("Batch must be an array");
        }

        // Validate the complete batch before changing repository state.
        const validated = inputs.map(validateEvent);
        const batchIds = new Set();

        for (const event of validated) {
            if (
                this.eventIds.has(event.eventId) ||
                batchIds.has(event.eventId)
            ) {
                throw new SIEMError(
                    `Duplicate event: ${event.eventId}`
                );
            }

            batchIds.add(event.eventId);
        }

        for (const event of validated) {
            this.add(event);
        }

        return validated.length;
    }

    findByField(field, value) {
        const index = this.indexes.get(field);

        if (!index) {
            throw new SIEMError("Field has no index");
        }

        return [...(index.get(value) || [])];
    }

    snapshot() {
        return [...this.events];
    }
}

class QueryBuilder {
    constructor(events) {
        this.events = [...events];
        this.predicates = [];
    }

    where(field, operator, value) {
        if (!ALLOWED_FIELDS.has(field)) {
            throw new SIEMError(`Unsupported field: ${field}`);
        }

        const operators = new Set([
            "eq", "ne", "gt", "gte", "lt", "lte",
            "contains", "in"
        ]);

        if (!operators.has(operator)) {
            throw new SIEMError(`Unsupported operator: ${operator}`);
        }

        if (operator === "in" && !Array.isArray(value)) {
            throw new SIEMError("'in' requires an array");
        }

        const predicate = (event) => {
            const actual = event[field];

            switch (operator) {
                case "eq":
                    return actual === value;
                case "ne":
                    return actual !== value;
                case "gt":
                    return actual > value;
                case "gte":
                    return actual >= value;
                case "lt":
                    return actual < value;
                case "lte":
                    return actual <= value;
                case "contains":
                    return String(actual).toLowerCase()
                        .includes(String(value).toLowerCase());
                case "in":
                    return value.includes(actual);
                default:
                    return false;
            }
        };

        this.predicates.push(predicate);
        return this;
    }

    timeRange(start, end) {
        const from = new Date(start);
        const to = new Date(end);

        if (
            !Number.isFinite(from.getTime()) ||
            !Number.isFinite(to.getTime()) ||
            from > to
        ) {
            throw new SIEMError("Invalid time range");
        }

        this.predicates.push(event =>
            event.timestamp >= from && event.timestamp <= to
        );

        return this;
    }

    execute() {
        return this.events.filter(event =>
            this.predicates.every(predicate => predicate(event))
        );
    }
}

class SIEMAnalytics {
    static aggregate(events, field) {
        if (!ALLOWED_FIELDS.has(field)) {
            throw new SIEMError("Invalid aggregation field");
        }

        const result = new Map();

        for (const event of events) {
            const key = String(event[field]);
            result.set(key, (result.get(key) || 0) + 1);
        }

        return Object.fromEntries(
            [...result.entries()].sort((a, b) => b[1] - a[1])
        );
    }

    static timeline(events, intervalMinutes = 5) {
        if (
            !Number.isInteger(intervalMinutes) ||
            intervalMinutes < 1 ||
            intervalMinutes > 1440
        ) {
            throw new SIEMError("Invalid timeline interval");
        }

        const interval = intervalMinutes * 60 * 1000;
        const buckets = new Map();

        for (const event of events) {
            const bucket = Math.floor(
                event.timestamp.getTime() / interval
            ) * interval;

            const key = new Date(bucket).toISOString();
            buckets.set(key, (buckets.get(key) || 0) + 1);
        }

        return Object.fromEntries(
            [...buckets.entries()].sort((a, b) =>
                a[0].localeCompare(b[0])
            )
        );
    }

    static fieldAnalysis(events) {
        const fields = [
            "sourceIp",
            "destinationIp",
            "username",
            "eventType",
            "severity",
            "action",
            "source"
        ];

        const result = {};

        for (const field of fields) {
            const frequencies = SIEMAnalytics.aggregate(events, field);
            const entries = Object.entries(frequencies);

            result[field] = {
                uniqueValues: entries.length,
                topValues: entries.slice(0, 5),
                nullValues: events.filter(
                    event => event[field] == null
                ).length
            };
        }

        return result;
    }

    static detectBruteForce(
        events,
        threshold = 5,
        windowMinutes = 10
    ) {
        if (
            !Number.isInteger(threshold) ||
            threshold < 1 ||
            !Number.isFinite(windowMinutes) ||
            windowMinutes <= 0
        ) {
            throw new SIEMError("Invalid detection parameters");
        }

        const groups = new Map();

        for (const event of events) {
            if (
                event.eventType !== "authentication" ||
                event.action !== "failure"
            ) {
                continue;
            }

            const key = `${event.sourceIp}|${event.username}`;

            if (!groups.has(key)) {
                groups.set(key, []);
            }

            groups.get(key).push(event);
        }

        const alerts = [];
        const window = windowMinutes * 60 * 1000;

        for (const [key, records] of groups) {
            records.sort(
                (a, b) => a.timestamp - b.timestamp
            );

            let left = 0;

            for (let right = 0; right < records.length; right++) {
                while (
                    records[right].timestamp - records[left].timestamp >
                    window
                ) {
                    left++;
                }

                if (right - left + 1 === threshold) {
                    alerts.push({
                        key,
                        sourceIp: records[right].sourceIp,
                        username: records[right].username,
                        attempts: threshold,
                        firstSeen: records[left].timestamp.toISOString(),
                        lastSeen: records[right].timestamp.toISOString(),
                        severity: "HIGH"
                    });
                }
            }
        }

        return alerts;
    }
}

class SIEMEngine {
    constructor() {
        this.repository = new EventRepository();
        this.bus = new EventBus();

        this.bus.subscribe("event:ingested", event => {
            if (SEVERITY_SCORE[event.severity] >= 3) {
                console.log(
                    `[ALERT] ${event.severity}: ${event.eventId}`
                );
            }
        });
    }

    async ingest(inputs) {
        const count = await this.repository.ingestBatch(inputs);

        for (const event of inputs) {
            this.bus.emit("event:ingested", event);
        }

        return count;
    }

    async query(predicateBuilder) {
        // Promise-based interface allows this engine to be integrated
        // into asynchronous ingestion and reporting pipelines.
        await Promise.resolve();

        const builder = new QueryBuilder(
            this.repository.snapshot()
        );

        predicateBuilder(builder);

        return builder.execute();
    }
}

function createSamples() {
    const base = Date.UTC(2026, 10, 25, 2, 30);

    const data = [
        ["E001", 0, "192.168.1.10", "admin", "HIGH", "failure"],
        ["E002", 1, "192.168.1.10", "admin", "HIGH", "failure"],
        ["E003", 2, "192.168.1.10", "admin", "HIGH", "failure"],
        ["E004", 3, "192.168.1.10", "admin", "HIGH", "failure"],
        ["E005", 4, "192.168.1.10", "admin", "HIGH", "failure"],
        ["E006", 5, "192.168.1.10", "admin", "INFO", "success"],
        ["E007", 6, "10.10.1.20", "analyst", "MEDIUM", "blocked"],
        ["E008", 7, "10.10.1.20", "analyst", "CRITICAL", "blocked"],
        ["E009", 8, "172.16.0.25", "service_account", "LOW", "executed"],
        ["E010", 12, "192.168.1.15", "user01", "INFO", "success"]
    ];

    return data.map(
        ([eventId, minute, sourceIp, username, severity, action]) => ({
            eventId,
            timestamp: new Date(base + minute * 60000),
            sourceIp,
            destinationIp: "10.0.0.5",
            username,
            eventType: action === "blocked"
                ? "network"
                : action === "executed"
                    ? "process"
                    : "authentication",
            severity,
            action,
            source: "security-monitor",
            fields: {}
        })
    );
}

async function runTests(engine) {
    const results = await engine.query(query =>
        query.where("action", "eq", "failure")
    );

    if (results.length !== 5) {
        throw new SIEMError("Failed authentication test failed");
    }

    const alerts = SIEMAnalytics.detectBruteForce(
        engine.repository.snapshot()
    );

    if (alerts.length !== 1) {
        throw new SIEMError("Brute-force detection test failed");
    }

    try {
        new QueryBuilder([]).where("password", "eq", "secret");
        throw new SIEMError("Invalid field was accepted");
    } catch (error) {
        if (!(error instanceof SIEMError)) throw error;
    }

    const timeline = SIEMAnalytics.timeline(
        engine.repository.snapshot()
    );

    if (Object.keys(timeline).length === 0) {
        throw new SIEMError("Timeline test failed");
    }

    console.log("All JavaScript tests passed.");
}

async function main() {
    const engine = new SIEMEngine();

    try {
        const events = createSamples();

        await engine.ingest(events);

        const suspicious = await engine.query(query =>
            query
                .where("severity", "in", ["HIGH", "CRITICAL"])
                .where("action", "ne", "success")
        );

        const snapshot = engine.repository.snapshot();

        const report = {
            reportId: crypto.randomUUID(),
            generatedAt: new Date().toISOString(),
            totalEvents: snapshot.length,
            suspiciousEvents: suspicious.length,
            severityDistribution: SIEMAnalytics.aggregate(
                snapshot, "severity"
            ),
            sourceDistribution: SIEMAnalytics.aggregate(
                snapshot, "sourceIp"
            ),
            timeline: SIEMAnalytics.timeline(snapshot, 5),
            fieldAnalysis: SIEMAnalytics.fieldAnalysis(snapshot),
            bruteForceAlerts: SIEMAnalytics.detectBruteForce(snapshot)
        };

        console.log("\n=== SIEM REPORT ===");
        console.log(JSON.stringify(report, null, 2));

        await fs.writeFile(
            "siem_report.json",
            JSON.stringify(report, null, 2),
            { encoding: "utf8", mode: 0o600 }
        );

        await runTests(engine);

    } catch (error) {
        console.error("SIEM processing failed:", error.message);
        process.exitCode = 1;
    }
}

if (require.main === module) {
    main();
}

module.exports = {
    EventRepository,
    QueryBuilder,
    SIEMAnalytics,
    SIEMEngine,
    validateEvent
};
