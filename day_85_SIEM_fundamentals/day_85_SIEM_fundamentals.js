"use strict";

/*
 * SIEM FUNDAMENTALS
 * Event pipelines, structured fields, indexing, search,
 * time-window correlation, alert evaluation and incident handling.
 *
 * Runtime: Node.js 18+
 * Dependencies: None
 */

const crypto = require("node:crypto");
const fs = require("node:fs");
const { EventEmitter } = require("node:events");

const Severity = Object.freeze({
    INFO: "INFO",
    LOW: "LOW",
    MEDIUM: "MEDIUM",
    HIGH: "HIGH",
    CRITICAL: "CRITICAL"
});

const Category = Object.freeze({
    AUTHENTICATION: "authentication",
    NETWORK: "network",
    ENDPOINT: "endpoint",
    FIREWALL: "firewall",
    DNS: "dns",
    APPLICATION: "application"
});

const AlertStatus = Object.freeze({
    NEW: "NEW",
    ACKNOWLEDGED: "ACKNOWLEDGED",
    INVESTIGATING: "INVESTIGATING",
    RESOLVED: "RESOLVED",
    FALSE_POSITIVE: "FALSE_POSITIVE"
});

const VALID_SEVERITIES = new Set(Object.values(Severity));
const VALID_CATEGORIES = new Set(Object.values(Category));

class SIEMError extends Error {
    constructor(message, code = "SIEM_ERROR") {
        super(message);
        this.name = "SIEMError";
        this.code = code;
    }
}

function normalize(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "object") {
        return JSON.stringify(value);
    }
    return String(value).trim().toLowerCase();
}

function validateEvent(event) {
    if (!event || typeof event !== "object" || Array.isArray(event)) {
        throw new SIEMError("Event must be an object", "INVALID_EVENT");
    }

    const required = [
        "eventId",
        "timestamp",
        "source",
        "category",
        "eventType",
        "severity",
        "fields"
    ];

    for (const property of required) {
        if (!(property in event)) {
            throw new SIEMError(
                `Missing event property: ${property}`,
                "MISSING_FIELD"
            );
        }
    }

    if (
        typeof event.eventId !== "string" ||
        !/^[A-Za-z0-9_.-]{1,128}$/.test(event.eventId)
    ) {
        throw new SIEMError("Invalid event ID");
    }

    if (!Number.isFinite(Date.parse(event.timestamp))) {
        throw new SIEMError("Invalid event timestamp");
    }

    if (!VALID_CATEGORIES.has(event.category)) {
        throw new SIEMError("Unknown event category");
    }

    if (!VALID_SEVERITIES.has(event.severity)) {
        throw new SIEMError("Unknown event severity");
    }

    if (
        typeof event.source !== "string" ||
        event.source.trim().length === 0 ||
        event.source.length > 100
    ) {
        throw new SIEMError("Invalid event source");
    }

    if (
        typeof event.eventType !== "string" ||
        !/^[A-Za-z0-9_.-]{1,100}$/.test(event.eventType)
    ) {
        throw new SIEMError("Invalid event type");
    }

    if (
        !event.fields ||
        typeof event.fields !== "object" ||
        Array.isArray(event.fields)
    ) {
        throw new SIEMError("Event fields must be an object");
    }

    const normalizedTimestamp = new Date(event.timestamp).toISOString();
    const normalizedEvent = {
        ...event,
        timestamp: normalizedTimestamp,
        source: event.source.trim(),
        fields: structuredClone(event.fields)
    };

    const bytes = Buffer.byteLength(
        JSON.stringify(normalizedEvent),
        "utf8"
    );

    if (bytes > 65536) {
        throw new SIEMError("Event exceeds 64 KB");
    }

    return Object.freeze(normalizedEvent);
}


class EventIndex {
    constructor() {
        this.fields = new Map();
    }

    add(field, value, eventId) {
        const key = `${field}:${normalize(value)}`;

        if (!this.fields.has(key)) {
            this.fields.set(key, new Set());
        }

        this.fields.get(key).add(eventId);
    }

    lookup(field, value) {
        return new Set(
            this.fields.get(`${field}:${normalize(value)}`) || []
        );
    }

    intersect(sets) {
        if (sets.length === 0) return null;

        const ordered = [...sets].sort(
            (a, b) => a.size - b.size
        );

        return ordered.slice(1).reduce(
            (result, current) => {
                for (const id of result) {
                    if (!current.has(id)) result.delete(id);
                }
                return result;
            },
            new Set(ordered[0])
        );
    }
}


class SIEM extends EventEmitter {
    #events = new Map();
    #alerts = new Map();
    #rules = new Map();
    #processed = new Set();

    constructor() {
        super();

        this.index = new EventIndex();
        this.metrics = {
            accepted: 0,
            rejected: 0,
            duplicates: 0,
            searches: 0,
            generatedAlerts: 0
        };
    }

    async ingest(rawEvent) {
        // The asynchronous boundary allows ingestion to integrate
        // with message queues and network collectors.
        await Promise.resolve();

        let event;

        try {
            event = validateEvent(rawEvent);
        } catch (error) {
            this.metrics.rejected++;
            throw error;
        }

        if (this.#events.has(event.eventId)) {
            this.metrics.duplicates++;
            return false;
        }

        this.#events.set(event.eventId, event);

        const indexedFields = {
            source: event.source,
            category: event.category,
            severity: event.severity,
            eventType: event.eventType,
            ...event.fields
        };

        for (const [field, value] of Object.entries(indexedFields)) {
            if (
                value === null ||
                typeof value === "object"
            ) {
                continue;
            }

            this.index.add(field, value, event.eventId);
        }

        this.metrics.accepted++;

        this.emit("event:ingested", {
            eventId: event.eventId,
            category: event.category
        });

        return true;
    }

    async ingestBatch(events, concurrency = 10) {
        if (!Array.isArray(events)) {
            throw new SIEMError("Batch must be an array");
        }

        if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 100) {
            throw new SIEMError("Concurrency must be between 1 and 100");
        }

        const results = [];

        // Bounded batches prevent unrestrained concurrent work.
        for (let i = 0; i < events.length; i += concurrency) {
            const batch = events.slice(i, i + concurrency);

            const settled = await Promise.allSettled(
                batch.map(event => this.ingest(event))
            );

            results.push(...settled);
        }

        return {
            accepted: results.filter(
                result => result.status === "fulfilled" && result.value
            ).length,
            duplicates: results.filter(
                result => result.status === "fulfilled" && !result.value
            ).length,
            failures: results.filter(
                result => result.status === "rejected"
            ).map(result => result.reason.message)
        };
    }

    search(criteria = {}) {
        const {
            field,
            value,
            category,
            severity,
            startTime,
            endTime,
            limit = 100
        } = criteria;

        if (!Number.isInteger(limit) || limit < 1 || limit > 10000) {
            throw new SIEMError("Search limit must be 1-10000");
        }

        if (startTime && !Number.isFinite(Date.parse(startTime))) {
            throw new SIEMError("Invalid start time");
        }

        if (endTime && !Number.isFinite(Date.parse(endTime))) {
            throw new SIEMError("Invalid end time");
        }

        if (
            startTime &&
            endTime &&
            Date.parse(startTime) > Date.parse(endTime)
        ) {
            throw new SIEMError("Invalid time range");
        }

        const started = process.hrtime.bigint();

        const indexSets = [];

        if (field !== undefined && value !== undefined) {
            indexSets.push(this.index.lookup(field, value));
        }

        if (category) {
            indexSets.push(this.index.lookup("category", category));
        }

        if (severity) {
            indexSets.push(this.index.lookup("severity", severity));
        }

        const candidates = this.index.intersect(indexSets);

        const source = candidates === null
            ? this.#events.keys()
            : candidates;

        const matching = [];

        for (const id of source) {
            const event = this.#events.get(id);

            if (!event) continue;

            const timestamp = Date.parse(event.timestamp);

            if (startTime && timestamp < Date.parse(startTime)) {
                continue;
            }

            if (endTime && timestamp > Date.parse(endTime)) {
                continue;
            }

            if (field !== undefined && value !== undefined) {
                const actual = event[field] ?? event.fields[field];

                if (actual === undefined || normalize(actual) !== normalize(value)) {
                    continue;
                }
            }

            matching.push(event);
        }

        matching.sort(
            (a, b) =>
                Date.parse(b.timestamp) - Date.parse(a.timestamp) ||
                a.eventId.localeCompare(b.eventId)
        );

        this.metrics.searches++;

        const elapsed = Number(
            process.hrtime.bigint() - started
        ) / 1e6;

        return {
            total: matching.length,
            events: matching.slice(0, limit),
            executionMs: Number(elapsed.toFixed(3))
        };
    }

    registerRule(rule) {
        if (!rule || typeof rule !== "object") {
            throw new SIEMError("Invalid correlation rule");
        }

        if (this.#rules.has(rule.id)) {
            throw new SIEMError("Rule already exists");
        }

        if (
            !Number.isInteger(rule.windowSeconds) ||
            rule.windowSeconds < 1 ||
            !Number.isInteger(rule.threshold) ||
            rule.threshold < 1 ||
            !VALID_SEVERITIES.has(rule.severity)
        ) {
            throw new SIEMError("Invalid rule parameters");
        }

        this.#rules.set(rule.id, Object.freeze({ ...rule }));
    }

    correlate(now = new Date()) {
        if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
            throw new SIEMError("Invalid correlation timestamp");
        }

        const generated = [];

        for (const rule of this.#rules.values()) {
            const start = new Date(
                now.getTime() - rule.windowSeconds * 1000
            );

            const result = this.search({
                field: "eventType",
                value: rule.eventType,
                startTime: start.toISOString(),
                endTime: now.toISOString(),
                limit: 10000
            });

            const groups = new Map();

            for (const event of result.events) {
                const value = event.fields[rule.groupField];

                if (value === undefined || value === null) continue;

                const key = normalize(value);

                if (!groups.has(key)) groups.set(key, []);
                groups.get(key).push(event);
            }

            for (const [key, events] of groups) {
                if (events.length < rule.threshold) continue;

                const bucket = Math.floor(
                    now.getTime() / (rule.windowSeconds * 1000)
                );

                const fingerprint = [
                    rule.id,
                    key,
                    bucket
                ].join(":");

                if (this.#processed.has(fingerprint)) continue;

                const alertId = crypto
                    .createHash("sha256")
                    .update(fingerprint)
                    .digest("hex")
                    .slice(0, 24);

                const alert = {
                    alertId,
                    ruleId: rule.id,
                    title: rule.name,
                    severity: rule.severity,
                    createdAt: now.toISOString(),
                    eventIds: events.map(e => e.eventId).sort(),
                    description: `${events.length} matching events for ${rule.groupField}=${key}`,
                    status: AlertStatus.NEW,
                    assignedTo: null
                };

                this.#alerts.set(alertId, alert);
                this.#processed.add(fingerprint);
                this.metrics.generatedAlerts++;

                generated.push(alert);
                this.emit("alert:created", structuredClone(alert));
            }
        }

        return generated;
    }

    transitionAlert(alertId, newStatus, analyst = null) {
        const alert = this.#alerts.get(alertId);

        if (!alert) {
            throw new SIEMError("Alert not found", "NOT_FOUND");
        }

        const transitions = {
            NEW: ["ACKNOWLEDGED", "FALSE_POSITIVE"],
            ACKNOWLEDGED: [
                "INVESTIGATING",
                "RESOLVED",
                "FALSE_POSITIVE"
            ],
            INVESTIGATING: ["RESOLVED", "FALSE_POSITIVE"],
            RESOLVED: [],
            FALSE_POSITIVE: []
        };

        if (!transitions[alert.status]?.includes(newStatus)) {
            throw new SIEMError(
                `Invalid alert transition ${alert.status} -> ${newStatus}`
            );
        }

        if (analyst !== null) {
            if (
                typeof analyst !== "string" ||
                analyst.trim().length === 0 ||
                analyst.length > 100
            ) {
                throw new SIEMError("Invalid analyst identity");
            }

            alert.assignedTo = analyst.trim();
        }

        alert.status = newStatus;

        this.emit("alert:updated", structuredClone(alert));

        return structuredClone(alert);
    }

    getAlerts() {
        return [...this.#alerts.values()].map(
            alert => structuredClone(alert)
        );
    }

    statistics() {
        const categories = new Map();
        const severities = new Map();

        for (const event of this.#events.values()) {
            categories.set(
                event.category,
                (categories.get(event.category) || 0) + 1
            );

            severities.set(
                event.severity,
                (severities.get(event.severity) || 0) + 1
            );
        }

        return {
            eventCount: this.#events.size,
            alertCount: this.#alerts.size,
            categories: Object.fromEntries(categories),
            severities: Object.fromEntries(severities),
            metrics: { ...this.metrics }
        };
    }

    exportAlerts(filename) {
        if (typeof filename !== "string" || !filename.trim()) {
            throw new SIEMError("Invalid output filename");
        }

        fs.writeFileSync(
            filename,
            JSON.stringify(this.getAlerts(), null, 2),
            { encoding: "utf8", mode: 0o600 }
        );
    }
}


function sampleEvent(id, offset, fields = {}) {
    return {
        eventId: id,
        timestamp: new Date(
            Date.UTC(2026, 10, 24, 6, 0, offset)
        ).toISOString(),
        source: "linux-auth-01",
        category: Category.AUTHENTICATION,
        eventType: "failed_login",
        severity: Severity.MEDIUM,
        fields: {
            src_ip: "203.0.113.45",
            username: "admin",
            host: "server-01",
            protocol: "ssh",
            ...fields
        }
    };
}


async function main() {
    const siem = new SIEM();

    siem.on("event:ingested", event => {
        console.log("INGESTED:", event.eventId);
    });

    siem.on("alert:created", alert => {
        console.log("ALERT CREATED:", alert.alertId);
    });

    siem.on("alert:updated", alert => {
        console.log("ALERT STATUS:", alert.status);
    });

    const events = Array.from(
        { length: 6 },
        (_, index) => sampleEvent(
            `AUTH-${index + 1}`,
            index * 5
        )
    );

    events.push({
        eventId: "FW-001",
        timestamp: "2026-11-24T06:00:30.000Z",
        source: "firewall-01",
        category: Category.FIREWALL,
        eventType: "blocked_connection",
        severity: Severity.HIGH,
        fields: {
            src_ip: "203.0.113.45",
            dst_port: 22,
            action: "blocked"
        }
    });

    const ingestion = await siem.ingestBatch(events, 3);

    console.log("\nINGESTION RESULT");
    console.log(ingestion);

    siem.registerRule({
        id: "RULE-SSH-001",
        name: "SSH Brute Force",
        description: "Repeated failed authentication",
        eventType: "failed_login",
        groupField: "src_ip",
        windowSeconds: 300,
        threshold: 5,
        severity: Severity.CRITICAL
    });

    console.log("\nINDEXED SEARCH");

    const search = siem.search({
        field: "src_ip",
        value: "203.0.113.45",
        category: Category.AUTHENTICATION,
        limit: 100
    });

    console.log({
        total: search.total,
        executionMs: search.executionMs
    });

    const alerts = siem.correlate(
        new Date("2026-11-24T06:01:00.000Z")
    );

    console.log("\nCORRELATION RESULTS");
    console.log(alerts);

    if (alerts.length > 0) {
        siem.transitionAlert(
            alerts[0].alertId,
            AlertStatus.ACKNOWLEDGED,
            "soc-analyst-01"
        );

        siem.transitionAlert(
            alerts[0].alertId,
            AlertStatus.INVESTIGATING
        );
    }

    console.log("\nSIEM STATISTICS");
    console.log(siem.statistics());

    // Verify deduplication.
    const duplicate = await siem.ingest(events[0]);
    console.assert(duplicate === false);

    // Verify invalid transition handling.
    if (alerts.length > 0) {
        try {
            siem.transitionAlert(
                alerts[0].alertId,
                AlertStatus.NEW
            );
        } catch (error) {
            console.log("EXPECTED POLICY ERROR:", error.message);
        }
    }

    console.log("\nSIEM execution completed.");
}


main().catch(error => {
    console.error("SIEM FAILURE:", error.message);
    process.exitCode = 1;
});
