"use strict";

/*
 * SOC Architecture: Event-driven security monitoring pipeline.
 *
 * Node.js 18+
 *
 * This implementation emphasizes asynchronous collection,
 * event-driven processing, bounded buffering, normalization,
 * correlation, alert lifecycle management, and operational metrics.
 */

const { EventEmitter } = require("node:events");
const crypto = require("node:crypto");

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

const CONFIG = Object.freeze({
    MAX_BUFFER: 5000,
    MAX_PAYLOAD_BYTES: 65536,
    FAILURE_THRESHOLD: 5,
    CORRELATION_WINDOW_MS: 5 * 60 * 1000,
    DEDUPLICATION_WINDOW_MS: 10 * 60 * 1000,
    MAX_EVENTS: 50000
});

const SEVERITIES = Object.freeze([
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
]);

const CATEGORIES = Object.freeze([
    "AUTHENTICATION",
    "NETWORK",
    "ENDPOINT",
    "APPLICATION",
    "CLOUD"
]);

// ------------------------------------------------------------
// Validation utilities
// ------------------------------------------------------------

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}

class CapacityError extends Error {
    constructor(message) {
        super(message);
        this.name = "CapacityError";
    }
}

function requireString(value, field, maxLength = 255) {
    if (
        typeof value !== "string" ||
        value.trim().length === 0 ||
        value.length > maxLength
    ) {
        throw new ValidationError(`Invalid ${field}`);
    }

    return value.trim();
}

function validateIPv4(value) {
    if (value === undefined || value === null) {
        return null;
    }

    const parts = value.split(".");

    if (
        parts.length !== 4 ||
        parts.some(part =>
            !/^\d{1,3}$/.test(part) ||
            Number(part) > 255
        )
    ) {
        throw new ValidationError("Invalid IPv4 address");
    }

    return value;
}

function parseTimestamp(value) {
    const timestamp = Date.parse(value);

    if (!Number.isFinite(timestamp)) {
        throw new ValidationError("Invalid timestamp");
    }

    if (!/(Z|[+-]\d{2}:\d{2})$/i.test(value)) {
        throw new ValidationError("Timezone is required");
    }

    return new Date(timestamp);
}

function stableHash(value) {
    return crypto
        .createHash("sha256")
        .update(value)
        .digest("hex");
}

// ------------------------------------------------------------
// Data source registry
// ------------------------------------------------------------

class SourceRegistry {

    #sources = new Map();

    register(source) {
        const id = requireString(source.id, "source ID");

        if (this.#sources.has(id)) {
            throw new ValidationError("Duplicate source");
        }

        const normalized = Object.freeze({
            id,
            name: requireString(source.name, "source name"),
            type: requireString(source.type, "source type"),
            environment: requireString(
                source.environment,
                "environment"
            ),
            enabled: source.enabled !== false
        });

        this.#sources.set(id, normalized);
        return normalized;
    }

    get(id) {
        const source = this.#sources.get(id);

        if (!source) {
            throw new ValidationError("Unknown source");
        }

        return source;
    }

    values() {
        return [...this.#sources.values()];
    }
}

// ------------------------------------------------------------
// Asynchronous collector
// ------------------------------------------------------------

class EventCollector extends EventEmitter {

    #queue = [];
    #registry;

    constructor(registry) {
        super();
        this.#registry = registry;
        this.dropped = 0;
        this.accepted = 0;
    }

    async ingest(sourceId, payload) {
        const source = this.#registry.get(sourceId);

        if (!source.enabled) {
            this.dropped++;
            return false;
        }

        if (typeof payload !== "string" || !payload.trim()) {
            throw new ValidationError("Empty payload");
        }

        if (
            Buffer.byteLength(payload, "utf8") >
            CONFIG.MAX_PAYLOAD_BYTES
        ) {
            throw new ValidationError("Payload too large");
        }

        if (this.#queue.length >= CONFIG.MAX_BUFFER) {
            this.dropped++;
            this.emit("overflow", {
                sourceId,
                dropped: this.dropped
            });
            return false;
        }

        const raw = Object.freeze({
            sourceId,
            payload,
            receivedAt: new Date()
        });

        this.#queue.push(raw);
        this.accepted++;

        this.emit("collected", {
            sourceId,
            receivedAt: raw.receivedAt
        });

        return true;
    }

    drain(limit = 100) {
        if (!Number.isInteger(limit) || limit <= 0) {
            throw new ValidationError("Invalid batch limit");
        }

        return this.#queue.splice(
            0,
            Math.min(limit, this.#queue.length)
        );
    }

    get queueSize() {
        return this.#queue.length;
    }
}

// ------------------------------------------------------------
// Normalization and parsing
// ------------------------------------------------------------

class EventNormalizer {

    normalize(raw) {
        let input;

        try {
            input = JSON.parse(raw.payload);
        } catch {
            throw new ValidationError("Malformed JSON");
        }

        if (
            input === null ||
            typeof input !== "object" ||
            Array.isArray(input)
        ) {
            throw new ValidationError("Expected JSON object");
        }

        const category = requireString(
            input.category,
            "category"
        ).toUpperCase();

        const severity = requireString(
            input.severity,
            "severity"
        ).toUpperCase();

        if (!CATEGORIES.includes(category)) {
            throw new ValidationError("Unsupported category");
        }

        if (!SEVERITIES.includes(severity)) {
            throw new ValidationError("Unsupported severity");
        }

        const eventType = requireString(
            input.event_type,
            "event type"
        );

        const timestamp = parseTimestamp(input.timestamp);

        const username = input.username == null
            ? null
            : requireString(input.username, "username");

        const hostname = input.hostname == null
            ? null
            : requireString(input.hostname, "hostname");

        const message = input.message ?? "";

        if (typeof message !== "string") {
            throw new ValidationError("Invalid message");
        }

        const reserved = new Set([
            "timestamp",
            "category",
            "severity",
            "event_type",
            "source_ip",
            "destination_ip",
            "username",
            "hostname",
            "message"
        ]);

        const attributes = {};

        for (const [key, value] of Object.entries(input)) {
            if (!reserved.has(key)) {
                attributes[key] = value;
            }
        }

        const eventId = stableHash(
            `${raw.sourceId}|${raw.payload}`
        ).slice(0, 24);

        return Object.freeze({
            eventId,
            sourceId: raw.sourceId,
            timestamp,
            category,
            severity,
            eventType,
            sourceIp: validateIPv4(input.source_ip),
            destinationIp: validateIPv4(input.destination_ip),
            username,
            hostname,
            message,
            attributes
        });
    }
}

// ------------------------------------------------------------
// Event storage
// ------------------------------------------------------------

class EventStore {

    #events = new Map();
    #byUser = new Map();
    #bySource = new Map();
    #recentHashes = new Map();

    duplicates = 0;

    save(event) {
        if (this.#events.has(event.eventId)) {
            this.duplicates++;
            return false;
        }

        if (this.#events.size >= CONFIG.MAX_EVENTS) {
            throw new CapacityError("Event storage is full");
        }

        this.#events.set(event.eventId, event);

        if (event.username) {
            if (!this.#byUser.has(event.username)) {
                this.#byUser.set(event.username, []);
            }

            this.#byUser.get(event.username).push(event.eventId);
        }

        if (!this.#bySource.has(event.sourceId)) {
            this.#bySource.set(event.sourceId, []);
        }

        this.#bySource.get(event.sourceId).push(event.eventId);

        return true;
    }

    getByUser(username) {
        return (this.#byUser.get(username) || [])
            .map(id => this.#events.get(id));
    }

    getBySource(sourceId) {
        return (this.#bySource.get(sourceId) || [])
            .map(id => this.#events.get(id));
    }

    query(predicate = () => true) {
        return [...this.#events.values()].filter(predicate);
    }

    get size() {
        return this.#events.size;
    }

    values() {
        return [...this.#events.values()];
    }
}

// ------------------------------------------------------------
// Correlation rules
// ------------------------------------------------------------

class CorrelationRule {

    constructor({
        id,
        title,
        severity,
        category,
        eventType,
        threshold,
        windowMs,
        groupBy
    }) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.category = category;
        this.eventType = eventType;
        this.threshold = threshold;
        this.windowMs = windowMs;
        this.groupBy = groupBy;
    }

    matches(event) {
        return (
            event.category === this.category &&
            event.eventType === this.eventType
        );
    }
}

class CorrelationEngine {

    #rules = [];
    #alerts = new Map();

    constructor() {
        this.addRule(new CorrelationRule({
            id: "AUTH-001",
            title: "Possible brute-force attack",
            severity: "HIGH",
            category: "AUTHENTICATION",
            eventType: "LOGIN_FAILURE",
            threshold: CONFIG.FAILURE_THRESHOLD,
            windowMs: CONFIG.CORRELATION_WINDOW_MS,
            groupBy: event =>
                `${event.sourceIp}|${event.username}`
        }));
    }

    addRule(rule) {
        if (
            !rule.id ||
            !Number.isInteger(rule.threshold) ||
            rule.threshold < 2 ||
            rule.windowMs <= 0 ||
            typeof rule.groupBy !== "function"
        ) {
            throw new ValidationError("Invalid correlation rule");
        }

        if (this.#rules.some(existing => existing.id === rule.id)) {
            throw new ValidationError("Duplicate correlation rule");
        }

        this.#rules.push(rule);
    }

    evaluate(events) {
        const generated = [];

        for (const rule of this.#rules) {
            const groups = new Map();

            for (const event of events) {
                if (!rule.matches(event)) {
                    continue;
                }

                const key = rule.groupBy(event);

                if (!groups.has(key)) {
                    groups.set(key, []);
                }

                groups.get(key).push(event);
            }

            for (const [key, group] of groups) {
                group.sort(
                    (a, b) => a.timestamp - b.timestamp
                );

                let left = 0;

                for (let right = 0; right < group.length; right++) {
                    const current = group[right];

                    while (
                        group[left] &&
                        current.timestamp.getTime() -
                        group[left].timestamp.getTime() >
                        rule.windowMs
                    ) {
                        left++;
                    }

                    const matching = group.slice(left, right + 1);

                    if (matching.length < rule.threshold) {
                        continue;
                    }

                    const eventIds = matching.map(
                        event => event.eventId
                    ).sort();

                    const alertId = stableHash(
                        `${rule.id}|${key}|${eventIds.join("|")}`
                    ).slice(0, 24);

                    if (!this.#alerts.has(alertId)) {
                        const alert = {
                            alertId,
                            ruleId: rule.id,
                            title: rule.title,
                            severity: rule.severity,
                            eventIds,
                            description:
                                `${matching.length} matching events for ${key}`,
                            status: "OPEN",
                            createdAt: new Date()
                        };

                        this.#alerts.set(alertId, alert);
                        generated.push(alert);
                    }

                    break;
                }
            }
        }

        // Independent critical-event detection.
        for (const event of events) {
            if (event.severity !== "CRITICAL") {
                continue;
            }

            const alertId = `CRITICAL-${event.eventId}`;

            if (!this.#alerts.has(alertId)) {
                const alert = {
                    alertId,
                    ruleId: "CRITICAL-EVENT",
                    title: "Critical security event",
                    severity: "CRITICAL",
                    eventIds: [event.eventId],
                    description: event.message || event.eventType,
                    status: "OPEN",
                    createdAt: new Date()
                };

                this.#alerts.set(alertId, alert);
                generated.push(alert);
            }
        }

        return generated;
    }

    transition(alertId, newStatus) {
        const allowed = {
            OPEN: ["INVESTIGATING", "RESOLVED"],
            INVESTIGATING: ["OPEN", "RESOLVED"],
            RESOLVED: ["OPEN"]
        };

        const alert = this.#alerts.get(alertId);

        if (!alert) {
            throw new ValidationError("Alert not found");
        }

        if (!allowed[alert.status]?.includes(newStatus)) {
            throw new ValidationError("Invalid alert transition");
        }

        alert.status = newStatus;
        return alert;
    }

    values() {
        return [...this.#alerts.values()];
    }
}

// ------------------------------------------------------------
// Dashboard service
// ------------------------------------------------------------

class DashboardService {

    constructor(store, correlation, collector) {
        this.store = store;
        this.correlation = correlation;
        this.collector = collector;
    }

    snapshot() {
        const events = this.store.values();
        const alerts = this.correlation.values();

        const distribution = field => {
            const result = {};

            for (const event of events) {
                result[event[field]] =
                    (result[event[field]] || 0) + 1;
            }

            return result;
        };

        return {
            generatedAt: new Date().toISOString(),
            ingestion: {
                accepted: this.collector.accepted,
                dropped: this.collector.dropped,
                queued: this.collector.queueSize,
                stored: this.store.size,
                duplicates: this.store.duplicates
            },
            events: {
                total: events.length,
                severity: distribution("severity"),
                category: distribution("category"),
                sources: distribution("sourceId")
            },
            alerts: {
                total: alerts.length,
                open: alerts.filter(a => a.status === "OPEN").length,
                investigating: alerts.filter(
                    a => a.status === "INVESTIGATING"
                ).length,
                resolved: alerts.filter(
                    a => a.status === "RESOLVED"
                ).length
            }
        };
    }
}

// ------------------------------------------------------------
// Event-driven SOC application
// ------------------------------------------------------------

class SOCApplication extends EventEmitter {

    constructor() {
        super();

        this.registry = new SourceRegistry();
        this.collector = new EventCollector(this.registry);
        this.normalizer = new EventNormalizer();
        this.store = new EventStore();
        this.correlation = new CorrelationEngine();

        this.dashboard = new DashboardService(
            this.store,
            this.correlation,
            this.collector
        );

        this.invalidEvents = 0;

        this.collector.on("collected", event => {
            this.emit("ingestion", event);
        });

        this.collector.on("overflow", event => {
            this.emit("warning", {
                type: "BUFFER_OVERFLOW",
                ...event
            });
        });
    }

    async processBatch(limit = 100) {
        const rawEvents = this.collector.drain(limit);
        let processed = 0;

        for (const raw of rawEvents) {
            try {
                const event = this.normalizer.normalize(raw);

                if (this.store.save(event)) {
                    processed++;
                    this.emit("normalized", {
                        eventId: event.eventId
                    });
                }
            } catch (error) {
                this.invalidEvents++;

                this.emit("processing-error", {
                    sourceId: raw.sourceId,
                    message: error.message
                });
            }
        }

        const alerts = this.correlation.evaluate(
            this.store.values()
        );

        for (const alert of alerts) {
            this.emit("alert", alert);
        }

        return {
            processed,
            invalid: this.invalidEvents,
            alerts
        };
    }
}

// ------------------------------------------------------------
// Demonstration
// ------------------------------------------------------------

function sampleEvents() {
    const base = Date.now() - 180000;

    const events = [];

    for (let i = 0; i < 6; i++) {
        events.push({
            timestamp: new Date(base + i * 20000).toISOString(),
            category: "AUTHENTICATION",
            severity: "MEDIUM",
            event_type: "LOGIN_FAILURE",
            source_ip: "203.0.113.45",
            username: "admin",
            hostname: "identity-server-01",
            message: "Authentication failure"
        });
    }

    events.push({
        timestamp: new Date().toISOString(),
        category: "ENDPOINT",
        severity: "CRITICAL",
        event_type: "MALWARE_DETECTED",
        source_ip: "192.0.2.10",
        username: "analyst",
        hostname: "endpoint-01",
        message: "Malware detection generated"
    });

    return events;
}

async function main() {
    const soc = new SOCApplication();

    soc.registry.register({
        id: "firewall-01",
        name: "Enterprise Firewall",
        type: "NETWORK",
        environment: "PRODUCTION"
    });

    soc.registry.register({
        id: "edr-01",
        name: "Endpoint Detection",
        type: "ENDPOINT",
        environment: "PRODUCTION"
    });

    soc.on("alert", alert => {
        console.log(
            `[ALERT] ${alert.severity}: ${alert.title}`
        );
    });

    soc.on("processing-error", error => {
        console.error("[PARSER ERROR]", error);
    });

    soc.on("warning", warning => {
        console.error("[INGESTION WARNING]", warning);
    });

    const records = sampleEvents();

    await Promise.all(
        records.map((record, index) =>
            soc.collector.ingest(
                index === 6 ? "edr-01" : "firewall-01",
                JSON.stringify(record)
            )
        )
    );

    const result = await soc.processBatch(100);

    if (result.processed !== records.length) {
        throw new Error("Unexpected processing count");
    }

    // Verify duplicate handling.
    await soc.collector.ingest(
        "firewall-01",
        JSON.stringify(records[0])
    );

    await soc.processBatch();

    if (soc.store.duplicates !== 1) {
        throw new Error("Deduplication test failed");
    }

    // Verify invalid event handling.
    await soc.collector.ingest(
        "firewall-01",
        '{"category":"INVALID"}'
    );

    await soc.processBatch();

    if (soc.invalidEvents !== 1) {
        throw new Error("Invalid event test failed");
    }

    // Exercise alert state transitions.
    const openAlert = soc.correlation.values().find(
        alert => alert.status === "OPEN"
    );

    if (openAlert) {
        soc.correlation.transition(
            openAlert.alertId,
            "INVESTIGATING"
        );
    }

    console.log("\nSOC DASHBOARD");
    console.log(
        JSON.stringify(soc.dashboard.snapshot(), null, 2)
    );

    console.log("\nSOC event-driven processing verified.");
}

main().catch(error => {
    console.error("SOC application failure:", error);
    process.exitCode = 1;
});
