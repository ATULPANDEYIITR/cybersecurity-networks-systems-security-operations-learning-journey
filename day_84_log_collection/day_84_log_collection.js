"use strict";

/*
 * Event-driven distributed log collection system.
 *
 * Features:
 * - Agent registration and source management
 * - JSON and Syslog ingestion
 * - Timestamp and severity normalization
 * - Sensitive-data redaction
 * - Event-driven processing
 * - Asynchronous batch forwarding
 * - Backpressure and retry handling
 * - Idempotent delivery
 * - Dead-letter processing
 * - Retention and operational metrics
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only
 */

const crypto = require("node:crypto");
const EventEmitter = require("node:events");


class CollectionError extends Error {}
class ValidationError extends CollectionError {}
class QueueOverflowError extends CollectionError {}
class DeliveryError extends CollectionError {}


const Severity = Object.freeze({
    DEBUG: 10,
    INFO: 20,
    WARNING: 30,
    ERROR: 40,
    CRITICAL: 50
});


const SeverityAliases = Object.freeze({
    trace: 10,
    debug: 10,
    info: 20,
    notice: 20,
    warn: 30,
    warning: 30,
    error: 40,
    err: 40,
    critical: 50,
    fatal: 50,
    emergency: 50
});


class AgentRegistry {
    #agents = new Map();

    register(configuration) {
        const {
            id,
            hostname,
            environment,
            sourceType,
            enabled = true
        } = configuration;

        if (
            typeof id !== "string" ||
            !id.trim() ||
            typeof hostname !== "string" ||
            !hostname.trim()
        ) {
            throw new ValidationError(
                "Agent ID and hostname are required"
            );
        }

        if (!["json", "syslog"].includes(sourceType)) {
            throw new ValidationError(
                "Unsupported source type"
            );
        }

        if (this.#agents.has(id)) {
            throw new ValidationError(
                `Agent already registered: ${id}`
            );
        }

        const agent = Object.freeze({
            id,
            hostname,
            environment,
            sourceType,
            enabled: Boolean(enabled)
        });

        this.#agents.set(id, agent);

        return agent;
    }

    get(id) {
        const agent = this.#agents.get(id);

        if (!agent) {
            throw new ValidationError(
                `Unknown agent: ${id}`
            );
        }

        return agent;
    }

    list() {
        return [...this.#agents.values()];
    }
}


class TimestampService {
    static normalize(value) {
        let date;

        if (typeof value === "number") {
            // Unix timestamps are interpreted as seconds.
            date = new Date(value * 1000);
        } else if (value instanceof Date) {
            date = new Date(value.getTime());
        } else if (typeof value === "string") {
            date = new Date(value);
        } else {
            throw new ValidationError(
                "Invalid timestamp type"
            );
        }

        if (Number.isNaN(date.getTime())) {
            throw new ValidationError(
                `Invalid timestamp: ${value}`
            );
        }

        return date.toISOString();
    }
}


class LogParser {
    static parse(raw, sourceType) {
        if (
            typeof raw !== "string" ||
            raw.trim().length === 0
        ) {
            throw new ValidationError(
                "Empty log message"
            );
        }

        if (Buffer.byteLength(raw, "utf8") > 1048576) {
            throw new ValidationError(
                "Log exceeds maximum size"
            );
        }

        if (sourceType === "json") {
            let data;

            try {
                data = JSON.parse(raw);
            } catch {
                throw new ValidationError(
                    "Malformed JSON"
                );
            }

            if (
                data === null ||
                Array.isArray(data) ||
                typeof data !== "object"
            ) {
                throw new ValidationError(
                    "JSON log must be an object"
                );
            }

            for (const field of [
                "timestamp",
                "severity",
                "message"
            ]) {
                if (!(field in data)) {
                    throw new ValidationError(
                        `Missing field: ${field}`
                    );
                }
            }

            return data;
        }

        if (sourceType === "syslog") {
            const match = raw.match(
                /^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$/
            );

            if (!match) {
                throw new ValidationError(
                    "Unsupported Syslog message"
                );
            }

            const [
                ,
                priorityText,
                version,
                timestamp,
                hostname,
                application,
                processId,
                messageId,
                message
            ] = match;

            const priority = Number(priorityText);

            if (priority > 191) {
                throw new ValidationError(
                    "Invalid Syslog priority"
                );
            }

            const severityCode = priority % 8;

            const syslogLevels = [
                50, 50, 50, 40, 30, 20, 20, 10
            ];

            return {
                timestamp,
                severity: syslogLevels[severityCode],
                message,
                hostname,
                application,
                processId,
                messageId,
                version,
                facility: Math.floor(priority / 8)
            };
        }

        throw new ValidationError(
            `Unsupported source: ${sourceType}`
        );
    }
}


class RedactionService {
    static redact(value) {
        return value
            .replace(
                /(?i:password|passwd|token|secret|api_key)\s*[=:]\s*['"]?[^,\s'"]+/gi,
                "[CREDENTIAL_REDACTED]"
            )
            .replace(
                /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
                "[EMAIL_REDACTED]"
            )
            .replace(
                /\b(?:\d[ -]*?){13,19}\b/g,
                "[CARD_REDACTED]"
            );
    }
}


class NormalizationService {
    static normalize(raw, agent) {
        const parsed = LogParser.parse(
            raw,
            agent.sourceType
        );

        const timestamp = TimestampService.normalize(
            parsed.timestamp
        );

        let severity;

        if (typeof parsed.severity === "number") {
            severity = parsed.severity;
        } else {
            severity = SeverityAliases[
                String(parsed.severity).toLowerCase()
            ];
        }

        if (
            !Object.values(Severity).includes(severity)
        ) {
            throw new ValidationError(
                "Invalid severity"
            );
        }

        if (
            parsed.message === null ||
            parsed.message === undefined
        ) {
            throw new ValidationError(
                "Missing log message"
            );
        }

        const message = RedactionService.redact(
            String(parsed.message)
        ).slice(0, 10000);

        const attributes = {};

        for (const [key, value] of Object.entries(parsed)) {
            if (
                ![
                    "timestamp",
                    "severity",
                    "message"
                ].includes(key)
            ) {
                if (
                    key.length > 128 ||
                    typeof value === "function"
                ) {
                    throw new ValidationError(
                        "Invalid log attribute"
                    );
                }

                attributes[key] = value;
            }
        }

        if (Object.keys(attributes).length > 100) {
            throw new ValidationError(
                "Too many attributes"
            );
        }

        const hostname = String(
            attributes.hostname || agent.hostname
        );

        delete attributes.hostname;

        const identity = [
            agent.id,
            hostname,
            timestamp,
            severity,
            message
        ].join("|");

        const fingerprint = crypto
            .createHash("sha256")
            .update(identity)
            .digest("hex");

        return Object.freeze({
            eventId: crypto.randomUUID(),
            agentId: agent.id,
            hostname,
            environment: agent.environment,
            timestamp,
            receivedAt: new Date().toISOString(),
            severity,
            message,
            attributes: Object.freeze(attributes),
            fingerprint,
            state: "NORMALIZED"
        });
    }
}


class Metrics {
    #counters = new Map();

    increment(name, amount = 1) {
        this.#counters.set(
            name,
            (this.#counters.get(name) || 0) + amount
        );
    }

    get(name) {
        return this.#counters.get(name) || 0;
    }

    snapshot() {
        return Object.fromEntries(this.#counters);
    }
}


class MemoryDestination {
    #records = new Map();

    constructor() {
        this.failuresRemaining = 0;
    }

    async send(batch) {
        if (this.failuresRemaining > 0) {
            this.failuresRemaining--;

            throw new DeliveryError(
                "Destination temporarily unavailable"
            );
        }

        // Fingerprint-based idempotency prevents duplicate
        // storage when a response is lost after ingestion.
        for (const record of batch) {
            if (!this.#records.has(record.fingerprint)) {
                this.#records.set(
                    record.fingerprint,
                    record
                );
            }
        }
    }

    get size() {
        return this.#records.size;
    }

    values() {
        return [...this.#records.values()];
    }
}


class ForwardingService extends EventEmitter {
    constructor(destination, options = {}) {
        super();

        this.destination = destination;
        this.batchSize = options.batchSize ?? 10;
        this.maxRetries = options.maxRetries ?? 3;
        this.maxQueueSize = options.maxQueueSize ?? 1000;
        this.maxDeadLetters = options.maxDeadLetters ?? 10000;

        if (
            this.batchSize <= 0 ||
            this.maxRetries < 0 ||
            this.maxQueueSize <= 0 ||
            this.maxDeadLetters <= 0
        ) {
            throw new ValidationError(
                "Invalid forwarding configuration"
            );
        }

        this.queue = [];
        this.deadLetters = [];
        this.metrics = new Metrics();
        this.running = false;
    }

    enqueue(record) {
        if (this.queue.length >= this.maxQueueSize) {
            this.metrics.increment("queue_overflow");

            throw new QueueOverflowError(
                "Forwarding queue is full"
            );
        }

        this.queue.push(record);
        this.metrics.increment("enqueued");

        this.emit("queued", record.eventId);
    }

    async deliverBatch(batch) {
        for (
            let attempt = 0;
            attempt <= this.maxRetries;
            attempt++
        ) {
            try {
                await this.destination.send(batch);

                this.metrics.increment(
                    "forwarded",
                    batch.length
                );

                this.emit("delivered", batch);

                return true;

            } catch (error) {
                this.metrics.increment("delivery_errors");

                this.emit("deliveryError", {
                    attempt,
                    message: error.message
                });

                if (attempt < this.maxRetries) {
                    const delay = Math.min(
                        100 * (2 ** attempt),
                        2000
                    );

                    await new Promise(resolve =>
                        setTimeout(resolve, delay)
                    );
                }
            }
        }

        return false;
    }

    async flush() {
        if (this.running) {
            throw new DeliveryError(
                "A flush operation is already running"
            );
        }

        this.running = true;

        let delivered = 0;

        try {
            while (this.queue.length > 0) {
                const batch = this.queue.splice(
                    0,
                    this.batchSize
                );

                const success = await this.deliverBatch(
                    batch
                );

                if (success) {
                    delivered += batch.length;
                } else {
                    const available = Math.max(
                        0,
                        this.maxDeadLetters -
                        this.deadLetters.length
                    );

                    const failed = batch.slice(
                        0,
                        available
                    );

                    this.deadLetters.push(...failed);

                    this.metrics.increment(
                        "dead_lettered",
                        failed.length
                    );

                    if (failed.length < batch.length) {
                        // Restore unrecorded failures instead of
                        // silently discarding them.
                        this.queue.unshift(
                            ...batch.slice(failed.length)
                        );

                        throw new DeliveryError(
                            "Dead-letter capacity exhausted"
                        );
                    }
                }
            }

            return delivered;

        } finally {
            this.running = false;
        }
    }

    async replayDeadLetters() {
        const pending = this.deadLetters;
        this.deadLetters = [];

        for (const record of pending) {
            if (this.queue.length >= this.maxQueueSize) {
                this.deadLetters.push(record);
                continue;
            }

            this.queue.push(record);
        }

        this.metrics.increment(
            "dead_letter_replay_requests"
        );

        return this.flush();
    }
}


class RetentionService {
    constructor({
        hotDays = 30,
        archiveDays = 90
    } = {}) {
        if (
            hotDays <= 0 ||
            archiveDays <= hotDays
        ) {
            throw new ValidationError(
                "Invalid retention periods"
            );
        }

        this.hotDays = hotDays;
        this.archiveDays = archiveDays;
        this.archive = [];
    }

    apply(records, now = new Date()) {
        const current = new Date(now);

        if (Number.isNaN(current.getTime())) {
            throw new ValidationError(
                "Invalid retention reference time"
            );
        }

        const hotLimit =
            current.getTime() -
            this.hotDays * 86400000;

        const archiveLimit =
            current.getTime() -
            this.archiveDays * 86400000;

        const retained = [];

        let archived = 0;
        let deleted = 0;

        for (const record of records) {
            const timestamp = Date.parse(
                record.timestamp
            );

            if (!Number.isFinite(timestamp)) {
                throw new ValidationError(
                    "Invalid stored event timestamp"
                );
            }

            if (timestamp > current.getTime()) {
                retained.push(record);
            } else if (timestamp <= archiveLimit) {
                deleted++;
            } else if (timestamp <= hotLimit) {
                this.archive.push(record);
                archived++;
            } else {
                retained.push(record);
            }
        }

        return {
            retained,
            archived,
            deleted,
            archiveSize: this.archive.length
        };
    }
}


class LogCollectionSystem extends EventEmitter {
    constructor() {
        super();

        this.agents = new AgentRegistry();
        this.destination = new MemoryDestination();

        this.forwarder = new ForwardingService(
            this.destination,
            {
                batchSize: 2,
                maxRetries: 2,
                maxQueueSize: 1000,
                maxDeadLetters: 10000
            }
        );

        this.retention = new RetentionService();
        this.records = [];
        this.fingerprints = new Set();
        this.metrics = new Metrics();
    }

    ingest(agentId, raw) {
        const agent = this.agents.get(agentId);

        if (!agent.enabled) {
            this.metrics.increment("disabled_agent");
            return null;
        }

        try {
            const record = NormalizationService.normalize(
                raw,
                agent
            );

            if (this.fingerprints.has(record.fingerprint)) {
                this.metrics.increment("duplicates");
                return null;
            }

            this.forwarder.enqueue(record);

            this.fingerprints.add(record.fingerprint);
            this.records.push(record);

            this.metrics.increment("collected");

            this.emit("collected", record);

            return record;

        } catch (error) {
            this.metrics.increment("rejected");

            this.emit("rejected", {
                agentId,
                reason: error.message
            });

            throw error;
        }
    }

    async process() {
        return this.forwarder.flush();
    }

    report() {
        const severityCounts = {};

        for (const record of this.records) {
            const name = Object.entries(Severity).find(
                ([, value]) => value === record.severity
            )?.[0] || "UNKNOWN";

            severityCounts[name] =
                (severityCounts[name] || 0) + 1;
        }

        return {
            agents: this.agents.list().length,
            collected: this.records.length,
            destinationRecords: this.destination.size,
            severityCounts,
            collectionMetrics: this.metrics.snapshot(),
            forwardingMetrics: this.forwarder.metrics.snapshot(),
            queued: this.forwarder.queue.length,
            deadLetters: this.forwarder.deadLetters.length
        };
    }
}


async function main() {
    const system = new LogCollectionSystem();

    system.on("rejected", event => {
        console.error(
            "Rejected event:",
            event.reason
        );
    });

    system.on("deliveryError", event => {
        console.warn(
            "Delivery error:",
            event.message
        );
    });

    system.agents.register({
        id: "web-agent-01",
        hostname: "web-01",
        environment: "production",
        sourceType: "json"
    });

    system.agents.register({
        id: "database-agent-01",
        hostname: "db-01",
        environment: "production",
        sourceType: "syslog"
    });

    const events = [
        [
            "web-agent-01",
            JSON.stringify({
                timestamp: "2026-11-23T04:00:00Z",
                severity: "INFO",
                message: "Authentication successful",
                service: "identity"
            })
        ],
        [
            "web-agent-01",
            JSON.stringify({
                timestamp: "2026-11-23T04:01:00Z",
                severity: "ERROR",
                message: "password=secret123 database unavailable",
                service: "payments"
            })
        ],
        [
            "database-agent-01",
            "<34>1 2026-11-23T04:02:00Z "
            + "db-01 postgres 1234 ID47 "
            + "Connection restored"
        ],
        [
            "web-agent-01",
            JSON.stringify({
                timestamp: "2026-11-23T04:03:00Z",
                severity: "WARNING",
                message: "CPU utilization above threshold",
                utilization: 93
            })
        ]
    ];

    for (const [agentId, raw] of events) {
        system.ingest(agentId, raw);
    }

    // Identical content is rejected through fingerprinting.
    system.ingest("web-agent-01", events[0][1]);

    const delivered = await system.process();

    console.log("Delivered:", delivered);

    console.log(
        "Operational report:",
        JSON.stringify(system.report(), null, 2)
    );

    // Demonstrate destination failure and dead-letter handling.
    const failingDestination = new MemoryDestination();

    failingDestination.failuresRemaining = 5;

    const failingForwarder = new ForwardingService(
        failingDestination,
        {
            batchSize: 1,
            maxRetries: 1,
            maxQueueSize: 10,
            maxDeadLetters: 10
        }
    );

    failingForwarder.enqueue({
        eventId: "failure-test",
        fingerprint: "failure-fingerprint"
    });

    await failingForwarder.flush();

    console.log(
        "Dead-letter count:",
        failingForwarder.deadLetters.length
    );

    // Historical retention example.
    const historicalRecords = [
        {
            eventId: "historical-1",
            timestamp: new Date(
                Date.now() - 45 * 86400000
            ).toISOString()
        },
        {
            eventId: "historical-2",
            timestamp: new Date(
                Date.now() - 120 * 86400000
            ).toISOString()
        }
    ];

    console.log(
        "Retention:",
        system.retention.apply(historicalRecords)
    );

    if (delivered !== 4) {
        throw new Error(
            "Unexpected forwarding count"
        );
    }

    if (system.metrics.get("duplicates") !== 1) {
        throw new Error(
            "Duplicate detection failed"
        );
    }

    console.log("All assertions passed.");
}


main().catch(error => {
    console.error("Pipeline failure:", error);
    process.exitCode = 1;
});
