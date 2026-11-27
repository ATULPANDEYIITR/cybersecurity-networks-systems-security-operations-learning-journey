"use strict";

/*
 * IOC Investigation and Event-Driven Threat Detection
 *
 * Runtime: Node.js 18+
 * Dependencies: Node.js standard library only.
 *
 * Demonstrates:
 * - Typed IOC registration and normalization
 * - IP, domain, hash, URL, filename and registry indicators
 * - Event-driven security event processing
 * - Threat intelligence correlation
 * - Confidence and severity policies
 * - Allowlisting and expiration
 * - Investigation lifecycle
 * - Asynchronous batch processing
 * - Audit events
 * - Deterministic test scenarios
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");
const net = require("node:net");

const IOC_TYPES = Object.freeze({
    IP: "ip",
    DOMAIN: "domain",
    HASH: "hash",
    URL: "url",
    FILENAME: "filename",
    REGISTRY: "registry"
});

const SEVERITY = Object.freeze({
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical"
});

const CASE_STATES = Object.freeze({
    OPEN: "open",
    INVESTIGATING: "investigating",
    CONTAINED: "contained",
    CLOSED: "closed"
});

class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}

function normalizeIOC(type, raw) {
    if (typeof raw !== "string") {
        throw new ValidationError("IOC must be a string");
    }

    const value = raw.trim();

    if (!value || value.length > 4096) {
        throw new ValidationError("Invalid IOC length");
    }

    switch (type) {
        case IOC_TYPES.IP: {
            const version = net.isIP(value);

            if (!version) {
                throw new ValidationError("Invalid IP address");
            }

            return version === 6
                ? value.toLowerCase()
                : value;
        }

        case IOC_TYPES.DOMAIN: {
            const domain = value.replace(/\.$/, "").toLowerCase();

            let ascii;

            try {
                ascii = new URL(`http://${domain}`).hostname;
            } catch {
                throw new ValidationError("Invalid domain");
            }

            if (
                !ascii.includes(".") ||
                ascii.length > 253 ||
                ascii.split(".").some(
                    label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
                )
            ) {
                throw new ValidationError("Invalid domain format");
            }

            return ascii;
        }

        case IOC_TYPES.HASH: {
            const hash = value.toLowerCase();

            if (!/^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(hash)) {
                throw new ValidationError("Invalid cryptographic hash");
            }

            return hash;
        }

        case IOC_TYPES.URL: {
            let url;

            try {
                url = new URL(value);
            } catch {
                throw new ValidationError("Malformed URL");
            }

            if (!["http:", "https:"].includes(url.protocol)) {
                throw new ValidationError("Unsupported URL scheme");
            }

            if (url.username || url.password) {
                throw new ValidationError("Credential-bearing URLs rejected");
            }

            url.hostname = url.hostname.toLowerCase();

            if (url.port && !/^\d{1,5}$/.test(url.port)) {
                throw new ValidationError("Invalid URL port");
            }

            url.hash = "";

            return url.toString();
        }

        case IOC_TYPES.FILENAME:
            if (
                value.length > 255 ||
                /[\/\\\x00\r\n]/.test(value)
            ) {
                throw new ValidationError("Invalid filename");
            }

            return value.toLowerCase();

        case IOC_TYPES.REGISTRY: {
            let key = value
                .replace(/^HKEY_LOCAL_MACHINE/i, "HKLM")
                .replace(/^HKEY_CURRENT_USER/i, "HKCU")
                .replace(/^HKEY_CLASSES_ROOT/i, "HKCR")
                .replace(/^HKEY_USERS/i, "HKU");

            if (!/^HK(?:LM|CU|CR|U)\\/i.test(key)) {
                throw new ValidationError("Unsupported registry root");
            }

            if (key.includes("\0")) {
                throw new ValidationError("Invalid registry path");
            }

            return key.toLowerCase();
        }

        default:
            throw new ValidationError("Unsupported IOC type");
    }
}

class Indicator {
    constructor({
        type,
        value,
        source,
        confidence = 50,
        severity = SEVERITY.MEDIUM,
        tags = [],
        expiresAt = null
    }) {
        if (!Object.values(IOC_TYPES).includes(type)) {
            throw new ValidationError("Unknown indicator type");
        }

        if (!source || !source.trim()) {
            throw new ValidationError("Source is required");
        }

        if (!Number.isInteger(confidence) || confidence < 0 || confidence > 100) {
            throw new ValidationError("Confidence must be 0-100");
        }

        if (!Object.values(SEVERITY).includes(severity)) {
            throw new ValidationError("Invalid severity");
        }

        this.type = type;
        this.value = normalizeIOC(type, value);
        this.source = source.trim();
        this.confidence = confidence;
        this.severity = severity;
        this.tags = new Set(tags.map(tag => String(tag).toLowerCase()));
        this.expiresAt = expiresAt ? new Date(expiresAt) : null;

        if (this.expiresAt && Number.isNaN(this.expiresAt.getTime())) {
            throw new ValidationError("Invalid expiration timestamp");
        }

        this.active = true;
        this.createdAt = new Date();

        this.id = crypto
            .createHash("sha256")
            .update(`${type}:${this.value}`)
            .digest("hex");
    }

    isActive(now = new Date()) {
        return this.active &&
            (!this.expiresAt || this.expiresAt > now);
    }

    serialize() {
        return {
            id: this.id,
            type: this.type,
            value: this.value,
            source: this.source,
            confidence: this.confidence,
            severity: this.severity,
            tags: [...this.tags],
            expiresAt: this.expiresAt?.toISOString() ?? null,
            active: this.active,
            createdAt: this.createdAt.toISOString()
        };
    }
}

class IndicatorStore {
    #indicators = new Map();
    #allowlist = new Set();

    makeKey(type, value) {
        return `${type}:${value}`;
    }

    add(indicator) {
        const key = this.makeKey(indicator.type, indicator.value);

        if (this.#indicators.has(key)) {
            throw new Error("Duplicate IOC registration");
        }

        this.#indicators.set(key, indicator);
    }

    get(type, value) {
        const normalized = normalizeIOC(type, value);

        return this.#indicators.get(
            this.makeKey(type, normalized)
        ) ?? null;
    }

    allow(type, value) {
        const normalized = normalizeIOC(type, value);

        this.#allowlist.add(
            this.makeKey(type, normalized)
        );
    }

    isAllowed(type, value) {
        return this.#allowlist.has(
            this.makeKey(type, value)
        );
    }

    getAll() {
        return [...this.#indicators.values()];
    }

    getActive() {
        return this.getAll().filter(item => item.isActive());
    }
}

class InvestigationCase {
    #matches = [];
    #notes = [];

    constructor(id, title) {
        if (!id || !title) {
            throw new ValidationError("Case ID and title required");
        }

        this.id = id;
        this.title = title;
        this.status = CASE_STATES.OPEN;
        this.createdAt = new Date();
    }

    addMatch(match) {
        if (this.status === CASE_STATES.CLOSED) {
            throw new Error("Closed cases cannot accept matches");
        }

        const duplicate = this.#matches.some(
            item => item.eventId === match.eventId &&
                item.iocId === match.iocId
        );

        if (!duplicate) {
            this.#matches.push(Object.freeze({ ...match }));
        }
    }

    addNote(note) {
        if (this.status === CASE_STATES.CLOSED) {
            throw new Error("Closed cases cannot be modified");
        }

        if (!note.trim()) {
            throw new ValidationError("Empty case note");
        }

        this.#notes.push({
            text: note,
            timestamp: new Date()
        });
    }

    transition(next) {
        const transitions = {
            open: ["investigating", "closed"],
            investigating: ["contained", "closed"],
            contained: ["investigating", "closed"],
            closed: []
        };

        if (!transitions[this.status].includes(next)) {
            throw new Error(
                `Invalid transition: ${this.status} -> ${next}`
            );
        }

        this.status = next;
    }

    get matches() {
        return [...this.#matches];
    }

    get notes() {
        return [...this.#notes];
    }
}

class ThreatDetectionService extends EventEmitter {
    constructor(store) {
        super();

        this.store = store;
        this.audit = [];
        this.processing = false;

        this.on("security-event", event => {
            try {
                const match = this.evaluate(event);

                if (match) {
                    this.emit("ioc-match", match);
                }
            } catch (error) {
                this.emit("processing-error", {
                    eventId: event.id,
                    message: error.message
                });
            }
        });
    }

    evaluate(event) {
        const indicator = this.store.get(
            event.type,
            event.value
        );

        if (!indicator || !indicator.isActive()) {
            return null;
        }

        if (this.store.isAllowed(event.type, indicator.value)) {
            this.recordAudit("allowlisted", event.id, indicator.id);
            return null;
        }

        const match = Object.freeze({
            eventId: event.id,
            iocId: indicator.id,
            type: indicator.type,
            value: indicator.value,
            confidence: indicator.confidence,
            severity: indicator.severity,
            asset: event.asset,
            matchedAt: new Date()
        });

        this.recordAudit("ioc-match", event.id, indicator.id);

        return match;
    }

    async processBatch(events, concurrency = 10) {
        if (!Number.isInteger(concurrency) || concurrency < 1) {
            throw new ValidationError("Invalid concurrency");
        }

        const results = [];

        // Bounded workers prevent uncontrolled parallel processing.
        let cursor = 0;

        const worker = async () => {
            while (true) {
                const index = cursor++;

                if (index >= events.length) {
                    return;
                }

                const event = events[index];

                await Promise.resolve();

                const match = this.evaluate(event);

                if (match) {
                    results.push(match);
                    this.emit("ioc-match", match);
                }
            }
        };

        await Promise.all(
            Array.from(
                { length: Math.min(concurrency, events.length) },
                () => worker()
            )
        );

        return results;
    }

    recordAudit(action, eventId, iocId) {
        this.audit.push(Object.freeze({
            action,
            eventId,
            iocId,
            timestamp: new Date().toISOString()
        }));
    }
}

class ThreatPolicy {
    static priority(matches) {
        if (!matches.length) return 0;

        const weight = {
            low: 1,
            medium: 2,
            high: 3,
            critical: 4
        };

        return Math.min(
            100,
            Math.round(
                Math.max(
                    ...matches.map(
                        match => match.confidence *
                            weight[match.severity] / 4
                    )
                )
            )
        );
    }

    static classify(matches) {
        const priority = this.priority(matches);

        if (priority >= 90) return "critical";
        if (priority >= 70) return "high";
        if (priority >= 40) return "medium";

        return "low";
    }
}

async function hashFile(filePath, algorithm = "sha256") {
    if (!["md5", "sha1", "sha256"].includes(algorithm)) {
        throw new ValidationError("Unsupported hashing algorithm");
    }

    const hash = crypto.createHash(algorithm);
    const stream = require("node:fs").createReadStream(filePath);

    for await (const chunk of stream) {
        hash.update(chunk);
    }

    return hash.digest("hex");
}

async function exportIndicators(store, filePath) {
    const content = JSON.stringify(
        store.getAll().map(item => item.serialize()),
        null,
        2
    );

    await fs.writeFile(filePath, content, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx"
    });
}

function createDemo() {
    const store = new IndicatorStore();

    store.add(new Indicator({
        type: IOC_TYPES.IP,
        value: "203.0.113.45",
        source: "Firewall Intelligence",
        confidence: 95,
        severity: SEVERITY.CRITICAL,
        tags: ["c2", "network"]
    }));

    store.add(new Indicator({
        type: IOC_TYPES.DOMAIN,
        value: "malware.example",
        source: "DNS Intelligence",
        confidence: 90,
        severity: SEVERITY.HIGH
    }));

    store.add(new Indicator({
        type: IOC_TYPES.HASH,
        value: "a".repeat(64),
        source: "Endpoint Intelligence",
        confidence: 99,
        severity: SEVERITY.CRITICAL
    }));

    store.add(new Indicator({
        type: IOC_TYPES.URL,
        value: "https://malware.example/payload",
        source: "URL Feed",
        confidence: 92,
        severity: SEVERITY.HIGH
    }));

    store.add(new Indicator({
        type: IOC_TYPES.FILENAME,
        value: "suspicious.exe",
        source: "Endpoint Investigation",
        confidence: 80,
        severity: SEVERITY.MEDIUM
    }));

    store.add(new Indicator({
        type: IOC_TYPES.REGISTRY,
        value: "HKLM\\Software\\BadActor\\Persistence",
        source: "Registry Intelligence",
        confidence: 90,
        severity: SEVERITY.HIGH
    }));

    store.allow(IOC_TYPES.IP, "192.0.2.10");

    return store;
}

async function runTests() {
    const assert = require("node:assert/strict");

    assert.equal(
        normalizeIOC(IOC_TYPES.DOMAIN, "MALWARE.EXAMPLE."),
        "malware.example"
    );

    assert.equal(
        normalizeIOC(IOC_TYPES.HASH, "A".repeat(64)),
        "a".repeat(64)
    );

    assert.throws(
        () => normalizeIOC(IOC_TYPES.IP, "999.999.999.999"),
        ValidationError
    );

    assert.throws(
        () => normalizeIOC(IOC_TYPES.URL, "javascript:alert(1)"),
        ValidationError
    );

    assert.throws(
        () => normalizeIOC(IOC_TYPES.REGISTRY, "HKZZ\\Bad"),
        ValidationError
    );

    const store = createDemo();

    assert.equal(store.getAll().length, 6);

    const service = new ThreatDetectionService(store);

    const events = [
        {
            id: "EVT-001",
            type: IOC_TYPES.IP,
            value: "203.0.113.45",
            asset: "HOST-01"
        },
        {
            id: "EVT-002",
            type: IOC_TYPES.DOMAIN,
            value: "malware.example",
            asset: "HOST-02"
        }
    ];

    const matches = await service.processBatch(events, 2);

    assert.equal(matches.length, 2);
    assert.equal(ThreatPolicy.priority(matches), 95);

    const investigation = new InvestigationCase(
        "CASE-001",
        "Threat correlation"
    );

    investigation.addMatch(matches[0]);
    investigation.transition(CASE_STATES.INVESTIGATING);
    investigation.transition(CASE_STATES.CONTAINED);

    assert.equal(investigation.status, CASE_STATES.CONTAINED);

    console.log("All JavaScript validation tests passed.");
}

async function main() {
    const store = createDemo();
    const service = new ThreatDetectionService(store);

    const investigation = new InvestigationCase(
        "CASE-2026-001",
        "Endpoint and network threat investigation"
    );

    service.on("processing-error", error => {
        process.stderr.write(
            `Event processing failed: ${JSON.stringify(error)}\n`
        );
    });

    const events = [
        {
            id: "EVT-001",
            type: IOC_TYPES.IP,
            value: "203.0.113.45",
            asset: "WORKSTATION-01"
        },
        {
            id: "EVT-002",
            type: IOC_TYPES.DOMAIN,
            value: "MALWARE.EXAMPLE.",
            asset: "WORKSTATION-02"
        },
        {
            id: "EVT-003",
            type: IOC_TYPES.HASH,
            value: "a".repeat(64),
            asset: "SERVER-01"
        },
        {
            id: "EVT-004",
            type: IOC_TYPES.URL,
            value: "https://malware.example/payload",
            asset: "WORKSTATION-03"
        },
        {
            id: "EVT-005",
            type: IOC_TYPES.FILENAME,
            value: "suspicious.exe",
            asset: "WORKSTATION-04"
        },
        {
            id: "EVT-006",
            type: IOC_TYPES.REGISTRY,
            value: "HKLM\\Software\\BadActor\\Persistence",
            asset: "WORKSTATION-05"
        }
    ];

    const matches = await service.processBatch(events, 3);

    for (const match of matches) {
        investigation.addMatch(match);
    }

    if (matches.length) {
        investigation.transition(CASE_STATES.INVESTIGATING);
    }

    console.log("\nIOC INVESTIGATION");
    console.log("=================");

    console.log("Registered IOCs:", store.getAll().length);
    console.log("Analyzed events:", events.length);
    console.log("Confirmed matches:", matches.length);
    console.log("Priority:", ThreatPolicy.priority(matches));
    console.log("Classification:", ThreatPolicy.classify(matches));

    for (const match of matches) {
        console.log(
            `${match.eventId} | ${match.type} | ${match.value} | ` +
            `${match.severity} | ${match.confidence}%`
        );
    }

    console.log("Case:", investigation.id);
    console.log("Status:", investigation.status);
    console.log("Audit events:", service.audit.length);

    await runTests();
}

main().catch(error => {
    console.error("Fatal execution error:", error.message);
    process.exitCode = 1;
});
