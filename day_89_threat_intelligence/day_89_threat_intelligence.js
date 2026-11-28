"use strict";

/*
 * Threat Intelligence Management and Event Processing Engine
 *
 * Node.js 18+
 *
 * Capabilities:
 * - Asynchronous threat-feed ingestion
 * - Strategic, operational and tactical intelligence
 * - IOC validation and normalization
 * - Threat actor and campaign correlation
 * - Confidence and risk evaluation
 * - TLP sharing policies
 * - Event-driven processing
 * - Deduplication and expiration
 * - Feed failure isolation
 * - Observable matching
 * - Intelligence reporting
 */

const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");


const IntelligenceType = Object.freeze({
    STRATEGIC: "strategic",
    OPERATIONAL: "operational",
    TACTICAL: "tactical"
});

const IndicatorType = Object.freeze({
    IPV4: "ipv4",
    IPV6: "ipv6",
    DOMAIN: "domain",
    URL: "url",
    MD5: "md5",
    SHA1: "sha1",
    SHA256: "sha256",
    EMAIL: "email"
});

const TLP = Object.freeze({
    CLEAR: "clear",
    GREEN: "green",
    AMBER: "amber",
    AMBER_STRICT: "amber+strict",
    RED: "red"
});

const Severity = Object.freeze({
    LOW: 1,
    MEDIUM: 2,
    HIGH: 3,
    CRITICAL: 4
});

const Status = Object.freeze({
    ACTIVE: "active",
    EXPIRED: "expired",
    FALSE_POSITIVE: "false_positive",
    REVOKED: "revoked"
});


class ThreatIntelError extends Error {
    constructor(message, code = "THREAT_INTEL_ERROR") {
        super(message);
        this.name = "ThreatIntelError";
        this.code = code;
    }
}


function validateEnum(value, enumeration, field) {
    if (!Object.values(enumeration).includes(value)) {
        throw new ThreatIntelError(
            `Invalid ${field}: ${value}`,
            "INVALID_ENUM"
        );
    }
}


function normalizeIndicator(value, type) {

    if (typeof value !== "string" || !value.trim()) {
        throw new ThreatIntelError(
            "Indicator must be a non-empty string."
        );
    }

    if (value.length > 2048) {
        throw new ThreatIntelError("Indicator is too long.");
    }

    value = value.trim();

    if (type === IndicatorType.IPV4) {

        const parts = value.split(".");

        if (
            parts.length !== 4 ||
            parts.some(part =>
                !/^\d{1,3}$/.test(part) ||
                Number(part) > 255
            )
        ) {
            throw new ThreatIntelError("Invalid IPv4 address.");
        }

        return parts.map(Number).join(".");
    }

    if (type === IndicatorType.IPV6) {

        if (
            !/^[0-9a-fA-F:.]+$/.test(value) ||
            !value.includes(":")
        ) {
            throw new ThreatIntelError("Invalid IPv6 address.");
        }

        const groups = value.split("::");

        if (groups.length > 2) {
            throw new ThreatIntelError("Invalid IPv6 compression.");
        }

        const count = groups.reduce(
            (sum, group) => sum +
                (group ? group.split(":").length : 0),
            0
        );

        if (
            (groups.length === 1 && count !== 8) ||
            (groups.length === 2 && count >= 8)
        ) {
            throw new ThreatIntelError("Invalid IPv6 address.");
        }

        return value.toLowerCase();
    }

    if (type === IndicatorType.DOMAIN) {

        const domain = value.replace(/\.$/, "").toLowerCase();

        const labels = domain.split(".");

        if (
            domain.length > 253 ||
            labels.length < 2 ||
            labels.some(label =>
                !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
            )
        ) {
            throw new ThreatIntelError("Invalid domain.");
        }

        return domain;
    }

    const hashLengths = {
        md5: 32,
        sha1: 40,
        sha256: 64
    };

    if (hashLengths[type]) {

        if (
            !new RegExp(`^[a-fA-F0-9]{${hashLengths[type]}}$`).test(value)
        ) {
            throw new ThreatIntelError("Invalid cryptographic hash.");
        }

        return value.toLowerCase();
    }

    if (type === IndicatorType.EMAIL) {

        const match = /^([^@\s]+)@([^@\s]+)$/.exec(value);

        if (!match) {
            throw new ThreatIntelError("Invalid email indicator.");
        }

        return `${match[1]}@${normalizeIndicator(
            match[2],
            IndicatorType.DOMAIN
        )}`;
    }

    if (type === IndicatorType.URL) {

        let parsed;

        try {
            parsed = new URL(value);
        } catch {
            throw new ThreatIntelError("Invalid URL.");
        }

        if (!["http:", "https:"].includes(parsed.protocol)) {
            throw new ThreatIntelError("Unsupported URL protocol.");
        }

        if (parsed.username || parsed.password) {
            throw new ThreatIntelError(
                "URLs containing credentials are prohibited."
            );
        }

        parsed.hostname = normalizeIndicator(
            parsed.hostname,
            IndicatorType.DOMAIN
        );

        parsed.hash = "";

        return parsed.toString();
    }

    throw new ThreatIntelError("Unsupported indicator type.");
}


class SharingPolicy {

    static allowedGroups = Object.freeze({
        [TLP.CLEAR]: new Set([
            "public",
            "community",
            "organization",
            "designated_group",
            "internal"
        ]),
        [TLP.GREEN]: new Set([
            "community",
            "organization",
            "designated_group",
            "internal"
        ]),
        [TLP.AMBER]: new Set([
            "organization",
            "designated_group",
            "internal"
        ]),
        [TLP.AMBER_STRICT]: new Set([
            "designated_group",
            "internal"
        ]),
        [TLP.RED]: new Set()
    });

    static canShare(classification, recipient) {

        validateEnum(classification, TLP, "TLP");

        return (
            this.allowedGroups[classification].has(recipient)
        );
    }
}


class ThreatIndicator {

    constructor(data) {

        validateEnum(
            data.type,
            IndicatorType,
            "indicator type"
        );

        validateEnum(
            data.intelligenceType,
            IntelligenceType,
            "intelligence type"
        );

        validateEnum(data.tlp, TLP, "TLP");

        validateEnum(data.severity, Severity, "severity");

        if (
            !Number.isInteger(data.confidence) ||
            data.confidence < 0 ||
            data.confidence > 100
        ) {
            throw new ThreatIntelError(
                "Confidence must be an integer from 0 to 100."
            );
        }

        if (!data.source?.trim()) {
            throw new ThreatIntelError("Source is required.");
        }

        const firstSeen = new Date(data.firstSeen);
        const lastSeen = new Date(data.lastSeen);
        const expiresAt = new Date(data.expiresAt);

        if (
            [firstSeen, lastSeen, expiresAt].some(
                date => Number.isNaN(date.getTime())
            )
        ) {
            throw new ThreatIntelError("Invalid indicator timestamp.");
        }

        if (
            lastSeen < firstSeen ||
            expiresAt <= firstSeen
        ) {
            throw new ThreatIntelError(
                "Invalid indicator timestamp ordering."
            );
        }

        this.value = normalizeIndicator(data.value, data.type);
        this.type = data.type;
        this.source = data.source.trim();
        this.confidence = data.confidence;
        this.severity = data.severity;
        this.tlp = data.tlp;
        this.intelligenceType = data.intelligenceType;
        this.firstSeen = firstSeen;
        this.lastSeen = lastSeen;
        this.expiresAt = expiresAt;
        this.description = data.description || "";
        this.actorId = data.actorId || null;
        this.campaignId = data.campaignId || null;
        this.tags = new Set(data.tags || []);
        this.status = Status.ACTIVE;
        this.references = new Set([this.source]);

        this.id = crypto
            .createHash("sha256")
            .update(`${this.type}:${this.value}`)
            .digest("hex")
            .slice(0, 24);
    }

    isActive(now = new Date()) {
        return (
            this.status === Status.ACTIVE &&
            this.expiresAt > now
        );
    }

    riskScore(now = new Date()) {

        if (!this.isActive(now)) return 0;

        const ageHours = Math.max(
            0,
            (now - this.lastSeen) / 3600000
        );

        const recency = Math.max(
            0,
            100 - ageHours / 24 * 5
        );

        return Number((
            this.confidence * 0.4 +
            this.severity * 25 * 0.4 +
            recency * 0.2
        ).toFixed(2));
    }
}


class ThreatIntelligenceEngine extends EventEmitter {

    #indicators = new Map();
    #actors = new Map();
    #campaigns = new Map();

    constructor() {
        super();
        this.feedMetrics = {
            received: 0,
            accepted: 0,
            rejected: 0
        };
    }

    registerActor(actor) {

        if (!actor.id || !actor.name) {
            throw new ThreatIntelError("Invalid threat actor.");
        }

        if (this.#actors.has(actor.id)) {
            throw new ThreatIntelError("Duplicate threat actor.");
        }

        this.#actors.set(actor.id, Object.freeze({...actor}));
        this.emit("actor:registered", actor);
    }

    registerCampaign(campaign) {

        if (!this.#actors.has(campaign.actorId)) {
            throw new ThreatIntelError(
                "Campaign references an unknown actor."
            );
        }

        if (this.#campaigns.has(campaign.id)) {
            throw new ThreatIntelError("Duplicate campaign.");
        }

        this.#campaigns.set(
            campaign.id,
            Object.freeze({...campaign})
        );

        this.emit("campaign:registered", campaign);
    }

    ingest(data) {

        const indicator = data instanceof ThreatIndicator
            ? data
            : new ThreatIndicator(data);

        if (
            indicator.actorId &&
            !this.#actors.has(indicator.actorId)
        ) {
            throw new ThreatIntelError("Unknown threat actor.");
        }

        if (
            indicator.campaignId &&
            !this.#campaigns.has(indicator.campaignId)
        ) {
            throw new ThreatIntelError("Unknown campaign.");
        }

        const existing = this.#indicators.get(indicator.id);

        if (existing) {

            existing.confidence = Math.max(
                existing.confidence,
                indicator.confidence
            );

            existing.severity = Math.max(
                existing.severity,
                indicator.severity
            );

            existing.lastSeen = new Date(Math.max(
                existing.lastSeen.getTime(),
                indicator.lastSeen.getTime()
            ));

            existing.expiresAt = new Date(Math.max(
                existing.expiresAt.getTime(),
                indicator.expiresAt.getTime()
            ));

            for (const tag of indicator.tags) {
                existing.tags.add(tag);
            }

            existing.references.add(indicator.source);

            this.emit("indicator:updated", existing);

            return existing.id;
        }

        this.#indicators.set(indicator.id, indicator);

        this.feedMetrics.accepted++;

        this.emit("indicator:ingested", indicator);

        return indicator.id;
    }

    async ingestFeeds(feeds, concurrency = 3) {

        if (
            !Number.isInteger(concurrency) ||
            concurrency < 1 ||
            concurrency > 20
        ) {
            throw new ThreatIntelError("Invalid concurrency limit.");
        }

        const results = new Array(feeds.length);
        let nextIndex = 0;

        const worker = async () => {

            while (true) {

                const index = nextIndex++;

                if (index >= feeds.length) return;

                const feed = feeds[index];

                this.feedMetrics.received++;

                try {

                    // Feed readers are asynchronous and isolated.
                    const records = await feed.fetch();

                    if (!Array.isArray(records)) {
                        throw new ThreatIntelError(
                            "Feed must return an array."
                        );
                    }

                    const accepted = [];
                    const rejected = [];

                    for (const record of records) {

                        try {
                            accepted.push(this.ingest({
                                ...record,
                                source: feed.name
                            }));
                        } catch (error) {
                            this.feedMetrics.rejected++;

                            rejected.push({
                                error: error.message
                            });
                        }
                    }

                    results[index] = {
                        feed: feed.name,
                        accepted,
                        rejected
                    };

                } catch (error) {

                    this.feedMetrics.rejected++;

                    results[index] = {
                        feed: feed.name,
                        failure: error.message
                    };

                    this.emit("feed:failed", {
                        feed: feed.name,
                        error
                    });
                }
            }
        };

        await Promise.all(
            Array.from(
                {length: Math.min(concurrency, feeds.length)},
                () => worker()
            )
        );

        this.emit("feeds:completed", results);

        return results;
    }

    getIndicator(id) {
        return this.#indicators.get(id) || null;
    }

    search(filters = {}) {

        const now = new Date();

        return [...this.#indicators.values()]
            .filter(item => {

                if (filters.activeOnly !== false && !item.isActive(now)) {
                    return false;
                }

                if (
                    filters.type &&
                    item.type !== filters.type
                ) return false;

                if (
                    filters.intelligenceType &&
                    item.intelligenceType !== filters.intelligenceType
                ) return false;

                if (
                    filters.tag &&
                    !item.tags.has(filters.tag)
                ) return false;

                if (
                    filters.minimumConfidence !== undefined &&
                    item.confidence < filters.minimumConfidence
                ) return false;

                return true;
            })
            .sort(
                (a, b) => b.riskScore(now) - a.riskScore(now)
            );
    }

    correlate(campaignId) {

        if (!this.#campaigns.has(campaignId)) {
            throw new ThreatIntelError("Campaign not found.");
        }

        return this.search({
            activeOnly: false
        }).filter(item => item.campaignId === campaignId);
    }

    evaluateObservable(value, type) {

        const normalized = normalizeIndicator(value, type);

        return this.search().filter(
            item =>
                item.type === type &&
                item.value === normalized
        ).map(item => ({
            id: item.id,
            value: item.value,
            severity: item.severity,
            confidence: item.confidence,
            riskScore: item.riskScore(),
            source: item.source,
            tlp: item.tlp
        }));
    }

    expire() {

        const now = new Date();
        let expired = 0;

        for (const indicator of this.#indicators.values()) {

            if (
                indicator.status === Status.ACTIVE &&
                indicator.expiresAt <= now
            ) {
                indicator.status = Status.EXPIRED;
                expired++;
                this.emit("indicator:expired", indicator);
            }
        }

        return expired;
    }

    updateStatus(id, status) {

        validateEnum(status, Status, "status");

        const indicator = this.#indicators.get(id);

        if (!indicator) {
            throw new ThreatIntelError("Indicator not found.");
        }

        indicator.status = status;

        this.emit("indicator:status-changed", {
            id,
            status
        });
    }

    report() {

        const active = this.search();

        const countBy = (items, selector) =>
            items.reduce((result, item) => {
                const key = selector(item);
                result[key] = (result[key] || 0) + 1;
                return result;
            }, {});

        return {
            generatedAt: new Date().toISOString(),
            totalIndicators: this.#indicators.size,
            activeIndicators: active.length,
            threatActors: this.#actors.size,
            campaigns: this.#campaigns.size,
            intelligenceTypes: countBy(
                active,
                item => item.intelligenceType
            ),
            severities: countBy(
                active,
                item => item.severity
            ),
            priorityIndicators: active.slice(0, 10).map(item => ({
                value: item.value,
                type: item.type,
                riskScore: item.riskScore()
            })),
            feedMetrics: {...this.feedMetrics}
        };
    }

    async save(filepath) {

        const records = [...this.#indicators.values()].map(item => ({
            ...item,
            firstSeen: item.firstSeen.toISOString(),
            lastSeen: item.lastSeen.toISOString(),
            expiresAt: item.expiresAt.toISOString(),
            tags: [...item.tags],
            references: [...item.references]
        }));

        const temporary = `${filepath}.tmp`;

        await fs.writeFile(
            temporary,
            JSON.stringify(records, null, 2),
            {encoding: "utf8", mode: 0o600}
        );

        await fs.rename(temporary, filepath);
    }
}


async function main() {

    const engine = new ThreatIntelligenceEngine();

    engine.on("indicator:ingested", item => {
        console.log("INGESTED:", item.value);
    });

    engine.on("feed:failed", event => {
        console.error(
            "FEED FAILURE:",
            event.feed,
            event.error.message
        );
    });

    engine.registerActor({
        id: "ACT-001",
        name: "Example APT",
        motivation: "Espionage"
    });

    engine.registerCampaign({
        id: "CMP-001",
        name: "Northern Gateway",
        actorId: "ACT-001",
        objective: "Credential theft"
    });

    const now = new Date();

    const sampleRecords = [
        {
            value: "203.0.113.25",
            type: IndicatorType.IPV4,
            confidence: 95,
            severity: Severity.CRITICAL,
            tlp: TLP.AMBER,
            intelligenceType: IntelligenceType.TACTICAL,
            firstSeen: now,
            lastSeen: now,
            expiresAt: new Date(now.getTime() + 86400000 * 30),
            actorId: "ACT-001",
            campaignId: "CMP-001",
            tags: ["c2", "malware"]
        },
        {
            value: "malicious-example.org",
            type: IndicatorType.DOMAIN,
            confidence: 85,
            severity: Severity.HIGH,
            tlp: TLP.GREEN,
            intelligenceType: IntelligenceType.OPERATIONAL,
            firstSeen: now,
            lastSeen: now,
            expiresAt: new Date(now.getTime() + 86400000 * 15),
            actorId: "ACT-001",
            campaignId: "CMP-001",
            tags: ["phishing"]
        }
    ];

    const feeds = [
        {
            name: "Example-Feed",
            async fetch() {
                return sampleRecords;
            }
        },
        {
            name: "Unavailable-Feed",
            async fetch() {
                throw new Error("Connection timeout");
            }
        }
    ];

    await engine.ingestFeeds(feeds, 2);

    console.log("\nTACTICAL INTELLIGENCE");

    console.table(engine.search({
        intelligenceType: IntelligenceType.TACTICAL
    }).map(item => ({
        indicator: item.value,
        severity: item.severity,
        confidence: item.confidence,
        risk: item.riskScore()
    })));

    console.log("\nCAMPAIGN CORRELATION");

    console.log(
        engine.correlate("CMP-001").map(item => item.value)
    );

    console.log("\nOBSERVABLE EVALUATION");

    console.log(
        engine.evaluateObservable(
            "203.0.113.25",
            IndicatorType.IPV4
        )
    );

    console.log("\nSHARING POLICY");

    console.log(
        SharingPolicy.canShare(TLP.AMBER, "organization")
    );

    console.log("\nINTELLIGENCE REPORT");

    console.log(
        JSON.stringify(engine.report(), null, 2)
    );

    console.log("\nPERSISTENCE");

    await engine.save("./threat-intelligence.json");

    console.log("Threat intelligence persisted.");
}


if (require.main === module) {

    main().catch(error => {
        console.error("ENGINE FAILURE:", error.message);
        process.exitCode = 1;
    });
}

module.exports = {
    ThreatIntelligenceEngine,
    ThreatIndicator,
    SharingPolicy,
    normalizeIndicator,
    IntelligenceType,
    IndicatorType,
    Severity,
    TLP,
    Status
};
