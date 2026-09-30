"use strict";

/*
 * Networking Security Review
 *
 * This Node.js program models a defensive network review without performing
 * live scanning or probing. It focuses on four related but distinct areas:
 *
 *   Attack surface -> what can be reached
 *   Exposed services -> which service endpoints cross a trust boundary
 *   Insecure protocols -> whether the communication mechanism protects data
 *   Segmentation -> which network zones are allowed to communicate
 *
 * JavaScript-specific design:
 * - EventEmitter represents security-review lifecycle events.
 * - Map and Set provide explicit inventory and policy indexes.
 * - async/await models a multi-stage review pipeline.
 * - structured errors distinguish invalid configuration from findings.
 */

const { EventEmitter } = require("node:events");
const fs = require("node:fs/promises");

const ProtocolSecurity = Object.freeze({
    SECURE: "secure",
    LEGACY: "legacy",
    INSECURE: "insecure",
    CONTEXT_DEPENDENT: "context-dependent"
});

const Severity = Object.freeze({
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical"
});

class ConfigurationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ConfigurationError";
    }
}

class ReviewFinding {
    constructor({
        category,
        severity,
        asset,
        title,
        evidence,
        recommendation,
        score
    }) {
        this.category = category;
        this.severity = severity;
        this.asset = asset;
        this.title = title;
        this.evidence = evidence;
        this.recommendation = recommendation;
        this.score = score;
    }
}

class NetworkAsset {
    constructor({
        id,
        hostname,
        address,
        zone,
        owner,
        role,
        criticality,
        services
    }) {
        this.id = id;
        this.hostname = hostname;
        this.address = address;
        this.zone = zone;
        this.owner = owner;
        this.role = role;
        this.criticality = criticality;
        this.services = services;
    }

    validate() {
        if (!this.id || !this.hostname || !this.address) {
            throw new ConfigurationError(
                "Asset ID, hostname, and address are required."
            );
        }

        if (!Number.isInteger(this.criticality) ||
            this.criticality < 1 ||
            this.criticality > 5) {
            throw new ConfigurationError(
                `Invalid criticality for ${this.id}.`
            );
        }

        if (!Array.isArray(this.services)) {
            throw new ConfigurationError(
                `Services for ${this.id} must be an array.`
            );
        }

        for (const service of this.services) {
            validateService(service);
        }
    }
}

function validateService(service) {
    if (!Number.isInteger(service.port) ||
        service.port < 1 ||
        service.port > 65535) {
        throw new ConfigurationError(
            `Invalid port for ${service.protocol}.`
        );
    }

    if (!["tcp", "udp"].includes(service.transport)) {
        throw new ConfigurationError(
            `Unsupported transport: ${service.transport}`
        );
    }

    if (!service.protocol || !service.purpose) {
        throw new ConfigurationError(
            "Service protocol and purpose are required."
        );
    }

    if (service.security === ProtocolSecurity.SECURE &&
        service.encrypted !== true) {
        throw new ConfigurationError(
            `${service.protocol} cannot be marked secure without encryption.`
        );
    }
}

function severityForScore(score) {
    if (score >= 8) return Severity.CRITICAL;
    if (score >= 6) return Severity.HIGH;
    if (score >= 3) return Severity.MEDIUM;
    return Severity.LOW;
}

class AttackSurfaceReview {
    constructor(assets) {
        this.assets = assets;
        this.assetMap = new Map(assets.map(asset => [asset.id, asset]));
    }

    validate() {
        for (const asset of this.assets) {
            asset.validate();
        }

        if (this.assetMap.size !== this.assets.length) {
            throw new ConfigurationError(
                "Duplicate asset identifiers detected."
            );
        }
    }

    collectServices() {
        return this.assets.flatMap(asset =>
            asset.services.map(service => ({
                assetId: asset.id,
                asset,
                service
            }))
        );
    }

    analyze() {
        this.validate();

        const findings = [];
        const services = this.collectServices();

        const exposed = services.filter(
            ({ service }) => service.internetExposed
        );

        for (const { asset, service } of exposed) {
            if (
                service.security === ProtocolSecurity.INSECURE ||
                service.security === ProtocolSecurity.LEGACY
            ) {
                let score =
                    service.security === ProtocolSecurity.INSECURE
                        ? 8
                        : 6.5;

                if (!service.authenticated) {
                    score += 1;
                }

                findings.push(new ReviewFinding({
                    category: "insecure_protocol",
                    severity: severityForScore(Math.min(score, 10)),
                    asset: asset.id,
                    title: `Risky Internet-facing protocol: ${service.protocol}`,
                    evidence:
                        `${service.protocol}/${service.transport}:${service.port}; ` +
                        `encrypted=${service.encrypted}; ` +
                        `authenticated=${service.authenticated}`,
                    recommendation:
                        "Replace the protocol with a protected alternative " +
                        "or remove Internet exposure.",
                    score: Math.min(score, 10)
                }));
            }

            if (!service.authenticated) {
                const score = Math.min(
                    10,
                    5 + asset.criticality * 0.7
                );

                findings.push(new ReviewFinding({
                    category: "exposed_service",
                    severity: severityForScore(score),
                    asset: asset.id,
                    title: "Internet-facing service lacks authentication",
                    evidence:
                        `${service.protocol}:${service.port} crosses the " +
                        "public boundary without modeled authentication.`,
                    recommendation:
                        "Restrict access, introduce strong authentication, " +
                        "or remove public exposure.",
                    score
                }));
            }
        }

        if (exposed.length >= 4) {
            findings.push(new ReviewFinding({
                category: "attack_surface",
                severity: Severity.HIGH,
                asset: "network",
                title: "Large public service surface",
                evidence:
                    `${exposed.length} service endpoints are Internet exposed.`,
                recommendation:
                    "Review each public endpoint and remove services that do " +
                    "not have a documented public business requirement.",
                score: 7
            }));
        }

        return findings;
    }
}

class SegmentationPolicy {
    constructor({ zones, rules }) {
        this.zones = new Map(zones.map(zone => [zone.name, zone]));
        this.rules = rules;
    }

    validate() {
        if (this.zones.size !== this.rulesZoneCount()) {
            // A zone can legitimately have no rules, so this condition is not
            // treated as an error. It only demonstrates Map-based indexing.
        }

        for (const rule of this.rules) {
            if (!this.zones.has(rule.source) ||
                !this.zones.has(rule.destination)) {
                throw new ConfigurationError(
                    `Unknown zone in flow ${rule.source} -> ${rule.destination}`
                );
            }

            if (!Number.isInteger(rule.port) ||
                rule.port < 1 ||
                rule.port > 65535) {
                throw new ConfigurationError(
                    `Invalid port in rule ${rule.service}.`
                );
            }
        }
    }

    rulesZoneCount() {
        const names = new Set();

        for (const rule of this.rules) {
            names.add(rule.source);
            names.add(rule.destination);
        }

        return names.size;
    }

    allows(source, destination, port) {
        return this.rules.some(rule =>
            rule.source === source &&
            rule.destination === destination &&
            rule.port === port &&
            rule.allowed
        );
    }

    evaluate() {
        this.validate();

        const findings = [];

        for (const rule of this.rules) {
            if (!rule.allowed) {
                continue;
            }

            const destination = this.zones.get(rule.destination);

            if (
                destination.trust >= 4 &&
                [22, 3389].includes(rule.port)
            ) {
                findings.push(new ReviewFinding({
                    category: "segmentation",
                    severity: Severity.HIGH,
                    asset: rule.destination,
                    title: "Administrative service crosses protected boundary",
                    evidence:
                        `${rule.service}:${rule.port} is allowed from ` +
                        `${rule.source} to ${rule.destination}.`,
                    recommendation:
                        "Limit administrative protocols to a dedicated " +
                        "management path or explicitly authorized hosts.",
                    score: 7
                }));
            }
        }

        const protectedZones = [...this.zones.values()]
            .filter(zone => zone.trust >= 4);

        for (const source of this.zones.values()) {
            for (const destination of protectedZones) {
                if (source.name === destination.name) {
                    continue;
                }

                const inboundRules = this.rules.filter(rule =>
                    rule.source === source.name &&
                    rule.destination === destination.name &&
                    rule.allowed
                );

                /*
                 * The model does not invent a default allow. Absence of an
                 * explicit rule is therefore treated as blocked for the policy
                 * engine, which makes required flows auditable.
                 */
                if (inboundRules.length === 0) {
                    findings.push(new ReviewFinding({
                        category: "segmentation",
                        severity: Severity.HIGH,
                        asset: destination.name,
                        title: "No explicit inbound flow to protected zone",
                        evidence:
                            `${source.name} has no approved inbound flow to ` +
                            `${destination.name}.`,
                        recommendation:
                            "Document required application flows and enforce " +
                            "specific allow rules rather than broad network access.",
                        score: 6.5
                    }));
                }
            }
        }

        return findings;
    }
}

class ReviewPipeline extends EventEmitter {
    constructor({ assets, segmentation }) {
        super();
        this.assets = assets;
        this.segmentation = segmentation;
        this.findings = [];
    }

    async run() {
        this.emit("stage", "inventory-validation");

        const attackSurface = new AttackSurfaceReview(this.assets);
        const surfaceFindings = attackSurface.analyze();

        this.emit("stage", "attack-surface-analysis");

        await new Promise(resolve => setImmediate(resolve));

        const segmentationFindings = this.segmentation.evaluate();

        this.emit("stage", "segmentation-analysis");

        this.findings = [
            ...surfaceFindings,
            ...segmentationFindings
        ];

        this.findings.sort(
            (a, b) => b.score - a.score ||
                a.asset.localeCompare(b.asset)
        );

        this.emit("complete", this.findings.length);

        return this.findings;
    }
}

function buildInventory() {
    const assets = [
        new NetworkAsset({
            id: "public-web",
            hostname: "web-gateway.example.internal",
            address: "10.30.10.20",
            zone: "dmz",
            owner: "Web Platform",
            role: "Public application gateway",
            criticality: 4,
            services: [
                {
                    port: 443,
                    protocol: "HTTPS",
                    transport: "tcp",
                    purpose: "Public application",
                    security: ProtocolSecurity.SECURE,
                    authenticated: true,
                    encrypted: true,
                    internetExposed: true
                },
                {
                    port: 22,
                    protocol: "SSH",
                    transport: "tcp",
                    purpose: "Administration",
                    security: ProtocolSecurity.SECURE,
                    authenticated: true,
                    encrypted: true,
                    internetExposed: true
                }
            ]
        }),
        new NetworkAsset({
            id: "legacy-transfer",
            hostname: "transfer.example.internal",
            address: "10.30.20.25",
            zone: "user",
            owner: "Operations",
            role: "Legacy file transfer",
            criticality: 4,
            services: [
                {
                    port: 21,
                    protocol: "FTP",
                    transport: "tcp",
                    purpose: "Legacy transfer",
                    security: ProtocolSecurity.INSECURE,
                    authenticated: false,
                    encrypted: false,
                    internetExposed: true
                }
            ]
        }),
        new NetworkAsset({
            id: "application-api",
            hostname: "api.example.internal",
            address: "10.30.30.15",
            zone: "application",
            owner: "Application Team",
            role: "Internal API",
            criticality: 5,
            services: [
                {
                    port: 443,
                    protocol: "HTTPS",
                    transport: "tcp",
                    purpose: "Application API",
                    security: ProtocolSecurity.SECURE,
                    authenticated: true,
                    encrypted: true,
                    internetExposed: false
                }
            ]
        }),
        new NetworkAsset({
            id: "database",
            hostname: "db.example.internal",
            address: "10.30.40.10",
            zone: "database",
            owner: "Data Platform",
            role: "Transactional database",
            criticality: 5,
            services: [
                {
                    port: 5432,
                    protocol: "PostgreSQL",
                    transport: "tcp",
                    purpose: "Application data",
                    security: ProtocolSecurity.SECURE,
                    authenticated: true,
                    encrypted: true,
                    internetExposed: false
                }
            ]
        })
    ];

    const zones = [
        {
            name: "internet",
            trust: 1,
            purpose: "Untrusted external network"
        },
        {
            name: "user",
            trust: 2,
            purpose: "Employee endpoints"
        },
        {
            name: "dmz",
            trust: 3,
            purpose: "Public application boundary"
        },
        {
            name: "application",
            trust: 4,
            purpose: "Application services"
        },
        {
            name: "database",
            trust: 5,
            purpose: "Data services"
        },
        {
            name: "management",
            trust: 5,
            purpose: "Administrative access"
        }
    ];

    const rules = [
        {
            source: "internet",
            destination: "dmz",
            service: "HTTPS",
            port: 443,
            allowed: true
        },
        {
            source: "dmz",
            destination: "application",
            service: "HTTPS",
            port: 443,
            allowed: true
        },
        {
            source: "application",
            destination: "database",
            service: "PostgreSQL",
            port: 5432,
            allowed: true
        },
        {
            source: "user",
            destination: "management",
            service: "SSH",
            port: 22,
            allowed: true
        }
    ];

    return {
        assets,
        segmentation: new SegmentationPolicy({ zones, rules })
    };
}

function printInventory(assets) {
    console.log("\n=== NETWORK SERVICE INVENTORY ===");

    for (const asset of assets) {
        console.log(
            `\n${asset.id} | zone=${asset.zone} | ` +
            `criticality=${asset.criticality}`
        );

        for (const service of asset.services) {
            console.log(
                `  ${service.protocol}/${service.port} ` +
                `exposed=${service.internetExposed} ` +
                `encrypted=${service.encrypted} ` +
                `authenticated=${service.authenticated}`
            );
        }
    }
}

function printFindings(findings) {
    console.log("\n=== SECURITY FINDINGS ===");

    if (findings.length === 0) {
        console.log("No findings.");
        return;
    }

    for (const finding of findings) {
        console.log(
            `\n[${finding.severity.toUpperCase()}] ` +
            `${finding.category} | ${finding.asset}`
        );
        console.log(`Title: ${finding.title}`);
        console.log(`Evidence: ${finding.evidence}`);
        console.log(`Recommendation: ${finding.recommendation}`);
        console.log(`Score: ${finding.score.toFixed(1)}`);
    }
}

function calculateMetrics(assets) {
    const services = assets.flatMap(asset => asset.services);
    const publicServices = services.filter(
        service => service.internetExposed
    );

    const insecurePublic = publicServices.filter(
        service =>
            service.security === ProtocolSecurity.INSECURE ||
            service.security === ProtocolSecurity.LEGACY
    );

    return {
        assets: assets.length,
        services: services.length,
        publicServices: publicServices.length,
        insecurePublicServices: insecurePublic.length,
        encryptedServices: services.filter(
            service => service.encrypted
        ).length
    };
}

async function saveReport(findings, assets) {
    const report = {
        generatedAt: new Date().toISOString(),
        reviewedAssets: assets.length,
        reviewedServices: assets.reduce(
            (total, asset) => total + asset.services.length,
            0
        ),
        findings: findings.map(finding => ({ ...finding }))
    };

    await fs.writeFile(
        "network-security-review.json",
        JSON.stringify(report, null, 2),
        "utf8"
    );
}

async function main() {
    console.log("NETWORKING SECURITY REVIEW");
    console.log("===========================");

    const { assets, segmentation } = buildInventory();

    printInventory(assets);

    console.log("\n=== SURFACE METRICS ===");
    console.table(calculateMetrics(assets));

    const pipeline = new ReviewPipeline({
        assets,
        segmentation
    });

    pipeline.on("stage", stage => {
        console.log(`Review stage: ${stage}`);
    });

    pipeline.on("complete", count => {
        console.log(`Review complete: ${count} findings`);
    });

    const findings = await pipeline.run();

    printFindings(findings);

    await saveReport(findings, assets);

    console.log(
        "\nThe report was written to network-security-review.json."
    );
}

main().catch(error => {
    if (error instanceof ConfigurationError) {
        console.error(`Configuration error: ${error.message}`);
    } else {
        console.error("Unexpected review failure:", error);
    }

    process.exitCode = 1;
});
