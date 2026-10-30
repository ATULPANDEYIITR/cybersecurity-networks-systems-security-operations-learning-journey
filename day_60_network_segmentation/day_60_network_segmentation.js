"use strict";

/*
 * Event-driven network segmentation and traffic-policy evaluator.
 *
 * Runtime:
 *     node network_segmentation.js
 *
 * Features:
 * - VLAN and trust-zone inventory
 * - IPv4 subnet validation and overlap detection
 * - Network-boundary policy evaluation
 * - Workload-level microsegmentation
 * - Asynchronous flow processing
 * - Bounded audit history
 * - Event-based security monitoring
 * - Default-deny policy behavior
 */

const { EventEmitter } = require("node:events");
const net = require("node:net");

const Zone = Object.freeze({
    USER: "USER",
    DMZ: "DMZ",
    APPLICATION: "APPLICATION",
    DATA: "DATA",
    MANAGEMENT: "MANAGEMENT",
    INTERNET: "INTERNET",
});

const Protocol = Object.freeze({
    TCP: "TCP",
    UDP: "UDP",
});

const Action = Object.freeze({
    ALLOW: "ALLOW",
    DENY: "DENY",
});

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function validatePortRange(start, end) {
    assert(
        Number.isInteger(start) &&
        Number.isInteger(end) &&
        start >= 1 &&
        end <= 65535 &&
        start <= end,
        `Invalid port range: ${start}-${end}`
    );
}

function ipv4ToBigInt(address) {
    assert(net.isIP(address) === 4, `Invalid IPv4 address: ${address}`);

    return address
        .split(".")
        .reduce(
            (value, octet) => (value << 8n) | BigInt(Number(octet)),
            0n
        );
}

function parseCidr(cidr) {
    const parts = cidr.split("/");

    assert(parts.length === 2, `Invalid CIDR: ${cidr}`);

    const address = ipv4ToBigInt(parts[0]);
    const prefix = Number(parts[1]);

    assert(
        Number.isInteger(prefix) && prefix >= 0 && prefix <= 32,
        `Invalid CIDR prefix: ${cidr}`
    );

    const fullMask = (1n << 32n) - 1n;
    const mask = prefix === 0
        ? 0n
        : (fullMask << BigInt(32 - prefix)) & fullMask;

    const first = address & mask;
    const last = first | (fullMask ^ mask);

    assert(first === address, `CIDR contains host bits: ${cidr}`);

    return Object.freeze({ first, last, prefix });
}

function overlaps(first, second) {
    return first.first <= second.last &&
        second.first <= first.last;
}

function contains(range, address) {
    const value = ipv4ToBigInt(address);
    return value >= range.first && value <= range.last;
}

class NetworkInventory {
    constructor() {
        this.segments = new Map();
        this.endpoints = new Map();
        this.vlanIds = new Set();
        this.addresses = new Set();
    }

    addSegment(segment) {
        assert(segment.id && segment.name, "Segment identity is required.");
        assert(
            Number.isInteger(segment.vlanId) &&
            segment.vlanId >= 1 &&
            segment.vlanId <= 4094,
            "VLAN ID must be between 1 and 4094."
        );

        assert(
            Object.values(Zone).includes(segment.zone),
            `Unknown trust zone: ${segment.zone}`
        );

        assert(!this.segments.has(segment.id), "Duplicate segment ID.");
        assert(!this.vlanIds.has(segment.vlanId), "Duplicate VLAN ID.");

        const range = parseCidr(segment.cidr);

        for (const existing of this.segments.values()) {
            assert(
                !overlaps(range, existing.range),
                `Overlapping network ranges: ${segment.cidr}`
            );
        }

        const stored = Object.freeze({
            ...segment,
            range,
        });

        this.segments.set(segment.id, stored);
        this.vlanIds.add(segment.vlanId);
    }

    addEndpoint(endpoint) {
        assert(endpoint.id, "Endpoint ID is required.");
        assert(!this.endpoints.has(endpoint.id), "Duplicate endpoint ID.");
        assert(
            endpoint.labels && endpoint.labels.role,
            "Endpoint role label is required."
        );

        const segment = this.segments.get(endpoint.segmentId);
        assert(segment, `Unknown segment: ${endpoint.segmentId}`);

        assert(
            contains(segment.range, endpoint.address),
            `Endpoint address ${endpoint.address} is outside its subnet.`
        );

        assert(
            !this.addresses.has(endpoint.address),
            `Duplicate IP address: ${endpoint.address}`
        );

        const stored = Object.freeze({
            ...endpoint,
            labels: Object.freeze({ ...endpoint.labels }),
        });

        this.endpoints.set(endpoint.id, stored);
        this.addresses.add(endpoint.address);
    }

    getEndpoint(id) {
        const endpoint = this.endpoints.get(id);
        assert(endpoint, `Unknown endpoint: ${id}`);
        return endpoint;
    }

    getSegment(id) {
        const segment = this.segments.get(id);
        assert(segment, `Unknown segment: ${id}`);
        return segment;
    }
}

function validateRule(rule, micro = false) {
    assert(rule.id, "Rule ID is required.");
    assert(Number.isInteger(rule.priority) && rule.priority >= 0);
    assert(
        Object.values(Protocol).includes(rule.protocol),
        "Unsupported protocol."
    );
    assert(
        Object.values(Action).includes(rule.action),
        "Unsupported policy action."
    );

    validatePortRange(rule.portFrom, rule.portTo);

    if (micro) {
        assert(rule.sourceRole, "Source workload selector is required.");
        assert(
            rule.destinationRole,
            "Destination workload selector is required."
        );
    } else {
        assert(
            Object.values(Zone).includes(rule.sourceZone),
            "Invalid source trust zone."
        );
        assert(
            Object.values(Zone).includes(rule.destinationZone),
            "Invalid destination trust zone."
        );
    }
}

class TrafficPolicyEngine extends EventEmitter {
    constructor(inventory, networkRules, microRules, options = {}) {
        super();

        this.inventory = inventory;
        this.maxAuditEntries = options.maxAuditEntries ?? 10000;

        assert(
            Number.isInteger(this.maxAuditEntries) &&
            this.maxAuditEntries > 0,
            "Audit capacity must be positive."
        );

        this.networkRules = this.prepareRules(networkRules, false);
        this.microRules = this.prepareRules(microRules, true);

        this.seenFlowIds = new Set();
        this.metrics = new Map();
        this.audit = [];
    }

    prepareRules(rules, micro) {
        const identifiers = new Set();

        const prepared = rules.map((rule) => {
            validateRule(rule, micro);
            assert(
                !identifiers.has(rule.id),
                `Duplicate rule ID: ${rule.id}`
            );
            identifiers.add(rule.id);

            return Object.freeze({ ...rule });
        });

        return prepared.sort(
            (a, b) => a.priority - b.priority || a.id.localeCompare(b.id)
        );
    }

    findNetworkRule(sourceZone, destinationZone, protocol, port) {
        return this.networkRules.find((rule) =>
            rule.sourceZone === sourceZone &&
            rule.destinationZone === destinationZone &&
            rule.protocol === protocol &&
            port >= rule.portFrom &&
            port <= rule.portTo
        );
    }

    findMicroRule(source, destination, protocol, port) {
        const sourceRole = source.labels.role;
        const destinationRole = destination.labels.role;

        return this.microRules.find((rule) =>
            (rule.sourceRole === "*" ||
                rule.sourceRole === sourceRole) &&
            (rule.destinationRole === "*" ||
                rule.destinationRole === destinationRole) &&
            rule.protocol === protocol &&
            port >= rule.portFrom &&
            port <= rule.portTo
        );
    }

    async evaluateFlow(flow) {
        assert(flow && flow.id, "Flow ID is required.");
        assert(
            Object.values(Protocol).includes(flow.protocol),
            "Unsupported flow protocol."
        );
        validatePortRange(flow.port, flow.port);

        assert(
            !this.seenFlowIds.has(flow.id),
            `Duplicate flow ID: ${flow.id}`
        );

        const source = this.inventory.getEndpoint(flow.sourceId);
        const destination = this.inventory.getEndpoint(
            flow.destinationId
        );

        const sourceSegment = this.inventory.getSegment(
            source.segmentId
        );

        const destinationSegment = this.inventory.getSegment(
            destination.segmentId
        );

        this.seenFlowIds.add(flow.id);

        // Yield to the event loop so batches can be processed asynchronously.
        await new Promise((resolve) => setImmediate(resolve));

        const sameSegment =
            source.segmentId === destination.segmentId;

        let trafficClass;

        if (
            sourceSegment.zone === Zone.INTERNET ||
            destinationSegment.zone === Zone.INTERNET
        ) {
            trafficClass = "NORTH_SOUTH";
        } else if (sameSegment) {
            trafficClass = "INTRA_SEGMENT";
        } else {
            trafficClass = "EAST_WEST";
        }

        const networkRule = sameSegment
            ? null
            : this.findNetworkRule(
                sourceSegment.zone,
                destinationSegment.zone,
                flow.protocol,
                flow.port
            );

        const networkResult = sameSegment
            ? "NOT_REQUIRED"
            : networkRule?.action ?? Action.DENY;

        const microRule = this.findMicroRule(
            source,
            destination,
            flow.protocol,
            flow.port
        );

        const microResult = microRule?.action ?? Action.DENY;

        const allowed =
            networkResult === "NOT_REQUIRED" ||
            networkResult === Action.ALLOW;

        const finalAllowed = allowed && microResult === Action.ALLOW;

        let reason;

        if (!allowed) {
            reason = "NETWORK_BOUNDARY_DENY";
        } else if (microResult === Action.DENY) {
            reason = "MICROSEGMENTATION_DEFAULT_DENY";
        } else {
            reason = "BOTH_POLICY_LAYERS_ALLOW";
        }

        const decision = Object.freeze({
            flowId: flow.id,
            trafficClass,
            networkResult,
            microResult,
            allowed: finalAllowed,
            reason,
            sourceId: source.id,
            destinationId: destination.id,
        });

        this.recordDecision(decision);
        this.emit("decision", decision);

        return decision;
    }

    recordDecision(decision) {
        const key = [
            decision.trafficClass,
            decision.allowed ? "ALLOW" : "DENY",
        ].join(":");

        this.metrics.set(key, (this.metrics.get(key) ?? 0) + 1);

        this.audit.push(decision);

        // Bound retained memory in long-running simulations.
        if (this.audit.length > this.maxAuditEntries) {
            this.audit.shift();
        }
    }

    async evaluateBatch(flows, concurrency = 4) {
        assert(Array.isArray(flows), "Flows must be an array.");
        assert(
            Number.isInteger(concurrency) &&
            concurrency >= 1 &&
            concurrency <= 32,
            "Concurrency must be between 1 and 32."
        );

        const results = new Array(flows.length);
        let cursor = 0;

        const worker = async () => {
            while (true) {
                const index = cursor++;

                if (index >= flows.length) {
                    return;
                }

                try {
                    results[index] = await this.evaluateFlow(flows[index]);
                } catch (error) {
                    results[index] = Object.freeze({
                        flowId: flows[index]?.id ?? "UNKNOWN",
                        allowed: false,
                        error: error.message,
                    });

                    this.emit("evaluationError", results[index]);
                }
            }
        };

        const workers = Array.from(
            { length: Math.min(concurrency, flows.length) },
            () => worker()
        );

        await Promise.all(workers);
        return results;
    }
}

function createDemoEnvironment() {
    const inventory = new NetworkInventory();

    const segments = [
        {
            id: "users",
            name: "User VLAN",
            vlanId: 10,
            cidr: "10.10.0.0/24",
            zone: Zone.USER,
        },
        {
            id: "dmz",
            name: "DMZ",
            vlanId: 20,
            cidr: "10.20.0.0/24",
            zone: Zone.DMZ,
        },
        {
            id: "apps",
            name: "Application VLAN",
            vlanId: 30,
            cidr: "10.30.0.0/24",
            zone: Zone.APPLICATION,
        },
        {
            id: "data",
            name: "Database VLAN",
            vlanId: 40,
            cidr: "10.40.0.0/24",
            zone: Zone.DATA,
        },
        {
            id: "management",
            name: "Management VLAN",
            vlanId: 50,
            cidr: "10.50.0.0/24",
            zone: Zone.MANAGEMENT,
        },
        {
            id: "internet",
            name: "External Test VLAN",
            vlanId: 900,
            cidr: "198.51.100.0/24",
            zone: Zone.INTERNET,
        },
    ];

    for (const segment of segments) {
        inventory.addSegment(segment);
    }

    const endpoints = [
        {
            id: "workstation-01",
            segmentId: "users",
            address: "10.10.0.10",
            labels: { role: "employee" },
        },
        {
            id: "web-01",
            segmentId: "dmz",
            address: "10.20.0.10",
            labels: { role: "web" },
        },
        {
            id: "api-01",
            segmentId: "apps",
            address: "10.30.0.10",
            labels: { role: "api" },
        },
        {
            id: "api-02",
            segmentId: "apps",
            address: "10.30.0.11",
            labels: { role: "api" },
        },
        {
            id: "db-01",
            segmentId: "data",
            address: "10.40.0.10",
            labels: { role: "database" },
        },
        {
            id: "admin-01",
            segmentId: "management",
            address: "10.50.0.10",
            labels: { role: "administrator" },
        },
        {
            id: "external-client",
            segmentId: "internet",
            address: "198.51.100.10",
            labels: { role: "internet-client" },
        },
    ];

    for (const endpoint of endpoints) {
        inventory.addEndpoint(endpoint);
    }

    const networkRules = [
        {
            id: "NET-001",
            priority: 10,
            sourceZone: Zone.INTERNET,
            destinationZone: Zone.DMZ,
            protocol: Protocol.TCP,
            portFrom: 443,
            portTo: 443,
            action: Action.ALLOW,
        },
        {
            id: "NET-002",
            priority: 20,
            sourceZone: Zone.USER,
            destinationZone: Zone.DMZ,
            protocol: Protocol.TCP,
            portFrom: 443,
            portTo: 443,
            action: Action.ALLOW,
        },
        {
            id: "NET-003",
            priority: 30,
            sourceZone: Zone.DMZ,
            destinationZone: Zone.APPLICATION,
            protocol: Protocol.TCP,
            portFrom: 8443,
            portTo: 8443,
            action: Action.ALLOW,
        },
        {
            id: "NET-004",
            priority: 40,
            sourceZone: Zone.APPLICATION,
            destinationZone: Zone.DATA,
            protocol: Protocol.TCP,
            portFrom: 5432,
            portTo: 5432,
            action: Action.ALLOW,
        },
        {
            id: "NET-005",
            priority: 50,
            sourceZone: Zone.MANAGEMENT,
            destinationZone: Zone.APPLICATION,
            protocol: Protocol.TCP,
            portFrom: 22,
            portTo: 22,
            action: Action.ALLOW,
        },
    ];

    const microRules = [
        {
            id: "MICRO-001",
            priority: 10,
            sourceRole: "internet-client",
            destinationRole: "web",
            protocol: Protocol.TCP,
            portFrom: 443,
            portTo: 443,
            action: Action.ALLOW,
        },
        {
            id: "MICRO-002",
            priority: 20,
            sourceRole: "employee",
            destinationRole: "web",
            protocol: Protocol.TCP,
            portFrom: 443,
            portTo: 443,
            action: Action.ALLOW,
        },
        {
            id: "MICRO-003",
            priority: 30,
            sourceRole: "web",
            destinationRole: "api",
            protocol: Protocol.TCP,
            portFrom: 8443,
            portTo: 8443,
            action: Action.ALLOW,
        },
        {
            id: "MICRO-004",
            priority: 40,
            sourceRole: "api",
            destinationRole: "database",
            protocol: Protocol.TCP,
            portFrom: 5432,
            portTo: 5432,
            action: Action.ALLOW,
        },
        {
            id: "MICRO-005",
            priority: 50,
            sourceRole: "administrator",
            destinationRole: "api",
            protocol: Protocol.TCP,
            portFrom: 22,
            portTo: 22,
            action: Action.ALLOW,
        },
    ];

    return new TrafficPolicyEngine(
        inventory,
        networkRules,
        microRules,
        { maxAuditEntries: 1000 }
    );
}

async function main() {
    const engine = createDemoEnvironment();

    engine.on("decision", (decision) => {
        console.log(
            `[${decision.flowId}] ` +
            `${decision.trafficClass} ` +
            `${decision.allowed ? "ALLOW" : "DENY"} ` +
            `network=${decision.networkResult} ` +
            `micro=${decision.microResult}`
        );
    });

    engine.on("evaluationError", (error) => {
        console.error(
            `[${error.flowId}] Evaluation error: ${error.error}`
        );
    });

    const flows = [
        {
            id: "FLOW-001",
            sourceId: "external-client",
            destinationId: "web-01",
            protocol: Protocol.TCP,
            port: 443,
        },
        {
            id: "FLOW-002",
            sourceId: "workstation-01",
            destinationId: "web-01",
            protocol: Protocol.TCP,
            port: 443,
        },
        {
            id: "FLOW-003",
            sourceId: "web-01",
            destinationId: "api-01",
            protocol: Protocol.TCP,
            port: 8443,
        },
        {
            id: "FLOW-004",
            sourceId: "api-01",
            destinationId: "db-01",
            protocol: Protocol.TCP,
            port: 5432,
        },
        {
            id: "FLOW-005",
            sourceId: "web-01",
            destinationId: "db-01",
            protocol: Protocol.TCP,
            port: 5432,
        },
        {
            id: "FLOW-006",
            sourceId: "api-01",
            destinationId: "api-02",
            protocol: Protocol.TCP,
            port: 8080,
        },
        {
            id: "FLOW-007",
            sourceId: "admin-01",
            destinationId: "api-01",
            protocol: Protocol.TCP,
            port: 22,
        },
    ];

    const results = await engine.evaluateBatch(flows, 3);

    const allowed = results.filter(
        (result) => result.allowed === true
    ).length;

    const denied = results.length - allowed;

    console.log("\nTraffic report");
    console.log(`Processed: ${results.length}`);
    console.log(`Allowed:   ${allowed}`);
    console.log(`Denied:    ${denied}`);
    console.log("Metrics:", Object.fromEntries(engine.metrics));

    assert(results.length === 7, "Unexpected evaluation count.");
    assert(allowed === 5, "Unexpected allowed-flow count.");
    assert(denied === 2, "Unexpected denied-flow count.");
}

main().catch((error) => {
    console.error(`Fatal error: ${error.message}`);
    process.exitCode = 1;
});
