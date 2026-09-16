"use strict";

/*
 * ARP: Address Resolution Protocol
 *
 * This standalone JavaScript program demonstrates:
 * - IPv4-to-MAC resolution
 * - ARP requests and replies
 * - ARP cache behavior
 * - Same-subnet reasoning
 * - Gratuitous ARP
 * - ARP poisoning concepts
 * - Passive conflict detection
 * - Wireshark-oriented analysis
 * - A safe simulated LAN
 *
 * No real ARP packets are transmitted.
 */

// ---------------------------------------------------------------------------
// 1. Utility functions
// ---------------------------------------------------------------------------

function printSection(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function normalizeMac(macAddress) {
    const parts = macAddress.trim().toLowerCase().split(":");

    if (
        parts.length !== 6 ||
        parts.some((part) => !/^[0-9a-f]{2}$/.test(part))
    ) {
        throw new Error(`Invalid MAC address: ${macAddress}`);
    }

    return parts.join(":");
}

function validateIPv4(ipAddress) {
    const parts = ipAddress.split(".");

    if (
        parts.length !== 4 ||
        parts.some(
            (part) =>
                !/^\d+$/.test(part) ||
                Number(part) < 0 ||
                Number(part) > 255
        )
    ) {
        throw new Error(`Invalid IPv4 address: ${ipAddress}`);
    }

    return parts.map(Number).join(".");
}

// ---------------------------------------------------------------------------
// 2. IPv4 subnet calculations
// ---------------------------------------------------------------------------

function ipv4ToInteger(ipAddress) {
    const parts = validateIPv4(ipAddress)
        .split(".")
        .map(Number);

    return (
        ((parts[0] << 24) |
            (parts[1] << 16) |
            (parts[2] << 8) |
            parts[3]) >>> 0
    );
}

function networkAddress(ipAddress, prefixLength) {
    if (prefixLength < 0 || prefixLength > 32) {
        throw new Error("Prefix length must be between 0 and 32.");
    }

    const ip = ipv4ToInteger(ipAddress);
    const mask =
        prefixLength === 0
            ? 0
            : (0xffffffff << (32 - prefixLength)) >>> 0;

    const network = (ip & mask) >>> 0;

    return [
        network >>> 24,
        (network >>> 16) & 255,
        (network >>> 8) & 255,
        network & 255,
    ].join(".");
}

function sameSubnet(firstIp, secondIp, prefixLength) {
    return (
        networkAddress(firstIp, prefixLength) ===
        networkAddress(secondIp, prefixLength)
    );
}

// ---------------------------------------------------------------------------
// 3. ARP packet representation
// ---------------------------------------------------------------------------

const ArpOperation = Object.freeze({
    REQUEST: 1,
    REPLY: 2,
});

class ArpPacket {
    constructor(
        operation,
        senderMac,
        senderIp,
        targetMac,
        targetIp
    ) {
        if (
            operation !== ArpOperation.REQUEST &&
            operation !== ArpOperation.REPLY
        ) {
            throw new Error("Unsupported ARP operation.");
        }

        this.operation = operation;
        this.senderMac = normalizeMac(senderMac);
        this.senderIp = validateIPv4(senderIp);
        this.targetMac = normalizeMac(targetMac);
        this.targetIp = validateIPv4(targetIp);
    }

    operationName() {
        return this.operation === ArpOperation.REQUEST
            ? "REQUEST"
            : "REPLY";
    }

    describe() {
        return (
            `ARP ${this.operationName()}: ` +
            `${this.senderIp} (${this.senderMac}) -> ` +
            `${this.targetIp} (${this.targetMac})`
        );
    }
}

// ---------------------------------------------------------------------------
// 4. ARP cache
// ---------------------------------------------------------------------------

const CacheState = Object.freeze({
    REACHABLE: "reachable",
    STALE: "stale",
    STATIC: "static",
});

class ArpCache {
    constructor(reachableTimeoutMs = 60000) {
        this.entries = new Map();
        this.reachableTimeoutMs = reachableTimeoutMs;
    }

    add(ipAddress, macAddress, state = CacheState.REACHABLE) {
        const ip = validateIPv4(ipAddress);
        const mac = normalizeMac(macAddress);

        this.entries.set(ip, {
            ipAddress: ip,
            macAddress: mac,
            state,
            learnedAt: Date.now(),
        });
    }

    lookup(ipAddress) {
        const ip = validateIPv4(ipAddress);
        const entry = this.entries.get(ip);

        if (!entry) {
            return null;
        }

        if (
            entry.state === CacheState.REACHABLE &&
            Date.now() - entry.learnedAt > this.reachableTimeoutMs
        ) {
            entry.state = CacheState.STALE;
        }

        return entry;
    }

    remove(ipAddress) {
        return this.entries.delete(validateIPv4(ipAddress));
    }

    print() {
        if (this.entries.size === 0) {
            console.log("(empty ARP cache)");
            return;
        }

        console.log(
            `${"IPv4".padEnd(18)}` +
            `${"MAC".padEnd(20)}` +
            `${"State".padEnd(12)}` +
            "Age(ms)"
        );

        console.log("-".repeat(58));

        const now = Date.now();

        for (const entry of this.entries.values()) {
            console.log(
                `${entry.ipAddress.padEnd(18)}` +
                `${entry.macAddress.padEnd(20)}` +
                `${entry.state.padEnd(12)}` +
                `${now - entry.learnedAt}`
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Host and simulated LAN
// ---------------------------------------------------------------------------

class Host {
    constructor(name, ipAddress, macAddress) {
        this.name = name;
        this.ipAddress = validateIPv4(ipAddress);
        this.macAddress = normalizeMac(macAddress);
    }
}

const BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";
const ZERO_MAC = "00:00:00:00:00:00";

class SimulatedLan {
    constructor(subnetPrefix = 24) {
        this.subnetPrefix = subnetPrefix;
        this.hosts = new Map();
        this.caches = new Map();
    }

    addHost(host) {
        this.hosts.set(host.ipAddress, host);
        this.caches.set(host.ipAddress, new ArpCache());
    }

    sendArpRequest(requesterIp, targetIp) {
        const requester = this.hosts.get(requesterIp);

        if (!requester) {
            throw new Error(`Unknown requester: ${requesterIp}`);
        }

        if (!sameSubnet(requesterIp, targetIp, this.subnetPrefix)) {
            console.log(
                `ARP should not directly resolve ${targetIp} from ` +
                `${requesterIp} when the destinations are on different subnets.`
            );
            return null;
        }

        console.log(
            `${requester.name} broadcasts: ` +
            `Who has ${targetIp}? Tell ${requesterIp}`
        );

        console.log(`Ethernet destination: ${BROADCAST_MAC}`);

        const target = this.hosts.get(targetIp);

        if (!target) {
            console.log("No host answers.");
            return null;
        }

        const reply = new ArpPacket(
            ArpOperation.REPLY,
            target.macAddress,
            target.ipAddress,
            requester.macAddress,
            requester.ipAddress
        );

        this.caches
            .get(requesterIp)
            .add(target.ipAddress, target.macAddress);

        console.log(
            `${target.name} replies: ` +
            `${target.ipAddress} is at ${target.macAddress}`
        );

        return reply;
    }

    resolveMac(requesterIp, targetIp) {
        const cache = this.caches.get(requesterIp);

        if (!cache) {
            throw new Error(`No cache exists for ${requesterIp}`);
        }

        const cached = cache.lookup(targetIp);

        if (cached && cached.state !== CacheState.STALE) {
            console.log(
                `Cache hit: ${targetIp} -> ${cached.macAddress}`
            );
            return cached.macAddress;
        }

        console.log(`Cache miss: ${targetIp}`);

        const reply = this.sendArpRequest(requesterIp, targetIp);

        return reply ? reply.senderMac : null;
    }
}

// ---------------------------------------------------------------------------
// 6. Basic demonstrations
// ---------------------------------------------------------------------------

function demonstrateBasics() {
    printSection("1. ARP fundamentals");

    console.log(`
ARP maps an IPv4 address to a MAC address when a local Ethernet sender
needs a Layer 2 destination.

Typical request:

    Who has 192.168.1.20?
    Tell 192.168.1.10.

The request is normally broadcast because the requester does not know
the destination MAC.

Typical reply:

    192.168.1.20 is at aa:bb:cc:dd:ee:20

The reply can then be stored in an ARP cache.
`);
}

function demonstrateValidation() {
    printSection("2. Validation");

    console.log(
        "MAC:",
        normalizeMac("AA:BB:CC:DD:EE:FF")
    );

    console.log(
        "IPv4:",
        validateIPv4("192.168.1.10")
    );

    for (const value of ["AA:BB:CC", "not-a-mac"]) {
        try {
            normalizeMac(value);
        } catch (error) {
            console.log("Rejected:", value, "|", error.message);
        }
    }

    for (const value of ["999.1.1.1", "192.168.1.999"]) {
        try {
            validateIPv4(value);
        } catch (error) {
            console.log("Rejected:", value, "|", error.message);
        }
    }
}

function demonstratePackets() {
    printSection("3. ARP packets");

    const request = new ArpPacket(
        ArpOperation.REQUEST,
        "02:00:00:00:00:10",
        "192.168.1.10",
        ZERO_MAC,
        "192.168.1.20"
    );

    const reply = new ArpPacket(
        ArpOperation.REPLY,
        "02:00:00:00:00:20",
        "192.168.1.20",
        "02:00:00:00:00:10",
        "192.168.1.10"
    );

    console.log(request.describe());
    console.log(reply.describe());
}

function demonstrateSubnetLogic() {
    printSection("4. Subnet reasoning");

    const tests = [
        ["192.168.1.10", "192.168.1.20", 24],
        ["192.168.1.10", "192.168.2.20", 24],
        ["10.0.0.10", "10.0.0.11", 24],
    ];

    for (const [first, second, prefix] of tests) {
        console.log(
            `${first} and ${second} /${prefix}:`,
            sameSubnet(first, second, prefix)
        );
    }

    console.log(`
For a remote destination, the local host generally resolves the MAC
address of its next-hop router rather than the remote Internet host.
`);
}

function demonstrateCache() {
    printSection("5. ARP cache");

    const cache = new ArpCache();

    cache.add(
        "192.168.1.1",
        "02:00:00:00:00:01",
        CacheState.STATIC
    );

    cache.add(
        "192.168.1.20",
        "02:00:00:00:00:20",
        CacheState.REACHABLE
    );

    cache.print();

    console.log(
        "\nLookup:",
        cache.lookup("192.168.1.20")
    );

    console.log(
        "\nUnknown host:",
        cache.lookup("192.168.1.99")
    );
}

function demonstrateLan() {
    printSection("6. Simulated LAN");

    const lan = new SimulatedLan(24);

    const alice = new Host(
        "Alice",
        "192.168.1.10",
        "02:00:00:00:00:10"
    );

    const bob = new Host(
        "Bob",
        "192.168.1.20",
        "02:00:00:00:00:20"
    );

    const router = new Host(
        "Router",
        "192.168.1.1",
        "02:00:00:00:00:01"
    );

    lan.addHost(alice);
    lan.addHost(bob);
    lan.addHost(router);

    lan.resolveMac(alice.ipAddress, bob.ipAddress);

    // Second lookup demonstrates the cache avoiding another ARP request.
    lan.resolveMac(alice.ipAddress, bob.ipAddress);

    console.log("\nAlice cache:");
    lan.caches.get(alice.ipAddress).print();

    console.log("\nAlice resolves the gateway:");
    lan.resolveMac(alice.ipAddress, router.ipAddress);
}

// ---------------------------------------------------------------------------
// 7. Gratuitous ARP
// ---------------------------------------------------------------------------

function createGratuitousArp(host) {
    return new ArpPacket(
        ArpOperation.REQUEST,
        host.macAddress,
        host.ipAddress,
        ZERO_MAC,
        host.ipAddress
    );
}

function demonstrateGratuitousArp() {
    printSection("7. Gratuitous ARP");

    const host = new Host(
        "FailoverServer",
        "192.168.1.50",
        "02:00:00:00:00:50"
    );

    const packet = createGratuitousArp(host);

    console.log(packet.describe());

    console.log(`
Legitimate uses can include duplicate-address detection and announcing
a changed MAC address after failover.

Because unsolicited ARP information can influence neighboring caches,
unexpected gratuitous ARP traffic can also be useful for monitoring.
`);
}

// ---------------------------------------------------------------------------
// 8. Passive ARP anomaly detection
// ---------------------------------------------------------------------------

class ArpSecurityMonitor {
    constructor() {
        this.ipToMacs = new Map();
    }

    observe(packet) {
        if (!this.ipToMacs.has(packet.senderIp)) {
            this.ipToMacs.set(packet.senderIp, new Set());
        }

        const macs = this.ipToMacs.get(packet.senderIp);
        const previousSize = macs.size;

        macs.add(packet.senderMac);

        if (macs.size > previousSize && macs.size > 1) {
            return {
                ipAddress: packet.senderIp,
                macAddresses: [...macs].sort(),
                message:
                    `Possible ARP anomaly: ${packet.senderIp} ` +
                    "has multiple observed MAC addresses.",
            };
        }

        return null;
    }
}

function demonstratePoisoningConcept() {
    printSection("8. ARP poisoning concepts");

    console.log(`
ARP does not cryptographically authenticate the assertion:

    IPv4 address X is owned by MAC address Y.

ARP poisoning or ARP spoofing can abuse this weakness by causing a host
to associate an important IP address, such as a gateway, with an
unexpected MAC address.

Possible effects include traffic interception or disruption.

This program does not transmit forged ARP packets. It only models the
observation that defenders can use to detect suspicious changes.
`);

    const monitor = new ArpSecurityMonitor();

    const legitimate = new ArpPacket(
        ArpOperation.REPLY,
        "02:00:00:00:00:01",
        "192.168.1.1",
        "02:00:00:00:00:10",
        "192.168.1.10"
    );

    const conflicting = new ArpPacket(
        ArpOperation.REPLY,
        "02:00:00:00:00:99",
        "192.168.1.1",
        "02:00:00:00:00:10",
        "192.168.1.10"
    );

    for (const packet of [legitimate, conflicting]) {
        console.log(packet.describe());

        const alert = monitor.observe(packet);

        if (alert) {
            console.log("ALERT:", alert.message);
            console.log(
                "Observed MACs:",
                alert.macAddresses.join(", ")
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 9. Event-driven example
// ---------------------------------------------------------------------------

class ArpEventBus {
    constructor() {
        this.listeners = new Map();
    }

    on(eventName, listener) {
        if (!this.listeners.has(eventName)) {
            this.listeners.set(eventName, []);
        }

        this.listeners.get(eventName).push(listener);
    }

    emit(eventName, eventData) {
        const listeners = this.listeners.get(eventName) || [];

        for (const listener of listeners) {
            listener(eventData);
        }
    }
}

function demonstrateEvents() {
    printSection("9. Event-driven ARP monitoring");

    const eventBus = new ArpEventBus();

    eventBus.on("arp", (packet) => {
        console.log(
            `Event listener received: ${packet.describe()}`
        );
    });

    eventBus.on("arp-alert", (alert) => {
        console.log(
            `Security event: ${alert.message}`
        );
    });

    const monitor = new ArpSecurityMonitor();

    const packets = [
        new ArpPacket(
            ArpOperation.REPLY,
            "02:00:00:00:00:01",
            "192.168.1.1",
            "02:00:00:00:00:10",
            "192.168.1.10"
        ),
        new ArpPacket(
            ArpOperation.REPLY,
            "02:00:00:00:00:99",
            "192.168.1.1",
            "02:00:00:00:00:10",
            "192.168.1.10"
        ),
    ];

    for (const packet of packets) {
        eventBus.emit("arp", packet);

        const alert = monitor.observe(packet);

        if (alert) {
            eventBus.emit("arp-alert", alert);
        }
    }
}

// ---------------------------------------------------------------------------
// 10. Wireshark study reference
// ---------------------------------------------------------------------------

function wiresharkReference() {
    printSection("10. Wireshark reference");

    console.log(`
Useful Wireshark display filters:

    arp
    arp.opcode == 1
    arp.opcode == 2
    arp.src.proto_ipv4 == 192.168.1.1
    arp.dst.proto_ipv4 == 192.168.1.20
    arp.src.hw_mac == 02:00:00:00:00:01
    eth.dst == ff:ff:ff:ff:ff:ff && arp

When inspecting an ARP request, examine:

    Ethernet destination
    Ethernet source
    ARP opcode
    Sender MAC
    Sender IPv4
    Target MAC
    Target IPv4

When inspecting a possible anomaly, compare sender IPv4 and sender MAC
across several packets rather than interpreting one packet in isolation.
`);
}

// ---------------------------------------------------------------------------
// 11. Performance and security considerations
// ---------------------------------------------------------------------------

function considerations() {
    printSection("11. Performance and security");

    console.log(`
Performance:

    Map lookup:
        Average O(1)

    Processing n captured ARP observations:
        Time: O(n)

    Stored unique IP/MAC relationships:
        Space: O(k)

where k is the number of distinct mappings retained.

Security:

- Monitor unexpected gateway MAC changes.
- Investigate repeated unsolicited ARP replies.
- Watch for excessive ARP traffic.
- Consider DHCP snooping and Dynamic ARP Inspection where supported.
- Segment networks appropriately.
- Use authenticated application protocols such as TLS.
- Treat IP/MAC conflicts as investigation signals, not automatic proof.

JavaScript is particularly useful here for modeling event-driven monitoring
logic, cache state, validation, and application-level processing.
`);
}

// ---------------------------------------------------------------------------
// 12. Main
// ---------------------------------------------------------------------------

function main() {
    console.log("ARP STUDY PROGRAM");
    console.log("Safe simulation of IPv4-to-MAC resolution");

    demonstrateBasics();
    demonstrateValidation();
    demonstratePackets();
    demonstrateSubnetLogic();
    demonstrateCache();
    demonstrateLan();
    demonstrateGratuitousArp();
    demonstratePoisoningConcept();
    demonstrateEvents();
    wiresharkReference();
    considerations();

    printSection("Program complete");
    console.log(
        "No real ARP packets were transmitted by this program."
    );
}

main();
