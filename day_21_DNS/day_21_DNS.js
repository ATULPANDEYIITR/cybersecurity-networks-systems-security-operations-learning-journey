"use strict";

/*
 * DNS: Resolution Process, Recursive Queries, Authoritative Servers,
 * Records, and Caching
 *
 * This standalone JavaScript file complements the Python implementation.
 * It demonstrates DNS using:
 *   - Node.js DNS APIs
 *   - asynchronous resolution
 *   - promises
 *   - custom TTL-aware caching
 *   - DNS record inspection
 *   - domain validation
 *   - DNS query construction
 *   - DNS header parsing
 *   - simulated recursive resolution
 *   - performance measurements
 *
 * Run with:
 *   node dns-study.js
 *
 * No external npm packages are required.
 *
 * Note:
 * Network DNS examples depend on the machine's DNS configuration and
 * Internet/network availability. The simulated examples work without
 * network access.
 */

const dns = require("node:dns");
const { performance } = require("node:perf_hooks");

// ---------------------------------------------------------------------------
// SECTION 1: BASIC TERMINOLOGY
// ---------------------------------------------------------------------------

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function subsection(title) {
    console.log("\n" + "-".repeat(78));
    console.log(title);
    console.log("-".repeat(78));
}

function explainBasics() {
    section("1. DNS FUNDAMENTALS");

    const concepts = {
        DNS: "A hierarchical naming system that maps names to network-related information.",
        Resolver: "A component that obtains DNS answers on behalf of a client.",
        RecursiveResolver: "A resolver that obtains the final answer for the requesting client.",
        AuthoritativeServer: "A DNS server that holds authoritative data for a zone.",
        Zone: "An administratively managed portion of the DNS namespace.",
        TTL: "The time for which cached DNS data may normally be reused.",
        Record: "A DNS data item such as A, AAAA, MX, NS, CNAME, or TXT.",
        Root: "The top of the DNS hierarchy, represented by the root label.",
        TLD: "A top-level domain such as .com or .org."
    };

    for (const [name, description] of Object.entries(concepts)) {
        console.log(`${name.padEnd(20)} ${description}`);
    }

    console.log("\nExample:");
    console.log("www.example.com.");
    console.log("  www     -> host/service label");
    console.log("  example -> registered-domain label");
    console.log("  com     -> TLD");
    console.log("  .       -> DNS root");
}


// ---------------------------------------------------------------------------
// SECTION 2: DOMAIN NORMALIZATION AND VALIDATION
// ---------------------------------------------------------------------------

function normalizeDomain(name) {
    if (typeof name !== "string") {
        throw new TypeError("Domain name must be a string.");
    }

    let normalized = name.trim().toLowerCase();

    if (normalized.endsWith(".")) {
        normalized = normalized.slice(0, -1);
    }

    return normalized;
}

function isValidHostname(name) {
    let normalized;

    try {
        normalized = normalizeDomain(name);
    } catch {
        return false;
    }

    if (!normalized || normalized.length > 253) {
        return false;
    }

    const labels = normalized.split(".");

    return labels.every((label) => {
        if (label.length < 1 || label.length > 63) {
            return false;
        }

        if (label.startsWith("-") || label.endsWith("-")) {
            return false;
        }

        return /^[A-Za-z0-9-]+$/.test(label);
    });
}

function demonstrateDomainHandling() {
    section("2. DOMAIN NAMES");

    const names = [
        "example.com",
        "Example.COM.",
        "www.example.com",
        "",
        "-bad.example.com",
        "bad-.example.com"
    ];

    for (const name of names) {
        console.log(
            `${JSON.stringify(name).padEnd(28)} ` +
            `normalized=${isValidHostname(name) ? normalizeDomain(name) : "invalid"}`
        );
    }
}


// ---------------------------------------------------------------------------
// SECTION 3: DNS RECORD MODEL
// ---------------------------------------------------------------------------

class DNSRecord {
    constructor(name, type, value, ttl = 300) {
        this.name = normalizeDomain(name);
        this.type = type.toUpperCase();
        this.value = value;
        this.ttl = ttl;
    }

    toString() {
        return `${this.name.padEnd(28)} ${String(this.ttl).padEnd(6)} IN ${this.type.padEnd(6)} ${this.value}`;
    }
}

function demonstrateRecordTypes() {
    section("3. DNS RECORD TYPES");

    const records = [
        new DNSRecord("example.com", "A", "93.184.216.34", 300),
        new DNSRecord("example.com", "AAAA", "2001:db8::10", 300),
        new DNSRecord("www.example.com", "CNAME", "example.com.", 300),
        new DNSRecord("example.com", "MX", "10 mail.example.com.", 3600),
        new DNSRecord("example.com", "NS", "ns1.example.com.", 86400),
        new DNSRecord("example.com", "TXT", "v=spf1 -all", 3600)
    ];

    console.log("NAME".padEnd(28) + " TTL".padEnd(6) + " CLASS TYPE   VALUE");
    console.log("-".repeat(78));

    for (const record of records) {
        console.log(record.toString());
    }
}


// ---------------------------------------------------------------------------
// SECTION 4: SIMULATED AUTHORITATIVE ZONE
// ---------------------------------------------------------------------------

class DNSZone {
    constructor(name) {
        this.name = normalizeDomain(name);
        this.records = new Map();
    }

    key(name, type) {
        return `${normalizeDomain(name)}|${type.toUpperCase()}`;
    }

    addRecord(record) {
        const key = this.key(record.name, record.type);

        if (!this.records.has(key)) {
            this.records.set(key, []);
        }

        this.records.get(key).push(record);
    }

    lookup(name, type) {
        return [...(this.records.get(this.key(name, type)) || [])];
    }
}

class AuthoritativeServer {
    constructor(name, zones = []) {
        this.name = name;
        this.zones = new Map();

        for (const zone of zones) {
            this.addZone(zone);
        }
    }

    addZone(zone) {
        this.zones.set(zone.name, zone);
    }

    findZone(name) {
        const normalized = normalizeDomain(name);

        const matchingZones = [...this.zones.entries()]
            .filter(([zoneName]) => {
                return (
                    normalized === zoneName ||
                    normalized.endsWith(`.${zoneName}`)
                );
            })
            .sort((a, b) => b[0].length - a[0].length);

        return matchingZones.length > 0 ? matchingZones[0][1] : null;
    }

    query(name, type) {
        const zone = this.findZone(name);

        if (!zone) {
            return [];
        }

        return zone.lookup(name, type);
    }
}

function createDemoInfrastructure() {
    const rootZone = new DNSZone(".");
    rootZone.addRecord(
        new DNSRecord("com", "NS", "a.gtld-servers.net.", 172800)
    );

    const comZone = new DNSZone("com");
    comZone.addRecord(
        new DNSRecord("example.com", "NS", "ns1.example.com.", 86400)
    );

    const exampleZone = new DNSZone("example.com");
    exampleZone.addRecord(
        new DNSRecord("example.com", "A", "93.184.216.34", 300)
    );
    exampleZone.addRecord(
        new DNSRecord("example.com", "AAAA", "2001:db8::10", 300)
    );
    exampleZone.addRecord(
        new DNSRecord("www.example.com", "CNAME", "example.com.", 300)
    );
    exampleZone.addRecord(
        new DNSRecord("mail.example.com", "A", "192.0.2.25", 300)
    );

    return {
        root: new AuthoritativeServer("Root Server", [rootZone]),
        tld: new AuthoritativeServer("COM TLD Server", [comZone]),
        authoritative: new AuthoritativeServer(
            "ns1.example.com",
            [exampleZone]
        )
    };
}


// ---------------------------------------------------------------------------
// SECTION 5: TTL-AWARE CACHE
// ---------------------------------------------------------------------------

class DNSCache {
    constructor(capacity = 100) {
        if (!Number.isInteger(capacity) || capacity <= 0) {
            throw new RangeError("Cache capacity must be positive.");
        }

        this.capacity = capacity;
        this.entries = new Map();
        this.hits = 0;
        this.misses = 0;
    }

    key(name, type) {
        return `${normalizeDomain(name)}|${type.toUpperCase()}`;
    }

    get(name, type, now = Date.now()) {
        const key = this.key(name, type);
        const entry = this.entries.get(key);

        if (!entry) {
            this.misses++;
            return null;
        }

        if (now >= entry.expiresAt) {
            this.entries.delete(key);
            this.misses++;
            return null;
        }

        this.hits++;
        return entry.records.map((record) => ({ ...record }));
    }

    put(name, type, records, now = Date.now()) {
        if (!records.length) {
            return;
        }

        const key = this.key(name, type);

        if (this.entries.size >= this.capacity && !this.entries.has(key)) {
            // This is an educational eviction policy. A production resolver
            // normally uses a more carefully designed cache structure.
            const oldest = [...this.entries.entries()]
                .sort((a, b) => a[1].expiresAt - b[1].expiresAt)[0];

            if (oldest) {
                this.entries.delete(oldest[0]);
            }
        }

        const ttlSeconds = Math.min(
            ...records.map((record) => Math.max(0, record.ttl))
        );

        this.entries.set(key, {
            records: records.map((record) => ({ ...record })),
            expiresAt: now + ttlSeconds * 1000
        });
    }

    statistics() {
        const total = this.hits + this.misses;

        return {
            hits: this.hits,
            misses: this.misses,
            hitRate: total === 0 ? 0 : this.hits / total,
            entries: this.entries.size
        };
    }
}


// ---------------------------------------------------------------------------
// SECTION 6: RECURSIVE RESOLUTION SIMULATION
// ---------------------------------------------------------------------------

class RecursiveResolver {
    constructor(infrastructure) {
        this.root = infrastructure.root;
        this.tld = infrastructure.tld;
        this.authoritative = infrastructure.authoritative;
        this.cache = new DNSCache(100);
    }

    resolve(name, type = "A", now = Date.now()) {
        const normalizedName = normalizeDomain(name);
        const normalizedType = type.toUpperCase();

        const cached = this.cache.get(
            normalizedName,
            normalizedType,
            now
        );

        if (cached !== null) {
            return {
                status: "NOERROR",
                records: cached,
                cacheHit: true,
                path: [
                    "Client",
                    "Recursive Resolver",
                    "Cache"
                ]
            };
        }

        const rootReferral = this.root.query("com", "NS");

        if (rootReferral.length === 0) {
            return {
                status: "SERVFAIL",
                records: [],
                cacheHit: false,
                path: ["Client", "Recursive Resolver", "Root Server"]
            };
        }

        const tldReferral = this.tld.query("example.com", "NS");

        if (tldReferral.length === 0) {
            return {
                status: "SERVFAIL",
                records: [],
                cacheHit: false,
                path: [
                    "Client",
                    "Recursive Resolver",
                    "Root Server",
                    "COM TLD Server"
                ]
            };
        }

        let records = this.authoritative.query(
            normalizedName,
            normalizedType
        );

        // If A/AAAA does not exist directly, inspect CNAME and then follow
        // the alias within the simulated zone.
        if (
            records.length === 0 &&
            ["A", "AAAA"].includes(normalizedType)
        ) {
            const aliases = this.authoritative.query(
                normalizedName,
                "CNAME"
            );

            if (aliases.length > 0) {
                const target = normalizeDomain(aliases[0].value);

                records = this.authoritative.query(
                    target,
                    normalizedType
                );
            }
        }

        if (records.length === 0) {
            return {
                status: "NXDOMAIN",
                records: [],
                cacheHit: false,
                path: [
                    "Client",
                    "Recursive Resolver",
                    "Root Server",
                    "COM TLD Server",
                    "Authoritative Server"
                ]
            };
        }

        this.cache.put(
            normalizedName,
            normalizedType,
            records,
            now
        );

        return {
            status: "NOERROR",
            records,
            cacheHit: false,
            path: [
                "Client",
                "Recursive Resolver",
                "Root Server",
                "COM TLD Server",
                "Authoritative Server"
            ]
        };
    }
}

function demonstrateSimulatedResolver() {
    section("6. SIMULATED RECURSIVE RESOLVER");

    const infrastructure = createDemoInfrastructure();
    const resolver = new RecursiveResolver(infrastructure);

    const first = resolver.resolve("example.com", "A");

    console.log("First query:");
    console.log(`Status: ${first.status}`);
    console.log(`Cache hit: ${first.cacheHit}`);
    console.log(`Answer: ${first.records.map((r) => r.value).join(", ")}`);
    console.log("Path:");
    first.path.forEach((step) => console.log(`  -> ${step}`));

    const second = resolver.resolve("example.com", "A");

    console.log("\nSecond query:");
    console.log(`Status: ${second.status}`);
    console.log(`Cache hit: ${second.cacheHit}`);
    console.log(`Answer: ${second.records.map((r) => r.value).join(", ")}`);

    const missing = resolver.resolve("missing.example.com", "A");
    console.log("\nMissing name:");
    console.log(`Status: ${missing.status}`);
}


// ---------------------------------------------------------------------------
// SECTION 7: CNAME CHAIN
// ---------------------------------------------------------------------------

function resolveCnameChain(records, startName, maxDepth = 10) {
    const mapping = new Map(
        records
            .filter((record) => record.type === "CNAME")
            .map((record) => [
                normalizeDomain(record.name),
                normalizeDomain(record.value)
            ])
    );

    const chain = [normalizeDomain(startName)];
    const visited = new Set(chain);

    for (let depth = 0; depth < maxDepth; depth++) {
        const current = chain[chain.length - 1];
        const target = mapping.get(current);

        if (!target) {
            return chain;
        }

        if (visited.has(target)) {
            throw new Error(
                `CNAME loop detected: ${[...chain, target].join(" -> ")}`
            );
        }

        chain.push(target);
        visited.add(target);
    }

    throw new Error("CNAME chain exceeded maximum depth.");
}

function demonstrateCname() {
    section("7. CNAME CHAINS");

    const records = [
        new DNSRecord("app.example.com", "CNAME", "edge.example.net."),
        new DNSRecord("edge.example.net", "CNAME", "origin.example.net.")
    ];

    const chain = resolveCnameChain(records, "app.example.com");

    console.log(chain.join(" -> "));

    try {
        resolveCnameChain(
            [
                new DNSRecord("a.example", "CNAME", "b.example"),
                new DNSRecord("b.example", "CNAME", "a.example")
            ],
            "a.example"
        );
    } catch (error) {
        console.log(`Expected validation error: ${error.message}`);
    }
}


// ---------------------------------------------------------------------------
// SECTION 8: NODE.JS ASYNCHRONOUS DNS
// ---------------------------------------------------------------------------

function dnsLookup(hostname, options = {}) {
    return new Promise((resolve, reject) => {
        dns.lookup(hostname, options, (error, address, family) => {
            if (error) {
                reject(error);
                return;
            }

            resolve({ address, family });
        });
    });
}

function dnsResolve4(hostname) {
    return new Promise((resolve, reject) => {
        dns.resolve4(hostname, (error, addresses) => {
            if (error) {
                reject(error);
                return;
            }

            resolve(addresses);
        });
    });
}

function dnsResolve6(hostname) {
    return new Promise((resolve, reject) => {
        dns.resolve6(hostname, (error, addresses) => {
            if (error) {
                reject(error);
                return;
            }

            resolve(addresses);
        });
    });
}

function dnsResolveMx(hostname) {
    return new Promise((resolve, reject) => {
        dns.resolveMx(hostname, (error, records) => {
            if (error) {
                reject(error);
                return;
            }

            resolve(records);
        });
    });
}

async function demonstrateNodeDNS() {
    section("8. NODE.JS DNS API");

    const hostname = "example.com";

    console.log("dns.lookup() uses the operating-system resolver path.");
    try {
        const result = await dnsLookup(hostname);
        console.log(
            `lookup: ${result.address} (IPv${result.family})`
        );
    } catch (error) {
        console.log(`lookup failed: ${error.code || error.message}`);
    }

    console.log("\ndns.resolve4() performs DNS resolution through Node's DNS resolver.");
    try {
        const addresses = await dnsResolve4(hostname);
        console.log(`A records: ${addresses.join(", ")}`);
    } catch (error) {
        console.log(`A query failed: ${error.code || error.message}`);
    }

    console.log("\ndns.resolve6() requests AAAA records.");
    try {
        const addresses = await dnsResolve6(hostname);
        console.log(`AAAA records: ${addresses.join(", ")}`);
    } catch (error) {
        console.log(`AAAA query failed: ${error.code || error.message}`);
    }

    console.log("\ndns.resolveMx() requests MX records.");
    try {
        const records = await dnsResolveMx(hostname);
        for (const record of records) {
            console.log(`MX preference=${record.priority} exchange=${record.exchange}`);
        }
    } catch (error) {
        console.log(`MX query failed: ${error.code || error.message}`);
    }

    console.log(
        "\nThe exact records returned can change over time because DNS data, "
        "load balancing, CDN behavior, and resolver caching can change."
    );
}


// ---------------------------------------------------------------------------
// SECTION 9: DNS QUERY PACKET CONSTRUCTION
// ---------------------------------------------------------------------------

const DNS_TYPE_CODES = {
    A: 1,
    NS: 2,
    CNAME: 5,
    SOA: 6,
    PTR: 12,
    MX: 15,
    TXT: 16,
    AAAA: 28
};

function encodeDnsName(name) {
    const normalized = normalizeDomain(name);

    if (!normalized) {
        return Buffer.from([0]);
    }

    const pieces = [];

    for (const label of normalized.split(".")) {
        const bytes = Buffer.from(label, "ascii");

        if (bytes.length > 63) {
            throw new Error("DNS labels cannot exceed 63 octets.");
        }

        pieces.push(Buffer.from([bytes.length]));
        pieces.push(bytes);
    }

    pieces.push(Buffer.from([0]));

    return Buffer.concat(pieces);
}

function buildDnsQuery(transactionId, name, type = "A") {
    if (!Number.isInteger(transactionId) || transactionId < 0 || transactionId > 65535) {
        throw new RangeError("Transaction ID must fit into 16 bits.");
    }

    const typeCode = DNS_TYPE_CODES[type.toUpperCase()];

    if (!typeCode) {
        throw new Error(`Unsupported DNS type: ${type}`);
    }

    // Node.js Buffer makes binary protocol construction explicit. The
    // question asks for IN class (1) and the RD flag is set in the header.
    const header = Buffer.alloc(12);

    header.writeUInt16BE(transactionId, 0);
    header.writeUInt16BE(0x0100, 2); // RD = recursion desired
    header.writeUInt16BE(1, 4);       // QDCOUNT
    header.writeUInt16BE(0, 6);       // ANCOUNT
    header.writeUInt16BE(0, 8);       // NSCOUNT
    header.writeUInt16BE(0, 10);      // ARCOUNT

    const question = Buffer.alloc(encodeDnsName(name).length + 4);
    const encodedName = encodeDnsName(name);

    encodedName.copy(question, 0);
    question.writeUInt16BE(typeCode, encodedName.length);
    question.writeUInt16BE(1, encodedName.length + 2); // IN

    return Buffer.concat([header, question]);
}

function parseDnsHeader(packet) {
    if (!Buffer.isBuffer(packet) || packet.length < 12) {
        throw new Error("DNS packet must contain at least a 12-byte header.");
    }

    const flags = packet.readUInt16BE(2);

    return {
        transactionId: packet.readUInt16BE(0),
        flags,
        questionCount: packet.readUInt16BE(4),
        answerCount: packet.readUInt16BE(6),
        authorityCount: packet.readUInt16BE(8),
        additionalCount: packet.readUInt16BE(10)
    };
}

function decodeDnsFlags(flags) {
    return {
        QR: (flags >>> 15) & 1,
        AA: (flags >>> 10) & 1,
        TC: (flags >>> 9) & 1,
        RD: (flags >>> 8) & 1,
        RA: (flags >>> 7) & 1,
        RCODE: flags & 0x0f
    };
}

function demonstrateWireFormat() {
    section("9. DNS WIRE FORMAT");

    const packet = buildDnsQuery(
        0x1234,
        "example.com",
        "A"
    );

    console.log(`Packet: ${packet.toString("hex")}`);

    const header = parseDnsHeader(packet);

    console.log("\nHeader:");
    console.table(header);

    console.log("\nFlags:");
    console.table(decodeDnsFlags(header.flags));

    console.log(
        "\nThe first 12 bytes form the DNS header. The remaining bytes contain "
        "the question in DNS wire format."
    );
}


// ---------------------------------------------------------------------------
// SECTION 10: PERFORMANCE AND CACHE TEST
// ---------------------------------------------------------------------------

function benchmarkCache() {
    section("10. CACHE PERFORMANCE");

    const infrastructure = createDemoInfrastructure();
    const resolver = new RecursiveResolver(infrastructure);

    const start = performance.now();

    for (let i = 0; i < 10000; i++) {
        resolver.resolve("example.com", "A");
    }

    const elapsed = performance.now() - start;
    const statistics = resolver.cache.statistics();

    console.log(`10,000 simulated lookups: ${elapsed.toFixed(2)} ms`);
    console.log(`Cache hits: ${statistics.hits}`);
    console.log(`Cache misses: ${statistics.misses}`);
    console.log(`Hit rate: ${(statistics.hitRate * 100).toFixed(2)}%`);

    console.log(
        "\nThis benchmark measures the local simulation only. It is not a "
        "measurement of Internet DNS performance."
    );
}


// ---------------------------------------------------------------------------
// SECTION 11: DIAGNOSTIC COMMANDS
// ---------------------------------------------------------------------------

function explainDiagnosticTools() {
    section("11. DIG, NSLOOKUP, AND WIRESHARK");

    console.log(`
Typical dig commands:

  dig example.com A
  dig example.com AAAA
  dig example.com MX
  dig example.com NS
  dig +short example.com
  dig +trace example.com
  dig @1.1.1.1 example.com

Typical nslookup commands:

  nslookup example.com
  nslookup -type=MX example.com
  nslookup example.com 1.1.1.1

Useful Wireshark display filters:

  dns
  dns.flags.response == 0
  dns.flags.response == 1
  dns.qry.name == "example.com"
  dns.qry.type == 1

A DNS packet can reveal the transaction ID, flags, query name, query type,
response code, records, TTLs, and whether the packet is a query or response.
`);
}


// ---------------------------------------------------------------------------
// SECTION 12: SECURITY CONCEPTS
// ---------------------------------------------------------------------------

function explainSecurity() {
    section("12. DNS SECURITY");

    const topics = [
        ["Cache poisoning", "False data is inserted into a resolver cache."],
        ["Spoofing", "A forged response attempts to appear legitimate."],
        ["DNSSEC", "Cryptographic signatures allow validation of DNS data."],
        ["DoT", "DNS queries are transported through TLS."],
        ["DoH", "DNS queries are carried through HTTPS."],
        ["Amplification", "Open or abused DNS infrastructure can be used for reflection."],
        ["Rebinding", "DNS answers can change to manipulate where a hostname resolves."]
    ];

    for (const [name, description] of topics) {
        console.log(`${name.padEnd(20)} ${description}`);
    }
}


// ---------------------------------------------------------------------------
// SECTION 13: ASSERTIONS
// ---------------------------------------------------------------------------

function runAssertions() {
    section("13. BUILT-IN TESTS");

    console.assert(
        normalizeDomain("WWW.Example.COM.") === "www.example.com",
        "Domain normalization failed."
    );

    console.assert(
        isValidHostname("example.com"),
        "Valid hostname rejected."
    );

    console.assert(
        !isValidHostname("-bad.example.com"),
        "Invalid hostname accepted."
    );

    const encoded = encodeDnsName("example.com");
    console.assert(
        encoded[0] === 7 &&
        encoded.subarray(1, 8).toString("ascii") === "example",
        "DNS name encoding failed."
    );

    const packet = buildDnsQuery(0xABCD, "example.com", "A");
    const header = parseDnsHeader(packet);

    console.assert(
        header.transactionId === 0xABCD,
        "Transaction ID parsing failed."
    );

    console.assert(
        header.questionCount === 1,
        "Question count failed."
    );

    const infrastructure = createDemoInfrastructure();
    const resolver = new RecursiveResolver(infrastructure);

    const first = resolver.resolve("example.com", "A");
    console.assert(
        first.status === "NOERROR" &&
        first.records[0].value === "93.184.216.34",
        "Simulated DNS answer failed."
    );

    const second = resolver.resolve("example.com", "A");
    console.assert(
        second.cacheHit === true,
        "Cache hit failed."
    );

    const missing = resolver.resolve("does-not-exist.example.com", "A");
    console.assert(
        missing.status === "NXDOMAIN",
        "NXDOMAIN simulation failed."
    );

    console.log("Assertions completed.");
}


// ---------------------------------------------------------------------------
// SECTION 14: MAIN
// ---------------------------------------------------------------------------

async function main() {
    console.log(`
DNS STUDY PROGRAM
=================
The program demonstrates DNS concepts from basic names and records through
recursive resolution, caching, binary packets, Node.js DNS APIs, diagnostics,
performance, and security.
`);

    explainBasics();
    demonstrateDomainHandling();
    demonstrateRecordTypes();
    demonstrateSimulatedResolver();
    demonstrateCname();
    demonstrateWireFormat();
    benchmarkCache();
    explainDiagnosticTools();
    explainSecurity();
    runAssertions();

    // The live DNS examples are intentionally executed last. A machine can
    // still complete the rest of the study if network DNS is unavailable.
    await demonstrateNodeDNS();

    section("END");
    console.log("DNS study program completed.");
}

main().catch((error) => {
    console.error(`Unexpected error: ${error.message}`);
    process.exitCode = 1;
});
