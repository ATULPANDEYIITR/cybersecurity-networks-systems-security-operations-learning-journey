/*
 * Network Troubleshooting in JavaScript
 *
 * Demonstrates:
 * - DNS resolution
 * - TCP connectivity
 * - latency measurement
 * - asynchronous diagnostics
 * - timeout handling
 * - routing concepts
 * - packet-loss simulation
 * - MTU calculations
 * - diagnostic decision logic
 * - structured reporting
 *
 * Runtime: Node.js 18+.
 *
 * This file performs low-volume diagnostic operations only.
 * It does not perform flooding, exploitation, credential collection, or
 * unauthorized scanning.
 */

"use strict";

const dns = require("node:dns").promises;
const net = require("node:net");
const os = require("node:os");
const { execFile } = require("node:child_process");
const { promisify } = require("node:util");

const execFileAsync = promisify(execFile);

function section(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

// ---------------------------------------------------------------------------
// 1. FUNDAMENTALS
// ---------------------------------------------------------------------------

function fundamentals() {
    section("1. NETWORK TROUBLESHOOTING FUNDAMENTALS");

    const concepts = {
        DNS: "Maps names to addresses and other service information.",
        Routing: "Selects a path for IP packets toward a destination.",
        Latency: "Measures delay between an observation point and a target.",
        PacketLoss: "Represents packets that fail to produce the expected response.",
        MTU: "Maximum IP packet size a path/interface can carry without fragmentation at that point.",
        TCP: "Reliable, connection-oriented transport protocol.",
        UDP: "Connectionless transport protocol.",
        ICMP: "Network-control protocol commonly used by diagnostic tools."
    };

    for (const [name, definition] of Object.entries(concepts)) {
        console.log(`${name.padEnd(14)} ${definition}`);
    }

    console.log(`
A useful troubleshooting model is:

local configuration
    -> gateway
    -> IP routing
    -> DNS
    -> transport
    -> application

A successful test at one layer does not prove that every higher layer works.
`);
}

// ---------------------------------------------------------------------------
// 2. DNS
// ---------------------------------------------------------------------------

async function resolveHostname(hostname) {
    try {
        // dns.lookup() uses the operating system's name-resolution path.
        const addresses = await dns.lookup(hostname, {
            all: true,
            verbatim: true
        });

        return {
            success: true,
            addresses: addresses.map(item => ({
                address: item.address,
                family: item.family
            }))
        };
    } catch (error) {
        return {
            success: false,
            error: error.code || error.message
        };
    }
}

async function dnsDemo(hostname) {
    section("2. DNS DIAGNOSTICS");

    console.log(`Resolving: ${hostname}`);

    const result = await resolveHostname(hostname);

    if (!result.success) {
        console.log(`Resolution failed: ${result.error}`);
        console.log(`
Possible explanations:
- hostname does not exist
- DNS resolver unavailable
- network path to resolver unavailable
- local resolver configuration issue
- split DNS or VPN configuration
- temporary resolver failure
`);
        return result;
    }

    for (const address of result.addresses) {
        console.log(`  IPv${address.family}: ${address.address}`);
    }

    console.log(`
DNS success proves that a name-resolution operation succeeded.
It does not prove that TCP/443, HTTP, TLS, or the application is healthy.
`);
    return result;
}

// ---------------------------------------------------------------------------
// 3. TCP CONNECTIVITY
// ---------------------------------------------------------------------------

function tcpConnect(host, port, timeoutMs = 3000) {
    return new Promise(resolve => {
        const started = process.hrtime.bigint();
        let settled = false;

        const socket = net.createConnection({
            host,
            port
        });

        const finish = result => {
            if (settled) return;
            settled = true;

            socket.destroy();

            const elapsedMs =
                Number(process.hrtime.bigint() - started) / 1e6;

            resolve({
                host,
                port,
                elapsedMs,
                ...result
            });
        };

        socket.once("connect", () => {
            finish({
                success: true,
                error: null
            });
        });

        socket.once("error", error => {
            finish({
                success: false,
                error: error.code || error.message
            });
        });

        socket.setTimeout(timeoutMs, () => {
            finish({
                success: false,
                error: "TIMEOUT"
            });
        });
    });
}

async function tcpDemo(addresses) {
    section("3. TCP CONNECTIVITY");

    if (addresses.length === 0) {
        console.log("No addresses available.");
        return [];
    }

    const results = [];

    for (const address of addresses.slice(0, 4)) {
        const result = await tcpConnect(address.address, 443);

        results.push(result);

        if (result.success) {
            console.log(
                `${address.address}: TCP/443 reachable in ` +
                `${result.elapsedMs.toFixed(2)} ms`
            );
        } else {
            console.log(
                `${address.address}: TCP/443 failed: ${result.error}`
            );
        }
    }

    console.log(`
A TCP failure can indicate:
- no route
- firewall filtering
- inactive service
- incorrect port
- server-side failure
- packet loss
- timeout caused by an intermediate device

TCP success only establishes transport connectivity. TLS and the application
protocol still require separate validation.
`);

    return results;
}

// ---------------------------------------------------------------------------
// 4. LATENCY USING SYSTEM PING
// ---------------------------------------------------------------------------

function pingExecutable() {
    return process.platform === "win32" ? "ping" : "ping";
}

async function pingHost(host, count = 4) {
    const args =
        process.platform === "win32"
            ? ["-n", String(count), "-w", "2000", host]
            : ["-c", String(count), "-W", "2", host];

    try {
        const { stdout, stderr } = await execFileAsync(
            pingExecutable(),
            args,
            {
                timeout: count * 3000 + 5000,
                maxBuffer: 1024 * 1024
            }
        );

        const output = `${stdout}\n${stderr}`;

        const matches = [
            ...output.matchAll(/time[=<]\s*(\d+(?:\.\d+)?)\s*ms/gi)
        ];

        const values = matches.map(match => Number(match[1]));

        return {
            success: true,
            values,
            output
        };
    } catch (error) {
        const output = `${error.stdout || ""}\n${error.stderr || ""}`;

        const values = [
            ...output.matchAll(/time[=<]\s*(\d+(?:\.\d+)?)\s*ms/gi)
        ].map(match => Number(match[1]));

        return {
            success: false,
            values,
            error: error.message,
            output
        };
    }
}

function percentile(values, percentileValue) {
    if (values.length === 0) return null;

    const sorted = [...values].sort((a, b) => a - b);
    const index =
        (percentileValue / 100) * (sorted.length - 1);

    const lower = Math.floor(index);
    const upper = Math.ceil(index);

    if (lower === upper) return sorted[lower];

    const fraction = index - lower;

    return (
        sorted[lower] +
        (sorted[upper] - sorted[lower]) * fraction
    );
}

function summarizeLatency(values, sent) {
    if (values.length === 0) {
        return {
            sent,
            received: 0,
            lossPercent: 100,
            minMs: null,
            averageMs: null,
            maxMs: null,
            p95Ms: null
        };
    }

    const minMs = Math.min(...values);
    const maxMs = Math.max(...values);
    const averageMs =
        values.reduce((sum, value) => sum + value, 0) /
        values.length;

    return {
        sent,
        received: values.length,
        lossPercent: ((sent - values.length) / sent) * 100,
        minMs,
        averageMs,
        maxMs,
        p95Ms: percentile(values, 95)
    };
}

async function latencyDemo(host) {
    section("4. LATENCY AND PACKET LOSS");

    const result = await pingHost(host, 4);

    if (result.values.length > 0) {
        console.log("Observed replies:", result.values);
    }

    if (!result.success) {
        console.log(`Ping command reported an error: ${result.error}`);
    }

    console.table(summarizeLatency(result.values, 4));

    console.log(`
Latency should be interpreted in context.
Packet loss and jitter can be more important than small differences in average
latency.

A ping response is an observation about ICMP behavior. It is not equivalent to
an HTTP or database transaction.
`);
}

// ---------------------------------------------------------------------------
// 5. ROUTING
// ---------------------------------------------------------------------------

async function routeDemo(host) {
    section("5. ROUTING DIAGNOSTICS");

    const windows = process.platform === "win32";

    const command = windows ? "tracert" : "traceroute";
    const args = windows ? ["-d", host] : ["-n", host];

    try {
        const { stdout, stderr } = await execFileAsync(
            command,
            args,
            {
                timeout: 60000,
                maxBuffer: 2 * 1024 * 1024
            }
        );

        console.log((stdout || stderr).slice(0, 12000));
    } catch (error) {
        console.log(
            `Route diagnostic unavailable or failed: ${error.message}`
        );
    }

    console.log(`
Traceroute depends on diagnostic response packets such as ICMP messages.
An intermediate timeout does not automatically mean that the router is
dropping the application's packets.

Look for patterns:
- destination unreachable
- path changes
- repeated delay increases
- loss that begins at a point and persists to the destination
- differences between destinations
`);
}

// ---------------------------------------------------------------------------
// 6. MTU
// ---------------------------------------------------------------------------

function calculateMtu(mtu, ipVersion = 4, transport = "TCP") {
    const ipHeader = ipVersion === 4 ? 20 : 40;
    const transportHeader =
        transport.toUpperCase() === "TCP" ? 20 : 8;

    return {
        mtu,
        ipVersion,
        transport,
        maxIpPayload: mtu - ipHeader,
        approximateMss: mtu - ipHeader - transportHeader
    };
}

function mtuDemo() {
    section("6. MTU AND MSS");

    for (const mtu of [1280, 1400, 1500, 9000]) {
        console.log(calculateMtu(mtu));
    }

    console.log(`
MTU and MSS are related but not identical.

MTU:
    maximum IP packet size carried by the relevant interface/path.

MSS:
    maximum TCP segment payload negotiated by endpoints.

For a basic IPv4/TCP example:
    MSS ~= MTU - 20-byte IPv4 header - 20-byte TCP header

Real environments can have additional headers and encapsulation, especially
with VPNs, tunnels, VLANs, and other overlays.

Symptoms of an MTU problem can include:
- small requests succeed
- large responses stall
- some sites work and others fail
- VPN connections behave differently
- TCP handshakes succeed but transfers fail
`);
}

// ---------------------------------------------------------------------------
// 7. LONGEST PREFIX MATCH
// ---------------------------------------------------------------------------

function ipv4ToInteger(address) {
    const octets = address.split(".").map(Number);

    if (
        octets.length !== 4 ||
        octets.some(value => !Number.isInteger(value) || value < 0 || value > 255)
    ) {
        throw new Error(`Invalid IPv4 address: ${address}`);
    }

    return (
        ((octets[0] << 24) >>> 0) |
        (octets[1] << 16) |
        (octets[2] << 8) |
        octets[3]
    ) >>> 0;
}

function networkMask(prefixLength) {
    if (prefixLength === 0) return 0;

    return (0xffffffff << (32 - prefixLength)) >>> 0;
}

function matchesRoute(destination, network, prefixLength) {
    const destinationInteger = ipv4ToInteger(destination);
    const networkInteger = ipv4ToInteger(network);
    const mask = networkMask(prefixLength);

    return (destinationInteger & mask) === (networkInteger & mask);
}

function longestPrefixMatch(destination, routes) {
    const matches = routes.filter(route =>
        matchesRoute(
            destination,
            route.network,
            route.prefixLength
        )
    );

    if (matches.length === 0) return null;

    return matches.sort(
        (a, b) =>
            b.prefixLength - a.prefixLength ||
            a.metric - b.metric
    )[0];
}

function routingAlgorithmDemo() {
    section("7. ROUTING DECISION MODEL");

    const routes = [
        {
            network: "0.0.0.0",
            prefixLength: 0,
            gateway: "192.168.1.1",
            interface: "eth0",
            metric: 100
        },
        {
            network: "10.0.0.0",
            prefixLength: 8,
            gateway: "192.168.1.254",
            interface: "eth0",
            metric: 50
        },
        {
            network: "10.20.0.0",
            prefixLength: 16,
            gateway: "10.20.0.1",
            interface: "vpn0",
            metric: 20
        },
        {
            network: "10.20.30.0",
            prefixLength: 24,
            gateway: null,
            interface: "vpn0",
            metric: 10
        }
    ];

    for (const destination of [
        "8.8.8.8",
        "10.5.6.7",
        "10.20.40.10",
        "10.20.30.15"
    ]) {
        const route = longestPrefixMatch(destination, routes);

        if (route) {
            console.log(
                `${destination.padEnd(16)} -> ` +
                `${route.network}/${route.prefixLength} ` +
                `via ${route.gateway || "direct"} ` +
                `on ${route.interface}`
            );
        } else {
            console.log(`${destination} -> no route`);
        }
    }

    console.log(`
The longest-prefix rule means a more specific route normally takes precedence
over a less specific route.

Real routing systems also consider route source, administrative distance,
policy, metrics, protocol behavior, and other platform-specific rules.
`);
}

// ---------------------------------------------------------------------------
// 8. PACKET LOSS AND JITTER SIMULATION
// ---------------------------------------------------------------------------

function deterministicRandom(seed) {
    let state = seed >>> 0;

    return () => {
        state = (1664525 * state + 1013904223) >>> 0;
        return state / 0x100000000;
    };
}

function simulatePath(hops, packetCount = 20) {
    const random = deterministicRandom(42);

    return hops.map(hop => {
        const observations = [];

        for (let i = 0; i < packetCount; i += 1) {
            if (random() < hop.lossProbability) {
                observations.push(null);
                continue;
            }

            const variation = random() * 2 - 1;
            observations.push(
                Math.max(0, hop.baseLatencyMs + variation)
            );
        }

        const received = observations.filter(
            value => value !== null
        );

        let jitterMs = 0;

        if (received.length > 1) {
            const differences = [];

            for (let i = 1; i < received.length; i += 1) {
                differences.push(
                    Math.abs(received[i] - received[i - 1])
                );
            }

            jitterMs =
                differences.reduce((sum, value) => sum + value, 0) /
                differences.length;
        }

        return {
            hop: hop.name,
            sent: packetCount,
            received: received.length,
            lossPercent:
                ((packetCount - received.length) / packetCount) * 100,
            averageLatencyMs:
                received.length > 0
                    ? received.reduce((sum, value) => sum + value, 0) /
                      received.length
                    : null,
            jitterMs
        };
    });
}

function simulationDemo() {
    section("8. PACKET-LOSS SIMULATION");

    const path = [
        {
            name: "LAN gateway",
            baseLatencyMs: 1,
            lossProbability: 0
        },
        {
            name: "ISP edge",
            baseLatencyMs: 8,
            lossProbability: 0.02
        },
        {
            name: "Regional router",
            baseLatencyMs: 20,
            lossProbability: 0.05
        },
        {
            name: "Destination",
            baseLatencyMs: 35,
            lossProbability: 0.05
        }
    ];

    console.table(simulatePath(path, 20));

    console.log(`
This simulation demonstrates why a single intermediate timeout is weak
evidence. Diagnostic replies may be rate-limited while forwarding continues.

If loss begins at a hop and consistently persists through later observations,
the evidence becomes more significant.
`);
}

// ---------------------------------------------------------------------------
// 9. DIAGNOSTIC CLASSIFICATION
// ---------------------------------------------------------------------------

function classifySymptom(symptom) {
    const text = symptom.toLowerCase();

    if (text.includes("dns") || text.includes("hostname")) {
        return {
            likelyLayer: "DNS",
            evidence: "The symptom explicitly involves name resolution.",
            nextTest: "Resolve the name and compare with direct IP connectivity."
        };
    }

    if (
        text.includes("latency") ||
        text.includes("slow") ||
        text.includes("delay")
    ) {
        return {
            likelyLayer: "Path/transport/application",
            evidence: "Delay is the primary reported symptom.",
            nextTest: "Measure latency, jitter, packet loss, and route behavior."
        };
    }

    if (text.includes("loss")) {
        return {
            likelyLayer: "Link/path/transport",
            evidence: "Expected packets are not consistently observed.",
            nextTest: "Compare loss to the gateway, path, and destination."
        };
    }

    if (
        text.includes("mtu") ||
        text.includes("large packet")
    ) {
        return {
            likelyLayer: "MTU/path",
            evidence: "Packet-size sensitivity is reported.",
            nextTest: "Use progressively smaller probes with fragmentation disabled."
        };
    }

    if (
        text.includes("route") ||
        text.includes("unreachable")
    ) {
        return {
            likelyLayer: "IP routing",
            evidence: "The destination may lack a usable path.",
            nextTest: "Inspect routing information and path behavior."
        };
    }

    return {
        likelyLayer: "Unknown",
        evidence: "The symptom is insufficient to isolate a layer.",
        nextTest:
            "Check local configuration, gateway, DNS, routing, transport, and application."
    };
}

function classificationDemo() {
    section("9. SYMPTOM CLASSIFICATION");

    const symptoms = [
        "DNS lookup fails",
        "Application is slow",
        "There is packet loss",
        "Large packets fail",
        "Destination is unreachable"
    ];

    for (const symptom of symptoms) {
        console.log(`\nSymptom: ${symptom}`);
        console.table(classifySymptom(symptom));
    }
}

// ---------------------------------------------------------------------------
// 10. ASYNCHRONOUS PARALLEL DIAGNOSTICS
// ---------------------------------------------------------------------------

async function parallelConnectivityDemo(hostname) {
    section("10. ASYNCHRONOUS PARALLEL DIAGNOSTICS");

    const dnsResult = await resolveHostname(hostname);

    if (!dnsResult.success) {
        console.log("Cannot continue to IP tests because DNS failed.");
        return;
    }

    // Independent TCP tests can be executed concurrently.
    const tests = dnsResult.addresses
        .slice(0, 4)
        .map(address => tcpConnect(address.address, 443));

    const results = await Promise.all(tests);

    console.table(results);

    console.log(`
Promise.all() is useful when multiple independent diagnostic operations can
run concurrently. This reduces total waiting time compared with sequential
testing.

Concurrency must still be bounded in production monitoring. Uncontrolled
parallelism can overload local resources or the systems being tested.
`);
}

// ---------------------------------------------------------------------------
// 11. TIMEOUT AND FAILURE SEMANTICS
// ---------------------------------------------------------------------------

async function timeoutDemo() {
    section("11. TIMEOUT AND FAILURE HANDLING");

    const result = await tcpConnect(
        "192.0.2.1",
        443,
        500
    );

    console.log(result);

    console.log(`
192.0.2.0/24 is reserved for documentation examples. A timeout or refusal
should be interpreted as an observation from this test, not as proof of a
specific root cause.

Useful distinctions include:
- ECONNREFUSED: a TCP endpoint actively rejected the connection.
- ETIMEDOUT: the expected operation exceeded its timeout.
- ENETUNREACH: the local system reports no usable network path.
- EHOSTUNREACH: the host is reported unreachable.
- DNS error: name resolution failed before transport testing.
`);
}

// ---------------------------------------------------------------------------
// 12. MACHINE-READABLE REPORT
// ---------------------------------------------------------------------------

async function buildReport(hostname) {
    const report = {
        target: hostname,
        timestamp: new Date().toISOString(),
        platform: process.platform,
        hostname: os.hostname(),
        dns: null,
        tcp443: []
    };

    const dnsResult = await resolveHostname(hostname);
    report.dns = dnsResult;

    if (dnsResult.success) {
        const tests = dnsResult.addresses
            .slice(0, 4)
            .map(address =>
                tcpConnect(address.address, 443)
            );

        report.tcp443 = await Promise.all(tests);
    }

    return report;
}

async function reportDemo(hostname) {
    section("12. STRUCTURED DIAGNOSTIC REPORT");

    const report = await buildReport(hostname);

    console.log(JSON.stringify(report, null, 2));
}

// ---------------------------------------------------------------------------
// 13. DECISION TREE
// ---------------------------------------------------------------------------

async function decisionTree(hostname) {
    section("13. SYSTEMATIC DECISION TREE");

    console.log(`Target: ${hostname}`);

    const dnsResult = await resolveHostname(hostname);

    if (!dnsResult.success) {
        console.log(`
DNS branch:
    Name resolution failed.

Next investigations:
    - configured resolver
    - DNS server reachability
    - resolver logs
    - DNS record existence
    - VPN/split-DNS behavior
`);
        return;
    }

    console.log(
        `DNS branch: success (${dnsResult.addresses.length} address(es))`
    );

    const tcpResults = await Promise.all(
        dnsResult.addresses
            .slice(0, 4)
            .map(address => tcpConnect(address.address, 443))
    );

    const anyTcpSuccess = tcpResults.some(
        result => result.success
    );

    if (anyTcpSuccess) {
        console.log(`
Transport branch:
    At least one address accepts TCP/443.

Next investigations:
    - TLS handshake
    - certificate validation
    - HTTP status
    - application response
`);
    } else {
        console.log(`
Transport branch:
    No tested address accepted TCP/443.

Next investigations:
    - routing
    - firewall rules
    - destination service
    - address-family differences
    - packet loss
    - MTU/path issues
`);
    }
}

// ---------------------------------------------------------------------------
// 14. MAIN
// ---------------------------------------------------------------------------

async function main() {
    const hostname = process.argv[2] || "example.com";
    const quick = process.argv.includes("--quick");
    const reportOnly = process.argv.includes("--json");

    if (reportOnly) {
        console.log(
            JSON.stringify(
                await buildReport(hostname),
                null,
                2
            )
        );
        return;
    }

    if (quick) {
        section("QUICK NETWORK DIAGNOSTIC");

        const dnsResult = await resolveHostname(hostname);

        if (!dnsResult.success) {
            console.log(`DNS failed: ${dnsResult.error}`);
            return;
        }

        console.log("Resolved addresses:");
        console.table(dnsResult.addresses);

        const tcpResults = await tcpDemo(dnsResult.addresses);
        console.table(tcpResults);

        return;
    }

    fundamentals();
    await dnsDemo(hostname);

    const dnsResult = await resolveHostname(hostname);

    if (dnsResult.success) {
        await tcpDemo(dnsResult.addresses);
    }

    await latencyDemo(hostname);
    await routeDemo(hostname);
    mtuDemo();
    routingAlgorithmDemo();
    simulationDemo();
    classificationDemo();

    await parallelConnectivityDemo(hostname);
    await timeoutDemo();
    await decisionTree(hostname);
    await reportDemo(hostname);

    section("DIAGNOSTIC PRINCIPLES");

    console.log(`
1. Define the exact symptom.
2. Establish whether the problem is local or remote.
3. Separate DNS from IP connectivity.
4. Separate ICMP behavior from application behavior.
5. Test the relevant transport port.
6. Inspect the route when reachability fails.
7. Measure loss and latency instead of relying on perception.
8. Investigate MTU when failures depend on packet size.
9. Record evidence before changing configuration.
10. Change one meaningful variable at a time.

A good diagnosis identifies evidence that supports a hypothesis and evidence
that rules out competing hypotheses.
`);
}

main().catch(error => {
    console.error("Fatal diagnostic error:", error);
    process.exitCode = 1;
});
