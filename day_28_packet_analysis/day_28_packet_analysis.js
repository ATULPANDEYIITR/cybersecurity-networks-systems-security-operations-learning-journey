'use strict';

/*
 * Packet Analysis Study File
 * ===========================
 *
 * Offline, self-contained demonstrations of:
 *   - Ethernet/IP/TCP/UDP packet structures
 *   - packet filtering
 *   - TCP stream reconstruction
 *   - DNS analysis
 *   - HTTP inspection
 *   - protocol statistics
 *   - suspicious-traffic indicators
 *   - asynchronous packet-processing pipelines
 *   - performance-aware indexing
 *
 * This program operates on synthetic packet objects rather than capturing
 * live traffic. It is therefore suitable for learning and deterministic
 * testing without requiring network privileges or third-party packages.
 *
 * Run:
 *   node packet_analysis.js
 */

const crypto = require('crypto');


// ---------------------------------------------------------------------------
// Basic packet model
// ---------------------------------------------------------------------------

class Packet {
    constructor({
        number,
        timestamp,
        source,
        destination,
        protocol,
        sourcePort = null,
        destinationPort = null,
        flags = [],
        sequence = null,
        payload = '',
        length = null
    }) {
        this.number = number;
        this.timestamp = timestamp;
        this.source = source;
        this.destination = destination;
        this.protocol = protocol;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.flags = new Set(flags);
        this.sequence = sequence;
        this.payload = payload;
        this.length = length ?? Buffer.byteLength(payload, 'utf8');
    }

    hasFlag(flag) {
        return this.flags.has(flag.toUpperCase());
    }

    endpoint() {
        const source = `${this.source}:${this.sourcePort ?? '-'}`;
        const destination = `${this.destination}:${this.destinationPort ?? '-'}`;
        return [source, destination];
    }

    streamKey() {
        const [first, second] = this.endpoint().sort();
        return `${first}<->${second}`;
    }
}


// ---------------------------------------------------------------------------
// Synthetic capture
// ---------------------------------------------------------------------------

function createSyntheticCapture() {
    const now = Date.now();

    return [
        new Packet({
            number: 1,
            timestamp: now,
            source: '192.168.1.10',
            destination: '192.168.1.20',
            protocol: 'TCP',
            sourcePort: 50000,
            destinationPort: 80,
            flags: ['SYN'],
            sequence: 1000,
            payload: ''
        }),

        new Packet({
            number: 2,
            timestamp: now + 10,
            source: '192.168.1.20',
            destination: '192.168.1.10',
            protocol: 'TCP',
            sourcePort: 80,
            destinationPort: 50000,
            flags: ['SYN', 'ACK'],
            sequence: 2000,
            payload: ''
        }),

        new Packet({
            number: 3,
            timestamp: now + 20,
            source: '192.168.1.10',
            destination: '192.168.1.20',
            protocol: 'TCP',
            sourcePort: 50000,
            destinationPort: 80,
            flags: ['ACK', 'PSH'],
            sequence: 1001,
            payload:
                'GET /index.html HTTP/1.1\r\n' +
                'Host: example.test\r\n' +
                'User-Agent: PacketStudy/1.0\r\n'
        }),

        new Packet({
            number: 4,
            timestamp: now + 25,
            source: '192.168.1.20',
            destination: '192.168.1.10',
            protocol: 'TCP',
            sourcePort: 80,
            destinationPort: 50000,
            flags: ['ACK', 'PSH'],
            sequence: 2001,
            payload:
                'HTTP/1.1 200 OK\r\n' +
                'Content-Type: text/plain\r\n\r\n' +
                'hello world\n'
        }),

        new Packet({
            number: 5,
            timestamp: now + 30,
            source: '192.168.1.10',
            destination: '8.8.8.8',
            protocol: 'UDP',
            sourcePort: 53000,
            destinationPort: 53,
            payload: JSON.stringify({
                transactionId: '1234',
                query: 'example.test',
                type: 'A'
            })
        }),

        new Packet({
            number: 6,
            timestamp: now + 40,
            source: '192.168.1.10',
            destination: '192.168.1.30',
            protocol: 'TCP',
            sourcePort: 51000,
            destinationPort: 445,
            flags: ['SYN'],
            sequence: 7000,
            payload: ''
        }),

        new Packet({
            number: 7,
            timestamp: now + 50,
            source: '192.168.1.10',
            destination: '192.168.1.31',
            protocol: 'TCP',
            sourcePort: 51001,
            destinationPort: 445,
            flags: ['SYN'],
            sequence: 8000,
            payload: ''
        }),

        new Packet({
            number: 8,
            timestamp: now + 60,
            source: '192.168.1.10',
            destination: '192.168.1.32',
            protocol: 'TCP',
            sourcePort: 51002,
            destinationPort: 445,
            flags: ['RST'],
            sequence: 9000,
            payload: ''
        })
    ];
}


// ---------------------------------------------------------------------------
// Protocol analysis
// ---------------------------------------------------------------------------

function classifyApplicationProtocol(packet) {
    const ports = new Set([
        packet.sourcePort,
        packet.destinationPort
    ]);

    if (ports.has(53)) return 'DNS';
    if (ports.has(80)) return 'HTTP';
    if (ports.has(443)) return 'HTTPS/TLS';
    if (ports.has(22)) return 'SSH';
    if (ports.has(25) || ports.has(587)) return 'SMTP';
    if (ports.has(123)) return 'NTP';
    if (ports.has(445)) return 'SMB';

    if (/^(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s/.test(packet.payload)) {
        return 'HTTP';
    }

    if (packet.payload.startsWith('\u0016\u0003')) {
        return 'TLS';
    }

    return packet.protocol;
}

function analyzeHTTP(payload) {
    const request = payload.match(
        /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP\/(\d\.\d)/m
    );

    if (!request) {
        return null;
    }

    const hostMatch = payload.match(/\r?\nHost:\s*([^\r\n]+)/i);

    return {
        method: request[1],
        path: request[2],
        version: request[3],
        host: hostMatch ? hostMatch[1].trim() : null
    };
}

function analyzeDNS(payload) {
    try {
        const record = JSON.parse(payload);

        if (!record.query) {
            return null;
        }

        return {
            transactionId: record.transactionId ?? null,
            query: record.query,
            type: record.type ?? 'UNKNOWN'
        };
    } catch {
        return null;
    }
}


// ---------------------------------------------------------------------------
// Display-filter implementation
// ---------------------------------------------------------------------------

function compare(left, operator, right) {
    switch (operator) {
        case '==': return left === right;
        case '>': return left > right;
        case '<': return left < right;
        case '>=': return left >= right;
        case '<=': return left <= right;
        default:
            throw new Error(`Unsupported comparison operator: ${operator}`);
    }
}

function packetMatchesAtom(packet, expression) {
    const text = expression.trim().toLowerCase();

    if (text === 'tcp') {
        return packet.protocol === 'TCP';
    }

    if (text === 'udp') {
        return packet.protocol === 'UDP';
    }

    if (text === 'dns') {
        return classifyApplicationProtocol(packet) === 'DNS';
    }

    if (text === 'http') {
        return classifyApplicationProtocol(packet) === 'HTTP';
    }

    if (text === 'tcp port 80') {
        return (
            packet.protocol === 'TCP' &&
            (packet.sourcePort === 80 || packet.destinationPort === 80)
        );
    }

    let match = text.match(/^tcp\.port\s*==\s*(\d+)$/);

    if (match) {
        const port = Number(match[1]);

        return (
            packet.protocol === 'TCP' &&
            (packet.sourcePort === port || packet.destinationPort === port)
        );
    }

    match = text.match(/^ip\.addr\s*==\s*([\d.]+)$/);

    if (match) {
        return packet.source === match[1] || packet.destination === match[1];
    }

    match = text.match(/^ip\.src\s*==\s*([\d.]+)$/);

    if (match) {
        return packet.source === match[1];
    }

    match = text.match(/^ip\.dst\s*==\s*([\d.]+)$/);

    if (match) {
        return packet.destination === match[1];
    }

    match = text.match(/^frame\.len\s*(==|>=|<=|>|<)\s*(\d+)$/);

    if (match) {
        return compare(packet.length, match[1], Number(match[2]));
    }

    match = text.match(/^tcp\.flags\.(syn|ack|fin|rst|psh|urg)\s*==\s*([01])$/);

    if (match) {
        if (packet.protocol !== 'TCP') return false;

        const flagName = match[1].toUpperCase();
        const expected = match[2] === '1';

        return packet.hasFlag(flagName) === expected;
    }

    throw new Error(`Unsupported filter: ${expression}`);
}

function matchesFilter(packet, expression) {
    if (!expression.trim()) return true;

    const normalized = expression
        .replace(/\(/g, '')
        .replace(/\)/g, '');

    const orParts = normalized.split(/\s+(?:\|\||or)\s+/i);

    if (orParts.length > 1) {
        return orParts.some(part => matchesFilter(packet, part));
    }

    const andParts = normalized.split(/\s+(?:&&|and)\s+/i);

    if (andParts.length > 1) {
        return andParts.every(part => matchesFilter(packet, part));
    }

    return packetMatchesAtom(packet, normalized);
}

function filterPackets(packets, expression) {
    return packets.filter(packet => matchesFilter(packet, expression));
}


// ---------------------------------------------------------------------------
// TCP stream reconstruction
// ---------------------------------------------------------------------------

class TCPStream {
    constructor(key) {
        this.key = key;
        this.segments = [];
    }

    add(packet) {
        this.segments.push(packet);
    }

    directions() {
        const groups = new Map();

        for (const packet of this.segments) {
            const key = `${packet.source}:${packet.sourcePort}`;

            if (!groups.has(key)) {
                groups.set(key, []);
            }

            groups.get(key).push(packet);
        }

        return groups;
    }

    reconstruct(source, sourcePort) {
        const segments = this.segments
            .filter(packet =>
                packet.source === source &&
                packet.sourcePort === sourcePort &&
                packet.payload.length > 0
            )
            .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));

        let output = '';
        let nextSequence = null;

        for (const packet of segments) {
            const sequence = packet.sequence ?? 0;

            if (nextSequence === null) {
                output += packet.payload;
                nextSequence = sequence + Buffer.byteLength(packet.payload);
                continue;
            }

            if (sequence >= nextSequence) {
                output += packet.payload;
                nextSequence = sequence + Buffer.byteLength(packet.payload);
                continue;
            }

            // Overlapping data may represent retransmission. This simple
            // implementation trims already-reassembled bytes.
            const overlap = nextSequence - sequence;
            const bytes = Buffer.from(packet.payload);

            if (overlap < bytes.length) {
                output += bytes.subarray(overlap).toString();
                nextSequence += bytes.length - overlap;
            }
        }

        return output;
    }
}

function buildTCPStreams(packets) {
    const streams = new Map();

    for (const packet of packets) {
        if (packet.protocol !== 'TCP') continue;

        const endpoints = packet.endpoint().sort();
        const key = `${endpoints[0]}<->${endpoints[1]}`;

        if (!streams.has(key)) {
            streams.set(key, new TCPStream(key));
        }

        streams.get(key).add(packet);
    }

    return streams;
}


// ---------------------------------------------------------------------------
// Statistics and indexes
// ---------------------------------------------------------------------------

function calculateStatistics(packets) {
    const protocolCounts = new Map();
    const sourceCounts = new Map();
    const destinationCounts = new Map();

    let totalBytes = 0;

    for (const packet of packets) {
        totalBytes += packet.length;

        protocolCounts.set(
            packet.protocol,
            (protocolCounts.get(packet.protocol) ?? 0) + 1
        );

        sourceCounts.set(
            packet.source,
            (sourceCounts.get(packet.source) ?? 0) + 1
        );

        destinationCounts.set(
            packet.destination,
            (destinationCounts.get(packet.destination) ?? 0) + 1
        );
    }

    return {
        packetCount: packets.length,
        totalBytes,
        protocolCounts,
        sourceCounts,
        destinationCounts
    };
}

class PacketIndex {
    /*
     * Repeated filtering can become O(number_of_packets) per query.
     * Indexes allow common exact-match queries to avoid scanning every packet.
     */
    constructor(packets) {
        this.bySource = new Map();
        this.byDestination = new Map();
        this.byProtocol = new Map();

        for (const packet of packets) {
            this.#add(this.bySource, packet.source, packet);
            this.#add(this.byDestination, packet.destination, packet);
            this.#add(this.byProtocol, packet.protocol, packet);
        }
    }

    #add(map, key, packet) {
        if (!map.has(key)) {
            map.set(key, []);
        }

        map.get(key).push(packet);
    }

    source(address) {
        return this.bySource.get(address) ?? [];
    }

    destination(address) {
        return this.byDestination.get(address) ?? [];
    }

    protocol(protocol) {
        return this.byProtocol.get(protocol) ?? [];
    }
}


// ---------------------------------------------------------------------------
// Suspicious-traffic indicators
// ---------------------------------------------------------------------------

const SUSPICIOUS_PORTS = new Map([
    [23, 'Telnet'],
    [445, 'SMB'],
    [3389, 'RDP'],
    [5900, 'VNC']
]);

function detectSuspiciousTraffic(packets) {
    const findings = [];
    const synCounts = new Map();
    const destinations = new Map();

    for (const packet of packets) {
        if (packet.protocol === 'TCP') {
            if (packet.hasFlag('SYN') && !packet.hasFlag('ACK')) {
                const key =
                    `${packet.source}->${packet.destination}:${packet.destinationPort}`;

                synCounts.set(key, (synCounts.get(key) ?? 0) + 1);
            }

            const service = SUSPICIOUS_PORTS.get(packet.destinationPort);

            if (service) {
                findings.push({
                    severity: 'MEDIUM',
                    packet: packet.number,
                    title: `Traffic to ${service}`,
                    evidence:
                        `${packet.source}:${packet.sourcePort} -> ` +
                        `${packet.destination}:${packet.destinationPort}`
                });
            }

            if (packet.hasFlag('RST')) {
                findings.push({
                    severity: 'LOW',
                    packet: packet.number,
                    title: 'TCP reset observed',
                    evidence:
                        `${packet.source}:${packet.sourcePort} -> ` +
                        `${packet.destination}:${packet.destinationPort}`
                });
            }
        }

        if (!destinations.has(packet.source)) {
            destinations.set(packet.source, new Set());
        }

        destinations.get(packet.source).add(packet.destination);
    }

    for (const [key, count] of synCounts) {
        if (count >= 10) {
            findings.push({
                severity: 'MEDIUM',
                packet: 0,
                title: 'Repeated TCP SYN attempts',
                evidence: `${key}: ${count} SYN packets`
            });
        }
    }

    for (const [source, destinationSet] of destinations) {
        if (destinationSet.size >= 50) {
            findings.push({
                severity: 'LOW',
                packet: 0,
                title: 'High destination fan-out',
                evidence:
                    `${source} contacted ${destinationSet.size} unique addresses`
            });
        }
    }

    return findings;
}


// ---------------------------------------------------------------------------
// Asynchronous analysis pipeline
// ---------------------------------------------------------------------------

function delay(milliseconds) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function analyzePacketAsynchronously(packet) {
    /*
     * A real application might perform asynchronous enrichment here.
     * The example deliberately avoids external services and simply yields
     * control to the event loop.
     */
    await delay(0);

    return {
        packetNumber: packet.number,
        applicationProtocol: classifyApplicationProtocol(packet),
        payloadBytes: Buffer.byteLength(packet.payload)
    };
}

async function analyzeCaptureAsynchronously(packets) {
    const results = [];

    for (const packet of packets) {
        results.push(await analyzePacketAsynchronously(packet));
    }

    return results;
}


// ---------------------------------------------------------------------------
// Defensive parsing example
// ---------------------------------------------------------------------------

function parseLengthPrefixedRecord(buffer) {
    /*
     * Network data must never be trusted merely because it is received in a
     * valid container. Validate lengths before slicing to prevent malformed
     * data from producing incorrect parser state.
     */
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError('Expected a Buffer.');
    }

    if (buffer.length < 4) {
        throw new Error('Record is too short to contain a length.');
    }

    const declaredLength = buffer.readUInt32BE(0);

    if (declaredLength > buffer.length - 4) {
        throw new Error(
            `Declared payload length ${declaredLength} exceeds available data.`
        );
    }

    return buffer.subarray(4, 4 + declaredLength);
}


// ---------------------------------------------------------------------------
// Demonstration
// ---------------------------------------------------------------------------

async function main() {
    console.log('=== PACKET ANALYSIS STUDY ===\n');

    const packets = createSyntheticCapture();

    console.log('Packet table:');

    for (const packet of packets) {
        console.log(
            String(packet.number).padStart(3),
            packet.source.padEnd(16),
            '->',
            packet.destination.padEnd(16),
            packet.protocol.padEnd(5),
            `${packet.sourcePort ?? '-'} -> ${packet.destinationPort ?? '-'}`
        );
    }

    console.log('\n=== PROTOCOL IDENTIFICATION ===');

    for (const packet of packets) {
        console.log(
            `Packet ${packet.number}: ${classifyApplicationProtocol(packet)}`
        );
    }

    console.log('\n=== FILTERS ===');

    const filters = [
        'tcp',
        'udp',
        'http',
        'tcp port 80',
        'ip.addr == 192.168.1.10',
        'tcp.flags.syn == 1',
        'tcp && ip.dst == 192.168.1.20'
    ];

    for (const expression of filters) {
        const matched = filterPackets(packets, expression);
        console.log(
            `${expression.padEnd(40)} ${matched.length} packet(s)`
        );
    }

    console.log('\n=== TCP STREAMS ===');

    const streams = buildTCPStreams(packets);

    for (const stream of streams.values()) {
        console.log(`\n${stream.key}`);

        for (const [direction] of stream.directions()) {
            const separator = direction.lastIndexOf(':');
            const source = direction.slice(0, separator);
            const sourcePort = Number(direction.slice(separator + 1));

            const payload = stream.reconstruct(source, sourcePort);

            console.log(
                `  ${direction}: ${Buffer.byteLength(payload)} bytes`
            );

            const http = analyzeHTTP(payload);

            if (http) {
                console.log(`    HTTP ${http.method} ${http.path}`);
                console.log(`    Host: ${http.host ?? '(not supplied)'}`);
            }
        }
    }

    console.log('\n=== DNS ===');

    for (const packet of packets) {
        if (classifyApplicationProtocol(packet) !== 'DNS') continue;

        const dns = analyzeDNS(packet.payload);

        if (dns) {
            console.log(
                `Packet ${packet.number}: ${dns.type} ${dns.query}`
            );
        }
    }

    console.log('\n=== STATISTICS ===');

    const statistics = calculateStatistics(packets);

    console.log(`Packets: ${statistics.packetCount}`);
    console.log(`Bytes:   ${statistics.totalBytes}`);

    console.log('Protocols:');

    for (const [protocol, count] of statistics.protocolCounts) {
        console.log(`  ${protocol}: ${count}`);
    }

    console.log('\n=== INDEXED LOOKUP ===');

    const index = new PacketIndex(packets);

    console.log(
        'Packets from 192.168.1.10:',
        index.source('192.168.1.10').length
    );

    console.log(
        'TCP packets:',
        index.protocol('TCP').length
    );

    console.log('\n=== TRAFFIC INDICATORS ===');

    const findings = detectSuspiciousTraffic(packets);

    for (const finding of findings) {
        console.log(
            `[${finding.severity}] ${finding.title}: ${finding.evidence}`
        );
    }

    console.log('\n=== ASYNCHRONOUS PIPELINE ===');

    const asynchronousResults =
        await analyzeCaptureAsynchronously(packets);

    for (const result of asynchronousResults.slice(0, 5)) {
        console.log(
            `Packet ${result.packetNumber}: ` +
            `${result.applicationProtocol}, ` +
            `${result.payloadBytes} payload bytes`
        );
    }

    console.log('\n=== MALFORMED-DATA VALIDATION ===');

    try {
        parseLengthPrefixedRecord(
            Buffer.from([0, 0, 0, 100, 1, 2])
        );
    } catch (error) {
        console.log(`Rejected malformed record: ${error.message}`);
    }

    console.log('\n=== HASHED PAYLOAD FINGERPRINT ===');

    const examplePayload = Buffer.from(
        packets[2].payload,
        'utf8'
    );

    /*
     * Hashing can help correlate identical artifacts without printing the
     * complete content. It is not encryption and cannot prove that a payload
     * is malicious.
     */
    const digest = crypto
        .createHash('sha256')
        .update(examplePayload)
        .digest('hex');

    console.log(`SHA-256: ${digest}`);
}

main().catch(error => {
    console.error(`Analysis failed: ${error.message}`);
    process.exitCode = 1;
});
