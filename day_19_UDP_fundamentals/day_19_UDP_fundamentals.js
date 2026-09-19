'use strict';

/*
 * UDP Fundamentals in JavaScript / Node.js
 *
 * This file demonstrates:
 * - UDP sockets and datagrams
 * - connectionless communication
 * - message boundaries
 * - ports and addresses
 * - asynchronous event-driven networking
 * - request/response protocols
 * - DNS-style application design
 * - sequence numbers
 * - application-level acknowledgements
 * - telemetry and streaming policies
 * - validation and security considerations
 * - multicast configuration
 * - simulated packet loss
 * - performance measurement
 *
 * Requires Node.js with the built-in `dgram` module.
 */

const dgram = require('node:dgram');
const crypto = require('node:crypto');

const HOST = '127.0.0.1';

function printSection(title) {
    console.log('\n' + '='.repeat(78));
    console.log(title);
    console.log('='.repeat(78));
}

// -----------------------------------------------------------------------------
// 1. FUNDAMENTAL CONCEPTS
// -----------------------------------------------------------------------------

function explainFundamentals() {
    printSection('UDP FUNDAMENTALS');

    console.log(`
UDP is the User Datagram Protocol.

It is a transport-layer protocol with a deliberately small service model.

Important properties:
- connectionless
- datagram-oriented
- best effort
- no built-in retransmission
- no built-in ordering guarantee
- no built-in duplicate suppression
- low transport overhead
- application-defined reliability when required

A UDP socket does not need a transport-layer connection to be established
before an application sends a datagram.

JavaScript running on Node.js accesses UDP through the built-in dgram module.
`);
}

// -----------------------------------------------------------------------------
// 2. UDP HEADER
// -----------------------------------------------------------------------------

function explainHeader() {
    printSection('UDP HEADER');

    const fields = [
        ['Source port', '16 bits'],
        ['Destination port', '16 bits'],
        ['Length', '16 bits'],
        ['Checksum', '16 bits']
    ];

    for (const [name, size] of fields) {
        console.log(`${name.padEnd(20)} ${size}`);
    }

    console.log(`
The UDP header is 8 bytes.

UDP does not carry TCP-style sequence numbers, acknowledgement numbers,
receive windows, or connection-state fields.

Those functions can be implemented by a higher-level protocol when necessary.
`);
}

// -----------------------------------------------------------------------------
// 3. BASIC UDP SERVER
// -----------------------------------------------------------------------------

function createUdpEchoServer({
    host = HOST,
    port = 0,
    messageLimit = 3
} = {}) {
    return new Promise((resolve, reject) => {
        const server = dgram.createSocket('udp4');
        let received = 0;

        server.on('error', (error) => {
            server.close();
            reject(error);
        });

        server.on('message', (message, remote) => {
            received += 1;

            console.log(
                `Server received ${message.length} bytes from ` +
                `${remote.address}:${remote.port}`
            );

            const response = Buffer.concat([
                Buffer.from('echo:'),
                message
            ]);

            server.send(
                response,
                remote.port,
                remote.address,
                (error) => {
                    if (error) {
                        console.error('send error:', error.message);
                    }
                }
            );

            if (received >= messageLimit) {
                setTimeout(() => server.close(), 20);
            }
        });

        server.bind(port, host, () => {
            const address = server.address();

            server.on('close', () => {
                resolve(address.port);
            });
        });
    });
}

function sendUdpMessage(host, port, message, timeoutMs = 1000) {
    return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        const payload = Buffer.from(message, 'utf8');

        let settled = false;

        const finish = (callback, value) => {
            if (settled) {
                return;
            }

            settled = true;
            clearTimeout(timer);
            client.close();
            callback(value);
        };

        const timer = setTimeout(() => {
            finish(reject, new Error('UDP response timeout'));
        }, timeoutMs);

        client.on('error', (error) => {
            finish(reject, error);
        });

        client.on('message', (response, remote) => {
            finish(resolve, {
                response,
                remote
            });
        });

        client.send(payload, port, host, (error) => {
            if (error) {
                finish(reject, error);
            }
        });
    });
}

async function demonstrateBasicUdp() {
    printSection('BASIC UDP CLIENT/SERVER');

    const serverPromise = createUdpEchoServer({
        messageLimit: 3
    });

    // The server binds asynchronously, so the demonstration waits until the
    // promise resolves with the operating-system-selected port.
    const port = await serverPromise;

    // The server has already closed after three messages, so this pattern
    // intentionally demonstrates a separate server lifecycle for each example.
    console.log(`Echo server used local UDP port ${port}.`);

    console.log(`
Node.js dgram uses an event-driven model. The 'message' event is emitted
when a UDP datagram arrives.

The `send()` method sends one datagram. The receiving application receives a
datagram as a Buffer, preserving UDP message boundaries.
`);
}

// -----------------------------------------------------------------------------
// 4. REUSABLE ECHO SERVER FOR REQUEST/RESPONSE
// -----------------------------------------------------------------------------

function startTemporaryEchoServer(messageLimit = 1) {
    return new Promise((resolve, reject) => {
        const server = dgram.createSocket('udp4');
        let received = 0;

        server.once('error', reject);

        server.on('message', (message, remote) => {
            received += 1;

            server.send(
                Buffer.concat([Buffer.from('echo:'), message]),
                remote.port,
                remote.address
            );

            if (received >= messageLimit) {
                setTimeout(() => server.close(), 10);
            }
        });

        server.bind(0, HOST, () => {
            const address = server.address();

            server.once('close', () => {
                resolve(address.port);
            });
        });
    });
}

function requestEcho(host, port, text) {
    return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        let completed = false;

        const timeout = setTimeout(() => {
            if (!completed) {
                completed = true;
                client.close();
                reject(new Error('request timed out'));
            }
        }, 1000);

        client.once('error', (error) => {
            if (!completed) {
                completed = true;
                clearTimeout(timeout);
                client.close();
                reject(error);
            }
        });

        client.once('message', (message) => {
            if (!completed) {
                completed = true;
                clearTimeout(timeout);
                client.close();
                resolve(message.toString('utf8'));
            }
        });

        client.send(Buffer.from(text), port, host);
    });
}

async function demonstrateDatagramBoundaries() {
    printSection('DATAGRAM BOUNDARIES');

    const port = await startTemporaryEchoServer(2);

    const first = await requestEcho(HOST, port, 'first');
    const second = await requestEcho(HOST, port, 'second');

    console.log('First response :', first);
    console.log('Second response:', second);

    console.log(`
UDP is message-oriented.

A datagram sent as "first" is not merged with the next datagram merely because
the same socket is used.

This differs from TCP, which exposes a continuous ordered byte stream.
`);
}

// -----------------------------------------------------------------------------
// 5. SERIALIZATION
// -----------------------------------------------------------------------------

class SensorReading {
    constructor(sensorId, sequence, temperatureC, timestamp = Date.now()) {
        this.sensorId = sensorId;
        this.sequence = sequence;
        this.temperatureC = temperatureC;
        this.timestamp = timestamp;
    }

    encode() {
        return Buffer.from(JSON.stringify({
            sensor_id: this.sensorId,
            sequence: this.sequence,
            temperature_c: this.temperatureC,
            timestamp: this.timestamp
        }), 'utf8');
    }

    static decode(buffer) {
        let object;

        try {
            object = JSON.parse(buffer.toString('utf8'));
        } catch (error) {
            throw new Error(`invalid JSON: ${error.message}`);
        }

        if (
            object === null ||
            typeof object !== 'object' ||
            Array.isArray(object)
        ) {
            throw new Error('message must contain a JSON object');
        }

        if (typeof object.sensor_id !== 'string') {
            throw new Error('sensor_id must be a string');
        }

        if (!Number.isInteger(object.sequence)) {
            throw new Error('sequence must be an integer');
        }

        if (
            typeof object.temperature_c !== 'number' ||
            !Number.isFinite(object.temperature_c)
        ) {
            throw new Error('temperature_c must be a finite number');
        }

        return new SensorReading(
            object.sensor_id,
            object.sequence,
            object.temperature_c,
            Number(object.timestamp)
        );
    }
}

function demonstrateSerialization() {
    printSection('APPLICATION MESSAGE SERIALIZATION');

    const reading = new SensorReading(
        'warehouse-17',
        42,
        21.75
    );

    const encoded = reading.encode();
    const decoded = SensorReading.decode(encoded);

    console.log('Encoded:', encoded.toString('utf8'));
    console.log('Decoded:', decoded);
}

// -----------------------------------------------------------------------------
// 6. SEQUENCE TRACKING
// -----------------------------------------------------------------------------

class SequenceTracker {
    constructor() {
        this.lastSequence = null;
        this.missingPackets = 0;
        this.duplicatesOrLate = 0;
    }

    observe(sequence) {
        if (this.lastSequence === null) {
            this.lastSequence = sequence;
            return;
        }

        if (sequence > this.lastSequence + 1) {
            this.missingPackets += sequence - this.lastSequence - 1;
            this.lastSequence = sequence;
        } else if (sequence === this.lastSequence + 1) {
            this.lastSequence = sequence;
        } else {
            this.duplicatesOrLate += 1;
        }
    }
}

function demonstrateSequenceNumbers() {
    printSection('SEQUENCE NUMBERS');

    const tracker = new SequenceTracker();
    const received = [1, 2, 4, 5, 5, 7];

    for (const sequence of received) {
        tracker.observe(sequence);
    }

    console.log('Received:', received);
    console.log('Missing estimate:', tracker.missingPackets);
    console.log('Duplicate/late observations:', tracker.duplicatesOrLate);

    console.log(`
A sequence number is application data. UDP itself does not interpret it.

The receiving application can use sequence numbers to:
- identify gaps
- reject duplicates
- reorder data
- detect stale state
- trigger retransmission
`);
}

// -----------------------------------------------------------------------------
// 7. APPLICATION-LEVEL ACKNOWLEDGEMENTS
// -----------------------------------------------------------------------------

const MESSAGE_TYPES = Object.freeze({
    DATA: 1,
    ACK: 2
});

function encodeReliableMessage(sequence, payload) {
    const header = Buffer.alloc(10);

    header.writeUInt8(1, 0);                 // protocol version
    header.writeUInt8(MESSAGE_TYPES.DATA, 1);
    header.writeBigUInt64BE(BigInt(sequence), 2);

    return Buffer.concat([header, Buffer.from(payload)]);
}

function decodeReliableMessage(buffer) {
    if (buffer.length < 10) {
        throw new Error('reliable message is too short');
    }

    const version = buffer.readUInt8(0);
    const messageType = buffer.readUInt8(1);
    const sequence = Number(buffer.readBigUInt64BE(2));

    if (version !== 1) {
        throw new Error(`unsupported protocol version: ${version}`);
    }

    if (messageType !== MESSAGE_TYPES.DATA) {
        throw new Error('expected DATA message');
    }

    return {
        sequence,
        payload: buffer.subarray(10)
    };
}

function encodeAck(sequence) {
    const header = Buffer.alloc(10);

    header.writeUInt8(1, 0);
    header.writeUInt8(MESSAGE_TYPES.ACK, 1);
    header.writeBigUInt64BE(BigInt(sequence), 2);

    return header;
}

function decodeAck(buffer) {
    if (buffer.length !== 10) {
        throw new Error('invalid ACK length');
    }

    const version = buffer.readUInt8(0);
    const messageType = buffer.readUInt8(1);

    if (version !== 1 || messageType !== MESSAGE_TYPES.ACK) {
        throw new Error('invalid ACK');
    }

    return Number(buffer.readBigUInt64BE(2));
}

function startAckServer(expectedMessages = 3) {
    return new Promise((resolve, reject) => {
        const server = dgram.createSocket('udp4');
        let processed = 0;

        server.once('error', reject);

        server.on('message', (message, remote) => {
            try {
                const decoded = decodeReliableMessage(message);

                console.log(
                    `ACK server received sequence=${decoded.sequence} ` +
                    `payload=${decoded.payload.toString('utf8')}`
                );

                server.send(
                    encodeAck(decoded.sequence),
                    remote.port,
                    remote.address
                );

                processed += 1;

                if (processed >= expectedMessages) {
                    setTimeout(() => server.close(), 10);
                }
            } catch (error) {
                console.error('Rejected packet:', error.message);
            }
        });

        server.bind(0, HOST, () => {
            resolve(server.address().port);
        });
    });
}

function sendReliableMessage(
    host,
    port,
    sequence,
    payload,
    {
        retries = 3,
        timeoutMs = 300
    } = {}
) {
    return new Promise((resolve) => {
        const attempt = (number) => {
            if (number > retries) {
                resolve(false);
                return;
            }

            const client = dgram.createSocket('udp4');
            let completed = false;

            const finish = (success) => {
                if (completed) {
                    return;
                }

                completed = true;
                clearTimeout(timeout);
                client.close();
                resolve(success);
            };

            const timeout = setTimeout(() => {
                console.log(
                    `sequence=${sequence} timed out on attempt ${number}`
                );

                client.close();
                attempt(number + 1);
            }, timeoutMs);

            client.on('error', () => {
                finish(false);
            });

            client.on('message', (message) => {
                try {
                    const acknowledged = decodeAck(message);

                    if (acknowledged === sequence) {
                        console.log(
                            `sequence=${sequence} acknowledged on attempt ${number}`
                        );
                        finish(true);
                    } else {
                        finish(false);
                    }
                } catch {
                    finish(false);
                }
            });

            client.send(
                encodeReliableMessage(sequence, payload),
                port,
                host
            );
        };

        attempt(1);
    });
}

async function demonstrateReliability() {
    printSection('APPLICATION-LEVEL RELIABILITY');

    const port = await startAckServer(3);

    for (let sequence = 1; sequence <= 3; sequence += 1) {
        const success = await sendReliableMessage(
            HOST,
            port,
            sequence,
            `payload-${sequence}`
        );

        console.log(
            `sequence=${sequence} success=${success}`
        );
    }

    console.log(`
This stop-and-wait design demonstrates the principle of reliability layered
above UDP.

Production protocols may require:
- sliding windows
- selective acknowledgements
- congestion control
- retransmission timers
- duplicate suppression
- authentication
- encryption
- connection/session identifiers
`);
}

// -----------------------------------------------------------------------------
// 8. DNS-STYLE REQUEST/RESPONSE
// -----------------------------------------------------------------------------

class MiniDnsService {
    constructor(records) {
        this.records = new Map(
            Object.entries(records).map(([name, address]) => [
                name.toLowerCase().replace(/\.$/, ''),
                address
            ])
        );
    }

    handle(buffer) {
        let query;

        try {
            query = JSON.parse(buffer.toString('utf8'));
        } catch {
            return Buffer.from(JSON.stringify({
                status: 'FORMERR'
            }));
        }

        if (
            query === null ||
            typeof query !== 'object' ||
            typeof query.name !== 'string'
        ) {
            return Buffer.from(JSON.stringify({
                status: 'FORMERR'
            }));
        }

        const name = query.name.toLowerCase().replace(/\.$/, '');
        const address = this.records.get(name);

        if (!address) {
            return Buffer.from(JSON.stringify({
                status: 'NXDOMAIN',
                name
            }));
        }

        return Buffer.from(JSON.stringify({
            status: 'NOERROR',
            name,
            address
        }));
    }
}

function startMiniDnsService(records) {
    return new Promise((resolve, reject) => {
        const service = new MiniDnsService(records);
        const server = dgram.createSocket('udp4');

        server.once('error', reject);

        server.on('message', (message, remote) => {
            if (message.toString('utf8') === '__STOP__') {
                server.close();
                return;
            }

            const response = service.handle(message);

            server.send(
                response,
                remote.port,
                remote.address
            );
        });

        server.bind(0, HOST, () => {
            resolve({
                port: server.address().port,
                stop() {
                    const stopper = dgram.createSocket('udp4');
                    stopper.send(
                        Buffer.from('__STOP__'),
                        server.address().port,
                        HOST,
                        () => stopper.close()
                    );
                }
            });
        });
    });
}

function miniDnsQuery(port, name) {
    return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');

        const timer = setTimeout(() => {
            client.close();
            reject(new Error('DNS-style query timeout'));
        }, 1000);

        client.once('error', (error) => {
            clearTimeout(timer);
            client.close();
            reject(error);
        });

        client.once('message', (message) => {
            clearTimeout(timer);
            client.close();

            try {
                resolve(JSON.parse(message.toString('utf8')));
            } catch (error) {
                reject(error);
            }
        });

        client.send(
            Buffer.from(JSON.stringify({ name })),
            port,
            HOST
        );
    });
}

async function demonstrateDnsStyle() {
    printSection('DNS-STYLE UDP REQUEST/RESPONSE');

    const service = await startMiniDnsService({
        'example.local': '192.0.2.20',
        'api.local': '192.0.2.30'
    });

    try {
        for (const name of [
            'example.local',
            'missing.local',
            'api.local'
        ]) {
            const answer = await miniDnsQuery(service.port, name);
            console.log(name, '->', answer);
        }
    } finally {
        service.stop();
    }

    console.log(`
DNS commonly uses UDP for compact request/response exchanges, although DNS
also supports other transports and mechanisms.

Real DNS has binary message formats, transaction identifiers, resource records,
caching, recursive resolution, truncation handling, DNSSEC, EDNS, and other
features not represented by this educational service.
`);
}

// -----------------------------------------------------------------------------
// 9. REAL-TIME TELEMETRY
// -----------------------------------------------------------------------------

class TelemetryReceiver {
    constructor() {
        this.latestSequence = -1;
        this.latestValue = null;
        this.accepted = 0;
        this.discarded = 0;
    }

    receive(sequence, value) {
        if (sequence <= this.latestSequence) {
            this.discarded += 1;
            return;
        }

        this.latestSequence = sequence;
        this.latestValue = value;
        this.accepted += 1;
    }
}

function demonstrateTelemetry() {
    printSection('REAL-TIME TELEMETRY');

    const receiver = new TelemetryReceiver();

    const samples = [
        [100, 20.1],
        [101, 20.2],
        [103, 20.4],
        [102, 20.3],
        [104, 20.5]
    ];

    for (const [sequence, value] of samples) {
        receiver.receive(sequence, value);
    }

    console.log(receiver);

    console.log(`
For some real-time applications, old data has limited value.

A receiver may therefore:
- accept the newest state
- discard stale packets
- interpolate missing samples
- tolerate limited loss
- use a jitter buffer

This is fundamentally different from an application where every message
represents a transaction that must be processed exactly once.
`);
}

// -----------------------------------------------------------------------------
// 10. MULTICAST
// -----------------------------------------------------------------------------

function demonstrateMulticastConfiguration() {
    printSection('MULTICAST');

    const group = '239.255.0.1';
    const ttl = 2;

    console.log('Example multicast group:', group);
    console.log('Example TTL:', ttl);

    console.log(`
Node.js dgram supports multicast operations such as:
- addMembership()
- dropMembership()
- setMulticastTTL()
- setMulticastInterface()

A multicast group allows multiple receivers to subscribe to the same
destination address.

Actual multicast behavior depends on network interfaces, operating-system
permissions, routing, firewalls, and network infrastructure.
`);
}

// -----------------------------------------------------------------------------
// 11. SECURITY VALIDATION
// -----------------------------------------------------------------------------

const MAX_DATAGRAM_SIZE = 1200;

function validateApplicationMessage(buffer) {
    if (!Buffer.isBuffer(buffer)) {
        throw new TypeError('expected a Buffer');
    }

    if (buffer.length > MAX_DATAGRAM_SIZE) {
        throw new Error('application datagram exceeds configured limit');
    }

    let object;

    try {
        object = JSON.parse(buffer.toString('utf8'));
    } catch {
        throw new Error('invalid JSON');
    }

    if (
        object === null ||
        typeof object !== 'object' ||
        Array.isArray(object)
    ) {
        throw new Error('expected a JSON object');
    }

    if (!['telemetry', 'heartbeat'].includes(object.type)) {
        throw new Error('unsupported message type');
    }

    return object;
}

function demonstrateSecurity() {
    printSection('SECURITY AND VALIDATION');

    const valid = Buffer.from(
        JSON.stringify({
            type: 'heartbeat',
            device: 'sensor-7'
        })
    );

    const invalid = Buffer.from(
        JSON.stringify({
            type: 'unexpected',
            device: 'sensor-7'
        })
    );

    console.log('Valid:', validateApplicationMessage(valid));

    try {
        validateApplicationMessage(invalid);
    } catch (error) {
        console.log('Rejected invalid datagram:', error.message);
    }

    console.log(`
UDP does not authenticate source addresses.

Important security concerns include:
- spoofing
- reflection/amplification
- flooding
- malformed input
- replay
- resource exhaustion
- state exhaustion
- lack of confidentiality
- lack of application-level authentication

Defensive measures include bounded parsing, rate limiting, authentication,
replay protection, careful state management, logging, and firewall policy.
`);
}

// -----------------------------------------------------------------------------
// 12. CRYPTOGRAPHIC INTEGRITY
// -----------------------------------------------------------------------------

function demonstrateHashing() {
    printSection('CRYPTOGRAPHIC INTEGRITY');

    const payload = Buffer.from('important UDP application data');

    const digest = crypto
        .createHash('sha256')
        .update(payload)
        .digest('hex');

    console.log('Payload:', payload.toString('utf8'));
    console.log('SHA-256:', digest);

    console.log(`
A hash detects changes when the expected digest is trusted.

A plain hash does not prove who sent a packet.

For authenticated communication, use an appropriate cryptographic
authentication mechanism. For confidentiality, use authenticated encryption
or an established secure protocol rather than inventing cryptography.
`);
}

// -----------------------------------------------------------------------------
// 13. SIMULATED LOSS
// -----------------------------------------------------------------------------

class LossyChannel {
    constructor({
        lossProbability = 0.2,
        duplicateProbability = 0.1,
        random = Math.random
    } = {}) {
        if (
            lossProbability < 0 ||
            lossProbability > 1 ||
            duplicateProbability < 0 ||
            duplicateProbability > 1
        ) {
            throw new RangeError('probabilities must be between 0 and 1');
        }

        this.lossProbability = lossProbability;
        this.duplicateProbability = duplicateProbability;
        this.random = random;
    }

    transmit(packet) {
        if (this.random() < this.lossProbability) {
            return [];
        }

        const result = [packet];

        if (this.random() < this.duplicateProbability) {
            result.push(packet);
        }

        return result;
    }
}

function demonstrateLossSimulation() {
    printSection('SIMULATED PACKET LOSS');

    // A deterministic pseudo-random source makes this example repeatable.
    let state = 123456789;

    function deterministicRandom() {
        state = (1664525 * state + 1013904223) >>> 0;
        return state / 0x100000000;
    }

    const channel = new LossyChannel({
        lossProbability: 0.2,
        duplicateProbability: 0.1,
        random: deterministicRandom
    });

    let delivered = 0;
    let duplicateEvents = 0;

    for (let sequence = 1; sequence <= 20; sequence += 1) {
        const packet = Buffer.from(`packet-${sequence}`);
        const copies = channel.transmit(packet);

        delivered += copies.length;

        if (copies.length === 2) {
            duplicateEvents += 1;
        }
    }

    console.log('Original packets:', 20);
    console.log('Delivered copies:', delivered);
    console.log('Duplicate events:', duplicateEvents);
}

// -----------------------------------------------------------------------------
// 14. PERFORMANCE MEASUREMENT
// -----------------------------------------------------------------------------

function startBenchmarkServer(iterations) {
    return new Promise((resolve, reject) => {
        const server = dgram.createSocket('udp4');
        let count = 0;

        server.once('error', reject);

        server.on('message', (message, remote) => {
            count += 1;

            server.send(
                message,
                remote.port,
                remote.address
            );

            if (count >= iterations) {
                setTimeout(() => server.close(), 10);
            }
        });

        server.bind(0, HOST, () => {
            resolve(server.address().port);
        });
    });
}

function runBenchmarkRequest(port, payload) {
    return new Promise((resolve, reject) => {
        const client = dgram.createSocket('udp4');
        const started = process.hrtime.bigint();

        const timeout = setTimeout(() => {
            client.close();
            reject(new Error('benchmark timeout'));
        }, 1000);

        client.once('error', (error) => {
            clearTimeout(timeout);
            client.close();
            reject(error);
        });

        client.once('message', () => {
            clearTimeout(timeout);
            client.close();

            const elapsedNs =
                process.hrtime.bigint() - started;

            resolve(Number(elapsedNs) / 1_000_000);
        });

        client.send(payload, port, HOST);
    });
}

async function benchmarkLocalUdp(iterations = 50) {
    printSection('LOCAL UDP LATENCY BENCHMARK');

    const port = await startBenchmarkServer(iterations);
    const samples = [];

    for (let i = 0; i < iterations; i += 1) {
        samples.push(
            await runBenchmarkRequest(
                port,
                Buffer.from(`benchmark-${i}`)
            )
        );
    }

    const minimum = Math.min(...samples);
    const maximum = Math.max(...samples);
    const average =
        samples.reduce((sum, value) => sum + value, 0) /
        samples.length;

    console.log(`Iterations: ${iterations}`);
    console.log(`Minimum:   ${minimum.toFixed(3)} ms`);
    console.log(`Average:   ${average.toFixed(3)} ms`);
    console.log(`Maximum:   ${maximum.toFixed(3)} ms`);

    console.log(`
This measures only a local loopback path. It does not represent Internet
latency, loss, jitter, congestion, or geographic distance.
`);
}

// -----------------------------------------------------------------------------
// 15. EDGE CASES
// -----------------------------------------------------------------------------

function demonstrateEdgeCases() {
    printSection('EDGE CASES');

    const edgeCases = [
        {
            name: 'empty payload',
            payload: Buffer.alloc(0)
        },
        {
            name: 'binary payload',
            payload: Buffer.from([0, 1, 2, 255])
        },
        {
            name: 'Unicode payload',
            payload: Buffer.from('नमस्ते UDP', 'utf8')
        }
    ];

    for (const item of edgeCases) {
        console.log(
            `${item.name}: ${item.payload.length} bytes`
        );
    }

    console.log(`
Applications should explicitly define whether empty messages are valid,
whether payloads are text or binary, how character encoding is handled,
and what maximum datagram size is accepted.
`);
}

// -----------------------------------------------------------------------------
// 16. UDP VS TCP
// -----------------------------------------------------------------------------

function compareUdpTcp() {
    printSection('UDP VS TCP');

    const comparison = [
        ['Connection setup', 'None at transport layer', 'Transport connection setup'],
        ['Data model', 'Datagrams', 'Byte stream'],
        ['Ordering', 'Not guaranteed', 'Ordered byte stream'],
        ['Retransmission', 'Not built in', 'Built in'],
        ['Message boundaries', 'Preserved', 'Not preserved'],
        ['Congestion control', 'Not provided by UDP', 'Provided by TCP'],
        ['Multicast/broadcast model', 'Compatible with relevant IP mechanisms', 'Not a TCP feature'],
        ['Typical applications', 'DNS, telemetry, media, games', 'Web, file transfer, many APIs']
    ];

    for (const [property, udp, tcp] of comparison) {
        console.log(`\n${property}`);
        console.log(`  UDP: ${udp}`);
        console.log(`  TCP: ${tcp}`);
    }
}

// -----------------------------------------------------------------------------
// 17. ADVANCED CONCEPTS
// -----------------------------------------------------------------------------

function explainAdvancedConcepts() {
    printSection('ADVANCED UDP CONCEPTS');

    console.log(`
Jitter
  Variation in packet arrival timing. Real-time systems may buffer packets
  briefly to reduce the visible effect of timing variation.

Loss
  A datagram may never reach the application.

Reordering
  Datagrams may arrive in an order different from their sending order.

Sliding windows
  Multiple messages can be outstanding before acknowledgements arrive.
  This can improve throughput compared with stop-and-wait.

Selective retransmission
  Only missing packets are retransmitted.

Forward error correction
  Redundancy can allow some lost information to be recovered without
  retransmission.

Congestion control
  UDP itself does not supply TCP-style congestion control. A responsible
  UDP-based Internet protocol needs an appropriate congestion strategy.

DTLS
  Datagram Transport Layer Security provides security mechanisms designed
  for datagram-oriented communication.

QUIC
  QUIC runs over UDP while providing a much richer transport service,
  including encryption, connection management, streams, reliability,
  congestion control, and loss recovery.

NAT traversal
  UDP is used in several real-time communication architectures where endpoints
  need to establish paths through NAT devices.

UDP is therefore a transport building block, not a complete application
communication architecture.
`);
}

// -----------------------------------------------------------------------------
// 18. PRODUCTION CHECKLIST
// -----------------------------------------------------------------------------

function printProductionChecklist() {
    printSection('PRODUCTION DESIGN CHECKLIST');

    const checklist = [
        'Define whether packet loss is acceptable.',
        'Define whether ordering is required.',
        'Define duplicate handling.',
        'Define timeout behavior.',
        'Bound accepted datagram sizes.',
        'Validate every field.',
        'Use explicit message types and versions.',
        'Consider sequence numbers.',
        'Consider authentication.',
        'Use encryption when confidentiality is required.',
        'Prevent unbounded sender/client state.',
        'Implement rate limiting where appropriate.',
        'Test loss, duplication, delay, and malformed packets.',
        'Measure latency and jitter rather than assuming them.',
        'Document the application protocol.',
        'Consider MTU and fragmentation behavior.',
        'Monitor packet loss and resource consumption.'
    ];

    for (const item of checklist) {
        console.log(`[ ] ${item}`);
    }
}

// -----------------------------------------------------------------------------
// 19. SELF TESTS
// -----------------------------------------------------------------------------

function runSelfTests() {
    printSection('SELF TESTS');

    const sensor = new SensorReading(
        'sensor-a',
        7,
        22.5,
        1000
    );

    const decodedSensor =
        SensorReading.decode(sensor.encode());

    console.assert(
        decodedSensor.sensorId === 'sensor-a',
        'sensor ID test failed'
    );

    console.assert(
        decodedSensor.sequence === 7,
        'sensor sequence test failed'
    );

    const reliable = encodeReliableMessage(
        42,
        'hello'
    );

    const decodedReliable =
        decodeReliableMessage(reliable);

    console.assert(
        decodedReliable.sequence === 42,
        'reliable sequence test failed'
    );

    console.assert(
        decodedReliable.payload.toString() === 'hello',
        'reliable payload test failed'
    );

    const ack = encodeAck(42);

    console.assert(
        decodeAck(ack) === 42,
        'ACK test failed'
    );

    try {
        decodeReliableMessage(Buffer.alloc(2));
        throw new Error('short packet was not rejected');
    } catch (error) {
        if (error.message === 'short packet was not rejected') {
            throw error;
        }
    }

    try {
        validateApplicationMessage(
            Buffer.from(JSON.stringify({
                type: 'unknown'
            }))
        );
        throw new Error('invalid message type was not rejected');
    } catch (error) {
        if (error.message === 'invalid message type was not rejected') {
            throw error;
        }
    }

    console.log('All self-tests passed.');
}

// -----------------------------------------------------------------------------
// 20. MAIN
// -----------------------------------------------------------------------------

async function main() {
    explainFundamentals();
    explainHeader();
    await demonstrateBasicUdp();
    await demonstrateDatagramBoundaries();
    demonstrateSerialization();
    demonstrateSequenceNumbers();
    await demonstrateReliability();
    await demonstrateDnsStyle();
    demonstrateTelemetry();
    demonstrateMulticastConfiguration();
    demonstrateSecurity();
    demonstrateHashing();
    demonstrateLossSimulation();
    demonstrateEdgeCases();
    compareUdpTcp();
    explainAdvancedConcepts();
    printProductionChecklist();
    runSelfTests();
    await benchmarkLocalUdp(30);

    printSection('END OF UDP STUDY PROGRAM');
}

main().catch((error) => {
    console.error('Fatal error:', error);
    process.exitCode = 1;
});
