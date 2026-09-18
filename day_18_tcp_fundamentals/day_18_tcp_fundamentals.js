'use strict';

/*
 * TCP Fundamentals in JavaScript
 * --------------------------------
 *
 * This file complements the Python study implementation by emphasizing
 * JavaScript's object model, typed arrays, functional processing, event-driven
 * simulation, asynchronous timers, validation, and browser-friendly design.
 *
 * No external npm packages are required.
 */

// -----------------------------------------------------------------------------
// 1. TCP segment representation
// -----------------------------------------------------------------------------

const TCP_FLAGS = Object.freeze({
    FIN: 0x01,
    SYN: 0x02,
    RST: 0x04,
    PSH: 0x08,
    ACK: 0x10,
    URG: 0x20,
    ECE: 0x40,
    CWR: 0x80
});

function flagNames(flagMask) {
    return Object.entries(TCP_FLAGS)
        .filter(([, value]) => (flagMask & value) !== 0)
        .map(([name]) => name);
}

class TCPSegment {
    constructor({
        source,
        destination,
        sequenceNumber,
        acknowledgmentNumber = null,
        flags = 0,
        payload = new Uint8Array(),
        advertisedWindow = 65535
    }) {
        if (!Number.isSafeInteger(sequenceNumber) || sequenceNumber < 0) {
            throw new RangeError('Invalid sequence number');
        }

        if (
            acknowledgmentNumber !== null &&
            (!Number.isSafeInteger(acknowledgmentNumber) ||
                acknowledgmentNumber < 0)
        ) {
            throw new RangeError('Invalid acknowledgment number');
        }

        if (!(payload instanceof Uint8Array)) {
            throw new TypeError('Payload must be a Uint8Array');
        }

        if (!Number.isSafeInteger(advertisedWindow) || advertisedWindow < 0) {
            throw new RangeError('Invalid advertised window');
        }

        this.source = source;
        this.destination = destination;
        this.sequenceNumber = sequenceNumber;
        this.acknowledgmentNumber = acknowledgmentNumber;
        this.flags = flags;
        this.payload = payload;
        this.advertisedWindow = advertisedWindow;
    }

    get payloadLength() {
        return this.payload.byteLength;
    }

    get sequenceSpaceConsumed() {
        let consumed = this.payloadLength;

        if ((this.flags & TCP_FLAGS.SYN) !== 0) {
            consumed += 1;
        }

        if ((this.flags & TCP_FLAGS.FIN) !== 0) {
            consumed += 1;
        }

        return consumed;
    }

    describe() {
        return [
            `${this.source} -> ${this.destination}`,
            `SEQ=${this.sequenceNumber}`,
            `ACK=${this.acknowledgmentNumber ?? '-'}`,
            `FLAGS=${flagNames(this.flags).join(',') || 'NONE'}`,
            `PAYLOAD=${this.payloadLength}`,
            `WINDOW=${this.advertisedWindow}`
        ].join(' | ');
    }
}

function textToBytes(text) {
    return new TextEncoder().encode(text);
}

function bytesToText(bytes) {
    return new TextDecoder().decode(bytes);
}


// -----------------------------------------------------------------------------
// 2. Three-way handshake
// -----------------------------------------------------------------------------

function createHandshake(clientISN, serverISN) {
    const syn = new TCPSegment({
        source: 'CLIENT',
        destination: 'SERVER',
        sequenceNumber: clientISN,
        flags: TCP_FLAGS.SYN
    });

    const synAck = new TCPSegment({
        source: 'SERVER',
        destination: 'CLIENT',
        sequenceNumber: serverISN,
        acknowledgmentNumber: clientISN + 1,
        flags: TCP_FLAGS.SYN | TCP_FLAGS.ACK
    });

    const ack = new TCPSegment({
        source: 'CLIENT',
        destination: 'SERVER',
        sequenceNumber: clientISN + 1,
        acknowledgmentNumber: serverISN + 1,
        flags: TCP_FLAGS.ACK
    });

    return [syn, synAck, ack];
}

console.log('=== TCP three-way handshake ===');

createHandshake(1000, 5000).forEach((segment, index) => {
    console.log(`Step ${index + 1}: ${segment.describe()}`);
});


// -----------------------------------------------------------------------------
// 3. Sequence-number arithmetic
// -----------------------------------------------------------------------------

const TCP_SEQUENCE_SPACE = 2 ** 32;

function addSequenceNumber(sequenceNumber, amount) {
    if (!Number.isInteger(sequenceNumber) || !Number.isInteger(amount)) {
        throw new TypeError('Sequence values must be integers');
    }

    return (sequenceNumber + amount) % TCP_SEQUENCE_SPACE;
}

console.log('\n=== Sequence numbers ===');

const dataSegment = new TCPSegment({
    source: 'CLIENT',
    destination: 'SERVER',
    sequenceNumber: 1001,
    acknowledgmentNumber: 5001,
    flags: TCP_FLAGS.ACK,
    payload: textToBytes('HELLO')
});

console.log(dataSegment.describe());
console.log(
    'Next expected sequence number:',
    dataSegment.sequenceNumber + dataSegment.sequenceSpaceConsumed
);

console.log(
    'Wrap-around example:',
    addSequenceNumber(TCP_SEQUENCE_SPACE - 2, 5)
);


// -----------------------------------------------------------------------------
// 4. Receive-window model
// -----------------------------------------------------------------------------

class ReceiveWindow {
    constructor(capacity) {
        if (!Number.isSafeInteger(capacity) || capacity < 0) {
            throw new RangeError('Capacity must be a non-negative integer');
        }

        this.capacity = capacity;
        this.buffered = 0;
    }

    get advertisedWindow() {
        return Math.max(0, this.capacity - this.buffered);
    }

    receive(byteCount) {
        if (!Number.isSafeInteger(byteCount) || byteCount < 0) {
            throw new RangeError('byteCount must be a non-negative integer');
        }

        if (byteCount > this.advertisedWindow) {
            return false;
        }

        this.buffered += byteCount;
        return true;
    }

    consume(byteCount) {
        if (!Number.isSafeInteger(byteCount) || byteCount < 0) {
            throw new RangeError('byteCount must be a non-negative integer');
        }

        this.buffered = Math.max(0, this.buffered - byteCount);
    }
}

console.log('\n=== Receive window ===');

const receiveWindow = new ReceiveWindow(10_000);

console.log('Initial window:', receiveWindow.advertisedWindow);

for (const bytes of [2000, 3000, 4000]) {
    console.log(
        `Receive ${bytes}:`,
        receiveWindow.receive(bytes),
        'window:',
        receiveWindow.advertisedWindow
    );
}

receiveWindow.consume(5000);

console.log(
    'After application consumes 5000 bytes:',
    receiveWindow.advertisedWindow
);


// -----------------------------------------------------------------------------
// 5. Sliding-window sender
// -----------------------------------------------------------------------------

class SlidingWindowSender {
    constructor({
        initialSequence,
        receiveWindow,
        congestionWindow
    }) {
        if (!Number.isSafeInteger(initialSequence) || initialSequence < 0) {
            throw new RangeError('Invalid initial sequence');
        }

        this.oldestUnacknowledged = initialSequence;
        this.nextSequence = initialSequence;
        this.receiveWindow = receiveWindow;
        this.congestionWindow = congestionWindow;
        this.outstanding = new Map();
    }

    get effectiveWindow() {
        return Math.min(
            this.receiveWindow,
            this.congestionWindow
        );
    }

    get bytesInFlight() {
        return this.nextSequence - this.oldestUnacknowledged;
    }

    get availableCapacity() {
        return Math.max(
            0,
            this.effectiveWindow - this.bytesInFlight
        );
    }

    send(payload) {
        if (!(payload instanceof Uint8Array)) {
            throw new TypeError('Payload must be Uint8Array');
        }

        if (payload.length === 0) {
            throw new RangeError('Payload cannot be empty');
        }

        const capacity = this.availableCapacity;

        if (capacity === 0) {
            throw new Error('Sliding window is full');
        }

        const actualLength = Math.min(capacity, payload.length);
        const actualPayload = payload.slice(0, actualLength);
        const sequence = this.nextSequence;

        this.outstanding.set(sequence, actualPayload);
        this.nextSequence += actualLength;

        return new TCPSegment({
            source: 'SENDER',
            destination: 'RECEIVER',
            sequenceNumber: sequence,
            flags: TCP_FLAGS.ACK,
            payload: actualPayload,
            advertisedWindow: this.receiveWindow
        });
    }

    acknowledge(acknowledgmentNumber) {
        if (acknowledgmentNumber < this.oldestUnacknowledged) {
            return 0;
        }

        if (acknowledgmentNumber > this.nextSequence) {
            throw new RangeError(
                'ACK acknowledges unsent sequence space'
            );
        }

        const previous = this.oldestUnacknowledged;
        this.oldestUnacknowledged = acknowledgmentNumber;

        for (const [sequence, payload] of this.outstanding) {
            if (sequence + payload.length <= acknowledgmentNumber) {
                this.outstanding.delete(sequence);
            }
        }

        return acknowledgmentNumber - previous;
    }
}

console.log('\n=== Sliding-window sender ===');

const sender = new SlidingWindowSender({
    initialSequence: 10_000,
    receiveWindow: 5000,
    congestionWindow: 3000
});

const firstPayload = new Uint8Array(2000).fill(65);
const secondPayload = new Uint8Array(2000).fill(66);

const firstSegment = sender.send(firstPayload);
const secondSegment = sender.send(secondPayload);

console.log(firstSegment.describe());
console.log(secondSegment.describe());
console.log('Bytes in flight:', sender.bytesInFlight);
console.log('Available capacity:', sender.availableCapacity);

console.log(
    'Newly acknowledged bytes:',
    sender.acknowledge(13_000)
);

console.log('Bytes in flight:', sender.bytesInFlight);


// -----------------------------------------------------------------------------
// 6. Out-of-order receiver
// -----------------------------------------------------------------------------

class OrderedTCPReceiver {
    constructor(initialSequence) {
        this.nextExpected = initialSequence;
        this.buffer = new Map();
        this.receivedChunks = [];
    }

    receive(segment) {
        if (segment.payloadLength === 0) {
            return this.nextExpected;
        }

        const sequence = segment.sequenceNumber;

        if (sequence === this.nextExpected) {
            this.deliver(segment.payload);

            while (this.buffer.has(this.nextExpected)) {
                const payload = this.buffer.get(this.nextExpected);
                this.buffer.delete(this.nextExpected);
                this.deliver(payload);
            }
        } else if (sequence > this.nextExpected) {
            // Data arrived too early. Keep it until the missing range arrives.
            if (!this.buffer.has(sequence)) {
                this.buffer.set(sequence, segment.payload);
            }
        }

        return this.nextExpected;
    }

    deliver(payload) {
        this.receivedChunks.push(payload);
        this.nextExpected += payload.length;
    }

    getData() {
        const totalLength = this.receivedChunks.reduce(
            (sum, chunk) => sum + chunk.length,
            0
        );

        const combined = new Uint8Array(totalLength);
        let offset = 0;

        for (const chunk of this.receivedChunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }

        return combined;
    }
}

console.log('\n=== Out-of-order data ===');

const receiver = new OrderedTCPReceiver(1000);

const segmentA = new TCPSegment({
    source: 'SENDER',
    destination: 'RECEIVER',
    sequenceNumber: 1000,
    flags: TCP_FLAGS.ACK,
    payload: textToBytes('AAAAA')
});

const segmentB = new TCPSegment({
    source: 'SENDER',
    destination: 'RECEIVER',
    sequenceNumber: 1010,
    flags: TCP_FLAGS.ACK,
    payload: textToBytes('CCCCC')
});

const segmentC = new TCPSegment({
    source: 'SENDER',
    destination: 'RECEIVER',
    sequenceNumber: 1005,
    flags: TCP_FLAGS.ACK,
    payload: textToBytes('BBBBB')
});

console.log('ACK after A:', receiver.receive(segmentA));
console.log('ACK after C:', receiver.receive(segmentC));
console.log('ACK after B:', receiver.receive(segmentB));
console.log('Reconstructed stream:', bytesToText(receiver.getData()));


// -----------------------------------------------------------------------------
// 7. Retransmission timer
// -----------------------------------------------------------------------------

class RTTEstimator {
    constructor() {
        this.smoothedRTT = null;
        this.rttVariation = null;
        this.retransmissionTimeout = null;
    }

    update(measuredRTT) {
        if (!Number.isFinite(measuredRTT) || measuredRTT <= 0) {
            throw new RangeError('RTT must be positive');
        }

        const alpha = 1 / 8;
        const beta = 1 / 4;

        if (this.smoothedRTT === null) {
            this.smoothedRTT = measuredRTT;
            this.rttVariation = measuredRTT / 2;
        } else {
            this.rttVariation =
                (1 - beta) * this.rttVariation +
                beta * Math.abs(this.smoothedRTT - measuredRTT);

            this.smoothedRTT =
                (1 - alpha) * this.smoothedRTT +
                alpha * measuredRTT;
        }

        this.retransmissionTimeout =
            this.smoothedRTT + 4 * this.rttVariation;
    }
}

console.log('\n=== RTT estimation ===');

const estimator = new RTTEstimator();

for (const rtt of [0.080, 0.095, 0.090, 0.110, 0.085]) {
    estimator.update(rtt);

    console.log({
        measuredRTT: rtt,
        smoothedRTT: estimator.smoothedRTT,
        rttVariation: estimator.rttVariation,
        retransmissionTimeout: estimator.retransmissionTimeout
    });
}


// -----------------------------------------------------------------------------
// 8. Duplicate ACK detection
// -----------------------------------------------------------------------------

class DuplicateAckDetector {
    constructor() {
        this.lastAck = null;
        this.duplicateCount = 0;
    }

    observe(acknowledgmentNumber) {
        if (this.lastAck === null) {
            this.lastAck = acknowledgmentNumber;
            this.duplicateCount = 0;
            return false;
        }

        if (acknowledgmentNumber === this.lastAck) {
            this.duplicateCount += 1;
        } else if (acknowledgmentNumber > this.lastAck) {
            this.lastAck = acknowledgmentNumber;
            this.duplicateCount = 0;
        } else {
            return false;
        }

        return this.duplicateCount >= 3;
    }
}

console.log('\n=== Duplicate ACKs ===');

const ackDetector = new DuplicateAckDetector();

for (const acknowledgmentNumber of [
    4000,
    4000,
    4000,
    4000,
    4500
]) {
    console.log({
        acknowledgmentNumber,
        fastRetransmit: ackDetector.observe(acknowledgmentNumber),
        duplicateCount: ackDetector.duplicateCount
    });
}


// -----------------------------------------------------------------------------
// 9. MSS-based segmentation
// -----------------------------------------------------------------------------

function segmentData(data, initialSequence, mss) {
    if (!(data instanceof Uint8Array)) {
        throw new TypeError('Data must be Uint8Array');
    }

    if (!Number.isInteger(mss) || mss <= 0) {
        throw new RangeError('MSS must be positive');
    }

    const segments = [];

    for (let offset = 0; offset < data.length; offset += mss) {
        const payload = data.slice(offset, offset + mss);

        segments.push(
            new TCPSegment({
                source: 'SENDER',
                destination: 'RECEIVER',
                sequenceNumber: initialSequence + offset,
                flags: TCP_FLAGS.ACK,
                payload
            })
        );
    }

    return segments;
}

console.log('\n=== MSS segmentation ===');

const applicationData = textToBytes(
    'TCP is a reliable ordered byte stream.'
);

const segmentedData = segmentData(
    applicationData,
    20_000,
    10
);

segmentedData.forEach(segment => {
    console.log(segment.describe());
});


// -----------------------------------------------------------------------------
// 10. Event-driven packet-loss simulation
// -----------------------------------------------------------------------------

class EventEmitter {
    constructor() {
        this.listeners = new Map();
    }

    on(eventName, listener) {
        if (!this.listeners.has(eventName)) {
            this.listeners.set(eventName, []);
        }

        this.listeners.get(eventName).push(listener);
    }

    emit(eventName, payload) {
        const listeners = this.listeners.get(eventName) || [];

        for (const listener of listeners) {
            listener(payload);
        }
    }
}

class NetworkSimulator extends EventEmitter {
    constructor({ lossProbability = 0, seed = 12345 } = {}) {
        super();

        if (lossProbability < 0 || lossProbability > 1) {
            throw new RangeError(
                'lossProbability must be between 0 and 1'
            );
        }

        this.lossProbability = lossProbability;
        this.state = seed >>> 0;
    }

    random() {
        // Deterministic linear-congruential generator for reproducible
        // educational simulations. It is NOT a cryptographic RNG.
        this.state =
            (1664525 * this.state + 1013904223) >>> 0;

        return this.state / 2 ** 32;
    }

    transmit(segment) {
        const lost = this.random() < this.lossProbability;

        if (lost) {
            this.emit('packetLost', segment);
            return false;
        }

        this.emit('packetDelivered', segment);
        return true;
    }
}

console.log('\n=== Event-driven loss simulation ===');

const network = new NetworkSimulator({
    lossProbability: 0.25,
    seed: 42
});

network.on('packetLost', segment => {
    console.log('LOST:', segment.sequenceNumber);
});

network.on('packetDelivered', segment => {
    console.log('DELIVERED:', segment.sequenceNumber);
});

for (let sequence = 1; sequence <= 10; sequence++) {
    network.transmit(
        new TCPSegment({
            source: 'A',
            destination: 'B',
            sequenceNumber: sequence,
            flags: TCP_FLAGS.ACK,
            payload: new Uint8Array([sequence])
        })
    );
}


// -----------------------------------------------------------------------------
// 11. Asynchronous retransmission timer demonstration
// -----------------------------------------------------------------------------

function wait(milliseconds) {
    return new Promise(resolve => {
        setTimeout(resolve, milliseconds);
    });
}

async function demonstrateRetransmissionTimer() {
    console.log('\n=== Asynchronous retransmission timer ===');

    let acknowledged = false;
    let retransmissionCount = 0;

    const timeoutMilliseconds = 100;

    const timer = setTimeout(() => {
        if (!acknowledged) {
            retransmissionCount += 1;
            console.log(
                'Timer expired: retransmitting outstanding segment'
            );
        }
    }, timeoutMilliseconds);

    // Simulate an ACK arriving before the timer expires.
    await wait(50);

    acknowledged = true;
    clearTimeout(timer);

    console.log('ACK arrived before timeout.');
    console.log('Retransmissions:', retransmissionCount);
}


// -----------------------------------------------------------------------------
// 12. Application message boundaries versus TCP byte stream
// -----------------------------------------------------------------------------

class ByteStreamAssembler {
    constructor() {
        this.buffer = new Uint8Array();
    }

    append(bytes) {
        const combined = new Uint8Array(
            this.buffer.length + bytes.length
        );

        combined.set(this.buffer, 0);
        combined.set(bytes, this.buffer.length);

        this.buffer = combined;
    }

    read(length) {
        if (length < 0 || length > this.buffer.length) {
            throw new RangeError('Invalid read length');
        }

        const result = this.buffer.slice(0, length);
        this.buffer = this.buffer.slice(length);

        return result;
    }

    availableBytes() {
        return this.buffer.length;
    }
}

console.log('\n=== TCP byte-stream behavior ===');

const stream = new ByteStreamAssembler();

stream.append(textToBytes('HEL'));
stream.append(textToBytes('LO'));
stream.append(textToBytes('WORLD'));

console.log(
    'Available bytes:',
    stream.availableBytes()
);

console.log(
    'Application reads:',
    bytesToText(stream.read(5))
);

console.log(
    'Remaining:',
    bytesToText(stream.read(stream.availableBytes()))
);

console.log(
    '\nTCP does not guarantee that one send() call corresponds to one receive() call.'
);


// -----------------------------------------------------------------------------
// 13. Graceful close
// -----------------------------------------------------------------------------

function createCloseSequence(clientSequence, serverSequence) {
    return [
        new TCPSegment({
            source: 'CLIENT',
            destination: 'SERVER',
            sequenceNumber: clientSequence,
            acknowledgmentNumber: serverSequence,
            flags: TCP_FLAGS.FIN | TCP_FLAGS.ACK
        }),

        new TCPSegment({
            source: 'SERVER',
            destination: 'CLIENT',
            sequenceNumber: serverSequence,
            acknowledgmentNumber: clientSequence + 1,
            flags: TCP_FLAGS.ACK
        }),

        new TCPSegment({
            source: 'SERVER',
            destination: 'CLIENT',
            sequenceNumber: serverSequence,
            acknowledgmentNumber: clientSequence + 1,
            flags: TCP_FLAGS.FIN | TCP_FLAGS.ACK
        }),

        new TCPSegment({
            source: 'CLIENT',
            destination: 'SERVER',
            sequenceNumber: clientSequence + 1,
            acknowledgmentNumber: serverSequence + 1,
            flags: TCP_FLAGS.ACK
        })
    ];
}

console.log('\n=== Graceful TCP close ===');

createCloseSequence(7000, 9000).forEach(
    (segment, index) => {
        console.log(`Step ${index + 1}: ${segment.describe()}`);
    }
);


// -----------------------------------------------------------------------------
// 14. Performance calculation: bandwidth-delay product
// -----------------------------------------------------------------------------

function bandwidthDelayProductBytes(
    bandwidthBitsPerSecond,
    roundTripTimeSeconds
) {
    if (
        !Number.isFinite(bandwidthBitsPerSecond) ||
        bandwidthBitsPerSecond <= 0
    ) {
        throw new RangeError('Bandwidth must be positive');
    }

    if (
        !Number.isFinite(roundTripTimeSeconds) ||
        roundTripTimeSeconds <= 0
    ) {
        throw new RangeError('RTT must be positive');
    }

    return (
        bandwidthBitsPerSecond *
        roundTripTimeSeconds /
        8
    );
}

console.log('\n=== Bandwidth-delay product ===');

console.log(
    '100 Mbps × 100 ms:',
    bandwidthDelayProductBytes(
        100_000_000,
        0.1
    ),
    'bytes'
);


// -----------------------------------------------------------------------------
// 15. Validation and edge cases
// -----------------------------------------------------------------------------

console.log('\n=== Edge cases ===');

try {
    segmentData(textToBytes('test'), 100, 0);
} catch (error) {
    console.log('Invalid MSS rejected:', error.message);
}

try {
    new TCPSegment({
        source: 'A',
        destination: 'B',
        sequenceNumber: -1
    });
} catch (error) {
    console.log('Invalid sequence number rejected:', error.message);
}

try {
    new ReceiveWindow(-10);
} catch (error) {
    console.log('Invalid receive window rejected:', error.message);
}


// -----------------------------------------------------------------------------
// 16. Self-test
// -----------------------------------------------------------------------------

function runSelfTests() {
    const handshake = createHandshake(100, 500);

    console.assert(
        handshake[0].sequenceNumber === 100,
        'Client ISN is incorrect'
    );

    console.assert(
        handshake[1].acknowledgmentNumber === 101,
        'SYN-ACK ACK number is incorrect'
    );

    console.assert(
        handshake[2].acknowledgmentNumber === 501,
        'Final ACK is incorrect'
    );

    console.assert(
        dataSegment.sequenceSpaceConsumed === 5,
        'Payload sequence-space calculation is incorrect'
    );

    console.assert(
        addSequenceNumber(TCP_SEQUENCE_SPACE - 1, 2) === 1,
        'Sequence wrap-around is incorrect'
    );

    const testReceiver = new OrderedTCPReceiver(1000);

    testReceiver.receive(segmentA);
    testReceiver.receive(segmentB);
    testReceiver.receive(segmentC);

    console.assert(
        bytesToText(testReceiver.getData()) === 'AAAAABBBBBCCCCC',
        'Out-of-order reconstruction failed'
    );

    const detector = new DuplicateAckDetector();

    detector.observe(2000);
    detector.observe(2000);
    detector.observe(2000);

    console.assert(
        detector.observe(2000) === true,
        'Duplicate ACK detection failed'
    );

    console.log('\nAll JavaScript self-tests passed.');
}


// -----------------------------------------------------------------------------
// 17. Run asynchronous and synchronous demonstrations
// -----------------------------------------------------------------------------

runSelfTests();

demonstrateRetransmissionTimer()
    .then(() => {
        console.log('\nTCP JavaScript demonstrations completed.');
    })
    .catch(error => {
        console.error('Demonstration failed:', error);
        process.exitCode = 1;
    });
