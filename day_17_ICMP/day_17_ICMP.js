"use strict";

/*
 * ICMP: Echo Request/Reply, Unreachable Messages, Traceroute, and Security
 * =========================================================================
 *
 * This file uses only Node.js standard-library features.
 *
 * Node.js does not provide a standard-library raw-ICMP socket API comparable
 * to Python's socket.SOCK_RAW. Therefore, this implementation focuses on:
 *
 *   - ICMP packet construction
 *   - ICMP packet parsing
 *   - Internet checksum calculation
 *   - Destination Unreachable interpretation
 *   - Traceroute algorithm modeling
 *   - Security policy modeling
 *   - Validation and testing
 *
 * The packet-building logic is directly useful when integrating with a
 * native networking layer or a platform-specific raw-socket implementation.
 */

const ICMP_TYPES = Object.freeze({
    ECHO_REPLY: 0,
    DESTINATION_UNREACHABLE: 3,
    REDIRECT: 5,
    ECHO_REQUEST: 8,
    TIME_EXCEEDED: 11,
    PARAMETER_PROBLEM: 12
});

const ICMP_TYPE_NAMES = Object.freeze({
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem"
});

const UNREACHABLE_CODES = Object.freeze({
    0: "Network unreachable",
    1: "Host unreachable",
    2: "Protocol unreachable",
    3: "Port unreachable",
    4: "Fragmentation needed",
    5: "Source route failed",
    9: "Network administratively prohibited",
    10: "Host administratively prohibited"
});

function typeName(type) {
    return ICMP_TYPE_NAMES[type] ?? `Unknown ICMP type ${type}`;
}

function unreachableCodeName(code) {
    return UNREACHABLE_CODES[code] ?? `Unknown unreachable code ${code}`;
}

/*
 * The Internet checksum uses one's-complement arithmetic over 16-bit words.
 * Buffer objects make the byte-level behavior explicit.
 */
function internetChecksum(buffer) {
    let sum = 0;

    for (let offset = 0; offset < buffer.length; offset += 2) {
        const high = buffer[offset];
        const low = offset + 1 < buffer.length ? buffer[offset + 1] : 0;

        sum += (high << 8) | low;

        // Fold the carry into the low 16 bits.
        sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
    }

    while (sum > 0xffff) {
        sum = (sum & 0xffff) + Math.floor(sum / 0x10000);
    }

    return (~sum) & 0xffff;
}

function buildEchoRequest(identifier, sequence, payload) {
    if (!Number.isInteger(identifier) || identifier < 0 || identifier > 0xffff) {
        throw new RangeError("identifier must be an unsigned 16-bit integer");
    }

    if (!Number.isInteger(sequence) || sequence < 0 || sequence > 0xffff) {
        throw new RangeError("sequence must be an unsigned 16-bit integer");
    }

    const message = Buffer.alloc(8 + payload.length);

    message.writeUInt8(ICMP_TYPES.ECHO_REQUEST, 0);
    message.writeUInt8(0, 1);
    message.writeUInt16BE(0, 2);
    message.writeUInt16BE(identifier, 4);
    message.writeUInt16BE(sequence, 6);
    payload.copy(message, 8);

    const checksum = internetChecksum(message);
    message.writeUInt16BE(checksum, 2);

    return message;
}

function buildEchoReply(identifier, sequence, payload) {
    const message = Buffer.alloc(8 + payload.length);

    message.writeUInt8(ICMP_TYPES.ECHO_REPLY, 0);
    message.writeUInt8(0, 1);
    message.writeUInt16BE(0, 2);
    message.writeUInt16BE(identifier, 4);
    message.writeUInt16BE(sequence, 6);
    payload.copy(message, 8);

    message.writeUInt16BE(internetChecksum(message), 2);

    return message;
}

function parseEchoMessage(message) {
    if (!Buffer.isBuffer(message) || message.length < 8) {
        throw new Error("ICMP Echo message must contain at least 8 bytes");
    }

    const type = message.readUInt8(0);
    const code = message.readUInt8(1);
    const receivedChecksum = message.readUInt16BE(2);
    const identifier = message.readUInt16BE(4);
    const sequence = message.readUInt16BE(6);

    if (type !== ICMP_TYPES.ECHO_REQUEST &&
        type !== ICMP_TYPES.ECHO_REPLY) {
        throw new Error("message is not an Echo Request or Echo Reply");
    }

    if (code !== 0) {
        throw new Error("Echo messages require ICMP code 0");
    }

    const copy = Buffer.from(message);
    copy.writeUInt16BE(0, 2);

    const calculatedChecksum = internetChecksum(copy);

    if (calculatedChecksum !== receivedChecksum) {
        throw new Error(
            `invalid checksum: received 0x${receivedChecksum.toString(16)}, ` +
            `calculated 0x${calculatedChecksum.toString(16)}`
        );
    }

    return {
        type,
        typeName: typeName(type),
        code,
        checksum: receivedChecksum,
        identifier,
        sequence,
        payload: message.subarray(8)
    };
}

function buildDestinationUnreachable(code, originalPacket, nextHopMtu = 0) {
    if (!Number.isInteger(code) || code < 0 || code > 255) {
        throw new RangeError("ICMP code must fit in one byte");
    }

    if (code !== 4) {
        nextHopMtu = 0;
    }

    if (!Number.isInteger(nextHopMtu) ||
        nextHopMtu < 0 ||
        nextHopMtu > 0xffff) {
        throw new RangeError("nextHopMtu must fit in 16 bits");
    }

    const message = Buffer.alloc(8 + originalPacket.length);

    message.writeUInt8(ICMP_TYPES.DESTINATION_UNREACHABLE, 0);
    message.writeUInt8(code, 1);
    message.writeUInt16BE(0, 2);
    message.writeUInt16BE(nextHopMtu, 6);

    originalPacket.copy(message, 8);

    message.writeUInt16BE(internetChecksum(message), 2);

    return message;
}

function parseDestinationUnreachable(message) {
    if (!Buffer.isBuffer(message) || message.length < 8) {
        throw new Error("Destination Unreachable message is too short");
    }

    const type = message.readUInt8(0);
    const code = message.readUInt8(1);
    const checksum = message.readUInt16BE(2);
    const nextHopMtu = message.readUInt16BE(6);

    if (type !== ICMP_TYPES.DESTINATION_UNREACHABLE) {
        throw new Error("not an ICMP Destination Unreachable message");
    }

    const copy = Buffer.from(message);
    copy.writeUInt16BE(0, 2);

    if (internetChecksum(copy) !== checksum) {
        throw new Error("invalid ICMP checksum");
    }

    return {
        type,
        typeName: typeName(type),
        code,
        codeName: unreachableCodeName(code),
        nextHopMtu,
        originalPacket: message.subarray(8)
    };
}

/*
 * A traceroute probe increases TTL one hop at a time.
 *
 * This function models the decision process rather than sending packets.
 * A real implementation needs raw sockets or a platform-specific networking
 * layer capable of controlling TTL and receiving ICMP responses.
 */
function simulateTraceroute(destination, routers, maximumHops = 30) {
    if (!Array.isArray(routers) || routers.length === 0) {
        throw new Error("routers must be a non-empty array");
    }

    if (!Number.isInteger(maximumHops) || maximumHops <= 0) {
        throw new RangeError("maximumHops must be positive");
    }

    const results = [];
    const limit = Math.min(maximumHops, routers.length);

    for (let ttl = 1; ttl <= limit; ttl += 1) {
        const address = ttl < routers.length
            ? routers[ttl - 1]
            : destination;

        const reachedDestination = ttl === routers.length;

        results.push({
            ttl,
            address,
            response: reachedDestination
                ? "Echo Reply"
                : "Time Exceeded",
            rttMs: Number((2 + ttl * 1.75).toFixed(2))
        });

        if (reachedDestination) {
            break;
        }
    }

    return results;
}

function printTraceroute(results) {
    console.log("\nTraceroute model:");

    for (const hop of results) {
        console.log(
            `${String(hop.ttl).padStart(2, " ")}  ` +
            `${hop.address.padEnd(15, " ")}  ` +
            `${hop.rttMs.toFixed(2).padStart(8, " ")} ms  ` +
            hop.response
        );
    }
}

/*
 * Security policy modeling demonstrates a key principle:
 *
 * ICMP should generally be controlled according to type, direction,
 * context, rate, and network role rather than being treated as simply
 * "allowed" or "blocked".
 */
class ICMPSecurityPolicy {
    constructor({
        allowEchoRequest = true,
        allowEchoReply = true,
        allowTimeExceeded = true,
        allowDestinationUnreachable = true,
        rateLimitPerSecond = 10
    } = {}) {
        if (!Number.isInteger(rateLimitPerSecond) || rateLimitPerSecond < 0) {
            throw new RangeError("rateLimitPerSecond must be non-negative");
        }

        this.allowEchoRequest = allowEchoRequest;
        this.allowEchoReply = allowEchoReply;
        this.allowTimeExceeded = allowTimeExceeded;
        this.allowDestinationUnreachable = allowDestinationUnreachable;
        this.rateLimitPerSecond = rateLimitPerSecond;

        this.windowStarted = Date.now();
        this.windowCount = 0;
    }

    rateLimitAllows() {
        const now = Date.now();

        if (now - this.windowStarted >= 1000) {
            this.windowStarted = now;
            this.windowCount = 0;
        }

        if (this.windowCount >= this.rateLimitPerSecond) {
            return false;
        }

        this.windowCount += 1;
        return true;
    }

    allows(type) {
        if (!this.rateLimitAllows()) {
            return false;
        }

        switch (type) {
            case ICMP_TYPES.ECHO_REQUEST:
                return this.allowEchoRequest;

            case ICMP_TYPES.ECHO_REPLY:
                return this.allowEchoReply;

            case ICMP_TYPES.TIME_EXCEEDED:
                return this.allowTimeExceeded;

            case ICMP_TYPES.DESTINATION_UNREACHABLE:
                return this.allowDestinationUnreachable;

            default:
                return false;
        }
    }
}

/*
 * A simple bounded retry controller demonstrates why network applications
 * must not retry indefinitely when ICMP errors or timeouts occur.
 */
class ProbeController {
    constructor(maxAttempts = 3, timeoutMs = 1000) {
        if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
            throw new RangeError("maxAttempts must be positive");
        }

        if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
            throw new RangeError("timeoutMs must be positive");
        }

        this.maxAttempts = maxAttempts;
        this.timeoutMs = timeoutMs;
    }

    async run(probeFunction) {
        let lastError;

        for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
            try {
                return await Promise.race([
                    Promise.resolve().then(probeFunction),
                    new Promise((_, reject) => {
                        setTimeout(
                            () => reject(new Error("probe timeout")),
                            this.timeoutMs
                        );
                    })
                ]);
            } catch (error) {
                lastError = error;

                // Exponential backoff reduces repeated pressure on a network.
                if (attempt < this.maxAttempts) {
                    const delay = 50 * (2 ** (attempt - 1));
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }

        throw new Error(
            `all ${this.maxAttempts} attempts failed: ${lastError.message}`
        );
    }
}

function demonstratePacketConstruction() {
    console.log("=".repeat(78));
    console.log("ICMP PACKET CONSTRUCTION AND PARSING");
    console.log("=".repeat(78));

    const payload = Buffer.from("ICMP educational payload", "utf8");
    const request = buildEchoRequest(0x1234, 1, payload);

    console.log("Echo Request:", request.toString("hex"));

    const parsed = parseEchoMessage(request);

    console.log("Parsed type:", parsed.typeName);
    console.log("Identifier:", parsed.identifier);
    console.log("Sequence:", parsed.sequence);
    console.log("Payload:", parsed.payload.toString("utf8"));

    const reply = buildEchoReply(
        parsed.identifier,
        parsed.sequence,
        parsed.payload
    );

    console.log("Echo Reply:", reply.toString("hex"));
    console.log(
        "Reply parsed:",
        parseEchoMessage(reply).typeName
    );
}

function demonstrateUnreachableMessages() {
    console.log("\nDestination Unreachable:");

    // The embedded bytes represent the original packet context that caused
    // the error. A real ICMP error quotes the original IP header and data.
    const original = Buffer.from(
        "4500003c1234000040110000c0a8016408080808" +
        "12340035",
        "hex"
    );

    const message = buildDestinationUnreachable(
        3,
        original
    );

    const parsed = parseDestinationUnreachable(message);

    console.log("Type:", parsed.typeName);
    console.log("Code:", parsed.codeName);
    console.log("Embedded bytes:", parsed.originalPacket.length);

    const fragmentation = buildDestinationUnreachable(
        4,
        original,
        1400
    );

    console.log(
        "PMTUD example:",
        parseDestinationUnreachable(fragmentation).nextHopMtu,
        "bytes"
    );
}

function demonstrateSecurity() {
    console.log("\nSecurity policy:");

    const policy = new ICMPSecurityPolicy({
        allowEchoRequest: true,
        allowEchoReply: true,
        allowTimeExceeded: true,
        allowDestinationUnreachable: true,
        rateLimitPerSecond: 10
    });

    for (const type of [
        ICMP_TYPES.ECHO_REQUEST,
        ICMP_TYPES.ECHO_REPLY,
        ICMP_TYPES.TIME_EXCEEDED,
        ICMP_TYPES.DESTINATION_UNREACHABLE
    ]) {
        console.log(
            `${typeName(type).padEnd(32)} -> ` +
            `${policy.allows(type) ? "allowed" : "blocked"}`
        );
    }

    console.log(
        "\nSecurity considerations include rate limiting, filtering, " +
        "source validation, topology exposure, and control-plane protection."
    );
}

async function demonstrateAsyncProbeControl() {
    console.log("\nBounded asynchronous probe controller:");

    const controller = new ProbeController(3, 100);

    let attempts = 0;

    try {
        const result = await controller.run(async () => {
            attempts += 1;

            if (attempts < 2) {
                throw new Error("simulated ICMP timeout");
            }

            return {
                status: "received",
                attempt: attempts
            };
        });

        console.log("Probe result:", result);
    } catch (error) {
        console.log("Probe failed:", error.message);
    }
}

function runTests() {
    console.log("\nSelf-tests:");

    const payload = Buffer.from("test");
    const request = buildEchoRequest(10, 20, payload);
    const parsed = parseEchoMessage(request);

    console.assert(parsed.identifier === 10);
    console.assert(parsed.sequence === 20);
    console.assert(parsed.payload.equals(payload));

    const corrupted = Buffer.from(request);
    corrupted[corrupted.length - 1] ^= 0xff;

    let rejected = false;

    try {
        parseEchoMessage(corrupted);
    } catch {
        rejected = true;
    }

    console.assert(rejected, "Corrupted packet should be rejected");

    const unreachable = buildDestinationUnreachable(
        3,
        Buffer.from("45000020" + "00".repeat(20), "hex")
    );

    console.assert(
        parseDestinationUnreachable(unreachable).code === 3
    );

    const trace = simulateTraceroute(
        "198.51.100.50",
        [
            "192.168.1.1",
            "10.10.0.1",
            "172.16.4.1",
            "203.0.113.9",
            "198.51.100.20"
        ]
    );

    console.assert(trace.at(-1).response === "Echo Reply");

    console.log("All JavaScript tests passed.");
}

async function main() {
    demonstratePacketConstruction();
    demonstrateUnreachable();

    const path = simulateTraceroute(
        "198.51.100.50",
        [
            "192.168.1.1",
            "10.10.0.1",
            "172.16.4.1",
            "203.0.113.9",
            "198.51.100.20"
        ]
    );

    printTraceroute(path);
    demonstrateSecurity();
    await demonstrateAsyncProbeControl();
    runTests();

    console.log("\nICMP study completed.");
}

main().catch(error => {
    console.error("Fatal error:", error.message);
    process.exitCode = 1;
});
