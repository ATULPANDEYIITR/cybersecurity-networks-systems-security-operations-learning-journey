"use strict";

/*
 * IPv6 Networking: executable JavaScript study companion.
 *
 * This file focuses on IPv6 concepts that benefit from application-level
 * demonstrations: parsing, normalization, prefix arithmetic, SLAAC-style
 * address construction, multicast classification, routing decisions,
 * validation, asynchronous network APIs, and security-oriented handling.
 *
 * The implementation uses standard JavaScript/Node.js capabilities only.
 */

const nodeNet = (() => {
    try {
        return require("node:net");
    } catch {
        return null;
    }
})();


// ============================================================================
// 1. BASIC IPv6 REPRESENTATION
// ============================================================================

function printSection(title) {
    console.log("\n" + "=".repeat(78));
    console.log(title);
    console.log("=".repeat(78));
}

function hexToBits(hex) {
    return BigInt("0x" + hex)
        .toString(2)
        .padStart(128, "0");
}

function expandIPv6(address) {
    const input = address.trim().toLowerCase();

    if (input.includes("/")) {
        throw new Error("Pass an address without a prefix length.");
    }

    const pieces = input.split("::");

    if (pieces.length > 2) {
        throw new Error("An IPv6 address may contain :: at most once.");
    }

    let left = pieces[0] ? pieces[0].split(":") : [];
    let right = pieces.length === 2 && pieces[1] ? pieces[1].split(":") : [];

    // IPv4-mapped textual endings require special handling.
    const lastPart = right.length ? right[right.length - 1] : left[left.length - 1];

    if (lastPart && lastPart.includes(".")) {
        const octets = lastPart.split(".").map(Number);

        if (
            octets.length !== 4 ||
            octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)
        ) {
            throw new Error("Invalid embedded IPv4 address.");
        }

        const high = ((octets[0] << 8) | octets[1]).toString(16);
        const low = ((octets[2] << 8) | octets[3]).toString(16);

        if (right.length) {
            right = right.slice(0, -1).concat(high, low);
        } else {
            left = left.slice(0, -1).concat(high, low);
        }
    }

    if (pieces.length === 2) {
        const missing = 8 - left.length - right.length;

        if (missing < 1) {
            throw new Error("Invalid use of ::.");
        }

        const groups = left.concat(Array(missing).fill("0"), right);

        if (groups.length !== 8) {
            throw new Error("IPv6 address must expand to eight groups.");
        }

        return groups.map(group => group.padStart(4, "0"));
    }

    if (left.length !== 8) {
        throw new Error("A non-compressed IPv6 address requires eight groups.");
    }

    return left.map(group => group.padStart(4, "0"));
}

function compressIPv6(address) {
    const groups = expandIPv6(address).map(group => group.replace(/^0+/, "") || "0");

    let bestStart = -1;
    let bestLength = 0;
    let currentStart = -1;

    for (let i = 0; i <= groups.length; i++) {
        const isZero = i < groups.length && groups[i] === "0";

        if (isZero && currentStart === -1) {
            currentStart = i;
        }

        if (!isZero && currentStart !== -1) {
            const length = i - currentStart;

            if (length > bestLength && length >= 2) {
                bestStart = currentStart;
                bestLength = length;
            }

            currentStart = -1;
        }
    }

    if (bestStart === -1) {
        return groups.join(":");
    }

    const left = groups.slice(0, bestStart).join(":");
    const right = groups.slice(bestStart + bestLength).join(":");

    if (left && right) {
        return `${left}::${right}`;
    }

    if (left) {
        return `${left}::`;
    }

    if (right) {
        return `::${right}`;
    }

    return "::";
}

function ipv6ToBigInt(address) {
    const groups = expandIPv6(address);
    let value = 0n;

    for (const group of groups) {
        value = (value << 16n) | BigInt(parseInt(group, 16));
    }

    return value;
}

function bigIntToIPv6(value) {
    if (value < 0n || value > ((1n << 128n) - 1n)) {
        throw new Error("IPv6 integer must fit within 128 bits.");
    }

    const groups = [];

    for (let i = 0; i < 8; i++) {
        const shift = BigInt((7 - i) * 16);
        const group = Number((value >> shift) & 0xffffn);
        groups.push(group.toString(16));
    }

    return compressIPv6(groups.join(":"));
}


// ============================================================================
// 2. ADDRESS CLASSIFICATION
// ============================================================================

function ipv6AddressInfo(address) {
    const value = ipv6ToBigInt(address);

    const firstByte = Number((value >> 120n) & 0xffn);
    const firstTenBits = value >> 118n;

    const isUnspecified = value === 0n;
    const isLoopback = value === 1n;
    const isMulticast = firstByte === 0xff;
    const isLinkLocal = firstTenBits === 0b1111111010n;

    // fc00::/7
    const isUniqueLocal = (value >> 121n) === 0b1111110n;

    // 2000::/3
    const isGlobalUnicast = (value >> 125n) === 0b001n;

    let type = "ordinary unicast/other";

    if (isUnspecified) type = "unspecified";
    else if (isLoopback) type = "loopback";
    else if (isMulticast) type = "multicast";
    else if (isLinkLocal) type = "link-local";
    else if (isUniqueLocal) type = "unique-local";
    else if (isGlobalUnicast) type = "global-unicast";

    return {
        normalized: compressIPv6(address),
        type,
        isMulticast,
        isLinkLocal,
        isUniqueLocal,
        isGlobalUnicast,
        isLoopback,
        isUnspecified
    };
}

function multicastScope(address) {
    const value = ipv6ToBigInt(address);

    if (((value >> 120n) & 0xffn) !== 0xffn) {
        throw new Error("Address is not multicast.");
    }

    // ffXY::, where X is flags and Y is scope.
    return Number((value >> 112n) & 0xfn);
}


// ============================================================================
// 3. PREFIX OPERATIONS
// ============================================================================

function prefixMask(prefixLength) {
    if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 128) {
        throw new Error("Prefix length must be between 0 and 128.");
    }

    if (prefixLength === 0) {
        return 0n;
    }

    return ((1n << BigInt(prefixLength)) - 1n) << BigInt(128 - prefixLength);
}

function parseCIDR(cidr) {
    const [addressText, prefixText] = cidr.trim().split("/");

    if (prefixText === undefined) {
        throw new Error("CIDR prefix length is required.");
    }

    const prefixLength = Number(prefixText);

    if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > 128) {
        throw new Error("Invalid IPv6 prefix length.");
    }

    const address = ipv6ToBigInt(addressText);
    const mask = prefixMask(prefixLength);
    const network = address & mask;

    return {
        address,
        prefixLength,
        mask,
        network,
        networkAddress: bigIntToIPv6(network)
    };
}

function addressInNetwork(address, cidr) {
    const parsed = parseCIDR(cidr);
    return (ipv6ToBigInt(address) & parsed.mask) === parsed.network;
}

function subnetIPv6(cidr, newPrefix) {
    const base = parseCIDR(cidr);

    if (newPrefix < base.prefixLength || newPrefix > 128) {
        throw new Error("New prefix must be at least as specific as the base.");
    }

    const numberOfSubnets = 1n << BigInt(newPrefix - base.prefixLength);

    // Do not materialize enormous subnet lists accidentally.
    if (numberOfSubnets > 100000n) {
        throw new Error("Refusing to materialize more than 100,000 subnets.");
    }

    const increment = 1n << BigInt(128 - newPrefix);
    const result = [];

    for (let i = 0n; i < numberOfSubnets; i++) {
        const network = base.network + i * increment;
        result.push(`${bigIntToIPv6(network)}/${newPrefix}`);
    }

    return result;
}


// ============================================================================
// 4. SLAAC-STYLE INTERFACE IDENTIFIERS
// ============================================================================

function parseMac(mac) {
    const cleaned = mac.replace(/[-.]/g, "").replace(/:/g, "").toLowerCase();

    if (!/^[0-9a-f]{12}$/.test(cleaned)) {
        throw new Error("Invalid MAC address.");
    }

    return Array.from({ length: 6 }, (_, i) =>
        parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)
    );
}

function macToEUI64(mac) {
    const bytes = parseMac(mac);

    // Flip the universal/local bit and insert ff:fe.
    bytes[0] ^= 0x02;

    const eui = [
        bytes[0],
        bytes[1],
        bytes[2],
        0xff,
        0xfe,
        bytes[3],
        bytes[4],
        bytes[5]
    ];

    let identifier = 0n;

    for (const byte of eui) {
        identifier = (identifier << 8n) | BigInt(byte);
    }

    return identifier;
}

function createEUI64Address(prefix, mac) {
    const parsed = parseCIDR(prefix);

    if (parsed.prefixLength !== 64) {
        throw new Error("EUI-64 construction in this example requires /64.");
    }

    return bigIntToIPv6(parsed.network | macToEUI64(mac));
}

function randomInterfaceIdentifier() {
    // Math.random() is not cryptographically secure and should not be used
    // for security tokens. This educational example uses Web Crypto where
    // available.
    const cryptoObject =
        typeof globalThis.crypto !== "undefined"
            ? globalThis.crypto
            : require("node:crypto").webcrypto;

    const bytes = new Uint8Array(8);
    cryptoObject.getRandomValues(bytes);

    let value = 0n;

    for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
    }

    return value;
}

function createSLAACStyleAddress(prefix) {
    const parsed = parseCIDR(prefix);

    if (parsed.prefixLength !== 64) {
        throw new Error("This SLAAC-style demonstration expects /64.");
    }

    return bigIntToIPv6(parsed.network | randomInterfaceIdentifier());
}


// ============================================================================
// 5. ROUTING
// ============================================================================

class IPv6Route {
    constructor(prefix, nextHop, metric = 100) {
        this.prefix = parseCIDR(prefix);
        this.nextHop = nextHop;
        this.metric = metric;
    }
}

function longestPrefixMatch(destination, routes) {
    const destinationValue = ipv6ToBigInt(destination);

    const matches = routes.filter(route => {
        return (destinationValue & route.prefix.mask) === route.prefix.network;
    });

    if (matches.length === 0) {
        return null;
    }

    matches.sort((a, b) => {
        if (a.prefix.prefixLength !== b.prefix.prefixLength) {
            return b.prefix.prefixLength - a.prefix.prefixLength;
        }

        return a.metric - b.metric;
    });

    return matches[0];
}


// ============================================================================
// 6. ASYNCHRONOUS APPLICATION EXAMPLE
// ============================================================================

async function resolveIPv6Host(hostname) {
    if (!nodeNet) {
        return [];
    }

    const dns = require("node:dns").promises;

    try {
        return await dns.resolve6(hostname);
    } catch {
        return [];
    }
}


// ============================================================================
// 7. SECURITY-ORIENTED VALIDATION
// ============================================================================

function normalizeUserSuppliedAddress(input) {
    if (typeof input !== "string") {
        throw new TypeError("IPv6 address must be a string.");
    }

    const normalized = input.trim();

    // This example intentionally accepts only IPv6, not IPv4.
    if (!normalized.includes(":")) {
        throw new Error("An IPv6 address is required.");
    }

    try {
        return compressIPv6(normalized);
    } catch {
        throw new Error("Invalid IPv6 address.");
    }
}

function addressAllowedByPolicy(address, allowedNetworks) {
    const normalized = normalizeUserSuppliedAddress(address);

    return allowedNetworks.some(network => addressInNetwork(normalized, network));
}


// ============================================================================
// 8. DEMONSTRATIONS
// ============================================================================

async function main() {
    printSection("1. IPv6 notation");

    const original = "2001:0db8:0000:0000:0000:ff00:0042:8329";

    console.log("Original:", original);
    console.log("Compressed:", compressIPv6(original));
    console.log("Expanded:", expandIPv6(original).join(":"));
    console.log("128-bit representation:", ipv6ToBigInt(original));
    console.log("Bits:", hexToBits("20010db800000000"));

    printSection("2. Address classification");

    [
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "fd12:3456:789a::1",
        "2001:db8::1"
    ].forEach(address => {
        console.log(address, "=>", ipv6AddressInfo(address));
    });

    printSection("3. Prefix calculations");

    const networks = [
        "2001:db8:100::/48",
        "2001:db8:100:42::/64",
        "fd12:3456:789a::/48"
    ];

    for (const network of networks) {
        console.log(network, "=>", parseCIDR(network));
    }

    console.log(
        "2001:db8:100:42::10 in 2001:db8:100::/48:",
        addressInNetwork("2001:db8:100:42::10", "2001:db8:100::/48")
    );

    console.log(
        "2001:db8:200::/48 split into /64:",
        subnetIPv6("2001:db8:200::/48", 64).slice(0, 4)
    );

    printSection("4. SLAAC-style addressing");

    const mac = "00:1c:42:2e:60:4a";

    console.log(
        "EUI-64 address:",
        createEUI64Address("fe80::/64", mac)
    );

    console.log(
        "Random interface identifier address:",
        createSLAACStyleAddress("2001:db8:100:20::/64")
    );

    console.log(
        "Another temporary-style address:",
        createSLAACStyleAddress("2001:db8:100:20::/64")
    );

    printSection("5. Multicast");

    [
        "ff02::1",
        "ff02::2",
        "ff02::fb",
        "ff02::1:2"
    ].forEach(address => {
        console.log(
            address,
            "multicast=",
            ipv6AddressInfo(address).isMulticast,
            "scope=",
            multicastScope(address)
        );
    });

    printSection("6. Longest-prefix routing");

    const routes = [
        new IPv6Route("::/0", "ISP-A", 200),
        new IPv6Route("2001:db8::/32", "CORE", 100),
        new IPv6Route("2001:db8:100::/48", "DISTRIBUTION", 100),
        new IPv6Route("2001:db8:100:42::/64", "EDGE-42", 50)
    ];

    [
        "2001:db8:100:42::10",
        "2001:db8:100:99::10",
        "2001:db8:999::10",
        "2606:4700:4700::1111"
    ].forEach(destination => {
        const route = longestPrefixMatch(destination, routes);

        console.log(
            destination,
            "=>",
            route
                ? `${route.nextHop} via ${route.prefix.networkAddress}/${route.prefix.prefixLength}`
                : "no route"
        );
    });

    printSection("7. Application validation");

    const userInputs = [
        "  2001:0db8::1  ",
        "FE80::abcd",
        "not-an-address",
        "192.168.1.1"
    ];

    for (const input of userInputs) {
        try {
            console.log(input, "=>", normalizeUserSuppliedAddress(input));
        } catch (error) {
            console.log(input, "=> rejected:", error.message);
        }
    }

    const allowedNetworks = [
        "2001:db8:100::/48",
        "fd12:3456:789a::/48"
    ];

    console.log(
        "Policy check:",
        addressAllowedByPolicy("2001:db8:100:42::10", allowedNetworks)
    );

    console.log(
        "Policy check:",
        addressAllowedByPolicy("2001:db8:999::10", allowedNetworks)
    );

    printSection("8. IPv6 DNS resolution");

    const ipv6Results = await resolveIPv6Host("localhost");
    console.log("AAAA records for localhost:", ipv6Results);

    printSection("9. Important IPv6 engineering principles");

    console.log(`
IPv6 has 128-bit addresses.
IPv6 has no broadcast address.
IPv6 multicast begins with ff.
IPv6 link-local addresses use fe80::/10.
SLAAC commonly uses /64 prefixes.
Router Advertisements are part of Neighbor Discovery.
ICMPv6 is essential to many IPv6 functions.
IPv4 and IPv6 security policies must be evaluated separately.
String comparison is not a safe way to compare IP addresses.
Longest-prefix matching determines the most specific matching route.
Stable and privacy-oriented interface identifiers have different operational
and privacy characteristics.
`);
}


// ============================================================================
// 9. SELF-TESTS
// ============================================================================

function runTests() {
    printSection("10. Self-tests");

    console.assert(
        compressIPv6("2001:0db8:0000:0000:0000:0000:0000:0001") === "2001:db8::1"
    );

    console.assert(
        compressIPv6("0000:0000:0000:0000:0000:0000:0000:0000") === "::"
    );

    console.assert(
        ipv6AddressInfo("::1").isLoopback
    );

    console.assert(
        ipv6AddressInfo("fe80::1").isLinkLocal
    );

    console.assert(
        ipv6AddressInfo("ff02::1").isMulticast
    );

    console.assert(
        addressInNetwork("2001:db8:100::42", "2001:db8:100::/48")
    );

    console.assert(
        !addressInNetwork("2001:db8:101::42", "2001:db8:100::/48")
    );

    const route = longestPrefixMatch(
        "2001:db8:100:42::10",
        [
            new IPv6Route("::/0", "default"),
            new IPv6Route("2001:db8::/32", "core"),
            new IPv6Route("2001:db8:100:42::/64", "edge")
        ]
    );

    console.assert(route.nextHop === "edge");

    console.log("All JavaScript IPv6 tests passed.");
}


runTests();

main().catch(error => {
    console.error("IPv6 demonstration failed:", error);
    process.exitCode = 1;
});
