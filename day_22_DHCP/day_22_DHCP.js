/*
 * DHCP Discovery, Offers, Requests, Acknowledgments, Leases,
 * Rogue DHCP Concepts, and Wireshark-Oriented Analysis
 *
 * This file implements a self-contained DHCP learning simulation.
 * It does not modify the operating system's network configuration and
 * does not send DHCP packets onto a real network.
 *
 * The implementation demonstrates:
 *   - DHCP terminology
 *   - DORA message exchange
 *   - Client state transitions
 *   - DHCP leases
 *   - Multiple DHCP servers
 *   - Rogue DHCP detection concepts
 *   - Wireshark display-filter concepts
 *   - Event-driven asynchronous simulation
 *   - Validation and error handling
 *   - Performance-oriented data structures
 *
 * Run with:
 *   node dhcp_learning.js
 */

"use strict";

// ---------------------------------------------------------------------------
// 1. DHCP message types and client states
// ---------------------------------------------------------------------------

const DHCPMessageType = Object.freeze({
    DISCOVER: "DHCPDISCOVER",
    OFFER: "DHCPOFFER",
    REQUEST: "DHCPREQUEST",
    ACK: "DHCPACK",
    NAK: "DHCPNAK",
    DECLINE: "DHCPDECLINE",
    RELEASE: "DHCPRELEASE",
    INFORM: "DHCPINFORM"
});

const ClientState = Object.freeze({
    INIT: "INIT",
    SELECTING: "SELECTING",
    REQUESTING: "REQUESTING",
    BOUND: "BOUND",
    RENEWING: "RENEWING",
    REBINDING: "REBINDING",
    EXPIRED: "EXPIRED"
});


// ---------------------------------------------------------------------------
// 2. Utility functions
// ---------------------------------------------------------------------------

function normalizeMac(macAddress) {
    const normalized = macAddress.replaceAll("-", ":").toLowerCase();
    const parts = normalized.split(":");

    if (
        parts.length !== 6 ||
        parts.some(part => !/^[0-9a-f]{2}$/.test(part))
    ) {
        throw new Error(`Invalid MAC address: ${macAddress}`);
    }

    return parts.join(":");
}

function generateTransactionId() {
    // JavaScript numbers safely represent integers only up to 2^53 - 1.
    // A 32-bit transaction ID is therefore safely represented as a number.
    return Math.floor(Math.random() * 0x100000000);
}

function formatTransactionId(transactionId) {
    return `0x${transactionId.toString(16).padStart(8, "0")}`;
}

function delay(milliseconds) {
    // Promise-based delay demonstrates JavaScript's asynchronous execution
    // model without requiring an external package.
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

function ipToInteger(ipAddress) {
    const octets = ipAddress.split(".").map(Number);

    if (
        octets.length !== 4 ||
        octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)
    ) {
        throw new Error(`Invalid IPv4 address: ${ipAddress}`);
    }

    return (
        ((octets[0] << 24) >>> 0) +
        ((octets[1] << 16) >>> 0) +
        ((octets[2] << 8) >>> 0) +
        octets[3]
    ) >>> 0;
}

function isAddressBetween(address, start, end) {
    const value = ipToInteger(address);
    return value >= ipToInteger(start) && value <= ipToInteger(end);
}


// ---------------------------------------------------------------------------
// 3. DHCP packet class
// ---------------------------------------------------------------------------

class DHCPPacket {
    constructor({
        messageType,
        transactionId,
        clientMac,
        sourceIp = "0.0.0.0",
        destinationIp = "255.255.255.255",
        serverIdentifier = null,
        requestedIp = null,
        offeredIp = null,
        subnetMask = null,
        router = null,
        dnsServers = [],
        leaseSeconds = null
    }) {
        this.messageType = messageType;
        this.transactionId = transactionId;
        this.clientMac = normalizeMac(clientMac);
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.serverIdentifier = serverIdentifier;
        this.requestedIp = requestedIp;
        this.offeredIp = offeredIp;
        this.subnetMask = subnetMask;
        this.router = router;
        this.dnsServers = [...dnsServers];
        this.leaseSeconds = leaseSeconds;
    }

    summary() {
        return [
            this.messageType.padEnd(12),
            `xid=${formatTransactionId(this.transactionId)}`,
            `client=${this.clientMac}`,
            `src=${this.sourceIp}`,
            `dst=${this.destinationIp}`
        ].join(" ");
    }

    get options() {
        // Option 53 identifies DHCP message type.
        // Option 50 identifies a requested address.
        // Option 54 identifies a DHCP server.
        // Option 51 identifies lease time.
        return {
            53: this.messageType,
            50: this.requestedIp,
            54: this.serverIdentifier,
            51: this.leaseSeconds,
            1: this.subnetMask,
            3: this.router,
            6: this.dnsServers
        };
    }
}


// ---------------------------------------------------------------------------
// 4. DHCP lease
// ---------------------------------------------------------------------------

class DHCPLease {
    constructor({
        macAddress,
        ipAddress,
        serverIdentifier,
        leaseSeconds,
        startTime = Date.now()
    }) {
        this.macAddress = normalizeMac(macAddress);
        this.ipAddress = ipAddress;
        this.serverIdentifier = serverIdentifier;
        this.leaseSeconds = leaseSeconds;
        this.startTime = startTime;
        this.state = "ACTIVE";
    }

    get expirationTime() {
        return this.startTime + this.leaseSeconds * 1000;
    }

    isExpired(now = Date.now()) {
        return now >= this.expirationTime;
    }

    remainingSeconds(now = Date.now()) {
        return Math.max(
            0,
            Math.floor((this.expirationTime - now) / 1000)
        );
    }
}


// ---------------------------------------------------------------------------
// 5. DHCP server
// ---------------------------------------------------------------------------

class DHCPServer {
    constructor({
        serverIdentifier,
        poolStart,
        poolEnd,
        subnetMask,
        router,
        dnsServers,
        leaseSeconds = 3600,
        name = "DHCP Server"
    }) {
        this.serverIdentifier = serverIdentifier;
        this.poolStart = poolStart;
        this.poolEnd = poolEnd;
        this.subnetMask = subnetMask;
        this.router = router;
        this.dnsServers = [...dnsServers];
        this.leaseSeconds = leaseSeconds;
        this.name = name;

        // Maps provide approximately O(1) lookup for the common operations:
        // MAC -> lease and IP -> lease.
        this.leasesByMac = new Map();
        this.leasesByIp = new Map();

        // The pool is small for this simulation, so precomputing addresses
        // makes allocation logic simple and deterministic.
        this.poolAddresses = this.generatePoolAddresses();
    }

    generatePoolAddresses() {
        const addresses = [];

        const start = ipToInteger(this.poolStart);
        const end = ipToInteger(this.poolEnd);

        for (let value = start; value <= end; value++) {
            const octet1 = (value >>> 24) & 255;
            const octet2 = (value >>> 16) & 255;
            const octet3 = (value >>> 8) & 255;
            const octet4 = value & 255;

            addresses.push(
                `${octet1}.${octet2}.${octet3}.${octet4}`
            );
        }

        return addresses;
    }

    removeExpiredLeases(now = Date.now()) {
        for (const [ipAddress, lease] of this.leasesByIp) {
            if (lease.isExpired(now)) {
                this.leasesByIp.delete(ipAddress);
                this.leasesByMac.delete(lease.macAddress);
            }
        }
    }

    findAvailableIp() {
        this.removeExpiredLeases();

        return this.poolAddresses.find(
            address => !this.leasesByIp.has(address)
        ) ?? null;
    }

    receiveDiscover(packet) {
        if (packet.messageType !== DHCPMessageType.DISCOVER) {
            throw new Error("Server expected DHCPDISCOVER.");
        }

        const existingLease = this.leasesByMac.get(packet.clientMac);

        const offeredIp =
            existingLease && !existingLease.isExpired()
                ? existingLease.ipAddress
                : this.findAvailableIp();

        if (!offeredIp) {
            return null;
        }

        return new DHCPPacket({
            messageType: DHCPMessageType.OFFER,
            transactionId: packet.transactionId,
            clientMac: packet.clientMac,
            sourceIp: this.serverIdentifier,
            destinationIp: "255.255.255.255",
            serverIdentifier: this.serverIdentifier,
            offeredIp,
            subnetMask: this.subnetMask,
            router: this.router,
            dnsServers: this.dnsServers,
            leaseSeconds: this.leaseSeconds
        });
    }

    receiveRequest(packet) {
        if (packet.messageType !== DHCPMessageType.REQUEST) {
            throw new Error("Server expected DHCPREQUEST.");
        }

        const reject = () => new DHCPPacket({
            messageType: DHCPMessageType.NAK,
            transactionId: packet.transactionId,
            clientMac: packet.clientMac,
            sourceIp: this.serverIdentifier,
            destinationIp: "255.255.255.255",
            serverIdentifier: this.serverIdentifier
        });

        if (packet.serverIdentifier !== this.serverIdentifier) {
            return reject();
        }

        const requestedIp = packet.requestedIp;

        if (!requestedIp) {
            return reject();
        }

        if (!isAddressBetween(
            requestedIp,
            this.poolStart,
            this.poolEnd
        )) {
            return reject();
        }

        const existingIpLease = this.leasesByIp.get(requestedIp);

        if (
            existingIpLease &&
            existingIpLease.macAddress !== packet.clientMac &&
            !existingIpLease.isExpired()
        ) {
            return reject();
        }

        const previousLease = this.leasesByMac.get(packet.clientMac);

        if (
            previousLease &&
            previousLease.ipAddress !== requestedIp
        ) {
            this.leasesByIp.delete(previousLease.ipAddress);
        }

        const lease = new DHCPLease({
            macAddress: packet.clientMac,
            ipAddress: requestedIp,
            serverIdentifier: this.serverIdentifier,
            leaseSeconds: this.leaseSeconds
        });

        this.leasesByMac.set(packet.clientMac, lease);
        this.leasesByIp.set(requestedIp, lease);

        return new DHCPPacket({
            messageType: DHCPMessageType.ACK,
            transactionId: packet.transactionId,
            clientMac: packet.clientMac,
            sourceIp: this.serverIdentifier,
            destinationIp: "255.255.255.255",
            serverIdentifier: this.serverIdentifier,
            offeredIp: requestedIp,
            subnetMask: this.subnetMask,
            router: this.router,
            dnsServers: this.dnsServers,
            leaseSeconds: this.leaseSeconds
        });
    }

    release(macAddress) {
        const mac = normalizeMac(macAddress);
        const lease = this.leasesByMac.get(mac);

        if (!lease) {
            return false;
        }

        this.leasesByMac.delete(mac);
        this.leasesByIp.delete(lease.ipAddress);
        lease.state = "RELEASED";

        return true;
    }

    printLeaseTable() {
        this.removeExpiredLeases();

        console.log(`\nLease table for ${this.name}`);
        console.log("-".repeat(75));

        if (this.leasesByMac.size === 0) {
            console.log("No active leases.");
            return;
        }

        for (const lease of this.leasesByMac.values()) {
            console.log(
                `${lease.macAddress} -> ${lease.ipAddress} | ` +
                `remaining=${lease.remainingSeconds()}s | ` +
                `state=${lease.state}`
            );
        }
    }
}


// ---------------------------------------------------------------------------
// 6. DHCP client state machine
// ---------------------------------------------------------------------------

class DHCPClient {
    constructor(macAddress) {
        this.macAddress = normalizeMac(macAddress);
        this.state = ClientState.INIT;
        this.transactionId = null;

        this.ipAddress = null;
        this.serverIdentifier = null;
        this.subnetMask = null;
        this.router = null;
        this.dnsServers = [];
        this.leaseSeconds = null;
        this.leaseStart = null;
    }

    createDiscover() {
        this.transactionId = generateTransactionId();
        this.state = ClientState.SELECTING;

        return new DHCPPacket({
            messageType: DHCPMessageType.DISCOVER,
            transactionId: this.transactionId,
            clientMac: this.macAddress,
            sourceIp: "0.0.0.0",
            destinationIp: "255.255.255.255"
        });
    }

    createRequest(offer) {
        if (offer.messageType !== DHCPMessageType.OFFER) {
            throw new Error("The client can request only an offer.");
        }

        if (offer.transactionId !== this.transactionId) {
            throw new Error("Offer transaction ID does not match.");
        }

        if (!offer.offeredIp || !offer.serverIdentifier) {
            throw new Error("Offer is missing required DHCP information.");
        }

        this.state = ClientState.REQUESTING;

        return new DHCPPacket({
            messageType: DHCPMessageType.REQUEST,
            transactionId: this.transactionId,
            clientMac: this.macAddress,
            sourceIp: "0.0.0.0",
            destinationIp: "255.255.255.255",
            serverIdentifier: offer.serverIdentifier,
            requestedIp: offer.offeredIp
        });
    }

    processResponse(packet) {
        if (packet.transactionId !== this.transactionId) {
            throw new Error("DHCP transaction ID mismatch.");
        }

        if (packet.messageType === DHCPMessageType.NAK) {
            this.state = ClientState.INIT;
            this.ipAddress = null;
            this.serverIdentifier = null;
            return;
        }

        if (packet.messageType !== DHCPMessageType.ACK) {
            throw new Error("Expected DHCPACK or DHCPNAK.");
        }

        if (!packet.offeredIp) {
            throw new Error("DHCPACK does not contain an IP address.");
        }

        this.ipAddress = packet.offeredIp;
        this.serverIdentifier = packet.serverIdentifier;
        this.subnetMask = packet.subnetMask;
        this.router = packet.router;
        this.dnsServers = [...packet.dnsServers];
        this.leaseSeconds = packet.leaseSeconds;
        this.leaseStart = Date.now();
        this.state = ClientState.BOUND;
    }

    updateLeaseState(now = Date.now()) {
        if (this.leaseStart === null || this.leaseSeconds === null) {
            return this.state;
        }

        const fraction =
            (now - this.leaseStart) /
            (this.leaseSeconds * 1000);

        if (fraction >= 1) {
            this.state = ClientState.EXPIRED;
        } else if (fraction >= 0.875) {
            this.state = ClientState.REBINDING;
        } else if (fraction >= 0.5) {
            this.state = ClientState.RENEWING;
        } else {
            this.state = ClientState.BOUND;
        }

        return this.state;
    }

    createRenewalRequest() {
        if (!this.ipAddress || !this.serverIdentifier) {
            throw new Error("No active DHCP lease.");
        }

        if (
            ![
                ClientState.BOUND,
                ClientState.RENEWING,
                ClientState.REBINDING
            ].includes(this.state)
        ) {
            throw new Error(
                `Cannot renew from state ${this.state}.`
            );
        }

        return new DHCPPacket({
            messageType: DHCPMessageType.REQUEST,
            transactionId: generateTransactionId(),
            clientMac: this.macAddress,
            sourceIp: this.ipAddress,
            destinationIp: this.serverIdentifier,
            serverIdentifier: this.serverIdentifier,
            requestedIp: this.ipAddress
        });
    }

    printConfiguration() {
        console.log("\nClient configuration");
        console.log("-".repeat(55));
        console.log(`MAC:       ${this.macAddress}`);
        console.log(`State:     ${this.state}`);
        console.log(`IPv4:      ${this.ipAddress}`);
        console.log(`Mask:      ${this.subnetMask}`);
        console.log(`Gateway:   ${this.router}`);
        console.log(`DNS:       ${this.dnsServers.join(", ")}`);
        console.log(`DHCP:      ${this.serverIdentifier}`);
        console.log(`Lease:     ${this.leaseSeconds}s`);
    }
}


// ---------------------------------------------------------------------------
// 7. Asynchronous network simulation
// ---------------------------------------------------------------------------

async function simulateDora(server, client) {
    console.log("\n" + "=".repeat(80));
    console.log("ASYNC DHCP DORA SIMULATION");
    console.log("=".repeat(80));

    const discover = client.createDiscover();

    console.log("\nClient -> broadcast");
    console.log(discover.summary());

    // setTimeout/Promise models network delay without actually sending traffic.
    await delay(100);

    const offer = server.receiveDiscover(discover);

    if (!offer) {
        console.log("Server: address pool exhausted.");
        return false;
    }

    console.log("\nServer -> client");
    console.log(offer.summary());

    await delay(100);

    const request = client.createRequest(offer);

    console.log("\nClient -> server/broadcast");
    console.log(request.summary());

    await delay(100);

    const response = server.receiveRequest(request);

    console.log("\nServer -> client");
    console.log(response.summary());

    client.processResponse(response);

    client.printConfiguration();

    return response.messageType === DHCPMessageType.ACK;
}


// ---------------------------------------------------------------------------
// 8. Multiple DHCP offers and rogue-server analysis
// ---------------------------------------------------------------------------

async function collectOffers(servers, discover) {
    // Promise.all demonstrates concurrent asynchronous server responses.
    // In a real broadcast domain, multiple DHCP servers may independently
    // process the same DHCPDISCOVER.
    return Promise.all(
        servers.map(async server => {
            await delay(Math.floor(Math.random() * 50));
            return server.receiveDiscover(discover);
        })
    );
}

function detectUnexpectedServers(offers, trustedServerIds) {
    const findings = [];

    for (const offer of offers) {
        if (!offer) {
            continue;
        }

        if (!trustedServerIds.has(offer.serverIdentifier)) {
            findings.push({
                serverIdentifier: offer.serverIdentifier,
                offeredIp: offer.offeredIp,
                router: offer.router,
                dnsServers: offer.dnsServers
            });
        }
    }

    return findings;
}

async function demonstrateRogueDhcp(legitimateServer, rogueServer) {
    console.log("\n" + "=".repeat(80));
    console.log("MULTIPLE OFFERS AND ROGUE DHCP ANALYSIS");
    console.log("=".repeat(80));

    const client = new DHCPClient("aa:bb:cc:dd:ee:22");
    const discover = client.createDiscover();

    const offers = (
        await collectOffers(
            [legitimateServer, rogueServer],
            discover
        )
    ).filter(Boolean);

    console.log(`\nReceived ${offers.length} offer(s).`);

    for (const offer of offers) {
        console.log("\nOffer:");
        console.log(offer.summary());
        console.log(`Server:  ${offer.serverIdentifier}`);
        console.log(`Address: ${offer.offeredIp}`);
        console.log(`Gateway: ${offer.router}`);
        console.log(`DNS:     ${offer.dnsServers.join(", ")}`);
    }

    const trustedServers = new Set([
        legitimateServer.serverIdentifier
    ]);

    const findings = detectUnexpectedServers(
        offers,
        trustedServers
    );

    if (findings.length > 0) {
        console.log("\nPotential unauthorized DHCP source(s):");

        for (const finding of findings) {
            console.log(
                `${finding.serverIdentifier} offered ` +
                `${finding.offeredIp}, gateway=${finding.router}, ` +
                `DNS=${finding.dnsServers.join(",")}`
            );
        }
    } else {
        console.log("\nNo unexpected DHCP server detected.");
    }
}


// ---------------------------------------------------------------------------
// 9. Wireshark display-filter reference
// ---------------------------------------------------------------------------

function displayWiresharkFilters() {
    console.log("\n" + "=".repeat(80));
    console.log("WIRESHARK DISPLAY FILTERS");
    console.log("=".repeat(80));

    const filters = [
        ["All DHCP/BOOTP packets", "dhcp"],
        ["All BOOTP/DHCP packets", "bootp"],
        ["UDP ports used by DHCP", "udp.port == 67 || udp.port == 68"],
        ["DHCP Discover", "bootp.option.dhcp == 1"],
        ["DHCP Offer", "bootp.option.dhcp == 2"],
        ["DHCP Request", "bootp.option.dhcp == 3"],
        ["DHCP ACK", "bootp.option.dhcp == 5"],
        ["DHCP NAK", "bootp.option.dhcp == 6"],
        ["DHCP server identifier", "bootp.option.dhcp_server"],
        [
            "Client MAC",
            "eth.addr == aa:bb:cc:dd:ee:22"
        ]
    ];

    for (const [description, filter] of filters) {
        console.log(`${description.padEnd(32)} ${filter}`);
    }

    console.log("\nUseful packet-analysis sequence:");
    console.log("1. Locate DHCPDISCOVER.");
    console.log("2. Record the transaction ID.");
    console.log("3. Identify every DHCPOFFER.");
    console.log("4. Compare server identifiers.");
    console.log("5. Inspect gateway and DNS options.");
    console.log("6. Follow the selected DHCPREQUEST.");
    console.log("7. Confirm DHCPACK or DHCPNAK.");
    console.log("8. Check lease duration and assigned address.");
}


// ---------------------------------------------------------------------------
// 10. Lease timing demonstration
// ---------------------------------------------------------------------------

function demonstrateLeaseTimers(client) {
    console.log("\n" + "=".repeat(80));
    console.log("LEASE TIMER STATES");
    console.log("=".repeat(80));

    if (client.leaseStart === null || client.leaseSeconds === null) {
        console.log("Client has no lease.");
        return;
    }

    const checkpoints = [
        ["25%", 0.25],
        ["50%", 0.50],
        ["87.5%", 0.875],
        ["100%", 1.00]
    ];

    for (const [label, fraction] of checkpoints) {
        const simulatedNow =
            client.leaseStart +
            client.leaseSeconds * 1000 * fraction;

        const state = client.updateLeaseState(simulatedNow);

        console.log(`${label.padEnd(8)} -> ${state}`);
    }

    // Restore an operational state for subsequent demonstrations.
    client.state = ClientState.BOUND;
}


// ---------------------------------------------------------------------------
// 11. Pool exhaustion and invalid request demonstrations
// ---------------------------------------------------------------------------

function demonstratePoolExhaustion() {
    console.log("\n" + "=".repeat(80));
    console.log("DHCP POOL EXHAUSTION");
    console.log("=".repeat(80));

    const server = new DHCPServer({
        serverIdentifier: "192.168.70.1",
        poolStart: "192.168.70.10",
        poolEnd: "192.168.70.11",
        subnetMask: "255.255.255.0",
        router: "192.168.70.1",
        dnsServers: ["192.168.70.1"],
        leaseSeconds: 120,
        name: "Small Pool Server"
    });

    for (let index = 1; index <= 3; index++) {
        const client = new DHCPClient(
            `00:00:00:00:70:${String(index).padStart(2, "0")}`
        );

        const discover = client.createDiscover();
        const offer = server.receiveDiscover(discover);

        if (!offer) {
            console.log(
                `${client.macAddress}: NO AVAILABLE ADDRESS`
            );
            continue;
        }

        const request = client.createRequest(offer);
        const response = server.receiveRequest(request);

        if (response.messageType === DHCPMessageType.ACK) {
            client.processResponse(response);
            console.log(
                `${client.macAddress}: assigned ${client.ipAddress}`
            );
        }
    }

    server.printLeaseTable();
}

function demonstrateInvalidRequest(server) {
    console.log("\n" + "=".repeat(80));
    console.log("INVALID DHCPREQUEST");
    console.log("=".repeat(80));

    const client = new DHCPClient(
        "00:11:22:33:44:55"
    );

    const request = new DHCPPacket({
        messageType: DHCPMessageType.REQUEST,
        transactionId: generateTransactionId(),
        clientMac: client.macAddress,
        requestedIp: "10.10.10.10",
        serverIdentifier: server.serverIdentifier
    });

    const response = server.receiveRequest(request);

    console.log("Requested:", request.requestedIp);
    console.log("Response: ", response.messageType);
}


// ---------------------------------------------------------------------------
// 12. Security-control discussion
// ---------------------------------------------------------------------------

function demonstrateSecurityControls() {
    console.log("\n" + "=".repeat(80));
    console.log("ROGUE DHCP DEFENSIVE CONTROLS");
    console.log("=".repeat(80));

    const controls = [
        {
            control: "DHCP snooping",
            purpose:
                "Switch-based control that can distinguish trusted DHCP "
                + "server interfaces from untrusted access ports."
        },
        {
            control: "Trusted DHCP server ports",
            purpose:
                "Only authorized DHCP server or relay interfaces should "
                + "normally be configured as trusted."
        },
        {
            control: "Network monitoring",
            purpose:
                "Unexpected DHCP server identifiers and configuration "
                + "values can be detected through packet analysis."
        },
        {
            control: "Segmentation",
            purpose:
                "VLAN and network boundaries can limit the scope of DHCP "
                + "broadcast domains."
        }
    ];

    for (const control of controls) {
        console.log(`\n${control.control}`);
        console.log(control.purpose);
    }

    console.log(
        "\nWireshark observes and analyzes packets; it does not itself "
        + "enforce DHCP server authorization."
    );
}


// ---------------------------------------------------------------------------
// 13. Main
// ---------------------------------------------------------------------------

async function main() {
    console.log("=".repeat(80));
    console.log("DHCP LEARNING LAB");
    console.log("=".repeat(80));

    const legitimateServer = new DHCPServer({
        serverIdentifier: "192.168.10.1",
        poolStart: "192.168.10.100",
        poolEnd: "192.168.10.110",
        subnetMask: "255.255.255.0",
        router: "192.168.10.1",
        dnsServers: ["192.168.10.1", "1.1.1.1"],
        leaseSeconds: 3600,
        name: "Authorized DHCP Server"
    });

    const client = new DHCPClient(
        "AA:BB:CC:DD:EE:01"
    );

    await simulateDora(legitimateServer, client);

    demonstrateLeaseTimers(client);

    legitimateServer.printLeaseTable();

    const rogueServer = new DHCPServer({
        serverIdentifier: "192.168.10.254",
        poolStart: "192.168.10.200",
        poolEnd: "192.168.10.210",
        subnetMask: "255.255.255.0",
        router: "192.168.10.254",
        dnsServers: ["192.168.10.254"],
        leaseSeconds: 7200,
        name: "Unauthorized DHCP Server"
    });

    await demonstrateRogueDhcp(
        legitimateServer,
        rogueServer
    );

    displayWiresharkFilters();

    demonstratePoolExhaustion();
    demonstrateInvalidRequest(legitimateServer);
    demonstrateSecurityControls();

    console.log("\n" + "=".repeat(80));
    console.log("DHCP MESSAGE RELATIONSHIPS");
    console.log("=".repeat(80));

    const messages = [
        ["DHCPDISCOVER", "Client", "Searches for available DHCP servers."],
        ["DHCPOFFER", "Server", "Proposes an address and configuration."],
        ["DHCPREQUEST", "Client", "Requests a specific offered configuration."],
        ["DHCPACK", "Server", "Confirms the lease and configuration."],
        ["DHCPNAK", "Server", "Rejects an invalid configuration request."],
        ["DHCPDECLINE", "Client", "Reports that an offered address is unusable."],
        ["DHCPRELEASE", "Client", "Returns an address before lease expiration."],
        ["DHCPINFORM", "Client", "Requests configuration information."]
    ];

    for (const [message, sender, meaning] of messages) {
        console.log(
            `${message.padEnd(14)} | ` +
            `${sender.padEnd(8)} | ${meaning}`
        );
    }
}

main().catch(error => {
    console.error("\nFatal simulation error:");
    console.error(error.message);
    process.exitCode = 1;
});
