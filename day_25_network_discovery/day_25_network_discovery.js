#!/usr/bin/env node

/**
 * Network Discovery: Host Discovery, Service Discovery, Banners, Network Mapping
 *
 * This file provides a self-contained Node.js implementation of authorized
 * TCP-based network inventory.
 *
 * It intentionally avoids:
 *   - stealth/evasion techniques
 *   - exploitation
 *   - credential attacks
 *   - vulnerability exploitation
 *   - arbitrary protocol payload generation
 *
 * Use only against systems and networks you own or are explicitly authorized
 * to test.
 *
 * The examples progress through:
 *   1. IP and port fundamentals
 *   2. TCP connection testing
 *   3. Service classification
 *   4. Passive banner collection
 *   5. Reverse DNS
 *   6. Network mapping
 *   7. Concurrent inventory
 *   8. JSON reporting
 *   9. Nmap conceptual comparison
 */

"use strict";

const net = require("net");
const dns = require("dns").promises;
const os = require("os");
const fs = require("fs/promises");

const COMMON_SERVICES = new Map([
    [20, "FTP-DATA"],
    [21, "FTP"],
    [22, "SSH"],
    [23, "TELNET"],
    [25, "SMTP"],
    [53, "DNS"],
    [80, "HTTP"],
    [110, "POP3"],
    [123, "NTP"],
    [135, "MS-RPC"],
    [139, "NETBIOS-SSN"],
    [143, "IMAP"],
    [161, "SNMP"],
    [389, "LDAP"],
    [443, "HTTPS"],
    [445, "SMB"],
    [587, "SMTP-SUBMISSION"],
    [631, "IPP"],
    [636, "LDAPS"],
    [993, "IMAPS"],
    [995, "POP3S"],
    [1433, "MSSQL"],
    [1521, "ORACLE"],
    [2049, "NFS"],
    [2375, "DOCKER"],
    [3306, "MYSQL"],
    [3389, "RDP"],
    [5432, "POSTGRESQL"],
    [5900, "VNC"],
    [6379, "REDIS"],
    [8080, "HTTP-ALT"],
    [8443, "HTTPS-ALT"],
    [9200, "ELASTICSEARCH"]
]);

function utcNow() {
    return new Date().toISOString();
}

function serviceGuess(port) {
    return COMMON_SERVICES.get(port) || "unknown";
}

function validatePort(port) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid TCP port: ${port}`);
    }

    return port;
}

function parsePorts(value) {
    const ports = value
        .split(",")
        .map(part => Number(part.trim()))
        .filter(Number.isFinite)
        .map(validatePort);

    const uniquePorts = [...new Set(ports)];

    if (uniquePorts.length === 0) {
        throw new Error("At least one port is required.");
    }

    return uniquePorts;
}

function cleanBanner(buffer, maximumLength = 512) {
    /*
     * Network responses are untrusted input. Limit their size and remove
     * non-printable characters before displaying or storing them.
     */
    const text = buffer
        .subarray(0, maximumLength)
        .toString("utf8");

    return [...text]
        .filter(character => {
            const code = character.charCodeAt(0);
            return (
                character === "\n" ||
                character === "\r" ||
                character === "\t" ||
                (code >= 32 && code <= 126)
            );
        })
        .join("")
        .trim();
}

function tcpConnect(host, port, timeoutMs = 700, readBanner = false) {
    validatePort(port);

    return new Promise(resolve => {
        const started = process.hrtime.bigint();

        const socket = new net.Socket();
        let settled = false;
        let receivedData = Buffer.alloc(0);

        const finish = result => {
            if (settled) {
                return;
            }

            settled = true;
            socket.destroy();

            const elapsedNs = process.hrtime.bigint() - started;
            result.latencyMs = Number(elapsedNs) / 1_000_000;

            resolve(result);
        };

        socket.setTimeout(timeoutMs);

        socket.on("connect", () => {
            /*
             * TCP connect success proves that the target accepted the
             * connection. It does not prove the identity of the application.
             */
            if (!readBanner) {
                finish({
                    port,
                    protocol: "tcp",
                    state: "open",
                    serviceGuess: serviceGuess(port),
                    banner: "",
                    error: null
                });
            }
        });

        socket.on("data", chunk => {
            if (!readBanner || settled) {
                return;
            }

            receivedData = Buffer.concat([
                receivedData,
                chunk.subarray(0, 512 - receivedData.length)
            ]);

            /*
             * Passive banner collection reads what the server voluntarily
             * sends. The implementation does not send arbitrary probes.
             */
            if (receivedData.length >= 512) {
                finish({
                    port,
                    protocol: "tcp",
                    state: "open",
                    serviceGuess: serviceGuess(port),
                    banner: cleanBanner(receivedData),
                    error: null
                });
            }
        });

        socket.on("timeout", () => {
            finish({
                port,
                protocol: "tcp",
                state: "filtered_or_timeout",
                serviceGuess: serviceGuess(port),
                banner: "",
                error: "connection timed out"
            });
        });

        socket.on("error", error => {
            const isRefused =
                error.code === "ECONNREFUSED";

            finish({
                port,
                protocol: "tcp",
                state: isRefused
                    ? "closed"
                    : "error",
                serviceGuess: serviceGuess(port),
                banner: "",
                error: `${error.code || "SOCKET_ERROR"}: ${error.message}`
            });
        });

        socket.on("close", () => {
            if (!settled && readBanner) {
                finish({
                    port,
                    protocol: "tcp",
                    state: "open",
                    serviceGuess: serviceGuess(port),
                    banner: cleanBanner(receivedData),
                    error: null
                });
            }
        });

        socket.connect({
            host,
            port
        });
    });
}

async function reverseDns(host) {
    try {
        const names = await dns.reverse(host);
        return names[0] || null;
    } catch {
        return null;
    }
}

async function hostDiscovery(host, ports, timeoutMs) {
    const started = process.hrtime.bigint();

    /*
     * A host can be online even if all selected ports are closed or filtered.
     * Therefore this is evidence-based discovery, not absolute reachability.
     */
    for (const port of ports) {
        const result = await tcpConnect(host, port, timeoutMs, false);

        if (result.state === "open") {
            const elapsed =
                Number(process.hrtime.bigint() - started) / 1_000_000;

            return {
                ip: host,
                reachable: true,
                reverseDns: await reverseDns(host),
                latencyMs: elapsed,
                ports: [],
                scannedAt: utcNow()
            };
        }
    }

    const elapsed =
        Number(process.hrtime.bigint() - started) / 1_000_000;

    return {
        ip: host,
        reachable: false,
        reverseDns: await reverseDns(host),
        latencyMs: elapsed,
        ports: [],
        scannedAt: utcNow()
    };
}

async function serviceDiscovery(host, ports, timeoutMs, collectBanners) {
    const results = [];

    /*
     * Sequential processing makes this educational example easy to follow.
     * A production inventory system can use bounded concurrency instead of
     * creating an unbounded number of sockets.
     */
    for (const port of ports) {
        const result = await tcpConnect(
            host,
            port,
            timeoutMs,
            collectBanners
        );

        results.push(result);
    }

    return results;
}

async function inspectHost(
    host,
    ports,
    timeoutMs = 700,
    collectBanners = true
) {
    const hostResult = await hostDiscovery(
        host,
        ports,
        timeoutMs
    );

    if (!hostResult.reachable) {
        return hostResult;
    }

    hostResult.ports = await serviceDiscovery(
        host,
        ports,
        timeoutMs,
        collectBanners
    );

    return hostResult;
}

function getLocalAddresses() {
    const interfaces = os.networkInterfaces();
    const addresses = new Set(["127.0.0.1"]);

    for (const entries of Object.values(interfaces)) {
        for (const entry of entries || []) {
            if (entry && entry.family === "IPv4") {
                addresses.add(entry.address);
            }
        }
    }

    return [...addresses].sort();
}

function printHostResult(host) {
    console.log(
        `${host.ip.padEnd(16)} ` +
        `${(host.reachable ? "UP" : "NOT CONFIRMED").padEnd(16)} ` +
        `DNS=${host.reverseDns || "-"}`
    );

    console.log(
        `  latency: ${host.latencyMs.toFixed(2)} ms`
    );

    for (const port of host.ports) {
        const banner = port.banner
            ? port.banner.replace(/\n/g, "\\n")
            : "-";

        console.log(
            `  TCP/${String(port.port).padEnd(5)} ` +
            `${port.state.padEnd(22)} ` +
            `${port.serviceGuess.padEnd(18)} ` +
            `banner=${banner}`
        );
    }
}

function printNetworkMap(networkMap) {
    console.log("=".repeat(78));
    console.log("NETWORK MAP");
    console.log("=".repeat(78));
    console.log(`Target: ${networkMap.target}`);
    console.log(`Created: ${networkMap.createdAt}`);
    console.log(`Records: ${networkMap.hosts.length}`);
    console.log();

    for (const host of networkMap.hosts) {
        printHostResult(host);
        console.log();
    }
}

function explainNmap() {
    console.log("=".repeat(78));
    console.log("NMAP CONCEPTS");
    console.log("=".repeat(78));

    const examples = [
        [
            "nmap 192.168.1.10",
            "Explore one explicitly authorized target."
        ],
        [
            "nmap -sn 192.168.1.0/24",
            "Host discovery without a normal port scan."
        ],
        [
            "nmap -p 22,80,443 192.168.1.10",
            "Examine selected TCP ports."
        ],
        [
            "nmap -sV 192.168.1.10",
            "Attempt service/version identification."
        ],
        [
            "nmap -O 192.168.1.10",
            "Attempt operating-system identification."
        ]
    ];

    for (const [command, explanation] of examples) {
        console.log(command);
        console.log(`  ${explanation}`);
    }

    console.log();
    console.log("Typical state meanings:");
    console.log("  open      -> an application accepted the probe");
    console.log("  closed    -> the host responded but no service accepted it");
    console.log("  filtered  -> filtering prevented a reliable determination");
    console.log();
}

async function runLocalDemo() {
    console.log("=".repeat(78));
    console.log("LOCALHOST NETWORK DISCOVERY DEMONSTRATION");
    console.log("=".repeat(78));

    const ports = [22, 80, 443, 8000, 8080];

    console.log("Target: 127.0.0.1");
    console.log(`Ports : ${ports.join(", ")}`);
    console.log();

    const result = await inspectHost(
        "127.0.0.1",
        ports,
        500,
        true
    );

    printHostResult(result);
    console.log();

    explainNmap();
}

async function boundedMap(items, worker, concurrency) {
    /*
     * Bounded concurrency is preferable to Promise.all(items.map(...))
     * when the list can become large. It controls simultaneous network work.
     */
    const results = new Array(items.length);
    let nextIndex = 0;

    async function runner() {
        while (true) {
            const index = nextIndex++;

            if (index >= items.length) {
                return;
            }

            results[index] = await worker(items[index], index);
        }
    }

    const workerCount = Math.min(
        Math.max(1, concurrency),
        items.length || 1
    );

    await Promise.all(
        Array.from(
            { length: workerCount },
            () => runner()
        )
    );

    return results;
}

function parseArguments(argv) {
    const options = {
        target: null,
        ports: [22, 80, 443, 8080],
        timeout: 700,
        concurrency: 8,
        output: null,
        banners: true,
        demo: false
    };

    for (let index = 0; index < argv.length; index++) {
        const argument = argv[index];

        if (argument === "--demo") {
            options.demo = true;
        } else if (argument === "--target") {
            options.target = argv[++index];
        } else if (argument === "--ports") {
            options.ports = parsePorts(argv[++index]);
        } else if (argument === "--timeout") {
            options.timeout = Number(argv[++index]);

            if (!Number.isFinite(options.timeout) || options.timeout <= 0) {
                throw new Error("Timeout must be greater than zero.");
            }
        } else if (argument === "--concurrency") {
            options.concurrency = Number(argv[++index]);

            if (
                !Number.isInteger(options.concurrency) ||
                options.concurrency < 1
            ) {
                throw new Error(
                    "Concurrency must be a positive integer."
                );
            }
        } else if (argument === "--output") {
            options.output = argv[++index];
        } else if (argument === "--no-banners") {
            options.banners = false;
        } else if (argument === "--local-addresses") {
            options.localAddresses = true;
        } else if (argument === "--help") {
            printUsage();
            process.exit(0);
        } else {
            throw new Error(`Unknown argument: ${argument}`);
        }
    }

    return options;
}

function printUsage() {
    console.log(`
Network Discovery Study Program

Safe demonstration:
  node network_discovery.js --demo

Inspect local address candidates:
  node network_discovery.js --local-addresses

Inspect one authorized host:
  node network_discovery.js --target 192.168.1.10

Inspect selected ports:
  node network_discovery.js --target 192.168.1.10 --ports 22,80,443

Save JSON:
  node network_discovery.js --target 192.168.1.10 --output map.json

Disable passive banners:
  node network_discovery.js --target 192.168.1.10 --no-banners

The target must be a system or network for which you have authorization.
`);
}

async function main() {
    const options = parseArguments(
        process.argv.slice(2)
    );

    if (options.localAddresses) {
        console.log("Local IPv4 address candidates:");

        for (const address of getLocalAddresses()) {
            console.log(`  ${address}`);
        }

        return;
    }

    if (options.demo || !options.target) {
        await runLocalDemo();
        return;
    }

    console.log("=".repeat(78));
    console.log("AUTHORIZED NETWORK INVENTORY");
    console.log("=".repeat(78));
    console.log(`Target: ${options.target}`);
    console.log(`Ports: ${options.ports.join(", ")}`);
    console.log(`Timeout: ${options.timeout} ms`);
    console.log(`Concurrency: ${options.concurrency}`);
    console.log(`Banners: ${options.banners}`);
    console.log();

    /*
     * This implementation intentionally accepts a single explicit IPv4
     * address. CIDR expansion is omitted so that the example cannot silently
     * expand into a large network. A network inventory tool can add explicit
     * CIDR parsing with a strict address-count limit.
     */
    const addresses = [options.target];

    const started = process.hrtime.bigint();

    const hosts = await boundedMap(
        addresses,
        address => inspectHost(
            address,
            options.ports,
            options.timeout,
            options.banners
        ),
        options.concurrency
    );

    const networkMap = {
        target: options.target,
        createdAt: utcNow(),
        hosts
    };

    printNetworkMap(networkMap);

    const elapsed =
        Number(process.hrtime.bigint() - started) / 1_000_000;

    console.log("=".repeat(78));
    console.log("INVENTORY STATISTICS");
    console.log("=".repeat(78));
    console.log(
        `Hosts confirmed: ${hosts.filter(host => host.reachable).length}`
    );
    console.log(
        `Open TCP ports: ${
            hosts.reduce(
                (total, host) =>
                    total +
                    host.ports.filter(
                        port => port.state === "open"
                    ).length,
                0
            )
        }`
    );
    console.log(`Elapsed: ${elapsed.toFixed(2)} ms`);

    if (options.output) {
        await fs.writeFile(
            options.output,
            JSON.stringify(networkMap, null, 2),
            "utf8"
        );

        console.log(`JSON written to: ${options.output}`);
    }
}

main().catch(error => {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
});
