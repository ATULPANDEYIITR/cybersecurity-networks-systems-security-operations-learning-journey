#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <algorithm>

/*
 * Linux Networking Case Study
 *
 * Scenario:
 * A small service host has two IPv4 networks:
 *
 *   Management: 10.20.0.0/16
 *   Application: 10.30.0.0/16
 *
 * The host also has a default route to an upstream gateway.
 *
 * The program models:
 *   - interface/address inventory
 *   - longest-prefix route selection
 *   - TCP socket behavior
 *   - DNS configuration inspection
 *   - first-match firewall policy evaluation
 *
 * It also demonstrates a real TCP client using Linux/POSIX sockets.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -Wextra -pedantic linux_networking.cpp -o linux_networking
 *
 * Run:
 *   ./linux_networking
 *
 * The diagnostic portions use standard Linux files and commands where
 * appropriate. No firewall configuration is modified.
 */

struct Interface {
    std::string name;
    std::string address;
    std::string state;
    int mtu;
};

struct Route {
    std::string network;
    std::string gateway;
    std::string device;
    int prefixLength;
    int metric;
};

struct Packet {
    std::string protocol;
    std::string sourceIp;
    std::string destinationIp;
    int sourcePort;
    int destinationPort;
};

enum class FirewallAction {
    Accept,
    Drop
};

struct FirewallRule {
    FirewallAction action;
    std::string protocol;
    std::string sourceNetwork;
    int destinationPort;
    std::string description;
};

static uint32_t parseIPv4(const std::string& address) {
    in_addr parsed{};

    if (inet_pton(AF_INET, address.c_str(), &parsed) != 1) {
        throw std::invalid_argument("Invalid IPv4 address: " + address);
    }

    return ntohl(parsed.s_addr);
}

static bool networkContains(
    const std::string& network,
    int prefixLength,
    const std::string& address
) {
    if (prefixLength < 0 || prefixLength > 32) {
        throw std::invalid_argument("Invalid IPv4 prefix length.");
    }

    const uint32_t networkValue = parseIPv4(network);
    const uint32_t addressValue = parseIPv4(address);

    if (prefixLength == 0) {
        return true;
    }

    const uint32_t mask = 0xFFFFFFFFu << (32 - prefixLength);

    return (networkValue & mask) == (addressValue & mask);
}

static std::optional<Route> selectRoute(
    const std::vector<Route>& routes,
    const std::string& destination
) {
    std::vector<Route> matches;

    for (const auto& route : routes) {
        if (networkContains(
                route.network,
                route.prefixLength,
                destination
            )) {
            matches.push_back(route);
        }
    }

    if (matches.empty()) {
        return std::nullopt;
    }

    /*
     * Longest-prefix matching is more specific than a default route.
     * If prefix lengths tie, this model uses the lower metric.
     * Linux policy routing can be more complex because rules and multiple
     * routing tables may participate before a route is selected.
     */
    return *std::max_element(
        matches.begin(),
        matches.end(),
        [](const Route& left, const Route& right) {
            if (left.prefixLength != right.prefixLength) {
                return left.prefixLength < right.prefixLength;
            }

            return left.metric > right.metric;
        }
    );
}

static std::string actionName(FirewallAction action) {
    return action == FirewallAction::Accept ? "ACCEPT" : "DROP";
}

static bool firewallRuleMatches(
    const FirewallRule& rule,
    const Packet& packet
) {
    if (!rule.protocol.empty() && rule.protocol != packet.protocol) {
        return false;
    }

    if (
        !rule.sourceNetwork.empty() &&
        !networkContains(
            rule.sourceNetwork,
            rule.sourceNetwork == "0.0.0.0/0"
                ? 0
                : std::stoi(
                    rule.sourceNetwork.substr(
                        rule.sourceNetwork.find('/') + 1
                    )
                ),
            packet.sourceIp
        )
    ) {
        return false;
    }

    if (
        rule.destinationPort != 0 &&
        rule.destinationPort != packet.destinationPort
    ) {
        return false;
    }

    return true;
}

static std::pair<FirewallAction, std::string> evaluateFirewall(
    const std::vector<FirewallRule>& rules,
    FirewallAction defaultAction,
    const Packet& packet
) {
    for (const auto& rule : rules) {
        if (firewallRuleMatches(rule, packet)) {
            return {rule.action, rule.description};
        }
    }

    return {defaultAction, "default firewall policy"};
}

static void showInterfaces() {
    std::cout << "\n=== Interface inventory ===\n";

    /*
     * /sys/class/net provides kernel-visible interface names without requiring
     * the iproute2 package. Detailed addresses are normally obtained through
     * netlink or `ip`; this example keeps the interface inventory portable
     * within Linux userspace.
     */
    std::ifstream interfaces("/proc/net/dev");

    if (!interfaces) {
        std::cerr << "Unable to read /proc/net/dev\n";
        return;
    }

    std::string line;

    while (std::getline(interfaces, line)) {
        const auto colon = line.find(':');

        if (colon == std::string::npos) {
            continue;
        }

        std::string name = line.substr(0, colon);

        name.erase(
            std::remove_if(
                name.begin(),
                name.end(),
                [](unsigned char character) {
                    return std::isspace(character);
                }
            ),
            name.end()
        );

        std::cout << "interface=" << name << '\n';
    }
}

static void showDnsConfiguration() {
    std::cout << "\n=== DNS configuration ===\n";

    std::ifstream resolv("/etc/resolv.conf");

    if (!resolv) {
        std::cerr << "Unable to read /etc/resolv.conf\n";
        return;
    }

    std::string line;

    while (std::getline(resolv, line)) {
        if (
            line.rfind("nameserver ", 0) == 0 ||
            line.rfind("search ", 0) == 0 ||
            line.rfind("domain ", 0) == 0
        ) {
            std::cout << line << '\n';
        }
    }
}

static void showKernelRouteTable() {
    std::cout << "\n=== Kernel route table ===\n";

    std::ifstream routes("/proc/net/route");

    if (!routes) {
        std::cerr << "Unable to read /proc/net/route\n";
        return;
    }

    std::string line;

    while (std::getline(routes, line)) {
        std::cout << line << '\n';
    }

    std::cout
        << "\nThe hexadecimal addresses in /proc/net/route are kernel "
           "representation details; `ip route` is easier for human analysis.\n";
}

static void demonstrateRouteSelection() {
    std::cout << "\n=== Route-selection case study ===\n";

    const std::vector<Route> routes = {
        {"0.0.0.0", "192.0.2.1", "eth0", 0, 100},
        {"10.0.0.0", "", "eth1", 8, 100},
        {"10.20.0.0", "10.20.0.1", "eth2", 16, 50},
        {"10.20.30.0", "", "eth3", 24, 10}
    };

    const std::vector<std::string> destinations = {
        "8.8.8.8",
        "10.40.5.8",
        "10.20.8.9",
        "10.20.30.44"
    };

    for (const auto& destination : destinations) {
        const auto selected = selectRoute(routes, destination);

        if (!selected) {
            std::cout << destination << " -> no route\n";
            continue;
        }

        std::cout
            << destination
            << " -> "
            << selected->network << "/"
            << selected->prefixLength
            << " dev="
            << selected->device
            << " gateway="
            << (selected->gateway.empty() ? "-" : selected->gateway)
            << '\n';
    }
}

static void demonstrateFirewall() {
    std::cout << "\n=== Firewall policy case study ===\n";

    const std::vector<FirewallRule> rules = {
        {
            FirewallAction::Accept,
            "tcp",
            "10.20.0.0/16",
            22,
            "SSH administration from management network"
        },
        {
            FirewallAction::Accept,
            "tcp",
            "0.0.0.0/0",
            443,
            "Public HTTPS endpoint"
        },
        {
            FirewallAction::Drop,
            "udp",
            "0.0.0.0/0",
            23,
            "Explicitly reject legacy Telnet-like destination"
        }
    };

    const std::vector<Packet> packets = {
        {"tcp", "10.20.5.10", "192.0.2.20", 51000, 22},
        {"tcp", "198.51.100.8", "192.0.2.20", 51001, 22},
        {"tcp", "198.51.100.8", "192.0.2.20", 51002, 443},
        {"udp", "198.51.100.8", "192.0.2.20", 51003, 23},
        {"udp", "198.51.100.8", "192.0.2.20", 51004, 53}
    };

    for (const auto& packet : packets) {
        const auto [action, reason] =
            evaluateFirewall(
                rules,
                FirewallAction::Drop,
                packet
            );

        std::cout
            << packet.protocol
            << " "
            << packet.sourceIp
            << ":"
            << packet.sourcePort
            << " -> "
            << packet.destinationIp
            << ":"
            << packet.destinationPort
            << " => "
            << actionName(action)
            << " ("
            << reason
            << ")\n";
    }

    std::cout
        << "\nA real nftables policy can also use connection tracking, "
           "interfaces, states, sets, NAT, chains, hooks, and priorities.\n";
}

static bool tcpConnect(
    const std::string& host,
    uint16_t port,
    int timeoutSeconds
) {
    std::cout
        << "\n=== TCP socket test ===\n"
        << "host=" << host
        << " port=" << port << '\n';

    /*
     * This example deliberately uses a numeric IPv4 destination. A production
     * client normally calls getaddrinfo() so that DNS and IPv6 candidates can
     * be considered according to application policy.
     */
    const uint32_t address = parseIPv4(host);

    const int socketFd = ::socket(AF_INET, SOCK_STREAM, 0);

    if (socketFd < 0) {
        std::cerr
            << "socket() failed: "
            << std::strerror(errno)
            << '\n';
        return false;
    }

    timeval timeout{};
    timeout.tv_sec = timeoutSeconds;
    timeout.tv_usec = 0;

    if (
        setsockopt(
            socketFd,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &timeout,
            sizeof(timeout)
        ) < 0
    ) {
        std::cerr
            << "setsockopt(SO_SNDTIMEO) failed: "
            << std::strerror(errno)
            << '\n';
        close(socketFd);
        return false;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(address);

    const auto start = std::chrono::steady_clock::now();

    const int result = connect(
        socketFd,
        reinterpret_cast<sockaddr*>(&server),
        sizeof(server)
    );

    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start
        );

    if (result == 0) {
        std::cout
            << "TCP connection succeeded in "
            << elapsed.count()
            << " ms\n";

        close(socketFd);
        return true;
    }

    std::cerr
        << "connect() failed after "
        << elapsed.count()
        << " ms: "
        << std::strerror(errno)
        << '\n';

    close(socketFd);
    return false;
}

int main(int argc, char* argv[]) {
    try {
        showInterfaces();
        showKernelRouteTable();
        showDnsConfiguration();

        demonstrateRouteSelection();
        demonstrateFirewall();

        /*
         * The network below is documentation-only TEST-NET-1. It is not
         * expected to be routable on the public Internet. The call is kept
         * behind an explicit command-line argument so the normal diagnostic
         * run does not make an unnecessary network connection.
         */
        if (argc == 4 && std::string(argv[1]) == "--tcp") {
            const std::string host = argv[2];
            const int parsedPort = std::stoi(argv[3]);

            if (parsedPort < 1 || parsedPort > 65535) {
                throw std::invalid_argument(
                    "TCP port must be between 1 and 65535."
                );
            }

            tcpConnect(
                host,
                static_cast<uint16_t>(parsedPort),
                3
            );
        }

        std::cout
            << "\nNo firewall rule was modified. "
               "Diagnostic programs should not silently change host policy.\n";
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }

    return 0;
}
