#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

class AddressValidator {
public:
    static std::string validateIPv4(const std::string& address) {
        std::stringstream stream(address);
        std::string component;
        int count = 0;

        while (std::getline(stream, component, '.')) {
            if (component.empty()) {
                throw std::invalid_argument(
                    "Invalid IPv4 address: " + address
                );
            }

            for (char character : component) {
                if (character < '0' || character > '9') {
                    throw std::invalid_argument(
                        "Invalid IPv4 address: " + address
                    );
                }
            }

            int value = std::stoi(component);

            if (value < 0 || value > 255) {
                throw std::invalid_argument(
                    "Invalid IPv4 address: " + address
                );
            }

            ++count;
        }

        if (count != 4) {
            throw std::invalid_argument(
                "Invalid IPv4 address: " + address
            );
        }

        return address;
    }

    static std::string validateMac(const std::string& mac) {
        if (mac.size() != 17) {
            throw std::invalid_argument(
                "Invalid MAC address: " + mac
            );
        }

        for (std::size_t index = 0; index < mac.size(); ++index) {
            if ((index + 1) % 3 == 0) {
                if (mac[index] != ':') {
                    throw std::invalid_argument(
                        "Invalid MAC address: " + mac
                    );
                }
            } else {
                const char character = mac[index];
                const bool hexadecimal =
                    (character >= '0' && character <= '9') ||
                    (character >= 'a' && character <= 'f') ||
                    (character >= 'A' && character <= 'F');

                if (!hexadecimal) {
                    throw std::invalid_argument(
                        "Invalid MAC address: " + mac
                    );
                }
            }
        }

        return mac;
    }
};

// ---------------------------------------------------------------------------
// ARP packet model
// ---------------------------------------------------------------------------

enum class ArpOperation {
    Request = 1,
    Reply = 2
};

std::string operationName(ArpOperation operation) {
    switch (operation) {
        case ArpOperation::Request:
            return "REQUEST";
        case ArpOperation::Reply:
            return "REPLY";
    }

    return "UNKNOWN";
}

struct ArpPacket {
    ArpOperation operation;
    std::string senderMac;
    std::string senderIp;
    std::string targetMac;
    std::string targetIp;

    ArpPacket(
        ArpOperation operationValue,
        const std::string& senderMacValue,
        const std::string& senderIpValue,
        const std::string& targetMacValue,
        const std::string& targetIpValue
    )
        : operation(operationValue),
          senderMac(AddressValidator::validateMac(senderMacValue)),
          senderIp(AddressValidator::validateIPv4(senderIpValue)),
          targetMac(AddressValidator::validateMac(targetMacValue)),
          targetIp(AddressValidator::validateIPv4(targetIpValue)) {}

    std::string description() const {
        return "ARP " + operationName(operation) + ": " +
               senderIp + " (" + senderMac + ") -> " +
               targetIp + " (" + targetMac + ")";
    }
};

// ---------------------------------------------------------------------------
// Host model
// ---------------------------------------------------------------------------

struct Host {
    std::string name;
    std::string ipAddress;
    std::string macAddress;

    Host(
        const std::string& hostName,
        const std::string& ip,
        const std::string& mac
    )
        : name(hostName),
          ipAddress(AddressValidator::validateIPv4(ip)),
          macAddress(AddressValidator::validateMac(mac)) {}
};

// ---------------------------------------------------------------------------
// ARP cache
// ---------------------------------------------------------------------------

enum class CacheState {
    Reachable,
    Stale,
    Static
};

std::string cacheStateName(CacheState state) {
    switch (state) {
        case CacheState::Reachable:
            return "reachable";
        case CacheState::Stale:
            return "stale";
        case CacheState::Static:
            return "static";
    }

    return "unknown";
}

struct ArpCacheEntry {
    std::string ipAddress;
    std::string macAddress;
    CacheState state;
    Clock::time_point learnedAt;
};

class ArpCache {
private:
    std::unordered_map<std::string, ArpCacheEntry> entries;
    std::chrono::seconds reachableTimeout;

public:
    explicit ArpCache(
        std::chrono::seconds timeout = std::chrono::seconds(60)
    )
        : reachableTimeout(timeout) {}

    void add(
        const std::string& ipAddress,
        const std::string& macAddress,
        CacheState state = CacheState::Reachable
    ) {
        AddressValidator::validateIPv4(ipAddress);
        AddressValidator::validateMac(macAddress);

        entries[ipAddress] = {
            ipAddress,
            macAddress,
            state,
            Clock::now()
        };
    }

    std::optional<ArpCacheEntry> lookup(
        const std::string& ipAddress
    ) {
        AddressValidator::validateIPv4(ipAddress);

        auto iterator = entries.find(ipAddress);

        if (iterator == entries.end()) {
            return std::nullopt;
        }

        ArpCacheEntry& entry = iterator->second;

        const auto age =
            std::chrono::duration_cast<std::chrono::seconds>(
                Clock::now() - entry.learnedAt
            );

        if (
            entry.state == CacheState::Reachable &&
            age > reachableTimeout
        ) {
            entry.state = CacheState::Stale;
        }

        return entry;
    }

    bool remove(const std::string& ipAddress) {
        return entries.erase(ipAddress) > 0;
    }

    void print() const {
        if (entries.empty()) {
            std::cout << "(empty ARP cache)\n";
            return;
        }

        std::cout
            << std::left
            << std::setw(18) << "IPv4"
            << std::setw(22) << "MAC"
            << std::setw(12) << "State"
            << "Age(s)\n";

        std::cout << std::string(62, '-') << '\n';

        for (const auto& [ip, entry] : entries) {
            const auto age =
                std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - entry.learnedAt
                );

            std::cout
                << std::left
                << std::setw(18) << entry.ipAddress
                << std::setw(22) << entry.macAddress
                << std::setw(12) << cacheStateName(entry.state)
                << age.count()
                << '\n';
        }
    }
};

// ---------------------------------------------------------------------------
// Enterprise LAN
// ---------------------------------------------------------------------------

class EnterpriseLan {
private:
    std::unordered_map<std::string, Host> hosts;
    std::unordered_map<std::string, ArpCache> caches;

    static constexpr const char* BroadcastMac =
        "ff:ff:ff:ff:ff:ff";

    static constexpr const char* ZeroMac =
        "00:00:00:00:00:00";

public:
    void addHost(const Host& host) {
        if (hosts.find(host.ipAddress) != hosts.end()) {
            throw std::runtime_error(
                "Duplicate IPv4 address: " + host.ipAddress
            );
        }

        hosts.emplace(host.ipAddress, host);
        caches.emplace(host.ipAddress, ArpCache{});
    }

    std::optional<ArpPacket> broadcastArpRequest(
        const std::string& requesterIp,
        const std::string& targetIp
    ) {
        auto requesterIterator = hosts.find(requesterIp);

        if (requesterIterator == hosts.end()) {
            throw std::runtime_error(
                "Requester is not present on the LAN."
            );
        }

        const Host& requester = requesterIterator->second;

        std::cout
            << requester.name
            << " broadcasts: Who has "
            << targetIp
            << "? Tell "
            << requesterIp
            << '\n';

        std::cout
            << "Ethernet destination: "
            << BroadcastMac
            << '\n';

        auto targetIterator = hosts.find(targetIp);

        if (targetIterator == hosts.end()) {
            std::cout
                << "No host answers the ARP request.\n";
            return std::nullopt;
        }

        const Host& target = targetIterator->second;

        ArpPacket reply(
            ArpOperation::Reply,
            target.macAddress,
            target.ipAddress,
            requester.macAddress,
            requester.ipAddress
        );

        caches.at(requester.ipAddress).add(
            target.ipAddress,
            target.macAddress
        );

        std::cout
            << target.name
            << " replies: "
            << target.ipAddress
            << " is at "
            << target.macAddress
            << '\n';

        return reply;
    }

    std::optional<std::string> resolveMac(
        const std::string& requesterIp,
        const std::string& targetIp
    ) {
        auto cacheIterator = caches.find(requesterIp);

        if (cacheIterator == caches.end()) {
            throw std::runtime_error(
                "Requester has no ARP cache."
            );
        }

        auto cached =
            cacheIterator->second.lookup(targetIp);

        if (
            cached.has_value() &&
            cached->state != CacheState::Stale
        ) {
            std::cout
                << "Cache hit: "
                << targetIp
                << " -> "
                << cached->macAddress
                << '\n';

            return cached->macAddress;
        }

        std::cout
            << "Cache miss: "
            << targetIp
            << '\n';

        auto reply =
            broadcastArpRequest(requesterIp, targetIp);

        if (!reply.has_value()) {
            return std::nullopt;
        }

        return reply->senderMac;
    }

    void printCache(const std::string& hostIp) {
        auto iterator = caches.find(hostIp);

        if (iterator == caches.end()) {
            throw std::runtime_error(
                "Unknown host: " + hostIp
            );
        }

        iterator->second.print();
    }
};

// ---------------------------------------------------------------------------
// Passive security monitoring
// ---------------------------------------------------------------------------

class ArpSecurityMonitor {
private:
    std::unordered_map<
        std::string,
        std::unordered_set<std::string>
    > ipToMacs;

public:
    bool observe(const ArpPacket& packet) {
        auto& macSet = ipToMacs[packet.senderIp];

        const std::size_t oldSize = macSet.size();

        macSet.insert(packet.senderMac);

        return macSet.size() > oldSize &&
               macSet.size() > 1;
    }

    void printConflicts() const {
        for (const auto& [ip, macs] : ipToMacs) {
            if (macs.size() <= 1) {
                continue;
            }

            std::cout
                << "Potential IP/MAC conflict for "
                << ip
                << ":\n";

            for (const auto& mac : macs) {
                std::cout
                    << "    "
                    << mac
                    << '\n';
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Demonstrations
// ---------------------------------------------------------------------------

void printSection(const std::string& title) {
    std::cout << '\n'
              << std::string(78, '=')
              << '\n'
              << title
              << '\n'
              << std::string(78, '=')
              << '\n';
}

void demonstrateAddressValidation() {
    printSection("1. Address validation");

    std::cout
        << "IPv4: "
        << AddressValidator::validateIPv4("192.168.1.10")
        << '\n';

    std::cout
        << "MAC: "
        << AddressValidator::validateMac(
            "02:00:00:00:00:10"
        )
        << '\n';

    try {
        AddressValidator::validateIPv4("192.168.1.999");
    } catch (const std::exception& error) {
        std::cout
            << "Rejected invalid IPv4: "
            << error.what()
            << '\n';
    }
}

void demonstrateArpPacket() {
    printSection("2. ARP packet structure");

    ArpPacket request(
        ArpOperation::Request,
        "02:00:00:00:00:10",
        "192.168.1.10",
        "00:00:00:00:00:00",
        "192.168.1.20"
    );

    ArpPacket reply(
        ArpOperation::Reply,
        "02:00:00:00:00:20",
        "192.168.1.20",
        "02:00:00:00:00:10",
        "192.168.1.10"
    );

    std::cout << request.description() << '\n';
    std::cout << reply.description() << '\n';

    std::cout
        << "\nThe request uses an unknown target MAC and is normally "
           "delivered through an Ethernet broadcast.\n";
}

void demonstrateCache() {
    printSection("3. ARP cache");

    ArpCache cache;

    cache.add(
        "192.168.1.1",
        "02:00:00:00:00:01",
        CacheState::Static
    );

    cache.add(
        "192.168.1.20",
        "02:00:00:00:00:20",
        CacheState::Reachable
    );

    cache.print();

    auto entry = cache.lookup("192.168.1.20");

    if (entry.has_value()) {
        std::cout
            << "\nLookup result: "
            << entry->ipAddress
            << " -> "
            << entry->macAddress
            << '\n';
    }
}

void demonstrateEnterpriseLan() {
    printSection("4. Enterprise LAN ARP resolution");

    EnterpriseLan lan;

    Host client(
        "Engineering-Client",
        "10.20.30.10",
        "02:20:00:00:00:10"
    );

    Host server(
        "Application-Server",
        "10.20.30.20",
        "02:20:00:00:00:20"
    );

    Host gateway(
        "Default-Gateway",
        "10.20.30.1",
        "02:20:00:00:00:01"
    );

    lan.addHost(client);
    lan.addHost(server);
    lan.addHost(gateway);

    std::cout
        << "First access to the application server:\n";

    lan.resolveMac(
        client.ipAddress,
        server.ipAddress
    );

    std::cout
        << "\nSecond access to the application server:\n";

    lan.resolveMac(
        client.ipAddress,
        server.ipAddress
    );

    std::cout
        << "\nClient ARP cache:\n";

    lan.printCache(client.ipAddress);

    std::cout
        << "\nClient resolves its default gateway:\n";

    lan.resolveMac(
        client.ipAddress,
        gateway.ipAddress
    );

    std::cout
        << "\nUpdated client cache:\n";

    lan.printCache(client.ipAddress);
}

void demonstrateSecurityMonitoring() {
    printSection("5. Passive ARP security monitoring");

    /*
     * A legitimate gateway initially advertises one MAC address.
     */
    ArpPacket legitimateGateway(
        ArpOperation::Reply,
        "02:20:00:00:00:01",
        "10.20.30.1",
        "02:20:00:00:00:10",
        "10.20.30.10"
    );

    /*
     * A second MAC claiming the same gateway IP is an anomaly worth
     * investigating. The program does not generate this packet on a
     * network; it merely models what a passive sensor might observe.
     */
    ArpPacket conflictingObservation(
        ArpOperation::Reply,
        "02:20:00:00:00:99",
        "10.20.30.1",
        "02:20:00:00:00:10",
        "10.20.30.10"
    );

    ArpSecurityMonitor monitor;

    std::vector<ArpPacket> observations = {
        legitimateGateway,
        conflictingObservation
    };

    for (const auto& packet : observations) {
        std::cout
            << packet.description()
            << '\n';

        if (monitor.observe(packet)) {
            std::cout
                << "ALERT: the sender IPv4 address is now associated "
                   "with multiple observed MAC addresses.\n";
        }
    }

    monitor.printConflicts();

    std::cout
        << "\nThis is a detection signal, not proof of an attack. "
           "High availability, virtualization, proxy ARP, and legitimate "
           "network changes can produce similar observations.\n";
}

void demonstrateWiresharkAnalysis() {
    printSection("6. Wireshark analysis");

    std::cout
        << R"(
Useful Wireshark display filters:

    arp
    arp.opcode == 1
    arp.opcode == 2
    arp.src.proto_ipv4 == 10.20.30.1
    arp.dst.proto_ipv4 == 10.20.30.10
    arp.src.hw_mac == 02:20:00:00:00:01
    eth.dst == ff:ff:ff:ff:ff:ff && arp

When examining a request, inspect:

    Ethernet destination
    Ethernet source
    ARP opcode
    Sender MAC
    Sender IPv4
    Target MAC
    Target IPv4

For security analysis, compare the sender IPv4 and sender MAC across
multiple frames. A single unusual frame can have several legitimate
explanations.
)"
        << '\n';
}

void demonstrateArchitecture() {
    printSection("7. Architecture and design decisions");

    std::cout
        << R"(
The case study separates responsibilities into:

    AddressValidator
        Validates IPv4 and MAC addresses.

    ArpPacket
        Represents the semantic contents of an ARP message.

    Host
        Represents an endpoint with an IPv4 and MAC address.

    ArpCache
        Stores IP-to-MAC mappings and models aging.

    EnterpriseLan
        Models broadcast resolution and cache-assisted lookup.

    ArpSecurityMonitor
        Tracks observed IP-to-MAC relationships and identifies conflicts.

This separation makes the design easier to test and extend.

The main performance-sensitive lookup structures use unordered_map,
providing average O(1) lookup complexity.

Processing n observed packets is approximately O(n), while the number of
stored relationships determines monitoring memory usage.
)"
        << '\n';
}

void demonstrateFailureConditions() {
    printSection("8. Failure conditions and edge cases");

    EnterpriseLan lan;

    lan.addHost(
        Host(
            "Client",
            "192.168.50.10",
            "02:50:00:00:00:10"
        )
    );

    std::cout
        << "Resolving an unknown host:\n";

    auto result = lan.resolveMac(
        "192.168.50.10",
        "192.168.50.99"
    );

    if (!result.has_value()) {
        std::cout
            << "Resolution failed because no simulated host answered.\n";
    }

    try {
        lan.addHost(
            Host(
                "Duplicate-IP-Host",
                "192.168.50.10",
                "02:50:00:00:00:99"
            )
        );
    } catch (const std::exception& error) {
        std::cout
            << "Duplicate IP rejected: "
            << error.what()
            << '\n';
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "ARP ENTERPRISE LAN CASE STUDY\n"
            << "C++17 offline simulation\n";

        demonstrateAddressValidation();
        demonstrateArpPacket();
        demonstrateCache();
        demonstrateEnterpriseLan();
        demonstrateSecurityMonitoring();
        demonstrateWiresharkAnalysis();
        demonstrateArchitecture();
        demonstrateFailureConditions();

        printSection("Case study complete");

        std::cout
            << "No real ARP frames were transmitted.\n";
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }

    return 0;
}
