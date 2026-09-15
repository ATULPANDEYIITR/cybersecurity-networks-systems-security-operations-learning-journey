#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using U128 = unsigned __int128;

/*
 * IPv6 industry-style case study:
 *
 * Scenario:
 *   A network operations system manages IPv6 addressing for a company with
 *   multiple departments. It must validate addresses, allocate /64 LANs from
 *   an organizational /48, perform longest-prefix routing, model SLAAC-style
 *   address creation, classify multicast/link-local addresses, and enforce
 *   basic security policy.
 *
 * The program uses only the C++ standard library plus the widely supported
 * unsigned __int128 integer type for practical 128-bit address arithmetic.
 *
 * Compile:
 *   g++ -std=c++17 -O2 ipv6_case_study.cpp -o ipv6_case_study
 *
 * The program does not transmit real network packets. It models the
 * addressing and routing mechanisms that an actual network implementation
 * would use.
 */


// ============================================================================
// 1. IPv6 ADDRESS TYPE
// ============================================================================

class IPv6Address {
private:
    U128 value_;

public:
    explicit IPv6Address(U128 value = 0) : value_(value) {}

    U128 value() const {
        return value_;
    }

    bool operator==(const IPv6Address& other) const {
        return value_ == other.value_;
    }

    bool operator!=(const IPv6Address& other) const {
        return !(*this == other);
    }

    static IPv6Address fromHex(const std::string& text) {
        std::string input = text;

        if (input.empty()) {
            throw std::invalid_argument("IPv6 address is empty.");
        }

        std::size_t doubleColon = input.find("::");

        if (doubleColon != std::string::npos &&
            input.find("::", doubleColon + 2) != std::string::npos) {
            throw std::invalid_argument("IPv6 address contains multiple :: sequences.");
        }

        std::vector<std::string> left;
        std::vector<std::string> right;

        auto splitGroups = [](const std::string& part) {
            std::vector<std::string> result;

            if (part.empty()) {
                return result;
            }

            std::stringstream stream(part);
            std::string group;

            while (std::getline(stream, group, ':')) {
                if (group.empty()) {
                    throw std::invalid_argument("Empty IPv6 group.");
                }

                result.push_back(group);
            }

            return result;
        };

        if (doubleColon == std::string::npos) {
            left = splitGroups(input);

            if (left.size() != 8) {
                throw std::invalid_argument(
                    "Uncompressed IPv6 address must contain eight groups."
                );
            }
        } else {
            left = splitGroups(input.substr(0, doubleColon));
            right = splitGroups(input.substr(doubleColon + 2));

            const std::size_t total = left.size() + right.size();

            if (total >= 8) {
                throw std::invalid_argument(
                    ":: must replace at least one zero group."
                );
            }

            const std::size_t missing = 8 - total;

            std::vector<std::string> expanded = left;

            for (std::size_t i = 0; i < missing; ++i) {
                expanded.push_back("0");
            }

            expanded.insert(expanded.end(), right.begin(), right.end());
            left = expanded;
        }

        U128 value = 0;

        for (const auto& group : left) {
            if (group.size() > 4) {
                throw std::invalid_argument("IPv6 group is longer than four hex digits.");
            }

            unsigned int groupValue = 0;

            for (char character : group) {
                groupValue <<= 4;

                if (character >= '0' && character <= '9') {
                    groupValue += static_cast<unsigned int>(character - '0');
                } else if (character >= 'a' && character <= 'f') {
                    groupValue += static_cast<unsigned int>(character - 'a' + 10);
                } else if (character >= 'A' && character <= 'F') {
                    groupValue += static_cast<unsigned int>(character - 'A' + 10);
                } else {
                    throw std::invalid_argument("Invalid hexadecimal character.");
                }
            }

            if (groupValue > 0xffff) {
                throw std::invalid_argument("IPv6 group exceeds 16 bits.");
            }

            value = (value << 16) | groupValue;
        }

        return IPv6Address(value);
    }

    std::string toString() const {
        std::array<uint16_t, 8> groups{};

        for (int i = 7; i >= 0; --i) {
            groups[static_cast<std::size_t>(i)] =
                static_cast<uint16_t>(value_ & 0xffff);
            value_ >> 16;
        }

        // Recalculate correctly without modifying the address object.
        U128 working = value_;

        for (int i = 7; i >= 0; --i) {
            groups[static_cast<std::size_t>(i)] =
                static_cast<uint16_t>(working & 0xffff);
            working >>= 16;
        }

        std::size_t bestStart = 8;
        std::size_t bestLength = 0;
        std::size_t currentStart = 8;

        for (std::size_t i = 0; i <= 8; ++i) {
            bool zero = i < 8 && groups[i] == 0;

            if (zero && currentStart == 8) {
                currentStart = i;
            }

            if (!zero && currentStart != 8) {
                std::size_t length = i - currentStart;

                if (length > bestLength && length >= 2) {
                    bestStart = currentStart;
                    bestLength = length;
                }

                currentStart = 8;
            }
        }

        std::ostringstream output;
        output << std::hex << std::nouppercase;

        for (std::size_t i = 0; i < 8;) {
            if (i == bestStart) {
                output << "::";
                i += bestLength;

                if (i >= 8) {
                    break;
                }
            } else {
                if (i != 0 && i != bestStart + bestLength) {
                    output << ":";
                }

                output << groups[i];
                ++i;
            }
        }

        return output.str();
    }

    bool isUnspecified() const {
        return value_ == 0;
    }

    bool isLoopback() const {
        return value_ == 1;
    }

    bool isMulticast() const {
        return static_cast<uint8_t>(value_ >> 120) == 0xff;
    }

    bool isLinkLocal() const {
        // fe80::/10
        return (value_ >> 118) == 0b1111111010ULL;
    }

    bool isUniqueLocal() const {
        // fc00::/7
        return (value_ >> 121) == 0b1111110ULL;
    }

    bool isGlobalUnicast() const {
        // 2000::/3
        return (value_ >> 125) == 0b001;
    }
};


// ============================================================================
// 2. PREFIX
// ============================================================================

class IPv6Prefix {
private:
    IPv6Address network_;
    uint8_t length_;

    static U128 maskFor(uint8_t length) {
        if (length > 128) {
            throw std::invalid_argument("IPv6 prefix length must be 0..128.");
        }

        if (length == 0) {
            return 0;
        }

        if (length == 128) {
            return ~static_cast<U128>(0);
        }

        return (~static_cast<U128>(0)) << (128 - length);
    }

public:
    IPv6Prefix(const IPv6Address& address, uint8_t length)
        : length_(length) {
        if (length > 128) {
            throw std::invalid_argument("IPv6 prefix length must be 0..128.");
        }

        U128 mask = maskFor(length);
        network_ = IPv6Address(address.value() & mask);
    }

    static IPv6Prefix parse(const std::string& cidr) {
        const std::size_t slash = cidr.find('/');

        if (slash == std::string::npos) {
            throw std::invalid_argument("Prefix must use CIDR notation.");
        }

        IPv6Address address = IPv6Address::fromHex(cidr.substr(0, slash));
        int length = std::stoi(cidr.substr(slash + 1));

        if (length < 0 || length > 128) {
            throw std::invalid_argument("Invalid prefix length.");
        }

        return IPv6Prefix(address, static_cast<uint8_t>(length));
    }

    const IPv6Address& network() const {
        return network_;
    }

    uint8_t length() const {
        return length_;
    }

    U128 mask() const {
        return maskFor(length_);
    }

    bool contains(const IPv6Address& address) const {
        return (address.value() & mask()) == network_.value();
    }

    std::string toString() const {
        return network_.toString() + "/" + std::to_string(length_);
    }
};


// ============================================================================
// 3. ADDRESS CLASSIFICATION
// ============================================================================

std::string classify(const IPv6Address& address) {
    if (address.isUnspecified()) {
        return "unspecified";
    }

    if (address.isLoopback()) {
        return "loopback";
    }

    if (address.isMulticast()) {
        return "multicast";
    }

    if (address.isLinkLocal()) {
        return "link-local";
    }

    if (address.isUniqueLocal()) {
        return "unique-local";
    }

    if (address.isGlobalUnicast()) {
        return "global-unicast";
    }

    return "other unicast/reserved";
}


// ============================================================================
// 4. SLAAC-STYLE ADDRESS GENERATION
// ============================================================================

U128 eui64FromMac(const std::array<uint8_t, 6>& mac) {
    std::array<uint8_t, 8> eui{
        static_cast<uint8_t>(mac[0] ^ 0x02),
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5]
    };

    U128 result = 0;

    for (uint8_t byte : eui) {
        result = (result << 8) | byte;
    }

    return result;
}

IPv6Address createEUI64Address(
    const IPv6Prefix& prefix,
    const std::array<uint8_t, 6>& mac
) {
    if (prefix.length() != 64) {
        throw std::invalid_argument("EUI-64 construction requires /64.");
    }

    return IPv6Address(prefix.network().value() | eui64FromMac(mac));
}

IPv6Address createRandomInterfaceAddress(const IPv6Prefix& prefix) {
    if (prefix.length() != 64) {
        throw std::invalid_argument("This SLAAC model expects a /64 prefix.");
    }

    std::random_device randomDevice;
    std::mt19937_64 generator(randomDevice());

    uint64_t low = generator();

    return IPv6Address(
        prefix.network().value() |
        static_cast<U128>(low)
    );
}


// ============================================================================
// 5. ROUTING TABLE
// ============================================================================

struct Route {
    IPv6Prefix prefix;
    std::string nextHop;
    int metric;

    Route(
        IPv6Prefix prefixValue,
        std::string nextHopValue,
        int metricValue = 100
    )
        : prefix(std::move(prefixValue)),
          nextHop(std::move(nextHopValue)),
          metric(metricValue) {}
};

std::optional<Route> longestPrefixMatch(
    const IPv6Address& destination,
    const std::vector<Route>& routes
) {
    const Route* best = nullptr;

    for (const auto& route : routes) {
        if (!route.prefix.contains(destination)) {
            continue;
        }

        if (best == nullptr ||
            route.prefix.length() > best->prefix.length() ||
            (route.prefix.length() == best->prefix.length() &&
             route.metric < best->metric)) {
            best = &route;
        }
    }

    if (best == nullptr) {
        return std::nullopt;
    }

    return *best;
}


// ============================================================================
// 6. SECURITY POLICY
// ============================================================================

class SecurityPolicy {
private:
    std::vector<IPv6Prefix> allowedNetworks_;

public:
    explicit SecurityPolicy(std::vector<IPv6Prefix> networks)
        : allowedNetworks_(std::move(networks)) {}

    bool isAllowed(const IPv6Address& address) const {
        return std::any_of(
            allowedNetworks_.begin(),
            allowedNetworks_.end(),
            [&address](const IPv6Prefix& prefix) {
                return prefix.contains(address);
            }
        );
    }
};


// ============================================================================
// 7. NETWORK DESIGN MODEL
// ============================================================================

struct Department {
    std::string name;
    IPv6Prefix subnet;
    IPv6Address exampleHost;
};

class IPv6NetworkManager {
private:
    IPv6Prefix aggregate_;
    std::vector<Department> departments_;

public:
    explicit IPv6NetworkManager(IPv6Prefix aggregate)
        : aggregate_(std::move(aggregate)) {}

    Department allocateDepartment(
        const std::string& name,
        uint16_t subnetIdentifier
    ) {
        if (aggregate_.length() != 48) {
            throw std::invalid_argument(
                "This organizational allocation model expects a /48."
            );
        }

        // Place the 16-bit subnet identifier in bits 48..63.
        U128 networkValue =
            aggregate_.network().value() |
            (static_cast<U128>(subnetIdentifier) << 64);

        IPv6Prefix subnet(IPv6Address(networkValue), 64);

        IPv6Address exampleHost(
            subnet.network().value() | static_cast<U128>(1)
        );

        Department department{
            name,
            subnet,
            exampleHost
        };

        departments_.push_back(department);
        return department;
    }

    const std::vector<Department>& departments() const {
        return departments_;
    }
};


// ============================================================================
// 8. CASE STUDY OPERATIONS
// ============================================================================

void printAddressDetails(const IPv6Address& address) {
    std::cout
        << std::left
        << std::setw(42)
        << address.toString()
        << "type=" << classify(address)
        << '\n';
}

void demonstrateAddressFundamentals() {
    std::cout << "\n=== Address fundamentals ===\n";

    const std::vector<std::string> addresses{
        "::",
        "::1",
        "fe80::1",
        "ff02::1",
        "fd12:3456:789a::1",
        "2001:db8::1"
    };

    for (const auto& text : addresses) {
        printAddressDetails(IPv6Address::fromHex(text));
    }

    std::cout
        << "\nIPv6 uses 128-bit addresses, represented as eight 16-bit "
           "hexadecimal groups.\n"
        << "There is no IPv6 broadcast address; multicast provides group "
           "communication.\n";
}

void demonstrateEnterpriseAllocation() {
    std::cout << "\n=== Enterprise /48 allocation ===\n";

    IPv6NetworkManager manager(
        IPv6Prefix::parse("2001:db8:5000::/48")
    );

    manager.allocateDepartment("Engineering", 0x0010);
    manager.allocateDepartment("Finance", 0x0020);
    manager.allocateDepartment("Operations", 0x0030);
    manager.allocateDepartment("Wireless", 0x0040);
    manager.allocateDepartment("Guest", 0x0050);
    manager.allocateDepartment("Management", 0x0060);

    for (const auto& department : manager.departments()) {
        std::cout
            << std::setw(15)
            << department.name
            << " "
            << std::setw(28)
            << department.subnet.toString()
            << " example="
            << department.exampleHost.toString()
            << '\n';
    }

    std::cout
        << "\nA /48 provides 16 bits for conventional /64 subnet IDs, "
           "which yields 65,536 /64 subnets.\n";
}

void demonstrateSLAAC() {
    std::cout << "\n=== SLAAC-style address creation ===\n";

    const auto prefix = IPv6Prefix::parse(
        "2001:db8:5000:10::/64"
    );

    const std::array<uint8_t, 6> mac{
        0x00, 0x1c, 0x42, 0x2e, 0x60, 0x4a
    };

    IPv6Address euiAddress = createEUI64Address(prefix, mac);
    IPv6Address privacyAddress = createRandomInterfaceAddress(prefix);

    std::cout << "EUI-64-style address: "
              << euiAddress.toString() << '\n';

    std::cout << "Random interface identifier: "
              << privacyAddress.toString() << '\n';

    std::cout
        << "\nSLAAC is driven by Router Advertisements. This program models "
           "the address-formation step, not the full Neighbor Discovery "
           "protocol.\n"
        << "Real hosts also perform Duplicate Address Detection and apply "
           "address-lifetime and router configuration information.\n";
}

void demonstrateLinkLocalAndMulticast() {
    std::cout << "\n=== Link-local and multicast ===\n";

    IPv6Address linkLocal =
        IPv6Address::fromHex("fe80::1");

    IPv6Address allNodes =
        IPv6Address::fromHex("ff02::1");

    IPv6Address allRouters =
        IPv6Address::fromHex("ff02::2");

    printAddressDetails(linkLocal);
    printAddressDetails(allNodes);
    printAddressDetails(allRouters);

    std::cout
        << "\nfe80::/10 is link-local and is restricted to the local link.\n"
        << "ff00::/8 is multicast.\n"
        << "ff02::1 identifies all IPv6 nodes on a link.\n"
        << "ff02::2 identifies all IPv6 routers on a link.\n";
}

void demonstrateRouting() {
    std::cout << "\n=== Longest-prefix routing ===\n";

    std::vector<Route> routes{
        Route(
            IPv6Prefix::parse("::/0"),
            "ISP-A",
            200
        ),
        Route(
            IPv6Prefix::parse("2001:db8::/32"),
            "CORE",
            100
        ),
        Route(
            IPv6Prefix::parse("2001:db8:5000::/48"),
            "DISTRIBUTION",
            100
        ),
        Route(
            IPv6Prefix::parse("2001:db8:5000:10::/64"),
            "EDGE-10",
            50
        )
    };

    std::vector<std::string> destinations{
        "2001:db8:5000:10::100",
        "2001:db8:5000:20::100",
        "2001:db8:9000::100",
        "2606:4700:4700::1111"
    };

    for (const auto& destinationText : destinations) {
        IPv6Address destination =
            IPv6Address::fromHex(destinationText);

        auto route =
            longestPrefixMatch(destination, routes);

        std::cout << destination.toString() << " -> ";

        if (route) {
            std::cout
                << route->nextHop
                << " via "
                << route->prefix.toString()
                << " metric="
                << route->metric
                << '\n';
        } else {
            std::cout << "no route\n";
        }
    }

    std::cout
        << "\nThe /64 route wins for a destination inside it because "
           "longest-prefix matching prefers the most specific route.\n";
}

void demonstrateSecurity() {
    std::cout << "\n=== IPv6 security policy ===\n";

    SecurityPolicy policy({
        IPv6Prefix::parse("2001:db8:5000:10::/64"),
        IPv6Prefix::parse("fd12:3456:789a::/48")
    });

    const std::vector<std::string> testAddresses{
        "2001:db8:5000:10::25",
        "2001:db8:5000:99::25",
        "fd12:3456:789a:1::25",
        "2001:db8:ffff::25"
    };

    for (const auto& text : testAddresses) {
        IPv6Address address =
            IPv6Address::fromHex(text);

        std::cout
            << std::setw(40)
            << address.toString()
            << " allowed="
            << std::boolalpha
            << policy.isAllowed(address)
            << '\n';
    }

    std::cout
        << "\nSecurity policy must operate on parsed addresses and prefixes, "
           "not raw strings.\n"
        << "An IPv4 firewall configuration does not automatically establish "
           "an equivalent IPv6 policy.\n"
        << "ICMPv6 must be filtered intelligently because Neighbor Discovery "
           "and other essential functions depend on it.\n"
        << "Router Advertisement spoofing and Neighbor Discovery attacks "
           "require appropriate Layer-2/network protections.\n";
}


// ============================================================================
// 9. VALIDATION AND FAILURE CONDITIONS
// ============================================================================

void demonstrateValidation() {
    std::cout << "\n=== Validation and failure conditions ===\n";

    const std::vector<std::string> inputs{
        "2001:db8::1",
        "2001:db8:0:0:0:0:0:1",
        "::",
        "fe80::abcd",
        "2001:db8::gggg",
        "2001:db8::/129"
    };

    for (const auto& input : inputs) {
        try {
            if (input.find('/') != std::string::npos) {
                IPv6Prefix prefix =
                    IPv6Prefix::parse(input);

                std::cout
                    << input
                    << " -> valid prefix "
                    << prefix.toString()
                    << '\n';
            } else {
                IPv6Address address =
                    IPv6Address::fromHex(input);

                std::cout
                    << input
                    << " -> valid address "
                    << address.toString()
                    << '\n';
            }
        } catch (const std::exception& error) {
            std::cout
                << input
                << " -> rejected: "
                << error.what()
                << '\n';
        }
    }
}


// ============================================================================
// 10. COMPLEXITY DISCUSSION
// ============================================================================

void printComplexityNotes() {
    std::cout << "\n=== Complexity considerations ===\n";

    std::cout
        << R"(
Address parsing:
    O(1) in practical terms because an IPv6 address has a fixed 128-bit size.

Prefix membership:
    O(1) for one prefix using a 128-bit mask and comparison.

Longest-prefix lookup in this case study:
    O(R), where R is the number of routing entries.

Production routing systems:
    Large routing tables normally use specialized structures such as radix
    trees, Patricia tries, or hardware-assisted lookup. These reduce the
    search cost compared with scanning every route.

Enterprise subnet allocation:
    O(1) per department in this model because the subnet identifier is placed
    directly into the 16-bit field between /48 and /64.

Memory:
    An IPv6 address requires 16 bytes of raw address data. A production route
    entry requires additional metadata such as next-hop, interface, metric,
    protocol, timers, and policy information.
)";
}


// ============================================================================
// 11. SELF-TESTS
// ============================================================================

void runTests() {
    std::cout << "\n=== Automated tests ===\n";

    IPv6Address loopback =
        IPv6Address::fromHex("::1");

    if (!loopback.isLoopback()) {
        throw std::runtime_error("Loopback test failed.");
    }

    IPv6Address linkLocal =
        IPv6Address::fromHex("fe80::1");

    if (!linkLocal.isLinkLocal()) {
        throw std::runtime_error("Link-local test failed.");
    }

    IPv6Address multicast =
        IPv6Address::fromHex("ff02::1");

    if (!multicast.isMulticast()) {
        throw std::runtime_error("Multicast test failed.");
    }

    IPv6Prefix prefix =
        IPv6Prefix::parse("2001:db8:100::/48");

    if (!prefix.contains(
            IPv6Address::fromHex("2001:db8:100:42::1"))) {
        throw std::runtime_error("Prefix membership test failed.");
    }

    if (prefix.contains(
            IPv6Address::fromHex("2001:db8:101::1"))) {
        throw std::runtime_error("Negative prefix membership test failed.");
    }

    std::vector<Route> routes{
        Route(IPv6Prefix::parse("::/0"), "default"),
        Route(IPv6Prefix::parse("2001:db8::/32"), "core"),
        Route(IPv6Prefix::parse("2001:db8:100::/48"), "distribution"),
        Route(IPv6Prefix::parse("2001:db8:100:42::/64"), "edge")
    };

    auto route = longestPrefixMatch(
        IPv6Address::fromHex("2001:db8:100:42::5"),
        routes
    );

    if (!route || route->nextHop != "edge") {
        throw std::runtime_error("Longest-prefix test failed.");
    }

    IPv6Address euiAddress = createEUI64Address(
        IPv6Prefix::parse("fe80::/64"),
        {0x00, 0x1c, 0x42, 0x2e, 0x60, 0x4a}
    );

    if (!euiAddress.isLinkLocal()) {
        throw std::runtime_error("EUI-64 link-local test failed.");
    }

    std::cout << "All C++ IPv6 tests passed.\n";
}


// ============================================================================
// 12. MAIN
// ============================================================================

int main() {
    try {
        std::cout
            << "IPv6 Enterprise Network Case Study\n"
            << "==================================\n"
            << "C++17 technical implementation\n";

        demonstrateAddressFundamentals();
        demonstrateEnterpriseAllocation();
        demonstrateSLAAC();
        demonstrateLinkLocalAndMulticast();
        demonstrateRouting();
        demonstrateSecurity();
        demonstrateValidation();
        printComplexityNotes();
        runTests();

        std::cout
            << "\nCase study execution completed successfully.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
