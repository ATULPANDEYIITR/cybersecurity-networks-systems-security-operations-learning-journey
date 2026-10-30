/*
 * Network Segmentation and Merge-Eligibility-Style Policy Engine
 * Technical implementation: C++17
 *
 * Models:
 * - VLAN-based segmentation
 * - Isolated trust zones
 * - DMZ boundary filtering
 * - Microsegmentation
 * - East-west traffic
 * - Default-deny enforcement
 * - Rule-priority evaluation
 * - Flow auditing
 *
 * Compile:
 *     g++ -std=c++17 -O2 -Wall -Wextra -pedantic network_segmentation.cpp -o network_segmentation
 *
 * Run:
 *     ./network_segmentation
 */

#include <algorithm>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum class Zone {
    USER,
    DMZ,
    APPLICATION,
    DATA,
    MANAGEMENT,
    INTERNET
};

enum class Protocol {
    TCP,
    UDP
};

enum class Action {
    ALLOW,
    DENY
};

enum class TrafficClass {
    NORTH_SOUTH,
    EAST_WEST,
    INTRA_SEGMENT
};

std::string toString(Zone zone) {
    switch (zone) {
        case Zone::USER: return "USER";
        case Zone::DMZ: return "DMZ";
        case Zone::APPLICATION: return "APPLICATION";
        case Zone::DATA: return "DATA";
        case Zone::MANAGEMENT: return "MANAGEMENT";
        case Zone::INTERNET: return "INTERNET";
    }

    throw std::logic_error("Unknown trust zone.");
}

std::string toString(Protocol protocol) {
    switch (protocol) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
    }

    throw std::logic_error("Unknown protocol.");
}

std::string toString(Action action) {
    return action == Action::ALLOW ? "ALLOW" : "DENY";
}

std::string toString(TrafficClass trafficClass) {
    switch (trafficClass) {
        case TrafficClass::NORTH_SOUTH: return "NORTH_SOUTH";
        case TrafficClass::EAST_WEST: return "EAST_WEST";
        case TrafficClass::INTRA_SEGMENT: return "INTRA_SEGMENT";
    }

    throw std::logic_error("Unknown traffic class.");
}

void validatePortRange(int first, int last) {
    if (first < 1 || last > 65535 || first > last) {
        throw std::invalid_argument("Invalid TCP/UDP port range.");
    }
}

std::uint32_t parseIPv4(const std::string& address) {
    std::uint32_t result = 0;
    std::size_t start = 0;

    for (int index = 0; index < 4; ++index) {
        const std::size_t end = address.find('.', start);

        const std::string part =
            address.substr(
                start,
                end == std::string::npos ? end : end - start
            );

        if (
            part.empty() ||
            !std::all_of(
                part.begin(),
                part.end(),
                [](unsigned char character) {
                    return character >= '0' && character <= '9';
                }
            )
        ) {
            throw std::invalid_argument("Invalid IPv4 address.");
        }

        const unsigned long octet = std::stoul(part);

        if (octet > 255) {
            throw std::invalid_argument("IPv4 octet exceeds 255.");
        }

        result = (result << 8U) | static_cast<std::uint32_t>(octet);

        if (index < 3) {
            if (end == std::string::npos) {
                throw std::invalid_argument("IPv4 requires four octets.");
            }

            start = end + 1;
        } else if (end != std::string::npos) {
            throw std::invalid_argument("IPv4 contains too many octets.");
        }
    }

    return result;
}

struct IPv4Range {
    std::uint32_t first;
    std::uint32_t last;
    int prefix;

    static IPv4Range parse(const std::string& cidr) {
        const std::size_t slash = cidr.find('/');

        if (slash == std::string::npos) {
            throw std::invalid_argument("CIDR prefix is required.");
        }

        const std::uint32_t address =
            parseIPv4(cidr.substr(0, slash));

        const std::string prefixText = cidr.substr(slash + 1);

        if (
            prefixText.empty() ||
            !std::all_of(
                prefixText.begin(),
                prefixText.end(),
                [](unsigned char character) {
                    return character >= '0' && character <= '9';
                }
            )
        ) {
            throw std::invalid_argument("Invalid CIDR prefix.");
        }

        const int prefix = std::stoi(prefixText);

        if (prefix < 0 || prefix > 32) {
            throw std::invalid_argument("CIDR prefix must be 0-32.");
        }

        const std::uint32_t mask =
            prefix == 0
                ? 0U
                : (0xFFFFFFFFU << (32 - prefix));

        const std::uint32_t first = address & mask;
        const std::uint32_t last = first | (~mask);

        if (first != address) {
            throw std::invalid_argument(
                "CIDR address contains host bits."
            );
        }

        return {first, last, prefix};
    }

    bool contains(std::uint32_t address) const {
        return address >= first && address <= last;
    }

    bool overlaps(const IPv4Range& other) const {
        return first <= other.last && other.first <= last;
    }
};

struct Segment {
    std::string id;
    std::string name;
    int vlanId;
    IPv4Range network;
    Zone zone;
};

struct Endpoint {
    std::string id;
    std::string segmentId;
    std::uint32_t address;
    std::unordered_map<std::string, std::string> labels;
};

class NetworkInventory {
private:
    std::unordered_map<std::string, Segment> segments_;
    std::unordered_map<std::string, Endpoint> endpoints_;
    std::unordered_set<int> vlanIds_;
    std::unordered_set<std::uint32_t> addresses_;

public:
    void addSegment(const Segment& segment) {
        if (segment.id.empty() || segment.name.empty()) {
            throw std::invalid_argument("Segment identity is required.");
        }

        if (segment.vlanId < 1 || segment.vlanId > 4094) {
            throw std::invalid_argument("VLAN ID must be 1-4094.");
        }

        if (segments_.count(segment.id) || vlanIds_.count(segment.vlanId)) {
            throw std::invalid_argument("Duplicate segment or VLAN.");
        }

        for (const auto& entry : segments_) {
            if (segment.network.overlaps(entry.second.network)) {
                throw std::invalid_argument(
                    "Overlapping network ranges are not permitted."
                );
            }
        }

        segments_.emplace(segment.id, segment);
        vlanIds_.insert(segment.vlanId);
    }

    void addEndpoint(const Endpoint& endpoint) {
        if (endpoint.id.empty()) {
            throw std::invalid_argument("Endpoint ID is required.");
        }

        if (endpoints_.count(endpoint.id)) {
            throw std::invalid_argument("Duplicate endpoint ID.");
        }

        if (endpoint.labels.find("role") == endpoint.labels.end()) {
            throw std::invalid_argument("Endpoint role is required.");
        }

        const Segment& parent = segment(endpoint.segmentId);

        if (!parent.network.contains(endpoint.address)) {
            throw std::invalid_argument(
                "Endpoint address is outside its assigned subnet."
            );
        }

        if (addresses_.count(endpoint.address)) {
            throw std::invalid_argument("Duplicate endpoint IP address.");
        }

        endpoints_.emplace(endpoint.id, endpoint);
        addresses_.insert(endpoint.address);
    }

    const Segment& segment(const std::string& id) const {
        const auto found = segments_.find(id);

        if (found == segments_.end()) {
            throw std::invalid_argument("Unknown segment: " + id);
        }

        return found->second;
    }

    const Endpoint& endpoint(const std::string& id) const {
        const auto found = endpoints_.find(id);

        if (found == endpoints_.end()) {
            throw std::invalid_argument("Unknown endpoint: " + id);
        }

        return found->second;
    }

    std::size_t segmentCount() const {
        return segments_.size();
    }

    std::size_t endpointCount() const {
        return endpoints_.size();
    }
};

struct NetworkRule {
    std::string id;
    int priority;
    Zone sourceZone;
    Zone destinationZone;
    Protocol protocol;
    int portFrom;
    int portTo;
    Action action;
};

struct MicroRule {
    std::string id;
    int priority;
    std::string sourceRole;
    std::string destinationRole;
    Protocol protocol;
    int portFrom;
    int portTo;
    Action action;
};

struct TrafficFlow {
    std::string id;
    std::string sourceId;
    std::string destinationId;
    Protocol protocol;
    int destinationPort;
};

struct Decision {
    std::string flowId;
    bool allowed;
    TrafficClass trafficClass;
    std::string networkResult;
    std::string microResult;
    std::string reason;
};

class SegmentationEngine {
private:
    const NetworkInventory& inventory_;

    std::vector<NetworkRule> networkRules_;
    std::vector<MicroRule> microRules_;

    std::unordered_set<std::string> seenFlowIds_;
    std::vector<Decision> auditLog_;

    static std::string roleOf(const Endpoint& endpoint) {
        return endpoint.labels.at("role");
    }

    std::optional<Action> findNetworkAction(
        Zone source,
        Zone destination,
        const TrafficFlow& flow
    ) const {
        for (const NetworkRule& rule : networkRules_) {
            if (
                rule.sourceZone == source &&
                rule.destinationZone == destination &&
                rule.protocol == flow.protocol &&
                flow.destinationPort >= rule.portFrom &&
                flow.destinationPort <= rule.portTo
            ) {
                return rule.action;
            }
        }

        return std::nullopt;
    }

    std::optional<Action> findMicroAction(
        const Endpoint& source,
        const Endpoint& destination,
        const TrafficFlow& flow
    ) const {
        const std::string sourceRole = roleOf(source);
        const std::string destinationRole = roleOf(destination);

        for (const MicroRule& rule : microRules_) {
            const bool sourceMatches =
                rule.sourceRole == "*" ||
                rule.sourceRole == sourceRole;

            const bool destinationMatches =
                rule.destinationRole == "*" ||
                rule.destinationRole == destinationRole;

            if (
                sourceMatches &&
                destinationMatches &&
                rule.protocol == flow.protocol &&
                flow.destinationPort >= rule.portFrom &&
                flow.destinationPort <= rule.portTo
            ) {
                return rule.action;
            }
        }

        return std::nullopt;
    }

    template <typename Rule>
    static void validateAndSortRules(
        std::vector<Rule>& rules,
        const std::string& category
    ) {
        std::unordered_set<std::string> identifiers;

        for (const Rule& rule : rules) {
            if (rule.id.empty() || rule.priority < 0) {
                throw std::invalid_argument(
                    "Invalid " + category + " rule metadata."
                );
            }

            validatePortRange(rule.portFrom, rule.portTo);

            if (!identifiers.insert(rule.id).second) {
                throw std::invalid_argument(
                    "Duplicate " + category + " rule ID."
                );
            }
        }

        std::sort(
            rules.begin(),
            rules.end(),
            [](const Rule& left, const Rule& right) {
                if (left.priority != right.priority) {
                    return left.priority < right.priority;
                }

                return left.id < right.id;
            }
        );
    }

public:
    SegmentationEngine(
        const NetworkInventory& inventory,
        std::vector<NetworkRule> networkRules,
        std::vector<MicroRule> microRules
    )
        : inventory_(inventory),
          networkRules_(std::move(networkRules)),
          microRules_(std::move(microRules)) {
        validateAndSortRules(networkRules_, "network");
        validateAndSortRules(microRules_, "microsegmentation");
    }

    Decision evaluate(const TrafficFlow& flow) {
        if (flow.id.empty()) {
            throw std::invalid_argument("Flow ID is required.");
        }

        validatePortRange(flow.destinationPort, flow.destinationPort);

        if (seenFlowIds_.count(flow.id)) {
            throw std::invalid_argument("Duplicate flow ID.");
        }

        const Endpoint& source = inventory_.endpoint(flow.sourceId);
        const Endpoint& destination =
            inventory_.endpoint(flow.destinationId);

        const Segment& sourceSegment =
            inventory_.segment(source.segmentId);

        const Segment& destinationSegment =
            inventory_.segment(destination.segmentId);

        seenFlowIds_.insert(flow.id);

        const bool sameSegment =
            source.segmentId == destination.segmentId;

        TrafficClass trafficClass;

        if (
            sourceSegment.zone == Zone::INTERNET ||
            destinationSegment.zone == Zone::INTERNET
        ) {
            trafficClass = TrafficClass::NORTH_SOUTH;
        } else if (sameSegment) {
            trafficClass = TrafficClass::INTRA_SEGMENT;
        } else {
            trafficClass = TrafficClass::EAST_WEST;
        }

        Action networkAction = Action::ALLOW;
        std::string networkResult = "NOT_REQUIRED";

        if (!sameSegment) {
            const auto matched = findNetworkAction(
                sourceSegment.zone,
                destinationSegment.zone,
                flow
            );

            networkAction = matched.value_or(Action::DENY);
            networkResult = toString(networkAction);
        }

        const auto microMatch = findMicroAction(
            source,
            destination,
            flow
        );

        const Action microAction =
            microMatch.value_or(Action::DENY);

        const std::string microResult = toString(microAction);

        const bool allowed =
            networkAction == Action::ALLOW &&
            microAction == Action::ALLOW;

        std::string reason;

        if (networkAction == Action::DENY) {
            reason = "NETWORK_BOUNDARY_DENY";
        } else if (microAction == Action::DENY) {
            reason = "MICROSEGMENTATION_DEFAULT_DENY";
        } else {
            reason = "BOTH_POLICY_LAYERS_ALLOW";
        }

        Decision decision{
            flow.id,
            allowed,
            trafficClass,
            networkResult,
            microResult,
            reason
        };

        auditLog_.push_back(decision);
        return decision;
    }

    const std::vector<Decision>& auditLog() const {
        return auditLog_;
    }
};

NetworkInventory buildInventory() {
    NetworkInventory inventory;

    inventory.addSegment({
        "users", "User VLAN", 10,
        IPv4Range::parse("10.10.0.0/24"),
        Zone::USER
    });

    inventory.addSegment({
        "dmz", "DMZ", 20,
        IPv4Range::parse("10.20.0.0/24"),
        Zone::DMZ
    });

    inventory.addSegment({
        "apps", "Application VLAN", 30,
        IPv4Range::parse("10.30.0.0/24"),
        Zone::APPLICATION
    });

    inventory.addSegment({
        "data", "Database VLAN", 40,
        IPv4Range::parse("10.40.0.0/24"),
        Zone::DATA
    });

    inventory.addSegment({
        "management", "Management VLAN", 50,
        IPv4Range::parse("10.50.0.0/24"),
        Zone::MANAGEMENT
    });

    inventory.addSegment({
        "internet", "External Test VLAN", 900,
        IPv4Range::parse("198.51.100.0/24"),
        Zone::INTERNET
    });

    inventory.addEndpoint({
        "workstation-01",
        "users",
        parseIPv4("10.10.0.10"),
        {{"role", "employee"}}
    });

    inventory.addEndpoint({
        "web-01",
        "dmz",
        parseIPv4("10.20.0.10"),
        {{"role", "web"}}
    });

    inventory.addEndpoint({
        "api-01",
        "apps",
        parseIPv4("10.30.0.10"),
        {{"role", "api"}}
    });

    inventory.addEndpoint({
        "api-02",
        "apps",
        parseIPv4("10.30.0.11"),
        {{"role", "api"}}
    });

    inventory.addEndpoint({
        "db-01",
        "data",
        parseIPv4("10.40.0.10"),
        {{"role", "database"}}
    });

    inventory.addEndpoint({
        "admin-01",
        "management",
        parseIPv4("10.50.0.10"),
        {{"role", "administrator"}}
    });

    inventory.addEndpoint({
        "external-client",
        "internet",
        parseIPv4("198.51.100.10"),
        {{"role", "internet-client"}}
    });

    return inventory;
}

SegmentationEngine buildEngine(const NetworkInventory& inventory) {
    std::vector<NetworkRule> networkRules = {
        {
            "NET-001", 10, Zone::INTERNET, Zone::DMZ,
            Protocol::TCP, 443, 443, Action::ALLOW
        },
        {
            "NET-002", 20, Zone::USER, Zone::DMZ,
            Protocol::TCP, 443, 443, Action::ALLOW
        },
        {
            "NET-003", 30, Zone::DMZ, Zone::APPLICATION,
            Protocol::TCP, 8443, 8443, Action::ALLOW
        },
        {
            "NET-004", 40, Zone::APPLICATION, Zone::DATA,
            Protocol::TCP, 5432, 5432, Action::ALLOW
        },
        {
            "NET-005", 50, Zone::MANAGEMENT, Zone::APPLICATION,
            Protocol::TCP, 22, 22, Action::ALLOW
        }
    };

    std::vector<MicroRule> microRules = {
        {
            "MICRO-001", 10, "internet-client", "web",
            Protocol::TCP, 443, 443, Action::ALLOW
        },
        {
            "MICRO-002", 20, "employee", "web",
            Protocol::TCP, 443, 443, Action::ALLOW
        },
        {
            "MICRO-003", 30, "web", "api",
            Protocol::TCP, 8443, 8443, Action::ALLOW
        },
        {
            "MICRO-004", 40, "api", "database",
            Protocol::TCP, 5432, 5432, Action::ALLOW
        },
        {
            "MICRO-005", 50, "administrator", "api",
            Protocol::TCP, 22, 22, Action::ALLOW
        }
    };

    return SegmentationEngine(
        inventory,
        std::move(networkRules),
        std::move(microRules)
    );
}

int main() {
    try {
        NetworkInventory inventory = buildInventory();

        SegmentationEngine engine = buildEngine(inventory);

        const std::vector<TrafficFlow> flows = {
            {
                "FLOW-001", "external-client", "web-01",
                Protocol::TCP, 443
            },
            {
                "FLOW-002", "workstation-01", "web-01",
                Protocol::TCP, 443
            },
            {
                "FLOW-003", "web-01", "api-01",
                Protocol::TCP, 8443
            },
            {
                "FLOW-004", "api-01", "db-01",
                Protocol::TCP, 5432
            },
            {
                "FLOW-005", "web-01", "db-01",
                Protocol::TCP, 5432
            },
            {
                "FLOW-006", "api-01", "api-02",
                Protocol::TCP, 8080
            },
            {
                "FLOW-007", "admin-01", "api-01",
                Protocol::TCP, 22
            }
        };

        std::cout << "NETWORK SEGMENTATION GOVERNANCE\n";
        std::cout << "Segments: " << inventory.segmentCount() << '\n';
        std::cout << "Endpoints: " << inventory.endpointCount() << "\n\n";

        int allowed = 0;
        int denied = 0;

        for (const TrafficFlow& flow : flows) {
            const Decision result = engine.evaluate(flow);

            if (result.allowed) {
                ++allowed;
            } else {
                ++denied;
            }

            std::cout
                << result.flowId
                << " | "
                << toString(result.trafficClass)
                << " | "
                << (result.allowed ? "ALLOW" : "DENY")
                << " | Network="
                << result.networkResult
                << " | Micro="
                << result.microResult
                << " | "
                << result.reason
                << '\n';
        }

        if (engine.auditLog().size() != flows.size()) {
            throw std::runtime_error("Audit record count mismatch.");
        }

        if (allowed != 5 || denied != 2) {
            throw std::runtime_error("Unexpected policy evaluation result.");
        }

        std::cout << "\nTRAFFIC STATISTICS\n";
        std::cout << "Evaluated: " << flows.size() << '\n';
        std::cout << "Allowed:   " << allowed << '\n';
        std::cout << "Denied:    " << denied << '\n';

        // Invalid subnet configurations must be rejected before deployment.
        bool overlapRejected = false;

        try {
            NetworkInventory validationInventory;

            validationInventory.addSegment({
                "first", "First", 100,
                IPv4Range::parse("172.16.0.0/24"),
                Zone::USER
            });

            validationInventory.addSegment({
                "second", "Second", 101,
                IPv4Range::parse("172.16.0.128/25"),
                Zone::DATA
            });
        } catch (const std::invalid_argument&) {
            overlapRejected = true;
        }

        if (!overlapRejected) {
            throw std::runtime_error("Overlapping subnet was accepted.");
        }

        std::cout << "Subnet validation: PASSED\n";

    } catch (const std::exception& error) {
        std::cerr << "Execution failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
