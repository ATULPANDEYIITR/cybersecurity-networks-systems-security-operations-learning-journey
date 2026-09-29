/*
 * Network Troubleshooting Case Study
 *
 * Scenario:
 *   A company operates an internal API accessed through a VPN. Users report
 *   that some applications work normally while larger API responses sometimes
 *   stall. At other times, users report DNS failures and high latency.
 *
 * The program builds an industry-style diagnostic model containing:
 *   - IPv4 addressing and CIDR
 *   - routing and longest-prefix matching
 *   - DNS observations
 *   - TCP service observations
 *   - latency, jitter, and packet-loss measurements
 *   - MTU/MSS calculations
 *   - symptom classification
 *   - diagnostic evidence and confidence
 *   - structured reporting
 *   - configuration validation
 *
 * Standard: C++17
 *
 * This program is an educational diagnostic model. It does not generate
 * flooding traffic, perform unauthorized scanning, or exploit systems.
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace std;

// -----------------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------------

void section(const string& title) {
    cout << "\n" << string(78, '=') << "\n";
    cout << title << "\n";
    cout << string(78, '=') << "\n";
}

string formatDouble(double value, int precision = 2) {
    ostringstream output;
    output << fixed << setprecision(precision) << value;
    return output.str();
}

// -----------------------------------------------------------------------------
// IPv4 representation
// -----------------------------------------------------------------------------

class IPv4Address {
public:
    IPv4Address() : value_(0) {}

    explicit IPv4Address(const string& address) {
        value_ = parse(address);
    }

    explicit IPv4Address(uint32_t value)
        : value_(value) {}

    uint32_t value() const {
        return value_;
    }

    string toString() const {
        ostringstream output;

        output
            << ((value_ >> 24) & 0xff) << "."
            << ((value_ >> 16) & 0xff) << "."
            << ((value_ >> 8) & 0xff) << "."
            << (value_ & 0xff);

        return output.str();
    }

    bool operator==(const IPv4Address& other) const {
        return value_ == other.value_;
    }

private:
    uint32_t value_;

    static uint32_t parse(const string& address) {
        vector<int> octets;
        string current;

        for (size_t i = 0; i <= address.size(); ++i) {
            if (i == address.size() || address[i] == '.') {
                if (current.empty()) {
                    throw invalid_argument(
                        "Invalid IPv4 address: " + address
                    );
                }

                int number = stoi(current);

                if (number < 0 || number > 255) {
                    throw invalid_argument(
                        "IPv4 octet outside 0-255: " + address
                    );
                }

                octets.push_back(number);
                current.clear();
            } else {
                if (!isdigit(static_cast<unsigned char>(address[i]))) {
                    throw invalid_argument(
                        "Invalid character in IPv4 address: " + address
                    );
                }

                current += address[i];
            }
        }

        if (octets.size() != 4) {
            throw invalid_argument(
                "IPv4 address must contain four octets: " + address
            );
        }

        return
            (static_cast<uint32_t>(octets[0]) << 24) |
            (static_cast<uint32_t>(octets[1]) << 16) |
            (static_cast<uint32_t>(octets[2]) << 8) |
            static_cast<uint32_t>(octets[3]);
    }
};

// -----------------------------------------------------------------------------
// CIDR network
// -----------------------------------------------------------------------------

class IPv4Network {
public:
    IPv4Network(const string& address, int prefixLength)
        : prefixLength_(prefixLength) {

        if (prefixLength < 0 || prefixLength > 32) {
            throw invalid_argument("CIDR prefix must be between 0 and 32.");
        }

        address_ = IPv4Address(address);
        mask_ = createMask(prefixLength);
        network_ = IPv4Address(address_.value() & mask_);
    }

    bool contains(const IPv4Address& address) const {
        return (address.value() & mask_) == network_.value();
    }

    int prefixLength() const {
        return prefixLength_;
    }

    string toString() const {
        return network_.toString() + "/" +
               to_string(prefixLength_);
    }

private:
    IPv4Address address_;
    IPv4Address network_;
    uint32_t mask_;
    int prefixLength_;

    static uint32_t createMask(int prefixLength) {
        if (prefixLength == 0) {
            return 0;
        }

        return 0xffffffffu << (32 - prefixLength);
    }
};

// -----------------------------------------------------------------------------
// Routing
// -----------------------------------------------------------------------------

struct Route {
    IPv4Network destination;
    optional<IPv4Address> gateway;
    string interfaceName;
    int metric;
};

class RoutingTable {
public:
    void addRoute(Route route) {
        routes_.push_back(move(route));
    }

    optional<Route> lookup(const IPv4Address& destination) const {
        vector<const Route*> matches;

        for (const auto& route : routes_) {
            if (route.destination.contains(destination)) {
                matches.push_back(&route);
            }
        }

        if (matches.empty()) {
            return nullopt;
        }

        // Longest-prefix match is the central IP forwarding principle.
        // For equal prefixes this model uses the lowest metric.
        const Route* selected = *min_element(
            matches.begin(),
            matches.end(),
            [](const Route* a, const Route* b) {
                if (
                    a->destination.prefixLength() !=
                    b->destination.prefixLength()
                ) {
                    return
                        a->destination.prefixLength() >
                        b->destination.prefixLength();
                }

                return a->metric < b->metric;
            }
        );

        return *selected;
    }

private:
    vector<Route> routes_;
};

void demonstrateRouting() {
    section("1. ROUTING AND LONGEST-PREFIX MATCH");

    RoutingTable table;

    table.addRoute({
        IPv4Network("0.0.0.0", 0),
        IPv4Address("192.168.1.1"),
        "eth0",
        100
    });

    table.addRoute({
        IPv4Network("10.0.0.0", 8),
        IPv4Address("192.168.1.254"),
        "eth0",
        50
    });

    table.addRoute({
        IPv4Network("10.20.0.0", 16),
        IPv4Address("10.20.0.1"),
        "vpn0",
        20
    });

    table.addRoute({
        IPv4Network("10.20.30.0", 24),
        nullopt,
        "vpn0",
        10
    });

    const vector<string> destinations = {
        "8.8.8.8",
        "10.5.6.7",
        "10.20.40.10",
        "10.20.30.15"
    };

    for (const auto& destinationText : destinations) {
        IPv4Address destination(destinationText);
        auto route = table.lookup(destination);

        cout << left << setw(18)
             << destination.toString();

        if (!route) {
            cout << " -> NO ROUTE\n";
            continue;
        }

        cout << " -> "
             << route->destination.toString()
             << " via ";

        if (route->gateway) {
            cout << route->gateway->toString();
        } else {
            cout << "direct";
        }

        cout << " on " << route->interfaceName
             << " metric " << route->metric
             << "\n";
    }

    cout << R"(
A routing failure can be caused by:
- no matching route
- incorrect default gateway
- incorrect prefix
- stale or missing dynamic route
- policy routing
- VPN route precedence
- asymmetric routing
- firewall or forwarding policy

An application timeout does not by itself prove a routing failure.
)";
}

// -----------------------------------------------------------------------------
// DNS model
// -----------------------------------------------------------------------------

enum class DnsStatus {
    Success,
    NxDomain,
    ServFail,
    Timeout,
    ConfigurationError
};

string dnsStatusToString(DnsStatus status) {
    switch (status) {
        case DnsStatus::Success:
            return "SUCCESS";
        case DnsStatus::NxDomain:
            return "NXDOMAIN";
        case DnsStatus::ServFail:
            return "SERVFAIL";
        case DnsStatus::Timeout:
            return "TIMEOUT";
        case DnsStatus::ConfigurationError:
            return "CONFIGURATION_ERROR";
    }

    return "UNKNOWN";
}

struct DnsObservation {
    string hostname;
    DnsStatus status;
    vector<IPv4Address> addresses;
    string resolver;
    string detail;
};

DnsObservation simulateDns(
    const string& hostname,
    bool resolverReachable,
    bool recordExists
) {
    if (!resolverReachable) {
        return {
            hostname,
            DnsStatus::Timeout,
            {},
            "10.10.0.53",
            "Resolver did not respond within the diagnostic interval."
        };
    }

    if (!recordExists) {
        return {
            hostname,
            DnsStatus::NxDomain,
            {},
            "10.10.0.53",
            "The resolver reports that the name does not exist."
        };
    }

    return {
        hostname,
        DnsStatus::Success,
        {
            IPv4Address("10.20.30.50")
        },
        "10.10.0.53",
        "Authoritative or cached address returned."
    };
}

void demonstrateDns() {
    section("2. DNS OBSERVATIONS");

    vector<DnsObservation> observations = {
        simulateDns("api.example.internal", true, true),
        simulateDns("missing.example.internal", true, false),
        simulateDns("resolver-failure.example.internal", false, true)
    };

    for (const auto& observation : observations) {
        cout << observation.hostname
             << " -> "
             << dnsStatusToString(observation.status)
             << " via "
             << observation.resolver
             << "\n";

        cout << "  " << observation.detail << "\n";
    }

    cout << R"(
DNS troubleshooting should separate different failure modes.

NXDOMAIN:
    The resolver reports that the name does not exist.

SERVFAIL:
    The resolver could not provide a valid answer.

Timeout:
    The DNS query or resolver path did not produce a response.

A successful DNS response does not establish that the resulting IP address is
reachable or that the requested application service is healthy.
)";
}

// -----------------------------------------------------------------------------
// TCP observations
// -----------------------------------------------------------------------------

struct TcpObservation {
    IPv4Address destination;
    uint16_t port;
    bool connected;
    double elapsedMs;
    string error;
};

TcpObservation simulateTcp(
    const IPv4Address& destination,
    uint16_t port,
    bool connected,
    double elapsedMs,
    const string& error = ""
) {
    return {
        destination,
        port,
        connected,
        elapsedMs,
        error
    };
}

void demonstrateTcp() {
    section("3. TCP CONNECTIVITY");

    vector<TcpObservation> tests = {
        simulateTcp(
            IPv4Address("10.20.30.50"),
            443,
            true,
            31.4
        ),
        simulateTcp(
            IPv4Address("10.20.30.60"),
            443,
            false,
            3000.0,
            "TIMEOUT"
        ),
        simulateTcp(
            IPv4Address("10.20.30.70"),
            443,
            false,
            4.1,
            "CONNECTION_REFUSED"
        )
    };

    for (const auto& test : tests) {
        cout << test.destination.toString()
             << ": TCP/" << test.port
             << " -> "
             << (test.connected ? "CONNECTED" : "FAILED")
             << ", "
             << formatDouble(test.elapsedMs)
             << " ms";

        if (!test.error.empty()) {
            cout << ", error=" << test.error;
        }

        cout << "\n";
    }

    cout << R"(
Important distinctions:

CONNECTION_REFUSED:
    The destination or an intermediate device actively rejected the attempt.

TIMEOUT:
    The expected connection event did not occur within the timeout.

NO ROUTE:
    The local or intermediate system reports that no path exists.

A TCP handshake can succeed while TLS, HTTP, authentication, or application
processing subsequently fails.
)";
}

// -----------------------------------------------------------------------------
// Latency, loss, and jitter
// -----------------------------------------------------------------------------

struct LatencyStatistics {
    size_t sent = 0;
    size_t received = 0;
    double lossPercent = 0.0;
    double minMs = 0.0;
    double averageMs = 0.0;
    double maxMs = 0.0;
    double jitterMs = 0.0;
};

LatencyStatistics calculateLatency(
    const vector<optional<double>>& samples
) {
    LatencyStatistics statistics;
    statistics.sent = samples.size();

    vector<double> successful;

    for (const auto& sample : samples) {
        if (sample) {
            successful.push_back(*sample);
        }
    }

    statistics.received = successful.size();

    if (statistics.sent > 0) {
        statistics.lossPercent =
            100.0 *
            static_cast<double>(
                statistics.sent - statistics.received
            ) /
            static_cast<double>(statistics.sent);
    }

    if (successful.empty()) {
        return statistics;
    }

    auto [minimum, maximum] =
        minmax_element(successful.begin(), successful.end());

    statistics.minMs = *minimum;
    statistics.maxMs = *maximum;

    statistics.averageMs =
        accumulate(
            successful.begin(),
            successful.end(),
            0.0
        ) /
        successful.size();

    if (successful.size() > 1) {
        double totalDifference = 0.0;

        for (size_t i = 1; i < successful.size(); ++i) {
            totalDifference +=
                abs(successful[i] - successful[i - 1]);
        }

        statistics.jitterMs =
            totalDifference /
            static_cast<double>(successful.size() - 1);
    }

    return statistics;
}

void printLatencyStatistics(
    const LatencyStatistics& statistics
) {
    cout << "Sent:          " << statistics.sent << "\n";
    cout << "Received:      " << statistics.received << "\n";
    cout << "Packet loss:   "
         << formatDouble(statistics.lossPercent)
         << "%\n";

    if (statistics.received > 0) {
        cout << "Minimum:       "
             << formatDouble(statistics.minMs)
             << " ms\n";

        cout << "Average:       "
             << formatDouble(statistics.averageMs)
             << " ms\n";

        cout << "Maximum:       "
             << formatDouble(statistics.maxMs)
             << " ms\n";

        cout << "Jitter:        "
             << formatDouble(statistics.jitterMs)
             << " ms\n";
    }
}

void demonstrateLatency() {
    section("4. LATENCY, PACKET LOSS, AND JITTER");

    vector<optional<double>> observations = {
        29.8,
        31.2,
        nullopt,
        30.4,
        31.0,
        45.7,
        30.8,
        nullopt,
        32.0,
        31.4
    };

    for (size_t i = 0; i < observations.size(); ++i) {
        cout << "Probe " << i + 1 << ": ";

        if (observations[i]) {
            cout << formatDouble(*observations[i])
                 << " ms\n";
        } else {
            cout << "NO RESPONSE\n";
        }
    }

    cout << "\nStatistics:\n";
    printLatencyStatistics(
        calculateLatency(observations)
    );

    cout << R"(
Latency:
    time required for a response.

Packet loss:
    percentage of probes that produced no expected response.

Jitter:
    variation in observed delay.

These metrics should be measured over enough observations to distinguish normal
variation from a persistent condition.
)";
}

// -----------------------------------------------------------------------------
// MTU
// -----------------------------------------------------------------------------

struct MtuAnalysis {
    int mtu;
    int ipHeader;
    int transportHeader;
    int maximumIpPayload;
    int approximateMss;
};

MtuAnalysis calculateMtu(
    int mtu,
    int ipVersion,
    bool tcp
) {
    if (mtu <= 0) {
        throw invalid_argument("MTU must be positive.");
    }

    const int ipHeader =
        ipVersion == 4 ? 20 :
        ipVersion == 6 ? 40 :
        throw invalid_argument("Only IPv4 and IPv6 are modeled.");

    const int transportHeader =
        tcp ? 20 : 8;

    if (mtu <= ipHeader + transportHeader) {
        throw invalid_argument(
            "MTU is too small for the selected headers."
        );
    }

    return {
        mtu,
        ipHeader,
        transportHeader,
        mtu - ipHeader,
        mtu - ipHeader - transportHeader
    };
}

void demonstrateMtu() {
    section("5. MTU, MSS, AND PATH MTU");

    for (int mtu : {1280, 1400, 1500, 9000}) {
        auto result = calculateMtu(mtu, 4, true);

        cout << "MTU " << result.mtu
             << " -> IPv4 payload "
             << result.maximumIpPayload
             << " bytes, approximate TCP MSS "
             << result.approximateMss
             << " bytes\n";
    }

    cout << R"(
MTU problems are particularly important with tunnels and VPNs because
encapsulation consumes additional bytes.

A path with a lower effective MTU can cause:
- fragmentation
- packet drops when fragmentation is prohibited
- PMTUD failures
- TCP black-hole behavior
- application-specific stalls

PMTUD depends on control information being delivered correctly. Filtering
required ICMP messages can interfere with path-MTU discovery.
)";
}

// -----------------------------------------------------------------------------
// Configuration validation
// -----------------------------------------------------------------------------

struct NetworkConfiguration {
    IPv4Address address;
    int prefixLength;
    IPv4Address gateway;
    vector<IPv4Address> dnsServers;
};

vector<string> validateConfiguration(
    const NetworkConfiguration& configuration
) {
    vector<string> errors;

    if (configuration.prefixLength < 0 ||
        configuration.prefixLength > 32) {
        errors.push_back(
            "Prefix length must be between 0 and 32."
        );
    }

    if (configuration.dnsServers.empty()) {
        errors.push_back(
            "At least one DNS server should be configured."
        );
    }

    // For this educational model, the gateway is expected to be on the same
    // subnet. Production networks can have more complex designs.
    try {
        IPv4Network network(
            configuration.address.toString(),
            configuration.prefixLength
        );

        if (!network.contains(configuration.gateway)) {
            errors.push_back(
                "Gateway is outside the configured local subnet."
            );
        }
    } catch (const exception& error) {
        errors.push_back(
            string("Network validation failed: ") +
            error.what()
        );
    }

    return errors;
}

void demonstrateConfigurationValidation() {
    section("6. CONFIGURATION VALIDATION");

    NetworkConfiguration valid {
        IPv4Address("192.168.10.20"),
        24,
        IPv4Address("192.168.10.1"),
        {
            IPv4Address("1.1.1.1"),
            IPv4Address("8.8.8.8")
        }
    };

    NetworkConfiguration invalid {
        IPv4Address("192.168.10.20"),
        24,
        IPv4Address("192.168.20.1"),
        {}
    };

    for (const auto& configuration : {valid, invalid}) {
        const auto errors =
            validateConfiguration(configuration);

        if (errors.empty()) {
            cout << "Configuration: VALID\n";
        } else {
            cout << "Configuration: INVALID\n";

            for (const auto& error : errors) {
                cout << "  ERROR: " << error << "\n";
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Symptom classification
// -----------------------------------------------------------------------------

enum class Layer {
    LocalConfiguration,
    DNS,
    Routing,
    Transport,
    MTU,
    Unknown
};

string layerToString(Layer layer) {
    switch (layer) {
        case Layer::LocalConfiguration:
            return "Local configuration";
        case Layer::DNS:
            return "DNS";
        case Layer::Routing:
            return "Routing";
        case Layer::Transport:
            return "Transport";
        case Layer::MTU:
            return "MTU/path";
        case Layer::Unknown:
            return "Unknown";
    }

    return "Unknown";
}

struct SymptomAnalysis {
    Layer likelyLayer;
    string evidence;
    string nextTest;
};

SymptomAnalysis classifySymptom(const string& symptom) {
    string normalized = symptom;

    transform(
        normalized.begin(),
        normalized.end(),
        normalized.begin(),
        [](unsigned char character) {
            return static_cast<char>(tolower(character));
        }
    );

    if (
        normalized.find("dns") != string::npos ||
        normalized.find("name") != string::npos
    ) {
        return {
            Layer::DNS,
            "The symptom directly implicates name resolution.",
            "Resolve the name and compare the result with direct IP connectivity."
        };
    }

    if (
        normalized.find("mtu") != string::npos ||
        normalized.find("large") != string::npos
    ) {
        return {
            Layer::MTU,
            "The symptom may depend on packet size.",
            "Test smaller packets and inspect PMTUD behavior."
        };
    }

    if (
        normalized.find("route") != string::npos ||
        normalized.find("unreachable") != string::npos
    ) {
        return {
            Layer::Routing,
            "The destination may not have a usable route.",
            "Inspect the routing table and path."
        };
    }

    if (
        normalized.find("packet") != string::npos ||
        normalized.find("loss") != string::npos
    ) {
        return {
            Layer::Transport,
            "Packets are not consistently producing expected responses.",
            "Measure loss at multiple points and compare destinations."
        };
    }

    return {
        Layer::Unknown,
        "The symptom does not isolate a network layer.",
        "Start with local configuration and proceed systematically."
    };
}

void demonstrateSymptomClassification() {
    section("7. SYMPTOM CLASSIFICATION");

    const vector<string> symptoms = {
        "DNS lookup fails",
        "Large API response stalls",
        "Destination is unreachable",
        "Packet loss occurs",
        "Application behavior is unusual"
    };

    for (const auto& symptom : symptoms) {
        const auto analysis = classifySymptom(symptom);

        cout << "\nSymptom: " << symptom << "\n";
        cout << "Likely layer: "
             << layerToString(analysis.likelyLayer)
             << "\n";
        cout << "Evidence: "
             << analysis.evidence
             << "\n";
        cout << "Next test: "
             << analysis.nextTest
             << "\n";
    }
}

// -----------------------------------------------------------------------------
// Simulated multi-hop path
// -----------------------------------------------------------------------------

struct Hop {
    string name;
    double baseLatencyMs;
    double lossProbability;
};

struct HopResult {
    string name;
    LatencyStatistics statistics;
};

vector<HopResult> simulatePath(
    const vector<Hop>& hops,
    size_t packetsPerHop
) {
    mt19937 generator(42);

    vector<HopResult> results;

    for (const auto& hop : hops) {
        bernoulli_distribution lost(
            hop.lossProbability
        );

        uniform_real_distribution<double> jitter(
            -1.0,
            1.0
        );

        vector<optional<double>> observations;

        for (size_t i = 0; i < packetsPerHop; ++i) {
            if (lost(generator)) {
                observations.push_back(nullopt);
            } else {
                observations.push_back(
                    max(
                        0.0,
                        hop.baseLatencyMs + jitter(generator)
                    )
                );
            }
        }

        results.push_back({
            hop.name,
            calculateLatency(observations)
        });
    }

    return results;
}

void demonstratePathSimulation() {
    section("8. MULTI-HOP PATH SIMULATION");

    const vector<Hop> path = {
        {"LAN gateway", 1.0, 0.00},
        {"ISP edge", 8.0, 0.02},
        {"Regional router", 20.0, 0.05},
        {"VPN gateway", 30.0, 0.04},
        {"API server", 35.0, 0.05}
    };

    const auto results =
        simulatePath(path, 20);

    for (const auto& result : results) {
        cout << left
             << setw(20)
             << result.name
             << " loss="
             << setw(6)
             << formatDouble(
                    result.statistics.lossPercent,
                    1
                )
             << "%";

        if (result.statistics.received > 0) {
            cout << " avg="
                 << setw(8)
                 << formatDouble(
                        result.statistics.averageMs
                    )
                 << " ms jitter="
                 << formatDouble(
                        result.statistics.jitterMs
                    )
                 << " ms";
        }

        cout << "\n";
    }

    cout << R"(
Interpretation rule:

An intermediate device may fail to answer diagnostic probes while continuing
to forward application traffic. Therefore, an isolated timeout at one hop is
weak evidence.

A loss pattern that begins at a hop and continues through later observations is
stronger evidence of a downstream path problem, but it still needs correlation
with other tests.
)";
}

// -----------------------------------------------------------------------------
// Case-study engine
// -----------------------------------------------------------------------------

class IncidentAnalyzer {
public:
    void addObservation(string observation) {
        observations_.push_back(move(observation));
    }

    void addFinding(string finding) {
        findings_.push_back(move(finding));
    }

    void printReport() const {
        section("9. INCIDENT ANALYSIS REPORT");

        cout << "OBSERVATIONS\n";

        for (const auto& observation : observations_) {
            cout << "  - " << observation << "\n";
        }

        cout << "\nFINDINGS\n";

        for (const auto& finding : findings_) {
            cout << "  - " << finding << "\n";
        }

        cout << R"(
The report deliberately separates observations from findings.

Observation:
    A directly measured or recorded fact.

Finding:
    An interpretation supported by one or more observations.

Root cause:
    A stronger claim requiring sufficient evidence and elimination of
    plausible alternatives.
)";
    }

private:
    vector<string> observations_;
    vector<string> findings_;
};

void runCaseStudy() {
    section("10. INDUSTRY-STYLE VPN API CASE STUDY");

    cout << R"(
Scenario:

Employees access an internal API through a VPN.

Observed symptoms:
1. DNS sometimes fails.
2. Small API calls work.
3. Large API responses sometimes stall.
4. Some users report high latency.
5. Direct internet browsing remains usable.

Diagnostic objective:
    Determine which layers require investigation without assuming a root cause.
)";

    IncidentAnalyzer analyzer;

    // Stage 1: DNS
    const auto dns =
        simulateDns("api.example.internal", true, true);

    if (dns.status == DnsStatus::Success) {
        analyzer.addObservation(
            "Internal API hostname resolved successfully."
        );
    }

    // Stage 2: routing
    RoutingTable table;

    table.addRoute({
        IPv4Network("0.0.0.0", 0),
        IPv4Address("192.168.1.1"),
        "eth0",
        100
    });

    table.addRoute({
        IPv4Network("10.20.0.0", 16),
        IPv4Address("10.10.0.1"),
        "vpn0",
        10
    });

    IPv4Address apiAddress("10.20.30.50");
    const auto route =
        table.lookup(apiAddress);

    if (route) {
        analyzer.addObservation(
            "Routing table contains a VPN route for the API address."
        );
    } else {
        analyzer.addFinding(
            "No route to the API destination was modeled."
        );
    }

    // Stage 3: TCP
    const auto tcp =
        simulateTcp(
            apiAddress,
            443,
            true,
            32.7
        );

    if (tcp.connected) {
        analyzer.addObservation(
            "TCP/443 connectivity to the API succeeded."
        );
    }

    // Stage 4: latency
    vector<optional<double>> latencySamples = {
        30.2,
        31.0,
        29.8,
        32.1,
        75.4,
        nullopt,
        30.8,
        31.5,
        nullopt,
        34.0
    };

    const auto latency =
        calculateLatency(latencySamples);

    analyzer.addObservation(
        "Latency measurements contain occasional high delay and loss."
    );

    if (latency.lossPercent > 0) {
        analyzer.addFinding(
            "The path exhibits non-zero diagnostic loss in the modeled interval."
        );
    }

    if (latency.jitterMs > 5.0) {
        analyzer.addFinding(
            "Delay variation is significant enough to justify additional path investigation."
        );
    }

    // Stage 5: MTU hypothesis
    const auto mtu =
        calculateMtu(1400, 4, true);

    analyzer.addObservation(
        "The VPN path is modeled with an effective MTU of " +
        to_string(mtu.mtu) +
        " bytes."
    );

    if (mtu.approximateMss < 1460) {
        analyzer.addFinding(
            "The modeled VPN path has a TCP MSS below the common 1500-byte Ethernet baseline."
        );
    }

    analyzer.addFinding(
        "Because small requests succeed while larger responses stall, MTU/PMTUD should be tested."
    );

    analyzer.addFinding(
        "Because DNS is independently reported as intermittent, resolver reachability should be investigated separately from the API path."
    );

    analyzer.printReport();

    cout << R"(
Case-study reasoning:

The available evidence does not justify declaring one root cause automatically.

Instead, the diagnostic plan separates:
- DNS resolver behavior
- VPN route availability
- TCP service connectivity
- packet loss and latency
- packet-size sensitivity
- application behavior

This separation prevents a common troubleshooting mistake: assigning every
symptom to the first suspicious component.
)";
}

// -----------------------------------------------------------------------------
// Edge cases
// -----------------------------------------------------------------------------

void demonstrateEdgeCases() {
    section("11. EDGE CASES AND FAILURE CONDITIONS");

    cout << R"(
Edge case 1: Ping fails but HTTPS succeeds
    ICMP may be filtered. Test the actual application transport.

Edge case 2: DNS fails but direct IP access succeeds
    DNS is a strong candidate for the immediate failure.

Edge case 3: DNS succeeds but TCP fails
    Investigate routing, firewall policy, service state, and address family.

Edge case 4: TCP succeeds but application fails
    Investigate TLS, HTTP, authentication, server processing, and application
    dependencies.

Edge case 5: Traceroute shows '*' at one hop
    The router may rate-limit or filter diagnostic responses.

Edge case 6: Only large packets fail
    Investigate MTU, PMTUD, encapsulation, fragmentation, and ICMP filtering.

Edge case 7: IPv4 works but IPv6 fails
    Compare DNS records, address-family preference, IPv6 routing, and service
    bindings.

Edge case 8: A route exists but traffic still fails
    Routing existence does not prove forwarding, return-path correctness,
    firewall policy, or service availability.

Edge case 9: Intermittent failure
    Capture time windows, repeated observations, interface changes, DHCP
    behavior, DNS server selection, VPN state, and path changes.

Edge case 10: Only one application fails
    Network reachability may already be healthy. Test application-specific
    dependencies before changing network configuration.
)";
}

// -----------------------------------------------------------------------------
// Complexity
// -----------------------------------------------------------------------------

void demonstrateComplexity() {
    section("12. PERFORMANCE AND ALGORITHMIC COMPLEXITY");

    cout << R"(
Longest-prefix routing lookup in this educational vector-based implementation:

    O(R)

where R is the number of routes, because every route can be examined.

Production routing systems use specialized data structures and forwarding
planes to make lookups substantially faster.

Diagnostic measurement:
    O(N)

where N is the number of observations.

Sorting N latency samples:
    O(N log N)

Computing mean and adjacent-sample jitter:
    O(N)

Memory:
    O(N) for storing N measurements.

Practical lesson:
    Measurement volume should be large enough to characterize behavior but
    controlled enough to avoid unnecessary diagnostic load.
)";
}

// -----------------------------------------------------------------------------
// Security
// -----------------------------------------------------------------------------

void demonstrateSecurity() {
    section("13. SECURITY AND OPERATIONAL CONSIDERATIONS");

    cout << R"(
1. Authorization
   Perform diagnostics only against systems and networks you are authorized
   to test.

2. Diagnostic exposure
   Network tests can reveal hostnames, addresses, routing topology, and timing.

3. DNS security
   DNS integrity matters because incorrect name resolution can redirect clients.
   DNSSEC can provide authenticity for signed DNS data.

4. Encryption
   TCP reachability is not equivalent to secure communication. TLS validation
   remains necessary.

5. Logs
   Diagnostic logs can contain IP addresses and internal hostnames. Treat them
   according to organizational security requirements.

6. Rate limits
   Excessive probes can create load and can resemble abusive traffic.

7. Change management
   Do not simultaneously change routes, firewall rules, MTU settings, and DNS
   configuration without recording each change.

8. Evidence
   Preserve timestamps and test conditions so results can be correlated with
   server, firewall, VPN, and application logs.
)";
}

// -----------------------------------------------------------------------------
// Educational comparison
// -----------------------------------------------------------------------------

void languageComparison() {
    section("14. IMPLEMENTATION DESIGN COMPARISON");

    cout << R"(
Python:
    Particularly convenient for diagnostics, automation, data analysis,
    structured reports, and rapid experimentation.

JavaScript/Node.js:
    Particularly useful for asynchronous network operations, service
    diagnostics, event-driven applications, and integration with web tooling.

C++:
    Useful when diagnostics are part of performance-sensitive systems,
    agents, network appliances, monitoring infrastructure, or applications
    requiring precise resource control.

The networking principles remain the same:
    DNS, IP, routing, transport, latency, packet loss, and MTU are protocol
    and systems concepts rather than language-specific concepts.
)";
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

int main() {
    try {
        section("NETWORK TROUBLESHOOTING CASE STUDY");

        cout << R"(
Target scenario:
    Intermittent DNS problems, VPN connectivity, latency, packet loss,
    and possible MTU-related API failures.

Diagnostic philosophy:
    Observe -> isolate -> test -> correlate -> document.

The program models the diagnostic process with standard C++17 facilities.
)";

        demonstrateRouting();
        demonstrateDns();
        demonstrateTcp();
        demonstrateLatency();
        demonstrateMtu();
        demonstrateConfigurationValidation();
        demonstrateSymptomClassification();
        demonstratePathSimulation();
        runCaseStudy();
        demonstrateEdgeCases();
        demonstrateComplexity();
        demonstrateSecurity();
        languageComparison();

        section("15. FINAL DIAGNOSTIC WORKFLOW");

        cout << R"(
1. Define the exact failure.
2. Determine scope: one device, subnet, site, VPN, service, or global.
3. Validate local IP configuration.
4. Test the local gateway.
5. Test DNS independently.
6. Compare hostname and direct-IP behavior.
7. Test the destination transport port.
8. Inspect the route and return path.
9. Measure packet loss, latency, and jitter.
10. Investigate MTU when packet size changes the result.
11. Correlate with firewall, VPN, DNS, server, and application logs.
12. Change one variable at a time.
13. Re-test after every meaningful change.
14. Record evidence and timestamps.

A technically sound diagnosis should explain why the evidence supports the
selected hypothesis and why plausible alternatives have been tested.
)";

        return 0;
    } catch (const exception& error) {
        cerr << "Diagnostic program error: "
             << error.what()
             << "\n";

        return 1;
    }
}
