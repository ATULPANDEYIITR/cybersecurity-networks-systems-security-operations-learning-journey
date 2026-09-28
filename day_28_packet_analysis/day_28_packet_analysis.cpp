#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * Packet Analysis Case Study
 * ==========================
 *
 * Scenario:
 *     A security operations team receives an offline packet dataset from a
 *     controlled lab network. The analyst needs to:
 *
 *       1. validate and normalize packet records,
 *       2. identify protocols,
 *       3. reconstruct TCP conversations,
 *       4. inspect DNS and HTTP metadata,
 *       5. apply filters,
 *       6. detect configured traffic indicators,
 *       7. produce a structured report.
 *
 * This program uses synthetic packet records rather than live packet capture.
 * It therefore demonstrates analysis architecture without requiring raw
 * network privileges or collecting real user traffic.
 *
 * Compile:
 *     g++ -std=c++17 -O2 packet_analysis.cpp -o packet_analysis
 *
 * Run:
 *     ./packet_analysis
 *
 * Complexity:
 *     Basic packet traversal is O(n).
 *     Hash-based indexing is approximately O(n) construction and O(1)
 *     average exact-key lookup.
 *     TCP reconstruction sorts segments and is approximately O(k log k)
 *     for a stream containing k segments.
 */

#include <cctype>


// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

enum class Protocol {
    Unknown,
    TCP,
    UDP,
    DNS,
    HTTP,
    HTTPS,
    SSH,
    SMB,
    ICMP
};

std::string protocolName(Protocol protocol) {
    switch (protocol) {
        case Protocol::TCP:   return "TCP";
        case Protocol::UDP:   return "UDP";
        case Protocol::DNS:   return "DNS";
        case Protocol::HTTP:  return "HTTP";
        case Protocol::HTTPS: return "HTTPS/TLS";
        case Protocol::SSH:   return "SSH";
        case Protocol::SMB:   return "SMB";
        case Protocol::ICMP:  return "ICMP";
        default:              return "UNKNOWN";
    }
}


struct Packet {
    std::size_t number{};
    std::uint64_t timestampMilliseconds{};
    std::string source;
    std::string destination;

    Protocol protocol{Protocol::Unknown};

    std::uint16_t sourcePort{};
    std::uint16_t destinationPort{};

    std::uint32_t sequence{};
    std::set<std::string> flags;

    std::string payload;

    std::size_t capturedLength() const {
        return payload.size();
    }

    bool hasFlag(const std::string& flag) const {
        return flags.find(flag) != flags.end();
    }
};


// ---------------------------------------------------------------------------
// Endpoint and stream keys
// ---------------------------------------------------------------------------

struct Endpoint {
    std::string address;
    std::uint16_t port{};

    bool operator<(const Endpoint& other) const {
        if (address != other.address) {
            return address < other.address;
        }

        return port < other.port;
    }

    bool operator==(const Endpoint& other) const {
        return address == other.address && port == other.port;
    }
};


struct StreamKey {
    Endpoint first;
    Endpoint second;

    static StreamKey fromPacket(const Packet& packet) {
        Endpoint source{packet.source, packet.sourcePort};
        Endpoint destination{packet.destination, packet.destinationPort};

        if (destination < source) {
            std::swap(source, destination);
        }

        return StreamKey{source, destination};
    }

    bool operator<(const StreamKey& other) const {
        if (first.address != other.first.address) {
            return first.address < other.first.address;
        }

        if (first.port != other.first.port) {
            return first.port < other.first.port;
        }

        if (second.address != other.second.address) {
            return second.address < other.second.address;
        }

        return second.port < other.second.port;
    }

    std::string toString() const {
        std::ostringstream output;

        output << first.address << ':' << first.port
               << " <-> "
               << second.address << ':' << second.port;

        return output.str();
    }
};


// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

bool isValidIPv4(const std::string& address) {
    std::istringstream input(address);
    std::string component;
    int count = 0;

    while (std::getline(input, component, '.')) {
        if (component.empty()) {
            return false;
        }

        if (component.size() > 3) {
            return false;
        }

        for (char character : component) {
            if (!std::isdigit(
                    static_cast<unsigned char>(character))) {
                return false;
            }
        }

        int value = std::stoi(component);

        if (value < 0 || value > 255) {
            return false;
        }

        ++count;
    }

    return count == 4;
}


void validatePacket(const Packet& packet) {
    if (!isValidIPv4(packet.source)) {
        throw std::invalid_argument(
            "Invalid source IPv4 address: " + packet.source
        );
    }

    if (!isValidIPv4(packet.destination)) {
        throw std::invalid_argument(
            "Invalid destination IPv4 address: " + packet.destination
        );
    }

    if (packet.protocol == Protocol::TCP ||
        packet.protocol == Protocol::UDP) {

        if (packet.sourcePort == 0 ||
            packet.destinationPort == 0) {
            throw std::invalid_argument(
                "Transport ports must be non-zero."
            );
        }
    }

    // A packet cannot have an arbitrarily large synthetic payload.
    // This protects downstream processing from accidental oversized records.
    constexpr std::size_t maximumStudyPayload = 1024 * 1024;

    if (packet.payload.size() > maximumStudyPayload) {
        throw std::invalid_argument(
            "Packet payload exceeds configured analysis limit."
        );
    }
}


// ---------------------------------------------------------------------------
// Protocol classification
// ---------------------------------------------------------------------------

Protocol classifyApplicationProtocol(const Packet& packet) {
    if (packet.protocol == Protocol::UDP &&
        (packet.sourcePort == 53 || packet.destinationPort == 53)) {
        return Protocol::DNS;
    }

    if (packet.protocol == Protocol::TCP) {
        if (packet.sourcePort == 80 || packet.destinationPort == 80) {
            return Protocol::HTTP;
        }

        if (packet.sourcePort == 443 || packet.destinationPort == 443) {
            return Protocol::HTTPS;
        }

        if (packet.sourcePort == 22 || packet.destinationPort == 22) {
            return Protocol::SSH;
        }

        if (packet.sourcePort == 445 || packet.destinationPort == 445) {
            return Protocol::SMB;
        }

        if (packet.payload.rfind("GET ", 0) == 0 ||
            packet.payload.rfind("POST ", 0) == 0 ||
            packet.payload.rfind("HEAD ", 0) == 0) {
            return Protocol::HTTP;
        }
    }

    return packet.protocol;
}


// ---------------------------------------------------------------------------
// HTTP metadata extraction
// ---------------------------------------------------------------------------

struct HTTPRequest {
    std::string method;
    std::string path;
    std::string version;
    std::string host;
};


std::optional<HTTPRequest> parseHTTPRequest(
    const std::string& payload
) {
    std::istringstream lines(payload);
    std::string requestLine;

    if (!std::getline(lines, requestLine)) {
        return std::nullopt;
    }

    if (!requestLine.empty() &&
        requestLine.back() == '\r') {
        requestLine.pop_back();
    }

    std::istringstream request(requestLine);

    HTTPRequest result;

    if (!(request >>
          result.method >>
          result.path >>
          result.version)) {
        return std::nullopt;
    }

    if (result.version.rfind("HTTP/", 0) != 0) {
        return std::nullopt;
    }

    std::string line;

    while (std::getline(lines, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        constexpr const char* hostPrefix = "Host:";

        if (line.rfind(hostPrefix, 0) == 0) {
            result.host = line.substr(5);

            while (!result.host.empty() &&
                   std::isspace(
                       static_cast<unsigned char>(
                           result.host.front()))) {
                result.host.erase(result.host.begin());
            }

            break;
        }
    }

    return result;
}


// ---------------------------------------------------------------------------
// DNS metadata model
// ---------------------------------------------------------------------------

struct DNSQuestion {
    std::string name;
    std::string type;
};


std::optional<DNSQuestion> parseSyntheticDNS(
    const std::string& payload
) {
    /*
     * The synthetic capture represents DNS metadata as:
     *
     *     QUERY|example.test|A
     *
     * Real DNS packets are binary messages containing:
     *     header
     *     question section
     *     answer section
     *     authority section
     *     additional section
     *
     * Keeping the case-study representation textual lets the C++ program
     * concentrate on analysis architecture while the Python implementation
     * demonstrates binary DNS parsing.
     */

    constexpr const char* prefix = "QUERY|";

    if (payload.rfind(prefix, 0) != 0) {
        return std::nullopt;
    }

    std::size_t separator = payload.find('|', 6);

    if (separator == std::string::npos) {
        return std::nullopt;
    }

    DNSQuestion question;

    question.name = payload.substr(6, separator - 6);
    question.type = payload.substr(separator + 1);

    if (question.name.empty() || question.type.empty()) {
        return std::nullopt;
    }

    return question;
}


// ---------------------------------------------------------------------------
// Filter system
// ---------------------------------------------------------------------------

enum class FilterField {
    Protocol,
    SourceIP,
    DestinationIP,
    SourcePort,
    DestinationPort,
    PacketLength
};


struct FilterExpression {
    FilterField field;
    std::string stringValue;
    std::uint16_t numericValue{};
};


std::optional<FilterExpression> parseFilter(
    const std::string& expression
) {
    /*
     * Supported exact filters:
     *
     *     tcp
     *     udp
     *     dns
     *     http
     *     ip.src == 192.168.1.10
     *     ip.dst == 192.168.1.20
     *     tcp.port == 80
     *     frame.len > 100
     *
     * A production parser would normally tokenize expressions and construct
     * an abstract syntax tree for AND/OR/NOT and parentheses.
     */

    if (expression == "tcp") {
        return FilterExpression{
            FilterField::Protocol,
            "TCP",
            0
        };
    }

    if (expression == "udp") {
        return FilterExpression{
            FilterField::Protocol,
            "UDP",
            0
        };
    }

    if (expression == "dns") {
        return FilterExpression{
            FilterField::Protocol,
            "DNS",
            0
        };
    }

    if (expression == "http") {
        return FilterExpression{
            FilterField::Protocol,
            "HTTP",
            0
        };
    }

    const std::string sourcePrefix = "ip.src == ";

    if (expression.rfind(sourcePrefix, 0) == 0) {
        return FilterExpression{
            FilterField::SourceIP,
            expression.substr(sourcePrefix.size()),
            0
        };
    }

    const std::string destinationPrefix = "ip.dst == ";

    if (expression.rfind(destinationPrefix, 0) == 0) {
        return FilterExpression{
            FilterField::DestinationIP,
            expression.substr(destinationPrefix.size()),
            0
        };
    }

    const std::string portPrefix = "tcp.port == ";

    if (expression.rfind(portPrefix, 0) == 0) {
        unsigned long port = std::stoul(
            expression.substr(portPrefix.size())
        );

        if (port > 65535) {
            throw std::invalid_argument("TCP port exceeds 65535.");
        }

        return FilterExpression{
            FilterField::SourcePort,
            "",
            static_cast<std::uint16_t>(port)
        };
    }

    return std::nullopt;
}


bool matchesFilter(
    const Packet& packet,
    const FilterExpression& filter
) {
    Protocol application = classifyApplicationProtocol(packet);

    switch (filter.field) {
        case FilterField::Protocol:
            return protocolName(application) == filter.stringValue;

        case FilterField::SourceIP:
            return packet.source == filter.stringValue;

        case FilterField::DestinationIP:
            return packet.destination == filter.stringValue;

        case FilterField::SourcePort:
            return packet.sourcePort == filter.numericValue ||
                   packet.destinationPort == filter.numericValue;

        case FilterField::DestinationPort:
        case FilterField::PacketLength:
            return false;
    }

    return false;
}


// ---------------------------------------------------------------------------
// TCP stream reconstruction
// ---------------------------------------------------------------------------

class TCPStream {
public:
    explicit TCPStream(StreamKey key)
        : key_(std::move(key)) {}

    void addPacket(const Packet& packet) {
        packets_.push_back(packet);
    }

    const StreamKey& key() const {
        return key_;
    }

    std::size_t packetCount() const {
        return packets_.size();
    }

    std::string reconstruct(
        const Endpoint& source
    ) const {
        std::vector<const Packet*> segments;

        for (const Packet& packet : packets_) {
            if (packet.source == source.address &&
                packet.sourcePort == source.port &&
                !packet.payload.empty()) {

                segments.push_back(&packet);
            }
        }

        std::sort(
            segments.begin(),
            segments.end(),
            [](const Packet* left, const Packet* right) {
                return left->sequence < right->sequence;
            }
        );

        std::string output;
        std::uint32_t nextSequence = 0;
        bool initialized = false;

        for (const Packet* packet : segments) {
            const std::uint32_t sequence = packet->sequence;

            if (!initialized) {
                output += packet->payload;
                nextSequence =
                    sequence +
                    static_cast<std::uint32_t>(
                        packet->payload.size()
                    );
                initialized = true;
                continue;
            }

            if (sequence >= nextSequence) {
                output += packet->payload;
                nextSequence =
                    sequence +
                    static_cast<std::uint32_t>(
                        packet->payload.size()
                    );
                continue;
            }

            // Handle a simple retransmission/overlap.
            std::size_t overlap =
                static_cast<std::size_t>(
                    nextSequence - sequence
                );

            if (overlap < packet->payload.size()) {
                output += packet->payload.substr(overlap);

                nextSequence += static_cast<std::uint32_t>(
                    packet->payload.size() - overlap
                );
            }
        }

        return output;
    }

private:
    StreamKey key_;
    std::vector<Packet> packets_;
};


// ---------------------------------------------------------------------------
// Packet analyzer
// ---------------------------------------------------------------------------

class PacketAnalyzer {
public:
    explicit PacketAnalyzer(
        std::vector<Packet> packets
    )
        : packets_(std::move(packets)) {
        validateAll();
        buildIndexes();
        buildStreams();
    }

    const std::vector<Packet>& packets() const {
        return packets_;
    }

    std::vector<Packet> filter(
        const std::string& expression
    ) const {
        auto parsed = parseFilter(expression);

        if (!parsed) {
            throw std::invalid_argument(
                "Unsupported filter: " + expression
            );
        }

        std::vector<Packet> result;

        for (const Packet& packet : packets_) {
            if (matchesFilter(packet, *parsed)) {
                result.push_back(packet);
            }
        }

        return result;
    }

    const std::map<StreamKey, TCPStream>& streams() const {
        return streams_;
    }

    std::vector<const Packet*> packetsFrom(
        const std::string& address
    ) const {
        auto iterator = bySource_.find(address);

        if (iterator == bySource_.end()) {
            return {};
        }

        return iterator->second;
    }

    void printStatistics() const {
        std::map<std::string, std::size_t> counts;

        std::size_t totalBytes = 0;

        for (const Packet& packet : packets_) {
            Protocol protocol =
                classifyApplicationProtocol(packet);

            ++counts[protocolName(protocol)];
            totalBytes += packet.capturedLength();
        }

        std::cout << "\n=== CAPTURE STATISTICS ===\n";
        std::cout << "Packets: " << packets_.size() << '\n';
        std::cout << "Payload bytes: " << totalBytes << '\n';

        std::cout << "\nProtocols:\n";

        for (const auto& [protocol, count] : counts) {
            std::cout << "  "
                      << std::setw(12)
                      << std::left
                      << protocol
                      << count
                      << '\n';
        }
    }

    void printStreams() const {
        std::cout << "\n=== TCP STREAMS ===\n";

        for (const auto& [key, stream] : streams_) {
            std::cout << "\n"
                      << key.toString()
                      << '\n';

            std::cout
                << "Packets: "
                << stream.packetCount()
                << '\n';

            std::string forward =
                stream.reconstruct(key.first);

            std::string reverse =
                stream.reconstruct(key.second);

            std::cout
                << "First direction bytes: "
                << forward.size()
                << '\n';

            std::cout
                << "Second direction bytes: "
                << reverse.size()
                << '\n';

            if (auto request = parseHTTPRequest(forward)) {
                std::cout
                    << "HTTP method: "
                    << request->method
                    << '\n';

                std::cout
                    << "HTTP path: "
                    << request->path
                    << '\n';

                std::cout
                    << "HTTP host: "
                    << request->host
                    << '\n';
            }
        }
    }

    void printDNS() const {
        std::cout << "\n=== DNS ANALYSIS ===\n";

        for (const Packet& packet : packets_) {
            if (classifyApplicationProtocol(packet) !=
                Protocol::DNS) {
                continue;
            }

            auto question =
                parseSyntheticDNS(packet.payload);

            if (!question) {
                continue;
            }

            std::cout
                << "Packet "
                << packet.number
                << ": "
                << question->type
                << " "
                << question->name
                << '\n';
        }
    }

    void printIndicators() const {
        std::cout << "\n=== TRAFFIC INDICATORS ===\n";

        std::map<std::uint16_t, std::string> monitoredPorts{
            {23, "Telnet"},
            {445, "SMB"},
            {3389, "RDP"},
            {5900, "VNC"}
        };

        std::map<
            std::string,
            std::size_t
        > synCounts;

        for (const Packet& packet : packets_) {
            if (packet.protocol != Protocol::TCP) {
                continue;
            }

            if (packet.hasFlag("SYN") &&
                !packet.hasFlag("ACK")) {

                std::ostringstream key;

                key << packet.source
                    << " -> "
                    << packet.destination
                    << ':'
                    << packet.destinationPort;

                ++synCounts[key.str()];
            }

            auto service =
                monitoredPorts.find(
                    packet.destinationPort
                );

            if (service != monitoredPorts.end()) {
                std::cout
                    << "[MEDIUM] Packet "
                    << packet.number
                    << ": traffic to "
                    << service->second
                    << " port\n";
            }

            if (packet.hasFlag("RST")) {
                std::cout
                    << "[LOW] Packet "
                    << packet.number
                    << ": TCP reset\n";
            }
        }

        for (const auto& [destination, count] : synCounts) {
            if (count >= 10) {
                std::cout
                    << "[MEDIUM] "
                    << destination
                    << ": "
                    << count
                    << " SYN packets\n";
            }
        }

        /*
         * These indicators are not verdicts.
         *
         * A SYN burst can represent:
         *     - scanning,
         *     - connection retries,
         *     - an unavailable service,
         *     - a legitimate diagnostic operation.
         *
         * Context and additional evidence are required.
         */
    }

private:
    std::vector<Packet> packets_;

    std::unordered_map<
        std::string,
        std::vector<const Packet*>
    > bySource_;

    std::map<StreamKey, TCPStream> streams_;

    void validateAll() const {
        for (const Packet& packet : packets_) {
            validatePacket(packet);
        }
    }

    void buildIndexes() {
        for (const Packet& packet : packets_) {
            bySource_[packet.source].push_back(&packet);
        }
    }

    void buildStreams() {
        for (const Packet& packet : packets_) {
            if (packet.protocol != Protocol::TCP) {
                continue;
            }

            StreamKey key =
                StreamKey::fromPacket(packet);

            auto iterator =
                streams_.find(key);

            if (iterator == streams_.end()) {
                iterator =
                    streams_.emplace(
                        key,
                        TCPStream(key)
                    ).first;
            }

            iterator->second.addPacket(packet);
        }
    }
};


// ---------------------------------------------------------------------------
// Synthetic case-study dataset
// ---------------------------------------------------------------------------

std::vector<Packet> createCaseStudyPackets() {
    std::vector<Packet> packets;

    packets.push_back(Packet{
        1,
        1000,
        "192.168.1.10",
        "192.168.1.20",
        Protocol::TCP,
        50000,
        80,
        1000,
        {"SYN"},
        ""
    });

    packets.push_back(Packet{
        2,
        1010,
        "192.168.1.20",
        "192.168.1.10",
        Protocol::TCP,
        80,
        50000,
        2000,
        {"SYN", "ACK"},
        ""
    });

    /*
     * The HTTP request is deliberately split into two segments. This
     * illustrates why packet-level inspection and stream-level inspection
     * are different operations.
     */
    packets.push_back(Packet{
        3,
        1020,
        "192.168.1.10",
        "192.168.1.20",
        Protocol::TCP,
        50000,
        80,
        1001,
        {"ACK", "PSH"},
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.test\r\n"
    });

    packets.push_back(Packet{
        4,
        1030,
        "192.168.1.10",
        "192.168.1.20",
        Protocol::TCP,
        50000,
        80,
        1050,
        {"ACK", "PSH"},
        "User-Agent: PacketStudy/1.0\r\n"
        "Accept: text/plain\r\n"
        "\r\n"
    });

    packets.push_back(Packet{
        5,
        1040,
        "192.168.1.20",
        "192.168.1.10",
        Protocol::TCP,
        80,
        50000,
        2001,
        {"ACK", "PSH"},
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "\r\n"
        "hello world\n"
    });

    packets.push_back(Packet{
        6,
        1050,
        "192.168.1.10",
        "8.8.8.8",
        Protocol::UDP,
        53000,
        53,
        0,
        {},
        "QUERY|example.test|A"
    });

    packets.push_back(Packet{
        7,
        1060,
        "192.168.1.10",
        "192.168.1.30",
        Protocol::TCP,
        51000,
        445,
        7000,
        {"SYN"},
        ""
    });

    packets.push_back(Packet{
        8,
        1070,
        "192.168.1.10",
        "192.168.1.31",
        Protocol::TCP,
        51001,
        445,
        8000,
        {"SYN"},
        ""
    });

    packets.push_back(Packet{
        9,
        1080,
        "192.168.1.10",
        "192.168.1.32",
        Protocol::TCP,
        51002,
        445,
        9000,
        {"RST"},
        ""
    });

    return packets;
}


// ---------------------------------------------------------------------------
// Main application
// ---------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "=== PACKET ANALYSIS CASE STUDY ===\n";

        std::vector<Packet> packets =
            createCaseStudyPackets();

        PacketAnalyzer analyzer(
            std::move(packets)
        );

        std::cout << "\n=== PACKET LIST ===\n";

        std::cout
            << std::left
            << std::setw(6)
            << "No."
            << std::setw(18)
            << "Source"
            << std::setw(18)
            << "Destination"
            << std::setw(14)
            << "Protocol"
            << "Length\n";

        for (const Packet& packet :
             analyzer.packets()) {

            Protocol application =
                classifyApplicationProtocol(packet);

            std::cout
                << std::setw(6)
                << packet.number
                << std::setw(18)
                << packet.source
                << std::setw(18)
                << packet.destination
                << std::setw(14)
                << protocolName(application)
                << packet.capturedLength()
                << '\n';
        }

        analyzer.printStatistics();

        std::cout << "\n=== FILTER TESTS ===\n";

        const std::vector<std::string> filters{
            "tcp",
            "udp",
            "dns",
            "http",
            "ip.src == 192.168.1.10",
            "tcp.port == 80"
        };

        for (const std::string& expression : filters) {
            auto result =
                analyzer.filter(expression);

            std::cout
                << std::setw(32)
                << std::left
                << expression
                << result.size()
                << " packet(s)\n";
        }

        analyzer.printStreams();
        analyzer.printDNS();
        analyzer.printIndicators();

        std::cout
            << "\n=== INDEXED SOURCE LOOKUP ===\n";

        auto sourcePackets =
            analyzer.packetsFrom("192.168.1.10");

        std::cout
            << "Packets originating from "
            << "192.168.1.10: "
            << sourcePackets.size()
            << '\n';

        std::cout
            << "\n=== DESIGN NOTES ===\n"
            << "Packet validation occurs before analysis.\n"
            << "Application protocol classification is separated "
               "from transport protocol identification.\n"
            << "TCP streams canonicalize both directions into one key.\n"
            << "TCP payloads are ordered by sequence number.\n"
            << "Exact source lookups use an unordered_map index.\n"
            << "Traffic indicators are evidence for investigation, "
               "not automatic verdicts.\n";

        std::cout
            << "\nCase study completed successfully.\n";

        return 0;

    } catch (const std::exception& error) {
        std::cerr
            << "Analysis error: "
            << error.what()
            << '\n';

        return 1;
    }
}
