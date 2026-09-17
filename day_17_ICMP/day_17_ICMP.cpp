#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * ICMP Network Diagnostics Case Study
 * ====================================
 *
 * Scenario:
 *     A network operations component needs to represent ICMP diagnostics
 *     for an enterprise connectivity-monitoring system.
 *
 * The program demonstrates:
 *     - ICMP Echo Request/Reply packet structure
 *     - Internet checksum calculation
 *     - Destination Unreachable messages
 *     - TTL-driven traceroute reasoning
 *     - ICMP security policy
 *     - validation and bounded probing
 *     - data structures and modular architecture
 *     - complexity and operational trade-offs
 *
 * The program intentionally does not open raw sockets. Raw ICMP sockets are
 * operating-system-specific and commonly require elevated privileges.
 * The packet engine is therefore separated from the transport mechanism.
 *
 * Compile:
 *     g++ -std=c++17 -O2 -Wall -Wextra -pedantic icmp_case_study.cpp -o icmp_case_study
 */

namespace icmp {

enum class Type : std::uint8_t {
    EchoReply = 0,
    DestinationUnreachable = 3,
    Redirect = 5,
    EchoRequest = 8,
    TimeExceeded = 11,
    ParameterProblem = 12
};

enum class UnreachableCode : std::uint8_t {
    NetworkUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeeded = 4,
    NetworkAdminProhibited = 9,
    HostAdminProhibited = 10
};

std::string typeName(Type type) {
    switch (type) {
        case Type::EchoReply:
            return "Echo Reply";
        case Type::DestinationUnreachable:
            return "Destination Unreachable";
        case Type::Redirect:
            return "Redirect";
        case Type::EchoRequest:
            return "Echo Request";
        case Type::TimeExceeded:
            return "Time Exceeded";
        case Type::ParameterProblem:
            return "Parameter Problem";
    }

    return "Unknown ICMP type";
}

std::string unreachableCodeName(std::uint8_t code) {
    switch (static_cast<UnreachableCode>(code)) {
        case UnreachableCode::NetworkUnreachable:
            return "Network unreachable";
        case UnreachableCode::HostUnreachable:
            return "Host unreachable";
        case UnreachableCode::ProtocolUnreachable:
            return "Protocol unreachable";
        case UnreachableCode::PortUnreachable:
            return "Port unreachable";
        case UnreachableCode::FragmentationNeeded:
            return "Fragmentation needed";
        case UnreachableCode::NetworkAdminProhibited:
            return "Network administratively prohibited";
        case UnreachableCode::HostAdminProhibited:
            return "Host administratively prohibited";
    }

    return "Unknown unreachable code";
}

/*
 * Packet is represented as bytes because network protocols are defined in
 * terms of octets and bit fields rather than C++ objects.
 */
using Bytes = std::vector<std::uint8_t>;

/*
 * Convert an unsigned 16-bit value into network byte order.
 * Network protocols conventionally use big-endian byte order.
 */
void append16(Bytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    output.push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint16_t read16(const Bytes& input, std::size_t offset) {
    if (offset + 2 > input.size()) {
        throw std::out_of_range("attempt to read beyond packet boundary");
    }

    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8) |
        input[offset + 1]
    );
}

void write16(Bytes& input, std::size_t offset, std::uint16_t value) {
    if (offset + 2 > input.size()) {
        throw std::out_of_range("attempt to write beyond packet boundary");
    }

    input[offset] = static_cast<std::uint8_t>((value >> 8) & 0xff);
    input[offset + 1] = static_cast<std::uint8_t>(value & 0xff);
}

/*
 * Internet checksum.
 *
 * Time complexity: O(n)
 * Space complexity: O(1)
 */
std::uint16_t internetChecksum(const Bytes& data) {
    std::uint32_t sum = 0;

    for (std::size_t offset = 0; offset < data.size(); offset += 2) {
        const std::uint16_t high = data[offset];
        const std::uint16_t low =
            (offset + 1 < data.size()) ? data[offset + 1] : 0;

        const std::uint16_t word =
            static_cast<std::uint16_t>((high << 8) | low);

        sum += word;

        // Fold carries so the arithmetic remains one's-complement arithmetic.
        sum = (sum & 0xffffU) + (sum >> 16U);
    }

    while (sum >> 16U) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }

    return static_cast<std::uint16_t>(~sum);
}

struct EchoMessage {
    Type type;
    std::uint8_t code;
    std::uint16_t checksum;
    std::uint16_t identifier;
    std::uint16_t sequence;
    Bytes payload;
};

class EchoPacket {
public:
    static Bytes build(
        Type type,
        std::uint16_t identifier,
        std::uint16_t sequence,
        const Bytes& payload
    ) {
        if (type != Type::EchoRequest && type != Type::EchoReply) {
            throw std::invalid_argument(
                "EchoPacket accepts only Echo Request or Echo Reply"
            );
        }

        Bytes packet;
        packet.reserve(8 + payload.size());

        packet.push_back(static_cast<std::uint8_t>(type));
        packet.push_back(0);
        append16(packet, 0);
        append16(packet, identifier);
        append16(packet, sequence);
        packet.insert(packet.end(), payload.begin(), payload.end());

        const auto checksum = internetChecksum(packet);
        write16(packet, 2, checksum);

        return packet;
    }

    static EchoMessage parse(const Bytes& packet) {
        if (packet.size() < 8) {
            throw std::invalid_argument("ICMP Echo packet is too short");
        }

        const auto type = static_cast<Type>(packet[0]);
        const auto code = packet[1];
        const auto receivedChecksum = read16(packet, 2);
        const auto identifier = read16(packet, 4);
        const auto sequence = read16(packet, 6);

        if (type != Type::EchoRequest && type != Type::EchoReply) {
            throw std::invalid_argument("not an ICMP Echo packet");
        }

        if (code != 0) {
            throw std::invalid_argument(
                "Echo Request/Reply requires code 0"
            );
        }

        Bytes copy = packet;
        write16(copy, 2, 0);

        if (internetChecksum(copy) != receivedChecksum) {
            throw std::invalid_argument("invalid ICMP checksum");
        }

        Bytes payload(packet.begin() + 8, packet.end());

        return {
            type,
            code,
            receivedChecksum,
            identifier,
            sequence,
            payload
        };
    }
};

struct UnreachableMessage {
    std::uint8_t code;
    std::uint16_t nextHopMtu;
    Bytes embeddedPacket;
};

class DestinationUnreachablePacket {
public:
    static Bytes build(
        std::uint8_t code,
        const Bytes& embeddedPacket,
        std::uint16_t nextHopMtu = 0
    ) {
        /*
         * In the classic IPv4 format, the MTU field is meaningful for
         * Fragmentation Needed (Code 4). For other codes it is zero here.
         */
        if (code != static_cast<std::uint8_t>(
                        UnreachableCode::FragmentationNeeded)) {
            nextHopMtu = 0;
        }

        Bytes packet;
        packet.reserve(8 + embeddedPacket.size());

        packet.push_back(
            static_cast<std::uint8_t>(Type::DestinationUnreachable)
        );
        packet.push_back(code);
        append16(packet, 0);
        append16(packet, 0);
        append16(packet, nextHopMtu);

        packet.insert(
            packet.end(),
            embeddedPacket.begin(),
            embeddedPacket.end()
        );

        write16(packet, 2, internetChecksum(packet));

        return packet;
    }

    static UnreachableMessage parse(const Bytes& packet) {
        if (packet.size() < 8) {
            throw std::invalid_argument(
                "Destination Unreachable packet is too short"
            );
        }

        if (packet[0] != static_cast<std::uint8_t>(
                              Type::DestinationUnreachable)) {
            throw std::invalid_argument(
                "packet is not Destination Unreachable"
            );
        }

        const auto code = packet[1];
        const auto checksum = read16(packet, 2);
        const auto nextHopMtu = read16(packet, 6);

        Bytes copy = packet;
        write16(copy, 2, 0);

        if (internetChecksum(copy) != checksum) {
            throw std::invalid_argument(
                "invalid Destination Unreachable checksum"
            );
        }

        Bytes embedded(packet.begin() + 8, packet.end());

        return {code, nextHopMtu, embedded};
    }
};

enum class TraceResponse {
    TimeExceeded,
    EchoReply,
    DestinationUnreachable,
    Timeout
};

std::string traceResponseName(TraceResponse response) {
    switch (response) {
        case TraceResponse::TimeExceeded:
            return "Time Exceeded";
        case TraceResponse::EchoReply:
            return "Echo Reply";
        case TraceResponse::DestinationUnreachable:
            return "Destination Unreachable";
        case TraceResponse::Timeout:
            return "Timeout";
    }

    return "Unknown";
}

struct TraceHop {
    int ttl;
    std::string address;
    TraceResponse response;
    double rttMilliseconds;
};

class TracerouteEngine {
public:
    explicit TracerouteEngine(
        std::vector<std::string> simulatedRouters
    )
        : routers_(std::move(simulatedRouters)) {}

    std::vector<TraceHop> trace(
        const std::string& destination,
        int maximumTtl
    ) const {
        if (maximumTtl <= 0) {
            throw std::invalid_argument(
                "maximum TTL must be positive"
            );
        }

        std::vector<TraceHop> results;

        const int limit = std::min(
            maximumTtl,
            static_cast<int>(routers_.size())
        );

        for (int ttl = 1; ttl <= limit; ++ttl) {
            const bool reachedDestination =
                ttl == static_cast<int>(routers_.size());

            const std::string& address =
                reachedDestination
                    ? destination
                    : routers_[ttl - 1];

            const auto response =
                reachedDestination
                    ? TraceResponse::EchoReply
                    : TraceResponse::TimeExceeded;

            /*
             * These are simulated values, not actual measurements.
             * Real traceroute requires clocks around transmitted probes
             * and received ICMP responses.
             */
            const double rtt = 1.25 + (ttl * 2.10);

            results.push_back({
                ttl,
                address,
                response,
                rtt
            });

            if (reachedDestination) {
                break;
            }
        }

        return results;
    }

private:
    std::vector<std::string> routers_;
};

struct SecurityPolicy {
    bool allowEchoRequest = true;
    bool allowEchoReply = true;
    bool allowTimeExceeded = true;
    bool allowDestinationUnreachable = true;
    std::size_t rateLimitPerSecond = 10;
};

class ICMPSecurityController {
public:
    explicit ICMPSecurityController(SecurityPolicy policy)
        : policy_(policy),
          windowStart_(std::chrono::steady_clock::now()) {}

    bool allows(Type type) {
        if (!rateLimitAllows()) {
            return false;
        }

        switch (type) {
            case Type::EchoRequest:
                return policy_.allowEchoRequest;
            case Type::EchoReply:
                return policy_.allowEchoReply;
            case Type::TimeExceeded:
                return policy_.allowTimeExceeded;
            case Type::DestinationUnreachable:
                return policy_.allowDestinationUnreachable;
            default:
                return false;
        }
    }

private:
    bool rateLimitAllows() {
        const auto now = std::chrono::steady_clock::now();

        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                now - windowStart_
            ).count();

        if (elapsed >= 1000) {
            windowStart_ = now;
            windowCount_ = 0;
        }

        if (windowCount_ >= policy_.rateLimitPerSecond) {
            return false;
        }

        ++windowCount_;
        return true;
    }

    SecurityPolicy policy_;
    std::chrono::steady_clock::time_point windowStart_;
    std::size_t windowCount_ = 0;
};

class ConnectivityMonitor {
public:
    explicit ConnectivityMonitor(TracerouteEngine tracerouteEngine)
        : tracerouteEngine_(std::move(tracerouteEngine)) {}

    void run(const std::string& destination) const {
        std::cout << "\nConnectivity report for "
                  << destination << "\n";

        const auto hops = tracerouteEngine_.trace(destination, 30);

        for (const auto& hop : hops) {
            std::cout
                << std::setw(2) << hop.ttl
                << "  "
                << std::setw(15) << std::left << hop.address
                << std::right
                << "  "
                << std::fixed << std::setprecision(2)
                << std::setw(7) << hop.rttMilliseconds
                << " ms  "
                << traceResponseName(hop.response)
                << "\n";
        }

        /*
         * A production monitor would normally store structured events
         * instead of relying only on console output.
         */
    }

private:
    TracerouteEngine tracerouteEngine_;
};

std::string bytesToHex(const Bytes& data) {
    std::ostringstream output;

    for (const auto byte : data) {
        output
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(byte);
    }

    return output.str();
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error("Test failure: " + message);
    }
}

void demonstrateEcho() {
    std::cout << "=== ICMP Echo Request/Reply ===\n";

    const Bytes payload = {
        'I', 'C', 'M', 'P', '-', 'C', 'A', 'S', 'E'
    };

    const Bytes request = EchoPacket::build(
        Type::EchoRequest,
        0x1234,
        1,
        payload
    );

    const EchoMessage parsed = EchoPacket::parse(request);

    std::cout << "Request type: "
              << typeName(parsed.type)
              << "\n";

    std::cout << "Identifier: 0x"
              << std::hex
              << parsed.identifier
              << std::dec
              << "\n";

    std::cout << "Sequence: "
              << parsed.sequence
              << "\n";

    std::cout << "Payload bytes: "
              << parsed.payload.size()
              << "\n";

    std::cout << "Packet hex: "
              << bytesToHex(request)
              << "\n";

    const Bytes reply = EchoPacket::build(
        Type::EchoReply,
        parsed.identifier,
        parsed.sequence,
        parsed.payload
    );

    const EchoMessage parsedReply = EchoPacket::parse(reply);

    std::cout << "Reply type: "
              << typeName(parsedReply.type)
              << "\n";
}

void demonstrateUnreachable() {
    std::cout << "\n=== Destination Unreachable ===\n";

    /*
     * This byte sequence represents an abbreviated original IPv4 packet.
     * In real traffic, the ICMP error embeds the triggering packet's
     * original IP header and enough following bytes for identification.
     */
    const Bytes originalPacket = {
        0x45, 0x00, 0x00, 0x3c,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        0xc0, 0xa8, 0x01, 0x64,
        0x08, 0x08, 0x08, 0x08,
        0x12, 0x34, 0x00, 0x35
    };

    const Bytes unreachable =
        DestinationUnreachablePacket::build(
            static_cast<std::uint8_t>(
                UnreachableCode::PortUnreachable
            ),
            originalPacket
        );

    const auto parsed =
        DestinationUnreachablePacket::parse(unreachable);

    std::cout
        << "Code: "
        << static_cast<int>(parsed.code)
        << " ("
        << unreachableCodeName(parsed.code)
        << ")\n";

    std::cout
        << "Embedded packet bytes: "
        << parsed.embeddedPacket.size()
        << "\n";

    const Bytes pmtud =
        DestinationUnreachablePacket::build(
            static_cast<std::uint8_t>(
                UnreachableCode::FragmentationNeeded
            ),
            originalPacket,
            1400
        );

    const auto pmtudParsed =
        DestinationUnreachablePacket::parse(pmtud);

    std::cout
        << "Next-Hop MTU: "
        << pmtudParsed.nextHopMtu
        << "\n";
}

void demonstrateTraceroute() {
    std::cout << "\n=== Traceroute Case Study ===\n";

    /*
     * Documentation/test addresses are used here. No real network packets
     * are transmitted.
     */
    std::vector<std::string> routers = {
        "192.168.1.1",
        "10.10.0.1",
        "172.16.4.1",
        "203.0.113.9",
        "198.51.100.20"
    };

    TracerouteEngine engine(routers);

    ConnectivityMonitor monitor(std::move(engine));

    monitor.run("198.51.100.50");
}

void demonstrateSecurity() {
    std::cout << "\n=== ICMP Security Policy ===\n";

    SecurityPolicy policy;
    policy.allowEchoRequest = true;
    policy.allowEchoReply = true;
    policy.allowTimeExceeded = true;
    policy.allowDestinationUnreachable = true;
    policy.rateLimitPerSecond = 4;

    ICMPSecurityController controller(policy);

    const std::array<Type, 4> types = {
        Type::EchoRequest,
        Type::EchoReply,
        Type::TimeExceeded,
        Type::DestinationUnreachable
    };

    for (const auto type : types) {
        std::cout
            << std::setw(30)
            << std::left
            << typeName(type)
            << " -> "
            << (controller.allows(type)
                ? "allowed"
                : "blocked")
            << "\n";
    }

    /*
     * Security is not equivalent to simply blocking ICMP.
     *
     * Useful operational ICMP can support:
     *     - diagnostics
     *     - path discovery
     *     - MTU discovery
     *     - error reporting
     *
     * Security controls can instead apply:
     *     - type/code filtering
     *     - direction restrictions
     *     - rate limits
     *     - source/destination policy
     *     - control-plane policing
     *     - logging and monitoring
     */
}

void demonstrateFailureConditions() {
    std::cout << "\n=== Failure and Validation Tests ===\n";

    try {
        EchoPacket::parse({0x08, 0x00});
    } catch (const std::exception& error) {
        std::cout
            << "Short packet safely rejected: "
            << error.what()
            << "\n";
    }

    const Bytes valid =
        EchoPacket::build(
            Type::EchoRequest,
            1,
            1,
            {'t', 'e', 's', 't'}
        );

    Bytes corrupted = valid;
    corrupted.back() ^= 0xff;

    try {
        EchoPacket::parse(corrupted);
        throw std::runtime_error(
            "corrupted packet unexpectedly accepted"
        );
    } catch (const std::invalid_argument& error) {
        std::cout
            << "Corrupted packet rejected: "
            << error.what()
            << "\n";
    }

    try {
        TracerouteEngine engine({"192.0.2.1"});
        engine.trace("198.51.100.1", 0);
    } catch (const std::exception& error) {
        std::cout
            << "Invalid TTL safely rejected: "
            << error.what()
            << "\n";
    }
}

void runTests() {
    std::cout << "\n=== Automated Tests ===\n";

    const Bytes payload = {'h', 'e', 'l', 'l', 'o'};

    const Bytes packet =
        EchoPacket::build(
            Type::EchoRequest,
            100,
            7,
            payload
        );

    const auto parsed = EchoPacket::parse(packet);

    require(
        parsed.identifier == 100,
        "Echo identifier"
    );

    require(
        parsed.sequence == 7,
        "Echo sequence"
    );

    require(
        parsed.payload == payload,
        "Echo payload"
    );

    const Bytes unreachable =
        DestinationUnreachablePacket::build(
            static_cast<std::uint8_t>(
                UnreachableCode::PortUnreachable
            ),
            packet
        );

    const auto unreachableParsed =
        DestinationUnreachablePacket::parse(unreachable);

    require(
        unreachableParsed.code ==
            static_cast<std::uint8_t>(
                UnreachableCode::PortUnreachable
            ),
        "Destination Unreachable code"
    );

    TracerouteEngine engine({
        "192.168.1.1",
        "10.10.0.1",
        "198.51.100.20"
    });

    const auto trace =
        engine.trace("198.51.100.50", 30);

    require(
        !trace.empty(),
        "traceroute must return hops"
    );

    require(
        trace.back().response == TraceResponse::EchoReply,
        "final traceroute response"
    );

    std::cout << "All C++ tests passed.\n";
}

void printArchitecture() {
    std::cout
        << "\n=== Architecture ===\n"
        << "Packet construction/parsing\n"
        << "        |\n"
        << "        +-- Checksum engine\n"
        << "        |\n"
        << "        +-- ICMP message models\n"
        << "        |\n"
        << "        +-- Traceroute engine\n"
        << "        |\n"
        << "        +-- Security policy controller\n"
        << "        |\n"
        << "        +-- Connectivity monitor\n"
        << "\nThe design separates protocol logic from packet transport.\n"
        << "This allows the packet engine to be tested without network access.\n";
}

} // namespace icmp

int main() {
    try {
        std::cout
            << "ICMP Network Diagnostics Technical Case Study\n"
            << "==============================================\n";

        icmp::printArchitecture();
        icmp::demonstrateEcho();
        icmp::demonstrateUnreachable();
        icmp::demonstrateTraceroute();
        icmp::demonstrateSecurity();
        icmp::demonstrateFailureConditions();
        icmp::runTests();

        std::cout
            << "\nCase study completed successfully.\n"
            << "\nEngineering observations:\n"
            << "  * Checksum calculation is O(n).\n"
            << "  * Packet parsing requires strict bounds checking.\n"
            << "  * Traceroute requires one or more probes for each TTL.\n"
            << "  * ICMP errors do not provide reliable transport semantics.\n"
            << "  * Missing ICMP responses do not necessarily mean a host is down.\n"
            << "  * Raw-socket transport should be separated from protocol logic.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
