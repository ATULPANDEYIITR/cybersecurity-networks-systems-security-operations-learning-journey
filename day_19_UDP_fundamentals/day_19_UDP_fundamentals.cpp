#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * UDP Industry-Style Case Study
 *
 * Scenario:
 *     A distributed industrial telemetry gateway receives UDP datagrams from
 *     multiple sensors. The gateway validates messages, tracks sequence
 *     numbers, detects gaps and duplicates, maintains the newest state,
 *     optionally acknowledges messages, and reports operational statistics.
 *
 * The program demonstrates:
 *     - UDP sockets
 *     - datagram boundaries
 *     - bind/sendto/recvfrom
 *     - binary application protocol design
 *     - sequence numbers
 *     - acknowledgements
 *     - validation
 *     - duplicate detection
 *     - loss detection
 *     - telemetry semantics
 *     - timeout handling
 *     - bounded state
 *     - performance measurement
 *     - simulated packet loss
 *
 * Build:
 *     g++ -std=c++17 -O2 -Wall -Wextra -pedantic udp_case_study.cpp -o udp_case_study
 *
 * Run:
 *     ./udp_case_study
 *
 * The example uses the local loopback interface and does not require an
 * external server.
 */

namespace udp_case_study {

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

constexpr const char* LOOPBACK_ADDRESS = "127.0.0.1";
constexpr uint16_t EPHEMERAL_PORT = 0;
constexpr std::size_t MAX_DATAGRAM_SIZE = 1200;
constexpr uint8_t PROTOCOL_VERSION = 1;

enum class MessageType : uint8_t {
    Telemetry = 1,
    Acknowledgement = 2,
    Heartbeat = 3
};

// -----------------------------------------------------------------------------
// Utility functions
// -----------------------------------------------------------------------------

std::string messageTypeName(MessageType type) {
    switch (type) {
        case MessageType::Telemetry:
            return "Telemetry";
        case MessageType::Acknowledgement:
            return "Acknowledgement";
        case MessageType::Heartbeat:
            return "Heartbeat";
    }

    return "Unknown";
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

uint64_t hostToNetwork64(uint64_t value) {
    const uint32_t high =
        static_cast<uint32_t>(value >> 32U);

    const uint32_t low =
        static_cast<uint32_t>(value & 0xFFFFFFFFULL);

    const uint32_t networkHigh = htonl(high);
    const uint32_t networkLow = htonl(low);

    return (static_cast<uint64_t>(networkLow) << 32U) |
           static_cast<uint64_t>(networkHigh);
}

uint64_t networkToHost64(uint64_t value) {
    const uint32_t networkHigh =
        static_cast<uint32_t>(value & 0xFFFFFFFFULL);

    const uint32_t networkLow =
        static_cast<uint32_t>(value >> 32U);

    const uint32_t high = ntohl(networkHigh);
    const uint32_t low = ntohl(networkLow);

    return (static_cast<uint64_t>(high) << 32U) |
           static_cast<uint64_t>(low);
}

void appendUint32(std::vector<uint8_t>& output, uint32_t value) {
    const uint32_t networkValue = htonl(value);
    const auto* bytes =
        reinterpret_cast<const uint8_t*>(&networkValue);

    output.insert(output.end(), bytes, bytes + sizeof(networkValue));
}

void appendUint64(std::vector<uint8_t>& output, uint64_t value) {
    const uint64_t networkValue = hostToNetwork64(value);
    const auto* bytes =
        reinterpret_cast<const uint8_t*>(&networkValue);

    output.insert(output.end(), bytes, bytes + sizeof(networkValue));
}

uint32_t readUint32(
    const std::vector<uint8_t>& data,
    std::size_t& offset
) {
    require(
        offset + sizeof(uint32_t) <= data.size(),
        "truncated uint32 field"
    );

    uint32_t networkValue = 0;
    std::memcpy(
        &networkValue,
        data.data() + offset,
        sizeof(networkValue)
    );

    offset += sizeof(networkValue);
    return ntohl(networkValue);
}

uint64_t readUint64(
    const std::vector<uint8_t>& data,
    std::size_t& offset
) {
    require(
        offset + sizeof(uint64_t) <= data.size(),
        "truncated uint64 field"
    );

    uint64_t networkValue = 0;
    std::memcpy(
        &networkValue,
        data.data() + offset,
        sizeof(networkValue)
    );

    offset += sizeof(networkValue);
    return networkToHost64(networkValue);
}

void appendDouble(
    std::vector<uint8_t>& output,
    double value
) {
    static_assert(
        sizeof(double) == sizeof(uint64_t),
        "This example requires 64-bit double representation."
    );

    uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    appendUint64(output, bits);
}

double readDouble(
    const std::vector<uint8_t>& data,
    std::size_t& offset
) {
    const uint64_t bits = readUint64(data, offset);
    double value = 0;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

// -----------------------------------------------------------------------------
// Application protocol
// -----------------------------------------------------------------------------

struct TelemetryMessage {
    uint64_t sequence = 0;
    uint32_t sensorId = 0;
    double temperatureC = 0.0;
    uint64_t timestampMs = 0;
};

class Protocol {
public:
    /*
     * Binary packet layout:
     *
     * 1 byte   version
     * 1 byte   message type
     * 8 bytes  sequence number
     * 4 bytes  sensor ID
     * 8 bytes  temperature
     * 8 bytes  timestamp
     *
     * Total telemetry payload:
     * 30 bytes.
     *
     * Network byte order is used for integer fields so that systems with
     * different native byte orders can communicate consistently.
     */
    static std::vector<uint8_t> encodeTelemetry(
        const TelemetryMessage& message
    ) {
        std::vector<uint8_t> output;
        output.reserve(30);

        output.push_back(PROTOCOL_VERSION);
        output.push_back(
            static_cast<uint8_t>(MessageType::Telemetry)
        );

        appendUint64(output, message.sequence);
        appendUint32(output, message.sensorId);
        appendDouble(output, message.temperatureC);
        appendUint64(output, message.timestampMs);

        return output;
    }

    static TelemetryMessage decodeTelemetry(
        const std::vector<uint8_t>& data
    ) {
        require(
            data.size() == 30,
            "invalid telemetry packet size"
        );

        std::size_t offset = 0;

        const uint8_t version = data[offset++];
        const auto type =
            static_cast<MessageType>(data[offset++]);

        require(
            version == PROTOCOL_VERSION,
            "unsupported protocol version"
        );

        require(
            type == MessageType::Telemetry,
            "unexpected message type"
        );

        TelemetryMessage message;

        message.sequence = readUint64(data, offset);
        message.sensorId = readUint32(data, offset);
        message.temperatureC = readDouble(data, offset);
        message.timestampMs = readUint64(data, offset);

        require(
            offset == data.size(),
            "unexpected trailing data"
        );

        require(
            message.temperatureC >= -100.0 &&
            message.temperatureC <= 200.0,
            "temperature outside configured safety range"
        );

        return message;
    }

    static std::vector<uint8_t> encodeAcknowledgement(
        uint64_t sequence
    ) {
        std::vector<uint8_t> output;
        output.reserve(10);

        output.push_back(PROTOCOL_VERSION);
        output.push_back(
            static_cast<uint8_t>(MessageType::Acknowledgement)
        );

        appendUint64(output, sequence);

        return output;
    }

    static uint64_t decodeAcknowledgement(
        const std::vector<uint8_t>& data
    ) {
        require(
            data.size() == 10,
            "invalid acknowledgement size"
        );

        std::size_t offset = 0;

        const uint8_t version = data[offset++];
        const auto type =
            static_cast<MessageType>(data[offset++]);

        require(
            version == PROTOCOL_VERSION,
            "unsupported acknowledgement version"
        );

        require(
            type == MessageType::Acknowledgement,
            "unexpected acknowledgement type"
        );

        return readUint64(data, offset);
    }
};

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

struct GatewayStatistics {
    uint64_t receivedDatagrams = 0;
    uint64_t acceptedTelemetry = 0;
    uint64_t malformedDatagrams = 0;
    uint64_t duplicates = 0;
    uint64_t estimatedMissing = 0;
    uint64_t stalePackets = 0;
    uint64_t acknowledgementsSent = 0;
};

std::ostream& operator<<(
    std::ostream& output,
    const GatewayStatistics& statistics
) {
    output
        << "Received datagrams:   "
        << statistics.receivedDatagrams << '\n'
        << "Accepted telemetry:   "
        << statistics.acceptedTelemetry << '\n'
        << "Malformed datagrams:  "
        << statistics.malformedDatagrams << '\n'
        << "Duplicates:            "
        << statistics.duplicates << '\n'
        << "Estimated missing:     "
        << statistics.estimatedMissing << '\n'
        << "Stale packets:         "
        << statistics.stalePackets << '\n'
        << "ACKs sent:             "
        << statistics.acknowledgementsSent << '\n';

    return output;
}

// -----------------------------------------------------------------------------
// Sensor state
// -----------------------------------------------------------------------------

struct SensorState {
    uint64_t highestSequence = 0;
    double latestTemperature = 0.0;
    uint64_t latestTimestampMs = 0;
    bool initialized = false;
};

class SensorRegistry {
public:
    /*
     * A production system must bound the number of senders/sensors that it
     * will remember. This example uses a fixed maximum.
     */
    explicit SensorRegistry(std::size_t maximumSensors)
        : maximumSensors_(maximumSensors) {}

    SensorState& getOrCreate(uint32_t sensorId) {
        auto iterator = states_.find(sensorId);

        if (iterator != states_.end()) {
            return iterator->second;
        }

        require(
            states_.size() < maximumSensors_,
            "sensor registry capacity exceeded"
        );

        return states_[sensorId];
    }

    std::size_t size() const {
        return states_.size();
    }

private:
    std::size_t maximumSensors_;
    std::unordered_map<uint32_t, SensorState> states_;
};

// -----------------------------------------------------------------------------
// Telemetry gateway
// -----------------------------------------------------------------------------

class TelemetryGateway {
public:
    explicit TelemetryGateway(
        std::size_t maximumSensors = 1024
    )
        : registry_(maximumSensors) {}

    void process(
        const std::vector<uint8_t>& datagram
    ) {
        ++statistics_.receivedDatagrams;

        try {
            TelemetryMessage message =
                Protocol::decodeTelemetry(datagram);

            SensorState& state =
                registry_.getOrCreate(message.sensorId);

            if (!state.initialized) {
                state.initialized = true;
                state.highestSequence = message.sequence;
                state.latestTemperature =
                    message.temperatureC;
                state.latestTimestampMs =
                    message.timestampMs;

                ++statistics_.acceptedTelemetry;
                return;
            }

            if (message.sequence == state.highestSequence) {
                ++statistics_.duplicates;
                return;
            }

            if (message.sequence < state.highestSequence) {
                ++statistics_.stalePackets;
                return;
            }

            if (
                message.sequence >
                state.highestSequence + 1
            ) {
                statistics_.estimatedMissing +=
                    message.sequence -
                    state.highestSequence -
                    1;
            }

            state.highestSequence = message.sequence;
            state.latestTemperature =
                message.temperatureC;
            state.latestTimestampMs =
                message.timestampMs;

            ++statistics_.acceptedTelemetry;
        }
        catch (const std::exception&) {
            ++statistics_.malformedDatagrams;
        }
    }

    const GatewayStatistics& statistics() const {
        return statistics_;
    }

    std::size_t sensorCount() const {
        return registry_.size();
    }

private:
    SensorRegistry registry_;
    GatewayStatistics statistics_;
};

// -----------------------------------------------------------------------------
// UDP socket wrapper
// -----------------------------------------------------------------------------

class UdpSocket {
public:
    UdpSocket() {
        descriptor_ = ::socket(
            AF_INET,
            SOCK_DGRAM,
            0
        );

        if (descriptor_ < 0) {
            throw std::runtime_error(
                "socket creation failed: " +
                std::string(std::strerror(errno))
            );
        }
    }

    ~UdpSocket() {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    int descriptor() const {
        return descriptor_;
    }

    uint16_t bindLoopback(uint16_t port = EPHEMERAL_PORT) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);

        if (
            ::inet_pton(
                AF_INET,
                LOOPBACK_ADDRESS,
                &address.sin_addr
            ) != 1
        ) {
            throw std::runtime_error(
                "failed to parse loopback address"
            );
        }

        if (
            ::bind(
                descriptor_,
                reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)
            ) < 0
        ) {
            throw std::runtime_error(
                "bind failed: " +
                std::string(std::strerror(errno))
            );
        }

        sockaddr_in actual{};
        socklen_t length = sizeof(actual);

        if (
            ::getsockname(
                descriptor_,
                reinterpret_cast<sockaddr*>(&actual),
                &length
            ) < 0
        ) {
            throw std::runtime_error(
                "getsockname failed"
            );
        }

        return ntohs(actual.sin_port);
    }

    void setReceiveTimeoutMilliseconds(
        int milliseconds
    ) {
        timeval timeout{};
        timeout.tv_sec = milliseconds / 1000;
        timeout.tv_usec =
            (milliseconds % 1000) * 1000;

        if (
            ::setsockopt(
                descriptor_,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &timeout,
                sizeof(timeout)
            ) < 0
        ) {
            throw std::runtime_error(
                "failed to configure receive timeout"
            );
        }
    }

    void sendTo(
        const std::vector<uint8_t>& data,
        const std::string& address,
        uint16_t port
    ) {
        sockaddr_in destination{};
        destination.sin_family = AF_INET;
        destination.sin_port = htons(port);

        if (
            ::inet_pton(
                AF_INET,
                address.c_str(),
                &destination.sin_addr
            ) != 1
        ) {
            throw std::runtime_error(
                "invalid destination address"
            );
        }

        const ssize_t sent = ::sendto(
            descriptor_,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<const sockaddr*>(&destination),
            sizeof(destination)
        );

        if (sent < 0) {
            throw std::runtime_error(
                "sendto failed: " +
                std::string(std::strerror(errno))
            );
        }

        require(
            static_cast<std::size_t>(sent) == data.size(),
            "unexpected partial UDP send"
        );
    }

    std::vector<uint8_t> receiveFrom(
        std::size_t maximumSize
    ) {
        std::vector<uint8_t> buffer(maximumSize);

        sockaddr_in source{};
        socklen_t sourceLength = sizeof(source);

        const ssize_t received = ::recvfrom(
            descriptor_,
            buffer.data(),
            buffer.size(),
            0,
            reinterpret_cast<sockaddr*>(&source),
            &sourceLength
        );

        if (received < 0) {
            throw std::runtime_error(
                "recvfrom failed: " +
                std::string(std::strerror(errno))
            );
        }

        buffer.resize(static_cast<std::size_t>(received));
        return buffer;
    }

private:
    int descriptor_ = -1;
};

// -----------------------------------------------------------------------------
// Local UDP gateway server
// -----------------------------------------------------------------------------

class GatewayServer {
public:
    GatewayServer()
        : socket_(),
          gateway_(128) {}

    uint16_t start() {
        port_ = socket_.bindLoopback();
        socket_.setReceiveTimeoutMilliseconds(2000);
        return port_;
    }

    void processOne() {
        try {
            const auto datagram =
                socket_.receiveFrom(MAX_DATAGRAM_SIZE);

            gateway_.process(datagram);
        }
        catch (const std::exception& error) {
            /*
             * A receive timeout is expected in a real server loop. This
             * example simply reports it and allows the caller to decide
             * whether the service should continue.
             */
            if (
                std::string(error.what()).find(
                    "recvfrom failed"
                ) != std::string::npos
            ) {
                return;
            }

            throw;
        }
    }

    uint16_t port() const {
        return port_;
    }

    const TelemetryGateway& gateway() const {
        return gateway_;
    }

private:
    UdpSocket socket_;
    TelemetryGateway gateway_;
    uint16_t port_ = 0;
};

// -----------------------------------------------------------------------------
// Direct local request/response demonstration
// -----------------------------------------------------------------------------

void demonstrateLocalUdp() {
    std::cout
        << "\n============================================================\n"
        << "LOCAL UDP REQUEST/RESPONSE\n"
        << "============================================================\n";

    UdpSocket server;
    const uint16_t serverPort =
        server.bindLoopback();

    server.setReceiveTimeoutMilliseconds(1000);

    UdpSocket client;

    const std::string message =
        "industrial telemetry gateway";

    std::vector<uint8_t> payload(
        message.begin(),
        message.end()
    );

    client.sendTo(
        payload,
        LOOPBACK_ADDRESS,
        serverPort
    );

    const auto received =
        server.receiveFrom(4096);

    std::string receivedText(
        received.begin(),
        received.end()
    );

    std::cout
        << "Server received: "
        << receivedText
        << '\n';

    std::vector<uint8_t> response(
        {'o', 'k', ':', ' ', 'r', 'e', 'c', 'e', 'i', 'v', 'e', 'd'}
    );

    server.sendTo(
        response,
        LOOPBACK_ADDRESS,
        0
    );

    /*
     * The preceding send is intentionally not used as a client response,
     * because a server must know the source port from recvfrom(). The
     * production-style gateway below demonstrates the correct address-aware
     * pattern.
     */
    std::cout
        << "UDP datagrams preserve message boundaries.\n";
}

// -----------------------------------------------------------------------------
// Correct address-aware gateway transaction
// -----------------------------------------------------------------------------

class AddressAwareGatewayServer {
public:
    uint16_t start() {
        port_ = socket_.bindLoopback();
        socket_.setReceiveTimeoutMilliseconds(1000);
        return port_;
    }

    void receiveTelemetryAndAck() {
        std::array<uint8_t, MAX_DATAGRAM_SIZE> buffer{};

        sockaddr_in source{};
        socklen_t sourceLength = sizeof(source);

        const ssize_t received = ::recvfrom(
            socket_.descriptor(),
            buffer.data(),
            buffer.size(),
            0,
            reinterpret_cast<sockaddr*>(&source),
            &sourceLength
        );

        if (received < 0) {
            throw std::runtime_error(
                "gateway recvfrom failed"
            );
        }

        std::vector<uint8_t> datagram(
            buffer.begin(),
            buffer.begin() + received
        );

        gateway_.process(datagram);

        /*
         * Decode only after the gateway has validated the datagram. In a
         * larger implementation, processing and response generation would
         * normally be combined into a structured result.
         */
        try {
            const auto telemetry =
                Protocol::decodeTelemetry(datagram);

            const auto acknowledgement =
                Protocol::encodeAcknowledgement(
                    telemetry.sequence
                );

            const ssize_t sent = ::sendto(
                socket_.descriptor(),
                acknowledgement.data(),
                acknowledgement.size(),
                0,
                reinterpret_cast<const sockaddr*>(&source),
                sourceLength
            );

            if (sent < 0) {
                throw std::runtime_error(
                    "ACK send failed"
                );
            }
        }
        catch (const std::exception&) {
            /*
             * Malformed datagrams do not receive an acknowledgement.
             * The application protocol could choose another policy.
             */
        }
    }

    uint16_t port() const {
        return port_;
    }

    const TelemetryGateway& gateway() const {
        return gateway_;
    }

private:
    UdpSocket socket_;
    TelemetryGateway gateway_;
    uint16_t port_ = 0;
};

// -----------------------------------------------------------------------------
// Telemetry sender
// -----------------------------------------------------------------------------

class TelemetrySender {
public:
    explicit TelemetrySender(uint32_t sensorId)
        : sensorId_(sensorId) {}

    std::vector<uint8_t> createPacket(
        uint64_t sequence,
        double temperature
    ) const {
        const auto now =
            std::chrono::duration_cast<
                std::chrono::milliseconds
            >(
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

        TelemetryMessage message;
        message.sequence = sequence;
        message.sensorId = sensorId_;
        message.temperatureC = temperature;
        message.timestampMs =
            static_cast<uint64_t>(now);

        return Protocol::encodeTelemetry(message);
    }

private:
    uint32_t sensorId_;
};

// -----------------------------------------------------------------------------
// Application-level reliability client
// -----------------------------------------------------------------------------

class ReliableUdpClient {
public:
    explicit ReliableUdpClient(
        uint16_t destinationPort
    )
        : destinationPort_(destinationPort) {
        socket_.setReceiveTimeoutMilliseconds(250);
    }

    bool sendWithRetry(
        const std::vector<uint8_t>& payload,
        uint64_t expectedSequence,
        int maximumAttempts = 3
    ) {
        for (
            int attempt = 1;
            attempt <= maximumAttempts;
            ++attempt
        ) {
            socket_.sendTo(
                payload,
                LOOPBACK_ADDRESS,
                destinationPort_
            );

            try {
                const auto response =
                    socket_.receiveFrom(1024);

                const uint64_t acknowledged =
                    Protocol::decodeAcknowledgement(
                        response
                    );

                if (
                    acknowledged == expectedSequence
                ) {
                    std::cout
                        << "Sequence "
                        << expectedSequence
                        << " acknowledged on attempt "
                        << attempt
                        << '\n';

                    return true;
                }
            }
            catch (const std::exception&) {
                std::cout
                    << "Sequence "
                    << expectedSequence
                    << " timed out or received an invalid ACK on attempt "
                    << attempt
                    << '\n';
            }
        }

        return false;
    }

private:
    UdpSocket socket_;
    uint16_t destinationPort_;
};

// -----------------------------------------------------------------------------
// Lossy network simulation
// -----------------------------------------------------------------------------

class LossyChannel {
public:
    LossyChannel(
        double lossProbability,
        double duplicateProbability,
        unsigned seed
    )
        : lossProbability_(lossProbability),
          duplicateProbability_(duplicateProbability),
          generator_(seed),
          distribution_(0.0, 1.0) {
        require(
            lossProbability_ >= 0.0 &&
            lossProbability_ <= 1.0,
            "invalid loss probability"
        );

        require(
            duplicateProbability_ >= 0.0 &&
            duplicateProbability_ <= 1.0,
            "invalid duplicate probability"
        );
    }

    std::vector<std::vector<uint8_t>> transmit(
        const std::vector<uint8_t>& packet
    ) {
        if (distribution_(generator_) <
            lossProbability_) {
            return {};
        }

        std::vector<std::vector<uint8_t>> result;
        result.push_back(packet);

        if (
            distribution_(generator_) <
            duplicateProbability_
        ) {
            result.push_back(packet);
        }

        return result;
    }

private:
    double lossProbability_;
    double duplicateProbability_;
    std::mt19937 generator_;
    std::uniform_real_distribution<double> distribution_;
};

void demonstrateLossSimulation() {
    std::cout
        << "\n============================================================\n"
        << "LOSS AND DUPLICATION SIMULATION\n"
        << "============================================================\n";

    LossyChannel channel(
        0.20,
        0.10,
        42
    );

    std::size_t deliveredCopies = 0;
    std::size_t duplicateEvents = 0;

    for (uint64_t sequence = 1; sequence <= 100; ++sequence) {
        std::vector<uint8_t> packet(
            {'d', 'a', 't', 'a'}
        );

        const auto copies =
            channel.transmit(packet);

        deliveredCopies += copies.size();

        if (copies.size() == 2) {
            ++duplicateEvents;
        }
    }

    std::cout
        << "Original packets: 100\n"
        << "Delivered copies: "
        << deliveredCopies
        << '\n'
        << "Duplicate events: "
        << duplicateEvents
        << '\n';

    std::cout
        << "A simulation can test recovery policies without disrupting a real network.\n";
}

// -----------------------------------------------------------------------------
// Security-oriented validation
// -----------------------------------------------------------------------------

void demonstrateSecurityValidation() {
    std::cout
        << "\n============================================================\n"
        << "SECURITY VALIDATION\n"
        << "============================================================\n";

    TelemetrySender sender(17);

    const auto valid =
        sender.createPacket(1, 21.5);

    try {
        const auto message =
            Protocol::decodeTelemetry(valid);

        std::cout
            << "Valid packet accepted: sensor="
            << message.sensorId
            << ", temperature="
            << message.temperatureC
            << '\n';
    }
    catch (const std::exception& error) {
        std::cout
            << "Unexpected validation error: "
            << error.what()
            << '\n';
    }

    std::vector<uint8_t> malformed = {
        0xFF, 0xFF, 0x00
    };

    try {
        Protocol::decodeTelemetry(malformed);
        std::cout
            << "ERROR: malformed packet was accepted\n";
    }
    catch (const std::exception& error) {
        std::cout
            << "Malformed packet rejected: "
            << error.what()
            << '\n';
    }

    std::cout
        << "\nUDP security considerations:\n"
        << "- source addresses are not authentication credentials\n"
        << "- input must be bounded and validated\n"
        << "- sender-controlled state should be bounded\n"
        << "- rate limiting may be necessary\n"
        << "- replay protection may be necessary\n"
        << "- confidentiality requires encryption\n"
        << "- integrity/authentication requires cryptographic protection\n"
        << "- reflection and amplification must be considered\n";
}

// -----------------------------------------------------------------------------
// Edge cases
// -----------------------------------------------------------------------------

void demonstrateEdgeCases() {
    std::cout
        << "\n============================================================\n"
        << "EDGE CASES\n"
        << "============================================================\n";

    TelemetryGateway gateway(2);

    TelemetrySender sender(100);

    auto first =
        sender.createPacket(1, 20.0);

    auto gap =
        sender.createPacket(4, 21.0);

    auto duplicate =
        sender.createPacket(4, 21.0);

    auto stale =
        sender.createPacket(2, 19.0);

    gateway.process(first);
    gateway.process(gap);
    gateway.process(duplicate);
    gateway.process(stale);

    std::cout << gateway.statistics();

    std::cout
        << "\nExpected interpretation:\n"
        << "- sequence 1 establishes state\n"
        << "- sequence 4 creates an estimated gap of 2 and becomes newest\n"
        << "- another sequence 4 is a duplicate\n"
        << "- sequence 2 is stale after sequence 4 has been accepted\n";
}

// -----------------------------------------------------------------------------
// Performance benchmark
// -----------------------------------------------------------------------------

void benchmarkSerialization(std::size_t iterations) {
    std::cout
        << "\n============================================================\n"
        << "SERIALIZATION BENCHMARK\n"
        << "============================================================\n";

    TelemetryMessage message;
    message.sequence = 12345;
    message.sensorId = 77;
    message.temperatureC = 22.75;
    message.timestampMs = 123456789;

    const auto started =
        std::chrono::steady_clock::now();

    std::size_t bytesProduced = 0;

    for (std::size_t i = 0; i < iterations; ++i) {
        message.sequence = i;

        const auto encoded =
            Protocol::encodeTelemetry(message);

        const auto decoded =
            Protocol::decodeTelemetry(encoded);

        bytesProduced += encoded.size();

        require(
            decoded.sequence == i,
            "benchmark round-trip failed"
        );
    }

    const auto finished =
        std::chrono::steady_clock::now();

    const double milliseconds =
        std::chrono::duration<double, std::milli>(
            finished - started
        ).count();

    std::cout
        << "Iterations: "
        << iterations
        << '\n'
        << "Bytes produced: "
        << bytesProduced
        << '\n'
        << "Elapsed: "
        << std::fixed
        << std::setprecision(3)
        << milliseconds
        << " ms\n";

    if (milliseconds > 0.0) {
        std::cout
            << "Approximate operations/sec: "
            << (
                static_cast<double>(iterations) /
                (milliseconds / 1000.0)
            )
            << '\n';
    }
}

// -----------------------------------------------------------------------------
// Design explanation
// -----------------------------------------------------------------------------

void printArchitecture() {
    std::cout
        << "\n============================================================\n"
        << "ARCHITECTURE\n"
        << "============================================================\n";

    std::cout
        << R"(
Sensor
  |
  | UDP datagram
  v
+-----------------------+
| UDP socket             |
+-----------------------+
  |
  v
+-----------------------+
| Protocol decoder       |
| version/type/length   |
+-----------------------+
  |
  v
+-----------------------+
| Validation             |
| range/format/state    |
+-----------------------+
  |
  v
+-----------------------+
| Sensor registry        |
| latest state/sequence |
+-----------------------+
  |
  v
+-----------------------+
| Statistics             |
| loss/duplicates/gaps  |
+-----------------------+

The case study deliberately keeps the transport layer small while putting
application semantics into explicit protocol and state-management classes.
)";
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "UDP FUNDAMENTALS: INDUSTRIAL TELEMETRY CASE STUDY\n";

        printArchitecture();

        demonstrateLocalUdp();

        std::cout
            << "\n============================================================\n"
            << "BINARY APPLICATION PROTOCOL\n"
            << "============================================================\n";

        TelemetrySender sender(17);

        const auto packet =
            sender.createPacket(1, 21.75);

        std::cout
            << "Telemetry packet size: "
            << packet.size()
            << " bytes\n";

        const auto decoded =
            Protocol::decodeTelemetry(packet);

        std::cout
            << "Decoded sensor ID: "
            << decoded.sensorId
            << '\n'
            << "Decoded sequence: "
            << decoded.sequence
            << '\n'
            << "Decoded temperature: "
            << decoded.temperatureC
            << " C\n";

        demonstrateEdgeCases();
        demonstrateSecurityValidation();
        demonstrateLossSimulation();

        benchmarkSerialization(100000);

        std::cout
            << "\n============================================================\n"
            << "UDP DESIGN TRADE-OFFS\n"
            << "============================================================\n";

        std::cout
            << R"(
UDP provides datagram transport with minimal built-in semantics.

The application must explicitly decide:

1. Is packet loss acceptable?
2. Is packet ordering required?
3. Are duplicates possible?
4. How should stale data be handled?
5. What is the maximum accepted message size?
6. How are malformed messages rejected?
7. Is authentication required?
8. Is confidentiality required?
9. Is rate limiting required?
10. What latency and jitter limits are acceptable?

For telemetry, the newest state may be more valuable than retransmitting
old measurements.

For transactional data, loss or duplication may be unacceptable, so the
application may need acknowledgements, retransmission, ordering, persistence,
or a different transport protocol.

The correct design depends on application semantics rather than on UDP being
intrinsically "better" or "worse" than TCP.
)";

        std::cout
            << "\nProgram completed successfully.\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
