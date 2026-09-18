#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <deque>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

/*
 * TCP Fundamentals: C++ Industry-Style Case Study
 *
 * Scenario:
 * ---------
 * A simplified reliable telemetry transport is modeled between an industrial
 * monitoring gateway and a central analytics server.
 *
 * The case study demonstrates:
 * - TCP three-way handshake
 * - flags
 * - sequence numbers
 * - cumulative ACKs
 * - advertised receive windows
 * - sliding-window transmission
 * - out-of-order delivery
 * - duplicate ACKs
 * - retransmission
 * - RTT/RTO estimation
 * - graceful FIN-based shutdown
 * - validation and failure conditions
 *
 * This is an educational TCP model, not a replacement for an operating
 * system's production TCP implementation.
 */

namespace tcp {

// -----------------------------------------------------------------------------
// Constants and utility functions
// -----------------------------------------------------------------------------

constexpr std::uint64_t TCP_SEQUENCE_SPACE = (1ULL << 32);

std::uint32_t wrapSequence(std::uint64_t value) {
    return static_cast<std::uint32_t>(
        value % TCP_SEQUENCE_SPACE
    );
}

std::string join(const std::vector<std::string>& values,
                 const std::string& separator) {
    std::ostringstream output;

    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i != 0) {
            output << separator;
        }
        output << values[i];
    }

    return output.str();
}


// -----------------------------------------------------------------------------
// TCP flags
// -----------------------------------------------------------------------------

enum class TCPFlag : std::uint16_t {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80
};

constexpr std::uint16_t operator|(TCPFlag left, TCPFlag right) {
    return static_cast<std::uint16_t>(left) |
           static_cast<std::uint16_t>(right);
}

constexpr bool hasFlag(std::uint16_t flags, TCPFlag flag) {
    return (flags &
            static_cast<std::uint16_t>(flag)) != 0;
}

std::string flagString(std::uint16_t flags) {
    std::vector<std::string> names;

    if (hasFlag(flags, TCPFlag::FIN)) names.emplace_back("FIN");
    if (hasFlag(flags, TCPFlag::SYN)) names.emplace_back("SYN");
    if (hasFlag(flags, TCPFlag::RST)) names.emplace_back("RST");
    if (hasFlag(flags, TCPFlag::PSH)) names.emplace_back("PSH");
    if (hasFlag(flags, TCPFlag::ACK)) names.emplace_back("ACK");
    if (hasFlag(flags, TCPFlag::URG)) names.emplace_back("URG");
    if (hasFlag(flags, TCPFlag::ECE)) names.emplace_back("ECE");
    if (hasFlag(flags, TCPFlag::CWR)) names.emplace_back("CWR");

    return names.empty() ? "NONE" : join(names, ",");
}


// -----------------------------------------------------------------------------
// TCP segment
// -----------------------------------------------------------------------------

struct TCPSegment {
    std::string source;
    std::string destination;

    std::uint32_t sequenceNumber = 0;
    std::optional<std::uint32_t> acknowledgmentNumber;

    std::uint16_t flags = 0;

    std::vector<std::uint8_t> payload;

    std::uint32_t advertisedWindow = 65535;

    std::size_t sequenceSpaceConsumed() const {
        std::size_t consumed = payload.size();

        if (hasFlag(flags, TCPFlag::SYN)) {
            ++consumed;
        }

        if (hasFlag(flags, TCPFlag::FIN)) {
            ++consumed;
        }

        return consumed;
    }

    std::string describe() const {
        std::ostringstream output;

        output
            << source << " -> " << destination
            << " | SEQ=" << sequenceNumber
            << " | ACK=";

        if (acknowledgmentNumber.has_value()) {
            output << acknowledgmentNumber.value();
        } else {
            output << "-";
        }

        output
            << " | FLAGS=" << flagString(flags)
            << " | PAYLOAD=" << payload.size()
            << " | WINDOW=" << advertisedWindow;

        return output.str();
    }
};


// -----------------------------------------------------------------------------
// Receive window
// -----------------------------------------------------------------------------

class ReceiveWindow {
public:
    explicit ReceiveWindow(std::size_t capacity)
        : capacity_(capacity) {}

    std::size_t advertisedWindow() const {
        return capacity_ - buffered_;
    }

    bool receive(std::size_t bytes) {
        if (bytes > advertisedWindow()) {
            return false;
        }

        buffered_ += bytes;
        return true;
    }

    void applicationConsumes(std::size_t bytes) {
        if (bytes > buffered_) {
            buffered_ = 0;
        } else {
            buffered_ -= bytes;
        }
    }

private:
    std::size_t capacity_;
    std::size_t buffered_ = 0;
};


// -----------------------------------------------------------------------------
// TCP receiver with out-of-order buffering
// -----------------------------------------------------------------------------

class TCPReceiver {
public:
    explicit TCPReceiver(std::uint32_t initialSequence)
        : nextExpected_(initialSequence) {}

    std::uint32_t receive(const TCPSegment& segment) {
        if (segment.payload.empty()) {
            return nextExpected_;
        }

        const std::uint32_t sequence = segment.sequenceNumber;

        if (sequence == nextExpected_) {
            deliver(segment.payload);

            // Once the missing segment arrives, buffered contiguous segments
            // can immediately become deliverable.
            while (true) {
                auto iterator = outOfOrder_.find(nextExpected_);

                if (iterator == outOfOrder_.end()) {
                    break;
                }

                deliver(iterator->second);
                outOfOrder_.erase(iterator);
            }
        } else if (sequence > nextExpected_) {
            // Future data is retained. A production TCP implementation has
            // much more sophisticated overlap and SACK handling.
            outOfOrder_.try_emplace(sequence, segment.payload);
        } else {
            // The segment begins before the current receive point.
            // It may be a duplicate or an overlapping segment.
        }

        return nextExpected_;
    }

    std::string dataAsString() const {
        return std::string(
            deliveredData_.begin(),
            deliveredData_.end()
        );
    }

    std::size_t bufferedOutOfOrderSegments() const {
        return outOfOrder_.size();
    }

private:
    void deliver(const std::vector<std::uint8_t>& payload) {
        deliveredData_.insert(
            deliveredData_.end(),
            payload.begin(),
            payload.end()
        );

        nextExpected_ =
            wrapSequence(
                static_cast<std::uint64_t>(nextExpected_) +
                payload.size()
            );
    }

    std::uint32_t nextExpected_;

    std::map<
        std::uint32_t,
        std::vector<std::uint8_t>
    > outOfOrder_;

    std::vector<std::uint8_t> deliveredData_;
};


// -----------------------------------------------------------------------------
// RTT estimator
// -----------------------------------------------------------------------------

class RTTEstimator {
public:
    void update(double measuredRTT) {
        if (!std::isfinite(measuredRTT) || measuredRTT <= 0.0) {
            throw std::invalid_argument(
                "RTT must be positive"
            );
        }

        constexpr double alpha = 1.0 / 8.0;
        constexpr double beta = 1.0 / 4.0;

        if (!smoothedRTT_.has_value()) {
            smoothedRTT_ = measuredRTT;
            rttVariation_ = measuredRTT / 2.0;
        } else {
            const double variation =
                std::abs(
                    smoothedRTT_.value() -
                    measuredRTT
                );

            rttVariation_ =
                (1.0 - beta) * rttVariation_.value() +
                beta * variation;

            smoothedRTT_ =
                (1.0 - alpha) * smoothedRTT_.value() +
                alpha * measuredRTT;
        }

        retransmissionTimeout_ =
            smoothedRTT_.value() +
            4.0 * rttVariation_.value();
    }

    std::optional<double> smoothedRTT() const {
        return smoothedRTT_;
    }

    std::optional<double> rttVariation() const {
        return rttVariation_;
    }

    std::optional<double> retransmissionTimeout() const {
        return retransmissionTimeout_;
    }

private:
    std::optional<double> smoothedRTT_;
    std::optional<double> rttVariation_;
    std::optional<double> retransmissionTimeout_;
};


// -----------------------------------------------------------------------------
// Sliding-window sender
// -----------------------------------------------------------------------------

struct OutstandingSegment {
    TCPSegment segment;
    double sentAtSeconds = 0.0;
};

class TCPSender {
public:
    TCPSender(
        std::uint32_t initialSequence,
        std::uint32_t receiveWindow,
        std::uint32_t congestionWindow
    )
        : oldestUnacknowledged_(initialSequence),
          nextSequence_(initialSequence),
          receiveWindow_(receiveWindow),
          congestionWindow_(congestionWindow) {}

    std::uint32_t effectiveWindow() const {
        return std::min(
            receiveWindow_,
            congestionWindow_
        );
    }

    std::uint32_t bytesInFlight() const {
        return nextSequence_ - oldestUnacknowledged_;
    }

    std::uint32_t availableCapacity() const {
        const std::uint32_t window = effectiveWindow();

        if (bytesInFlight() >= window) {
            return 0;
        }

        return window - bytesInFlight();
    }

    TCPSegment send(
        const std::vector<std::uint8_t>& payload,
        double currentTime
    ) {
        if (payload.empty()) {
            throw std::invalid_argument(
                "Cannot send an empty payload"
            );
        }

        const std::uint32_t capacity =
            availableCapacity();

        if (capacity == 0) {
            throw std::runtime_error(
                "Effective send window is full"
            );
        }

        const std::size_t actualLength =
            std::min<std::size_t>(
                capacity,
                payload.size()
            );

        TCPSegment segment;

        segment.source = "GATEWAY";
        segment.destination = "ANALYTICS-SERVER";
        segment.sequenceNumber = nextSequence_;
        segment.flags =
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        segment.payload.assign(
            payload.begin(),
            payload.begin() + actualLength
        );

        segment.advertisedWindow =
            receiveWindow_;

        outstanding_.push_back({
            segment,
            currentTime
        });

        nextSequence_ =
            wrapSequence(
                static_cast<std::uint64_t>(nextSequence_) +
                actualLength
            );

        return segment;
    }

    std::size_t acknowledge(
        std::uint32_t acknowledgmentNumber
    ) {
        const std::uint32_t previous =
            oldestUnacknowledged_;

        if (acknowledgmentNumber == previous) {
            return 0;
        }

        // This simplified model assumes the ACK is ahead in the normal
        // non-wraparound portion of the sequence space.
        if (acknowledgmentNumber > nextSequence_) {
            throw std::invalid_argument(
                "ACK acknowledges unsent data"
            );
        }

        oldestUnacknowledged_ =
            acknowledgmentNumber;

        while (!outstanding_.empty()) {
            const auto& first =
                outstanding_.front().segment;

            const std::uint32_t end =
                wrapSequence(
                    static_cast<std::uint64_t>(
                        first.sequenceNumber
                    ) +
                    first.payload.size()
                );

            if (end <= acknowledgmentNumber) {
                outstanding_.pop_front();
            } else {
                break;
            }
        }

        return acknowledgmentNumber - previous;
    }

    const std::deque<OutstandingSegment>&
    outstanding() const {
        return outstanding_;
    }

private:
    std::uint32_t oldestUnacknowledged_;
    std::uint32_t nextSequence_;

    std::uint32_t receiveWindow_;
    std::uint32_t congestionWindow_;

    std::deque<OutstandingSegment> outstanding_;
};


// -----------------------------------------------------------------------------
// Duplicate ACK detector
// -----------------------------------------------------------------------------

class DuplicateACKDetector {
public:
    bool observe(std::uint32_t acknowledgmentNumber) {
        if (!lastACK_.has_value()) {
            lastACK_ = acknowledgmentNumber;
            duplicateCount_ = 0;
            return false;
        }

        if (acknowledgmentNumber == lastACK_.value()) {
            ++duplicateCount_;
        } else if (acknowledgmentNumber > lastACK_.value()) {
            lastACK_ = acknowledgmentNumber;
            duplicateCount_ = 0;
        } else {
            // Older ACK. Ignore it in this simplified model.
            return false;
        }

        return duplicateCount_ >= 3;
    }

    std::size_t duplicateCount() const {
        return duplicateCount_;
    }

private:
    std::optional<std::uint32_t> lastACK_;
    std::size_t duplicateCount_ = 0;
};


// -----------------------------------------------------------------------------
// TCP connection state
// -----------------------------------------------------------------------------

enum class TCPState {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    LAST_ACK,
    CLOSING,
    TIME_WAIT
};

std::string stateName(TCPState state) {
    switch (state) {
        case TCPState::CLOSED: return "CLOSED";
        case TCPState::LISTEN: return "LISTEN";
        case TCPState::SYN_SENT: return "SYN-SENT";
        case TCPState::SYN_RECEIVED: return "SYN-RECEIVED";
        case TCPState::ESTABLISHED: return "ESTABLISHED";
        case TCPState::FIN_WAIT_1: return "FIN-WAIT-1";
        case TCPState::FIN_WAIT_2: return "FIN-WAIT-2";
        case TCPState::CLOSE_WAIT: return "CLOSE-WAIT";
        case TCPState::LAST_ACK: return "LAST-ACK";
        case TCPState::CLOSING: return "CLOSING";
        case TCPState::TIME_WAIT: return "TIME-WAIT";
    }

    return "UNKNOWN";
}


// -----------------------------------------------------------------------------
// Industrial telemetry transport case study
// -----------------------------------------------------------------------------

class TelemetryTransport {
public:
    TelemetryTransport(
        std::uint32_t gatewayISN,
        std::uint32_t serverISN,
        std::uint32_t receiveWindow,
        std::uint32_t congestionWindow,
        std::size_t maximumSegmentSize
    )
        : gatewayISN_(gatewayISN),
          serverISN_(serverISN),
          receiveWindow_(receiveWindow),
          congestionWindow_(congestionWindow),
          maximumSegmentSize_(maximumSegmentSize),
          receiver_(gatewayISN + 1),
          sender_(
              gatewayISN + 1,
              receiveWindow,
              congestionWindow
          ) {
        if (maximumSegmentSize_ == 0) {
            throw std::invalid_argument(
                "MSS must be positive"
            );
        }
    }

    void establishConnection() {
        std::cout << "\n=== Connection establishment ===\n";

        // Step 1: gateway sends SYN.
        TCPSegment syn;
        syn.source = "GATEWAY";
        syn.destination = "ANALYTICS-SERVER";
        syn.sequenceNumber = gatewayISN_;
        syn.flags =
            static_cast<std::uint16_t>(
                TCPFlag::SYN
            );

        std::cout << "1. " << syn.describe() << '\n';

        gatewayState_ = TCPState::SYN_SENT;
        serverState_ = TCPState::LISTEN;

        // Step 2: server sends SYN+ACK.
        TCPSegment synAck;
        synAck.source = "ANALYTICS-SERVER";
        synAck.destination = "GATEWAY";
        synAck.sequenceNumber = serverISN_;
        synAck.acknowledgmentNumber =
            wrapSequence(
                static_cast<std::uint64_t>(gatewayISN_) + 1
            );

        synAck.flags =
            static_cast<std::uint16_t>(
                TCPFlag::SYN
            ) |
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        std::cout << "2. " << synAck.describe() << '\n';

        gatewayState_ = TCPState::SYN_SENT;
        serverState_ = TCPState::SYN_RECEIVED;

        // Step 3: gateway confirms server ISN.
        TCPSegment ack;
        ack.source = "GATEWAY";
        ack.destination = "ANALYTICS-SERVER";
        ack.sequenceNumber =
            wrapSequence(
                static_cast<std::uint64_t>(gatewayISN_) + 1
            );

        ack.acknowledgmentNumber =
            wrapSequence(
                static_cast<std::uint64_t>(serverISN_) + 1
            );

        ack.flags =
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        std::cout << "3. " << ack.describe() << '\n';

        gatewayState_ = TCPState::ESTABLISHED;
        serverState_ = TCPState::ESTABLISHED;
    }

    std::vector<TCPSegment> createTelemetrySegments(
        const std::string& telemetry,
        double startTime
    ) {
        std::vector<TCPSegment> segments;

        std::vector<std::uint8_t> bytes(
            telemetry.begin(),
            telemetry.end()
        );

        std::size_t offset = 0;
        double currentTime = startTime;

        while (offset < bytes.size()) {
            const std::size_t length =
                std::min(
                    maximumSegmentSize_,
                    bytes.size() - offset
                );

            std::vector<std::uint8_t> chunk(
                bytes.begin() + offset,
                bytes.begin() + offset + length
            );

            TCPSegment segment =
                sender_.send(
                    chunk,
                    currentTime
                );

            segments.push_back(segment);

            offset += length;
            currentTime += 0.001;
        }

        return segments;
    }

    std::uint32_t deliver(
        const TCPSegment& segment
    ) {
        return receiver_.receive(segment);
    }

    std::size_t acknowledge(
        std::uint32_t acknowledgmentNumber
    ) {
        return sender_.acknowledge(
            acknowledgmentNumber
        );
    }

    const TCPReceiver& receiver() const {
        return receiver_;
    }

    const TCPSender& sender() const {
        return sender_;
    }

    TCPState gatewayState() const {
        return gatewayState_;
    }

    TCPState serverState() const {
        return serverState_;
    }

    void gracefulClose() {
        std::cout
            << "\n=== Graceful connection termination ===\n";

        const std::uint32_t gatewayFINSequence =
            senderNextSequenceForFIN();

        TCPSegment fin;
        fin.source = "GATEWAY";
        fin.destination = "ANALYTICS-SERVER";
        fin.sequenceNumber = gatewayFINSequence;
        fin.acknowledgmentNumber = serverISN_ + 1;
        fin.flags =
            static_cast<std::uint16_t>(
                TCPFlag::FIN
            ) |
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        std::cout << "1. " << fin.describe() << '\n';

        gatewayState_ = TCPState::FIN_WAIT_1;

        TCPSegment ack;
        ack.source = "ANALYTICS-SERVER";
        ack.destination = "GATEWAY";
        ack.sequenceNumber = serverISN_ + 1;
        ack.acknowledgmentNumber =
            wrapSequence(
                static_cast<std::uint64_t>(
                    gatewayFINSequence
                ) + 1
            );

        ack.flags =
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        std::cout << "2. " << ack.describe() << '\n';

        gatewayState_ = TCPState::FIN_WAIT_2;

        TCPSegment serverFIN;
        serverFIN.source = "ANALYTICS-SERVER";
        serverFIN.destination = "GATEWAY";
        serverFIN.sequenceNumber = serverISN_ + 1;
        serverFIN.acknowledgmentNumber =
            wrapSequence(
                static_cast<std::uint64_t>(
                    gatewayFINSequence
                ) + 1
            );

        serverFIN.flags =
            static_cast<std::uint16_t>(
                TCPFlag::FIN
            ) |
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        std::cout << "3. " << serverFIN.describe() << '\n';

        TCPSegment finalACK;
        finalACK.source = "GATEWAY";
        finalACK.destination = "ANALYTICS-SERVER";
        finalACK.sequenceNumber =
            wrapSequence(
                static_cast<std::uint64_t>(
                    gatewayFINSequence
                ) + 1
            );

        finalACK.acknowledgmentNumber =
            wrapSequence(
                static_cast<std::uint64_t>(
                    serverISN_
                ) + 2
            );

        finalACK.flags =
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );

        std::cout << "4. " << finalACK.describe() << '\n';

        gatewayState_ = TCPState::TIME_WAIT;
        serverState_ = TCPState::CLOSED;
    }

private:
    std::uint32_t senderNextSequenceForFIN() const {
        if (sender_.outstanding().empty()) {
            return gatewayISN_ + 1;
        }

        const auto& last =
            sender_.outstanding().back().segment;

        return wrapSequence(
            static_cast<std::uint64_t>(
                last.sequenceNumber
            ) +
            last.payload.size()
        );
    }

    std::uint32_t gatewayISN_;
    std::uint32_t serverISN_;

    std::uint32_t receiveWindow_;
    std::uint32_t congestionWindow_;
    std::size_t maximumSegmentSize_;

    TCPState gatewayState_ = TCPState::CLOSED;
    TCPState serverState_ = TCPState::CLOSED;

    TCPReceiver receiver_;
    TCPSender sender_;
};


// -----------------------------------------------------------------------------
// Lossy network model
// -----------------------------------------------------------------------------

class LossyNetwork {
public:
    explicit LossyNetwork(
        double lossProbability,
        std::uint32_t seed = 42
    )
        : lossProbability_(lossProbability),
          generator_(seed),
          distribution_(0.0, 1.0) {
        if (lossProbability_ < 0.0 ||
            lossProbability_ > 1.0) {
            throw std::invalid_argument(
                "Loss probability must be between 0 and 1"
            );
        }
    }

    bool transmit(const TCPSegment& segment) {
        const double randomValue =
            distribution_(generator_);

        const bool lost =
            randomValue < lossProbability_;

        if (lost) {
            std::cout
                << "NETWORK LOSS: SEQ="
                << segment.sequenceNumber
                << '\n';
            return false;
        }

        std::cout
            << "NETWORK DELIVERY: SEQ="
            << segment.sequenceNumber
            << '\n';

        return true;
    }

private:
    double lossProbability_;

    std::mt19937 generator_;
    std::uniform_real_distribution<double> distribution_;
};


// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

std::vector<std::uint8_t> makePayload(
    const std::string& value
) {
    return std::vector<std::uint8_t>(
        value.begin(),
        value.end()
    );
}

void printSection(const std::string& title) {
    std::cout
        << "\n"
        << std::string(78, '=')
        << "\n"
        << title
        << "\n"
        << std::string(78, '=')
        << "\n";
}


// -----------------------------------------------------------------------------
// Main case study
// -----------------------------------------------------------------------------

} // namespace tcp


int main() {
    using namespace tcp;

    try {
        printSection(
            "TCP Fundamentals: Industrial Telemetry Case Study"
        );

        std::cout
            << "Scenario: an industrial gateway sends ordered telemetry "
               "records to an analytics server.\n";

        // ---------------------------------------------------------------------
        // Handshake
        // ---------------------------------------------------------------------

        TelemetryTransport transport(
            1000,   // Gateway initial sequence number
            5000,   // Server initial sequence number
            5000,   // Receive window
            3000,   // Congestion window
            8       // Educational MSS
        );

        transport.establishConnection();

        assert(
            transport.gatewayState() ==
            TCPState::ESTABLISHED
        );

        assert(
            transport.serverState() ==
            TCPState::ESTABLISHED
        );

        // ---------------------------------------------------------------------
        // Telemetry segmentation
        // ---------------------------------------------------------------------

        printSection("Telemetry segmentation");

        const std::string telemetry =
            "TEMP=27.5;PRESSURE=101.3;STATUS=OK";

        const auto segments =
            transport.createTelemetrySegments(
                telemetry,
                0.0
            );

        for (const auto& segment : segments) {
            std::cout
                << segment.describe()
                << '\n';
        }

        // ---------------------------------------------------------------------
        // Deliberate out-of-order delivery
        // ---------------------------------------------------------------------

        printSection(
            "Out-of-order delivery and cumulative ACKs"
        );

        std::vector<TCPSegment> deliveryOrder =
            segments;

        if (deliveryOrder.size() >= 3) {
            // Deliver segment 0 first, then segment 2, then segment 1.
            std::swap(
                deliveryOrder[1],
                deliveryOrder[2]
            );
        }

        for (const auto& segment : deliveryOrder) {
            const std::uint32_t acknowledgment =
                transport.deliver(segment);

            std::cout
                << "Received SEQ="
                << segment.sequenceNumber
                << " -> cumulative ACK="
                << acknowledgment
                << '\n';
        }

        std::cout
            << "Reconstructed telemetry: "
            << transport.receiver().dataAsString()
            << '\n';

        // ---------------------------------------------------------------------
        // ACK sender
        // ---------------------------------------------------------------------

        printSection("Cumulative acknowledgment");

        const std::string expected =
            telemetry;

        assert(
            transport.receiver().dataAsString() ==
            expected
        );

        const std::uint32_t finalACK =
            1001 + static_cast<std::uint32_t>(
                telemetry.size()
            );

        const std::size_t acknowledged =
            transport.acknowledge(finalACK);

        std::cout
            << "ACK="
            << finalACK
            << " acknowledged "
            << acknowledged
            << " bytes.\n";

        std::cout
            << "Bytes in flight after ACK: "
            << transport.sender().bytesInFlight()
            << '\n';

        // ---------------------------------------------------------------------
        // Duplicate ACK and fast retransmission model
        // ---------------------------------------------------------------------

        printSection(
            "Duplicate ACK and fast retransmission"
        );

        DuplicateACKDetector detector;

        for (int i = 1; i <= 4; ++i) {
            const bool trigger =
                detector.observe(2000);

            std::cout
                << "Duplicate ACK #"
                << i
                << " -> fast retransmit="
                << std::boolalpha
                << trigger
                << '\n';
        }

        // ---------------------------------------------------------------------
        // RTT estimator
        // ---------------------------------------------------------------------

        printSection(
            "RTT and retransmission timeout estimation"
        );

        RTTEstimator estimator;

        const std::array<double, 5> rtts{
            0.080,
            0.095,
            0.090,
            0.110,
            0.085
        };

        std::cout
            << std::fixed
            << std::setprecision(4);

        for (double rtt : rtts) {
            estimator.update(rtt);

            std::cout
                << "Measured RTT="
                << rtt
                << " s, SRTT="
                << estimator.smoothedRTT().value()
                << " s, RTTVAR="
                << estimator.rttVariation().value()
                << " s, RTO="
                << estimator.retransmissionTimeout().value()
                << " s\n";
        }

        // ---------------------------------------------------------------------
        // Receive-window behavior
        // ---------------------------------------------------------------------

        printSection(
            "Flow-control receive window"
        );

        ReceiveWindow receiveWindow(10'000);

        std::cout
            << "Initial window: "
            << receiveWindow.advertisedWindow()
            << '\n';

        for (std::size_t amount : {2000U, 3000U, 4000U}) {
            const bool accepted =
                receiveWindow.receive(amount);

            std::cout
                << "Receive "
                << amount
                << " bytes -> accepted="
                << std::boolalpha
                << accepted
                << ", advertised window="
                << receiveWindow.advertisedWindow()
                << '\n';
        }

        receiveWindow.applicationConsumes(5000);

        std::cout
            << "After application consumption: "
            << receiveWindow.advertisedWindow()
            << '\n';

        // ---------------------------------------------------------------------
        // Lossy network
        // ---------------------------------------------------------------------

        printSection(
            "Lossy network and retransmission concept"
        );

        LossyNetwork network(
            0.25,
            12345
        );

        TCPSegment testSegment;
        testSegment.source = "GATEWAY";
        testSegment.destination = "ANALYTICS-SERVER";
        testSegment.sequenceNumber = 9000;
        testSegment.flags =
            static_cast<std::uint16_t>(
                TCPFlag::ACK
            );
        testSegment.payload =
            makePayload("critical");

        const bool delivered =
            network.transmit(testSegment);

        if (!delivered) {
            std::cout
                << "Sender would retain this segment and recover "
                   "through a loss-detection mechanism.\n";

            std::cout
                << "Possible mechanisms include a retransmission "
                   "timeout or duplicate-ACK-based recovery.\n";

            std::cout
                << "The retransmission should use the original "
                   "sequence range.\n";
        }

        // ---------------------------------------------------------------------
        // Bandwidth-delay product
        // ---------------------------------------------------------------------

        printSection(
            "Bandwidth-delay product"
        );

        constexpr double bandwidthBitsPerSecond =
            100'000'000.0;

        constexpr double roundTripTimeSeconds =
            0.100;

        const double bdpBytes =
            bandwidthBitsPerSecond *
            roundTripTimeSeconds /
            8.0;

        std::cout
            << "100 Mbps × 100 ms = "
            << bdpBytes
            << " bytes of bandwidth-delay product.\n";

        // ---------------------------------------------------------------------
        // Sequence-number wrap-around
        // ---------------------------------------------------------------------

        printSection(
            "32-bit sequence-number wrap-around"
        );

        const std::uint32_t nearEnd =
            std::numeric_limits<std::uint32_t>::max() - 2;

        for (std::uint64_t offset = 0; offset < 6; ++offset) {
            std::cout
                << "Offset "
                << offset
                << " -> sequence "
                << wrapSequence(
                    static_cast<std::uint64_t>(
                        nearEnd
                    ) +
                    offset
                )
                << '\n';
        }

        // ---------------------------------------------------------------------
        // Security considerations
        // ---------------------------------------------------------------------

        printSection(
            "Security considerations"
        );

        std::cout
            << "TCP does not encrypt telemetry payloads.\n"
            << "TCP does not provide cryptographic peer authentication.\n"
            << "Sequence-number randomization reduces some spoofing risks "
               "but is not authentication.\n"
            << "TLS can provide confidentiality and authentication above TCP.\n"
            << "SYN-flood protection and connection-rate controls can reduce "
               "resource exhaustion risks.\n";

        // ---------------------------------------------------------------------
        // Graceful close
        // ---------------------------------------------------------------------

        transport.gracefulClose();

        assert(
            transport.gatewayState() ==
            TCPState::TIME_WAIT
        );

        assert(
            transport.serverState() ==
            TCPState::CLOSED
        );

        // ---------------------------------------------------------------------
        // Edge cases
        // ---------------------------------------------------------------------

        printSection("Edge-case validation");

        try {
            RTTEstimator invalidEstimator;
            invalidEstimator.update(0.0);
            assert(false && "Zero RTT should have been rejected");
        } catch (const std::invalid_argument& error) {
            std::cout
                << "Correctly rejected invalid RTT: "
                << error.what()
                << '\n';
        }

        try {
            ReceiveWindow tinyWindow(10);

            const bool accepted =
                tinyWindow.receive(11);

            assert(!accepted);

            std::cout
                << "Correctly rejected data exceeding "
                   "advertised receive window.\n";
        } catch (const std::exception& error) {
            std::cout
                << "Unexpected receive-window error: "
                << error.what()
                << '\n';
        }

        // ---------------------------------------------------------------------
        // Final assertions
        // ---------------------------------------------------------------------

        printSection("Case-study validation");

        assert(
            transport.receiver().dataAsString() ==
            telemetry
        );

        assert(
            transport.sender().bytesInFlight() == 0
        );

        assert(
            estimator.smoothedRTT().has_value()
        );

        assert(
            estimator.retransmissionTimeout().has_value()
        );

        std::cout
            << "All TCP case-study assertions passed.\n";

        std::cout
            << "\nImportant architectural distinction:\n"
            << "Flow control protects the receiver.\n"
            << "Congestion control responds to network conditions.\n"
            << "Retransmission provides loss recovery.\n"
            << "ACK numbers communicate cumulative receive progress.\n"
            << "Sequence numbers identify byte positions.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
