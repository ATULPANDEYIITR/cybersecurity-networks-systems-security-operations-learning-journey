#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

/*
 * C++17 distributed log collection and governance engine.
 *
 * Models:
 * - Collection agents
 * - Structured log events
 * - Timestamp normalization
 * - Severity normalization
 * - Log validation
 * - Deduplication
 * - Bounded forwarding queues
 * - Batch delivery
 * - Dead-letter handling
 * - Retention and archival
 * - Operational metrics
 *
 * No external libraries.
 */

enum class Severity {
    Debug = 10,
    Info = 20,
    Warning = 30,
    Error = 40,
    Critical = 50
};

enum class LogState {
    Collected,
    Normalized,
    Queued,
    Forwarded,
    Failed,
    Archived
};

enum class SourceType {
    Json,
    Syslog
};

struct Agent {
    std::string id;
    std::string hostname;
    std::string environment;
    SourceType sourceType;
    bool enabled = true;
};

struct LogEvent {
    std::string eventId;
    std::string agentId;
    std::string hostname;
    std::string environment;
    std::string source;
    std::string timestamp;
    std::string message;
    Severity severity;
    std::string fingerprint;
    LogState state = LogState::Collected;
};

class ValidationError : public std::runtime_error {
public:
    explicit ValidationError(const std::string& message)
        : std::runtime_error(message) {}
};

class DeliveryError : public std::runtime_error {
public:
    explicit DeliveryError(const std::string& message)
        : std::runtime_error(message) {}
};

class Utility {
public:
    static std::string trim(const std::string& value) {
        const auto first = value.find_first_not_of(" \t\r\n");

        if (first == std::string::npos) {
            return "";
        }

        const auto last = value.find_last_not_of(" \t\r\n");

        return value.substr(first, last - first + 1);
    }

    static std::string lowercase(std::string value) {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            }
        );

        return value;
    }

    static std::string escape(const std::string& value) {
        std::string output;

        for (char c : value) {
            if (c == '"' || c == '\\') {
                output += '\\';
            }

            if (c == '\n') {
                output += "\\n";
            } else if (c == '\r') {
                output += "\\r";
            } else {
                output += c;
            }
        }

        return output;
    }

    static std::string redact(std::string message) {
        const std::vector<std::string> sensitive = {
            "password=",
            "token=",
            "secret=",
            "api_key="
        };

        std::string lower = lowercase(message);

        for (const auto& marker : sensitive) {
            std::size_t position = 0;

            while (
                (position = lower.find(marker, position))
                != std::string::npos
            ) {
                const std::size_t start =
                    position + marker.length();

                std::size_t end = message.find_first_of(
                    " ,;\t",
                    start
                );

                if (end == std::string::npos) {
                    end = message.length();
                }

                message.replace(
                    start,
                    end - start,
                    "[REDACTED]"
                );

                lower = lowercase(message);
                position = start + 10;
            }
        }

        return message;
    }

    static std::string makeId(int sequence) {
        return "event-" + std::to_string(sequence);
    }

    static std::string fingerprint(
        const LogEvent& event
    ) {
        const std::string input =
            event.agentId + "|" +
            event.hostname + "|" +
            event.timestamp + "|" +
            event.message + "|" +
            std::to_string(
                static_cast<int>(event.severity)
            );

        // FNV-1a is used for deterministic demonstration
        // fingerprints. Production systems should use SHA-256.
        std::uint64_t hash = 14695981039346656037ULL;

        for (unsigned char c : input) {
            hash ^= c;
            hash *= 1099511628211ULL;
        }

        std::ostringstream output;
        output << std::hex << hash;

        return output.str();
    }
};

class TimestampNormalizer {
public:
    static std::string normalize(
        const std::string& input
    ) {
        if (input.size() < 20) {
            throw ValidationError(
                "Timestamp must include an ISO-8601 timezone"
            );
        }

        std::tm value = {};

        std::istringstream stream(input.substr(0, 19));

        stream >> std::get_time(
            &value,
            "%Y-%m-%dT%H:%M:%S"
        );

        if (stream.fail()) {
            throw ValidationError(
                "Invalid timestamp format"
            );
        }

        const std::string timezone =
            input.substr(19);

        int offsetSeconds = 0;

        if (timezone == "Z") {
            offsetSeconds = 0;
        } else if (
            timezone.size() == 6 &&
            (timezone[0] == '+' || timezone[0] == '-')
        ) {
            if (
                timezone[3] != ':' ||
                !std::isdigit(
                    static_cast<unsigned char>(timezone[1])
                ) ||
                !std::isdigit(
                    static_cast<unsigned char>(timezone[2])
                ) ||
                !std::isdigit(
                    static_cast<unsigned char>(timezone[4])
                ) ||
                !std::isdigit(
                    static_cast<unsigned char>(timezone[5])
                )
            ) {
                throw ValidationError(
                    "Invalid timezone offset"
                );
            }

            int hours = std::stoi(timezone.substr(1, 2));
            int minutes = std::stoi(timezone.substr(4, 2));

            if (hours > 14 || minutes > 59 ||
                (hours == 14 && minutes != 0)) {
                throw ValidationError(
                    "Timezone offset out of range"
                );
            }

            offsetSeconds =
                (hours * 3600 + minutes * 60);

            if (timezone[0] == '-') {
                offsetSeconds = -offsetSeconds;
            }
        } else {
            throw ValidationError(
                "Timezone is required"
            );
        }

        // Convert local timestamp to UTC.
        const std::time_t localAsUtc = std::mktime(&value);

        const std::time_t utc =
            localAsUtc - offsetSeconds;

        std::tm result = {};

#if defined(_WIN32)
        gmtime_s(&result, &utc);
#else
        gmtime_r(&utc, &result);
#endif

        std::ostringstream output;

        output << std::put_time(
            &result,
            "%Y-%m-%dT%H:%M:%SZ"
        );

        return output.str();
    }
};

class SeverityNormalizer {
public:
    static Severity normalize(
        const std::string& input
    ) {
        const std::string value =
            Utility::lowercase(input);

        static const std::map<std::string, Severity> mapping = {
            {"trace", Severity::Debug},
            {"debug", Severity::Debug},
            {"info", Severity::Info},
            {"notice", Severity::Info},
            {"warn", Severity::Warning},
            {"warning", Severity::Warning},
            {"error", Severity::Error},
            {"critical", Severity::Critical},
            {"fatal", Severity::Critical}
        };

        auto found = mapping.find(value);

        if (found == mapping.end()) {
            throw ValidationError(
                "Unsupported severity"
            );
        }

        return found->second;
    }

    static std::string name(Severity severity) {
        switch (severity) {
            case Severity::Debug: return "DEBUG";
            case Severity::Info: return "INFO";
            case Severity::Warning: return "WARNING";
            case Severity::Error: return "ERROR";
            case Severity::Critical: return "CRITICAL";
        }

        return "UNKNOWN";
    }
};

class LogParser {
public:
    static LogEvent parseJson(
        const std::string& raw,
        const Agent& agent,
        int sequence
    ) {
        /*
         * This self-contained example accepts a deliberately
         * constrained JSON input format without claiming to
         * implement a complete JSON parser.
         *
         * The production boundary should use a standards-
         * compliant JSON parser with duplicate-key rejection.
         */

        auto extract = [&raw](
            const std::string& key
        ) -> std::string {
            const std::string marker =
                "\"" + key + "\"";

            std::size_t position = raw.find(marker);

            if (position == std::string::npos) {
                throw ValidationError(
                    "Missing JSON field: " + key
                );
            }

            position = raw.find(':', position);

            if (position == std::string::npos) {
                throw ValidationError(
                    "Invalid JSON field"
                );
            }

            position = raw.find('"', position + 1);

            if (position == std::string::npos) {
                throw ValidationError(
                    "Expected string value"
                );
            }

            std::size_t end = raw.find('"', position + 1);

            if (end == std::string::npos) {
                throw ValidationError(
                    "Unterminated JSON string"
                );
            }

            return raw.substr(
                position + 1,
                end - position - 1
            );
        };

        if (raw.empty() || raw.size() > 1048576) {
            throw ValidationError(
                "Invalid log size"
            );
        }

        LogEvent event;

        event.eventId = Utility::makeId(sequence);
        event.agentId = agent.id;
        event.hostname = agent.hostname;
        event.environment = agent.environment;
        event.source = "json";

        event.timestamp =
            TimestampNormalizer::normalize(
                extract("timestamp")
            );

        event.severity =
            SeverityNormalizer::normalize(
                extract("severity")
            );

        event.message = Utility::redact(
            extract("message")
        );

        event.state = LogState::Normalized;
        event.fingerprint = Utility::fingerprint(event);

        return event;
    }

    static LogEvent parseSyslog(
        const std::string& raw,
        const Agent& agent,
        int sequence
    ) {
        std::istringstream stream(raw);

        int priority = -1;
        int version = -1;

        char opening = '\0';

        stream >> opening;

        if (opening != '<') {
            throw ValidationError(
                "Invalid Syslog priority"
            );
        }

        stream >> priority;

        char closing = '\0';
        stream >> closing >> version;

        if (
            !stream ||
            closing != '>' ||
            priority < 0 ||
            priority > 191
        ) {
            throw ValidationError(
                "Invalid Syslog header"
            );
        }

        std::string timestamp;
        std::string hostname;
        std::string application;
        std::string processId;
        std::string messageId;

        stream >>
            timestamp >>
            hostname >>
            application >>
            processId >>
            messageId;

        if (!stream) {
            throw ValidationError(
                "Incomplete Syslog header"
            );
        }

        std::string message;
        std::getline(stream, message);

        message = Utility::trim(message);

        const int severityCode = priority % 8;

        static const std::map<int, Severity> levels = {
            {0, Severity::Critical},
            {1, Severity::Critical},
            {2, Severity::Critical},
            {3, Severity::Error},
            {4, Severity::Warning},
            {5, Severity::Info},
            {6, Severity::Info},
            {7, Severity::Debug}
        };

        LogEvent event;

        event.eventId = Utility::makeId(sequence);
        event.agentId = agent.id;
        event.hostname = hostname;
        event.environment = agent.environment;
        event.source = "syslog";

        event.timestamp =
            TimestampNormalizer::normalize(timestamp);

        event.severity = levels.at(severityCode);

        event.message = Utility::redact(message);

        event.state = LogState::Normalized;
        event.fingerprint = Utility::fingerprint(event);

        return event;
    }
};

class LogDestination {
public:
    virtual ~LogDestination() = default;

    virtual void send(
        const std::vector<LogEvent>& batch
    ) = 0;
};

class MemoryDestination : public LogDestination {
private:
    std::unordered_map<
        std::string,
        LogEvent
    > records_;

    int failuresRemaining_ = 0;

public:
    void simulateFailures(int count) {
        if (count < 0) {
            throw std::invalid_argument(
                "Failure count cannot be negative"
            );
        }

        failuresRemaining_ = count;
    }

    void send(
        const std::vector<LogEvent>& batch
    ) override {
        if (failuresRemaining_ > 0) {
            --failuresRemaining_;

            throw DeliveryError(
                "Destination unavailable"
            );
        }

        for (const auto& event : batch) {
            records_.emplace(
                event.fingerprint,
                event
            );
        }
    }

    std::size_t size() const {
        return records_.size();
    }
};

class ForwardingEngine {
private:
    std::shared_ptr<LogDestination> destination_;

    std::vector<LogEvent> queue_;
    std::vector<LogEvent> deadLetters_;

    std::size_t capacity_;
    std::size_t batchSize_;
    int maxRetries_;

    std::unordered_map<std::string, std::size_t> metrics_;

public:
    ForwardingEngine(
        std::shared_ptr<LogDestination> destination,
        std::size_t capacity = 1000,
        std::size_t batchSize = 10,
        int maxRetries = 3
    )
        : destination_(std::move(destination)),
          capacity_(capacity),
          batchSize_(batchSize),
          maxRetries_(maxRetries) {

        if (
            !destination_ ||
            capacity_ == 0 ||
            batchSize_ == 0 ||
            maxRetries_ < 0
        ) {
            throw std::invalid_argument(
                "Invalid forwarding configuration"
            );
        }
    }

    void enqueue(LogEvent event) {
        if (queue_.size() >= capacity_) {
            ++metrics_["queue_overflow"];

            throw DeliveryError(
                "Forwarding queue capacity exceeded"
            );
        }

        event.state = LogState::Queued;
        queue_.push_back(std::move(event));

        ++metrics_["enqueued"];
    }

    std::size_t flush() {
        std::size_t delivered = 0;

        while (!queue_.empty()) {
            const std::size_t count = std::min(
                batchSize_,
                queue_.size()
            );

            std::vector<LogEvent> batch(
                queue_.begin(),
                queue_.begin() + count
            );

            queue_.erase(
                queue_.begin(),
                queue_.begin() + count
            );

            bool success = false;

            for (
                int attempt = 0;
                attempt <= maxRetries_;
                ++attempt
            ) {
                try {
                    destination_->send(batch);
                    success = true;
                    break;
                } catch (const std::exception&) {
                    ++metrics_["delivery_errors"];
                }
            }

            if (success) {
                delivered += batch.size();
                metrics_["forwarded"] += batch.size();
            } else {
                for (auto& event : batch) {
                    event.state = LogState::Failed;
                    deadLetters_.push_back(
                        std::move(event)
                    );
                }

                metrics_["dead_lettered"] += batch.size();
            }
        }

        return delivered;
    }

    std::size_t replayDeadLetters() {
        std::vector<LogEvent> pending;
        pending.swap(deadLetters_);

        for (auto& event : pending) {
            if (queue_.size() >= capacity_) {
                deadLetters_.push_back(
                    std::move(event)
                );
                continue;
            }

            event.state = LogState::Queued;
            queue_.push_back(std::move(event));
        }

        return flush();
    }

    std::size_t deadLetterCount() const {
        return deadLetters_.size();
    }

    std::size_t queueSize() const {
        return queue_.size();
    }

    const auto& metrics() const {
        return metrics_;
    }
};

class RetentionEngine {
private:
    std::chrono::seconds hotRetention_;
    std::chrono::seconds archiveRetention_;

    std::vector<LogEvent> archive_;

public:
    RetentionEngine(
        int hotDays = 30,
        int archiveDays = 90
    ) {
        if (
            hotDays <= 0 ||
            archiveDays <= hotDays
        ) {
            throw std::invalid_argument(
                "Invalid retention configuration"
            );
        }

        hotRetention_ =
            std::chrono::hours(24 * hotDays);

        archiveRetention_ =
            std::chrono::hours(24 * archiveDays);
    }

    template<typename Clock>
    std::map<std::string, std::size_t> apply(
        std::vector<LogEvent>& records,
        const std::chrono::time_point<Clock>& now
    ) {
        std::vector<LogEvent> retained;

        std::size_t archived = 0;
        std::size_t deleted = 0;

        for (auto& event : records) {
            const auto timestamp =
                parseUtcTimestamp(event.timestamp);

            const auto age = now - timestamp;

            if (age < Clock::duration::zero()) {
                retained.push_back(event);
            } else if (age >= archiveRetention_) {
                ++deleted;
            } else if (age >= hotRetention_) {
                event.state = LogState::Archived;
                archive_.push_back(event);
                ++archived;
            } else {
                retained.push_back(event);
            }
        }

        records.swap(retained);

        return {
            {"retained", records.size()},
            {"archived", archived},
            {"deleted", deleted}
        };
    }

private:
    static std::chrono::system_clock::time_point
    parseUtcTimestamp(const std::string& timestamp) {
        std::tm value = {};

        std::istringstream stream(
            timestamp.substr(0, 19)
        );

        stream >> std::get_time(
            &value,
            "%Y-%m-%dT%H:%M:%S"
        );

        if (stream.fail()) {
            throw ValidationError(
                "Invalid stored timestamp"
            );
        }

        const auto raw = std::mktime(&value);

        return std::chrono::system_clock::from_time_t(raw);
    }

public:
    std::size_t archiveSize() const {
        return archive_.size();
    }
};

class LogCollectionSystem {
private:
    std::unordered_map<std::string, Agent> agents_;

    std::vector<LogEvent> records_;

    std::unordered_set<std::string> fingerprints_;

    std::shared_ptr<MemoryDestination> destination_;

    ForwardingEngine forwarder_;

    RetentionEngine retention_;

    int sequence_ = 0;

    std::unordered_map<std::string, std::size_t> metrics_;

public:
    LogCollectionSystem()
        : destination_(
            std::make_shared<MemoryDestination>()
        ),
          forwarder_(destination_, 1000, 2, 2),
          retention_(30, 90) {}

    void registerAgent(const Agent& agent) {
        if (
            agent.id.empty() ||
            agent.hostname.empty() ||
            agent.environment.empty()
        ) {
            throw ValidationError(
                "Invalid agent configuration"
            );
        }

        if (agents_.count(agent.id)) {
            throw ValidationError(
                "Duplicate agent registration"
            );
        }

        agents_.emplace(agent.id, agent);
    }

    bool collect(
        const std::string& agentId,
        const std::string& raw
    ) {
        auto found = agents_.find(agentId);

        if (found == agents_.end()) {
            throw ValidationError(
                "Unknown agent"
            );
        }

        const Agent& agent = found->second;

        if (!agent.enabled) {
            ++metrics_["disabled_agent_events"];
            return false;
        }

        LogEvent event;

        try {
            if (agent.sourceType == SourceType::Json) {
                event = LogParser::parseJson(
                    raw,
                    agent,
                    ++sequence_
                );
            } else {
                event = LogParser::parseSyslog(
                    raw,
                    agent,
                    ++sequence_
                );
            }

            if (
                fingerprints_.count(event.fingerprint)
            ) {
                ++metrics_["duplicates"];
                return false;
            }

            // Reserve capacity before committing local state.
            forwarder_.enqueue(event);

            fingerprints_.insert(event.fingerprint);
            records_.push_back(event);

            ++metrics_["collected"];

            return true;

        } catch (const ValidationError&) {
            ++metrics_["invalid_events"];
            throw;
        } catch (const DeliveryError&) {
            ++metrics_["queue_failures"];
            throw;
        }
    }

    void simulateDestinationFailures(int count) {
        destination_->simulateFailures(count);
    }

    std::size_t flush() {
        return forwarder_.flush();
    }

    void report() const {
        std::map<std::string, std::size_t> severityCounts;

        for (const auto& event : records_) {
            ++severityCounts[
                SeverityNormalizer::name(event.severity)
            ];
        }

        std::cout << "\n=== COLLECTION REPORT ===\n";

        std::cout
            << "Agents: "
            << agents_.size()
            << "\n";

        std::cout
            << "Collected: "
            << records_.size()
            << "\n";

        std::cout
            << "Destination records: "
            << destination_->size()
            << "\n";

        std::cout
            << "Dead letters: "
            << forwarder_.deadLetterCount()
            << "\n";

        std::cout << "\nSeverity distribution:\n";

        for (const auto& item : severityCounts) {
            std::cout
                << item.first
                << ": "
                << item.second
                << "\n";
        }

        std::cout << "\nCollection metrics:\n";

        for (const auto& item : metrics_) {
            std::cout
                << item.first
                << ": "
                << item.second
                << "\n";
        }

        std::cout << "\nForwarding metrics:\n";

        for (const auto& item : forwarder_.metrics()) {
            std::cout
                << item.first
                << ": "
                << item.second
                << "\n";
        }
    }

    std::size_t recordCount() const {
        return records_.size();
    }

    std::size_t destinationCount() const {
        return destination_->size();
    }

    std::size_t duplicateCount() const {
        auto found = metrics_.find("duplicates");

        return found == metrics_.end()
            ? 0
            : found->second;
    }

    std::map<std::string, std::size_t> applyRetention(
        const std::chrono::system_clock::time_point& now
    ) {
        return retention_.apply(records_, now);
    }
};

int main() {
    try {
        LogCollectionSystem system;

        system.registerAgent({
            "web-agent-01",
            "web-server-01",
            "production",
            SourceType::Json,
            true
        });

        system.registerAgent({
            "db-agent-01",
            "database-01",
            "production",
            SourceType::Syslog,
            true
        });

        std::vector<std::pair<std::string, std::string>> events = {
            {
                "web-agent-01",
                R"({"timestamp":"2026-11-23T04:00:00Z","severity":"INFO","message":"Login successful"})"
            },
            {
                "web-agent-01",
                R"({"timestamp":"2026-11-23T04:01:00+05:30","severity":"ERROR","message":"password=secret123 database unavailable"})"
            },
            {
                "db-agent-01",
                "<34>1 2026-11-23T04:02:00Z database-01 postgres 1234 ID47 Connection restored"
            },
            {
                "web-agent-01",
                R"({"timestamp":"2026-11-23T04:03:00Z","severity":"WARNING","message":"CPU usage above threshold"})"
            }
        };

        for (const auto& item : events) {
            system.collect(
                item.first,
                item.second
            );
        }

        // Duplicate events are ignored.
        system.collect(
            events[0].first,
            events[0].second
        );

        std::cout
            << "Delivered: "
            << system.flush()
            << "\n";

        system.report();

        if (system.recordCount() != 4) {
            throw std::runtime_error(
                "Collection count mismatch"
            );
        }

        if (system.destinationCount() != 4) {
            throw std::runtime_error(
                "Forwarding count mismatch"
            );
        }

        if (system.duplicateCount() != 1) {
            throw std::runtime_error(
                "Deduplication failed"
            );
        }

        std::cout
            << "\nAll C++17 assertions passed.\n";

    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }

    return 0;
}
