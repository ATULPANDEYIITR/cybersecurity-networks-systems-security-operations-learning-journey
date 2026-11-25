#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * SIEM Query and Security Detection Engine
 *
 * C++17 implementation of:
 * - Event ingestion and validation
 * - Query filtering
 * - Aggregation
 * - Time-bucket analysis
 * - Field frequency analysis
 * - Brute-force detection
 * - Query-based security reporting
 */

using namespace std;

enum class Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

string severityName(Severity severity) {
    switch (severity) {
        case Severity::INFO: return "INFO";
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }

    throw invalid_argument("Unknown severity");
}

int severityScore(Severity severity) {
    return static_cast<int>(severity);
}

struct SecurityEvent {
    string eventId;
    long long timestamp;
    string sourceIp;
    string destinationIp;
    string username;
    string eventType;
    Severity severity;
    string action;
    string source;
};

void validateEvent(const SecurityEvent& event) {
    if (event.eventId.empty() ||
        event.sourceIp.empty() ||
        event.destinationIp.empty() ||
        event.username.empty() ||
        event.eventType.empty() ||
        event.action.empty() ||
        event.source.empty()) {
        throw invalid_argument("Event contains an empty required field");
    }

    if (event.timestamp < 0) {
        throw invalid_argument("Negative event timestamp");
    }
}

class EventRepository {
private:
    vector<SecurityEvent> events;
    set<string> eventIds;

    unordered_map<string, vector<size_t>> sourceIndex;
    unordered_map<string, vector<size_t>> usernameIndex;
    unordered_map<string, vector<size_t>> typeIndex;

public:
    void add(const SecurityEvent& event) {
        validateEvent(event);

        if (eventIds.count(event.eventId)) {
            throw invalid_argument("Duplicate event ID");
        }

        const size_t position = events.size();

        events.push_back(event);
        eventIds.insert(event.eventId);

        sourceIndex[event.sourceIp].push_back(position);
        usernameIndex[event.username].push_back(position);
        typeIndex[event.eventType].push_back(position);
    }

    void addBatch(const vector<SecurityEvent>& batch) {
        set<string> pending;

        for (const auto& event : batch) {
            validateEvent(event);

            if (eventIds.count(event.eventId) ||
                !pending.insert(event.eventId).second) {
                throw invalid_argument("Duplicate event in batch");
            }
        }

        for (const auto& event : batch) {
            add(event);
        }
    }

    const vector<SecurityEvent>& all() const {
        return events;
    }

    vector<SecurityEvent> bySource(const string& ip) const {
        vector<SecurityEvent> result;

        auto found = sourceIndex.find(ip);
        if (found == sourceIndex.end()) return result;

        for (size_t index : found->second) {
            result.push_back(events[index]);
        }

        return result;
    }

    vector<SecurityEvent> byUsername(const string& username) const {
        vector<SecurityEvent> result;

        auto found = usernameIndex.find(username);
        if (found == usernameIndex.end()) return result;

        for (size_t index : found->second) {
            result.push_back(events[index]);
        }

        return result;
    }
};

enum class Operator {
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN,
    LESS_THAN,
    CONTAINS
};

class QueryEngine {
private:
    vector<SecurityEvent> records;

public:
    explicit QueryEngine(const vector<SecurityEvent>& input)
        : records(input) {}

    QueryEngine& filterSeverity(
        const set<Severity>& allowed
    ) {
        records.erase(
            remove_if(
                records.begin(),
                records.end(),
                [&](const SecurityEvent& event) {
                    return !allowed.count(event.severity);
                }
            ),
            records.end()
        );

        return *this;
    }

    QueryEngine& filterAction(
        Operator operation,
        const string& expected
    ) {
        records.erase(
            remove_if(
                records.begin(),
                records.end(),
                [&](const SecurityEvent& event) {
                    bool match = false;

                    switch (operation) {
                        case Operator::EQUAL:
                            match = event.action == expected;
                            break;

                        case Operator::NOT_EQUAL:
                            match = event.action != expected;
                            break;

                        case Operator::CONTAINS:
                            match = event.action.find(expected)
                                    != string::npos;
                            break;

                        default:
                            throw invalid_argument(
                                "Unsupported action comparison"
                            );
                    }

                    return !match;
                }
            ),
            records.end()
        );

        return *this;
    }

    QueryEngine& filterTime(
        long long start,
        long long end
    ) {
        if (start > end) {
            throw invalid_argument("Invalid time range");
        }

        records.erase(
            remove_if(
                records.begin(),
                records.end(),
                [&](const SecurityEvent& event) {
                    return event.timestamp < start ||
                           event.timestamp > end;
                }
            ),
            records.end()
        );

        return *this;
    }

    QueryEngine& filterUsername(
        const string& username
    ) {
        records.erase(
            remove_if(
                records.begin(),
                records.end(),
                [&](const SecurityEvent& event) {
                    return event.username != username;
                }
            ),
            records.end()
        );

        return *this;
    }

    const vector<SecurityEvent>& results() const {
        return records;
    }
};

class SIEMAnalytics {
public:
    static map<string, size_t> aggregate(
        const vector<SecurityEvent>& events,
        const string& field
    ) {
        map<string, size_t> counts;

        for (const auto& event : events) {
            if (field == "source_ip") {
                counts[event.sourceIp]++;
            } else if (field == "destination_ip") {
                counts[event.destinationIp]++;
            } else if (field == "username") {
                counts[event.username]++;
            } else if (field == "event_type") {
                counts[event.eventType]++;
            } else if (field == "severity") {
                counts[severityName(event.severity)]++;
            } else if (field == "action") {
                counts[event.action]++;
            } else if (field == "source") {
                counts[event.source]++;
            } else {
                throw invalid_argument(
                    "Unsupported aggregation field"
                );
            }
        }

        return counts;
    }

    static map<long long, size_t> timeline(
        const vector<SecurityEvent>& events,
        long long intervalSeconds
    ) {
        if (intervalSeconds <= 0) {
            throw invalid_argument("Invalid timeline interval");
        }

        map<long long, size_t> buckets;

        for (const auto& event : events) {
            const long long bucket =
                (event.timestamp / intervalSeconds) *
                intervalSeconds;

            buckets[bucket]++;
        }

        return buckets;
    }

    static map<string, size_t> severityDistribution(
        const vector<SecurityEvent>& events
    ) {
        map<string, size_t> counts;

        for (const auto& event : events) {
            counts[severityName(event.severity)]++;
        }

        return counts;
    }

    static void fieldAnalysis(
        const vector<SecurityEvent>& events
    ) {
        const vector<string> fields = {
            "source_ip",
            "destination_ip",
            "username",
            "event_type",
            "severity",
            "action",
            "source"
        };

        cout << "\nFIELD ANALYSIS\n";

        for (const auto& field : fields) {
            auto counts = aggregate(events, field);

            cout << field
                 << " | unique values: "
                 << counts.size() << '\n';

            vector<pair<string, size_t>> ranked(
                counts.begin(), counts.end()
            );

            sort(
                ranked.begin(),
                ranked.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) {
                        return a.second > b.second;
                    }
                    return a.first < b.first;
                }
            );

            for (size_t i = 0;
                 i < min<size_t>(3, ranked.size());
                 ++i) {
                cout << "  " << ranked[i].first
                     << " = " << ranked[i].second << '\n';
            }
        }
    }
};

struct DetectionAlert {
    string sourceIp;
    string username;
    size_t attempts;
    long long firstSeen;
    long long lastSeen;
};

class DetectionEngine {
public:
    static vector<DetectionAlert> bruteForce(
        const vector<SecurityEvent>& events,
        size_t threshold = 5,
        long long windowSeconds = 600
    ) {
        if (threshold == 0 || windowSeconds <= 0) {
            throw invalid_argument(
                "Invalid detection configuration"
            );
        }

        map<pair<string, string>, vector<long long>> groups;

        for (const auto& event : events) {
            if (
                event.eventType == "authentication" &&
                event.action == "failure"
            ) {
                groups[
                    {event.sourceIp, event.username}
                ].push_back(event.timestamp);
            }
        }

        vector<DetectionAlert> alerts;

        for (auto& [identity, timestamps] : groups) {
            sort(timestamps.begin(), timestamps.end());

            size_t left = 0;

            for (size_t right = 0;
                 right < timestamps.size();
                 ++right) {

                while (
                    timestamps[right] - timestamps[left]
                    > windowSeconds
                ) {
                    ++left;
                }

                if (right - left + 1 == threshold) {
                    alerts.push_back({
                        identity.first,
                        identity.second,
                        threshold,
                        timestamps[left],
                        timestamps[right]
                    });
                }
            }
        }

        return alerts;
    }
};

vector<SecurityEvent> sampleEvents() {
    const long long base = 1795573800LL;

    vector<SecurityEvent> events;

    vector<tuple<
        string, int, string, string, string,
        Severity, string, string
    >> data = {
        {"E001", 0, "192.168.1.10", "10.0.0.5",
         "admin", Severity::HIGH, "failure", "authentication"},
        {"E002", 60, "192.168.1.10", "10.0.0.5",
         "admin", Severity::HIGH, "failure", "authentication"},
        {"E003", 120, "192.168.1.10", "10.0.0.5",
         "admin", Severity::HIGH, "failure", "authentication"},
        {"E004", 180, "192.168.1.10", "10.0.0.5",
         "admin", Severity::HIGH, "failure", "authentication"},
        {"E005", 240, "192.168.1.10", "10.0.0.5",
         "admin", Severity::HIGH, "failure", "authentication"},
        {"E006", 300, "192.168.1.10", "10.0.0.5",
         "admin", Severity::INFO, "success", "authentication"},
        {"E007", 360, "10.10.1.20", "10.0.0.8",
         "analyst", Severity::MEDIUM, "blocked", "network"},
        {"E008", 420, "10.10.1.20", "10.0.0.8",
         "analyst", Severity::CRITICAL, "blocked", "network"},
        {"E009", 480, "172.16.0.25", "10.0.0.9",
         "service_account", Severity::LOW, "executed", "process"},
        {"E010", 720, "192.168.1.15", "10.0.0.5",
         "user01", Severity::INFO, "success", "authentication"}
    };

    for (const auto& row : data) {
        events.push_back({
            get<0>(row),
            base + get<1>(row),
            get<2>(row),
            get<3>(row),
            get<4>(row),
            get<7>(row),
            get<5>(row),
            get<6>(row),
            "security-monitor"
        });
    }

    return events;
}

void printAggregation(
    const string& title,
    const map<string, size_t>& counts
) {
    cout << "\n" << title << '\n';

    for (const auto& [key, value] : counts) {
        cout << "  " << key << ": " << value << '\n';
    }
}

void runTests(const vector<SecurityEvent>& events) {
    if (events.size() != 10) {
        throw runtime_error("Event count test failed");
    }

    const auto failed = QueryEngine(events)
        .filterAction(Operator::EQUAL, "failure")
        .results();

    if (failed.size() != 5) {
        throw runtime_error("Authentication filter failed");
    }

    const auto high = QueryEngine(events)
        .filterSeverity({
            Severity::HIGH,
            Severity::CRITICAL
        })
        .results();

    if (high.size() != 6) {
        throw runtime_error("Severity filter failed");
    }

    const auto alerts = DetectionEngine::bruteForce(events);

    if (alerts.size() != 1 || alerts[0].attempts != 5) {
        throw runtime_error("Brute-force detection failed");
    }

    cout << "\nAll C++ tests passed.\n";
}

int main() {
    try {
        EventRepository repository;
        repository.addBatch(sampleEvents());

        const auto& events = repository.all();

        cout << "=== SIEM QUERY ENGINE ===\n";
        cout << "Total events: " << events.size() << '\n';

        auto suspicious = QueryEngine(events)
            .filterSeverity({
                Severity::HIGH,
                Severity::CRITICAL
            })
            .results();

        cout << "High severity events: "
             << suspicious.size() << '\n';

        printAggregation(
            "SEVERITY DISTRIBUTION",
            SIEMAnalytics::severityDistribution(events)
        );

        printAggregation(
            "SOURCE IP DISTRIBUTION",
            SIEMAnalytics::aggregate(events, "source_ip")
        );

        cout << "\nTIMELINE (5-MINUTE BUCKETS)\n";

        for (const auto& [timestamp, count] :
             SIEMAnalytics::timeline(events, 300)) {
            cout << "  " << timestamp << ": "
                 << count << '\n';
        }

        SIEMAnalytics::fieldAnalysis(events);

        const auto alerts = DetectionEngine::bruteForce(events);

        cout << "\nBRUTE-FORCE ALERTS\n";

        for (const auto& alert : alerts) {
            cout << "  HIGH: " << alert.sourceIp
                 << " -> " << alert.username
                 << " | attempts=" << alert.attempts
                 << " | first=" << alert.firstSeen
                 << " | last=" << alert.lastSeen
                 << '\n';
        }

        runTests(events);

    } catch (const exception& error) {
        cerr << "SIEM failure: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
