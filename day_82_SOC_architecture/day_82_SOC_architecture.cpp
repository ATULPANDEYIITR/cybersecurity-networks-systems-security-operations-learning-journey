#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;
using namespace std::chrono;

// ------------------------------------------------------------
// SOC Governance and Event Processing Engine
// ------------------------------------------------------------

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class Category {
    AUTHENTICATION,
    NETWORK,
    ENDPOINT,
    APPLICATION,
    CLOUD
};

enum class AlertState {
    OPEN,
    INVESTIGATING,
    RESOLVED
};

string toString(Severity severity) {
    switch (severity) {
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }

    throw invalid_argument("Unknown severity");
}

string toString(Category category) {
    switch (category) {
        case Category::AUTHENTICATION: return "AUTHENTICATION";
        case Category::NETWORK: return "NETWORK";
        case Category::ENDPOINT: return "ENDPOINT";
        case Category::APPLICATION: return "APPLICATION";
        case Category::CLOUD: return "CLOUD";
    }

    throw invalid_argument("Unknown category");
}

string toString(AlertState state) {
    switch (state) {
        case AlertState::OPEN: return "OPEN";
        case AlertState::INVESTIGATING: return "INVESTIGATING";
        case AlertState::RESOLVED: return "RESOLVED";
    }

    throw invalid_argument("Unknown alert state");
}

// ------------------------------------------------------------
// Domain models
// ------------------------------------------------------------

struct DataSource {
    string id;
    string name;
    string type;
    string environment;
    bool enabled = true;
};

struct SecurityEvent {
    string id;
    string sourceId;
    system_clock::time_point timestamp;

    Category category;
    Severity severity;

    string eventType;
    optional<string> sourceIP;
    optional<string> destinationIP;
    optional<string> username;
    optional<string> hostname;

    string message;
};

struct SecurityAlert {
    string id;
    string title;
    Severity severity;
    vector<string> eventIds;
    string description;

    system_clock::time_point createdAt;
    AlertState state = AlertState::OPEN;
};

struct CorrelationPolicy {
    string id;
    string title;
    Category category;
    string eventType;
    Severity alertSeverity;
    size_t threshold;
    minutes window;
};

// ------------------------------------------------------------
// Utility validation
// ------------------------------------------------------------

bool validIPv4(const string& ip) {
    istringstream stream(ip);
    string segment;
    int count = 0;

    while (getline(stream, segment, '.')) {
        if (segment.empty() || segment.size() > 3) {
            return false;
        }

        if (!all_of(
            segment.begin(),
            segment.end(),
            [](unsigned char c) {
                return isdigit(c);
            }
        )) {
            return false;
        }

        int value = stoi(segment);

        if (value < 0 || value > 255) {
            return false;
        }

        count++;
    }

    return count == 4;
}

string severityName(Severity severity) {
    return toString(severity);
}

// ------------------------------------------------------------
// Data source registry
// ------------------------------------------------------------

class SourceRegistry {

private:
    unordered_map<string, DataSource> sources;

public:

    void registerSource(const DataSource& source) {
        if (source.id.empty() || source.name.empty()) {
            throw invalid_argument("Invalid source definition");
        }

        if (sources.count(source.id)) {
            throw invalid_argument("Duplicate source");
        }

        sources.emplace(source.id, source);
    }

    const DataSource& get(const string& id) const {
        auto it = sources.find(id);

        if (it == sources.end()) {
            throw invalid_argument("Unknown data source");
        }

        return it->second;
    }

    size_t size() const {
        return sources.size();
    }
};

// ------------------------------------------------------------
// Collector with bounded buffer
// ------------------------------------------------------------

class Collector {

private:
    const SourceRegistry& registry;
    vector<SecurityEvent> buffer;
    size_t capacity;

public:
    size_t accepted = 0;
    size_t dropped = 0;

    explicit Collector(
        const SourceRegistry& sourceRegistry,
        size_t maximumCapacity = 10000
    )
        : registry(sourceRegistry),
          capacity(maximumCapacity) {

        if (capacity == 0) {
            throw invalid_argument("Capacity must be positive");
        }

        buffer.reserve(capacity);
    }

    bool ingest(const SecurityEvent& event) {
        const auto& source = registry.get(event.sourceId);

        if (!source.enabled) {
            dropped++;
            return false;
        }

        if (buffer.size() >= capacity) {
            dropped++;
            return false;
        }

        if (event.id.empty() || event.eventType.empty()) {
            throw invalid_argument("Invalid event");
        }

        if (event.sourceIP && !validIPv4(*event.sourceIP)) {
            throw invalid_argument("Invalid source IP");
        }

        if (
            event.destinationIP &&
            !validIPv4(*event.destinationIP)
        ) {
            throw invalid_argument("Invalid destination IP");
        }

        buffer.push_back(event);
        accepted++;

        return true;
    }

    vector<SecurityEvent> drain(size_t limit) {
        size_t count = min(limit, buffer.size());

        vector<SecurityEvent> batch(
            buffer.begin(),
            buffer.begin() + static_cast<ptrdiff_t>(count)
        );

        buffer.erase(
            buffer.begin(),
            buffer.begin() + static_cast<ptrdiff_t>(count)
        );

        return batch;
    }

    size_t pending() const {
        return buffer.size();
    }
};

// ------------------------------------------------------------
// Event storage and indexing
// ------------------------------------------------------------

class EventStore {

private:
    unordered_map<string, SecurityEvent> events;

    unordered_map<
        string,
        vector<string>
    > userIndex;

    unordered_map<
        string,
        vector<string>
    > sourceIndex;

    size_t maximumCapacity;

public:
    size_t duplicates = 0;

    explicit EventStore(size_t capacity = 50000)
        : maximumCapacity(capacity) {

        if (capacity == 0) {
            throw invalid_argument("Invalid storage capacity");
        }
    }

    bool save(const SecurityEvent& event) {
        if (events.count(event.id)) {
            duplicates++;
            return false;
        }

        if (events.size() >= maximumCapacity) {
            throw overflow_error("Event store capacity reached");
        }

        events.emplace(event.id, event);

        if (event.username) {
            userIndex[*event.username].push_back(event.id);
        }

        sourceIndex[event.sourceId].push_back(event.id);

        return true;
    }

    vector<SecurityEvent> all() const {
        vector<SecurityEvent> result;
        result.reserve(events.size());

        for (const auto& [id, event] : events) {
            result.push_back(event);
        }

        sort(
            result.begin(),
            result.end(),
            [](const SecurityEvent& a, const SecurityEvent& b) {
                return a.timestamp < b.timestamp;
            }
        );

        return result;
    }

    vector<SecurityEvent> byUser(const string& username) const {
        vector<SecurityEvent> result;

        auto it = userIndex.find(username);

        if (it == userIndex.end()) {
            return result;
        }

        for (const string& id : it->second) {
            result.push_back(events.at(id));
        }

        return result;
    }

    vector<SecurityEvent> bySource(
        const string& sourceId
    ) const {
        vector<SecurityEvent> result;

        auto it = sourceIndex.find(sourceId);

        if (it == sourceIndex.end()) {
            return result;
        }

        for (const string& id : it->second) {
            result.push_back(events.at(id));
        }

        return result;
    }

    size_t size() const {
        return events.size();
    }
};

// ------------------------------------------------------------
// Correlation engine
// ------------------------------------------------------------

class CorrelationEngine {

private:
    vector<CorrelationPolicy> policies;
    unordered_map<string, SecurityAlert> alerts;

    static string makeAlertId(
        const string& policyId,
        const string& groupKey,
        const vector<string>& eventIds
    ) {
        ostringstream out;

        out << policyId << "|" << groupKey;

        for (const auto& id : eventIds) {
            out << "|" << id;
        }

        // Deterministic compact identifier for this simulation.
        return out.str();
    }

    static bool matches(
        const SecurityEvent& event,
        const CorrelationPolicy& policy
    ) {
        return event.category == policy.category &&
               event.eventType == policy.eventType;
    }

public:

    void addPolicy(const CorrelationPolicy& policy) {
        if (
            policy.id.empty() ||
            policy.threshold < 2 ||
            policy.window.count() <= 0
        ) {
            throw invalid_argument("Invalid correlation policy");
        }

        auto duplicate = find_if(
            policies.begin(),
            policies.end(),
            [&](const CorrelationPolicy& existing) {
                return existing.id == policy.id;
            }
        );

        if (duplicate != policies.end()) {
            throw invalid_argument("Duplicate policy ID");
        }

        policies.push_back(policy);
    }

    vector<SecurityAlert> evaluate(
        const vector<SecurityEvent>& events
    ) {
        vector<SecurityAlert> generated;

        for (const auto& policy : policies) {
            unordered_map<
                string,
                vector<const SecurityEvent*>
            > groups;

            for (const auto& event : events) {
                if (!matches(event, policy)) {
                    continue;
                }

                if (!event.sourceIP || !event.username) {
                    continue;
                }

                string key =
                    *event.sourceIP + "|" + *event.username;

                groups[key].push_back(&event);
            }

            for (auto& [key, group] : groups) {
                sort(
                    group.begin(),
                    group.end(),
                    [](const SecurityEvent* a,
                       const SecurityEvent* b) {
                        return a->timestamp < b->timestamp;
                    }
                );

                size_t left = 0;

                for (size_t right = 0;
                     right < group.size();
                     right++) {

                    while (
                        left <= right &&
                        group[right]->timestamp -
                        group[left]->timestamp >
                        policy.window
                    ) {
                        left++;
                    }

                    size_t count = right - left + 1;

                    if (count < policy.threshold) {
                        continue;
                    }

                    vector<string> ids;

                    for (size_t i = left; i <= right; i++) {
                        ids.push_back(group[i]->id);
                    }

                    sort(ids.begin(), ids.end());

                    string alertId = makeAlertId(
                        policy.id,
                        key,
                        ids
                    );

                    if (!alerts.count(alertId)) {
                        SecurityAlert alert{
                            alertId,
                            policy.title,
                            policy.alertSeverity,
                            ids,
                            to_string(count) +
                                " matching events for " + key,
                            system_clock::now(),
                            AlertState::OPEN
                        };

                        alerts.emplace(alertId, alert);
                        generated.push_back(alert);
                    }

                    break;
                }
            }
        }

        // Critical events are evaluated independently.
        for (const auto& event : events) {
            if (event.severity != Severity::CRITICAL) {
                continue;
            }

            string alertId = "CRITICAL-" + event.id;

            if (!alerts.count(alertId)) {
                SecurityAlert alert{
                    alertId,
                    "Critical security event",
                    Severity::CRITICAL,
                    {event.id},
                    event.message,
                    system_clock::now(),
                    AlertState::OPEN
                };

                alerts.emplace(alertId, alert);
                generated.push_back(alert);
            }
        }

        return generated;
    }

    void transition(
        const string& alertId,
        AlertState newState
    ) {
        auto it = alerts.find(alertId);

        if (it == alerts.end()) {
            throw invalid_argument("Alert not found");
        }

        AlertState current = it->second.state;

        bool valid =
            (current == AlertState::OPEN &&
                (newState == AlertState::INVESTIGATING ||
                 newState == AlertState::RESOLVED))
            ||
            (current == AlertState::INVESTIGATING &&
                (newState == AlertState::OPEN ||
                 newState == AlertState::RESOLVED))
            ||
            (current == AlertState::RESOLVED &&
                newState == AlertState::OPEN);

        if (!valid) {
            throw invalid_argument("Invalid alert transition");
        }

        it->second.state = newState;
    }

    vector<SecurityAlert> allAlerts() const {
        vector<SecurityAlert> result;

        for (const auto& [id, alert] : alerts) {
            result.push_back(alert);
        }

        return result;
    }

    size_t openCount() const {
        return count_if(
            alerts.begin(),
            alerts.end(),
            [](const auto& entry) {
                return entry.second.state == AlertState::OPEN;
            }
        );
    }

    size_t size() const {
        return alerts.size();
    }
};

// ------------------------------------------------------------
// Pipeline
// ------------------------------------------------------------

class SOCEngine {

private:
    SourceRegistry registry;
    Collector collector;
    EventStore store;
    CorrelationEngine correlation;

public:

    size_t invalidEvents = 0;

    SOCEngine()
        : collector(registry),
          store(50000) {

        correlation.addPolicy({
            "AUTH-001",
            "Possible brute-force attack",
            Category::AUTHENTICATION,
            "LOGIN_FAILURE",
            Severity::HIGH,
            5,
            minutes(5)
        });
    }

    SourceRegistry& sources() {
        return registry;
    }

    bool ingest(const SecurityEvent& event) {
        return collector.ingest(event);
    }

    size_t processBatch(size_t limit = 100) {
        auto batch = collector.drain(limit);
        size_t processed = 0;

        for (const auto& event : batch) {
            try {
                if (store.save(event)) {
                    processed++;
                }
            } catch (const exception& error) {
                invalidEvents++;
                cerr << "Storage error: "
                     << error.what() << '\n';
            }
        }

        return processed;
    }

    vector<SecurityAlert> analyze() {
        return correlation.evaluate(store.all());
    }

    EventStore& storage() {
        return store;
    }

    CorrelationEngine& alerts() {
        return correlation;
    }

    size_t pending() const {
        return collector.pending();
    }

    void dashboard() const {
        auto events = store.all();
        auto alerts = correlation.allAlerts();

        map<string, size_t> severityCounts;
        map<string, size_t> categoryCounts;
        map<string, size_t> sourceCounts;

        for (const auto& event : events) {
            severityCounts[toString(event.severity)]++;
            categoryCounts[toString(event.category)]++;
            sourceCounts[event.sourceId]++;
        }

        cout << "\n========== SOC DASHBOARD ==========\n";

        cout << "Total events: " << events.size() << '\n';
        cout << "Total alerts: " << alerts.size() << '\n';
        cout << "Open alerts: " << correlation.openCount() << '\n';
        cout << "Duplicate events: " << store.duplicates << '\n';
        cout << "Pending events: " << collector.pending() << '\n';

        cout << "\nSeverity distribution:\n";

        for (const auto& [name, count] : severityCounts) {
            cout << "  " << name << ": " << count << '\n';
        }

        cout << "\nCategory distribution:\n";

        for (const auto& [name, count] : categoryCounts) {
            cout << "  " << name << ": " << count << '\n';
        }

        cout << "\nSource distribution:\n";

        for (const auto& [name, count] : sourceCounts) {
            cout << "  " << name << ": " << count << '\n';
        }

        cout << "\nAlerts:\n";

        for (const auto& alert : alerts) {
            cout << "  [" << toString(alert.severity) << "] "
                 << alert.title
                 << " | " << toString(alert.state)
                 << " | " << alert.description << '\n';
        }

        cout << "===================================\n";
    }
};

// ------------------------------------------------------------
// Demonstration
// ------------------------------------------------------------

SecurityEvent makeEvent(
    string id,
    string sourceId,
    int secondsOffset,
    Category category,
    Severity severity,
    string eventType,
    optional<string> sourceIP,
    optional<string> username,
    string message
) {
    return SecurityEvent{
        move(id),
        move(sourceId),
        system_clock::now() + seconds(secondsOffset),
        category,
        severity,
        move(eventType),
        move(sourceIP),
        nullopt,
        move(username),
        nullopt,
        move(message)
    };
}

int main() {
    try {
        SOCEngine soc;

        soc.sources().registerSource({
            "firewall-01",
            "Enterprise Firewall",
            "NETWORK",
            "PRODUCTION",
            true
        });

        soc.sources().registerSource({
            "edr-01",
            "Endpoint Detection",
            "ENDPOINT",
            "PRODUCTION",
            true
        });

        vector<SecurityEvent> samples;

        for (int i = 0; i < 6; i++) {
            samples.push_back(makeEvent(
                "AUTH-" + to_string(i + 1),
                "firewall-01",
                i * 20,
                Category::AUTHENTICATION,
                Severity::MEDIUM,
                "LOGIN_FAILURE",
                "203.0.113.45",
                "admin",
                "Authentication failure"
            ));
        }

        samples.push_back(makeEvent(
            "EDR-001",
            "edr-01",
            0,
            Category::ENDPOINT,
            Severity::CRITICAL,
            "MALWARE_DETECTED",
            "192.0.2.10",
            "analyst",
            "Suspicious executable detected"
        ));

        samples.push_back(makeEvent(
            "NET-001",
            "firewall-01",
            0,
            Category::NETWORK,
            Severity::LOW,
            "CONNECTION_ALLOWED",
            "192.0.2.20",
            nullopt,
            "Permitted connection"
        ));

        for (const auto& event : samples) {
            if (!soc.ingest(event)) {
                throw runtime_error("Event ingestion rejected");
            }
        }

        size_t processed = soc.processBatch();

        if (processed != samples.size()) {
            throw runtime_error("Unexpected processing count");
        }

        auto generated = soc.analyze();

        if (generated.size() < 2) {
            throw runtime_error("Expected security alerts were not generated");
        }

        // Duplicate handling.
        soc.ingest(samples.front());
        soc.processBatch();

        if (soc.storage().duplicates != 1) {
            throw runtime_error("Duplicate detection failed");
        }

        // Invalid IP handling.
        SecurityEvent invalid = makeEvent(
            "INVALID-001",
            "firewall-01",
            0,
            Category::NETWORK,
            Severity::LOW,
            "CONNECTION",
            "999.999.999.999",
            nullopt,
            "Invalid source address"
        );

        bool rejected = false;

        try {
            soc.ingest(invalid);
        } catch (const invalid_argument&) {
            rejected = true;
        }

        if (!rejected) {
            throw runtime_error("Invalid IP was accepted");
        }

        // Alert state transition.
        auto allAlerts = soc.alerts().allAlerts();

        if (!allAlerts.empty()) {
            soc.alerts().transition(
                allAlerts.front().id,
                AlertState::INVESTIGATING
            );
        }

        // Indexed user retrieval.
        auto adminEvents = soc.storage().byUser("admin");

        if (adminEvents.size() != 6) {
            throw runtime_error("User index verification failed");
        }

        soc.dashboard();

        cout << "\nSOC C++17 verification passed.\n";

    } catch (const exception& error) {
        cerr << "SOC failure: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
