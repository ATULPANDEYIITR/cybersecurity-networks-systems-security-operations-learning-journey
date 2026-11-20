#include <algorithm>
#include <array>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

// =========================================================
// SECURITY OPERATIONS FUNDAMENTALS
// SOC monitoring, alert triage, escalation and governance.
// C++17 standalone implementation.
// =========================================================

enum class Severity {
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

enum class Tier {
    L1 = 1,
    L2 = 2,
    L3 = 3
};

enum class IncidentStatus {
    NEW,
    TRIAGED,
    INVESTIGATING,
    ESCALATED,
    CONTAINED,
    RESOLVED,
    CLOSED,
    FALSE_POSITIVE
};

enum class IncidentType {
    BRUTE_FORCE,
    MALWARE,
    PHISHING,
    DATA_EXFILTRATION,
    UNAUTHORIZED_ACCESS,
    NETWORK_INTRUSION
};

string toString(Severity value) {
    switch (value) {
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    throw invalid_argument("Unknown severity");
}

string toString(Tier value) {
    switch (value) {
        case Tier::L1: return "L1";
        case Tier::L2: return "L2";
        case Tier::L3: return "L3";
    }
    throw invalid_argument("Unknown tier");
}

string toString(IncidentStatus value) {
    switch (value) {
        case IncidentStatus::NEW: return "NEW";
        case IncidentStatus::TRIAGED: return "TRIAGED";
        case IncidentStatus::INVESTIGATING: return "INVESTIGATING";
        case IncidentStatus::ESCALATED: return "ESCALATED";
        case IncidentStatus::CONTAINED: return "CONTAINED";
        case IncidentStatus::RESOLVED: return "RESOLVED";
        case IncidentStatus::CLOSED: return "CLOSED";
        case IncidentStatus::FALSE_POSITIVE: return "FALSE_POSITIVE";
    }
    throw invalid_argument("Unknown status");
}

string toString(IncidentType value) {
    switch (value) {
        case IncidentType::BRUTE_FORCE: return "BRUTE_FORCE";
        case IncidentType::MALWARE: return "MALWARE";
        case IncidentType::PHISHING: return "PHISHING";
        case IncidentType::DATA_EXFILTRATION: return "DATA_EXFILTRATION";
        case IncidentType::UNAUTHORIZED_ACCESS: return "UNAUTHORIZED_ACCESS";
        case IncidentType::NETWORK_INTRUSION: return "NETWORK_INTRUSION";
    }
    throw invalid_argument("Unknown incident type");
}


// =========================================================
// 1. Security event
// =========================================================

struct SecurityEvent {
    string eventId;
    string source;
    string eventType;
    string sourceIP;
    string destination;
    int failedAttempts = 0;
    double transferredMB = 0.0;
    string description;

    void validate() const {
        if (eventId.empty() || source.empty() || eventType.empty()) {
            throw invalid_argument("Missing event identity");
        }

        if (failedAttempts < 0 || transferredMB < 0) {
            throw invalid_argument("Negative event measurements");
        }

        stringstream stream(sourceIP);
        string octet;
        int count = 0;

        while (getline(stream, octet, '.')) {
            if (octet.empty() || octet.size() > 3) {
                throw invalid_argument("Invalid IPv4 address");
            }

            if (!all_of(octet.begin(), octet.end(), ::isdigit)) {
                throw invalid_argument("Invalid IPv4 octet");
            }

            int value = stoi(octet);

            if (value > 255) {
                throw invalid_argument("IPv4 octet exceeds 255");
            }

            ++count;
        }

        if (count != 4) {
            throw invalid_argument("IPv4 requires four octets");
        }
    }
};


// =========================================================
// 2. Analyst model
// =========================================================

struct Analyst {
    string id;
    string name;
    Tier tier;
    set<IncidentType> skills;
    bool active = true;
    int currentAssignments = 0;
    int maximumAssignments = 5;
};


// =========================================================
// 3. Alert model
// =========================================================

struct HistoryEntry {
    string action;
    string actor;
    string reason;
};

struct Alert {
    string id;
    SecurityEvent event;
    IncidentType type;
    Severity severity;
    IncidentStatus status = IncidentStatus::NEW;
    Tier assignedTier = Tier::L1;
    optional<string> analystId;
    double confidence = 0.0;
    vector<string> evidence;
    vector<HistoryEntry> history;
};


// =========================================================
// 4. Detection engine
// =========================================================

class DetectionEngine {
public:
    optional<Alert> analyze(const SecurityEvent& event) const {
        event.validate();

        optional<IncidentType> type;
        Severity severity = Severity::LOW;
        double confidence = 0.0;

        if (event.failedAttempts >= 25) {
            type = IncidentType::BRUTE_FORCE;
            severity = Severity::CRITICAL;
            confidence = 0.98;
        }
        else if (event.failedAttempts >= 10) {
            type = IncidentType::BRUTE_FORCE;
            severity = Severity::HIGH;
            confidence = 0.90;
        }
        else if (event.eventType == "malware_detected") {
            type = IncidentType::MALWARE;
            severity = Severity::HIGH;
            confidence = 0.95;
        }
        else if (event.eventType == "phishing_report") {
            type = IncidentType::PHISHING;
            severity = Severity::MEDIUM;
            confidence = 0.85;
        }
        else if (event.eventType == "unauthorized_access") {
            type = IncidentType::UNAUTHORIZED_ACCESS;
            severity = Severity::HIGH;
            confidence = 0.90;
        }
        else if (
            event.eventType == "outbound_transfer" &&
            event.transferredMB >= 500.0
        ) {
            type = IncidentType::DATA_EXFILTRATION;
            severity = Severity::CRITICAL;
            confidence = 0.95;
        }

        if (!type) {
            return nullopt;
        }

        Alert alert;
        alert.id = event.eventId;
        alert.event = event;
        alert.type = *type;
        alert.severity = severity;
        alert.confidence = confidence;

        alert.evidence.push_back(
            "Detection rule matched: " + toString(*type)
        );

        alert.history.push_back({
            "DETECTED",
            "DETECTION_ENGINE",
            "Automated security event analysis"
        });

        return alert;
    }
};


// =========================================================
// 5. Analyst registry
// =========================================================

class AnalystRegistry {
private:
    unordered_map<string, Analyst> analysts;

public:
    void registerAnalyst(const Analyst& analyst) {
        if (analyst.id.empty() || analyst.name.empty()) {
            throw invalid_argument("Analyst identity required");
        }

        if (analysts.count(analyst.id)) {
            throw invalid_argument("Duplicate analyst ID");
        }

        if (analyst.maximumAssignments < 1) {
            throw invalid_argument("Invalid analyst capacity");
        }

        analysts.emplace(analyst.id, analyst);
    }

    optional<Analyst> assign(
        IncidentType type,
        Tier preferredTier
    ) {
        vector<Analyst*> candidates;

        for (auto& [id, analyst] : analysts) {
            if (
                analyst.active &&
                static_cast<int>(analyst.tier) >=
                    static_cast<int>(preferredTier) &&
                analyst.skills.count(type) &&
                analyst.currentAssignments <
                    analyst.maximumAssignments
            ) {
                candidates.push_back(&analyst);
            }
        }

        sort(
            candidates.begin(),
            candidates.end(),
            [](const Analyst* a, const Analyst* b) {
                if (a->tier != b->tier) {
                    return static_cast<int>(a->tier) <
                           static_cast<int>(b->tier);
                }
                return a->id < b->id;
            }
        );

        if (candidates.empty()) {
            return nullopt;
        }

        candidates.front()->currentAssignments++;

        return *candidates.front();
    }

    void release(const string& analystId) {
        auto it = analysts.find(analystId);

        if (it != analysts.end() &&
            it->second.currentAssignments > 0) {
            --it->second.currentAssignments;
        }
    }
};


// =========================================================
// 6. Incident lifecycle and state machine
// =========================================================

class IncidentManager {
private:
    AnalystRegistry& registry;

    bool allowed(
        IncidentStatus current,
        IncidentStatus next
    ) const {
        static const map<IncidentStatus, set<IncidentStatus>> rules = {
            {IncidentStatus::NEW, {
                IncidentStatus::TRIAGED,
                IncidentStatus::ESCALATED,
                IncidentStatus::FALSE_POSITIVE
            }},
            {IncidentStatus::TRIAGED, {
                IncidentStatus::INVESTIGATING,
                IncidentStatus::ESCALATED,
                IncidentStatus::FALSE_POSITIVE
            }},
            {IncidentStatus::INVESTIGATING, {
                IncidentStatus::ESCALATED,
                IncidentStatus::CONTAINED,
                IncidentStatus::FALSE_POSITIVE
            }},
            {IncidentStatus::ESCALATED, {
                IncidentStatus::INVESTIGATING,
                IncidentStatus::CONTAINED
            }},
            {IncidentStatus::CONTAINED, {
                IncidentStatus::RESOLVED
            }},
            {IncidentStatus::RESOLVED, {
                IncidentStatus::CLOSED
            }},
            {IncidentStatus::FALSE_POSITIVE, {
                IncidentStatus::CLOSED
            }},
            {IncidentStatus::CLOSED, {}}
        };

        auto it = rules.find(current);

        return it != rules.end() &&
               it->second.count(next) > 0;
    }

public:
    explicit IncidentManager(AnalystRegistry& registry)
        : registry(registry) {}

    bool assign(Alert& alert) {
        Tier preferred =
            alert.severity == Severity::CRITICAL
                ? Tier::L3
                : alert.severity == Severity::HIGH
                    ? Tier::L2
                    : Tier::L1;

        auto analyst = registry.assign(alert.type, preferred);

        if (!analyst) {
            transition(
                alert,
                IncidentStatus::ESCALATED,
                "SYSTEM",
                "No qualified analyst available"
            );
            return false;
        }

        alert.analystId = analyst->id;
        alert.assignedTier = analyst->tier;

        transition(
            alert,
            IncidentStatus::TRIAGED,
            "SYSTEM",
            "Assigned to " + analyst->name
        );

        return true;
    }

    void transition(
        Alert& alert,
        IncidentStatus next,
        const string& actor,
        const string& reason
    ) {
        if (!allowed(alert.status, next)) {
            throw logic_error(
                "Invalid incident state transition"
            );
        }

        if (actor.empty() || reason.empty()) {
            throw invalid_argument("Actor and reason required");
        }

        if (
            next == IncidentStatus::CONTAINED &&
            alert.evidence.empty()
        ) {
            throw logic_error("Containment requires evidence");
        }

        alert.status = next;

        alert.history.push_back({
            toString(next),
            actor,
            reason
        });

        if (
            next == IncidentStatus::CLOSED ||
            next == IncidentStatus::FALSE_POSITIVE
        ) {
            if (alert.analystId) {
                registry.release(*alert.analystId);
            }
        }
    }
};


// =========================================================
// 7. SOC governance and merge-free operational decisions
// =========================================================

struct MonitoringPolicy {
    int bruteForceThreshold = 10;
    double exfiltrationThresholdMB = 500.0;
    int criticalThreshold = 25;
    int maximumQueueSize = 10000;

    void validate() const {
        if (
            bruteForceThreshold < 1 ||
            criticalThreshold <= bruteForceThreshold ||
            exfiltrationThresholdMB <= 0 ||
            maximumQueueSize < 1
        ) {
            throw invalid_argument("Invalid monitoring policy");
        }
    }
};

struct SOCMetrics {
    size_t totalAlerts = 0;
    size_t criticalAlerts = 0;
    size_t highAlerts = 0;
    size_t activeIncidents = 0;
    size_t resolvedIncidents = 0;
    size_t falsePositives = 0;
};

class SOCPlatform {
private:
    MonitoringPolicy policy;
    DetectionEngine detector;
    AnalystRegistry registry;
    IncidentManager incidentManager;
    vector<Alert> alerts;
    set<string> processedEventIds;

public:
    SOCPlatform()
        : incidentManager(registry) {
        policy.validate();
    }

    AnalystRegistry& getRegistry() {
        return registry;
    }

    void process(const SecurityEvent& event) {
        if (processedEventIds.count(event.eventId)) {
            throw logic_error("Duplicate event rejected");
        }

        if (alerts.size() >=
            static_cast<size_t>(policy.maximumQueueSize)) {
            throw overflow_error("SOC processing capacity exceeded");
        }

        auto alert = detector.analyze(event);

        processedEventIds.insert(event.eventId);

        if (!alert) {
            cout << "[NORMAL] " << event.eventId << '\n';
            return;
        }

        incidentManager.assign(*alert);

        cout << "[ALERT] "
             << alert->id << " | "
             << toString(alert->type) << " | "
             << toString(alert->severity) << " | "
             << toString(alert->status) << '\n';

        alerts.push_back(std::move(*alert));
    }

    SOCMetrics metrics() const {
        SOCMetrics result;
        result.totalAlerts = alerts.size();

        for (const auto& alert : alerts) {
            if (alert.severity == Severity::CRITICAL) {
                ++result.criticalAlerts;
            }

            if (alert.severity == Severity::HIGH) {
                ++result.highAlerts;
            }

            if (
                alert.status == IncidentStatus::RESOLVED ||
                alert.status == IncidentStatus::CLOSED
            ) {
                ++result.resolvedIncidents;
            }
            else if (alert.status == IncidentStatus::FALSE_POSITIVE) {
                ++result.falsePositives;
            }
            else {
                ++result.activeIncidents;
            }
        }

        return result;
    }

    const vector<Alert>& getAlerts() const {
        return alerts;
    }
};


// =========================================================
// 8. Demonstration and validation
// =========================================================

int main() {
    try {
        SOCPlatform soc;

        soc.getRegistry().registerAnalyst({
            "A001",
            "L1 Security Analyst",
            Tier::L1,
            {
                IncidentType::PHISHING,
                IncidentType::BRUTE_FORCE
            },
            true,
            0,
            5
        });

        soc.getRegistry().registerAnalyst({
            "A002",
            "L2 Incident Responder",
            Tier::L2,
            {
                IncidentType::MALWARE,
                IncidentType::UNAUTHORIZED_ACCESS
            },
            true,
            0,
            5
        });

        soc.getRegistry().registerAnalyst({
            "A003",
            "L3 Threat Hunter",
            Tier::L3,
            {
                IncidentType::BRUTE_FORCE,
                IncidentType::DATA_EXFILTRATION
            },
            true,
            0,
            5
        });

        vector<SecurityEvent> events = {
            {
                "EVT-001",
                "VPN Firewall",
                "authentication_failure",
                "203.0.113.45",
                "VPN Gateway",
                30,
                0,
                "Repeated failed authentication"
            },
            {
                "EVT-002",
                "Endpoint EDR",
                "malware_detected",
                "198.51.100.20",
                "Workstation-17",
                0,
                0,
                "Suspicious executable detected"
            },
            {
                "EVT-003",
                "Email Gateway",
                "phishing_report",
                "192.0.2.20",
                "Mail Server",
                0,
                0,
                "Suspicious email reported"
            },
            {
                "EVT-004",
                "Network Monitor",
                "normal_traffic",
                "192.0.2.40",
                "Application Server",
                0,
                20,
                "Routine traffic"
            }
        };

        for (const auto& event : events) {
            soc.process(event);
        }

        // Demonstrate the full incident lifecycle.
        auto& alerts = const_cast<vector<Alert>&>(soc.getAlerts());

        if (!alerts.empty()) {
            Alert& alert = alerts.front();

            IncidentManager manager(soc.getRegistry());

            if (alert.status == IncidentStatus::TRIAGED) {
                manager.transition(
                    alert,
                    IncidentStatus::INVESTIGATING,
                    *alert.analystId,
                    "Correlation with authentication logs"
                );

                manager.transition(
                    alert,
                    IncidentStatus::CONTAINED,
                    *alert.analystId,
                    "Suspicious source temporarily blocked"
                );

                manager.transition(
                    alert,
                    IncidentStatus::RESOLVED,
                    *alert.analystId,
                    "Access controls restored"
                );

                manager.transition(
                    alert,
                    IncidentStatus::CLOSED,
                    *alert.analystId,
                    "Incident evidence documented"
                );
            }
        }

        SOCMetrics report = soc.metrics();

        cout << "\nSOC OPERATIONAL REPORT\n";
        cout << "Total alerts: " << report.totalAlerts << '\n';
        cout << "Critical alerts: " << report.criticalAlerts << '\n';
        cout << "High alerts: " << report.highAlerts << '\n';
        cout << "Active incidents: " << report.activeIncidents << '\n';
        cout << "Resolved incidents: " << report.resolvedIncidents << '\n';
        cout << "False positives: " << report.falsePositives << '\n';

        cout << "\nINCIDENT HISTORY\n";

        for (const auto& alert : soc.getAlerts()) {
            cout << "\n" << alert.id
                 << " | " << toString(alert.status) << '\n';

            for (const auto& entry : alert.history) {
                cout << "  " << entry.action
                     << " | " << entry.actor
                     << " | " << entry.reason << '\n';
            }
        }

        // Invalid input test.
        SecurityEvent invalid = {
            "EVT-INVALID",
            "Firewall",
            "authentication_failure",
            "999.999.999.999",
            "VPN",
            20,
            0,
            "Invalid address"
        };

        try {
            soc.process(invalid);
        }
        catch (const exception& error) {
            cout << "\nVALIDATION: " << error.what() << '\n';
        }

        // Duplicate event test.
        try {
            soc.process(events.front());
        }
        catch (const exception& error) {
            cout << "DUPLICATE EVENT: " << error.what() << '\n';
        }

        cout << "\nSOC processing completed.\n";

    }
    catch (const exception& error) {
        cerr << "SOC SYSTEM FAILURE: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
