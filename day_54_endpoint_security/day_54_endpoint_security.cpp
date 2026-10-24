#include <algorithm>
#include <array>
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
#include <unordered_set>
#include <vector>

using namespace std;

enum class Severity { Low = 1, Medium = 2, High = 3, Critical = 4 };
enum class Sensor { Antivirus, EDR, HIDS, Behavioral };
enum class IncidentState { New, Triaged, Contained, Investigating, Resolved };

string toString(Severity value) {
    switch (value) {
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    throw logic_error("Unknown severity");
}

string toString(Sensor value) {
    switch (value) {
        case Sensor::Antivirus: return "antivirus";
        case Sensor::EDR: return "edr";
        case Sensor::HIDS: return "hids";
        case Sensor::Behavioral: return "behavioral";
    }
    throw logic_error("Unknown sensor");
}

string toString(IncidentState value) {
    switch (value) {
        case IncidentState::New: return "new";
        case IncidentState::Triaged: return "triaged";
        case IncidentState::Contained: return "contained";
        case IncidentState::Investigating: return "investigating";
        case IncidentState::Resolved: return "resolved";
    }
    throw logic_error("Unknown incident state");
}

struct Event {
    string id;
    string endpoint;
    long long timestampSeconds;
    Sensor sensor;
    string type;
    Severity severity;
    string process;
    string user;
};

struct Incident {
    string id;
    string endpoint;
    Severity severity;
    vector<string> eventIds;
    vector<string> reasons;
    IncidentState state = IncidentState::New;
};

class GovernanceEngine {
private:
    unordered_map<string, Event> events_;
    map<string, Incident> incidents_;
    map<string, string> endpointStates_;
    unsigned long sequence_ = 0;

    static int rank(Severity value) {
        return static_cast<int>(value);
    }

    static bool validIdentifier(const string& value) {
        if (value.empty() || value.size() > 128) return false;
        return all_of(value.begin(), value.end(), [](unsigned char c) {
            return isalnum(c) || c == '-' || c == '_' || c == '.';
        });
    }

    static bool allowedTransition(IncidentState from, IncidentState to) {
        switch (from) {
            case IncidentState::New:
                return to == IncidentState::Triaged;
            case IncidentState::Triaged:
                return to == IncidentState::Contained ||
                       to == IncidentState::Investigating;
            case IncidentState::Contained:
                return to == IncidentState::Investigating;
            case IncidentState::Investigating:
                return to == IncidentState::Contained ||
                       to == IncidentState::Resolved;
            case IncidentState::Resolved:
                return false;
        }
        return false;
    }

public:
    void ingest(const Event& event) {
        if (!validIdentifier(event.id) || !validIdentifier(event.endpoint) ||
            !validIdentifier(event.process) || event.user.empty()) {
            throw invalid_argument("Invalid event identity or process metadata");
        }

        auto it = events_.find(event.id);
        if (it != events_.end()) {
            const Event& old = it->second;
            if (old.endpoint != event.endpoint ||
                old.timestampSeconds != event.timestampSeconds ||
                old.type != event.type || old.process != event.process ||
                old.user != event.user || old.sensor != event.sensor ||
                old.severity != event.severity) {
                throw invalid_argument("Conflicting duplicate event identifier");
            }
            return;
        }

        events_.emplace(event.id, event);
    }

    vector<Incident> detect() {
        map<string, vector<Event>> byEndpoint;
        for (const auto& entry : events_) {
            byEndpoint[entry.second.endpoint].push_back(entry.second);
        }

        vector<Incident> created;

        for (auto& entry : byEndpoint) {
            const string& endpoint = entry.first;
            auto& stream = entry.second;

            sort(stream.begin(), stream.end(), [](const Event& a, const Event& b) {
                return a.timestampSeconds < b.timestampSeconds;
            });

            Incident incident;
            incident.endpoint = endpoint;
            incident.severity = Severity::Low;
            set<string> evidence;
            set<string> reasons;

            auto record = [&](const Event& event, const string& reason,
                              Severity severity) {
                evidence.insert(event.id);
                reasons.insert(reason);
                if (rank(severity) > rank(incident.severity)) {
                    incident.severity = severity;
                }
            };

            vector<Event> suspicious;
            vector<Event> outbound;
            map<string, int> failures;

            for (const Event& event : stream) {
                if (event.sensor == Sensor::Antivirus &&
                    event.type == "malware_detected") {
                    record(event, "Antivirus malware detection", event.severity);
                } else if (event.sensor == Sensor::Antivirus &&
                           event.type == "quarantine_failed") {
                    record(event, "Antivirus quarantine failed", Severity::High);
                } else if (event.sensor == Sensor::HIDS &&
                           event.type == "integrity_violation") {
                    record(event, "Protected-file integrity violation",
                           event.severity);
                } else if (event.sensor == Sensor::EDR &&
                           (event.type == "suspicious_process" ||
                            event.type == "credential_access")) {
                    suspicious.push_back(event);
                    record(event, "EDR event: " + event.type, event.severity);
                } else if (event.sensor == Sensor::EDR &&
                           event.type == "unusual_outbound_connection") {
                    outbound.push_back(event);
                }

                if (event.sensor == Sensor::Behavioral) {
                    if (event.type == "authentication_failure") {
                        ++failures[event.user];
                    } else if (event.type == "authentication_success" &&
                               failures[event.user] >= 5) {
                        record(event,
                               "Repeated authentication failures followed by success",
                               Severity::High);
                    }
                }
            }

            if (!suspicious.empty()) {
                const long long first = min_element(
                    suspicious.begin(), suspicious.end(),
                    [](const Event& a, const Event& b) {
                        return a.timestampSeconds < b.timestampSeconds;
                    })->timestampSeconds;

                for (const Event& event : outbound) {
                    const long long elapsed = event.timestampSeconds - first;
                    if (elapsed >= 0 && elapsed <= 300) {
                        record(event,
                               "Suspicious execution correlated with outbound activity",
                               Severity::Critical);
                    }
                }
            }

            if (evidence.empty()) continue;

            ostringstream id;
            id << "INC-" << setw(5) << setfill('0') << ++sequence_;
            incident.id = id.str();
            incident.eventIds.assign(evidence.begin(), evidence.end());
            incident.reasons.assign(reasons.begin(), reasons.end());
            incidents_.emplace(incident.id, incident);
            created.push_back(incident);
        }

        return created;
    }

    void transition(const string& incidentId, IncidentState next) {
        auto it = incidents_.find(incidentId);
        if (it == incidents_.end()) {
            throw out_of_range("Incident does not exist");
        }

        Incident& incident = it->second;
        if (!allowedTransition(incident.state, next)) {
            throw logic_error("Invalid incident state transition");
        }

        incident.state = next;
        if (next == IncidentState::Contained) {
            endpointStates_[incident.endpoint] = "isolated";
        } else if (next == IncidentState::Resolved) {
            endpointStates_[incident.endpoint] = "review_required";
        }
    }

    void printReport() const {
        map<string, int> severityCounts;
        map<string, int> stateCounts;
        map<string, int> sensorCounts;

        for (const auto& entry : incidents_) {
            ++severityCounts[toString(entry.second.severity)];
            ++stateCounts[toString(entry.second.state)];
        }
        for (const auto& entry : events_) {
            ++sensorCounts[toString(entry.second.sensor)];
        }

        cout << "\nEndpoint security report\n"
             << "========================\n"
             << "Telemetry events: " << events_.size() << '\n'
             << "Incidents: " << incidents_.size() << '\n';

        cout << "\nIncidents by severity:\n";
        for (const auto& entry : severityCounts) {
            cout << "  " << entry.first << ": " << entry.second << '\n';
        }

        cout << "\nEvents by sensor:\n";
        for (const auto& entry : sensorCounts) {
            cout << "  " << entry.first << ": " << entry.second << '\n';
        }

        cout << "\nIncident details:\n";
        for (const auto& entry : incidents_) {
            const Incident& incident = entry.second;
            cout << incident.id << " endpoint=" << incident.endpoint
                 << " severity=" << toString(incident.severity)
                 << " state=" << toString(incident.state)
                 << " evidence=" << incident.eventIds.size() << '\n';

            for (const string& reason : incident.reasons) {
                cout << "  - " << reason << '\n';
            }
        }

        cout << "\nEndpoint response states:\n";
        for (const auto& entry : endpointStates_) {
            cout << "  " << entry.first << ": " << entry.second << '\n';
        }
    }

    const map<string, Incident>& incidents() const {
        return incidents_;
    }
};

int main() {
    try {
        GovernanceEngine engine;
        const long long base = 1792814400LL;

        vector<Event> events = {
            {"EV-001", "WS-101", base, Sensor::Antivirus,
             "malware_detected", Severity::High, "invoice.exe", "employee"},
            {"EV-002", "WS-202", base + 1, Sensor::HIDS,
             "integrity_violation", Severity::High, "sshd", "root"},
            {"EV-003", "WS-303", base + 2, Sensor::EDR,
             "suspicious_process", Severity::High, "powershell.exe", "employee"},
            {"EV-004", "WS-303", base + 30, Sensor::EDR,
             "unusual_outbound_connection", Severity::Medium,
             "powershell.exe", "employee"},
            {"AUTH-1", "WS-404", base, Sensor::Behavioral,
             "authentication_failure", Severity::Medium, "login_service", "svc-backup"},
            {"AUTH-2", "WS-404", base + 1, Sensor::Behavioral,
             "authentication_failure", Severity::Medium, "login_service", "svc-backup"},
            {"AUTH-3", "WS-404", base + 2, Sensor::Behavioral,
             "authentication_failure", Severity::Medium, "login_service", "svc-backup"},
            {"AUTH-4", "WS-404", base + 3, Sensor::Behavioral,
             "authentication_failure", Severity::Medium, "login_service", "svc-backup"},
            {"AUTH-5", "WS-404", base + 4, Sensor::Behavioral,
             "authentication_failure", Severity::Medium, "login_service", "svc-backup"},
            {"AUTH-6", "WS-404", base + 5, Sensor::Behavioral,
             "authentication_success", Severity::Medium, "login_service", "svc-backup"},
            {"EV-005", "WS-505", base + 6, Sensor::EDR,
             "process_started", Severity::Low, "notepad.exe", "employee"}
        };

        for (const Event& event : events) {
            engine.ingest(event);
        }

        // Replaying identical telemetry is idempotent.
        engine.ingest(events.front());

        vector<Incident> incidents = engine.detect();

        for (const Incident& incident : incidents) {
            if (incident.endpoint == "WS-303") {
                engine.transition(incident.id, IncidentState::Triaged);
                engine.transition(incident.id, IncidentState::Contained);
                engine.transition(incident.id, IncidentState::Investigating);
            }
        }

        engine.printReport();

        bool rejected = false;
        try {
            Event invalid = events.front();
            invalid.id = "BAD EVENT ID";
            engine.ingest(invalid);
        } catch (const invalid_argument&) {
            rejected = true;
        }
        if (!rejected) {
            throw logic_error("Invalid event was not rejected");
        }

        cout << "\nValidation test passed.\n";
        return 0;
    } catch (const exception& error) {
        cerr << "Endpoint security failure: " << error.what() << '\n';
        return 1;
    }
}
