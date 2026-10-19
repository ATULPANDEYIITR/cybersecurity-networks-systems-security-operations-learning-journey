#include <algorithm>
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

/*
 * Windows Event Log Governance Engine
 *
 * Case study:
 * A security operations team receives normalized Windows events from
 * Security, System, Application, and PowerShell logs. The engine evaluates
 * authentication behavior, high-risk events, and operational telemetry.
 *
 * The program focuses on C++ value types, policy objects, indexes, and
 * deterministic rule evaluation rather than OS-specific event collection.
 */

enum class LogChannel {
    Security,
    System,
    Application,
    PowerShell
};

enum class Severity {
    Informational,
    Warning,
    Critical
};

struct Event {
    long long recordId;
    LogChannel channel;
    int eventId;
    Severity severity;
    std::string timestamp;
    std::string computer;
    std::string user;
    std::string sourceIp;
    std::string message;
};

struct Finding {
    Severity severity;
    std::string rule;
    std::string evidence;
};

std::string channelName(LogChannel channel) {
    switch (channel) {
        case LogChannel::Security: return "Security";
        case LogChannel::System: return "System";
        case LogChannel::Application: return "Application";
        case LogChannel::PowerShell: return "PowerShell";
    }
    return "Unknown";
}

std::string severityName(Severity severity) {
    switch (severity) {
        case Severity::Informational: return "Informational";
        case Severity::Warning: return "Warning";
        case Severity::Critical: return "Critical";
    }
    return "Unknown";
}

class EventIndex {
private:
    std::unordered_map<int, std::vector<const Event*>> byEventId_;
    std::unordered_map<std::string, std::vector<const Event*>> byUser_;
    std::unordered_map<std::string, std::vector<const Event*>> bySourceIp_;

public:
    void add(const Event& event) {
        byEventId_[event.eventId].push_back(&event);

        if (!event.user.empty()) {
            byUser_[event.user].push_back(&event);
        }

        if (!event.sourceIp.empty()) {
            bySourceIp_[event.sourceIp].push_back(&event);
        }
    }

    const std::vector<const Event*>& eventId(int id) const {
        static const std::vector<const Event*> empty;
        auto it = byEventId_.find(id);
        return it == byEventId_.end() ? empty : it->second;
    }

    const std::vector<const Event*>& user(const std::string& name) const {
        static const std::vector<const Event*> empty;
        auto it = byUser_.find(name);
        return it == byUser_.end() ? empty : it->second;
    }

    const std::vector<const Event*>& sourceIp(const std::string& ip) const {
        static const std::vector<const Event*> empty;
        auto it = bySourceIp_.find(ip);
        return it == bySourceIp_.end() ? empty : it->second;
    }
};

class DetectionEngine {
public:
    static std::vector<Finding> evaluate(const std::vector<Event>& events) {
        std::vector<Finding> findings;

        EventIndex index;
        for (const auto& event : events) {
            index.add(event);
        }

        // 4625 is failed Windows logon. Counting by source and account
        // detects a concentrated authentication attack without treating
        // ordinary isolated failures as malicious by themselves.
        std::map<std::pair<std::string, std::string>, int> failures;

        for (const auto& event : events) {
            if (event.eventId == 4625) {
                failures[{event.user, event.sourceIp}]++;
            }
        }

        for (const auto& [key, count] : failures) {
            if (count >= 3) {
                findings.push_back({
                    Severity::Warning,
                    "Repeated authentication failures",
                    "user=" + key.first +
                    " source=" + key.second +
                    " failures=" + std::to_string(count)
                });
            }
        }

        // 1102 is materially different from an authentication failure:
        // clearing the Security log affects the audit trail itself.
        for (const Event* event : index.eventId(1102)) {
            findings.push_back({
                Severity::Critical,
                "Security audit log cleared",
                "record=" + std::to_string(event->recordId) +
                " user=" + event->user
            });
        }

        // 7045 records service installation. The rule is intentionally
        // independent of authentication because persistence can originate
        // from an already compromised process or administrative action.
        for (const Event* event : index.eventId(7045)) {
            findings.push_back({
                Severity::Critical,
                "Service installation observed",
                event->message
            });
        }

        // 4104 represents PowerShell script-block logging. The presence of
        // 4104 is telemetry, not proof of malicious behavior, so it is
        // classified as informational in this model.
        for (const Event* event : index.eventId(4104)) {
            findings.push_back({
                Severity::Informational,
                "PowerShell script block observed",
                "user=" + event->user
            });
        }

        return findings;
    }
};

class EventStore {
private:
    std::vector<Event> events_;

public:
    void insert(Event event) {
        if (event.recordId <= 0) {
            throw std::invalid_argument("recordId must be positive");
        }

        if (event.eventId < 0) {
            throw std::invalid_argument("eventId cannot be negative");
        }

        if (event.computer.empty()) {
            throw std::invalid_argument("computer name is required");
        }

        if (event.eventId == 4625 && event.sourceIp.empty()) {
            throw std::invalid_argument(
                "failed authentication requires a source IP"
            );
        }

        events_.push_back(std::move(event));
    }

    const std::vector<Event>& all() const {
        return events_;
    }
};

int main() {
    try {
        EventStore store;

        store.insert({
            1001, LogChannel::Security, 4624, Severity::Informational,
            "2026-10-19T05:00:00Z", "WS-101", "alice", "10.10.20.50",
            "LogonType=10 AuthenticationPackage=Negotiate"
        });

        store.insert({
            1002, LogChannel::Security, 4625, Severity::Warning,
            "2026-10-19T05:01:00Z", "WS-101", "administrator", "10.10.20.88",
            "Status=0xC000006D"
        });

        store.insert({
            1003, LogChannel::Security, 4625, Severity::Warning,
            "2026-10-19T05:01:20Z", "WS-101", "administrator", "10.10.20.88",
            "Status=0xC000006D"
        });

        store.insert({
            1004, LogChannel::Security, 4625, Severity::Warning,
            "2026-10-19T05:01:40Z", "WS-101", "administrator", "10.10.20.88",
            "Status=0xC000006D"
        });

        store.insert({
            1005, LogChannel::Security, 1102, Severity::Critical,
            "2026-10-19T05:03:00Z", "WS-101", "administrator", "",
            "Security audit log was cleared"
        });

        store.insert({
            1006, LogChannel::System, 7045, Severity::Critical,
            "2026-10-19T05:04:00Z", "WS-101", "SYSTEM", "",
            "ServiceName=RemoteSupport ImagePath=C:\\ProgramData\\support.exe"
        });

        store.insert({
            1007, LogChannel::PowerShell, 4104, Severity::Informational,
            "2026-10-19T05:05:00Z", "WS-101", "alice", "",
            "ScriptBlock=Get-Process; Get-Service"
        });

        std::cout << "Windows Event Log Governance Case Study\n";
        std::cout << "=======================================\n";

        std::map<LogChannel, int> channelCounts;
        for (const auto& event : store.all()) {
            channelCounts[event.channel]++;
        }

        std::cout << "\nChannel distribution\n";
        for (const auto& [channel, count] : channelCounts) {
            std::cout << "  " << channelName(channel)
                      << ": " << count << '\n';
        }

        const auto findings = DetectionEngine::evaluate(store.all());

        std::cout << "\nDetection findings\n";
        for (const auto& finding : findings) {
            std::cout << "  [" << severityName(finding.severity) << "] "
                      << finding.rule << " -> "
                      << finding.evidence << '\n';
        }

        std::cout << "\nOperational design characteristics\n";
        std::cout << "  Event storage: contiguous vector of normalized records\n";
        std::cout << "  Query indexes: hash maps by event ID, user, and source IP\n";
        std::cout << "  Authentication rule: 4625 failures grouped by account/source\n";
        std::cout << "  Audit-integrity rule: 1102 treated as critical evidence\n";
        std::cout << "  Persistence rule: 7045 treated independently of authentication\n";
        std::cout << "  PowerShell rule: 4104 is telemetry, not automatic compromise proof\n";

        // The in-memory indexes make repeated event-ID and source lookups
        // approximately O(1) on average, while the complete detection pass
        // remains O(n) for the supplied event set.
        std::cout << "\nComplexity\n";
        std::cout << "  Index construction: expected O(n)\n";
        std::cout << "  Rule evaluation: O(n + k), where k is indexed finding volume\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
