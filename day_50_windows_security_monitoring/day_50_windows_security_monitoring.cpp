#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

enum class Severity {
    Low,
    Medium,
    High
};

std::string severityName(Severity severity) {
    switch (severity) {
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
    }
    return "UNKNOWN";
}

struct SecurityEvent {
    int eventId{};
    long long timestamp{};
    std::string computer;
    std::string subjectUser;
    std::optional<std::string> targetUser;
    std::optional<std::string> sourceIp;
    std::optional<std::string> processName;
    std::optional<int> processId;
    std::optional<int> logonType;
    std::optional<std::string> privilege;
};

struct Alert {
    Severity severity;
    std::string rule;
    long long timestamp;
    std::string computer;
    std::string user;
    std::string evidence;
};

class RepositoryGovernanceStyleMonitor {
private:
    std::vector<SecurityEvent> events_;
    std::vector<Alert> alerts_;

    static bool containsIgnoreCase(
        const std::string& value,
        const std::string& needle
    ) {
        std::string lowerValue = value;
        std::string lowerNeedle = needle;

        std::transform(
            lowerValue.begin(),
            lowerValue.end(),
            lowerValue.begin(),
            [](unsigned char c) { return std::tolower(c); }
        );

        std::transform(
            lowerNeedle.begin(),
            lowerNeedle.end(),
            lowerNeedle.begin(),
            [](unsigned char c) { return std::tolower(c); }
        );

        return lowerValue.find(lowerNeedle) != std::string::npos;
    }

    static std::string userOf(const SecurityEvent& event) {
        return event.targetUser.value_or(event.subjectUser);
    }

    void addAlert(
        Severity severity,
        std::string rule,
        const SecurityEvent& event,
        std::string evidence
    ) {
        alerts_.push_back({
            severity,
            std::move(rule),
            event.timestamp,
            event.computer,
            userOf(event),
            std::move(evidence)
        });
    }

    void detectFailedLogonBursts() {
        std::unordered_map<std::string, std::vector<const SecurityEvent*>> grouped;

        for (const auto& event : events_) {
            if (event.eventId == 4625) {
                grouped[userOf(event)].push_back(&event);
            }
        }

        constexpr long long fiveMinutes = 5 * 60;

        for (const auto& [user, entries] : grouped) {
            std::size_t left = 0;

            for (std::size_t right = 0; right < entries.size(); ++right) {
                while (
                    left <= right &&
                    entries[right]->timestamp - entries[left]->timestamp >
                        fiveMinutes
                ) {
                    ++left;
                }

                if (right - left + 1 >= 3) {
                    const auto& event = *entries[right];
                    addAlert(
                        Severity::High,
                        "failed_logon_burst",
                        event,
                        std::to_string(right - left + 1) +
                            " failed logons within five minutes"
                    );
                    break;
                }
            }
        }
    }

    void detectPrivilegeAndProcessActivity() {
        const std::set<std::string> interpreters{
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "certutil.exe"
        };

        for (std::size_t i = 0; i < events_.size(); ++i) {
            const auto& event = events_[i];

            if (event.eventId == 4672) {
                Severity severity =
                    event.privilege &&
                    containsIgnoreCase(*event.privilege, "debug")
                    ? Severity::High
                    : Severity::Medium;

                addAlert(
                    severity,
                    "special_privilege_assignment",
                    event,
                    event.privilege.value_or("special privilege")
                );
            }

            if (
                event.eventId == 4688 &&
                event.processName &&
                interpreters.contains(*event.processName)
            ) {
                addAlert(
                    Severity::Medium,
                    "script_interpreter_process",
                    event,
                    *event.processName +
                        " PID=" +
                        std::to_string(event.processId.value_or(-1))
                );
            }

            if (
                event.eventId == 4688 &&
                i > 0 &&
                events_[i - 1].eventId == 4672 &&
                events_[i - 1].computer == event.computer &&
                events_[i - 1].subjectUser == event.subjectUser &&
                event.timestamp - events_[i - 1].timestamp <= 60
            ) {
                addAlert(
                    Severity::High,
                    "privilege_then_process",
                    event,
                    "special privilege followed by " +
                        event.processName.value_or("process")
                );
            }
        }
    }

    void detectAccountActivity() {
        for (const auto& event : events_) {
            switch (event.eventId) {
                case 4720:
                    addAlert(
                        Severity::High,
                        "account_created",
                        event,
                        "account created: " + userOf(event)
                    );
                    break;

                case 4722:
                    addAlert(
                        Severity::High,
                        "account_enabled",
                        event,
                        "account enabled: " + userOf(event)
                    );
                    break;

                case 4725:
                    addAlert(
                        Severity::Medium,
                        "account_disabled",
                        event,
                        "account disabled: " + userOf(event)
                    );
                    break;

                case 4726:
                    addAlert(
                        Severity::Medium,
                        "account_deleted",
                        event,
                        "account deleted: " + userOf(event)
                    );
                    break;

                case 4738:
                    addAlert(
                        Severity::Medium,
                        "account_changed",
                        event,
                        "account changed: " + userOf(event)
                    );
                    break;

                default:
                    break;
            }
        }
    }

    void detectPrivilegedLogons() {
        for (const auto& event : events_) {
            if (
                event.eventId == 4624 &&
                event.logonType &&
                (*event.logonType == 2 ||
                 *event.logonType == 10 ||
                 *event.logonType == 11)
            ) {
                const std::string user = userOf(event);

                if (
                    user == "Administrator" ||
                    user == "administrator" ||
                    user == "admin"
                ) {
                    addAlert(
                        Severity::High,
                        "privileged_interactive_logon",
                        event,
                        "logon_type=" +
                            std::to_string(*event.logonType)
                    );
                }
            }
        }
    }

public:
    void addEvent(SecurityEvent event) {
        if (event.eventId <= 0) {
            throw std::invalid_argument("event ID must be positive");
        }

        if (event.computer.empty() || event.subjectUser.empty()) {
            throw std::invalid_argument(
                "computer and subject user are required"
            );
        }

        events_.push_back(std::move(event));
    }

    void analyze() {
        std::sort(
            events_.begin(),
            events_.end(),
            [](const auto& a, const auto& b) {
                return a.timestamp < b.timestamp;
            }
        );

        alerts_.clear();
        detectFailedLogonBursts();
        detectPrivilegeAndProcessActivity();
        detectAccountActivity();
        detectPrivilegedLogons();

        std::sort(
            alerts_.begin(),
            alerts_.end(),
            [](const auto& a, const auto& b) {
                if (a.timestamp != b.timestamp) {
                    return a.timestamp < b.timestamp;
                }
                return static_cast<int>(a.severity) >
                       static_cast<int>(b.severity);
            }
        );
    }

    void printReport() const {
        std::map<int, int> eventCounts;

        for (const auto& event : events_) {
            ++eventCounts[event.eventId];
        }

        std::cout << "WINDOWS SECURITY MONITOR\n";
        std::cout << "========================\n";
        std::cout << "Events analyzed: " << events_.size() << "\n\n";

        std::cout << "Event counts:\n";
        for (const auto& [id, count] : eventCounts) {
            std::cout << "  Event " << id << ": " << count << "\n";
        }

        std::cout << "\nAlerts:\n";
        if (alerts_.empty()) {
            std::cout << "  No detection rules triggered.\n";
            return;
        }

        for (const auto& alert : alerts_) {
            std::cout
                << "  [" << severityName(alert.severity) << "] "
                << alert.computer << " "
                << alert.user << " "
                << alert.rule << ": "
                << alert.evidence << "\n";
        }
    }
};

int main() {
    try {
        RepositoryGovernanceStyleMonitor monitor;

        monitor.addEvent({
            4624, 0, "WS-01", "SYSTEM",
            "alice", "10.10.1.20",
            std::nullopt, std::nullopt, 2, std::nullopt
        });

        monitor.addEvent({
            4672, 120, "WS-01", "alice",
            std::nullopt, std::nullopt,
            std::nullopt, std::nullopt,
            std::nullopt, "SeDebugPrivilege"
        });

        monitor.addEvent({
            4688, 150, "WS-01", "alice",
            std::nullopt, std::nullopt,
            "powershell.exe", 2120,
            std::nullopt, std::nullopt
        });

        monitor.addEvent({
            4625, 180, "WS-01", "scanner",
            "administrator", "10.10.1.90",
            std::nullopt, std::nullopt, 10, std::nullopt
        });

        monitor.addEvent({
            4625, 240, "WS-01", "scanner",
            "administrator", "10.10.1.90",
            std::nullopt, std::nullopt, 10, std::nullopt
        });

        monitor.addEvent({
            4625, 300, "WS-01", "scanner",
            "administrator", "10.10.1.90",
            std::nullopt, std::nullopt, 10, std::nullopt
        });

        monitor.addEvent({
            4720, 420, "DC-01", "admin",
            "backupsvc", std::nullopt,
            std::nullopt, std::nullopt,
            std::nullopt, std::nullopt
        });

        monitor.addEvent({
            4722, 480, "DC-01", "admin",
            "backupsvc", std::nullopt,
            std::nullopt, std::nullopt,
            std::nullopt, std::nullopt
        });

        monitor.analyze();
        monitor.printReport();
    }
    catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
