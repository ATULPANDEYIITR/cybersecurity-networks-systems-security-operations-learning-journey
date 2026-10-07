#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

enum class Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7
};

struct LogRecord {
    std::string timestamp;
    std::string host;
    std::string service;
    std::string facility;
    Severity severity;
    std::string message;
    std::string source;
    std::optional<int> pid;
    std::optional<std::string> user;
    std::optional<std::string> ip;
};

std::string severityName(Severity severity) {
    switch (severity) {
        case Severity::Emergency: return "emerg";
        case Severity::Alert: return "alert";
        case Severity::Critical: return "crit";
        case Severity::Error: return "err";
        case Severity::Warning: return "warning";
        case Severity::Notice: return "notice";
        case Severity::Info: return "info";
        case Severity::Debug: return "debug";
    }
    return "info";
}

int severityValue(Severity severity) {
    return static_cast<int>(severity);
}

int facilityValue(const std::string& facility) {
    static const std::map<std::string, int> facilities{
        {"kern", 0},
        {"user", 1},
        {"daemon", 3},
        {"auth", 4},
        {"syslog", 5},
        {"cron", 9},
        {"authpriv", 10},
        {"local0", 16},
        {"local1", 17},
        {"local2", 18},
        {"local3", 19},
        {"local4", 20},
        {"local5", 21},
        {"local6", 22},
        {"local7", 23}
    };

    auto it = facilities.find(facility);
    return it == facilities.end() ? 3 : it->second;
}

int syslogPriority(const std::string& facility, Severity severity) {
    return facilityValue(facility) * 8 + severityValue(severity);
}

bool containsCaseInsensitive(
    const std::string& text,
    const std::string& value
) {
    std::string a = text;
    std::string b = value;

    std::transform(
        a.begin(),
        a.end(),
        a.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );

    std::transform(
        b.begin(),
        b.end(),
        b.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); }
    );

    return a.find(b) != std::string::npos;
}

class RepositoryGovernanceLogEngine {
public:
    void ingest(LogRecord record) {
        records_.push_back(std::move(record));
    }

    void validateRecord(const LogRecord& record) const {
        if (record.service.empty()) {
            throw std::invalid_argument("log record has no service");
        }

        if (record.message.empty()) {
            throw std::invalid_argument("log record has no message");
        }

        if (record.source.empty()) {
            throw std::invalid_argument("log record has no source");
        }
    }

    std::map<std::string, int> severityReport() const {
        std::map<std::string, int> result;

        for (const auto& record : records_) {
            ++result[severityName(record.severity)];
        }

        return result;
    }

    std::map<std::string, int> serviceReport() const {
        std::map<std::string, int> result;

        for (const auto& record : records_) {
            ++result[record.service];
        }

        return result;
    }

    std::vector<LogRecord> authenticationFailures() const {
        std::vector<LogRecord> result;

        for (const auto& record : records_) {
            if (record.service == "sshd" &&
                containsCaseInsensitive(record.message, "failed password")) {
                result.push_back(record);
            }
        }

        return result;
    }

    std::map<std::string, int> failedAttemptsByIp() const {
        std::map<std::string, int> result;

        for (const auto& record : authenticationFailures()) {
            if (record.ip.has_value()) {
                ++result[*record.ip];
            }
        }

        return result;
    }

    std::map<std::string, std::vector<std::string>> classifyKernelLogs() const {
        std::map<std::string, std::vector<std::string>> result;

        for (const auto& record : records_) {
            if (record.facility != "kern" && record.service != "kernel") {
                continue;
            }

            bool matched = false;

            const std::vector<std::pair<std::string, std::vector<std::string>>>
                categories{
                    {"memory", {"oom", "out of memory", "memory"}},
                    {"storage", {"i/o error", "filesystem", "nvme", "ext4"}},
                    {"network", {"link is down", "link is up", "network"}},
                    {"hardware", {"thermal", "firmware", "hardware"}},
                    {"security", {"apparmor", "selinux", "audit", "denied"}}
                };

            for (const auto& [category, keywords] : categories) {
                for (const auto& keyword : keywords) {
                    if (containsCaseInsensitive(record.message, keyword)) {
                        result[category].push_back(record.message);
                        matched = true;
                        break;
                    }
                }
            }

            if (!matched) {
                result["other"].push_back(record.message);
            }
        }

        return result;
    }

    void print() const {
        std::cout << "\nLOGGING ENGINE REPORT\n";
        std::cout << "=====================\n";

        std::cout << "\nSeverity counts:\n";
        for (const auto& [severity, count] : severityReport()) {
            std::cout << "  " << severity << ": " << count << '\n';
        }

        std::cout << "\nService counts:\n";
        for (const auto& [service, count] : serviceReport()) {
            std::cout << "  " << service << ": " << count << '\n';
        }

        std::cout << "\nAuthentication failures:\n";
        for (const auto& [ip, count] : failedAttemptsByIp()) {
            std::cout << "  " << ip << ": " << count << '\n';
        }

        std::cout << "\nKernel categories:\n";
        for (const auto& [category, messages] : classifyKernelLogs()) {
            std::cout << "  [" << category << "]\n";
            for (const auto& message : messages) {
                std::cout << "    " << message << '\n';
            }
        }
    }

private:
    std::vector<LogRecord> records_;
};

std::vector<LogRecord> buildOperationalDataset() {
    return {
        {
            "2026-10-07T16:00:00Z",
            "prod-db-01",
            "sshd",
            "authpriv",
            Severity::Warning,
            "Failed password for invalid user admin from 203.0.113.42 port 40001",
            "/var/log/auth.log",
            std::nullopt,
            std::string("admin"),
            std::string("203.0.113.42")
        },
        {
            "2026-10-07T16:00:08Z",
            "prod-db-01",
            "sshd",
            "authpriv",
            Severity::Warning,
            "Failed password for root from 203.0.113.42 port 40002",
            "/var/log/auth.log",
            std::nullopt,
            std::string("root"),
            std::string("203.0.113.42")
        },
        {
            "2026-10-07T16:00:20Z",
            "prod-db-01",
            "sshd",
            "authpriv",
            Severity::Info,
            "Accepted publickey for deploy from 10.10.20.15 port 41000",
            "/var/log/auth.log",
            std::nullopt,
            std::string("deploy"),
            std::string("10.10.20.15")
        },
        {
            "2026-10-07T16:01:00Z",
            "prod-db-01",
            "kernel",
            "kern",
            Severity::Error,
            "nvme0: I/O error, aborting command",
            "/var/log/kern.log",
            std::nullopt,
            std::nullopt,
            std::nullopt
        },
        {
            "2026-10-07T16:01:10Z",
            "prod-db-01",
            "kernel",
            "kern",
            Severity::Warning,
            "Out of memory: Kill process 8121 (postgres)",
            "/var/log/kern.log",
            8121,
            std::nullopt,
            std::nullopt
        },
        {
            "2026-10-07T16:01:30Z",
            "prod-db-01",
            "postgres",
            "local0",
            Severity::Error,
            "connection pool exhausted",
            "/var/log/postgresql/app.log",
            9012,
            std::nullopt,
            std::string("192.0.2.44")
        },
        {
            "2026-10-07T16:02:00Z",
            "prod-db-01",
            "inventory-api",
            "local0",
            Severity::Info,
            "request completed status=200 route=/health",
            "/var/log/inventory-api.json",
            9018,
            std::nullopt,
            std::string("10.10.20.15")
        }
    };
}

void demonstrateFilesystemDiscovery() {
    std::cout << "\nCONVENTIONAL LINUX LOG LOCATIONS\n";
    std::cout << "================================\n";

    const std::vector<fs::path> candidates{
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/kern.log"
    };

    for (const auto& path : candidates) {
        std::cout << "  " << path << ": "
                  << (fs::exists(path) ? "present" : "not present")
                  << '\n';
    }

    std::cout
        << "\nDistribution configuration determines which traditional text "
        << "files exist. systemd systems can store the same operational "
        << "evidence in the journal instead of, or alongside, text files.\n";
}

void demonstrateSyslog() {
    std::cout << "\nSYSLOG PRIORITY CALCULATION\n";
    std::cout << "===========================\n";

    for (const auto& [facility, severity] :
         std::vector<std::pair<std::string, Severity>>{
             {"authpriv", Severity::Warning},
             {"kern", Severity::Error},
             {"local0", Severity::Info}}) {
        std::cout << facility
                  << " / "
                  << severityName(severity)
                  << " -> priority "
                  << syslogPriority(facility, severity)
                  << '\n';
    }

    std::cout
        << "\nThe facility answers 'which subsystem?' while severity answers "
        << "'how urgent is this event?'. Combining them produces the syslog "
        << "priority value.\n";
}

void demonstrateValidation(
    RepositoryGovernanceLogEngine& engine,
    const LogRecord& validRecord
) {
    std::cout << "\nLOG RECORD VALIDATION\n";
    std::cout << "=====================\n";

    try {
        engine.validateRecord(validRecord);
        std::cout << "Valid record accepted.\n";
    } catch (const std::exception& error) {
        std::cout << "Validation failure: " << error.what() << '\n';
    }

    LogRecord invalid{
        "2026-10-07T16:05:00Z",
        "prod-db-01",
        "",
        "daemon",
        Severity::Info,
        "worker event",
        "/var/log/app.log",
        std::nullopt,
        std::nullopt,
        std::nullopt
    };

    try {
        engine.validateRecord(invalid);
        std::cout << "Invalid record accepted unexpectedly.\n";
    } catch (const std::exception& error) {
        std::cout
            << "Expected rejection: "
            << error.what()
            << '\n';
    }
}

int main() {
    try {
        std::cout << "LINUX LOGGING OPERATIONAL CASE STUDY\n";
        std::cout << "=====================================\n";

        demonstrateSyslog();
        demonstrateFilesystemDiscovery();

        RepositoryGovernanceLogEngine engine;
        const auto dataset = buildOperationalDataset();

        for (const auto& record : dataset) {
            engine.ingest(record);
        }

        demonstrateValidation(engine, dataset.front());
        engine.print();

        std::cout << "\nOPERATIONAL INTERPRETATION\n";
        std::cout << "==========================\n";
        std::cout
            << "The authentication records identify repeated SSH failures, "
            << "kernel records expose host-level storage and memory problems, "
            << "and application records describe service behavior. Keeping "
            << "these sources distinct makes diagnosis possible while "
            << "correlation connects events that share operational context.\n";

        std::cout
            << "\nProduction design considerations include log retention, "
            << "permissions, centralized collection, timestamp consistency, "
            << "rotation, integrity protection, sensitive-data redaction, "
            << "and controlled access to authentication and security logs.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
