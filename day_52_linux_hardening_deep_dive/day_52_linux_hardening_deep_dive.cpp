#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

struct Finding {
    std::string category;
    std::string control;
    std::string status;
    std::string severity;
    std::string evidence;
    std::string recommendation;
};

class GovernanceEngine {
public:
    void addFinding(
        std::string category,
        std::string control,
        std::string status,
        std::string severity,
        std::string evidence,
        std::string recommendation
    ) {
        findings_.push_back({
            std::move(category),
            std::move(control),
            std::move(status),
            std::move(severity),
            std::move(evidence),
            std::move(recommendation)
        });
    }

    const std::vector<Finding>& findings() const {
        return findings_;
    }

private:
    std::vector<Finding> findings_;
};

class LinuxHardeningEngine {
public:
    void audit() {
        auditSsh();
        auditSudo();
        auditFilesystem();
        auditKernel();
        auditAudit();
    }

    const std::vector<Finding>& findings() const {
        return engine_.findings();
    }

private:
    GovernanceEngine engine_;

    static std::optional<std::string> readFile(const std::string& path) {
        std::ifstream input(path);
        if (!input) {
            return std::nullopt;
        }

        std::ostringstream buffer;
        buffer << input.rdbuf();
        return buffer.str();
    }

    static std::map<std::string, std::string> parseKeyValueConfig(
        const std::string& content
    ) {
        std::map<std::string, std::string> values;
        std::istringstream stream(content);
        std::string line;

        while (std::getline(stream, line)) {
            auto first = line.find_first_not_of(" \t");
            if (first == std::string::npos || line[first] == '#') {
                continue;
            }

            auto separator = line.find_first_of(" \t", first);
            if (separator == std::string::npos) {
                continue;
            }

            auto key = line.substr(first, separator - first);

            auto valueStart = line.find_first_not_of(" \t", separator);
            if (valueStart == std::string::npos) {
                continue;
            }

            auto value = line.substr(valueStart);
            std::transform(
                key.begin(),
                key.end(),
                key.begin(),
                [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                }
            );

            values[key] = value;
        }

        return values;
    }

    void auditSsh() {
        const auto content = readFile("/etc/ssh/sshd_config");

        if (!content) {
            engine_.addFinding(
                "SSH",
                "sshd_config",
                "UNKNOWN",
                "medium",
                "Unable to read /etc/ssh/sshd_config.",
                "Inspect the SSH daemon configuration with appropriate permissions."
            );
            return;
        }

        const auto config = parseKeyValueConfig(*content);

        struct Rule {
            const char* directive;
            bool (*valid)(const std::string&);
            const char* recommendation;
        };

        const std::array<Rule, 4> rules{{
            {
                "permitrootlogin",
                [](const std::string& value) {
                    return value == "no" || value == "prohibit-password";
                },
                "Disable direct root SSH login unless explicitly required."
            },
            {
                "passwordauthentication",
                [](const std::string& value) {
                    return value == "no";
                },
                "Prefer key-based authentication where operationally appropriate."
            },
            {
                "permitemptypasswords",
                [](const std::string& value) {
                    return value == "no";
                },
                "Disable empty-password SSH authentication."
            },
            {
                "x11forwarding",
                [](const std::string& value) {
                    return value == "no";
                },
                "Disable X11 forwarding when it is not required."
            }
        }};

        for (const auto& rule : rules) {
            auto iterator = config.find(rule.directive);

            if (iterator == config.end()) {
                engine_.addFinding(
                    "SSH",
                    rule.directive,
                    "REVIEW",
                    "medium",
                    "Directive is not explicitly configured.",
                    rule.recommendation
                );
            } else if (rule.valid(iterator->second)) {
                engine_.addFinding(
                    "SSH",
                    rule.directive,
                    "PASS",
                    "info",
                    std::string(rule.directive) + "=" + iterator->second,
                    "No immediate issue identified."
                );
            } else {
                engine_.addFinding(
                    "SSH",
                    rule.directive,
                    "FAIL",
                    "high",
                    std::string(rule.directive) + "=" + iterator->second,
                    rule.recommendation
                );
            }
        }
    }

    void auditSudo() {
        const auto content = readFile("/etc/sudoers");

        if (!content) {
            engine_.addFinding(
                "sudo",
                "sudoers readability",
                "UNKNOWN",
                "medium",
                "Unable to read /etc/sudoers.",
                "Inspect sudo policy using appropriate administrative permissions."
            );
            return;
        }

        std::istringstream stream(*content);
        std::string line;
        std::vector<std::string> passwordless;
        std::size_t lineNumber = 0;

        while (std::getline(stream, line)) {
            ++lineNumber;

            auto first = line.find_first_not_of(" \t");
            if (first == std::string::npos || line[first] == '#') {
                continue;
            }

            if (line.find("NOPASSWD:") != std::string::npos ||
                line.find("NOPASSWD :") != std::string::npos) {
                passwordless.push_back(
                    "line " + std::to_string(lineNumber) + ": " + line
                );
            }
        }

        if (passwordless.empty()) {
            engine_.addFinding(
                "sudo",
                "passwordless elevation",
                "PASS",
                "info",
                "No NOPASSWD rule found in /etc/sudoers.",
                "Review included sudoers files as part of the complete policy."
            );
        } else {
            std::ostringstream evidence;
            for (std::size_t i = 0; i < passwordless.size(); ++i) {
                if (i != 0) {
                    evidence << "; ";
                }
                evidence << passwordless[i];
            }

            engine_.addFinding(
                "sudo",
                "passwordless elevation",
                "REVIEW",
                "medium",
                evidence.str(),
                "Confirm that passwordless commands are narrowly scoped and justified."
            );
        }
    }

    static std::string modeString(mode_t mode) {
        std::ostringstream output;
        output << std::oct << std::setfill('0') << std::setw(4)
               << (mode & 0777);
        return output.str();
    }

    void auditFilesystem() {
        struct FileRule {
            const char* path;
            mode_t maximum;
            bool sensitive;
        };

        const std::array<FileRule, 3> files{{
            {"/etc/passwd", 0644, false},
            {"/etc/shadow", 0640, true},
            {"/etc/sudoers", 0440, true}
        }};

        for (const auto& file : files) {
            struct stat metadata{};

            if (stat(file.path, &metadata) != 0) {
                engine_.addFinding(
                    "Filesystem permissions",
                    file.path,
                    "UNKNOWN",
                    "medium",
                    std::strerror(errno),
                    "Inspect ownership and permissions manually."
                );
                continue;
            }

            const mode_t mode = metadata.st_mode & 0777;

            if (file.sensitive && (mode & 0007)) {
                engine_.addFinding(
                    "Filesystem permissions",
                    file.path,
                    "FAIL",
                    "high",
                    "Mode " + modeString(mode) + " grants world permissions.",
                    "Remove unnecessary world permissions and verify ownership."
                );
            } else if ((mode & ~file.maximum) != 0) {
                engine_.addFinding(
                    "Filesystem permissions",
                    file.path,
                    "REVIEW",
                    "medium",
                    "Mode " + modeString(mode) +
                        " exceeds baseline " + modeString(file.maximum) + ".",
                    "Verify that every additional permission is intentional."
                );
            } else {
                engine_.addFinding(
                    "Filesystem permissions",
                    file.path,
                    "PASS",
                    "info",
                    "Mode " + modeString(mode),
                    "No excessive permission detected against this baseline."
                );
            }
        }
    }

    void auditKernel() {
        struct KernelRule {
            const char* name;
            const char* path;
            const char* expected;
        };

        const std::array<KernelRule, 3> controls{{
            {
                "kernel.randomize_va_space",
                "/proc/sys/kernel/randomize_va_space",
                "2"
            },
            {
                "fs.protected_hardlinks",
                "/proc/sys/fs/protected_hardlinks",
                "1"
            },
            {
                "fs.protected_symlinks",
                "/proc/sys/fs/protected_symlinks",
                "1"
            }
        }};

        for (const auto& control : controls) {
            const auto value = readFile(control.path);

            if (!value) {
                engine_.addFinding(
                    "Kernel controls",
                    control.name,
                    "UNKNOWN",
                    "medium",
                    std::string("Unable to read ") + control.path,
                    "Verify the kernel control manually."
                );
                continue;
            }

            std::string actual = *value;
            actual.erase(
                std::remove_if(
                    actual.begin(),
                    actual.end(),
                    [](unsigned char c) { return std::isspace(c); }
                ),
                actual.end()
            );

            if (actual == control.expected) {
                engine_.addFinding(
                    "Kernel controls",
                    control.name,
                    "PASS",
                    "info",
                    "Value " + actual,
                    "No immediate issue identified."
                );
            } else {
                engine_.addFinding(
                    "Kernel controls",
                    control.name,
                    "FAIL",
                    "high",
                    "Value " + actual +
                        "; expected " + control.expected + ".",
                    std::string("Evaluate ") + control.name +
                        " using the distribution's supported persistent configuration."
                );
            }
        }
    }

    void auditAudit() {
        const auto value = readFile("/proc/sys/kernel/audit_enabled");

        if (!value) {
            engine_.addFinding(
                "Auditing",
                "kernel audit status",
                "UNKNOWN",
                "medium",
                "Unable to read /proc/sys/kernel/audit_enabled.",
                "Inspect the audit subsystem with administrative permissions."
            );
            return;
        }

        const std::string actual = value->substr(
            0,
            value->find_first_of("\r\n")
        );

        if (actual == "1") {
            engine_.addFinding(
                "Auditing",
                "kernel audit status",
                "PASS",
                "info",
                "Kernel audit interface is enabled.",
                "Verify that persistent audit rules cover required security events."
            );
        } else {
            engine_.addFinding(
                "Auditing",
                "kernel audit status",
                "REVIEW",
                "high",
                "kernel audit status=" + actual,
                "Verify the active auditing architecture and persistent audit configuration."
            );
        }
    }
};

int main() {
    if (geteuid() < 0) {
        std::cerr << "Unable to determine effective UID.\n";
        return 2;
    }

    LinuxHardeningEngine auditor;
    auditor.audit();

    std::map<std::string, int> counts;

    for (const auto& finding : auditor.findings()) {
        ++counts[finding.status];

        std::cout
            << "[" << std::left << std::setw(7) << finding.status << "] "
            << std::setw(24) << finding.category
            << finding.control << '\n'
            << "  Severity: " << finding.severity << '\n'
            << "  Evidence: " << finding.evidence << '\n'
            << "  Action:   " << finding.recommendation << "\n\n";
    }

    std::cout << "Result counts:\n";
    for (const auto& [status, count] : counts) {
        std::cout << "  " << status << ": " << count << '\n';
    }

    const bool failure = std::any_of(
        auditor.findings().begin(),
        auditor.findings().end(),
        [](const Finding& finding) {
            return finding.status == "FAIL";
        }
    );

    return failure ? 1 : 0;
}
