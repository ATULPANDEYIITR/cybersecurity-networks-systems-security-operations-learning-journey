#include <algorithm>
#include <bitset>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

std::string severityName(Severity severity) {
    switch (severity) {
        case Severity::Info: return "INFO";
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

int severityPenalty(Severity severity) {
    switch (severity) {
        case Severity::Info: return 0;
        case Severity::Low: return 2;
        case Severity::Medium: return 5;
        case Severity::High: return 10;
        case Severity::Critical: return 20;
    }
    return 0;
}

struct Finding {
    std::string area;
    Severity severity;
    std::string title;
    std::string detail;
    std::string recommendation;
};

struct User {
    std::string name;
    std::set<std::string> groups;
    bool root{false};
    bool locked{false};
    bool publicKeyConfigured{false};
};

struct SSHPolicy {
    bool permitRootLogin{false};
    bool passwordAuthentication{false};
    bool publicKeyAuthentication{true};
    std::set<std::string> allowedUsers;
    std::set<std::string> allowedGroups;
    int maxAuthTries{3};
    bool x11Forwarding{false};
    bool agentForwarding{false};
    bool tcpForwarding{false};

    std::pair<bool, std::string> authorize(
        const User* user,
        const std::string& method,
        int attempts
    ) const {
        if (user == nullptr) {
            return {false, "Unknown account."};
        }

        if (user->locked) {
            return {false, "Account is locked."};
        }

        if (user->root && !permitRootLogin) {
            return {false, "Direct root SSH login is disabled."};
        }

        if (!allowedUsers.empty() &&
            allowedUsers.find(user->name) == allowedUsers.end()) {
            return {false, "Account is outside the allowed SSH users."};
        }

        bool groupAllowed = false;
        for (const auto& group : user->groups) {
            if (allowedGroups.find(group) != allowedGroups.end()) {
                groupAllowed = true;
                break;
            }
        }

        if (!allowedGroups.empty() && !groupAllowed) {
            return {false, "User is outside the allowed SSH groups."};
        }

        if (attempts > maxAuthTries) {
            return {false, "Maximum authentication attempts exceeded."};
        }

        if (method == "password" && !passwordAuthentication) {
            return {false, "Password authentication is disabled."};
        }

        if (method == "public_key") {
            if (!publicKeyAuthentication) {
                return {false, "Public-key authentication is disabled."};
            }

            if (!user->publicKeyConfigured) {
                return {false, "No public key is configured for this account."};
            }
        }

        return {true, "SSH policy permits the connection."};
    }

    std::vector<Finding> audit() const {
        std::vector<Finding> findings;

        if (permitRootLogin) {
            findings.push_back({
                "SSH",
                Severity::Critical,
                "Direct root login enabled",
                "Remote users can authenticate directly as root.",
                "Disable direct root SSH access and use controlled privilege escalation."
            });
        }

        if (passwordAuthentication) {
            findings.push_back({
                "SSH",
                Severity::High,
                "Password authentication enabled",
                "SSH accepts password-based authentication.",
                "Prefer public-key authentication and disable passwords where appropriate."
            });
        }

        if (maxAuthTries > 4) {
            findings.push_back({
                "SSH",
                Severity::Medium,
                "High authentication retry limit",
                "The configured retry count is unnecessarily high.",
                "Use a restrictive authentication attempt limit."
            });
        }

        if (x11Forwarding) {
            findings.push_back({
                "SSH",
                Severity::Medium,
                "X11 forwarding enabled",
                "SSH sessions can request X11 forwarding.",
                "Disable it unless explicitly required."
            });
        }

        if (agentForwarding) {
            findings.push_back({
                "SSH",
                Severity::Medium,
                "Agent forwarding enabled",
                "Forwarded SSH agents can expose credentials through compromised hosts.",
                "Disable agent forwarding unless required."
            });
        }

        if (tcpForwarding) {
            findings.push_back({
                "SSH",
                Severity::Medium,
                "TCP forwarding enabled",
                "Users can create SSH tunnels.",
                "Disable forwarding unless tunneling is explicitly authorized."
            });
        }

        return findings;
    }
};

struct SudoRule {
    std::set<std::string> users;
    std::set<std::string> commands;
    bool requirePassword{true};
    bool noexec{false};

    bool matches(const std::string& user, const std::string& command) const {
        const bool userMatch =
            users.count("ALL") > 0 || users.count(user) > 0;

        const bool commandMatch =
            commands.count("ALL") > 0 || commands.count(command) > 0;

        return userMatch && commandMatch;
    }
};

class SudoPolicy {
private:
    std::vector<SudoRule> rules;

public:
    explicit SudoPolicy(std::vector<SudoRule> configuredRules)
        : rules(std::move(configuredRules)) {}

    std::pair<bool, std::string> authorize(
        const std::string& user,
        const std::string& command
    ) const {
        for (const auto& rule : rules) {
            if (rule.matches(user, command)) {
                std::ostringstream result;
                result << "Authorized; password_required="
                       << std::boolalpha << rule.requirePassword
                       << ", noexec=" << rule.noexec;
                return {true, result.str()};
            }
        }

        return {false, "No sudo rule authorizes this command."};
    }

    std::vector<Finding> audit() const {
        std::vector<Finding> findings;

        for (const auto& rule : rules) {
            if (rule.users.count("ALL") > 0 &&
                rule.commands.count("ALL") > 0) {
                findings.push_back({
                    "sudo",
                    Severity::Critical,
                    "Unrestricted sudo rule",
                    "Every user can execute every command with privilege.",
                    "Replace unrestricted authorization with explicit command rules."
                });
            } else if (rule.commands.count("ALL") > 0) {
                findings.push_back({
                    "sudo",
                    Severity::High,
                    "Broad sudo command scope",
                    "The rule permits unrestricted command execution for its users.",
                    "Apply least privilege and authorize only required commands."
                });
            }

            if (!rule.requirePassword) {
                findings.push_back({
                    "sudo",
                    Severity::Medium,
                    "Passwordless sudo",
                    "The rule does not require a password.",
                    "Use passwordless execution only for controlled automation."
                });
            }
        }

        return findings;
    }
};

struct FileObject {
    std::string path;
    std::string owner;
    std::string group;
    unsigned int mode;
    bool directory{false};
};

class PermissionEngine {
private:
    std::vector<FileObject> objects;

    int permissionBits(
        const FileObject& object,
        const std::string& user,
        const std::set<std::string>& groups,
        std::string& selectedClass
    ) const {
        if (object.owner == user) {
            selectedClass = "owner";
            return (object.mode >> 6) & 7;
        }

        if (groups.count(object.group) > 0) {
            selectedClass = "group";
            return (object.mode >> 3) & 7;
        }

        selectedClass = "other";
        return object.mode & 7;
    }

public:
    explicit PermissionEngine(std::vector<FileObject> configuredObjects)
        : objects(std::move(configuredObjects)) {}

    std::pair<bool, std::string> canAccess(
        const std::string& path,
        const std::string& user,
        const std::set<std::string>& groups,
        const std::string& action
    ) const {
        auto iterator = std::find_if(
            objects.begin(),
            objects.end(),
            [&path](const FileObject& object) {
                return object.path == path;
            }
        );

        if (iterator == objects.end()) {
            return {false, "Path does not exist in the model."};
        }

        int required = 0;
        if (action == "read") required = 4;
        else if (action == "write") required = 2;
        else if (action == "execute") required = 1;
        else return {false, "Unsupported permission action."};

        std::string selectedClass;
        int available = permissionBits(
            *iterator,
            user,
            groups,
            selectedClass
        );

        if ((available & required) == required) {
            return {
                true,
                "Allowed by " + selectedClass + " permission bits."
            };
        }

        return {
            false,
            "Denied by " + selectedClass + " permission bits."
        };
    }

    std::vector<Finding> audit() const {
        std::vector<Finding> findings;

        for (const auto& object : objects) {
            unsigned int basicMode = object.mode & 0777;

            if (basicMode & 0002) {
                findings.push_back({
                    "Permissions",
                    Severity::High,
                    "World-writable object",
                    object.path + " permits writes by other users.",
                    "Remove unnecessary write permission for other users."
                });
            }

            if (!object.directory && (basicMode & 0004)) {
                findings.push_back({
                    "Permissions",
                    Severity::Medium,
                    "World-readable file",
                    object.path + " can be read by other users.",
                    "Restrict sensitive file access to the required owner or group."
                });
            }

            if (object.mode & 04000) {
                findings.push_back({
                    "Permissions",
                    Severity::High,
                    "Setuid executable",
                    object.path + " executes with its owner's effective privileges.",
                    "Verify that the privileged executable is required and trusted."
                });
            }

            if (object.directory && (object.mode & 02000)) {
                findings.push_back({
                    "Permissions",
                    Severity::Low,
                    "Setgid directory",
                    object.path + " propagates group ownership behavior.",
                    "Verify that inherited group ownership is intentional."
                });
            }
        }

        return findings;
    }
};

struct Service {
    std::string name;
    bool enabledAtBoot;
    std::set<int> ports;
    bool businessRequired;
    bool remoteReachable;
};

class ServiceMinimizer {
private:
    std::vector<Service> services;

public:
    explicit ServiceMinimizer(std::vector<Service> configuredServices)
        : services(std::move(configuredServices)) {}

    std::vector<Finding> audit() const {
        std::vector<Finding> findings;

        for (const auto& service : services) {
            if (!service.businessRequired && service.enabledAtBoot) {
                findings.push_back({
                    "Services",
                    Severity::High,
                    "Unnecessary enabled service",
                    service.name + " starts automatically without a business requirement.",
                    "Disable or remove the service."
                });
            }

            if (!service.businessRequired && !service.ports.empty()) {
                findings.push_back({
                    "Services",
                    Severity::High,
                    "Unnecessary listener",
                    service.name + " exposes network ports without a business requirement.",
                    "Stop the service or remove unnecessary listeners."
                });
            }

            if (service.remoteReachable && !service.ports.empty()) {
                findings.push_back({
                    "Services",
                    Severity::Medium,
                    "Remote service exposure",
                    service.name + " has remotely reachable listeners.",
                    "Verify that each exposed listener is required."
                });
            }
        }

        return findings;
    }
};

struct HostConfiguration {
    bool firewallEnabled;
    bool automaticUpdates;
    bool auditLogging;
    bool timeSynchronization;
    bool restrictedCoreDumps;
    bool restrictedKernelModules;
    bool fileIntegrityMonitoring;
    bool secureBoot;
};

class ConfigurationAuditor {
private:
    HostConfiguration configuration;

public:
    explicit ConfigurationAuditor(HostConfiguration configured)
        : configuration(configured) {}

    std::vector<Finding> audit() const {
        std::vector<Finding> findings;

        if (!configuration.firewallEnabled) {
            findings.push_back({
                "Secure configuration",
                Severity::High,
                "Firewall disabled",
                "Host network exposure is not constrained locally.",
                "Enable a host firewall with a minimal allowed traffic policy."
            });
        }

        if (!configuration.automaticUpdates) {
            findings.push_back({
                "Secure configuration",
                Severity::Medium,
                "Automatic security updates disabled",
                "Security fixes may remain unapplied.",
                "Use controlled automatic patching or equivalent lifecycle management."
            });
        }

        if (!configuration.auditLogging) {
            findings.push_back({
                "Secure configuration",
                Severity::High,
                "Audit logging disabled",
                "Security events may be unavailable during investigation.",
                "Enable appropriate audit and system logging."
            });
        }

        if (!configuration.timeSynchronization) {
            findings.push_back({
                "Secure configuration",
                Severity::Medium,
                "Time synchronization disabled",
                "Security event timelines can become unreliable.",
                "Synchronize system clocks with a trusted time source."
            });
        }

        if (!configuration.restrictedCoreDumps) {
            findings.push_back({
                "Secure configuration",
                Severity::Medium,
                "Core dumps unrestricted",
                "Crash artifacts can contain sensitive memory.",
                "Restrict core dumps according to security requirements."
            });
        }

        if (!configuration.restrictedKernelModules) {
            findings.push_back({
                "Secure configuration",
                Severity::Medium,
                "Kernel module loading unrestricted",
                "Privileged kernel extensibility increases attack surface.",
                "Restrict module loading where operationally appropriate."
            });
        }

        if (!configuration.fileIntegrityMonitoring) {
            findings.push_back({
                "Secure configuration",
                Severity::Medium,
                "File integrity monitoring disabled",
                "Unauthorized modifications to critical files may go undetected.",
                "Monitor sensitive configuration and executable paths."
            });
        }

        if (!configuration.secureBoot) {
            findings.push_back({
                "Secure configuration",
                Severity::Low,
                "Secure Boot disabled",
                "Firmware-level boot-chain verification is not active.",
                "Enable Secure Boot when platform and operational requirements permit it."
            });
        }

        return findings;
    }
};

class GovernanceEngine {
private:
    SSHPolicy ssh;
    SudoPolicy sudo;
    PermissionEngine permissions;
    ConfigurationAuditor configuration;
    ServiceMinimizer services;

public:
    GovernanceEngine(
        SSHPolicy sshPolicy,
        SudoPolicy sudoPolicy,
        PermissionEngine permissionPolicy,
        ConfigurationAuditor configurationPolicy,
        ServiceMinimizer servicePolicy
    )
        : ssh(std::move(sshPolicy)),
          sudo(std::move(sudoPolicy)),
          permissions(std::move(permissionPolicy)),
          configuration(std::move(configurationPolicy)),
          services(std::move(servicePolicy)) {}

    std::vector<Finding> findings() const {
        std::vector<Finding> all;

        auto append = [&all](const std::vector<Finding>& source) {
            all.insert(all.end(), source.begin(), source.end());
        };

        append(ssh.audit());
        append(sudo.audit());
        append(permissions.audit());
        append(configuration.audit());
        append(services.audit());

        return all;
    }

    int score() const {
        int penalty = 0;

        for (const auto& finding : findings()) {
            penalty += severityPenalty(finding.severity);
        }

        return std::max(0, 100 - penalty);
    }

    void printReport() const {
        auto all = findings();

        std::cout << "\n=== Linux Security Governance Report ===\n";
        std::cout << "Posture score: " << score() << "/100\n";
        std::cout << "Finding count: " << all.size() << "\n";

        for (const auto& finding : all) {
            std::cout
                << "\n[" << std::left << std::setw(8)
                << severityName(finding.severity) << "] "
                << finding.area << ": "
                << finding.title << "\n"
                << "    " << finding.detail << "\n"
                << "    Recommendation: "
                << finding.recommendation << "\n";
        }
    }

    void demonstrate(const std::map<std::string, User>& users) const {
        std::cout << "\n=== SSH Access Case Study ===\n";

        struct LoginAttempt {
            std::string user;
            std::string method;
            int attempts;
        };

        const std::vector<LoginAttempt> attempts{
            {"opsadmin", "public_key", 1},
            {"developer", "public_key", 1},
            {"legacy", "password", 1},
            {"root", "public_key", 1},
            {"opsadmin", "public_key", 5}
        };

        for (const auto& attempt : attempts) {
            auto iterator = users.find(attempt.user);
            const User* user =
                iterator == users.end() ? nullptr : &iterator->second;

            auto result = ssh.authorize(
                user,
                attempt.method,
                attempt.attempts
            );

            std::cout
                << (result.first ? "ALLOW" : "DENY ")
                << " " << attempt.user
                << " -> " << result.second << "\n";
        }

        std::cout << "\n=== sudo Case Study ===\n";

        const std::vector<std::pair<std::string, std::string>> sudoRequests{
            {"opsadmin", "/usr/bin/systemctl restart nginx"},
            {"opsadmin", "/bin/bash"},
            {"developer", "/usr/bin/journalctl"},
            {"developer", "/bin/bash"}
        };

        for (const auto& request : sudoRequests) {
            auto result = sudo.authorize(request.first, request.second);

            std::cout
                << (result.first ? "ALLOW" : "DENY ")
                << " " << request.first
                << " -> " << request.second
                << ": " << result.second << "\n";
        }

        std::cout << "\n=== Filesystem Case Study ===\n";

        const std::set<std::string> developerGroups{"developers"};

        const std::vector<std::tuple<std::string, std::string>> fileRequests{
            {"/etc/ssh/sshd_config", "read"},
            {"/srv/application", "execute"},
            {"/tmp/uploads", "write"}
        };

        for (const auto& request : fileRequests) {
            auto result = permissions.canAccess(
                std::get<0>(request),
                "developer",
                developerGroups,
                std::get<1>(request)
            );

            std::cout
                << (result.first ? "ALLOW" : "DENY ")
                << " developer "
                << std::get<1>(request)
                << " " << std::get<0>(request)
                << ": " << result.second << "\n";
        }
    }
};

int main() {
    std::cout << "Linux Security Governance Engine\n";
    std::cout
        << "This C++17 case study evaluates policy without modifying "
        << "the host operating system.\n";

    std::map<std::string, User> users{
        {
            "opsadmin",
            {
                "opsadmin",
                {"linux-admins"},
                false,
                false,
                true
            }
        },
        {
            "developer",
            {
                "developer",
                {"developers"},
                false,
                false,
                true
            }
        },
        {
            "legacy",
            {
                "legacy",
                {"legacy-users"},
                false,
                false,
                false
            }
        },
        {
            "root",
            {
                "root",
                {"root"},
                true,
                false,
                true
            }
        }
    };

    SSHPolicy ssh{
        false,
        false,
        true,
        {"opsadmin", "developer"},
        {"linux-admins"},
        3,
        false,
        false,
        false
    };

    SudoPolicy sudo({
        {
            {"opsadmin"},
            {
                "/usr/bin/systemctl restart nginx",
                "/usr/bin/systemctl status nginx"
            },
            true,
            true
        },
        {
            {"developer"},
            {"/usr/bin/journalctl"},
            true,
            true
        }
    });

    PermissionEngine permissions({
        {"/etc/ssh/sshd_config", "root", "root", 0600, false},
        {"/etc/shadow", "root", "shadow", 0640, false},
        {"/srv/application", "deploy", "app", 0750, true},
        {"/tmp/uploads", "deploy", "app", 0777, true},
        {"/usr/local/bin/privileged-helper", "root", "root", 04755, false}
    });

    ConfigurationAuditor configuration({
        true,
        true,
        true,
        true,
        true,
        true,
        false,
        true
    });

    ServiceMinimizer services({
        {"sshd", true, {22}, true, true},
        {"nginx", true, {443}, true, true},
        {"telnet", true, {23}, false, true},
        {"cups", true, {631}, false, false}
    });

    GovernanceEngine engine(
        ssh,
        sudo,
        permissions,
        configuration,
        services
    );

    engine.demonstrate(users);
    engine.printReport();

    std::cout << "\n=== Architectural Boundaries ===\n";
    std::cout
        << "SSH answers whether a remote session may be established.\n"
        << "sudo answers whether an authenticated account may execute a "
        << "specific privileged command.\n"
        << "Filesystem permissions answer whether a process identity may "
        << "access a filesystem object.\n"
        << "Secure configuration controls dangerous host-wide behavior.\n"
        << "Service minimization reduces the number of active components "
        << "that can expose vulnerabilities.\n";

    return 0;
}
