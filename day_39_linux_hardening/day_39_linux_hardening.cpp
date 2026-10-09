#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

enum class Severity { Critical = 0, High = 1, Medium = 2, Low = 3, Info = 4 };

std::string toString(Severity severity) {
    switch (severity) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        case Severity::Info: return "INFO";
    }
    throw std::logic_error("Unknown severity");
}

struct Finding {
    std::string control;
    Severity severity;
    std::string title;
    std::string evidence;
    std::string remediation;
};

struct Account {
    std::string name;
    unsigned int uid;
    bool passwordLocked;
    bool interactive;
    bool sudo;
    bool service;
    std::string shell;
};

struct SshPolicy {
    bool rootLoginAllowed;
    bool passwordAuthentication;
    bool publicKeyAuthentication;
    bool tcpForwarding;
    unsigned int maxAuthTries;
    std::set<std::string> allowedUsers;
};

struct FirewallRule {
    std::string direction;
    std::string action;
    std::string protocol;
    int port;
    std::string source;
};

struct FirewallPolicy {
    std::string inboundDefault;
    std::string outboundDefault;
    std::string forwardDefault;
    std::vector<FirewallRule> rules;
};

struct PatchInventory {
    int criticalPending;
    int securityPending;
    int daysSinceSuccessfulUpdate;
    bool rebootRequired;
    bool unattendedUpdatesEnabled;
};

struct AuditInventory {
    bool auditdEnabled;
    bool persistentRules;
    bool authenticationLogs;
    bool timeSynchronization;
    bool integrityMonitoring;
    int retentionDays;
};

class GovernanceEngine {
public:
    std::vector<Finding> assessAccounts(const std::vector<Account>& accounts) const {
        std::vector<Finding> findings;
        std::map<unsigned int, std::string> uidOwners;
        std::set<std::string> names;

        for (const auto& account : accounts) {
            if (!names.insert(account.name).second) {
                findings.push_back({
                    "ACC-DUPLICATE", Severity::High,
                    "Duplicate account inventory entry", account.name,
                    "Deduplicate the inventory and investigate account provisioning."
                });
            }

            auto owner = uidOwners.find(account.uid);
            if (owner != uidOwners.end()) {
                findings.push_back({
                    "ACC-UID-COLLISION", Severity::High,
                    "UID collision",
                    account.name + " shares UID " + std::to_string(account.uid) +
                        " with " + owner->second,
                    "Verify file ownership and remove unintended UID sharing."
                });
            } else {
                uidOwners.emplace(account.uid, account.name);
            }

            if (account.uid == 0 && account.name != "root") {
                findings.push_back({
                    "ACC-UID0", Severity::Critical,
                    "Unexpected superuser identity", account.name,
                    "Investigate immediately and remove unintended UID 0 privileges."
                });
            }

            if (account.sudo && account.service) {
                findings.push_back({
                    "ACC-SERVICE-PRIVILEGE", Severity::High,
                    "Service identity has administrator privileges", account.name,
                    "Remove interactive sudo privileges unless explicitly justified."
                });
            }

            if (account.interactive && account.service &&
                account.shell != "/usr/sbin/nologin" &&
                account.shell != "/sbin/nologin") {
                findings.push_back({
                    "ACC-SERVICE-SHELL", Severity::Medium,
                    "Service account has an interactive shell",
                    account.name + ": " + account.shell,
                    "Use a non-login shell if compatible with the service."
                });
            }

            if (account.name == "root" && !account.passwordLocked) {
                findings.push_back({
                    "ACC-ROOT-PASSWORD", Severity::High,
                    "Root password is not locked", "root",
                    "Review direct root authentication and use controlled privilege escalation."
                });
            }
        }

        return findings;
    }

    std::vector<Finding> assessSsh(const SshPolicy& policy) const {
        std::vector<Finding> findings;

        if (policy.rootLoginAllowed) {
            findings.push_back({
                "SSH-ROOT", Severity::Critical,
                "Direct root SSH login is allowed", "PermitRootLogin permits root access",
                "Set PermitRootLogin no and test a separate administrative account."
            });
        }

        if (policy.passwordAuthentication) {
            findings.push_back({
                "SSH-PASSWORD", Severity::High,
                "SSH password authentication is enabled", "PasswordAuthentication=yes",
                "Prefer approved public-key or centrally managed strong authentication."
            });
        }

        if (!policy.publicKeyAuthentication) {
            findings.push_back({
                "SSH-PUBKEY", Severity::High,
                "Public-key authentication is disabled", "PubkeyAuthentication=no",
                "Enable a reviewed authentication method and validate recovery access."
            });
        }

        if (policy.maxAuthTries == 0 || policy.maxAuthTries > 4) {
            findings.push_back({
                "SSH-TRIES", Severity::Medium,
                "Authentication attempt limit outside policy",
                std::to_string(policy.maxAuthTries),
                "Use a small positive MaxAuthTries value."
            });
        }

        if (policy.allowedUsers.empty()) {
            findings.push_back({
                "SSH-ALLOWLIST", Severity::Medium,
                "No SSH user allowlist is defined", "Allowed-user set is empty",
                "Define authorized SSH identities and verify automation dependencies."
            });
        }

        if (policy.tcpForwarding) {
            findings.push_back({
                "SSH-FORWARD", Severity::Medium,
                "TCP forwarding is enabled", "AllowTcpForwarding=yes",
                "Disable forwarding or restrict it to accounts with a documented need."
            });
        }

        return findings;
    }

    std::vector<Finding> assessFirewall(const FirewallPolicy& policy) const {
        std::vector<Finding> findings;

        if (policy.inboundDefault != "deny" &&
            policy.inboundDefault != "reject") {
            findings.push_back({
                "FW-INBOUND-DEFAULT", Severity::Critical,
                "Inbound traffic is not denied by default",
                policy.inboundDefault,
                "Use a deny-by-default policy and add narrow service-specific exceptions."
            });
        }

        if (policy.forwardDefault == "allow") {
            findings.push_back({
                "FW-FORWARD", Severity::High,
                "Forwarded traffic is allowed by default", policy.forwardDefault,
                "Restrict forwarding to documented routing requirements."
            });
        }

        using Signature = std::tuple<std::string, std::string, std::string, int, std::string>;
        std::set<Signature> signatures;

        for (const auto& rule : policy.rules) {
            if (rule.direction != "inbound" &&
                rule.direction != "outbound" &&
                rule.direction != "forward") {
                findings.push_back({
                    "FW-DIRECTION", Severity::High,
                    "Invalid firewall direction", rule.direction,
                    "Use inbound, outbound, or forward."
                });
                continue;
            }

            if (rule.action != "allow" && rule.action != "deny" &&
                rule.action != "reject") {
                findings.push_back({
                    "FW-ACTION", Severity::High,
                    "Invalid firewall action", rule.action,
                    "Use allow, deny, or reject."
                });
                continue;
            }

            if (rule.port < 0 || rule.port > 65535) {
                findings.push_back({
                    "FW-PORT", Severity::High,
                    "Invalid firewall port", std::to_string(rule.port),
                    "Use zero for a protocol without a transport port, or a valid port."
                });
                continue;
            }

            Signature signature{
                rule.direction, rule.action, rule.protocol, rule.port, rule.source
            };

            if (!signatures.insert(signature).second) {
                findings.push_back({
                    "FW-DUPLICATE", Severity::Low,
                    "Duplicate firewall rule", rule.source,
                    "Review ordering and remove redundant rules."
                });
            }

            if (rule.direction == "inbound" && rule.action == "allow" &&
                rule.protocol == "tcp" && rule.port == 22 &&
                (rule.source == "any" || rule.source == "0.0.0.0/0" ||
                 rule.source == "::/0")) {
                findings.push_back({
                    "FW-SSH-OPEN", Severity::High,
                    "SSH is open to all sources", rule.source,
                    "Restrict SSH to trusted administrative networks or an access gateway."
                });
            }

            if (rule.direction == "inbound" && rule.action == "allow" &&
                (rule.port == 23 || rule.port == 445 || rule.port == 3389) &&
                (rule.source == "any" || rule.source == "0.0.0.0/0" ||
                 rule.source == "::/0")) {
                findings.push_back({
                    "FW-SENSITIVE-PORT", Severity::High,
                    "Sensitive service exposed broadly",
                    "TCP port " + std::to_string(rule.port),
                    "Remove unnecessary exposure or restrict authorized source networks."
                });
            }
        }

        return findings;
    }

    std::vector<Finding> assessPatching(const PatchInventory& patch) const {
        std::vector<Finding> findings;

        if (patch.criticalPending < 0 || patch.securityPending < 0 ||
            patch.daysSinceSuccessfulUpdate < 0) {
            findings.push_back({
                "PATCH-INVENTORY", Severity::High,
                "Invalid patch inventory", "Negative update count or update age",
                "Correct the inventory and verify host clock and package-manager results."
            });
            return findings;
        }

        if (patch.criticalPending > 0) {
            findings.push_back({
                "PATCH-CRITICAL", Severity::Critical,
                "Critical updates pending", std::to_string(patch.criticalPending),
                "Assess exposure and install validated security fixes urgently."
            });
        } else if (patch.securityPending > 0) {
            findings.push_back({
                "PATCH-SECURITY", Severity::High,
                "Security updates pending", std::to_string(patch.securityPending),
                "Prioritize fixes using vulnerability severity and host exposure."
            });
        }

        if (patch.daysSinceSuccessfulUpdate > 30) {
            findings.push_back({
                "PATCH-STALE", Severity::High,
                "Patch activity is stale",
                std::to_string(patch.daysSinceSuccessfulUpdate) + " days",
                "Investigate update failures and restore the approved patch cadence."
            });
        }

        if (patch.rebootRequired) {
            findings.push_back({
                "PATCH-REBOOT", Severity::High,
                "Restart required after patching", "reboot pending",
                "Schedule a controlled restart and verify application health."
            });
        }

        if (!patch.unattendedUpdatesEnabled) {
            findings.push_back({
                "PATCH-AUTOMATION", Severity::Medium,
                "Automated security updates are disabled", "No unattended update policy",
                "Enable a suitable policy or document equivalent managed patching."
            });
        }

        return findings;
    }

    std::vector<Finding> assessAuditing(const AuditInventory& audit) const {
        std::vector<Finding> findings;

        const std::vector<std::tuple<bool, std::string, Severity, std::string, std::string>> checks = {
            {audit.auditdEnabled, "AUDIT-DAEMON", Severity::High,
             "Audit daemon disabled", "Enable supported audit collection."},
            {audit.persistentRules, "AUDIT-PERSISTENCE", Severity::Medium,
             "Audit rules are not persistent", "Persist reviewed rules and validate after reboot."},
            {audit.authenticationLogs, "AUDIT-AUTH-LOGS", Severity::High,
             "Authentication logs unavailable", "Enable authentication logging and log collection."},
            {audit.timeSynchronization, "AUDIT-TIME", Severity::Medium,
             "Time synchronization disabled", "Use a trusted time synchronization service."},
            {audit.integrityMonitoring, "AUDIT-INTEGRITY", Severity::Medium,
             "Integrity monitoring disabled", "Monitor critical files for unexpected modifications."}
        };

        for (const auto& check : checks) {
            bool enabled;
            std::string id;
            Severity severity;
            std::string title;
            std::string remediation;
            std::tie(enabled, id, severity, title, remediation) = check;

            if (!enabled) {
                findings.push_back({
                    id, severity, title, "Control disabled in inventory", remediation
                });
            }
        }

        if (audit.retentionDays < 30) {
            findings.push_back({
                "AUDIT-RETENTION", Severity::Medium,
                "Short audit-log retention",
                std::to_string(audit.retentionDays) + " days",
                "Set retention according to incident response, legal, and storage needs."
            });
        }

        return findings;
    }

    std::vector<Finding> assessAll(
        const std::vector<Account>& accounts,
        const SshPolicy& ssh,
        const FirewallPolicy& firewall,
        const PatchInventory& patch,
        const AuditInventory& audit
    ) const {
        std::vector<Finding> result;

        auto append = [&result](std::vector<Finding> items) {
            result.insert(result.end(), items.begin(), items.end());
        };

        append(assessAccounts(accounts));
        append(assessSsh(ssh));
        append(assessFirewall(firewall));
        append(assessPatching(patch));
        append(assessAuditing(audit));

        std::sort(result.begin(), result.end(),
            [](const Finding& left, const Finding& right) {
                return std::tie(left.severity, left.control) <
                       std::tie(right.severity, right.control);
            });

        return result;
    }
};

int main() {
    try {
        // This incident-response case study models a production API host whose
        // exposure and overdue patches require coordinated remediation.
        const std::vector<Account> accounts = {
            {"root", 0, true, true, true, false, "/bin/bash"},
            {"platform", 1000, false, true, true, false, "/bin/bash"},
            {"buildbot", 1001, true, true, true, true, "/bin/bash"},
            {"metrics", 1002, true, false, false, true, "/usr/sbin/nologin"}
        };

        const SshPolicy ssh = {
            false, true, true, true, 6, {"platform", "buildbot"}
        };

        const FirewallPolicy firewall = {
            "allow", "allow", "deny",
            {
                {"inbound", "allow", "tcp", 22, "0.0.0.0/0"},
                {"inbound", "allow", "tcp", 443, "0.0.0.0/0"},
                {"inbound", "allow", "tcp", 22, "0.0.0.0/0"},
                {"inbound", "allow", "tcp", 23, "0.0.0.0/0"}
            }
        };

        const PatchInventory patch = {2, 11, 42, true, false};
        const AuditInventory audit = {false, false, true, true, false, 14};

        const GovernanceEngine engine;
        const auto findings = engine.assessAll(accounts, ssh, firewall, patch, audit);

        std::map<Severity, std::size_t> counts;
        for (const auto& item : findings) {
            ++counts[item.severity];
        }

        std::cout << "Linux hardening case study: api-prod-03\n";
        std::cout << "Assessment findings: " << findings.size() << "\n\n";

        for (const auto& item : findings) {
            std::cout << "[" << toString(item.severity) << "] "
                      << item.control << " - " << item.title << "\n"
                      << "Evidence: " << item.evidence << "\n"
                      << "Remediation: " << item.remediation << "\n\n";
        }

        std::cout << "Risk distribution\n";
        for (const auto& [severity, count] : counts) {
            std::cout << std::setw(8) << toString(severity) << ": "
                      << count << "\n";
        }

        const bool hasCritical = counts[Severity::Critical] > 0;
        std::cout << "\nOperational decision: "
                  << (hasCritical
                      ? "hold routine deployment until critical exposure is reviewed"
                      : "continue through the approved change process")
                  << "\n";

        return hasCritical ? 2 : 0;
    } catch (const std::exception& exception) {
        std::cerr << "Assessment failed: " << exception.what() << "\n";
        return 1;
    }
}
