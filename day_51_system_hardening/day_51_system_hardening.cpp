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
#include <vector>

enum class Severity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

enum class ReviewState {
    NotReviewed,
    Scheduled,
    Installed,
    Deferred
};

enum class MergeMethod {
    MergeCommit,
    Squash,
    Rebase
};

struct Service {
    std::string name;
    std::optional<int> port;
    bool required;
    bool externallyReachable;
    bool encrypted;
};

struct StatusCheck {
    std::string name;
    bool required;
    bool passed;
};

struct Patch {
    std::string identifier;
    Severity severity;
    std::string affectedService;
    std::string fixedVersion;
    ReviewState state;
};

struct BranchProtection {
    bool protectedBranch;
    bool requireStatusChecks;
    bool requireReviews;
    int requiredApprovals;
    bool requireResolvedConversations;
    bool prohibitDirectPush;
    bool prohibitForcePush;
    bool prohibitDeletion;
    bool requireLinearHistory;
};

struct Repository {
    std::string name;
    std::string defaultBranch;
    std::set<std::string> administrators;
    std::vector<std::string> maintainers;
    std::map<std::string, BranchProtection> protection;
};

struct PullRequest {
    int number;
    std::string sourceBranch;
    std::string targetBranch;
    bool open;
    bool draft;
    bool conversationsResolved;
    std::vector<StatusCheck> checks;
    std::map<std::string, bool> approvals;
    std::set<std::string> requestedChanges;
};

struct Host {
    std::string hostname;
    bool firewallEnabled;
    bool remoteRootLoginDisabled;
    bool auditLoggingEnabled;
    bool diskEncryptionEnabled;
    std::vector<Service> services;
    std::vector<Patch> patches;
};

struct Decision {
    bool eligible;
    std::vector<std::string> blockers;
};

class GovernanceEngine {
public:
    static Decision evaluateMerge(
        const Repository& repository,
        const PullRequest& pullRequest,
        const std::string& actor
    ) {
        Decision decision{true, {}};

        auto branchIt = repository.protection.find(
            pullRequest.targetBranch
        );

        if (branchIt == repository.protection.end()) {
            return decision;
        }

        const BranchProtection& policy = branchIt->second;

        if (!policy.protectedBranch) {
            return decision;
        }

        if (!pullRequest.open) {
            decision.blockers.push_back("Pull Request is not open.");
        }

        if (pullRequest.draft) {
            decision.blockers.push_back(
                "Draft Pull Requests cannot be merged."
            );
        }

        if (policy.prohibitDirectPush && pullRequest.sourceBranch.empty()) {
            decision.blockers.push_back(
                "Protected branches require a Pull Request."
            );
        }

        if (policy.requireStatusChecks) {
            for (const auto& check : pullRequest.checks) {
                if (check.required && !check.passed) {
                    decision.blockers.push_back(
                        "Required status check failed: " + check.name
                    );
                }
            }
        }

        if (policy.requireReviews) {
            int validApprovals = 0;

            for (const auto& [reviewer, approved] : pullRequest.approvals) {
                if (approved) {
                    validApprovals++;
                }
            }

            if (validApprovals < policy.requiredApprovals) {
                decision.blockers.push_back(
                    "Required approval count has not been reached."
                );
            }
        }

        if (policy.requireResolvedConversations &&
            !pullRequest.conversationsResolved) {
            decision.blockers.push_back(
                "Review conversations remain unresolved."
            );
        }

        if (policy.prohibitForcePush && pullRequest.sourceBranch == "force-push") {
            decision.blockers.push_back(
                "Force-push behavior is prohibited by policy."
            );
        }

        if (policy.prohibitDeletion &&
            pullRequest.targetBranch == repository.defaultBranch &&
            actor.empty()) {
            decision.blockers.push_back(
                "An authenticated merge actor is required."
            );
        }

        decision.eligible = decision.blockers.empty();
        return decision;
    }

    static std::vector<std::string> assessHost(const Host& host) {
        std::vector<std::string> findings;

        if (!host.firewallEnabled) {
            findings.push_back("Host firewall is disabled.");
        }

        if (!host.remoteRootLoginDisabled) {
            findings.push_back("Remote root login is permitted.");
        }

        if (!host.auditLoggingEnabled) {
            findings.push_back("Audit logging is disabled.");
        }

        if (!host.diskEncryptionEnabled) {
            findings.push_back("Disk encryption is not enabled.");
        }

        for (const auto& service : host.services) {
            if (!service.required) {
                findings.push_back(
                    "Unnecessary service enabled: " + service.name
                );
            }

            if (service.externallyReachable && !service.encrypted) {
                findings.push_back(
                    "Unencrypted externally reachable service: " +
                    service.name
                );
            }
        }

        for (const auto& patch : host.patches) {
            if (patch.state != ReviewState::Installed) {
                findings.push_back(
                    "Uninstalled patch: " + patch.identifier
                );
            }
        }

        return findings;
    }

    static int attackSurface(const Host& host) {
        int score = 0;

        for (const auto& service : host.services) {
            if (!service.externallyReachable) {
                continue;
            }

            score += 3;

            if (!service.required) {
                score += 2;
            }

            if (!service.encrypted) {
                score += 3;
            }
        }

        return score;
    }

    static void minimizeServices(Host& host) {
        for (auto& service : host.services) {
            if (!service.required) {
                service.externallyReachable = false;
            }
        }
    }
};

std::string severityName(Severity severity) {
    switch (severity) {
        case Severity::Low: return "LOW";
        case Severity::Medium: return "MEDIUM";
        case Severity::High: return "HIGH";
        case Severity::Critical: return "CRITICAL";
    }

    return "UNKNOWN";
}

void printDecision(const Decision& decision) {
    std::cout << "Merge eligible: "
              << (decision.eligible ? "YES" : "NO") << '\n';

    for (const auto& blocker : decision.blockers) {
        std::cout << "  Blocker: " << blocker << '\n';
    }
}

int main() {
    try {
        Repository repository{
            "payments-platform",
            "main",
            {"security-admin"},
            {"release-manager", "platform-lead"},
            {
                {
                    "main",
                    BranchProtection{
                        true,
                        true,
                        true,
                        2,
                        true,
                        true,
                        true,
                        true,
                        true
                    }
                }
            }
        };

        PullRequest pullRequest{
            142,
            "feature/rotate-api-keys",
            "main",
            true,
            false,
            false,
            {
                {"unit-tests", true, true},
                {"static-analysis", true, true},
                {"security-scan", true, false}
            },
            {
                {"alice", true},
                {"bob", true}
            },
            {"Review encryption-key rotation logic"}
        };

        std::cout << "Repository: " << repository.name << '\n';
        std::cout << "Pull Request: #" << pullRequest.number << '\n';

        Decision decision = GovernanceEngine::evaluateMerge(
            repository,
            pullRequest,
            "release-manager"
        );

        printDecision(decision);

        Host host{
            "payments-api-01",
            false,
            false,
            false,
            false,
            {
                {"ssh", 22, true, true, true},
                {"https", 443, true, true, true},
                {"telnet", 23, false, true, false},
                {"ftp", 21, false, true, false},
                {"metrics", 9100, true, false, true}
            },
            {
                {
                    "CVE-2026-10001",
                    Severity::Critical,
                    "https",
                    "4.8.2",
                    ReviewState::Required
                },
                {
                    "CVE-2026-10017",
                    Severity::High,
                    "ssh",
                    "9.9p2",
                    ReviewState::Scheduled
                }
            }
        };

        std::cout << "\nHost: " << host.hostname << '\n';
        std::cout << "Initial attack-surface score: "
                  << GovernanceEngine::attackSurface(host) << '\n';

        std::cout << "\nHardening findings:\n";
        for (const auto& finding : GovernanceEngine::assessHost(host)) {
            std::cout << "  - " << finding << '\n';
        }

        GovernanceEngine::minimizeServices(host);

        std::cout << "\nAfter service minimization:\n";
        std::cout << "Attack-surface score: "
                  << GovernanceEngine::attackSurface(host) << '\n';

        std::cout << "\nPatch inventory:\n";
        for (const auto& patch : host.patches) {
            std::cout << "  "
                      << patch.identifier
                      << " ["
                      << severityName(patch.severity)
                      << "] fixed="
                      << patch.fixedVersion
                      << '\n';
        }

        std::cout << "\nCorrective governance action:\n";
        pullRequest.checks[2].passed = true;
        pullRequest.conversationsResolved = true;

        Decision repairedDecision = GovernanceEngine::evaluateMerge(
            repository,
            pullRequest,
            "release-manager"
        );

        printDecision(repairedDecision);

    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
