#include <algorithm>
#include <exception>
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

enum class ReviewState {
    Pending,
    Approved,
    ChangesRequested,
    Dismissed
};

enum class MergeStrategy {
    MergeCommit,
    Squash,
    Rebase
};

struct Commit {
    std::string id;
    std::string message;
};

struct Review {
    std::string reviewer;
    ReviewState state;
    bool eligible;
    std::vector<std::string> comments;
};

struct StatusCheck {
    std::string name;
    bool required;
    bool passed;
};

struct PullRequest {
    int id;
    std::string sourceBranch;
    std::string targetBranch;
    std::vector<Commit> commits;
    std::vector<Review> reviews;
    std::vector<StatusCheck> checks;
    bool draft{false};
    bool open{true};
    bool hasConflicts{false};
    bool conversationsResolved{true};
    MergeStrategy strategy{MergeStrategy::Squash};
};

struct BranchProtection {
    std::string branch;
    int requiredApprovals{2};
    bool requireChecks{true};
    bool restrictDirectPush{true};
    bool restrictForcePush{true};
    bool restrictDeletion{true};
    bool requireResolvedConversations{true};
    bool requireLinearHistory{false};
    bool allowAdministratorBypass{false};
};

struct MergeDecision {
    bool eligible;
    std::vector<std::string> blockers;
};

class GovernanceEngine {
private:
    std::unordered_map<std::string, BranchProtection> policies_;

    static int validApprovals(const PullRequest& pr) {
        std::set<std::string> approvedReviewers;
        for (const auto& review : pr.reviews) {
            if (review.eligible && review.state == ReviewState::Approved) {
                approvedReviewers.insert(review.reviewer);
            }
        }
        return static_cast<int>(approvedReviewers.size());
    }

public:
    void addPolicy(const BranchProtection& policy) {
        if (policy.branch.empty() || policy.requiredApprovals < 0) {
            throw std::invalid_argument("Invalid branch protection policy");
        }
        policies_[policy.branch] = policy;
    }

    MergeDecision evaluate(const PullRequest& pr, bool administrator = false) const {
        MergeDecision result{true, {}};

        if (!pr.open)
            result.blockers.push_back("Pull Request is closed");
        if (pr.draft)
            result.blockers.push_back("Pull Request is still a draft");
        if (pr.commits.empty())
            result.blockers.push_back("Pull Request contains no commits");
        if (pr.sourceBranch.empty() || pr.targetBranch.empty())
            result.blockers.push_back("Source and target branches are required");
        if (pr.hasConflicts)
            result.blockers.push_back("Merge conflicts must be resolved");

        const auto policyIt = policies_.find(pr.targetBranch);
        if (policyIt == policies_.end()) {
            result.blockers.push_back("No branch protection policy exists");
        } else {
            const auto& policy = policyIt->second;

            if (administrator && policy.allowAdministratorBypass) {
                // Bypass is explicit and policy-controlled rather than implicit.
                return result;
            }

            if (validApprovals(pr) < policy.requiredApprovals) {
                std::ostringstream message;
                message << "Required approvals: " << policy.requiredApprovals
                        << ", eligible approvals: " << validApprovals(pr);
                result.blockers.push_back(message.str());
            }

            if (policy.requireChecks) {
                for (const auto& check : pr.checks) {
                    if (check.required && !check.passed) {
                        result.blockers.push_back(
                            "Required status check failed: " + check.name
                        );
                    }
                }
            }

            if (policy.requireResolvedConversations && !pr.conversationsResolved) {
                result.blockers.push_back("Unresolved review conversations remain");
            }

            if (policy.requireLinearHistory &&
                pr.strategy == MergeStrategy::MergeCommit) {
                result.blockers.push_back("Merge commit violates linear-history policy");
            }
        }

        result.eligible = result.blockers.empty();
        return result;
    }

    void printDecision(const PullRequest& pr) const {
        const auto decision = evaluate(pr);
        std::cout << "\nPR #" << pr.id << " -> " << pr.targetBranch << "\n";
        std::cout << "Merge eligible: " << std::boolalpha << decision.eligible << "\n";

        for (const auto& blocker : decision.blockers) {
            std::cout << "  BLOCKER: " << blocker << "\n";
        }
    }
};

PullRequest buildPullRequest() {
    PullRequest pr;
    pr.id = 417;
    pr.sourceBranch = "feature/secure-config";
    pr.targetBranch = "main";
    pr.commits = {
        {"a91c7d", "Add hardened production baseline"},
        {"b72e11", "Add configuration drift checks"},
        {"c8412f", "Add compliance reporting"}
    };

    pr.reviews = {
        {"security-reviewer", ReviewState::Approved, true, {}},
        {"platform-reviewer", ReviewState::Approved, true, {}},
        {"external-reviewer", ReviewState::Approved, false,
            {"Reviewer is not eligible for this repository"}}
    };

    pr.checks = {
        {"unit-tests", true, true},
        {"security-scan", true, true},
        {"configuration-policy", true, true},
        {"documentation-check", false, false}
    };

    pr.draft = false;
    pr.open = true;
    pr.hasConflicts = false;
    pr.conversationsResolved = true;
    pr.strategy = MergeStrategy::Squash;

    return pr;
}

int main() {
    try {
        GovernanceEngine engine;

        engine.addPolicy({
            "main",
            2,
            true,
            true,
            true,
            true,
            true,
            true,
            false
        });

        PullRequest pr = buildPullRequest();
        engine.printDecision(pr);

        // Demonstrate a realistic failure: one approval is dismissed.
        pr.reviews[1].state = ReviewState::Dismissed;
        engine.printDecision(pr);

        // Demonstrate recovery after the required reviewer re-approves.
        pr.reviews[1].state = ReviewState::Approved;
        engine.printDecision(pr);

        // Demonstrate status-check enforcement.
        pr.checks[1].passed = false;
        engine.printDecision(pr);

        std::cout << "\nSecurity properties:\n"
                  << "- Ineligible reviewers cannot satisfy approval requirements.\n"
                  << "- Required checks are evaluated independently of review approval.\n"
                  << "- Branch protection is attached to the target branch.\n"
                  << "- Administrator bypass is disabled by policy.\n"
                  << "- Duplicate approvals by one reviewer count only once.\n";

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Governance error: " << ex.what() << '\n';
        return 1;
    }
}
