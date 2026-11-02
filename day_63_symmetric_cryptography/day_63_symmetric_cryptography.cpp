#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

enum class Algorithm {
    RSA,
    ECC
};

enum class ReviewState {
    Pending,
    Approved,
    Rejected,
    ChangesRequested
};

struct StatusCheck {
    std::string name;
    bool passed;
};

struct Review {
    std::string reviewer;
    ReviewState state;
    bool eligible;
};

struct BranchPolicy {
    std::string branch;
    int requiredApprovals;
    bool requireStatusChecks;
    bool requireConversationResolution;
    bool restrictDirectPush;
    bool restrictForcePush;
    bool requireLinearHistory;
};

struct PullRequest {
    int id;
    std::string title;
    std::string sourceBranch;
    std::string targetBranch;
    std::vector<std::string> commits;
    std::vector<Review> reviews;
    std::vector<StatusCheck> checks;
    int unresolvedConversations;
    bool draft;
    bool mergeable;
    bool closed;
};

struct EligibilityResult {
    bool eligible;
    std::vector<std::string> reasons;
};

class Repository {
private:
    std::string name_;
    std::unordered_map<std::string, BranchPolicy> policies_;

public:
    explicit Repository(std::string name) : name_(std::move(name)) {}

    void protectBranch(const BranchPolicy& policy) {
        if (policy.branch.empty() || policy.requiredApprovals < 0) {
            throw std::invalid_argument("Invalid branch policy");
        }
        policies_[policy.branch] = policy;
    }

    const BranchPolicy& policyFor(const std::string& branch) const {
        auto it = policies_.find(branch);
        if (it == policies_.end()) {
            throw std::runtime_error("No branch policy exists");
        }
        return it->second;
    }

    const std::string& name() const {
        return name_;
    }
};

class MergeEligibilityEngine {
public:
    static EligibilityResult evaluate(
        const PullRequest& pr,
        const BranchPolicy& policy
    ) {
        EligibilityResult result{true, {}};

        if (pr.closed) {
            result.eligible = false;
            result.reasons.push_back("Pull Request is closed");
        }

        if (pr.draft) {
            result.eligible = false;
            result.reasons.push_back("Draft Pull Request cannot be merged");
        }

        if (pr.sourceBranch == pr.targetBranch) {
            result.eligible = false;
            result.reasons.push_back("Source and target branches are identical");
        }

        if (pr.commits.empty()) {
            result.eligible = false;
            result.reasons.push_back("Pull Request has no commits");
        }

        if (!pr.mergeable) {
            result.eligible = false;
            result.reasons.push_back("Merge conflict or non-mergeable state");
        }

        if (policy.requireStatusChecks) {
            for (const auto& check : pr.checks) {
                if (!check.passed) {
                    result.eligible = false;
                    result.reasons.push_back(
                        "Failed status check: " + check.name
                    );
                }
            }

            if (pr.checks.empty()) {
                result.eligible = false;
                result.reasons.push_back("Required status checks are missing");
            }
        }

        int approvals = 0;
        for (const auto& review : pr.reviews) {
            if (review.eligible && review.state == ReviewState::Approved) {
                ++approvals;
            }

            if (review.eligible &&
                review.state == ReviewState::ChangesRequested) {
                result.eligible = false;
                result.reasons.push_back(
                    "Eligible reviewer requested changes"
                );
            }
        }

        if (approvals < policy.requiredApprovals) {
            result.eligible = false;
            result.reasons.push_back(
                "Insufficient eligible approvals: " +
                std::to_string(approvals) + "/" +
                std::to_string(policy.requiredApprovals)
            );
        }

        if (policy.requireConversationResolution &&
            pr.unresolvedConversations > 0) {
            result.eligible = false;
            result.reasons.push_back(
                "Unresolved conversations: " +
                std::to_string(pr.unresolvedConversations)
            );
        }

        if (result.eligible) {
            result.reasons.push_back("All merge gates passed");
        }

        return result;
    }
};

std::string stateName(ReviewState state) {
    switch (state) {
        case ReviewState::Pending:
            return "pending";
        case ReviewState::Approved:
            return "approved";
        case ReviewState::Rejected:
            return "rejected";
        case ReviewState::ChangesRequested:
            return "changes_requested";
    }
    return "unknown";
}

void printResult(const PullRequest& pr, const EligibilityResult& result) {
    std::cout << "PR #" << pr.id << " - " << pr.title << '\n';
    std::cout << "Merge eligible: "
              << (result.eligible ? "YES" : "NO") << '\n';

    for (const auto& reason : result.reasons) {
        std::cout << "  - " << reason << '\n';
    }

    std::cout << '\n';
}

int main() {
    try {
        Repository repository("payments-platform");

        repository.protectBranch({
            "main",
            2,
            true,
            true,
            true,
            true,
            true
        });

        const BranchPolicy& policy = repository.policyFor("main");

        PullRequest good{
            101,
            "Add signed release manifest",
            "feature/release-signing",
            "main",
            {"a1b2c3d", "e4f5g6h"},
            {
                {"security-reviewer", ReviewState::Approved, true},
                {"platform-reviewer", ReviewState::Approved, true},
                {"author", ReviewState::Approved, false}
            },
            {
                {"unit-tests", true},
                {"security-scan", true},
                {"integration-tests", true}
            },
            0,
            false,
            true,
            false
        };

        PullRequest blocked{
            102,
            "Update cryptographic configuration",
            "feature/crypto-config",
            "main",
            {"deadbeef"},
            {
                {"security-reviewer", ReviewState::Approved, true},
                {"platform-reviewer", ReviewState::ChangesRequested, true}
            },
            {
                {"unit-tests", true},
                {"security-scan", false}
            },
            2,
            false,
            true,
            false
        };

        printResult(
            good,
            MergeEligibilityEngine::evaluate(good, policy)
        );

        printResult(
            blocked,
            MergeEligibilityEngine::evaluate(blocked, policy)
        );

        std::cout << "Repository: " << repository.name() << '\n';
        std::cout << "Protected branch: " << policy.branch << '\n';
        std::cout << "Required approvals: "
                  << policy.requiredApprovals << '\n';
        std::cout << "Direct pushes restricted: "
                  << std::boolalpha << policy.restrictDirectPush << '\n';
        std::cout << "Force pushes restricted: "
                  << policy.restrictForcePush << '\n';
        std::cout << "Linear history required: "
                  << policy.requireLinearHistory << '\n';

        // Security boundary: authorization and policy evaluation are kept
        // separate from the merge operation so an administrator can audit
        // the decision before changing repository state.
    }
    catch (const std::exception& ex) {
        std::cerr << "Governance engine failure: "
                  << ex.what() << '\n';
        return 1;
    }

    return 0;
}
