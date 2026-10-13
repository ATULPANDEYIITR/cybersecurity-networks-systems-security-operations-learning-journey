#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

enum class ReviewState {
    Approved,
    ChangesRequested,
    Commented
};

enum class CheckState {
    Pending,
    Passed,
    Failed
};

enum class RequestState {
    Draft,
    Open,
    Closed,
    Merged
};

enum class MergeMethod {
    MergeCommit,
    Squash,
    Rebase
};

struct Review {
    string reviewer;
    ReviewState state;
    string commit;
};

struct StatusCheck {
    string name;
    CheckState state;
};

struct ProtectionPolicy {
    size_t requiredApprovals = 2;
    set<string> requiredChecks{"unit-tests", "security-scan"};
    bool requireResolvedDiscussions = true;
    bool requireLinearHistory = true;
    bool restrictDirectPush = true;
    bool prohibitForcePush = true;
    bool prohibitDeletion = true;
    bool administratorsMustComply = true;
    MergeMethod permittedMethod = MergeMethod::Rebase;
};

class PullRequest {
private:
    int id_;
    string author_;
    string source_;
    string target_;
    string baseRevision_;
    RequestState state_;
    vector<string> commits_;
    map<string, Review> reviews_;
    map<string, CheckState> checks_;
    map<string, bool> discussions_;
    bool conflicted_ = false;
    bool stale_ = false;

public:
    PullRequest(int id, string author, string source, string target,
                string baseRevision, bool draft = false)
        : id_(id), author_(move(author)), source_(move(source)),
          target_(move(target)), baseRevision_(move(baseRevision)),
          state_(draft ? RequestState::Draft : RequestState::Open) {
        if (id_ <= 0 || author_.empty() || source_.empty() ||
            target_.empty() || source_ == target_ || baseRevision_.empty()) {
            throw invalid_argument("Invalid pull request metadata.");
        }
    }

    int id() const { return id_; }
    const string& target() const { return target_; }
    RequestState state() const { return state_; }

    void markReady() {
        if (state_ != RequestState::Draft) {
            throw logic_error("Only a draft can be marked ready.");
        }
        state_ = RequestState::Open;
    }

    void addCommit(const string& hash) {
        if (state_ != RequestState::Open) {
            throw logic_error("Commits require an open pull request.");
        }
        if (hash.size() < 7 ||
            !all_of(hash.begin(), hash.end(), [](unsigned char c) {
                return isxdigit(c) != 0;
            })) {
            throw invalid_argument("Commit identifier must be hexadecimal.");
        }

        commits_.push_back(hash);
        // A new source commit invalidates reviews of the previous changeset.
        reviews_.clear();
        stale_ = false;
    }

    void submitReview(const string& reviewer, ReviewState state,
                      const string& commit) {
        if (state_ != RequestState::Open) {
            throw logic_error("Review requires an open pull request.");
        }
        if (reviewer.empty() || reviewer == author_) {
            throw invalid_argument("Reviewer must be a different user from the author.");
        }
        if (commits_.empty() || commits_.back() != commit) {
            throw invalid_argument("Review must reference the current head commit.");
        }

        reviews_[reviewer] = Review{reviewer, state, commit};
    }

    void setCheck(const string& name, CheckState state) {
        if (name.empty()) throw invalid_argument("Check name cannot be empty.");
        checks_[name] = state;
    }

    void setDiscussion(const string& id, bool resolved) {
        if (id.empty()) throw invalid_argument("Discussion identifier cannot be empty.");
        discussions_[id] = resolved;
    }

    void setConflicted(bool conflicted) {
        conflicted_ = conflicted;
        if (conflicted_) reviews_.clear();
    }

    void synchronizeBase(const string& newRevision) {
        if (newRevision.empty() || newRevision == baseRevision_) {
            throw invalid_argument("A new base revision is required.");
        }
        baseRevision_ = newRevision;
        // A changed base can alter the effective changeset and review validity.
        reviews_.clear();
        stale_ = true;
    }

    vector<string> mergeBlockers(const ProtectionPolicy& policy,
                                 MergeMethod requestedMethod) const {
        vector<string> blockers;

        if (state_ != RequestState::Open) blockers.push_back("Request is not open.");
        if (commits_.empty()) blockers.push_back("No commits are present.");
        if (conflicted_) blockers.push_back("Source and target branches conflict.");
        if (stale_) blockers.push_back("Reviews must be renewed after base synchronization.");

        size_t approvals = 0;
        bool changesRequested = false;

        for (const auto& entry : reviews_) {
            if (entry.second.state == ReviewState::Approved) ++approvals;
            if (entry.second.state == ReviewState::ChangesRequested) {
                changesRequested = true;
            }
        }

        if (changesRequested) blockers.push_back("A reviewer requested changes.");
        if (approvals < policy.requiredApprovals) {
            blockers.push_back("Required approval count has not been met.");
        }

        for (const auto& required : policy.requiredChecks) {
            auto found = checks_.find(required);
            if (found == checks_.end() || found->second != CheckState::Passed) {
                blockers.push_back("Required check is missing or unsuccessful: " + required);
            }
        }

        if (policy.requireResolvedDiscussions) {
            for (const auto& discussion : discussions_) {
                if (!discussion.second) {
                    blockers.push_back("Unresolved discussion: " + discussion.first);
                }
            }
        }

        if (policy.requireLinearHistory &&
            requestedMethod != MergeMethod::Rebase) {
            blockers.push_back("The requested merge method violates linear-history policy.");
        }

        if (requestedMethod != policy.permittedMethod) {
            blockers.push_back("The requested merge method is not permitted.");
        }

        return blockers;
    }

    bool merge(const ProtectionPolicy& policy, MergeMethod method) {
        const auto blockers = mergeBlockers(policy, method);
        if (!blockers.empty()) {
            cout << "PR #" << id_ << " cannot merge:\n";
            for (const auto& blocker : blockers) {
                cout << "  - " << blocker << '\n';
            }
            return false;
        }

        state_ = RequestState::Merged;
        cout << "PR #" << id_ << " merged into " << target_
             << " using rebase.\n";
        return true;
    }

    void close() {
        if (state_ != RequestState::Open && state_ != RequestState::Draft) {
            throw logic_error("Only open or draft requests can be closed.");
        }
        state_ = RequestState::Closed;
    }

    void reopen() {
        if (state_ != RequestState::Closed) {
            throw logic_error("Only a closed request can be reopened.");
        }
        state_ = RequestState::Open;
    }
};

class ProtectedBranch {
private:
    string name_;
    ProtectionPolicy policy_;

public:
    ProtectedBranch(string name, ProtectionPolicy policy)
        : name_(move(name)), policy_(move(policy)) {
        if (name_.empty()) throw invalid_argument("Branch name is required.");
    }

    const string& name() const { return name_; }

    bool allowDirectPush(bool actorIsAdministrator, bool hasBypass) const {
        if (hasBypass) return true;
        if (actorIsAdministrator && !policy_.administratorsMustComply) return true;
        return !policy_.restrictDirectPush;
    }

    bool allowForcePush(bool actorIsAdministrator, bool hasBypass) const {
        if (hasBypass) return true;
        if (actorIsAdministrator && !policy_.administratorsMustComply) return true;
        return !policy_.prohibitForcePush;
    }

    bool allowDeletion(bool actorIsAdministrator, bool hasBypass) const {
        if (hasBypass) return true;
        if (actorIsAdministrator && !policy_.administratorsMustComply) return true;
        return !policy_.prohibitDeletion;
    }

    const ProtectionPolicy& policy() const { return policy_; }
};

int main() {
    try {
        ProtectionPolicy policy;
        policy.requiredApprovals = 2;

        ProtectedBranch mainBranch("main", policy);
        PullRequest request(
            184, "developer-asha", "feature/registry-audit",
            mainBranch.name(), "base-7f2e91a", true
        );

        cout << "Repository governance case study\n";
        cout << "Target branch: " << mainBranch.name() << '\n';

        request.markReady();
        request.addCommit("a81f2c9");
        request.setCheck("unit-tests", CheckState::Passed);
        request.setCheck("security-scan", CheckState::Passed);
        request.setDiscussion("inline-comment-22", false);

        request.submitReview("reviewer-ravi", ReviewState::Approved, "a81f2c9");
        request.submitReview("reviewer-meera", ReviewState::Approved, "a81f2c9");

        cout << "\nFirst merge attempt\n";
        request.merge(policy, MergeMethod::Rebase);

        cout << "\nResolve the review discussion\n";
        request.setDiscussion("inline-comment-22", true);
        cout << "Second merge attempt\n";
        request.merge(policy, MergeMethod::Rebase);

        cout << "\nBranch protection decisions\n";
        cout << boolalpha;
        cout << "Developer direct push allowed: "
             << mainBranch.allowDirectPush(false, false) << '\n';
        cout << "Administrator force push allowed: "
             << mainBranch.allowForcePush(true, false) << '\n';
        cout << "Authorized bypass available: "
             << mainBranch.allowDirectPush(false, true) << '\n';

        // A bypass is an explicit policy exception, not evidence that checks passed.
        // Production governance should audit bypass identity, justification, and time.
    } catch (const exception& error) {
        cerr << "Governance error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
