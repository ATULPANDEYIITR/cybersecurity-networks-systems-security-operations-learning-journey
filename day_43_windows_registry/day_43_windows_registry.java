import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

public class RepositoryGovernance {
    enum RequestState {
        DRAFT, OPEN, CLOSED, MERGED
    }

    enum ReviewState {
        APPROVED, CHANGES_REQUESTED, COMMENTED
    }

    enum CheckState {
        PENDING, SUCCESS, FAILURE
    }

    enum MergeMethod {
        MERGE_COMMIT, SQUASH, REBASE
    }

    enum Permission {
        READ, WRITE, DELETE, BYPASS
    }

    record Commit(String hash, String message) {
        private static final Pattern HASH = Pattern.compile("[a-fA-F0-9]{7,40}");

        Commit {
            if (hash == null || !HASH.matcher(hash).matches()) {
                throw new IllegalArgumentException("Invalid commit identifier.");
            }
            if (message == null || message.isBlank()) {
                throw new IllegalArgumentException("Commit message is required.");
            }
        }
    }

    record Review(String reviewer, ReviewState state, String reviewedHead) {
        Review {
            if (reviewer == null || reviewer.isBlank()) {
                throw new IllegalArgumentException("Reviewer identity is required.");
            }
            Objects.requireNonNull(state);
            Objects.requireNonNull(reviewedHead);
        }
    }

    record BranchProtection(
        int requiredApprovals,
        Set<String> requiredChecks,
        boolean requireResolvedDiscussions,
        boolean requireLinearHistory,
        boolean restrictDirectPush,
        boolean prohibitForcePush,
        boolean prohibitDeletion,
        boolean administratorsMustComply
    ) {
        BranchProtection {
            if (requiredApprovals < 0) {
                throw new IllegalArgumentException("Approval count cannot be negative.");
            }
            requiredChecks = Set.copyOf(requiredChecks);
        }
    }

    static final class PullRequest {
        private final int id;
        private final String author;
        private final String sourceBranch;
        private final String targetBranch;
        private final List<Commit> commits = new ArrayList<>();
        private final Map<String, Review> reviews = new HashMap<>();
        private final Map<String, CheckState> checks = new HashMap<>();
        private final Map<String, Boolean> discussions = new HashMap<>();
        private RequestState state;
        private boolean conflicted;
        private boolean baseChanged;

        PullRequest(int id, String author, String sourceBranch,
                    String targetBranch, boolean draft) {
            if (id <= 0 || author == null || author.isBlank()
                    || sourceBranch == null || sourceBranch.isBlank()
                    || targetBranch == null || targetBranch.isBlank()
                    || sourceBranch.equals(targetBranch)) {
                throw new IllegalArgumentException("Invalid pull request metadata.");
            }
            this.id = id;
            this.author = author;
            this.sourceBranch = sourceBranch;
            this.targetBranch = targetBranch;
            this.state = draft ? RequestState.DRAFT : RequestState.OPEN;
        }

        String head() {
            if (commits.isEmpty()) return "";
            return commits.get(commits.size() - 1).hash();
        }

        void markReady() {
            requireState(RequestState.DRAFT);
            state = RequestState.OPEN;
        }

        void addCommit(Commit commit) {
            requireState(RequestState.OPEN);
            commits.add(Objects.requireNonNull(commit));
            // A new head means an earlier approval may no longer describe the changeset.
            reviews.clear();
            baseChanged = false;
        }

        void submitReview(String reviewer, ReviewState reviewState, String reviewedHead) {
            requireState(RequestState.OPEN);
            if (reviewer.equals(author)) {
                throw new IllegalArgumentException("Authors cannot approve their own request.");
            }
            if (head().isEmpty() || !head().equals(reviewedHead)) {
                throw new IllegalArgumentException("Review does not reference the current head.");
            }
            reviews.put(reviewer, new Review(reviewer, reviewState, reviewedHead));
        }

        void updateCheck(String name, CheckState checkState) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Check name is required.");
            }
            checks.put(name, Objects.requireNonNull(checkState));
        }

        void setDiscussion(String discussionId, boolean resolved) {
            if (discussionId == null || discussionId.isBlank()) {
                throw new IllegalArgumentException("Discussion ID is required.");
            }
            discussions.put(discussionId, resolved);
        }

        void setConflict(boolean value) {
            conflicted = value;
            if (value) reviews.clear();
        }

        void synchronizeBase() {
            requireState(RequestState.OPEN);
            reviews.clear();
            baseChanged = true;
        }

        List<String> evaluateMerge(BranchProtection policy, MergeMethod method) {
            List<String> blockers = new ArrayList<>();

            if (state != RequestState.OPEN) blockers.add("Request must be open.");
            if (commits.isEmpty()) blockers.add("No commits exist.");
            if (conflicted) blockers.add("Merge conflicts must be resolved.");
            if (baseChanged) blockers.add("Reviews must be renewed after base synchronization.");

            long approvals = reviews.values().stream()
                .filter(review -> review.state() == ReviewState.APPROVED)
                .count();

            boolean changesRequested = reviews.values().stream()
                .anyMatch(review -> review.state() == ReviewState.CHANGES_REQUESTED);

            if (approvals < policy.requiredApprovals()) {
                blockers.add("Required approvals are missing.");
            }
            if (changesRequested) {
                blockers.add("At least one reviewer requested changes.");
            }

            for (String required : policy.requiredChecks()) {
                if (checks.get(required) != CheckState.SUCCESS) {
                    blockers.add("Required check has not passed: " + required);
                }
            }

            if (policy.requireResolvedDiscussions()
                    && discussions.values().stream().anyMatch(resolved -> !resolved)) {
                blockers.add("Review discussions remain unresolved.");
            }

            if (policy.requireLinearHistory() && method == MergeMethod.MERGE_COMMIT) {
                blockers.add("Merge commits violate the linear-history policy.");
            }

            return List.copyOf(blockers);
        }

        boolean merge(BranchProtection policy, MergeMethod method) {
            List<String> blockers = evaluateMerge(policy, method);
            if (!blockers.isEmpty()) {
                System.out.println("PR #" + id + " blocked: " + blockers);
                return false;
            }

            state = RequestState.MERGED;
            System.out.println(
                "PR #" + id + " merged into " + targetBranch + " using " + method
            );
            return true;
        }

        void close() {
            if (state != RequestState.OPEN && state != RequestState.DRAFT) {
                throw new IllegalStateException("Only an open request can be closed.");
            }
            state = RequestState.CLOSED;
        }

        void reopen() {
            requireState(RequestState.CLOSED);
            state = RequestState.OPEN;
        }

        private void requireState(RequestState expected) {
            if (state != expected) {
                throw new IllegalStateException(
                    "Expected " + expected + ", found " + state
                );
            }
        }
    }

    static final class ProtectedBranch {
        private final String name;
        private final BranchProtection policy;

        ProtectedBranch(String name, BranchProtection policy) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Branch name is required.");
            }
            this.name = name;
            this.policy = Objects.requireNonNull(policy);
        }

        boolean permits(Permission permission, boolean administrator, boolean bypass) {
            if (bypass) return true;
            if (administrator && !policy.administratorsMustComply()) return true;

            return switch (permission) {
                case READ -> true;
                case WRITE -> !policy.restrictDirectPush();
                case DELETE -> !policy.prohibitDeletion();
                case BYPASS -> false;
            };
        }

        boolean permitsForcePush(boolean administrator, boolean bypass) {
            if (bypass) return true;
            if (administrator && !policy.administratorsMustComply()) return true;
            return !policy.prohibitForcePush();
        }
    }

    public static void main(String[] args) {
        BranchProtection policy = new BranchProtection(
            2,
            Set.of("unit-tests", "security-scan"),
            true,
            true,
            true,
            true,
            true,
            true
        );

        ProtectedBranch main = new ProtectedBranch("main", policy);
        PullRequest request = new PullRequest(
            305, "developer-isha", "feature/registry-policy", main.name, true
        );

        request.markReady();
        request.addCommit(new Commit("ab129fc", "Add registry policy validation"));
        request.updateCheck("unit-tests", CheckState.SUCCESS);
        request.updateCheck("security-scan", CheckState.SUCCESS);
        request.setDiscussion("inline-security-comment", false);

        request.submitReview("reviewer-kabir", ReviewState.APPROVED, request.head());
        request.submitReview("reviewer-neha", ReviewState.APPROVED, request.head());

        System.out.println("First eligibility evaluation:");
        request.merge(policy, MergeMethod.REBASE);

        request.setDiscussion("inline-security-comment", true);

        System.out.println("Eligibility after discussion resolution:");
        request.merge(policy, MergeMethod.REBASE);

        System.out.println("Developer direct push: "
            + main.permits(Permission.WRITE, false, false));
        System.out.println("Administrator force push: "
            + main.permitsForcePush(true, false));
        System.out.println("Explicit bypass: "
            + main.permits(Permission.WRITE, false, true));

        request.synchronizeBase();
        System.out.println("Eligibility after base synchronization:");
        System.out.println(request.evaluateMerge(policy, MergeMethod.REBASE));
    }
}
