import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class ConfigurationGovernance {

    enum PullRequestState {
        DRAFT, OPEN, CLOSED, MERGED
    }

    enum ReviewDecision {
        COMMENTED, APPROVED, CHANGES_REQUESTED, DISMISSED
    }

    enum ChangeState {
        PROPOSED, APPROVED, REJECTED, APPLIED
    }

    record Commit(String id, String message) {
        Commit {
            if (id == null || id.isBlank() || message == null || message.isBlank()) {
                throw new IllegalArgumentException("Commit requires id and message");
            }
        }
    }

    record ReviewComment(
            String reviewer,
            String file,
            int line,
            String body,
            boolean resolved
    ) {
        ReviewComment {
            if (reviewer == null || reviewer.isBlank()) {
                throw new IllegalArgumentException("Reviewer is required");
            }
            if (line < 1 || body == null || body.isBlank()) {
                throw new IllegalArgumentException("Invalid review comment");
            }
        }
    }

    record Review(
            String reviewer,
            boolean eligible,
            ReviewDecision decision,
            List<ReviewComment> comments,
            Instant submittedAt
    ) {
        Review {
            Objects.requireNonNull(reviewer);
            Objects.requireNonNull(decision);
            Objects.requireNonNull(submittedAt);
            comments = List.copyOf(comments);
        }
    }

    record StatusCheck(String name, boolean required, boolean passed) {}

    record BranchProtectionPolicy(
            String branch,
            int requiredApprovals,
            Set<String> eligibleReviewers,
            Set<String> requiredChecks,
            boolean restrictDirectPush,
            boolean restrictForcePush,
            boolean restrictDeletion,
            boolean requireResolvedConversations,
            boolean requireLinearHistory,
            boolean administratorBypass
    ) {
        BranchProtectionPolicy {
            if (branch == null || branch.isBlank() || requiredApprovals < 0) {
                throw new IllegalArgumentException("Invalid branch policy");
            }
            eligibleReviewers = Set.copyOf(eligibleReviewers);
            requiredChecks = Set.copyOf(requiredChecks);
        }
    }

    record PullRequest(
            int id,
            String sourceBranch,
            String targetBranch,
            List<Commit> commits,
            List<Review> reviews,
            List<StatusCheck> checks,
            PullRequestState state,
            boolean mergeConflict,
            boolean squashMerge,
            boolean linearHistory
    ) {
        PullRequest {
            if (id <= 0 || sourceBranch == null || targetBranch == null) {
                throw new IllegalArgumentException("Invalid Pull Request");
            }
            commits = List.copyOf(commits);
            reviews = List.copyOf(reviews);
            checks = List.copyOf(checks);
        }
    }

    record MergeDecision(boolean eligible, List<String> blockers) {}

    static final class AuditService {
        private final List<String> events = new ArrayList<>();

        void record(String actor, String action, String target) {
            events.add(Instant.now() + " | " + actor + " | " + action + " | " + target);
        }

        List<String> events() {
            return List.copyOf(events);
        }
    }

    static final class MergeEligibilityService {
        private final Map<String, BranchProtectionPolicy> policies;

        MergeEligibilityService(Map<String, BranchProtectionPolicy> policies) {
            this.policies = Map.copyOf(policies);
        }

        MergeDecision evaluate(PullRequest pr, String actor, boolean administrator) {
            List<String> blockers = new ArrayList<>();

            if (pr.state() == PullRequestState.DRAFT) {
                blockers.add("Pull Request remains a draft");
            }
            if (pr.state() != PullRequestState.OPEN) {
                blockers.add("Pull Request is not open");
            }
            if (pr.commits().isEmpty()) {
                blockers.add("No commits are proposed");
            }
            if (pr.mergeConflict()) {
                blockers.add("Merge conflict exists");
            }

            BranchProtectionPolicy policy = policies.get(pr.targetBranch());
            if (policy == null) {
                blockers.add("Target branch has no protection policy");
                return new MergeDecision(false, List.copyOf(blockers));
            }

            if (administrator && policy.administratorBypass()) {
                return new MergeDecision(true, List.of());
            }

            Set<String> approvals = new HashSet<>();
            boolean unresolved = false;

            for (Review review : pr.reviews()) {
                if (review.eligible()
                        && policy.eligibleReviewers().contains(review.reviewer())
                        && review.decision() == ReviewDecision.APPROVED) {
                    approvals.add(review.reviewer());
                }

                for (ReviewComment comment : review.comments()) {
                    if (!comment.resolved()) {
                        unresolved = true;
                    }
                }
            }

            if (approvals.size() < policy.requiredApprovals()) {
                blockers.add(
                        "Approval requirement not met: "
                                + approvals.size() + "/"
                                + policy.requiredApprovals()
                );
            }

            Map<String, StatusCheck> checks = new HashMap<>();
            for (StatusCheck check : pr.checks()) {
                checks.put(check.name(), check);
            }

            for (String required : policy.requiredChecks()) {
                StatusCheck check = checks.get(required);
                if (check == null || !check.passed()) {
                    blockers.add("Required status check failed: " + required);
                }
            }

            if (policy.requireResolvedConversations() && unresolved) {
                blockers.add("Unresolved review conversations exist");
            }

            if (policy.requireLinearHistory()
                    && !pr.linearHistory()
                    && !pr.squashMerge()) {
                blockers.add("Linear history is required");
            }

            return new MergeDecision(blockers.isEmpty(), List.copyOf(blockers));
        }
    }

    static final class ConfigurationChangeService {
        private ChangeState state = ChangeState.PROPOSED;
        private final AuditService audit;

        ConfigurationChangeService(AuditService audit) {
            this.audit = audit;
        }

        void approve(String actor) {
            if (state != ChangeState.PROPOSED) {
                throw new IllegalStateException("Only proposed changes can be approved");
            }
            state = ChangeState.APPROVED;
            audit.record(actor, "CONFIGURATION_CHANGE_APPROVED", "baseline-v7");
        }

        void apply(String actor, MergeDecision decision) {
            if (state != ChangeState.APPROVED) {
                throw new IllegalStateException("Configuration change is not approved");
            }
            if (!decision.eligible()) {
                state = ChangeState.REJECTED;
                throw new IllegalStateException(
                        "Governance conditions block configuration application"
                );
            }
            state = ChangeState.APPLIED;
            audit.record(actor, "CONFIGURATION_CHANGE_APPLIED", "baseline-v7");
        }

        ChangeState state() {
            return state;
        }
    }

    public static void main(String[] args) {
        AuditService audit = new AuditService();

        BranchProtectionPolicy mainPolicy = new BranchProtectionPolicy(
                "main",
                2,
                Set.of("security-reviewer", "platform-reviewer", "release-manager"),
                Set.of("unit-tests", "security-scan", "configuration-policy"),
                true,
                true,
                true,
                true,
                true,
                false
        );

        Map<String, BranchProtectionPolicy> policies = Map.of("main", mainPolicy);
        MergeEligibilityService eligibility =
                new MergeEligibilityService(policies);

        List<Review> reviews = List.of(
                new Review(
                        "security-reviewer",
                        true,
                        ReviewDecision.APPROVED,
                        List.of(),
                        Instant.now()
                ),
                new Review(
                        "platform-reviewer",
                        true,
                        ReviewDecision.APPROVED,
                        List.of(),
                        Instant.now()
                ),
                new Review(
                        "untrusted-reviewer",
                        false,
                        ReviewDecision.APPROVED,
                        List.of(),
                        Instant.now()
                )
        );

        PullRequest pr = new PullRequest(
                912,
                "feature/hardened-config",
                "main",
                List.of(
                        new Commit("a1", "Add production baseline"),
                        new Commit("b2", "Add drift controls")
                ),
                reviews,
                List.of(
                        new StatusCheck("unit-tests", true, true),
                        new StatusCheck("security-scan", true, true),
                        new StatusCheck("configuration-policy", true, true),
                        new StatusCheck("documentation", false, false)
                ),
                PullRequestState.OPEN,
                false,
                true,
                true
        );

        MergeDecision decision = eligibility.evaluate(pr, "release-service", false);

        System.out.println("=== Enterprise Configuration Governance ===");
        System.out.println("Pull Request: #" + pr.id());
        System.out.println("Target branch: " + pr.targetBranch());
        System.out.println("Merge eligible: " + decision.eligible());

        for (String blocker : decision.blockers()) {
            System.out.println("BLOCKER: " + blocker);
        }

        ConfigurationChangeService changeService =
                new ConfigurationChangeService(audit);

        if (decision.eligible()) {
            changeService.approve("security-manager");
            changeService.apply("deployment-service", decision);
        }

        System.out.println("Configuration change state: " + changeService.state());
        System.out.println("Audit events: " + audit.events().size());

        for (String event : audit.events()) {
            System.out.println(event);
        }

        /*
         * The model separates proposed configuration changes from repository
         * governance. Approval of a configuration change is only useful after
         * repository-level merge conditions have been evaluated.
         */
    }
}
