import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class RepositoryCryptographyGovernance {

    enum Algorithm {
        RSA,
        EC
    }

    enum ReviewDecision {
        PENDING,
        APPROVED,
        CHANGES_REQUESTED,
        REJECTED
    }

    enum PullRequestState {
        DRAFT,
        OPEN,
        CLOSED,
        MERGED
    }

    record Reviewer(String username, Set<String> teams, boolean eligible) {
        Reviewer {
            Objects.requireNonNull(username);
            Objects.requireNonNull(teams);
        }
    }

    record Review(
        Reviewer reviewer,
        ReviewDecision decision,
        String comment
    ) {}

    record StatusCheck(String name, boolean passed) {}

    record BranchProtectionPolicy(
        String branchName,
        int requiredApprovals,
        Set<String> requiredChecks,
        boolean requireResolvedConversations,
        boolean preventForcePush,
        boolean requireLinearHistory
    ) {}

    static final class PullRequest {
        private final int number;
        private final String title;
        private final String source;
        private final String target;
        private final List<String> commits;
        private final List<Review> reviews;
        private final List<StatusCheck> checks;
        private PullRequestState state;
        private int unresolvedConversations;
        private boolean mergeable;

        PullRequest(
            int number,
            String title,
            String source,
            String target,
            List<String> commits,
            List<Review> reviews,
            List<StatusCheck> checks
        ) {
            if (number <= 0 || source.isBlank() || target.isBlank()) {
                throw new IllegalArgumentException("Invalid Pull Request");
            }

            this.number = number;
            this.title = Objects.requireNonNull(title);
            this.source = source;
            this.target = target;
            this.commits = new ArrayList<>(commits);
            this.reviews = new ArrayList<>(reviews);
            this.checks = new ArrayList<>(checks);
            this.state = PullRequestState.OPEN;
            this.mergeable = true;
        }

        void setUnresolvedConversations(int count) {
            if (count < 0) {
                throw new IllegalArgumentException("Conversation count cannot be negative");
            }
            unresolvedConversations = count;
        }

        void setMergeable(boolean mergeable) {
            this.mergeable = mergeable;
        }

        void close() {
            if (state == PullRequestState.MERGED) {
                throw new IllegalStateException("Merged Pull Request cannot be closed");
            }
            state = PullRequestState.CLOSED;
        }

        void merge() {
            if (state != PullRequestState.OPEN) {
                throw new IllegalStateException("Only open Pull Requests can merge");
            }
            state = PullRequestState.MERGED;
        }

        List<Review> reviews() {
            return List.copyOf(reviews);
        }

        List<StatusCheck> checks() {
            return List.copyOf(checks);
        }

        String source() {
            return source;
        }

        String target() {
            return target;
        }

        List<String> commits() {
            return List.copyOf(commits);
        }

        int unresolvedConversations() {
            return unresolvedConversations;
        }

        boolean mergeable() {
            return mergeable;
        }

        PullRequestState state() {
            return state;
        }

        int number() {
            return number;
        }

        String title() {
            return title;
        }
    }

    record EligibilityResult(
        boolean eligible,
        List<String> reasons
    ) {}

    interface MergePolicy {
        EligibilityResult evaluate(
            PullRequest pullRequest,
            BranchProtectionPolicy policy
        );
    }

    static final class EnterpriseMergePolicy implements MergePolicy {

        @Override
        public EligibilityResult evaluate(
            PullRequest pr,
            BranchProtectionPolicy policy
        ) {
            List<String> failures = new ArrayList<>();

            if (pr.state() != PullRequestState.OPEN) {
                failures.add("Pull Request is not open");
            }

            if (pr.source().equals(pr.target())) {
                failures.add("Source and target branches are identical");
            }

            if (pr.commits().isEmpty()) {
                failures.add("No commits are attached");
            }

            if (!pr.mergeable()) {
                failures.add("Branch has a merge conflict");
            }

            Set<String> actualChecks = pr.checks().stream()
                .filter(StatusCheck::passed)
                .map(StatusCheck::name)
                .collect(Collectors.toSet());

            for (String required : policy.requiredChecks()) {
                if (!actualChecks.contains(required)) {
                    failures.add("Required check failed or missing: " + required);
                }
            }

            long approvals = pr.reviews().stream()
                .filter(review -> review.reviewer().eligible())
                .filter(review -> review.decision() == ReviewDecision.APPROVED)
                .count();

            boolean changesRequested = pr.reviews().stream()
                .anyMatch(review ->
                    review.reviewer().eligible() &&
                    review.decision() == ReviewDecision.CHANGES_REQUESTED
                );

            if (changesRequested) {
                failures.add("An eligible reviewer requested changes");
            }

            if (approvals < policy.requiredApprovals()) {
                failures.add(
                    "Required approvals not met: " +
                    approvals + "/" + policy.requiredApprovals()
                );
            }

            if (policy.requireResolvedConversations() &&
                pr.unresolvedConversations() > 0) {
                failures.add(
                    "Unresolved conversations: " +
                    pr.unresolvedConversations()
                );
            }

            if (failures.isEmpty()) {
                failures.add("All repository merge gates passed");
            }

            return new EligibilityResult(failures.size() == 1, failures);
        }
    }

    static KeyPair generateRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    static KeyPair generateEcKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        return generator.generateKeyPair();
    }

    static byte[] sign(
        byte[] data,
        java.security.PrivateKey privateKey,
        String algorithm
    ) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    static boolean verify(
        byte[] data,
        byte[] signatureBytes,
        java.security.PublicKey publicKey,
        String algorithm
    ) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(algorithm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        KeyPair rsa = generateRsaKeyPair();
        KeyPair ec = generateEcKeyPair();

        byte[] releaseManifest =
            "repository=payments-platform;version=4.2.0".getBytes();

        byte[] rsaSignature = sign(
            releaseManifest,
            rsa.getPrivate(),
            "SHA256withRSA"
        );

        byte[] ecSignature = sign(
            releaseManifest,
            ec.getPrivate(),
            "SHA256withECDSA"
        );

        System.out.println(
            "RSA signature valid: " +
            verify(
                releaseManifest,
                rsaSignature,
                rsa.getPublic(),
                "SHA256withRSA"
            )
        );

        System.out.println(
            "ECDSA signature valid: " +
            verify(
                releaseManifest,
                ecSignature,
                ec.getPublic(),
                "SHA256withECDSA"
            )
        );

        byte[] modifiedManifest =
            "repository=payments-platform;version=4.2.1".getBytes();

        System.out.println(
            "Modified manifest valid: " +
            verify(
                modifiedManifest,
                rsaSignature,
                rsa.getPublic(),
                "SHA256withRSA"
            )
        );

        Reviewer security = new Reviewer(
            "security-reviewer",
            Set.of("security"),
            true
        );

        Reviewer platform = new Reviewer(
            "platform-reviewer",
            Set.of("platform"),
            true
        );

        Reviewer author = new Reviewer(
            "release-author",
            Set.of("authors"),
            false
        );

        PullRequest pr = new PullRequest(
            501,
            "Sign production release manifest",
            "feature/release-signing",
            "main",
            List.of("a12bc3", "d45ef6"),
            List.of(
                new Review(security, ReviewDecision.APPROVED, "Cryptographic design reviewed"),
                new Review(platform, ReviewDecision.APPROVED, "Deployment impact reviewed"),
                new Review(author, ReviewDecision.APPROVED, "Self approval")
            ),
            List.of(
                new StatusCheck("unit-tests", true),
                new StatusCheck("security-scan", true),
                new StatusCheck("integration-tests", true)
            )
        );

        BranchProtectionPolicy policy = new BranchProtectionPolicy(
            "main",
            2,
            Set.of("unit-tests", "security-scan", "integration-tests"),
            true,
            true,
            true
        );

        MergePolicy mergePolicy = new EnterpriseMergePolicy();
        EligibilityResult result = mergePolicy.evaluate(pr, policy);

        System.out.println("PR #" + pr.number() + ": " + pr.title());
        System.out.println("Merge eligible: " + result.eligible());
        result.reasons().forEach(reason -> System.out.println(" - " + reason));

        if (result.eligible()) {
            pr.merge();
            System.out.println("State after merge: " + pr.state());
        }

        // Public keys can verify signatures; private keys must remain confined
        // to the signing boundary. Encryption and signing are separate operations.
        Map<Algorithm, String> keyUsage = Map.of(
            Algorithm.RSA, "Encryption and signatures",
            Algorithm.EC, "ECDSA signatures"
        );

        keyUsage.forEach((algorithm, usage) ->
            System.out.println(algorithm + ": " + usage)
        );
    }
}
