import java.time.LocalDate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public class SystemHardeningGovernance {

    enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    enum PatchState {
        REQUIRED, SCHEDULED, INSTALLED, DEFERRED
    }

    enum ServiceProtocol {
        SSH, HTTPS, TELNET, FTP, METRICS
    }

    record Service(
        String name,
        ServiceProtocol protocol,
        int port,
        boolean required,
        boolean externallyReachable,
        boolean encrypted
    ) {
        Service {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("Service name is required.");
            }
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Invalid service port.");
            }
        }
    }

    record Patch(
        String identifier,
        Severity severity,
        String service,
        String fixedVersion,
        LocalDate dueDate,
        PatchState state
    ) {
        Patch {
            if (identifier == null || !identifier.matches("CVE-\\d{4}-\\d{4,}")) {
                throw new IllegalArgumentException("Invalid vulnerability identifier.");
            }
            if (fixedVersion == null || fixedVersion.isBlank()) {
                throw new IllegalArgumentException("Fixed version is required.");
            }
        }

        boolean overdue(LocalDate today) {
            return state != PatchState.INSTALLED && dueDate.isBefore(today);
        }
    }

    record SecureBaseline(
        int minimumPasswordLength,
        int maximumPasswordAgeDays,
        boolean firewallRequired,
        boolean remoteRootLoginDisabled,
        boolean auditLoggingRequired,
        boolean diskEncryptionRequired
    ) {}

    record HardeningFinding(
        String category,
        Severity severity,
        String message,
        String remediation
    ) {}

    record StatusCheck(
        String name,
        boolean required,
        boolean passed
    ) {}

    record Review(
        String reviewer,
        boolean eligible,
        boolean approved,
        boolean stale
    ) {}

    record BranchPolicy(
        String branchName,
        boolean protectedBranch,
        boolean requiredStatusChecks,
        boolean requiredReviews,
        int requiredApprovals,
        boolean requireResolvedConversations,
        boolean prohibitDirectPush,
        boolean prohibitForcePush
    ) {}

    record PullRequest(
        int number,
        String sourceBranch,
        String targetBranch,
        boolean open,
        boolean draft,
        boolean conversationsResolved,
        List<StatusCheck> checks,
        List<Review> reviews
    ) {}

    record Repository(
        String name,
        String defaultBranch,
        Map<String, BranchPolicy> branchPolicies,
        Set<String> administrators
    ) {}

    record MergeDecision(
        boolean eligible,
        List<String> blockers
    ) {}

    static final class Host {
        private final String hostname;
        private int passwordLength;
        private int passwordAgeDays;
        private boolean firewallEnabled;
        private boolean remoteRootLoginDisabled;
        private boolean auditLoggingEnabled;
        private boolean diskEncryptionEnabled;
        private final List<Service> services;
        private final List<Patch> patches;

        Host(
            String hostname,
            int passwordLength,
            int passwordAgeDays,
            boolean firewallEnabled,
            boolean remoteRootLoginDisabled,
            boolean auditLoggingEnabled,
            boolean diskEncryptionEnabled,
            List<Service> services,
            List<Patch> patches
        ) {
            if (hostname == null || hostname.isBlank()) {
                throw new IllegalArgumentException("Hostname is required.");
            }
            this.hostname = hostname;
            this.passwordLength = passwordLength;
            this.passwordAgeDays = passwordAgeDays;
            this.firewallEnabled = firewallEnabled;
            this.remoteRootLoginDisabled = remoteRootLoginDisabled;
            this.auditLoggingEnabled = auditLoggingEnabled;
            this.diskEncryptionEnabled = diskEncryptionEnabled;
            this.services = new ArrayList<>(services);
            this.patches = new ArrayList<>(patches);
        }

        List<Service> services() {
            return List.copyOf(services);
        }

        List<Patch> patches() {
            return List.copyOf(patches);
        }

        void applyBaseline(SecureBaseline baseline) {
            passwordLength = Math.max(
                passwordLength,
                baseline.minimumPasswordLength()
            );

            passwordAgeDays = Math.min(
                passwordAgeDays,
                baseline.maximumPasswordAgeDays()
            );

            if (baseline.firewallRequired()) {
                firewallEnabled = true;
            }

            if (baseline.remoteRootLoginDisabled()) {
                remoteRootLoginDisabled = true;
            }

            if (baseline.auditLoggingRequired()) {
                auditLoggingEnabled = true;
            }

            if (baseline.diskEncryptionRequired()) {
                diskEncryptionEnabled = true;
            }
        }
    }

    static final class HardeningService {

        private static final Map<Severity, Integer> SEVERITY_WEIGHT =
            new EnumMap<>(Severity.class);

        static {
            SEVERITY_WEIGHT.put(Severity.LOW, 1);
            SEVERITY_WEIGHT.put(Severity.MEDIUM, 2);
            SEVERITY_WEIGHT.put(Severity.HIGH, 3);
            SEVERITY_WEIGHT.put(Severity.CRITICAL, 4);
        }

        static List<HardeningFinding> assessHost(
            Host host,
            SecureBaseline baseline,
            LocalDate today
        ) {
            List<HardeningFinding> findings = new ArrayList<>();

            if (host.passwordLength < baseline.minimumPasswordLength()) {
                findings.add(new HardeningFinding(
                    "authentication",
                    Severity.HIGH,
                    "Password length violates the secure baseline.",
                    "Increase the minimum password length."
                ));
            }

            if (host.passwordAgeDays > baseline.maximumPasswordAgeDays()) {
                findings.add(new HardeningFinding(
                    "authentication",
                    Severity.MEDIUM,
                    "Password maximum age exceeds the baseline.",
                    "Reduce the maximum password age."
                ));
            }

            if (baseline.firewallRequired() && !host.firewallEnabled) {
                findings.add(new HardeningFinding(
                    "network",
                    Severity.CRITICAL,
                    "Host firewall is disabled.",
                    "Enable the host firewall."
                ));
            }

            if (
                baseline.remoteRootLoginDisabled() &&
                !host.remoteRootLoginDisabled
            ) {
                findings.add(new HardeningFinding(
                    "access-control",
                    Severity.CRITICAL,
                    "Remote root login is allowed.",
                    "Disable direct remote root authentication."
                ));
            }

            if (baseline.auditLoggingRequired() &&
                !host.auditLoggingEnabled) {
                findings.add(new HardeningFinding(
                    "logging",
                    Severity.HIGH,
                    "Audit logging is disabled.",
                    "Enable protected security audit logging."
                ));
            }

            if (
                baseline.diskEncryptionRequired() &&
                !host.diskEncryptionEnabled
            ) {
                findings.add(new HardeningFinding(
                    "storage",
                    Severity.HIGH,
                    "Disk encryption is disabled.",
                    "Enable encryption and protect recovery material."
                ));
            }

            for (Service service : host.services()) {
                if (!service.required()) {
                    findings.add(new HardeningFinding(
                        "service-minimization",
                        service.externallyReachable()
                            ? Severity.HIGH
                            : Severity.MEDIUM,
                        "Unnecessary service enabled: " + service.name(),
                        "Disable or remove the service after dependency analysis."
                    ));
                }

                if (
                    service.externallyReachable() &&
                    !service.encrypted()
                ) {
                    findings.add(new HardeningFinding(
                        "network-exposure",
                        Severity.HIGH,
                        "Unencrypted external service: " + service.name(),
                        "Restrict exposure or require encryption."
                    ));
                }
            }

            for (Patch patch : host.patches()) {
                if (patch.state() != PatchState.INSTALLED) {
                    Severity severity = patch.severity();

                    if (patch.severity() == Severity.CRITICAL ||
                        patch.overdue(today)) {
                        severity = patch.severity() == Severity.CRITICAL
                            ? Severity.CRITICAL
                            : Severity.HIGH;
                    }

                    findings.add(new HardeningFinding(
                        "patch-management",
                        severity,
                        patch.identifier() +
                            " affects " + patch.service(),
                        "Install fixed version " +
                            patch.fixedVersion() +
                            " by " +
                            patch.dueDate()
                    ));
                }
            }

            return findings;
        }

        static int attackSurface(Host host) {
            return host.services().stream()
                .filter(Service::externallyReachable)
                .mapToInt(service -> {
                    int score = 3;
                    if (!service.required()) {
                        score += 2;
                    }
                    if (!service.encrypted()) {
                        score += 3;
                    }
                    return score;
                })
                .sum();
        }

        static List<Patch> prioritizedPatches(
            Host host,
            LocalDate today
        ) {
            return host.patches().stream()
                .filter(patch -> patch.state() != PatchState.INSTALLED)
                .sorted(
                    (a, b) -> {
                        int severity =
                            Integer.compare(
                                SEVERITY_WEIGHT.get(b.severity()),
                                SEVERITY_WEIGHT.get(a.severity())
                            );

                        if (severity != 0) {
                            return severity;
                        }

                        return a.dueDate().compareTo(b.dueDate());
                    }
                )
                .toList();
        }
    }

    static final class RepositoryGovernanceService {

        static MergeDecision evaluateMerge(
            Repository repository,
            PullRequest pullRequest
        ) {
            List<String> blockers = new ArrayList<>();

            BranchPolicy policy =
                repository.branchPolicies().get(
                    pullRequest.targetBranch()
                );

            if (policy == null || !policy.protectedBranch()) {
                return new MergeDecision(true, List.of());
            }

            if (!pullRequest.open()) {
                blockers.add("Pull Request is not open.");
            }

            if (pullRequest.draft()) {
                blockers.add("Draft Pull Requests cannot be merged.");
            }

            if (
                policy.prohibitDirectPush() &&
                pullRequest.sourceBranch() == null
            ) {
                blockers.add("Protected branch requires a Pull Request.");
            }

            if (policy.requiredStatusChecks()) {
                pullRequest.checks().stream()
                    .filter(StatusCheck::required)
                    .filter(check -> !check.passed())
                    .map(check ->
                        "Failed required status check: " + check.name()
                    )
                    .forEach(blockers::add);
            }

            if (policy.requiredReviews()) {
                long approvals = pullRequest.reviews().stream()
                    .filter(Review::eligible)
                    .filter(Review::approved)
                    .filter(review -> !review.stale())
                    .count();

                if (approvals < policy.requiredApprovals()) {
                    blockers.add(
                        "Required eligible approvals have not been reached."
                    );
                }
            }

            if (
                policy.requireResolvedConversations() &&
                !pullRequest.conversationsResolved()
            ) {
                blockers.add("Review conversations remain unresolved.");
            }

            return new MergeDecision(
                blockers.isEmpty(),
                List.copyOf(blockers)
            );
        }
    }

    public static void main(String[] args) {
        LocalDate today = LocalDate.of(2026, 10, 21);

        SecureBaseline baseline = new SecureBaseline(
            14,
            90,
            true,
            true,
            true,
            true
        );

        List<Service> services = List.of(
            new Service(
                "ssh",
                ServiceProtocol.SSH,
                22,
                true,
                true,
                true
            ),
            new Service(
                "https",
                ServiceProtocol.HTTPS,
                443,
                true,
                true,
                true
            ),
            new Service(
                "telnet",
                ServiceProtocol.TELNET,
                23,
                false,
                true,
                false
            ),
            new Service(
                "ftp",
                ServiceProtocol.FTP,
                21,
                false,
                true,
                false
            ),
            new Service(
                "metrics",
                ServiceProtocol.METRICS,
                9100,
                true,
                false,
                true
            )
        );

        List<Patch> patches = List.of(
            new Patch(
                "CVE-2026-10001",
                Severity.CRITICAL,
                "https",
                "4.8.2",
                LocalDate.of(2026, 10, 18),
                PatchState.REQUIRED
            ),
            new Patch(
                "CVE-2026-10017",
                Severity.HIGH,
                "ssh",
                "9.9p2",
                LocalDate.of(2026, 10, 28),
                PatchState.SCHEDULED
            )
        );

        Host host = new Host(
            "payments-api-01",
            10,
            180,
            false,
            false,
            false,
            false,
            services,
            patches
        );

        System.out.println("Host: " + "payments-api-01");
        System.out.println(
            "Initial attack-surface score: " +
            HardeningService.attackSurface(host)
        );

        System.out.println("\nHardening findings:");
        HardeningService.assessHost(host, baseline, today)
            .forEach(finding ->
                System.out.println(
                    "[" + finding.severity() + "] " +
                    finding.category() + ": " +
                    finding.message() +
                    " Remediation: " +
                    finding.remediation()
                )
            );

        host.applyBaseline(baseline);

        System.out.println("\nAfter baseline correction:");
        System.out.println(
            "Attack-surface score remains: " +
            HardeningService.attackSurface(host)
        );

        System.out.println("\nPatch priority:");
        HardeningService.prioritizedPatches(host, today)
            .forEach(patch ->
                System.out.println(
                    patch.identifier() +
                    " | " +
                    patch.severity() +
                    " | due=" +
                    patch.dueDate() +
                    " | fixed=" +
                    patch.fixedVersion()
                )
            );

        BranchPolicy mainPolicy = new BranchPolicy(
            "main",
            true,
            true,
            true,
            2,
            true,
            true,
            true
        );

        Repository repository = new Repository(
            "payments-platform",
            "main",
            Map.of("main", mainPolicy),
            Set.of("security-admin")
        );

        PullRequest pullRequest = new PullRequest(
            142,
            "feature/security-fix",
            "main",
            true,
            false,
            false,
            List.of(
                new StatusCheck("unit-tests", true, true),
                new StatusCheck("security-scan", true, false)
            ),
            List.of(
                new Review("alice", true, true, false),
                new Review("bob", true, true, false)
            )
        );

        MergeDecision decision =
            RepositoryGovernanceService.evaluateMerge(
                repository,
                pullRequest
            );

        System.out.println("\nMerge eligibility:");
        System.out.println("Eligible: " + decision.eligible());
        decision.blockers()
            .forEach(blocker -> System.out.println("Blocker: " + blocker));

        PullRequest corrected = new PullRequest(
            pullRequest.number(),
            pullRequest.sourceBranch(),
            pullRequest.targetBranch(),
            pullRequest.open(),
            pullRequest.draft(),
            true,
            List.of(
                new StatusCheck("unit-tests", true, true),
                new StatusCheck("security-scan", true, true)
            ),
            pullRequest.reviews()
        );

        MergeDecision correctedDecision =
            RepositoryGovernanceService.evaluateMerge(
                repository,
                corrected
            );

        System.out.println("\nAfter governance conditions are satisfied:");
        System.out.println("Eligible: " + correctedDecision.eligible());
    }
}
