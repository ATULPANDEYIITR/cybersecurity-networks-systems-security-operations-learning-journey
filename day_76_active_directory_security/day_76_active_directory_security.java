import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/*
 * Enterprise Active Directory Security Governance
 *
 * Java 17
 *
 * Domain capabilities:
 * - Privileged identity governance
 * - Administrative tier separation
 * - Service account lifecycle management
 * - Kerberos delegation assessment
 * - Cross-domain trust validation
 * - Security relationship analysis
 * - Finding lifecycle management
 * - Risk aggregation and reporting
 */

public class ActiveDirectorySecurity {

    enum AccountType {
        USER,
        ADMINISTRATOR,
        SERVICE,
        MANAGED_SERVICE
    }

    enum Tier {
        TIER_0,
        TIER_1,
        TIER_2
    }

    enum Delegation {
        NONE,
        UNCONSTRAINED,
        CONSTRAINED,
        RESOURCE_BASED
    }

    enum Severity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    enum FindingStatus {
        OPEN,
        MITIGATED,
        ACCEPTED
    }

    enum TrustDirection {
        INBOUND,
        OUTBOUND,
        BIDIRECTIONAL
    }

    record Account(
        String name,
        AccountType type,
        Tier tier,
        boolean enabled,
        boolean privileged,
        boolean mfaEnabled,
        boolean passwordNeverExpires,
        boolean interactiveLogonAllowed,
        boolean managedPassword,
        boolean trustedToAuthenticate,
        Delegation delegation,
        int spnCount,
        int passwordAgeDays
    ) {
        private static final Pattern IDENTIFIER =
            Pattern.compile("[A-Za-z0-9_.-]{1,64}");

        Account {
            Objects.requireNonNull(name);
            Objects.requireNonNull(type);
            Objects.requireNonNull(tier);
            Objects.requireNonNull(delegation);

            if (!IDENTIFIER.matcher(name).matches()) {
                throw new IllegalArgumentException(
                    "Invalid account identifier"
                );
            }

            if (spnCount < 0 || passwordAgeDays < 0) {
                throw new IllegalArgumentException(
                    "Invalid account security attributes"
                );
            }
        }
    }

    record Trust(
        String id,
        String sourceDomain,
        String targetDomain,
        TrustDirection direction,
        boolean enabled,
        boolean sidFiltering,
        boolean selectiveAuthentication
    ) {
        Trust {
            Objects.requireNonNull(id);
            Objects.requireNonNull(sourceDomain);
            Objects.requireNonNull(targetDomain);
            Objects.requireNonNull(direction);

            if (
                id.isBlank() ||
                sourceDomain.isBlank() ||
                targetDomain.isBlank()
            ) {
                throw new IllegalArgumentException(
                    "Invalid trust definition"
                );
            }

            if (sourceDomain.equalsIgnoreCase(targetDomain)) {
                throw new IllegalArgumentException(
                    "Self-trust is not permitted"
                );
            }
        }
    }

    record Relationship(
        String source,
        String target,
        String permission
    ) {
        Relationship {
            Objects.requireNonNull(source);
            Objects.requireNonNull(target);
            Objects.requireNonNull(permission);

            if (
                source.isBlank() ||
                target.isBlank() ||
                permission.isBlank() ||
                source.equals(target)
            ) {
                throw new IllegalArgumentException(
                    "Invalid relationship"
                );
            }
        }
    }

    record SecurityFinding(
        String id,
        Severity severity,
        String category,
        String subject,
        String description,
        String recommendation,
        FindingStatus status,
        Instant createdAt
    ) {
        SecurityFinding withStatus(FindingStatus newStatus) {
            return new SecurityFinding(
                id,
                severity,
                category,
                subject,
                description,
                recommendation,
                newStatus,
                createdAt
            );
        }
    }

    interface SecurityRule<T> {
        List<SecurityFinding> evaluate(T subject);
    }

    record GovernancePolicy(
        boolean requirePrivilegedMFA,
        boolean prohibitUnconstrainedDelegation,
        boolean requireManagedServicePasswords,
        boolean requireTrustSIDFiltering,
        boolean requireSelectiveAuthentication,
        int maximumServicePasswordAge
    ) {
        GovernancePolicy {
            if (maximumServicePasswordAge < 0) {
                throw new IllegalArgumentException(
                    "Invalid password age threshold"
                );
            }
        }

        static GovernancePolicy standard() {
            return new GovernancePolicy(
                true,
                true,
                true,
                true,
                true,
                180
            );
        }
    }

    static class AccountPolicy implements SecurityRule<Account> {

        private final GovernancePolicy policy;

        AccountPolicy(GovernancePolicy policy) {
            this.policy = policy;
        }

        private SecurityFinding finding(
            Account account,
            Severity severity,
            String category,
            String description,
            String recommendation
        ) {
            return new SecurityFinding(
                "",
                severity,
                category,
                account.name(),
                description,
                recommendation,
                FindingStatus.OPEN,
                Instant.now()
            );
        }

        @Override
        public List<SecurityFinding> evaluate(Account account) {
            List<SecurityFinding> findings = new ArrayList<>();

            if (!account.enabled()) {
                return findings;
            }

            if (
                policy.requirePrivilegedMFA() &&
                account.privileged() &&
                !account.mfaEnabled()
            ) {
                findings.add(finding(
                    account,
                    Severity.CRITICAL,
                    "PRIVILEGED_MFA",
                    "Privileged account does not use MFA.",
                    "Enforce strong MFA for privileged identities."
                ));
            }

            if (
                account.privileged() &&
                account.passwordNeverExpires()
            ) {
                findings.add(finding(
                    account,
                    Severity.HIGH,
                    "PASSWORD_LIFECYCLE",
                    "Privileged account has a non-expiring password.",
                    "Adopt managed credentials and lifecycle controls."
                ));
            }

            if (
                account.type() == AccountType.ADMINISTRATOR &&
                account.privileged() &&
                account.tier() != Tier.TIER_0 &&
                account.interactiveLogonAllowed()
            ) {
                findings.add(finding(
                    account,
                    Severity.HIGH,
                    "TIER_SEPARATION",
                    "Administrative tier requires review.",
                    "Separate privileged identities by security tier."
                ));
            }

            if (
                policy.prohibitUnconstrainedDelegation() &&
                account.delegation() == Delegation.UNCONSTRAINED
            ) {
                findings.add(finding(
                    account,
                    Severity.CRITICAL,
                    "UNCONSTRAINED_DELEGATION",
                    "Unconstrained Kerberos delegation is enabled.",
                    "Remove unnecessary unconstrained delegation."
                ));
            }

            if (account.trustedToAuthenticate()) {
                findings.add(finding(
                    account,
                    Severity.HIGH,
                    "PROTOCOL_TRANSITION",
                    "Protocol transition is configured.",
                    "Review delegation scope and allowed targets."
                ));
            }

            boolean service =
                account.type() == AccountType.SERVICE ||
                account.type() == AccountType.MANAGED_SERVICE;

            if (
                service &&
                account.interactiveLogonAllowed()
            ) {
                findings.add(finding(
                    account,
                    Severity.MEDIUM,
                    "INTERACTIVE_SERVICE_LOGON",
                    "Service account allows interactive logon.",
                    "Restrict interactive logon where feasible."
                ));
            }

            if (
                account.type() == AccountType.SERVICE &&
                policy.requireManagedServicePasswords() &&
                !account.managedPassword()
            ) {
                findings.add(finding(
                    account,
                    Severity.HIGH,
                    "SERVICE_CREDENTIALS",
                    "Service account does not use managed credentials.",
                    "Evaluate a group Managed Service Account."
                ));
            }

            if (
                account.type() == AccountType.SERVICE &&
                account.spnCount() > 0 &&
                account.passwordAgeDays() >
                    policy.maximumServicePasswordAge()
            ) {
                findings.add(finding(
                    account,
                    Severity.HIGH,
                    "SERVICE_PASSWORD_AGE",
                    "SPN-bearing service account has an old password.",
                    "Rotate credentials or migrate to managed credentials."
                ));
            }

            return findings;
        }
    }

    static class TrustPolicy implements SecurityRule<Trust> {

        private final GovernancePolicy policy;

        TrustPolicy(GovernancePolicy policy) {
            this.policy = policy;
        }

        @Override
        public List<SecurityFinding> evaluate(Trust trust) {
            List<SecurityFinding> findings = new ArrayList<>();

            if (!trust.enabled()) {
                return findings;
            }

            if (
                policy.requireTrustSIDFiltering() &&
                !trust.sidFiltering()
            ) {
                findings.add(new SecurityFinding(
                    "",
                    Severity.CRITICAL,
                    "TRUST_SID_FILTERING",
                    trust.id(),
                    "SID filtering is disabled.",
                    "Enable appropriate SID filtering.",
                    FindingStatus.OPEN,
                    Instant.now()
                ));
            }

            if (
                policy.requireSelectiveAuthentication() &&
                !trust.selectiveAuthentication()
            ) {
                findings.add(new SecurityFinding(
                    "",
                    Severity.HIGH,
                    "TRUST_SELECTIVE_AUTHENTICATION",
                    trust.id(),
                    "Selective authentication is disabled.",
                    "Restrict cross-domain authentication.",
                    FindingStatus.OPEN,
                    Instant.now()
                ));
            }

            return findings;
        }
    }

    static class FindingRegistry {

        private final Map<String, SecurityFinding> findings =
            new LinkedHashMap<>();

        private int counter = 0;

        void replaceAll(List<SecurityFinding> newFindings) {
            findings.clear();
            counter = 0;

            for (SecurityFinding finding : newFindings) {
                String id = String.format("AD-%04d", ++counter);

                SecurityFinding identified = new SecurityFinding(
                    id,
                    finding.severity(),
                    finding.category(),
                    finding.subject(),
                    finding.description(),
                    finding.recommendation(),
                    FindingStatus.OPEN,
                    finding.createdAt()
                );

                findings.put(id, identified);
            }
        }

        void update(String id, FindingStatus status) {
            SecurityFinding finding = findings.get(id);

            if (finding == null) {
                throw new IllegalArgumentException(
                    "Finding not found: " + id
                );
            }

            findings.put(id, finding.withStatus(status));
        }

        List<SecurityFinding> all() {
            return List.copyOf(findings.values());
        }
    }

    static class DirectoryRepository {

        private final String domain;

        private final Map<String, Account> accounts =
            new LinkedHashMap<>();

        private final Map<String, Trust> trusts =
            new LinkedHashMap<>();

        private final Set<Relationship> relationships =
            new HashSet<>();

        DirectoryRepository(String domain) {
            Objects.requireNonNull(domain);

            if (domain.isBlank() || domain.length() > 253) {
                throw new IllegalArgumentException("Invalid domain");
            }

            this.domain = domain.toLowerCase();
        }

        void addAccount(Account account) {
            String key = account.name().toLowerCase();

            if (accounts.putIfAbsent(key, account) != null) {
                throw new IllegalArgumentException(
                    "Duplicate account: " + account.name()
                );
            }
        }

        void addTrust(Trust trust) {
            if (trusts.putIfAbsent(trust.id(), trust) != null) {
                throw new IllegalArgumentException("Duplicate trust");
            }
        }

        void addRelationship(Relationship relationship) {
            relationships.add(relationship);
        }

        List<Account> accounts() {
            return List.copyOf(accounts.values());
        }

        List<Trust> trusts() {
            return List.copyOf(trusts.values());
        }

        List<Relationship> relationships() {
            return List.copyOf(relationships);
        }

        String domain() {
            return domain;
        }
    }

    static class AttackPathAnalyzer {

        private final Map<String, Set<String>> graph =
            new HashMap<>();

        AttackPathAnalyzer(List<Relationship> relationships) {
            for (Relationship relationship : relationships) {
                graph.computeIfAbsent(
                    relationship.source(),
                    key -> new HashSet<>()
                ).add(relationship.target());
            }
        }

        List<List<String>> shortestPaths(
            String start,
            String target,
            int maximumDepth
        ) {
            if (maximumDepth < 1) {
                throw new IllegalArgumentException(
                    "Maximum depth must be positive"
                );
            }

            if (start.equals(target)) {
                return List.of(List.of(start));
            }

            record NodePath(String node, List<String> path) {}

            ArrayDeque<NodePath> queue = new ArrayDeque<>();
            Map<String, Integer> bestDepth = new HashMap<>();

            queue.add(new NodePath(start, List.of(start)));
            bestDepth.put(start, 0);

            List<List<String>> results = new ArrayList<>();
            int shortest = Integer.MAX_VALUE;

            while (!queue.isEmpty()) {
                NodePath current = queue.removeFirst();
                int depth = current.path().size() - 1;

                if (
                    depth >= maximumDepth ||
                    depth >= shortest
                ) {
                    continue;
                }

                for (
                    String neighbor :
                    graph.getOrDefault(
                        current.node(),
                        Collections.emptySet()
                    )
                ) {
                    if (current.path().contains(neighbor)) {
                        continue;
                    }

                    List<String> nextPath =
                        new ArrayList<>(current.path());

                    nextPath.add(neighbor);

                    int nextDepth = depth + 1;

                    if (neighbor.equals(target)) {
                        shortest = nextDepth;
                        results.add(List.copyOf(nextPath));
                        continue;
                    }

                    int previous =
                        bestDepth.getOrDefault(
                            neighbor,
                            Integer.MAX_VALUE
                        );

                    if (nextDepth <= previous) {
                        bestDepth.put(neighbor, nextDepth);

                        queue.addLast(
                            new NodePath(
                                neighbor,
                                List.copyOf(nextPath)
                            )
                        );
                    }
                }
            }

            final int finalShortest = shortest;

            return results.stream()
                .filter(path -> path.size() - 1 == finalShortest)
                .sorted(Comparator.comparing(Object::toString))
                .toList();
        }
    }

    static class GovernanceService {

        private final DirectoryRepository repository;
        private final GovernancePolicy policy;

        private final AccountPolicy accountPolicy;
        private final TrustPolicy trustPolicy;

        private final FindingRegistry registry =
            new FindingRegistry();

        GovernanceService(
            DirectoryRepository repository,
            GovernancePolicy policy
        ) {
            this.repository = repository;
            this.policy = policy;

            this.accountPolicy = new AccountPolicy(policy);
            this.trustPolicy = new TrustPolicy(policy);
        }

        List<SecurityFinding> audit() {
            List<SecurityFinding> all = new ArrayList<>();

            for (Account account : repository.accounts()) {
                all.addAll(accountPolicy.evaluate(account));
            }

            for (Trust trust : repository.trusts()) {
                all.addAll(trustPolicy.evaluate(trust));
            }

            registry.replaceAll(all);
            return registry.all();
        }

        void updateFinding(String id, FindingStatus status) {
            registry.update(id, status);
        }

        Map<Severity, Long> severityDistribution() {
            Map<Severity, Long> counts =
                new EnumMap<>(Severity.class);

            for (Severity severity : Severity.values()) {
                counts.put(severity, 0L);
            }

            for (SecurityFinding finding : registry.all()) {
                counts.compute(
                    finding.severity(),
                    (key, value) -> value + 1
                );
            }

            return counts;
        }

        List<SecurityFinding> openCriticalFindings() {
            return registry.all().stream()
                .filter(f -> f.severity() == Severity.CRITICAL)
                .filter(f -> f.status() == FindingStatus.OPEN)
                .toList();
        }

        void exportReport(String filename) throws IOException {
            if (!filename.matches("[A-Za-z0-9_-]+\\.json")) {
                throw new IllegalArgumentException(
                    "Invalid report filename"
                );
            }

            StringBuilder json = new StringBuilder();

            json.append("{\n");
            json.append("  \"domain\": \"")
                .append(repository.domain())
                .append("\",\n");

            json.append("  \"generated_at\": \"")
                .append(Instant.now())
                .append("\",\n");

            json.append("  \"account_count\": ")
                .append(repository.accounts().size())
                .append(",\n");

            json.append("  \"findings\": [\n");

            List<SecurityFinding> findings = registry.all();

            for (int i = 0; i < findings.size(); i++) {
                SecurityFinding f = findings.get(i);

                json.append("    {\n");
                json.append("      \"id\": \"")
                    .append(f.id()).append("\",\n");
                json.append("      \"category\": \"")
                    .append(f.category()).append("\",\n");
                json.append("      \"subject\": \"")
                    .append(f.subject()).append("\",\n");
                json.append("      \"severity\": \"")
                    .append(f.severity()).append("\",\n");
                json.append("      \"status\": \"")
                    .append(f.status()).append("\"\n");
                json.append("    }");

                if (i + 1 < findings.size()) {
                    json.append(",");
                }

                json.append("\n");
            }

            json.append("  ]\n");
            json.append("}\n");

            Files.writeString(
                Path.of(filename),
                json.toString(),
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING
            );
        }
    }

    private static DirectoryRepository buildRepository() {
        DirectoryRepository repository =
            new DirectoryRepository("corp.example.com");

        repository.addAccount(new Account(
            "domain_admin",
            AccountType.ADMINISTRATOR,
            Tier.TIER_0,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            Delegation.NONE,
            0,
            20
        ));

        repository.addAccount(new Account(
            "helpdesk_admin",
            AccountType.ADMINISTRATOR,
            Tier.TIER_2,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            Delegation.NONE,
            0,
            120
        ));

        repository.addAccount(new Account(
            "sql_service",
            AccountType.SERVICE,
            Tier.TIER_1,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            Delegation.NONE,
            2,
            240
        ));

        repository.addAccount(new Account(
            "legacy_web",
            AccountType.SERVICE,
            Tier.TIER_1,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            Delegation.UNCONSTRAINED,
            1,
            300
        ));

        repository.addAccount(new Account(
            "web_gmsa",
            AccountType.MANAGED_SERVICE,
            Tier.TIER_1,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            Delegation.NONE,
            1,
            5
        ));

        repository.addTrust(new Trust(
            "TRUST-001",
            "corp.example.com",
            "partner.example.net",
            TrustDirection.BIDIRECTIONAL,
            true,
            false,
            false
        ));

        repository.addRelationship(new Relationship(
            "employee01",
            "helpdesk_admin",
            "group_membership"
        ));

        repository.addRelationship(new Relationship(
            "helpdesk_admin",
            "server01",
            "administrative_access"
        ));

        repository.addRelationship(new Relationship(
            "server01",
            "legacy_web",
            "service_dependency"
        ));

        repository.addRelationship(new Relationship(
            "legacy_web",
            "domain_admin",
            "delegation_exposure"
        ));

        repository.addRelationship(new Relationship(
            "employee01",
            "server02",
            "remote_access"
        ));

        repository.addRelationship(new Relationship(
            "server02",
            "domain_admin",
            "privileged_dependency"
        ));

        return repository;
    }

    public static void main(String[] args) {
        try {
            DirectoryRepository repository = buildRepository();

            GovernancePolicy policy = GovernancePolicy.standard();

            GovernanceService service =
                new GovernanceService(repository, policy);

            System.out.println(
                "ACTIVE DIRECTORY ENTERPRISE GOVERNANCE"
            );

            System.out.println("Domain: " + repository.domain());

            List<SecurityFinding> findings = service.audit();

            System.out.println("\nSECURITY FINDINGS");

            for (SecurityFinding finding : findings) {
                System.out.printf(
                    "[%s] %s | %s | %s%n",
                    finding.severity(),
                    finding.id(),
                    finding.category(),
                    finding.subject()
                );

                System.out.println(
                    "  " + finding.description()
                );

                System.out.println(
                    "  Action: " + finding.recommendation()
                );
            }

            System.out.println("\nSEVERITY DISTRIBUTION");

            service.severityDistribution().forEach(
                (severity, count) ->
                    System.out.println(severity + ": " + count)
            );

            System.out.println("\nDEFENSIVE ATTACK-PATH ANALYSIS");

            AttackPathAnalyzer analyzer =
                new AttackPathAnalyzer(repository.relationships());

            List<List<String>> paths = analyzer.shortestPaths(
                "employee01",
                "domain_admin",
                8
            );

            paths.forEach(path ->
                System.out.println(
                    String.join(" -> ", path)
                )
            );

            if (!findings.isEmpty()) {
                service.updateFinding(
                    findings.get(0).id(),
                    FindingStatus.MITIGATED
                );
            }

            System.out.println(
                "\nOpen critical findings: " +
                service.openCriticalFindings().size()
            );

            service.exportReport("ad_security_report.json");

            System.out.println(
                "Report exported to ad_security_report.json"
            );

        } catch (IOException | IllegalArgumentException exception) {
            System.err.println(
                "Governance failure: " + exception.getMessage()
            );

            System.exit(1);
        }
    }
}
