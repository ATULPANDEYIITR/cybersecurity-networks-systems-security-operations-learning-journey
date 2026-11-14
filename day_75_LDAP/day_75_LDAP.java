import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/*
 * Enterprise LDAP Directory and Identity Governance
 *
 * Java 17 implementation covering:
 * - Directory Information Tree
 * - Distinguished Names
 * - Immutable directory attributes
 * - LDAP filter evaluation
 * - Authentication and PBKDF2
 * - Account lockout
 * - Role-based access control
 * - Review and approval policy modeling
 * - Repository branch protection
 * - Merge eligibility service
 */

public class LDAPEnterprise {

    enum AccountStatus {
        ACTIVE, LOCKED, DISABLED
    }

    enum SearchScope {
        BASE, ONE, SUBTREE
    }

    enum Role {
        ADMINISTRATOR,
        DIRECTORY_MANAGER,
        EMPLOYEE,
        SERVICE_ACCOUNT
    }

    enum ReviewState {
        PENDING, APPROVED, CHANGES_REQUESTED, DISMISSED
    }

    static class DirectoryException extends RuntimeException {
        DirectoryException(String message) {
            super(message);
        }
    }

    static class AuthenticationException extends DirectoryException {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static class AuthorizationException extends DirectoryException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class DN {
        private final String value;

        DN(String input) {
            if (input == null || input.isBlank()) {
                throw new DirectoryException("DN cannot be empty.");
            }

            String[] components = input.split("(?<!\\\\),");

            List<String> normalized = new ArrayList<>();

            for (String component : components) {
                String[] pair = component.split("=", 2);

                if (pair.length != 2 ||
                    pair[0].isBlank() ||
                    pair[1].isBlank()) {
                    throw new DirectoryException("Invalid RDN.");
                }

                String attribute = pair[0].trim().toLowerCase(Locale.ROOT);
                String attributeValue = pair[1].trim().toLowerCase(Locale.ROOT);

                if (!attribute.matches("[a-z][a-z0-9-]*")) {
                    throw new DirectoryException("Invalid DN attribute.");
                }

                normalized.add(attribute + "=" + attributeValue);
            }

            this.value = String.join(",", normalized);
        }

        String value() {
            return value;
        }

        boolean isWithin(DN base) {
            return value.equals(base.value) ||
                value.endsWith("," + base.value);
        }

        int depth() {
            return value.split(",").length;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof DN dn && value.equals(dn.value);
        }

        @Override
        public int hashCode() {
            return value.hashCode();
        }

        @Override
        public String toString() {
            return value;
        }
    }

    record Credentials(
        byte[] salt,
        byte[] hash,
        int iterations
    ) {
        Credentials {
            salt = salt.clone();
            hash = hash.clone();

            if (iterations < 100_000) {
                throw new DirectoryException("Insufficient KDF iterations.");
            }
        }

        @Override
        public byte[] salt() {
            return salt.clone();
        }

        @Override
        public byte[] hash() {
            return hash.clone();
        }
    }

    static final class PasswordService {
        private static final int ITERATIONS = 210_000;
        private static final int KEY_LENGTH = 256;
        private static final SecureRandom RANDOM = new SecureRandom();

        static Credentials create(String password) {
            if (password == null || password.length() < 12) {
                throw new DirectoryException(
                    "Password requires at least 12 characters."
                );
            }

            byte[] salt = new byte[32];
            RANDOM.nextBytes(salt);

            return new Credentials(
                salt,
                derive(password, salt, ITERATIONS),
                ITERATIONS
            );
        }

        static boolean verify(String password, Credentials credentials) {
            if (password == null) return false;

            byte[] actual = derive(
                password,
                credentials.salt(),
                credentials.iterations()
            );

            return MessageDigest.isEqual(
                actual,
                credentials.hash()
            );
        }

        private static byte[] derive(
            String password,
            byte[] salt,
            int iterations
        ) {
            PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                iterations,
                KEY_LENGTH
            );

            try {
                return SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
            } catch (GeneralSecurityException exception) {
                throw new DirectoryException(
                    "Password derivation failed."
                );
            } finally {
                spec.clearPassword();
            }
        }
    }

    static final class DirectoryEntry {
        private final DN dn;
        private final Map<String, List<String>> attributes;
        private Credentials credentials;
        private AccountStatus status = AccountStatus.ACTIVE;
        private int failedAttempts;
        private long version;

        DirectoryEntry(
            String dn,
            Map<String, List<String>> attributes
        ) {
            this.dn = new DN(dn);

            Map<String, List<String>> copy = new HashMap<>();

            attributes.forEach((key, values) -> {
                String normalized = key.toLowerCase(Locale.ROOT);

                if (!normalized.matches("[a-z][a-z0-9-]*")) {
                    throw new DirectoryException("Invalid attribute.");
                }

                copy.put(
                    normalized,
                    List.copyOf(values)
                );
            });

            if (!copy.containsKey("objectclass")) {
                throw new DirectoryException("objectClass is mandatory.");
            }

            this.attributes = Map.copyOf(copy);
        }

        DN dn() {
            return dn;
        }

        List<String> get(String attribute) {
            return attributes.getOrDefault(
                attribute.toLowerCase(Locale.ROOT),
                List.of()
            );
        }

        Map<String, List<String>> attributes() {
            return attributes;
        }

        AccountStatus status() {
            return status;
        }
    }

    static final class AccessPolicy {
        private static final Map<Role, Set<String>> PERMISSIONS = Map.of(
            Role.ADMINISTRATOR,
            Set.of("read", "search", "write", "delete"),

            Role.DIRECTORY_MANAGER,
            Set.of("read", "search", "write"),

            Role.EMPLOYEE,
            Set.of("read", "search"),

            Role.SERVICE_ACCOUNT,
            Set.of("read", "search")
        );

        static void require(Role role, String operation) {
            if (!PERMISSIONS.getOrDefault(role, Set.of())
                .contains(operation)) {
                throw new AuthorizationException(
                    "Insufficient directory permissions."
                );
            }
        }
    }

    static final class LDAPFilter {
        private final String expression;

        LDAPFilter(String expression) {
            this.expression = expression;

            if (expression == null ||
                expression.length() < 3 ||
                expression.charAt(0) != '(' ||
                expression.charAt(expression.length() - 1) != ')') {
                throw new DirectoryException("Invalid LDAP filter.");
            }

            validate(expression);
        }

        private void validate(String filter) {
            int depth = 0;

            for (char character : filter.toCharArray()) {
                if (character == '(') depth++;
                if (character == ')') depth--;

                if (depth < 0) {
                    throw new DirectoryException("Invalid filter nesting.");
                }
            }

            if (depth != 0) {
                throw new DirectoryException("Unbalanced filter.");
            }
        }

        boolean matches(DirectoryEntry entry) {
            return evaluate(expression, entry);
        }

        private boolean evaluate(
            String filter,
            DirectoryEntry entry
        ) {
            if (!filter.startsWith("(") || !filter.endsWith(")")) {
                throw new DirectoryException("Invalid filter expression.");
            }

            String body = filter.substring(1, filter.length() - 1);

            if (body.startsWith("&") || body.startsWith("|")) {
                char operator = body.charAt(0);
                List<String> children = splitChildren(body.substring(1));

                if (children.isEmpty()) {
                    throw new DirectoryException("Empty logical filter.");
                }

                if (operator == '&') {
                    return children.stream().allMatch(
                        child -> evaluate(child, entry)
                    );
                }

                return children.stream().anyMatch(
                    child -> evaluate(child, entry)
                );
            }

            if (body.startsWith("!")) {
                return !evaluate(body.substring(1), entry);
            }

            int separator = body.indexOf('=');

            if (separator <= 0) {
                throw new DirectoryException("Equality filter required.");
            }

            String attribute = body.substring(0, separator)
                .toLowerCase(Locale.ROOT);

            String expected = body.substring(separator + 1);

            if (!attribute.matches("[a-z][a-z0-9-]*")) {
                throw new DirectoryException("Invalid filter attribute.");
            }

            List<String> values = entry.get(attribute);

            if (expected.equals("*")) {
                return !values.isEmpty();
            }

            return values.stream().anyMatch(
                value -> value.equalsIgnoreCase(expected)
            );
        }

        private List<String> splitChildren(String content) {
            List<String> children = new ArrayList<>();
            int depth = 0;
            int start = -1;

            for (int i = 0; i < content.length(); i++) {
                char c = content.charAt(i);

                if (c == '(') {
                    if (depth == 0) start = i;
                    depth++;
                } else if (c == ')') {
                    depth--;

                    if (depth == 0 && start >= 0) {
                        children.add(content.substring(start, i + 1));
                        start = -1;
                    }

                    if (depth < 0) {
                        throw new DirectoryException("Invalid filter.");
                    }
                }
            }

            if (depth != 0) {
                throw new DirectoryException("Incomplete filter.");
            }

            return children;
        }
    }

    record SearchResult(
        DN dn,
        Map<String, List<String>> attributes
    ) {}

    record AuditEvent(
        String operation,
        String dn,
        String outcome,
        long timestamp
    ) {}

    static final class DirectoryService {
        private final Map<DN, DirectoryEntry> entries =
            new ConcurrentHashMap<>();

        private final List<AuditEvent> audit =
            Collections.synchronizedList(new ArrayList<>());

        private final int maxFailures = 5;

        private void record(String operation, DN dn, String outcome) {
            audit.add(new AuditEvent(
                operation,
                dn.toString(),
                outcome,
                System.currentTimeMillis()
            ));
        }

        void add(DirectoryEntry entry, Role role) {
            AccessPolicy.require(role, "write");

            DN dn = entry.dn();

            if (entries.containsKey(dn)) {
                throw new DirectoryException("Duplicate DN.");
            }

            String[] parts = dn.toString().split(",", 2);

            if (parts.length == 2) {
                DN parent = new DN(parts[1]);

                if (!entries.containsKey(parent)) {
                    throw new DirectoryException("Parent does not exist.");
                }
            }

            entries.put(dn, entry);
            record("ADD", dn, "SUCCESS");
        }

        void setPassword(String dn, String password) {
            DN key = new DN(dn);
            DirectoryEntry entry = entries.get(key);

            if (entry == null) {
                throw new DirectoryException("Entry not found.");
            }

            synchronized (entry) {
                entry.credentials = PasswordService.create(password);
                entry.failedAttempts = 0;
                entry.status = AccountStatus.ACTIVE;
                entry.version++;
            }

            record("PASSWORD_CHANGE", key, "SUCCESS");
        }

        boolean bind(String dn, String password) {
            DN key = new DN(dn);
            DirectoryEntry entry = entries.get(key);

            if (entry == null || entry.credentials == null) {
                record("BIND", key, "REJECTED");
                throw new AuthenticationException("Invalid credentials.");
            }

            synchronized (entry) {
                if (entry.status != AccountStatus.ACTIVE) {
                    throw new AuthenticationException(
                        "Account unavailable."
                    );
                }

                if (!PasswordService.verify(password, entry.credentials)) {
                    entry.failedAttempts++;

                    if (entry.failedAttempts >= maxFailures) {
                        entry.status = AccountStatus.LOCKED;
                    }

                    record("BIND", key, "REJECTED");
                    throw new AuthenticationException(
                        "Invalid credentials."
                    );
                }

                entry.failedAttempts = 0;
                record("BIND", key, "SUCCESS");
                return true;
            }
        }

        List<SearchResult> search(
            String baseDN,
            String expression,
            SearchScope scope,
            List<String> requestedAttributes,
            Role role,
            int limit
        ) {
            AccessPolicy.require(role, "search");

            DN base = new DN(baseDN);

            if (!entries.containsKey(base)) {
                throw new DirectoryException("Search base not found.");
            }

            if (limit < 1 || limit > 1000) {
                throw new DirectoryException("Invalid search limit.");
            }

            LDAPFilter filter = new LDAPFilter(expression);
            List<SearchResult> results = new ArrayList<>();

            for (DirectoryEntry entry : entries.values()) {
                DN dn = entry.dn();

                boolean withinScope = switch (scope) {
                    case BASE -> dn.equals(base);
                    case ONE -> dn.isWithin(base) &&
                        dn.depth() == base.depth() + 1;
                    case SUBTREE -> dn.isWithin(base);
                };

                if (!withinScope || !filter.matches(entry)) continue;

                Map<String, List<String>> selected = new HashMap<>();

                for (String attribute : requestedAttributes) {
                    List<String> values = entry.get(attribute);

                    if (!values.isEmpty()) {
                        selected.put(attribute.toLowerCase(Locale.ROOT),
                                     values);
                    }
                }

                results.add(new SearchResult(
                    dn,
                    Map.copyOf(selected)
                ));

                if (results.size() >= limit) break;
            }

            record("SEARCH", base, "RESULTS=" + results.size());

            return List.copyOf(results);
        }

        void modify(
            String dn,
            String attribute,
            List<String> values,
            Role role
        ) {
            AccessPolicy.require(role, "write");

            DN key = new DN(dn);
            DirectoryEntry existing = entries.get(key);

            if (existing == null) {
                throw new DirectoryException("Entry not found.");
            }

            attribute = attribute.toLowerCase(Locale.ROOT);

            if (Set.of("objectclass", "userpassword").contains(attribute)) {
                throw new AuthorizationException(
                    "Protected attribute modification rejected."
                );
            }

            if (!attribute.matches("[a-z][a-z0-9-]*") ||
                values == null || values.isEmpty()) {
                throw new DirectoryException("Invalid attribute update.");
            }

            Map<String, List<String>> updated =
                new HashMap<>(existing.attributes());

            updated.put(attribute, List.copyOf(values));

            DirectoryEntry replacement = new DirectoryEntry(
                key.toString(),
                updated
            );

            replacement.credentials = existing.credentials;
            replacement.status = existing.status;
            replacement.failedAttempts = existing.failedAttempts;
            replacement.version = existing.version + 1;

            entries.replace(key, existing, replacement);

            record("MODIFY", key, "SUCCESS");
        }

        List<AuditEvent> auditEvents() {
            synchronized (audit) {
                return List.copyOf(audit);
            }
        }
    }

    record Review(
        String reviewer,
        ReviewState state,
        boolean eligible,
        boolean stale,
        String discussion
    ) {}

    record StatusCheck(
        String name,
        boolean required,
        boolean passed
    ) {}

    record PullRequest(
        int id,
        String sourceBranch,
        String targetBranch,
        String author,
        List<String> commits,
        List<Review> reviews,
        List<StatusCheck> checks,
        int unresolvedConversations,
        boolean draft,
        boolean closed,
        boolean conflicts,
        boolean synchronizedWithBase
    ) {
        PullRequest {
            commits = List.copyOf(commits);
            reviews = List.copyOf(reviews);
            checks = List.copyOf(checks);
        }
    }

    record BranchProtection(
        int requiredApprovals,
        boolean requireStatusChecks,
        boolean requireResolvedConversations,
        boolean prohibitDirectPush,
        boolean prohibitForcePush,
        boolean prohibitDeletion,
        boolean requireLinearHistory
    ) {
        BranchProtection {
            if (requiredApprovals < 0) {
                throw new DirectoryException("Invalid approval requirement.");
            }
        }
    }

    record Eligibility(
        boolean eligible,
        List<String> violations
    ) {
        Eligibility {
            violations = List.copyOf(violations);
        }
    }

    interface EligibilityPolicy {
        Eligibility evaluate(PullRequest request);
    }

    static final class MergeEligibilityService
        implements EligibilityPolicy {

        private final BranchProtection policy;

        MergeEligibilityService(BranchProtection policy) {
            this.policy = policy;
        }

        @Override
        public Eligibility evaluate(PullRequest request) {
            List<String> violations = new ArrayList<>();

            if (request.draft()) {
                violations.add("Draft Pull Request.");
            }

            if (request.closed()) {
                violations.add("Pull Request is closed.");
            }

            if (request.sourceBranch().equals(request.targetBranch())) {
                violations.add("Source and target branches must differ.");
            }

            if (request.commits().isEmpty()) {
                violations.add("No proposed commits.");
            }

            if (request.conflicts()) {
                violations.add("Merge conflicts exist.");
            }

            if (!request.synchronizedWithBase()) {
                violations.add("Base branch synchronization required.");
            }

            Set<String> reviewers = new HashSet<>();
            int approvals = 0;

            for (Review review : request.reviews()) {
                if (!reviewers.add(review.reviewer())) continue;

                if (!review.eligible() || review.stale()) continue;

                if (review.state() == ReviewState.CHANGES_REQUESTED) {
                    violations.add(
                        "Reviewer requested changes: " + review.reviewer()
                    );
                }

                if (review.state() == ReviewState.APPROVED) {
                    approvals++;
                }
            }

            if (approvals < policy.requiredApprovals()) {
                violations.add(
                    "Approval requirement not met: " + approvals +
                    "/" + policy.requiredApprovals()
                );
            }

            if (policy.requireStatusChecks()) {
                List<StatusCheck> required = request.checks().stream()
                    .filter(StatusCheck::required)
                    .toList();

                if (required.isEmpty()) {
                    violations.add("Required status checks are missing.");
                }

                required.stream()
                    .filter(check -> !check.passed())
                    .forEach(check -> violations.add(
                        "Failed check: " + check.name()
                    ));
            }

            if (policy.requireResolvedConversations() &&
                request.unresolvedConversations() > 0) {
                violations.add("Unresolved conversations remain.");
            }

            return new Eligibility(
                violations.isEmpty(),
                violations
            );
        }
    }

    private static DirectoryEntry createUser(
        String uid,
        String name,
        String department
    ) {
        return new DirectoryEntry(
            "uid=" + uid + ",ou=people,dc=example,dc=com",
            Map.of(
                "objectclass",
                List.of("top", "person", "inetOrgPerson"),
                "uid", List.of(uid),
                "cn", List.of(name),
                "sn", List.of(name.split(" ")[1]),
                "department", List.of(department),
                "mail", List.of(uid + "@example.com"),
                "active", List.of("true")
            )
        );
    }

    public static void main(String[] args) {
        try {
            DirectoryService directory = new DirectoryService();

            directory.add(
                new DirectoryEntry(
                    "dc=example,dc=com",
                    Map.of(
                        "objectclass", List.of("top", "domain"),
                        "dc", List.of("example")
                    )
                ),
                Role.ADMINISTRATOR
            );

            directory.add(
                new DirectoryEntry(
                    "ou=people,dc=example,dc=com",
                    Map.of(
                        "objectclass", List.of("top", "organizationalUnit"),
                        "ou", List.of("people")
                    )
                ),
                Role.ADMINISTRATOR
            );

            directory.add(
                createUser("alice", "Alice Sharma", "Engineering"),
                Role.ADMINISTRATOR
            );

            directory.add(
                createUser("bob", "Bob Kumar", "Security"),
                Role.ADMINISTRATOR
            );

            directory.add(
                createUser("carol", "Carol Singh", "Engineering"),
                Role.ADMINISTRATOR
            );

            directory.setPassword(
                "uid=alice,ou=people,dc=example,dc=com",
                "Alice-Secure-Password-2026"
            );

            directory.setPassword(
                "uid=bob,ou=people,dc=example,dc=com",
                "Bob-Secure-Password-2026"
            );

            System.out.println("1. LDAP SUBTREE SEARCH");

            List<SearchResult> results = directory.search(
                "dc=example,dc=com",
                "(&(department=Engineering)(active=true))",
                SearchScope.SUBTREE,
                List.of("uid", "cn", "department", "mail"),
                Role.EMPLOYEE,
                100
            );

            results.forEach(System.out::println);

            System.out.println("\n2. LDAP BIND");

            boolean authenticated = directory.bind(
                "uid=alice,ou=people,dc=example,dc=com",
                "Alice-Secure-Password-2026"
            );

            System.out.println("Authenticated: " + authenticated);

            System.out.println("\n3. INVALID BIND");

            try {
                directory.bind(
                    "uid=alice,ou=people,dc=example,dc=com",
                    "wrong-password"
                );
            } catch (AuthenticationException exception) {
                System.out.println(exception.getMessage());
            }

            System.out.println("\n4. ATTRIBUTE UPDATE");

            directory.modify(
                "uid=alice,ou=people,dc=example,dc=com",
                "telephoneNumber",
                List.of("+91-9876543210"),
                Role.DIRECTORY_MANAGER
            );

            System.out.println("Attribute update completed.");

            System.out.println("\n5. ACCESS CONTROL");

            try {
                directory.modify(
                    "uid=alice,ou=people,dc=example,dc=com",
                    "department",
                    List.of("Finance"),
                    Role.EMPLOYEE
                );
            } catch (AuthorizationException exception) {
                System.out.println(exception.getMessage());
            }

            System.out.println("\n6. MERGE ELIGIBILITY");

            BranchProtection policy = new BranchProtection(
                2, true, true, true, true, true, false
            );

            MergeEligibilityService service =
                new MergeEligibilityService(policy);

            PullRequest request = new PullRequest(
                501,
                "feature/ldap-security",
                "main",
                "alice",
                List.of("commit-a", "commit-b"),
                List.of(
                    new Review(
                        "bob",
                        ReviewState.APPROVED,
                        true,
                        false,
                        "Security review passed."
                    ),
                    new Review(
                        "carol",
                        ReviewState.APPROVED,
                        true,
                        false,
                        "Implementation reviewed."
                    )
                ),
                List.of(
                    new StatusCheck("unit-tests", true, true),
                    new StatusCheck("security-scan", true, true),
                    new StatusCheck("integration-tests", true, true)
                ),
                0,
                false,
                false,
                false,
                true
            );

            Eligibility eligibility = service.evaluate(request);

            System.out.println(eligibility);

            System.out.println("\n7. FAILURE SCENARIO");

            PullRequest blocked = new PullRequest(
                502,
                "feature/ldap-schema",
                "main",
                "alice",
                List.of("commit-c"),
                List.of(
                    new Review(
                        "bob",
                        ReviewState.APPROVED,
                        true,
                        true,
                        "Stale approval."
                    )
                ),
                List.of(
                    new StatusCheck("unit-tests", true, true),
                    new StatusCheck("security-scan", true, false)
                ),
                2,
                true,
                false,
                true,
                false
            );

            service.evaluate(blocked).violations()
                .forEach(System.out::println);

            System.out.println("\n8. DIRECTORY AUDIT");

            directory.auditEvents().forEach(System.out::println);

        } catch (Exception exception) {
            System.err.println("Execution failed: " + exception.getMessage());
            System.exit(1);
        }
    }
}
