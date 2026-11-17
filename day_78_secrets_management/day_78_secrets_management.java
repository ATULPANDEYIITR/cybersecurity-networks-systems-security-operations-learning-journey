import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Enterprise Secrets Management System.
 *
 * Java 17 implementation covering:
 * - Secret lifecycle management
 * - API keys, passwords and tokens
 * - Role-based authorization
 * - Version control and credential rotation
 * - Expiration monitoring
 * - Exposure detection
 * - Audit logging
 * - Concurrent access
 * - Enterprise policy evaluation
 *
 * Compile: javac SecretsManagement.java
 * Run: java SecretsManagement
 *
 * This is an in-memory educational implementation.
 */
public class SecretsManagement {

    enum SecretType {
        API_KEY,
        ACCESS_TOKEN,
        REFRESH_TOKEN,
        PASSWORD,
        DATABASE_CREDENTIAL,
        PRIVATE_KEY
    }

    enum SecretStatus {
        ACTIVE,
        EXPIRED,
        REVOKED
    }

    enum Permission {
        READ,
        WRITE,
        ROTATE,
        REVOKE,
        ADMIN
    }

    enum Environment {
        DEVELOPMENT,
        TESTING,
        STAGING,
        PRODUCTION
    }

    enum ReviewState {
        APPROVED,
        CHANGES_REQUESTED,
        COMMENTED,
        DISMISSED
    }

    static class SecretException extends RuntimeException {
        SecretException(String message) {
            super(message);
        }
    }

    static class AuthorizationException extends SecretException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class ValidationException extends SecretException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class RotationException extends SecretException {
        RotationException(String message) {
            super(message);
        }
    }

    static class NotFoundException extends SecretException {
        NotFoundException(String message) {
            super(message);
        }
    }

    record Principal(String id, Set<String> roles) {
        Principal {
            if (id == null || id.isBlank()) {
                throw new ValidationException("Principal ID is required.");
            }

            roles = Set.copyOf(roles);
        }
    }

    record SecretMetadata(
        String id,
        String name,
        SecretType type,
        Environment environment,
        String owner,
        int version,
        SecretStatus status,
        Instant createdAt,
        Instant expiresAt
    ) {}

    record AuditEvent(
        String eventId,
        String principal,
        String action,
        String secretId,
        Instant timestamp,
        String outcome,
        String details
    ) {}

    record PolicyDecision(
        boolean eligible,
        List<String> violations
    ) {
        PolicyDecision {
            violations = List.copyOf(violations);
        }
    }

    static final class SecretVersion {
        private final int version;
        private String value;
        private final Instant createdAt;
        private final Instant expiresAt;
        private SecretStatus status;

        SecretVersion(
            int version,
            String value,
            Duration ttl
        ) {
            this.version = version;
            this.value = value;
            this.createdAt = Instant.now();
            this.expiresAt = createdAt.plus(ttl);
            this.status = SecretStatus.ACTIVE;
        }

        int getVersion() {
            return version;
        }

        String getValue() {
            return value;
        }

        Instant getExpiresAt() {
            return expiresAt;
        }

        SecretStatus getStatus() {
            return status;
        }

        void setStatus(SecretStatus status) {
            this.status = status;
        }

        void eraseValue() {
            value = null;
        }

        boolean isExpired() {
            return !Instant.now().isBefore(expiresAt);
        }
    }

    static final class SecretRecord {
        private final String id;
        private final String name;
        private final SecretType type;
        private final Environment environment;
        private final String owner;
        private final Set<String> tags;
        private final List<SecretVersion> versions;

        SecretRecord(
            String id,
            String name,
            SecretType type,
            Environment environment,
            String owner,
            Set<String> tags,
            SecretVersion firstVersion
        ) {
            this.id = id;
            this.name = name;
            this.type = type;
            this.environment = environment;
            this.owner = owner;
            this.tags = Set.copyOf(tags);
            this.versions = new ArrayList<>();
            this.versions.add(firstVersion);
        }

        SecretVersion current() {
            return versions.get(versions.size() - 1);
        }

        void addVersion(SecretVersion version) {
            versions.add(version);
        }

        List<SecretVersion> versions() {
            return Collections.unmodifiableList(versions);
        }
    }

    static final class AccessPolicy {

        private final Map<String, Set<Permission>> roles = Map.of(
            "developer",
            EnumSet.of(Permission.READ),

            "operator",
            EnumSet.of(Permission.READ, Permission.ROTATE),

            "security_admin",
            EnumSet.allOf(Permission.class)
        );

        Set<Permission> permissions(Principal principal) {
            EnumSet<Permission> result =
                EnumSet.noneOf(Permission.class);

            for (String role : principal.roles()) {
                Set<Permission> rolePermissions = roles.get(role);

                if (rolePermissions != null) {
                    result.addAll(rolePermissions);
                }
            }

            return result;
        }

        void require(
            Principal principal,
            Permission permission
        ) {
            Set<Permission> permissions = permissions(principal);

            if (
                !permissions.contains(permission) &&
                !permissions.contains(Permission.ADMIN)
            ) {
                throw new AuthorizationException(
                    principal.id() + " cannot perform " + permission
                );
            }
        }
    }

    static final class SecretValidator {

        private static final Pattern NAME_PATTERN =
            Pattern.compile("^[a-zA-Z][a-zA-Z0-9_.-]{2,99}$");

        static void validateName(String name) {
            if (
                name == null ||
                !NAME_PATTERN.matcher(name).matches()
            ) {
                throw new ValidationException("Invalid secret name.");
            }
        }

        static void validateValue(String value) {
            if (
                value == null ||
                value.isEmpty() ||
                value.length() > 65536 ||
                value.indexOf('\0') >= 0
            ) {
                throw new ValidationException("Invalid secret value.");
            }
        }

        static void validateTTL(Duration ttl) {
            if (
                ttl == null ||
                ttl.compareTo(Duration.ofDays(1)) < 0 ||
                ttl.compareTo(Duration.ofDays(3650)) > 0
            ) {
                throw new ValidationException("Invalid secret TTL.");
            }
        }
    }

    static final class SecretGenerator {

        private static final SecureRandom RANDOM = new SecureRandom();

        private static final String ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            + "abcdefghijklmnopqrstuvwxyz"
            + "0123456789";

        static String generateAPIKey(int length) {
            if (length < 24 || length > 128) {
                throw new ValidationException("Invalid key length.");
            }

            StringBuilder builder = new StringBuilder(length);

            for (int i = 0; i < length; i++) {
                builder.append(
                    ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length()))
                );
            }

            return builder.toString();
        }

        static String generatePassword() {
            return generateAPIKey(40);
        }
    }

    static final class AuditService {

        private final List<AuditEvent> events =
            Collections.synchronizedList(new ArrayList<>());

        void record(
            Principal principal,
            String action,
            String secretId,
            String outcome,
            String details
        ) {
            events.add(
                new AuditEvent(
                    UUID.randomUUID().toString(),
                    principal.id(),
                    action,
                    secretId,
                    Instant.now(),
                    outcome,
                    details
                )
            );
        }

        List<AuditEvent> getEvents() {
            synchronized (events) {
                return List.copyOf(events);
            }
        }
    }

    static final class SecretVault {

        private final ConcurrentHashMap<String, SecretRecord> records =
            new ConcurrentHashMap<>();

        private final Map<String, String> nameIndex =
            new ConcurrentHashMap<>();

        private final AccessPolicy accessPolicy;
        private final AuditService auditService;

        private final ReentrantReadWriteLock lock =
            new ReentrantReadWriteLock();

        SecretVault(
            AccessPolicy accessPolicy,
            AuditService auditService
        ) {
            this.accessPolicy = accessPolicy;
            this.auditService = auditService;
        }

        String create(
            Principal principal,
            String name,
            String value,
            SecretType type,
            Environment environment,
            String owner,
            Duration ttl,
            Set<String> tags
        ) {
            String id = UUID.randomUUID().toString();

            try {
                accessPolicy.require(principal, Permission.WRITE);

                SecretValidator.validateName(name);
                SecretValidator.validateValue(value);
                SecretValidator.validateTTL(ttl);

                Objects.requireNonNull(type, "Secret type required.");
                Objects.requireNonNull(environment, "Environment required.");

                if (owner == null || owner.isBlank()) {
                    throw new ValidationException("Owner is required.");
                }

                String indexKey = environment + ":" + name;

                lock.writeLock().lock();

                try {
                    if (nameIndex.containsKey(indexKey)) {
                        throw new ValidationException(
                            "Secret already exists in this environment."
                        );
                    }

                    SecretVersion firstVersion =
                        new SecretVersion(1, value, ttl);

                    SecretRecord record = new SecretRecord(
                        id,
                        name,
                        type,
                        environment,
                        owner,
                        tags == null ? Set.of() : tags,
                        firstVersion
                    );

                    records.put(id, record);
                    nameIndex.put(indexKey, id);

                } finally {
                    lock.writeLock().unlock();
                }

                auditService.record(
                    principal,
                    "CREATE",
                    id,
                    "SUCCESS",
                    "Initial version created."
                );

                return id;

            } catch (RuntimeException exception) {
                auditService.record(
                    principal,
                    "CREATE",
                    id,
                    "FAILED",
                    exception.getClass().getSimpleName()
                );

                throw exception;
            }
        }

        String retrieve(Principal principal, String id) {
            try {
                accessPolicy.require(principal, Permission.READ);

                lock.readLock().lock();

                try {
                    SecretRecord record = records.get(id);

                    if (record == null) {
                        throw new NotFoundException("Secret not found.");
                    }

                    SecretVersion current = record.current();

                    if (current.getStatus() == SecretStatus.REVOKED) {
                        throw new SecretException("Secret is revoked.");
                    }

                    if (
                        current.getStatus() == SecretStatus.EXPIRED ||
                        current.isExpired()
                    ) {
                        throw new SecretException("Secret has expired.");
                    }

                    auditService.record(
                        principal,
                        "READ",
                        id,
                        "SUCCESS",
                        "Secret retrieved."
                    );

                    return current.getValue();

                } finally {
                    lock.readLock().unlock();
                }

            } catch (RuntimeException exception) {
                auditService.record(
                    principal,
                    "READ",
                    id,
                    "FAILED",
                    exception.getClass().getSimpleName()
                );

                throw exception;
            }
        }

        int rotate(
            Principal principal,
            String id,
            String newValue,
            Duration ttl
        ) {
            try {
                accessPolicy.require(principal, Permission.ROTATE);

                SecretValidator.validateValue(newValue);
                SecretValidator.validateTTL(ttl);

                lock.writeLock().lock();

                try {
                    SecretRecord record = records.get(id);

                    if (record == null) {
                        throw new NotFoundException("Secret not found.");
                    }

                    SecretVersion previous = record.current();

                    if (previous.getStatus() == SecretStatus.REVOKED) {
                        throw new RotationException(
                            "Cannot rotate a revoked secret."
                        );
                    }

                    if (previous.getValue().equals(newValue)) {
                        throw new RotationException(
                            "New value must differ from the old value."
                        );
                    }

                    previous.setStatus(SecretStatus.EXPIRED);

                    int nextVersion = previous.getVersion() + 1;

                    record.addVersion(
                        new SecretVersion(nextVersion, newValue, ttl)
                    );

                    auditService.record(
                        principal,
                        "ROTATE",
                        id,
                        "SUCCESS",
                        "Version " + nextVersion
                    );

                    return nextVersion;

                } finally {
                    lock.writeLock().unlock();
                }

            } catch (RuntimeException exception) {
                auditService.record(
                    principal,
                    "ROTATE",
                    id,
                    "FAILED",
                    exception.getClass().getSimpleName()
                );

                throw exception;
            }
        }

        void revoke(Principal principal, String id) {
            accessPolicy.require(principal, Permission.REVOKE);

            lock.writeLock().lock();

            try {
                SecretRecord record = records.get(id);

                if (record == null) {
                    throw new NotFoundException("Secret not found.");
                }

                for (SecretVersion version : record.versions()) {
                    version.setStatus(SecretStatus.REVOKED);
                    version.eraseValue();
                }

                auditService.record(
                    principal,
                    "REVOKE",
                    id,
                    "SUCCESS",
                    "All versions revoked."
                );

            } finally {
                lock.writeLock().unlock();
            }
        }

        SecretMetadata metadata(Principal principal, String id) {
            accessPolicy.require(principal, Permission.READ);

            lock.readLock().lock();

            try {
                SecretRecord record = records.get(id);

                if (record == null) {
                    throw new NotFoundException("Secret not found.");
                }

                SecretVersion current = record.current();

                return new SecretMetadata(
                    record.id,
                    record.name,
                    record.type,
                    record.environment,
                    record.owner,
                    current.getVersion(),
                    current.getStatus(),
                    Instant.now(),
                    current.getExpiresAt()
                );

            } finally {
                lock.readLock().unlock();
            }
        }

        List<String> findExpiring(Duration window) {
            if (window == null || window.isNegative()) {
                throw new ValidationException("Invalid monitoring window.");
            }

            Instant threshold = Instant.now().plus(window);

            return records.values()
                .stream()
                .filter(record -> {
                    SecretVersion current = record.current();

                    return (
                        current.getStatus() == SecretStatus.ACTIVE &&
                        !current.getExpiresAt().isAfter(threshold)
                    );
                })
                .map(record -> record.id)
                .collect(Collectors.toList());
        }
    }

    static final class ExposureScanner {

        private static final Map<String, Pattern> PATTERNS = Map.of(
            "API_KEY",
            Pattern.compile(
                "(?i)api[_-]?key\\s*[:=]\\s*['\"]?[A-Za-z0-9_-]{20,}"
            ),

            "PASSWORD",
            Pattern.compile(
                "(?i)password\\s*[:=]\\s*['\"][^'\"]{8,}['\"]"
            ),

            "BEARER_TOKEN",
            Pattern.compile(
                "(?i)bearer\\s+[A-Za-z0-9._~-]{20,}"
            ),

            "PRIVATE_KEY",
            Pattern.compile(
                "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
            )
        );

        static Map<String, Integer> scan(String content) {
            Map<String, Integer> findings = new HashMap<>();

            for (var entry : PATTERNS.entrySet()) {
                int count = 0;

                var matcher = entry.getValue().matcher(content);

                while (matcher.find()) {
                    count++;
                }

                if (count > 0) {
                    findings.put(entry.getKey(), count);
                }
            }

            return findings;
        }

        static String redact(String content) {
            String result = content;

            for (Pattern pattern : PATTERNS.values()) {
                result = pattern.matcher(result)
                    .replaceAll("[REDACTED]");
            }

            return result;
        }
    }

    record BranchPolicy(
        int minimumApprovals,
        boolean requireChecks,
        boolean requireResolvedConversations,
        boolean preventDirectPush,
        boolean preventForcePush,
        boolean preventDeletion
    ) {
        BranchPolicy {
            if (minimumApprovals < 0) {
                throw new ValidationException(
                    "Minimum approvals cannot be negative."
                );
            }
        }
    }

    record Review(
        String reviewer,
        boolean eligible,
        ReviewState state,
        boolean stale
    ) {}

    record StatusCheck(
        String name,
        boolean required,
        boolean passed
    ) {}

    record PullRequest(
        String id,
        String sourceBranch,
        String targetBranch,
        boolean open,
        boolean draft,
        boolean conflicts,
        boolean conversationsResolved,
        List<Review> reviews,
        List<StatusCheck> checks
    ) {
        PullRequest {
            reviews = List.copyOf(reviews);
            checks = List.copyOf(checks);
        }
    }

    static final class MergeEligibilityService {

        PolicyDecision evaluate(
            PullRequest request,
            BranchPolicy policy
        ) {
            List<String> violations = new ArrayList<>();

            if (!request.open()) {
                violations.add("Pull Request is closed.");
            }

            if (request.draft()) {
                violations.add("Draft Pull Request cannot be merged.");
            }

            if (request.sourceBranch().equals(request.targetBranch())) {
                violations.add("Source and target branches are identical.");
            }

            if (request.conflicts()) {
                violations.add("Merge conflicts exist.");
            }

            long approvals = request.reviews()
                .stream()
                .filter(review ->
                    review.eligible() &&
                    !review.stale() &&
                    review.state() == ReviewState.APPROVED
                )
                .map(Review::reviewer)
                .distinct()
                .count();

            if (approvals < policy.minimumApprovals()) {
                violations.add("Insufficient eligible approvals.");
            }

            if (
                policy.requireResolvedConversations() &&
                !request.conversationsResolved()
            ) {
                violations.add("Unresolved review conversations.");
            }

            if (policy.requireChecks()) {
                request.checks().stream()
                    .filter(check -> check.required() && !check.passed())
                    .forEach(check ->
                        violations.add(
                            "Required status check failed: " + check.name()
                        )
                    );
            }

            return new PolicyDecision(
                violations.isEmpty(),
                violations
            );
        }
    }

    public static void main(String[] args) {

        System.out.println("ENTERPRISE SECRETS MANAGEMENT");
        System.out.println("=".repeat(55));

        AccessPolicy policy = new AccessPolicy();
        AuditService audit = new AuditService();

        SecretVault vault = new SecretVault(policy, audit);

        Principal administrator = new Principal(
            "security-team",
            Set.of("security_admin")
        );

        Principal developer = new Principal(
            "developer-01",
            Set.of("developer")
        );

        Principal operator = new Principal(
            "operator-01",
            Set.of("operator")
        );

        String secretId = vault.create(
            administrator,
            "payment_api_key",
            SecretGenerator.generateAPIKey(40),
            SecretType.API_KEY,
            Environment.PRODUCTION,
            "payment-platform",
            Duration.ofDays(90),
            Set.of("payments", "external-api")
        );

        System.out.println("\n1. Secret metadata");

        System.out.println(vault.metadata(administrator, secretId));

        System.out.println("\n2. Authorized retrieval");

        String value = vault.retrieve(developer, secretId);

        System.out.println(
            "Credential prefix: " + value.substring(0, 5) + "********"
        );

        System.out.println("\n3. Unauthorized creation");

        try {
            vault.create(
                developer,
                "unauthorized_secret",
                SecretGenerator.generatePassword(),
                SecretType.PASSWORD,
                Environment.TESTING,
                "developer",
                Duration.ofDays(90),
                Set.of()
            );
        } catch (AuthorizationException exception) {
            System.out.println("Blocked: " + exception.getMessage());
        }

        System.out.println("\n4. Credential rotation");

        int version = vault.rotate(
            operator,
            secretId,
            SecretGenerator.generateAPIKey(40),
            Duration.ofDays(90)
        );

        System.out.println("New version: " + version);

        System.out.println("\n5. Expiration monitoring");

        System.out.println(
            "Expiring secrets: " +
            vault.findExpiring(Duration.ofDays(15))
        );

        System.out.println("\n6. Secret exposure scanning");

        String sample = """
            api_key=example_api_key_12345678901234567890
            password='ExamplePassword123!'
            Authorization: Bearer example_token_12345678901234567890
            """;

        System.out.println(ExposureScanner.scan(sample));
        System.out.println(ExposureScanner.redact(sample));

        System.out.println("\n7. Enterprise merge policy");

        BranchPolicy branchPolicy = new BranchPolicy(
            2,
            true,
            true,
            true,
            true,
            true
        );

        PullRequest request = new PullRequest(
            "PR-101",
            "feature/secret-rotation",
            "main",
            true,
            false,
            false,
            true,
            List.of(
                new Review(
                    "reviewer-01",
                    true,
                    ReviewState.APPROVED,
                    false
                ),
                new Review(
                    "reviewer-02",
                    true,
                    ReviewState.APPROVED,
                    false
                )
            ),
            List.of(
                new StatusCheck("unit-tests", true, true),
                new StatusCheck("security-scan", true, true),
                new StatusCheck("integration-tests", true, true)
            )
        );

        PolicyDecision decision =
            new MergeEligibilityService().evaluate(
                request,
                branchPolicy
            );

        System.out.println("Merge eligible: " + decision.eligible());

        decision.violations().forEach(System.out::println);

        System.out.println("\n8. Revocation");

        vault.revoke(administrator, secretId);

        try {
            vault.retrieve(developer, secretId);
        } catch (SecretException exception) {
            System.out.println("Retrieval blocked: " + exception.getMessage());
        }

        System.out.println("\n9. Audit records");

        audit.getEvents().forEach(System.out::println);

        System.out.println("\nAll demonstration operations completed.");
    }
}
