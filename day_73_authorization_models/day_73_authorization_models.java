import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Enterprise Authorization Governance System.
 *
 * Models RBAC, ABAC, ACL, DAC, MAC, and least privilege
 * using immutable domain records and explicit policy services.
 *
 * Runtime: Java 17
 *
 * Compile:
 * javac AuthorizationGovernance.java
 *
 * Run:
 * java AuthorizationGovernance
 */
public class AuthorizationGovernance {

    enum Permission {
        READ, WRITE, DELETE, EXECUTE, SHARE, ADMIN
    }

    enum Classification {
        PUBLIC(0),
        INTERNAL(1),
        CONFIDENTIAL(2),
        SECRET(3),
        TOP_SECRET(4);

        private final int level;

        Classification(int level) {
            this.level = level;
        }

        public int level() {
            return level;
        }
    }

    enum Decision {
        ALLOW, DENY
    }

    enum Purpose {
        BUSINESS,
        RESEARCH,
        MAINTENANCE,
        COMPLIANCE
    }

    enum ReviewState {
        NOT_REQUIRED,
        PENDING,
        APPROVED,
        REJECTED
    }

    record User(
        String id,
        String department,
        Classification clearance,
        String location,
        boolean active,
        boolean mfaVerified,
        boolean privilegedAdmin,
        boolean deleteAuthorized,
        boolean suspended
    ) {
        User {
            requireIdentifier(id, "user ID");
            requireIdentifier(department, "department");
            requireIdentifier(location, "location");
            Objects.requireNonNull(clearance);
        }
    }

    record Role(
        String name,
        Set<Permission> permissions
    ) {
        Role {
            requireIdentifier(name, "role name");
            permissions = Set.copyOf(permissions);

            if (permissions.isEmpty()) {
                throw new ValidationException(
                    "A role must contain at least one permission"
                );
            }
        }
    }

    record Resource(
        String id,
        String ownerId,
        String department,
        Classification classification,
        Set<String> allowedLocations,
        boolean requireMfa,
        boolean deletionEnabled
    ) {
        Resource {
            requireIdentifier(id, "resource ID");
            requireIdentifier(ownerId, "owner ID");
            requireIdentifier(department, "department");

            Objects.requireNonNull(classification);

            allowedLocations = Set.copyOf(allowedLocations);
        }
    }

    record AccessRequest(
        String userId,
        String resourceId,
        Permission permission,
        Purpose purpose,
        Instant requestedAt
    ) {
        AccessRequest {
            requireIdentifier(userId, "user ID");
            requireIdentifier(resourceId, "resource ID");

            Objects.requireNonNull(permission);
            Objects.requireNonNull(purpose);
            Objects.requireNonNull(requestedAt);
        }

        static AccessRequest create(
            String userId,
            String resourceId,
            Permission permission,
            Purpose purpose
        ) {
            return new AccessRequest(
                userId,
                resourceId,
                permission,
                purpose,
                Instant.now()
            );
        }
    }

    record PolicyDecision(
        boolean allowed,
        List<String> reasons
    ) {
        PolicyDecision {
            reasons = List.copyOf(reasons);
        }
    }

    record AuditEvent(
        String requestId,
        String userId,
        String resourceId,
        Permission permission,
        Decision decision,
        List<String> reasons,
        Instant timestamp
    ) {
        AuditEvent {
            reasons = List.copyOf(reasons);
        }
    }

    static class AuthorizationException extends RuntimeException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class ValidationException extends AuthorizationException {
        ValidationException(String message) {
            super(message);
        }
    }

    static void requireIdentifier(String value, String label) {
        if (
            value == null ||
            value.isBlank() ||
            value.length() > 128
        ) {
            throw new ValidationException("Invalid " + label);
        }
    }

    interface AuthorizationRule {
        boolean evaluate(PolicyContext context);
    }

    record PolicyContext(
        User user,
        Resource resource,
        AccessRequest request
    ) {}

    /**
     * Each policy has a separate responsibility.
     * Mandatory policies are evaluated before grant mechanisms.
     */
    static final class PolicyRegistry {

        private final Map<String, AuthorizationRule> rules =
            new HashMap<>();

        void register(String name, AuthorizationRule rule) {
            requireIdentifier(name, "policy name");

            if (rules.putIfAbsent(name, rule) != null) {
                throw new ValidationException(
                    "Duplicate policy: " + name
                );
            }
        }

        boolean evaluate(String name, PolicyContext context) {
            AuthorizationRule rule = rules.get(name);

            if (rule == null) {
                throw new AuthorizationException(
                    "Unknown policy: " + name
                );
            }

            return rule.evaluate(context);
        }
    }

    /**
     * RBAC and ACL are alternative grant sources.
     * MAC, ABAC, and least privilege are mandatory constraints.
     */
    static final class AuthorizationService {

        private final Map<String, User> users = new HashMap<>();

        private final Map<String, Role> roles = new HashMap<>();

        private final Map<String, Set<String>> userRoles =
            new HashMap<>();

        private final Map<String, Resource> resources =
            new HashMap<>();

        private final Map<String, Map<String, Set<Permission>>> acls =
            new HashMap<>();

        private final List<AuditEvent> auditEvents =
            new ArrayList<>();

        private final PolicyRegistry policies =
            new PolicyRegistry();

        AuthorizationService() {
            configurePolicies();
        }

        private void configurePolicies() {

            policies.register(
                "ACTIVE_ACCOUNT",
                context -> context.user().active()
                    && !context.user().suspended()
            );

            policies.register(
                "MAC_CLEARANCE",
                context ->
                    context.user().clearance().level() >=
                    context.resource().classification().level()
            );

            policies.register(
                "ABAC_ATTRIBUTES",
                context -> {
                    User user = context.user();
                    Resource resource = context.resource();
                    AccessRequest request = context.request();

                    if (
                        user.department().equals(resource.department())
                    ) {
                        // Same-department access is permitted.
                    } else if (
                        request.purpose() != Purpose.COMPLIANCE
                    ) {
                        return false;
                    }

                    if (
                        !resource.allowedLocations().isEmpty() &&
                        !resource.allowedLocations().contains(
                            user.location()
                        )
                    ) {
                        return false;
                    }

                    return !resource.requireMfa() ||
                           user.mfaVerified();
                }
            );

            policies.register(
                "LEAST_PRIVILEGE",
                context -> {
                    User user = context.user();
                    Resource resource = context.resource();
                    Permission permission =
                        context.request().permission();

                    if (permission == Permission.ADMIN) {
                        return user.privilegedAdmin();
                    }

                    if (permission == Permission.DELETE) {
                        return user.deleteAuthorized()
                               && resource.deletionEnabled();
                    }

                    return true;
                }
            );
        }

        void addUser(User user) {
            if (users.putIfAbsent(user.id(), user) != null) {
                throw new ValidationException("Duplicate user");
            }

            userRoles.put(user.id(), new HashSet<>());
        }

        void addRole(Role role) {
            if (roles.putIfAbsent(role.name(), role) != null) {
                throw new ValidationException("Duplicate role");
            }
        }

        void assignRole(String userId, String roleName) {
            requireUser(userId);
            requireRole(roleName);

            userRoles.get(userId).add(roleName);
        }

        void revokeRole(String userId, String roleName) {
            requireUser(userId);
            userRoles.get(userId).remove(roleName);
        }

        void addResource(Resource resource) {
            requireUser(resource.ownerId());

            if (resources.putIfAbsent(resource.id(), resource) != null) {
                throw new ValidationException("Duplicate resource");
            }

            acls.put(resource.id(), new HashMap<>());
        }

        void grantAcl(
            String resourceId,
            String principal,
            Set<Permission> permissions
        ) {
            requireResource(resourceId);

            if (!users.containsKey(principal) &&
                !roles.containsKey(principal)) {
                throw new ValidationException("Unknown ACL principal");
            }

            if (permissions.isEmpty()) {
                throw new ValidationException("Empty ACL grant");
            }

            Map<String, Set<Permission>> resourceAcl =
                acls.get(resourceId);

            Set<Permission> grants = resourceAcl.computeIfAbsent(
                principal,
                ignored -> EnumSet.noneOf(Permission.class)
            );

            grants.addAll(permissions);
        }

        void revokeAcl(String resourceId, String principal) {
            requireResource(resourceId);
            acls.get(resourceId).remove(principal);
        }

        private User requireUser(String userId) {
            User user = users.get(userId);

            if (user == null) {
                throw new ValidationException("Unknown user: " + userId);
            }

            return user;
        }

        private Role requireRole(String roleName) {
            Role role = roles.get(roleName);

            if (role == null) {
                throw new ValidationException("Unknown role");
            }

            return role;
        }

        private Resource requireResource(String resourceId) {
            Resource resource = resources.get(resourceId);

            if (resource == null) {
                throw new ValidationException("Unknown resource");
            }

            return resource;
        }

        private boolean evaluateRBAC(
            String userId,
            Permission permission
        ) {
            return userRoles.get(userId).stream()
                .map(roles::get)
                .anyMatch(role ->
                    role.permissions().contains(permission)
                );
        }

        private boolean evaluateACL(
            User user,
            Resource resource,
            Permission permission
        ) {
            Map<String, Set<Permission>> resourceAcl =
                acls.get(resource.id());

            Set<Permission> direct =
                resourceAcl.getOrDefault(user.id(), Set.of());

            if (direct.contains(permission)) {
                return true;
            }

            return userRoles.get(user.id()).stream()
                .map(role -> resourceAcl.getOrDefault(role, Set.of()))
                .anyMatch(grants -> grants.contains(permission));
        }

        private boolean evaluateDAC(
            User user,
            Resource resource,
            Permission permission
        ) {
            return user.id().equals(resource.ownerId())
                && Set.of(
                    Permission.READ,
                    Permission.WRITE,
                    Permission.SHARE
                ).contains(permission);
        }

        PolicyDecision evaluate(AccessRequest request) {
            User user = requireUser(request.userId());
            Resource resource = requireResource(request.resourceId());

            PolicyContext context = new PolicyContext(
                user,
                resource,
                request
            );

            List<String> reasons = new ArrayList<>();

            List<String> mandatoryPolicyNames = List.of(
                "ACTIVE_ACCOUNT",
                "MAC_CLEARANCE",
                "ABAC_ATTRIBUTES",
                "LEAST_PRIVILEGE"
            );

            boolean mandatoryPassed = true;

            for (String policyName : mandatoryPolicyNames) {
                boolean passed = policies.evaluate(
                    policyName,
                    context
                );

                reasons.add(
                    policyName + ": " + (passed ? "PASS" : "FAIL")
                );

                mandatoryPassed &= passed;
            }

            boolean rbac = evaluateRBAC(
                user.id(),
                request.permission()
            );

            boolean acl = evaluateACL(
                user,
                resource,
                request.permission()
            );

            boolean dac = evaluateDAC(
                user,
                resource,
                request.permission()
            );

            boolean grantFound = rbac || acl || dac;

            reasons.add(
                "RBAC=" + rbac +
                ", ACL=" + acl +
                ", DAC=" + dac
            );

            reasons.add(
                grantFound
                    ? "At least one grant mechanism matched"
                    : "No grant mechanism matched"
            );

            return new PolicyDecision(
                mandatoryPassed && grantFound,
                reasons
            );
        }

        Decision authorize(AccessRequest request) {
            PolicyDecision policyDecision;

            try {
                policyDecision = evaluate(request);

            } catch (AuthorizationException exception) {
                auditEvents.add(new AuditEvent(
                    UUID.randomUUID().toString(),
                    request.userId(),
                    request.resourceId(),
                    request.permission(),
                    Decision.DENY,
                    List.of("Authorization validation failure"),
                    Instant.now()
                ));

                throw exception;
            }

            Decision decision = policyDecision.allowed()
                ? Decision.ALLOW
                : Decision.DENY;

            auditEvents.add(new AuditEvent(
                UUID.randomUUID().toString(),
                request.userId(),
                request.resourceId(),
                request.permission(),
                decision,
                policyDecision.reasons(),
                Instant.now()
            ));

            return decision;
        }

        List<AuditEvent> getAuditEvents() {
            return List.copyOf(auditEvents);
        }

        long countDecisions(Decision decision) {
            return auditEvents.stream()
                .filter(event -> event.decision() == decision)
                .count();
        }

        Map<String, Long> decisionsByResource() {
            return auditEvents.stream().collect(
                Collectors.groupingBy(
                    AuditEvent::resourceId,
                    Collectors.counting()
                )
            );
        }
    }

    private static AuthorizationService buildExample() {
        AuthorizationService service = new AuthorizationService();

        service.addUser(new User(
            "alice",
            "engineering",
            Classification.CONFIDENTIAL,
            "India",
            true,
            true,
            false,
            false,
            false
        ));

        service.addUser(new User(
            "bob",
            "finance",
            Classification.SECRET,
            "India",
            true,
            true,
            true,
            true,
            false
        ));

        service.addUser(new User(
            "charlie",
            "engineering",
            Classification.PUBLIC,
            "India",
            false,
            false,
            false,
            false,
            false
        ));

        service.addRole(new Role(
            "developer",
            EnumSet.of(Permission.READ, Permission.WRITE)
        ));

        service.addRole(new Role(
            "security-admin",
            EnumSet.of(Permission.READ, Permission.ADMIN)
        ));

        service.assignRole("alice", "developer");
        service.assignRole("bob", "security-admin");

        service.addResource(new Resource(
            "source-code",
            "alice",
            "engineering",
            Classification.CONFIDENTIAL,
            Set.of("India"),
            true,
            false
        ));

        service.addResource(new Resource(
            "financial-report",
            "bob",
            "finance",
            Classification.SECRET,
            Set.of("India"),
            true,
            true
        ));

        service.grantAcl(
            "financial-report",
            "alice",
            EnumSet.of(Permission.READ)
        );

        return service;
    }

    private static void runTests(AuthorizationService service) {
        record TestCase(
            String name,
            AccessRequest request,
            Decision expected
        ) {}

        List<TestCase> cases = List.of(
            new TestCase(
                "RBAC read",
                AccessRequest.create(
                    "alice",
                    "source-code",
                    Permission.READ,
                    Purpose.BUSINESS
                ),
                Decision.ALLOW
            ),
            new TestCase(
                "ACL compliance access",
                AccessRequest.create(
                    "alice",
                    "financial-report",
                    Permission.READ,
                    Purpose.COMPLIANCE
                ),
                Decision.ALLOW
            ),
            new TestCase(
                "MAC denial",
                AccessRequest.create(
                    "alice",
                    "financial-report",
                    Permission.WRITE,
                    Purpose.COMPLIANCE
                ),
                Decision.DENY
            ),
            new TestCase(
                "Inactive user",
                AccessRequest.create(
                    "charlie",
                    "source-code",
                    Permission.READ,
                    Purpose.BUSINESS
                ),
                Decision.DENY
            ),
            new TestCase(
                "Delete restriction",
                AccessRequest.create(
                    "alice",
                    "source-code",
                    Permission.DELETE,
                    Purpose.MAINTENANCE
                ),
                Decision.DENY
            ),
            new TestCase(
                "Authorized administrator",
                AccessRequest.create(
                    "bob",
                    "financial-report",
                    Permission.ADMIN,
                    Purpose.MAINTENANCE
                ),
                Decision.ALLOW
            )
        );

        for (TestCase test : cases) {
            Decision actual = service.authorize(test.request());

            if (actual != test.expected()) {
                throw new AssertionError(
                    test.name() + " expected " +
                    test.expected() + " but received " + actual
                );
            }

            System.out.println(
                test.name() + ": " + actual
            );
        }

        try {
            service.authorize(
                AccessRequest.create(
                    "unknown",
                    "source-code",
                    Permission.READ,
                    Purpose.BUSINESS
                )
            );

            throw new AssertionError(
                "Unknown user should have been rejected"
            );

        } catch (ValidationException expected) {
            System.out.println("Unknown identity validation: PASS");
        }

        service.revokeRole("alice", "developer");
        service.revokeAcl("financial-report", "alice");

        Decision afterRevocation = service.authorize(
            AccessRequest.create(
                "alice",
                "source-code",
                Permission.READ,
                Purpose.BUSINESS
            )
        );

        if (afterRevocation != Decision.ALLOW) {
            throw new AssertionError(
                "The resource owner DAC grant should remain effective"
            );
        }

        System.out.println(
            "Owner DAC after role revocation: " + afterRevocation
        );
    }

    public static void main(String[] args) {
        AuthorizationService service = buildExample();

        runTests(service);

        System.out.println("\nAUDIT REPORT");

        for (AuditEvent event : service.getAuditEvents()) {
            System.out.println(
                event.timestamp() + " | " +
                event.userId() + " | " +
                event.resourceId() + " | " +
                event.permission() + " | " +
                event.decision()
            );
        }

        System.out.println(
            "\nAllowed: " +
            service.countDecisions(Decision.ALLOW)
        );

        System.out.println(
            "Denied: " +
            service.countDecisions(Decision.DENY)
        );

        System.out.println(
            "Decisions by resource: " +
            service.decisionsByResource()
        );
    }
}
