import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * IAM SECURITY REVIEW
 *
 * Enterprise identity governance and access certification engine.
 *
 * Java version: 17
 *
 * Capabilities:
 * - Strongly typed IAM domain objects
 * - RBAC and inherited permissions
 * - Identity attack surface assessment
 * - Privilege escalation exposure
 * - Access certification
 * - Approval and review policies
 * - Separation of duties
 * - Risk classification
 * - Immutable audit events
 * - Controlled identity state transitions
 */
public class IAMSecurityReview {

    enum IdentityType {
        HUMAN, SERVICE, APPLICATION, EXTERNAL
    }

    enum IdentityStatus {
        ACTIVE, SUSPENDED, DISABLED
    }

    enum Decision {
        APPROVE, REVOKE, REDUCE, ESCALATE
    }

    enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    static class IAMException extends RuntimeException {
        IAMException(String message) {
            super(message);
        }
    }

    static class ValidationException extends IAMException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class PolicyException extends IAMException {
        PolicyException(String message) {
            super(message);
        }
    }

    record Permission(String resource, String action) {
        Permission {
            if (resource == null || resource.isBlank()
                    || action == null || action.isBlank()) {
                throw new ValidationException(
                        "Permission resource and action are required"
                );
            }
        }

        String key() {
            return resource + ":" + action;
        }
    }

    record AuditEvent(
            UUID eventId,
            Instant timestamp,
            String actor,
            String eventType,
            String subject,
            String details
    ) {
        AuditEvent {
            Objects.requireNonNull(eventId);
            Objects.requireNonNull(timestamp);
            Objects.requireNonNull(actor);
            Objects.requireNonNull(eventType);
            Objects.requireNonNull(subject);
            Objects.requireNonNull(details);
        }

        static AuditEvent create(
                String actor,
                String eventType,
                String subject,
                String details
        ) {
            return new AuditEvent(
                    UUID.randomUUID(),
                    Instant.now(),
                    actor,
                    eventType,
                    subject,
                    details
            );
        }
    }

    record Role(
            String id,
            String name,
            Set<Permission> permissions,
            Set<String> inheritedRoles,
            boolean privileged
    ) {
        Role {
            if (id == null || id.isBlank()
                    || name == null || name.isBlank()) {
                throw new ValidationException("Invalid role");
            }

            permissions = Set.copyOf(permissions);
            inheritedRoles = Set.copyOf(inheritedRoles);
        }
    }

    static final class Identity {
        private final String id;
        private final String name;
        private final IdentityType type;
        private final String owner;
        private final String department;

        private IdentityStatus status;
        private final Set<String> roles;
        private final Set<Permission> directPermissions;
        private boolean mfaEnabled;
        private final Instant lastLogin;

        Identity(
                String id,
                String name,
                IdentityType type,
                IdentityStatus status,
                String owner,
                String department,
                Set<String> roles,
                Set<Permission> directPermissions,
                boolean mfaEnabled,
                Instant lastLogin
        ) {
            if (id == null || id.isBlank()
                    || name == null || name.isBlank()
                    || owner == null || owner.isBlank()) {
                throw new ValidationException(
                        "Identity ID, name, and owner are required"
                );
            }

            this.id = id;
            this.name = name;
            this.type = Objects.requireNonNull(type);
            this.status = Objects.requireNonNull(status);
            this.owner = owner;
            this.department = Objects.requireNonNull(department);
            this.roles = new HashSet<>(roles);
            this.directPermissions = new HashSet<>(directPermissions);
            this.mfaEnabled = mfaEnabled;
            this.lastLogin = lastLogin;
        }

        String id() {
            return id;
        }

        String name() {
            return name;
        }

        IdentityStatus status() {
            return status;
        }

        Set<String> roles() {
            return Collections.unmodifiableSet(roles);
        }

        boolean mfaEnabled() {
            return mfaEnabled;
        }

        void disable() {
            status = IdentityStatus.DISABLED;
            roles.clear();
            directPermissions.clear();
        }

        void removeDirectPermissions(Set<String> permissionKeys) {
            directPermissions.removeIf(
                    permission -> permissionKeys.contains(permission.key())
            );
        }
    }

    record ReviewRequest(
            String identityId,
            String reviewer,
            Decision decision,
            String justification,
            Set<String> permissionsToRemove
    ) {
        ReviewRequest {
            if (identityId == null || identityId.isBlank()
                    || reviewer == null || reviewer.isBlank()
                    || justification == null
                    || justification.isBlank()) {
                throw new ValidationException(
                        "Review identity, reviewer, and justification required"
                );
            }

            Objects.requireNonNull(decision);
            permissionsToRemove = Set.copyOf(permissionsToRemove);
        }
    }

    record ReviewRecord(
            UUID reviewId,
            String identityId,
            String reviewer,
            Decision decision,
            String justification,
            Instant reviewedAt
    ) {}

    record Finding(
            String identityId,
            String category,
            Severity severity,
            int riskScore,
            String evidence,
            String recommendation
    ) {}

    record ApprovalPolicy(
            int minimumReviews,
            int minimumApprovals,
            boolean requireIndependentReviewers,
            boolean rejectSelfReview,
            boolean requireMFAForPrivileged
    ) {
        ApprovalPolicy {
            if (minimumReviews < 0
                    || minimumApprovals < 0
                    || minimumApprovals > minimumReviews) {
                throw new ValidationException("Invalid approval policy");
            }
        }
    }

    record ProtectionPolicy(
            boolean blockDirectPush,
            boolean blockForcePush,
            boolean blockBranchDeletion,
            boolean requireMFA,
            boolean requireOwnerCertification,
            boolean enforceSeparationOfDuties
    ) {}

    static class ReviewPolicy {
        private final Set<String> eligibleReviewers;
        private final ApprovalPolicy approvalPolicy;
        private final ProtectionPolicy protectionPolicy;

        ReviewPolicy(
                Set<String> eligibleReviewers,
                ApprovalPolicy approvalPolicy,
                ProtectionPolicy protectionPolicy
        ) {
            this.eligibleReviewers = Set.copyOf(eligibleReviewers);
            this.approvalPolicy = Objects.requireNonNull(approvalPolicy);
            this.protectionPolicy = Objects.requireNonNull(protectionPolicy);
        }

        void validateReviewer(String reviewer, String owner) {
            if (!eligibleReviewers.contains(reviewer)) {
                throw new PolicyException("Reviewer is not eligible");
            }

            if (approvalPolicy.rejectSelfReview()
                    && reviewer.equals(owner)) {
                throw new PolicyException(
                        "Self-review is prohibited"
                );
            }
        }

        ApprovalPolicy approvalPolicy() {
            return approvalPolicy;
        }

        ProtectionPolicy protectionPolicy() {
            return protectionPolicy;
        }
    }

    static class IAMRepository {
        private final Map<String, Identity> identities = new HashMap<>();
        private final Map<String, Role> roles = new HashMap<>();
        private final List<ReviewRecord> reviews = new ArrayList<>();
        private final List<AuditEvent> auditEvents = new ArrayList<>();

        void addRole(Role role) {
            if (roles.putIfAbsent(role.id(), role) != null) {
                throw new ValidationException("Duplicate role " + role.id());
            }
        }

        void addIdentity(Identity identity) {
            if (identities.containsKey(identity.id())) {
                throw new ValidationException(
                        "Duplicate identity " + identity.id()
                );
            }

            for (String roleId : identity.roles()) {
                if (!roles.containsKey(roleId)) {
                    throw new ValidationException(
                            "Unknown role " + roleId
                    );
                }
            }

            identities.put(identity.id(), identity);

            auditEvents.add(AuditEvent.create(
                    "system",
                    "IDENTITY_CREATED",
                    identity.id(),
                    identity.name()
            ));
        }

        Identity getIdentity(String id) {
            Identity identity = identities.get(id);

            if (identity == null) {
                throw new ValidationException("Unknown identity " + id);
            }

            return identity;
        }

        void validateRoleGraph() {
            Set<String> visiting = new HashSet<>();
            Set<String> visited = new HashSet<>();

            for (String id : roles.keySet()) {
                visit(id, visiting, visited);
            }
        }

        private void visit(
                String id,
                Set<String> visiting,
                Set<String> visited
        ) {
            if (!roles.containsKey(id)) {
                throw new ValidationException(
                        "Unknown inherited role " + id
                );
            }

            if (visiting.contains(id)) {
                throw new PolicyException(
                        "Circular role inheritance at " + id
                );
            }

            if (visited.contains(id)) return;

            visiting.add(id);

            for (String parent : roles.get(id).inheritedRoles()) {
                visit(parent, visiting, visited);
            }

            visiting.remove(id);
            visited.add(id);
        }

        Set<Permission> effectivePermissions(String identityId) {
            Identity identity = getIdentity(identityId);

            if (identity.status() != IdentityStatus.ACTIVE) {
                return Set.of();
            }

            Set<Permission> result =
                    new HashSet<>(identity.directPermissions);

            Set<String> visited = new HashSet<>();

            for (String roleId : identity.roles()) {
                collectRolePermissions(roleId, result, visited);
            }

            return Set.copyOf(result);
        }

        private void collectRolePermissions(
                String roleId,
                Set<Permission> result,
                Set<String> visited
        ) {
            if (!visited.add(roleId)) return;

            Role role = roles.get(roleId);

            if (role == null) {
                throw new ValidationException("Unknown role " + roleId);
            }

            result.addAll(role.permissions());

            for (String parent : role.inheritedRoles()) {
                collectRolePermissions(parent, result, visited);
            }
        }

        boolean isPrivileged(Identity identity) {
            Set<String> sensitiveActions = Set.of(
                    "admin",
                    "manage_roles",
                    "manage_policies",
                    "manage_credentials",
                    "configure_security",
                    "delete"
            );

            if (identity.roles().stream()
                    .map(roles::get)
                    .anyMatch(Role::privileged)) {
                return true;
            }

            return effectivePermissions(identity.id()).stream()
                    .anyMatch(p -> sensitiveActions.contains(p.action()));
        }

        List<String> separationOfDutiesViolations(Identity identity) {
            List<String> violations = new ArrayList<>();

            if (identity.roles().contains("finance_approver")
                    && identity.roles().contains("payment_creator")) {
                violations.add(
                        "finance_approver conflicts with payment_creator"
                );
            }

            if (identity.roles().contains("security_admin")
                    && identity.roles().contains("audit_reviewer")) {
                violations.add(
                        "security_admin conflicts with audit_reviewer"
                );
            }

            return violations;
        }

        void recordReview(
                ReviewRequest request,
                ReviewPolicy policy
        ) {
            Identity identity = getIdentity(request.identityId());

            policy.validateReviewer(
                    request.reviewer(),
                    identity.owner
            );

            if (request.justification().length() < 10) {
                throw new PolicyException(
                        "Review justification is too short"
                );
            }

            if (request.decision() == Decision.REDUCE) {
                Set<String> available = effectivePermissions(identity.id())
                        .stream()
                        .map(Permission::key)
                        .collect(Collectors.toSet());

                if (!available.containsAll(request.permissionsToRemove())) {
                    throw new ValidationException(
                            "Reduction references unassigned permissions"
                    );
                }
            }

            switch (request.decision()) {
                case APPROVE -> {
                    // Certification does not itself create access.
                }

                case REVOKE -> identity.disable();

                case REDUCE -> {
                    // Remove only identity-level permissions.
                    // Shared role permissions require a role-governance change.
                    identity.removeDirectPermissions(
                            request.permissionsToRemove()
                    );
                }

                case ESCALATE -> auditEvents.add(
                        AuditEvent.create(
                                request.reviewer(),
                                "REVIEW_ESCALATED",
                                identity.id(),
                                request.justification()
                        )
                );
            }

            ReviewRecord record = new ReviewRecord(
                    UUID.randomUUID(),
                    identity.id(),
                    request.reviewer(),
                    request.decision(),
                    request.justification(),
                    Instant.now()
            );

            reviews.add(record);

            auditEvents.add(AuditEvent.create(
                    request.reviewer(),
                    "ACCESS_REVIEW_RECORDED",
                    identity.id(),
                    request.decision().name()
            ));
        }

        List<Finding> assess() {
            validateRoleGraph();

            List<Finding> findings = new ArrayList<>();

            Set<String> sensitiveActions = Set.of(
                    "admin",
                    "manage_roles",
                    "manage_policies",
                    "manage_credentials",
                    "configure_security",
                    "delete"
            );

            Instant now = Instant.now();

            for (Identity identity : identities.values()) {
                if (identity.status() != IdentityStatus.ACTIVE) {
                    continue;
                }

                Set<Permission> permissions =
                        effectivePermissions(identity.id());

                List<String> dangerous = permissions.stream()
                        .filter(p -> sensitiveActions.contains(p.action()))
                        .map(Permission::key)
                        .sorted()
                        .toList();

                if (!dangerous.isEmpty()) {
                    findings.add(new Finding(
                            identity.id(),
                            "PRIVILEGE_ESCALATION_EXPOSURE",
                            Severity.CRITICAL,
                            95,
                            String.join(", ", dangerous),
                            "Review administrative permissions and role inheritance."
                    ));
                }

                if (permissions.size() > 8) {
                    findings.add(new Finding(
                            identity.id(),
                            "EXCESSIVE_PRIVILEGES",
                            Severity.MEDIUM,
                            55,
                            permissions.size() + " effective permissions",
                            "Apply least privilege."
                    ));
                }

                if (isPrivileged(identity)
                        && !identity.mfaEnabled()) {
                    findings.add(new Finding(
                            identity.id(),
                            "MISSING_PRIVILEGED_MFA",
                            Severity.CRITICAL,
                            98,
                            "Privileged account without MFA",
                            "Require phishing-resistant MFA."
                    ));
                }

                if (identity.lastLogin == null
                        || Duration.between(
                                identity.lastLogin, now
                        ).toDays() > 90) {
                    findings.add(new Finding(
                            identity.id(),
                            "DORMANT_IDENTITY",
                            isPrivileged(identity)
                                    ? Severity.CRITICAL : Severity.HIGH,
                            isPrivileged(identity) ? 95 : 75,
                            "No recent login activity",
                            "Validate ownership and disable unused accounts."
                    ));
                }

                for (String violation :
                        separationOfDutiesViolations(identity)) {
                    findings.add(new Finding(
                            identity.id(),
                            "SEPARATION_OF_DUTIES",
                            Severity.CRITICAL,
                            95,
                            violation,
                            "Remove conflicting roles or require independent control."
                    ));
                }
            }

            findings.sort(
                    Comparator.comparingInt(Finding::riskScore)
                            .reversed()
                            .thenComparing(Finding::identityId)
            );

            return List.copyOf(findings);
        }

        void printAuditLog() {
            System.out.println("\nAUDIT EVENTS");

            auditEvents.forEach(event ->
                    System.out.printf(
                            "%s | %s | %s | %s%n",
                            event.timestamp(),
                            event.eventType(),
                            event.subject(),
                            event.actor()
                    )
            );
        }

        void printInventory() {
            System.out.println("\nIDENTITY INVENTORY");

            identities.values().stream()
                    .sorted(Comparator.comparing(Identity::id))
                    .forEach(identity -> System.out.printf(
                            "%s | %s | %s | Roles: %s%n",
                            identity.id(),
                            identity.name(),
                            identity.status(),
                            identity.roles()
                    ));
        }

        int identityCount() {
            return identities.size();
        }

        int reviewCount() {
            return reviews.size();
        }
    }

    static void printFindings(List<Finding> findings) {
        System.out.println("\nIAM SECURITY FINDINGS");
        System.out.println("==============================");

        for (Finding finding : findings) {
            System.out.printf(
                    "%s | %s | %s | Risk: %d%n",
                    finding.identityId(),
                    finding.category(),
                    finding.severity(),
                    finding.riskScore()
            );

            System.out.println("Evidence: " + finding.evidence());
            System.out.println("Action: " + finding.recommendation());
        }
    }

    static IAMRepository buildDemoRepository() {
        IAMRepository repository = new IAMRepository();

        repository.addRole(new Role(
                "employee",
                "Employee",
                Set.of(new Permission("documents", "read")),
                Set.of(),
                false
        ));

        repository.addRole(new Role(
                "developer",
                "Developer",
                Set.of(
                        new Permission("source_code", "read"),
                        new Permission("source_code", "write"),
                        new Permission("deployment", "read")
                ),
                Set.of("employee"),
                false
        ));

        repository.addRole(new Role(
                "security_admin",
                "Security Administrator",
                Set.of(
                        new Permission("iam", "manage_roles"),
                        new Permission("iam", "manage_policies"),
                        new Permission("secrets", "manage_credentials")
                ),
                Set.of(),
                true
        ));

        repository.addRole(new Role(
                "finance_approver",
                "Finance Approver",
                Set.of(new Permission("payments", "approve")),
                Set.of(),
                false
        ));

        repository.addRole(new Role(
                "payment_creator",
                "Payment Creator",
                Set.of(new Permission("payments", "create")),
                Set.of(),
                false
        ));

        Instant now = Instant.now();

        repository.addIdentity(new Identity(
                "USR-301",
                "Software Developer",
                IdentityType.HUMAN,
                IdentityStatus.ACTIVE,
                "engineering_manager",
                "engineering",
                Set.of("developer"),
                Set.of(),
                true,
                now.minus(Duration.ofDays(2))
        ));

        repository.addIdentity(new Identity(
                "USR-302",
                "Privileged Operator",
                IdentityType.HUMAN,
                IdentityStatus.ACTIVE,
                "security_director",
                "security",
                Set.of("security_admin"),
                Set.of(),
                false,
                now.minus(Duration.ofDays(120))
        ));

        repository.addIdentity(new Identity(
                "USR-303",
                "Finance Operator",
                IdentityType.HUMAN,
                IdentityStatus.ACTIVE,
                "finance_director",
                "finance",
                Set.of("finance_approver", "payment_creator"),
                Set.of(),
                true,
                now.minus(Duration.ofDays(1))
        ));

        repository.addIdentity(new Identity(
                "SVC-301",
                "Legacy Integration",
                IdentityType.SERVICE,
                IdentityStatus.ACTIVE,
                "integration_team",
                "platform",
                Set.of("security_admin"),
                Set.of(),
                false,
                null
        ));

        return repository;
    }

    public static void main(String[] args) {
        try {
            IAMRepository repository = buildDemoRepository();

            ApprovalPolicy approvalPolicy = new ApprovalPolicy(
                    2,
                    1,
                    true,
                    true,
                    true
            );

            ProtectionPolicy protectionPolicy =
                    new ProtectionPolicy(
                            true,
                            true,
                            true,
                            true,
                            true,
                            true
                    );

            ReviewPolicy policy = new ReviewPolicy(
                    Set.of(
                            "security_director",
                            "compliance_officer",
                            "engineering_manager"
                    ),
                    approvalPolicy,
                    protectionPolicy
            );

            System.out.println("IAM SECURITY REVIEW");
            System.out.println("==============================");

            repository.printInventory();

            List<Finding> findings = repository.assess();
            printFindings(findings);

            System.out.println("\nACCESS CERTIFICATION");

            repository.recordReview(
                    new ReviewRequest(
                            "USR-302",
                            "security_director",
                            Decision.REVOKE,
                            "Dormant privileged identity without MFA.",
                            Set.of()
                    ),
                    policy
            );

            System.out.println("Privileged identity revoked.");

            System.out.println("\nPOST-REMEDIATION ASSESSMENT");
            printFindings(repository.assess());

            System.out.println("\nMETRICS");
            System.out.println("Identities: " + repository.identityCount());
            System.out.println("Reviews: " + repository.reviewCount());

            repository.printAuditLog();

        } catch (IAMException exception) {
            System.err.println(
                    "IAM governance failure: " + exception.getMessage()
            );
            System.exit(1);
        }
    }
}
