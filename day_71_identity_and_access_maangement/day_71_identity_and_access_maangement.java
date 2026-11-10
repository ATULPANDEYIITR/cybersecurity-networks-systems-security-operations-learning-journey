import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
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
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Enterprise Identity and Access Management.
 *
 * Java 17
 * No third-party dependencies.
 *
 * Demonstrates authentication, authorization, accounting,
 * role administration, session control and identity lifecycle.
 */
public class IAMEnterprise {

    enum IdentityStatus {
        PENDING,
        ACTIVE,
        SUSPENDED,
        DISABLED,
        TERMINATED
    }

    enum Role {
        EMPLOYEE,
        MANAGER,
        SECURITY_ADMIN,
        AUDITOR
    }

    enum Permission {
        DOCUMENT_READ,
        DOCUMENT_WRITE,
        DOCUMENT_DELETE,
        USER_MANAGE,
        ROLE_MANAGE,
        AUDIT_READ
    }

    enum EventType {
        IDENTITY_CREATED,
        IDENTITY_ACTIVATED,
        ROLE_ASSIGNED,
        ROLE_REMOVED,
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        ACCESS_GRANTED,
        ACCESS_DENIED,
        SESSION_REVOKED,
        IDENTITY_SUSPENDED,
        IDENTITY_DISABLED,
        IDENTITY_TERMINATED
    }

    enum Decision {
        ALLOW,
        DENY
    }

    static class IAMException extends RuntimeException {
        IAMException(String message) {
            super(message);
        }
    }

    static class AuthenticationException extends IAMException {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static class AuthorizationException extends IAMException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class LifecycleException extends IAMException {
        LifecycleException(String message) {
            super(message);
        }
    }

    record AuditEvent(
        long sequence,
        String identityId,
        EventType type,
        String resource,
        String reason,
        Instant timestamp
    ) {}

    record AccessDecision(
        Decision decision,
        String reason,
        String identityId,
        Permission permission
    ) {}

    record AuthenticationResult(
        String sessionToken,
        Instant expiresAt
    ) {}

    record IdentitySnapshot(
        String identityId,
        String username,
        IdentityStatus status,
        Set<Role> roles,
        long version
    ) {
        IdentitySnapshot {
            roles = Set.copyOf(roles);
        }
    }

    static final class Identity {
        private final String id;
        private final String username;
        private final String email;

        // Credential verification is delegated to a dedicated provider.
        private final String credentialReference;

        private IdentityStatus status = IdentityStatus.PENDING;
        private final Set<Role> roles = EnumSet.noneOf(Role.class);
        private boolean mfaEnabled;
        private int failedAttempts;
        private long version = 1;

        Identity(
            String id,
            String username,
            String email,
            String credentialReference
        ) {
            this.id = id;
            this.username = username;
            this.email = email;
            this.credentialReference = credentialReference;
        }

        IdentitySnapshot snapshot() {
            return new IdentitySnapshot(
                id,
                username,
                status,
                roles,
                version
            );
        }
    }

    static final class Session {
        private final String token;
        private final String identityId;
        private final Instant createdAt;
        private final Instant expiresAt;
        private boolean revoked;

        Session(
            String token,
            String identityId,
            Instant createdAt,
            Instant expiresAt
        ) {
            this.token = token;
            this.identityId = identityId;
            this.createdAt = createdAt;
            this.expiresAt = expiresAt;
        }
    }

    interface CredentialProvider {
        boolean verify(
            String credentialReference,
            String suppliedCredential
        );
    }

    static final class DemoCredentialProvider
        implements CredentialProvider {

        private final Map<String, String> credentials =
            new ConcurrentHashMap<>();

        void register(String reference, String credential) {
            credentials.put(reference, credential);
        }

        @Override
        public boolean verify(
            String reference,
            String suppliedCredential
        ) {
            String expected = credentials.get(reference);

            if (expected == null || suppliedCredential == null) {
                return false;
            }

            return java.security.MessageDigest.isEqual(
                expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                suppliedCredential.getBytes(
                    java.nio.charset.StandardCharsets.UTF_8
                )
            );
        }
    }

    static final class RolePolicy {
        private final Map<Role, Set<Permission>> grants =
            new EnumMap<>(Role.class);

        RolePolicy() {
            grants.put(
                Role.EMPLOYEE,
                EnumSet.of(
                    Permission.DOCUMENT_READ,
                    Permission.DOCUMENT_WRITE
                )
            );

            grants.put(
                Role.MANAGER,
                EnumSet.of(
                    Permission.DOCUMENT_READ,
                    Permission.DOCUMENT_WRITE,
                    Permission.DOCUMENT_DELETE
                )
            );

            grants.put(
                Role.SECURITY_ADMIN,
                EnumSet.allOf(Permission.class)
            );

            grants.put(
                Role.AUDITOR,
                EnumSet.of(
                    Permission.DOCUMENT_READ,
                    Permission.AUDIT_READ
                )
            );
        }

        boolean allows(Set<Role> roles, Permission permission) {
            return roles.stream().anyMatch(
                role -> grants.getOrDefault(
                    role,
                    Collections.emptySet()
                ).contains(permission)
            );
        }
    }

    static final class AuditService {
        private final AtomicLong sequence = new AtomicLong();

        private final List<AuditEvent> events =
            Collections.synchronizedList(new ArrayList<>());

        void record(
            String identityId,
            EventType type,
            String resource,
            String reason
        ) {
            events.add(
                new AuditEvent(
                    sequence.incrementAndGet(),
                    identityId,
                    type,
                    resource,
                    reason,
                    Instant.now()
                )
            );
        }

        List<AuditEvent> getEvents() {
            synchronized (events) {
                return List.copyOf(events);
            }
        }

        Map<EventType, Long> report() {
            return getEvents().stream().collect(
                Collectors.groupingBy(
                    AuditEvent::type,
                    () -> new EnumMap<>(EventType.class),
                    Collectors.counting()
                )
            );
        }
    }

    static final class ReviewPolicy {
        private final Set<String> explicitDenials =
            ConcurrentHashMap.newKeySet();

        AccessDecision evaluate(
            Identity identity,
            Permission permission,
            String resource,
            RolePolicy rolePolicy
        ) {
            if (identity.status != IdentityStatus.ACTIVE) {
                return new AccessDecision(
                    Decision.DENY,
                    "IDENTITY_NOT_ACTIVE",
                    identity.id,
                    permission
                );
            }

            if (explicitDenials.contains(identity.id)) {
                return new AccessDecision(
                    Decision.DENY,
                    "EXPLICIT_DENY",
                    identity.id,
                    permission
                );
            }

            if (
                resource == null ||
                resource.isBlank() ||
                resource.length() > 500
            ) {
                return new AccessDecision(
                    Decision.DENY,
                    "INVALID_RESOURCE",
                    identity.id,
                    permission
                );
            }

            boolean allowed = rolePolicy.allows(
                identity.roles,
                permission
            );

            return new AccessDecision(
                allowed ? Decision.ALLOW : Decision.DENY,
                allowed ? "ROLE_PERMISSION_MATCH" : "PERMISSION_NOT_GRANTED",
                identity.id,
                permission
            );
        }

        void deny(String identityId) {
            explicitDenials.add(identityId);
        }

        void restore(String identityId) {
            explicitDenials.remove(identityId);
        }
    }

    static final class IAMService {

        private final Map<String, Identity> identities =
            new ConcurrentHashMap<>();

        private final Map<String, String> usernameIndex =
            new ConcurrentHashMap<>();

        private final Map<String, Session> sessions =
            new ConcurrentHashMap<>();

        private final Map<String, Instant> lockouts =
            new ConcurrentHashMap<>();

        private final CredentialProvider credentialProvider;
        private final RolePolicy rolePolicy;
        private final ReviewPolicy reviewPolicy;
        private final AuditService audit;

        private final int maxAttempts;
        private final Duration sessionDuration;
        private final Duration lockoutDuration;

        IAMService(
            CredentialProvider credentialProvider,
            int maxAttempts,
            Duration sessionDuration,
            Duration lockoutDuration
        ) {
            this.credentialProvider = Objects.requireNonNull(
                credentialProvider
            );

            if (
                maxAttempts <= 0 ||
                sessionDuration.isZero() ||
                sessionDuration.isNegative() ||
                lockoutDuration.isZero() ||
                lockoutDuration.isNegative()
            ) {
                throw new IllegalArgumentException(
                    "Invalid IAM configuration"
                );
            }

            this.maxAttempts = maxAttempts;
            this.sessionDuration = sessionDuration;
            this.lockoutDuration = lockoutDuration;

            this.rolePolicy = new RolePolicy();
            this.reviewPolicy = new ReviewPolicy();
            this.audit = new AuditService();
        }

        private Identity getIdentity(String id) {
            Identity identity = identities.get(id);

            if (identity == null) {
                throw new LifecycleException("Identity not found");
            }

            return identity;
        }

        synchronized String createIdentity(
            String username,
            String email,
            String credentialReference
        ) {
            username = Objects.requireNonNull(username)
                .trim().toLowerCase();

            if (!username.matches("[a-z0-9._-]{3,100}")) {
                throw new IllegalArgumentException("Invalid username");
            }

            if (
                email == null ||
                !email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")
            ) {
                throw new IllegalArgumentException("Invalid email");
            }

            if (
                credentialReference == null ||
                credentialReference.isBlank()
            ) {
                throw new IllegalArgumentException(
                    "Credential reference is required"
                );
            }

            if (usernameIndex.containsKey(username)) {
                throw new LifecycleException("Duplicate username");
            }

            String id = UUID.randomUUID().toString();

            Identity identity = new Identity(
                id,
                username,
                email.toLowerCase(),
                credentialReference
            );

            identities.put(id, identity);
            usernameIndex.put(username, id);

            audit.record(
                id,
                EventType.IDENTITY_CREATED,
                "identity",
                "provisioning"
            );

            return id;
        }

        synchronized void activate(String id) {
            Identity identity = getIdentity(id);

            if (identity.status != IdentityStatus.PENDING) {
                throw new LifecycleException(
                    "Invalid activation transition"
                );
            }

            identity.status = IdentityStatus.ACTIVE;
            identity.version++;

            audit.record(
                id,
                EventType.IDENTITY_ACTIVATED,
                "identity",
                "approved"
            );
        }

        synchronized void assignRole(String id, Role role) {
            Identity identity = getIdentity(id);

            if (identity.status != IdentityStatus.ACTIVE) {
                throw new LifecycleException(
                    "Identity must be active"
                );
            }

            if (!identity.roles.add(role)) {
                throw new LifecycleException("Role already assigned");
            }

            identity.version++;

            audit.record(
                id,
                EventType.ROLE_ASSIGNED,
                "identity",
                role.name()
            );
        }

        synchronized void removeRole(String id, Role role) {
            Identity identity = getIdentity(id);

            if (!identity.roles.remove(role)) {
                throw new LifecycleException("Role not assigned");
            }

            identity.version++;

            audit.record(
                id,
                EventType.ROLE_REMOVED,
                "identity",
                role.name()
            );
        }

        synchronized void enableMfa(String id) {
            Identity identity = getIdentity(id);

            if (identity.status != IdentityStatus.ACTIVE) {
                throw new LifecycleException(
                    "Identity must be active"
                );
            }

            identity.mfaEnabled = true;
            identity.version++;
        }

        synchronized AuthenticationResult authenticate(
            String username,
            String suppliedCredential,
            boolean mfaVerified
        ) {
            String id = usernameIndex.get(
                Objects.requireNonNull(username).trim().toLowerCase()
            );

            if (id == null) {
                audit.record(
                    null,
                    EventType.LOGIN_FAILURE,
                    "authentication",
                    "unknown_identity"
                );

                throw new AuthenticationException(
                    "Invalid credentials"
                );
            }

            Identity identity = getIdentity(id);

            Instant now = Instant.now();

            Instant lockedUntil = lockouts.get(id);

            if (lockedUntil != null && now.isBefore(lockedUntil)) {
                throw new AuthenticationException(
                    "Account temporarily locked"
                );
            }

            if (identity.status != IdentityStatus.ACTIVE) {
                throw new AuthenticationException(
                    "Identity is not active"
                );
            }

            boolean valid = credentialProvider.verify(
                identity.credentialReference,
                suppliedCredential
            );

            if (!valid || (identity.mfaEnabled && !mfaVerified)) {
                identity.failedAttempts++;

                audit.record(
                    id,
                    EventType.LOGIN_FAILURE,
                    "authentication",
                    "credential_or_mfa_failure"
                );

                if (identity.failedAttempts >= maxAttempts) {
                    lockouts.put(
                        id,
                        now.plus(lockoutDuration)
                    );
                }

                throw new AuthenticationException(
                    "Authentication failed"
                );
            }

            identity.failedAttempts = 0;
            lockouts.remove(id);

            String token = UUID.randomUUID().toString();

            Instant expiresAt = now.plus(sessionDuration);

            sessions.put(
                token,
                new Session(
                    token,
                    id,
                    now,
                    expiresAt
                )
            );

            audit.record(
                id,
                EventType.LOGIN_SUCCESS,
                "session",
                "authenticated"
            );

            return new AuthenticationResult(token, expiresAt);
        }

        AccessDecision authorize(
            String token,
            Permission permission,
            String resource
        ) {
            Session session = sessions.get(token);

            if (session == null || session.revoked) {
                throw new AuthorizationException(
                    "Invalid session"
                );
            }

            if (!Instant.now().isBefore(session.expiresAt)) {
                session.revoked = true;

                audit.record(
                    session.identityId,
                    EventType.SESSION_REVOKED,
                    "session",
                    "expired"
                );

                throw new AuthorizationException(
                    "Session expired"
                );
            }

            Identity identity = getIdentity(session.identityId);

            AccessDecision result = reviewPolicy.evaluate(
                identity,
                permission,
                resource,
                rolePolicy
            );

            audit.record(
                identity.id,
                result.decision() == Decision.ALLOW
                    ? EventType.ACCESS_GRANTED
                    : EventType.ACCESS_DENIED,
                resource,
                result.reason()
            );

            return result;
        }

        synchronized void revokeSessions(String id) {
            for (Session session : sessions.values()) {
                if (
                    session.identityId.equals(id) &&
                    !session.revoked
                ) {
                    session.revoked = true;

                    audit.record(
                        id,
                        EventType.SESSION_REVOKED,
                        "session",
                        "administrative_action"
                    );
                }
            }
        }

        synchronized void suspend(String id) {
            Identity identity = getIdentity(id);

            if (identity.status != IdentityStatus.ACTIVE) {
                throw new LifecycleException(
                    "Only active identities can be suspended"
                );
            }

            identity.status = IdentityStatus.SUSPENDED;
            identity.version++;

            revokeSessions(id);

            audit.record(
                id,
                EventType.IDENTITY_SUSPENDED,
                "identity",
                "administrative_action"
            );
        }

        synchronized void disable(String id) {
            Identity identity = getIdentity(id);

            if (
                identity.status == IdentityStatus.DISABLED ||
                identity.status == IdentityStatus.TERMINATED
            ) {
                throw new LifecycleException(
                    "Identity already disabled"
                );
            }

            identity.status = IdentityStatus.DISABLED;
            identity.version++;

            revokeSessions(id);

            audit.record(
                id,
                EventType.IDENTITY_DISABLED,
                "identity",
                "administrative_action"
            );
        }

        synchronized void terminate(String id) {
            Identity identity = getIdentity(id);

            if (
                identity.status == IdentityStatus.PENDING ||
                identity.status == IdentityStatus.TERMINATED
            ) {
                throw new LifecycleException(
                    "Invalid termination transition"
                );
            }

            identity.status = IdentityStatus.TERMINATED;
            identity.roles.clear();
            identity.version++;

            revokeSessions(id);

            audit.record(
                id,
                EventType.IDENTITY_TERMINATED,
                "identity",
                "offboarding"
            );
        }

        synchronized void reactivate(String id) {
            Identity identity = getIdentity(id);

            if (identity.status != IdentityStatus.SUSPENDED) {
                throw new LifecycleException(
                    "Only suspended identities can reactivate"
                );
            }

            identity.status = IdentityStatus.ACTIVE;
            identity.version++;

            audit.record(
                id,
                EventType.IDENTITY_ACTIVATED,
                "identity",
                "reactivated"
            );
        }

        IdentitySnapshot getSnapshot(String id) {
            return getIdentity(id).snapshot();
        }

        void addExplicitDenial(String id) {
            getIdentity(id);
            reviewPolicy.deny(id);
        }

        void removeExplicitDenial(String id) {
            reviewPolicy.restore(id);
        }

        List<AuditEvent> getAuditEvents() {
            return audit.getEvents();
        }

        Map<EventType, Long> accountingReport() {
            return audit.report();
        }
    }

    public static void main(String[] args) {

        DemoCredentialProvider credentials =
            new DemoCredentialProvider();

        credentials.register(
            "credential-1001",
            "Enterprise-Secret-2026"
        );

        IAMService iam = new IAMService(
            credentials,
            5,
            Duration.ofMinutes(30),
            Duration.ofMinutes(15)
        );

        try {
            String alice = iam.createIdentity(
                "alice",
                "alice@example.org",
                "credential-1001"
            );

            iam.activate(alice);
            iam.assignRole(alice, Role.EMPLOYEE);
            iam.enableMfa(alice);

            AuthenticationResult authentication =
                iam.authenticate(
                    "alice",
                    "Enterprise-Secret-2026",
                    true
                );

            String token = authentication.sessionToken();

            AccessDecision read = iam.authorize(
                token,
                Permission.DOCUMENT_READ,
                "documents/report.pdf"
            );

            AccessDecision deletion = iam.authorize(
                token,
                Permission.DOCUMENT_DELETE,
                "documents/report.pdf"
            );

            System.out.println("Read: " + read);
            System.out.println("Delete: " + deletion);

            if (read.decision() != Decision.ALLOW) {
                throw new IllegalStateException(
                    "Expected read permission"
                );
            }

            if (deletion.decision() != Decision.DENY) {
                throw new IllegalStateException(
                    "Unexpected delete permission"
                );
            }

            iam.removeRole(alice, Role.EMPLOYEE);

            AccessDecision afterRemoval = iam.authorize(
                token,
                Permission.DOCUMENT_READ,
                "documents/report.pdf"
            );

            System.out.println(
                "After role removal: " + afterRemoval
            );

            iam.addExplicitDenial(alice);
            iam.removeExplicitDenial(alice);

            iam.suspend(alice);
            iam.reactivate(alice);

            System.out.println(
                "Identity: " + iam.getSnapshot(alice)
            );

            System.out.println("\nAccounting report:");

            iam.accountingReport().forEach(
                (event, count) ->
                    System.out.println(event + ": " + count)
            );

            System.out.println(
                "Audit events: " + iam.getAuditEvents().size()
            );

        } catch (IAMException exception) {
            System.err.println(
                "IAM operation failed: " + exception.getMessage()
            );

            System.exitCode = 1;
        }
    }
}
