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
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * Enterprise Zero Trust Access Governance.
 *
 * Java 17
 * No external dependencies.
 *
 * Implements:
 * - Identity verification
 * - Device posture assessment
 * - Context-aware authorization
 * - Least-privilege access
 * - Resource segmentation
 * - Policy-driven approvals
 * - Session lifecycle management
 * - Continuous authorization
 * - Security audit events
 */
public class ZeroTrustEnterprise {

    // =====================================================
    // Enumerations
    // =====================================================

    enum Decision {
        ALLOW,
        DENY,
        REVOKE
    }

    enum TrustLevel {
        UNTRUSTED(0),
        VERIFIED(1),
        HIGH(2);

        private final int rank;

        TrustLevel(int rank) {
            this.rank = rank;
        }

        public int rank() {
            return rank;
        }
    }

    enum ResourceZone {
        PUBLIC,
        INTERNAL,
        RESTRICTED,
        CRITICAL
    }

    enum AccessAction {
        READ,
        WRITE,
        DELETE,
        ADMIN
    }

    enum SessionState {
        ACTIVE,
        REVOKED,
        EXPIRED
    }

    // =====================================================
    // Exceptions
    // =====================================================

    static class SecurityException extends RuntimeException {
        SecurityException(String message) {
            super(message);
        }
    }

    static class ValidationException extends SecurityException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class AuthenticationException extends SecurityException {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static class AuthorizationException extends SecurityException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class SessionException extends SecurityException {
        SessionException(String message) {
            super(message);
        }
    }

    // =====================================================
    // Validation utility
    // =====================================================

    static final class Validation {

        private Validation() {}

        static String required(String value, String field) {
            if (value == null || value.isBlank()) {
                throw new ValidationException(
                    field + " is required."
                );
            }

            return value.trim();
        }

        static int risk(int value) {
            if (value < 0 || value > 100) {
                throw new ValidationException(
                    "Risk must be between 0 and 100."
                );
            }

            return value;
        }

        static Duration positiveDuration(Duration duration) {
            Objects.requireNonNull(duration);

            if (duration.isZero() || duration.isNegative()) {
                throw new ValidationException(
                    "Duration must be positive."
                );
            }

            return duration;
        }
    }

    // =====================================================
    // Domain records
    // =====================================================

    record Identity(
        String id,
        String username,
        Set<String> roles,
        boolean enabled,
        boolean mfaVerified
    ) {
        Identity {
            id = Validation.required(id, "Identity ID");
            username = Validation.required(username, "Username");

            if (roles == null || roles.isEmpty()) {
                throw new ValidationException(
                    "At least one identity role is required."
                );
            }

            roles = Collections.unmodifiableSet(
                new HashSet<>(roles)
            );
        }
    }

    record Device(
        String id,
        String ownerId,
        boolean managed,
        boolean encrypted,
        boolean patched,
        boolean endpointProtected,
        int riskScore,
        long version
    ) {
        Device {
            id = Validation.required(id, "Device ID");
            ownerId = Validation.required(ownerId, "Device owner");
            Validation.risk(riskScore);

            if (version < 1) {
                throw new ValidationException(
                    "Invalid device version."
                );
            }
        }

        boolean compliant() {
            return managed
                && encrypted
                && patched
                && endpointProtected
                && riskScore <= 30;
        }

        Device withRisk(int newRisk) {
            return new Device(
                id,
                ownerId,
                managed,
                encrypted,
                patched,
                endpointProtected,
                Validation.risk(newRisk),
                version + 1
            );
        }
    }

    record Resource(
        String id,
        String name,
        ResourceZone zone,
        Set<String> allowedRoles,
        Set<AccessAction> allowedActions,
        TrustLevel minimumTrust,
        boolean requireMFA
    ) {
        Resource {
            id = Validation.required(id, "Resource ID");
            name = Validation.required(name, "Resource name");

            Objects.requireNonNull(zone);
            Objects.requireNonNull(minimumTrust);

            if (allowedRoles == null || allowedRoles.isEmpty()) {
                throw new ValidationException(
                    "Resource requires allowed roles."
                );
            }

            if (allowedActions == null || allowedActions.isEmpty()) {
                throw new ValidationException(
                    "Resource requires allowed actions."
                );
            }

            allowedRoles = Collections.unmodifiableSet(
                new HashSet<>(allowedRoles)
            );

            allowedActions = Collections.unmodifiableSet(
                EnumSet.copyOf(allowedActions)
            );
        }
    }

    record AccessContext(
        String sourceIP,
        String networkZone,
        AccessAction action,
        int riskScore,
        Instant timestamp
    ) {
        AccessContext {
            sourceIP = Validation.required(sourceIP, "Source IP");
            networkZone = Validation.required(
                networkZone,
                "Network zone"
            );

            Objects.requireNonNull(action);
            Objects.requireNonNull(timestamp);

            Validation.risk(riskScore);

            try {
                if (java.net.InetAddress.getByName(sourceIP) == null) {
                    throw new ValidationException("Invalid IP address.");
                }
            } catch (java.net.UnknownHostException exception) {
                throw new ValidationException("Invalid IP address.");
            }
        }
    }

    record Evaluation(
        boolean allowed,
        String reason,
        TrustLevel trust
    ) {}

    record AuditEvent(
        long sequence,
        Instant timestamp,
        String userId,
        String resourceId,
        Decision decision,
        String reason,
        String sessionId
    ) {}

    // =====================================================
    // Identity service
    // =====================================================

    static final class IdentityService {

        private final Map<String, Identity> identities =
            new ConcurrentHashMap<>();

        void register(Identity identity) {
            Identity previous = identities.putIfAbsent(
                identity.id(),
                identity
            );

            if (previous != null) {
                throw new ValidationException(
                    "Duplicate identity."
                );
            }
        }

        Identity authenticate(String id) {
            Identity identity = identities.get(id);

            if (identity == null || !identity.enabled()) {
                throw new AuthenticationException(
                    "Identity authentication failed."
                );
            }

            return identity;
        }

        void disable(String id) {
            Identity identity = authenticate(id);

            identities.put(
                id,
                new Identity(
                    identity.id(),
                    identity.username(),
                    identity.roles(),
                    false,
                    identity.mfaVerified()
                )
            );
        }
    }

    // =====================================================
    // Device posture service
    // =====================================================

    static final class DeviceService {

        private final Map<String, Device> devices =
            new ConcurrentHashMap<>();

        void register(Device device) {
            if (devices.putIfAbsent(device.id(), device) != null) {
                throw new ValidationException(
                    "Duplicate device."
                );
            }
        }

        Device get(String id) {
            Device device = devices.get(id);

            if (device == null) {
                throw new AuthenticationException(
                    "Unknown device."
                );
            }

            return device;
        }

        Device updateRisk(String id, int risk) {
            return devices.compute(id, (key, current) -> {
                if (current == null) {
                    throw new ValidationException(
                        "Unknown device."
                    );
                }

                return current.withRisk(risk);
            });
        }

        TrustLevel evaluate(
            Device device,
            Identity identity
        ) {
            if (!device.ownerId().equals(identity.id())
                || !device.compliant()) {
                return TrustLevel.UNTRUSTED;
            }

            if (identity.mfaVerified() && device.riskScore() <= 10) {
                return TrustLevel.HIGH;
            }

            return TrustLevel.VERIFIED;
        }
    }

    // =====================================================
    // Resource registry
    // =====================================================

    static final class ResourceService {

        private final Map<String, Resource> resources =
            new ConcurrentHashMap<>();

        void register(Resource resource) {
            if (resources.putIfAbsent(resource.id(), resource) != null) {
                throw new ValidationException(
                    "Duplicate resource."
                );
            }
        }

        Resource get(String id) {
            Resource resource = resources.get(id);

            if (resource == null) {
                throw new AuthorizationException(
                    "Resource not found."
                );
            }

            return resource;
        }
    }

    // =====================================================
    // Policy objects
    // =====================================================

    interface AccessPolicy {
        Evaluation evaluate(
            Identity identity,
            Device device,
            Resource resource,
            AccessContext context
        );
    }

    static final class EnterpriseAccessPolicy
        implements AccessPolicy {

        private final DeviceService deviceService;

        EnterpriseAccessPolicy(DeviceService deviceService) {
            this.deviceService = deviceService;
        }

        @Override
        public Evaluation evaluate(
            Identity identity,
            Device device,
            Resource resource,
            AccessContext context
        ) {
            if (!identity.enabled()) {
                return deny("Identity disabled.");
            }

            if (!device.compliant()) {
                return deny("Device is noncompliant.");
            }

            if (resource.requireMFA() && !identity.mfaVerified()) {
                return deny("MFA verification required.");
            }

            boolean authorizedRole = identity.roles()
                .stream()
                .anyMatch(resource.allowedRoles()::contains);

            if (!authorizedRole) {
                return deny("Role authorization failed.");
            }

            if (!resource.allowedActions().contains(context.action())) {
                return deny("Requested action is not permitted.");
            }

            if (context.riskScore() >= 80) {
                return deny("Contextual risk threshold exceeded.");
            }

            TrustLevel trust = deviceService.evaluate(
                device,
                identity
            );

            if (trust.rank() < resource.minimumTrust().rank()) {
                return new Evaluation(
                    false,
                    "Insufficient device trust.",
                    trust
                );
            }

            if (resource.zone() == ResourceZone.RESTRICTED) {
                if (!Set.of("CORPORATE", "VPN").contains(
                    context.networkZone()
                )) {
                    return new Evaluation(
                        false,
                        "Restricted network boundary violated.",
                        trust
                    );
                }
            }

            if (resource.zone() == ResourceZone.CRITICAL) {
                if (!context.networkZone().equals("CORPORATE")
                    || context.riskScore() > 10
                    || trust != TrustLevel.HIGH) {

                    return new Evaluation(
                        false,
                        "Critical resource policy failed.",
                        trust
                    );
                }
            }

            return new Evaluation(
                true,
                "All enterprise policies satisfied.",
                trust
            );
        }

        private Evaluation deny(String reason) {
            return new Evaluation(
                false,
                reason,
                TrustLevel.UNTRUSTED
            );
        }
    }

    // =====================================================
    // Session aggregate
    // =====================================================

    static final class SecuritySession {

        private final String id;
        private final String userId;
        private final String deviceId;
        private final String resourceId;

        private final long deviceVersion;

        private final Instant createdAt;
        private final Instant expiresAt;

        private SessionState state;
        private Instant lastEvaluated;

        SecuritySession(
            String userId,
            Device device,
            Resource resource,
            Duration lifetime,
            Instant now
        ) {
            this.id = UUID.randomUUID().toString();
            this.userId = userId;
            this.deviceId = device.id();
            this.resourceId = resource.id();
            this.deviceVersion = device.version();
            this.createdAt = now;
            this.expiresAt = now.plus(lifetime);
            this.lastEvaluated = now;
            this.state = SessionState.ACTIVE;
        }

        String id() {
            return id;
        }

        String userId() {
            return userId;
        }

        String deviceId() {
            return deviceId;
        }

        String resourceId() {
            return resourceId;
        }

        long deviceVersion() {
            return deviceVersion;
        }

        Instant expiresAt() {
            return expiresAt;
        }

        SessionState state() {
            return state;
        }

        void revoke() {
            state = SessionState.REVOKED;
        }

        void expire() {
            state = SessionState.EXPIRED;
        }

        void updateEvaluationTime(Instant now) {
            lastEvaluated = now;
        }
    }

    // =====================================================
    // Session management
    // =====================================================

    static final class SessionService {

        private final Map<String, SecuritySession> sessions =
            new ConcurrentHashMap<>();

        private final Duration lifetime;

        SessionService(Duration lifetime) {
            this.lifetime = Validation.positiveDuration(lifetime);
        }

        SecuritySession create(
            Identity identity,
            Device device,
            Resource resource,
            Instant now
        ) {
            SecuritySession session = new SecuritySession(
                identity.id(),
                device,
                resource,
                lifetime,
                now
            );

            sessions.put(session.id(), session);
            return session;
        }

        SecuritySession getActive(String id, Instant now) {
            SecuritySession session = sessions.get(id);

            if (session == null) {
                throw new SessionException("Unknown session.");
            }

            if (session.state() != SessionState.ACTIVE) {
                throw new SessionException("Session is inactive.");
            }

            if (!now.isBefore(session.expiresAt())) {
                session.expire();
                throw new SessionException("Session expired.");
            }

            return session;
        }

        void revoke(String id) {
            SecuritySession session = sessions.get(id);

            if (session == null) {
                throw new SessionException("Unknown session.");
            }

            session.revoke();
        }

        long activeCount() {
            return sessions.values()
                .stream()
                .filter(s -> s.state() == SessionState.ACTIVE)
                .count();
        }
    }

    // =====================================================
    // Audit service
    // =====================================================

    static final class AuditService {

        private final AtomicLong sequence = new AtomicLong();

        private final List<AuditEvent> events =
            Collections.synchronizedList(new ArrayList<>());

        void record(
            String userId,
            String resourceId,
            Decision decision,
            String reason,
            String sessionId
        ) {
            events.add(new AuditEvent(
                sequence.incrementAndGet(),
                Instant.now(),
                userId,
                resourceId,
                decision,
                reason,
                sessionId
            ));
        }

        List<AuditEvent> snapshot() {
            synchronized (events) {
                return List.copyOf(events);
            }
        }

        void report() {
            snapshot().forEach(event ->
                System.out.printf(
                    "%d | %s | %s | %s | %s%n",
                    event.sequence(),
                    event.userId(),
                    event.resourceId(),
                    event.decision(),
                    event.reason()
                )
            );
        }

        Map<Decision, Long> aggregate() {
            return snapshot()
                .stream()
                .collect(Collectors.groupingBy(
                    AuditEvent::decision,
                    Collectors.counting()
                ));
        }
    }

    // =====================================================
    // Enterprise authorization service
    // =====================================================

    static final class ZeroTrustService {

        private final IdentityService identities =
            new IdentityService();

        private final DeviceService devices =
            new DeviceService();

        private final ResourceService resources =
            new ResourceService();

        private final AccessPolicy policy =
            new EnterpriseAccessPolicy(devices);

        private final SessionService sessions =
            new SessionService(Duration.ofMinutes(15));

        private final AuditService audit =
            new AuditService();

        IdentityService identities() {
            return identities;
        }

        DeviceService devices() {
            return devices;
        }

        ResourceService resources() {
            return resources;
        }

        Optional<SecuritySession> requestAccess(
            String userId,
            String deviceId,
            String resourceId,
            AccessContext context
        ) {
            try {
                Identity identity = identities.authenticate(userId);
                Device device = devices.get(deviceId);
                Resource resource = resources.get(resourceId);

                Evaluation evaluation = policy.evaluate(
                    identity,
                    device,
                    resource,
                    context
                );

                if (!evaluation.allowed()) {
                    audit.record(
                        userId,
                        resourceId,
                        Decision.DENY,
                        evaluation.reason(),
                        null
                    );

                    return Optional.empty();
                }

                SecuritySession session = sessions.create(
                    identity,
                    device,
                    resource,
                    context.timestamp()
                );

                audit.record(
                    userId,
                    resourceId,
                    Decision.ALLOW,
                    evaluation.reason(),
                    session.id()
                );

                return Optional.of(session);

            } catch (SecurityException exception) {
                audit.record(
                    userId,
                    resourceId,
                    Decision.DENY,
                    exception.getMessage(),
                    null
                );

                return Optional.empty();
            }
        }

        Decision continuouslyEvaluate(
            String sessionId,
            AccessContext context
        ) {
            SecuritySession session = null;

            try {
                session = sessions.getActive(
                    sessionId,
                    context.timestamp()
                );

                Identity identity = identities.authenticate(
                    session.userId()
                );

                Device device = devices.get(session.deviceId());
                Resource resource = resources.get(session.resourceId());

                Evaluation evaluation = policy.evaluate(
                    identity,
                    device,
                    resource,
                    context
                );

                if (!evaluation.allowed()
                    || device.version() != session.deviceVersion()) {

                    sessions.revoke(sessionId);

                    String reason = evaluation.allowed()
                        ? "Device posture changed."
                        : evaluation.reason();

                    audit.record(
                        identity.id(),
                        resource.id(),
                        Decision.REVOKE,
                        reason,
                        sessionId
                    );

                    return Decision.REVOKE;
                }

                session.updateEvaluationTime(context.timestamp());

                audit.record(
                    identity.id(),
                    resource.id(),
                    Decision.ALLOW,
                    "Continuous verification passed.",
                    sessionId
                );

                return Decision.ALLOW;

            } catch (SecurityException exception) {
                if (session != null) {
                    try {
                        sessions.revoke(sessionId);
                    } catch (SecurityException ignored) {
                        // Preserve the original security failure.
                    }
                }

                audit.record(
                    session == null ? "SYSTEM" : session.userId(),
                    session == null ? "UNKNOWN" : session.resourceId(),
                    Decision.REVOKE,
                    exception.getMessage(),
                    sessionId
                );

                return Decision.REVOKE;
            }
        }

        void report() {
            System.out.println("\nAUDIT EVENTS");
            audit.report();

            System.out.println("\nDECISION AGGREGATION");
            System.out.println(audit.aggregate());

            System.out.println(
                "Active sessions: " + sessions.activeCount()
            );
        }
    }

    // =====================================================
    // Main enterprise scenario
    // =====================================================

    public static void main(String[] args) {

        ZeroTrustService service = new ZeroTrustService();

        service.identities().register(new Identity(
            "USR-100",
            "security-analyst",
            Set.of("SECURITY_ANALYST"),
            true,
            true
        ));

        service.devices().register(new Device(
            "DEV-100",
            "USR-100",
            true,
            true,
            true,
            true,
            5,
            1
        ));

        service.resources().register(new Resource(
            "RES-100",
            "Security Operations Dashboard",
            ResourceZone.RESTRICTED,
            Set.of("SECURITY_ANALYST"),
            EnumSet.of(AccessAction.READ),
            TrustLevel.VERIFIED,
            true
        ));

        service.resources().register(new Resource(
            "RES-200",
            "Production Administration",
            ResourceZone.CRITICAL,
            Set.of("SECURITY_ADMIN"),
            EnumSet.of(AccessAction.ADMIN),
            TrustLevel.HIGH,
            true
        ));

        Instant now = Instant.now();

        AccessContext validContext = new AccessContext(
            "10.0.0.25",
            "VPN",
            AccessAction.READ,
            5,
            now
        );

        System.out.println("ENTERPRISE ZERO TRUST GOVERNANCE");

        Optional<SecuritySession> result = service.requestAccess(
            "USR-100",
            "DEV-100",
            "RES-100",
            validContext
        );

        if (result.isEmpty()) {
            throw new IllegalStateException(
                "Expected authorization success."
            );
        }

        SecuritySession session = result.get();

        System.out.println("Initial access: ALLOW");
        System.out.println("Session ID: " + session.id());

        // Simulate endpoint compromise after initial authorization.
        service.devices().updateRisk("DEV-100", 95);

        Decision reevaluation = service.continuouslyEvaluate(
            session.id(),
            new AccessContext(
                "10.0.0.25",
                "VPN",
                AccessAction.READ,
                5,
                now.plusSeconds(120)
            )
        );

        System.out.println(
            "Continuous evaluation: " + reevaluation
        );

        if (reevaluation != Decision.REVOKE) {
            throw new IllegalStateException(
                "Expected session revocation."
            );
        }

        Optional<SecuritySession> denied = service.requestAccess(
            "USR-100",
            "DEV-100",
            "RES-100",
            validContext
        );

        System.out.println(
            "Noncompliant device request: "
                + (denied.isPresent() ? "ALLOW" : "DENY")
        );

        if (denied.isPresent()) {
            throw new IllegalStateException(
                "Expected access denial."
            );
        }

        service.report();

        System.out.println("\nAll enterprise security assertions passed.");
    }
}
