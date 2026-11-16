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
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Enterprise Privileged Access Management System.
 *
 * Java 17
 *
 * Domain capabilities:
 * - Privileged identity management
 * - Administrative group management
 * - Credential isolation
 * - Just-in-time access
 * - Separation of duties
 * - Approval policy evaluation
 * - Access request state transitions
 * - Session lifecycle management
 * - Automated security checks
 * - Credential rotation
 * - Security audit reporting
 *
 * In-memory implementation for domain and workflow simulation.
 */

public class PAMEnterprise {

    // ========================================================
    // ENUMERATIONS
    // ========================================================

    enum Privilege {
        STANDARD,
        ELEVATED,
        ADMIN,
        SUPER_ADMIN
    }

    enum AccountStatus {
        ACTIVE,
        DISABLED,
        LOCKED
    }

    enum RequestStatus {
        PENDING,
        APPROVED,
        DENIED,
        ACTIVE,
        EXPIRED,
        REVOKED
    }

    enum ReviewDecision {
        APPROVE,
        DENY
    }

    enum CheckStatus {
        PENDING,
        PASSED,
        FAILED
    }

    enum Severity {
        INFO,
        WARNING,
        CRITICAL
    }


    // ========================================================
    // EXCEPTIONS
    // ========================================================

    static class PAMException extends RuntimeException {
        PAMException(String message) {
            super(message);
        }
    }

    static class AuthorizationException extends PAMException {
        AuthorizationException(String message) {
            super(message);
        }
    }

    static class ValidationException extends PAMException {
        ValidationException(String message) {
            super(message);
        }
    }

    static class WorkflowException extends PAMException {
        WorkflowException(String message) {
            super(message);
        }
    }


    // ========================================================
    // DOMAIN RECORDS
    // ========================================================

    record User(
        String id,
        String username,
        String department,
        boolean active,
        boolean mfaEnabled,
        Set<String> roles
    ) {
        User {
            Objects.requireNonNull(id);
            Objects.requireNonNull(username);
            Objects.requireNonNull(department);

            if (id.isBlank() || username.isBlank()) {
                throw new ValidationException(
                    "Invalid user identity."
                );
            }

            roles = Set.copyOf(roles);
        }

        boolean hasRole(String role) {
            return roles.contains(role);
        }
    }


    record AuditEvent(
        String id,
        Instant timestamp,
        String actor,
        String action,
        String resource,
        Severity severity
    ) {}


    record StatusCheck(
        String name,
        CheckStatus status
    ) {}


    record AccessDecision(
        boolean eligible,
        List<String> violations
    ) {
        AccessDecision {
            violations = List.copyOf(violations);
        }
    }


    // ========================================================
    // PRIVILEGED GROUP
    // ========================================================

    static final class PrivilegedGroup {

        private final String id;
        private final String name;
        private final Privilege privilege;
        private final Set<String> members =
            ConcurrentHashMap.newKeySet();

        private final int maximumSessionMinutes;
        private final boolean approvalRequired;

        PrivilegedGroup(
            String id,
            String name,
            Privilege privilege,
            int maximumSessionMinutes,
            boolean approvalRequired
        ) {
            if (
                id == null ||
                id.isBlank() ||
                name == null ||
                name.isBlank()
            ) {
                throw new ValidationException(
                    "Invalid group."
                );
            }

            if (maximumSessionMinutes < 1) {
                throw new ValidationException(
                    "Invalid session duration."
                );
            }

            this.id = id;
            this.name = name;
            this.privilege = privilege;
            this.maximumSessionMinutes =
                maximumSessionMinutes;
            this.approvalRequired = approvalRequired;
        }

        void addMember(User user) {
            if (!user.active()) {
                throw new AuthorizationException(
                    "Inactive user cannot join group."
                );
            }

            members.add(user.id());
        }

        boolean contains(String userId) {
            return members.contains(userId);
        }

        int maximumSessionMinutes() {
            return maximumSessionMinutes;
        }

        boolean approvalRequired() {
            return approvalRequired;
        }

        String id() {
            return id;
        }
    }


    // ========================================================
    // PRIVILEGED ACCOUNT
    // ========================================================

    static final class PrivilegedAccount {

        private final String id;
        private final String username;
        private final String system;
        private final Privilege privilege;

        private final Set<String> groupIds;

        private volatile AccountStatus status =
            AccountStatus.ACTIVE;

        private volatile Instant lastRotated =
            Instant.now();

        private final int rotationIntervalDays;

        PrivilegedAccount(
            String id,
            String username,
            String system,
            Privilege privilege,
            Set<String> groupIds,
            int rotationIntervalDays
        ) {
            if (
                id == null ||
                id.isBlank() ||
                username == null ||
                username.isBlank() ||
                system == null ||
                system.isBlank()
            ) {
                throw new ValidationException(
                    "Invalid privileged account."
                );
            }

            if (rotationIntervalDays < 1) {
                throw new ValidationException(
                    "Invalid rotation interval."
                );
            }

            this.id = id;
            this.username = username;
            this.system = system;
            this.privilege = privilege;
            this.groupIds = Set.copyOf(groupIds);
            this.rotationIntervalDays = rotationIntervalDays;
        }

        String id() {
            return id;
        }

        AccountStatus status() {
            return status;
        }

        void disable() {
            status = AccountStatus.DISABLED;
        }

        void rotate() {
            if (status != AccountStatus.ACTIVE) {
                throw new WorkflowException(
                    "Cannot rotate inactive account."
                );
            }

            lastRotated = Instant.now();
        }

        boolean rotationDue() {
            return lastRotated.plus(
                Duration.ofDays(rotationIntervalDays)
            ).isBefore(Instant.now());
        }

        Set<String> groupIds() {
            return groupIds;
        }
    }


    // ========================================================
    // APPROVAL POLICY
    // ========================================================

    static final class ApprovalPolicy {

        private final int requiredApprovals;
        private final boolean prohibitSelfApproval;
        private final boolean requireMFA;
        private final boolean requireApproval;
        private final boolean requireStatusChecks;
        private final boolean prohibitConcurrentSessions;
        private final boolean requireSessionRecording;
        private final int maximumSessionMinutes;

        ApprovalPolicy(
            int requiredApprovals,
            boolean prohibitSelfApproval,
            boolean requireMFA,
            boolean requireApproval,
            boolean requireStatusChecks,
            boolean prohibitConcurrentSessions,
            boolean requireSessionRecording,
            int maximumSessionMinutes
        ) {
            if (
                requiredApprovals < 1 ||
                maximumSessionMinutes < 1
            ) {
                throw new ValidationException(
                    "Invalid approval policy."
                );
            }

            this.requiredApprovals = requiredApprovals;
            this.prohibitSelfApproval = prohibitSelfApproval;
            this.requireMFA = requireMFA;
            this.requireApproval = requireApproval;
            this.requireStatusChecks = requireStatusChecks;
            this.prohibitConcurrentSessions =
                prohibitConcurrentSessions;
            this.requireSessionRecording =
                requireSessionRecording;
            this.maximumSessionMinutes =
                maximumSessionMinutes;
        }
    }


    // ========================================================
    // APPROVAL RECORD
    // ========================================================

    record Approval(
        String approverId,
        ReviewDecision decision,
        Instant reviewedAt
    ) {}


    // ========================================================
    // ACCESS REQUEST AGGREGATE
    // ========================================================

    static final class AccessRequest {

        private final String id;
        private final String requesterId;
        private final String accountId;
        private final String justification;
        private final int durationMinutes;
        private final Instant createdAt;

        private volatile RequestStatus status =
            RequestStatus.PENDING;

        private final List<Approval> approvals =
            new ArrayList<>();

        private final Map<String, CheckStatus> checks =
            new HashMap<>();

        AccessRequest(
            String requesterId,
            String accountId,
            String justification,
            int durationMinutes
        ) {
            this.id = UUID.randomUUID().toString();
            this.requesterId = requesterId;
            this.accountId = accountId;
            this.justification = justification;
            this.durationMinutes = durationMinutes;
            this.createdAt = Instant.now();

            checks.put("identity", CheckStatus.PASSED);
            checks.put("mfa", CheckStatus.PASSED);
            checks.put("group_membership", CheckStatus.PASSED);
            checks.put("account_status", CheckStatus.PASSED);
            checks.put("credential_availability", CheckStatus.PASSED);
        }

        synchronized void addApproval(Approval approval) {
            approvals.add(approval);
        }

        synchronized void updateCheck(
            String name,
            CheckStatus status
        ) {
            if (!checks.containsKey(name)) {
                throw new ValidationException(
                    "Unknown security check."
                );
            }

            checks.put(name, status);
        }

        synchronized boolean allChecksPassed() {
            return checks.values().stream()
                .allMatch(s -> s == CheckStatus.PASSED);
        }

        synchronized long countValidApprovals(
            Predicate<Approval> eligibility
        ) {
            return approvals.stream()
                .filter(eligibility)
                .filter(a ->
                    a.decision() == ReviewDecision.APPROVE
                )
                .count();
        }

        synchronized void approve() {
            status = RequestStatus.APPROVED;
        }

        synchronized void deny() {
            status = RequestStatus.DENIED;
        }

        synchronized void activate() {
            if (status != RequestStatus.APPROVED) {
                throw new WorkflowException(
                    "Only approved requests can activate."
                );
            }

            status = RequestStatus.ACTIVE;
        }

        synchronized void revoke() {
            status = RequestStatus.REVOKED;
        }

        synchronized void expire() {
            status = RequestStatus.EXPIRED;
        }

        String id() {
            return id;
        }

        String requesterId() {
            return requesterId;
        }

        String accountId() {
            return accountId;
        }

        int durationMinutes() {
            return durationMinutes;
        }

        RequestStatus status() {
            return status;
        }
    }


    // ========================================================
    // CREDENTIAL VAULT INTERFACE
    // ========================================================

    interface Vault {

        String provision(String accountId, String secret);

        String retrieveReference(String accountId);

        void rotate(String accountId, String newSecret);

        boolean exists(String accountId);
    }


    /**
     * Demonstration vault.
     *
     * A production implementation must integrate with an
     * encrypted external secrets manager.
     */
    static final class IsolatedVault implements Vault {

        private final Map<String, String> references =
            new ConcurrentHashMap<>();

        private final Map<String, String> fingerprints =
            new ConcurrentHashMap<>();

        @Override
        public String provision(
            String accountId,
            String secret
        ) {
            if (
                secret == null ||
                secret.getBytes(
                    java.nio.charset.StandardCharsets.UTF_8
                ).length < 16
            ) {
                throw new ValidationException(
                    "Credential must contain at least 16 bytes."
                );
            }

            String reference =
                "vault-" + UUID.randomUUID();

            references.put(accountId, reference);

            try {
                byte[] hash = java.security.MessageDigest
                    .getInstance("SHA-256")
                    .digest(
                        secret.getBytes(
                            java.nio.charset.StandardCharsets.UTF_8
                        )
                    );

                fingerprints.put(
                    accountId,
                    java.util.HexFormat.of().formatHex(hash)
                );

            } catch (
                java.security.NoSuchAlgorithmException exception
            ) {
                throw new PAMException(
                    "Fingerprint service unavailable."
                );
            }

            return reference;
        }

        @Override
        public String retrieveReference(String accountId) {
            String reference = references.get(accountId);

            if (reference == null) {
                throw new PAMException(
                    "Credential reference unavailable."
                );
            }

            return reference;
        }

        @Override
        public void rotate(
            String accountId,
            String newSecret
        ) {
            provision(accountId, newSecret);
        }

        @Override
        public boolean exists(String accountId) {
            return references.containsKey(accountId);
        }
    }


    // ========================================================
    // SESSION ENTITY
    // ========================================================

    static final class PrivilegedSession {

        private final String id;
        private final String requestId;
        private final String userId;
        private final String accountId;

        private final Instant startedAt;
        private final Instant expiresAt;

        private volatile boolean active = true;
        private final boolean recordingEnabled;

        PrivilegedSession(
            String requestId,
            String userId,
            String accountId,
            int durationMinutes,
            boolean recordingEnabled
        ) {
            this.id = UUID.randomUUID().toString();
            this.requestId = requestId;
            this.userId = userId;
            this.accountId = accountId;
            this.startedAt = Instant.now();
            this.expiresAt = startedAt.plus(
                Duration.ofMinutes(durationMinutes)
            );
            this.recordingEnabled = recordingEnabled;
        }

        boolean expired() {
            return !Instant.now().isBefore(expiresAt);
        }

        boolean active() {
            return active && !expired();
        }

        void terminate() {
            active = false;
        }

        String id() {
            return id;
        }

        String userId() {
            return userId;
        }

        String accountId() {
            return accountId;
        }

        String requestId() {
            return requestId;
        }
    }


    // ========================================================
    // AUDIT SERVICE
    // ========================================================

    static final class AuditService {

        private final List<AuditEvent> events =
            Collections.synchronizedList(
                new ArrayList<>()
            );

        void record(
            String actor,
            String action,
            String resource,
            Severity severity
        ) {
            events.add(new AuditEvent(
                UUID.randomUUID().toString(),
                Instant.now(),
                actor,
                action,
                resource,
                severity
            ));
        }

        List<AuditEvent> events() {
            synchronized (events) {
                return List.copyOf(events);
            }
        }

        long countBySeverity(Severity severity) {
            synchronized (events) {
                return events.stream()
                    .filter(e -> e.severity() == severity)
                    .count();
            }
        }
    }


    // ========================================================
    // ACCESS CONTROL SERVICE
    // ========================================================

    static final class AccessControlService {

        private final Map<String, User> users =
            new ConcurrentHashMap<>();

        private final Map<String, PrivilegedGroup> groups =
            new ConcurrentHashMap<>();

        private final Map<String, PrivilegedAccount> accounts =
            new ConcurrentHashMap<>();

        private final Map<String, AccessRequest> requests =
            new ConcurrentHashMap<>();

        private final Map<String, PrivilegedSession> sessions =
            new ConcurrentHashMap<>();

        private final Vault vault;
        private final ApprovalPolicy policy;
        private final AuditService audit;

        private final ReentrantLock transactionLock =
            new ReentrantLock();

        AccessControlService(
            Vault vault,
            ApprovalPolicy policy,
            AuditService audit
        ) {
            this.vault = vault;
            this.policy = policy;
            this.audit = audit;
        }

        // ----------------------------------------------------
        // REGISTRATION
        // ----------------------------------------------------

        void registerUser(User user) {
            if (users.putIfAbsent(user.id(), user) != null) {
                throw new ValidationException(
                    "Duplicate user."
                );
            }

            audit.record(
                user.id(),
                "USER_REGISTERED",
                user.id(),
                Severity.INFO
            );
        }

        void registerGroup(PrivilegedGroup group) {
            if (
                groups.putIfAbsent(group.id(), group) != null
            ) {
                throw new ValidationException(
                    "Duplicate group."
                );
            }
        }

        void addMember(String groupId, String userId) {
            PrivilegedGroup group = groups.get(groupId);
            User user = users.get(userId);

            if (group == null || user == null) {
                throw new ValidationException(
                    "Unknown group or user."
                );
            }

            group.addMember(user);

            audit.record(
                userId,
                "GROUP_MEMBERSHIP_GRANTED",
                groupId,
                Severity.INFO
            );
        }

        void registerAccount(
            PrivilegedAccount account,
            String initialSecret
        ) {
            for (String groupId : account.groupIds()) {
                if (!groups.containsKey(groupId)) {
                    throw new ValidationException(
                        "Unknown privileged group."
                    );
                }
            }

            vault.provision(
                account.id(),
                initialSecret
            );

            if (
                accounts.putIfAbsent(
                    account.id(),
                    account
                ) != null
            ) {
                throw new ValidationException(
                    "Duplicate privileged account."
                );
            }
        }

        // ----------------------------------------------------
        // ELIGIBILITY EVALUATION
        // ----------------------------------------------------

        AccessDecision evaluate(
            User user,
            PrivilegedAccount account
        ) {
            List<String> violations = new ArrayList<>();

            if (!user.active()) {
                violations.add("User is inactive.");
            }

            if (policy.requireMFA && !user.mfaEnabled()) {
                violations.add("MFA verification required.");
            }

            if (account.status() != AccountStatus.ACTIVE) {
                violations.add("Account is unavailable.");
            }

            boolean member = account.groupIds().stream()
                .map(groups::get)
                .filter(Objects::nonNull)
                .anyMatch(group -> group.contains(user.id()));

            if (!member) {
                violations.add(
                    "No authorized privileged group membership."
                );
            }

            if (!vault.exists(account.id())) {
                violations.add("Credential vault unavailable.");
            }

            return new AccessDecision(
                violations.isEmpty(),
                violations
            );
        }

        int maximumDuration(
            User user,
            PrivilegedAccount account
        ) {
            int maximum = policy.maximumSessionMinutes;

            for (String groupId : account.groupIds()) {
                PrivilegedGroup group = groups.get(groupId);

                if (
                    group != null &&
                    group.contains(user.id())
                ) {
                    maximum = Math.min(
                        maximum,
                        group.maximumSessionMinutes()
                    );
                }
            }

            return maximum;
        }

        // ----------------------------------------------------
        // REQUEST CREATION
        // ----------------------------------------------------

        AccessRequest requestAccess(
            String userId,
            String accountId,
            String justification,
            int durationMinutes
        ) {
            User user = users.get(userId);
            PrivilegedAccount account = accounts.get(accountId);

            if (user == null || account == null) {
                throw new ValidationException(
                    "Unknown user or account."
                );
            }

            AccessDecision decision = evaluate(user, account);

            if (!decision.eligible()) {
                throw new AuthorizationException(
                    String.join(" ", decision.violations())
                );
            }

            if (
                justification == null ||
                justification.isBlank()
            ) {
                throw new ValidationException(
                    "Business justification required."
                );
            }

            if (
                durationMinutes < 1 ||
                durationMinutes > maximumDuration(user, account)
            ) {
                throw new ValidationException(
                    "Invalid session duration."
                );
            }

            AccessRequest request = new AccessRequest(
                userId,
                accountId,
                justification,
                durationMinutes
            );

            requests.put(request.id(), request);

            audit.record(
                userId,
                "ACCESS_REQUEST_CREATED",
                request.id(),
                Severity.INFO
            );

            return request;
        }

        // ----------------------------------------------------
        // SECURITY CHECK MANAGEMENT
        // ----------------------------------------------------

        void updateCheck(
            String requestId,
            String checkName,
            CheckStatus status
        ) {
            AccessRequest request = requests.get(requestId);

            if (request == null) {
                throw new ValidationException(
                    "Request not found."
                );
            }

            request.updateCheck(checkName, status);

            audit.record(
                "SYSTEM",
                "STATUS_CHECK_UPDATED",
                requestId,
                status == CheckStatus.FAILED
                    ? Severity.WARNING
                    : Severity.INFO
            );
        }

        // ----------------------------------------------------
        // APPROVAL PROCESSING
        // ----------------------------------------------------

        void review(
            String requestId,
            String approverId,
            ReviewDecision decision
        ) {
            transactionLock.lock();

            try {
                AccessRequest request = requests.get(requestId);
                User approver = users.get(approverId);

                if (request == null || approver == null) {
                    throw new ValidationException(
                        "Request or approver not found."
                    );
                }

                if (request.status() != RequestStatus.PENDING) {
                    throw new WorkflowException(
                        "Request is not pending."
                    );
                }

                if (
                    policy.prohibitSelfApproval &&
                    request.requesterId().equals(approverId)
                ) {
                    throw new AuthorizationException(
                        "Self-approval prohibited."
                    );
                }

                if (
                    !approver.active() ||
                    (policy.requireMFA && !approver.mfaEnabled()) ||
                    !approver.hasRole("pam_approver")
                ) {
                    throw new AuthorizationException(
                        "Approver eligibility failed."
                    );
                }

                request.addApproval(new Approval(
                    approverId,
                    decision,
                    Instant.now()
                ));

                if (decision == ReviewDecision.DENY) {
                    request.deny();

                    audit.record(
                        approverId,
                        "REQUEST_DENIED",
                        requestId,
                        Severity.WARNING
                    );

                    return;
                }

                User requester = users.get(
                    request.requesterId()
                );

                PrivilegedAccount account = accounts.get(
                    request.accountId()
                );

                AccessDecision eligibility = evaluate(
                    requester,
                    account
                );

                if (!eligibility.eligible()) {
                    throw new AuthorizationException(
                        String.join(" ", eligibility.violations())
                    );
                }

                if (
                    request.durationMinutes() >
                    maximumDuration(requester, account)
                ) {
                    throw new AuthorizationException(
                        "Requested duration no longer permitted."
                    );
                }

                long approvals = request.countValidApprovals(
                    approval -> {
                        User reviewer = users.get(
                            approval.approverId()
                        );

                        return reviewer != null &&
                            reviewer.active() &&
                            reviewer.hasRole("pam_approver") &&
                            reviewer.mfaEnabled();
                    }
                );

                if (approvals >= policy.requiredApprovals) {
                    request.approve();
                }

                audit.record(
                    approverId,
                    "APPROVAL_RECORDED",
                    requestId,
                    Severity.INFO
                );

            } finally {
                transactionLock.unlock();
            }
        }

        // ----------------------------------------------------
        // FINAL ACCESS ELIGIBILITY
        // ----------------------------------------------------

        AccessDecision evaluateFinalEligibility(
            AccessRequest request
        ) {
            List<String> violations = new ArrayList<>();

            if (request.status() != RequestStatus.APPROVED) {
                violations.add("Required approval is missing.");
            }

            if (
                policy.requireStatusChecks &&
                !request.allChecksPassed()
            ) {
                violations.add(
                    "Required security checks have not passed."
                );
            }

            User user = users.get(request.requesterId());

            PrivilegedAccount account = accounts.get(
                request.accountId()
            );

            if (user == null || account == null) {
                violations.add("Identity or account unavailable.");
            } else {
                AccessDecision identityDecision = evaluate(
                    user,
                    account
                );

                violations.addAll(
                    identityDecision.violations()
                );
            }

            return new AccessDecision(
                violations.isEmpty(),
                violations
            );
        }

        // ----------------------------------------------------
        // SESSION CREATION
        // ----------------------------------------------------

        PrivilegedSession startSession(String requestId) {

            transactionLock.lock();

            try {
                AccessRequest request = requests.get(requestId);

                if (request == null) {
                    throw new ValidationException(
                        "Request not found."
                    );
                }

                AccessDecision eligibility =
                    evaluateFinalEligibility(request);

                if (!eligibility.eligible()) {
                    throw new AuthorizationException(
                        String.join(" ", eligibility.violations())
                    );
                }

                User user = users.get(request.requesterId());

                PrivilegedAccount account = accounts.get(
                    request.accountId()
                );

                if (
                    policy.prohibitConcurrentSessions &&
                    sessions.values().stream().anyMatch(
                        session ->
                            session.userId().equals(user.id()) &&
                            session.accountId().equals(account.id()) &&
                            session.active()
                    )
                ) {
                    throw new WorkflowException(
                        "Concurrent session prohibited."
                    );
                }

                PrivilegedSession session =
                    new PrivilegedSession(
                        request.id(),
                        user.id(),
                        account.id(),
                        request.durationMinutes(),
                        policy.requireSessionRecording
                    );

                sessions.put(session.id(), session);
                request.activate();

                audit.record(
                    user.id(),
                    "PRIVILEGED_SESSION_STARTED",
                    session.id(),
                    Severity.INFO
                );

                return session;

            } finally {
                transactionLock.unlock();
            }
        }

        // ----------------------------------------------------
        // VAULT REFERENCE ACCESS
        // ----------------------------------------------------

        String getCredentialReference(
            String sessionId,
            String userId
        ) {
            PrivilegedSession session = sessions.get(sessionId);

            if (session == null) {
                throw new ValidationException(
                    "Session not found."
                );
            }

            if (!session.userId().equals(userId)) {
                throw new AuthorizationException(
                    "Session ownership violation."
                );
            }

            if (!session.active()) {
                session.terminate();

                throw new AuthorizationException(
                    "Session is inactive or expired."
                );
            }

            PrivilegedAccount account = accounts.get(
                session.accountId()
            );

            if (account.status() != AccountStatus.ACTIVE) {
                throw new AuthorizationException(
                    "Privileged account disabled."
                );
            }

            audit.record(
                userId,
                "VAULT_REFERENCE_ACCESSED",
                sessionId,
                Severity.INFO
            );

            return vault.retrieveReference(account.id());
        }

        // ----------------------------------------------------
        // SESSION REVOCATION
        // ----------------------------------------------------

        void revokeSession(
            String sessionId,
            String actorId
        ) {
            PrivilegedSession session = sessions.get(sessionId);

            if (session == null) {
                throw new ValidationException(
                    "Session not found."
                );
            }

            session.terminate();

            AccessRequest request = requests.get(
                session.requestId()
            );

            request.revoke();

            audit.record(
                actorId,
                "SESSION_REVOKED",
                sessionId,
                Severity.CRITICAL
            );
        }

        void terminateSession(
            String sessionId,
            String actorId
        ) {
            PrivilegedSession session = sessions.get(sessionId);

            if (session == null) {
                throw new ValidationException(
                    "Session not found."
                );
            }

            session.terminate();

            requests.get(session.requestId()).expire();

            audit.record(
                actorId,
                "SESSION_TERMINATED",
                sessionId,
                Severity.INFO
            );
        }

        // ----------------------------------------------------
        // ACCOUNT DISABLEMENT
        // ----------------------------------------------------

        void disableAccount(
            String accountId,
            String actorId
        ) {
            PrivilegedAccount account = accounts.get(accountId);

            if (account == null) {
                throw new ValidationException(
                    "Account not found."
                );
            }

            account.disable();

            sessions.values().stream()
                .filter(session ->
                    session.accountId().equals(accountId)
                )
                .forEach(session -> {
                    session.terminate();

                    requests.get(
                        session.requestId()
                    ).revoke();
                });

            audit.record(
                actorId,
                "ACCOUNT_DISABLED",
                accountId,
                Severity.CRITICAL
            );
        }

        // ----------------------------------------------------
        // CREDENTIAL ROTATION
        // ----------------------------------------------------

        void rotateCredential(
            String accountId,
            String newSecret,
            String actorId
        ) {
            PrivilegedAccount account = accounts.get(accountId);

            if (account == null) {
                throw new ValidationException(
                    "Account not found."
                );
            }

            if (account.status() != AccountStatus.ACTIVE) {
                throw new WorkflowException(
                    "Account is not active."
                );
            }

            vault.rotate(accountId, newSecret);
            account.rotate();

            audit.record(
                actorId,
                "CREDENTIAL_ROTATED",
                accountId,
                Severity.WARNING
            );
        }

        // ----------------------------------------------------
        // ENTERPRISE REPORTING
        // ----------------------------------------------------

        Map<String, Long> report() {

            Map<String, Long> result = new HashMap<>();

            result.put("users", (long) users.size());
            result.put("groups", (long) groups.size());
            result.put("accounts", (long) accounts.size());
            result.put("requests", (long) requests.size());

            result.put(
                "pendingRequests",
                requests.values().stream()
                    .filter(r ->
                        r.status() == RequestStatus.PENDING
                    )
                    .count()
            );

            result.put(
                "activeSessions",
                sessions.values().stream()
                    .filter(PrivilegedSession::active)
                    .count()
            );

            result.put(
                "rotationDue",
                accounts.values().stream()
                    .filter(PrivilegedAccount::rotationDue)
                    .count()
            );

            return Map.copyOf(result);
        }

        List<AuditEvent> auditEvents() {
            return audit.events();
        }
    }


    // ========================================================
    // APPLICATION ENTRY POINT
    // ========================================================

    public static void main(String[] args) {

        AuditService audit = new AuditService();

        Vault vault = new IsolatedVault();

        ApprovalPolicy policy = new ApprovalPolicy(
            1,
            true,
            true,
            true,
            true,
            true,
            true,
            60
        );

        AccessControlService pam =
            new AccessControlService(
                vault,
                policy,
                audit
            );

        User operator = new User(
            "USR001",
            "database.operator",
            "Infrastructure",
            true,
            true,
            Set.of("system_operator")
        );

        User approver = new User(
            "USR002",
            "security.approver",
            "Security",
            true,
            true,
            Set.of("pam_approver")
        );

        pam.registerUser(operator);
        pam.registerUser(approver);

        PrivilegedGroup group = new PrivilegedGroup(
            "GRP001",
            "Production Database Administrators",
            Privilege.ADMIN,
            45,
            true
        );

        pam.registerGroup(group);
        pam.addMember("GRP001", "USR001");

        PrivilegedAccount account =
            new PrivilegedAccount(
                "ACC001",
                "production_dba",
                "production-postgresql",
                Privilege.ADMIN,
                Set.of("GRP001"),
                30
            );

        pam.registerAccount(
            account,
            "demonstration-credential-2026"
        );

        AccessRequest request = pam.requestAccess(
            "USR001",
            "ACC001",
            "Production database incident investigation.",
            30
        );

        System.out.println(
            "Request created: " + request.id()
        );

        pam.review(
            request.id(),
            "USR002",
            ReviewDecision.APPROVE
        );

        PrivilegedSession session =
            pam.startSession(request.id());

        System.out.println(
            "Session created: " + session.id()
        );

        String reference = pam.getCredentialReference(
            session.id(),
            "USR001"
        );

        System.out.println(
            "Vault reference: " + reference
        );

        // Ownership violation.
        try {
            pam.getCredentialReference(
                session.id(),
                "USR002"
            );
        } catch (AuthorizationException exception) {
            System.out.println(
                "Expected denial: " + exception.getMessage()
            );
        }

        pam.terminateSession(
            session.id(),
            "USR001"
        );

        System.out.println("\nENTERPRISE PAM REPORT");

        pam.report().entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .forEach(entry ->
                System.out.println(
                    entry.getKey() + ": " + entry.getValue()
                )
            );

        System.out.println("\nAUDIT EVENTS");

        pam.auditEvents().forEach(event ->
            System.out.println(
                event.timestamp() + " | " +
                event.action() + " | " +
                event.resource()
            )
        );

        System.out.println(
            "\nCritical events: " +
            audit.countBySeverity(Severity.CRITICAL)
        );
    }
}
