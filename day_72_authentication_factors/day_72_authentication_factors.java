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
import java.security.SecureRandom;

/*
 * Authentication Factors
 * Enterprise authentication and adaptive access governance.
 *
 * Java 17, standard library only.
 */

public class AuthenticationFactors {

    enum Factor {
        PASSWORD,
        TOTP,
        HARDWARE_TOKEN,
        BIOMETRIC
    }

    enum RiskLevel {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    enum AuthStatus {
        SUCCESS,
        REJECTED,
        MFA_REQUIRED,
        STEP_UP_REQUIRED,
        LOCKED
    }

    enum CredentialState {
        ACTIVE,
        LOCKED,
        DISABLED
    }

    record RiskAssessment(int score, RiskLevel level) {}

    record LoginContext(
        String deviceId,
        String country,
        boolean newDevice,
        boolean impossibleTravel,
        boolean unusualTime,
        boolean sensitiveAction
    ) {
        LoginContext {
            Objects.requireNonNull(deviceId);
            Objects.requireNonNull(country);

            if (deviceId.isBlank() || country.isBlank()) {
                throw new IllegalArgumentException(
                    "Device and country are required."
                );
            }
        }
    }

    record FactorEvidence(
        Factor factor,
        boolean verified,
        boolean trusted,
        boolean userPresent
    ) {
        FactorEvidence {
            Objects.requireNonNull(factor);
        }
    }

    record AuthenticationResult(
        AuthStatus status,
        RiskAssessment risk,
        List<Factor> requiredFactors,
        List<Factor> completedFactors,
        String message
    ) {
        AuthenticationResult {
            requiredFactors = List.copyOf(requiredFactors);
            completedFactors = List.copyOf(completedFactors);
        }
    }

    record PasswordCredential(
        byte[] salt,
        byte[] passwordHash,
        int iterations
    ) {
        PasswordCredential {
            salt = salt.clone();
            passwordHash = passwordHash.clone();
        }

        @Override
        public byte[] salt() {
            return salt.clone();
        }

        @Override
        public byte[] passwordHash() {
            return passwordHash.clone();
        }
    }

    static class AuthenticationException extends RuntimeException {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static class UserAccount {
        private final String id;
        private final String username;
        private final PasswordCredential password;
        private final EnumSet<Factor> registeredFactors;

        private CredentialState state = CredentialState.ACTIVE;
        private int failedAttempts;
        private Instant lockedUntil;
        private Instant lastLogin;

        UserAccount(
            String id,
            String username,
            PasswordCredential password,
            EnumSet<Factor> factors
        ) {
            this.id = id;
            this.username = username;
            this.password = password;
            this.registeredFactors = factors.clone();
        }

        public String username() {
            return username;
        }

        public EnumSet<Factor> factors() {
            return registeredFactors.clone();
        }

        public CredentialState state() {
            return state;
        }
    }

    interface FactorVerifier {
        boolean verify(UserAccount user, FactorEvidence evidence);
    }

    static class TrustedEvidenceVerifier implements FactorVerifier {

        @Override
        public boolean verify(
            UserAccount user,
            FactorEvidence evidence
        ) {
            if (!evidence.verified()) return false;

            return switch (evidence.factor()) {
                case PASSWORD -> true;

                case TOTP -> evidence.userPresent();

                case HARDWARE_TOKEN, BIOMETRIC ->
                    evidence.trusted() && evidence.userPresent();
            };
        }
    }

    static class PasswordService {
        private static final int ITERATIONS = 210_000;
        private static final int KEY_LENGTH = 256;
        private static final SecureRandom RANDOM = new SecureRandom();

        static PasswordCredential create(String password) {
            if (password == null ||
                password.length() < 12 ||
                password.length() > 1024) {
                throw new IllegalArgumentException(
                    "Password must contain 12 to 1024 characters."
                );
            }

            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);

            return new PasswordCredential(
                salt,
                derive(password, salt, ITERATIONS),
                ITERATIONS
            );
        }

        private static byte[] derive(
            String password,
            byte[] salt,
            int iterations
        ) {
            char[] chars = password.toCharArray();

            try {
                var specification =
                    new javax.crypto.spec.PBEKeySpec(
                        chars,
                        salt,
                        iterations,
                        KEY_LENGTH
                    );

                try {
                    return javax.crypto.SecretKeyFactory
                        .getInstance("PBKDF2WithHmacSHA256")
                        .generateSecret(specification)
                        .getEncoded();
                } finally {
                    specification.clearPassword();
                }

            } catch (java.security.GeneralSecurityException exception) {
                throw new AuthenticationException(
                    "Password derivation failed."
                );
            } finally {
                java.util.Arrays.fill(chars, '\0');
            }
        }

        static boolean verify(
            String candidate,
            PasswordCredential credential
        ) {
            if (candidate == null) return false;

            byte[] actual = derive(
                candidate,
                credential.salt(),
                credential.iterations()
            );

            return java.security.MessageDigest.isEqual(
                actual,
                credential.passwordHash()
            );
        }
    }

    static class RiskEngine {

        static RiskAssessment evaluate(LoginContext context) {
            int score = 0;

            if (context.newDevice()) score += 25;
            if (context.impossibleTravel()) score += 55;
            if (context.unusualTime()) score += 15;
            if (context.sensitiveAction()) score += 20;

            RiskLevel level;

            if (score >= 70) {
                level = RiskLevel.CRITICAL;
            } else if (score >= 45) {
                level = RiskLevel.HIGH;
            } else if (score >= 20) {
                level = RiskLevel.MEDIUM;
            } else {
                level = RiskLevel.LOW;
            }

            return new RiskAssessment(score, level);
        }
    }

    static class AuthenticationPolicy {

        static List<Factor> evaluate(
            UserAccount user,
            RiskAssessment risk,
            LoginContext context
        ) {
            EnumSet<Factor> registered = user.factors();

            List<Factor> required = new ArrayList<>();
            required.add(Factor.PASSWORD);

            if (registered.contains(Factor.TOTP)) {
                required.add(Factor.TOTP);
            }

            if (
                risk.level() == RiskLevel.HIGH ||
                risk.level() == RiskLevel.CRITICAL
            ) {
                if (registered.contains(Factor.HARDWARE_TOKEN)) {
                    required.add(Factor.HARDWARE_TOKEN);
                } else if (registered.contains(Factor.BIOMETRIC)) {
                    required.add(Factor.BIOMETRIC);
                }
            }

            if (
                context.sensitiveAction() &&
                registered.contains(Factor.BIOMETRIC) &&
                !required.contains(Factor.BIOMETRIC)
            ) {
                required.add(Factor.BIOMETRIC);
            }

            return List.copyOf(required);
        }
    }

    static class AuditService {
        private final List<String> events = new ArrayList<>();

        void record(String username, String event) {
            events.add(
                Instant.now() + " | " + username + " | " + event
            );
        }

        List<String> events() {
            return List.copyOf(events);
        }
    }

    static class AuthenticationService {
        private final Map<String, UserAccount> accounts = new HashMap<>();
        private final Map<Factor, FactorVerifier> verifiers =
            new HashMap<>();

        private final AuditService audit = new AuditService();

        private static final int MAX_FAILURES = 5;
        private static final long LOCK_SECONDS = 300;

        AuthenticationService() {
            FactorVerifier verifier = new TrustedEvidenceVerifier();

            for (Factor factor : Factor.values()) {
                verifiers.put(factor, verifier);
            }
        }

        UserAccount register(
            String username,
            String password,
            EnumSet<Factor> factors
        ) {
            if (username == null ||
                username.isBlank() ||
                username.length() > 100) {
                throw new IllegalArgumentException("Invalid username.");
            }

            if (accounts.containsKey(username)) {
                throw new AuthenticationException("Account already exists.");
            }

            if (!factors.contains(Factor.PASSWORD)) {
                throw new AuthenticationException(
                    "Password factor is required."
                );
            }

            UserAccount user = new UserAccount(
                UUID.randomUUID().toString(),
                username,
                PasswordService.create(password),
                factors
            );

            accounts.put(username, user);
            audit.record(username, "ACCOUNT_REGISTERED");

            return user;
        }

        AuthenticationResult authenticate(
            String username,
            String password,
            LoginContext context,
            List<FactorEvidence> evidence
        ) {
            UserAccount user = accounts.get(username);

            RiskAssessment risk = RiskEngine.evaluate(context);

            if (user == null) {
                audit.record(username, "UNKNOWN_USER");

                return result(
                    AuthStatus.REJECTED,
                    risk,
                    List.of(),
                    List.of(),
                    "Invalid credentials."
                );
            }

            if (user.state == CredentialState.DISABLED) {
                return result(
                    AuthStatus.REJECTED,
                    risk,
                    List.of(),
                    List.of(),
                    "Account disabled."
                );
            }

            if (user.state == CredentialState.LOCKED) {
                if (
                    user.lockedUntil != null &&
                    Instant.now().isBefore(user.lockedUntil)
                ) {
                    return result(
                        AuthStatus.LOCKED,
                        risk,
                        List.of(),
                        List.of(),
                        "Account temporarily locked."
                    );
                }

                user.state = CredentialState.ACTIVE;
                user.failedAttempts = 0;
                user.lockedUntil = null;
            }

            if (!PasswordService.verify(password, user.password)) {
                user.failedAttempts++;

                if (user.failedAttempts >= MAX_FAILURES) {
                    user.state = CredentialState.LOCKED;
                    user.lockedUntil = Instant.now().plusSeconds(
                        LOCK_SECONDS
                    );
                }

                audit.record(username, "PASSWORD_FAILURE");

                return result(
                    user.state == CredentialState.LOCKED
                        ? AuthStatus.LOCKED
                        : AuthStatus.REJECTED,
                    risk,
                    List.of(),
                    List.of(),
                    "Invalid credentials."
                );
            }

            user.failedAttempts = 0;

            List<Factor> required =
                AuthenticationPolicy.evaluate(user, risk, context);

            Map<Factor, FactorEvidence> supplied = new HashMap<>();

            for (FactorEvidence item : evidence) {
                if (supplied.put(item.factor(), item) != null) {
                    throw new AuthenticationException(
                        "Duplicate factor evidence."
                    );
                }
            }

            List<Factor> completed = new ArrayList<>();
            completed.add(Factor.PASSWORD);

            for (Factor factor : required) {
                if (factor == Factor.PASSWORD) continue;

                FactorEvidence item = supplied.get(factor);

                if (
                    item == null ||
                    !verifiers.get(factor).verify(user, item)
                ) {
                    AuthStatus status =
                        factor == Factor.TOTP
                            ? AuthStatus.MFA_REQUIRED
                            : AuthStatus.STEP_UP_REQUIRED;

                    audit.record(username, "ADDITIONAL_FACTOR_REQUIRED");

                    return result(
                        status,
                        risk,
                        required,
                        completed,
                        "Additional factor verification required."
                    );
                }

                completed.add(factor);
            }

            user.lastLogin = Instant.now();

            audit.record(username, "AUTHENTICATION_SUCCESS");

            return result(
                AuthStatus.SUCCESS,
                risk,
                required,
                completed,
                "Authentication successful."
            );
        }

        private AuthenticationResult result(
            AuthStatus status,
            RiskAssessment risk,
            List<Factor> required,
            List<Factor> completed,
            String message
        ) {
            return new AuthenticationResult(
                status,
                risk,
                required,
                completed,
                message
            );
        }

        AuditService audit() {
            return audit;
        }
    }

    private static void runTests() {
        AuthenticationService service = new AuthenticationService();

        UserAccount user = service.register(
            "admin@example.com",
            "EnterprisePassword!2026",
            EnumSet.allOf(Factor.class)
        );

        LoginContext normal = new LoginContext(
            "device-001",
            "IN",
            false,
            false,
            false,
            false
        );

        AuthenticationResult success = service.authenticate(
            user.username(),
            "EnterprisePassword!2026",
            normal,
            List.of(
                new FactorEvidence(Factor.TOTP, true, true, true)
            )
        );

        if (success.status() != AuthStatus.SUCCESS) {
            throw new AssertionError("Normal authentication failed.");
        }

        LoginContext highRisk = new LoginContext(
            "unknown-device",
            "US",
            true,
            true,
            false,
            false
        );

        AuthenticationResult stepUp = service.authenticate(
            user.username(),
            "EnterprisePassword!2026",
            highRisk,
            List.of(
                new FactorEvidence(Factor.TOTP, true, true, true)
            )
        );

        if (stepUp.status() != AuthStatus.STEP_UP_REQUIRED) {
            throw new AssertionError("Adaptive step-up test failed.");
        }

        AuthenticationResult rejected = service.authenticate(
            user.username(),
            "WrongPassword!2026",
            normal,
            List.of()
        );

        if (rejected.status() != AuthStatus.REJECTED) {
            throw new AssertionError("Invalid password test failed.");
        }

        RiskAssessment risk = RiskEngine.evaluate(highRisk);

        if (risk.score() != 80 || risk.level() != RiskLevel.CRITICAL) {
            throw new AssertionError("Risk scoring test failed.");
        }

        System.out.println("All Java 17 tests passed.");
    }

    public static void main(String[] args) {
        try {
            AuthenticationService service = new AuthenticationService();

            UserAccount user = service.register(
                "security@example.com",
                "EnterprisePassword!2026",
                EnumSet.allOf(Factor.class)
            );

            LoginContext context = new LoginContext(
                "corporate-device-001",
                "IN",
                true,
                false,
                false,
                false
            );

            AuthenticationResult result = service.authenticate(
                user.username(),
                "EnterprisePassword!2026",
                context,
                List.of(
                    new FactorEvidence(Factor.TOTP, true, true, true)
                )
            );

            System.out.println("\nAUTHENTICATION REPORT");
            System.out.println("Status: " + result.status());
            System.out.println("Risk: " + result.risk());
            System.out.println("Required: " + result.requiredFactors());
            System.out.println("Completed: " + result.completedFactors());
            System.out.println("Message: " + result.message());

            runTests();

        } catch (RuntimeException exception) {
            System.err.println(
                "Authentication failure: " + exception.getMessage()
            );
            System.exit(1);
        }
    }
}
