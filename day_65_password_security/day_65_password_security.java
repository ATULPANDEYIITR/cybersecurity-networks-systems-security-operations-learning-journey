import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/*
 * Enterprise Password Security Management
 *
 * Java 17 implementation:
 * - PBKDF2-HMAC-SHA-256
 * - Cryptographically secure random salts
 * - Password policy objects
 * - Immutable password records
 * - Constant-time verification
 * - Account state management
 * - Password history
 * - Failed authentication tracking
 * - Security event reporting
 */

public class PasswordSecurity {

    // --------------------------------------------------
    // Configuration
    // --------------------------------------------------

    private static final int ITERATIONS = 600_000;
    private static final int KEY_LENGTH = 256;
    private static final int SALT_LENGTH = 16;

    private static final SecureRandom SECURE_RANDOM =
            new SecureRandom();

    // --------------------------------------------------
    // Custom exceptions
    // --------------------------------------------------

    static class PasswordPolicyException
            extends IllegalArgumentException {

        PasswordPolicyException(String message) {
            super(message);
        }
    }

    static class AccountSecurityException
            extends RuntimeException {

        AccountSecurityException(String message) {
            super(message);
        }
    }

    // --------------------------------------------------
    // Password policy
    // --------------------------------------------------

    record PolicyResult(
            boolean accepted,
            List<String> violations
    ) {
        PolicyResult {
            violations = List.copyOf(violations);
        }
    }

    static final class PasswordPolicy {

        private static final Set<String> COMMON_PASSWORDS =
                Set.of(
                        "password123456",
                        "passwordpassword",
                        "123456789012345",
                        "qwerty123456789",
                        "administrator123"
                );

        private final int minimumLength;
        private final int maximumLength;

        PasswordPolicy(int minimumLength, int maximumLength) {
            if (
                    minimumLength < 1 ||
                    maximumLength < minimumLength
            ) {
                throw new IllegalArgumentException(
                        "Invalid password policy configuration"
                );
            }

            this.minimumLength = minimumLength;
            this.maximumLength = maximumLength;
        }

        PolicyResult evaluate(String password) {
            if (password == null) {
                return new PolicyResult(
                        false,
                        List.of("Password cannot be null")
                );
            }

            var violations =
                    new java.util.ArrayList<String>();

            int length = password.codePointCount(
                    0, password.length()
            );

            if (length < minimumLength) {
                violations.add("Password is too short");
            }

            if (length > maximumLength) {
                violations.add("Password is too long");
            }

            if (password.isBlank()) {
                violations.add("Password cannot be blank");
            }

            if (password.indexOf('\0') >= 0) {
                violations.add("Null characters are prohibited");
            }

            if (
                    COMMON_PASSWORDS.contains(
                            password.toLowerCase(
                                    java.util.Locale.ROOT
                            )
                    )
            ) {
                violations.add("Password is commonly used");
            }

            return new PolicyResult(
                    violations.isEmpty(),
                    violations
            );
        }

        void validate(String password) {
            PolicyResult result = evaluate(password);

            if (!result.accepted()) {
                throw new PasswordPolicyException(
                        String.join("; ", result.violations())
                );
            }
        }
    }

    // --------------------------------------------------
    // Password record
    // --------------------------------------------------

    record PasswordRecord(
            String algorithm,
            int iterations,
            String saltHex,
            String hashHex,
            int version
    ) {
        PasswordRecord {
            Objects.requireNonNull(algorithm);
            Objects.requireNonNull(saltHex);
            Objects.requireNonNull(hashHex);

            if (
                    !algorithm.equals("PBKDF2WithHmacSHA256") ||
                    iterations < 1_000 ||
                    iterations > 2_000_000 ||
                    version != 1
            ) {
                throw new IllegalArgumentException(
                        "Invalid password record parameters"
                );
            }

            byte[] salt = HexFormat.of().parseHex(saltHex);
            byte[] hash = HexFormat.of().parseHex(hashHex);

            if (salt.length != SALT_LENGTH || hash.length != 32) {
                throw new IllegalArgumentException(
                        "Invalid password record length"
                );
            }
        }
    }

    // --------------------------------------------------
    // Password hashing service
    // --------------------------------------------------

    static final class PasswordHasher {

        private final int iterations;
        private final PasswordPolicy policy;

        PasswordHasher(
                int iterations,
                PasswordPolicy policy
        ) {
            if (
                    iterations < 1_000 ||
                    iterations > 2_000_000
            ) {
                throw new IllegalArgumentException(
                        "Invalid PBKDF2 iteration count"
                );
            }

            this.iterations = iterations;
            this.policy = Objects.requireNonNull(policy);
        }

        private byte[] derive(
                char[] password,
                byte[] salt,
                int iterationCount
        ) {
            PBEKeySpec specification = new PBEKeySpec(
                    password,
                    salt,
                    iterationCount,
                    KEY_LENGTH
            );

            try {
                SecretKeyFactory factory =
                        SecretKeyFactory.getInstance(
                                "PBKDF2WithHmacSHA256"
                        );

                return factory.generateSecret(
                        specification
                ).getEncoded();

            } catch (GeneralSecurityException error) {
                throw new AccountSecurityException(
                        "Password derivation failed"
                );

            } finally {
                specification.clearPassword();
            }
        }

        PasswordRecord hash(char[] password) {
            String text = new String(password);

            policy.validate(text);

            byte[] salt = new byte[SALT_LENGTH];

            SECURE_RANDOM.nextBytes(salt);

            byte[] derived = derive(
                    password,
                    salt,
                    iterations
            );

            try {
                return new PasswordRecord(
                        "PBKDF2WithHmacSHA256",
                        iterations,
                        HexFormat.of().formatHex(salt),
                        HexFormat.of().formatHex(derived),
                        1
                );
            } finally {
                Arrays.fill(derived, (byte) 0);
                Arrays.fill(salt, (byte) 0);
            }
        }

        boolean verify(
                char[] password,
                PasswordRecord record
        ) {
            byte[] salt = HexFormat.of().parseHex(
                    record.saltHex()
            );

            byte[] expected = HexFormat.of().parseHex(
                    record.hashHex()
            );

            byte[] candidate = null;

            try {
                candidate = derive(
                        password,
                        salt,
                        record.iterations()
                );

                return java.security.MessageDigest.isEqual(
                        candidate,
                        expected
                );

            } catch (RuntimeException error) {
                return false;

            } finally {
                Arrays.fill(salt, (byte) 0);
                Arrays.fill(expected, (byte) 0);

                if (candidate != null) {
                    Arrays.fill(candidate, (byte) 0);
                }
            }
        }

        boolean needsRehash(PasswordRecord record) {
            return (
                    !record.algorithm().equals(
                            "PBKDF2WithHmacSHA256"
                    ) ||
                    record.iterations() != iterations
            );
        }
    }

    // --------------------------------------------------
    // Enterprise account model
    // --------------------------------------------------

    enum AccountStatus {
        ACTIVE,
        LOCKED,
        DISABLED
    }

    static final class UserAccount {

        private final String username;

        private volatile PasswordRecord passwordRecord;

        private final AtomicInteger failedAttempts =
                new AtomicInteger(0);

        private volatile AccountStatus status =
                AccountStatus.ACTIVE;

        private volatile long lockedUntil;

        private final java.util.ArrayDeque<String> passwordHistory =
                new java.util.ArrayDeque<>();

        private long passwordChangedAt;

        UserAccount(
                String username,
                PasswordRecord passwordRecord
        ) {
            this.username = username;
            this.passwordRecord = passwordRecord;
            this.passwordChangedAt =
                    System.currentTimeMillis();
        }

        String username() {
            return username;
        }

        AccountStatus status() {
            return status;
        }

        int failedAttempts() {
            return failedAttempts.get();
        }

        synchronized void recordFailure(
                int maximumFailures,
                long lockDuration
        ) {
            if (
                    failedAttempts.incrementAndGet()
                            >= maximumFailures
            ) {
                status = AccountStatus.LOCKED;

                lockedUntil =
                        System.currentTimeMillis() +
                        lockDuration;
            }
        }

        synchronized void recordSuccess() {
            failedAttempts.set(0);

            if (
                    status == AccountStatus.LOCKED &&
                    System.currentTimeMillis() >= lockedUntil
            ) {
                status = AccountStatus.ACTIVE;
            }
        }

        synchronized boolean isAvailable() {
            if (status == AccountStatus.DISABLED) {
                return false;
            }

            if (
                    status == AccountStatus.LOCKED &&
                    System.currentTimeMillis() < lockedUntil
            ) {
                return false;
            }

            if (status == AccountStatus.LOCKED) {
                status = AccountStatus.ACTIVE;
                failedAttempts.set(0);
            }

            return true;
        }

        synchronized boolean hasRecentPassword(String hash) {
            return passwordHistory.contains(hash);
        }

        synchronized void changePassword(
                PasswordRecord newRecord,
                int historyLimit
        ) {
            passwordHistory.addFirst(
                    passwordRecord.hashHex()
            );

            while (passwordHistory.size() > historyLimit) {
                passwordHistory.removeLast();
            }

            passwordRecord = newRecord;

            passwordChangedAt =
                    System.currentTimeMillis();

            failedAttempts.set(0);
        }

        synchronized PasswordRecord getPasswordRecord() {
            return passwordRecord;
        }

        synchronized long passwordChangedAt() {
            return passwordChangedAt;
        }
    }

    // --------------------------------------------------
    // Audit events
    // --------------------------------------------------

    record SecurityEvent(
            String eventType,
            String username,
            long timestamp
    ) {}

    // --------------------------------------------------
    // Authentication service
    // --------------------------------------------------

    static final class AuthenticationService {

        private final Map<String, UserAccount> accounts =
                new ConcurrentHashMap<>();

        private final java.util.concurrent.ConcurrentLinkedQueue
                <SecurityEvent> auditEvents =
                new java.util.concurrent.ConcurrentLinkedQueue<>();

        private final PasswordHasher hasher;

        private static final int MAX_FAILURES = 5;
        private static final long LOCK_DURATION = 60_000;
        private static final int HISTORY_LIMIT = 5;

        AuthenticationService(PasswordHasher hasher) {
            this.hasher = hasher;
        }

        private void audit(String event, String username) {
            auditEvents.add(
                    new SecurityEvent(
                            event,
                            username,
                            System.currentTimeMillis()
                    )
            );
        }

        void register(
                String username,
                char[] password
        ) {
            if (
                    username == null ||
                    username.isBlank() ||
                    username.length() > 100
            ) {
                throw new IllegalArgumentException(
                        "Invalid username"
                );
            }

            PasswordRecord record = hasher.hash(password);

            UserAccount account = new UserAccount(
                    username,
                    record
            );

            if (
                    accounts.putIfAbsent(username, account) != null
            ) {
                throw new AccountSecurityException(
                        "Account already exists"
                );
            }

            audit("ACCOUNT_REGISTERED", username);
        }

        boolean authenticate(
                String username,
                char[] password
        ) {
            UserAccount account = accounts.get(username);

            if (account == null) {
                audit("UNKNOWN_ACCOUNT", username);
                return false;
            }

            if (!account.isAvailable()) {
                audit("ACCOUNT_UNAVAILABLE", username);
                return false;
            }

            PasswordRecord record =
                    account.getPasswordRecord();

            boolean valid = hasher.verify(password, record);

            if (!valid) {
                account.recordFailure(
                        MAX_FAILURES,
                        LOCK_DURATION
                );

                audit("AUTHENTICATION_FAILED", username);

                return false;
            }

            account.recordSuccess();

            if (hasher.needsRehash(record)) {
                PasswordRecord updated = hasher.hash(password);

                account.changePassword(
                        updated,
                        HISTORY_LIMIT
                );

                audit("PASSWORD_REHASHED", username);
            }

            audit("AUTHENTICATION_SUCCEEDED", username);

            return true;
        }

        synchronized void changePassword(
                String username,
                char[] currentPassword,
                char[] newPassword
        ) {
            UserAccount account = accounts.get(username);

            if (account == null || !account.isAvailable()) {
                throw new AccountSecurityException(
                        "Account unavailable"
                );
            }

            PasswordRecord current =
                    account.getPasswordRecord();

            if (!hasher.verify(currentPassword, current)) {
                audit("PASSWORD_CHANGE_REJECTED", username);

                throw new AccountSecurityException(
                        "Current password is incorrect"
                );
            }

            PasswordRecord newRecord =
                    hasher.hash(newPassword);

            if (
                    account.hasRecentPassword(
                            newRecord.hashHex()
                    )
            ) {
                throw new AccountSecurityException(
                        "Password was used recently"
                );
            }

            if (
                    hasher.verify(newPassword, current)
            ) {
                throw new AccountSecurityException(
                        "New password must differ from current password"
                );
            }

            account.changePassword(
                    newRecord,
                    HISTORY_LIMIT
            );

            audit("PASSWORD_CHANGED", username);
        }

        UserAccount findAccount(String username) {
            return accounts.get(username);
        }

        List<SecurityEvent> getAuditEvents() {
            return List.copyOf(auditEvents);
        }
    }

    // --------------------------------------------------
    // Application and test scenarios
    // --------------------------------------------------

    public static void main(String[] args) {

        PasswordPolicy policy = new PasswordPolicy(
                15,
                128
        );

        PasswordHasher hasher = new PasswordHasher(
                ITERATIONS,
                policy
        );

        AuthenticationService service =
                new AuthenticationService(hasher);

        char[] password =
                "Correct-Horse-Battery-47!".toCharArray();

        char[] wrongPassword =
                "Incorrect-Enterprise-Password!".toCharArray();

        char[] newPassword =
                "Enterprise-Secure-Password-82!".toCharArray();

        try {
            System.out.println(
                    "ENTERPRISE PASSWORD SECURITY"
            );

            System.out.println(
                    "============================="
            );

            service.register("alice", password);

            UserAccount account =
                    service.findAccount("alice");

            System.out.println(
                    "Hash algorithm: PBKDF2-HMAC-SHA256"
            );

            System.out.println(
                    "Iterations: " + ITERATIONS
            );

            System.out.println(
                    "Account status: " + account.status()
            );

            System.out.println(
                    "Correct authentication: " +
                    service.authenticate("alice", password)
            );

            System.out.println(
                    "Incorrect authentication: " +
                    service.authenticate("alice", wrongPassword)
            );

            PolicyResult shortPassword =
                    policy.evaluate("short");

            System.out.println(
                    "Short password accepted: " +
                    shortPassword.accepted()
            );

            service.changePassword(
                    "alice",
                    password,
                    newPassword
            );

            System.out.println(
                    "Password changed successfully."
            );

            System.out.println(
                    "New password authentication: " +
                    service.authenticate("alice", newPassword)
            );

            System.out.println(
                    "Audit events: " +
                    service.getAuditEvents().size()
            );

            System.out.println(
                    "Password changed at: " +
                    account.passwordChangedAt()
            );

            if (
                    !service.authenticate("alice", newPassword)
            ) {
                throw new AssertionError(
                        "Authentication test failed"
                );
            }

            System.out.println(
                    "\nAll enterprise security checks passed."
            );

        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(wrongPassword, '\0');
            Arrays.fill(newPassword, '\0');
        }
    }
}
