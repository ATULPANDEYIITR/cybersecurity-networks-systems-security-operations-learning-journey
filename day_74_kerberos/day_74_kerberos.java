import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * ENTERPRISE KERBEROS AUTHENTICATION MODEL
 *
 * Components:
 * - Authentication Server
 * - Ticket Granting Server
 * - Key Distribution Center
 * - Client principals
 * - Service principals
 * - TGT issuance
 * - Service-ticket issuance
 * - Authentication policies
 * - Replay detection
 * - Audit records
 * - Mutual authentication
 *
 * Educational implementation using HMAC-authenticated tickets.
 * It does not implement RFC 4120 encryption or wire compatibility.
 */

public class KerberosEnterprise {

    enum TicketType {
        TGT,
        SERVICE
    }

    enum PrincipalStatus {
        ACTIVE,
        DISABLED
    }

    enum SessionState {
        CREATED,
        AUTHENTICATED,
        SERVICE_AUTHENTICATED,
        REJECTED
    }

    enum AuditAction {
        PRINCIPAL_REGISTERED,
        SERVICE_REGISTERED,
        TGT_ISSUED,
        SERVICE_TICKET_ISSUED,
        AUTHENTICATION_REJECTED,
        SERVICE_ACCESS_GRANTED,
        REPLAY_REJECTED,
        PRINCIPAL_DISABLED
    }

    static class KerberosException extends RuntimeException {
        KerberosException(String message) {
            super(message);
        }
    }

    static class AuthenticationException extends KerberosException {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static class TicketException extends KerberosException {
        TicketException(String message) {
            super(message);
        }
    }

    static class ReplayException extends KerberosException {
        ReplayException(String message) {
            super(message);
        }
    }

    record TicketPolicy(
        Duration tgtLifetime,
        Duration serviceLifetime,
        Duration clockTolerance
    ) {
        TicketPolicy {
            Objects.requireNonNull(tgtLifetime);
            Objects.requireNonNull(serviceLifetime);
            Objects.requireNonNull(clockTolerance);

            if (
                tgtLifetime.isZero() ||
                tgtLifetime.isNegative() ||
                serviceLifetime.isZero() ||
                serviceLifetime.isNegative() ||
                clockTolerance.isNegative()
            ) {
                throw new IllegalArgumentException(
                    "Invalid ticket policy"
                );
            }
        }

        static TicketPolicy standard() {
            return new TicketPolicy(
                Duration.ofMinutes(10),
                Duration.ofMinutes(5),
                Duration.ofSeconds(60)
            );
        }
    }

    record Ticket(
        String id,
        TicketType type,
        String client,
        String service,
        String realm,
        String sessionKey,
        Instant issuedAt,
        Instant expiresAt,
        String body,
        String signature
    ) {}

    record Authenticator(
        String client,
        Instant timestamp,
        String nonce,
        String signature
    ) {}

    record AuditRecord(
        Instant timestamp,
        AuditAction action,
        String principal,
        String service,
        String result
    ) {}

    static final class Principal {
        private final String name;
        private final byte[] salt;
        private final byte[] passwordVerifier;
        private final Set<String> roles;
        private PrincipalStatus status;

        Principal(
            String name,
            byte[] salt,
            byte[] passwordVerifier,
            Set<String> roles
        ) {
            this.name = name;
            this.salt = salt.clone();
            this.passwordVerifier = passwordVerifier.clone();
            this.roles = Collections.unmodifiableSet(
                new HashSet<>(roles)
            );
            this.status = PrincipalStatus.ACTIVE;
        }

        String name() {
            return name;
        }

        boolean isActive() {
            return status == PrincipalStatus.ACTIVE;
        }

        Set<String> roles() {
            return roles;
        }

        void disable() {
            status = PrincipalStatus.DISABLED;
        }

        byte[] salt() {
            return salt.clone();
        }

        byte[] verifier() {
            return passwordVerifier.clone();
        }
    }

    static final class ServicePrincipal {
        private final String name;
        private final byte[] longTermKey;

        ServicePrincipal(String name, byte[] key) {
            this.name = name;
            this.longTermKey = key.clone();
        }

        String name() {
            return name;
        }

        byte[] key() {
            return longTermKey.clone();
        }
    }

    static final class ReplayCache {
        private final ConcurrentMap<String, Instant> entries =
            new ConcurrentHashMap<>();

        void accept(
            String identifier,
            Instant expiry,
            Instant now
        ) {
            entries.entrySet().removeIf(
                entry -> !entry.getValue().isAfter(now)
            );

            Instant previous = entries.putIfAbsent(
                identifier,
                expiry
            );

            if (previous != null) {
                throw new ReplayException(
                    "Authenticator replay detected"
                );
            }
        }

        int size() {
            return entries.size();
        }
    }

    static final class CryptoSupport {
        private static final SecureRandom RANDOM = new SecureRandom();

        static byte[] randomBytes(int length) {
            byte[] result = new byte[length];
            RANDOM.nextBytes(result);
            return result;
        }

        static byte[] derivePasswordKey(
            char[] password,
            byte[] salt
        ) {
            PBEKeySpec specification = new PBEKeySpec(
                password,
                salt,
                200_000,
                256
            );

            try {
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");

                return factory.generateSecret(
                    specification
                ).getEncoded();

            } catch (Exception exception) {
                throw new KerberosException(
                    "Password derivation failed"
                );
            } finally {
                specification.clearPassword();
            }
        }

        static String hmac(String message, byte[] key) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");

                mac.init(
                    new SecretKeySpec(key, "HmacSHA256")
                );

                byte[] result = mac.doFinal(
                    message.getBytes(StandardCharsets.UTF_8)
                );

                return Base64.getEncoder().encodeToString(result);

            } catch (Exception exception) {
                throw new KerberosException("HMAC operation failed");
            }
        }

        static boolean constantTimeEquals(String a, String b) {
            if (a == null || b == null) {
                return false;
            }

            return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8)
            );
        }

        static String newId() {
            return UUID.randomUUID().toString();
        }

        static String encode(String value) {
            return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                    value.getBytes(StandardCharsets.UTF_8)
                );
        }
    }

    static final class KeyDistributionCenter {

        private final String realm;
        private final TicketPolicy policy;

        private final byte[] tgsKey;

        private final ConcurrentMap<String, Principal> principals =
            new ConcurrentHashMap<>();

        private final ConcurrentMap<String, ServicePrincipal> services =
            new ConcurrentHashMap<>();

        private final ConcurrentMap<String, Ticket> issuedTickets =
            new ConcurrentHashMap<>();

        private final List<AuditRecord> audit =
            Collections.synchronizedList(new ArrayList<>());

        private final ReplayCache replayCache = new ReplayCache();

        KeyDistributionCenter(
            String realm,
            TicketPolicy policy
        ) {
            if (
                realm == null ||
                !realm.contains(".") ||
                realm.isBlank()
            ) {
                throw new IllegalArgumentException("Invalid realm");
            }

            this.realm = realm.toUpperCase();
            this.policy = Objects.requireNonNull(policy);
            this.tgsKey = CryptoSupport.randomBytes(32);
        }

        private void record(
            AuditAction action,
            String principal,
            String service,
            String result
        ) {
            audit.add(
                new AuditRecord(
                    Instant.now(),
                    action,
                    principal,
                    service,
                    result
                )
            );
        }

        void registerPrincipal(
            String name,
            char[] password,
            Set<String> roles
        ) {
            if (
                name == null ||
                !name.contains("@") ||
                password == null ||
                password.length < 12
            ) {
                throw new IllegalArgumentException(
                    "Invalid principal registration"
                );
            }

            byte[] salt = CryptoSupport.randomBytes(16);

            byte[] verifier = CryptoSupport.derivePasswordKey(
                password,
                salt
            );

            Principal principal = new Principal(
                name,
                salt,
                verifier,
                roles
            );

            if (principals.putIfAbsent(name, principal) != null) {
                throw new KerberosException(
                    "Duplicate principal"
                );
            }

            record(
                AuditAction.PRINCIPAL_REGISTERED,
                name,
                "KDC",
                "SUCCESS"
            );
        }

        void registerService(String serviceName) {
            if (
                serviceName == null ||
                !serviceName.contains("/")
            ) {
                throw new IllegalArgumentException(
                    "Service must contain service/hostname"
                );
            }

            ServicePrincipal service = new ServicePrincipal(
                serviceName,
                CryptoSupport.randomBytes(32)
            );

            if (
                services.putIfAbsent(serviceName, service) != null
            ) {
                throw new KerberosException(
                    "Duplicate service"
                );
            }

            record(
                AuditAction.SERVICE_REGISTERED,
                serviceName,
                serviceName,
                "SUCCESS"
            );
        }

        Ticket authenticateAS(
            String principalName,
            char[] password
        ) {
            Principal principal = principals.get(principalName);

            if (principal == null || !principal.isActive()) {
                record(
                    AuditAction.AUTHENTICATION_REJECTED,
                    principalName,
                    "AS",
                    "UNKNOWN_OR_DISABLED"
                );

                throw new AuthenticationException(
                    "Unknown or disabled principal"
                );
            }

            byte[] candidate = CryptoSupport.derivePasswordKey(
                password,
                principal.salt()
            );

            if (!MessageDigest.isEqual(
                candidate,
                principal.verifier()
            )) {
                record(
                    AuditAction.AUTHENTICATION_REJECTED,
                    principalName,
                    "AS",
                    "INVALID_CREDENTIALS"
                );

                throw new AuthenticationException(
                    "Invalid credentials"
                );
            }

            Instant now = Instant.now();

            String sessionKey = Base64.getEncoder().encodeToString(
                CryptoSupport.randomBytes(32)
            );

            Ticket ticket = issueTicket(
                TicketType.TGT,
                principalName,
                "krbtgt/" + realm,
                sessionKey,
                now,
                now.plus(policy.tgtLifetime()),
                tgsKey
            );

            record(
                AuditAction.TGT_ISSUED,
                principalName,
                "TGS",
                "SUCCESS"
            );

            return ticket;
        }

        private Ticket issueTicket(
            TicketType type,
            String client,
            String service,
            String sessionKey,
            Instant issuedAt,
            Instant expiresAt,
            byte[] signingKey
        ) {
            String id = CryptoSupport.newId();

            String body = String.join(
                "|",
                id,
                type.name(),
                client,
                service,
                realm,
                sessionKey,
                issuedAt.toEpochMilli() + "",
                expiresAt.toEpochMilli() + ""
            );

            String signature = CryptoSupport.hmac(
                body,
                signingKey
            );

            Ticket ticket = new Ticket(
                id,
                type,
                client,
                service,
                realm,
                sessionKey,
                issuedAt,
                expiresAt,
                body,
                signature
            );

            issuedTickets.put(id, ticket);

            return ticket;
        }

        private void verifyTicketSignature(
            Ticket ticket,
            byte[] key
        ) {
            String expected = CryptoSupport.hmac(
                ticket.body(),
                key
            );

            if (!CryptoSupport.constantTimeEquals(
                expected,
                ticket.signature()
            )) {
                throw new TicketException(
                    "Ticket integrity verification failed"
                );
            }
        }

        private void validateLifetime(Ticket ticket) {
            Instant now = Instant.now();

            if (
                !ticket.expiresAt().isAfter(ticket.issuedAt()) ||
                ticket.issuedAt().isAfter(
                    now.plus(policy.clockTolerance())
                )
            ) {
                throw new TicketException(
                    "Invalid ticket timestamps"
                );
            }

            if (!ticket.expiresAt().isAfter(now)) {
                throw new TicketException("Ticket expired");
            }
        }

        Ticket authenticateTGS(
            Ticket tgt,
            String requestedService
        ) {
            ServicePrincipal service = services.get(
                requestedService
            );

            if (service == null) {
                throw new AuthenticationException(
                    "Unknown service principal"
                );
            }

            Ticket stored = issuedTickets.get(tgt.id());

            if (
                stored == null ||
                stored.type() != TicketType.TGT ||
                !stored.body().equals(tgt.body())
            ) {
                throw new TicketException("Unknown TGT");
            }

            verifyTicketSignature(tgt, tgsKey);
            validateLifetime(tgt);

            if (!tgt.realm().equals(realm)) {
                throw new TicketException("Realm mismatch");
            }

            Principal principal = principals.get(tgt.client());

            if (principal == null || !principal.isActive()) {
                throw new AuthenticationException(
                    "Principal disabled or unknown"
                );
            }

            Instant now = Instant.now();

            String serviceSessionKey =
                Base64.getEncoder().encodeToString(
                    CryptoSupport.randomBytes(32)
                );

            Instant expiry = now.plus(
                policy.serviceLifetime()
            );

            if (tgt.expiresAt().isBefore(expiry)) {
                expiry = tgt.expiresAt();
            }

            Ticket serviceTicket = issueTicket(
                TicketType.SERVICE,
                tgt.client(),
                requestedService,
                serviceSessionKey,
                now,
                expiry,
                service.key()
            );

            record(
                AuditAction.SERVICE_TICKET_ISSUED,
                tgt.client(),
                requestedService,
                "SUCCESS"
            );

            return serviceTicket;
        }

        String authenticateService(
            Ticket ticket,
            String requestedService,
            Authenticator authenticator
        ) {
            ServicePrincipal service = services.get(
                requestedService
            );

            if (service == null) {
                throw new AuthenticationException(
                    "Unknown service"
                );
            }

            Ticket stored = issuedTickets.get(ticket.id());

            if (
                stored == null ||
                !stored.body().equals(ticket.body()) ||
                stored.type() != TicketType.SERVICE
            ) {
                throw new TicketException(
                    "Unrecognized service ticket"
                );
            }

            verifyTicketSignature(ticket, service.key());
            validateLifetime(ticket);

            if (
                !ticket.service().equals(requestedService) ||
                !ticket.client().equals(authenticator.client())
            ) {
                throw new AuthenticationException(
                    "Service or client mismatch"
                );
            }

            Instant now = Instant.now();

            Duration drift = Duration.between(
                authenticator.timestamp(),
                now
            ).abs();

            if (drift.compareTo(policy.clockTolerance()) > 0) {
                throw new AuthenticationException(
                    "Authenticator timestamp rejected"
                );
            }

            byte[] sessionKey = Base64.getDecoder().decode(
                ticket.sessionKey()
            );

            String message = String.join(
                "|",
                authenticator.client(),
                requestedService,
                authenticator.timestamp().toEpochMilli() + "",
                authenticator.nonce()
            );

            String expected = CryptoSupport.hmac(
                message,
                sessionKey
            );

            if (!CryptoSupport.constantTimeEquals(
                expected,
                authenticator.signature()
            )) {
                throw new AuthenticationException(
                    "Invalid authenticator"
                );
            }

            replayCache.accept(
                ticket.id() + ":" + authenticator.nonce(),
                ticket.expiresAt(),
                now
            );

            record(
                AuditAction.SERVICE_ACCESS_GRANTED,
                ticket.client(),
                requestedService,
                "SUCCESS"
            );

            // AP-REP-style educational proof of service identity.
            return CryptoSupport.hmac(
                "SERVER|" + message,
                sessionKey
            );
        }

        boolean verifyServerProof(
            Ticket ticket,
            Authenticator authenticator,
            String proof
        ) {
            byte[] key = Base64.getDecoder().decode(
                ticket.sessionKey()
            );

            String message = String.join(
                "|",
                authenticator.client(),
                ticket.service(),
                authenticator.timestamp().toEpochMilli() + "",
                authenticator.nonce()
            );

            String expected = CryptoSupport.hmac(
                "SERVER|" + message,
                key
            );

            return CryptoSupport.constantTimeEquals(
                expected,
                proof
            );
        }

        Authenticator createAuthenticator(
            Ticket ticket,
            String client
        ) {
            Instant timestamp = Instant.now();
            String nonce = CryptoSupport.newId();

            String message = String.join(
                "|",
                client,
                ticket.service(),
                timestamp.toEpochMilli() + "",
                nonce
            );

            String signature = CryptoSupport.hmac(
                message,
                Base64.getDecoder().decode(ticket.sessionKey())
            );

            return new Authenticator(
                client,
                timestamp,
                nonce,
                signature
            );
        }

        void disablePrincipal(String name) {
            Principal principal = principals.get(name);

            if (principal == null) {
                throw new AuthenticationException(
                    "Unknown principal"
                );
            }

            principal.disable();

            record(
                AuditAction.PRINCIPAL_DISABLED,
                name,
                "KDC",
                "SUCCESS"
            );
        }

        List<AuditRecord> auditReport() {
            synchronized (audit) {
                return List.copyOf(audit);
            }
        }

        int principalCount() {
            return principals.size();
        }

        int serviceCount() {
            return services.size();
        }

        int replayCacheSize() {
            return replayCache.size();
        }
    }

    static final class AuthenticationSession {
        private final String principal;
        private final KeyDistributionCenter kdc;

        private final AtomicReference<SessionState> state =
            new AtomicReference<>(SessionState.CREATED);

        private Ticket tgt;

        AuthenticationSession(
            String principal,
            KeyDistributionCenter kdc
        ) {
            this.principal = principal;
            this.kdc = kdc;
        }

        void login(char[] password) {
            if (state.get() != SessionState.CREATED) {
                throw new KerberosException(
                    "Invalid session transition"
                );
            }

            try {
                tgt = kdc.authenticateAS(principal, password);
                state.set(SessionState.AUTHENTICATED);
            } catch (KerberosException exception) {
                state.set(SessionState.REJECTED);
                throw exception;
            }
        }

        boolean access(String serviceName) {
            if (state.get() != SessionState.AUTHENTICATED) {
                throw new KerberosException(
                    "Authentication required"
                );
            }

            Ticket serviceTicket = kdc.authenticateTGS(
                tgt,
                serviceName
            );

            Authenticator authenticator = kdc.createAuthenticator(
                serviceTicket,
                principal
            );

            String proof = kdc.authenticateService(
                serviceTicket,
                serviceName,
                authenticator
            );

            if (!kdc.verifyServerProof(
                serviceTicket,
                authenticator,
                proof
            )) {
                throw new AuthenticationException(
                    "Mutual authentication failed"
                );
            }

            state.set(SessionState.SERVICE_AUTHENTICATED);

            return true;
        }

        SessionState state() {
            return state.get();
        }
    }

    public static void main(String[] args) {

        System.out.println("KERBEROS ENTERPRISE AUTHENTICATION");
        System.out.println("==================================");

        KeyDistributionCenter kdc = new KeyDistributionCenter(
            "EXAMPLE.LOCAL",
            TicketPolicy.standard()
        );

        String user = "alice@EXAMPLE.LOCAL";

        char[] password = "StrongPassword2026!".toCharArray();

        kdc.registerPrincipal(
            user,
            password,
            Set.of("developer", "employee")
        );

        kdc.registerService("http/web.example.local");
        kdc.registerService("postgres/db.example.local");

        AuthenticationSession session =
            new AuthenticationSession(user, kdc);

        System.out.println("\n1. Authentication Server");

        session.login(password);

        System.out.println("TGT issued");
        System.out.println("State: " + session.state());

        System.out.println("\n2. Ticket Granting Server");

        boolean web = session.access(
            "http/web.example.local"
        );

        System.out.println("Web access: " + web);

        System.out.println("\n3. Database authentication");

        boolean database = session.access(
            "postgres/db.example.local"
        );

        System.out.println("Database access: " + database);

        System.out.println("\n4. Invalid credential test");

        try {
            kdc.authenticateAS(
                user,
                "IncorrectPassword".toCharArray()
            );
        } catch (AuthenticationException exception) {
            System.out.println(
                "Rejected: " + exception.getMessage()
            );
        }

        System.out.println("\n5. Principal and service inventory");

        System.out.println(
            "Principals: " + kdc.principalCount()
        );

        System.out.println(
            "Services: " + kdc.serviceCount()
        );

        System.out.println("\n6. Audit records");

        for (AuditRecord record : kdc.auditReport()) {
            System.out.printf(
                "%-28s %-32s %s%n",
                record.action(),
                record.principal(),
                record.result()
            );
        }

        System.out.println(
            "\nReplay cache entries: " + kdc.replayCacheSize()
        );

        System.out.println("\nEnterprise authentication completed.");
    }
}
