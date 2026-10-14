import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/*
 * Windows authentication enterprise domain model.
 *
 * Compile and run:
 *   javac WindowsAuthenticationEnterprise.java
 *   java WindowsAuthenticationEnterprise
 *
 * This program models authentication flows and policy decisions. It
 * does not connect to Windows LSA, SAM, NTLM, Active Directory, or KDCs.
 * Cryptographic proofs and tickets are educational simulations.
 */
public class WindowsAuthenticationEnterprise {

    enum AccountType {
        LOCAL,
        DOMAIN,
        SERVICE
    }

    enum AuthenticationProtocol {
        LOCAL,
        NTLM_CONCEPT,
        KERBEROS_CONCEPT
    }

    enum LogonType {
        INTERACTIVE,
        NETWORK,
        SERVICE
    }

    enum AccountStatus {
        ENABLED,
        DISABLED,
        LOCKED
    }

    static final class AuthenticationException extends Exception {
        AuthenticationException(String message) {
            super(message);
        }
    }

    static final class AuthorizationException extends Exception {
        AuthorizationException(String message) {
            super(message);
        }
    }

    record Principal(String username, String domain, AccountType type) {
        Principal {
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException(
                    "Username cannot be blank."
                );
            }
            Objects.requireNonNull(type, "Account type is required.");

            if (type == AccountType.DOMAIN && (
                domain == null || domain.isBlank()
            )) {
                throw new IllegalArgumentException(
                    "Domain accounts require a domain."
                );
            }
            if (type == AccountType.LOCAL && domain != null) {
                throw new IllegalArgumentException(
                    "Local accounts cannot have a domain."
                );
            }

            username = username.toLowerCase();
            domain = domain == null ? null : domain.toUpperCase();
        }

        String qualifiedName() {
            return type == AccountType.LOCAL
                ? "LOCALHOST\\" + username
                : domain + "\\" + username;
        }

        String kerberosName() {
            if (type != AccountType.DOMAIN) {
                throw new IllegalStateException(
                    "A domain principal is required."
                );
            }
            return username + "@" + domain;
        }
    }

    static final class Account {
        private final Principal principal;
        private final Set<String> groups;
        private byte[] salt;
        private byte[] passwordVerifier;
        private AccountStatus status = AccountStatus.ENABLED;
        private int failedAttempts;

        Account(Principal principal, String password, Set<String> groups) {
            this.principal = Objects.requireNonNull(principal);
            this.groups = Set.copyOf(groups);
            setPassword(password);
        }

        Principal principal() {
            return principal;
        }

        Set<String> groups() {
            return groups;
        }

        AccountStatus status() {
            return status;
        }

        void setStatus(AccountStatus status) {
            this.status = Objects.requireNonNull(status);
        }

        void setPassword(String password) {
            if (password == null || password.isEmpty()) {
                throw new IllegalArgumentException(
                    "Password cannot be empty."
                );
            }

            // SHA-256 with a random salt is used only to keep the
            // example dependency-free. Production systems require
            // an appropriate password-hashing design and key handling.
            this.salt = randomBytes(16);
            this.passwordVerifier = digest(
                combine(
                    salt,
                    password.getBytes(StandardCharsets.UTF_8)
                )
            );
        }

        boolean verifyPassword(String password) {
            if (password == null) {
                return false;
            }
            byte[] candidate = digest(
                combine(
                    salt,
                    password.getBytes(StandardCharsets.UTF_8)
                )
            );
            return MessageDigest.isEqual(
                candidate, passwordVerifier
            );
        }

        void recordFailure(int lockoutThreshold) {
            failedAttempts++;
            if (failedAttempts >= lockoutThreshold) {
                status = AccountStatus.LOCKED;
            }
        }

        void recordSuccess() {
            failedAttempts = 0;
        }
    }

    record AuthenticatedSession(
        Principal principal,
        AuthenticationProtocol protocol,
        LogonType logonType,
        Set<String> groups,
        UUID sessionId
    ) {
        AuthenticatedSession {
            Objects.requireNonNull(principal);
            Objects.requireNonNull(protocol);
            Objects.requireNonNull(logonType);
            groups = Collections.unmodifiableSet(new HashSet<>(groups));
            Objects.requireNonNull(sessionId);
        }
    }

    record AuditEvent(
        long timestampMillis,
        String action,
        String principal,
        String result,
        String details
    ) {}

    static final class AuditService {
        private final List<AuditEvent> events = new ArrayList<>();

        void record(
            String action,
            String principal,
            String result,
            String details
        ) {
            // Credentials, proof values, and ticket keys are never logged.
            events.add(new AuditEvent(
                System.currentTimeMillis(),
                action,
                principal,
                result,
                details
            ));
        }

        List<AuditEvent> events() {
            return List.copyOf(events);
        }
    }

    static final class AccountRepository {
        private final Map<String, Account> accounts = new HashMap<>();

        void register(Account account) {
            String key = key(account.principal());
            if (accounts.putIfAbsent(key, account) != null) {
                throw new IllegalArgumentException(
                    "Duplicate principal: " + key
                );
            }
        }

        Account find(Principal principal)
            throws AuthenticationException {
            Account account = accounts.get(key(principal));
            if (account == null) {
                throw new AuthenticationException("Unknown principal.");
            }
            return account;
        }

        private static String key(Principal principal) {
            return principal.qualifiedName().toUpperCase();
        }
    }

    static final class SessionService {
        AuthenticatedSession create(
            Account account,
            AuthenticationProtocol protocol,
            LogonType logonType
        ) throws AuthenticationException {
            if (account.status() != AccountStatus.ENABLED) {
                throw new AuthenticationException(
                    "Account is disabled or locked."
                );
            }

            return new AuthenticatedSession(
                account.principal(),
                protocol,
                logonType,
                account.groups(),
                UUID.randomUUID()
            );
        }
    }

    static final class LocalLogonService {
        private final AccountRepository accounts;
        private final SessionService sessions;
        private final AuditService audit;
        private final int lockoutThreshold;

        LocalLogonService(
            AccountRepository accounts,
            SessionService sessions,
            AuditService audit,
            int lockoutThreshold
        ) {
            if (lockoutThreshold < 1) {
                throw new IllegalArgumentException(
                    "Lockout threshold must be positive."
                );
            }
            this.accounts = accounts;
            this.sessions = sessions;
            this.audit = audit;
            this.lockoutThreshold = lockoutThreshold;
        }

        AuthenticatedSession authenticate(
            Principal principal,
            String password
        ) throws AuthenticationException {
            if (principal.type() != AccountType.LOCAL) {
                throw new AuthenticationException(
                    "Local logon requires a local account."
                );
            }

            Account account = accounts.find(principal);
            if (account.status() != AccountStatus.ENABLED) {
                throw new AuthenticationException(
                    "Account is unavailable."
                );
            }

            if (!account.verifyPassword(password)) {
                account.recordFailure(lockoutThreshold);
                audit.record(
                    "local-logon",
                    principal.qualifiedName(),
                    "denied",
                    "Invalid credentials"
                );
                throw new AuthenticationException(
                    "Invalid local credentials."
                );
            }

            account.recordSuccess();
            AuthenticatedSession session = sessions.create(
                account,
                AuthenticationProtocol.LOCAL,
                LogonType.INTERACTIVE
            );
            audit.record(
                "local-logon",
                principal.qualifiedName(),
                "accepted",
                "Local interactive session created"
            );
            return session;
        }
    }

    record Challenge(
        UUID id,
        String server,
        byte[] nonce,
        long issuedAtMillis
    ) {}

    static final class NtlmChallengeService {
        private final AccountRepository accounts;
        private final SessionService sessions;
        private final AuditService audit;
        private final Map<UUID, Challenge> challenges = new HashMap<>();
        private final long lifetimeMillis = 60_000L;

        NtlmChallengeService(
            AccountRepository accounts,
            SessionService sessions,
            AuditService audit
        ) {
            this.accounts = accounts;
            this.sessions = sessions;
            this.audit = audit;
        }

        Challenge issue(String server) {
            if (server == null || server.isBlank()) {
                throw new IllegalArgumentException(
                    "Server name is required."
                );
            }

            Challenge challenge = new Challenge(
                UUID.randomUUID(),
                server,
                randomBytes(32),
                System.currentTimeMillis()
            );
            challenges.put(challenge.id(), challenge);
            return challenge;
        }

        byte[] demonstrationResponse(
            Challenge challenge,
            String username,
            String domain,
            String password
        ) {
            /*
             * This digest is a deliberately simplified demonstration,
             * not an NTLM response or a replacement for its algorithms.
             */
            String message = challenge.server() + "|"
                + username.toLowerCase() + "|"
                + domain.toUpperCase() + "|"
                + bytesToHex(challenge.nonce()) + "|"
                + password;

            return digest(message.getBytes(StandardCharsets.UTF_8));
        }

        AuthenticatedSession authenticate(
            Principal principal,
            Challenge suppliedChallenge,
            byte[] suppliedResponse,
            String password
        ) throws AuthenticationException {
            Challenge stored = challenges.remove(suppliedChallenge.id());

            if (stored == null) {
                throw new AuthenticationException(
                    "Challenge is missing or already consumed."
                );
            }
            if (System.currentTimeMillis() - stored.issuedAtMillis()
                > lifetimeMillis) {
                throw new AuthenticationException("Challenge expired.");
            }
            if (principal.type() != AccountType.DOMAIN) {
                throw new AuthenticationException(
                    "A domain principal is required."
                );
            }

            Account account = accounts.find(principal);
            if (account.status() != AccountStatus.ENABLED) {
                throw new AuthenticationException(
                    "Account is unavailable."
                );
            }

            // The password is supplied solely because this simulator
            // does not maintain a real NTLM-compatible verifier.
            byte[] expected = demonstrationResponse(
                stored,
                principal.username(),
                principal.domain(),
                password
            );

            if (!MessageDigest.isEqual(expected, suppliedResponse)) {
                audit.record(
                    "ntlm-concept",
                    principal.qualifiedName(),
                    "denied",
                    "Challenge-response mismatch"
                );
                throw new AuthenticationException(
                    "Invalid challenge response."
                );
            }

            AuthenticatedSession session = sessions.create(
                account,
                AuthenticationProtocol.NTLM_CONCEPT,
                LogonType.NETWORK
            );
            audit.record(
                "ntlm-concept",
                principal.qualifiedName(),
                "accepted",
                "Synthetic challenge consumed"
            );
            return session;
        }
    }

    record Ticket(
        UUID id,
        String client,
        String service,
        String kind,
        long expiresAtMillis
    ) {}

    static final class KerberosTicketService {
        private final AccountRepository accounts;
        private final SessionService sessions;
        private final AuditService audit;
        private final Map<UUID, Ticket> tickets = new HashMap<>();
        private final long lifetimeMillis = 300_000L;

        KerberosTicketService(
            AccountRepository accounts,
            SessionService sessions,
            AuditService audit
        ) {
            this.accounts = accounts;
            this.sessions = sessions;
            this.audit = audit;
        }

        Ticket requestTgt(
            Principal principal,
            String password
        ) throws AuthenticationException {
            if (principal.type() != AccountType.DOMAIN) {
                throw new AuthenticationException(
                    "Kerberos initial authentication requires a domain account."
                );
            }

            Account account = accounts.find(principal);
            if (account.status() != AccountStatus.ENABLED) {
                throw new AuthenticationException(
                    "Account is unavailable."
                );
            }
            if (!account.verifyPassword(password)) {
                audit.record(
                    "kerberos-as",
                    principal.qualifiedName(),
                    "denied",
                    "Initial credential verification failed"
                );
                throw new AuthenticationException(
                    "Invalid initial credentials."
                );
            }

            Ticket tgt = new Ticket(
                UUID.randomUUID(),
                principal.kerberosName(),
                "krbtgt/" + principal.domain(),
                "TGT",
                System.currentTimeMillis() + lifetimeMillis
            );
            tickets.put(tgt.id(), tgt);
            audit.record(
                "kerberos-as",
                principal.qualifiedName(),
                "accepted",
                "Synthetic TGT issued"
            );
            return tgt;
        }

        Ticket requestServiceTicket(
            UUID tgtId,
            String servicePrincipal
        ) throws AuthenticationException {
            Ticket tgt = tickets.get(tgtId);
            if (tgt == null || !tgt.kind().equals("TGT")) {
                throw new AuthenticationException("Valid TGT required.");
            }
            if (System.currentTimeMillis() >= tgt.expiresAtMillis()) {
                throw new AuthenticationException("TGT expired.");
            }
            if (servicePrincipal == null ||
                !servicePrincipal.matches(
                    "[A-Za-z0-9-]+/[A-Za-z0-9.-]+"
                )) {
                throw new AuthenticationException(
                    "Malformed service principal."
                );
            }

            Ticket serviceTicket = new Ticket(
                UUID.randomUUID(),
                tgt.client(),
                servicePrincipal,
                "SERVICE",
                Math.min(
                    tgt.expiresAtMillis(),
                    System.currentTimeMillis() + lifetimeMillis
                )
            );
            tickets.put(serviceTicket.id(), serviceTicket);
            audit.record(
                "kerberos-tgs",
                tgt.client(),
                "accepted",
                "Service ticket issued for " + servicePrincipal
            );
            return serviceTicket;
        }

        AuthenticatedSession accept(
            UUID ticketId,
            String expectedService
        ) throws AuthenticationException {
            Ticket ticket = tickets.get(ticketId);
            if (ticket == null || !ticket.kind().equals("SERVICE")) {
                throw new AuthenticationException(
                    "Service ticket required."
                );
            }
            if (System.currentTimeMillis() >= ticket.expiresAtMillis()) {
                throw new AuthenticationException(
                    "Service ticket expired."
                );
            }
            if (!ticket.service().equals(expectedService)) {
                throw new AuthenticationException(
                    "Ticket targets another service."
                );
            }

            String[] identity = ticket.client().split("@", 2);
            if (identity.length != 2) {
                throw new AuthenticationException(
                    "Malformed client principal."
                );
            }

            Principal principal = new Principal(
                identity[0],
                identity[1],
                AccountType.DOMAIN
            );
            Account account = accounts.find(principal);
            AuthenticatedSession session = sessions.create(
                account,
                AuthenticationProtocol.KERBEROS_CONCEPT,
                LogonType.NETWORK
            );
            audit.record(
                "kerberos-service",
                principal.qualifiedName(),
                "accepted",
                "Service ticket validated"
            );
            return session;
        }
    }

    static final class AuthorizationService {
        private final Map<String, Set<String>> permissions = new HashMap<>();

        void grant(String group, String resource) {
            permissions.computeIfAbsent(
                group, ignored -> new HashSet<>()
            ).add(resource);
        }

        void authorize(
            AuthenticatedSession session,
            String resource
        ) throws AuthorizationException {
            boolean allowed = session.groups().stream().anyMatch(
                group -> permissions.getOrDefault(
                    group, Collections.emptySet()
                ).contains(resource)
            );

            if (!allowed) {
                throw new AuthorizationException(
                    session.principal().qualifiedName()
                    + " lacks access to " + resource
                );
            }
        }
    }

    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] digest(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(
                "SHA-256 is unavailable.", exception
            );
        }
    }

    private static byte[] combine(byte[] left, byte[] right) {
        byte[] result = new byte[left.length + right.length];
        System.arraycopy(left, 0, result, 0, left.length);
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte value : bytes) {
            result.append(String.format("%02x", value));
        }
        return result.toString();
    }

    public static void main(String[] args) throws Exception {
        AccountRepository accounts = new AccountRepository();

        Principal localPrincipal = new Principal(
            "helpdesk", null, AccountType.LOCAL
        );
        Principal domainPrincipal = new Principal(
            "alex", "CORP.EXAMPLE", AccountType.DOMAIN
        );

        accounts.register(new Account(
            localPrincipal,
            "LocalPass!2026",
            Set.of("Users", "IT Support")
        ));
        accounts.register(new Account(
            domainPrincipal,
            "DomainPass!2026",
            Set.of("Domain Users")
        ));

        AuditService audit = new AuditService();
        SessionService sessions = new SessionService();

        System.out.println("=== Local account authentication ===");
        LocalLogonService localService = new LocalLogonService(
            accounts, sessions, audit, 3
        );
        AuthenticatedSession local = localService.authenticate(
            localPrincipal, "LocalPass!2026"
        );
        System.out.println(
            local.principal().qualifiedName() + " -> " + local.protocol()
        );

        System.out.println("\n=== NTLM challenge-response concept ===");
        NtlmChallengeService ntlm = new NtlmChallengeService(
            accounts, sessions, audit
        );
        Challenge challenge = ntlm.issue("fileserver.corp.example");
        byte[] response = ntlm.demonstrationResponse(
            challenge, "alex", "CORP.EXAMPLE", "DomainPass!2026"
        );
        AuthenticatedSession ntlmSession = ntlm.authenticate(
            domainPrincipal, challenge, response, "DomainPass!2026"
        );
        System.out.println(
            ntlmSession.principal().qualifiedName()
            + " -> " + ntlmSession.protocol()
        );

        System.out.println("\n=== Kerberos ticket concept ===");
        KerberosTicketService kerberos = new KerberosTicketService(
            accounts, sessions, audit
        );
        Ticket tgt = kerberos.requestTgt(
            domainPrincipal, "DomainPass!2026"
        );
        Ticket serviceTicket = kerberos.requestServiceTicket(
            tgt.id(), "HTTP/intranet.corp.example"
        );
        AuthenticatedSession kerberosSession = kerberos.accept(
            serviceTicket.id(), "HTTP/intranet.corp.example"
        );
        System.out.println(
            kerberosSession.principal().qualifiedName()
            + " -> " + kerberosSession.protocol()
        );

        System.out.println("\n=== Resource authorization ===");
        AuthorizationService authorization = new AuthorizationService();
        authorization.grant("IT Support", "password-reset");
        authorization.grant("Domain Users", "intranet.read");

        for (Map.Entry<AuthenticatedSession, String> request : Map.of(
            local, "password-reset",
            kerberosSession, "intranet.read"
        ).entrySet()) {
            authorization.authorize(request.getKey(), request.getValue());
            System.out.println(
                "GRANTED " + request.getKey().principal().qualifiedName()
                + " -> " + request.getValue()
            );
        }

        try {
            authorization.authorize(
                kerberosSession, "payroll.admin"
            );
        } catch (AuthorizationException exception) {
            System.out.println("DENIED " + exception.getMessage());
        }

        System.out.println("\n=== Authentication audit ===");
        for (AuditEvent event : audit.events()) {
            System.out.println(
                event.action() + " | "
                + event.principal() + " | "
                + event.result() + " | "
                + event.details()
            );
        }

        System.out.println(
            "\nSynthetic protocol model only; not a Windows authentication client."
        );
    }
}
