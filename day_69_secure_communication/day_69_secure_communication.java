import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Secure Communications Enterprise Laboratory.
 *
 * Java 17 implementation:
 * - HTTPS and TLS
 * - SSH remote access through OpenSSH
 * - SFTP secure file transfer
 * - VPN configuration and routing validation
 * - Enterprise security policies
 * - Communication lifecycle management
 * - Audit events and transfer integrity
 *
 * No third-party dependencies.
 */
public class SecureCommunications {

    enum Protocol {
        SSH, HTTPS, VPN, SFTP
    }

    enum State {
        DISCONNECTED, CONNECTING, CONNECTED, FAILED
    }

    enum EventType {
        REGISTERED, STATE_CHANGED, SECURITY_VIOLATION,
        TRANSFER_COMPLETED
    }

    static class SecurityException extends RuntimeException {
        SecurityException(String message) {
            super(message);
        }

        SecurityException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    record SecurityPolicy(
        String minimumTLS,
        boolean verifyCertificates,
        boolean verifyHostname,
        boolean strictSSHHostChecking,
        boolean disableAgentForwarding,
        long maximumFileSize,
        Duration connectionTimeout
    ) {
        SecurityPolicy {
            if (!"TLSv1.2".equals(minimumTLS) &&
                !"TLSv1.3".equals(minimumTLS)) {
                throw new SecurityException("Unsupported TLS version.");
            }

            if (!verifyCertificates || !verifyHostname) {
                throw new SecurityException(
                    "TLS certificate and hostname validation are mandatory."
                );
            }

            if (!strictSSHHostChecking || !disableAgentForwarding) {
                throw new SecurityException(
                    "Secure SSH configuration is mandatory."
                );
            }

            if (maximumFileSize <= 0 ||
                connectionTimeout.isZero() ||
                connectionTimeout.isNegative()) {
                throw new SecurityException("Invalid security limits.");
            }
        }

        static SecurityPolicy enterpriseDefault() {
            return new SecurityPolicy(
                "TLSv1.2",
                true,
                true,
                true,
                true,
                50L * 1024 * 1024,
                Duration.ofSeconds(10)
            );
        }
    }

    record Endpoint(
        String hostname,
        int port,
        Protocol protocol
    ) {
        Endpoint {
            if (hostname == null ||
                !Pattern.matches(
                    "[A-Za-z0-9][A-Za-z0-9.-]{0,252}",
                    hostname
                )) {
                throw new SecurityException("Invalid hostname.");
            }

            if (port < 1 || port > 65535) {
                throw new SecurityException("Invalid port.");
            }

            if (protocol == null) {
                throw new SecurityException("Protocol is required.");
            }
        }
    }

    record AuditEvent(
        Instant timestamp,
        EventType type,
        String sessionId,
        String description
    ) {}

    interface SecurityEventListener {
        void onEvent(AuditEvent event);
    }

    static class AuditService {
        private final List<AuditEvent> events = new ArrayList<>();
        private final List<SecurityEventListener> listeners =
            new ArrayList<>();

        void subscribe(SecurityEventListener listener) {
            listeners.add(listener);
        }

        void publish(AuditEvent event) {
            events.add(event);

            for (SecurityEventListener listener : listeners) {
                listener.onEvent(event);
            }
        }

        List<AuditEvent> getEvents() {
            return Collections.unmodifiableList(events);
        }
    }

    static class CommunicationSession {
        private final String id;
        private final Endpoint endpoint;
        private State state;

        CommunicationSession(String id, Endpoint endpoint) {
            if (id == null || id.isBlank()) {
                throw new SecurityException("Session ID is required.");
            }

            this.id = id;
            this.endpoint = endpoint;
            this.state = State.DISCONNECTED;
        }

        String id() {
            return id;
        }

        Endpoint endpoint() {
            return endpoint;
        }

        State state() {
            return state;
        }

        void setState(State next) {
            Map<State, Set<State>> transitions =
                new EnumMap<>(State.class);

            transitions.put(
                State.DISCONNECTED,
                Set.of(State.CONNECTING)
            );

            transitions.put(
                State.CONNECTING,
                Set.of(State.CONNECTED, State.FAILED)
            );

            transitions.put(
                State.CONNECTED,
                Set.of(State.DISCONNECTED, State.FAILED)
            );

            transitions.put(
                State.FAILED,
                Set.of(State.DISCONNECTED)
            );

            if (!transitions.get(state).contains(next)) {
                throw new SecurityException(
                    "Invalid state transition: " + state + " -> " + next
                );
            }

            state = next;
        }
    }

    static class CommunicationService {
        private final Map<String, CommunicationSession> sessions =
            new HashMap<>();

        private final AuditService audit;

        CommunicationService(AuditService audit) {
            this.audit = audit;
        }

        void register(String id, Endpoint endpoint) {
            if (sessions.containsKey(id)) {
                throw new SecurityException("Duplicate session ID.");
            }

            CommunicationSession session =
                new CommunicationSession(id, endpoint);

            sessions.put(id, session);

            audit.publish(new AuditEvent(
                Instant.now(),
                EventType.REGISTERED,
                id,
                "Communication session registered."
            ));
        }

        void transition(String id, State next) {
            CommunicationSession session = sessions.get(id);

            if (session == null) {
                throw new SecurityException("Unknown session.");
            }

            State previous = session.state();
            session.setState(next);

            audit.publish(new AuditEvent(
                Instant.now(),
                EventType.STATE_CHANGED,
                id,
                previous + " -> " + next
            ));
        }

        List<CommunicationSession> activeSessions() {
            return sessions.values()
                .stream()
                .filter(s -> s.state() == State.CONNECTED)
                .toList();
        }
    }

    static class TLSService {
        private final SecurityPolicy policy;
        private final HttpClient client;

        TLSService(SecurityPolicy policy) {
            this.policy = policy;

            try {
                SSLContext context = SSLContext.getInstance("TLS");
                context.init(
                    null,
                    null,
                    new java.security.SecureRandom()
                );

                SSLParameters parameters = new SSLParameters();

                parameters.setProtocols(
                    policy.minimumTLS().equals("TLSv1.3")
                        ? new String[]{"TLSv1.3"}
                        : new String[]{"TLSv1.3", "TLSv1.2"}
                );

                parameters.setEndpointIdentificationAlgorithm("HTTPS");

                client = HttpClient.newBuilder()
                    .sslContext(context)
                    .sslParameters(parameters)
                    .connectTimeout(policy.connectionTimeout())
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .version(HttpClient.Version.HTTP_2)
                    .build();

            } catch (Exception e) {
                throw new SecurityException(
                    "Cannot initialize TLS client.",
                    e
                );
            }
        }

        CompletableFuture<HttpResponse<String>> get(String address) {
            URI uri = URI.create(address);

            if (!"https".equalsIgnoreCase(uri.getScheme()) ||
                uri.getHost() == null ||
                uri.getUserInfo() != null) {
                throw new SecurityException("Invalid HTTPS destination.");
            }

            HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(policy.connectionTimeout())
                .header("User-Agent", "SecureCommunicationsLab/1.0")
                .GET()
                .build();

            return client.sendAsync(
                request,
                HttpResponse.BodyHandlers.ofString()
            );
        }
    }

    static class SSHService {
        private final Path knownHosts;
        private final Path identityFile;
        private final SecurityPolicy policy;

        SSHService(
            Path knownHosts,
            Path identityFile,
            SecurityPolicy policy
        ) {
            this.knownHosts = knownHosts.toAbsolutePath().normalize();
            this.identityFile = identityFile == null
                ? null
                : identityFile.toAbsolutePath().normalize();

            this.policy = policy;

            if (!Files.isRegularFile(this.knownHosts)) {
                throw new SecurityException(
                    "SSH known_hosts file is required."
                );
            }

            if (this.identityFile != null &&
                !Files.isRegularFile(this.identityFile)) {
                throw new SecurityException("Invalid SSH identity file.");
            }
        }

        private void validate(String username, String host) {
            if (!Pattern.matches(
                "[A-Za-z_][A-Za-z0-9_.-]{0,31}",
                username
            )) {
                throw new SecurityException("Invalid SSH username.");
            }

            if (!Pattern.matches(
                "[A-Za-z0-9][A-Za-z0-9.-]{0,252}",
                host
            )) {
                throw new SecurityException("Invalid SSH hostname.");
            }
        }

        private List<String> baseArguments() {
            List<String> args = new ArrayList<>(List.of(
                "ssh",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "IdentitiesOnly=yes",
                "-o", "ConnectTimeout=10",
                "-o", "ForwardAgent=no",
                "-o", "UserKnownHostsFile=" + knownHosts
            ));

            if (identityFile != null) {
                args.add("-i");
                args.add(identityFile.toString());
            }

            return args;
        }

        ProcessResult execute(List<String> command, Duration timeout) {
            try {
                ProcessBuilder builder = new ProcessBuilder(command);
                builder.redirectErrorStream(true);

                Process process = builder.start();

                boolean completed = process.waitFor(
                    timeout.toMillis(),
                    TimeUnit.MILLISECONDS
                );

                if (!completed) {
                    process.destroyForcibly();
                    throw new SecurityException("SSH process timed out.");
                }

                String output = new String(
                    process.getInputStream().readAllBytes(),
                    java.nio.charset.StandardCharsets.UTF_8
                );

                if (process.exitValue() != 0) {
                    throw new SecurityException(
                        "OpenSSH command failed: " + output
                    );
                }

                return new ProcessResult(process.exitValue(), output);

            } catch (IOException e) {
                throw new SecurityException("Cannot execute OpenSSH.", e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new SecurityException("SSH execution interrupted.", e);
            }
        }

        ProcessResult connect(
            String username,
            String host,
            String remoteCommand
        ) {
            validate(username, host);

            if (remoteCommand == null ||
                remoteCommand.isBlank() ||
                remoteCommand.contains("\n") ||
                remoteCommand.contains("\r")) {
                throw new SecurityException("Invalid remote command.");
            }

            List<String> command = baseArguments();

            command.addAll(List.of(
                username + "@" + host,
                remoteCommand
            ));

            return execute(command, Duration.ofSeconds(30));
        }

        ProcessResult upload(
            Path localFile,
            String username,
            String host,
            String remotePath
        ) {
            validate(username, host);

            Path source = localFile.toAbsolutePath().normalize();

            try {
                if (!Files.isRegularFile(source) ||
                    Files.isSymbolicLink(source)) {
                    throw new SecurityException(
                        "A regular local file is required."
                    );
                }

                long size = Files.size(source);

                if (size > policy.maximumFileSize()) {
                    throw new SecurityException(
                        "File exceeds configured transfer limit."
                    );
                }

                if (remotePath == null ||
                    !remotePath.startsWith("/") ||
                    remotePath.matches(".*[\\s\"'\\\\\\r\\n].*") ||
                    remotePath.endsWith("/") ||
                    List.of(remotePath.split("/")).contains("..") ||
                    List.of(remotePath.split("/")).contains(".")) {
                    throw new SecurityException("Unsafe remote path.");
                }

                Path batch = Files.createTempFile(
                    "secure-sftp-",
                    ".batch"
                );

                try {
                    Files.writeString(
                        batch,
                        "put \"" + source + "\" \"" + remotePath + "\"\n" +
                        "ls \"" + remotePath + "\"\n" +
                        "bye\n",
                        StandardOpenOption.TRUNCATE_EXISTING
                    );

                    List<String> command = new ArrayList<>();
                    command.add("sftp");
                    command.add("-b");
                    command.add(batch.toString());

                    List<String> options = baseArguments();
                    command.addAll(options.subList(1, options.size()));

                    command.add(username + "@" + host);

                    return execute(command, Duration.ofMinutes(2));

                } finally {
                    Files.deleteIfExists(batch);
                }

            } catch (IOException e) {
                throw new SecurityException("SFTP file operation failed.", e);
            }
        }
    }

    record ProcessResult(int exitCode, String output) {}

    record VPNProfile(
        String interfaceName,
        String endpoint,
        int port,
        List<String> allowedNetworks,
        String protocol
    ) {
        VPNProfile {
            if (interfaceName == null ||
                !Pattern.matches("[A-Za-z0-9_.-]{1,15}", interfaceName)) {
                throw new SecurityException("Invalid VPN interface.");
            }

            if (endpoint == null || endpoint.isBlank()) {
                throw new SecurityException("VPN endpoint is required.");
            }

            if (port < 1 || port > 65535) {
                throw new SecurityException("Invalid VPN port.");
            }

            if (!protocol.equals("WireGuard") &&
                !protocol.equals("IPsec")) {
                throw new SecurityException("Unsupported VPN protocol.");
            }

            if (allowedNetworks == null || allowedNetworks.isEmpty()) {
                throw new SecurityException("VPN routes are required.");
            }

            allowedNetworks = List.copyOf(allowedNetworks);

            for (String network : allowedNetworks) {
                validateCIDR(network);
            }
        }

        private static void validateCIDR(String cidr) {
            if (cidr == null) {
                throw new SecurityException("Null VPN route.");
            }

            String[] parts = cidr.split("/", -1);

            if (parts.length != 2) {
                throw new SecurityException("Invalid CIDR notation.");
            }

            try {
                java.net.InetAddress address =
                    java.net.InetAddress.getByName(parts[0]);

                int prefix = Integer.parseInt(parts[1]);

                int maximum = address.getAddress().length * 8;

                if (prefix < 0 || prefix > maximum ||
                    !address.getHostAddress().equalsIgnoreCase(parts[0])) {
                    throw new SecurityException("Invalid VPN route.");
                }
            } catch (Exception e) {
                throw new SecurityException(
                    "Invalid VPN route: " + cidr,
                    e
                );
            }
        }
    }

    static class IntegrityService {
        static String sha256(Path file) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                try (var input = Files.newInputStream(file)) {
                    byte[] buffer = new byte[8192];
                    int count;

                    while ((count = input.read(buffer)) != -1) {
                        digest.update(buffer, 0, count);
                    }
                }

                StringBuilder result = new StringBuilder();

                for (byte value : digest.digest()) {
                    result.append(String.format("%02x", value));
                }

                return result.toString();

            } catch (IOException | NoSuchAlgorithmException e) {
                throw new SecurityException(
                    "Cannot calculate file digest.",
                    e
                );
            }
        }
    }

    static void demonstrate() throws Exception {
        System.out.println("\n=== SECURE COMMUNICATIONS LAB ===");

        SecurityPolicy policy = SecurityPolicy.enterpriseDefault();

        AuditService audit = new AuditService();

        audit.subscribe(event -> System.out.println(
            "AUDIT " + event.timestamp() + " | " +
            event.type() + " | " + event.description()
        ));

        CommunicationService communications =
            new CommunicationService(audit);

        System.out.println("\n1. HTTPS and TLS");

        communications.register(
            "HTTPS-001",
            new Endpoint("example.com", 443, Protocol.HTTPS)
        );

        communications.transition("HTTPS-001", State.CONNECTING);

        try {
            HttpResponse<String> response = new TLSService(policy)
                .get("https://example.com")
                .get(20, TimeUnit.SECONDS);

            communications.transition("HTTPS-001", State.CONNECTED);

            System.out.println("HTTP status: " + response.statusCode());

            communications.transition("HTTPS-001", State.DISCONNECTED);

        } catch (Exception e) {
            communications.transition("HTTPS-001", State.FAILED);
            System.out.println("HTTPS failed: " + e.getMessage());
        }

        System.out.println("\n2. SSH requirements");

        Path knownHosts = Path.of(
            System.getProperty("user.home"),
            ".ssh",
            "known_hosts"
        );

        System.out.println(
            "Known-hosts file available: " +
            Files.isRegularFile(knownHosts)
        );

        System.out.println("Unknown host keys must be rejected.");
        System.out.println("Agent forwarding is disabled.");

        System.out.println("\n3. VPN configuration");

        VPNProfile vpn = new VPNProfile(
            "wg0",
            "vpn.example.com",
            51820,
            List.of("10.20.0.0/16", "192.168.50.0/24"),
            "WireGuard"
        );

        System.out.println(vpn);

        System.out.println("\n4. SFTP file integrity");

        Path sample = Files.createTempFile(
            "secure-communication-",
            ".txt"
        );

        try {
            Files.writeString(
                sample,
                "Confidential enterprise transfer record."
            );

            System.out.println("File: " + sample.getFileName());

            System.out.println(
                "SHA-256: " + IntegrityService.sha256(sample)
            );

            System.out.println("Transfer protocol: SFTP over SSH");

        } finally {
            Files.deleteIfExists(sample);
        }

        System.out.println("\n5. Active sessions");

        System.out.println(communications.activeSessions());

        System.out.println("\n6. Audit event count");

        System.out.println(audit.getEvents().size());
    }

    static void runTests() {
        SecurityPolicy policy = SecurityPolicy.enterpriseDefault();

        if (!policy.verifyCertificates()) {
            throw new AssertionError("TLS verification disabled.");
        }

        VPNProfile profile = new VPNProfile(
            "wg0",
            "vpn.example.com",
            51820,
            List.of("10.0.0.0/8"),
            "WireGuard"
        );

        if (profile.allowedNetworks().isEmpty()) {
            throw new AssertionError("VPN route validation failed.");
        }

        AuditService audit = new AuditService();
        CommunicationService service = new CommunicationService(audit);

        service.register(
            "TEST-001",
            new Endpoint("example.com", 443, Protocol.HTTPS)
        );

        service.transition("TEST-001", State.CONNECTING);
        service.transition("TEST-001", State.CONNECTED);

        boolean rejected = false;

        try {
            service.transition("TEST-001", State.CONNECTING);
        } catch (SecurityException e) {
            rejected = true;
        }

        if (!rejected) {
            throw new AssertionError("Invalid transition accepted.");
        }

        System.out.println("All Java 17 security tests passed.");
    }

    public static void main(String[] args) {
        try {
            runTests();
            demonstrate();
        } catch (Exception e) {
            System.err.println("SECURITY ERROR: " + e.getMessage());
            System.exitCode = 1;
        }
    }
}
