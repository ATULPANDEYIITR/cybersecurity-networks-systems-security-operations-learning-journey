import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Enterprise TLS connection assessment and session governance.
 *
 * Compile:
 * javac TLSDeepDive.java
 *
 * Run:
 * java TLSDeepDive
 * java TLSDeepDive www.example.com 443
 */
public class TLSDeepDive {

    enum Protocol {
        TLS_1_2("TLSv1.2"),
        TLS_1_3("TLSv1.3");

        private final String javaName;

        Protocol(String javaName) {
            this.javaName = javaName;
        }

        public String javaName() {
            return javaName;
        }
    }

    enum ConnectionState {
        CREATED,
        CONNECTING,
        ESTABLISHED,
        FAILED,
        CLOSED
    }

    enum CertificateStatus {
        VALID,
        EXPIRED,
        NOT_YET_VALID,
        HOSTNAME_MISMATCH,
        UNTRUSTED,
        INVALID_USAGE
    }

    record CipherPolicy(
        String name,
        Protocol protocol,
        boolean approved,
        boolean forwardSecrecy,
        int keyBits
    ) {
        CipherPolicy {
            Objects.requireNonNull(name);
            Objects.requireNonNull(protocol);

            if (name.isBlank() || keyBits < 1) {
                throw new IllegalArgumentException(
                    "Invalid cipher policy."
                );
            }
        }
    }

    record CertificateReport(
        String subject,
        String issuer,
        String serialNumber,
        Instant notBefore,
        Instant notAfter,
        String signatureAlgorithm,
        String publicKeyAlgorithm,
        int publicKeyBits,
        String sha256Fingerprint
    ) {}

    record TLSReport(
        String hostname,
        int port,
        ConnectionState state,
        String protocol,
        String cipherSuite,
        boolean certificateVerified,
        boolean sessionResumed,
        Duration handshakeDuration,
        CertificateReport certificate,
        List<String> findings
    ) {
        TLSReport {
            findings = List.copyOf(findings);
        }
    }

    static class TLSException extends Exception {
        TLSException(String message) {
            super(message);
        }

        TLSException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static class TLSConfiguration {
        private final Set<String> allowedProtocols;
        private final Duration timeout;

        TLSConfiguration() {
            this.allowedProtocols = Set.of(
                "TLSv1.2",
                "TLSv1.3"
            );

            this.timeout = Duration.ofSeconds(8);
        }

        Set<String> allowedProtocols() {
            return allowedProtocols;
        }

        Duration timeout() {
            return timeout;
        }
    }

    static class CipherPolicyService {

        private final Map<String, CipherPolicy> policies;

        CipherPolicyService() {
            Map<String, CipherPolicy> configured =
                new HashMap<>();

            add(configured, new CipherPolicy(
                "TLS_AES_128_GCM_SHA256",
                Protocol.TLS_1_3,
                true,
                true,
                128
            ));

            add(configured, new CipherPolicy(
                "TLS_AES_256_GCM_SHA384",
                Protocol.TLS_1_3,
                true,
                true,
                256
            ));

            add(configured, new CipherPolicy(
                "TLS_CHACHA20_POLY1305_SHA256",
                Protocol.TLS_1_3,
                true,
                true,
                256
            ));

            add(configured, new CipherPolicy(
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                Protocol.TLS_1_2,
                true,
                true,
                128
            ));

            add(configured, new CipherPolicy(
                "TLS_RSA_WITH_AES_128_CBC_SHA",
                Protocol.TLS_1_2,
                false,
                false,
                128
            ));

            this.policies = Collections.unmodifiableMap(
                configured
            );
        }

        private void add(
            Map<String, CipherPolicy> target,
            CipherPolicy policy
        ) {
            if (target.putIfAbsent(
                policy.name(),
                policy
            ) != null) {
                throw new IllegalStateException(
                    "Duplicate cipher policy."
                );
            }
        }

        CipherPolicy evaluate(
            String cipherName,
            String protocolName
        ) throws TLSException {

            CipherPolicy policy = policies.get(cipherName);

            if (policy == null || !policy.approved()) {
                throw new TLSException(
                    "Cipher suite is not approved: " + cipherName
                );
            }

            if (!policy.protocol().javaName().equals(protocolName)) {
                throw new TLSException(
                    "Cipher and protocol combination is invalid."
                );
            }

            if (!policy.forwardSecrecy()) {
                throw new TLSException(
                    "Forward secrecy is required."
                );
            }

            return policy;
        }
    }

    static class CertificateService {

        CertificateReport inspect(
            X509Certificate certificate
        ) throws Exception {

            byte[] encoded = certificate.getEncoded();

            java.security.MessageDigest digest =
                java.security.MessageDigest.getInstance("SHA-256");

            byte[] fingerprint = digest.digest(encoded);

            StringBuilder hex = new StringBuilder();

            for (byte value : fingerprint) {
                hex.append(String.format("%02x", value));
            }

            return new CertificateReport(
                certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(),
                certificate.getSerialNumber().toString(16),
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant(),
                certificate.getSigAlgName(),
                certificate.getPublicKey().getAlgorithm(),
                -1,
                hex.toString()
            );
        }

        void validate(
            X509Certificate certificate,
            String hostname
        ) throws TLSException {

            try {
                certificate.checkValidity();

                if (certificate.getBasicConstraints() >= 0) {
                    throw new TLSException(
                        "Server certificate must not be a CA certificate."
                    );
                }

                certificate.checkUsage();

            } catch (UnsupportedOperationException ignored) {
                // Key usage is checked separately below.
            } catch (Exception exception) {
                throw new TLSException(
                    "Certificate validation failed: " +
                    exception.getMessage(),
                    exception
                );
            }

            boolean[] usage = certificate.getKeyUsage();

            if (
                usage != null &&
                usage.length > 0 &&
                !usage[0] &&
                (usage.length <= 2 || !usage[2])
            ) {
                throw new TLSException(
                    "Certificate does not permit digital signatures."
                );
            }

            boolean serverAuthAllowed = true;

            try {
                List<String> extended =
                    certificate.getExtendedKeyUsage();

                if (extended != null) {
                    serverAuthAllowed =
                        extended.contains("1.3.6.1.5.5.7.3.1") ||
                        extended.contains("2.5.29.37.0");
                }
            } catch (Exception exception) {
                throw new TLSException(
                    "Invalid extended key usage.",
                    exception
                );
            }

            if (!serverAuthAllowed) {
                throw new TLSException(
                    "Certificate is not valid for TLS server authentication."
                );
            }

            // Standard hostname verification is performed by JSSE
            // during the TLS handshake using endpoint identification.
            if (hostname == null || hostname.isBlank()) {
                throw new TLSException(
                    "Hostname is required."
                );
            }
        }
    }

    static class SessionRegistry {

        private record SessionEntry(
            byte[] sessionId,
            Instant storedAt,
            Duration lifetime
        ) {
            SessionEntry {
                sessionId = sessionId.clone();
            }
        }

        private final ConcurrentHashMap<String, SessionEntry> entries =
            new ConcurrentHashMap<>();

        void register(
            String hostname,
            byte[] sessionId,
            Duration lifetime
        ) {
            if (
                hostname == null ||
                hostname.isBlank() ||
                sessionId == null ||
                sessionId.length == 0 ||
                lifetime == null ||
                lifetime.isNegative() ||
                lifetime.isZero()
            ) {
                throw new IllegalArgumentException(
                    "Invalid session registration."
                );
            }

            entries.put(
                hostname,
                new SessionEntry(
                    sessionId,
                    Instant.now(),
                    lifetime
                )
            );
        }

        boolean isValid(String hostname) {
            SessionEntry entry = entries.get(hostname);

            if (entry == null) {
                return false;
            }

            if (
                Instant.now().isAfter(
                    entry.storedAt().plus(entry.lifetime())
                )
            ) {
                entries.remove(hostname, entry);
                return false;
            }

            return true;
        }

        void revoke(String hostname) {
            entries.remove(hostname);
        }

        int size() {
            return entries.size();
        }
    }

    static class TLSConnectionService {

        private final TLSConfiguration configuration;
        private final CipherPolicyService cipherPolicy;
        private final CertificateService certificateService;

        TLSConnectionService(
            TLSConfiguration configuration
        ) {
            this.configuration = configuration;
            this.cipherPolicy = new CipherPolicyService();
            this.certificateService = new CertificateService();
        }

        TLSReport connect(
            String hostname,
            int port
        ) throws TLSException {

            if (
                hostname == null ||
                hostname.isBlank() ||
                port < 1 ||
                port > 65535
            ) {
                throw new IllegalArgumentException(
                    "Invalid connection destination."
                );
            }

            AtomicReference<ConnectionState> state =
                new AtomicReference<>(ConnectionState.CREATED);

            Instant start = Instant.now();

            try {
                state.set(ConnectionState.CONNECTING);

                SSLContext context = SSLContext.getDefault();

                SSLSocketFactory factory =
                    context.getSocketFactory();

                try (
                    SSLSocket socket = (SSLSocket)
                        factory.createSocket(hostname, port)
                ) {
                    socket.setSoTimeout(
                        Math.toIntExact(
                            configuration.timeout().toMillis()
                        )
                    );

                    SSLParameters parameters =
                        socket.getSSLParameters();

                    parameters.setProtocols(
                        configuration.allowedProtocols()
                            .toArray(String[]::new)
                    );

                    parameters.setEndpointIdentificationAlgorithm(
                        "HTTPS"
                    );

                    socket.setSSLParameters(parameters);

                    socket.startHandshake();

                    state.set(ConnectionState.ESTABLISHED);

                    SSLSession session = socket.getSession();

                    if (!session.isValid()) {
                        throw new TLSException(
                            "Negotiated TLS session is invalid."
                        );
                    }

                    String protocol = session.getProtocol();
                    String cipher = session.getCipherSuite();

                    if (!configuration.allowedProtocols()
                        .contains(protocol)) {
                        throw new TLSException(
                            "Negotiated protocol is not approved."
                        );
                    }

                    cipherPolicy.evaluate(cipher, protocol);

                    Certificate[] certificates =
                        session.getPeerCertificates();

                    if (
                        certificates.length == 0 ||
                        !(certificates[0] instanceof X509Certificate)
                    ) {
                        throw new TLSException(
                            "Server did not provide an X.509 certificate."
                        );
                    }

                    X509Certificate leaf =
                        (X509Certificate) certificates[0];

                    certificateService.validate(
                        leaf,
                        hostname
                    );

                    CertificateReport certificateReport =
                        certificateService.inspect(leaf);

                    return new TLSReport(
                        hostname,
                        port,
                        state.get(),
                        protocol,
                        cipher,
                        true,
                        false,
                        Duration.between(start, Instant.now()),
                        certificateReport,
                        List.of(
                            "Hostname verification enabled.",
                            "Trust chain accepted by configured trust store.",
                            "Cipher policy passed.",
                            "Handshake completed."
                        )
                    );
                }

            } catch (Exception exception) {
                state.set(ConnectionState.FAILED);

                throw new TLSException(
                    "TLS connection failed: " +
                    exception.getMessage(),
                    exception
                );
            }
        }
    }

    static void displayTLS13Handshake() {
        List<String> messages = List.of(
            "ClientHello: supported versions, cipher suites, key shares, SNI",
            "ServerHello: selected version, cipher suite and key share",
            "EncryptedExtensions: negotiated extensions",
            "Certificate: server certificate chain",
            "CertificateVerify: proof of private-key possession",
            "Finished: authenticated handshake transcript",
            "Application Data: encrypted with directional traffic keys"
        );

        System.out.println("\nTLS 1.3 Handshake Sequence");

        messages.forEach(
            message -> System.out.println("  " + message)
        );
    }

    static void displayTLS12Distinction() {
        System.out.println("\nTLS 1.2 and TLS 1.3 Distinction");

        System.out.println(
            "TLS 1.2: Cipher suites specify key exchange, authentication, "
            + "bulk encryption and hash/MAC components."
        );

        System.out.println(
            "TLS 1.3: Cipher suites specify AEAD encryption and transcript "
            + "hash; key exchange and authentication are negotiated separately."
        );

        System.out.println(
            "Both versions use certificate authentication and derive "
            + "symmetric traffic keys."
        );
    }

    public static void main(String[] args) {
        String hostname = args.length > 0
            ? args[0]
            : "example.com";

        int port = args.length > 1
            ? Integer.parseInt(args[1])
            : 443;

        try {
            TLSConfiguration configuration =
                new TLSConfiguration();

            TLSConnectionService service =
                new TLSConnectionService(configuration);

            TLSReport report = service.connect(
                hostname,
                port
            );

            System.out.println("\nEnterprise TLS Assessment");
            System.out.println("=========================");

            System.out.println("Host: " + report.hostname());
            System.out.println("Port: " + report.port());
            System.out.println("State: " + report.state());
            System.out.println("Protocol: " + report.protocol());
            System.out.println("Cipher: " + report.cipherSuite());
            System.out.println(
                "Certificate verified: " +
                report.certificateVerified()
            );

            System.out.println(
                "Handshake duration: " +
                report.handshakeDuration().toMillis() +
                " ms"
            );

            CertificateReport cert = report.certificate();

            System.out.println("\nCertificate Details");
            System.out.println("Subject: " + cert.subject());
            System.out.println("Issuer: " + cert.issuer());
            System.out.println("Serial: " + cert.serialNumber());
            System.out.println("Valid from: " + cert.notBefore());
            System.out.println("Valid until: " + cert.notAfter());
            System.out.println(
                "SHA-256: " + cert.sha256Fingerprint()
            );

            System.out.println("\nSecurity Findings");

            report.findings().forEach(
                finding -> System.out.println("[PASS] " + finding)
            );

        } catch (Exception exception) {
            System.err.println(
                "TLS assessment failed: " +
                exception.getMessage()
            );

            System.exit(1);
        }

        displayTLS13Handshake();
        displayTLS12Distinction();

        SessionRegistry registry = new SessionRegistry();

        registry.register(
            hostname,
            new byte[]{1, 2, 3, 4},
            Duration.ofMinutes(30)
        );

        System.out.println(
            "\nSession registry entry valid: " +
            registry.isValid(hostname)
        );
    }
}
