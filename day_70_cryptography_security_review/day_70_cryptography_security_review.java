import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Cryptography Security Review
 *
 * Enterprise-oriented cryptographic governance application.
 *
 * Java 17
 * No third-party dependencies.
 *
 * Capabilities:
 * - Cryptographic asset inventory
 * - Algorithm and configuration assessment
 * - Key lifecycle governance
 * - Certificate security validation
 * - Review assignment and approval
 * - Remediation workflow
 * - Risk aggregation
 * - Immutable policy definitions
 * - Audit events
 */

public class CryptoSecurityReview {

    // ====================================================
    // ENUMERATIONS
    // ====================================================

    enum Severity {
        CRITICAL(10),
        HIGH(7),
        MEDIUM(4),
        LOW(2),
        INFORMATIONAL(1);

        private final int weight;

        Severity(int weight) {
            this.weight = weight;
        }

        public int weight() {
            return weight;
        }
    }

    enum Category {
        WEAK_ALGORITHM,
        KEY_MANAGEMENT,
        KEY_EXPOSURE,
        CERTIFICATE,
        TLS,
        RANDOMNESS,
        CONFIGURATION
    }

    enum FindingStatus {
        OPEN,
        IN_REVIEW,
        REMEDIATED,
        ACCEPTED_RISK,
        FALSE_POSITIVE
    }

    enum ReviewDecision {
        APPROVE_REMEDIATION,
        REJECT_REMEDIATION,
        ACCEPT_RISK
    }

    // ====================================================
    // EXCEPTIONS
    // ====================================================

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

    static class PolicyException extends SecurityException {
        PolicyException(String message) {
            super(message);
        }
    }

    // ====================================================
    // VALIDATION
    // ====================================================

    static void requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ValidationException(
                field + " cannot be empty."
            );
        }
    }

    static void requirePositive(int value, String field) {
        if (value <= 0) {
            throw new ValidationException(
                field + " must be positive."
            );
        }
    }

    static String normalize(String value) {
        requireText(value, "Algorithm");

        return value.toUpperCase()
            .replace("_", "-")
            .replace(" ", "");
    }

    // ====================================================
    // POLICY OBJECT
    // ====================================================

    record SecurityPolicy(
        int minimumRsaBits,
        int maximumKeyAgeDays,
        int certificateWarningDays,
        Set<String> deprecatedHashes,
        Set<String> weakCiphers,
        Set<String> approvedTlsVersions
    ) {

        SecurityPolicy {
            requirePositive(minimumRsaBits, "minimumRsaBits");
            requirePositive(maximumKeyAgeDays, "maximumKeyAgeDays");
            requirePositive(
                certificateWarningDays,
                "certificateWarningDays"
            );

            deprecatedHashes = Set.copyOf(deprecatedHashes);
            weakCiphers = Set.copyOf(weakCiphers);
            approvedTlsVersions = Set.copyOf(approvedTlsVersions);
        }

        static SecurityPolicy standard() {
            return new SecurityPolicy(
                2048,
                365,
                30,
                Set.of("MD5", "SHA1", "SHA-1"),
                Set.of("DES", "3DES", "RC4"),
                Set.of("TLS1.2", "TLS1.3")
            );
        }
    }

    // ====================================================
    // DOMAIN RECORDS
    // ====================================================

    record CryptoAsset(
        String id,
        String name,
        String algorithm,
        String purpose,
        Integer keyBits,
        String mode,
        Boolean authenticated,
        String tlsVersion,
        String randomnessSource
    ) {

        CryptoAsset {
            requireText(id, "Asset ID");
            requireText(name, "Asset name");
            requireText(algorithm, "Algorithm");
            requireText(purpose, "Purpose");

            if (keyBits != null) {
                requirePositive(keyBits, "Key bits");
            }
        }
    }

    record KeyRecord(
        String id,
        String algorithm,
        int bits,
        Instant createdAt,
        Instant lastRotatedAt,
        String storage,
        boolean exportable,
        boolean exposed
    ) {

        KeyRecord {
            requireText(id, "Key ID");
            requireText(algorithm, "Key algorithm");
            requirePositive(bits, "Key bits");
            Objects.requireNonNull(createdAt);
            Objects.requireNonNull(storage);

            if (
                lastRotatedAt != null &&
                lastRotatedAt.isBefore(createdAt)
            ) {
                throw new ValidationException(
                    "Rotation cannot precede creation."
                );
            }
        }
    }

    record CertificateRecord(
        String id,
        String hostname,
        String signatureAlgorithm,
        String publicKeyAlgorithm,
        int publicKeyBits,
        Instant notBefore,
        Instant notAfter,
        boolean trustedIssuer,
        boolean chainValid,
        boolean revoked
    ) {

        CertificateRecord {
            requireText(id, "Certificate ID");
            requireText(hostname, "Certificate hostname");
            requirePositive(publicKeyBits, "Public key bits");

            Objects.requireNonNull(notBefore);
            Objects.requireNonNull(notAfter);

            if (!notAfter.isAfter(notBefore)) {
                throw new ValidationException(
                    "Invalid certificate validity period."
                );
            }
        }
    }

    // ====================================================
    // SECURITY FINDING
    // ====================================================

    static final class SecurityFinding {

        private final String id;
        private final String assetId;
        private final Category category;
        private final Severity severity;
        private final String title;
        private final String description;
        private final String recommendation;
        private final Instant detectedAt;

        private FindingStatus status;

        SecurityFinding(
            String assetId,
            Category category,
            Severity severity,
            String title,
            String description,
            String recommendation
        ) {
            this.id = UUID.randomUUID().toString();
            this.assetId = assetId;
            this.category = category;
            this.severity = severity;
            this.title = title;
            this.description = description;
            this.recommendation = recommendation;
            this.detectedAt = Instant.now();
            this.status = FindingStatus.OPEN;
        }

        public synchronized void transition(
            FindingStatus next
        ) {
            Set<FindingStatus> allowed =
                switch (status) {
                    case OPEN -> Set.of(
                        FindingStatus.IN_REVIEW,
                        FindingStatus.REMEDIATED,
                        FindingStatus.ACCEPTED_RISK,
                        FindingStatus.FALSE_POSITIVE
                    );

                    case IN_REVIEW -> Set.of(
                        FindingStatus.OPEN,
                        FindingStatus.REMEDIATED,
                        FindingStatus.ACCEPTED_RISK,
                        FindingStatus.FALSE_POSITIVE
                    );

                    case ACCEPTED_RISK -> Set.of(
                        FindingStatus.OPEN,
                        FindingStatus.IN_REVIEW,
                        FindingStatus.REMEDIATED
                    );

                    case REMEDIATED, FALSE_POSITIVE -> Set.of();
                };

            if (!allowed.contains(next)) {
                throw new PolicyException(
                    "Invalid finding state transition: " +
                    status + " -> " + next
                );
            }

            status = next;
        }

        public String id() {
            return id;
        }

        public String assetId() {
            return assetId;
        }

        public Category category() {
            return category;
        }

        public Severity severity() {
            return severity;
        }

        public String title() {
            return title;
        }

        public String description() {
            return description;
        }

        public String recommendation() {
            return recommendation;
        }

        public FindingStatus status() {
            return status;
        }

        public Instant detectedAt() {
            return detectedAt;
        }
    }

    // ====================================================
    // AUDIT EVENTS
    // ====================================================

    record AuditEvent(
        Instant timestamp,
        String actor,
        String action,
        String entityId,
        String details
    ) {}

    interface AuditSink {
        void record(AuditEvent event);
    }

    static class InMemoryAuditSink implements AuditSink {

        private final List<AuditEvent> events =
            new ArrayList<>();

        @Override
        public synchronized void record(AuditEvent event) {
            events.add(event);
        }

        public synchronized List<AuditEvent> events() {
            return List.copyOf(events);
        }
    }

    // ====================================================
    // REVIEW ASSIGNMENT
    // ====================================================

    record Reviewer(
        String id,
        String name,
        Set<Category> responsibilities,
        boolean active
    ) {

        Reviewer {
            requireText(id, "Reviewer ID");
            requireText(name, "Reviewer name");
            responsibilities = Set.copyOf(responsibilities);
        }

        boolean eligible(Category category) {
            return active && responsibilities.contains(category);
        }
    }

    record ReviewRecord(
        String reviewerId,
        String findingId,
        ReviewDecision decision,
        String comments,
        Instant reviewedAt
    ) {}

    // ====================================================
    // ALGORITHM ANALYZER
    // ====================================================

    static class AlgorithmAnalyzer {

        private final SecurityPolicy policy;

        AlgorithmAnalyzer(SecurityPolicy policy) {
            this.policy = policy;
        }

        List<SecurityFinding> inspect(CryptoAsset asset) {
            List<SecurityFinding> results = new ArrayList<>();

            String algorithm = normalize(asset.algorithm());

            if (policy.deprecatedHashes().contains(algorithm)) {
                results.add(new SecurityFinding(
                    asset.id(),
                    Category.WEAK_ALGORITHM,
                    Severity.HIGH,
                    "Deprecated hash algorithm",
                    "Configured algorithm: " + algorithm,
                    "Replace with SHA-256 or a stronger approved hash."
                ));
            }

            if (policy.weakCiphers().contains(algorithm)) {
                results.add(new SecurityFinding(
                    asset.id(),
                    Category.WEAK_ALGORITHM,
                    Severity.CRITICAL,
                    "Weak encryption cipher",
                    "The configured cipher is deprecated.",
                    "Migrate to modern authenticated encryption."
                ));
            }

            if (
                algorithm.equals("RSA") ||
                algorithm.equals("RSA-PSS")
            ) {
                if (asset.keyBits() == null) {
                    results.add(new SecurityFinding(
                        asset.id(),
                        Category.CONFIGURATION,
                        Severity.MEDIUM,
                        "RSA key size unavailable",
                        "Key strength cannot be established.",
                        "Record and verify RSA modulus size."
                    ));
                } else if (
                    asset.keyBits() < policy.minimumRsaBits()
                ) {
                    results.add(new SecurityFinding(
                        asset.id(),
                        Category.WEAK_ALGORITHM,
                        Severity.HIGH,
                        "Weak RSA key",
                        "RSA modulus is below policy requirements.",
                        "Use an adequately sized RSA key."
                    ));
                }
            }

            if (
                Set.of("AES", "AES-128", "AES-256").contains(algorithm)
            ) {
                String mode = asset.mode() == null
                    ? ""
                    : asset.mode().toUpperCase();

                if (
                    mode.equals("ECB") ||
                    mode.equals("CBC_WITHOUT_MAC")
                ) {
                    results.add(new SecurityFinding(
                        asset.id(),
                        Category.CONFIGURATION,
                        Severity.HIGH,
                        "Unsafe encryption mode",
                        "Encryption does not provide authenticated protection.",
                        "Use AES-GCM with correct nonce management."
                    ));
                }

                if (Boolean.FALSE.equals(asset.authenticated())) {
                    results.add(new SecurityFinding(
                        asset.id(),
                        Category.CONFIGURATION,
                        Severity.HIGH,
                        "Missing ciphertext authentication",
                        "Ciphertext integrity is not verified.",
                        "Use authenticated encryption."
                    ));
                }
            }

            if (
                asset.tlsVersion() != null &&
                !asset.tlsVersion().isBlank() &&
                !policy.approvedTlsVersions().contains(
                    asset.tlsVersion().toUpperCase()
                )
            ) {
                results.add(new SecurityFinding(
                    asset.id(),
                    Category.TLS,
                    Severity.HIGH,
                    "Unsupported TLS version",
                    "Configured protocol: " + asset.tlsVersion(),
                    "Use TLS 1.2 or TLS 1.3."
                ));
            }

            if (
                asset.randomnessSource() != null &&
                Set.of(
                    "MATH.RANDOM",
                    "RANDOM.RANDOM",
                    "STATIC_SEED",
                    "TIME"
                ).contains(asset.randomnessSource().toUpperCase())
            ) {
                results.add(new SecurityFinding(
                    asset.id(),
                    Category.RANDOMNESS,
                    Severity.CRITICAL,
                    "Predictable randomness source",
                    "The source is unsuitable for cryptographic secrets.",
                    "Use a cryptographically secure random generator."
                ));
            }

            return results;
        }
    }

    // ====================================================
    // KEY MANAGEMENT SERVICE
    // ====================================================

    static class KeyManagementService {

        private final SecurityPolicy policy;

        KeyManagementService(SecurityPolicy policy) {
            this.policy = policy;
        }

        List<SecurityFinding> inspect(KeyRecord key) {
            List<SecurityFinding> findings = new ArrayList<>();

            if (key.exposed()) {
                findings.add(new SecurityFinding(
                    key.id(),
                    Category.KEY_EXPOSURE,
                    Severity.CRITICAL,
                    "Key exposure detected",
                    "The key must be considered compromised.",
                    "Revoke dependent credentials and rotate the key."
                ));
            }

            if (
                key.exportable() &&
                !key.storage().equalsIgnoreCase("HSM")
            ) {
                findings.add(new SecurityFinding(
                    key.id(),
                    Category.KEY_MANAGEMENT,
                    Severity.HIGH,
                    "Unprotected exportable key",
                    "The key is exportable outside the HSM boundary.",
                    "Use controlled key custody and hardware protection."
                ));
            }

            Instant reference = key.lastRotatedAt() == null
                ? key.createdAt()
                : key.lastRotatedAt();

            long ageDays = ChronoUnit.DAYS.between(
                reference,
                Instant.now()
            );

            if (ageDays > policy.maximumKeyAgeDays()) {
                findings.add(new SecurityFinding(
                    key.id(),
                    Category.KEY_MANAGEMENT,
                    Severity.MEDIUM,
                    "Key rotation overdue",
                    "Key age exceeds the configured cryptoperiod.",
                    "Rotate according to key lifecycle requirements."
                ));
            }

            if (
                normalize(key.algorithm()).equals("RSA") &&
                key.bits() < policy.minimumRsaBits()
            ) {
                findings.add(new SecurityFinding(
                    key.id(),
                    Category.WEAK_ALGORITHM,
                    Severity.HIGH,
                    "Insufficient RSA key size",
                    "RSA modulus is below the configured minimum.",
                    "Replace with an adequately sized RSA key."
                ));
            }

            return findings;
        }
    }

    // ====================================================
    // CERTIFICATE SERVICE
    // ====================================================

    static class CertificateService {

        private final SecurityPolicy policy;

        CertificateService(SecurityPolicy policy) {
            this.policy = policy;
        }

        boolean hostnameMatches(
            String pattern,
            String hostname
        ) {
            pattern = pattern.toLowerCase();
            hostname = hostname.toLowerCase();

            if (pattern.equals(hostname)) {
                return true;
            }

            if (!pattern.startsWith("*.")) {
                return false;
            }

            String suffix = pattern.substring(2);

            if (!hostname.endsWith("." + suffix)) {
                return false;
            }

            String prefix = hostname.substring(
                0,
                hostname.length() - suffix.length() - 1
            );

            return !prefix.isBlank() && !prefix.contains(".");
        }

        List<SecurityFinding> inspect(
            CertificateRecord certificate,
            String expectedHostname
        ) {
            List<SecurityFinding> findings = new ArrayList<>();

            Instant now = Instant.now();

            if (now.isBefore(certificate.notBefore())) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.HIGH,
                    "Certificate not yet valid",
                    "Current time precedes certificate validity.",
                    "Check certificate dates and system clocks."
                ));
            }

            if (!now.isBefore(certificate.notAfter())) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.CRITICAL,
                    "Certificate expired",
                    "The certificate is outside its validity period.",
                    "Renew and deploy a valid certificate."
                ));
            } else if (
                ChronoUnit.DAYS.between(
                    now,
                    certificate.notAfter()
                ) <= policy.certificateWarningDays()
            ) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.MEDIUM,
                    "Certificate expiring soon",
                    "The certificate is approaching expiration.",
                    "Schedule certificate renewal."
                ));
            }

            if (certificate.revoked()) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.CRITICAL,
                    "Revoked certificate",
                    "The certificate is marked revoked.",
                    "Reject the certificate and investigate."
                ));
            }

            if (
                !certificate.trustedIssuer() ||
                !certificate.chainValid()
            ) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.HIGH,
                    "Certificate chain validation failed",
                    "Issuer trust or chain integrity is invalid.",
                    "Validate the chain against trusted CA certificates."
                ));
            }

            if (!hostnameMatches(
                certificate.hostname(),
                expectedHostname
            )) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.HIGH,
                    "Hostname mismatch",
                    "Certificate identity does not match the requested hostname.",
                    "Deploy a certificate with the correct SAN."
                ));
            }

            if (
                Set.of("MD5", "SHA1", "SHA-1", "SHA1WITHRSA")
                    .contains(certificate.signatureAlgorithm().toUpperCase())
            ) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.HIGH,
                    "Weak certificate signature",
                    "The signature algorithm is deprecated.",
                    "Use an approved modern signature algorithm."
                ));
            }

            if (
                certificate.publicKeyAlgorithm().equalsIgnoreCase("RSA") &&
                certificate.publicKeyBits() < policy.minimumRsaBits()
            ) {
                findings.add(new SecurityFinding(
                    certificate.id(),
                    Category.CERTIFICATE,
                    Severity.HIGH,
                    "Weak certificate public key",
                    "RSA public key is below the configured minimum.",
                    "Replace the certificate with an adequately sized key."
                ));
            }

            return findings;
        }
    }

    // ====================================================
    // GOVERNANCE SERVICE
    // ====================================================

    static class GovernanceService {

        private final Map<String, Reviewer> reviewers =
            new HashMap<>();

        private final List<ReviewRecord> reviews =
            new ArrayList<>();

        private final AuditSink audit;

        GovernanceService(AuditSink audit) {
            this.audit = audit;
        }

        void registerReviewer(Reviewer reviewer) {
            if (reviewers.putIfAbsent(
                reviewer.id(),
                reviewer
            ) != null) {
                throw new ValidationException(
                    "Duplicate reviewer."
                );
            }
        }

        void review(
            String reviewerId,
            SecurityFinding finding,
            ReviewDecision decision,
            String comments
        ) {
            Reviewer reviewer = reviewers.get(reviewerId);

            if (reviewer == null) {
                throw new ValidationException(
                    "Unknown reviewer."
                );
            }

            if (!reviewer.eligible(finding.category())) {
                throw new PolicyException(
                    "Reviewer is not eligible for this finding."
                );
            }

            if (comments == null || comments.isBlank()) {
                throw new ValidationException(
                    "Review comments are required."
                );
            }

            switch (decision) {
                case APPROVE_REMEDIATION:
                    finding.transition(FindingStatus.REMEDIATED);
                    break;

                case REJECT_REMEDIATION:
                    finding.transition(FindingStatus.IN_REVIEW);
                    break;

                case ACCEPT_RISK:
                    finding.transition(FindingStatus.ACCEPTED_RISK);
                    break;
            }

            ReviewRecord record = new ReviewRecord(
                reviewerId,
                finding.id(),
                decision,
                comments,
                Instant.now()
            );

            reviews.add(record);

            audit.record(new AuditEvent(
                Instant.now(),
                reviewerId,
                "FINDING_REVIEWED",
                finding.id(),
                decision.name()
            ));
        }

        List<ReviewRecord> reviews() {
            return List.copyOf(reviews);
        }
    }

    // ====================================================
    // APPLICATION SERVICE
    // ====================================================

    static class SecurityReviewApplication {

        private final SecurityPolicy policy;

        private final AlgorithmAnalyzer algorithmAnalyzer;
        private final KeyManagementService keyService;
        private final CertificateService certificateService;

        private final Map<String, CryptoAsset> assets =
            new HashMap<>();

        private final Map<String, SecurityFinding> findings =
            new HashMap<>();

        private final AuditSink audit;

        SecurityReviewApplication(
            SecurityPolicy policy,
            AuditSink audit
        ) {
            this.policy = policy;
            this.audit = audit;

            this.algorithmAnalyzer = new AlgorithmAnalyzer(policy);
            this.keyService = new KeyManagementService(policy);
            this.certificateService = new CertificateService(policy);
        }

        void registerAsset(CryptoAsset asset) {
            if (assets.putIfAbsent(asset.id(), asset) != null) {
                throw new ValidationException(
                    "Asset already registered."
                );
            }

            audit.record(new AuditEvent(
                Instant.now(),
                "SYSTEM",
                "ASSET_REGISTERED",
                asset.id(),
                asset.name()
            ));
        }

        private void addFindings(List<SecurityFinding> detected) {
            for (SecurityFinding finding : detected) {
                findings.put(finding.id(), finding);

                audit.record(new AuditEvent(
                    Instant.now(),
                    "SECURITY_ENGINE",
                    "FINDING_CREATED",
                    finding.id(),
                    finding.severity().name()
                ));
            }
        }

        void assessAsset(String assetId) {
            CryptoAsset asset = assets.get(assetId);

            if (asset == null) {
                throw new ValidationException(
                    "Asset not found."
                );
            }

            addFindings(algorithmAnalyzer.inspect(asset));
        }

        void assessKey(KeyRecord key) {
            addFindings(keyService.inspect(key));
        }

        void assessCertificate(
            CertificateRecord certificate,
            String hostname
        ) {
            addFindings(
                certificateService.inspect(certificate, hostname)
            );
        }

        SecurityFinding finding(String id) {
            SecurityFinding finding = findings.get(id);

            if (finding == null) {
                throw new ValidationException(
                    "Finding does not exist."
                );
            }

            return finding;
        }

        List<SecurityFinding> findings() {
            return List.copyOf(findings.values());
        }

        int riskScore() {
            return Math.min(
                100,
                findings.values().stream()
                    .filter(f ->
                        f.status() == FindingStatus.OPEN
                    )
                    .mapToInt(f -> f.severity().weight())
                    .sum()
            );
        }

        String riskLevel() {
            int score = riskScore();

            if (score >= 30) return "CRITICAL";
            if (score >= 18) return "HIGH";
            if (score >= 8) return "MEDIUM";
            if (score > 0) return "LOW";

            return "NO_OPEN_FINDINGS";
        }

        Map<Severity, Long> severityDistribution() {
            return findings.values().stream()
                .collect(Collectors.groupingBy(
                    SecurityFinding::severity,
                    () -> new EnumMap<>(Severity.class),
                    Collectors.counting()
                ));
        }

        Map<FindingStatus, Long> statusDistribution() {
            return findings.values().stream()
                .collect(Collectors.groupingBy(
                    SecurityFinding::status,
                    () -> new EnumMap<>(FindingStatus.class),
                    Collectors.counting()
                ));
        }

        void printReport() {
            System.out.println("\nCRYPTOGRAPHY SECURITY REVIEW");
            System.out.println("====================================");

            System.out.println("Assets: " + assets.size());
            System.out.println("Findings: " + findings.size());
            System.out.println("Risk score: " + riskScore());
            System.out.println("Risk level: " + riskLevel());

            System.out.println("\nSEVERITY DISTRIBUTION");

            severityDistribution().forEach(
                (severity, count) ->
                    System.out.println(severity + ": " + count)
            );

            System.out.println("\nFINDINGS");

            findings.values().forEach(finding -> {
                System.out.println(
                    "\n[" + finding.severity() + "] " +
                    finding.title()
                );

                System.out.println("Asset: " + finding.assetId());
                System.out.println("Category: " + finding.category());
                System.out.println("Status: " + finding.status());
                System.out.println("Description: " + finding.description());
                System.out.println(
                    "Recommendation: " + finding.recommendation()
                );
            });
        }
    }

    // ====================================================
    // VALIDATION TESTS
    // ====================================================

    static void runTests() {

        SecurityPolicy policy = SecurityPolicy.standard();

        AlgorithmAnalyzer analyzer =
            new AlgorithmAnalyzer(policy);

        CryptoAsset weak = new CryptoAsset(
            "TEST-001",
            "Legacy Service",
            "MD5",
            "Integrity",
            null,
            null,
            null,
            null,
            null
        );

        List<SecurityFinding> findings = analyzer.inspect(weak);

        if (findings.size() != 1) {
            throw new AssertionError("Weak hash detection failed.");
        }

        if (findings.get(0).severity() != Severity.HIGH) {
            throw new AssertionError("Incorrect severity.");
        }

        CertificateService certificateService =
            new CertificateService(policy);

        if (!certificateService.hostnameMatches(
            "*.example.com",
            "api.example.com"
        )) {
            throw new AssertionError("Wildcard hostname test failed.");
        }

        if (certificateService.hostnameMatches(
            "*.example.com",
            "a.b.example.com"
        )) {
            throw new AssertionError("Wildcard depth validation failed.");
        }

        SecurityFinding finding = new SecurityFinding(
            "TEST",
            Category.WEAK_ALGORITHM,
            Severity.HIGH,
            "Test",
            "Description",
            "Recommendation"
        );

        finding.transition(FindingStatus.IN_REVIEW);
        finding.transition(FindingStatus.REMEDIATED);

        try {
            finding.transition(FindingStatus.OPEN);
            throw new AssertionError(
                "Terminal state transition was accepted."
            );
        } catch (PolicyException expected) {
            // Expected rejection.
        }

        System.out.println("All Java 17 tests passed.");
    }

    // ====================================================
    // MAIN
    // ====================================================

    public static void main(String[] args) {

        try {
            runTests();

            SecurityPolicy policy = SecurityPolicy.standard();

            InMemoryAuditSink audit = new InMemoryAuditSink();

            SecurityReviewApplication application =
                new SecurityReviewApplication(policy, audit);

            List<CryptoAsset> assets = List.of(
                new CryptoAsset(
                    "ASSET-001",
                    "Legacy Authentication",
                    "SHA1",
                    "Integrity",
                    null,
                    null,
                    null,
                    null,
                    null
                ),
                new CryptoAsset(
                    "ASSET-002",
                    "Payment Service",
                    "AES",
                    "Encryption",
                    256,
                    "ECB",
                    false,
                    null,
                    null
                ),
                new CryptoAsset(
                    "ASSET-003",
                    "External API",
                    "RSA",
                    "Digital signatures",
                    1024,
                    null,
                    null,
                    "TLS1.0",
                    null
                ),
                new CryptoAsset(
                    "ASSET-004",
                    "Token Generator",
                    "AES-256",
                    "Token protection",
                    256,
                    "GCM",
                    true,
                    "TLS1.3",
                    "MATH.RANDOM"
                ),
                new CryptoAsset(
                    "ASSET-005",
                    "Secure Storage",
                    "AES-256",
                    "Storage encryption",
                    256,
                    "GCM",
                    true,
                    "TLS1.3",
                    "SECURE_RANDOM"
                )
            );

            for (CryptoAsset asset : assets) {
                application.registerAsset(asset);
                application.assessAsset(asset.id());
            }

            Instant now = Instant.now();

            KeyRecord key = new KeyRecord(
                "KEY-001",
                "RSA",
                1024,
                now.minus(600, ChronoUnit.DAYS),
                now.minus(500, ChronoUnit.DAYS),
                "LOCAL_FILE",
                true,
                true
            );

            application.assessKey(key);

            CertificateRecord certificate = new CertificateRecord(
                "CERT-001",
                "old.example.com",
                "SHA1WITHRSA",
                "RSA",
                1024,
                now.minus(500, ChronoUnit.DAYS),
                now.minus(5, ChronoUnit.DAYS),
                false,
                false,
                true
            );

            application.assessCertificate(
                certificate,
                "api.example.com"
            );

            GovernanceService governance =
                new GovernanceService(audit);

            Reviewer reviewer = new Reviewer(
                "REVIEWER-001",
                "Security Engineering",
                Set.of(
                    Category.WEAK_ALGORITHM,
                    Category.KEY_MANAGEMENT,
                    Category.KEY_EXPOSURE,
                    Category.CERTIFICATE,
                    Category.TLS,
                    Category.CONFIGURATION,
                    Category.RANDOMNESS
                ),
                true
            );

            governance.registerReviewer(reviewer);

            SecurityFinding first =
                application.findings().get(0);

            first.transition(FindingStatus.IN_REVIEW);

            governance.review(
                reviewer.id(),
                first,
                ReviewDecision.REJECT_REMEDIATION,
                "Replacement evidence has not yet been supplied."
            );

            application.printReport();

            System.out.println(
                "\nAudit events: " + audit.events().size()
            );

        } catch (Exception exception) {
            System.err.println(
                "Security assessment failed: " +
                exception.getMessage()
            );

            System.exit(1);
        }
    }
}
