import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/*
 * Enterprise release-artifact integrity service.
 *
 * Compile:
 *   javac Hashing.java
 *
 * Run:
 *   java Hashing
 *
 * The implementation uses Java's JCA providers rather than implementing
 * cryptographic primitives manually.
 */

public class Hashing {

    private static final int BUFFER_SIZE = 1024 * 1024;
    private static final int MIN_HMAC_KEY_BYTES = 32;

    enum HashAlgorithm {
        SHA_256("SHA-256", "SHA-2", 32),
        SHA_512("SHA-512", "SHA-2", 64),
        SHA3_256("SHA3-256", "SHA-3", 32),
        SHA3_512("SHA3-512", "SHA-3", 64);

        private final String jcaName;
        private final String family;
        private final int digestBytes;

        HashAlgorithm(String jcaName, String family, int digestBytes) {
            this.jcaName = jcaName;
            this.family = family;
            this.digestBytes = digestBytes;
        }

        String jcaName() {
            return jcaName;
        }

        String family() {
            return family;
        }

        int digestBytes() {
            return digestBytes;
        }
    }

    enum VerificationStatus {
        MATCH,
        MISMATCH,
        MANIFEST_NOT_FOUND
    }

    enum ArtifactState {
        REGISTERED,
        VERIFIED,
        MODIFIED
    }

    record DigestResult(
        HashAlgorithm algorithm,
        String digestHex,
        long byteCount,
        Instant calculatedAt
    ) {
        DigestResult {
            if (algorithm == null || digestHex == null ||
                calculatedAt == null || byteCount < 0) {
                throw new IllegalArgumentException(
                    "Invalid digest result."
                );
            }
        }
    }

    record ArtifactManifest(
        UUID artifactId,
        String fileName,
        HashAlgorithm algorithm,
        String expectedDigest,
        long byteCount,
        Instant registeredAt,
        long revision
    ) {
        ArtifactManifest {
            if (artifactId == null ||
                fileName == null ||
                fileName.isBlank() ||
                algorithm == null ||
                expectedDigest == null ||
                registeredAt == null ||
                byteCount < 0 ||
                revision <= 0) {
                throw new IllegalArgumentException(
                    "Invalid artifact manifest."
                );
            }
        }
    }

    record VerificationResult(
        UUID artifactId,
        VerificationStatus status,
        HashAlgorithm algorithm,
        String expectedDigest,
        String actualDigest,
        long expectedBytes,
        long actualBytes,
        Instant checkedAt
    ) {
        VerificationResult {
            if (artifactId == null ||
                status == null ||
                checkedAt == null) {
                throw new IllegalArgumentException(
                    "Invalid verification result."
                );
            }
        }
    }

    static class HashingException extends RuntimeException {
        HashingException(String message, Throwable cause) {
            super(message, cause);
        }

        HashingException(String message) {
            super(message);
        }
    }

    /*
     * The policy is explicit: only SHA-2 and SHA-3 algorithms are accepted.
     * This prevents accidental use of legacy algorithms such as MD5 or SHA-1.
     */
    static final class DigestPolicy {
        private final Set<HashAlgorithm> approvedAlgorithms;

        DigestPolicy(Set<HashAlgorithm> approvedAlgorithms) {
            if (approvedAlgorithms == null ||
                approvedAlgorithms.isEmpty()) {
                throw new IllegalArgumentException(
                    "At least one algorithm must be approved."
                );
            }

            this.approvedAlgorithms = Set.copyOf(approvedAlgorithms);
        }

        void validate(HashAlgorithm algorithm) {
            if (algorithm == null ||
                !approvedAlgorithms.contains(algorithm)) {
                throw new HashingException(
                    "Algorithm is not approved by the release policy."
                );
            }
        }

        static DigestPolicy productionDefault() {
            return new DigestPolicy(Set.of(
                HashAlgorithm.SHA_256,
                HashAlgorithm.SHA_512,
                HashAlgorithm.SHA3_256,
                HashAlgorithm.SHA3_512
            ));
        }
    }

    static final class DigestEngine {
        private DigestEngine() {
        }

        private static MessageDigest newDigest(
            HashAlgorithm algorithm
        ) {
            try {
                return MessageDigest.getInstance(algorithm.jcaName());
            } catch (NoSuchAlgorithmException exception) {
                throw new HashingException(
                    "Required JCA algorithm is unavailable: " +
                    algorithm.jcaName(),
                    exception
                );
            }
        }

        static DigestResult hashBytes(
            byte[] content,
            HashAlgorithm algorithm
        ) {
            if (content == null || algorithm == null) {
                throw new IllegalArgumentException(
                    "Content and algorithm are required."
                );
            }

            MessageDigest digest = newDigest(algorithm);
            byte[] result = digest.digest(content);

            return new DigestResult(
                algorithm,
                HexFormat.of().formatHex(result),
                content.length,
                Instant.now()
            );
        }

        /*
         * File hashing uses a fixed-size buffer. It does not load the
         * entire release package into memory.
         */
        static DigestResult hashFile(
            Path file,
            HashAlgorithm algorithm
        ) throws IOException {
            if (file == null || algorithm == null) {
                throw new IllegalArgumentException(
                    "File and algorithm are required."
                );
            }

            if (!Files.isRegularFile(
                    file,
                    LinkOption.NOFOLLOW_LINKS
                )) {
                throw new IOException(
                    "Path must identify a regular non-symbolic-link file."
                );
            }

            MessageDigest digest = newDigest(algorithm);
            long byteCount = 0;
            byte[] buffer = new byte[BUFFER_SIZE];

            try (InputStream input = Files.newInputStream(
                    file,
                    StandardOpenOption.READ
                )) {
                int bytesRead;

                while ((bytesRead = input.read(buffer)) != -1) {
                    if (bytesRead == 0) {
                        continue;
                    }

                    digest.update(buffer, 0, bytesRead);
                    byteCount += bytesRead;
                }
            }

            return new DigestResult(
                algorithm,
                HexFormat.of().formatHex(digest.digest()),
                byteCount,
                Instant.now()
            );
        }

        static boolean verify(
            String expectedDigest,
            String actualDigest,
            HashAlgorithm algorithm
        ) {
            String expected = validateHexDigest(
                expectedDigest,
                algorithm
            );

            String actual = validateHexDigest(
                actualDigest,
                algorithm
            );

            byte[] expectedBytes = HexFormat.of().parseHex(expected);
            byte[] actualBytes = HexFormat.of().parseHex(actual);

            // Constant-time comparison for equal-length digest values.
            return MessageDigest.isEqual(
                expectedBytes,
                actualBytes
            );
        }

        static String validateHexDigest(
            String digest,
            HashAlgorithm algorithm
        ) {
            if (digest == null || algorithm == null) {
                throw new IllegalArgumentException(
                    "Digest and algorithm are required."
                );
            }

            String normalized = digest.trim().toLowerCase();

            if (!normalized.matches("[0-9a-f]+")) {
                throw new IllegalArgumentException(
                    "Digest contains invalid hexadecimal characters."
                );
            }

            if (normalized.length() != algorithm.digestBytes() * 2) {
                throw new IllegalArgumentException(
                    "Incorrect digest length for " + algorithm.jcaName()
                );
            }

            return normalized;
        }

        static byte[] hmacSha256(byte[] content, byte[] key) {
            if (content == null || key == null) {
                throw new IllegalArgumentException(
                    "HMAC content and key are required."
                );
            }

            if (key.length < MIN_HMAC_KEY_BYTES) {
                throw new IllegalArgumentException(
                    "HMAC key must contain at least 32 bytes."
                );
            }

            try {
                Mac mac = Mac.getInstance("HmacSHA256");

                mac.init(new SecretKeySpec(
                    key,
                    "HmacSHA256"
                ));

                return mac.doFinal(content);
            } catch (GeneralSecurityException exception) {
                throw new HashingException(
                    "Unable to calculate HMAC-SHA-256.",
                    exception
                );
            }
        }

        static boolean verifyHmacSha256(
            byte[] content,
            byte[] key,
            byte[] expectedTag
        ) {
            if (expectedTag == null || expectedTag.length != 32) {
                throw new IllegalArgumentException(
                    "HMAC-SHA-256 tag must contain 32 bytes."
                );
            }

            byte[] actualTag = hmacSha256(content, key);

            return MessageDigest.isEqual(
                actualTag,
                expectedTag
            );
        }
    }

    /*
     * The catalog represents the trusted release-management system.
     * ConcurrentHashMap supports concurrent registration and lookup.
     * Manifests are immutable records to prevent in-place modification.
     */
    static final class ArtifactCatalog {
        private final Map<UUID, ArtifactManifest> manifests =
            new ConcurrentHashMap<>();

        private final AtomicLong revisionCounter =
            new AtomicLong(0);

        private final DigestPolicy policy;

        ArtifactCatalog(DigestPolicy policy) {
            this.policy = policy;
        }

        ArtifactManifest register(
            Path file,
            HashAlgorithm algorithm
        ) throws IOException {
            policy.validate(algorithm);

            DigestResult result = DigestEngine.hashFile(
                file,
                algorithm
            );

            UUID id = UUID.randomUUID();

            ArtifactManifest manifest = new ArtifactManifest(
                id,
                file.getFileName().toString(),
                algorithm,
                result.digestHex(),
                result.byteCount(),
                Instant.now(),
                revisionCounter.incrementAndGet()
            );

            ArtifactManifest previous = manifests.putIfAbsent(
                id,
                manifest
            );

            if (previous != null) {
                throw new HashingException(
                    "Unexpected artifact identifier collision."
                );
            }

            return manifest;
        }

        Optional<ArtifactManifest> find(UUID artifactId) {
            return Optional.ofNullable(manifests.get(artifactId));
        }

        int size() {
            return manifests.size();
        }
    }

    /*
     * Verification is a separate operation from registration.
     * A match means the current bytes equal the registered bytes under
     * the selected digest and size checks. It does not prove authorship.
     */
    static final class IntegrityVerificationService {
        private final ArtifactCatalog catalog;

        private final ConcurrentLinkedQueue<VerificationResult> auditLog =
            new ConcurrentLinkedQueue<>();

        IntegrityVerificationService(ArtifactCatalog catalog) {
            this.catalog = catalog;
        }

        VerificationResult verify(
            UUID artifactId,
            Path currentFile
        ) throws IOException {
            Optional<ArtifactManifest> optionalManifest =
                catalog.find(artifactId);

            if (optionalManifest.isEmpty()) {
                VerificationResult missing = new VerificationResult(
                    artifactId,
                    VerificationStatus.MANIFEST_NOT_FOUND,
                    null,
                    null,
                    null,
                    0,
                    0,
                    Instant.now()
                );

                auditLog.add(missing);
                return missing;
            }

            ArtifactManifest manifest = optionalManifest.get();

            DigestResult current = DigestEngine.hashFile(
                currentFile,
                manifest.algorithm()
            );

            boolean sizeMatches =
                current.byteCount() == manifest.byteCount();

            boolean digestMatches = DigestEngine.verify(
                manifest.expectedDigest(),
                current.digestHex(),
                manifest.algorithm()
            );

            VerificationStatus status =
                sizeMatches && digestMatches
                    ? VerificationStatus.MATCH
                    : VerificationStatus.MISMATCH;

            VerificationResult result = new VerificationResult(
                artifactId,
                status,
                manifest.algorithm(),
                manifest.expectedDigest(),
                current.digestHex(),
                manifest.byteCount(),
                current.byteCount(),
                Instant.now()
            );

            auditLog.add(result);
            return result;
        }

        long auditEntryCount() {
            return auditLog.size();
        }

        void printAuditLog() {
            auditLog.forEach(entry -> {
                System.out.printf(
                    "%s | %s | %s%n",
                    entry.checkedAt(),
                    entry.artifactId(),
                    entry.status()
                );
            });
        }
    }

    private static void runKnownAnswerTests() {
        Map<HashAlgorithm, String> emptyVectors = Map.of(
            HashAlgorithm.SHA_256,
            "e3b0c44298fc1c149afbf4c8996fb924" +
            "27ae41e4649b934ca495991b7852b855",

            HashAlgorithm.SHA3_256,
            "a7ffc6f8bf1ed76651c14756a061d662" +
            "f580ff4de43b49fa82d80a4b80f8434a"
        );

        for (Map.Entry<HashAlgorithm, String> entry :
                emptyVectors.entrySet()) {
            String actual = DigestEngine.hashBytes(
                new byte[0],
                entry.getKey()
            ).digestHex();

            if (!actual.equals(entry.getValue())) {
                throw new AssertionError(
                    "Known-answer test failed for " + entry.getKey()
                );
            }
        }

        String sha256Abc = DigestEngine.hashBytes(
            "abc".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            HashAlgorithm.SHA_256
        ).digestHex();

        String expectedAbc =
            "ba7816bf8f01cfea414140de5dae2223" +
            "b00361a396177a9cb410ff61f20015ad";

        if (!sha256Abc.equals(expectedAbc)) {
            throw new AssertionError("SHA-256 abc test failed.");
        }

        byte[] key = new byte[MIN_HMAC_KEY_BYTES];
        java.util.Arrays.fill(key, (byte) 0x42);

        byte[] data = "release".getBytes(
            java.nio.charset.StandardCharsets.UTF_8
        );

        byte[] tag = DigestEngine.hmacSha256(data, key);

        if (!DigestEngine.verifyHmacSha256(data, key, tag)) {
            throw new AssertionError("HMAC verification failed.");
        }
    }

    public static void main(String[] args) throws Exception {
        runKnownAnswerTests();

        Path temporaryDirectory = Files.createTempDirectory(
            "release-integrity-"
        );

        Path packageFile = temporaryDirectory.resolve(
            "payment-service-release.bin"
        );

        byte[] originalContent = (
            "Release version: 2.4.1\n" +
            "Component: payment-service\n" +
            "Environment: production\n"
        ).getBytes(java.nio.charset.StandardCharsets.UTF_8);

        try {
            Files.write(packageFile, originalContent);

            DigestPolicy policy = DigestPolicy.productionDefault();
            ArtifactCatalog catalog = new ArtifactCatalog(policy);

            IntegrityVerificationService verificationService =
                new IntegrityVerificationService(catalog);

            ArtifactManifest manifest = catalog.register(
                packageFile,
                HashAlgorithm.SHA3_256
            );

            System.out.println("Enterprise artifact integrity service");
            System.out.println("---------------------------------------");
            System.out.println("Artifact ID: " + manifest.artifactId());
            System.out.println("Algorithm: " + manifest.algorithm());
            System.out.println("Digest: " + manifest.expectedDigest());
            System.out.println("Bytes: " + manifest.byteCount());

            VerificationResult initial = verificationService.verify(
                manifest.artifactId(),
                packageFile
            );

            System.out.println(
                "Initial verification: " + initial.status()
            );

            byte[] modifiedContent = (
                "Release version: 2.4.1\n" +
                "Component: payment-service\n" +
                "Environment: changed\n"
            ).getBytes(java.nio.charset.StandardCharsets.UTF_8);

            Files.write(packageFile, modifiedContent);

            VerificationResult modified = verificationService.verify(
                manifest.artifactId(),
                packageFile
            );

            System.out.println(
                "After modification: " + modified.status()
            );

            VerificationResult missing = verificationService.verify(
                UUID.randomUUID(),
                packageFile
            );

            System.out.println(
                "Unknown artifact: " + missing.status()
            );

            System.out.println(
                "Audit entries: " +
                verificationService.auditEntryCount()
            );

            System.out.println("\nAudit log:");
            verificationService.printAuditLog();

            System.out.println("\nKnown-answer tests: PASSED");
        } finally {
            Files.deleteIfExists(packageFile);
            Files.deleteIfExists(temporaryDirectory);
        }
    }
}
