import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/*
 * Enterprise Public Key Infrastructure (PKI)
 *
 * Domain-oriented certificate lifecycle management.
 *
 * Features:
 * - Root and intermediate certificate authorities
 * - Certificate issuance policies
 * - Trust anchor management
 * - Chain construction and structural validation
 * - Certificate renewal and replacement
 * - Revocation management
 * - Lifecycle audit events
 * - Enterprise policy enforcement
 *
 * This implementation models certificate lifecycle and trust metadata.
 * It does not perform X.509 signature verification or key generation.
 */

public class PKIEnterprise {

    enum CertificateType {
        ROOT,
        INTERMEDIATE,
        END_ENTITY
    }

    enum CertificateStatus {
        ACTIVE,
        EXPIRED,
        REVOKED,
        NOT_YET_VALID
    }

    enum KeyUsage {
        DIGITAL_SIGNATURE,
        KEY_ENCIPHERMENT,
        KEY_AGREEMENT,
        DATA_ENCIPHERMENT,
        CONTENT_COMMITMENT,
        KEY_CERT_SIGN,
        CRL_SIGN
    }

    enum RevocationReason {
        KEY_COMPROMISE,
        CA_COMPROMISE,
        SUPERSEDED,
        CESSATION_OF_OPERATION,
        PRIVILEGE_WITHDRAWN
    }

    enum AuditAction {
        ROOT_CREATED,
        INTERMEDIATE_CREATED,
        CERTIFICATE_ISSUED,
        CERTIFICATE_RENEWED,
        CERTIFICATE_REVOKED
    }

    static class PKIException extends RuntimeException {
        PKIException(String message) {
            super(message);
        }
    }

    static class PolicyException extends PKIException {
        PolicyException(String message) {
            super(message);
        }
    }

    record AuditEvent(
        Instant timestamp,
        AuditAction action,
        String certificateId,
        String details
    ) {}

    record ValidationResult(
        boolean valid,
        List<String> chain,
        String message
    ) {
        ValidationResult {
            chain = List.copyOf(chain);
        }
    }

    record IssuancePolicy(
        int maximumValidityDays,
        Set<KeyUsage> allowedUsage,
        boolean allowIntermediateCA
    ) {
        IssuancePolicy {
            if (maximumValidityDays <= 0) {
                throw new PolicyException(
                    "Maximum validity must be positive."
                );
            }

            allowedUsage = Set.copyOf(allowedUsage);

            if (allowedUsage.isEmpty()) {
                throw new PolicyException(
                    "Allowed key usage cannot be empty."
                );
            }
        }
    }

    static final class Certificate {

        private final String id;
        private final String serial;
        private final String subject;
        private final String issuerId;

        private final CertificateType type;

        private final Instant notBefore;
        private final Instant notAfter;

        private final boolean isCA;
        private final Integer pathLength;

        private final Set<KeyUsage> keyUsage;

        private final String subjectKeyId;
        private final String authorityKeyId;

        private Instant revokedAt;
        private RevocationReason revocationReason;
        private String replacementId;

        Certificate(
            String id,
            String serial,
            String subject,
            String issuerId,
            CertificateType type,
            Instant notBefore,
            Instant notAfter,
            boolean isCA,
            Integer pathLength,
            Set<KeyUsage> keyUsage,
            String subjectKeyId,
            String authorityKeyId
        ) {
            this.id = id;
            this.serial = serial;
            this.subject = subject;
            this.issuerId = issuerId;
            this.type = type;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.isCA = isCA;
            this.pathLength = pathLength;
            this.keyUsage = Set.copyOf(keyUsage);
            this.subjectKeyId = subjectKeyId;
            this.authorityKeyId = authorityKeyId;
        }

        CertificateStatus status(Instant now) {
            if (revokedAt != null) {
                return CertificateStatus.REVOKED;
            }

            if (now.isBefore(notBefore)) {
                return CertificateStatus.NOT_YET_VALID;
            }

            if (!now.isBefore(notAfter)) {
                return CertificateStatus.EXPIRED;
            }

            return CertificateStatus.ACTIVE;
        }

        String getId() {
            return id;
        }

        String getSubject() {
            return subject;
        }

        String getIssuerId() {
            return issuerId;
        }

        CertificateType getType() {
            return type;
        }

        Instant getNotAfter() {
            return notAfter;
        }

        boolean isCA() {
            return isCA;
        }

        Integer getPathLength() {
            return pathLength;
        }

        Set<KeyUsage> getKeyUsage() {
            return keyUsage;
        }

        String getSubjectKeyId() {
            return subjectKeyId;
        }

        String getAuthorityKeyId() {
            return authorityKeyId;
        }

        String getReplacementId() {
            return replacementId;
        }

        void revoke(Instant timestamp, RevocationReason reason) {
            if (revokedAt != null) {
                throw new PKIException("Certificate already revoked.");
            }

            revokedAt = timestamp;
            revocationReason = reason;
        }

        void setReplacementId(String replacementId) {
            this.replacementId = replacementId;
        }
    }

    static final class CertificateAuthority {

        private final Certificate certificate;
        private final IssuancePolicy policy;

        private final Set<String> issuedCertificates = new HashSet<>();

        private boolean active = true;

        CertificateAuthority(
            Certificate certificate,
            IssuancePolicy policy
        ) {
            this.certificate = certificate;
            this.policy = policy;
        }

        void deactivate() {
            active = false;
        }
    }

    static final class CertificateRepository {

        private final Map<String, Certificate> certificates =
            new HashMap<>();

        void save(Certificate certificate) {
            if (certificates.putIfAbsent(
                certificate.id,
                certificate
            ) != null) {
                throw new PKIException("Duplicate certificate identifier.");
            }
        }

        Optional<Certificate> find(String id) {
            return Optional.ofNullable(certificates.get(id));
        }

        Certificate require(String id) {
            return find(id).orElseThrow(
                () -> new PKIException("Certificate not found: " + id)
            );
        }

        List<Certificate> all() {
            return List.copyOf(certificates.values());
        }
    }

    static final class TrustStore {

        private final Set<String> trustedRoots = new HashSet<>();

        void addTrustAnchor(String id) {
            trustedRoots.add(id);
        }

        boolean trusts(String id) {
            return trustedRoots.contains(id);
        }
    }

    static final class PKIService {

        private final CertificateRepository repository =
            new CertificateRepository();

        private final Map<String, CertificateAuthority> authorities =
            new HashMap<>();

        private final TrustStore trustStore = new TrustStore();

        private final Map<String, RevocationReason> revocations =
            new HashMap<>();

        private final List<AuditEvent> auditLog =
            new CopyOnWriteArrayList<>();

        private static String generateId(String prefix) {
            return prefix + "-" +
                UUID.randomUUID().toString().replace("-", "").toUpperCase();
        }

        private static String keyIdentifier(String subject, String serial) {
            /*
             * Metadata identifier for the demonstration.
             * Real X.509 key identifiers are associated with public keys.
             */
            return Integer.toHexString(
                (subject + ":" + serial).hashCode()
            );
        }

        private void audit(
            AuditAction action,
            String certificateId,
            String details
        ) {
            auditLog.add(
                new AuditEvent(
                    Instant.now(),
                    action,
                    certificateId,
                    details
                )
            );
        }

        private CertificateAuthority requireCA(String id) {
            CertificateAuthority ca = authorities.get(id);

            if (ca == null || !ca.active) {
                throw new PolicyException("Unknown or inactive CA.");
            }

            validateCA(ca.certificate);

            return ca;
        }

        private void validateCA(Certificate certificate) {
            if (!certificate.isCA()) {
                throw new PolicyException("Certificate is not a CA.");
            }

            if (
                certificate.status(Instant.now()) !=
                CertificateStatus.ACTIVE
            ) {
                throw new PolicyException("CA certificate is not valid.");
            }

            if (!certificate.keyUsage.contains(KeyUsage.KEY_CERT_SIGN)) {
                throw new PolicyException("CA lacks certificate-signing usage.");
            }
        }

        Certificate createRootCA(
            String subject,
            int validityDays,
            int pathLength
        ) {
            if (
                subject == null ||
                subject.isBlank() ||
                validityDays <= 0 ||
                pathLength < 0
            ) {
                throw new PolicyException("Invalid root CA configuration.");
            }

            Instant now = Instant.now();
            String serial = UUID.randomUUID().toString();
            String id = generateId("ROOT");

            Certificate root = new Certificate(
                id,
                serial,
                subject,
                null,
                CertificateType.ROOT,
                now,
                now.plus(validityDays, ChronoUnit.DAYS),
                true,
                pathLength,
                EnumSet.of(
                    KeyUsage.KEY_CERT_SIGN,
                    KeyUsage.CRL_SIGN
                ),
                keyIdentifier(subject, serial),
                null
            );

            repository.save(root);

            IssuancePolicy policy = new IssuancePolicy(
                validityDays,
                EnumSet.of(
                    KeyUsage.DIGITAL_SIGNATURE,
                    KeyUsage.KEY_ENCIPHERMENT,
                    KeyUsage.KEY_AGREEMENT,
                    KeyUsage.DATA_ENCIPHERMENT,
                    KeyUsage.CONTENT_COMMITMENT
                ),
                true
            );

            authorities.put(
                id,
                new CertificateAuthority(root, policy)
            );

            trustStore.addTrustAnchor(id);

            audit(AuditAction.ROOT_CREATED, id, subject);

            return root;
        }

        Certificate createIntermediateCA(
            String parentId,
            String subject,
            int validityDays,
            int pathLength
        ) {
            CertificateAuthority parent = requireCA(parentId);
            Certificate parentCert = parent.certificate;

            if (
                subject == null ||
                subject.isBlank() ||
                validityDays <= 0 ||
                pathLength < 0
            ) {
                throw new PolicyException(
                    "Invalid intermediate CA configuration."
                );
            }

            if (
                parentCert.getPathLength() != null &&
                parentCert.getPathLength() <= 0
            ) {
                throw new PolicyException("Parent path length exceeded.");
            }

            if (!parent.policy.allowIntermediateCA()) {
                throw new PolicyException(
                    "Parent policy prohibits intermediate CAs."
                );
            }

            Instant now = Instant.now();

            Instant requestedExpiry =
                now.plus(validityDays, ChronoUnit.DAYS);

            Instant expiry = requestedExpiry.isAfter(
                parentCert.getNotAfter()
            ) ? parentCert.getNotAfter() : requestedExpiry;

            if (!expiry.isAfter(now)) {
                throw new PolicyException("Parent expires too soon.");
            }

            String serial = UUID.randomUUID().toString();
            String id = generateId("INT");

            Certificate intermediate = new Certificate(
                id,
                serial,
                subject,
                parentId,
                CertificateType.INTERMEDIATE,
                now,
                expiry,
                true,
                pathLength,
                EnumSet.of(
                    KeyUsage.KEY_CERT_SIGN,
                    KeyUsage.CRL_SIGN
                ),
                keyIdentifier(subject, serial),
                parentCert.getSubjectKeyId()
            );

            repository.save(intermediate);

            IssuancePolicy policy = new IssuancePolicy(
                validityDays,
                parent.policy.allowedUsage(),
                true
            );

            authorities.put(
                id,
                new CertificateAuthority(intermediate, policy)
            );

            parent.issuedCertificates.add(id);

            audit(AuditAction.INTERMEDIATE_CREATED, id, parentId);

            return intermediate;
        }

        Certificate issueCertificate(
            String issuerId,
            String subject,
            int validityDays,
            Set<KeyUsage> usage
        ) {
            CertificateAuthority issuer = requireCA(issuerId);
            Certificate parent = issuer.certificate;

            if (subject == null || subject.isBlank()) {
                throw new PolicyException("Subject is required.");
            }

            if (
                validityDays <= 0 ||
                validityDays > issuer.policy.maximumValidityDays()
            ) {
                throw new PolicyException("Invalid certificate lifetime.");
            }

            if (
                usage == null ||
                usage.isEmpty() ||
                !issuer.policy.allowedUsage().containsAll(usage)
            ) {
                throw new PolicyException("Key usage violates CA policy.");
            }

            if (
                usage.contains(KeyUsage.KEY_CERT_SIGN) ||
                usage.contains(KeyUsage.CRL_SIGN)
            ) {
                throw new PolicyException(
                    "End-entity certificates cannot receive CA privileges."
                );
            }

            Instant now = Instant.now();

            Instant requestedExpiry =
                now.plus(validityDays, ChronoUnit.DAYS);

            Instant expiry = requestedExpiry.isAfter(parent.getNotAfter())
                ? parent.getNotAfter()
                : requestedExpiry;

            if (!expiry.isAfter(now)) {
                throw new PolicyException("Issuer expires too soon.");
            }

            String serial = UUID.randomUUID().toString();
            String id = generateId("LEAF");

            Certificate certificate = new Certificate(
                id,
                serial,
                subject,
                issuerId,
                CertificateType.END_ENTITY,
                now,
                expiry,
                false,
                null,
                usage,
                keyIdentifier(subject, serial),
                parent.getSubjectKeyId()
            );

            repository.save(certificate);

            issuer.issuedCertificates.add(id);

            audit(AuditAction.CERTIFICATE_ISSUED, id, issuerId);

            return certificate;
        }

        List<Certificate> buildChain(String certificateId) {
            List<Certificate> chain = new ArrayList<>();
            Set<String> visited = new HashSet<>();

            Certificate current = repository.require(certificateId);

            while (current != null) {
                if (!visited.add(current.id)) {
                    throw new PKIException("Certificate chain cycle detected.");
                }

                chain.add(current);

                if (current.getIssuerId() == null) {
                    break;
                }

                Certificate parent = repository.require(
                    current.getIssuerId()
                );

                if (
                    !parent.getSubjectKeyId().equals(
                        current.getAuthorityKeyId()
                    )
                ) {
                    throw new PKIException(
                        "Authority key identifier mismatch."
                    );
                }

                current = parent;
            }

            return List.copyOf(chain);
        }

        ValidationResult validate(String certificateId) {
            try {
                List<Certificate> chain = buildChain(certificateId);

                Certificate root = chain.get(chain.size() - 1);

                if (!trustStore.trusts(root.id)) {
                    throw new PKIException("Untrusted root CA.");
                }

                Instant now = Instant.now();

                for (int i = 0; i < chain.size(); i++) {
                    Certificate certificate = chain.get(i);

                    if (
                        certificate.status(now) !=
                        CertificateStatus.ACTIVE
                    ) {
                        throw new PKIException(
                            certificate.id + " is " +
                            certificate.status(now)
                        );
                    }

                    if (i > 0) {
                        Certificate parent = chain.get(i - 1);

                        if (
                            !certificate.getIssuerId().equals(parent.id)
                        ) {
                            throw new PKIException("Invalid issuer relationship.");
                        }

                        if (
                            certificate.isCA() &&
                            !certificate.keyUsage.contains(
                                KeyUsage.KEY_CERT_SIGN
                            )
                        ) {
                            throw new PKIException("Invalid CA key usage.");
                        }

                        Integer parentLimit = parent.getPathLength();

                        if (parentLimit != null) {
                            long subordinateCAs = chain.subList(0, i)
                                .stream()
                                .filter(Certificate::isCA)
                                .count();

                            if (subordinateCAs > parentLimit) {
                                throw new PKIException(
                                    "CA path length exceeded."
                                );
                            }
                        }
                    }
                }

                return new ValidationResult(
                    true,
                    chain.stream().map(Certificate::getId).toList(),
                    "Structurally valid trusted chain."
                );

            } catch (RuntimeException exception) {
                return new ValidationResult(
                    false,
                    List.of(),
                    exception.getMessage()
                );
            }
        }

        void revoke(
            String certificateId,
            RevocationReason reason
        ) {
            Certificate certificate = repository.require(certificateId);

            if (reason == null) {
                throw new PKIException("Revocation reason is required.");
            }

            certificate.revoke(Instant.now(), reason);

            revocations.put(certificateId, reason);

            if (certificate.isCA()) {
                CertificateAuthority ca = authorities.get(certificateId);

                if (ca != null) {
                    ca.deactivate();
                }
            }

            audit(
                AuditAction.CERTIFICATE_REVOKED,
                certificateId,
                reason.name()
            );
        }

        Certificate renew(String certificateId, int validityDays) {
            Certificate old = repository.require(certificateId);

            if (old.getType() != CertificateType.END_ENTITY) {
                throw new PolicyException(
                    "Only end-entity certificates can be renewed."
                );
            }

            if (
                old.status(Instant.now()) == CertificateStatus.REVOKED
            ) {
                throw new PolicyException(
                    "Revoked certificates cannot be renewed."
                );
            }

            Certificate replacement = issueCertificate(
                old.getIssuerId(),
                old.getSubject(),
                validityDays,
                old.getKeyUsage()
            );

            old.setReplacementId(replacement.id);

            audit(
                AuditAction.CERTIFICATE_RENEWED,
                old.id,
                replacement.id
            );

            return replacement;
        }

        void printInventory() {
            System.out.println("\nCERTIFICATE INVENTORY");

            repository.all().stream()
                .sorted((a, b) -> a.id.compareTo(b.id))
                .forEach(cert -> System.out.printf(
                    "%-45s %-15s %-35s%n",
                    cert.id,
                    cert.type,
                    cert.subject
                ));
        }

        void printAudit() {
            System.out.println("\nAUDIT LOG");

            auditLog.forEach(System.out::println);
        }

        List<AuditEvent> getAuditLog() {
            return Collections.unmodifiableList(
                new ArrayList<>(auditLog)
            );
        }

        Map<String, RevocationReason> getRevocations() {
            return Map.copyOf(revocations);
        }
    }

    public static void main(String[] args) {
        try {
            PKIService pki = new PKIService();

            System.out.println("ENTERPRISE PKI MANAGEMENT");

            Certificate root = pki.createRootCA(
                "CN=Enterprise Root CA",
                3650,
                2
            );

            Certificate intermediate = pki.createIntermediateCA(
                root.id,
                "CN=Enterprise Issuing CA",
                730,
                0
            );

            Certificate server = pki.issueCertificate(
                intermediate.id,
                "DNS=api.example.com",
                90,
                EnumSet.of(
                    KeyUsage.DIGITAL_SIGNATURE,
                    KeyUsage.KEY_ENCIPHERMENT
                )
            );

            Certificate client = pki.issueCertificate(
                intermediate.id,
                "CN=enterprise-client",
                60,
                EnumSet.of(KeyUsage.DIGITAL_SIGNATURE)
            );

            System.out.println("\nCERTIFICATE ISSUANCE");

            System.out.println("Root: " + root.id);
            System.out.println("Intermediate: " + intermediate.id);
            System.out.println("Server: " + server.id);
            System.out.println("Client: " + client.id);

            System.out.println("\nCHAIN VALIDATION");

            ValidationResult result = pki.validate(server.id);

            System.out.println("Valid: " + result.valid());
            System.out.println("Message: " + result.message());
            result.chain().forEach(System.out::println);

            System.out.println("\nCERTIFICATE RENEWAL");

            Certificate replacement = pki.renew(server.id, 120);

            System.out.println("Old: " + server.id);
            System.out.println("New: " + replacement.id);

            System.out.println("\nCERTIFICATE REVOCATION");

            pki.revoke(
                client.id,
                RevocationReason.KEY_COMPROMISE
            );

            result = pki.validate(client.id);

            System.out.println("Valid: " + result.valid());
            System.out.println("Message: " + result.message());

            System.out.println("\nPOLICY FAILURE");

            try {
                pki.issueCertificate(
                    intermediate.id,
                    "CN=invalid",
                    5000,
                    EnumSet.of(KeyUsage.DIGITAL_SIGNATURE)
                );
            } catch (PKIException exception) {
                System.out.println("Expected: " + exception.getMessage());
            }

            System.out.println("\nREPEATED REVOCATION FAILURE");

            try {
                pki.revoke(
                    client.id,
                    RevocationReason.KEY_COMPROMISE
                );
            } catch (PKIException exception) {
                System.out.println("Expected: " + exception.getMessage());
            }

            if (!pki.validate(replacement.id).valid()) {
                throw new PKIException("Renewed certificate validation failed.");
            }

            if (pki.validate(client.id).valid()) {
                throw new PKIException("Revoked certificate was accepted.");
            }

            pki.printInventory();
            pki.printAudit();

            System.out.println("\nAudit records: " + pki.getAuditLog().size());

            System.out.println("\nAll enterprise PKI tests passed.");

        } catch (RuntimeException exception) {
            System.err.println("PKI execution error: " + exception.getMessage());
            System.exit(1);
        }
    }
}
