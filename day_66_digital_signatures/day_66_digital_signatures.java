import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/*
 * Digital Signatures: Enterprise Document Approval System.
 *
 * Java 17 standard cryptographic APIs.
 * Ed25519 provides signing and verification.
 * SHA-256 provides document fingerprints.
 *
 * Certificate records are signed by an issuing authority.
 * Trust anchors and revocation are evaluated separately.
 */

public class DigitalSignatures {

    enum VerificationStatus {
        VALID,
        INVALID,
        EXPIRED,
        NOT_YET_VALID,
        REVOKED,
        UNTRUSTED
    }

    enum DocumentState {
        DRAFT,
        SIGNED,
        VERIFIED,
        REJECTED
    }

    static class SecurityValidationException extends Exception {
        SecurityValidationException(String message) {
            super(message);
        }
    }

    record KeyIdentity(
        String name,
        PrivateKey privateKey,
        PublicKey publicKey
    ) {
        KeyIdentity {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException(
                    "Identity is required"
                );
            }

            Objects.requireNonNull(privateKey);
            Objects.requireNonNull(publicKey);
        }

        static KeyIdentity generate(String name)
                throws GeneralSecurityException {
            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("Ed25519");

            KeyPair pair = generator.generateKeyPair();

            return new KeyIdentity(
                name,
                pair.getPrivate(),
                pair.getPublic()
            );
        }
    }

    record CertificateRecord(
        String serial,
        String subject,
        String issuer,
        PublicKey publicKey,
        Instant notBefore,
        Instant notAfter,
        byte[] signature
    ) {
        CertificateRecord {
            if (serial == null || serial.isBlank()) {
                throw new IllegalArgumentException(
                    "Serial number is required"
                );
            }

            Objects.requireNonNull(subject);
            Objects.requireNonNull(issuer);
            Objects.requireNonNull(publicKey);
            Objects.requireNonNull(notBefore);
            Objects.requireNonNull(notAfter);

            if (!notAfter.isAfter(notBefore)) {
                throw new IllegalArgumentException(
                    "Invalid certificate validity interval"
                );
            }

            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }

        byte[] payload() {
            String encoded = String.join(
                "|",
                serial,
                subject,
                issuer,
                Base64.getEncoder().encodeToString(
                    publicKey.getEncoded()
                ),
                notBefore.toString(),
                notAfter.toString()
            );

            return encoded.getBytes(StandardCharsets.UTF_8);
        }
    }

    static class CertificateAuthority {

        private final String name;
        private final KeyPair keyPair;

        CertificateAuthority(String name)
                throws GeneralSecurityException {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException(
                    "CA name is required"
                );
            }

            this.name = name;

            KeyPairGenerator generator =
                KeyPairGenerator.getInstance("Ed25519");

            this.keyPair = generator.generateKeyPair();
        }

        String name() {
            return name;
        }

        PublicKey publicKey() {
            return keyPair.getPublic();
        }

        CertificateRecord issue(
            KeyIdentity identity,
            String serial,
            Instant notBefore,
            Instant notAfter
        ) throws GeneralSecurityException {

            if (identity == null) {
                throw new IllegalArgumentException(
                    "Identity is required"
                );
            }

            CertificateRecord unsigned =
                new CertificateRecord(
                    serial,
                    identity.name(),
                    name,
                    identity.publicKey(),
                    notBefore,
                    notAfter,
                    new byte[0]
                );

            Signature signature =
                Signature.getInstance("Ed25519");

            signature.initSign(keyPair.getPrivate());
            signature.update(unsigned.payload());

            return new CertificateRecord(
                serial,
                identity.name(),
                name,
                identity.publicKey(),
                notBefore,
                notAfter,
                signature.sign()
            );
        }
    }

    static class TrustStore {

        private final Map<String, PublicKey> anchors =
            new ConcurrentHashMap<>();

        private final Set<String> revoked =
            ConcurrentHashMap.newKeySet();

        void addTrustAnchor(String name, PublicKey key) {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException(
                    "Trust anchor name is required"
                );
            }

            anchors.put(name, Objects.requireNonNull(key));
        }

        void revoke(String serial) {
            revoked.add(serial);
        }

        boolean isRevoked(String serial) {
            return revoked.contains(serial);
        }

        PublicKey findIssuer(String issuer) {
            return anchors.get(issuer);
        }
    }

    record SignedDocument(
        String documentId,
        String content,
        String signer,
        String certificateSerial,
        byte[] signature,
        String digest,
        Instant signedAt
    ) {
        SignedDocument {
            Objects.requireNonNull(documentId);
            Objects.requireNonNull(content);
            Objects.requireNonNull(signer);
            Objects.requireNonNull(certificateSerial);
            Objects.requireNonNull(signature);
            Objects.requireNonNull(digest);
            Objects.requireNonNull(signedAt);

            signature = signature.clone();
        }

        @Override
        public byte[] signature() {
            return signature.clone();
        }
    }

    static class DocumentService {

        private final Map<String, SignedDocument> documents =
            new ConcurrentHashMap<>();

        SignedDocument sign(
            String documentId,
            String content,
            KeyIdentity identity,
            CertificateRecord certificate
        ) throws GeneralSecurityException,
                 SecurityValidationException {

            if (documentId == null || documentId.isBlank()) {
                throw new IllegalArgumentException(
                    "Document ID is required"
                );
            }

            if (content == null || content.isBlank()) {
                throw new IllegalArgumentException(
                    "Document content is required"
                );
            }

            if (!certificate.subject().equals(identity.name())) {
                throw new SecurityValidationException(
                    "Certificate identity mismatch"
                );
            }

            if (!MessageDigest.isEqual(
                certificate.publicKey().getEncoded(),
                identity.publicKey().getEncoded()
            )) {
                throw new SecurityValidationException(
                    "Public key does not match certificate"
                );
            }

            if (documents.containsKey(documentId)) {
                throw new SecurityValidationException(
                    "Document ID already exists"
                );
            }

            byte[] contentBytes =
                content.getBytes(StandardCharsets.UTF_8);

            Signature signature =
                Signature.getInstance("Ed25519");

            signature.initSign(identity.privateKey());
            signature.update(contentBytes);

            SignedDocument signed = new SignedDocument(
                documentId,
                content,
                identity.name(),
                certificate.serial(),
                signature.sign(),
                digest(contentBytes),
                Instant.now()
            );

            SignedDocument previous =
                documents.putIfAbsent(documentId, signed);

            if (previous != null) {
                throw new SecurityValidationException(
                    "Concurrent document creation conflict"
                );
            }

            return signed;
        }

        SignedDocument get(String documentId) {
            return documents.get(documentId);
        }
    }

    static class VerificationService {

        private final TrustStore trustStore;

        VerificationService(TrustStore trustStore) {
            this.trustStore = trustStore;
        }

        VerificationStatus verify(
            SignedDocument document,
            CertificateRecord certificate,
            Instant currentTime
        ) throws GeneralSecurityException {

            if (trustStore.isRevoked(certificate.serial())) {
                return VerificationStatus.REVOKED;
            }

            if (!document.certificateSerial().equals(
                    certificate.serial())) {
                return VerificationStatus.INVALID;
            }

            if (currentTime.isBefore(certificate.notBefore())) {
                return VerificationStatus.NOT_YET_VALID;
            }

            if (currentTime.isAfter(certificate.notAfter())) {
                return VerificationStatus.EXPIRED;
            }

            if (!certificate.subject().equals(document.signer())) {
                return VerificationStatus.INVALID;
            }

            PublicKey issuerKey =
                trustStore.findIssuer(certificate.issuer());

            if (issuerKey == null) {
                return VerificationStatus.UNTRUSTED;
            }

            Signature certificateVerifier =
                Signature.getInstance("Ed25519");

            certificateVerifier.initVerify(issuerKey);
            certificateVerifier.update(certificate.payload());

            if (!certificateVerifier.verify(
                    certificate.signature())) {
                return VerificationStatus.INVALID;
            }

            byte[] content =
                document.content().getBytes(StandardCharsets.UTF_8);

            if (!digest(content).equals(document.digest())) {
                return VerificationStatus.INVALID;
            }

            Signature documentVerifier =
                Signature.getInstance("Ed25519");

            documentVerifier.initVerify(certificate.publicKey());
            documentVerifier.update(content);

            return documentVerifier.verify(document.signature())
                ? VerificationStatus.VALID
                : VerificationStatus.INVALID;
        }
    }

    static String digest(byte[] data)
            throws GeneralSecurityException {
        return HexFormat.of().formatHex(
            MessageDigest.getInstance("SHA-256").digest(data)
        );
    }

    public static void main(String[] args) {

        try {
            Instant now = Instant.now();

            // Establish issuing authority and trust anchor.
            CertificateAuthority authority =
                new CertificateAuthority("Enterprise Root CA");

            TrustStore trustStore = new TrustStore();

            trustStore.addTrustAnchor(
                authority.name(),
                authority.publicKey()
            );

            // Generate the employee signing identity.
            KeyIdentity employee =
                KeyIdentity.generate("employee@enterprise.example");

            CertificateRecord certificate = authority.issue(
                employee,
                "CERT-2026-001",
                now.minusSeconds(60),
                now.plus(Duration.ofDays(365))
            );

            // Create and sign an enterprise document.
            DocumentService documentService =
                new DocumentService();

            SignedDocument signed = documentService.sign(
                "CONTRACT-1001",
                "Agreement: INR 500000 payable within 30 days.",
                employee,
                certificate
            );

            VerificationService verification =
                new VerificationService(trustStore);

            System.out.println("DOCUMENT SIGNING");
            System.out.println("-----------------");
            System.out.println("ID: " + signed.documentId());
            System.out.println("Signer: " + signed.signer());
            System.out.println("SHA-256: " + signed.digest());

            VerificationStatus valid = verification.verify(
                signed,
                certificate,
                Instant.now()
            );

            System.out.println("\nOriginal: " + valid);

            if (valid != VerificationStatus.VALID) {
                throw new SecurityValidationException(
                    "Expected valid signature"
                );
            }

            // Modification without a new signature.
            SignedDocument modified = new SignedDocument(
                signed.documentId(),
                "Agreement: INR 900000 payable within 30 days.",
                signed.signer(),
                signed.certificateSerial(),
                signed.signature(),
                signed.digest(),
                signed.signedAt()
            );

            System.out.println(
                "Modified: " + verification.verify(
                    modified, certificate, Instant.now()
                )
            );

            // Expired certificate.
            System.out.println(
                "Expired: " + verification.verify(
                    signed,
                    certificate,
                    certificate.notAfter().plusSeconds(1)
                )
            );

            // Unknown issuing authority.
            VerificationService unknownVerifier =
                new VerificationService(new TrustStore());

            System.out.println(
                "Untrusted: " + unknownVerifier.verify(
                    signed, certificate, Instant.now()
                )
            );

            // Certificate revocation.
            trustStore.revoke(certificate.serial());

            System.out.println(
                "Revoked: " + verification.verify(
                    signed, certificate, Instant.now()
                )
            );

            System.out.println("\nEnterprise workflow completed.");

        } catch (
            GeneralSecurityException |
            SecurityValidationException |
            IllegalArgumentException error
        ) {
            System.err.println(
                "Security processing failed: " + error.getMessage()
            );
            System.exit(1);
        }
    }
}
