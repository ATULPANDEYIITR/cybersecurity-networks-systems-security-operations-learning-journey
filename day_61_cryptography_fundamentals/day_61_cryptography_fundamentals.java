import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Cryptography Fundamentals
 *
 * Enterprise-oriented secure-message workflow:
 *
 * Application -> MessageService -> symmetric encryption
 *                           -> integrity verification
 *                           -> asymmetric key protection
 *
 * AES-256-GCM is used for authenticated symmetric encryption.
 * RSA-OAEP is used for asymmetric encryption.
 *
 * Java's JCA/JCE APIs are used instead of implementing production
 * cryptographic primitives manually.
 */
public class CryptographyFundamentals {

    enum MessageState {
        CREATED,
        ENCRYPTED,
        VERIFIED,
        DECRYPTED,
        REJECTED
    }

    record EncryptedEnvelope(
        byte[] iv,
        byte[] ciphertext,
        byte[] authenticationTag,
        MessageState state
    ) {
        EncryptedEnvelope {
            Objects.requireNonNull(iv);
            Objects.requireNonNull(ciphertext);
            Objects.requireNonNull(authenticationTag);
            Objects.requireNonNull(state);

            if (iv.length != 12) {
                throw new IllegalArgumentException("GCM IV must contain 12 bytes.");
            }
        }
    }

    record ProtectedKey(
        byte[] encryptedKey,
        String algorithm
    ) {}

    static final class CryptoPolicy {
        private final int minimumAesKeyBits;
        private final int minimumRsaKeyBits;

        CryptoPolicy(int minimumAesKeyBits, int minimumRsaKeyBits) {
            if (minimumAesKeyBits < 256) {
                throw new IllegalArgumentException(
                    "AES policy must require at least 256 bits."
                );
            }

            if (minimumRsaKeyBits < 2048) {
                throw new IllegalArgumentException(
                    "RSA policy must require at least 2048 bits."
                );
            }

            this.minimumAesKeyBits = minimumAesKeyBits;
            this.minimumRsaKeyBits = minimumRsaKeyBits;
        }

        int minimumAesKeyBits() {
            return minimumAesKeyBits;
        }

        int minimumRsaKeyBits() {
            return minimumRsaKeyBits;
        }

        void validateAesKey(SecretKey key) {
            Objects.requireNonNull(key);

            if (!"AES".equalsIgnoreCase(key.getAlgorithm())) {
                throw new SecurityException("Only AES keys are permitted.");
            }

            if (key.getEncoded() == null ||
                key.getEncoded().length * 8 < minimumAesKeyBits) {
                throw new SecurityException("AES key does not satisfy policy.");
            }
        }

        void validateRsaKey(KeyPair keyPair) {
            Objects.requireNonNull(keyPair);

            int estimatedBits = ((java.security.interfaces.RSAPublicKey)
                keyPair.getPublic()).getModulus().bitLength();

            if (estimatedBits < minimumRsaKeyBits) {
                throw new SecurityException("RSA key does not satisfy policy.");
            }
        }
    }

    static final class SecureMessageService {
        private static final int GCM_TAG_BITS = 128;
        private final SecureRandom random = new SecureRandom();
        private final CryptoPolicy policy;

        SecureMessageService(CryptoPolicy policy) {
            this.policy = Objects.requireNonNull(policy);
        }

        SecretKey generateAesKey() throws GeneralSecurityException {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(policy.minimumAesKeyBits(), random);
            return generator.generateKey();
        }

        KeyPair generateRsaKeyPair() throws GeneralSecurityException {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(
                policy.minimumRsaKeyBits(),
                random
            );

            KeyPair keyPair = generator.generateKeyPair();
            policy.validateRsaKey(keyPair);

            return keyPair;
        }

        EncryptedEnvelope encrypt(
            String plaintext,
            SecretKey key
        ) throws GeneralSecurityException {
            validatePlaintext(plaintext);
            policy.validateAesKey(key);

            byte[] iv = new byte[12];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                Cipher.ENCRYPT_MODE,
                key,
                new GCMParameterSpec(GCM_TAG_BITS, iv)
            );

            byte[] combined = cipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8)
            );

            /*
             * JCA returns ciphertext followed by the authentication tag.
             * Keeping them separated makes the envelope explicit.
             */
            int tagLength = GCM_TAG_BITS / 8;

            byte[] ciphertext = Arrays.copyOf(
                combined,
                combined.length - tagLength
            );

            byte[] tag = Arrays.copyOfRange(
                combined,
                combined.length - tagLength,
                combined.length
            );

            return new EncryptedEnvelope(
                iv,
                ciphertext,
                tag,
                MessageState.ENCRYPTED
            );
        }

        String decrypt(
            EncryptedEnvelope envelope,
            SecretKey key
        ) throws GeneralSecurityException {
            Objects.requireNonNull(envelope);
            policy.validateAesKey(key);

            if (envelope.state() != MessageState.ENCRYPTED) {
                throw new SecurityException(
                    "Only encrypted envelopes may be decrypted."
                );
            }

            byte[] combined = new byte[
                envelope.ciphertext().length +
                envelope.authenticationTag().length
            ];

            System.arraycopy(
                envelope.ciphertext(),
                0,
                combined,
                0,
                envelope.ciphertext().length
            );

            System.arraycopy(
                envelope.authenticationTag(),
                0,
                combined,
                envelope.ciphertext().length,
                envelope.authenticationTag().length
            );

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                new GCMParameterSpec(
                    GCM_TAG_BITS,
                    envelope.iv()
                )
            );

            try {
                byte[] plaintext = cipher.doFinal(combined);

                return new String(
                    plaintext,
                    StandardCharsets.UTF_8
                );
            } catch (GeneralSecurityException error) {
                throw new SecurityException(
                    "Authentication failed or ciphertext was modified.",
                    error
                );
            }
        }

        ProtectedKey wrapSymmetricKey(
            SecretKey symmetricKey,
            PublicKey publicKey
        ) throws GeneralSecurityException {
            Objects.requireNonNull(symmetricKey);
            Objects.requireNonNull(publicKey);

            Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return new ProtectedKey(
                cipher.doFinal(symmetricKey.getEncoded()),
                "RSA-OAEP-SHA-256"
            );
        }

        SecretKey unwrapSymmetricKey(
            ProtectedKey protectedKey,
            PrivateKey privateKey
        ) throws GeneralSecurityException {
            Objects.requireNonNull(protectedKey);
            Objects.requireNonNull(privateKey);

            Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
            );

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] rawKey = cipher.doFinal(
                protectedKey.encryptedKey()
            );

            return new SecretKeySpec(rawKey, "AES");
        }

        byte[] hmac(
            byte[] message,
            byte[] secret
        ) throws GeneralSecurityException {
            if (secret.length < 32) {
                throw new SecurityException(
                    "HMAC secret must contain at least 32 bytes."
                );
            }

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));

            return mac.doFinal(message);
        }

        boolean verifyHmac(
            byte[] message,
            byte[] secret,
            byte[] expected
        ) throws GeneralSecurityException {
            byte[] actual = hmac(message, secret);
            return MessageDigest.isEqual(actual, expected);
        }
    }

    record AuditEvent(
        String actor,
        String operation,
        MessageState state,
        boolean allowed
    ) {}

    static final class AuditLog {
        private final List<AuditEvent> events = new ArrayList<>();

        void record(AuditEvent event) {
            events.add(Objects.requireNonNull(event));
        }

        List<AuditEvent> snapshot() {
            return List.copyOf(events);
        }
    }

    private static void validatePlaintext(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) {
            throw new IllegalArgumentException(
                "Plaintext must not be null or blank."
            );
        }

        if (plaintext.getBytes(StandardCharsets.UTF_8).length > 1_048_576) {
            throw new IllegalArgumentException(
                "Plaintext exceeds the 1 MiB limit."
            );
        }
    }

    private static String fingerprint(byte[] key) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest
            .getInstance("SHA-256")
            .digest(key);

        return HexFormat.of()
            .formatHex(digest)
            .substring(0, 16);
    }

    private static void demonstrateBasicConcepts() {
        System.out.println("=== Plaintext and Ciphertext ===");

        String plaintext = "Meet at 10:30";
        byte[] plaintextBytes =
            plaintext.getBytes(StandardCharsets.UTF_8);

        String encoded =
            Base64.getEncoder().encodeToString(plaintextBytes);

        String recovered =
            new String(
                Base64.getDecoder().decode(encoded),
                StandardCharsets.UTF_8
            );

        System.out.println("Plaintext : " + plaintext);
        System.out.println("Encoded representation: " + encoded);
        System.out.println("Recovered : " + recovered);

        if (!plaintext.equals(recovered)) {
            throw new IllegalStateException(
                "Basic transformation failed."
            );
        }
    }

    private static void demonstrateEnterpriseWorkflow()
        throws Exception {

        System.out.println("\n=== Enterprise Encryption Workflow ===");

        CryptoPolicy policy = new CryptoPolicy(256, 2048);
        SecureMessageService service =
            new SecureMessageService(policy);

        AuditLog audit = new AuditLog();

        SecretKey dataKey = service.generateAesKey();
        KeyPair wrappingKeyPair = service.generateRsaKeyPair();

        audit.record(
            new AuditEvent(
                "payments-service",
                "CREATE_DATA_KEY",
                MessageState.CREATED,
                true
            )
        );

        String plaintext =
            "Customer payment instruction: transaction=TX-2048";

        EncryptedEnvelope envelope =
            service.encrypt(plaintext, dataKey);

        audit.record(
            new AuditEvent(
                "payments-service",
                "ENCRYPT",
                envelope.state(),
                true
            )
        );

        ProtectedKey protectedKey =
            service.wrapSymmetricKey(
                dataKey,
                wrappingKeyPair.getPublic()
            );

        audit.record(
            new AuditEvent(
                "key-service",
                "WRAP_DATA_KEY",
                MessageState.ENCRYPTED,
                true
            )
        );

        SecretKey recoveredDataKey =
            service.unwrapSymmetricKey(
                protectedKey,
                wrappingKeyPair.getPrivate()
            );

        String recovered =
            service.decrypt(
                envelope,
                recoveredDataKey
            );

        audit.record(
            new AuditEvent(
                "payments-service",
                "DECRYPT",
                MessageState.DECRYPTED,
                true
            )
        );

        if (!plaintext.equals(recovered)) {
            throw new SecurityException(
                "Hybrid encryption recovery failed."
            );
        }

        System.out.println(
            "AES key fingerprint: " +
            fingerprint(dataKey.getEncoded())
        );

        System.out.println(
            "RSA-wrapped AES key bytes: " +
            protectedKey.encryptedKey().length
        );

        System.out.println("Recovered message: " + recovered);

        System.out.println("\nAudit events:");

        for (AuditEvent event : audit.snapshot()) {
            System.out.printf(
                "%s | %s | %s | allowed=%s%n",
                event.actor(),
                event.operation(),
                event.state(),
                event.allowed()
            );
        }
    }

    private static void demonstrateHmac(
        SecureMessageService service,
        SecretKey key
    ) throws Exception {

        System.out.println("\n=== Integrity Authentication ===");

        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);

        byte[] message =
            "Authenticated message".getBytes(StandardCharsets.UTF_8);

        byte[] tag =
            service.hmac(message, secret);

        boolean valid =
            service.verifyHmac(message, secret, tag);

        System.out.println("Valid tag: " + valid);

        byte[] tampered = message.clone();
        tampered[0] ^= 1;

        boolean tamperedValid =
            service.verifyHmac(tampered, secret, tag);

        System.out.println(
            "Tampered message accepted: " + tamperedValid
        );

        if (tamperedValid) {
            throw new SecurityException(
                "Tampering was not detected."
            );
        }
    }

    private static void demonstrateFailureHandling(
        SecureMessageService service
    ) throws Exception {

        System.out.println("\n=== Failure Handling ===");

        SecretKey key = service.generateAesKey();

        EncryptedEnvelope envelope =
            service.encrypt(
                "Sensitive record",
                key
            );

        byte[] modifiedCiphertext =
            envelope.ciphertext().clone();

        modifiedCiphertext[0] ^= 1;

        EncryptedEnvelope tampered =
            new EncryptedEnvelope(
                envelope.iv(),
                modifiedCiphertext,
                envelope.authenticationTag(),
                MessageState.ENCRYPTED
            );

        try {
            service.decrypt(tampered, key);
            throw new IllegalStateException(
                "Tampered ciphertext was accepted."
            );
        } catch (SecurityException expected) {
            System.out.println(
                "Tampered ciphertext rejected."
            );
        }

        try {
            service.encrypt("", key);
            throw new IllegalStateException(
                "Empty plaintext was accepted."
            );
        } catch (IllegalArgumentException expected) {
            System.out.println(
                "Empty plaintext rejected."
            );
        }
    }

    public static void main(String[] args) {
        try {
            demonstrateBasicConcepts();

            CryptoPolicy policy =
                new CryptoPolicy(256, 2048);

            SecureMessageService service =
                new SecureMessageService(policy);

            demonstrateEnterpriseWorkflow();

            SecretKey key =
                service.generateAesKey();

            demonstrateHmac(service, key);
            demonstrateFailureHandling(service);

            System.out.println("\nCryptography workflow completed successfully.");

        } catch (Exception error) {
            System.err.println(
                "Fatal error: " + error.getMessage()
            );
            System.exit(1);
        }
    }
}
