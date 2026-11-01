import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

public class SymmetricCryptographyDemo {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private static final int AES_KEY_BITS = 256;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    enum KeyStatus {
        ACTIVE,
        RETIRED,
        REVOKED
    }

    enum EncryptionMode {
        GCM,
        CBC_HMAC
    }

    record KeyRecord(
        String keyId,
        SecretKey key,
        Instant createdAt,
        KeyStatus status
    ) {}

    record CipherEnvelope(
        String algorithm,
        String keyId,
        byte[] iv,
        byte[] ciphertext,
        byte[] tag,
        byte[] aad
    ) {}

    static final class CryptoException
        extends Exception {

        CryptoException(String message) {
            super(message);
        }

        CryptoException(
            String message,
            Throwable cause
        ) {
            super(message, cause);
        }
    }

    static final class KeyManager {

        private final Map<String, KeyRecord> keys =
            new java.util.LinkedHashMap<>();

        private String activeKeyId;

        KeyRecord generateKey()
            throws CryptoException {

            byte[] rawKey = randomBytes(
                AES_KEY_BITS / 8
            );

            String id = UUID.randomUUID().toString();

            if (activeKeyId != null) {
                KeyRecord previous =
                    keys.get(activeKeyId);

                keys.put(
                    activeKeyId,
                    new KeyRecord(
                        previous.keyId(),
                        previous.key(),
                        previous.createdAt(),
                        KeyStatus.RETIRED
                    )
                );
            }

            SecretKey key = new SecretKeySpec(
                rawKey,
                "AES"
            );

            KeyRecord record = new KeyRecord(
                id,
                key,
                Instant.now(),
                KeyStatus.ACTIVE
            );

            keys.put(id, record);
            activeKeyId = id;

            return record;
        }

        KeyRecord activeKey()
            throws CryptoException {

            if (activeKeyId == null) {
                throw new CryptoException(
                    "No active encryption key"
                );
            }

            KeyRecord record =
                keys.get(activeKeyId);

            if (record.status() != KeyStatus.ACTIVE) {
                throw new CryptoException(
                    "Active key is not usable"
                );
            }

            return record;
        }

        KeyRecord get(String keyId)
            throws CryptoException {

            KeyRecord record = keys.get(keyId);

            if (record == null) {
                throw new CryptoException(
                    "Unknown key identifier"
                );
            }

            if (record.status() != KeyStatus.ACTIVE) {
                throw new CryptoException(
                    "Requested key is not active"
                );
            }

            return record;
        }
    }

    static final class GcmService {

        CipherEnvelope encrypt(
            KeyRecord keyRecord,
            byte[] plaintext,
            byte[] aad
        ) throws CryptoException {

            try {
                byte[] iv =
                    randomBytes(GCM_IV_BYTES);

                Cipher cipher =
                    Cipher.getInstance(
                        "AES/GCM/NoPadding"
                    );

                GCMParameterSpec parameters =
                    new GCMParameterSpec(
                        GCM_TAG_BITS,
                        iv
                    );

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    keyRecord.key(),
                    parameters
                );

                cipher.updateAAD(aad);

                byte[] combined =
                    cipher.doFinal(plaintext);

                int tagLength =
                    GCM_TAG_BITS / 8;

                int ciphertextLength =
                    combined.length - tagLength;

                byte[] ciphertext =
                    java.util.Arrays.copyOfRange(
                        combined,
                        0,
                        ciphertextLength
                    );

                byte[] tag =
                    java.util.Arrays.copyOfRange(
                        combined,
                        ciphertextLength,
                        combined.length
                    );

                return new CipherEnvelope(
                    "AES-256-GCM",
                    keyRecord.keyId(),
                    iv,
                    ciphertext,
                    tag,
                    aad
                );
            } catch (GeneralSecurityException e) {
                throw new CryptoException(
                    "GCM encryption failed",
                    e
                );
            }
        }

        byte[] decrypt(
            KeyRecord keyRecord,
            CipherEnvelope envelope
        ) throws CryptoException {

            if (!"AES-256-GCM".equals(
                    envelope.algorithm())) {
                throw new CryptoException(
                    "Unsupported encryption algorithm"
                );
            }

            if (envelope.iv().length !=
                GCM_IV_BYTES) {
                throw new CryptoException(
                    "GCM IV must be 12 bytes"
                );
            }

            try {
                Cipher cipher =
                    Cipher.getInstance(
                        "AES/GCM/NoPadding"
                    );

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    keyRecord.key(),
                    new GCMParameterSpec(
                        GCM_TAG_BITS,
                        envelope.iv()
                    )
                );

                cipher.updateAAD(
                    envelope.aad()
                );

                byte[] authenticatedCiphertext =
                    new byte[
                        envelope.ciphertext().length
                        + envelope.tag().length
                    ];

                System.arraycopy(
                    envelope.ciphertext(),
                    0,
                    authenticatedCiphertext,
                    0,
                    envelope.ciphertext().length
                );

                System.arraycopy(
                    envelope.tag(),
                    0,
                    authenticatedCiphertext,
                    envelope.ciphertext().length,
                    envelope.tag().length
                );

                return cipher.doFinal(
                    authenticatedCiphertext
                );
            } catch (GeneralSecurityException e) {
                throw new CryptoException(
                    "GCM authentication failed",
                    e
                );
            }
        }
    }

    static final class CbcHmacService {

        record Envelope(
            byte[] iv,
            byte[] ciphertext,
            byte[] tag
        ) {}

        Envelope encrypt(
            SecretKey encryptionKey,
            SecretKey macKey,
            byte[] plaintext
        ) throws CryptoException {

            try {
                byte[] iv =
                    randomBytes(16);

                Cipher cipher =
                    Cipher.getInstance(
                        "AES/CBC/PKCS5Padding"
                    );

                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    encryptionKey,
                    new IvParameterSpec(iv)
                );

                byte[] ciphertext =
                    cipher.doFinal(plaintext);

                byte[] authenticatedData =
                    concatenate(
                        "AES-CBC-HMAC-v1"
                            .getBytes(StandardCharsets.UTF_8),
                        iv,
                        ciphertext
                    );

                byte[] tag =
                    hmacSha256(
                        macKey,
                        authenticatedData
                    );

                return new Envelope(
                    iv,
                    ciphertext,
                    tag
                );
            } catch (GeneralSecurityException e) {
                throw new CryptoException(
                    "CBC-HMAC encryption failed",
                    e
                );
            }
        }

        byte[] decrypt(
            SecretKey encryptionKey,
            SecretKey macKey,
            Envelope envelope
        ) throws CryptoException {

            try {
                byte[] authenticatedData =
                    concatenate(
                        "AES-CBC-HMAC-v1"
                            .getBytes(StandardCharsets.UTF_8),
                        envelope.iv(),
                        envelope.ciphertext()
                    );

                byte[] expected =
                    hmacSha256(
                        macKey,
                        authenticatedData
                    );

                if (!MessageDigest.isEqual(
                        expected,
                        envelope.tag())) {
                    throw new CryptoException(
                        "CBC authentication failed"
                    );
                }

                Cipher cipher =
                    Cipher.getInstance(
                        "AES/CBC/PKCS5Padding"
                    );

                cipher.init(
                    Cipher.DECRYPT_MODE,
                    encryptionKey,
                    new IvParameterSpec(
                        envelope.iv()
                    )
                );

                return cipher.doFinal(
                    envelope.ciphertext()
                );
            } catch (GeneralSecurityException e) {
                throw new CryptoException(
                    "CBC-HMAC decryption failed",
                    e
                );
            }
        }
    }

    static SecretKey deriveKey(
        char[] password,
        byte[] salt
    ) throws CryptoException {

        if (password.length < 12) {
            throw new CryptoException(
                "Password must contain at least 12 characters"
            );
        }

        try {
            PBEKeySpec specification =
                new PBEKeySpec(
                    password,
                    salt,
                    16_384,
                    AES_KEY_BITS
                );

            SecretKeyFactory factory =
                SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256"
                );

            byte[] derived =
                factory.generateSecret(
                    specification
                ).getEncoded();

            return new SecretKeySpec(
                derived,
                "AES"
            );
        } catch (GeneralSecurityException e) {
            throw new CryptoException(
                "Password key derivation failed",
                e
            );
        }
    }

    static byte[] hmacSha256(
        SecretKey key,
        byte[] data
    ) throws CryptoException {

        try {
            Mac mac =
                Mac.getInstance("HmacSHA256");

            mac.init(
                new SecretKeySpec(
                    key.getEncoded(),
                    "HmacSHA256"
                )
            );

            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new CryptoException(
                "HMAC calculation failed",
                e
            );
        }
    }

    static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    static byte[] concatenate(byte[]... arrays) {
        int total = 0;

        for (byte[] array : arrays) {
            total += array.length;
        }

        byte[] result = new byte[total];
        int position = 0;

        for (byte[] array : arrays) {
            System.arraycopy(
                array,
                0,
                result,
                position,
                array.length
            );

            position += array.length;
        }

        return result;
    }

    static void assertTrue(
        boolean condition,
        String message
    ) throws CryptoException {

        if (!condition) {
            throw new CryptoException(message);
        }
    }

    static void runTests()
        throws CryptoException {

        KeyManager manager =
            new KeyManager();

        KeyRecord record =
            manager.generateKey();

        GcmService gcm =
            new GcmService();

        byte[] plaintext =
            "Confidential deployment configuration"
                .getBytes(StandardCharsets.UTF_8);

        byte[] aad =
            "repository=payments;branch=main"
                .getBytes(StandardCharsets.UTF_8);

        CipherEnvelope envelope =
            gcm.encrypt(
                record,
                plaintext,
                aad
            );

        byte[] recovered =
            gcm.decrypt(
                record,
                envelope
            );

        assertTrue(
            java.util.Arrays.equals(
                plaintext,
                recovered
            ),
            "GCM round-trip failed"
        );

        byte[] tampered =
            envelope.ciphertext().clone();

        tampered[0] ^= 1;

        CipherEnvelope modified =
            new CipherEnvelope(
                envelope.algorithm(),
                envelope.keyId(),
                envelope.iv(),
                tampered,
                envelope.tag(),
                envelope.aad()
            );

        try {
            gcm.decrypt(
                record,
                modified
            );

            throw new CryptoException(
                "Tampering was not detected"
            );
        } catch (CryptoException expected) {
            assertTrue(
                expected.getMessage()
                    .contains("authentication"),
                "Unexpected tamper failure"
            );
        }

        SecretKey cbcKey =
            new SecretKeySpec(
                randomBytes(32),
                "AES"
            );

        SecretKey macKey =
            new SecretKeySpec(
                randomBytes(32),
                "HmacSHA256"
            );

        CbcHmacService cbc =
            new CbcHmacService();

        CbcHmacService.Envelope cbcEnvelope =
            cbc.encrypt(
                cbcKey,
                macKey,
                plaintext
            );

        assertTrue(
            java.util.Arrays.equals(
                plaintext,
                cbc.decrypt(
                    cbcKey,
                    macKey,
                    cbcEnvelope
                )
            ),
            "CBC-HMAC round-trip failed"
        );

        byte[] salt =
            randomBytes(16);

        SecretKey derived =
            deriveKey(
                "correct-horse-battery-staple"
                    .toCharArray(),
                salt
            );

        assertTrue(
            derived.getEncoded().length == 32,
            "Derived key length is incorrect"
        );

        KeyRecord rotated =
            manager.generateKey();

        assertTrue(
            !rotated.keyId().equals(
                record.keyId()
            ),
            "Key rotation failed"
        );

        System.out.println(
            "AES-GCM round-trip: PASS"
        );
        System.out.println(
            "AES-GCM tamper detection: PASS"
        );
        System.out.println(
            "AES-CBC-HMAC round-trip: PASS"
        );
        System.out.println(
            "PBKDF2 key derivation: PASS"
        );
        System.out.println(
            "Key rotation: PASS"
        );
    }

    public static void main(String[] args) {
        try {
            runTests();

            KeyManager keyManager =
                new KeyManager();

            KeyRecord active =
                keyManager.generateKey();

            GcmService service =
                new GcmService();

            String configuration =
                """
                repository=payments
                branch=main
                requiredReviews=2
                requiredStatusChecks=3
                """;

            byte[] aad =
                ("repository=payments;keyId="
                    + active.keyId())
                    .getBytes(
                        StandardCharsets.UTF_8
                    );

            CipherEnvelope envelope =
                service.encrypt(
                    active,
                    configuration.getBytes(
                        StandardCharsets.UTF_8
                    ),
                    aad
                );

            System.out.println(
                "\nEnterprise encryption record:"
            );
            System.out.println(
                "Algorithm: "
                + envelope.algorithm()
            );
            System.out.println(
                "Key ID: "
                + envelope.keyId()
            );
            System.out.println(
                "IV: "
                + HEX.formatHex(
                    envelope.iv()
                )
            );
            System.out.println(
                "Tag: "
                + HEX.formatHex(
                    envelope.tag()
                )
            );
            System.out.println(
                "Ciphertext bytes: "
                + envelope.ciphertext().length
            );

            byte[] plaintext =
                service.decrypt(
                    active,
                    envelope
                );

            System.out.println(
                "\nRecovered configuration:"
            );
            System.out.println(
                new String(
                    plaintext,
                    StandardCharsets.UTF_8
                )
            );

        } catch (Exception e) {
            System.err.println(
                "Cryptographic operation failed: "
                    + e.getMessage()
            );
            System.exit(1);
        }
    }
}
