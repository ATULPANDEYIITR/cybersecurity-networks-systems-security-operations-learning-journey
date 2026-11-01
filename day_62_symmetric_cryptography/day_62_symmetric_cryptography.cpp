#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message)
        : std::runtime_error(message) {}
};

using Bytes = std::vector<unsigned char>;

Bytes random_bytes(std::size_t length) {
    Bytes result(length);

    if (RAND_bytes(result.data(),
                   static_cast<int>(result.size())) != 1) {
        throw CryptoError("Secure random generation failed");
    }

    return result;
}

std::string hex_encode(const Bytes& data) {
    std::ostringstream output;

    for (unsigned char byte : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return output.str();
}

Bytes aes_gcm_encrypt(
    const Bytes& key,
    const Bytes& iv,
    const Bytes& plaintext,
    const Bytes& aad,
    Bytes& tag
) {
    if (key.size() != 32) {
        throw CryptoError("AES-256-GCM requires a 32-byte key");
    }

    if (iv.size() != 12) {
        throw CryptoError("GCM requires a 12-byte IV in this design");
    }

    using Context = std::unique_ptr<
        EVP_CIPHER_CTX,
        decltype(&EVP_CIPHER_CTX_free)
    >;

    Context context(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free
    );

    if (!context) {
        throw CryptoError("Unable to allocate cipher context");
    }

    if (EVP_EncryptInit_ex(
            context.get(),
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr) != 1) {
        throw CryptoError("GCM initialization failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(iv.size()),
            nullptr) != 1) {
        throw CryptoError("GCM IV configuration failed");
    }

    if (EVP_EncryptInit_ex(
            context.get(),
            nullptr,
            nullptr,
            key.data(),
            iv.data()) != 1) {
        throw CryptoError("GCM key initialization failed");
    }

    int output_length = 0;

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(
                context.get(),
                nullptr,
                &output_length,
                aad.data(),
                static_cast<int>(aad.size())) != 1) {
            throw CryptoError("GCM AAD processing failed");
        }
    }

    Bytes ciphertext(plaintext.size() + 16);

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(
                context.get(),
                ciphertext.data(),
                &output_length,
                plaintext.data(),
                static_cast<int>(plaintext.size())) != 1) {
            throw CryptoError("GCM encryption failed");
        }
    } else {
        output_length = 0;
    }

    int final_length = 0;

    if (EVP_EncryptFinal_ex(
            context.get(),
            ciphertext.data() + output_length,
            &final_length) != 1) {
        throw CryptoError("GCM finalization failed");
    }

    ciphertext.resize(
        static_cast<std::size_t>(
            output_length + final_length
        )
    );

    tag.resize(16);

    if (EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_GET_TAG,
            16,
            tag.data()) != 1) {
        throw CryptoError("GCM tag generation failed");
    }

    return ciphertext;
}

Bytes aes_gcm_decrypt(
    const Bytes& key,
    const Bytes& iv,
    const Bytes& ciphertext,
    const Bytes& aad,
    const Bytes& tag
) {
    if (key.size() != 32) {
        throw CryptoError("AES-256-GCM requires a 32-byte key");
    }

    if (iv.size() != 12) {
        throw CryptoError("GCM IV must be 12 bytes");
    }

    if (tag.size() != 16) {
        throw CryptoError("GCM tag must be 16 bytes");
    }

    using Context = std::unique_ptr<
        EVP_CIPHER_CTX,
        decltype(&EVP_CIPHER_CTX_free)
    >;

    Context context(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free
    );

    if (!context) {
        throw CryptoError("Unable to allocate cipher context");
    }

    if (EVP_DecryptInit_ex(
            context.get(),
            EVP_aes_256_gcm(),
            nullptr,
            nullptr,
            nullptr) != 1) {
        throw CryptoError("GCM initialization failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(iv.size()),
            nullptr) != 1) {
        throw CryptoError("GCM IV configuration failed");
    }

    if (EVP_DecryptInit_ex(
            context.get(),
            nullptr,
            nullptr,
            key.data(),
            iv.data()) != 1) {
        throw CryptoError("GCM key initialization failed");
    }

    int output_length = 0;

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(
                context.get(),
                nullptr,
                &output_length,
                aad.data(),
                static_cast<int>(aad.size())) != 1) {
            throw CryptoError("GCM AAD processing failed");
        }
    }

    Bytes plaintext(ciphertext.size() + 16);

    if (!ciphertext.empty()) {
        if (EVP_DecryptUpdate(
                context.get(),
                plaintext.data(),
                &output_length,
                ciphertext.data(),
                static_cast<int>(ciphertext.size())) != 1) {
            throw CryptoError("GCM decryption failed");
        }
    } else {
        output_length = 0;
    }

    if (EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag.size()),
            const_cast<unsigned char*>(tag.data())) != 1) {
        throw CryptoError("Unable to set authentication tag");
    }

    int final_length = 0;

    if (EVP_DecryptFinal_ex(
            context.get(),
            plaintext.data() + output_length,
            &final_length) != 1) {
        throw CryptoError(
            "Authentication failed: ciphertext, AAD, "
            "key, or tag was modified"
        );
    }

    plaintext.resize(
        static_cast<std::size_t>(
            output_length + final_length
        )
    );

    return plaintext;
}

class KeyStore {
public:
    struct KeyRecord {
        Bytes key;
        std::string status;
    };

    std::string create_key() {
        const std::string id =
            "key-" + std::to_string(next_id_++);

        records_.emplace(
            id,
            KeyRecord{random_bytes(32), "ACTIVE"}
        );

        active_key_id_ = id;
        return id;
    }

    void rotate() {
        if (!active_key_id_.empty()) {
            records_.at(active_key_id_).status = "RETIRED";
        }

        create_key();
    }

    const Bytes& active_key() const {
        if (active_key_id_.empty()) {
            throw CryptoError("No active key");
        }

        return active_record().key;
    }

    const std::string& active_id() const {
        return active_key_id_;
    }

    const Bytes& get_active_record_key() const {
        return active_record().key;
    }

private:
    const KeyRecord& active_record() const {
        return records_.at(active_key_id_);
    }

    std::map<std::string, KeyRecord> records_;
    std::string active_key_id_;
    int next_id_ = 1;
};

struct SecureEnvelope {
    std::string algorithm;
    std::string key_id;
    Bytes iv;
    Bytes ciphertext;
    Bytes tag;
    Bytes aad;
};

class MergeSecretService {
public:
    explicit MergeSecretService(KeyStore& key_store)
        : key_store_(key_store) {}

    SecureEnvelope encrypt(const std::string& message) {
        SecureEnvelope envelope;

        envelope.algorithm = "AES-256-GCM";
        envelope.key_id = key_store_.active_id();
        envelope.iv = random_bytes(12);

        const std::string aad_text =
            "repository-governance:key=" +
            envelope.key_id;

        envelope.aad.assign(
            aad_text.begin(),
            aad_text.end()
        );

        Bytes plaintext(
            message.begin(),
            message.end()
        );

        envelope.ciphertext = aes_gcm_encrypt(
            key_store_.active_key(),
            envelope.iv,
            plaintext,
            envelope.aad,
            envelope.tag
        );

        return envelope;
    }

    std::string decrypt(
        const SecureEnvelope& envelope
    ) const {
        if (envelope.algorithm != "AES-256-GCM") {
            throw CryptoError("Unsupported algorithm");
        }

        if (envelope.key_id != key_store_.active_id()) {
            throw CryptoError(
                "This demonstration accepts only the active key"
            );
        }

        Bytes plaintext = aes_gcm_decrypt(
            key_store_.get_active_record_key(),
            envelope.iv,
            envelope.ciphertext,
            envelope.aad,
            envelope.tag
        );

        return std::string(
            plaintext.begin(),
            plaintext.end()
        );
    }

private:
    KeyStore& key_store_;
};

void test_round_trip() {
    KeyStore store;
    store.create_key();

    MergeSecretService service(store);

    const std::string message =
        "Protected deployment configuration";

    SecureEnvelope envelope =
        service.encrypt(message);

    const std::string recovered =
        service.decrypt(envelope);

    if (recovered != message) {
        throw CryptoError("Round-trip test failed");
    }

    std::cout << "AES-GCM round-trip: PASS\n";
}

void test_tampering() {
    KeyStore store;
    store.create_key();

    MergeSecretService service(store);

    SecureEnvelope envelope =
        service.encrypt("sensitive configuration");

    envelope.ciphertext[0] ^= 0x01;

    try {
        service.decrypt(envelope);
        throw CryptoError(
            "Tampering was not detected"
        );
    } catch (const CryptoError& error) {
        const std::string text = error.what();

        if (text.find("Authentication failed") ==
            std::string::npos) {
            throw;
        }
    }

    std::cout << "AES-GCM tamper detection: PASS\n";
}

void test_aad_tampering() {
    KeyStore store;
    store.create_key();

    MergeSecretService service(store);

    SecureEnvelope envelope =
        service.encrypt("protected payload");

    envelope.aad[0] ^= 0x01;

    try {
        service.decrypt(envelope);
        throw CryptoError(
            "AAD tampering was not detected"
        );
    } catch (const CryptoError& error) {
        const std::string text = error.what();

        if (text.find("Authentication failed") ==
            std::string::npos) {
            throw;
        }
    }

    std::cout << "Authenticated AAD: PASS\n";
}

void test_key_rotation() {
    KeyStore store;
    const std::string first = store.create_key();

    if (store.active_id() != first) {
        throw CryptoError("Initial key activation failed");
    }

    store.rotate();

    if (store.active_id() == first) {
        throw CryptoError("Key rotation failed");
    }

    std::cout << "Key rotation: PASS\n";
}

int main() {
    try {
        test_round_trip();
        test_tampering();
        test_aad_tampering();
        test_key_rotation();

        KeyStore store;
        const std::string key_id =
            store.create_key();

        MergeSecretService service(store);

        SecureEnvelope envelope =
            service.encrypt(
                "Confidential repository merge policy"
            );

        std::cout << "\nEnvelope:\n";
        std::cout << "  Algorithm: "
                  << envelope.algorithm << '\n';
        std::cout << "  Key ID: "
                  << envelope.key_id << '\n';
        std::cout << "  IV: "
                  << hex_encode(envelope.iv) << '\n';
        std::cout << "  Tag: "
                  << hex_encode(envelope.tag) << '\n';
        std::cout << "  Ciphertext bytes: "
                  << envelope.ciphertext.size() << '\n';

        std::cout << "\nRecovered:\n"
                  << service.decrypt(envelope)
                  << '\n';

        /*
         * Production decisions:
         * - OpenSSL provides the cryptographic primitive.
         * - AES-GCM authenticates both ciphertext and AAD.
         * - A fresh 96-bit IV is generated for every encryption.
         * - Keys have explicit active/retired states.
         * - Authentication failure is treated as a hard failure.
         * - Raw keys should be kept in a KMS/HSM rather than source code.
         * - CBC/CTR should not be used without a separate authentication
         *   mechanism such as a carefully designed Encrypt-then-MAC scheme.
         */
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what()
                  << '\n';
        return 1;
    }
}
