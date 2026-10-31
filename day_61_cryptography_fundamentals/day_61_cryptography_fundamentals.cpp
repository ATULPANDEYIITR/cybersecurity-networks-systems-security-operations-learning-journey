#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/*
 * Cryptography Fundamentals
 *
 * This program models a small secure-message service:
 *
 * plaintext
 *    |
 *    +--> symmetric encryption --> ciphertext
 *    |
 *    +--> integrity authentication --> MAC
 *
 * A separate RSA-like educational engine demonstrates asymmetric
 * encryption using public and private keys.
 *
 * The XOR construction and small RSA implementation are educational.
 * They are not substitutes for AES-GCM, ChaCha20-Poly1305, RSA-OAEP,
 * or a vetted cryptographic library.
 */

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message)
        : std::runtime_error(message) {}
};

enum class EncryptionMode {
    Symmetric,
    Asymmetric
};

struct SymmetricKey {
    std::vector<std::uint8_t> bytes;
};

struct PublicKey {
    std::uint64_t n{};
    std::uint64_t e{};
};

struct PrivateKey {
    std::uint64_t n{};
    std::uint64_t d{};
};

struct RSAKeyPair {
    PublicKey publicKey;
    PrivateKey privateKey;
};

struct EncryptedMessage {
    EncryptionMode mode;
    std::vector<std::uint8_t> ciphertext;
    std::vector<std::uint8_t> authenticationTag;
};

static void require(bool condition, const std::string& message) {
    if (!condition) {
        throw CryptoError(message);
    }
}

static std::uint64_t modPow(
    std::uint64_t base,
    std::uint64_t exponent,
    std::uint64_t modulus
) {
    std::uint64_t result = 1 % modulus;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1ULL) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1ULL;
    }

    return result;
}

static bool isPrime(std::uint64_t value) {
    if (value < 2) {
        return false;
    }

    if (value % 2 == 0) {
        return value == 2;
    }

    for (std::uint64_t divisor = 3; divisor * divisor <= value; divisor += 2) {
        if (value % divisor == 0) {
            return false;
        }
    }

    return true;
}

static std::uint64_t randomPrime(std::mt19937_64& generator) {
    std::uniform_int_distribution<std::uint64_t> distribution(257, 1000);

    while (true) {
        std::uint64_t candidate = distribution(generator) | 1ULL;

        if (isPrime(candidate)) {
            return candidate;
        }
    }
}

static std::int64_t extendedGcd(
    std::int64_t a,
    std::int64_t b,
    std::int64_t& x,
    std::int64_t& y
) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }

    std::int64_t x1{};
    std::int64_t y1{};

    std::int64_t gcd = extendedGcd(b, a % b, x1, y1);

    x = y1;
    y = x1 - (a / b) * y1;

    return gcd;
}

static std::uint64_t modularInverse(
    std::uint64_t value,
    std::uint64_t modulus
) {
    std::int64_t x{};
    std::int64_t y{};

    auto gcd = extendedGcd(
        static_cast<std::int64_t>(value),
        static_cast<std::int64_t>(modulus),
        x,
        y
    );

    require(gcd == 1, "Modular inverse does not exist.");

    std::int64_t result = x % static_cast<std::int64_t>(modulus);

    if (result < 0) {
        result += static_cast<std::int64_t>(modulus);
    }

    return static_cast<std::uint64_t>(result);
}

static RSAKeyPair generateRSAKeyPair(std::mt19937_64& generator) {
    const std::uint64_t p = randomPrime(generator);
    std::uint64_t q = randomPrime(generator);

    while (q == p) {
        q = randomPrime(generator);
    }

    const std::uint64_t n = p * q;
    const std::uint64_t phi = (p - 1) * (q - 1);

    std::uint64_t e = 65537;

    if (e >= phi || std::gcd(e, phi) != 1) {
        e = 3;

        while (e < phi && std::gcd(e, phi) != 1) {
            e += 2;
        }
    }

    require(e < phi, "Could not select an RSA public exponent.");

    const std::uint64_t d = modularInverse(e, phi);

    return {
        {n, e},
        {n, d}
    };
}

static std::vector<std::uint8_t> xorCipher(
    const std::vector<std::uint8_t>& input,
    const SymmetricKey& key
) {
    require(key.bytes.size() >= 16, "Symmetric key must contain at least 16 bytes.");

    std::vector<std::uint8_t> result(input.size());

    for (std::size_t i = 0; i < input.size(); ++i) {
        result[i] = input[i] ^ key.bytes[i % key.bytes.size()];
    }

    return result;
}

static SymmetricKey generateSymmetricKey(
    std::mt19937_64& generator
) {
    std::uniform_int_distribution<int> distribution(0, 255);

    SymmetricKey key;
    key.bytes.resize(32);

    for (auto& byte : key.bytes) {
        byte = static_cast<std::uint8_t>(distribution(generator));
    }

    return key;
}

static std::string bytesToHex(
    const std::vector<std::uint8_t>& bytes
) {
    std::ostringstream output;

    for (auto byte : bytes) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return output.str();
}

static std::vector<std::uint8_t> stringToBytes(
    const std::string& value
) {
    return {
        value.begin(),
        value.end()
    };
}

static std::string bytesToString(
    const std::vector<std::uint8_t>& bytes
) {
    return {
        bytes.begin(),
        bytes.end()
    };
}

/*
 * This checksum is intentionally simple. Its purpose is to show that
 * encryption and integrity are separate concerns. It is not a secure MAC.
 */
static std::uint64_t demonstrationMac(
    const std::vector<std::uint8_t>& data,
    const SymmetricKey& key
) {
    std::uint64_t state = 1469598103934665603ULL;

    for (auto byte : key.bytes) {
        state ^= byte;
        state *= 1099511628211ULL;
    }

    for (auto byte : data) {
        state ^= byte;
        state *= 1099511628211ULL;
    }

    return state;
}

static std::vector<std::uint64_t> rsaEncrypt(
    const std::vector<std::uint8_t>& plaintext,
    const PublicKey& key
) {
    require(key.n > 255, "RSA modulus is too small for byte-wise encoding.");

    std::vector<std::uint64_t> ciphertext;
    ciphertext.reserve(plaintext.size());

    for (auto byte : plaintext) {
        ciphertext.push_back(
            modPow(byte, key.e, key.n)
        );
    }

    return ciphertext;
}

static std::vector<std::uint8_t> rsaDecrypt(
    const std::vector<std::uint64_t>& ciphertext,
    const PrivateKey& key
) {
    std::vector<std::uint8_t> plaintext;
    plaintext.reserve(ciphertext.size());

    for (auto value : ciphertext) {
        require(value < key.n, "RSA ciphertext value exceeds modulus.");

        const auto decoded = modPow(value, key.d, key.n);

        require(decoded <= 255, "Decoded RSA value is outside byte range.");

        plaintext.push_back(
            static_cast<std::uint8_t>(decoded)
        );
    }

    return plaintext;
}

static void demonstrateSymmetric(
    std::mt19937_64& generator
) {
    std::cout << "=== Symmetric Encryption ===\n";

    const std::string message =
        "A shared secret protects both encryption and decryption.";

    const auto key = generateSymmetricKey(generator);
    const auto plaintext = stringToBytes(message);

    const auto ciphertext = xorCipher(plaintext, key);
    const auto recovered = xorCipher(ciphertext, key);

    require(recovered == plaintext, "Symmetric round trip failed.");

    const auto tag = demonstrationMac(ciphertext, key);

    std::cout << "Plaintext : " << message << '\n';
    std::cout << "Ciphertext: " << bytesToHex(ciphertext) << '\n';
    std::cout << "Recovered : " << bytesToString(recovered) << '\n';
    std::cout << "MAC       : " << tag << '\n';

    auto tampered = ciphertext;

    if (!tampered.empty()) {
        tampered[0] ^= 0x01;
    }

    require(
        demonstrationMac(tampered, key) != tag,
        "Tampering was not detected."
    );

    std::cout << "Tampering detected: yes\n\n";
}

static void demonstrateAsymmetric(
    std::mt19937_64& generator
) {
    std::cout << "=== Asymmetric Encryption ===\n";

    const auto keyPair = generateRSAKeyPair(generator);

    const auto plaintext = stringToBytes(
        "The public key encrypts; the private key decrypts."
    );

    const auto ciphertext = rsaEncrypt(
        plaintext,
        keyPair.publicKey
    );

    const auto recovered = rsaDecrypt(
        ciphertext,
        keyPair.privateKey
    );

    require(
        recovered == plaintext,
        "RSA round trip failed."
    );

    std::cout << "Public modulus : " << keyPair.publicKey.n << '\n';
    std::cout << "Public exponent: " << keyPair.publicKey.e << '\n';
    std::cout << "Ciphertext items: " << ciphertext.size() << '\n';
    std::cout << "Recovered      : " << bytesToString(recovered) << "\n\n";
}

static void demonstrateHybridDesign(
    std::mt19937_64& generator
) {
    std::cout << "=== Hybrid Encryption Design ===\n";

    /*
     * A practical architecture normally encrypts bulk data with a symmetric
     * algorithm and protects the symmetric key using asymmetric encryption.
     * This avoids using RSA directly on large application payloads.
     */
    const auto dataKey = generateSymmetricKey(generator);
    const auto plaintext = stringToBytes(
        "Large application data should use efficient symmetric encryption."
    );

    const auto encryptedData = xorCipher(plaintext, dataKey);

    const auto rsaKeys = generateRSAKeyPair(generator);
    const auto wrappedKey = rsaEncrypt(
        dataKey.bytes,
        rsaKeys.publicKey
    );

    const auto unwrappedKeyBytes = rsaDecrypt(
        wrappedKey,
        rsaKeys.privateKey
    );

    SymmetricKey recoveredDataKey{unwrappedKeyBytes};

    const auto recoveredData = xorCipher(
        encryptedData,
        recoveredDataKey
    );

    require(
        recoveredData == plaintext,
        "Hybrid encryption round trip failed."
    );

    std::cout << "Bulk ciphertext bytes: "
              << encryptedData.size() << '\n';

    std::cout << "Wrapped symmetric-key values: "
              << wrappedKey.size() << '\n';

    std::cout << "Recovered: "
              << bytesToString(recoveredData) << "\n\n";
}

static void demonstrateValidation(
    std::mt19937_64& generator
) {
    std::cout << "=== Validation and Failure Handling ===\n";

    try {
        SymmetricKey invalidKey{{1, 2, 3}};
        xorCipher(stringToBytes("test"), invalidKey);
    } catch (const CryptoError& error) {
        std::cout << "Invalid symmetric key rejected: "
                  << error.what() << '\n';
    }

    const auto rsaKeys = generateRSAKeyPair(generator);

    try {
        rsaDecrypt({rsaKeys.privateKey.n}, rsaKeys.privateKey);
    } catch (const CryptoError& error) {
        std::cout << "Invalid RSA ciphertext rejected: "
                  << error.what() << '\n';
    }

    const std::string unicodeText = "Confidential text";
    const auto key = generateSymmetricKey(generator);
    const auto encrypted = xorCipher(
        stringToBytes(unicodeText),
        key
    );

    require(
        bytesToString(xorCipher(encrypted, key)) == unicodeText,
        "String recovery validation failed."
    );

    std::cout << "Round-trip validation passed.\n\n";
}

int main() {
    try {
        std::random_device device;
        std::mt19937_64 generator(device());

        std::cout << "Cryptography Fundamentals\n";
        std::cout << "=========================\n\n";

        demonstrateSymmetric(generator);
        demonstrateAsymmetric(generator);
        demonstrateHybridDesign(generator);
        demonstrateValidation(generator);

        std::cout << "Security notes:\n";
        std::cout << "- Plaintext is readable input before encryption.\n";
        std::cout << "- Ciphertext is the protected representation.\n";
        std::cout << "- Symmetric encryption is efficient for bulk data.\n";
        std::cout << "- Asymmetric encryption solves key-distribution problems.\n";
        std::cout << "- Integrity must be explicitly authenticated.\n";
        std::cout << "- Real systems require vetted cryptographic libraries.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
