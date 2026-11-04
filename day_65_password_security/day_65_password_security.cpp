#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Password Security Engine - C++17
 *
 * Implements:
 * - Password policy validation
 * - SHA-256
 * - HMAC-SHA-256
 * - PBKDF2-HMAC-SHA-256
 * - Unique cryptographic salts
 * - Constant-time comparison
 * - Password verification
 * - Account lockout
 *
 * PBKDF2 is implemented using the standardized SHA-256
 * and HMAC constructions for educational purposes.
 *
 * Production systems should use an audited cryptographic
 * library and a calibrated password hashing configuration.
 */

// -------------------------------------------------------
// SHA-256
// -------------------------------------------------------

class SHA256 {
private:
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf,
        0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85,
        0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e,
        0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c,
        0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
        0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2
    };

    static uint32_t rotateRight(uint32_t value, int bits) {
        return (value >> bits) | (value << (32 - bits));
    }

public:
    static std::array<uint8_t, 32> hash(
        const std::vector<uint8_t>& input
    ) {
        std::vector<uint8_t> data = input;

        uint64_t bitLength =
            static_cast<uint64_t>(data.size()) * 8;

        data.push_back(0x80);

        while (data.size() % 64 != 56) {
            data.push_back(0);
        }

        for (int i = 7; i >= 0; --i) {
            data.push_back(
                static_cast<uint8_t>(bitLength >> (i * 8))
            );
        }

        std::array<uint32_t, 8> state = {
            0x6a09e667, 0xbb67ae85,
            0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
        };

        for (size_t offset = 0; offset < data.size(); offset += 64) {
            std::array<uint32_t, 64> w{};

            for (int i = 0; i < 16; ++i) {
                size_t j = offset + i * 4;

                w[i] =
                    (uint32_t(data[j]) << 24) |
                    (uint32_t(data[j + 1]) << 16) |
                    (uint32_t(data[j + 2]) << 8) |
                    uint32_t(data[j + 3]);
            }

            for (int i = 16; i < 64; ++i) {
                uint32_t s0 =
                    rotateRight(w[i - 15], 7) ^
                    rotateRight(w[i - 15], 18) ^
                    (w[i - 15] >> 3);

                uint32_t s1 =
                    rotateRight(w[i - 2], 17) ^
                    rotateRight(w[i - 2], 19) ^
                    (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 +
                       w[i - 7] + s1;
            }

            uint32_t a = state[0];
            uint32_t b = state[1];
            uint32_t c = state[2];
            uint32_t d = state[3];
            uint32_t e = state[4];
            uint32_t f = state[5];
            uint32_t g = state[6];
            uint32_t h = state[7];

            for (int i = 0; i < 64; ++i) {
                uint32_t s1 =
                    rotateRight(e, 6) ^
                    rotateRight(e, 11) ^
                    rotateRight(e, 25);

                uint32_t choice =
                    (e & f) ^ (~e & g);

                uint32_t temp1 =
                    h + s1 + choice + K[i] + w[i];

                uint32_t s0 =
                    rotateRight(a, 2) ^
                    rotateRight(a, 13) ^
                    rotateRight(a, 22);

                uint32_t majority =
                    (a & b) ^ (a & c) ^ (b & c);

                uint32_t temp2 = s0 + majority;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        std::array<uint8_t, 32> output{};

        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 4; ++j) {
                output[i * 4 + j] =
                    static_cast<uint8_t>(
                        state[i] >> (24 - j * 8)
                    );
            }
        }

        return output;
    }

    static std::array<uint8_t, 32> hashString(
        const std::string& input
    ) {
        return hash(std::vector<uint8_t>(
            input.begin(), input.end()
        ));
    }
};


// -------------------------------------------------------
// HMAC-SHA-256
// -------------------------------------------------------

class HMACSHA256 {
public:
    static std::array<uint8_t, 32> calculate(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& message
    ) {
        constexpr size_t BLOCK_SIZE = 64;

        std::vector<uint8_t> normalizedKey = key;

        if (normalizedKey.size() > BLOCK_SIZE) {
            auto digest = SHA256::hash(normalizedKey);

            normalizedKey.assign(
                digest.begin(), digest.end()
            );
        }

        normalizedKey.resize(BLOCK_SIZE, 0);

        std::vector<uint8_t> inner(BLOCK_SIZE);
        std::vector<uint8_t> outer(BLOCK_SIZE);

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            inner[i] = normalizedKey[i] ^ 0x36;
            outer[i] = normalizedKey[i] ^ 0x5c;
        }

        inner.insert(
            inner.end(), message.begin(), message.end()
        );

        auto innerHash = SHA256::hash(inner);

        outer.insert(
            outer.end(), innerHash.begin(), innerHash.end()
        );

        return SHA256::hash(outer);
    }
};


// -------------------------------------------------------
// PBKDF2-HMAC-SHA-256
// -------------------------------------------------------

class PBKDF2 {
public:
    static std::array<uint8_t, 32> derive(
        const std::string& password,
        const std::vector<uint8_t>& salt,
        uint32_t iterations
    ) {
        if (iterations < 1000 || iterations > 2000000) {
            throw std::invalid_argument(
                "Invalid PBKDF2 iteration count"
            );
        }

        std::vector<uint8_t> key(
            password.begin(), password.end()
        );

        std::vector<uint8_t> message = salt;

        // PBKDF2 block index, big-endian, block 1.
        message.insert(
            message.end(), {0, 0, 0, 1}
        );

        auto u = HMACSHA256::calculate(key, message);
        auto result = u;

        for (uint32_t i = 1; i < iterations; ++i) {
            std::vector<uint8_t> previous(
                u.begin(), u.end()
            );

            u = HMACSHA256::calculate(key, previous);

            for (size_t j = 0; j < result.size(); ++j) {
                result[j] ^= u[j];
            }
        }

        return result;
    }
};


// -------------------------------------------------------
// Encoding and secure comparison
// -------------------------------------------------------

std::string toHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream output;

    output << std::hex << std::setfill('0');

    for (uint8_t value : bytes) {
        output << std::setw(2) << unsigned(value);
    }

    return output.str();
}

std::string toHex(const std::array<uint8_t, 32>& bytes) {
    return toHex(
        std::vector<uint8_t>(bytes.begin(), bytes.end())
    );
}

std::vector<uint8_t> fromHex(const std::string& value) {
    if (value.size() % 2 != 0) {
        throw std::invalid_argument("Invalid hexadecimal data");
    }

    std::vector<uint8_t> result;

    for (size_t i = 0; i < value.size(); i += 2) {
        size_t position = 0;

        unsigned long number = std::stoul(
            value.substr(i, 2), &position, 16
        );

        if (position != 2 || number > 255) {
            throw std::invalid_argument("Invalid hexadecimal data");
        }

        result.push_back(static_cast<uint8_t>(number));
    }

    return result;
}

bool constantTimeEqual(
    const std::array<uint8_t, 32>& a,
    const std::array<uint8_t, 32>& b
) {
    uint8_t difference = 0;

    for (size_t i = 0; i < a.size(); ++i) {
        difference |= a[i] ^ b[i];
    }

    return difference == 0;
}


// -------------------------------------------------------
// Password policy
// -------------------------------------------------------

class PasswordPolicy {
public:
    static constexpr size_t MIN_LENGTH = 15;
    static constexpr size_t MAX_LENGTH = 128;

    static bool validate(const std::string& password) {
        if (
            password.size() < MIN_LENGTH ||
            password.size() > MAX_LENGTH
        ) {
            return false;
        }

        if (
            password.find('\0') != std::string::npos
        ) {
            return false;
        }

        bool nonWhitespace = false;

        for (unsigned char ch : password) {
            if (ch > 32) {
                nonWhitespace = true;
                break;
            }
        }

        if (!nonWhitespace) {
            return false;
        }

        std::string lower = password;

        std::transform(
            lower.begin(),
            lower.end(),
            lower.begin(),
            [](unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            }
        );

        static const std::vector<std::string> common = {
            "password123456",
            "passwordpassword",
            "123456789012345",
            "qwerty123456789"
        };

        return std::find(
            common.begin(), common.end(), lower
        ) == common.end();
    }
};


// -------------------------------------------------------
// Password record and hashing service
// -------------------------------------------------------

struct PasswordRecord {
    std::string algorithm = "PBKDF2-HMAC-SHA256";
    uint32_t iterations = 600000;
    std::string salt;
    std::string hash;
};

class PasswordHasher {
private:
    uint32_t iterations;

public:
    explicit PasswordHasher(uint32_t count = 600000)
        : iterations(count) {
        if (count < 1000 || count > 2000000) {
            throw std::invalid_argument(
                "Invalid iteration count"
            );
        }
    }

    PasswordRecord hashPassword(
        const std::string& password
    ) const {
        if (!PasswordPolicy::validate(password)) {
            throw std::invalid_argument(
                "Password does not satisfy policy"
            );
        }

        // random_device is platform-dependent. Production systems
        // should use an operating-system CSPRNG or audited library.
        std::random_device random;

        std::vector<uint8_t> salt(16);

        for (auto& byte : salt) {
            byte = static_cast<uint8_t>(random());
        }

        auto derived = PBKDF2::derive(
            password, salt, iterations
        );

        return {
            "PBKDF2-HMAC-SHA256",
            iterations,
            toHex(salt),
            toHex(derived)
        };
    }

    bool verifyPassword(
        const std::string& password,
        const PasswordRecord& record
    ) const {
        try {
            if (
                record.algorithm != "PBKDF2-HMAC-SHA256" ||
                record.iterations < 1000 ||
                record.iterations > 2000000
            ) {
                return false;
            }

            auto salt = fromHex(record.salt);
            auto expected = fromHex(record.hash);

            if (salt.size() != 16 || expected.size() != 32) {
                return false;
            }

            auto candidate = PBKDF2::derive(
                password, salt, record.iterations
            );

            std::array<uint8_t, 32> expectedArray{};

            std::copy(
                expected.begin(),
                expected.end(),
                expectedArray.begin()
            );

            return constantTimeEqual(
                candidate, expectedArray
            );

        } catch (const std::exception&) {
            return false;
        }
    }

    bool needsRehash(const PasswordRecord& record) const {
        return (
            record.algorithm != "PBKDF2-HMAC-SHA256" ||
            record.iterations != iterations
        );
    }
};


// -------------------------------------------------------
// Enterprise account management
// -------------------------------------------------------

enum class AccountStatus {
    ACTIVE,
    LOCKED
};

struct Account {
    std::string username;
    PasswordRecord passwordRecord;
    int failedAttempts = 0;
    AccountStatus status = AccountStatus::ACTIVE;
};

class AuthenticationService {
private:
    PasswordHasher hasher;
    std::map<std::string, Account> accounts;

    static constexpr int MAX_FAILURES = 5;

public:
    explicit AuthenticationService(
        PasswordHasher passwordHasher
    ) : hasher(passwordHasher) {}

    void registerAccount(
        const std::string& username,
        const std::string& password
    ) {
        if (
            username.empty() ||
            username.size() > 100
        ) {
            throw std::invalid_argument("Invalid username");
        }

        if (accounts.count(username)) {
            throw std::invalid_argument(
                "Account already exists"
            );
        }

        Account account;

        account.username = username;
        account.passwordRecord = hasher.hashPassword(password);

        accounts.emplace(username, std::move(account));
    }

    bool authenticate(
        const std::string& username,
        const std::string& password
    ) {
        auto it = accounts.find(username);

        if (it == accounts.end()) {
            return false;
        }

        Account& account = it->second;

        if (account.status == AccountStatus::LOCKED) {
            return false;
        }

        if (
            hasher.verifyPassword(
                password, account.passwordRecord
            )
        ) {
            account.failedAttempts = 0;

            if (
                hasher.needsRehash(account.passwordRecord)
            ) {
                account.passwordRecord =
                    hasher.hashPassword(password);
            }

            return true;
        }

        ++account.failedAttempts;

        if (account.failedAttempts >= MAX_FAILURES) {
            account.status = AccountStatus::LOCKED;
        }

        return false;
    }

    bool changePassword(
        const std::string& username,
        const std::string& currentPassword,
        const std::string& newPassword
    ) {
        auto it = accounts.find(username);

        if (it == accounts.end()) {
            return false;
        }

        Account& account = it->second;

        if (account.status == AccountStatus::LOCKED) {
            return false;
        }

        if (
            !hasher.verifyPassword(
                currentPassword, account.passwordRecord
            )
        ) {
            return false;
        }

        if (currentPassword == newPassword) {
            return false;
        }

        account.passwordRecord =
            hasher.hashPassword(newPassword);

        account.failedAttempts = 0;

        return true;
    }

    const Account* findAccount(
        const std::string& username
    ) const {
        auto it = accounts.find(username);

        return it == accounts.end()
            ? nullptr
            : &it->second;
    }
};


// -------------------------------------------------------
// Main demonstration
// -------------------------------------------------------

int main() {
    try {
        std::cout << "PASSWORD SECURITY ENGINE\n";
        std::cout << "========================\n\n";

        PasswordHasher hasher(600000);

        AuthenticationService authentication(hasher);

        const std::string username = "alice";
        const std::string password =
            "Correct-Horse-Battery-47!";

        authentication.registerAccount(
            username, password
        );

        const Account* account =
            authentication.findAccount(username);

        std::cout << "Hash algorithm: "
                  << account->passwordRecord.algorithm
                  << '\n';

        std::cout << "PBKDF2 iterations: "
                  << account->passwordRecord.iterations
                  << '\n';

        std::cout << "Salt: "
                  << account->passwordRecord.salt
                  << '\n';

        std::cout << "\nCorrect password: "
                  << std::boolalpha
                  << authentication.authenticate(
                      username, password
                  )
                  << '\n';

        std::cout << "Incorrect password: "
                  << authentication.authenticate(
                      username, "Wrong-Password-12345!"
                  )
                  << '\n';

        std::cout << "Password policy check: "
                  << PasswordPolicy::validate(password)
                  << '\n';

        std::string newPassword =
            "Enterprise-Secure-Password-82!";

        std::cout << "Password change: "
                  << authentication.changePassword(
                      username, password, newPassword
                  )
                  << '\n';

        std::cout << "New password verification: "
                  << authentication.authenticate(
                      username, newPassword
                  )
                  << '\n';

        // SHA-256 known-answer test.
        auto digest = SHA256::hashString("abc");

        const std::string expected =
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad";

        if (toHex(digest) != expected) {
            throw std::runtime_error("SHA-256 test failed");
        }

        std::cout << "\nSHA-256 validation passed.\n";
        std::cout << "Password security checks completed.\n";

    } catch (const std::exception& error) {
        std::cerr << "Security error: "
                  << error.what() << '\n';

        return 1;
    }

    return 0;
}
