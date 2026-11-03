#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Self-contained SHA-256, SHA3-256 and HMAC-SHA-256 implementation.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic hashing.cpp -o hashing
 *
 * Run:
 *   ./hashing
 *   ./hashing release-package.bin
 *
 * SHA-256 belongs to SHA-2.
 * SHA3-256 belongs to SHA-3 and uses the Keccak sponge construction.
 *
 * This implementation is intended for learning and verification exercises.
 * Production systems should normally use a maintained cryptographic library
 * with platform-specific security review and tested constant-time primitives.
 */

namespace crypto {

using Bytes = std::vector<std::uint8_t>;

constexpr std::array<std::uint32_t, 64> SHA256_K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

constexpr std::array<std::uint64_t, 24> KECCAK_ROUND_CONSTANTS = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/*
 * Keccak lane rotation offsets indexed by x + 5*y.
 */
constexpr std::array<unsigned int, 25> KECCAK_ROTATION = {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};

std::uint32_t rotateRight32(std::uint32_t value, unsigned int amount) {
    return (value >> amount) | (value << (32U - amount));
}

std::uint64_t rotateLeft64(std::uint64_t value, unsigned int amount) {
    if (amount == 0) {
        return value;
    }

    return (value << amount) | (value >> (64U - amount));
}

std::uint32_t loadBigEndian32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24U)
        | (static_cast<std::uint32_t>(data[1]) << 16U)
        | (static_cast<std::uint32_t>(data[2]) << 8U)
        | static_cast<std::uint32_t>(data[3]);
}

void appendBigEndian64(Bytes& output, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(
            static_cast<std::uint8_t>((value >> shift) & 0xffU)
        );
    }
}

std::uint64_t loadLittleEndian64(const std::uint8_t* data) {
    std::uint64_t value = 0;

    for (unsigned int index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(data[index])
            << (8U * index);
    }

    return value;
}

void appendLittleEndian64(Bytes& output, std::uint64_t value) {
    for (unsigned int index = 0; index < 8; ++index) {
        output.push_back(
            static_cast<std::uint8_t>(
                (value >> (8U * index)) & 0xffU
            )
        );
    }
}

Bytes sha256(const Bytes& message) {
    if (message.size() >
        std::numeric_limits<std::uint64_t>::max() / 8ULL) {
        throw std::length_error("Input is too large for SHA-256 length encoding.");
    }

    std::array<std::uint32_t, 8> state = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    Bytes padded = message;
    const std::uint64_t bitLength =
        static_cast<std::uint64_t>(message.size()) * 8ULL;

    padded.push_back(0x80U);

    while ((padded.size() % 64U) != 56U) {
        padded.push_back(0x00U);
    }

    appendBigEndian64(padded, bitLength);

    for (std::size_t offset = 0; offset < padded.size(); offset += 64U) {
        std::array<std::uint32_t, 64> words{};

        for (std::size_t index = 0; index < 16U; ++index) {
            words[index] = loadBigEndian32(
                padded.data() + offset + index * 4U
            );
        }

        for (std::size_t index = 16U; index < 64U; ++index) {
            const std::uint32_t x = words[index - 15U];
            const std::uint32_t y = words[index - 2U];

            const std::uint32_t sigma0 =
                rotateRight32(x, 7U)
                ^ rotateRight32(x, 18U)
                ^ (x >> 3U);

            const std::uint32_t sigma1 =
                rotateRight32(y, 17U)
                ^ rotateRight32(y, 19U)
                ^ (y >> 10U);

            words[index] =
                words[index - 16U]
                + sigma0
                + words[index - 7U]
                + sigma1;
        }

        std::uint32_t a = state[0];
        std::uint32_t b = state[1];
        std::uint32_t c = state[2];
        std::uint32_t d = state[3];
        std::uint32_t e = state[4];
        std::uint32_t f = state[5];
        std::uint32_t g = state[6];
        std::uint32_t h = state[7];

        for (std::size_t index = 0; index < 64U; ++index) {
            const std::uint32_t upperSigma1 =
                rotateRight32(e, 6U)
                ^ rotateRight32(e, 11U)
                ^ rotateRight32(e, 25U);

            const std::uint32_t choose =
                (e & f) ^ ((~e) & g);

            const std::uint32_t temp1 =
                h + upperSigma1 + choose
                + SHA256_K[index] + words[index];

            const std::uint32_t upperSigma0 =
                rotateRight32(a, 2U)
                ^ rotateRight32(a, 13U)
                ^ rotateRight32(a, 22U);

            const std::uint32_t majority =
                (a & b) ^ (a & c) ^ (b & c);

            const std::uint32_t temp2 = upperSigma0 + majority;

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

    Bytes output;
    output.reserve(32U);

    for (std::uint32_t word : state) {
        output.push_back(static_cast<std::uint8_t>(word >> 24U));
        output.push_back(static_cast<std::uint8_t>(word >> 16U));
        output.push_back(static_cast<std::uint8_t>(word >> 8U));
        output.push_back(static_cast<std::uint8_t>(word));
    }

    return output;
}

void keccakPermutation(std::array<std::uint64_t, 25>& state) {
    for (std::uint64_t roundConstant : KECCAK_ROUND_CONSTANTS) {
        std::array<std::uint64_t, 5> columnParity{};
        std::array<std::uint64_t, 5> delta{};
        std::array<std::uint64_t, 25> moved{};

        // Theta: calculate parity for each column.
        for (std::size_t x = 0; x < 5U; ++x) {
            columnParity[x] =
                state[x]
                ^ state[x + 5U]
                ^ state[x + 10U]
                ^ state[x + 15U]
                ^ state[x + 20U];
        }

        for (std::size_t x = 0; x < 5U; ++x) {
            delta[x] =
                columnParity[(x + 4U) % 5U]
                ^ rotateLeft64(columnParity[(x + 1U) % 5U], 1U);
        }

        for (std::size_t y = 0; y < 5U; ++y) {
            for (std::size_t x = 0; x < 5U; ++x) {
                state[x + 5U * y] ^= delta[x];
            }
        }

        // Rho and Pi: rotate each lane and move it to its new position.
        for (std::size_t y = 0; y < 5U; ++y) {
            for (std::size_t x = 0; x < 5U; ++x) {
                const std::size_t source = x + 5U * y;
                const std::size_t destination =
                    y + 5U * ((2U * x + 3U * y) % 5U);

                moved[destination] = rotateLeft64(
                    state[source],
                    KECCAK_ROTATION[source]
                );
            }
        }

        // Chi: non-linear transformation within each row.
        for (std::size_t y = 0; y < 5U; ++y) {
            for (std::size_t x = 0; x < 5U; ++x) {
                state[x + 5U * y] =
                    moved[x + 5U * y]
                    ^ (
                        (~moved[(x + 1U) % 5U + 5U * y])
                        & moved[(x + 2U) % 5U + 5U * y]
                    );
            }
        }

        // Iota: inject the round constant.
        state[0] ^= roundConstant;
    }
}

Bytes sha3_256(const Bytes& message) {
    constexpr std::size_t RATE_BYTES = 136U;
    constexpr std::size_t OUTPUT_BYTES = 32U;

    std::array<std::uint64_t, 25> state{};

    /*
     * SHA3 domain separation begins with 0x06.
     * The final rate byte has its high bit set for multi-rate padding.
     */
    Bytes padded = message;
    padded.push_back(0x06U);

    while ((padded.size() % RATE_BYTES) != 0U) {
        padded.push_back(0x00U);
    }

    padded.back() |= 0x80U;

    // Absorb: each 136-byte block contributes 17 little-endian lanes.
    for (std::size_t offset = 0;
         offset < padded.size();
         offset += RATE_BYTES) {

        for (std::size_t lane = 0; lane < RATE_BYTES / 8U; ++lane) {
            state[lane] ^= loadLittleEndian64(
                padded.data() + offset + lane * 8U
            );
        }

        keccakPermutation(state);
    }

    // Squeeze the first 256 bits of the sponge state.
    Bytes output;
    output.reserve(OUTPUT_BYTES);

    for (std::size_t lane = 0; output.size() < OUTPUT_BYTES; ++lane) {
        Bytes laneBytes;
        laneBytes.reserve(8U);
        appendLittleEndian64(laneBytes, state[lane]);

        for (std::uint8_t byte : laneBytes) {
            if (output.size() == OUTPUT_BYTES) {
                break;
            }

            output.push_back(byte);
        }
    }

    return output;
}

std::string toHex(const Bytes& bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (std::uint8_t byte : bytes) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }

    return output.str();
}

Bytes fromHex(const std::string& hex) {
    if (hex.empty() || (hex.size() % 2U) != 0U) {
        throw std::invalid_argument("Digest has an invalid hexadecimal length.");
    }

    Bytes result;
    result.reserve(hex.size() / 2U);

    auto hexValue = [](char character) -> int {
        if (character >= '0' && character <= '9') {
            return character - '0';
        }
        if (character >= 'a' && character <= 'f') {
            return character - 'a' + 10;
        }
        if (character >= 'A' && character <= 'F') {
            return character - 'A' + 10;
        }
        return -1;
    };

    for (std::size_t index = 0; index < hex.size(); index += 2U) {
        const int high = hexValue(hex[index]);
        const int low = hexValue(hex[index + 1U]);

        if (high < 0 || low < 0) {
            throw std::invalid_argument(
                "Digest contains a non-hexadecimal character."
            );
        }

        result.push_back(
            static_cast<std::uint8_t>((high << 4) | low)
        );
    }

    return result;
}

bool constantTimeEqual(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) {
        return false;
    }

    std::uint8_t difference = 0;

    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(
            left[index] ^ right[index]
        );
    }

    return difference == 0;
}

bool verifySha256(
    const Bytes& message,
    const std::string& expectedHex
) {
    const Bytes expected = fromHex(expectedHex);
    const Bytes actual = sha256(message);

    if (expected.size() != actual.size()) {
        return false;
    }

    return constantTimeEqual(actual, expected);
}

Bytes hmacSha256(const Bytes& message, const Bytes& suppliedKey) {
    constexpr std::size_t BLOCK_SIZE = 64U;

    if (suppliedKey.size() < 32U) {
        throw std::invalid_argument(
            "HMAC key must contain at least 32 bytes."
        );
    }

    Bytes key = suppliedKey;

    if (key.size() > BLOCK_SIZE) {
        key = sha256(key);
    }

    key.resize(BLOCK_SIZE, 0x00U);

    Bytes innerKey(BLOCK_SIZE);
    Bytes outerKey(BLOCK_SIZE);

    for (std::size_t index = 0; index < BLOCK_SIZE; ++index) {
        innerKey[index] = key[index] ^ 0x36U;
        outerKey[index] = key[index] ^ 0x5cU;
    }

    Bytes innerMessage = innerKey;
    innerMessage.insert(
        innerMessage.end(),
        message.begin(),
        message.end()
    );

    const Bytes innerDigest = sha256(innerMessage);

    Bytes outerMessage = outerKey;
    outerMessage.insert(
        outerMessage.end(),
        innerDigest.begin(),
        innerDigest.end()
    );

    return sha256(outerMessage);
}

bool verifyHmacSha256(
    const Bytes& message,
    const Bytes& key,
    const Bytes& expectedTag
) {
    const Bytes actualTag = hmacSha256(message, key);
    return constantTimeEqual(actualTag, expectedTag);
}

Bytes readFile(const std::string& filePath) {
    std::ifstream input(filePath, std::ios::binary);

    if (!input) {
        throw std::runtime_error("Cannot open file: " + filePath);
    }

    Bytes data(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    );

    if (input.bad()) {
        throw std::runtime_error("I/O error while reading: " + filePath);
    }

    return data;
}

} // namespace crypto

struct Artifact {
    std::string name;
    crypto::Bytes content;
};

struct IntegrityReport {
    std::string artifactName;
    std::string algorithm;
    std::string digest;
    std::size_t byteCount;
    bool verified;
};

IntegrityReport inspectArtifact(const Artifact& artifact) {
    const crypto::Bytes sha2Digest = crypto::sha256(artifact.content);
    const crypto::Bytes sha3Digest = crypto::sha3_256(artifact.content);

    const std::string expectedSha2 = crypto::toHex(sha2Digest);

    return IntegrityReport{
        artifact.name,
        "SHA-256",
        expectedSha2,
        artifact.content.size(),
        crypto::verifySha256(artifact.content, expectedSha2)
    };
}

void runKnownAnswerTests() {
    const crypto::Bytes empty;

    const std::string expectedSha256Empty =
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855";

    const std::string expectedSha3Empty =
        "a7ffc6f8bf1ed76651c14756a061d662"
        "f580ff4de43b49fa82d80a4b80f8434a";

    const crypto::Bytes abc{'a', 'b', 'c'};

    const std::string expectedSha256Abc =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    const std::string expectedSha3Abc =
        "3a985da74fe225b2045c172d6bd390bd"
        "855f086e3e9d525b46bfe24511431532";

    if (crypto::toHex(crypto::sha256(empty)) != expectedSha256Empty) {
        throw std::runtime_error("SHA-256 empty-input test failed.");
    }

    if (crypto::toHex(crypto::sha3_256(empty)) != expectedSha3Empty) {
        throw std::runtime_error("SHA3-256 empty-input test failed.");
    }

    if (crypto::toHex(crypto::sha256(abc)) != expectedSha256Abc) {
        throw std::runtime_error("SHA-256 abc test failed.");
    }

    if (crypto::toHex(crypto::sha3_256(abc)) != expectedSha3Abc) {
        throw std::runtime_error("SHA3-256 abc test failed.");
    }

    if (!crypto::verifySha256(abc, expectedSha256Abc)) {
        throw std::runtime_error("Digest verification test failed.");
    }

    if (crypto::verifySha256({'a', 'b', 'd'}, expectedSha256Abc)) {
        throw std::runtime_error("Modified input was incorrectly accepted.");
    }

    const crypto::Bytes key(32U, 0x42U);
    const crypto::Bytes payload{'r', 'e', 'l', 'e', 'a', 's', 'e'};
    const crypto::Bytes tag = crypto::hmacSha256(payload, key);

    if (!crypto::verifyHmacSha256(payload, key, tag)) {
        throw std::runtime_error("HMAC verification test failed.");
    }

    if (crypto::verifyHmacSha256(
            {'c', 'h', 'a', 'n', 'g', 'e', 'd'},
            key,
            tag
        )) {
        throw std::runtime_error("Modified HMAC input was accepted.");
    }
}

void printReport(const Artifact& artifact) {
    const auto sha2Digest = crypto::sha256(artifact.content);
    const auto sha3Digest = crypto::sha3_256(artifact.content);

    std::cout << "\nArtifact: " << artifact.name << '\n';
    std::cout << "Bytes: " << artifact.content.size() << '\n';
    std::cout << "SHA-256: " << crypto::toHex(sha2Digest) << '\n';
    std::cout << "SHA3-256: " << crypto::toHex(sha3Digest) << '\n';

    const bool verified = crypto::constantTimeEqual(
        sha2Digest,
        crypto::fromHex(crypto::toHex(sha2Digest))
    );

    std::cout << "Self-verification: "
              << (verified ? "PASSED" : "FAILED") << '\n';

    Artifact modified = artifact;
    modified.content.push_back(
        static_cast<std::uint8_t>('!')
    );

    const bool originalDigestAcceptsModified =
        crypto::verifySha256(
            modified.content,
            crypto::toHex(sha2Digest)
        );

    std::cout << "Modified artifact accepted: "
              << (originalDigestAcceptsModified ? "YES" : "NO")
              << '\n';
}

int main(int argc, char* argv[]) {
    try {
        runKnownAnswerTests();

        Artifact artifact;

        if (argc > 2) {
            throw std::invalid_argument(
                "Usage: hashing [optional-file-path]"
            );
        }

        if (argc == 2) {
            artifact.name = argv[1];
            artifact.content = crypto::readFile(argv[1]);
        } else {
            artifact.name = "release-package.bin";

            const std::string sample =
                "Release package: version 2.4.1\n"
                "Component: payment-service\n"
                "Environment: production\n";

            artifact.content.assign(sample.begin(), sample.end());
        }

        std::cout << "Cryptographic hashing and integrity verification\n";
        std::cout << "Known-answer tests: PASSED\n";

        printReport(artifact);

        const crypto::Bytes key(32U, 0x5aU);
        const crypto::Bytes tag =
            crypto::hmacSha256(artifact.content, key);

        std::cout << "\nHMAC-SHA-256: " << crypto::toHex(tag) << '\n';
        std::cout << "HMAC valid: "
                  << (
                      crypto::verifyHmacSha256(
                          artifact.content,
                          key,
                          tag
                      )
                      ? "YES"
                      : "NO"
                  )
                  << '\n';

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
