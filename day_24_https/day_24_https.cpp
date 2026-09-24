/*
 * HTTPS and TLS Industry-Style Case Study
 * ========================================
 *
 * Scenario:
 * ---------
 * A security gateway receives HTTPS connections for an API service.
 * The gateway must model:
 *
 *   ClientHello
 *       -> TLS version negotiation
 *       -> certificate-chain validation
 *       -> hostname verification
 *       -> ephemeral key exchange
 *       -> traffic-key derivation
 *       -> authenticated application records
 *       -> HTTP request processing
 *
 * This program is deliberately implemented using only the C++17 standard
 * library. It models the protocol architecture rather than implementing
 * production TLS cryptography.
 *
 * Production systems must use a mature TLS implementation such as OpenSSL,
 * BoringSSL, LibreSSL, or the platform TLS provider. Reimplementing TLS
 * cryptography from scratch is unsafe for production.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic https_tls_case_study.cpp -o tls_demo
 *
 * Run:
 *   ./tls_demo
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>


// ============================================================================
// 1. GENERAL UTILITIES
// ============================================================================

std::string hexEncode(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream output;

    for (std::uint8_t byte : bytes) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return output.str();
}

std::string hexEncode(const std::array<std::uint8_t, 32>& bytes) {
    return hexEncode(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

void printSection(const std::string& name) {
    std::cout << "\n"
              << std::string(78, '=')
              << "\n"
              << name
              << "\n"
              << std::string(78, '=')
              << "\n";
}


// ============================================================================
// 2. TLS VERSIONS
// ============================================================================

enum class TlsVersion {
    TLS12,
    TLS13
};

std::string toString(TlsVersion version) {
    switch (version) {
        case TlsVersion::TLS12:
            return "TLS 1.2";
        case TlsVersion::TLS13:
            return "TLS 1.3";
    }

    return "Unknown";
}


// ============================================================================
// 3. TLS CIPHER SUITE MODEL
// ============================================================================

struct CipherSuite {
    std::string name;
    std::string aeadAlgorithm;
    std::string hashAlgorithm;
    std::size_t keyLength;
};

const CipherSuite TLS_AES_128_GCM_SHA256{
    "TLS_AES_128_GCM_SHA256",
    "AES-128-GCM",
    "SHA-256",
    16
};

const CipherSuite TLS_AES_256_GCM_SHA384{
    "TLS_AES_256_GCM_SHA384",
    "AES-256-GCM",
    "SHA-384",
    32
};


// ============================================================================
// 4. CERTIFICATE MODEL
// ============================================================================

struct Certificate {
    std::string subject;
    std::string issuer;
    std::vector<std::string> dnsNames;

    bool isCertificateAuthority;
    std::string publicKeyAlgorithm;
    std::string signatureAlgorithm;

    std::string notBefore;
    std::string notAfter;
};

void printCertificate(const Certificate& certificate) {
    std::cout << "Subject:              "
              << certificate.subject << "\n";
    std::cout << "Issuer:               "
              << certificate.issuer << "\n";
    std::cout << "Public-key algorithm: "
              << certificate.publicKeyAlgorithm << "\n";
    std::cout << "Signature algorithm:  "
              << certificate.signatureAlgorithm << "\n";
    std::cout << "CA:                   "
              << std::boolalpha
              << certificate.isCertificateAuthority
              << "\n";
    std::cout << "Validity:             "
              << certificate.notBefore
              << " -> "
              << certificate.notAfter
              << "\n";

    std::cout << "DNS names:            ";

    if (certificate.dnsNames.empty()) {
        std::cout << "(none)";
    } else {
        for (std::size_t i = 0; i < certificate.dnsNames.size(); ++i) {
            if (i != 0) {
                std::cout << ", ";
            }

            std::cout << certificate.dnsNames[i];
        }
    }

    std::cout << "\n";
}


// ============================================================================
// 5. CERTIFICATE AUTHORITY TRUST STORE
// ============================================================================

class TrustStore {
private:
    std::vector<Certificate> trustedRoots_;

public:
    void addRoot(const Certificate& root) {
        if (!root.isCertificateAuthority) {
            throw std::invalid_argument(
                "A trust anchor must be a CA certificate."
            );
        }

        trustedRoots_.push_back(root);
    }

    bool trustsSubject(const std::string& subject) const {
        return std::any_of(
            trustedRoots_.begin(),
            trustedRoots_.end(),
            [&](const Certificate& certificate) {
                return certificate.subject == subject;
            }
        );
    }
};


// ============================================================================
// 6. HOSTNAME VERIFICATION
// ============================================================================

bool hostnameMatches(
    const std::string& hostname,
    const std::vector<std::string>& names
) {
    for (const std::string& name : names) {
        if (name == hostname) {
            return true;
        }

        /*
         * Simplified wildcard handling:
         * *.example.com matches api.example.com but not
         * deep.api.example.com.
         */
        if (name.rfind("*.", 0) == 0) {
            const std::string suffix = name.substr(1);

            if (hostname.size() > suffix.size() &&
                hostname.compare(
                    hostname.size() - suffix.size(),
                    suffix.size(),
                    suffix
                ) == 0) {

                const std::string prefix =
                    hostname.substr(
                        0,
                        hostname.size() - suffix.size()
                    );

                if (prefix.find('.') == std::string::npos) {
                    return true;
                }
            }
        }
    }

    return false;
}


// ============================================================================
// 7. CERTIFICATE CHAIN VALIDATION
// ============================================================================

struct ValidationResult {
    bool valid = true;
    std::vector<std::string> errors;

    void fail(const std::string& message) {
        valid = false;
        errors.push_back(message);
    }
};

class CertificateValidator {
private:
    const TrustStore& trustStore_;

public:
    explicit CertificateValidator(const TrustStore& trustStore)
        : trustStore_(trustStore) {}

    ValidationResult validate(
        const std::vector<Certificate>& chain,
        const std::string& hostname
    ) const {
        ValidationResult result;

        if (chain.empty()) {
            result.fail("Certificate chain is empty.");
            return result;
        }

        const Certificate& leaf = chain.front();

        if (leaf.isCertificateAuthority) {
            result.fail("Leaf certificate is incorrectly marked as a CA.");
        }

        if (!hostnameMatches(hostname, leaf.dnsNames)) {
            result.fail(
                "Requested hostname is not present in the certificate SAN."
            );
        }

        for (std::size_t i = 0; i + 1 < chain.size(); ++i) {
            const Certificate& current = chain[i];
            const Certificate& issuer = chain[i + 1];

            if (current.issuer != issuer.subject) {
                result.fail(
                    current.subject +
                    " does not chain to " +
                    issuer.subject
                );
            }

            if (!issuer.isCertificateAuthority) {
                result.fail(
                    issuer.subject +
                    " is not a certificate authority."
                );
            }
        }

        const Certificate& last = chain.back();

        if (!trustStore_.trustsSubject(last.issuer) &&
            !trustStore_.trustsSubject(last.subject)) {
            result.fail(
                "Certificate chain does not terminate at a trusted root."
            );
        }

        /*
         * A real validator must also verify:
         *
         * - cryptographic certificate signatures
         * - validity periods against current time
         * - Basic Constraints
         * - Key Usage
         * - Extended Key Usage
         * - path length constraints
         * - name constraints where applicable
         * - revocation status
         * - algorithm constraints
         * - policy constraints
         *
         * Those operations are intentionally delegated to production TLS
         * libraries in real software.
         */
        return result;
    }
};


// ============================================================================
// 8. RANDOM KEY MATERIAL
// ============================================================================

class SecureRandomModel {
private:
    std::mt19937_64 generator_;
    std::uniform_int_distribution<unsigned int> distribution_;

public:
    SecureRandomModel()
        : generator_(
              static_cast<std::uint64_t>(
                  std::chrono::high_resolution_clock::now()
                      .time_since_epoch()
                      .count()
              )
          ),
          distribution_(0, 255) {}

    std::array<std::uint8_t, 32> bytes32() {
        std::array<std::uint8_t, 32> result{};

        for (auto& byte : result) {
            byte = static_cast<std::uint8_t>(distribution_(generator_));
        }

        return result;
    }
};


// ============================================================================
// 9. TOY HASH MODEL
// ============================================================================

std::array<std::uint8_t, 32> toyHash(const std::string& input) {
    /*
     * This is only a deterministic educational fingerprint.
     *
     * It is NOT SHA-256 and must never be used for cryptographic security.
     */
    std::array<std::uint8_t, 32> result{};

    std::uint64_t state =
        1469598103934665603ULL;

    for (unsigned char character : input) {
        state ^= character;
        state *= 1099511628211ULL;
    }

    for (std::size_t i = 0; i < result.size(); ++i) {
        state ^= state >> 13;
        state *= 0xff51afd7ed558ccdULL;
        state ^= state >> 17;

        result[i] =
            static_cast<std::uint8_t>(
                (state >> ((i % 8) * 8)) & 0xff
            );
    }

    return result;
}


// ============================================================================
// 10. SIMULATED HKDF
// ============================================================================

std::array<std::uint8_t, 32> deriveTrafficKey(
    const std::array<std::uint8_t, 32>& sharedSecret,
    const std::string& label
) {
    std::string input = hexEncode(sharedSecret) + "|" + label;
    return toyHash(input);
}


// ============================================================================
// 11. TLS RECORD
// ============================================================================

enum class TlsContentType : std::uint8_t {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
};

struct TlsRecord {
    TlsContentType contentType;
    TlsVersion version;
    std::vector<std::uint8_t> payload;
};

std::string contentTypeName(TlsContentType type) {
    switch (type) {
        case TlsContentType::ChangeCipherSpec:
            return "ChangeCipherSpec";
        case TlsContentType::Alert:
            return "Alert";
        case TlsContentType::Handshake:
            return "Handshake";
        case TlsContentType::ApplicationData:
            return "Application Data";
    }

    return "Unknown";
}


// ============================================================================
// 12. HTTP REQUEST
// ============================================================================

struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};

void printHttpRequest(const HttpRequest& request) {
    std::cout << request.method << " "
              << request.path
              << " HTTP/1.1\n";

    for (const auto& [name, value] : request.headers) {
        std::cout << name << ": " << value << "\n";
    }

    std::cout << "\n";

    if (!request.body.empty()) {
        std::cout << request.body << "\n";
    }
}


// ============================================================================
// 13. HANDSHAKE STATE MACHINE
// ============================================================================

enum class HandshakeState {
    Start,
    ClientHelloSent,
    ServerHelloReceived,
    CertificateValidated,
    HandshakeKeysReady,
    ApplicationKeysReady,
    Connected,
    Closed
};

std::string stateName(HandshakeState state) {
    switch (state) {
        case HandshakeState::Start:
            return "START";
        case HandshakeState::ClientHelloSent:
            return "CLIENT_HELLO_SENT";
        case HandshakeState::ServerHelloReceived:
            return "SERVER_HELLO_RECEIVED";
        case HandshakeState::CertificateValidated:
            return "CERTIFICATE_VALIDATED";
        case HandshakeState::HandshakeKeysReady:
            return "HANDSHAKE_KEYS_READY";
        case HandshakeState::ApplicationKeysReady:
            return "APPLICATION_KEYS_READY";
        case HandshakeState::Connected:
            return "CONNECTED";
        case HandshakeState::Closed:
            return "CLOSED";
    }

    return "UNKNOWN";
}

class TlsHandshakeStateMachine {
private:
    HandshakeState state_ = HandshakeState::Start;

    bool validTransition(
        HandshakeState from,
        HandshakeState to
    ) const {
        switch (from) {
            case HandshakeState::Start:
                return to == HandshakeState::ClientHelloSent ||
                       to == HandshakeState::Closed;

            case HandshakeState::ClientHelloSent:
                return to == HandshakeState::ServerHelloReceived ||
                       to == HandshakeState::Closed;

            case HandshakeState::ServerHelloReceived:
                return to == HandshakeState::CertificateValidated ||
                       to == HandshakeState::Closed;

            case HandshakeState::CertificateValidated:
                return to == HandshakeState::HandshakeKeysReady ||
                       to == HandshakeState::Closed;

            case HandshakeState::HandshakeKeysReady:
                return to == HandshakeState::ApplicationKeysReady ||
                       to == HandshakeState::Closed;

            case HandshakeState::ApplicationKeysReady:
                return to == HandshakeState::Connected ||
                       to == HandshakeState::Closed;

            case HandshakeState::Connected:
                return to == HandshakeState::Closed;

            case HandshakeState::Closed:
                return false;
        }

        return false;
    }

public:
    HandshakeState state() const {
        return state_;
    }

    void transition(HandshakeState next) {
        if (!validTransition(state_, next)) {
            throw std::logic_error(
                "Invalid TLS handshake transition from " +
                stateName(state_) +
                " to " +
                stateName(next)
            );
        }

        state_ = next;
    }
};


// ============================================================================
// 14. CLIENT HELLO
// ============================================================================

struct ClientHello {
    std::vector<TlsVersion> supportedVersions;
    std::vector<CipherSuite> supportedCipherSuites;
    std::string serverName;
    bool supportsAlpnHttp2;
    bool supportsAlpnHttp11;
};

void printClientHello(const ClientHello& hello) {
    std::cout << "ClientHello\n";
    std::cout << "  SNI: " << hello.serverName << "\n";

    std::cout << "  Versions: ";

    for (std::size_t i = 0; i < hello.supportedVersions.size(); ++i) {
        if (i != 0) {
            std::cout << ", ";
        }

        std::cout << toString(hello.supportedVersions[i]);
    }

    std::cout << "\n";

    std::cout << "  Cipher suites: ";

    for (std::size_t i = 0;
         i < hello.supportedCipherSuites.size();
         ++i) {

        if (i != 0) {
            std::cout << ", ";
        }

        std::cout << hello.supportedCipherSuites[i].name;
    }

    std::cout << "\n";
}


// ============================================================================
// 15. SERVER NEGOTIATION
// ============================================================================

struct ServerHello {
    TlsVersion selectedVersion;
    CipherSuite selectedCipherSuite;
    std::string negotiatedAlpn;
};

ServerHello negotiate(
    const ClientHello& client
) {
    const bool supportsTls13 =
        std::find(
            client.supportedVersions.begin(),
            client.supportedVersions.end(),
            TlsVersion::TLS13
        ) != client.supportedVersions.end();

    if (!supportsTls13) {
        throw std::runtime_error(
            "This gateway requires TLS 1.3."
        );
    }

    const bool supportsAes256 =
        std::find_if(
            client.supportedCipherSuites.begin(),
            client.supportedCipherSuites.end(),
            [](const CipherSuite& suite) {
                return suite.name == TLS_AES_256_GCM_SHA384.name;
            }
        ) != client.supportedCipherSuites.end();

    if (!supportsAes256) {
        throw std::runtime_error(
            "No permitted TLS 1.3 cipher suite is available."
        );
    }

    std::string alpn;

    if (client.supportsAlpnHttp2) {
        alpn = "h2";
    } else if (client.supportsAlpnHttp11) {
        alpn = "http/1.1";
    } else {
        throw std::runtime_error(
            "No supported application protocol."
        );
    }

    return {
        TlsVersion::TLS13,
        TLS_AES_256_GCM_SHA384,
        alpn
    };
}


// ============================================================================
// 16. HTTPS SECURITY GATEWAY
// ============================================================================

class HttpsSecurityGateway {
private:
    TrustStore trustStore_;
    CertificateValidator validator_;
    SecureRandomModel random_;

    std::size_t successfulConnections_ = 0;
    std::size_t rejectedConnections_ = 0;

public:
    HttpsSecurityGateway()
        : validator_(trustStore_) {}

    void installRootCertificate(const Certificate& root) {
        trustStore_.addRoot(root);
    }

    bool performHandshake(
        const ClientHello& clientHello,
        const std::vector<Certificate>& certificateChain
    ) {
        TlsHandshakeStateMachine stateMachine;

        try {
            printSection("TLS HANDSHAKE");

            stateMachine.transition(
                HandshakeState::ClientHelloSent
            );

            printClientHello(clientHello);

            ServerHello serverHello =
                negotiate(clientHello);

            stateMachine.transition(
                HandshakeState::ServerHelloReceived
            );

            std::cout << "\nServerHello\n";
            std::cout << "  Version: "
                      << toString(serverHello.selectedVersion)
                      << "\n";
            std::cout << "  Cipher:  "
                      << serverHello.selectedCipherSuite.name
                      << "\n";
            std::cout << "  ALPN:    "
                      << serverHello.negotiatedAlpn
                      << "\n";

            const std::string hostname =
                clientHello.serverName;

            ValidationResult validation =
                validator_.validate(
                    certificateChain,
                    hostname
                );

            if (!validation.valid) {
                ++rejectedConnections_;

                std::cout << "\nCertificate validation failed:\n";

                for (const auto& error : validation.errors) {
                    std::cout << "  - " << error << "\n";
                }

                stateMachine.transition(
                    HandshakeState::Closed
                );

                return false;
            }

            stateMachine.transition(
                HandshakeState::CertificateValidated
            );

            std::cout << "\nCertificate validation: PASSED\n";

            /*
             * Real TLS 1.3 performs an ephemeral key exchange here.
             * This model creates random values to represent ephemeral
             * key material, then derives separate client and server
             * traffic keys.
             */
            const auto clientEphemeral =
                random_.bytes32();

            const auto serverEphemeral =
                random_.bytes32();

            std::string sharedSecretInput =
                hexEncode(clientEphemeral) +
                "|" +
                hexEncode(serverEphemeral);

            const auto sharedSecret =
                toyHash(sharedSecretInput);

            stateMachine.transition(
                HandshakeState::HandshakeKeysReady
            );

            const auto clientTrafficKey =
                deriveTrafficKey(
                    sharedSecret,
                    "client application traffic"
                );

            const auto serverTrafficKey =
                deriveTrafficKey(
                    sharedSecret,
                    "server application traffic"
                );

            stateMachine.transition(
                HandshakeState::ApplicationKeysReady
            );

            std::cout << "\nKey schedule:\n";
            std::cout << "  Shared secret model: "
                      << hexEncode(sharedSecret)
                      << "\n";

            std::cout << "  Client traffic key:  "
                      << hexEncode(clientTrafficKey)
                      << "\n";

            std::cout << "  Server traffic key:  "
                      << hexEncode(serverTrafficKey)
                      << "\n";

            stateMachine.transition(
                HandshakeState::Connected
            );

            std::cout << "\nTLS state: "
                      << stateName(stateMachine.state())
                      << "\n";

            ++successfulConnections_;

            return true;

        } catch (const std::exception& error) {
            ++rejectedConnections_;

            std::cout << "\nHandshake rejected: "
                      << error.what()
                      << "\n";

            return false;
        }
    }

    void printStatistics() const {
        std::cout << "\nGateway statistics:\n";
        std::cout << "  Successful connections: "
                  << successfulConnections_
                  << "\n";
        std::cout << "  Rejected connections:   "
                  << rejectedConnections_
                  << "\n";
    }
};


// ============================================================================
// 17. APPLICATION DATA RECORD
// ============================================================================

TlsRecord createApplicationRecord(
    const std::string& plaintext
) {
    std::vector<std::uint8_t> payload(
        plaintext.begin(),
        plaintext.end()
    );

    return {
        TlsContentType::ApplicationData,
        TlsVersion::TLS13,
        payload
    };
}

void inspectRecord(const TlsRecord& record) {
    std::cout << "TLS record:\n";
    std::cout << "  Content type: "
              << contentTypeName(record.contentType)
              << "\n";
    std::cout << "  Version: "
              << toString(record.version)
              << "\n";
    std::cout << "  Payload bytes: "
              << record.payload.size()
              << "\n";
}


// ============================================================================
// 18. HTTP APPLICATION PROCESSING
// ============================================================================

class ApiApplication {
public:
    std::string handleRequest(
        const HttpRequest& request
    ) const {
        if (request.method != "GET" &&
            request.method != "POST") {

            return "HTTP/1.1 405 Method Not Allowed\r\n"
                   "Content-Length: 0\r\n"
                   "\r\n";
        }

        if (request.path == "/health") {
            const std::string body =
                R"({"status":"ok"})";

            return
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " +
                std::to_string(body.size()) +
                "\r\n"
                "\r\n" +
                body;
        }

        if (request.path == "/api/account") {
            const std::string body =
                R"({"account":"demo","transport":"HTTPS"})";

            return
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: " +
                std::to_string(body.size()) +
                "\r\n"
                "\r\n" +
                body;
        }

        return
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
    }
};


// ============================================================================
// 19. END-TO-END REQUEST PROCESSOR
// ============================================================================

class SecureRequestProcessor {
private:
    HttpsSecurityGateway& gateway_;
    ApiApplication application_;

public:
    explicit SecureRequestProcessor(
        HttpsSecurityGateway& gateway
    )
        : gateway_(gateway) {}

    void process(
        const ClientHello& hello,
        const std::vector<Certificate>& chain,
        const HttpRequest& request
    ) {
        printSection("END-TO-END HTTPS REQUEST");

        if (!gateway_.performHandshake(hello, chain)) {
            std::cout << "\nHTTP request was rejected because the TLS "
                      << "connection was not authenticated.\n";
            return;
        }

        std::cout << "\nEncrypted application-data record created.\n";

        TlsRecord incomingRecord =
            createApplicationRecord(
                request.method + " " + request.path
            );

        inspectRecord(incomingRecord);

        /*
         * At this point a real TLS stack would decrypt and authenticate the
         * record before handing the HTTP bytes to the application.
         */
        std::cout << "\nApplication received authenticated HTTP data:\n";
        printHttpRequest(request);

        const std::string response =
            application_.handleRequest(request);

        std::cout << "\nApplication response:\n";
        std::cout << response << "\n";

        std::cout << "\nThe response is passed back to TLS for encryption "
                  << "before it is sent over the network.\n";
    }
};


// ============================================================================
// 20. SECURITY TEST CASES
// ============================================================================

void runSecurityTestCases(
    HttpsSecurityGateway& gateway,
    const ClientHello& validHello,
    const std::vector<Certificate>& validChain
) {
    printSection("SECURITY TEST CASES");

    {
        std::cout << "\nTest 1: Valid hostname\n";

        gateway.performHandshake(
            validHello,
            validChain
        );
    }

    {
        std::cout << "\nTest 2: Wrong hostname\n";

        ClientHello wrongHostname = validHello;
        wrongHostname.serverName = "attacker.example.com";

        gateway.performHandshake(
            wrongHostname,
            validChain
        );
    }

    {
        std::cout << "\nTest 3: Broken issuer chain\n";

        std::vector<Certificate> brokenChain = validChain;

        brokenChain[0].issuer = "Unknown CA";

        gateway.performHandshake(
            validHello,
            brokenChain
        );
    }

    {
        std::cout << "\nTest 4: Client does not support TLS 1.3\n";

        ClientHello legacyClient = validHello;

        legacyClient.supportedVersions = {
            TlsVersion::TLS12
        };

        gateway.performHandshake(
            legacyClient,
            validChain
        );
    }

    {
        std::cout << "\nTest 5: No compatible application protocol\n";

        ClientHello unsupportedAlpn = validHello;
        unsupportedAlpn.supportsAlpnHttp2 = false;
        unsupportedAlpn.supportsAlpnHttp11 = false;

        gateway.performHandshake(
            unsupportedAlpn,
            validChain
        );
    }
}


// ============================================================================
// 21. COMPLEXITY DISCUSSION
// ============================================================================

void printComplexityAnalysis() {
    printSection("COMPLEXITY AND PERFORMANCE");

    std::cout
        << "Certificate-chain traversal: O(n), where n is chain length.\n"
        << "DNS-name search:             O(m), where m is SAN count.\n"
        << "Trust-root search here:      O(r), where r is trusted-root count.\n"
        << "HTTP route selection:        O(1) for the fixed routes in this demo.\n"
        << "Traffic-key derivation:      O(k), proportional to key material size.\n";

    std::cout
        << "\nReal TLS implementations contain optimized cryptographic primitives,\n"
        << "certificate stores, caches, session resumption and platform-specific\n"
        << "accelerators. Their performance characteristics are much more complex\n"
        << "than this educational model.\n";
}


// ============================================================================
// 22. PRODUCTION ARCHITECTURE
// ============================================================================

void printProductionArchitecture() {
    printSection("PRODUCTION ARCHITECTURE");

    std::cout
        << "A production HTTPS service typically separates responsibilities:\n\n"
        << "  Network listener\n"
        << "       |\n"
        << "       v\n"
        << "  TLS implementation\n"
        << "       |\n"
        << "       +-- certificate validation\n"
        << "       +-- key exchange\n"
        << "       +-- record protection\n"
        << "       +-- session management\n"
        << "       |\n"
        << "       v\n"
        << "  HTTP server\n"
        << "       |\n"
        << "       v\n"
        << "  Authentication / authorization\n"
        << "       |\n"
        << "       v\n"
        << "  Application services\n\n";

    std::cout
        << "The TLS layer should be treated as a security boundary. Application\n"
        << "code should not manually implement certificate signatures, AEAD,\n"
        << "Diffie-Hellman arithmetic, nonce management or TLS record protection.\n";
}


// ============================================================================
// 23. WIRESHARK OBSERVATION MODEL
// ============================================================================

void printWiresharkAnalysis() {
    printSection("WIRESHARK ANALYSIS MODEL");

    const std::vector<std::pair<std::string, std::string>> filters = {
        {"TLS traffic", "tls"},
        {"Port 443", "tcp.port == 443"},
        {"TLS handshake", "tls.handshake"},
        {"ClientHello", "tls.handshake.type == 1"},
        {"ServerHello", "tls.handshake.type == 2"},
        {"Certificate", "tls.handshake.type == 11"},
        {"TLS alerts", "tls.alert_message"},
        {"TCP retransmission", "tcp.analysis.retransmission"}
    };

    for (const auto& [description, filter] : filters) {
        std::cout << std::left
                  << std::setw(24)
                  << description
                  << filter
                  << "\n";
    }

    std::cout
        << "\nWireshark can expose handshake metadata, packet sizes, timing,\n"
        << "retransmissions and TLS records. Correctly protected application\n"
        << "plaintext remains unavailable unless a controlled decryption setup\n"
        << "provides the required session secrets.\n";
}


// ============================================================================
// 24. OPENSSL OPERATIONAL MODEL
// ============================================================================

void printOpenSslOperations() {
    printSection("OPENSSL OPERATIONS");

    const std::vector<std::string> commands = {
        "openssl version",
        "openssl x509 -in certificate.pem -text -noout",
        "openssl x509 -in certificate.pem -noout -dates",
        "openssl x509 -in certificate.pem -noout -ext subjectAltName",
        "openssl x509 -in certificate.pem -noout -fingerprint -sha256",
        "openssl s_client -connect example.com:443 -servername example.com",
        "openssl s_client -connect example.com:443 -servername example.com -tls1_3",
        "openssl s_client -connect example.com:443 -servername example.com -showcerts"
    };

    for (const auto& command : commands) {
        std::cout << command << "\n";
    }
}


// ============================================================================
// 25. MAIN CASE STUDY
// ============================================================================

int main() {
    try {
        printSection("HTTPS AND TLS SECURITY GATEWAY CASE STUDY");

        std::cout
            << "This program models an HTTPS API gateway using a simplified\n"
            << "TLS architecture. It does not implement production cryptography.\n";

        // --------------------------------------------------------------------
        // Build a trust hierarchy.
        // --------------------------------------------------------------------

        Certificate root{
            "Example Root CA",
            "Example Root CA",
            {},
            true,
            "RSA-4096",
            "RSA-PSS-SHA256",
            "2026-01-01",
            "2036-01-01"
        };

        Certificate intermediate{
            "Example TLS Intermediate CA",
            "Example Root CA",
            {},
            true,
            "RSA-3072",
            "RSA-PSS-SHA256",
            "2026-01-01",
            "2031-01-01"
        };

        Certificate server{
            "api.example.com",
            "Example TLS Intermediate CA",
            {
                "api.example.com",
                "example.com"
            },
            false,
            "ECDSA-P256",
            "ECDSA-SHA256",
            "2026-09-01",
            "2026-12-01"
        };

        printSection("CERTIFICATE CHAIN");

        printCertificate(server);
        std::cout << "\n";
        printCertificate(intermediate);
        std::cout << "\n";
        printCertificate(root);

        // --------------------------------------------------------------------
        // Configure the HTTPS gateway.
        // --------------------------------------------------------------------

        HttpsSecurityGateway gateway;

        gateway.installRootCertificate(root);

        // --------------------------------------------------------------------
        // Client capabilities.
        // --------------------------------------------------------------------

        ClientHello clientHello{
            {
                TlsVersion::TLS13,
                TlsVersion::TLS12
            },
            {
                TLS_AES_256_GCM_SHA384,
                TLS_AES_128_GCM_SHA256
            },
            "api.example.com",
            true,
            true
        };

        std::vector<Certificate> serverChain = {
            server,
            intermediate
        };

        // --------------------------------------------------------------------
        // Application request.
        // --------------------------------------------------------------------

        HttpRequest request{
            "GET",
            "/api/account",
            {
                {"Host", "api.example.com"},
                {"Accept", "application/json"}
            },
            ""
        };

        SecureRequestProcessor processor(gateway);

        processor.process(
            clientHello,
            serverChain,
            request
        );

        // --------------------------------------------------------------------
        // Security tests.
        // --------------------------------------------------------------------

        runSecurityTestCases(
            gateway,
            clientHello,
            serverChain
        );

        // --------------------------------------------------------------------
        // Operational analysis.
        // --------------------------------------------------------------------

        gateway.printStatistics();
        printComplexityAnalysis();
        printProductionArchitecture();
        printWiresharkAnalysis();
        printOpenSslOperations();

        printSection("SECURITY CONSIDERATIONS");

        std::cout
            << "[ ] Keep certificate private keys protected.\n"
            << "[ ] Validate the complete certificate chain.\n"
            << "[ ] Verify the requested hostname.\n"
            << "[ ] Prefer TLS 1.3 where compatible.\n"
            << "[ ] Disable obsolete protocol versions and algorithms.\n"
            << "[ ] Monitor certificate expiration.\n"
            << "[ ] Do not disable certificate verification to bypass failures.\n"
            << "[ ] Keep the TLS library patched.\n"
            << "[ ] Avoid logging session secrets.\n"
            << "[ ] Treat TLS termination infrastructure as security-sensitive.\n";

        printSection("CASE STUDY COMPLETE");

        std::cout
            << "The modeled architecture demonstrates how certificate trust,\n"
            << "TLS negotiation, key establishment, record protection and HTTP\n"
            << "processing form one HTTPS security boundary.\n";

        return 0;

    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
