#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

enum class TLSVersion {
    TLS12,
    TLS13
};

enum class HandshakeState {
    CREATED,
    CLIENT_HELLO_SENT,
    SERVER_HELLO_RECEIVED,
    CERTIFICATE_VERIFIED,
    KEY_ESTABLISHED,
    FINISHED,
    FAILED
};

enum class CheckStatus {
    PENDING,
    PASSED,
    FAILED
};

struct CipherSuite {
    std::string name;
    TLSVersion version;
    std::string keyExchange;
    std::string authentication;
    std::string encryption;
    std::string hash;
    int keyBits;
    bool forwardSecrecy;
    bool approved;
};

struct Certificate {
    std::string subject;
    std::string issuer;
    std::string serialNumber;
    std::string signatureAlgorithm;
    std::string publicKeyAlgorithm;
    std::string hostname;
    bool trusted;
    bool expired;
    bool hostnameMatches;
    bool usageValid;
};

struct TLSClientHello {
    std::vector<TLSVersion> supportedVersions;
    std::vector<std::string> cipherSuites;
    bool supportsSNI;
    bool supportsALPN;
    bool supportsSessionTickets;
};

struct TLSNegotiation {
    std::string serverName;
    TLSVersion negotiatedVersion;
    std::optional<CipherSuite> selectedCipher;
    std::optional<Certificate> certificate;
    HandshakeState state = HandshakeState::CREATED;
    bool keyShareAvailable = false;
    bool transcriptAuthenticated = false;
    std::vector<std::string> events;
};

class TLSSecurityError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class CipherRegistry {
private:
    std::map<std::string, CipherSuite> suites;

public:
    CipherRegistry() {
        add({
            "TLS_AES_128_GCM_SHA256",
            TLSVersion::TLS13,
            "ECDHE",
            "Certificate-based authentication",
            "AES-128-GCM",
            "SHA-256",
            128,
            true,
            true
        });

        add({
            "TLS_AES_256_GCM_SHA384",
            TLSVersion::TLS13,
            "ECDHE",
            "Certificate-based authentication",
            "AES-256-GCM",
            "SHA-384",
            256,
            true,
            true
        });

        add({
            "TLS_CHACHA20_POLY1305_SHA256",
            TLSVersion::TLS13,
            "ECDHE",
            "Certificate-based authentication",
            "ChaCha20-Poly1305",
            "SHA-256",
            256,
            true,
            true
        });

        add({
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            TLSVersion::TLS12,
            "ECDHE",
            "RSA",
            "AES-128-GCM",
            "SHA-256",
            128,
            true,
            true
        });

        add({
            "TLS_RSA_WITH_AES_128_CBC_SHA",
            TLSVersion::TLS12,
            "RSA key transport",
            "RSA",
            "AES-128-CBC",
            "SHA-1",
            128,
            false,
            false
        });
    }

    void add(const CipherSuite& suite) {
        if (suite.name.empty()) {
            throw std::invalid_argument("Cipher name cannot be empty.");
        }

        suites[suite.name] = suite;
    }

    std::optional<CipherSuite> find(
        const std::string& name
    ) const {
        auto it = suites.find(name);

        if (it == suites.end()) {
            return std::nullopt;
        }

        return it->second;
    }

    std::vector<CipherSuite> approvedFor(
        TLSVersion version
    ) const {
        std::vector<CipherSuite> result;

        for (const auto& [name, suite] : suites) {
            if (
                suite.version == version &&
                suite.approved
            ) {
                result.push_back(suite);
            }
        }

        return result;
    }
};

class CertificateValidator {
public:
    static void validate(
        const Certificate& certificate,
        const std::string& expectedHostname
    ) {
        if (!certificate.trusted) {
            throw TLSSecurityError(
                "Certificate chain is not trusted."
            );
        }

        if (certificate.expired) {
            throw TLSSecurityError(
                "Certificate has expired."
            );
        }

        if (!certificate.hostnameMatches ||
            certificate.hostname != expectedHostname) {
            throw TLSSecurityError(
                "Certificate hostname validation failed."
            );
        }

        if (!certificate.usageValid) {
            throw TLSSecurityError(
                "Certificate key usage or extended key usage is invalid."
            );
        }

        if (certificate.subject.empty() ||
            certificate.issuer.empty()) {
            throw TLSSecurityError(
                "Certificate identity information is incomplete."
            );
        }
    }
};

class TLSHandshakeEngine {
private:
    CipherRegistry registry;

    static std::string versionName(TLSVersion version) {
        return version == TLSVersion::TLS13
            ? "TLS 1.3"
            : "TLS 1.2";
    }

    void transition(
        TLSNegotiation& session,
        HandshakeState next
    ) {
        session.state = next;
    }

public:
    TLSNegotiation negotiate(
        const TLSClientHello& client,
        const std::string& serverName,
        const Certificate& certificate
    ) {
        if (serverName.empty()) {
            throw std::invalid_argument(
                "Server name cannot be empty."
            );
        }

        TLSNegotiation session;
        session.serverName = serverName;

        try {
            if (!client.supportsSNI) {
                throw TLSSecurityError(
                    "SNI is required by this server policy."
                );
            }

            transition(
                session,
                HandshakeState::CLIENT_HELLO_SENT
            );

            session.events.push_back(
                "ClientHello transmitted."
            );

            std::vector<TLSVersion> serverVersions = {
                TLSVersion::TLS13,
                TLSVersion::TLS12
            };

            bool selectedVersion = false;

            for (TLSVersion version : serverVersions) {
                bool supported = std::find(
                    client.supportedVersions.begin(),
                    client.supportedVersions.end(),
                    version
                ) != client.supportedVersions.end();

                if (supported) {
                    session.negotiatedVersion = version;
                    selectedVersion = true;
                    break;
                }
            }

            if (!selectedVersion) {
                throw TLSSecurityError(
                    "No mutually supported TLS version."
                );
            }

            transition(
                session,
                HandshakeState::SERVER_HELLO_RECEIVED
            );

            session.events.push_back(
                "ServerHello selected " +
                versionName(session.negotiatedVersion)
            );

            for (const auto& name : client.cipherSuites) {
                auto suite = registry.find(name);

                if (
                    suite &&
                    suite->version == session.negotiatedVersion &&
                    suite->approved
                ) {
                    session.selectedCipher = suite;
                    break;
                }
            }

            if (!session.selectedCipher) {
                throw TLSSecurityError(
                    "No approved common cipher suite."
                );
            }

            session.events.push_back(
                "Cipher selected: " +
                session.selectedCipher->name
            );

            session.certificate = certificate;

            CertificateValidator::validate(
                certificate,
                serverName
            );

            transition(
                session,
                HandshakeState::CERTIFICATE_VERIFIED
            );

            session.events.push_back(
                "Certificate chain and hostname validated."
            );

            session.keyShareAvailable = true;

            transition(
                session,
                HandshakeState::KEY_ESTABLISHED
            );

            session.events.push_back(
                "Ephemeral key exchange completed."
            );

            // This is a protocol-state simulation, not actual cryptography.
            session.transcriptAuthenticated = true;

            transition(
                session,
                HandshakeState::FINISHED
            );

            session.events.push_back(
                "Finished messages authenticated."
            );

            return session;

        } catch (...) {
            session.state = HandshakeState::FAILED;
            throw;
        }
    }
};

class BranchlessSessionCache {
private:
    struct SessionEntry {
        std::string ticketIdentifier;
        std::chrono::steady_clock::time_point created;
        std::chrono::seconds lifetime;
    };

    std::map<std::string, SessionEntry> sessions;
    std::size_t maximumEntries;

public:
    explicit BranchlessSessionCache(
        std::size_t capacity = 1000
    ) : maximumEntries(capacity) {
        if (capacity == 0) {
            throw std::invalid_argument(
                "Cache capacity must be positive."
            );
        }
    }

    void store(
        const std::string& identifier,
        std::chrono::seconds lifetime
    ) {
        if (identifier.empty() || lifetime.count() <= 0) {
            throw std::invalid_argument(
                "Invalid session metadata."
            );
        }

        if (
            sessions.size() >= maximumEntries &&
            sessions.find(identifier) == sessions.end()
        ) {
            auto oldest = std::min_element(
                sessions.begin(),
                sessions.end(),
                [](const auto& a, const auto& b) {
                    return a.second.created < b.second.created;
                }
            );

            if (oldest != sessions.end()) {
                sessions.erase(oldest);
            }
        }

        sessions[identifier] = {
            identifier,
            std::chrono::steady_clock::now(),
            lifetime
        };
    }

    bool isReusable(
        const std::string& identifier
    ) {
        auto it = sessions.find(identifier);

        if (it == sessions.end()) {
            return false;
        }

        auto elapsed =
            std::chrono::steady_clock::now() -
            it->second.created;

        if (elapsed >= it->second.lifetime) {
            sessions.erase(it);
            return false;
        }

        return true;
    }

    std::size_t size() const {
        return sessions.size();
    }
};

void printCipherSuites(const CipherRegistry& registry) {
    std::cout << "\nApproved Cipher Suites\n";

    for (TLSVersion version : {
        TLSVersion::TLS13,
        TLSVersion::TLS12
    }) {
        for (const auto& suite : registry.approvedFor(version)) {
            std::cout
                << suite.name
                << " | " << suite.encryption
                << " | " << suite.hash
                << " | Forward secrecy: "
                << (suite.forwardSecrecy ? "Yes" : "No")
                << '\n';
        }
    }
}

int main() {
    try {
        TLSClientHello client{
            {
                TLSVersion::TLS12,
                TLSVersion::TLS13
            },
            {
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            },
            true,
            true,
            true
        };

        Certificate certificate{
            "CN=api.example.com",
            "CN=Example Intermediate CA",
            "CERT-2026-001",
            "ECDSA-SHA256",
            "EC",
            "api.example.com",
            true,
            false,
            true,
            true
        };

        CipherRegistry registry;
        TLSHandshakeEngine engine;

        TLSNegotiation session = engine.negotiate(
            client,
            "api.example.com",
            certificate
        );

        std::cout << "TLS Handshake Simulation\n";
        std::cout << "========================\n";

        for (const auto& event : session.events) {
            std::cout << "[OK] " << event << '\n';
        }

        std::cout << "\nNegotiated Protocol: "
                  << (
                      session.negotiatedVersion == TLSVersion::TLS13
                      ? "TLS 1.3"
                      : "TLS 1.2"
                  )
                  << '\n';

        std::cout << "Final State: "
                  << (
                      session.state == HandshakeState::FINISHED
                      ? "FINISHED"
                      : "FAILED"
                  )
                  << '\n';

        std::cout << "Session key establishment: "
                  << (session.keyShareAvailable ? "Completed" : "Failed")
                  << '\n';

        std::cout << "Handshake authentication: "
                  << (
                      session.transcriptAuthenticated
                      ? "Completed"
                      : "Failed"
                  )
                  << '\n';

        printCipherSuites(registry);

        BranchlessSessionCache cache(100);

        cache.store(
            "session-api-001",
            std::chrono::seconds(3600)
        );

        std::cout << "\nSession Resumption Cache\n";
        std::cout << "Entries: " << cache.size() << '\n';

        std::cout
            << "Reusable: "
            << (
                cache.isReusable("session-api-001")
                ? "Yes"
                : "No"
            )
            << '\n';

        std::cout
            << "Unknown session reusable: "
            << (
                cache.isReusable("unknown-session")
                ? "Yes"
                : "No"
            )
            << '\n';

        // Negative test: an expired certificate must be rejected.
        Certificate expired = certificate;
        expired.expired = true;

        try {
            CertificateValidator::validate(
                expired,
                "api.example.com"
            );
        } catch (const TLSSecurityError& error) {
            std::cout << "\nExpected validation failure: "
                      << error.what()
                      << '\n';
        }

        return 0;

    } catch (const std::exception& error) {
        std::cerr << "TLS simulation failed: "
                  << error.what()
                  << '\n';

        return 1;
    }
}
