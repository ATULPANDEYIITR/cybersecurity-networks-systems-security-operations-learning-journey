#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

enum class Protocol {
    SSH,
    HTTPS,
    VPN,
    SFTP
};

enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Failed
};

enum class ReviewResult {
    Accepted,
    Rejected,
    Pending
};

std::string toString(Protocol protocol) {
    switch (protocol) {
        case Protocol::SSH: return "SSH";
        case Protocol::HTTPS: return "HTTPS";
        case Protocol::VPN: return "VPN";
        case Protocol::SFTP: return "SFTP";
    }
    throw std::logic_error("Unknown protocol.");
}

std::string toString(ConnectionState state) {
    switch (state) {
        case ConnectionState::Disconnected: return "DISCONNECTED";
        case ConnectionState::Connecting: return "CONNECTING";
        case ConnectionState::Connected: return "CONNECTED";
        case ConnectionState::Failed: return "FAILED";
    }
    throw std::logic_error("Unknown state.");
}

class ValidationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct SecurityPolicy {
    bool verifyCertificates = true;
    bool verifyHostname = true;
    bool strictHostKeyChecking = true;
    bool allowWeakAlgorithms = false;
    bool requireVPNForPrivateNetworks = true;
    std::uint64_t maximumFileSize = 50ULL * 1024ULL * 1024ULL;

    void validate() const {
        if (!verifyCertificates || !verifyHostname) {
            throw ValidationError(
                "TLS certificate and hostname verification are mandatory."
            );
        }

        if (!strictHostKeyChecking) {
            throw ValidationError(
                "SSH host-key verification must be enabled."
            );
        }

        if (allowWeakAlgorithms) {
            throw ValidationError("Weak algorithms are prohibited.");
        }

        if (maximumFileSize == 0) {
            throw ValidationError("File size limit must be positive.");
        }
    }
};

struct Endpoint {
    std::string hostname;
    std::uint16_t port;
    Protocol protocol;
    bool certificateVerificationRequired = true;
    bool hostnameVerificationRequired = true;

    void validate() const {
        if (hostname.empty() || hostname.size() > 253) {
            throw ValidationError("Invalid endpoint hostname.");
        }

        if (hostname.find_first_of(" \t\r\n/\\") != std::string::npos) {
            throw ValidationError("Invalid hostname characters.");
        }

        if (port == 0) {
            throw ValidationError("Invalid endpoint port.");
        }

        if (protocol == Protocol::HTTPS &&
            (!certificateVerificationRequired ||
             !hostnameVerificationRequired)) {
            throw ValidationError("Insecure HTTPS endpoint.");
        }
    }
};

struct CommunicationSession {
    std::string id;
    Endpoint endpoint;
    ConnectionState state = ConnectionState::Disconnected;
    std::vector<std::string> auditEvents;
};

class SessionManager {
private:
    std::map<std::string, CommunicationSession> sessions;

    static bool validTransition(
        ConnectionState current,
        ConnectionState next
    ) {
        switch (current) {
            case ConnectionState::Disconnected:
                return next == ConnectionState::Connecting;

            case ConnectionState::Connecting:
                return next == ConnectionState::Connected ||
                       next == ConnectionState::Failed;

            case ConnectionState::Connected:
                return next == ConnectionState::Disconnected ||
                       next == ConnectionState::Failed;

            case ConnectionState::Failed:
                return next == ConnectionState::Disconnected;
        }

        return false;
    }

public:
    void registerSession(
        const std::string& id,
        const Endpoint& endpoint
    ) {
        if (id.empty() || sessions.count(id)) {
            throw ValidationError("Invalid or duplicate session ID.");
        }

        endpoint.validate();

        sessions.emplace(
            id,
            CommunicationSession{id, endpoint}
        );
    }

    void transition(
        const std::string& id,
        ConnectionState next
    ) {
        auto it = sessions.find(id);

        if (it == sessions.end()) {
            throw ValidationError("Unknown communication session.");
        }

        auto& session = it->second;

        if (!validTransition(session.state, next)) {
            throw ValidationError(
                "Invalid state transition: " +
                toString(session.state) + " -> " + toString(next)
            );
        }

        session.auditEvents.push_back(
            toString(session.state) + " -> " + toString(next)
        );

        session.state = next;
    }

    void printReport() const {
        for (const auto& [id, session] : sessions) {
            std::cout
                << id << " | "
                << toString(session.endpoint.protocol) << " | "
                << session.endpoint.hostname << ":"
                << session.endpoint.port << " | "
                << toString(session.state) << '\n';

            for (const auto& event : session.auditEvents) {
                std::cout << "  AUDIT: " << event << '\n';
            }
        }
    }
};

struct VPNProfile {
    std::string interfaceName;
    std::string endpoint;
    std::uint16_t port;
    std::vector<std::string> allowedNetworks;
    std::string protocol;

    void validate() const {
        static const std::regex interfacePattern(
            R"([A-Za-z0-9_.-]{1,15})"
        );

        if (!std::regex_match(interfaceName, interfacePattern)) {
            throw ValidationError("Invalid VPN interface.");
        }

        if (endpoint.empty() || port == 0) {
            throw ValidationError("Invalid VPN endpoint.");
        }

        if (protocol != "WireGuard" && protocol != "IPsec") {
            throw ValidationError("Unsupported VPN protocol.");
        }

        if (allowedNetworks.empty()) {
            throw ValidationError("VPN requires allowed networks.");
        }

        static const std::regex cidrPattern(
            R"((([0-9]{1,3}\.){3}[0-9]{1,3})/([0-9]{1,2}))"
        );

        for (const auto& network : allowedNetworks) {
            std::smatch match;

            if (!std::regex_match(network, match, cidrPattern)) {
                throw ValidationError("Invalid IPv4 CIDR: " + network);
            }

            std::istringstream address(match[1].str());
            std::string octet;
            int count = 0;

            while (std::getline(address, octet, '.')) {
                int value = std::stoi(octet);

                if (value < 0 || value > 255) {
                    throw ValidationError("Invalid IPv4 octet.");
                }

                ++count;
            }

            int prefix = std::stoi(match[4].str());

            if (count != 4 || prefix < 0 || prefix > 32) {
                throw ValidationError("Invalid IPv4 network prefix.");
            }
        }
    }
};

struct TransferRequest {
    fs::path localFile;
    std::string username;
    std::string host;
    std::string remotePath;
};

struct TransferAssessment {
    bool eligible = false;
    std::uint64_t fileSize = 0;
    std::vector<std::string> reasons;
};

class SecureTransferPolicy {
private:
    SecurityPolicy policy;

    static bool safeUsername(const std::string& username) {
        static const std::regex pattern(
            R"([A-Za-z_][A-Za-z0-9_.-]{0,31})"
        );

        return std::regex_match(username, pattern);
    }

    static bool safeHost(const std::string& host) {
        static const std::regex pattern(
            R"([A-Za-z0-9][A-Za-z0-9.-]{0,252})"
        );

        return std::regex_match(host, pattern);
    }

    static bool safeRemotePath(const std::string& path) {
        if (path.empty() || path.front() != '/' ||
            path.find_first_of(" \t\r\n\"'\\") != std::string::npos) {
            return false;
        }

        std::istringstream stream(path);
        std::string part;

        while (std::getline(stream, part, '/')) {
            if (part == "." || part == "..") {
                return false;
            }
        }

        return path.back() != '/';
    }

public:
    explicit SecureTransferPolicy(SecurityPolicy configured)
        : policy(configured) {
        policy.validate();
    }

    TransferAssessment evaluate(const TransferRequest& request) const {
        TransferAssessment result;

        if (!safeUsername(request.username)) {
            result.reasons.push_back("Invalid SSH username.");
        }

        if (!safeHost(request.host)) {
            result.reasons.push_back("Invalid SSH hostname.");
        }

        if (!safeRemotePath(request.remotePath)) {
            result.reasons.push_back("Unsafe remote path.");
        }

        std::error_code error;

        if (!fs::exists(request.localFile, error) ||
            error ||
            !fs::is_regular_file(request.localFile, error) ||
            error) {
            result.reasons.push_back("Local file is not a regular file.");
        } else {
            result.fileSize = fs::file_size(request.localFile, error);

            if (error) {
                result.reasons.push_back("Cannot determine file size.");
            } else if (result.fileSize > policy.maximumFileSize) {
                result.reasons.push_back("File exceeds configured size limit.");
            }
        }

        result.eligible = result.reasons.empty();
        return result;
    }

    static std::string buildSftpCommand(const TransferRequest& request) {
        return "sftp -o BatchMode=yes "
               "-o StrictHostKeyChecking=yes "
               "-o IdentitiesOnly=yes "
               "-o ForwardAgent=no "
               + request.username + "@" + request.host;
    }
};

class CommunicationGovernance {
private:
    SecurityPolicy policy;
    SessionManager sessions;
    std::set<std::string> approvedHosts;

public:
    explicit CommunicationGovernance(SecurityPolicy configured)
        : policy(configured) {
        policy.validate();
    }

    void approveHost(const std::string& hostname) {
        if (hostname.empty()) {
            throw ValidationError("Empty hostname.");
        }

        approvedHosts.insert(hostname);
    }

    bool hostApproved(const std::string& hostname) const {
        return approvedHosts.count(hostname) != 0;
    }

    void registerHTTPS(
        const std::string& id,
        const std::string& hostname
    ) {
        if (!hostApproved(hostname)) {
            throw ValidationError("HTTPS destination is not approved.");
        }

        sessions.registerSession(
            id,
            Endpoint{
                hostname,
                443,
                Protocol::HTTPS,
                policy.verifyCertificates,
                policy.verifyHostname
            }
        );
    }

    SessionManager& sessionManager() {
        return sessions;
    }

    void report() const {
        sessions.printReport();
    }
};

void demonstrate() {
    std::cout << "\n=== SECURE COMMUNICATIONS ENGINE ===\n";

    SecurityPolicy policy;
    policy.validate();

    CommunicationGovernance governance(policy);

    governance.approveHost("example.com");

    std::cout << "\n1. HTTPS destination policy\n";

    governance.registerHTTPS("HTTPS-001", "example.com");

    auto& sessions = governance.sessionManager();

    sessions.transition("HTTPS-001", ConnectionState::Connecting);
    sessions.transition("HTTPS-001", ConnectionState::Connected);

    std::cout << "HTTPS destination approved.\n";
    std::cout << "TLS certificate verification required.\n";
    std::cout << "Hostname verification required.\n";

    std::cout << "\n2. SSH session requirements\n";

    Endpoint sshEndpoint{
        "server.example.com",
        22,
        Protocol::SSH
    };

    sshEndpoint.validate();

    std::cout << "SSH host: " << sshEndpoint.hostname << '\n';
    std::cout << "Host-key verification: mandatory\n";
    std::cout << "Agent forwarding: disabled\n";

    std::cout << "\n3. VPN configuration\n";

    VPNProfile vpn{
        "wg0",
        "vpn.example.com",
        51820,
        {"10.20.0.0/16", "192.168.50.0/24"},
        "WireGuard"
    };

    vpn.validate();

    std::cout << "Interface: " << vpn.interfaceName << '\n';
    std::cout << "Endpoint: " << vpn.endpoint << ":" << vpn.port << '\n';
    std::cout << "Protocol: " << vpn.protocol << '\n';

    for (const auto& network : vpn.allowedNetworks) {
        std::cout << "Allowed route: " << network << '\n';
    }

    std::cout << "\n4. SFTP transfer eligibility\n";

    fs::path sample = fs::temp_directory_path() /
                      "secure-communications-sample.txt";

    {
        std::ofstream output(sample);

        if (!output) {
            throw std::runtime_error("Cannot create sample file.");
        }

        output << "Confidential enterprise transfer record.";
    }

    TransferRequest request{
        sample,
        "secureuser",
        "sftp.example.com",
        "/incoming/record.txt"
    };

    SecureTransferPolicy transferPolicy(policy);
    TransferAssessment assessment = transferPolicy.evaluate(request);

    std::cout << "Eligible: "
              << std::boolalpha << assessment.eligible << '\n';

    std::cout << "File size: " << assessment.fileSize << " bytes\n";

    if (assessment.eligible) {
        std::cout << "Command plan: "
                  << SecureTransferPolicy::buildSftpCommand(request)
                  << '\n';

        std::cout << "The command is a plan; no transfer is executed.\n";
    } else {
        for (const auto& reason : assessment.reasons) {
            std::cout << "Rejected: " << reason << '\n';
        }
    }

    fs::remove(sample);

    std::cout << "\n5. Invalid transfer test\n";

    TransferRequest invalidRequest{
        fs::temp_directory_path() / "missing-file.txt",
        "bad user",
        "sftp.example.com",
        "/incoming/../secret.txt"
    };

    auto invalid = transferPolicy.evaluate(invalidRequest);

    std::cout << "Eligible: " << invalid.eligible << '\n';

    for (const auto& reason : invalid.reasons) {
        std::cout << "Rejected: " << reason << '\n';
    }

    std::cout << "\n6. Connection lifecycle\n";

    sessions.transition("HTTPS-001", ConnectionState::Disconnected);

    governance.report();

    std::cout << "\nSecure communications policy evaluation completed.\n";
}

void runTests() {
    SecurityPolicy policy;
    policy.validate();

    VPNProfile vpn{
        "wg0",
        "vpn.example.com",
        51820,
        {"10.0.0.0/8"},
        "WireGuard"
    };

    vpn.validate();

    SecureTransferPolicy transferPolicy(policy);

    TransferRequest invalid{
        "/nonexistent/file.txt",
        "bad username",
        "server.example.com",
        "/incoming/../file.txt"
    };

    auto result = transferPolicy.evaluate(invalid);

    if (result.eligible || result.reasons.size() < 3) {
        throw std::runtime_error("Transfer validation test failed.");
    }

    SessionManager manager;

    manager.registerSession(
        "TEST-001",
        Endpoint{"example.com", 443, Protocol::HTTPS}
    );

    manager.transition("TEST-001", ConnectionState::Connecting);
    manager.transition("TEST-001", ConnectionState::Connected);

    bool rejected = false;

    try {
        manager.transition("TEST-001", ConnectionState::Connecting);
    } catch (const ValidationError&) {
        rejected = true;
    }

    if (!rejected) {
        throw std::runtime_error("Invalid transition was accepted.");
    }

    std::cout << "All C++17 policy tests passed.\n";
}

int main() {
    try {
        runTests();
        demonstrate();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SECURITY ERROR: " << error.what() << '\n';
        return 1;
    }
}
