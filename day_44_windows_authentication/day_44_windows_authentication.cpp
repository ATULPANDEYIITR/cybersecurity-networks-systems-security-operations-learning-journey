#include <algorithm>
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
#include <utility>
#include <vector>

/*
 * Repository-independent Windows authentication governance case study.
 *
 * Scenario:
 * A corporate file service must distinguish local account logon,
 * NTLM challenge-response concepts, Kerberos ticket concepts, and
 * resource authorization. It must reject expired challenges, reused
 * challenge identifiers, wrong service tickets, disabled accounts,
 * and requests from users without resource permissions.
 *
 * The cryptographic values are illustrative and are not compatible with
 * real Windows NTLM, Kerberos, Active Directory, or Windows LSA.
 * No passwords are persisted in this simulation.
 */

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

enum class AccountKind {
    Local,
    Domain
};

enum class Protocol {
    Local,
    NtlmConcept,
    KerberosConcept
};

enum class LogonKind {
    Interactive,
    Network,
    Service
};

std::string toString(Protocol protocol) {
    switch (protocol) {
        case Protocol::Local: return "Local";
        case Protocol::NtlmConcept: return "NTLM concept";
        case Protocol::KerberosConcept: return "Kerberos concept";
    }
    throw std::logic_error("Unknown protocol");
}

class AuthenticationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class AuthorizationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Account {
    std::string username;
    std::string domain;
    AccountKind kind;
    std::set<std::string> groups;
    bool enabled{true};
    bool locked{false};

    std::string principal() const {
        if (kind == AccountKind::Local) {
            return "LOCALHOST\\" + username;
        }
        return domain + "\\" + username;
    }
};

struct Session {
    std::string principal;
    Protocol protocol;
    LogonKind logonKind;
    std::set<std::string> groups;
    std::string sessionId;
};

struct AuditEvent {
    std::string action;
    std::string principal;
    std::string result;
    std::string detail;
};

class AuditLog {
public:
    void write(
        std::string action,
        std::string principal,
        std::string result,
        std::string detail
    ) {
        events_.push_back({
            std::move(action),
            std::move(principal),
            std::move(result),
            std::move(detail)
        });
    }

    void print() const {
        for (const auto& event : events_) {
            std::cout << event.action << " | "
                      << event.principal << " | "
                      << event.result << " | "
                      << event.detail << '\n';
        }
    }

    std::size_t size() const {
        return events_.size();
    }

private:
    std::vector<AuditEvent> events_;
};

class AccountDirectory {
public:
    void add(Account account) {
        if (account.username.empty()) {
            throw std::invalid_argument("Username cannot be empty");
        }

        const std::string key = makeKey(
            account.username,
            account.domain,
            account.kind
        );

        if (accounts_.count(key) != 0) {
            throw std::invalid_argument("Duplicate account: " + key);
        }
        accounts_.emplace(key, std::move(account));
    }

    const Account& find(
        const std::string& username,
        const std::string& domain,
        AccountKind kind
    ) const {
        const auto iterator = accounts_.find(
            makeKey(username, domain, kind)
        );
        if (iterator == accounts_.end()) {
            throw AuthenticationError("Account not found");
        }
        return iterator->second;
    }

private:
    static std::string makeKey(
        const std::string& username,
        const std::string& domain,
        AccountKind kind
    ) {
        if (kind == AccountKind::Local) {
            return "LOCALHOST\\" + username;
        }
        return domain + "\\" + username;
    }

    std::map<std::string, Account> accounts_;
};

class SessionIssuer {
public:
    Session issue(
        const Account& account,
        Protocol protocol,
        LogonKind logonKind
    ) {
        if (!account.enabled || account.locked) {
            throw AuthenticationError("Account is unavailable");
        }

        return {
            account.principal(),
            protocol,
            logonKind,
            account.groups,
            makeIdentifier()
        };
    }

private:
    static std::string makeIdentifier() {
        static std::uint64_t counter = 0;
        std::ostringstream stream;
        stream << "session-" << ++counter;
        return stream.str();
    }
};

struct Challenge {
    std::string id;
    std::string server;
    std::uint64_t nonce;
    TimePoint issuedAt;
};

struct Ticket {
    std::string id;
    std::string client;
    std::string service;
    std::string kind;
    TimePoint expiresAt;
};

class ChallengeRegistry {
public:
    explicit ChallengeRegistry(
        std::chrono::seconds lifetime = std::chrono::seconds(30)
    ) : lifetime_(lifetime) {
        if (lifetime_.count() <= 0) {
            throw std::invalid_argument("Challenge lifetime must be positive");
        }
    }

    Challenge issue(const std::string& server) {
        if (server.empty()) {
            throw std::invalid_argument("Server name is required");
        }

        Challenge challenge{
            nextId("challenge"),
            server,
            random_(),
            Clock::now()
        };
        active_.emplace(challenge.id, challenge);
        return challenge;
    }

    Challenge consume(const std::string& id) {
        auto iterator = active_.find(id);
        if (iterator == active_.end()) {
            throw AuthenticationError(
                "Challenge missing or already consumed"
            );
        }

        // Consume the identifier before returning it. A later request
        // cannot authenticate again with the same challenge.
        Challenge challenge = iterator->second;
        active_.erase(iterator);

        if (Clock::now() - challenge.issuedAt > lifetime_) {
            throw AuthenticationError("Challenge expired");
        }
        return challenge;
    }

private:
    static std::string nextId(const std::string& prefix) {
        static std::uint64_t counter = 0;
        return prefix + "-" + std::to_string(++counter);
    }

    static std::uint64_t random() {
        static std::mt19937_64 engine(std::random_device{}());
        return engine();
    }

    std::chrono::seconds lifetime_;
    std::map<std::string, Challenge> active_;
};

class FileService {
public:
    FileService(
        const AccountDirectory& directory,
        AuditLog& audit
    ) : directory_(directory), audit_(audit) {}

    Session localLogon(
        const std::string& username,
        bool credentialVerified
    ) {
        const Account& account = directory_.find(
            username, "", AccountKind::Local
        );

        if (!credentialVerified) {
            audit_.write(
                "local-logon", account.principal(),
                "denied", "Credential verification failed"
            );
            throw AuthenticationError("Invalid local credentials");
        }

        Session session = issuer_.issue(
            account, Protocol::Local, LogonKind::Interactive
        );
        audit_.write(
            "local-logon", account.principal(),
            "accepted", "Local account authority model"
        );
        return session;
    }

    Session ntlmChallengeResponse(
        const std::string& username,
        const std::string& domain,
        const std::string& challengeId,
        bool responseVerified
    ) {
        Challenge challenge = challenges_.consume(challengeId);
        const Account& account = directory_.find(
            username, domain, AccountKind::Domain
        );

        if (!responseVerified) {
            audit_.write(
                "ntlm-concept", account.principal(),
                "denied", "Challenge-response mismatch"
            );
            throw AuthenticationError("Invalid challenge response");
        }

        Session session = issuer_.issue(
            account, Protocol::NtlmConcept, LogonKind::Network
        );
        audit_.write(
            "ntlm-concept", account.principal(),
            "accepted",
            "Challenge " + challenge.id + " consumed for " + challenge.server
        );
        return session;
    }

    Ticket issueTgt(
        const std::string& username,
        const std::string& domain,
        bool initialCredentialsVerified
    ) {
        const Account& account = directory_.find(
            username, domain, AccountKind::Domain
        );

        if (!initialCredentialsVerified) {
            audit_.write(
                "kerberos-as", account.principal(),
                "denied", "Initial credentials rejected"
            );
            throw AuthenticationError("Initial authentication failed");
        }
        if (!account.enabled || account.locked) {
            throw AuthenticationError("Account is unavailable");
        }

        Ticket tgt{
            nextTicketId(),
            account.principal(),
            "krbtgt/" + domain,
            "TGT",
            Clock::now() + std::chrono::minutes(5)
        };
        tickets_.emplace(tgt.id, tgt);
        audit_.write(
            "kerberos-as", account.principal(),
            "accepted", "Synthetic ticket-granting ticket issued"
        );
        return tgt;
    }

    Ticket issueServiceTicket(
        const std::string& tgtId,
        const std::string& service
    ) {
        auto iterator = tickets_.find(tgtId);
        if (iterator == tickets_.end() ||
            iterator->second.kind != "TGT") {
            throw AuthenticationError("Valid TGT required");
        }
        if (Clock::now() >= iterator->second.expiresAt) {
            throw AuthenticationError("TGT expired");
        }
        if (service.find('/') == std::string::npos) {
            throw AuthenticationError("Service principal is malformed");
        }

        const Ticket& tgt = iterator->second;
        Ticket serviceTicket{
            nextTicketId(),
            tgt.client,
            service,
            "SERVICE",
            std::min(
                tgt.expiresAt,
                Clock::now() + std::chrono::minutes(5)
            )
        };
        tickets_.emplace(serviceTicket.id, serviceTicket);
        audit_.write(
            "kerberos-tgs", tgt.client,
            "accepted", "Service ticket issued for " + service
        );
        return serviceTicket;
    }

    Session acceptServiceTicket(
        const std::string& ticketId,
        const std::string& expectedService
    ) {
        auto iterator = tickets_.find(ticketId);
        if (iterator == tickets_.end() ||
            iterator->second.kind != "SERVICE") {
            throw AuthenticationError("Service ticket required");
        }

        const Ticket& ticket = iterator->second;
        if (Clock::now() >= ticket.expiresAt) {
            throw AuthenticationError("Service ticket expired");
        }
        if (ticket.service != expectedService) {
            throw AuthenticationError("Ticket targets another service");
        }

        const auto separator = ticket.client.find('\\');
        if (separator == std::string::npos) {
            throw AuthenticationError("Malformed client principal");
        }

        const std::string domain = ticket.client.substr(0, separator);
        const std::string username = ticket.client.substr(separator + 1);
        const Account& account = directory_.find(
            username, domain, AccountKind::Domain
        );

        Session session = issuer_.issue(
            account, Protocol::KerberosConcept, LogonKind::Network
        );
        audit_.write(
            "kerberos-service", ticket.client,
            "accepted", "Ticket accepted for " + expectedService
        );
        return session;
    }

    Challenge createChallenge(const std::string& server) {
        return challenges_.issue(server);
    }

    bool authorize(
        const Session& session,
        const std::string& resource,
        const std::map<std::string, std::set<std::string>>& policy
    ) const {
        for (const auto& group : session.groups) {
            const auto iterator = policy.find(group);
            if (iterator != policy.end() &&
                iterator->second.count(resource) != 0) {
                return true;
            }
        }

        throw AuthorizationError(
            session.principal + " cannot access " + resource
        );
    }

private:
    static std::string nextTicketId() {
        static std::uint64_t counter = 0;
        return "ticket-" + std::to_string(++counter);
    }

    const AccountDirectory& directory_;
    AuditLog& audit_;
    SessionIssuer issuer_;
    ChallengeRegistry challenges_;
    std::map<std::string, Ticket> tickets_;
};

int main() {
    try {
        AccountDirectory directory;
        directory.add({
            "helpdesk", "", AccountKind::Local,
            {"Users", "IT Support"}, true, false
        });
        directory.add({
            "alex", "CORP.EXAMPLE", AccountKind::Domain,
            {"Domain Users"}, true, false
        });

        AuditLog audit;
        FileService service(directory, audit);

        std::cout << "=== Local account logon ===\n";
        Session local = service.localLogon("helpdesk", true);
        std::cout << local.principal << " authenticated using "
                  << toString(local.protocol) << '\n';

        std::cout << "\n=== NTLM challenge-response concept ===\n";
        Challenge challenge =
            service.createChallenge("fileserver.corp.example");

        Session ntlm = service.ntlmChallengeResponse(
            "alex", "CORP.EXAMPLE", challenge.id, true
        );
        std::cout << ntlm.principal << " authenticated using "
                  << toString(ntlm.protocol) << '\n';

        try {
            service.ntlmChallengeResponse(
                "alex", "CORP.EXAMPLE", challenge.id, true
            );
        } catch (const AuthenticationError& error) {
            std::cout << "Replay rejected: " << error.what() << '\n';
        }

        std::cout << "\n=== Kerberos ticket concept ===\n";
        Ticket tgt = service.issueTgt(
            "alex", "CORP.EXAMPLE", true
        );
        Ticket serviceTicket = service.issueServiceTicket(
            tgt.id, "CIFS/fileserver.corp.example"
        );
        Session kerberos = service.acceptServiceTicket(
            serviceTicket.id, "CIFS/fileserver.corp.example"
        );

        std::cout << kerberos.principal << " authenticated using "
                  << toString(kerberos.protocol) << '\n';

        try {
            service.acceptServiceTicket(
                serviceTicket.id, "HTTP/intranet.corp.example"
            );
        } catch (const AuthenticationError& error) {
            std::cout << "Wrong service rejected: "
                      << error.what() << '\n';
        }

        std::cout << "\n=== Resource authorization ===\n";
        const std::map<std::string, std::set<std::string>> policy{
            {"Domain Users", {"intranet.read"}},
            {"IT Support", {"password-reset"}}
        };

        for (const auto& request :
             std::vector<std::pair<Session, std::string>>{
                 {local, "password-reset"},
                 {kerberos, "intranet.read"},
                 {kerberos, "payroll.admin"}
             }) {
            try {
                service.authorize(request.first, request.second, policy);
                std::cout << "GRANTED " << request.first.principal
                          << " -> " << request.second << '\n';
            } catch (const AuthorizationError& error) {
                std::cout << "DENIED " << error.what() << '\n';
            }
        }

        std::cout << "\n=== Audit trail ===\n";
        audit.print();
        std::cout << "Audit event count: " << audit.size() << '\n';

        std::cout
            << "\nThis program models protocol roles and policy decisions. "
            << "Its credential-verification flags and tickets are "
            << "simulations, not production security controls.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
