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
#include <unordered_map>
#include <utility>
#include <vector>

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

enum class TicketType {
    TGT,
    SERVICE
};

enum class AuthenticationResult {
    SUCCESS,
    INVALID_PRINCIPAL,
    INVALID_TICKET,
    EXPIRED,
    REPLAY,
    WRONG_SERVICE,
    INVALID_AUTHENTICATOR
};

enum class PrincipalStatus {
    ACTIVE,
    DISABLED
};

struct Principal {
    std::string name;
    std::string credentialVerifier;
    PrincipalStatus status = PrincipalStatus::ACTIVE;
};

struct Service {
    std::string name;
    std::string serviceKey;
};

struct Ticket {
    std::string id;
    TicketType type;
    std::string client;
    std::string service;
    std::string sessionKey;
    std::string issuer;
    TimePoint issuedAt;
    TimePoint expiresAt;
    bool valid = true;
};

struct Authenticator {
    std::string client;
    std::string nonce;
    TimePoint timestamp;
};

struct AuditRecord {
    std::string principal;
    std::string action;
    AuthenticationResult result;
    TimePoint timestamp;
};

struct Policy {
    std::chrono::seconds tgtLifetime{600};
    std::chrono::seconds serviceLifetime{300};
    std::chrono::seconds clockTolerance{60};
};

class KerberosException : public std::runtime_error {
public:
    explicit KerberosException(const std::string& message)
        : std::runtime_error(message) {}
};

class ReplayCache {
private:
    std::unordered_map<std::string, TimePoint> entries;

public:
    bool accept(
        const std::string& identifier,
        TimePoint expiry,
        TimePoint now
    ) {
        for (auto it = entries.begin(); it != entries.end();) {
            if (it->second <= now) {
                it = entries.erase(it);
            } else {
                ++it;
            }
        }

        if (entries.count(identifier)) {
            return false;
        }

        entries.emplace(identifier, expiry);
        return true;
    }

    std::size_t size() const {
        return entries.size();
    }
};

class KeyDistributionCenter {
private:
    std::unordered_map<std::string, Principal> principals;
    std::unordered_map<std::string, Service> services;
    std::unordered_map<std::string, Ticket> tickets;

    std::vector<AuditRecord> audit;
    ReplayCache replayCache;

    Policy policy;
    std::string realm;
    std::uint64_t ticketCounter = 0;

    static std::string randomToken() {
        static std::uint64_t counter = 0;
        ++counter;

        std::ostringstream out;
        out << "EDU-" << std::hex
            << std::chrono::steady_clock::now()
                   .time_since_epoch().count()
            << "-" << counter;

        return out.str();
    }

    void record(
        const std::string& principal,
        const std::string& action,
        AuthenticationResult result
    ) {
        audit.push_back({
            principal,
            action,
            result,
            Clock::now()
        });
    }

    void validatePrincipal(const std::string& name) const {
        auto it = principals.find(name);

        if (it == principals.end()) {
            throw KerberosException("Unknown principal");
        }

        if (it->second.status != PrincipalStatus::ACTIVE) {
            throw KerberosException("Principal disabled");
        }
    }

public:
    explicit KeyDistributionCenter(
        std::string realmName,
        Policy authenticationPolicy = {}
    )
        : policy(authenticationPolicy),
          realm(std::move(realmName)) {

        if (realm.empty() || realm.find('.') == std::string::npos) {
            throw std::invalid_argument("Invalid Kerberos realm");
        }

        if (
            policy.tgtLifetime.count() <= 0 ||
            policy.serviceLifetime.count() <= 0 ||
            policy.clockTolerance.count() < 0
        ) {
            throw std::invalid_argument("Invalid ticket policy");
        }
    }

    void registerPrincipal(
        const std::string& name,
        const std::string& credentialVerifier
    ) {
        if (
            name.empty() ||
            name.find('@') == std::string::npos ||
            credentialVerifier.empty()
        ) {
            throw std::invalid_argument("Invalid principal data");
        }

        if (principals.count(name)) {
            throw KerberosException("Duplicate principal");
        }

        principals.emplace(
            name,
            Principal{name, credentialVerifier, PrincipalStatus::ACTIVE}
        );

        record(
            name,
            "PRINCIPAL_REGISTERED",
            AuthenticationResult::SUCCESS
        );
    }

    void registerService(
        const std::string& serviceName,
        const std::string& serviceKey
    ) {
        if (
            serviceName.empty() ||
            serviceName.find('/') == std::string::npos ||
            serviceKey.empty()
        ) {
            throw std::invalid_argument("Invalid service registration");
        }

        if (services.count(serviceName)) {
            throw KerberosException("Duplicate service");
        }

        services.emplace(
            serviceName,
            Service{serviceName, serviceKey}
        );
    }

    void disablePrincipal(const std::string& name) {
        validatePrincipal(name);
        principals.at(name).status = PrincipalStatus::DISABLED;

        record(
            name,
            "PRINCIPAL_DISABLED",
            AuthenticationResult::SUCCESS
        );
    }

    Ticket authenticateAS(
        const std::string& client,
        const std::string& credentialVerifier
    ) {
        try {
            validatePrincipal(client);

            if (
                principals.at(client).credentialVerifier
                != credentialVerifier
            ) {
                throw KerberosException("Invalid credentials");
            }

            const auto now = Clock::now();

            Ticket tgt{
                randomToken(),
                TicketType::TGT,
                client,
                "krbtgt/" + realm,
                randomToken(),
                realm,
                now,
                now + policy.tgtLifetime,
                true
            };

            tickets.emplace(tgt.id, tgt);

            record(
                client,
                "AS_TGT_ISSUED",
                AuthenticationResult::SUCCESS
            );

            return tgt;

        } catch (...) {
            record(
                client,
                "AS_AUTHENTICATION",
                AuthenticationResult::INVALID_PRINCIPAL
            );
            throw;
        }
    }

    Ticket authenticateTGS(
        const Ticket& tgt,
        const std::string& requestedService
    ) {
        auto service = services.find(requestedService);

        if (service == services.end()) {
            record(
                tgt.client,
                "TGS_UNKNOWN_SERVICE",
                AuthenticationResult::WRONG_SERVICE
            );
            throw KerberosException("Unknown service");
        }

        auto stored = tickets.find(tgt.id);

        if (
            stored == tickets.end() ||
            !stored->second.valid ||
            stored->second.type != TicketType::TGT ||
            stored->second.client != tgt.client
        ) {
            throw KerberosException("Invalid TGT");
        }

        const auto now = Clock::now();

        if (now >= stored->second.expiresAt) {
            record(
                tgt.client,
                "TGT_EXPIRED",
                AuthenticationResult::EXPIRED
            );
            throw KerberosException("TGT expired");
        }

        Ticket serviceTicket{
            randomToken(),
            TicketType::SERVICE,
            tgt.client,
            requestedService,
            randomToken(),
            realm,
            now,
            std::min(
                now + policy.serviceLifetime,
                stored->second.expiresAt
            ),
            true
        };

        tickets.emplace(serviceTicket.id, serviceTicket);

        record(
            tgt.client,
            "SERVICE_TICKET_ISSUED",
            AuthenticationResult::SUCCESS
        );

        return serviceTicket;
    }

    bool authenticateService(
        const Ticket& serviceTicket,
        const Authenticator& authenticator,
        const std::string& requestedService
    ) {
        auto stored = tickets.find(serviceTicket.id);

        if (
            stored == tickets.end() ||
            !stored->second.valid ||
            stored->second.type != TicketType::SERVICE
        ) {
            throw KerberosException("Invalid service ticket");
        }

        const Ticket& ticket = stored->second;

        if (
            ticket.service != requestedService ||
            serviceTicket.service != requestedService
        ) {
            throw KerberosException("Service identity mismatch");
        }

        const auto now = Clock::now();

        if (now >= ticket.expiresAt) {
            record(
                ticket.client,
                "SERVICE_TICKET_EXPIRED",
                AuthenticationResult::EXPIRED
            );
            throw KerberosException("Service ticket expired");
        }

        if (
            authenticator.client != ticket.client ||
            authenticator.nonce.empty()
        ) {
            throw KerberosException("Invalid authenticator identity");
        }

        const auto difference =
            now >= authenticator.timestamp
            ? now - authenticator.timestamp
            : authenticator.timestamp - now;

        if (difference > policy.clockTolerance) {
            throw KerberosException("Clock tolerance exceeded");
        }

        const std::string replayId =
            ticket.id + ":" + authenticator.nonce;

        if (!replayCache.accept(
            replayId,
            ticket.expiresAt,
            now
        )) {
            record(
                ticket.client,
                "AUTHENTICATOR_REPLAY",
                AuthenticationResult::REPLAY
            );
            throw KerberosException("Replay detected");
        }

        record(
            ticket.client,
            "SERVICE_AUTHENTICATED",
            AuthenticationResult::SUCCESS
        );

        return true;
    }

    const std::vector<AuditRecord>& getAudit() const {
        return audit;
    }

    std::size_t principalCount() const {
        return principals.size();
    }

    std::size_t serviceCount() const {
        return services.size();
    }
};

class KerberosClient {
private:
    std::string name;
    std::optional<Ticket> tgt;

public:
    explicit KerberosClient(std::string principal)
        : name(std::move(principal)) {}

    void login(
        KeyDistributionCenter& kdc,
        const std::string& credentialVerifier
    ) {
        tgt = kdc.authenticateAS(name, credentialVerifier);
    }

    bool accessService(
        KeyDistributionCenter& kdc,
        const std::string& serviceName
    ) {
        if (!tgt.has_value()) {
            throw KerberosException("Client has no TGT");
        }

        Ticket serviceTicket = kdc.authenticateTGS(
            *tgt,
            serviceName
        );

        Authenticator authenticator{
            name,
            randomNonce(),
            Clock::now()
        };

        return kdc.authenticateService(
            serviceTicket,
            authenticator,
            serviceName
        );
    }

private:
    static std::string randomNonce() {
        static std::uint64_t nonce = 0;
        return "NONCE-" + std::to_string(++nonce);
    }
};

int main() {
    try {
        Policy policy;
        policy.tgtLifetime = std::chrono::seconds(600);
        policy.serviceLifetime = std::chrono::seconds(300);

        KeyDistributionCenter kdc("EXAMPLE.LOCAL", policy);

        const std::string user = "alice@EXAMPLE.LOCAL";

        kdc.registerPrincipal(user, "EDUCATIONAL-VERIFIER-01");

        kdc.registerService(
            "http/web.example.local",
            "HTTP-SERVICE-KEY"
        );

        kdc.registerService(
            "postgres/db.example.local",
            "DATABASE-SERVICE-KEY"
        );

        KerberosClient client(user);

        std::cout << "KERBEROS AUTHENTICATION ENGINE\n";
        std::cout << "Realm: EXAMPLE.LOCAL\n\n";

        std::cout << "1. Authentication Server\n";

        client.login(kdc, "EDUCATIONAL-VERIFIER-01");

        std::cout << "TGT successfully issued.\n";

        std::cout << "\n2. Ticket Granting Server\n";

        std::cout << "HTTP service: "
                  << std::boolalpha
                  << client.accessService(
                         kdc,
                         "http/web.example.local"
                     )
                  << '\n';

        std::cout << "Database service: "
                  << client.accessService(
                         kdc,
                         "postgres/db.example.local"
                     )
                  << '\n';

        std::cout << "\n3. Invalid credentials\n";

        try {
            kdc.authenticateAS(
                user,
                "INVALID-VERIFIER"
            );
        } catch (const KerberosException& ex) {
            std::cout << "Rejected: " << ex.what() << '\n';
        }

        std::cout << "\n4. Principal management\n";

        std::cout << "Registered principals: "
                  << kdc.principalCount() << '\n';

        std::cout << "Registered services: "
                  << kdc.serviceCount() << '\n';

        std::cout << "\n5. Authentication audit\n";

        for (const auto& event : kdc.getAudit()) {
            std::cout
                << std::left
                << std::setw(32)
                << event.action
                << " principal=" << event.principal
                << '\n';
        }

        std::cout << "\nAuthentication simulation completed.\n";

    } catch (const std::exception& ex) {
        std::cerr << "System failure: " << ex.what() << '\n';
        return 1;
    }

    return 0;
}
