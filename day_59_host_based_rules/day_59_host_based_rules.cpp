#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

enum class Direction { Inbound, Outbound };
enum class Action { Allow, Deny };
enum class Protocol { Tcp, Udp, Icmp, Any };
enum class LogLevel { None, Denied, All };

std::string to_string(Direction value) {
    return value == Direction::Inbound ? "inbound" : "outbound";
}

std::string to_string(Action value) {
    return value == Action::Allow ? "allow" : "deny";
}

std::string to_string(Protocol value) {
    switch (value) {
        case Protocol::Tcp: return "tcp";
        case Protocol::Udp: return "udp";
        case Protocol::Icmp: return "icmp";
        default: return "any";
    }
}

class IPv4Network {
private:
    uint32_t network_;
    uint32_t mask_;

    static uint32_t parseAddress(const std::string& address) {
        std::stringstream stream(address);
        std::string token;
        uint32_t value = 0;
        int count = 0;

        while (std::getline(stream, token, '.')) {
            if (token.empty() || token.size() > 3) {
                throw std::invalid_argument("invalid IPv4 address: " + address);
            }

            int octet = std::stoi(token);
            if (octet < 0 || octet > 255) {
                throw std::invalid_argument("invalid IPv4 octet");
            }

            value = (value << 8U) | static_cast<uint32_t>(octet);
            ++count;
        }

        if (count != 4) {
            throw std::invalid_argument("IPv4 address requires four octets");
        }

        return value;
    }

public:
    explicit IPv4Network(const std::string& cidr) {
        const auto slash = cidr.find('/');
        if (slash == std::string::npos) {
            throw std::invalid_argument("network requires CIDR notation");
        }

        const std::string address = cidr.substr(0, slash);
        const int prefix = std::stoi(cidr.substr(slash + 1));

        if (prefix < 0 || prefix > 32) {
            throw std::invalid_argument("CIDR prefix must be 0..32");
        }

        mask_ = prefix == 0 ? 0U : (0xFFFFFFFFU << (32 - prefix));
        network_ = parseAddress(address) & mask_;
    }

    bool contains(const std::string& address) const {
        return (parseAddress(address) & mask_) == network_;
    }
};

struct Connection {
    Direction direction;
    Protocol protocol;
    std::string sourceIp;
    std::string destinationIp;
    std::optional<int> sourcePort;
    std::optional<int> destinationPort;
    std::string application;
    std::string user;
};

struct FirewallRule {
    std::string id;
    Direction direction;
    Action action;
    Protocol protocol;
    IPv4Network sourceNetwork;
    IPv4Network destinationNetwork;
    std::optional<int> destinationPort;
    std::string application;
    int priority;
    bool enabled;
    LogLevel logLevel;
    std::string description;

    FirewallRule(
        std::string ruleId,
        Direction ruleDirection,
        Action ruleAction,
        Protocol ruleProtocol,
        std::string source,
        std::string destination,
        std::optional<int> port,
        std::string app,
        int rulePriority,
        bool ruleEnabled,
        LogLevel level,
        std::string text
    )
        : id(std::move(ruleId)),
          direction(ruleDirection),
          action(ruleAction),
          protocol(ruleProtocol),
          sourceNetwork(std::move(source)),
          destinationNetwork(std::move(destination)),
          destinationPort(port),
          application(std::move(app)),
          priority(rulePriority),
          enabled(ruleEnabled),
          logLevel(level),
          description(std::move(text)) {
        if (id.empty() || priority < 1) {
            throw std::invalid_argument("invalid firewall rule");
        }
        if (destinationPort && (*destinationPort < 1 || *destinationPort > 65535)) {
            throw std::invalid_argument("invalid destination port");
        }
    }
};

struct Decision {
    Action action;
    std::string ruleId;
    bool logged;
    std::string reason;
};

class GovernanceFirewall {
private:
    Action defaultAction_;
    std::vector<FirewallRule> rules_;
    std::vector<std::string> audit_;

    static bool portMatches(
        const std::optional<int>& actual,
        const std::optional<int>& expected
    ) {
        return !expected || (actual && *actual == *expected);
    }

    static bool applicationMatches(
        const std::string& application,
        const std::string& pattern
    ) {
        if (pattern == "*") {
            return true;
        }

        if (!pattern.empty() && pattern.back() == '*') {
            const std::string prefix = pattern.substr(0, pattern.size() - 1);
            return application.rfind(prefix, 0) == 0;
        }

        return application == pattern;
    }

    static void validate(const Connection& connection) {
        IPv4Network source(connection.sourceIp + "/32");
        IPv4Network destination(connection.destinationIp + "/32");
        (void)source;
        (void)destination;

        for (const auto& port : {connection.sourcePort, connection.destinationPort}) {
            if (port && (*port < 1 || *port > 65535)) {
                throw std::invalid_argument("port outside 1..65535");
            }
        }

        if (connection.application.empty()) {
            throw std::invalid_argument("application identity is required");
        }
    }

    bool matches(const Connection& connection, const FirewallRule& rule) const {
        return rule.enabled &&
               connection.direction == rule.direction &&
               (rule.protocol == Protocol::Any ||
                connection.protocol == rule.protocol) &&
               rule.sourceNetwork.contains(connection.sourceIp) &&
               rule.destinationNetwork.contains(connection.destinationIp) &&
               portMatches(connection.destinationPort, rule.destinationPort) &&
               applicationMatches(connection.application, rule.application);
    }

    void audit(
        const Connection& connection,
        const Decision& decision
    ) {
        std::ostringstream record;
        record << to_string(connection.direction)
               << " "
               << to_string(connection.protocol)
               << " "
               << connection.sourceIp
               << " -> "
               << connection.destinationIp
               << ":"
               << (connection.destinationPort
                       ? std::to_string(*connection.destinationPort)
                       : "-")
               << " application=" << connection.application
               << " action=" << to_string(decision.action)
               << " rule=" << decision.ruleId;

        audit_.push_back(record.str());
    }

public:
    explicit GovernanceFirewall(Action defaultAction = Action::Deny)
        : defaultAction_(defaultAction) {}

    void addRule(FirewallRule rule) {
        const auto duplicate = std::find_if(
            rules_.begin(),
            rules_.end(),
            [&](const FirewallRule& existing) {
                return existing.id == rule.id;
            }
        );

        if (duplicate != rules_.end()) {
            throw std::invalid_argument("duplicate rule: " + rule.id);
        }

        rules_.push_back(std::move(rule));

        std::sort(
            rules_.begin(),
            rules_.end(),
            [](const FirewallRule& left, const FirewallRule& right) {
                return left.priority < right.priority;
            }
        );
    }

    Decision evaluate(const Connection& connection) {
        validate(connection);

        for (const auto& rule : rules_) {
            if (!matches(connection, rule)) {
                continue;
            }

            const bool shouldLog =
                rule.logLevel == LogLevel::All ||
                (rule.logLevel == LogLevel::Denied &&
                 rule.action == Action::Deny);

            Decision decision{
                rule.action,
                rule.id,
                shouldLog,
                rule.description.empty()
                    ? "matched rule"
                    : rule.description
            };

            if (shouldLog) {
                audit(connection, decision);
            }

            return decision;
        }

        Decision decision{
            defaultAction_,
            "DEFAULT",
            defaultAction_ == Action::Deny,
            "no explicit rule matched"
        };

        if (decision.logged) {
            audit(connection, decision);
        }

        return decision;
    }

    void printAudit() const {
        std::cout << "\nAudit log\n";
        for (const auto& entry : audit_) {
            std::cout << "  " << entry << '\n';
        }
    }
};

void printDecision(
    const Connection& connection,
    const Decision& decision
) {
    std::cout
        << std::left
        << std::setw(9) << to_string(connection.direction)
        << std::setw(15) << connection.application
        << std::setw(7) << to_string(decision.action)
        << std::setw(18) << decision.ruleId
        << decision.reason
        << '\n';
}

int main() {
    try {
        GovernanceFirewall firewall;

        firewall.addRule(FirewallRule(
            "ALLOW-SSH-MGMT",
            Direction::Inbound,
            Action::Allow,
            Protocol::Tcp,
            "10.20.0.0/24",
            "10.20.0.10/32",
            22,
            "sshd",
            10,
            true,
            LogLevel::All,
            "SSH permitted from management network"
        ));

        firewall.addRule(FirewallRule(
            "DENY-INBOUND-APP",
            Direction::Inbound,
            Action::Deny,
            Protocol::Tcp,
            "0.0.0.0/0",
            "0.0.0.0/0",
            8080,
            "*",
            20,
            true,
            LogLevel::Denied,
            "Unapproved inbound service"
        ));

        firewall.addRule(FirewallRule(
            "ALLOW-DNS",
            Direction::Outbound,
            Action::Allow,
            Protocol::Udp,
            "10.20.0.10/32",
            "10.20.0.53/32",
            53,
            "resolver",
            30,
            true,
            LogLevel::All,
            "Approved DNS resolver"
        ));

        firewall.addRule(FirewallRule(
            "ALLOW-HTTPS",
            Direction::Outbound,
            Action::Allow,
            Protocol::Tcp,
            "10.20.0.10/32",
            "0.0.0.0/0",
            443,
            "browser*",
            40,
            true,
            LogLevel::All,
            "Approved browser HTTPS"
        ));

        firewall.addRule(FirewallRule(
            "DENY-UNKNOWN-OUTBOUND",
            Direction::Outbound,
            Action::Deny,
            Protocol::Any,
            "0.0.0.0/0",
            "0.0.0.0/0",
            std::nullopt,
            "*",
            90,
            true,
            LogLevel::Denied,
            "Outbound traffic lacks an explicit allow rule"
        ));

        const std::vector<Connection> connections{
            {
                Direction::Inbound,
                Protocol::Tcp,
                "10.20.0.15",
                "10.20.0.10",
                51000,
                22,
                "sshd",
                "administrator"
            },
            {
                Direction::Inbound,
                Protocol::Tcp,
                "203.0.113.50",
                "10.20.0.10",
                51001,
                8080,
                "unknown",
                ""
            },
            {
                Direction::Outbound,
                Protocol::Udp,
                "10.20.0.10",
                "10.20.0.53",
                53000,
                53,
                "resolver",
                ""
            },
            {
                Direction::Outbound,
                Protocol::Tcp,
                "10.20.0.10",
                "198.51.100.20",
                52000,
                443,
                "browser",
                ""
            },
            {
                Direction::Outbound,
                Protocol::Tcp,
                "10.20.0.10",
                "198.51.100.40",
                52001,
                22,
                "unknown",
                ""
            }
        };

        for (const auto& connection : connections) {
            const auto decision = firewall.evaluate(connection);
            printDecision(connection, decision);
        }

        // Invalid addresses fail before policy evaluation.
        try {
            Connection malformed{
                Direction::Outbound,
                Protocol::Tcp,
                "not-an-ip",
                "198.51.100.10",
                50000,
                443,
                "browser",
                ""
            };
            firewall.evaluate(malformed);
        } catch (const std::exception& error) {
            std::cout << "\nValidation failure handled: "
                      << error.what() << '\n';
        }

        firewall.printAudit();

        // Expected policy outcomes.
        if (firewall.evaluate(connections[0]).action != Action::Allow) {
            throw std::runtime_error("SSH policy regression");
        }
        if (firewall.evaluate(connections[1]).action != Action::Deny) {
            throw std::runtime_error("inbound denial regression");
        }
        if (firewall.evaluate(connections[2]).action != Action::Allow) {
            throw std::runtime_error("DNS policy regression");
        }
        if (firewall.evaluate(connections[3]).action != Action::Allow) {
            throw std::runtime_error("HTTPS policy regression");
        }
        if (firewall.evaluate(connections[4]).action != Action::Deny) {
            throw std::runtime_error("outbound denial regression");
        }

        std::cout << "\nAll firewall policy assertions passed.\n";
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
