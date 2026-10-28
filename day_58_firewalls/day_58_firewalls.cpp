#include <algorithm>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

enum class Action {
    Allow,
    Deny
};

enum class Protocol {
    TCP,
    UDP,
    ICMP
};

enum class Direction {
    Inbound,
    Outbound
};

enum class Zone {
    Internet,
    DMZ,
    Internal,
    Untrusted
};

std::string toString(Action action) {
    return action == Action::Allow ? "ALLOW" : "DENY";
}

std::string toString(Protocol protocol) {
    switch (protocol) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
    }
    return "UNKNOWN";
}

std::string toString(Zone zone) {
    switch (zone) {
        case Zone::Internet: return "INTERNET";
        case Zone::DMZ: return "DMZ";
        case Zone::Internal: return "INTERNAL";
        case Zone::Untrusted: return "UNTRUSTED";
    }
    return "UNKNOWN";
}

struct IPv4 {
    std::uint32_t value{};

    static IPv4 parse(const std::string& text) {
        std::stringstream stream(text);
        std::string part;
        std::uint32_t result = 0;
        int count = 0;

        while (std::getline(stream, part, '.')) {
            if (part.empty() || count == 4) {
                throw std::invalid_argument("Invalid IPv4 address: " + text);
            }

            int octet = std::stoi(part);

            if (octet < 0 || octet > 255) {
                throw std::invalid_argument("Invalid IPv4 octet: " + text);
            }

            result = (result << 8U) | static_cast<std::uint32_t>(octet);
            ++count;
        }

        if (count != 4) {
            throw std::invalid_argument("Invalid IPv4 address: " + text);
        }

        return IPv4{result};
    }

    std::string str() const {
        std::ostringstream output;

        output
            << ((value >> 24U) & 255U) << '.'
            << ((value >> 16U) & 255U) << '.'
            << ((value >> 8U) & 255U) << '.'
            << (value & 255U);

        return output.str();
    }
};

struct Network {
    IPv4 address;
    std::uint8_t prefix{};

    bool contains(IPv4 ip) const {
        if (prefix == 0) {
            return true;
        }

        std::uint32_t mask = 0xFFFFFFFFU << (32U - prefix);
        return (address.value & mask) == (ip.value & mask);
    }
};

struct Packet {
    IPv4 source;
    IPv4 destination;
    Protocol protocol;
    std::optional<std::uint16_t> sourcePort;
    std::optional<std::uint16_t> destinationPort;
    Direction direction;
};

void validatePacket(const Packet& packet) {
    const bool portProtocol =
        packet.protocol == Protocol::TCP ||
        packet.protocol == Protocol::UDP;

    if (portProtocol) {
        if (!packet.sourcePort || !packet.destinationPort) {
            throw std::invalid_argument(
                "TCP and UDP packets require ports"
            );
        }
    } else if (packet.sourcePort || packet.destinationPort) {
        throw std::invalid_argument(
            "ICMP packets cannot contain TCP/UDP ports"
        );
    }

    for (const auto& port :
         {packet.sourcePort, packet.destinationPort}) {
        if (port && (*port < 1 || *port > 65535)) {
            throw std::invalid_argument("Port outside valid range");
        }
    }
}

struct Rule {
    std::string name;
    Action action;
    std::optional<Protocol> protocol;
    std::optional<Network> sourceNetwork;
    std::optional<Network> destinationNetwork;
    std::optional<std::uint16_t> sourcePort;
    std::optional<std::uint16_t> destinationPort;
    std::optional<Direction> direction;

    bool matches(const Packet& packet) const {
        if (protocol && *protocol != packet.protocol) {
            return false;
        }

        if (sourceNetwork && !sourceNetwork->contains(packet.source)) {
            return false;
        }

        if (
            destinationNetwork &&
            !destinationNetwork->contains(packet.destination)
        ) {
            return false;
        }

        if (sourcePort != packet.sourcePort) {
            if (sourcePort || packet.sourcePort) {
                return false;
            }
        }

        if (destinationPort != packet.destinationPort) {
            if (destinationPort || packet.destinationPort) {
                return false;
            }
        }

        if (direction && *direction != packet.direction) {
            return false;
        }

        return true;
    }
};

struct Decision {
    Action action;
    std::string rule;
    std::string reason;
};

class StatefulFirewall {
private:
    std::vector<Rule> rules_;
    std::unordered_set<std::string> flows_;
    Action defaultAction_;

    static std::string flowKey(const Packet& packet) {
        std::ostringstream key;

        key
            << packet.source.value << ':'
            << packet.destination.value << ':'
            << static_cast<int>(packet.protocol) << ':'
            << packet.sourcePort.value_or(0) << ':'
            << packet.destinationPort.value_or(0);

        return key.str();
    }

    static std::string reverseFlowKey(const Packet& packet) {
        std::ostringstream key;

        key
            << packet.destination.value << ':'
            << packet.source.value << ':'
            << static_cast<int>(packet.protocol) << ':'
            << packet.destinationPort.value_or(0) << ':'
            << packet.sourcePort.value_or(0);

        return key.str();
    }

public:
    StatefulFirewall(
        std::vector<Rule> rules,
        Action defaultAction = Action::Deny
    )
        : rules_(std::move(rules)),
          defaultAction_(defaultAction) {}

    Decision evaluate(const Packet& packet) {
        validatePacket(packet);

        const auto key = flowKey(packet);
        const auto reverse = reverseFlowKey(packet);

        if (
            flows_.contains(key) ||
            flows_.contains(reverse)
        ) {
            return {
                Action::Allow,
                "STATEFUL-ESTABLISHED",
                "Existing flow state permits traffic"
            };
        }

        for (const auto& rule : rules_) {
            if (rule.matches(packet)) {
                if (rule.action == Action::Allow) {
                    flows_.insert(key);
                }

                return {
                    rule.action,
                    rule.name,
                    "First matching rule"
                };
            }
        }

        return {
            defaultAction_,
            "DEFAULT-DENY",
            "No rule matched"
        };
    }

    std::size_t trackedFlows() const {
        return flows_.size();
    }
};

class ZoneFirewall {
private:
    std::vector<Rule> rules_;
    Action defaultAction_;

    Zone classify(IPv4 ip) const {
        const Network dmz{
            IPv4::parse("10.0.10.0"),
            24
        };

        const Network internal{
            IPv4::parse("10.0.20.0"),
            24
        };

        if (dmz.contains(ip)) {
            return Zone::DMZ;
        }

        if (internal.contains(ip)) {
            return Zone::Internal;
        }

        return Zone::Internet;
    }

public:
    explicit ZoneFirewall(
        std::vector<Rule> rules,
        Action defaultAction = Action::Deny
    )
        : rules_(std::move(rules)),
          defaultAction_(defaultAction) {}

    Decision evaluate(const Packet& packet) const {
        validatePacket(packet);

        const Zone sourceZone = classify(packet.source);
        const Zone destinationZone = classify(packet.destination);

        for (const auto& rule : rules_) {
            if (rule.matches(packet)) {
                return {
                    rule.action,
                    rule.name,
                    toString(sourceZone) + " -> " +
                        toString(destinationZone)
                };
            }
        }

        return {
            defaultAction_,
            "ZONE-DEFAULT-DENY",
            toString(sourceZone) + " -> " +
                toString(destinationZone) +
                " has no explicit permit"
        };
    }
};

Rule allowHttpsInbound() {
    return {
        "ALLOW-HTTPS-INBOUND",
        Action::Allow,
        Protocol::TCP,
        std::nullopt,
        Network{IPv4::parse("10.0.10.0"), 24},
        std::nullopt,
        443,
        Direction::Inbound
    };
}

Rule allowDnsOutbound() {
    return {
        "ALLOW-DNS-OUTBOUND",
        Action::Allow,
        Protocol::UDP,
        Network{IPv4::parse("10.0.20.0"), 24},
        std::nullopt,
        std::nullopt,
        53,
        Direction::Outbound
    };
}

Rule denyTelnet() {
    return {
        "DENY-TELNET",
        Action::Deny,
        Protocol::TCP,
        std::nullopt,
        std::nullopt,
        std::nullopt,
        23,
        std::nullopt
    };
}

Packet tcpPacket(
    const std::string& source,
    const std::string& destination,
    std::uint16_t sourcePort,
    std::uint16_t destinationPort,
    Direction direction
) {
    return {
        IPv4::parse(source),
        IPv4::parse(destination),
        Protocol::TCP,
        sourcePort,
        destinationPort,
        direction
    };
}

Packet udpPacket(
    const std::string& source,
    const std::string& destination,
    std::uint16_t sourcePort,
    std::uint16_t destinationPort,
    Direction direction
) {
    return {
        IPv4::parse(source),
        IPv4::parse(destination),
        Protocol::UDP,
        sourcePort,
        destinationPort,
        direction
    };
}

void printDecision(
    const Packet& packet,
    const Decision& decision
) {
    std::cout
        << packet.source.str() << " -> "
        << packet.destination.str()
        << " " << toString(packet.protocol)
        << ": " << toString(decision.action)
        << " [" << decision.rule << "] "
        << decision.reason << '\n';
}

int main() {
    try {
        std::vector<Rule> rules{
            allowHttpsInbound(),
            allowDnsOutbound(),
            denyTelnet()
        };

        StatefulFirewall firewall(rules);

        std::vector<Packet> traffic{
            tcpPacket(
                "203.0.113.10",
                "10.0.10.20",
                45000,
                443,
                Direction::Inbound
            ),
            tcpPacket(
                "10.0.10.20",
                "203.0.113.10",
                443,
                45000,
                Direction::Outbound
            ),
            udpPacket(
                "10.0.20.15",
                "8.8.8.8",
                51000,
                53,
                Direction::Outbound
            ),
            tcpPacket(
                "203.0.113.20",
                "10.0.20.20",
                40000,
                22,
                Direction::Inbound
            ),
            tcpPacket(
                "203.0.113.20",
                "10.0.20.20",
                40001,
                23,
                Direction::Inbound
            )
        };

        std::cout << "STATEFUL FIREWALL\n";

        for (const auto& packet : traffic) {
            printDecision(packet, firewall.evaluate(packet));
        }

        std::cout
            << "\nTracked flows: "
            << firewall.trackedFlows()
            << "\n";

        ZoneFirewall zoneFirewall({
            allowHttpsInbound(),
            allowDnsOutbound(),
            denyTelnet()
        });

        std::cout << "\nZONE-AWARE EVALUATION\n";

        printDecision(
            traffic[0],
            zoneFirewall.evaluate(traffic[0])
        );

        printDecision(
            traffic[2],
            zoneFirewall.evaluate(traffic[2])
        );

        printDecision(
            traffic[3],
            zoneFirewall.evaluate(traffic[3])
        );

        bool defaultDenyVerified = true;

        Packet sshAttempt = tcpPacket(
            "203.0.113.90",
            "10.0.10.20",
            50000,
            22,
            Direction::Inbound
        );

        const auto sshDecision = firewall.evaluate(sshAttempt);

        if (sshDecision.action != Action::Deny) {
            defaultDenyVerified = false;
        }

        if (!defaultDenyVerified) {
            throw std::logic_error(
                "Security invariant failed: unmatched traffic was allowed"
            );
        }

        std::cout
            << "\nSecurity invariant: default deny verified.\n";

        try {
            Packet malformed{
                IPv4::parse("10.0.0.1"),
                IPv4::parse("10.0.0.2"),
                Protocol::TCP,
                std::nullopt,
                443,
                Direction::Outbound
            };

            firewall.evaluate(malformed);
            throw std::logic_error(
                "Malformed TCP packet was accepted"
            );
        } catch (const std::invalid_argument&) {
            std::cout
                << "Validation invariant: malformed TCP packet rejected.\n";
        }

    } catch (const std::exception& error) {
        std::cerr
            << "Firewall engine failure: "
            << error.what()
            << '\n';

        return 1;
    }

    return 0;
}
