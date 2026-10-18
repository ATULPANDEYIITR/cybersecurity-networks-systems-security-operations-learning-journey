#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Enterprise Windows connectivity assessment.
 *
 * This C++17 case study models asset inventory, approved network paths,
 * Windows service exposure, and firewall-policy decisions. It deliberately
 * does not perform a port scan or alter a real firewall.
 */

enum class Service {
    SMB,
    RDP,
    WinRM,
    RPC
};

enum class FirewallAction {
    Allow,
    Block
};

enum class NetworkProfile {
    Domain,
    Private,
    Public
};

std::string toString(Service service) {
    switch (service) {
        case Service::SMB: return "SMB";
        case Service::RDP: return "RDP";
        case Service::WinRM: return "WinRM";
        case Service::RPC: return "RPC";
    }
    throw std::logic_error("Unknown service.");
}

std::string toString(FirewallAction action) {
    return action == FirewallAction::Allow ? "Allow" : "Block";
}

std::string toString(NetworkProfile profile) {
    switch (profile) {
        case NetworkProfile::Domain: return "Domain";
        case NetworkProfile::Private: return "Private";
        case NetworkProfile::Public: return "Public";
    }
    throw std::logic_error("Unknown network profile.");
}

std::vector<int> standardPorts(Service service) {
    switch (service) {
        case Service::SMB: return {445};
        case Service::RDP: return {3389};
        case Service::WinRM: return {5985, 5986};
        case Service::RPC: return {135};
    }
    throw std::logic_error("Unknown service.");
}

struct Asset {
    std::string hostname;
    std::string environment;
    std::set<Service> requiredServices;
};

struct FirewallRule {
    std::string name;
    Service service;
    int port;
    NetworkProfile profile;
    FirewallAction action;
    std::optional<std::string> approvedSource;
};

struct Assessment {
    std::string hostname;
    Service service;
    int port;
    bool requiredByApplication;
    FirewallAction decision;
    std::string explanation;
};

class NetworkGovernanceEngine {
public:
    explicit NetworkGovernanceEngine(FirewallAction defaultInbound)
        : defaultInbound_(defaultInbound) {}

    void addAsset(const Asset& asset) {
        if (asset.hostname.empty()) {
            throw std::invalid_argument("Hostname cannot be empty.");
        }

        if (assets_.count(asset.hostname)) {
            throw std::invalid_argument("Duplicate asset hostname.");
        }

        assets_.emplace(asset.hostname, asset);
    }

    void addRule(const FirewallRule& rule) {
        if (rule.port < 1 || rule.port > 65535) {
            throw std::invalid_argument("Firewall port is outside valid range.");
        }
        if (rule.name.empty()) {
            throw std::invalid_argument("Firewall rule requires a name.");
        }

        rules_.push_back(rule);
    }

    FirewallAction evaluate(
        Service service,
        int port,
        NetworkProfile profile,
        const std::string& source
    ) const {
        if (port < 1 || port > 65535) {
            throw std::invalid_argument("Invalid TCP port.");
        }

        // This is a simplified explicit-deny/allow policy model. Real Windows
        // Firewall evaluates a richer rule set and platform policy.
        for (const auto& rule : rules_) {
            if (rule.service != service ||
                rule.port != port ||
                rule.profile != profile) {
                continue;
            }

            if (rule.approvedSource && *rule.approvedSource != source) {
                continue;
            }

            return rule.action;
        }

        return defaultInbound_;
    }

    std::vector<Assessment> assessAsset(
        const std::string& hostname,
        NetworkProfile profile,
        const std::string& source
    ) const {
        const auto found = assets_.find(hostname);
        if (found == assets_.end()) {
            throw std::out_of_range("Asset is absent from the inventory.");
        }

        std::vector<Assessment> report;

        for (Service service : {
                 Service::SMB, Service::RDP, Service::WinRM, Service::RPC}) {
            const bool required =
                found->second.requiredServices.count(service) > 0;

            for (int port : standardPorts(service)) {
                const auto action = evaluate(service, port, profile, source);

                std::string explanation;
                if (!required && action == FirewallAction::Allow) {
                    explanation =
                        "Service is not declared as required but inbound traffic "
                        "is allowed by this model; investigate exposure.";
                } else if (required && action == FirewallAction::Block) {
                    explanation =
                        "Application dependency is blocked; validate the "
                        "business requirement before changing policy.";
                } else if (service == Service::RPC && port == 135) {
                    explanation =
                        "Endpoint mapper is evaluated separately from dynamic "
                        "RPC endpoints.";
                } else {
                    explanation = "Decision follows the configured policy model.";
                }

                report.push_back({
                    hostname, service, port, required, action, explanation
                });
            }
        }

        return report;
    }

private:
    FirewallAction defaultInbound_;
    std::map<std::string, Asset> assets_;
    std::vector<FirewallRule> rules_;
};

void printReport(const std::vector<Assessment>& report) {
    std::cout << "\nConnectivity governance assessment\n";
    std::cout << "---------------------------------\n";

    for (const auto& item : report) {
        std::cout
            << item.hostname
            << " | " << toString(item.service)
            << " | TCP " << item.port
            << " | required=" << (item.requiredByApplication ? "yes" : "no")
            << " | policy=" << toString(item.decision)
            << "\n  " << item.explanation << '\n';
    }
}

int main() {
    try {
        NetworkGovernanceEngine engine(FirewallAction::Block);

        engine.addAsset({
            "fileserver-01",
            "production",
            {Service::SMB, Service::RPC}
        });

        engine.addAsset({
            "admin-workstation-01",
            "corporate",
            {Service::RDP, Service::WinRM, Service::RPC}
        });

        engine.addRule({
            "Allow SMB from corporate subnet",
            Service::SMB,
            445,
            NetworkProfile::Domain,
            FirewallAction::Allow,
            std::string("192.168.10.25")
        });

        engine.addRule({
            "Block SMB on public profile",
            Service::SMB,
            445,
            NetworkProfile::Public,
            FirewallAction::Block,
            std::nullopt
        });

        engine.addRule({
            "Allow RDP from management workstation",
            Service::RDP,
            3389,
            NetworkProfile::Domain,
            FirewallAction::Allow,
            std::string("192.168.10.25")
        });

        engine.addRule({
            "Allow WinRM HTTPS from management workstation",
            Service::WinRM,
            5986,
            NetworkProfile::Domain,
            FirewallAction::Allow,
            std::string("192.168.10.25")
        });

        // TCP 5985 remains blocked by default, reducing reliance on
        // unencrypted WinRM transport.
        engine.addRule({
            "Explicitly block WinRM HTTP",
            Service::WinRM,
            5985,
            NetworkProfile::Domain,
            FirewallAction::Block,
            std::nullopt
        });

        printReport(engine.assessAsset(
            "fileserver-01",
            NetworkProfile::Domain,
            "192.168.10.25"
        ));

        printReport(engine.assessAsset(
            "admin-workstation-01",
            NetworkProfile::Public,
            "203.0.113.45"
        ));

        std::cout << "\nValidation case\n";
        try {
            engine.addRule({
                "Invalid port",
                Service::RDP,
                70000,
                NetworkProfile::Domain,
                FirewallAction::Allow,
                std::nullopt
            });
        } catch (const std::invalid_argument& error) {
            std::cout << "Rejected invalid rule: " << error.what() << '\n';
        }

        std::cout << "\nInventory lookup case\n";
        try {
            engine.assessAsset(
                "unknown-host",
                NetworkProfile::Private,
                "192.168.10.25"
            );
        } catch (const std::out_of_range& error) {
            std::cout << "Rejected unknown asset: " << error.what() << '\n';
        }

        std::cout
            << "\nSecurity limitation: this report evaluates a model, not "
            << "the live Windows Filtering Platform. A policy Allow decision "
            << "does not prove that a process is listening or that "
            << "authentication succeeds.\n";
    } catch (const std::exception& error) {
        std::cerr << "Assessment failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
