#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/*
 * Repository operations are not modeled here. This program implements
 * a Windows endpoint governance case study: a fictional enterprise
 * evaluates service exposure, account privileges, and filesystem access
 * before accepting an endpoint into a managed fleet.
 *
 * C++17, standard library only.
 */

enum class AccountKind {
    StandardUser,
    ServiceAccount,
    Administrator
};

enum class ServiceState {
    Running,
    Stopped,
    Disabled
};

enum class AccessRight : std::uint32_t {
    Read = 1,
    Write = 2,
    Execute = 4,
    Delete = 8,
    ChangePermissions = 16
};

constexpr std::uint32_t mask(AccessRight right) {
    return static_cast<std::uint32_t>(right);
}

struct Principal {
    std::string sid;
    std::string displayName;
    AccountKind kind;
    bool enabled;
    std::set<std::string> groups;
};

struct Service {
    std::string name;
    std::string executable;
    std::string runAsSid;
    ServiceState state;
    bool automaticStart;
    bool executableWritableByStandardUsers;
    bool unquotedPathWithSpaces;
};

struct AccessRule {
    std::string principalSid;
    std::uint32_t allowMask;
    std::uint32_t denyMask;
};

struct FileObject {
    std::string path;
    std::string ownerSid;
    bool inheritsParentRules;
    std::vector<AccessRule> rules;
};

struct Finding {
    std::string severity;
    std::string asset;
    std::string description;
};

class EndpointPolicy {
public:
    explicit EndpointPolicy(std::size_t minimumPasswordLength)
        : minimumPasswordLength_(minimumPasswordLength) {
        if (minimumPasswordLength_ < 8 || minimumPasswordLength_ > 128) {
            throw std::invalid_argument(
                "Password length policy must be between 8 and 128."
            );
        }
    }

    void addPrincipal(Principal principal) {
        if (principal.sid.empty() || principal.displayName.empty()) {
            throw std::invalid_argument("Principal SID and name are required.");
        }

        if (principals_.count(principal.sid) != 0) {
            throw std::invalid_argument("Duplicate principal SID.");
        }

        principals_.emplace(principal.sid, std::move(principal));
    }

    void addService(Service service) {
        if (service.name.empty() || service.executable.empty()) {
            throw std::invalid_argument("Service name and executable are required.");
        }

        if (services_.count(service.name) != 0) {
            throw std::invalid_argument("Duplicate service name.");
        }

        if (principals_.count(service.runAsSid) == 0) {
            throw std::invalid_argument(
                "A service must reference a known service identity."
            );
        }

        services_.emplace(service.name, std::move(service));
    }

    void addFileObject(FileObject object) {
        if (object.path.empty()) {
            throw std::invalid_argument("Filesystem object path is required.");
        }

        if (principals_.count(object.ownerSid) == 0) {
            throw std::invalid_argument("Filesystem owner is unknown.");
        }

        if (files_.count(object.path) != 0) {
            throw std::invalid_argument("Duplicate filesystem object.");
        }

        files_.emplace(object.path, std::move(object));
    }

    std::vector<Finding> audit() const {
        std::vector<Finding> findings;

        for (const auto& [name, service] : services_) {
            const auto identity = principals_.at(service.runAsSid);

            if (service.state == ServiceState::Disabled &&
                service.automaticStart) {
                findings.push_back({
                    "HIGH",
                    name,
                    "Inconsistent service configuration: disabled but automatic."
                });
            }

            if (service.state == ServiceState::Running &&
                identity.kind == AccountKind::Administrator) {
                findings.push_back({
                    "HIGH",
                    name,
                    "Running service uses an administrative identity."
                });
            }

            if (service.executableWritableByStandardUsers) {
                findings.push_back({
                    "CRITICAL",
                    name,
                    "Standard users can modify a service executable."
                });
            }

            if (service.unquotedPathWithSpaces) {
                findings.push_back({
                    "HIGH",
                    name,
                    "Executable path contains spaces and is not quoted."
                });
            }

            if (identity.kind == AccountKind::ServiceAccount &&
                identity.enabled &&
                identity.groups.count("LocalAdministrators") != 0) {
                findings.push_back({
                    "HIGH",
                    name,
                    "Dedicated service identity belongs to local administrators."
                });
            }
        }

        for (const auto& [path, object] : files_) {
            for (const auto& rule : object.rules) {
                if (principals_.count(rule.principalSid) == 0) {
                    findings.push_back({
                        "MEDIUM",
                        path,
                        "ACL rule references an unknown principal SID."
                    });
                }

                if (rule.denyMask != 0 && rule.allowMask != 0) {
                    findings.push_back({
                        "REVIEW",
                        path,
                        "Allow and deny rights coexist; evaluate the complete ACL."
                    });
                }
            }
        }

        std::sort(
            findings.begin(),
            findings.end(),
            [](const Finding& left, const Finding& right) {
                const auto rank = [](const std::string& severity) {
                    if (severity == "CRITICAL") return 0;
                    if (severity == "HIGH") return 1;
                    if (severity == "MEDIUM") return 2;
                    if (severity == "REVIEW") return 3;
                    return 4;
                };

                if (rank(left.severity) != rank(right.severity)) {
                    return rank(left.severity) < rank(right.severity);
                }
                return left.asset < right.asset;
            }
        );

        return findings;
    }

    /*
     * This is an intentionally simplified effective-rights model.
     * It handles explicit rules for the user SID and supplied group SIDs,
     * with deny bits taking precedence globally. Windows ACL evaluation
     * also depends on ACE ordering, inheritance, token privileges,
     * mandatory integrity levels, owner semantics, and object type.
     */
    std::uint32_t evaluateSimplifiedAccess(
        const FileObject& object,
        const std::string& userSid,
        const std::set<std::string>& tokenGroups
    ) const {
        if (principals_.count(userSid) == 0) {
            throw std::invalid_argument("Unknown user SID.");
        }

        std::uint32_t allowed = 0;
        std::uint32_t denied = 0;

        for (const auto& rule : object.rules) {
            const bool matches =
                rule.principalSid == userSid ||
                tokenGroups.count(rule.principalSid) != 0;

            if (matches) {
                allowed |= rule.allowMask;
                denied |= rule.denyMask;
            }
        }

        return allowed & ~denied;
    }

    const std::map<std::string, Principal>& principals() const {
        return principals_;
    }

    const std::map<std::string, Service>& services() const {
        return services_;
    }

private:
    std::size_t minimumPasswordLength_;
    std::map<std::string, Principal> principals_;
    std::map<std::string, Service> services_;
    std::map<std::string, FileObject> files_;
};

std::string accountKindName(AccountKind kind) {
    switch (kind) {
        case AccountKind::StandardUser: return "Standard user";
        case AccountKind::ServiceAccount: return "Service account";
        case AccountKind::Administrator: return "Administrator";
    }
    return "Unknown";
}

std::string serviceStateName(ServiceState state) {
    switch (state) {
        case ServiceState::Running: return "Running";
        case ServiceState::Stopped: return "Stopped";
        case ServiceState::Disabled: return "Disabled";
    }
    return "Unknown";
}

std::string rightsDescription(std::uint32_t rights) {
    const std::vector<std::pair<AccessRight, std::string>> names = {
        {AccessRight::Read, "Read"},
        {AccessRight::Write, "Write"},
        {AccessRight::Execute, "Execute"},
        {AccessRight::Delete, "Delete"},
        {AccessRight::ChangePermissions, "ChangePermissions"}
    };

    std::ostringstream output;
    bool first = true;

    for (const auto& [right, name] : names) {
        if ((rights & mask(right)) != 0) {
            if (!first) output << ", ";
            output << name;
            first = false;
        }
    }

    return first ? "None" : output.str();
}

int main() {
    try {
        EndpointPolicy policy(14);

        policy.addPrincipal({
            "S-1-5-21-100-100-100-1001",
            "Maya",
            AccountKind::StandardUser,
            true,
            {"Employees", "AuthenticatedUsers"}
        });

        policy.addPrincipal({
            "S-1-5-21-100-100-100-1002",
            "InventorySvc",
            AccountKind::ServiceAccount,
            true,
            {"ServiceAccounts", "LocalAdministrators"}
        });

        policy.addPrincipal({
            "S-1-5-21-100-100-100-500",
            "LocalAdmin",
            AccountKind::Administrator,
            true,
            {"LocalAdministrators", "AuthenticatedUsers"}
        });

        policy.addService({
            "InventoryAgent",
            "C:\\Program Files\\Inventory\\agent.exe",
            "S-1-5-21-100-100-100-1002",
            ServiceState::Running,
            true,
            true,
            false
        });

        policy.addService({
            "LegacyUpdater",
            "C:\\Program Files\\Legacy Tools\\update.exe",
            "S-1-5-21-100-100-100-500",
            ServiceState::Running,
            true,
            false,
            true
        });

        policy.addService({
            "DisabledDiagnostic",
            "C:\\Windows\\System32\\diagnostic.exe",
            "S-1-5-21-100-100-100-1002",
            ServiceState::Disabled,
            true,
            false,
            false
        });

        FileObject configuration{
            "C:\\ProgramData\\Inventory\\settings.json",
            "S-1-5-21-100-100-100-1002",
            true,
            {
                {
                    "S-1-5-21-100-100-100-1001",
                    mask(AccessRight::Read),
                    mask(AccessRight::Write)
                },
                {
                    "Employees",
                    mask(AccessRight::Read),
                    0
                },
                {
                    "S-1-5-21-100-100-100-1002",
                    mask(AccessRight::Read) |
                        mask(AccessRight::Write),
                    0
                }
            }
        };

        policy.addFileObject(configuration);

        std::cout << "Endpoint identity inventory\n";
        for (const auto& [sid, principal] : policy.principals()) {
            std::cout << principal.displayName
                      << " | " << sid
                      << " | " << accountKindName(principal.kind)
                      << " | enabled=" << std::boolalpha
                      << principal.enabled << '\n';
        }

        std::cout << "\nService inventory\n";
        for (const auto& [name, service] : policy.services()) {
            std::cout << name << " | "
                      << serviceStateName(service.state)
                      << " | run-as=" << service.runAsSid
                      << " | automatic=" << service.automaticStart
                      << '\n';
        }

        std::cout << "\nPolicy findings\n";
        const auto findings = policy.audit();

        if (findings.empty()) {
            std::cout << "No findings detected by the simplified policy.\n";
        }

        for (const auto& finding : findings) {
            std::cout << '[' << finding.severity << "] "
                      << finding.asset << ": "
                      << finding.description << '\n';
        }

        std::cout << "\nSimplified filesystem authorization\n";
        const auto effective = policy.evaluateSimplifiedAccess(
            configuration,
            "S-1-5-21-100-100-100-1001",
            {"Employees", "AuthenticatedUsers"}
        );

        std::cout << "Maya effective modeled rights: "
                  << rightsDescription(effective) << '\n';

        const auto serviceIdentity = policy.principals().at(
            "S-1-5-21-100-100-100-1002"
        );

        if (serviceIdentity.groups.count("LocalAdministrators") != 0) {
            std::cout
                << "Remediation: remove unnecessary administrative group "
                << "membership and restrict executable write permissions.\n";
        }

        std::cout
            << "\nThis simulation evaluates policy data, not the live Windows "
            << "security subsystem. Actual Windows access checks require "
            << "native security descriptors and access tokens.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Policy evaluation failed: "
                  << error.what() << '\n';
        return 1;
    }
}
