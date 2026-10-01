#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

/*
 * Linux Fundamentals Case Study
 *
 * Scenario:
 *   A company operates a Linux-hosted monitoring service. The governance
 *   engine below models the technical decisions needed to deploy and operate
 *   that service safely:
 *
 *   filesystem -> ownership/permissions -> service identity
 *              -> package dependencies -> process lifecycle
 *
 * The program intentionally models these mechanisms rather than modifying
 * the machine on which it runs. It therefore compiles on any C++17 system.
 */

namespace linux_lab {

// ---------------------------------------------------------------------------
// Filesystem and permission model
// ---------------------------------------------------------------------------

enum Permission : unsigned {
    READ = 4,
    WRITE = 2,
    EXECUTE = 1
};

struct Identity {
    std::string username;
    unsigned uid{};
    std::string primaryGroup;
    std::set<std::string> supplementaryGroups;

    bool belongsTo(const std::string& group) const {
        return primaryGroup == group ||
               supplementaryGroups.count(group) > 0;
    }
};

struct Inode {
    std::string path;
    std::string owner;
    std::string group;
    unsigned mode{};
    bool directory{false};
};

enum class PermissionClass {
    OWNER,
    GROUP,
    OTHER
};

PermissionClass selectPermissionClass(
    const Identity& identity,
    const Inode& inode
) {
    /*
     * Linux selects one permission class rather than combining permissions
     * from every matching class. Ownership therefore has priority over group
     * membership for the traditional mode-bit decision.
     */
    if (identity.username == inode.owner) {
        return PermissionClass::OWNER;
    }

    if (identity.belongsTo(inode.group)) {
        return PermissionClass::GROUP;
    }

    return PermissionClass::OTHER;
}

bool canAccess(
    const Identity& identity,
    const Inode& inode,
    Permission permission
) {
    const PermissionClass selected =
        selectPermissionClass(identity, inode);

    const unsigned shift =
        selected == PermissionClass::OWNER ? 6 :
        selected == PermissionClass::GROUP ? 3 : 0;

    return (inode.mode & (static_cast<unsigned>(permission) << shift)) != 0;
}

std::string permissionString(unsigned mode) {
    const std::array<std::pair<unsigned, char>, 9> bits{{
        {0400, 'r'}, {0200, 'w'}, {0100, 'x'},
        {0040, 'r'}, {0020, 'w'}, {0010, 'x'},
        {0004, 'r'}, {0002, 'w'}, {0001, 'x'}
    }};

    std::string result;

    for (const auto& [bit, character] : bits) {
        result += (mode & bit) ? character : '-';
    }

    return result;
}

std::string octalMode(unsigned mode) {
    std::ostringstream output;
    output << std::oct << std::setw(4) << std::setfill('0')
           << (mode & 07777);
    return output.str();
}


// ---------------------------------------------------------------------------
// Package dependency graph
// ---------------------------------------------------------------------------

struct Package {
    std::string name;
    std::string version;
    std::vector<std::string> dependencies;
};

class PackageGraph {
private:
    std::unordered_map<std::string, Package> packages;

    void resolveRecursive(
        const std::string& name,
        std::unordered_set<std::string>& visiting,
        std::unordered_set<std::string>& visited,
        std::vector<std::string>& order
    ) const {
        if (visited.count(name)) {
            return;
        }

        if (visiting.count(name)) {
            throw std::runtime_error(
                "package dependency cycle detected at " + name
            );
        }

        auto iterator = packages.find(name);
        if (iterator == packages.end()) {
            throw std::runtime_error(
                "required package is unavailable: " + name
            );
        }

        visiting.insert(name);

        for (const std::string& dependency :
             iterator->second.dependencies) {
            resolveRecursive(
                dependency,
                visiting,
                visited,
                order
            );
        }

        visiting.erase(name);
        visited.insert(name);
        order.push_back(name);
    }

public:
    void addPackage(const Package& package) {
        if (packages.count(package.name)) {
            throw std::invalid_argument(
                "duplicate package: " + package.name
            );
        }

        packages.emplace(package.name, package);
    }

    std::vector<std::string> installationOrder(
        const std::string& root
    ) const {
        std::unordered_set<std::string> visiting;
        std::unordered_set<std::string> visited;
        std::vector<std::string> order;

        resolveRecursive(root, visiting, visited, order);
        return order;
    }
};


// ---------------------------------------------------------------------------
// Process lifecycle
// ---------------------------------------------------------------------------

enum class ProcessState {
    CREATED,
    RUNNING,
    STOPPED,
    FAILED
};

std::string processStateName(ProcessState state) {
    switch (state) {
        case ProcessState::CREATED:
            return "created";
        case ProcessState::RUNNING:
            return "running";
        case ProcessState::STOPPED:
            return "stopped";
        case ProcessState::FAILED:
            return "failed";
    }

    return "unknown";
}

struct Process {
    int pid{};
    int parentPid{};
    std::string executable;
    std::string runtimeUser;
    ProcessState state{ProcessState::CREATED};
    int exitCode{-1};
};

class ProcessTable {
private:
    std::map<int, Process> processes;

public:
    void add(const Process& process) {
        if (processes.count(process.pid)) {
            throw std::invalid_argument(
                "PID already exists"
            );
        }

        processes.emplace(process.pid, process);
    }

    Process& get(int pid) {
        auto iterator = processes.find(pid);

        if (iterator == processes.end()) {
            throw std::out_of_range("unknown PID");
        }

        return iterator->second;
    }

    const std::map<int, Process>& all() const {
        return processes;
    }
};


// ---------------------------------------------------------------------------
// Service unit and governance engine
// ---------------------------------------------------------------------------

struct ServiceUnit {
    std::string name;
    std::string executable;
    std::string runtimeUser;
    std::string configurationPath;
    std::string logDirectory;
    std::vector<std::string> dependencies;

    bool enabled{false};
    bool active{false};
    bool restartOnFailure{false};
};

struct GovernanceResult {
    bool accepted{false};
    std::vector<std::string> reasons;
};

class GovernanceEngine {
private:
    std::map<std::string, Identity> identities;
    std::map<std::string, Inode> files;
    std::set<std::string> installedPackages;
    std::map<std::string, ServiceUnit> services;

public:
    void addIdentity(const Identity& identity) {
        identities[identity.username] = identity;
    }

    void addFile(const Inode& inode) {
        files[inode.path] = inode;
    }

    void markPackageInstalled(const std::string& package) {
        installedPackages.insert(package);
    }

    void registerService(const ServiceUnit& service) {
        services[service.name] = service;
    }

    GovernanceResult evaluateService(
        const std::string& serviceName
    ) const {
        GovernanceResult result;

        auto serviceIterator = services.find(serviceName);
        if (serviceIterator == services.end()) {
            result.reasons.push_back("service is not registered");
            return result;
        }

        const ServiceUnit& service = serviceIterator->second;

        auto identityIterator =
            identities.find(service.runtimeUser);

        if (identityIterator == identities.end()) {
            result.reasons.push_back(
                "service runtime account does not exist"
            );
        }

        const auto configIterator =
            files.find(service.configurationPath);

        if (configIterator == files.end()) {
            result.reasons.push_back(
                "service configuration file is missing"
            );
        } else if (
            identityIterator != identities.end() &&
            !canAccess(
                identityIterator->second,
                configIterator->second,
                Permission::READ
            )
        ) {
            result.reasons.push_back(
                "runtime account cannot read service configuration"
            );
        }

        const auto logIterator =
            files.find(service.logDirectory);

        if (logIterator == files.end()) {
            result.reasons.push_back(
                "service log directory is missing"
            );
        } else if (!logIterator->second.directory) {
            result.reasons.push_back(
                "configured log path is not a directory"
            );
        } else if (
            identityIterator != identities.end() &&
            !canAccess(
                identityIterator->second,
                logIterator->second,
                Permission::WRITE
            )
        ) {
            result.reasons.push_back(
                "runtime account cannot write the log directory"
            );
        }

        for (const std::string& dependency : service.dependencies) {
            if (!installedPackages.count(dependency)) {
                result.reasons.push_back(
                    "required package is not installed: " + dependency
                );
            }
        }

        if (service.executable.empty()) {
            result.reasons.push_back(
                "service has no executable"
            );
        }

        if (result.reasons.empty()) {
            result.accepted = true;
        }

        return result;
    }
};


// ---------------------------------------------------------------------------
// Scenario construction
// ---------------------------------------------------------------------------

GovernanceEngine buildProductionScenario() {
    GovernanceEngine engine;

    /*
     * A dedicated service identity limits the impact of a compromise compared
     * with running the application as root. Its group grants only the access
     * needed for application files and logs.
     */
    engine.addIdentity({
        "monitor",
        990,
        "webops",
        {}
    });

    engine.addIdentity({
        "deploy",
        1001,
        "webops",
        {"developers"}
    });

    /*
     * Configuration is root-owned but readable by the service group.
     * 0640 prevents unrelated users from reading configuration values.
     */
    engine.addFile({
        "/etc/monitor/monitor.conf",
        "root",
        "webops",
        0640,
        false
    });

    /*
     * Setgid on the log directory is useful in collaborative operational
     * directories because newly created files can inherit the directory group.
     * The service account still needs write permission through its group.
     */
    engine.addFile({
        "/var/log/monitor",
        "root",
        "webops",
        02770,
        true
    });

    engine.addFile({
        "/usr/local/bin/monitor-agent",
        "root",
        "root",
        0755,
        false
    });

    engine.markPackageInstalled("libssl");
    engine.markPackageInstalled("http-client");

    engine.registerService({
        "monitor-agent.service",
        "/usr/local/bin/monitor-agent",
        "monitor",
        "/etc/monitor/monitor.conf",
        "/var/log/monitor",
        {"http-client"},
        true,
        false,
        true
    });

    return engine;
}


// ---------------------------------------------------------------------------
// Demonstrations
// ---------------------------------------------------------------------------

void demonstratePermissions() {
    std::cout << "\n=== Filesystem Permission Analysis ===\n";

    Identity deployer{
        "deploy",
        1001,
        "webops",
        {"developers"}
    };

    Inode executable{
        "/srv/monitor/bin/monitor",
        "deploy",
        "webops",
        0750,
        false
    };

    std::cout
        << executable.path
        << " "
        << permissionString(executable.mode)
        << " "
        << octalMode(executable.mode)
        << '\n';

    std::cout
        << "Owner read    : "
        << canAccess(deployer, executable, Permission::READ)
        << '\n';

    std::cout
        << "Owner execute : "
        << canAccess(deployer, executable, Permission::EXECUTE)
        << '\n';

    /*
     * This illustrates a common source of confusion: directory write and
     * execute permissions govern entries and traversal, not file contents
     * directly.
     */
    Inode directory{
        "/srv/monitor",
        "root",
        "webops",
        02770,
        true
    };

    std::cout
        << "Directory group write: "
        << canAccess(deployer, directory, Permission::WRITE)
        << '\n';

    std::cout
        << "Directory group traverse: "
        << canAccess(deployer, directory, Permission::EXECUTE)
        << '\n';
}

void demonstratePackageResolution() {
    std::cout << "\n=== Package Dependency Resolution ===\n";

    PackageGraph graph;

    graph.addPackage({
        "libssl",
        "3.2",
        {}
    });

    graph.addPackage({
        "http-client",
        "8.6",
        {"libssl"}
    });

    graph.addPackage({
        "monitor-agent",
        "2.8",
        {"http-client"}
    });

    const auto order =
        graph.installationOrder("monitor-agent");

    std::cout << "Installation order:\n";

    for (const auto& package : order) {
        std::cout << "  " << package << '\n';
    }

    std::cout
        << "Dependency resolution is a directed-graph problem. "
        << "A cycle makes a valid topological installation order impossible.\n";
}

void demonstrateProcesses() {
    std::cout << "\n=== Process Table ===\n";

    ProcessTable table;

    table.add({
        4100,
        1,
        "/usr/local/bin/monitor-agent",
        "monitor",
        ProcessState::RUNNING,
        -1
    });

    table.add({
        4101,
        4100,
        "/usr/local/bin/log-writer",
        "monitor",
        ProcessState::RUNNING,
        -1
    });

    for (const auto& [pid, process] : table.all()) {
        std::cout
            << "PID=" << pid
            << " PPID=" << process.parentPid
            << " USER=" << process.runtimeUser
            << " STATE=" << processStateName(process.state)
            << " EXEC=" << process.executable
            << '\n';
    }

    /*
     * Parent-child relationships allow supervisors and administrators to
     * understand process trees. A process may also have open descriptors,
     * environment, credentials, memory mappings, and resource limits that
     * influence its behavior.
     */
}

void demonstrateServiceGovernance() {
    std::cout << "\n=== Service Governance Case Study ===\n";

    GovernanceEngine engine = buildProductionScenario();

    const GovernanceResult result =
        engine.evaluateService("monitor-agent.service");

    if (result.accepted) {
        std::cout
            << "monitor-agent.service: configuration is internally consistent\n"
            << "  runtime account exists\n"
            << "  configuration is readable\n"
            << "  log directory is writable\n"
            << "  required package is installed\n";
    } else {
        std::cout
            << "monitor-agent.service: deployment rejected\n";

        for (const auto& reason : result.reasons) {
            std::cout << "  - " << reason << '\n';
        }
    }
}

void demonstrateFailure() {
    std::cout << "\n=== Failure Analysis ===\n";

    GovernanceEngine engine;

    engine.addIdentity({
        "monitor",
        990,
        "webops",
        {}
    });

    /*
     * The configuration is intentionally 0600 and owned by root. The service
     * account therefore cannot read it. This is not a service-manager failure:
     * the process can be started but its runtime identity lacks filesystem
     * access to required data.
     */
    engine.addFile({
        "/etc/monitor/monitor.conf",
        "root",
        "root",
        0600,
        false
    });

    engine.addFile({
        "/var/log/monitor",
        "root",
        "webops",
        02770,
        true
    });

    engine.markPackageInstalled("http-client");

    engine.registerService({
        "monitor-agent.service",
        "/usr/local/bin/monitor-agent",
        "monitor",
        "/etc/monitor/monitor.conf",
        "/var/log/monitor",
        {"http-client"},
        true,
        false,
        true
    });

    const GovernanceResult result =
        engine.evaluateService("monitor-agent.service");

    std::cout
        << "Expected deployment failure:\n";

    for (const auto& reason : result.reasons) {
        std::cout << "  - " << reason << '\n';
    }

    std::cout
        << "The failure demonstrates why service debugging must inspect "
        << "both service configuration and the credentials of the process "
        << "that actually accesses the filesystem.\n";
}

} // namespace linux_lab


int main() {
    try {
        std::cout
            << "Linux Fundamentals Technical Case Study\n"
            << "========================================\n"
            << "Scenario: production monitoring service governance\n";

        linux_lab::demonstratePermissions();
        linux_lab::demonstratePackageResolution();
        linux_lab::demonstrateProcesses();
        linux_lab::demonstrateServiceGovernance();
        linux_lab::demonstrateFailure();

        std::cout
            << "\n=== Operational Relationship ===\n"
            << "Filesystem objects carry ownership and mode bits.\n"
            << "User/group identity determines which permission class applies.\n"
            << "Packages supply executables and libraries with dependency relationships.\n"
            << "A service manager supervises long-running processes.\n"
            << "The process runtime identity must be able to access its required files.\n"
            << "These mechanisms form a connected Linux operational model.\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
