#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

enum class Severity { Low, Medium, High, Critical };
enum class Environment { Development, Staging, Production };
enum class PatchStatus {
    Planned,
    Deploying,
    Validating,
    Completed,
    Failed,
    RolledBack
};

std::string to_string(Severity value) {
    switch (value) {
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "unknown";
}

std::string to_string(Environment value) {
    switch (value) {
        case Environment::Development: return "development";
        case Environment::Staging: return "staging";
        case Environment::Production: return "production";
    }
    return "unknown";
}

std::string to_string(PatchStatus value) {
    switch (value) {
        case PatchStatus::Planned: return "planned";
        case PatchStatus::Deploying: return "deploying";
        case PatchStatus::Validating: return "validating";
        case PatchStatus::Completed: return "completed";
        case PatchStatus::Failed: return "failed";
        case PatchStatus::RolledBack: return "rolled_back";
    }
    return "unknown";
}

class PatchException : public std::runtime_error {
public:
    explicit PatchException(const std::string& message)
        : std::runtime_error(message) {}
};

struct Patch {
    std::string id;
    std::string title;
    std::string component;
    std::string beforeVersion;
    std::string afterVersion;
    Severity severity;
    std::string checksum;
    bool requiresReboot;

    void validate() const {
        if (!std::regex_match(id, std::regex(R"(P-\d{4,})"))) {
            throw PatchException("Invalid patch ID: " + id);
        }

        if (title.empty() || component.empty()) {
            throw PatchException("Patch title and component are required.");
        }

        const std::regex versionPattern(R"(\d+(?:\.\d+){1,3})");
        if (!std::regex_match(beforeVersion, versionPattern) ||
            !std::regex_match(afterVersion, versionPattern)) {
            throw PatchException("Invalid patch version.");
        }

        if (beforeVersion == afterVersion) {
            throw PatchException("Patch versions must differ.");
        }

        if (checksum.size() != 64) {
            throw PatchException("Patch checksum must contain 64 characters.");
        }
    }
};

struct Server {
    std::string id;
    std::string hostname;
    Environment environment;
    std::unordered_map<std::string, std::string> versions;
    bool online{true};
    bool rebootRequired{false};
    std::optional<std::chrono::system_clock::time_point> lastPatched;
};

struct StatusCheck {
    std::string name;
    bool passed;
    std::string details;
};

struct Deployment {
    Patch patch;
    std::string serverId;
    PatchStatus status{PatchStatus::Planned};
    std::vector<StatusCheck> checks;

    void transition(PatchStatus next) {
        const std::map<PatchStatus, std::set<PatchStatus>> allowed = {
            {PatchStatus::Planned, {PatchStatus::Deploying, PatchStatus::Failed}},
            {PatchStatus::Deploying, {PatchStatus::Validating, PatchStatus::Failed}},
            {PatchStatus::Validating,
             {PatchStatus::Completed, PatchStatus::Failed, PatchStatus::RolledBack}},
            {PatchStatus::Failed, {PatchStatus::RolledBack}},
            {PatchStatus::Completed, {}},
            {PatchStatus::RolledBack, {}}
        };

        if (!allowed.at(status).count(next)) {
            throw PatchException(
                "Invalid deployment transition from " +
                to_string(status) + " to " + to_string(next)
            );
        }
        status = next;
    }
};

class GovernanceEngine {
private:
    std::unordered_map<std::string, Patch> patches_;
    std::unordered_map<std::string, Server> servers_;
    std::vector<Deployment> deployments_;

public:
    void registerPatch(const Patch& patch) {
        patch.validate();
        if (patches_.contains(patch.id)) {
            throw PatchException("Duplicate patch: " + patch.id);
        }
        patches_.emplace(patch.id, patch);
    }

    void registerServer(const Server& server) {
        if (server.id.empty() || server.hostname.empty()) {
            throw PatchException("Server ID and hostname are required.");
        }
        if (servers_.contains(server.id)) {
            throw PatchException("Duplicate server: " + server.id);
        }
        servers_.emplace(server.id, server);
    }

    Deployment& schedule(
        const std::string& patchId,
        const std::string& serverId,
        Environment approvedEnvironment
    ) {
        auto patchIt = patches_.find(patchId);
        auto serverIt = servers_.find(serverId);

        if (patchIt == patches_.end()) {
            throw PatchException("Unknown patch.");
        }
        if (serverIt == servers_.end()) {
            throw PatchException("Unknown server.");
        }

        Server& server = serverIt->second;
        const Patch& patch = patchIt->second;

        if (server.environment != approvedEnvironment) {
            throw PatchException("Server environment is outside the approved policy.");
        }

        if (!server.online) {
            throw PatchException("Server is offline.");
        }

        auto versionIt = server.versions.find(patch.component);
        if (versionIt == server.versions.end() ||
            versionIt->second != patch.beforeVersion) {
            throw PatchException("Installed version does not match patch prerequisite.");
        }

        deployments_.push_back(Deployment{patch, serverId});
        return deployments_.back();
    }

    bool evaluateChecks(const Server& server, const Patch& patch,
                        std::vector<StatusCheck>& checks) const {
        auto version = server.versions.find(patch.component);

        checks.push_back({
            "component_version",
            version != server.versions.end() &&
                version->second == patch.afterVersion,
            "Installed component version"
        });

        checks.push_back({
            "host_online",
            server.online,
            "Host availability"
        });

        checks.push_back({
            "reboot_state",
            !server.rebootRequired,
            "Reboot requirement cleared"
        });

        return std::all_of(
            checks.begin(),
            checks.end(),
            [](const StatusCheck& check) { return check.passed; }
        );
    }

    void deploy(Deployment& deployment, const std::string& observedChecksum) {
        Patch& patch = deployment.patch;
        Server& server = servers_.at(deployment.serverId);

        if (observedChecksum != patch.checksum) {
            deployment.transition(PatchStatus::Failed);
            throw PatchException("Checksum verification failed.");
        }

        deployment.transition(PatchStatus::Deploying);

        const auto previousVersion = server.versions.at(patch.component);
        const bool previousRebootState = server.rebootRequired;

        try {
            server.versions[patch.component] = patch.afterVersion;
            server.rebootRequired = patch.requiresReboot;

            deployment.transition(PatchStatus::Validating);

            // A production implementation would run service, dependency,
            // vulnerability, and synthetic-transaction checks here.
            server.rebootRequired = false;

            if (!evaluateChecks(server, patch, deployment.checks)) {
                deployment.transition(PatchStatus::Failed);
                server.versions[patch.component] = previousVersion;
                server.rebootRequired = previousRebootState;
                deployment.transition(PatchStatus::RolledBack);
                return;
            }

            server.lastPatched = std::chrono::system_clock::now();
            deployment.transition(PatchStatus::Completed);
        } catch (...) {
            if (deployment.status != PatchStatus::RolledBack) {
                server.versions[patch.component] = previousVersion;
                server.rebootRequired = previousRebootState;
                if (deployment.status != PatchStatus::Failed) {
                    deployment.transition(PatchStatus::Failed);
                }
                deployment.transition(PatchStatus::RolledBack);
            }
            throw;
        }
    }

    std::vector<const Patch*> emergencyPatches() const {
        std::vector<const Patch*> result;

        for (const auto& [id, patch] : patches_) {
            if (patch.severity == Severity::High ||
                patch.severity == Severity::Critical) {
                result.push_back(&patch);
            }
        }

        std::sort(
            result.begin(),
            result.end(),
            [](const Patch* a, const Patch* b) {
                auto rank = [](Severity s) {
                    return s == Severity::Critical ? 0 :
                           s == Severity::High ? 1 : 2;
                };
                return rank(a->severity) < rank(b->severity);
            }
        );

        return result;
    }

    void printDeployment(const Deployment& deployment) const {
        std::cout << "Patch " << deployment.patch.id
                  << " -> " << deployment.serverId
                  << " : " << to_string(deployment.status) << '\n';

        for (const auto& check : deployment.checks) {
            std::cout << "  [" << (check.passed ? "PASS" : "FAIL") << "] "
                      << check.name << " - " << check.details << '\n';
        }
    }
};

std::string digestPlaceholderForDemo(const std::string& value) {
    // The example uses a deterministic hexadecimal representation so the
    // governance engine can demonstrate checksum equality without crypto
    // dependencies. A production updater should verify a real SHA-256 digest.
    std::ostringstream out;
    std::hash<std::string> hasher;
    const std::size_t h = hasher(value);

    for (int i = 0; i < 64; ++i) {
        const unsigned shift = static_cast<unsigned>((i % sizeof(std::size_t)) * 8);
        const unsigned nibble =
            static_cast<unsigned>((h >> shift) & 0x0F);
        out << std::hex << nibble;
    }
    return out.str();
}

int main() {
    try {
        GovernanceEngine engine;

        const std::string checksum =
            digestPlaceholderForDemo("openssl-3.0.17-security");

        Patch emergencyPatch{
            "P-3001",
            "OpenSSL critical security update",
            "openssl",
            "3.0.12",
            "3.0.17",
            Severity::Critical,
            checksum,
            false
        };

        Patch kernelPatch{
            "P-3002",
            "Linux kernel security update",
            "linux-kernel",
            "6.1.70",
            "6.1.112",
            Severity::High,
            digestPlaceholderForDemo("kernel-6.1.112-security"),
            true
        };

        engine.registerPatch(emergencyPatch);
        engine.registerPatch(kernelPatch);

        engine.registerServer({
            "srv-301",
            "payments-prod-01",
            Environment::Production,
            {
                {"openssl", "3.0.12"},
                {"linux-kernel", "6.1.70"}
            }
        });

        engine.registerServer({
            "srv-302",
            "payments-stage-01",
            Environment::Staging,
            {
                {"openssl", "3.0.12"},
                {"linux-kernel", "6.1.70"}
            }
        });

        Deployment& deployment =
            engine.schedule("P-3001", "srv-301", Environment::Production);

        engine.deploy(deployment, checksum);
        engine.printDeployment(deployment);

        std::cout << "\nEmergency patches:\n";
        for (const Patch* patch : engine.emergencyPatches()) {
            std::cout << "  " << patch->id
                      << " " << patch->title
                      << " [" << to_string(patch->severity) << "]\n";
        }

        try {
            Deployment& bad =
                engine.schedule("P-3002", "srv-302", Environment::Production);
            engine.deploy(bad, "invalid-checksum");
        } catch (const PatchException& ex) {
            std::cout << "\nExpected policy failure: "
                      << ex.what() << '\n';
        }

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << '\n';
        return 1;
    }
}
