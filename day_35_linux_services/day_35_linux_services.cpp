#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Linux Services case study:
 *
 * A repository-hosting company operates several Linux daemons:
 *   - a network availability target
 *   - a metrics collector
 *   - an API daemon
 *
 * This program implements a governance-oriented service manager that evaluates
 * dependency ordering, startup enablement, restart policies, health checks,
 * configuration validation, and service state transitions.
 *
 * It does not invoke systemctl and therefore cannot change the host system.
 */

enum class ServiceState {
    Inactive,
    Activating,
    Active,
    Deactivating,
    Failed
};

enum class StartupPolicy {
    Disabled,
    Enabled,
    Static
};

enum class RestartPolicy {
    No,
    OnFailure,
    Always
};

std::string toString(ServiceState state) {
    switch (state) {
        case ServiceState::Inactive: return "inactive";
        case ServiceState::Activating: return "activating";
        case ServiceState::Active: return "active";
        case ServiceState::Deactivating: return "deactivating";
        case ServiceState::Failed: return "failed";
    }
    return "unknown";
}

std::string toString(StartupPolicy policy) {
    switch (policy) {
        case StartupPolicy::Disabled: return "disabled";
        case StartupPolicy::Enabled: return "enabled";
        case StartupPolicy::Static: return "static";
    }
    return "unknown";
}

std::string toString(RestartPolicy policy) {
    switch (policy) {
        case RestartPolicy::No: return "no";
        case RestartPolicy::OnFailure: return "on-failure";
        case RestartPolicy::Always: return "always";
    }
    return "unknown";
}

struct ServiceConfig {
    std::string name;
    std::string description;
    std::vector<std::string> execStart;
    std::string user;
    std::string workingDirectory;
    std::map<std::string, std::string> environment;
    std::vector<std::string> after;
    RestartPolicy restartPolicy{RestartPolicy::No};
    int restartSeconds{1};
    std::string wantedBy{"multi-user.target"};

    void validate() const {
        if (name.size() < 9 ||
            name.substr(name.size() - 8) != ".service") {
            throw std::invalid_argument(
                "service unit must have a .service suffix: " + name
            );
        }

        if (execStart.empty()) {
            throw std::invalid_argument(
                "ExecStart cannot be empty: " + name
            );
        }

        if (restartSeconds < 0) {
            throw std::invalid_argument(
                "restart delay cannot be negative: " + name
            );
        }

        if (wantedBy.empty()) {
            throw std::invalid_argument(
                "startup target cannot be empty: " + name
            );
        }
    }
};

class Service {
private:
    ServiceConfig config_;
    ServiceState state_{ServiceState::Inactive};
    StartupPolicy startup_{StartupPolicy::Disabled};
    std::size_t restartCount_{0};
    std::optional<std::string> failure_;
    std::vector<std::string> journal_;

    void record(const std::string& message) {
        using Clock = std::chrono::system_clock;
        const auto now = Clock::to_time_t(Clock::now());

        std::ostringstream timestamp;
        timestamp << std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S");

        journal_.push_back(
            timestamp.str() + " " + config_.name + ": " + message
        );
    }

public:
    explicit Service(ServiceConfig config)
        : config_(std::move(config)) {
        config_.validate();
    }

    const std::string& name() const {
        return config_.name;
    }

    ServiceState state() const {
        return state_;
    }

    StartupPolicy startupPolicy() const {
        return startup_;
    }

    const std::vector<std::string>& journal() const {
        return journal_;
    }

    void enable() {
        startup_ = StartupPolicy::Enabled;
        record("enabled for " + config_.wantedBy);
    }

    void disable() {
        startup_ = StartupPolicy::Disabled;
        record("disabled from startup");
    }

    void setStatic() {
        startup_ = StartupPolicy::Static;
        record("marked static; startup is dependency-driven");
    }

    bool start(class ServiceManager& manager);

    void stop() {
        if (state_ == ServiceState::Inactive) {
            record("stop request ignored because service is inactive");
            return;
        }

        state_ = ServiceState::Deactivating;
        record("entered deactivating state");

        state_ = ServiceState::Inactive;
        record("entered inactive state");
    }

    bool restart(ServiceManager& manager);

    void fail(const std::string& reason) {
        failure_ = reason;
        state_ = ServiceState::Failed;
        record("failed: " + reason);
    }

    std::string status() const {
        std::ostringstream out;
        out << config_.name << "\n"
            << "  Description: " << config_.description << "\n"
            << "  State: " << toString(state_) << "\n"
            << "  Startup: " << toString(startup_) << "\n"
            << "  Restart policy: " << toString(config_.restartPolicy) << "\n"
            << "  Restart count: " << restartCount_;

        if (failure_) {
            out << "\n  Failure: " << *failure_;
        }

        return out.str();
    }

    std::string unitFile() const {
        std::ostringstream out;

        out << "[Unit]\n"
            << "Description=" << config_.description << "\n";

        if (!config_.after.empty()) {
            out << "After=";
            for (std::size_t i = 0; i < config_.after.size(); ++i) {
                if (i > 0) out << ' ';
                out << config_.after[i];
            }
            out << "\n";
        }

        out << "\n[Service]\n"
            << "Type=simple\n"
            << "ExecStart=";

        for (std::size_t i = 0; i < config_.execStart.size(); ++i) {
            if (i > 0) out << ' ';
            out << config_.execStart[i];
        }

        out << "\nRestart=" << toString(config_.restartPolicy)
            << "\nRestartSec=" << config_.restartSeconds << "\n";

        if (!config_.user.empty()) {
            out << "User=" << config_.user << "\n";
        }

        if (!config_.workingDirectory.empty()) {
            out << "WorkingDirectory=" << config_.workingDirectory << "\n";
        }

        for (const auto& [key, value] : config_.environment) {
            out << "Environment=" << key << "=" << value << "\n";
        }

        out << "\n[Install]\n"
            << "WantedBy=" << config_.wantedBy << "\n";

        return out.str();
    }
};

class ServiceManager {
private:
    std::map<std::string, Service> services_;

public:
    void add(Service service) {
        const std::string name = service.name();

        if (services_.contains(name)) {
            throw std::invalid_argument("duplicate service: " + name);
        }

        services_.emplace(name, std::move(service));
    }

    Service& get(const std::string& name) {
        auto it = services_.find(name);

        if (it == services_.end()) {
            throw std::out_of_range("unknown service: " + name);
        }

        return it->second;
    }

    bool start(const std::string& name) {
        return get(name).start(*this);
    }

    bool restart(const std::string& name) {
        return get(name).restart(*this);
    }

    void boot() {
        /*
         * Startup enablement is separate from dependency ordering. Enabled
         * services are boot candidates, while dependencies can also be started
         * even when they are static and not independently enabled.
         */
        for (auto& [name, service] : services_) {
            if (service.startupPolicy() == StartupPolicy::Enabled) {
                service.start(*this);
            }
        }
    }

    void printStates() const {
        for (const auto& [name, service] : services_) {
            std::cout
                << std::left << std::setw(32) << name
                << std::setw(12) << toString(service.state())
                << toString(service.startupPolicy())
                << '\n';
        }
    }
};

bool Service::start(ServiceManager& manager) {
    if (state_ == ServiceState::Active) {
        record("start request ignored; already active");
        return true;
    }

    try {
        config_.validate();
    } catch (const std::exception& error) {
        fail(error.what());
        return false;
    }

    /*
     * Dependencies are represented as names of units. A missing dependency is
     * a configuration failure, not an application-level warning.
     */
    for (const auto& dependency : config_.after) {
        try {
            Service& required = manager.get(dependency);

            if (required.state() != ServiceState::Active) {
                if (!required.start(manager)) {
                    fail("dependency failed: " + dependency);
                    return false;
                }
            }
        } catch (const std::exception& error) {
            fail(error.what());
            return false;
        }
    }

    state_ = ServiceState::Activating;
    record("entered activating state");

    /*
     * A real systemd manager would now create or supervise the configured
     * process. The special executable name below gives the case study a
     * deterministic failure path without executing arbitrary programs.
     */
    if (config_.execStart.front() == "FAIL") {
        fail("simulated ExecStart failure");
        return false;
    }

    state_ = ServiceState::Active;
    failure_.reset();
    record("entered active state");
    return true;
}

bool Service::restart(ServiceManager& manager) {
    record("restart requested");
    stop();
    ++restartCount_;
    return start(manager);
}

class HealthEvaluator {
public:
    static bool healthy(const Service& service) {
        return service.state() == ServiceState::Active;
    }
};

void demonstrateFailurePolicy(ServiceManager& manager) {
    ServiceConfig failingConfig{
        "billing-worker.service",
        "Billing background worker",
        {"FAIL", "--config", "/etc/billing/worker.conf"},
        "billing",
        "/opt/billing",
        {{"APP_ENV", "production"}},
        {},
        RestartPolicy::OnFailure,
        5,
        "multi-user.target"
    };

    manager.add(Service(std::move(failingConfig)));
    Service& failing = manager.get("billing-worker.service");
    failing.enable();

    std::cout << "\nFailure scenario\n";
    manager.start(failing.name());
    std::cout << failing.status() << "\n";

    /*
     * Restart=on-failure is policy metadata. It does not mean every failure
     * should be hidden. The failure state remains observable to operators.
     */
    std::cout << "Health: "
              << (HealthEvaluator::healthy(failing) ? "healthy" : "unhealthy")
              << "\n";
}

int main() {
    try {
        std::cout << "Linux Services case study\n";

        ServiceManager manager;

        ServiceConfig networkTarget{
            "network-online.target.service",
            "Network availability target",
            {"/bin/true"},
            "",
            "",
            {},
            {},
            RestartPolicy::No,
            0,
            ""
        };

        Service network(std::move(networkTarget));
        network.setStatic();
        manager.add(std::move(network));

        ServiceConfig metricsConfig{
            "metrics-agent.service",
            "Host metrics collection daemon",
            {"/opt/metrics/bin/agent", "--config", "/etc/metrics/agent.conf"},
            "metrics",
            "/opt/metrics",
            {
                {"APP_ENV", "production"},
                {"SCRAPE_INTERVAL", "15"}
            },
            {"network-online.target.service"},
            RestartPolicy::Always,
            3,
            "multi-user.target"
        };

        ServiceConfig apiConfig{
            "orders-api.service",
            "Orders API daemon",
            {"/opt/orders/bin/server", "--port", "8080"},
            "orders",
            "/opt/orders",
            {
                {"APP_ENV", "production"},
                {"LOG_LEVEL", "info"}
            },
            {
                "network-online.target.service",
                "metrics-agent.service"
            },
            RestartPolicy::OnFailure,
            5,
            "multi-user.target"
        };

        manager.add(Service(std::move(metricsConfig)));
        manager.add(Service(std::move(apiConfig)));

        manager.get("metrics-agent.service").enable();
        manager.get("orders-api.service").enable();

        std::cout << "\nGenerated unit for orders-api.service\n";
        std::cout << manager.get("orders-api.service").unitFile();

        std::cout << "\nStartup state before boot\n";
        manager.printStates();

        std::cout << "\nBoot sequence\n";
        manager.boot();

        std::cout << "\nState after boot\n";
        manager.printStates();

        std::cout << "\nAPI health: "
                  << (HealthEvaluator::healthy(
                          manager.get("orders-api.service"))
                          ? "healthy"
                          : "unhealthy")
                  << "\n";

        std::cout << "\nRestarting API daemon\n";
        manager.restart("orders-api.service");
        std::cout << manager.get("orders-api.service").status() << "\n";

        demonstrateFailurePolicy(manager);

        std::cout << "\nService journal for orders-api.service\n";
        for (const auto& line :
             manager.get("orders-api.service").journal()) {
            std::cout << line << '\n';
        }

        std::cout << "\nDesign distinctions\n";
        std::cout << "systemd: manager responsible for unit lifecycle and boot targets.\n";
        std::cout << "daemon: long-running process represented by Service.\n";
        std::cout << "service configuration: declarative execution and restart policy.\n";
        std::cout << "startup service: enabled association with a boot target.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal configuration error: "
                  << error.what() << '\n';
        return 1;
    }
}
