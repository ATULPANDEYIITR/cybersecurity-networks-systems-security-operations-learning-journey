#include <algorithm>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/*
 * Case study: governance engine for a managed engineering workstation fleet.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -Wextra -pedantic group_policy_governance.cpp -o governance
 *
 * The program evaluates linked policy objects and reports workstation
 * configuration, password-policy findings, and policy provenance.
 * It is intentionally a simplified model rather than a Windows implementation.
 */

enum class Category {
    Security,
    Password,
    Workstation
};

enum class ScopeType {
    Site,
    Domain,
    OrganizationalUnit
};

enum class LinkMode {
    Normal,
    Enforced
};

std::string toString(Category category) {
    switch (category) {
        case Category::Security: return "security";
        case Category::Password: return "password";
        case Category::Workstation: return "workstation";
    }
    throw std::logic_error("Unknown policy category.");
}

std::string toString(ScopeType scope) {
    switch (scope) {
        case ScopeType::Site: return "site";
        case ScopeType::Domain: return "domain";
        case ScopeType::OrganizationalUnit: return "ou";
    }
    throw std::logic_error("Unknown scope.");
}

struct Setting {
    std::string name;
    std::string value;
    Category category;
};

struct PolicyLink {
    std::string gpoName;
    ScopeType scopeType;
    std::string scopeName;
    int linkOrder;
    LinkMode mode = LinkMode::Normal;
    bool enabled = true;
};

struct Workstation {
    std::string hostname;
    std::string site;
    std::string domain;
    std::vector<std::string> organizationalUnits;
};

struct Evaluation {
    std::map<std::string, std::string> settings;
    std::map<std::string, std::string> sources;
    std::vector<std::string> appliedGpos;
    std::vector<std::string> findings;
};

class GroupPolicyObject {
public:
    GroupPolicyObject(std::string name, std::string description)
        : name_(std::move(name)), description_(std::move(description)) {
        if (name_.empty()) {
            throw std::invalid_argument("GPO name cannot be empty.");
        }
    }

    const std::string& name() const {
        return name_;
    }

    bool enabled() const {
        return enabled_;
    }

    void setEnabled(bool enabled) {
        enabled_ = enabled;
    }

    void addBoolean(
        const std::string& name,
        bool value,
        Category category
    ) {
        add(name, value ? "true" : "false", category);
    }

    void addInteger(
        const std::string& name,
        int value,
        Category category
    ) {
        const std::map<std::string, std::pair<int, int>> limits = {
            {"minimumPasswordLength", {8, 128}},
            {"passwordHistoryCount", {0, 50}},
            {"maximumPasswordAgeDays", {0, 365}},
            {"minimumPasswordAgeDays", {0, 365}},
            {"lockoutThreshold", {0, 999}},
            {"screenLockTimeoutMinutes", {1, 1440}}
        };

        auto limit = limits.find(name);
        if (limit != limits.end()) {
            if (value < limit->second.first ||
                value > limit->second.second) {
                throw std::invalid_argument(
                    "Value outside allowed range for " + name
                );
            }
        }

        if (name == "minimumPasswordLength" ||
            name == "passwordHistoryCount" ||
            name == "maximumPasswordAgeDays" ||
            name == "minimumPasswordAgeDays") {
            if (category != Category::Password) {
                throw std::invalid_argument(
                    "Password setting has the wrong category."
                );
            }
        }

        add(name, std::to_string(value), category);
    }

    void add(
        const std::string& name,
        const std::string& value,
        Category category
    ) {
        if (name.empty()) {
            throw std::invalid_argument("Setting name cannot be empty.");
        }
        settings_[name] = Setting{name, value, category};
    }

    const std::map<std::string, Setting>& settings() const {
        return settings_;
    }

private:
    std::string name_;
    std::string description_;
    bool enabled_ = true;
    std::map<std::string, Setting> settings_;
};

class GovernanceEngine {
public:
    void addGpo(const GroupPolicyObject& gpo) {
        if (gpos_.count(gpo.name()) != 0) {
            throw std::invalid_argument("Duplicate GPO: " + gpo.name());
        }
        gpos_.emplace(gpo.name(), gpo);
    }

    void addLink(const PolicyLink& link) {
        if (gpos_.count(link.gpoName) == 0) {
            throw std::invalid_argument("Link refers to an unknown GPO.");
        }
        if (link.linkOrder < 1) {
            throw std::invalid_argument("Link order must be positive.");
        }
        links_.push_back(link);
    }

    Evaluation evaluate(const Workstation& machine) const {
        std::vector<PolicyLink> matching;

        for (const auto& link : links_) {
            if (!link.enabled) continue;

            const auto gpo = gpos_.find(link.gpoName);
            if (gpo == gpos_.end() || !gpo->second.enabled()) continue;

            bool scopeMatches = false;
            if (link.scopeType == ScopeType::Site) {
                scopeMatches = link.scopeName == machine.site;
            } else if (link.scopeType == ScopeType::Domain) {
                scopeMatches = link.scopeName == machine.domain;
            } else {
                scopeMatches = std::find(
                    machine.organizationalUnits.begin(),
                    machine.organizationalUnits.end(),
                    link.scopeName
                ) != machine.organizationalUnits.end();
            }

            if (scopeMatches) matching.push_back(link);
        }

        auto depth = [](ScopeType scope) {
            switch (scope) {
                case ScopeType::Site: return 0;
                case ScopeType::Domain: return 1;
                case ScopeType::OrganizationalUnit: return 2;
            }
            return 3;
        };

        std::sort(
            matching.begin(),
            matching.end(),
            [&](const PolicyLink& left, const PolicyLink& right) {
                if (depth(left.scopeType) != depth(right.scopeType)) {
                    return depth(left.scopeType) < depth(right.scopeType);
                }
                if (left.linkOrder != right.linkOrder) {
                    return left.linkOrder < right.linkOrder;
                }
                return left.gpoName < right.gpoName;
            }
        );

        Evaluation result;
        std::set<std::string> enforcedSettings;

        for (const auto& link : matching) {
            const auto& gpo = gpos_.at(link.gpoName);
            result.appliedGpos.push_back(gpo.name());

            for (const auto& entry : gpo.settings()) {
                const auto& settingName = entry.first;
                const auto& setting = entry.second;

                if (link.mode == LinkMode::Enforced) {
                    enforcedSettings.insert(settingName);
                    result.settings[settingName] = setting.value;
                    result.sources[settingName] = gpo.name();
                } else if (enforcedSettings.count(settingName) == 0) {
                    // Later normal links win unless an enforced ancestor
                    // has already established the effective setting.
                    result.settings[settingName] = setting.value;
                    result.sources[settingName] = gpo.name();
                }
            }
        }

        const auto screenLock = result.settings.find("screenLockEnabled");
        if (screenLock != result.settings.end() &&
            screenLock->second == "false") {
            result.findings.push_back(
                "Automatic screen locking is disabled."
            );
        }

        const auto firewall = result.settings.find("firewallEnabled");
        if (firewall != result.settings.end() &&
            firewall->second == "false") {
            result.findings.push_back("Workstation firewall is disabled.");
        }

        const int minimumAge = integerValue(
            result.settings, "minimumPasswordAgeDays", 0
        );
        const int maximumAge = integerValue(
            result.settings, "maximumPasswordAgeDays", 0
        );

        // A maximum age of zero is treated here as no forced expiry.
        if (maximumAge != 0 && minimumAge > maximumAge) {
            result.findings.push_back(
                "Minimum password age exceeds maximum password age."
            );
        }

        return result;
    }

private:
    static int integerValue(
        const std::map<std::string, std::string>& settings,
        const std::string& key,
        int fallback
    ) {
        const auto found = settings.find(key);
        if (found == settings.end()) return fallback;
        return std::stoi(found->second);
    }

    std::map<std::string, GroupPolicyObject> gpos_;
    std::vector<PolicyLink> links_;
};

void printEvaluation(const Workstation& machine, const Evaluation& result) {
    std::cout << "\nEffective policy for " << machine.hostname << "\n";

    for (const auto& [name, value] : result.settings) {
        std::cout << "  " << name << " = " << value
                  << " [source: " << result.sources.at(name) << "]\n";
    }

    std::cout << "\nApplied GPOs\n";
    for (const auto& gpo : result.appliedGpos) {
        std::cout << "  " << gpo << '\n';
    }

    std::cout << "\nAudit findings\n";
    if (result.findings.empty()) {
        std::cout << "  No configuration findings detected.\n";
    } else {
        for (const auto& finding : result.findings) {
            std::cout << "  " << finding << '\n';
        }
    }
}

int main() {
    try {
        GovernanceEngine engine;

        GroupPolicyObject domainBaseline(
            "Domain-Security-Baseline",
            "Central security and password configuration."
        );
        domainBaseline.addBoolean(
            "firewallEnabled", true, Category::Workstation
        );
        domainBaseline.addBoolean(
            "interactiveLogonBannerEnabled", true, Category::Security
        );
        domainBaseline.addInteger(
            "minimumPasswordLength", 14, Category::Password
        );
        domainBaseline.addInteger(
            "passwordHistoryCount", 24, Category::Password
        );
        domainBaseline.addInteger(
            "maximumPasswordAgeDays", 0, Category::Password
        );
        domainBaseline.addInteger(
            "minimumPasswordAgeDays", 1, Category::Password
        );
        domainBaseline.addInteger(
            "lockoutThreshold", 10, Category::Security
        );

        GroupPolicyObject engineering(
            "Engineering-Workstations",
            "Endpoint controls for development devices."
        );
        engineering.addBoolean(
            "usbStorageBlocked", true, Category::Workstation
        );
        engineering.addBoolean(
            "screenLockEnabled", true, Category::Workstation
        );
        engineering.addInteger(
            "screenLockTimeoutMinutes", 10, Category::Workstation
        );
        engineering.addBoolean(
            "localAdminInstallationBlocked", true, Category::Workstation
        );

        GroupPolicyObject legacy(
            "Legacy-Firewall-Exception",
            "Weak exception used to test enforced precedence."
        );
        legacy.addBoolean(
            "firewallEnabled", false, Category::Workstation
        );

        engine.addGpo(domainBaseline);
        engine.addGpo(engineering);
        engine.addGpo(legacy);

        engine.addLink({
            "Domain-Security-Baseline",
            ScopeType::Domain,
            "corp.example",
            1,
            LinkMode::Enforced,
            true
        });
        engine.addLink({
            "Engineering-Workstations",
            ScopeType::OrganizationalUnit,
            "Engineering",
            1,
            LinkMode::Normal,
            true
        });
        engine.addLink({
            "Legacy-Firewall-Exception",
            ScopeType::OrganizationalUnit,
            "Engineering",
            2,
            LinkMode::Normal,
            true
        });

        Workstation workstation{
            "ENG-WS-042",
            "North-Office",
            "corp.example",
            {"Engineering"}
        };

        const Evaluation result = engine.evaluate(workstation);
        printEvaluation(workstation, result);

        if (result.settings.at("firewallEnabled") != "true") {
            throw std::runtime_error(
                "Security invariant violated: firewall is not enabled."
            );
        }

        if (result.settings.at("minimumPasswordLength") != "14") {
            throw std::runtime_error(
                "Security invariant violated: password baseline missing."
            );
        }

        std::cout << "\nGovernance assertions passed.\n";

        try {
            GroupPolicyObject invalid(
                "Invalid-Policy",
                "Intentionally rejected definition."
            );
            invalid.addInteger(
                "minimumPasswordLength", 4, Category::Password
            );
        } catch (const std::invalid_argument& error) {
            std::cout << "Rejected invalid policy: "
                      << error.what() << '\n';
        }

    } catch (const std::exception& error) {
        std::cerr << "Governance evaluation failed: "
                  << error.what() << '\n';
        return 1;
    }

    return 0;
}
