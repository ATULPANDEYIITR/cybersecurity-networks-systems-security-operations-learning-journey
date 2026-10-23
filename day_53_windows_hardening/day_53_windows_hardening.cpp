/*
 * Windows Repository-Independent Hardening Engine
 *
 * A C++17 case study for endpoint security policy evaluation.
 *
 * The program uses strong domain types, unordered lookup, immutable baseline
 * expectations, and explicit findings. It never modifies the local Windows
 * configuration. Remediation commands are emitted as review artifacts.
 */

#include <algorithm>
#include <array>
#include <exception>
#include <iomanip>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

enum class Enforcement {
    Audit,
    Block,
    Allow,
    Disabled
};

enum class Severity {
    Critical,
    High,
    Medium,
    Low
};

std::string to_string(Enforcement state) {
    switch (state) {
        case Enforcement::Audit: return "Audit";
        case Enforcement::Block: return "Block";
        case Enforcement::Allow: return "Allow";
        case Enforcement::Disabled: return "Disabled";
    }
    return "Unknown";
}

std::string to_string(Severity severity) {
    switch (severity) {
        case Severity::Critical: return "Critical";
        case Severity::High: return "High";
        case Severity::Medium: return "Medium";
        case Severity::Low: return "Low";
    }
    return "Unknown";
}

struct DefenderConfig {
    bool realtimeMonitoring{};
    bool behaviorMonitoring{};
    bool ioavProtection{};
    bool cloudProtection{};
    bool tamperProtection{};
    int signatureAgeHours{};
};

struct FirewallProfile {
    std::string name;
    bool enabled{};
    std::string defaultInbound;
    std::string defaultOutbound;
};

struct SecurityPolicy {
    int passwordMinimumLength{};
    int lockoutThreshold{};
    int lockoutDurationMinutes{};
    bool auditLogonEvents{};
    bool auditProcessCreation{};
    bool powershellScriptBlockLogging{};
    bool powershellTranscription{};
};

struct ApplicationControl {
    Enforcement mode{Enforcement::Disabled};
    bool publisherRules{};
    bool pathRules{};
    bool unsignedBinaryBlocking{};
};

struct ASRRule {
    std::string id;
    std::string name;
    Enforcement requiredState;
    Severity severity;
};

struct Endpoint {
    std::string hostname;
    DefenderConfig defender;
    std::array<FirewallProfile, 3> firewall;
    SecurityPolicy security;
    ApplicationControl applicationControl;
    std::unordered_map<std::string, Enforcement> asrRules;
};

struct Finding {
    std::string control;
    Severity severity;
    std::string message;
    std::string remediation;
};

class HardeningEngine {
public:
    explicit HardeningEngine(
        DefenderConfig baselineDefender,
        std::array<FirewallProfile, 3> baselineFirewall,
        SecurityPolicy baselineSecurity,
        ApplicationControl baselineApplication,
        std::vector<ASRRule> baselineASR)
        : defender_(baselineDefender),
          firewall_(std::move(baselineFirewall)),
          security_(baselineSecurity),
          application_(baselineApplication),
          asr_(std::move(baselineASR)) {
        validateBaseline();
    }

    std::vector<Finding> evaluate(const Endpoint& endpoint) const {
        validateEndpoint(endpoint);

        std::vector<Finding> findings;
        evaluateDefender(endpoint, findings);
        evaluateFirewall(endpoint, findings);
        evaluateSecurity(endpoint, findings);
        evaluateApplicationControl(endpoint, findings);
        evaluateASR(endpoint, findings);

        return findings;
    }

private:
    DefenderConfig defender_;
    std::array<FirewallProfile, 3> firewall_;
    SecurityPolicy security_;
    ApplicationControl application_;
    std::vector<ASRRule> asr_;

    static void require(bool condition, const std::string& message) {
        if (!condition) {
            throw std::invalid_argument(message);
        }
    }

    void validateBaseline() const {
        require(defender_.signatureAgeHours >= 0,
                "Defender signature age cannot be negative");

        for (const auto& profile : firewall_) {
            require(profile.enabled, "All baseline firewall profiles must be enabled");
            require(profile.defaultInbound == "Block",
                    "Baseline inbound firewall policy must be Block");
        }

        require(security_.passwordMinimumLength >= 1,
                "Password minimum length is invalid");
        require(security_.lockoutThreshold >= 1,
                "Lockout threshold is invalid");
        require(application_.mode == Enforcement::Block,
                "Application-control baseline must use Block mode");
    }

    static void validateEndpoint(const Endpoint& endpoint) {
        static const std::regex hostnamePattern(
            R"([A-Za-z0-9][A-Za-z0-9._-]{0,62})"
        );

        require(std::regex_match(endpoint.hostname, hostnamePattern),
                "Invalid Windows hostname");
    }

    static void add(
        std::vector<Finding>& findings,
        const std::string& control,
        Severity severity,
        const std::string& message,
        const std::string& remediation) {

        findings.push_back({control, severity, message, remediation});
    }

    void evaluateDefender(
        const Endpoint& endpoint,
        std::vector<Finding>& findings) const {

        const auto& actual = endpoint.defender;

        const std::array<std::tuple<bool, bool, const char*, Severity>, 5> checks{{
            {actual.realtimeMonitoring, defender_.realtimeMonitoring,
             "Real-time monitoring", Severity::Critical},
            {actual.behaviorMonitoring, defender_.behaviorMonitoring,
             "Behavior monitoring", Severity::High},
            {actual.ioavProtection, defender_.ioavProtection,
             "IOAV protection", Severity::High},
            {actual.cloudProtection, defender_.cloudProtection,
             "Cloud protection", Severity::High},
            {actual.tamperProtection, defender_.tamperProtection,
             "Tamper protection", Severity::Critical}
        }};

        for (const auto& [observed, expected, name, severity] : checks) {
            if (expected && !observed) {
                add(
                    findings,
                    "Microsoft Defender",
                    severity,
                    std::string(name) + " is disabled",
                    std::string("Enable ") + name
                );
            }
        }

        if (actual.signatureAgeHours > defender_.signatureAgeHours) {
            add(
                findings,
                "Microsoft Defender",
                Severity::High,
                "Security intelligence is older than the baseline",
                "Update Microsoft Defender security intelligence"
            );
        }
    }

    void evaluateFirewall(
        const Endpoint& endpoint,
        std::vector<Finding>& findings) const {

        for (std::size_t i = 0; i < firewall_.size(); ++i) {
            const auto& expected = firewall_[i];
            const auto& actual = endpoint.firewall[i];

            if (expected.name != actual.name) {
                add(
                    findings,
                    "Windows Firewall",
                    Severity::Critical,
                    "Firewall profile ordering or identity is inconsistent",
                    "Collect Domain, Private, and Public profiles by name"
                );
                continue;
            }

            if (expected.enabled && !actual.enabled) {
                add(
                    findings,
                    "Windows Firewall",
                    actual.name == "Public" ? Severity::Critical : Severity::High,
                    actual.name + " firewall profile is disabled",
                    "Enable the " + actual.name + " firewall profile"
                );
            }

            if (actual.defaultInbound != expected.defaultInbound) {
                add(
                    findings,
                    "Windows Firewall",
                    Severity::High,
                    actual.name + " inbound default policy is " +
                        actual.defaultInbound,
                    "Set " + actual.name + " inbound default action to Block"
                );
            }
        }
    }

    void evaluateSecurity(
        const Endpoint& endpoint,
        std::vector<Finding>& findings) const {

        const auto& actual = endpoint.security;

        if (actual.passwordMinimumLength < security_.passwordMinimumLength) {
            add(
                findings,
                "Security Policy",
                Severity::Medium,
                "Password minimum length is below baseline",
                "Increase minimum password length"
            );
        }

        if (actual.lockoutThreshold == 0 ||
            actual.lockoutThreshold > security_.lockoutThreshold) {
            add(
                findings,
                "Security Policy",
                Severity::Medium,
                "Account lockout threshold is weaker than baseline",
                "Reduce the account lockout threshold"
            );
        }

        const std::array<std::tuple<bool, bool, const char*>, 4> auditChecks{{
            {actual.auditLogonEvents, security_.auditLogonEvents, "Logon auditing"},
            {actual.auditProcessCreation, security_.auditProcessCreation,
             "Process creation auditing"},
            {actual.powershellScriptBlockLogging,
             security_.powershellScriptBlockLogging,
             "PowerShell script block logging"},
            {actual.powershellTranscription,
             security_.powershellTranscription,
             "PowerShell transcription"}
        }};

        for (const auto& [observed, expected, name] : auditChecks) {
            if (expected && !observed) {
                add(
                    findings,
                    "Security Policy",
                    Severity::High,
                    std::string(name) + " is disabled",
                    std::string("Enable ") + name
                );
            }
        }
    }

    void evaluateApplicationControl(
        const Endpoint& endpoint,
        std::vector<Finding>& findings) const {

        const auto& actual = endpoint.applicationControl;

        if (actual.mode != application_.mode) {
            add(
                findings,
                "Application Control",
                Severity::High,
                "Application-control mode is " + to_string(actual.mode),
                "Move application control to Block mode"
            );
        }

        if (application_.publisherRules && !actual.publisherRules) {
            add(
                findings,
                "Application Control",
                Severity::High,
                "Publisher rules are disabled",
                "Enable publisher rules"
            );
        }

        if (application_.pathRules && !actual.pathRules) {
            add(
                findings,
                "Application Control",
                Severity::High,
                "Path rules are disabled",
                "Enable controlled path rules"
            );
        }

        if (application_.unsignedBinaryBlocking &&
            !actual.unsignedBinaryBlocking) {
            add(
                findings,
                "Application Control",
                Severity::High,
                "Unsigned binary blocking is disabled",
                "Block unsigned executable content"
            );
        }
    }

    void evaluateASR(
        const Endpoint& endpoint,
        std::vector<Finding>& findings) const {

        for (const auto& rule : asr_) {
            const auto iterator = endpoint.asrRules.find(rule.id);
            const Enforcement actual =
                iterator == endpoint.asrRules.end()
                    ? Enforcement::Disabled
                    : iterator->second;

            if (actual != rule.requiredState) {
                add(
                    findings,
                    "Attack Surface Reduction",
                    rule.severity,
                    rule.name + " is " + to_string(actual) +
                        "; baseline requires " + to_string(rule.requiredState),
                    "Set ASR rule " + rule.id + " to " +
                        to_string(rule.requiredState)
                );
            }
        }
    }
};

std::vector<ASRRule> makeASRRules() {
    return {
        {
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
            "Block executable content from email client and webmail",
            Enforcement::Block,
            Severity::High
        },
        {
            "3b576869-a4ec-4529-8536-b80a7769e899",
            "Block Office applications from creating executable content",
            Enforcement::Block,
            Severity::High
        },
        {
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
            "Block Office applications from injecting code into other processes",
            Enforcement::Block,
            Severity::High
        },
        {
            "26190899-1602-49e8-8b27-eb1d0a1ce869",
            "Block Office communication applications from creating child processes",
            Enforcement::Audit,
            Severity::Medium
        }
    };
}

HardeningEngine makeEngine() {
    DefenderConfig defender{
        true, true, true, true, true, 24
    };

    std::array<FirewallProfile, 3> firewall{{
        {"Domain", true, "Block", "Allow"},
        {"Private", true, "Block", "Allow"},
        {"Public", true, "Block", "Allow"}
    }};

    SecurityPolicy security{
        14, 5, 15,
        true, true, true, true
    };

    ApplicationControl application{
        Enforcement::Block, true, true, true
    };

    return HardeningEngine(
        defender,
        firewall,
        security,
        application,
        makeASRRules()
    );
}

Endpoint makeEndpoint() {
    Endpoint endpoint;
    endpoint.hostname = "WIN-RND-208";

    endpoint.defender = {
        true, false, true, true, false, 38
    };

    endpoint.firewall = {{
        {"Domain", true, "Block", "Allow"},
        {"Private", true, "Block", "Allow"},
        {"Public", false, "Allow", "Allow"}
    }};

    endpoint.security = {
        10, 10, 15,
        true, false, true, false
    };

    endpoint.applicationControl = {
        Enforcement::Audit, true, false, false
    };

    const auto rules = makeASRRules();

    endpoint.asrRules[rules[0].id] = Enforcement::Block;
    endpoint.asrRules[rules[1].id] = Enforcement::Audit;
    endpoint.asrRules[rules[2].id] = Enforcement::Block;
    endpoint.asrRules[rules[3].id] = Enforcement::Disabled;

    return endpoint;
}

void printFindings(const std::vector<Finding>& findings) {
    std::cout << "Hardening findings: " << findings.size() << "\n\n";

    for (const auto& finding : findings) {
        std::cout << '[' << to_string(finding.severity) << "] "
                  << finding.control << '\n'
                  << "  " << finding.message << '\n'
                  << "  Remediation: " << finding.remediation << "\n\n";
    }
}

void printDiagnostics(const std::vector<Finding>& findings) {
    bool defender = false;
    bool firewall = false;
    bool security = false;
    bool application = false;
    bool asr = false;

    for (const auto& finding : findings) {
        defender |= finding.control == "Microsoft Defender";
        firewall |= finding.control == "Windows Firewall";
        security |= finding.control == "Security Policy";
        application |= finding.control == "Application Control";
        asr |= finding.control == "Attack Surface Reduction";
    }

    std::cout << "Reviewable diagnostics:\n";

    if (defender) {
        std::cout
            << "  Get-MpComputerStatus | "
               "Select-Object RealTimeProtectionEnabled,AMServiceEnabled\n";
    }

    if (firewall) {
        std::cout
            << "  Get-NetFirewallProfile | "
               "Format-Table Name,Enabled,DefaultInboundAction\n";
    }

    if (security) {
        std::cout << "  auditpol /get /category:*\n";
    }

    if (application) {
        std::cout << "  Get-AppLockerPolicy -Effective | Format-List\n";
    }

    if (asr) {
        std::cout
            << "  Get-MpPreference | "
               "Select-Object AttackSurfaceReductionRules_Ids,"
               "AttackSurfaceReductionRules_Actions\n";
    }
}

int main() {
    try {
        const HardeningEngine engine = makeEngine();
        const Endpoint endpoint = makeEndpoint();

        const auto findings = engine.evaluate(endpoint);

        std::cout << "Windows Hardening Assessment\n";
        std::cout << "Endpoint: " << endpoint.hostname << "\n";
        std::cout << "============================\n";

        printFindings(findings);
        printDiagnostics(findings);

        std::cout << "\nNo operating-system configuration was modified.\n";
        return findings.empty() ? 0 : 2;
    }
    catch (const std::exception& exception) {
        std::cerr << "Assessment failed: " << exception.what() << '\n';
        return 1;
    }
}
