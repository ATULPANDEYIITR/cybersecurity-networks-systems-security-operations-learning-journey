#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

enum class Factor {
    Password,
    TOTP,
    HardwareToken,
    Biometric
};

enum class RiskLevel {
    Low,
    Medium,
    High,
    Critical
};

enum class PRStatus {
    NotApplicable
};

enum class AuthStatus {
    Success,
    Rejected,
    MFARequired,
    StepUpRequired,
    Locked
};

enum class ReviewDecision {
    Approved,
    ChangesRequested,
    Commented,
    Dismissed
};

struct LoginContext {
    string deviceId;
    string country;
    bool newDevice = false;
    bool impossibleTravel = false;
    bool unusualTime = false;
    bool sensitiveAction = false;
};

struct RiskAssessment {
    int score;
    RiskLevel level;
};

struct FactorEvidence {
    Factor factor;
    bool verified;
    bool trusted;
    bool userPresent;
};

struct User {
    string id;
    string username;
    string passwordDigest;
    set<Factor> registeredFactors;
    int failedAttempts = 0;
    bool locked = false;
};

struct AuthResult {
    AuthStatus status;
    RiskAssessment risk;
    vector<Factor> required;
    vector<Factor> completed;
    string message;
};

string toString(RiskLevel risk) {
    switch (risk) {
        case RiskLevel::Low: return "LOW";
        case RiskLevel::Medium: return "MEDIUM";
        case RiskLevel::High: return "HIGH";
        case RiskLevel::Critical: return "CRITICAL";
    }

    return "UNKNOWN";
}

string toString(AuthStatus status) {
    switch (status) {
        case AuthStatus::Success: return "SUCCESS";
        case AuthStatus::Rejected: return "REJECTED";
        case AuthStatus::MFARequired: return "MFA_REQUIRED";
        case AuthStatus::StepUpRequired: return "STEP_UP_REQUIRED";
        case AuthStatus::Locked: return "LOCKED";
    }

    return "UNKNOWN";
}

string toString(Factor factor) {
    switch (factor) {
        case Factor::Password: return "PASSWORD";
        case Factor::TOTP: return "TOTP";
        case Factor::HardwareToken: return "HARDWARE_TOKEN";
        case Factor::Biometric: return "BIOMETRIC";
    }

    return "UNKNOWN";
}

class PasswordPolicy {
public:
    static void validate(const string& password) {
        if (password.size() < 12 || password.size() > 1024) {
            throw invalid_argument(
                "Password must contain 12 to 1024 characters."
            );
        }
    }

    // Demonstration-only deterministic digest.
    // Production password storage requires Argon2id, scrypt or PBKDF2
    // with a unique random salt and a maintained cryptographic library.
    static string demonstrationDigest(const string& password) {
        size_t hash = hash<string>{}(password);
        return to_string(hash);
    }

    static bool verify(
        const string& password,
        const string& storedDigest
    ) {
        return demonstrationDigest(password) == storedDigest;
    }
};

class RiskEngine {
public:
    static RiskAssessment evaluate(const LoginContext& context) {
        int score = 0;

        if (context.newDevice) score += 25;
        if (context.impossibleTravel) score += 55;
        if (context.unusualTime) score += 15;
        if (context.sensitiveAction) score += 20;

        RiskLevel level = RiskLevel::Low;

        if (score >= 70) level = RiskLevel::Critical;
        else if (score >= 45) level = RiskLevel::High;
        else if (score >= 20) level = RiskLevel::Medium;

        return {score, level};
    }
};

class AuthenticationPolicy {
public:
    static vector<Factor> requiredFactors(
        const User& user,
        const RiskAssessment& risk,
        const LoginContext& context
    ) {
        vector<Factor> required = {Factor::Password};

        if (user.registeredFactors.count(Factor::TOTP)) {
            required.push_back(Factor::TOTP);
        }

        if (
            risk.level == RiskLevel::High ||
            risk.level == RiskLevel::Critical
        ) {
            if (user.registeredFactors.count(Factor::HardwareToken)) {
                required.push_back(Factor::HardwareToken);
            } else if (user.registeredFactors.count(Factor::Biometric)) {
                required.push_back(Factor::Biometric);
            }
        }

        if (
            context.sensitiveAction &&
            user.registeredFactors.count(Factor::Biometric) &&
            find(required.begin(), required.end(), Factor::Biometric)
                == required.end()
        ) {
            required.push_back(Factor::Biometric);
        }

        return required;
    }
};

class AuthenticationEngine {
private:
    map<string, User> users;
    static constexpr int MAX_FAILURES = 5;

    static const FactorEvidence* findEvidence(
        const vector<FactorEvidence>& evidence,
        Factor factor
    ) {
        auto it = find_if(
            evidence.begin(),
            evidence.end(),
            [factor](const FactorEvidence& item) {
                return item.factor == factor;
            }
        );

        return it == evidence.end() ? nullptr : &(*it);
    }

public:
    void registerUser(
        const string& id,
        const string& username,
        const string& password,
        const set<Factor>& factors
    ) {
        PasswordPolicy::validate(password);

        if (id.empty() || username.empty()) {
            throw invalid_argument("User ID and username are required.");
        }

        if (users.count(username)) {
            throw invalid_argument("Username already exists.");
        }

        if (!factors.count(Factor::Password)) {
            throw invalid_argument("Password factor is required.");
        }

        User user;
        user.id = id;
        user.username = username;
        user.passwordDigest =
            PasswordPolicy::demonstrationDigest(password);
        user.registeredFactors = factors;

        users.emplace(username, move(user));
    }

    AuthResult authenticate(
        const string& username,
        const string& password,
        const LoginContext& context,
        const vector<FactorEvidence>& evidence
    ) {
        auto userIt = users.find(username);

        RiskAssessment risk = RiskEngine::evaluate(context);

        if (userIt == users.end()) {
            return {
                AuthStatus::Rejected,
                risk,
                {},
                {},
                "Invalid credentials."
            };
        }

        User& user = userIt->second;

        if (user.locked) {
            return {
                AuthStatus::Locked,
                risk,
                {},
                {},
                "Account locked."
            };
        }

        if (!PasswordPolicy::verify(password, user.passwordDigest)) {
            ++user.failedAttempts;

            if (user.failedAttempts >= MAX_FAILURES) {
                user.locked = true;
            }

            return {
                user.locked ? AuthStatus::Locked : AuthStatus::Rejected,
                risk,
                {},
                {},
                "Invalid credentials."
            };
        }

        user.failedAttempts = 0;

        vector<Factor> required =
            AuthenticationPolicy::requiredFactors(user, risk, context);

        vector<Factor> completed = {Factor::Password};

        for (Factor factor : required) {
            if (factor == Factor::Password) continue;

            const FactorEvidence* item = findEvidence(evidence, factor);

            if (item == nullptr || !item->verified) {
                AuthStatus status =
                    factor == Factor::TOTP
                    ? AuthStatus::MFARequired
                    : AuthStatus::StepUpRequired;

                return {
                    status,
                    risk,
                    required,
                    completed,
                    "Additional authentication factor required."
                };
            }

            if (
                (factor == Factor::HardwareToken ||
                 factor == Factor::Biometric) &&
                (!item->trusted || !item->userPresent)
            ) {
                return {
                    AuthStatus::StepUpRequired,
                    risk,
                    required,
                    completed,
                    "Untrusted factor evidence."
                };
            }

            completed.push_back(factor);
        }

        return {
            AuthStatus::Success,
            risk,
            required,
            completed,
            "Authentication successful."
        };
    }
};

class GovernanceAudit {
private:
    vector<string> events;

public:
    void record(const string& username, const string& event) {
        events.push_back(username + ": " + event);
    }

    void print() const {
        for (const string& event : events) {
            cout << event << '\n';
        }
    }
};

void runTests() {
    AuthenticationEngine engine;

    engine.registerUser(
        "U001",
        "admin@example.com",
        "EnterprisePassword!2026",
        {
            Factor::Password,
            Factor::TOTP,
            Factor::HardwareToken,
            Factor::Biometric
        }
    );

    LoginContext normal;
    normal.deviceId = "workstation-001";
    normal.country = "IN";

    AuthResult success = engine.authenticate(
        "admin@example.com",
        "EnterprisePassword!2026",
        normal,
        {
            {Factor::TOTP, true, true, true}
        }
    );

    if (success.status != AuthStatus::Success) {
        throw runtime_error("Normal authentication test failed.");
    }

    LoginContext risky;
    risky.deviceId = "unknown-device";
    risky.country = "US";
    risky.newDevice = true;
    risky.impossibleTravel = true;

    AuthResult stepUp = engine.authenticate(
        "admin@example.com",
        "EnterprisePassword!2026",
        risky,
        {
            {Factor::TOTP, true, true, true}
        }
    );

    if (stepUp.status != AuthStatus::StepUpRequired) {
        throw runtime_error("Adaptive authentication test failed.");
    }

    AuthResult rejected = engine.authenticate(
        "admin@example.com",
        "IncorrectPassword!2026",
        normal,
        {}
    );

    if (rejected.status != AuthStatus::Rejected) {
        throw runtime_error("Invalid-password test failed.");
    }

    cout << "All C++ authentication tests passed.\n";
}

int main() {
    try {
        AuthenticationEngine engine;

        engine.registerUser(
            "U1001",
            "security@example.com",
            "EnterprisePassword!2026",
            {
                Factor::Password,
                Factor::TOTP,
                Factor::HardwareToken,
                Factor::Biometric
            }
        );

        LoginContext context;
        context.deviceId = "corporate-device-01";
        context.country = "IN";
        context.newDevice = true;

        vector<FactorEvidence> evidence = {
            {Factor::TOTP, true, true, true}
        };

        AuthResult result = engine.authenticate(
            "security@example.com",
            "EnterprisePassword!2026",
            context,
            evidence
        );

        cout << "\nAUTHENTICATION REPORT\n";
        cout << "Status: " << toString(result.status) << '\n';
        cout << "Risk: " << toString(result.risk.level) << '\n';
        cout << "Risk score: " << result.risk.score << '\n';
        cout << "Message: " << result.message << '\n';

        cout << "\nRequired factors:\n";

        for (Factor factor : result.required) {
            cout << "- " << toString(factor) << '\n';
        }

        cout << "\nCompleted factors:\n";

        for (Factor factor : result.completed) {
            cout << "- " << toString(factor) << '\n';
        }

        runTests();

    } catch (const exception& error) {
        cerr << "Authentication error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
