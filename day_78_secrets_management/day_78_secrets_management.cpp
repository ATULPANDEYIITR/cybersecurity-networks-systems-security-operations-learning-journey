#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <random>
#include <sstream>

using namespace std;

enum class SecretType {
    API_KEY,
    ACCESS_TOKEN,
    PASSWORD,
    DATABASE_CREDENTIAL,
    PRIVATE_KEY
};

enum class SecretStatus {
    ACTIVE,
    EXPIRED,
    REVOKED
};

enum class Permission {
    READ,
    WRITE,
    ROTATE,
    REVOKE,
    ADMIN
};

enum class Environment {
    DEVELOPMENT,
    TESTING,
    STAGING,
    PRODUCTION
};

string toString(SecretStatus status) {
    switch (status) {
        case SecretStatus::ACTIVE: return "ACTIVE";
        case SecretStatus::EXPIRED: return "EXPIRED";
        case SecretStatus::REVOKED: return "REVOKED";
    }
    return "UNKNOWN";
}

string toString(SecretType type) {
    switch (type) {
        case SecretType::API_KEY: return "API_KEY";
        case SecretType::ACCESS_TOKEN: return "ACCESS_TOKEN";
        case SecretType::PASSWORD: return "PASSWORD";
        case SecretType::DATABASE_CREDENTIAL: return "DATABASE_CREDENTIAL";
        case SecretType::PRIVATE_KEY: return "PRIVATE_KEY";
    }
    return "UNKNOWN";
}

string toString(Environment environment) {
    switch (environment) {
        case Environment::DEVELOPMENT: return "DEVELOPMENT";
        case Environment::TESTING: return "TESTING";
        case Environment::STAGING: return "STAGING";
        case Environment::PRODUCTION: return "PRODUCTION";
    }
    return "UNKNOWN";
}

class SecretException : public runtime_error {
public:
    explicit SecretException(const string& message)
        : runtime_error(message) {}
};

struct Principal {
    string id;
    set<string> roles;
};

struct SecretVersion {
    int number;
    string value;
    time_t createdAt;
    time_t expiresAt;
    SecretStatus status;
};

struct SecretRecord {
    string id;
    string name;
    SecretType type;
    Environment environment;
    string owner;
    vector<SecretVersion> versions;
    set<string> tags;
};

struct BranchPolicy {
    int minimumApprovals = 2;
    bool requireSuccessfulChecks = true;
    bool requireResolvedDiscussions = true;
    bool preventDirectPush = true;
    bool preventForcePush = true;
    bool preventDeletion = true;
};

struct ReviewDecision {
    string reviewer;
    bool eligible;
    bool approved;
    bool stale;
    bool dismissed;
};

struct StatusCheck {
    string name;
    bool required;
    bool passed;
};

struct MergeRequest {
    string id;
    string sourceBranch;
    string targetBranch;
    string headCommit;
    string baseCommit;
    bool open = true;
    bool draft = false;
    bool conflicts = false;
    bool conversationsResolved = true;
    vector<ReviewDecision> reviews;
    vector<StatusCheck> checks;
};

class AccessPolicy {
private:
    map<string, set<Permission>> rolePermissions;

public:
    AccessPolicy() {
        rolePermissions["developer"] = {
            Permission::READ
        };

        rolePermissions["operator"] = {
            Permission::READ,
            Permission::ROTATE
        };

        rolePermissions["security_admin"] = {
            Permission::READ,
            Permission::WRITE,
            Permission::ROTATE,
            Permission::REVOKE,
            Permission::ADMIN
        };
    }

    bool authorized(
        const Principal& principal,
        Permission permission
    ) const {
        for (const auto& role : principal.roles) {
            auto it = rolePermissions.find(role);

            if (it == rolePermissions.end()) {
                continue;
            }

            if (
                it->second.count(Permission::ADMIN) ||
                it->second.count(permission)
            ) {
                return true;
            }
        }

        return false;
    }

    void require(
        const Principal& principal,
        Permission permission
    ) const {
        if (!authorized(principal, permission)) {
            throw SecretException(
                "Access denied for principal: " + principal.id
            );
        }
    }
};

class SecretGenerator {
public:
    static string generate(size_t length = 40) {
        if (length < 24 || length > 128) {
            throw SecretException("Invalid secret length.");
        }

        static const string alphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789";

        random_device rd;
        mt19937_64 generator(rd());

        uniform_int_distribution<size_t> distribution(
            0,
            alphabet.size() - 1
        );

        string result;
        result.reserve(length);

        for (size_t i = 0; i < length; ++i) {
            result.push_back(alphabet[distribution(generator)]);
        }

        return result;
    }
};

class SecretValidator {
public:
    static void validateName(const string& name) {
        if (name.size() < 3 || name.size() > 100) {
            throw SecretException("Invalid secret name length.");
        }

        if (!isalpha(static_cast<unsigned char>(name.front()))) {
            throw SecretException("Secret name must start with a letter.");
        }

        for (unsigned char c : name) {
            if (
                !isalnum(c) &&
                c != '_' &&
                c != '-' &&
                c != '.'
            ) {
                throw SecretException("Invalid secret name characters.");
            }
        }
    }

    static void validateValue(const string& value) {
        if (value.empty() || value.size() > 65536) {
            throw SecretException("Invalid secret value.");
        }

        if (value.find('\0') != string::npos) {
            throw SecretException("Secret contains null byte.");
        }
    }
};

struct AuditEvent {
    string principal;
    string action;
    string secretId;
    string outcome;
    time_t timestamp;
};

class SecretVault {
private:
    unordered_map<string, SecretRecord> records;

    map<pair<Environment, string>, string> nameIndex;

    vector<AuditEvent> auditLog;

    AccessPolicy policy;

    static string generateId() {
        static mt19937_64 generator(random_device{}());
        static uniform_int_distribution<unsigned long long> distribution;

        stringstream stream;
        stream << hex << distribution(generator);
        return stream.str();
    }

    void audit(
        const Principal& principal,
        const string& action,
        const string& id,
        const string& outcome
    ) {
        auditLog.push_back({
            principal.id,
            action,
            id,
            outcome,
            time(nullptr)
        });
    }

    SecretRecord& findRecord(const string& id) {
        auto it = records.find(id);

        if (it == records.end()) {
            throw SecretException("Secret does not exist.");
        }

        return it->second;
    }

public:
    string create(
        const Principal& principal,
        const string& name,
        const string& value,
        SecretType type,
        Environment environment,
        const string& owner,
        int ttlDays = 90
    ) {
        string id = generateId();

        try {
            policy.require(principal, Permission::WRITE);
            SecretValidator::validateName(name);
            SecretValidator::validateValue(value);

            if (owner.empty()) {
                throw SecretException("Owner is required.");
            }

            if (ttlDays < 1 || ttlDays > 3650) {
                throw SecretException("Invalid expiration period.");
            }

            auto key = make_pair(environment, name);

            if (nameIndex.count(key)) {
                throw SecretException(
                    "Duplicate secret name in environment."
                );
            }

            time_t now = time(nullptr);

            SecretRecord record;
            record.id = id;
            record.name = name;
            record.type = type;
            record.environment = environment;
            record.owner = owner;

            record.versions.push_back({
                1,
                value,
                now,
                now + static_cast<time_t>(ttlDays) * 86400,
                SecretStatus::ACTIVE
            });

            records.emplace(id, move(record));
            nameIndex[key] = id;

            audit(principal, "CREATE", id, "SUCCESS");

            return id;

        } catch (...) {
            audit(principal, "CREATE", id, "FAILED");
            throw;
        }
    }

    string retrieve(
        const Principal& principal,
        const string& id
    ) {
        try {
            policy.require(principal, Permission::READ);

            SecretRecord& record = findRecord(id);

            SecretVersion& version = record.versions.back();

            if (version.status == SecretStatus::REVOKED) {
                throw SecretException("Secret is revoked.");
            }

            if (
                version.status == SecretStatus::EXPIRED ||
                time(nullptr) >= version.expiresAt
            ) {
                version.status = SecretStatus::EXPIRED;
                throw SecretException("Secret has expired.");
            }

            audit(principal, "READ", id, "SUCCESS");

            return version.value;

        } catch (...) {
            audit(principal, "READ", id, "FAILED");
            throw;
        }
    }

    int rotate(
        const Principal& principal,
        const string& id,
        const string& newValue,
        int ttlDays = 90
    ) {
        try {
            policy.require(principal, Permission::ROTATE);
            SecretValidator::validateValue(newValue);

            if (ttlDays < 1 || ttlDays > 3650) {
                throw SecretException("Invalid TTL.");
            }

            SecretRecord& record = findRecord(id);
            SecretVersion& previous = record.versions.back();

            if (previous.status == SecretStatus::REVOKED) {
                throw SecretException("Cannot rotate revoked secret.");
            }

            if (previous.value == newValue) {
                throw SecretException("New value must be different.");
            }

            previous.status = SecretStatus::EXPIRED;

            time_t now = time(nullptr);

            int nextVersion = previous.number + 1;

            record.versions.push_back({
                nextVersion,
                newValue,
                now,
                now + static_cast<time_t>(ttlDays) * 86400,
                SecretStatus::ACTIVE
            });

            audit(principal, "ROTATE", id, "SUCCESS");

            return nextVersion;

        } catch (...) {
            audit(principal, "ROTATE", id, "FAILED");
            throw;
        }
    }

    void revoke(
        const Principal& principal,
        const string& id
    ) {
        try {
            policy.require(principal, Permission::REVOKE);

            SecretRecord& record = findRecord(id);

            for (auto& version : record.versions) {
                version.status = SecretStatus::REVOKED;
                version.value.clear();
            }

            audit(principal, "REVOKE", id, "SUCCESS");

        } catch (...) {
            audit(principal, "REVOKE", id, "FAILED");
            throw;
        }
    }

    vector<string> findExpiring(int days) const {
        if (days < 0) {
            throw SecretException("Invalid monitoring period.");
        }

        vector<string> result;

        time_t threshold = time(nullptr) +
            static_cast<time_t>(days) * 86400;

        for (const auto& entry : records) {
            const auto& record = entry.second;
            const auto& current = record.versions.back();

            if (
                current.status == SecretStatus::ACTIVE &&
                current.expiresAt <= threshold
            ) {
                result.push_back(record.id);
            }
        }

        return result;
    }

    void printMetadata(
        const Principal& principal,
        const string& id
    ) const {
        policy.require(principal, Permission::READ);

        auto it = records.find(id);

        if (it == records.end()) {
            throw SecretException("Secret not found.");
        }

        const auto& record = it->second;
        const auto& current = record.versions.back();

        cout << "Secret ID: " << record.id << '\n';
        cout << "Name: " << record.name << '\n';
        cout << "Type: " << toString(record.type) << '\n';
        cout << "Environment: "
             << toString(record.environment) << '\n';
        cout << "Owner: " << record.owner << '\n';
        cout << "Version: " << current.number << '\n';
        cout << "Status: " << toString(current.status) << '\n';

        // Secret values are deliberately excluded from metadata.
    }

    void printAudit() const {
        cout << "\nAUDIT LOG\n";

        for (const auto& event : auditLog) {
            cout
                << event.principal << " | "
                << event.action << " | "
                << event.secretId << " | "
                << event.outcome << '\n';
        }
    }
};

class MergeEligibilityEngine {
public:
    static vector<string> evaluate(
        const MergeRequest& request,
        const BranchPolicy& policy
    ) {
        vector<string> failures;

        if (!request.open) {
            failures.push_back("Pull Request is closed.");
        }

        if (request.draft) {
            failures.push_back("Draft Pull Request cannot be merged.");
        }

        if (request.sourceBranch == request.targetBranch) {
            failures.push_back("Source and target branches are identical.");
        }

        if (request.conflicts) {
            failures.push_back("Merge conflicts must be resolved.");
        }

        int approvals = 0;
        set<string> approvedReviewers;

        for (const auto& review : request.reviews) {
            if (
                review.eligible &&
                review.approved &&
                !review.stale &&
                !review.dismissed
            ) {
                approvedReviewers.insert(review.reviewer);
            }
        }

        approvals = static_cast<int>(approvedReviewers.size());

        if (approvals < policy.minimumApprovals) {
            failures.push_back("Insufficient valid approvals.");
        }

        if (
            policy.requireResolvedDiscussions &&
            !request.conversationsResolved
        ) {
            failures.push_back("Unresolved review discussions.");
        }

        if (policy.requireSuccessfulChecks) {
            for (const auto& check : request.checks) {
                if (check.required && !check.passed) {
                    failures.push_back(
                        "Required check failed: " + check.name
                    );
                }
            }
        }

        return failures;
    }
};

int main() {
    try {
        cout << "SECRETS MANAGEMENT AND GOVERNANCE ENGINE\n";
        cout << "=========================================\n";

        SecretVault vault;

        Principal admin{
            "security-team",
            {"security_admin"}
        };

        Principal developer{
            "developer-01",
            {"developer"}
        };

        Principal operator{
            "operator-01",
            {"operator"}
        };

        string firstKey = SecretGenerator::generate();

        string secretId = vault.create(
            admin,
            "payment_api_key",
            firstKey,
            SecretType::API_KEY,
            Environment::PRODUCTION,
            "payment-platform",
            90
        );

        cout << "\n1. Secret created\n";
        vault.printMetadata(admin, secretId);

        cout << "\n2. Authorized retrieval\n";

        string retrieved = vault.retrieve(developer, secretId);

        cout << "Credential prefix: "
             << retrieved.substr(0, 5)
             << "********\n";

        cout << "\n3. Unauthorized operation\n";

        try {
            vault.create(
                developer,
                "unauthorized_key",
                SecretGenerator::generate(),
                SecretType::API_KEY,
                Environment::TESTING,
                "developer"
            );
        } catch (const exception& error) {
            cout << "Access blocked: " << error.what() << '\n';
        }

        cout << "\n4. Secret rotation\n";

        int version = vault.rotate(
            operator,
            secretId,
            SecretGenerator::generate(),
            90
        );

        cout << "New version: " << version << '\n';

        cout << "\n5. Rotation monitoring\n";

        auto candidates = vault.findExpiring(15);

        cout << "Expiring secrets: " << candidates.size() << '\n';

        cout << "\n6. Repository merge policy evaluation\n";

        BranchPolicy branchPolicy;
        branchPolicy.minimumApprovals = 2;

        MergeRequest request;

        request.id = "PR-101";
        request.sourceBranch = "feature/secret-rotation";
        request.targetBranch = "main";
        request.headCommit = "commit-feature";
        request.baseCommit = "commit-main";
        request.open = true;
        request.draft = false;
        request.conflicts = false;

        request.reviews = {
            {"reviewer-01", true, true, false, false},
            {"reviewer-02", true, true, false, false},
            {"reviewer-03", true, false, false, false}
        };

        request.checks = {
            {"unit-tests", true, true},
            {"security-scan", true, true},
            {"integration-tests", true, true}
        };

        auto failures = MergeEligibilityEngine::evaluate(
            request,
            branchPolicy
        );

        if (failures.empty()) {
            cout << "Merge eligible under configured policy.\n";
        } else {
            for (const auto& failure : failures) {
                cout << "Blocked: " << failure << '\n';
            }
        }

        cout << "\n7. Secret revocation\n";

        vault.revoke(admin, secretId);

        try {
            vault.retrieve(developer, secretId);
        } catch (const exception& error) {
            cout << "Retrieval blocked: " << error.what() << '\n';
        }

        vault.printAudit();

        cout << "\nAll demonstration operations completed.\n";

    } catch (const exception& error) {
        cerr << "Application error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
