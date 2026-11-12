#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

enum class Permission {
    READ,
    WRITE,
    DELETE,
    EXECUTE,
    SHARE,
    ADMIN
};

enum class Classification {
    PUBLIC = 0,
    INTERNAL = 1,
    CONFIDENTIAL = 2,
    SECRET = 3,
    TOP_SECRET = 4
};

enum class Decision {
    ALLOW,
    DENY
};

string toString(Permission permission) {
    switch (permission) {
        case Permission::READ: return "READ";
        case Permission::WRITE: return "WRITE";
        case Permission::DELETE: return "DELETE";
        case Permission::EXECUTE: return "EXECUTE";
        case Permission::SHARE: return "SHARE";
        case Permission::ADMIN: return "ADMIN";
    }

    throw invalid_argument("Unknown permission");
}

string toString(Decision decision) {
    return decision == Decision::ALLOW ? "ALLOW" : "DENY";
}

string toString(Classification classification) {
    switch (classification) {
        case Classification::PUBLIC: return "PUBLIC";
        case Classification::INTERNAL: return "INTERNAL";
        case Classification::CONFIDENTIAL: return "CONFIDENTIAL";
        case Classification::SECRET: return "SECRET";
        case Classification::TOP_SECRET: return "TOP_SECRET";
    }

    throw invalid_argument("Unknown classification");
}

struct User {
    string id;
    string department;
    Classification clearance;
    string location;
    bool active = true;
    bool mfaVerified = false;
    bool privilegedAdmin = false;
    bool deleteAuthorized = false;
    bool suspended = false;
};

struct Role {
    string name;
    set<Permission> permissions;
};

struct Resource {
    string id;
    string ownerId;
    string department;
    Classification classification;
    set<string> allowedLocations;
    bool requireMfa = true;
    bool deletionEnabled = false;

    // Principal may be a user ID or role name.
    map<string, set<Permission>> acl;
};

struct AccessRequest {
    string userId;
    string resourceId;
    Permission permission;
    string purpose;
};

struct PolicyResult {
    Decision decision;
    vector<string> reasons;
};

struct AuditRecord {
    string userId;
    string resourceId;
    string permission;
    Decision decision;
    vector<string> reasons;
};

class AuthorizationError : public runtime_error {
public:
    explicit AuthorizationError(const string& message)
        : runtime_error(message) {}
};

class AuthorizationEngine {
private:
    map<string, User> users;
    map<string, Role> roles;
    map<string, set<string>> userRoles;
    map<string, Resource> resources;

    vector<AuditRecord> audit;

    static void validateIdentifier(
        const string& value,
        const string& label
    ) {
        if (
            value.empty() ||
            value.size() > 128 ||
            value.find_first_not_of(" \t\n") == string::npos
        ) {
            throw AuthorizationError("Invalid " + label);
        }
    }

    const User& getUser(const string& id) const {
        auto iterator = users.find(id);

        if (iterator == users.end()) {
            throw AuthorizationError("Unknown user: " + id);
        }

        return iterator->second;
    }

    const Resource& getResource(const string& id) const {
        auto iterator = resources.find(id);

        if (iterator == resources.end()) {
            throw AuthorizationError("Unknown resource: " + id);
        }

        return iterator->second;
    }

    bool evaluateRBAC(
        const string& userId,
        Permission permission
    ) const {
        const auto& assignedRoles = userRoles.at(userId);

        return any_of(
            assignedRoles.begin(),
            assignedRoles.end(),
            [&](const string& roleName) {
                return roles.at(roleName).permissions.count(permission) > 0;
            }
        );
    }

    bool evaluateACL(
        const User& user,
        const Resource& resource,
        Permission permission
    ) const {
        auto userEntry = resource.acl.find(user.id);

        if (
            userEntry != resource.acl.end() &&
            userEntry->second.count(permission)
        ) {
            return true;
        }

        for (const string& roleName : userRoles.at(user.id)) {
            auto roleEntry = resource.acl.find(roleName);

            if (
                roleEntry != resource.acl.end() &&
                roleEntry->second.count(permission)
            ) {
                return true;
            }
        }

        return false;
    }

    bool evaluateDAC(
        const User& user,
        const Resource& resource,
        Permission permission
    ) const {
        if (user.id != resource.ownerId) {
            return false;
        }

        return permission == Permission::READ ||
               permission == Permission::WRITE ||
               permission == Permission::SHARE;
    }

    bool evaluateMAC(
        const User& user,
        const Resource& resource
    ) const {
        return static_cast<int>(user.clearance) >=
               static_cast<int>(resource.classification);
    }

    bool evaluateABAC(
        const User& user,
        const Resource& resource,
        const AccessRequest& request
    ) const {
        const set<string> allowedPurposes = {
            "business",
            "research",
            "maintenance",
            "compliance"
        };

        if (!allowedPurposes.count(request.purpose)) {
            return false;
        }

        if (
            user.department != resource.department &&
            request.purpose != "compliance"
        ) {
            return false;
        }

        if (
            !resource.allowedLocations.empty() &&
            !resource.allowedLocations.count(user.location)
        ) {
            return false;
        }

        if (resource.requireMfa && !user.mfaVerified) {
            return false;
        }

        return true;
    }

    bool evaluateLeastPrivilege(
        const User& user,
        const Resource& resource,
        Permission permission
    ) const {
        if (permission == Permission::ADMIN) {
            return user.privilegedAdmin;
        }

        if (permission == Permission::DELETE) {
            return user.deleteAuthorized &&
                   resource.deletionEnabled;
        }

        return true;
    }

    void record(
        const AccessRequest& request,
        const PolicyResult& result
    ) {
        audit.push_back({
            request.userId,
            request.resourceId,
            toString(request.permission),
            result.decision,
            result.reasons
        });
    }

public:
    void addUser(const User& user) {
        validateIdentifier(user.id, "user ID");

        if (users.count(user.id)) {
            throw AuthorizationError("Duplicate user");
        }

        users.emplace(user.id, user);
        userRoles.emplace(user.id, set<string>{});
    }

    void addRole(const Role& role) {
        validateIdentifier(role.name, "role name");

        if (roles.count(role.name)) {
            throw AuthorizationError("Duplicate role");
        }

        roles.emplace(role.name, role);
    }

    void assignRole(
        const string& userId,
        const string& roleName
    ) {
        getUser(userId);

        if (!roles.count(roleName)) {
            throw AuthorizationError("Unknown role");
        }

        userRoles.at(userId).insert(roleName);
    }

    void revokeRole(
        const string& userId,
        const string& roleName
    ) {
        getUser(userId);
        userRoles.at(userId).erase(roleName);
    }

    void addResource(const Resource& resource) {
        validateIdentifier(resource.id, "resource ID");
        getUser(resource.ownerId);

        if (resources.count(resource.id)) {
            throw AuthorizationError("Duplicate resource");
        }

        resources.emplace(resource.id, resource);
    }

    void grantACL(
        const string& resourceId,
        const string& principal,
        const set<Permission>& permissions
    ) {
        auto iterator = resources.find(resourceId);

        if (iterator == resources.end()) {
            throw AuthorizationError("Unknown resource");
        }

        if (!users.count(principal) && !roles.count(principal)) {
            throw AuthorizationError("Unknown ACL principal");
        }

        if (permissions.empty()) {
            throw AuthorizationError("Empty ACL grant");
        }

        auto& existing = iterator->second.acl[principal];

        existing.insert(permissions.begin(), permissions.end());
    }

    void revokeACL(
        const string& resourceId,
        const string& principal
    ) {
        auto iterator = resources.find(resourceId);

        if (iterator == resources.end()) {
            throw AuthorizationError("Unknown resource");
        }

        iterator->second.acl.erase(principal);
    }

    PolicyResult evaluate(const AccessRequest& request) const {
        const User& user = getUser(request.userId);
        const Resource& resource = getResource(request.resourceId);

        vector<string> reasons;

        if (!user.active) {
            return {Decision::DENY, {"Inactive account"}};
        }

        if (user.suspended) {
            return {Decision::DENY, {"Account suspended"}};
        }

        const bool mac = evaluateMAC(user, resource);

        reasons.push_back(
            mac ? "MAC passed" : "MAC clearance insufficient"
        );

        const bool abac = evaluateABAC(user, resource, request);

        reasons.push_back(
            abac ? "ABAC conditions passed" : "ABAC rejected request"
        );

        const bool leastPrivilege = evaluateLeastPrivilege(
            user,
            resource,
            request.permission
        );

        reasons.push_back(
            leastPrivilege
                ? "Least privilege passed"
                : "Least privilege denied operation"
        );

        const bool rbac = evaluateRBAC(
            user.id,
            request.permission
        );

        const bool acl = evaluateACL(
            user,
            resource,
            request.permission
        );

        const bool dac = evaluateDAC(
            user,
            resource,
            request.permission
        );

        const bool grant = rbac || acl || dac;

        reasons.push_back(
            string("RBAC=") + (rbac ? "YES" : "NO") +
            ", ACL=" + (acl ? "YES" : "NO") +
            ", DAC=" + (dac ? "YES" : "NO")
        );

        if (!grant) {
            reasons.push_back("No grant mechanism authorized access");
        }

        const bool allowed =
            mac && abac && leastPrivilege && grant;

        return {
            allowed ? Decision::ALLOW : Decision::DENY,
            reasons
        };
    }

    Decision authorize(const AccessRequest& request) {
        PolicyResult result = evaluate(request);

        record(request, result);

        return result.decision;
    }

    void printAudit() const {
        cout << "\nAUTHORIZATION AUDIT\n";

        for (const auto& event : audit) {
            cout << event.userId << " | "
                 << event.resourceId << " | "
                 << event.permission << " | "
                 << toString(event.decision) << '\n';

            for (const string& reason : event.reasons) {
                cout << "  - " << reason << '\n';
            }
        }
    }

    size_t auditCount() const {
        return audit.size();
    }
};

void configure(AuthorizationEngine& engine) {
    engine.addUser({
        "alice",
        "engineering",
        Classification::CONFIDENTIAL,
        "India",
        true,
        true,
        false,
        false,
        false
    });

    engine.addUser({
        "bob",
        "finance",
        Classification::SECRET,
        "India",
        true,
        true,
        true,
        true,
        false
    });

    engine.addUser({
        "charlie",
        "engineering",
        Classification::PUBLIC,
        "India",
        false,
        false,
        false,
        false,
        false
    });

    engine.addRole({
        "developer",
        {Permission::READ, Permission::WRITE}
    });

    engine.addRole({
        "security-admin",
        {Permission::READ, Permission::ADMIN}
    });

    engine.assignRole("alice", "developer");
    engine.assignRole("bob", "security-admin");

    engine.addResource({
        "source-code",
        "alice",
        "engineering",
        Classification::CONFIDENTIAL,
        {"India"},
        true,
        false,
        {}
    });

    engine.addResource({
        "financial-report",
        "bob",
        "finance",
        Classification::SECRET,
        {"India"},
        true,
        true,
        {}
    });

    engine.grantACL(
        "financial-report",
        "alice",
        {Permission::READ}
    );
}

int main() {
    try {
        AuthorizationEngine engine;

        configure(engine);

        const vector<AccessRequest> requests = {
            {
                "alice",
                "source-code",
                Permission::READ,
                "business"
            },
            {
                "alice",
                "financial-report",
                Permission::READ,
                "compliance"
            },
            {
                "alice",
                "financial-report",
                Permission::WRITE,
                "compliance"
            },
            {
                "bob",
                "financial-report",
                Permission::DELETE,
                "maintenance"
            },
            {
                "alice",
                "source-code",
                Permission::DELETE,
                "business"
            },
            {
                "charlie",
                "source-code",
                Permission::READ,
                "business"
            }
        };

        cout << "REPOSITORY AND RESOURCE AUTHORIZATION ENGINE\n\n";

        for (const auto& request : requests) {
            Decision decision = engine.authorize(request);

            cout << left
                 << setw(10) << request.userId
                 << setw(22) << request.resourceId
                 << setw(10) << toString(request.permission)
                 << toString(decision)
                 << '\n';
        }

        engine.printAudit();

        cout << "\nAudit records: "
             << engine.auditCount()
             << '\n';

        // Revocation immediately changes subsequent authorization.
        engine.revokeRole("alice", "developer");

        engine.revokeACL("financial-report", "alice");

        cout << "\nAfter revocation:\n";

        cout << "Alice source-code READ: "
             << toString(engine.authorize({
                 "alice",
                 "source-code",
                 Permission::READ,
                 "business"
             }))
             << '\n';

    } catch (const exception& error) {
        cerr << "Authorization failure: "
             << error.what() << '\n';

        return 1;
    }

    return 0;
}
