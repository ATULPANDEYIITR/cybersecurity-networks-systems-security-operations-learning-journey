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

enum class IdentityType {
    HUMAN,
    SERVICE,
    APPLICATION,
    EXTERNAL
};

enum class IdentityStatus {
    ACTIVE,
    SUSPENDED,
    DISABLED
};

enum class ReviewDecision {
    APPROVE,
    REVOKE,
    REDUCE,
    ESCALATE
};

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

string toString(Severity severity) {
    switch (severity) {
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }

    return "UNKNOWN";
}

struct Permission {
    string resource;
    string action;

    bool operator<(const Permission& other) const {
        return tie(resource, action) <
               tie(other.resource, other.action);
    }

    string key() const {
        return resource + ":" + action;
    }
};

struct Role {
    string id;
    string name;
    set<Permission> permissions;
    set<string> inheritedRoles;
    bool privileged = false;
};

struct Identity {
    string id;
    string name;
    IdentityType type;
    IdentityStatus status;
    set<string> roleIds;
    set<Permission> directPermissions;
    string owner;
    string department;
    bool mfaEnabled = false;
    int daysSinceLastLogin = 0;
};

struct Review {
    string identityId;
    string reviewer;
    ReviewDecision decision;
    string justification;
    set<string> permissionsToRemove;
};

struct Finding {
    string identityId;
    string category;
    Severity severity;
    int riskScore;
    string description;
    string recommendation;
};

class GovernanceEngine {
private:
    map<string, Role> roles;
    map<string, Identity> identities;
    vector<Review> reviews;
    vector<Finding> findings;

    set<string> sensitiveActions = {
        "admin",
        "manage_roles",
        "manage_policies",
        "manage_credentials",
        "configure_security",
        "delete"
    };

    vector<pair<string, string>> forbiddenRolePairs = {
        {"finance_approver", "payment_creator"},
        {"security_admin", "audit_reviewer"}
    };

    void validatePermission(const Permission& permission) const {
        if (permission.resource.empty() ||
            permission.action.empty()) {
            throw invalid_argument("Invalid permission");
        }
    }

    void collectPermissions(
        const string& roleId,
        set<Permission>& result,
        set<string>& visited
    ) const {
        if (visited.count(roleId)) {
            return;
        }

        auto it = roles.find(roleId);

        if (it == roles.end()) {
            throw runtime_error("Unknown role: " + roleId);
        }

        visited.insert(roleId);

        result.insert(
            it->second.permissions.begin(),
            it->second.permissions.end()
        );

        for (const string& parent : it->second.inheritedRoles) {
            collectPermissions(parent, result, visited);
        }
    }

public:
    void addRole(const Role& role) {
        if (role.id.empty() || role.name.empty()) {
            throw invalid_argument("Role ID and name are required");
        }

        if (roles.count(role.id)) {
            throw invalid_argument("Duplicate role: " + role.id);
        }

        for (const auto& permission : role.permissions) {
            validatePermission(permission);
        }

        roles.emplace(role.id, role);
    }

    void addIdentity(const Identity& identity) {
        if (identity.id.empty() || identity.name.empty()) {
            throw invalid_argument("Identity ID and name are required");
        }

        if (identities.count(identity.id)) {
            throw invalid_argument("Duplicate identity: " + identity.id);
        }

        if (identity.daysSinceLastLogin < 0) {
            throw invalid_argument("Invalid login age");
        }

        for (const string& roleId : identity.roleIds) {
            if (!roles.count(roleId)) {
                throw invalid_argument("Unknown assigned role: " + roleId);
            }
        }

        for (const auto& permission : identity.directPermissions) {
            validatePermission(permission);
        }

        identities.emplace(identity.id, identity);
    }

    void validateRoleGraph() const {
        set<string> visiting;
        set<string> visited;

        function<void(const string&)> visit =
            [&](const string& id) {
                if (!roles.count(id)) {
                    throw runtime_error("Missing inherited role: " + id);
                }

                if (visiting.count(id)) {
                    throw runtime_error(
                        "Circular role inheritance detected: " + id
                    );
                }

                if (visited.count(id)) return;

                visiting.insert(id);

                for (const string& parent :
                     roles.at(id).inheritedRoles) {
                    visit(parent);
                }

                visiting.erase(id);
                visited.insert(id);
            };

        for (const auto& entry : roles) {
            visit(entry.first);
        }
    }

    set<Permission> effectivePermissions(
        const string& identityId
    ) const {
        auto it = identities.find(identityId);

        if (it == identities.end()) {
            throw invalid_argument("Unknown identity: " + identityId);
        }

        const Identity& identity = it->second;

        if (identity.status != IdentityStatus::ACTIVE) {
            return {};
        }

        set<Permission> result = identity.directPermissions;
        set<string> visited;

        for (const string& roleId : identity.roleIds) {
            collectPermissions(roleId, result, visited);
        }

        return result;
    }

    bool isPrivileged(const Identity& identity) const {
        for (const string& roleId : identity.roleIds) {
            if (roles.at(roleId).privileged) {
                return true;
            }
        }

        for (const Permission& permission :
             effectivePermissions(identity.id)) {
            if (sensitiveActions.count(permission.action)) {
                return true;
            }
        }

        return false;
    }

    vector<string> checkSeparationOfDuties(
        const Identity& identity
    ) const {
        vector<string> violations;

        for (const auto& pair : forbiddenRolePairs) {
            if (
                identity.roleIds.count(pair.first) &&
                identity.roleIds.count(pair.second)
            ) {
                violations.push_back(
                    pair.first + " conflicts with " + pair.second
                );
            }
        }

        return violations;
    }

    void addFinding(
        const Identity& identity,
        const string& category,
        Severity severity,
        int risk,
        const string& description,
        const string& recommendation
    ) {
        findings.push_back({
            identity.id,
            category,
            severity,
            min(100, max(0, risk)),
            description,
            recommendation
        });
    }

    void assessIdentity(const Identity& identity) {
        if (identity.status != IdentityStatus::ACTIVE) {
            return;
        }

        const auto permissions = effectivePermissions(identity.id);
        const bool privileged = isPrivileged(identity);

        vector<string> dangerous;

        for (const Permission& permission : permissions) {
            if (sensitiveActions.count(permission.action)) {
                dangerous.push_back(permission.key());
            }
        }

        if (!dangerous.empty()) {
            ostringstream details;

            for (size_t i = 0; i < dangerous.size(); ++i) {
                if (i) details << ", ";
                details << dangerous[i];
            }

            addFinding(
                identity,
                "PRIVILEGE_ESCALATION_EXPOSURE",
                Severity::CRITICAL,
                95,
                "Sensitive effective permissions: " + details.str(),
                "Remove unnecessary administrative permissions and "
                "review inherited roles."
            );
        }

        if (permissions.size() > 8) {
            addFinding(
                identity,
                "EXCESSIVE_PRIVILEGES",
                Severity::MEDIUM,
                55,
                "Identity has " + to_string(permissions.size()) +
                    " effective permissions.",
                "Apply least privilege."
            );
        }

        if (privileged && !identity.mfaEnabled) {
            addFinding(
                identity,
                "PRIVILEGED_WITHOUT_MFA",
                Severity::CRITICAL,
                98,
                "Privileged identity does not have MFA.",
                "Require phishing-resistant MFA."
            );
        }

        if (identity.daysSinceLastLogin > 90) {
            addFinding(
                identity,
                "DORMANT_IDENTITY",
                privileged ? Severity::CRITICAL : Severity::HIGH,
                privileged ? 95 : 75,
                "Identity inactive for " +
                    to_string(identity.daysSinceLastLogin) + " days.",
                "Validate ownership and disable unused identities."
            );
        }

        const auto violations = checkSeparationOfDuties(identity);

        for (const string& violation : violations) {
            addFinding(
                identity,
                "SEPARATION_OF_DUTIES",
                Severity::CRITICAL,
                95,
                violation,
                "Remove conflicting access or require independent approval."
            );
        }
    }

    vector<Finding> assess() {
        validateRoleGraph();
        findings.clear();

        for (const auto& entry : identities) {
            assessIdentity(entry.second);
        }

        sort(
            findings.begin(),
            findings.end(),
            [](const Finding& a, const Finding& b) {
                if (a.riskScore != b.riskScore) {
                    return a.riskScore > b.riskScore;
                }

                return a.identityId < b.identityId;
            }
        );

        return findings;
    }

    void processReview(const Review& review) {
        auto it = identities.find(review.identityId);

        if (it == identities.end()) {
            throw invalid_argument("Review identity does not exist");
        }

        if (review.reviewer.empty() ||
            review.justification.size() < 10) {
            throw invalid_argument("Invalid review evidence");
        }

        Identity& identity = it->second;

        if (review.decision == ReviewDecision::REDUCE) {
            set<string> available;

            for (const Permission& permission :
                 identity.directPermissions) {
                available.insert(permission.key());
            }

            for (const string& roleId : identity.roleIds) {
                for (const Permission& permission :
                     roles.at(roleId).permissions) {
                    available.insert(permission.key());
                }
            }

            for (const string& permission :
                 review.permissionsToRemove) {
                if (!available.count(permission)) {
                    throw invalid_argument(
                        "Cannot remove unassigned permission: " + permission
                    );
                }
            }

            // Only direct permissions can be removed from an identity.
            // Shared role permissions require a separate role change.
            for (auto permission = identity.directPermissions.begin();
                 permission != identity.directPermissions.end();) {
                if (review.permissionsToRemove.count(
                        permission->key())) {
                    permission = identity.directPermissions.erase(permission);
                } else {
                    ++permission;
                }
            }
        } else if (review.decision == ReviewDecision::REVOKE) {
            identity.status = IdentityStatus::DISABLED;
            identity.roleIds.clear();
            identity.directPermissions.clear();
        } else if (review.decision == ReviewDecision::APPROVE) {
            // Approval records a decision but does not create permissions.
        } else if (review.decision == ReviewDecision::ESCALATE) {
            cout << "Review escalated for independent investigation.\n";
        }

        reviews.push_back(review);

        cout << "Review recorded for " << identity.id << "\n";
    }

    void printReport() const {
        cout << "\nIAM GOVERNANCE REPORT\n";
        cout << "==============================\n";

        cout << "Identities: " << identities.size() << "\n";
        cout << "Roles: " << roles.size() << "\n";
        cout << "Reviews: " << reviews.size() << "\n";
        cout << "Findings: " << findings.size() << "\n\n";

        for (const Finding& finding : findings) {
            cout << finding.identityId
                 << " | " << finding.category
                 << " | " << toString(finding.severity)
                 << " | Risk " << finding.riskScore << "\n";

            cout << "  " << finding.description << "\n";
            cout << "  Action: " << finding.recommendation << "\n";
        }
    }

    void printIdentity(const string& id) const {
        const Identity& identity = identities.at(id);

        cout << "\nIdentity: " << identity.name << "\n";
        cout << "Effective permissions:\n";

        for (const Permission& permission :
             effectivePermissions(id)) {
            cout << "  " << permission.key() << "\n";
        }
    }
};

Permission P(string resource, string action) {
    return {move(resource), move(action)};
}

int main() {
    try {
        GovernanceEngine engine;

        engine.addRole({
            "employee",
            "Employee",
            {P("documents", "read")},
            {},
            false
        });

        engine.addRole({
            "developer",
            "Developer",
            {
                P("source_code", "read"),
                P("source_code", "write"),
                P("deployment", "read")
            },
            {"employee"},
            false
        });

        engine.addRole({
            "security_admin",
            "Security Administrator",
            {
                P("iam", "manage_roles"),
                P("iam", "manage_policies"),
                P("secrets", "manage_credentials")
            },
            {},
            true
        });

        engine.addRole({
            "finance_approver",
            "Finance Approver",
            {P("payments", "approve")},
            {},
            false
        });

        engine.addRole({
            "payment_creator",
            "Payment Creator",
            {P("payments", "create")},
            {},
            false
        });

        engine.addIdentity({
            "USR-201",
            "Software Developer",
            IdentityType::HUMAN,
            IdentityStatus::ACTIVE,
            {"developer"},
            {},
            "engineering_manager",
            "engineering",
            true,
            2
        });

        engine.addIdentity({
            "USR-202",
            "Privileged Operator",
            IdentityType::HUMAN,
            IdentityStatus::ACTIVE,
            {"security_admin"},
            {},
            "security_director",
            "security",
            false,
            120
        });

        engine.addIdentity({
            "USR-203",
            "Finance Operator",
            IdentityType::HUMAN,
            IdentityStatus::ACTIVE,
            {"finance_approver", "payment_creator"},
            {},
            "finance_director",
            "finance",
            true,
            1
        });

        engine.addIdentity({
            "SVC-201",
            "Legacy Integration",
            IdentityType::SERVICE,
            IdentityStatus::ACTIVE,
            {"security_admin"},
            {},
            "integration_team",
            "platform",
            false,
            180
        });

        engine.printIdentity("USR-201");

        engine.assess();
        engine.printReport();

        cout << "\nACCESS CERTIFICATION\n";

        engine.processReview({
            "USR-202",
            "security_director",
            ReviewDecision::REVOKE,
            "Dormant privileged identity without MFA.",
            {}
        });

        cout << "\nREASSESSMENT\n";

        engine.assess();
        engine.printReport();

        return 0;
    } catch (const exception& error) {
        cerr << "Governance error: " << error.what() << "\n";
        return 1;
    }
}
