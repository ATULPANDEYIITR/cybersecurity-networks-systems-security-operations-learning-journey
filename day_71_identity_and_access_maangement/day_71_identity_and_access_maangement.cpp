#include <algorithm>
#include <chrono>
#include <cstdint>
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

using namespace std;

enum class IdentityStatus {
    Pending,
    Active,
    Suspended,
    Disabled,
    Terminated
};

enum class Role {
    Employee,
    Manager,
    SecurityAdmin,
    Auditor
};

enum class Permission {
    ReadDocument,
    WriteDocument,
    DeleteDocument,
    ManageUsers,
    ManageRoles,
    ReadAudit
};

enum class ReviewDecision {
    Allow,
    Deny
};

enum class EventType {
    IdentityCreated,
    IdentityActivated,
    RoleAssigned,
    RoleRemoved,
    LoginSuccess,
    LoginFailure,
    AccessGranted,
    AccessDenied,
    SessionRevoked,
    IdentitySuspended,
    IdentityDisabled,
    IdentityTerminated
};

string toString(IdentityStatus status) {
    switch (status) {
        case IdentityStatus::Pending: return "PENDING";
        case IdentityStatus::Active: return "ACTIVE";
        case IdentityStatus::Suspended: return "SUSPENDED";
        case IdentityStatus::Disabled: return "DISABLED";
        case IdentityStatus::Terminated: return "TERMINATED";
    }
    throw logic_error("Unknown identity status");
}

string toString(Role role) {
    switch (role) {
        case Role::Employee: return "EMPLOYEE";
        case Role::Manager: return "MANAGER";
        case Role::SecurityAdmin: return "SECURITY_ADMIN";
        case Role::Auditor: return "AUDITOR";
    }
    throw logic_error("Unknown role");
}

string toString(Permission permission) {
    switch (permission) {
        case Permission::ReadDocument: return "document:read";
        case Permission::WriteDocument: return "document:write";
        case Permission::DeleteDocument: return "document:delete";
        case Permission::ManageUsers: return "users:manage";
        case Permission::ManageRoles: return "roles:manage";
        case Permission::ReadAudit: return "audit:read";
    }
    throw logic_error("Unknown permission");
}

string toString(EventType event) {
    switch (event) {
        case EventType::IdentityCreated: return "IDENTITY_CREATED";
        case EventType::IdentityActivated: return "IDENTITY_ACTIVATED";
        case EventType::RoleAssigned: return "ROLE_ASSIGNED";
        case EventType::RoleRemoved: return "ROLE_REMOVED";
        case EventType::LoginSuccess: return "LOGIN_SUCCESS";
        case EventType::LoginFailure: return "LOGIN_FAILURE";
        case EventType::AccessGranted: return "ACCESS_GRANTED";
        case EventType::AccessDenied: return "ACCESS_DENIED";
        case EventType::SessionRevoked: return "SESSION_REVOKED";
        case EventType::IdentitySuspended: return "IDENTITY_SUSPENDED";
        case EventType::IdentityDisabled: return "IDENTITY_DISABLED";
        case EventType::IdentityTerminated: return "IDENTITY_TERMINATED";
    }
    throw logic_error("Unknown event");
}

struct Identity {
    string id;
    string username;
    string credentialReference;
    IdentityStatus status = IdentityStatus::Pending;
    set<Role> roles;
    bool mfaEnabled = false;
    unsigned failedAttempts = 0;
    uint64_t version = 1;
};

struct Session {
    string token;
    string identityId;
    chrono::system_clock::time_point createdAt;
    chrono::system_clock::time_point expiresAt;
    bool revoked = false;
};

struct AuditEvent {
    uint64_t sequence;
    string identityId;
    EventType type;
    string resource;
    string reason;
    chrono::system_clock::time_point timestamp;
};

struct AccessDecision {
    ReviewDecision decision;
    string reason;
    string identityId;
    string permission;
};

class CredentialVerifier {
public:
    // The external identity provider supplies a verified credential result.
    // Production password verification belongs in a dedicated secure
    // authentication component, not in this governance engine.
    static bool verify(
        bool credentialVerified,
        bool mfaRequired,
        bool mfaVerified
    ) {
        return credentialVerified &&
               (!mfaRequired || mfaVerified);
    }
};

class RolePolicy {
private:
    unordered_map<Role, unordered_set<Permission>> permissions;

public:
    RolePolicy() {
        permissions[Role::Employee] = {
            Permission::ReadDocument,
            Permission::WriteDocument
        };

        permissions[Role::Manager] = {
            Permission::ReadDocument,
            Permission::WriteDocument,
            Permission::DeleteDocument
        };

        permissions[Role::SecurityAdmin] = {
            Permission::ReadDocument,
            Permission::WriteDocument,
            Permission::DeleteDocument,
            Permission::ManageUsers,
            Permission::ManageRoles,
            Permission::ReadAudit
        };

        permissions[Role::Auditor] = {
            Permission::ReadDocument,
            Permission::ReadAudit
        };
    }

    bool allows(
        const set<Role>& roles,
        Permission requested
    ) const {
        for (Role role : roles) {
            auto it = permissions.find(role);

            if (
                it != permissions.end() &&
                it->second.count(requested)
            ) {
                return true;
            }
        }

        return false;
    }
};

class AuditLedger {
private:
    vector<AuditEvent> events;
    uint64_t nextSequence = 1;

public:
    void append(
        const string& identityId,
        EventType type,
        const string& resource,
        const string& reason
    ) {
        events.push_back({
            nextSequence++,
            identityId,
            type,
            resource,
            reason,
            chrono::system_clock::now()
        });
    }

    const vector<AuditEvent>& getEvents() const {
        return events;
    }

    void report() const {
        map<EventType, size_t> counts;

        for (const auto& event : events) {
            counts[event.type]++;
        }

        cout << "\nAccounting report\n";

        for (const auto& [type, count] : counts) {
            cout << toString(type) << ": " << count << '\n';
        }

        cout << "Total events: " << events.size() << '\n';
    }
};

class IAMEngine {
private:
    unordered_map<string, Identity> identities;
    unordered_map<string, string> usernameIndex;
    unordered_map<string, Session> sessions;
    unordered_map<string, unsigned> failedAttempts;
    unordered_set<string> explicitDenials;

    RolePolicy policy;
    AuditLedger audit;

    chrono::minutes sessionLifetime{30};
    unsigned maximumAttempts = 5;

    Identity& getIdentity(const string& id) {
        auto it = identities.find(id);

        if (it == identities.end()) {
            throw invalid_argument("Identity not found");
        }

        return it->second;
    }

    void revokeSessions(const string& id) {
        for (auto& [token, session] : sessions) {
            if (
                session.identityId == id &&
                !session.revoked
            ) {
                session.revoked = true;

                audit.append(
                    id,
                    EventType::SessionRevoked,
                    "session",
                    "identity_lifecycle_change"
                );
            }
        }
    }

public:
    string createIdentity(
        const string& id,
        const string& username,
        const string& credentialReference
    ) {
        if (
            id.empty() ||
            username.empty() ||
            credentialReference.empty()
        ) {
            throw invalid_argument("Identity fields cannot be empty");
        }

        if (usernameIndex.count(username)) {
            throw invalid_argument("Duplicate username");
        }

        if (identities.count(id)) {
            throw invalid_argument("Duplicate identity ID");
        }

        Identity identity;
        identity.id = id;
        identity.username = username;
        identity.credentialReference = credentialReference;

        identities.emplace(id, identity);
        usernameIndex.emplace(username, id);

        audit.append(
            id,
            EventType::IdentityCreated,
            "identity",
            "provisioning"
        );

        return id;
    }

    void activate(const string& id) {
        Identity& identity = getIdentity(id);

        if (identity.status != IdentityStatus::Pending) {
            throw logic_error("Invalid activation transition");
        }

        identity.status = IdentityStatus::Active;
        identity.version++;

        audit.append(
            id,
            EventType::IdentityActivated,
            "identity",
            "approved"
        );
    }

    void assignRole(const string& id, Role role) {
        Identity& identity = getIdentity(id);

        if (identity.status != IdentityStatus::Active) {
            throw logic_error("Identity must be active");
        }

        if (!identity.roles.insert(role).second) {
            throw logic_error("Role already assigned");
        }

        identity.version++;

        audit.append(
            id,
            EventType::RoleAssigned,
            "identity",
            toString(role)
        );
    }

    void removeRole(const string& id, Role role) {
        Identity& identity = getIdentity(id);

        if (!identity.roles.erase(role)) {
            throw logic_error("Role not assigned");
        }

        identity.version++;

        audit.append(
            id,
            EventType::RoleRemoved,
            "identity",
            toString(role)
        );
    }

    string authenticate(
        const string& username,
        bool credentialVerified,
        bool mfaVerified
    ) {
        auto user = usernameIndex.find(username);

        if (user == usernameIndex.end()) {
            audit.append(
                "",
                EventType::LoginFailure,
                "authentication",
                "unknown_identity"
            );

            throw runtime_error("Authentication failed");
        }

        Identity& identity = getIdentity(user->second);

        if (identity.status != IdentityStatus::Active) {
            throw runtime_error("Identity is not active");
        }

        if (identity.failedAttempts >= maximumAttempts) {
            throw runtime_error("Authentication temporarily locked");
        }

        if (!CredentialVerifier::verify(
                credentialVerified,
                identity.mfaEnabled,
                mfaVerified
            )) {
            identity.failedAttempts++;

            audit.append(
                identity.id,
                EventType::LoginFailure,
                "authentication",
                "credential_or_mfa_failure"
            );

            throw runtime_error("Authentication failed");
        }

        identity.failedAttempts = 0;

        auto now = chrono::system_clock::now();

        string token =
            "session-" + identity.id + "-" +
            to_string(sessions.size() + 1);

        sessions.emplace(
            token,
            Session{
                token,
                identity.id,
                now,
                now + sessionLifetime,
                false
            }
        );

        audit.append(
            identity.id,
            EventType::LoginSuccess,
            "session",
            "authenticated"
        );

        return token;
    }

    AccessDecision authorize(
        const string& token,
        Permission permission,
        const string& resource
    ) {
        auto sessionIt = sessions.find(token);

        if (
            sessionIt == sessions.end() ||
            sessionIt->second.revoked
        ) {
            return {
                ReviewDecision::Deny,
                "INVALID_SESSION",
                "",
                toString(permission)
            };
        }

        Session& session = sessionIt->second;

        if (chrono::system_clock::now() >= session.expiresAt) {
            session.revoked = true;

            audit.append(
                session.identityId,
                EventType::SessionRevoked,
                "session",
                "expired"
            );

            return {
                ReviewDecision::Deny,
                "SESSION_EXPIRED",
                session.identityId,
                toString(permission)
            };
        }

        Identity& identity = getIdentity(session.identityId);

        bool allowed =
            identity.status == IdentityStatus::Active &&
            !explicitDenials.count(identity.id) &&
            policy.allows(identity.roles, permission);

        EventType event = allowed
            ? EventType::AccessGranted
            : EventType::AccessDenied;

        string reason = allowed
            ? "ROLE_PERMISSION_MATCH"
            : "POLICY_DENIED";

        audit.append(
            identity.id,
            event,
            resource,
            reason
        );

        return {
            allowed ? ReviewDecision::Allow : ReviewDecision::Deny,
            reason,
            identity.id,
            toString(permission)
        };
    }

    void suspend(const string& id) {
        Identity& identity = getIdentity(id);

        if (identity.status != IdentityStatus::Active) {
            throw logic_error("Only active identities can be suspended");
        }

        identity.status = IdentityStatus::Suspended;
        identity.version++;

        revokeSessions(id);

        audit.append(
            id,
            EventType::IdentitySuspended,
            "identity",
            "administrative_action"
        );
    }

    void disable(const string& id) {
        Identity& identity = getIdentity(id);

        if (
            identity.status == IdentityStatus::Disabled ||
            identity.status == IdentityStatus::Terminated
        ) {
            throw logic_error("Invalid disable transition");
        }

        identity.status = IdentityStatus::Disabled;
        identity.version++;

        revokeSessions(id);

        audit.append(
            id,
            EventType::IdentityDisabled,
            "identity",
            "administrative_action"
        );
    }

    void terminate(const string& id) {
        Identity& identity = getIdentity(id);

        if (
            identity.status == IdentityStatus::Pending ||
            identity.status == IdentityStatus::Terminated
        ) {
            throw logic_error("Invalid termination transition");
        }

        identity.status = IdentityStatus::Terminated;
        identity.roles.clear();
        identity.version++;

        revokeSessions(id);

        audit.append(
            id,
            EventType::IdentityTerminated,
            "identity",
            "offboarding"
        );
    }

    void addExplicitDenial(const string& id) {
        getIdentity(id);
        explicitDenials.insert(id);
    }

    void removeExplicitDenial(const string& id) {
        explicitDenials.erase(id);
    }

    void printIdentities() const {
        cout << "\nIdentity registry\n";

        for (const auto& [id, identity] : identities) {
            cout << id << " | "
                 << identity.username << " | "
                 << toString(identity.status)
                 << " | version=" << identity.version
                 << '\n';
        }
    }

    void report() const {
        audit.report();
    }
};

int main() {
    try {
        IAMEngine iam;

        iam.createIdentity(
            "USR-1001",
            "alice",
            "external-credential-reference-1001"
        );

        iam.activate("USR-1001");

        iam.assignRole(
            "USR-1001",
            Role::Employee
        );

        string token = iam.authenticate(
            "alice",
            true,
            true
        );

        auto read = iam.authorize(
            token,
            Permission::ReadDocument,
            "documents/financial-report.pdf"
        );

        auto deletion = iam.authorize(
            token,
            Permission::DeleteDocument,
            "documents/financial-report.pdf"
        );

        cout << "\nRead: "
             << (read.decision == ReviewDecision::Allow
                     ? "ALLOW" : "DENY")
             << " (" << read.reason << ")\n";

        cout << "Delete: "
             << (deletion.decision == ReviewDecision::Allow
                     ? "ALLOW" : "DENY")
             << " (" << deletion.reason << ")\n";

        if (read.decision != ReviewDecision::Allow ||
            deletion.decision != ReviewDecision::Deny) {
            throw runtime_error("Unexpected policy evaluation");
        }

        iam.addExplicitDenial("USR-1001");

        auto denied = iam.authorize(
            token,
            Permission::ReadDocument,
            "documents/confidential.pdf"
        );

        cout << "Explicit denial: "
             << (denied.decision == ReviewDecision::Deny
                     ? "DENY" : "ALLOW")
             << '\n';

        iam.removeExplicitDenial("USR-1001");

        iam.suspend("USR-1001");

        iam.printIdentities();
        iam.report();

    } catch (const exception& error) {
        cerr << "IAM error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
