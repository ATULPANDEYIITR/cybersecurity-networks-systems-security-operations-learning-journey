#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

// ============================================================
// PRIVILEGED ACCESS MANAGEMENT AND GOVERNANCE ENGINE
// C++17
//
// Evaluates:
// - Privileged accounts
// - Administrative groups
// - Access requests
// - Reviewer eligibility
// - Approval decisions
// - MFA requirements
// - Status checks
// - Protected branches of access policy
// - Credential isolation
// - Session expiration
// - Merge-like access eligibility decisions
// ============================================================

enum class Privilege {
    STANDARD = 1,
    ELEVATED = 2,
    ADMIN = 3,
    SUPER_ADMIN = 4
};

enum class AccountStatus {
    ACTIVE,
    DISABLED,
    LOCKED
};

enum class RequestStatus {
    PENDING,
    APPROVED,
    DENIED,
    ACTIVE,
    REVOKED,
    EXPIRED
};

enum class Decision {
    APPROVE,
    DENY
};

enum class CheckStatus {
    PENDING,
    PASSED,
    FAILED
};

enum class Severity {
    INFO,
    WARNING,
    CRITICAL
};


string toString(RequestStatus status) {
    switch (status) {
        case RequestStatus::PENDING: return "PENDING";
        case RequestStatus::APPROVED: return "APPROVED";
        case RequestStatus::DENIED: return "DENIED";
        case RequestStatus::ACTIVE: return "ACTIVE";
        case RequestStatus::REVOKED: return "REVOKED";
        case RequestStatus::EXPIRED: return "EXPIRED";
    }
    return "UNKNOWN";
}

string toString(Privilege privilege) {
    switch (privilege) {
        case Privilege::STANDARD: return "STANDARD";
        case Privilege::ELEVATED: return "ELEVATED";
        case Privilege::ADMIN: return "ADMIN";
        case Privilege::SUPER_ADMIN: return "SUPER_ADMIN";
    }
    return "UNKNOWN";
}


class PAMException : public runtime_error {
public:
    explicit PAMException(const string& message)
        : runtime_error(message) {}
};


struct User {
    string id;
    string username;
    string department;
    bool active = true;
    bool mfaEnabled = false;
    set<string> roles;
};


struct PrivilegedGroup {
    string id;
    string name;
    Privilege privilege;
    set<string> members;
    bool approvalRequired = true;
    int maximumSessionMinutes = 60;
};


struct PrivilegedAccount {
    string id;
    string username;
    string system;
    Privilege privilege;
    AccountStatus status = AccountStatus::ACTIVE;
    set<string> groupIds;
    string credentialReference;
    int rotationIntervalDays = 30;
    time_t lastRotated = 0;
};


struct AccessRequest {
    string id;
    string requesterId;
    string accountId;
    string justification;
    int durationMinutes = 0;
    RequestStatus status = RequestStatus::PENDING;
    string approverId;
    time_t createdAt = 0;
};


struct PrivilegedSession {
    string id;
    string requestId;
    string userId;
    string accountId;
    time_t startedAt = 0;
    time_t expiresAt = 0;
    bool active = true;
    bool recorded = true;
};


struct StatusCheck {
    string name;
    CheckStatus status;
};


struct AuditEvent {
    string actor;
    string action;
    string resource;
    Severity severity;
    time_t timestamp;
};


struct GovernancePolicy {
    bool requireMFA = true;
    bool requireApproval = true;
    bool prohibitSelfApproval = true;
    bool prohibitDirectCredentialExposure = true;
    bool requireSessionRecording = true;
    bool requireAllChecksPassed = true;
    bool prohibitConcurrentSessions = true;
    bool prohibitUnapprovedAccounts = true;
    int maximumSessionMinutes = 60;
    int minimumApprovals = 1;
};


// ============================================================
// CREDENTIAL ISOLATION
// ============================================================

class CredentialVault {

private:
    map<string, string> references;

public:

    void provision(
        const string& accountId,
        const string& opaqueReference
    ) {
        if (accountId.empty() || opaqueReference.empty()) {
            throw PAMException("Invalid credential reference.");
        }

        references[accountId] = opaqueReference;
    }

    bool exists(const string& accountId) const {
        return references.count(accountId) > 0;
    }

    string getReference(const string& accountId) const {
        auto it = references.find(accountId);

        if (it == references.end()) {
            throw PAMException("Credential unavailable.");
        }

        return it->second;
    }

    void rotate(
        const string& accountId,
        const string& newReference
    ) {
        provision(accountId, newReference);
    }
};


// ============================================================
// PAM GOVERNANCE ENGINE
// ============================================================

class PAMEngine {

private:

    map<string, User> users;
    map<string, PrivilegedGroup> groups;
    map<string, PrivilegedAccount> accounts;
    map<string, AccessRequest> requests;
    map<string, PrivilegedSession> sessions;

    map<string, vector<StatusCheck>> requestChecks;

    CredentialVault vault;
    GovernancePolicy policy;

    vector<AuditEvent> auditLog;

    int sequence = 1000;

    string generateId(const string& prefix) {
        return prefix + to_string(++sequence);
    }

    time_t now() const {
        return chrono::system_clock::to_time_t(
            chrono::system_clock::now()
        );
    }

    void audit(
        const string& actor,
        const string& action,
        const string& resource,
        Severity severity = Severity::INFO
    ) {
        auditLog.push_back({
            actor,
            action,
            resource,
            severity,
            now()
        });
    }

    User& getUser(const string& id) {
        auto it = users.find(id);

        if (it == users.end()) {
            throw PAMException("User not found: " + id);
        }

        return it->second;
    }

    PrivilegedGroup& getGroup(const string& id) {
        auto it = groups.find(id);

        if (it == groups.end()) {
            throw PAMException("Group not found: " + id);
        }

        return it->second;
    }

    PrivilegedAccount& getAccount(const string& id) {
        auto it = accounts.find(id);

        if (it == accounts.end()) {
            throw PAMException("Account not found: " + id);
        }

        return it->second;
    }

    AccessRequest& getRequest(const string& id) {
        auto it = requests.find(id);

        if (it == requests.end()) {
            throw PAMException("Request not found: " + id);
        }

        return it->second;
    }

    PrivilegedSession& getSession(const string& id) {
        auto it = sessions.find(id);

        if (it == sessions.end()) {
            throw PAMException("Session not found: " + id);
        }

        return it->second;
    }

    vector<PrivilegedGroup*> eligibleGroups(
        const User& user,
        const PrivilegedAccount& account
    ) {
        vector<PrivilegedGroup*> result;

        for (const string& groupId : account.groupIds) {
            auto it = groups.find(groupId);

            if (
                it != groups.end() &&
                it->second.members.count(user.id)
            ) {
                result.push_back(
                    const_cast<PrivilegedGroup*>(&it->second)
                );
            }
        }

        return result;
    }

    int validateEligibility(
        const User& user,
        const PrivilegedAccount& account
    ) {
        if (!user.active) {
            throw PAMException("User is inactive.");
        }

        if (policy.requireMFA && !user.mfaEnabled) {
            throw PAMException("MFA verification required.");
        }

        if (
            policy.prohibitUnapprovedAccounts &&
            account.status != AccountStatus::ACTIVE
        ) {
            throw PAMException("Account unavailable.");
        }

        auto memberships = eligibleGroups(user, account);

        if (memberships.empty()) {
            throw PAMException("No privileged group membership.");
        }

        int maximum = policy.maximumSessionMinutes;

        for (const auto* group : memberships) {
            maximum = min(
                maximum,
                group->maximumSessionMinutes
            );
        }

        return maximum;
    }

    bool hasActiveSession(
        const string& userId,
        const string& accountId
    ) {
        for (auto& [id, session] : sessions) {
            if (
                session.userId == userId &&
                session.accountId == accountId &&
                session.active &&
                session.expiresAt > now()
            ) {
                return true;
            }
        }

        return false;
    }

public:

    explicit PAMEngine(GovernancePolicy configuredPolicy)
        : policy(configuredPolicy) {}

    // --------------------------------------------------------
    // USER REGISTRATION
    // --------------------------------------------------------

    void registerUser(User user) {

        if (user.id.empty() || user.username.empty()) {
            throw PAMException("Invalid user information.");
        }

        if (users.count(user.id)) {
            throw PAMException("Duplicate user.");
        }

        users.emplace(user.id, move(user));

        audit(
            "SYSTEM",
            "USER_REGISTERED",
            users.rbegin()->first
        );
    }

    // --------------------------------------------------------
    // GROUP MANAGEMENT
    // --------------------------------------------------------

    void createGroup(PrivilegedGroup group) {

        if (
            group.id.empty() ||
            group.name.empty() ||
            group.maximumSessionMinutes < 1
        ) {
            throw PAMException("Invalid privileged group.");
        }

        if (groups.count(group.id)) {
            throw PAMException("Duplicate group.");
        }

        groups.emplace(group.id, move(group));
    }

    void addMember(
        const string& groupId,
        const string& userId
    ) {
        auto& group = getGroup(groupId);
        auto& user = getUser(userId);

        if (!user.active) {
            throw PAMException("Inactive user cannot join group.");
        }

        group.members.insert(userId);

        audit(
            userId,
            "GROUP_MEMBERSHIP_GRANTED",
            groupId
        );
    }

    // --------------------------------------------------------
    // PRIVILEGED ACCOUNT INVENTORY
    // --------------------------------------------------------

    void registerAccount(
        PrivilegedAccount account,
        const string& credentialReference
    ) {
        if (
            account.id.empty() ||
            account.username.empty() ||
            account.system.empty()
        ) {
            throw PAMException("Invalid account information.");
        }

        if (accounts.count(account.id)) {
            throw PAMException("Duplicate privileged account.");
        }

        for (const string& groupId : account.groupIds) {
            getGroup(groupId);
        }

        account.lastRotated = now();

        vault.provision(
            account.id,
            credentialReference
        );

        accounts.emplace(account.id, move(account));

        audit(
            "SYSTEM",
            "PRIVILEGED_ACCOUNT_REGISTERED",
            account.id
        );
    }

    // --------------------------------------------------------
    // ACCESS REQUEST
    // --------------------------------------------------------

    string requestAccess(
        const string& userId,
        const string& accountId,
        const string& justification,
        int requestedMinutes
    ) {
        auto& user = getUser(userId);
        auto& account = getAccount(accountId);

        int maximum = validateEligibility(user, account);

        if (
            policy.prohibitConcurrentSessions &&
            hasActiveSession(userId, accountId)
        ) {
            throw PAMException("Concurrent session prohibited.");
        }

        if (
            justification.empty() ||
            requestedMinutes < 1 ||
            requestedMinutes > maximum
        ) {
            throw PAMException("Invalid access request.");
        }

        AccessRequest request;

        request.id = generateId("REQ");
        request.requesterId = userId;
        request.accountId = accountId;
        request.justification = justification;
        request.durationMinutes = requestedMinutes;
        request.createdAt = now();

        string requestId = request.id;

        requests.emplace(requestId, move(request));

        requestChecks[requestId] = {
            {"identity", CheckStatus::PASSED},
            {"mfa", CheckStatus::PASSED},
            {"account_status", CheckStatus::PASSED},
            {"group_membership", CheckStatus::PASSED},
            {"credential_availability", CheckStatus::PASSED}
        };

        audit(
            userId,
            "ACCESS_REQUEST_CREATED",
            requestId
        );

        return requestId;
    }

    // --------------------------------------------------------
    // AUTOMATED STATUS CHECKS
    // --------------------------------------------------------

    void updateStatusCheck(
        const string& requestId,
        const string& checkName,
        CheckStatus status
    ) {
        getRequest(requestId);

        auto& checks = requestChecks.at(requestId);

        auto it = find_if(
            checks.begin(),
            checks.end(),
            [&](const StatusCheck& check) {
                return check.name == checkName;
            }
        );

        if (it == checks.end()) {
            throw PAMException("Unknown status check.");
        }

        it->status = status;

        audit(
            "SYSTEM",
            "STATUS_CHECK_UPDATED",
            requestId,
            status == CheckStatus::FAILED
                ? Severity::WARNING
                : Severity::INFO
        );
    }

    bool allChecksPassed(const string& requestId) {

        const auto& checks = requestChecks.at(requestId);

        return all_of(
            checks.begin(),
            checks.end(),
            [](const StatusCheck& check) {
                return check.status == CheckStatus::PASSED;
            }
        );
    }

    // --------------------------------------------------------
    // APPROVAL POLICY
    // --------------------------------------------------------

    void reviewRequest(
        const string& requestId,
        const string& approverId,
        Decision decision
    ) {
        auto& request = getRequest(requestId);
        auto& approver = getUser(approverId);

        if (request.status != RequestStatus::PENDING) {
            throw PAMException("Request is not pending.");
        }

        if (
            !approver.active ||
            (policy.requireMFA && !approver.mfaEnabled)
        ) {
            throw PAMException("Approver authentication failed.");
        }

        if (
            policy.prohibitSelfApproval &&
            request.requesterId == approverId
        ) {
            throw PAMException("Self-approval prohibited.");
        }

        if (!approver.roles.count("pam_approver")) {
            throw PAMException("Approver role required.");
        }

        if (decision == Decision::DENY) {
            request.status = RequestStatus::DENIED;
            request.approverId = approverId;

            audit(
                approverId,
                "ACCESS_REQUEST_DENIED",
                requestId,
                Severity::WARNING
            );

            return;
        }

        // Identity and group membership are rechecked
        // immediately before the approval decision.
        auto& user = getUser(request.requesterId);
        auto& account = getAccount(request.accountId);

        int maximum = validateEligibility(user, account);

        if (request.durationMinutes > maximum) {
            throw PAMException("Duration exceeds policy.");
        }

        request.status = RequestStatus::APPROVED;
        request.approverId = approverId;

        audit(
            approverId,
            "ACCESS_REQUEST_APPROVED",
            requestId
        );
    }

    // --------------------------------------------------------
    // FINAL MERGE-LIKE ELIGIBILITY DECISION
    // --------------------------------------------------------

    vector<string> evaluateMergeEligibility(
        const string& requestId
    ) {
        auto& request = getRequest(requestId);

        vector<string> failures;

        if (request.status != RequestStatus::APPROVED) {
            failures.push_back("Required approval missing.");
        }

        if (
            policy.requireAllChecksPassed &&
            !allChecksPassed(requestId)
        ) {
            failures.push_back("Required status checks incomplete.");
        }

        if (
            policy.minimumApprovals > 1
        ) {
            failures.push_back(
                "Configured multi-approval policy is not satisfied "
                "by this single-approval workflow."
            );
        }

        if (!vault.exists(request.accountId)) {
            failures.push_back("Credential vault unavailable.");
        }

        return failures;
    }

    // --------------------------------------------------------
    // JUST-IN-TIME SESSION CREATION
    // --------------------------------------------------------

    string startSession(const string& requestId) {

        auto& request = getRequest(requestId);

        if (request.status != RequestStatus::APPROVED) {
            throw PAMException("Approved request required.");
        }

        auto failures = evaluateMergeEligibility(requestId);

        if (!failures.empty()) {
            ostringstream message;

            message << "Access eligibility failed:";

            for (const auto& failure : failures) {
                message << "\n- " << failure;
            }

            throw PAMException(message.str());
        }

        auto& user = getUser(request.requesterId);
        auto& account = getAccount(request.accountId);

        int maximum = validateEligibility(user, account);

        if (request.durationMinutes > maximum) {
            throw PAMException("Session duration invalid.");
        }

        if (
            policy.prohibitConcurrentSessions &&
            hasActiveSession(user.id, account.id)
        ) {
            throw PAMException("Concurrent session detected.");
        }

        if (
            policy.requireSessionRecording &&
            !vault.exists(account.id)
        ) {
            throw PAMException("Session prerequisites unavailable.");
        }

        time_t start = now();

        PrivilegedSession session;

        session.id = generateId("SES");
        session.requestId = requestId;
        session.userId = user.id;
        session.accountId = account.id;
        session.startedAt = start;
        session.expiresAt =
            start + request.durationMinutes * 60;

        session.recorded = policy.requireSessionRecording;

        string sessionId = session.id;

        sessions.emplace(sessionId, move(session));

        request.status = RequestStatus::ACTIVE;

        audit(
            user.id,
            "SESSION_STARTED",
            sessionId
        );

        return sessionId;
    }

    // --------------------------------------------------------
    // CREDENTIAL ACCESS
    // --------------------------------------------------------

    string getCredentialReference(
        const string& sessionId,
        const string& userId
    ) {
        auto& session = getSession(sessionId);

        if (session.userId != userId) {
            throw PAMException("Session ownership violation.");
        }

        if (!session.active) {
            throw PAMException("Session inactive.");
        }

        if (session.expiresAt <= now()) {
            session.active = false;

            getRequest(session.requestId).status =
                RequestStatus::EXPIRED;

            throw PAMException("Session expired.");
        }

        auto& account = getAccount(session.accountId);

        if (account.status != AccountStatus::ACTIVE) {
            throw PAMException("Account unavailable.");
        }

        return vault.getReference(session.accountId);
    }

    // --------------------------------------------------------
    // SESSION REVOCATION
    // --------------------------------------------------------

    void revokeSession(
        const string& sessionId,
        const string& actorId
    ) {
        auto& session = getSession(sessionId);

        if (!session.active) {
            return;
        }

        session.active = false;

        getRequest(session.requestId).status =
            RequestStatus::REVOKED;

        audit(
            actorId,
            "SESSION_REVOKED",
            sessionId,
            Severity::CRITICAL
        );
    }

    void endSession(
        const string& sessionId,
        const string& actorId
    ) {
        auto& session = getSession(sessionId);

        if (!session.active) {
            return;
        }

        session.active = false;

        getRequest(session.requestId).status =
            RequestStatus::EXPIRED;

        audit(
            actorId,
            "SESSION_TERMINATED",
            sessionId
        );
    }

    // --------------------------------------------------------
    // ACCOUNT DISABLEMENT
    // --------------------------------------------------------

    void disableAccount(
        const string& accountId,
        const string& actorId
    ) {
        auto& account = getAccount(accountId);

        account.status = AccountStatus::DISABLED;

        for (auto& [id, session] : sessions) {
            if (
                session.accountId == accountId &&
                session.active
            ) {
                session.active = false;

                getRequest(session.requestId).status =
                    RequestStatus::REVOKED;
            }
        }

        audit(
            actorId,
            "ACCOUNT_DISABLED",
            accountId,
            Severity::CRITICAL
        );
    }

    // --------------------------------------------------------
    // CREDENTIAL ROTATION
    // --------------------------------------------------------

    void rotateCredential(
        const string& accountId,
        const string& newReference,
        const string& actorId
    ) {
        auto& account = getAccount(accountId);

        if (account.status != AccountStatus::ACTIVE) {
            throw PAMException("Account is not active.");
        }

        vault.rotate(accountId, newReference);
        account.lastRotated = now();

        audit(
            actorId,
            "CREDENTIAL_ROTATED",
            accountId,
            Severity::WARNING
        );
    }

    // --------------------------------------------------------
    // REPORTING
    // --------------------------------------------------------

    void printReport() const {

        int activeSessions = 0;
        int pendingRequests = 0;
        int criticalEvents = 0;

        for (const auto& [id, session] : sessions) {
            if (
                session.active &&
                session.expiresAt > now()
            ) {
                ++activeSessions;
            }
        }

        for (const auto& [id, request] : requests) {
            if (request.status == RequestStatus::PENDING) {
                ++pendingRequests;
            }
        }

        for (const auto& event : auditLog) {
            if (event.severity == Severity::CRITICAL) {
                ++criticalEvents;
            }
        }

        cout << "\n========== PAM REPORT ==========\n";
        cout << "Users: " << users.size() << '\n';
        cout << "Groups: " << groups.size() << '\n';
        cout << "Privileged accounts: " << accounts.size() << '\n';
        cout << "Access requests: " << requests.size() << '\n';
        cout << "Pending requests: " << pendingRequests << '\n';
        cout << "Active sessions: " << activeSessions << '\n';
        cout << "Audit events: " << auditLog.size() << '\n';
        cout << "Critical events: " << criticalEvents << '\n';
    }

    void printAuditLog() const {

        cout << "\n========== AUDIT LOG ==========\n";

        for (const auto& event : auditLog) {
            cout
                << event.actor << " | "
                << event.action << " | "
                << event.resource << '\n';
        }
    }
};


// ============================================================
// EXECUTABLE SCENARIO
// ============================================================

int main() {

    try {

        GovernancePolicy policy;

        policy.requireMFA = true;
        policy.requireApproval = true;
        policy.prohibitSelfApproval = true;
        policy.requireAllChecksPassed = true;
        policy.prohibitConcurrentSessions = true;
        policy.maximumSessionMinutes = 60;
        policy.minimumApprovals = 1;

        PAMEngine engine(policy);

        User operatorUser{
            "USR001",
            "database.operator",
            "Infrastructure",
            true,
            true,
            {"system_operator"}
        };

        User approver{
            "USR002",
            "security.approver",
            "Security",
            true,
            true,
            {"pam_approver"}
        };

        engine.registerUser(operatorUser);
        engine.registerUser(approver);

        PrivilegedGroup group;

        group.id = "GRP001";
        group.name = "Production DBA";
        group.privilege = Privilege::ADMIN;
        group.approvalRequired = true;
        group.maximumSessionMinutes = 45;

        engine.createGroup(group);
        engine.addMember("GRP001", "USR001");

        PrivilegedAccount account;

        account.id = "ACC001";
        account.username = "production_dba";
        account.system = "production-postgresql";
        account.privilege = Privilege::ADMIN;
        account.groupIds = {"GRP001"};
        account.rotationIntervalDays = 30;

        // This is an opaque reference, not a real password.
        engine.registerAccount(
            account,
            "vault-reference-production-001"
        );

        cout << "PRIVILEGED ACCESS REQUEST\n";

        string requestId = engine.requestAccess(
            "USR001",
            "ACC001",
            "Production database incident investigation",
            30
        );

        cout << "Request: " << requestId << '\n';

        // Simulate automated identity and security checks.
        engine.updateStatusCheck(
            requestId,
            "identity",
            CheckStatus::PASSED
        );

        engine.reviewRequest(
            requestId,
            "USR002",
            Decision::APPROVE
        );

        cout << "Approval recorded.\n";

        // A failed automated check blocks session creation.
        engine.updateStatusCheck(
            requestId,
            "credential_availability",
            CheckStatus::FAILED
        );

        try {
            engine.startSession(requestId);
        } catch (const PAMException& error) {
            cout << "\nEXPECTED ELIGIBILITY FAILURE:\n";
            cout << error.what() << '\n';
        }

        // Restore the required status check.
        engine.updateStatusCheck(
            requestId,
            "credential_availability",
            CheckStatus::PASSED
        );

        string sessionId = engine.startSession(requestId);

        cout << "\nSESSION CREATED: " << sessionId << '\n';

        string reference = engine.getCredentialReference(
            sessionId,
            "USR001"
        );

        cout << "Credential reference: " << reference << '\n';

        // Another user cannot access the session.
        try {
            engine.getCredentialReference(
                sessionId,
                "USR002"
            );
        } catch (const PAMException& error) {
            cout << "\nEXPECTED OWNERSHIP DENIAL: "
                 << error.what() << '\n';
        }

        engine.endSession(sessionId, "USR001");

        engine.printReport();
        engine.printAuditLog();

        return 0;

    } catch (const exception& error) {

        cerr << "PAM ENGINE FAILURE: "
             << error.what() << '\n';

        return 1;
    }
}
