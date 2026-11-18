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
#include <vector>

using namespace std;

using Clock = chrono::system_clock;
using TimePoint = Clock::time_point;

// =========================================================
// Domain types
// =========================================================

enum class Decision {
    ALLOW,
    DENY,
    REVOKE
};

enum class TrustLevel {
    UNTRUSTED = 0,
    VERIFIED = 1,
    HIGH = 2
};

enum class ResourceZone {
    PUBLIC,
    INTERNAL,
    RESTRICTED,
    CRITICAL
};

enum class Action {
    READ,
    WRITE,
    DELETE_RESOURCE,
    ADMIN
};

enum class SessionState {
    ACTIVE,
    REVOKED,
    EXPIRED
};

string toString(Decision value) {
    switch (value) {
        case Decision::ALLOW: return "ALLOW";
        case Decision::DENY: return "DENY";
        case Decision::REVOKE: return "REVOKE";
    }
    return "UNKNOWN";
}

string toString(TrustLevel value) {
    switch (value) {
        case TrustLevel::UNTRUSTED: return "UNTRUSTED";
        case TrustLevel::VERIFIED: return "VERIFIED";
        case TrustLevel::HIGH: return "HIGH";
    }
    return "UNKNOWN";
}

// =========================================================
// Exceptions
// =========================================================

class SecurityException : public runtime_error {
public:
    explicit SecurityException(const string& message)
        : runtime_error(message) {}
};

class ValidationException : public SecurityException {
public:
    using SecurityException::SecurityException;
};

class AuthenticationException : public SecurityException {
public:
    using SecurityException::SecurityException;
};

class AuthorizationException : public SecurityException {
public:
    using SecurityException::SecurityException;
};

// =========================================================
// Identity and device domain
// =========================================================

struct Identity {
    string id;
    string username;
    set<string> roles;
    bool enabled;
    bool mfaVerified;
};

struct Device {
    string id;
    string ownerId;

    bool managed;
    bool encrypted;
    bool patched;
    bool endpointProtected;

    int riskScore;
    uint64_t version;

    bool compliant() const {
        return managed &&
               encrypted &&
               patched &&
               endpointProtected &&
               riskScore <= 30;
    }
};

struct Resource {
    string id;
    string name;
    ResourceZone zone;

    set<string> allowedRoles;
    set<Action> allowedActions;

    TrustLevel minimumTrust;
    bool requireMFA;
};

struct AccessContext {
    string sourceIP;
    string networkZone;
    Action action;
    int riskScore;
    TimePoint timestamp;
};

struct Evaluation {
    bool allowed;
    string reason;
    TrustLevel trust;
};

// =========================================================
// Input validation
// =========================================================

void validateRisk(int score) {
    if (score < 0 || score > 100) {
        throw ValidationException(
            "Risk score must be between 0 and 100."
        );
    }
}

void validateIdentifier(const string& value) {
    if (value.empty() || value.size() > 100) {
        throw ValidationException("Invalid identifier.");
    }

    if (value.find_first_of("\r\n\t") != string::npos) {
        throw ValidationException("Invalid identifier characters.");
    }
}

// =========================================================
// Identity repository
// =========================================================

class IdentityRepository {

private:
    map<string, Identity> identities;

public:
    void add(const Identity& identity) {
        validateIdentifier(identity.id);
        validateIdentifier(identity.username);

        if (identity.roles.empty()) {
            throw ValidationException("Identity requires a role.");
        }

        if (identities.count(identity.id)) {
            throw ValidationException("Duplicate identity.");
        }

        identities.emplace(identity.id, identity);
    }

    const Identity& authenticate(const string& id) const {
        auto it = identities.find(id);

        if (it == identities.end() || !it->second.enabled) {
            throw AuthenticationException(
                "Identity authentication failed."
            );
        }

        return it->second;
    }
};

// =========================================================
// Device inventory and posture management
// =========================================================

class DeviceRepository {

private:
    map<string, Device> devices;

public:
    void add(const Device& device) {
        validateIdentifier(device.id);
        validateIdentifier(device.ownerId);
        validateRisk(device.riskScore);

        if (devices.count(device.id)) {
            throw ValidationException("Duplicate device.");
        }

        devices.emplace(device.id, device);
    }

    const Device& get(const string& id) const {
        auto it = devices.find(id);

        if (it == devices.end()) {
            throw AuthenticationException("Unknown device.");
        }

        return it->second;
    }

    void updateRisk(const string& id, int risk) {
        validateRisk(risk);

        auto it = devices.find(id);

        if (it == devices.end()) {
            throw ValidationException("Unknown device.");
        }

        it->second.riskScore = risk;
        ++it->second.version;
    }

    TrustLevel evaluate(
        const Device& device,
        const Identity& identity
    ) const {

        if (device.ownerId != identity.id || !device.compliant()) {
            return TrustLevel::UNTRUSTED;
        }

        if (identity.mfaVerified && device.riskScore <= 10) {
            return TrustLevel::HIGH;
        }

        return TrustLevel::VERIFIED;
    }
};

// =========================================================
// Resource segmentation registry
// =========================================================

class ResourceRepository {

private:
    map<string, Resource> resources;

public:
    void add(const Resource& resource) {
        validateIdentifier(resource.id);

        if (resource.allowedRoles.empty() ||
            resource.allowedActions.empty()) {
            throw ValidationException(
                "Resource requires roles and actions."
            );
        }

        if (resources.count(resource.id)) {
            throw ValidationException("Duplicate resource.");
        }

        resources.emplace(resource.id, resource);
    }

    const Resource& get(const string& id) const {
        auto it = resources.find(id);

        if (it == resources.end()) {
            throw AuthorizationException("Resource not found.");
        }

        return it->second;
    }
};

// =========================================================
// Access policy engine
// =========================================================

class PolicyEngine {

private:
    const DeviceRepository& devices;

public:
    explicit PolicyEngine(const DeviceRepository& repository)
        : devices(repository) {}

    Evaluation evaluate(
        const Identity& identity,
        const Device& device,
        const Resource& resource,
        const AccessContext& context
    ) const {

        validateRisk(context.riskScore);

        if (!identity.enabled) {
            return {false, "Identity disabled.", TrustLevel::UNTRUSTED};
        }

        if (!device.compliant()) {
            return {
                false,
                "Device posture is noncompliant.",
                TrustLevel::UNTRUSTED
            };
        }

        if (resource.requireMFA && !identity.mfaVerified) {
            return {
                false,
                "MFA required.",
                TrustLevel::UNTRUSTED
            };
        }

        bool authorizedRole = any_of(
            identity.roles.begin(),
            identity.roles.end(),
            [&](const string& role) {
                return resource.allowedRoles.count(role) > 0;
            }
        );

        if (!authorizedRole) {
            return {
                false,
                "Role is not authorized.",
                TrustLevel::UNTRUSTED
            };
        }

        if (!resource.allowedActions.count(context.action)) {
            return {
                false,
                "Requested action is prohibited.",
                TrustLevel::UNTRUSTED
            };
        }

        if (context.riskScore >= 80) {
            return {
                false,
                "Contextual risk threshold exceeded.",
                TrustLevel::UNTRUSTED
            };
        }

        TrustLevel trust = devices.evaluate(device, identity);

        if (static_cast<int>(trust) <
            static_cast<int>(resource.minimumTrust)) {
            return {
                false,
                "Insufficient device trust.",
                trust
            };
        }

        if (resource.zone == ResourceZone::RESTRICTED) {
            if (context.networkZone != "CORPORATE" &&
                context.networkZone != "VPN") {
                return {
                    false,
                    "Restricted resource network violation.",
                    trust
                };
            }
        }

        if (resource.zone == ResourceZone::CRITICAL) {
            if (context.networkZone != "CORPORATE" ||
                context.riskScore > 10 ||
                trust != TrustLevel::HIGH) {
                return {
                    false,
                    "Critical resource policy failed.",
                    trust
                };
            }
        }

        return {
            true,
            "All access policies satisfied.",
            trust
        };
    }
};

// =========================================================
// Audit records
// =========================================================

struct AuditEvent {
    uint64_t sequence;
    TimePoint timestamp;

    string userId;
    string resourceId;
    string reason;

    Decision decision;
    optional<string> sessionId;
};

class AuditRepository {

private:
    vector<AuditEvent> events;
    uint64_t nextSequence = 1;

public:
    void append(
        const string& userId,
        const string& resourceId,
        Decision decision,
        const string& reason,
        optional<string> sessionId = nullopt
    ) {
        events.push_back({
            nextSequence++,
            Clock::now(),
            userId,
            resourceId,
            reason,
            decision,
            sessionId
        });
    }

    void report() const {
        cout << "\nSECURITY AUDIT\n";

        for (const auto& event : events) {
            cout << event.sequence
                 << " | " << event.userId
                 << " | " << event.resourceId
                 << " | " << toString(event.decision)
                 << " | " << event.reason
                 << '\n';
        }
    }

    size_t size() const {
        return events.size();
    }
};

// =========================================================
// Session lifecycle
// =========================================================

struct SecuritySession {
    string id;
    string userId;
    string deviceId;
    string resourceId;

    uint64_t deviceVersion;

    TimePoint issuedAt;
    TimePoint expiresAt;
    TimePoint lastEvaluated;

    SessionState state;
};

class SessionRepository {

private:
    map<string, SecuritySession> sessions;
    chrono::minutes lifetime{15};

    static string generateId() {
        static uint64_t sequence = 0;
        ++sequence;

        ostringstream out;
        out << "ZT-" << hex << sequence
            << "-" << Clock::now().time_since_epoch().count();

        return out.str();
    }

public:
    SecuritySession create(
        const Identity& identity,
        const Device& device,
        const Resource& resource,
        TimePoint now
    ) {
        SecuritySession session{
            generateId(),
            identity.id,
            device.id,
            resource.id,
            device.version,
            now,
            now + lifetime,
            now,
            SessionState::ACTIVE
        };

        sessions.emplace(session.id, session);
        return session;
    }

    SecuritySession& getActive(
        const string& id,
        TimePoint now
    ) {
        auto it = sessions.find(id);

        if (it == sessions.end()) {
            throw SecurityException("Unknown session.");
        }

        SecuritySession& session = it->second;

        if (session.state != SessionState::ACTIVE) {
            throw SecurityException("Session is not active.");
        }

        if (now >= session.expiresAt) {
            session.state = SessionState::EXPIRED;
            throw SecurityException("Session expired.");
        }

        return session;
    }

    void revoke(const string& id) {
        auto it = sessions.find(id);

        if (it == sessions.end()) {
            throw SecurityException("Unknown session.");
        }

        it->second.state = SessionState::REVOKED;
    }

    size_t activeCount() const {
        return count_if(
            sessions.begin(),
            sessions.end(),
            [](const auto& entry) {
                return entry.second.state == SessionState::ACTIVE;
            }
        );
    }
};

// =========================================================
// Repository governance and authorization service
// =========================================================

class ZeroTrustEngine {

private:
    IdentityRepository identities;
    DeviceRepository devices;
    ResourceRepository resources;
    SessionRepository sessions;
    AuditRepository audit;

    PolicyEngine policy;

public:
    ZeroTrustEngine()
        : policy(devices) {}

    IdentityRepository& identityRegistry() {
        return identities;
    }

    DeviceRepository& deviceRegistry() {
        return devices;
    }

    ResourceRepository& resourceRegistry() {
        return resources;
    }

    optional<SecuritySession> requestAccess(
        const string& userId,
        const string& deviceId,
        const string& resourceId,
        const AccessContext& context
    ) {
        try {
            const auto& identity = identities.authenticate(userId);
            const auto& device = devices.get(deviceId);
            const auto& resource = resources.get(resourceId);

            Evaluation result = policy.evaluate(
                identity,
                device,
                resource,
                context
            );

            if (!result.allowed) {
                audit.append(
                    userId,
                    resourceId,
                    Decision::DENY,
                    result.reason
                );

                return nullopt;
            }

            auto session = sessions.create(
                identity,
                device,
                resource,
                context.timestamp
            );

            audit.append(
                userId,
                resourceId,
                Decision::ALLOW,
                result.reason,
                session.id
            );

            return session;

        } catch (const SecurityException& error) {
            audit.append(
                userId,
                resourceId,
                Decision::DENY,
                error.what()
            );

            return nullopt;
        }
    }

    Decision continuouslyEvaluate(
        const string& sessionId,
        const AccessContext& context
    ) {
        try {
            auto& session = sessions.getActive(
                sessionId,
                context.timestamp
            );

            const auto& identity = identities.authenticate(session.userId);
            const auto& device = devices.get(session.deviceId);
            const auto& resource = resources.get(session.resourceId);

            Evaluation result = policy.evaluate(
                identity,
                device,
                resource,
                context
            );

            // A device posture version change requires a new session.
            if (!result.allowed ||
                device.version != session.deviceVersion) {

                sessions.revoke(sessionId);

                audit.append(
                    identity.id,
                    resource.id,
                    Decision::REVOKE,
                    result.allowed
                        ? "Device posture changed."
                        : result.reason,
                    sessionId
                );

                return Decision::REVOKE;
            }

            session.lastEvaluated = context.timestamp;

            audit.append(
                identity.id,
                resource.id,
                Decision::ALLOW,
                "Continuous evaluation passed.",
                sessionId
            );

            return Decision::ALLOW;

        } catch (const SecurityException& error) {
            try {
                sessions.revoke(sessionId);
            } catch (...) {
                // The session may already be expired or revoked.
            }

            audit.append(
                "SYSTEM",
                "UNKNOWN",
                Decision::REVOKE,
                error.what(),
                sessionId
            );

            return Decision::REVOKE;
        }
    }

    void printReport() const {
        audit.report();

        cout << "\nActive sessions: "
             << sessions.activeCount() << '\n';

        cout << "Audit events: "
             << audit.size() << '\n';
    }
};

// =========================================================
// Executable scenario
// =========================================================

int main() {
    try {
        ZeroTrustEngine engine;

        engine.identityRegistry().add({
            "USR-100",
            "security-analyst",
            {"SECURITY_ANALYST"},
            true,
            true
        });

        engine.deviceRegistry().add({
            "DEV-100",
            "USR-100",
            true,
            true,
            true,
            true,
            5,
            1
        });

        engine.resourceRegistry().add({
            "RES-100",
            "Security Operations Dashboard",
            ResourceZone::RESTRICTED,
            {"SECURITY_ANALYST"},
            {Action::READ},
            TrustLevel::VERIFIED,
            true
        });

        engine.resourceRegistry().add({
            "RES-200",
            "Production Administration",
            ResourceZone::CRITICAL,
            {"SECURITY_ADMIN"},
            {Action::ADMIN},
            TrustLevel::HIGH,
            true
        });

        const auto now = Clock::now();

        AccessContext context{
            "10.0.0.10",
            "VPN",
            Action::READ,
            5,
            now
        };

        cout << "ZERO TRUST GOVERNANCE ENGINE\n";
        cout << "============================\n";

        auto session = engine.requestAccess(
            "USR-100",
            "DEV-100",
            "RES-100",
            context
        );

        if (!session) {
            throw SecurityException("Expected access to be allowed.");
        }

        cout << "Initial access: ALLOW\n";
        cout << "Session: " << session->id << '\n';

        // Continuous evaluation detects changed device posture.
        engine.deviceRegistry().updateRisk("DEV-100", 95);

        Decision result = engine.continuouslyEvaluate(
            session->id,
            AccessContext{
                "10.0.0.10",
                "VPN",
                Action::READ,
                5,
                now + chrono::minutes(2)
            }
        );

        cout << "Continuous evaluation: "
             << toString(result) << '\n';

        if (result != Decision::REVOKE) {
            throw SecurityException("Expected session revocation.");
        }

        auto denied = engine.requestAccess(
            "USR-100",
            "DEV-100",
            "RES-100",
            context
        );

        cout << "Noncompliant device access: "
             << (denied ? "ALLOW" : "DENY") << '\n';

        if (denied) {
            throw SecurityException("Expected denial.");
        }

        engine.printReport();

        cout << "\nAll governance tests passed.\n";

        return 0;

    } catch (const exception& error) {
        cerr << "Security engine error: "
             << error.what() << '\n';

        return 1;
    }
}
