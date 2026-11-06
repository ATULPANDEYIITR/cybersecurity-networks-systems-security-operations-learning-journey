#include <algorithm>
#include <cassert>
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
#include <random>

using namespace std;

using Clock = chrono::system_clock;
using TimePoint = Clock::time_point;
using Days = chrono::hours;

enum class CertificateType {
    ROOT,
    INTERMEDIATE,
    END_ENTITY
};

enum class CertificateStatus {
    ACTIVE,
    EXPIRED,
    REVOKED,
    NOT_YET_VALID
};

enum class RevocationReason {
    KEY_COMPROMISE,
    CA_COMPROMISE,
    SUPERSEDED,
    CESSATION_OF_OPERATION,
    PRIVILEGE_WITHDRAWN
};

string toString(CertificateType type) {
    switch (type) {
        case CertificateType::ROOT: return "ROOT";
        case CertificateType::INTERMEDIATE: return "INTERMEDIATE";
        case CertificateType::END_ENTITY: return "END_ENTITY";
    }
    return "UNKNOWN";
}

string toString(CertificateStatus status) {
    switch (status) {
        case CertificateStatus::ACTIVE: return "ACTIVE";
        case CertificateStatus::EXPIRED: return "EXPIRED";
        case CertificateStatus::REVOKED: return "REVOKED";
        case CertificateStatus::NOT_YET_VALID: return "NOT_YET_VALID";
    }
    return "UNKNOWN";
}

string toString(RevocationReason reason) {
    switch (reason) {
        case RevocationReason::KEY_COMPROMISE: return "KEY_COMPROMISE";
        case RevocationReason::CA_COMPROMISE: return "CA_COMPROMISE";
        case RevocationReason::SUPERSEDED: return "SUPERSEDED";
        case RevocationReason::CESSATION_OF_OPERATION:
            return "CESSATION_OF_OPERATION";
        case RevocationReason::PRIVILEGE_WITHDRAWN:
            return "PRIVILEGE_WITHDRAWN";
    }
    return "UNKNOWN";
}

class PKIException : public runtime_error {
public:
    explicit PKIException(const string& message)
        : runtime_error(message) {}
};

struct Certificate {
    string id;
    string serial;
    string subject;
    optional<string> issuerId;

    CertificateType type;

    TimePoint notBefore;
    TimePoint notAfter;

    bool isCA;
    optional<int> pathLength;

    set<string> keyUsage;

    string subjectKeyId;
    optional<string> authorityKeyId;

    optional<TimePoint> revokedAt;
    optional<RevocationReason> revocationReason;
    optional<string> replacementId;

    CertificateStatus status(TimePoint now) const {
        if (revokedAt.has_value()) {
            return CertificateStatus::REVOKED;
        }

        if (now < notBefore) {
            return CertificateStatus::NOT_YET_VALID;
        }

        if (now >= notAfter) {
            return CertificateStatus::EXPIRED;
        }

        return CertificateStatus::ACTIVE;
    }
};

struct CertificateAuthority {
    string certificateId;
    int maximumValidityDays;
    bool active = true;
    set<string> issuedCertificates;
};

struct AuditEvent {
    TimePoint timestamp;
    string action;
    string certificateId;
    string details;
};

struct ValidationResult {
    bool valid;
    string message;
    vector<string> chain;
};

class PKIManager {
private:
    map<string, Certificate> certificates;
    map<string, CertificateAuthority> authorities;
    set<string> trustAnchors;
    map<string, RevocationReason> revocations;
    vector<AuditEvent> auditLog;

    mt19937_64 generator{random_device{}()};

    string randomHex(size_t length = 32) {
        static const string chars = "0123456789ABCDEF";

        uniform_int_distribution<int> distribution(0, 15);

        string result;

        for (size_t i = 0; i < length; ++i) {
            result += chars[distribution(generator)];
        }

        return result;
    }

    string generateId(const string& prefix) {
        return prefix + "-" + randomHex(12);
    }

    static string makeKeyId(
        const string& subject,
        const string& serial
    ) {
        /*
         * This deterministic identifier is only a simulation.
         * A production CA derives key identifiers from actual public keys.
         */
        return subject + "|" + serial;
    }

    void record(
        const string& action,
        const string& certificateId,
        const string& details
    ) {
        auditLog.push_back({
            Clock::now(),
            action,
            certificateId,
            details
        });
    }

    void registerCertificate(const Certificate& certificate) {
        if (certificates.count(certificate.id)) {
            throw PKIException("Duplicate certificate identifier.");
        }

        certificates.emplace(certificate.id, certificate);
    }

    CertificateAuthority& getAuthority(const string& id) {
        auto it = authorities.find(id);

        if (it == authorities.end() || !it->second.active) {
            throw PKIException("Unknown or inactive CA.");
        }

        return it->second;
    }

    void validateCA(
        const Certificate& certificate,
        TimePoint now
    ) const {
        if (!certificate.isCA) {
            throw PKIException("Certificate is not a CA.");
        }

        if (certificate.status(now) != CertificateStatus::ACTIVE) {
            throw PKIException("CA certificate is not valid.");
        }

        if (!certificate.keyUsage.count("keyCertSign")) {
            throw PKIException("CA cannot sign certificates.");
        }
    }

public:
    Certificate createRootCA(
        const string& subject,
        int validityDays = 3650,
        int pathLength = 2
    ) {
        if (subject.empty() || validityDays <= 0 || pathLength < 0) {
            throw PKIException("Invalid root CA configuration.");
        }

        TimePoint now = Clock::now();
        string serial = randomHex();
        string id = generateId("ROOT");

        Certificate cert{
            id,
            serial,
            subject,
            nullopt,
            CertificateType::ROOT,
            now,
            now + chrono::hours(24 * validityDays),
            true,
            pathLength,
            {"keyCertSign", "cRLSign"},
            makeKeyId(subject, serial),
            nullopt,
            nullopt,
            nullopt,
            nullopt
        };

        registerCertificate(cert);

        authorities.emplace(
            id,
            CertificateAuthority{id, validityDays, true, {}}
        );

        trustAnchors.insert(id);

        record("ROOT_CREATED", id, subject);

        return cert;
    }

    Certificate createIntermediateCA(
        const string& parentId,
        const string& subject,
        int validityDays = 730,
        int pathLength = 0
    ) {
        auto& parentAuthority = getAuthority(parentId);
        const Certificate& parent = certificates.at(parentId);

        validateCA(parent, Clock::now());

        if (subject.empty() || validityDays <= 0 || pathLength < 0) {
            throw PKIException("Invalid intermediate configuration.");
        }

        if (
            parent.pathLength.has_value() &&
            *parent.pathLength <= 0
        ) {
            throw PKIException("Parent path length exceeded.");
        }

        TimePoint now = Clock::now();

        TimePoint expiry = min(
            now + chrono::hours(24 * validityDays),
            parent.notAfter
        );

        if (expiry <= now) {
            throw PKIException("Parent CA expires too soon.");
        }

        string serial = randomHex();
        string id = generateId("INT");

        Certificate cert{
            id,
            serial,
            subject,
            parentId,
            CertificateType::INTERMEDIATE,
            now,
            expiry,
            true,
            pathLength,
            {"keyCertSign", "cRLSign"},
            makeKeyId(subject, serial),
            parent.subjectKeyId,
            nullopt,
            nullopt,
            nullopt
        };

        registerCertificate(cert);

        authorities.emplace(
            id,
            CertificateAuthority{id, validityDays, true, {}}
        );

        parentAuthority.issuedCertificates.insert(id);

        record("INTERMEDIATE_CREATED", id, parentId);

        return cert;
    }

    Certificate issueCertificate(
        const string& issuerId,
        const string& subject,
        int validityDays,
        const set<string>& usage
    ) {
        auto& issuer = getAuthority(issuerId);
        const Certificate& parent = certificates.at(issuerId);

        validateCA(parent, Clock::now());

        if (subject.empty() || validityDays <= 0) {
            throw PKIException("Invalid certificate request.");
        }

        if (validityDays > issuer.maximumValidityDays) {
            throw PKIException("Maximum validity exceeded.");
        }

        const set<string> allowed{
            "digitalSignature",
            "keyEncipherment",
            "keyAgreement",
            "dataEncipherment",
            "contentCommitment"
        };

        if (usage.empty()) {
            throw PKIException("Key usage cannot be empty.");
        }

        for (const auto& item : usage) {
            if (!allowed.count(item)) {
                throw PKIException("Invalid end-entity key usage.");
            }
        }

        TimePoint now = Clock::now();

        TimePoint expiry = min(
            now + chrono::hours(24 * validityDays),
            parent.notAfter
        );

        if (expiry <= now) {
            throw PKIException("Issuer expires too soon.");
        }

        string serial = randomHex();
        string id = generateId("LEAF");

        Certificate cert{
            id,
            serial,
            subject,
            issuerId,
            CertificateType::END_ENTITY,
            now,
            expiry,
            false,
            nullopt,
            usage,
            makeKeyId(subject, serial),
            parent.subjectKeyId,
            nullopt,
            nullopt,
            nullopt
        };

        registerCertificate(cert);
        issuer.issuedCertificates.insert(id);

        record("CERTIFICATE_ISSUED", id, issuerId);

        return cert;
    }

    vector<Certificate> buildChain(const string& id) const {
        auto it = certificates.find(id);

        if (it == certificates.end()) {
            throw PKIException("Certificate not found.");
        }

        vector<Certificate> chain;
        set<string> visited;

        const Certificate* current = &it->second;

        while (current != nullptr) {
            if (!visited.insert(current->id).second) {
                throw PKIException("Certificate chain cycle detected.");
            }

            chain.push_back(*current);

            if (!current->issuerId.has_value()) {
                break;
            }

            auto parent = certificates.find(*current->issuerId);

            if (parent == certificates.end()) {
                throw PKIException("Issuer certificate missing.");
            }

            if (
                !current->authorityKeyId.has_value() ||
                *current->authorityKeyId != parent->second.subjectKeyId
            ) {
                throw PKIException("Authority key identifier mismatch.");
            }

            current = &parent->second;
        }

        return chain;
    }

    ValidationResult validate(
        const string& id,
        TimePoint now = Clock::now()
    ) const {
        try {
            vector<Certificate> chain = buildChain(id);

            if (!trustAnchors.count(chain.back().id)) {
                throw PKIException("Root is not trusted.");
            }

            for (size_t i = 0; i < chain.size(); ++i) {
                const Certificate& cert = chain[i];

                if (cert.status(now) != CertificateStatus::ACTIVE) {
                    throw PKIException(
                        cert.id + " is " +
                        toString(cert.status(now))
                    );
                }

                if (i > 0) {
                    const Certificate& parent = chain[i - 1];

                    if (cert.issuerId != parent.id) {
                        throw PKIException("Issuer relationship mismatch.");
                    }

                    if (
                        cert.isCA &&
                        !cert.keyUsage.count("keyCertSign")
                    ) {
                        throw PKIException("Invalid CA key usage.");
                    }

                    if (parent.pathLength.has_value()) {
                        int subordinateCAs = 0;

                        for (size_t j = 0; j < i; ++j) {
                            if (chain[j].isCA) {
                                ++subordinateCAs;
                            }
                        }

                        if (subordinateCAs > *parent.pathLength) {
                            throw PKIException("Path length exceeded.");
                        }
                    }
                }
            }

            vector<string> identifiers;

            for (const auto& cert : chain) {
                identifiers.push_back(cert.id);
            }

            return {
                true,
                "Structurally trusted certificate chain.",
                identifiers
            };

        } catch (const exception& error) {
            return {false, error.what(), {}};
        }
    }

    void revoke(
        const string& id,
        RevocationReason reason
    ) {
        auto it = certificates.find(id);

        if (it == certificates.end()) {
            throw PKIException("Certificate not found.");
        }

        Certificate& cert = it->second;

        if (cert.revokedAt.has_value()) {
            throw PKIException("Certificate already revoked.");
        }

        cert.revokedAt = Clock::now();
        cert.revocationReason = reason;

        revocations[id] = reason;

        if (cert.isCA) {
            auto authority = authorities.find(id);

            if (authority != authorities.end()) {
                authority->second.active = false;
            }
        }

        record("CERTIFICATE_REVOKED", id, toString(reason));
    }

    Certificate renew(
        const string& id,
        int validityDays
    ) {
        auto it = certificates.find(id);

        if (it == certificates.end()) {
            throw PKIException("Certificate not found.");
        }

        const Certificate& old = it->second;

        if (old.type != CertificateType::END_ENTITY) {
            throw PKIException("Only end-entity certificates can be renewed.");
        }

        if (old.status(Clock::now()) == CertificateStatus::REVOKED) {
            throw PKIException("Revoked certificate cannot be renewed.");
        }

        Certificate replacement = issueCertificate(
            *old.issuerId,
            old.subject,
            validityDays,
            old.keyUsage
        );

        certificates.at(id).replacementId = replacement.id;

        record("CERTIFICATE_RENEWED", id, replacement.id);

        return replacement;
    }

    void printInventory() const {
        cout << "\nCERTIFICATE INVENTORY\n";

        for (const auto& [id, cert] : certificates) {
            cout << left << setw(25) << id
                 << setw(15) << toString(cert.type)
                 << setw(35) << cert.subject
                 << toString(cert.status(Clock::now()))
                 << '\n';
        }
    }

    void printAudit() const {
        cout << "\nAUDIT LOG\n";

        for (const auto& event : auditLog) {
            time_t timestamp = Clock::to_time_t(event.timestamp);

            cout << put_time(gmtime(&timestamp), "%Y-%m-%d %H:%M:%S")
                 << " UTC "
                 << event.action << " "
                 << event.certificateId << " "
                 << event.details << '\n';
        }
    }

    size_t certificateCount() const {
        return certificates.size();
    }

    size_t auditCount() const {
        return auditLog.size();
    }
};

int main() {
    try {
        cout << "PUBLIC KEY INFRASTRUCTURE GOVERNANCE ENGINE\n";

        PKIManager pki;

        Certificate root = pki.createRootCA(
            "CN=Enterprise Root CA",
            3650,
            2
        );

        Certificate intermediate = pki.createIntermediateCA(
            root.id,
            "CN=Enterprise Issuing CA",
            730,
            0
        );

        Certificate server = pki.issueCertificate(
            intermediate.id,
            "DNS=api.example.com",
            90,
            {"digitalSignature", "keyEncipherment"}
        );

        Certificate client = pki.issueCertificate(
            intermediate.id,
            "CN=application-client",
            60,
            {"digitalSignature"}
        );

        cout << "\nISSUANCE\n";
        cout << "Root: " << root.id << '\n';
        cout << "Intermediate: " << intermediate.id << '\n';
        cout << "Server: " << server.id << '\n';
        cout << "Client: " << client.id << '\n';

        ValidationResult result = pki.validate(server.id);

        cout << "\nSERVER VALIDATION: "
             << boolalpha << result.valid
             << " " << result.message << '\n';

        cout << "\nCERTIFICATE CHAIN\n";

        for (const auto& id : result.chain) {
            cout << id << '\n';
        }

        Certificate replacement = pki.renew(server.id, 120);

        cout << "\nRENEWAL\n";
        cout << "Old: " << server.id << '\n';
        cout << "New: " << replacement.id << '\n';

        pki.revoke(
            client.id,
            RevocationReason::KEY_COMPROMISE
        );

        result = pki.validate(client.id);

        cout << "\nREVOKED CLIENT: "
             << result.valid << " "
             << result.message << '\n';

        cout << "\nEDGE CASES\n";

        try {
            pki.issueCertificate(
                intermediate.id,
                "CN=invalid",
                5000,
                {"digitalSignature"}
            );
        } catch (const exception& error) {
            cout << "Expected failure: " << error.what() << '\n';
        }

        try {
            pki.revoke(
                client.id,
                RevocationReason::KEY_COMPROMISE
            );
        } catch (const exception& error) {
            cout << "Expected failure: " << error.what() << '\n';
        }

        assert(pki.validate(root.id).valid);
        assert(pki.validate(replacement.id).valid);
        assert(!pki.validate(client.id).valid);

        pki.printInventory();
        pki.printAudit();

        cout << "\nCertificates registered: "
             << pki.certificateCount() << '\n';

        cout << "Audit events: " << pki.auditCount() << '\n';

        cout << "\nAll PKI validation tests passed.\n";

    } catch (const exception& error) {
        cerr << "PKI error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
