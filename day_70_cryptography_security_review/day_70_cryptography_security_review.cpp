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
#include <unordered_map>
#include <unordered_set>

using namespace std;

/*
 * Cryptography Security Review
 *
 * C++17 cryptographic configuration assessment engine.
 *
 * Implements:
 * - Algorithm security evaluation
 * - Encryption mode inspection
 * - Key lifecycle analysis
 * - Certificate metadata validation
 * - TLS policy evaluation
 * - Risk aggregation
 * - Finding state transitions
 * - Repository-independent security governance
 *
 * No external dependencies.
 */


// ========================================================
// ENUMERATIONS
// ========================================================

enum class Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational
};

enum class FindingStatus {
    Open,
    InReview,
    Remediated,
    AcceptedRisk,
    FalsePositive
};

enum class Category {
    WeakAlgorithm,
    KeyManagement,
    KeyExposure,
    Certificate,
    TLS,
    Randomness,
    Configuration
};


// ========================================================
// STRING CONVERSION
// ========================================================

string toString(Severity severity) {
    switch (severity) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
        case Severity::Informational: return "INFORMATIONAL";
    }

    throw runtime_error("Unknown severity.");
}

string toString(FindingStatus status) {
    switch (status) {
        case FindingStatus::Open: return "OPEN";
        case FindingStatus::InReview: return "IN_REVIEW";
        case FindingStatus::Remediated: return "REMEDIATED";
        case FindingStatus::AcceptedRisk: return "ACCEPTED_RISK";
        case FindingStatus::FalsePositive: return "FALSE_POSITIVE";
    }

    throw runtime_error("Unknown status.");
}

string toString(Category category) {
    switch (category) {
        case Category::WeakAlgorithm: return "WEAK_ALGORITHM";
        case Category::KeyManagement: return "KEY_MANAGEMENT";
        case Category::KeyExposure: return "KEY_EXPOSURE";
        case Category::Certificate: return "CERTIFICATE";
        case Category::TLS: return "TLS";
        case Category::Randomness: return "RANDOMNESS";
        case Category::Configuration: return "CONFIGURATION";
    }

    throw runtime_error("Unknown category.");
}


// ========================================================
// VALIDATION UTILITIES
// ========================================================

void requireNonEmpty(const string& value, const string& field) {
    if (value.empty()) {
        throw invalid_argument(field + " cannot be empty.");
    }
}

string uppercase(string value) {
    transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](unsigned char c) {
            return static_cast<char>(toupper(c));
        }
    );

    return value;
}


// ========================================================
// DOMAIN MODELS
// ========================================================

struct CryptoAsset {
    string id;
    string name;
    string algorithm;
    string purpose;

    optional<int> keyBits;
    string mode;
    optional<bool> authenticated;
    string tlsVersion;
    string randomnessSource;

    void validate() const {
        requireNonEmpty(id, "Asset ID");
        requireNonEmpty(name, "Asset name");
        requireNonEmpty(algorithm, "Algorithm");

        if (keyBits && *keyBits <= 0) {
            throw invalid_argument("Key size must be positive.");
        }
    }
};

struct KeyRecord {
    string id;
    string algorithm;
    int bits;

    int ageDays;
    int daysSinceRotation;

    string storage;
    bool exportable;
    bool exposed;

    void validate() const {
        requireNonEmpty(id, "Key ID");
        requireNonEmpty(algorithm, "Key algorithm");

        if (bits <= 0 || ageDays < 0 || daysSinceRotation < 0) {
            throw invalid_argument("Invalid key lifecycle values.");
        }

        if (daysSinceRotation > ageDays) {
            throw invalid_argument(
                "Rotation cannot precede key creation."
            );
        }
    }
};

struct Certificate {
    string id;
    string hostname;
    string signatureAlgorithm;
    string publicKeyAlgorithm;

    int publicKeyBits;
    int daysUntilExpiry;

    bool trustedIssuer;
    bool chainValid;
    bool revoked;

    void validate() const {
        requireNonEmpty(id, "Certificate ID");
        requireNonEmpty(hostname, "Hostname");

        if (publicKeyBits <= 0) {
            throw invalid_argument("Invalid public key size.");
        }
    }
};


// ========================================================
// POLICY
// ========================================================

struct SecurityPolicy {
    int minimumRsaBits = 2048;
    int maximumKeyAgeDays = 365;
    int certificateWarningDays = 30;

    set<string> deprecatedHashes = {
        "MD5", "SHA1", "SHA-1"
    };

    set<string> weakCiphers = {
        "DES", "3DES", "RC4"
    };

    set<string> approvedTls = {
        "TLS1.2", "TLS1.3"
    };
};


// ========================================================
// FINDING
// ========================================================

struct Finding {
    string id;
    string assetId;

    Category category;
    Severity severity;

    string title;
    string description;
    string recommendation;

    FindingStatus status = FindingStatus::Open;

    void transition(FindingStatus next) {
        bool allowed = false;

        switch (status) {
            case FindingStatus::Open:
                allowed =
                    next == FindingStatus::InReview ||
                    next == FindingStatus::Remediated ||
                    next == FindingStatus::AcceptedRisk ||
                    next == FindingStatus::FalsePositive;
                break;

            case FindingStatus::InReview:
                allowed =
                    next == FindingStatus::Open ||
                    next == FindingStatus::Remediated ||
                    next == FindingStatus::AcceptedRisk ||
                    next == FindingStatus::FalsePositive;
                break;

            case FindingStatus::AcceptedRisk:
                allowed =
                    next == FindingStatus::Open ||
                    next == FindingStatus::InReview ||
                    next == FindingStatus::Remediated;
                break;

            case FindingStatus::Remediated:
            case FindingStatus::FalsePositive:
                allowed = false;
                break;
        }

        if (!allowed) {
            throw logic_error(
                "Invalid finding status transition."
            );
        }

        status = next;
    }
};


// ========================================================
// RISK SCORING
// ========================================================

class RiskScorer {
public:

    static int weight(Severity severity) {
        switch (severity) {
            case Severity::Critical: return 10;
            case Severity::High: return 7;
            case Severity::Medium: return 4;
            case Severity::Low: return 2;
            case Severity::Informational: return 1;
        }

        return 0;
    }

    static int calculate(const vector<Finding>& findings) {
        int score = 0;

        for (const auto& finding : findings) {
            if (finding.status == FindingStatus::Open) {
                score += weight(finding.severity);
            }
        }

        return min(score, 100);
    }

    static string classify(int score) {
        if (score >= 30) return "CRITICAL";
        if (score >= 18) return "HIGH";
        if (score >= 8) return "MEDIUM";
        if (score > 0) return "LOW";

        return "NO_OPEN_FINDINGS";
    }
};


// ========================================================
// ASSESSMENT ENGINE
// ========================================================

class CryptoSecurityEngine {
private:

    SecurityPolicy policy;

    unordered_map<string, CryptoAsset> assets;
    unordered_map<string, size_t> findingIndex;

    vector<Finding> findings;

    size_t sequence = 0;

    void addFinding(
        const string& assetId,
        Category category,
        Severity severity,
        const string& title,
        const string& description,
        const string& recommendation
    ) {
        Finding finding;

        ++sequence;

        ostringstream id;
        id << "CRYPTO-" << setw(5) << setfill('0') << sequence;

        finding.id = id.str();
        finding.assetId = assetId;
        finding.category = category;
        finding.severity = severity;
        finding.title = title;
        finding.description = description;
        finding.recommendation = recommendation;

        findingIndex[finding.id] = findings.size();
        findings.push_back(move(finding));
    }

public:

    explicit CryptoSecurityEngine(
        SecurityPolicy configuredPolicy = SecurityPolicy()
    ) : policy(move(configuredPolicy)) {}


    // ----------------------------------------------------
    // Asset registration
    // ----------------------------------------------------

    void registerAsset(const CryptoAsset& asset) {
        asset.validate();

        if (assets.count(asset.id)) {
            throw invalid_argument("Duplicate asset ID.");
        }

        assets.emplace(asset.id, asset);
    }


    // ----------------------------------------------------
    // Algorithm analysis
    // ----------------------------------------------------

    void assessAsset(const string& assetId) {
        auto it = assets.find(assetId);

        if (it == assets.end()) {
            throw invalid_argument("Unknown asset.");
        }

        const CryptoAsset& asset = it->second;

        string algorithm = uppercase(asset.algorithm);

        if (policy.deprecatedHashes.count(algorithm)) {
            addFinding(
                asset.id,
                Category::WeakAlgorithm,
                Severity::High,
                "Deprecated hash algorithm",
                "Configured algorithm: " + algorithm,
                "Replace with SHA-256 or a stronger approved hash."
            );
        }

        if (policy.weakCiphers.count(algorithm)) {
            addFinding(
                asset.id,
                Category::WeakAlgorithm,
                Severity::Critical,
                "Weak encryption algorithm",
                "The configured cipher is deprecated.",
                "Migrate to modern authenticated encryption."
            );
        }

        if (algorithm == "RSA" || algorithm == "RSA-PSS") {
            if (!asset.keyBits.has_value()) {
                addFinding(
                    asset.id,
                    Category::Configuration,
                    Severity::Medium,
                    "RSA key size unavailable",
                    "Key strength cannot be established.",
                    "Record and validate the RSA modulus size."
                );
            } else if (*asset.keyBits < policy.minimumRsaBits) {
                addFinding(
                    asset.id,
                    Category::WeakAlgorithm,
                    Severity::High,
                    "Insufficient RSA key strength",
                    "Configured RSA key is undersized.",
                    "Use an RSA key of at least 2048 bits."
                );
            }
        }

        if (
            algorithm == "AES" ||
            algorithm == "AES-128" ||
            algorithm == "AES-256"
        ) {
            string mode = uppercase(asset.mode);

            if (mode == "ECB" || mode == "CBC_WITHOUT_MAC") {
                addFinding(
                    asset.id,
                    Category::Configuration,
                    Severity::High,
                    "Unsafe AES mode",
                    "The encryption mode lacks authenticated protection.",
                    "Use AES-GCM with unique nonces."
                );
            }

            if (
                asset.authenticated.has_value() &&
                !*asset.authenticated
            ) {
                addFinding(
                    asset.id,
                    Category::Configuration,
                    Severity::High,
                    "Encryption authentication missing",
                    "Ciphertext authenticity is not established.",
                    "Use authenticated encryption and verify its tag."
                );
            }
        }

        if (
            !asset.tlsVersion.empty() &&
            !policy.approvedTls.count(uppercase(asset.tlsVersion))
        ) {
            addFinding(
                asset.id,
                Category::TLS,
                Severity::High,
                "Unsupported TLS version",
                "Configured TLS version: " + asset.tlsVersion,
                "Use TLS 1.2 or TLS 1.3."
            );
        }

        string randomness = uppercase(asset.randomnessSource);

        if (
            randomness == "MATH.RANDOM" ||
            randomness == "RANDOM.RANDOM" ||
            randomness == "STATIC_SEED" ||
            randomness == "TIME"
        ) {
            addFinding(
                asset.id,
                Category::Randomness,
                Severity::Critical,
                "Predictable random number source",
                "The randomness source is not cryptographically secure.",
                "Use an operating-system cryptographic random generator."
            );
        }
    }


    // ----------------------------------------------------
    // Key lifecycle analysis
    // ----------------------------------------------------

    void assessKey(const KeyRecord& key) {
        key.validate();

        if (key.exposed) {
            addFinding(
                key.id,
                Category::KeyExposure,
                Severity::Critical,
                "Key exposure detected",
                "The key must be considered compromised.",
                "Revoke dependent credentials and rotate the key."
            );
        }

        if (key.exportable && uppercase(key.storage) != "HSM") {
            addFinding(
                key.id,
                Category::KeyManagement,
                Severity::High,
                "Unprotected exportable key",
                "The exportable key is outside the recorded HSM boundary.",
                "Use non-exportable keys or approved hardware protection."
            );
        }

        if (key.daysSinceRotation > policy.maximumKeyAgeDays) {
            addFinding(
                key.id,
                Category::KeyManagement,
                Severity::Medium,
                "Key rotation overdue",
                "The key exceeds its configured cryptoperiod.",
                "Rotate according to the approved key lifecycle policy."
            );
        }

        if (
            uppercase(key.algorithm) == "RSA" &&
            key.bits < policy.minimumRsaBits
        ) {
            addFinding(
                key.id,
                Category::WeakAlgorithm,
                Severity::High,
                "Weak RSA key",
                "RSA modulus is below the configured minimum.",
                "Replace with an adequately sized RSA key."
            );
        }
    }


    // ----------------------------------------------------
    // Certificate analysis
    // ----------------------------------------------------

    void assessCertificate(
        const Certificate& cert,
        const string& expectedHostname
    ) {
        cert.validate();

        if (cert.daysUntilExpiry < 0) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::Critical,
                "Certificate expired",
                "Certificate validity has ended.",
                "Renew and deploy a valid certificate."
            );
        } else if (
            cert.daysUntilExpiry <= policy.certificateWarningDays
        ) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::Medium,
                "Certificate approaching expiry",
                "Certificate renewal is required soon.",
                "Schedule renewal before expiration."
            );
        }

        if (cert.revoked) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::Critical,
                "Certificate revoked",
                "Certificate revocation is reported.",
                "Reject the certificate and investigate."
            );
        }

        if (!cert.trustedIssuer || !cert.chainValid) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::High,
                "Certificate chain validation failed",
                "Issuer trust or chain integrity is invalid.",
                "Validate intermediates and trusted root certificates."
            );
        }

        if (cert.hostname != expectedHostname) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::High,
                "Hostname mismatch",
                "Certificate identity does not match expected hostname.",
                "Deploy a certificate containing the correct SAN."
            );
        }

        string signature = uppercase(cert.signatureAlgorithm);

        if (
            signature == "SHA1" ||
            signature == "MD5" ||
            signature == "SHA1WITHRSA"
        ) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::High,
                "Weak certificate signature",
                "A deprecated signature algorithm is configured.",
                "Use an approved modern certificate signature."
            );
        }

        if (
            uppercase(cert.publicKeyAlgorithm) == "RSA" &&
            cert.publicKeyBits < policy.minimumRsaBits
        ) {
            addFinding(
                cert.id,
                Category::Certificate,
                Severity::High,
                "Weak certificate public key",
                "RSA certificate key is undersized.",
                "Replace with an adequately sized public key."
            );
        }
    }


    // ----------------------------------------------------
    // Finding workflow
    // ----------------------------------------------------

    void updateFinding(
        const string& findingId,
        FindingStatus status
    ) {
        auto it = findingIndex.find(findingId);

        if (it == findingIndex.end()) {
            throw invalid_argument("Finding does not exist.");
        }

        findings[it->second].transition(status);
    }


    // ----------------------------------------------------
    // Reporting
    // ----------------------------------------------------

    const vector<Finding>& getFindings() const {
        return findings;
    }

    int riskScore() const {
        return RiskScorer::calculate(findings);
    }

    void printReport() const {
        map<string, int> severityCounts;

        for (const auto& finding : findings) {
            severityCounts[toString(finding.severity)]++;
        }

        cout << "\n========================================\n";
        cout << "CRYPTOGRAPHY SECURITY REVIEW\n";
        cout << "========================================\n";

        cout << "Assets assessed: " << assets.size() << '\n';
        cout << "Total findings: " << findings.size() << '\n';
        cout << "Risk score: " << riskScore() << "/100\n";

        cout << "Risk level: "
             << RiskScorer::classify(riskScore()) << '\n';

        cout << "\nSEVERITY DISTRIBUTION\n";

        for (const auto& [severity, count] : severityCounts) {
            cout << severity << ": " << count << '\n';
        }

        cout << "\nFINDINGS\n";

        for (const auto& finding : findings) {
            cout << "\n[" << toString(finding.severity) << "] "
                 << finding.id << '\n';

            cout << "Asset: " << finding.assetId << '\n';
            cout << "Category: " << toString(finding.category) << '\n';
            cout << "Title: " << finding.title << '\n';
            cout << "Description: " << finding.description << '\n';
            cout << "Recommendation: "
                 << finding.recommendation << '\n';

            cout << "Status: "
                 << toString(finding.status) << '\n';
        }
    }
};


// ========================================================
// TESTS
// ========================================================

void runTests() {
    SecurityPolicy policy;
    CryptoSecurityEngine engine(policy);

    CryptoAsset asset{
        "TEST-001",
        "Legacy Authentication",
        "MD5",
        "Integrity",
        nullopt,
        "",
        nullopt,
        "",
        ""
    };

    engine.registerAsset(asset);
    engine.assessAsset("TEST-001");

    if (engine.getFindings().empty()) {
        throw runtime_error("Weak hash test failed.");
    }

    if (
        engine.getFindings()[0].severity != Severity::High
    ) {
        throw runtime_error("Incorrect severity.");
    }

    Finding finding{
        "F1",
        "A1",
        Category::WeakAlgorithm,
        Severity::High,
        "Test finding",
        "Description",
        "Recommendation"
    };

    finding.transition(FindingStatus::InReview);
    finding.transition(FindingStatus::Remediated);

    bool rejected = false;

    try {
        finding.transition(FindingStatus::Open);
    } catch (const logic_error&) {
        rejected = true;
    }

    if (!rejected) {
        throw runtime_error("Invalid transition was accepted.");
    }

    if (RiskScorer::classify(0) != "NO_OPEN_FINDINGS") {
        throw runtime_error("Risk classification test failed.");
    }

    cout << "All C++17 tests passed.\n";
}


// ========================================================
// MAIN
// ========================================================

int main() {
    try {
        runTests();

        SecurityPolicy policy;

        CryptoSecurityEngine engine(policy);

        vector<CryptoAsset> assets = {
            {
                "ASSET-001",
                "Legacy Authentication",
                "SHA1",
                "Integrity",
                nullopt,
                "",
                nullopt,
                "",
                ""
            },
            {
                "ASSET-002",
                "Payment Service",
                "AES",
                "Encryption",
                256,
                "ECB",
                false,
                "",
                ""
            },
            {
                "ASSET-003",
                "External API",
                "RSA",
                "Digital signature",
                1024,
                "",
                nullopt,
                "TLS1.0",
                ""
            },
            {
                "ASSET-004",
                "Token Generator",
                "AES-256",
                "Token protection",
                256,
                "GCM",
                true,
                "TLS1.3",
                "MATH.RANDOM"
            },
            {
                "ASSET-005",
                "Secure Storage",
                "AES-256",
                "Storage encryption",
                256,
                "GCM",
                true,
                "TLS1.3",
                "OS_CSPRNG"
            }
        };

        for (const auto& asset : assets) {
            engine.registerAsset(asset);
            engine.assessAsset(asset.id);
        }

        KeyRecord exposedKey{
            "KEY-001",
            "RSA",
            1024,
            600,
            500,
            "LOCAL_FILE",
            true,
            true
        };

        engine.assessKey(exposedKey);

        Certificate certificate{
            "CERT-001",
            "old.example.com",
            "SHA1WITHRSA",
            "RSA",
            1024,
            -5,
            false,
            false,
            true
        };

        engine.assessCertificate(
            certificate,
            "api.example.com"
        );

        if (!engine.getFindings().empty()) {
            engine.updateFinding(
                engine.getFindings()[0].id,
                FindingStatus::InReview
            );
        }

        engine.printReport();

    } catch (const exception& error) {
        cerr << "Assessment failed: "
             << error.what() << '\n';

        return 1;
    }

    return 0;
}
