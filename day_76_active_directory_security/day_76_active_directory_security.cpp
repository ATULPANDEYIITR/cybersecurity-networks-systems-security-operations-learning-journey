#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

/*
 * Active Directory Repository and Identity Governance Engine
 *
 * C++17
 *
 * Implements:
 * - Privileged account inventory
 * - Security tiers
 * - Service account controls
 * - Kerberos delegation review
 * - Trust validation
 * - Relationship graph analysis
 * - Security findings
 * - Risk-based merge-independent governance decisions
 *
 * This is a defensive configuration model, not a live AD client.
 */

enum class AccountType {
    User,
    Administrator,
    Service,
    ManagedService
};

enum class Tier {
    Tier0 = 0,
    Tier1 = 1,
    Tier2 = 2
};

enum class Delegation {
    None,
    Unconstrained,
    Constrained,
    ResourceBased
};

enum class Severity {
    Critical,
    High,
    Medium,
    Low
};

enum class FindingStatus {
    Open,
    Mitigated,
    Accepted
};

enum class TrustDirection {
    Inbound,
    Outbound,
    Bidirectional
};

struct Account {
    string name;
    AccountType type;
    Tier tier;

    bool enabled = true;
    bool privileged = false;
    bool mfaEnabled = false;
    bool passwordNeverExpires = false;
    bool interactiveLogonAllowed = true;
    bool managedPassword = false;
    bool trustedToAuthenticate = false;

    Delegation delegation = Delegation::None;

    int spnCount = 0;
    int passwordAgeDays = 0;
};

struct Trust {
    string id;
    string sourceDomain;
    string targetDomain;
    TrustDirection direction;

    bool enabled = true;
    bool sidFiltering = true;
    bool selectiveAuthentication = true;
};

struct Relationship {
    string source;
    string target;
    string permission;
};

struct Finding {
    string id;
    string category;
    string subject;
    string description;
    string recommendation;

    Severity severity;
    FindingStatus status = FindingStatus::Open;
};

struct SecurityPolicy {
    bool requirePrivilegedMFA = true;
    bool prohibitUnconstrainedDelegation = true;
    bool requireManagedServicePasswords = true;
    bool requireTrustSIDFiltering = true;
    bool requireSelectiveAuthentication = true;

    int maximumServicePasswordAge = 180;
};

static string toString(Severity severity) {
    switch (severity) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low: return "LOW";
    }
    return "UNKNOWN";
}

static string toString(FindingStatus status) {
    switch (status) {
        case FindingStatus::Open: return "OPEN";
        case FindingStatus::Mitigated: return "MITIGATED";
        case FindingStatus::Accepted: return "ACCEPTED";
    }
    return "UNKNOWN";
}

static string toString(Delegation delegation) {
    switch (delegation) {
        case Delegation::None: return "NONE";
        case Delegation::Unconstrained: return "UNCONSTRAINED";
        case Delegation::Constrained: return "CONSTRAINED";
        case Delegation::ResourceBased: return "RESOURCE_BASED";
    }
    return "UNKNOWN";
}

class DirectoryGovernance {
private:
    string domain;
    SecurityPolicy policy;

    unordered_map<string, Account> accounts;
    unordered_map<string, Trust> trusts;

    vector<Relationship> relationships;
    vector<Finding> findings;

    int findingCounter = 0;

    static bool validIdentifier(const string& value) {
        if (value.empty() || value.size() > 64) {
            return false;
        }

        return all_of(
            value.begin(),
            value.end(),
            [](unsigned char c) {
                return isalnum(c) || c == '_' || c == '-' || c == '.';
            }
        );
    }

    void addFinding(
        Severity severity,
        const string& category,
        const string& subject,
        const string& description,
        const string& recommendation
    ) {
        ostringstream id;
        id << "AD-" << setw(4) << setfill('0') << ++findingCounter;

        findings.push_back({
            id.str(),
            category,
            subject,
            description,
            recommendation,
            severity,
            FindingStatus::Open
        });
    }

public:
    explicit DirectoryGovernance(
        string domainName,
        SecurityPolicy securityPolicy = {}
    ) : domain(move(domainName)), policy(securityPolicy) {
        if (domain.empty() || domain.size() > 253) {
            throw invalid_argument("Invalid domain name");
        }
    }

    void addAccount(const Account& account) {
        if (!validIdentifier(account.name)) {
            throw invalid_argument("Invalid account identifier");
        }

        if (account.spnCount < 0 || account.passwordAgeDays < 0) {
            throw invalid_argument("Invalid account security attributes");
        }

        if (accounts.count(account.name)) {
            throw invalid_argument("Duplicate account");
        }

        accounts.emplace(account.name, account);
    }

    void addTrust(const Trust& trust) {
        if (
            trust.id.empty() ||
            trust.sourceDomain.empty() ||
            trust.targetDomain.empty()
        ) {
            throw invalid_argument("Incomplete trust definition");
        }

        if (trust.sourceDomain == trust.targetDomain) {
            throw invalid_argument("Self-trust is not allowed");
        }

        if (trusts.count(trust.id)) {
            throw invalid_argument("Duplicate trust");
        }

        trusts.emplace(trust.id, trust);
    }

    void addRelationship(const Relationship& relationship) {
        if (
            relationship.source.empty() ||
            relationship.target.empty() ||
            relationship.permission.empty() ||
            relationship.source == relationship.target
        ) {
            throw invalid_argument("Invalid relationship");
        }

        auto duplicate = find_if(
            relationships.begin(),
            relationships.end(),
            [&](const Relationship& item) {
                return item.source == relationship.source &&
                       item.target == relationship.target &&
                       item.permission == relationship.permission;
            }
        );

        if (duplicate == relationships.end()) {
            relationships.push_back(relationship);
        }
    }

    void auditAccounts() {
        for (const auto& [name, account] : accounts) {
            if (!account.enabled) {
                continue;
            }

            if (
                policy.requirePrivilegedMFA &&
                account.privileged &&
                !account.mfaEnabled
            ) {
                addFinding(
                    Severity::Critical,
                    "PRIVILEGED_MFA",
                    name,
                    "Privileged identity has no MFA.",
                    "Enforce strong MFA for privileged authentication."
                );
            }

            if (
                account.privileged &&
                account.passwordNeverExpires
            ) {
                addFinding(
                    Severity::High,
                    "PASSWORD_LIFECYCLE",
                    name,
                    "Privileged identity has a non-expiring password.",
                    "Implement managed credential lifecycle controls."
                );
            }

            if (
                account.type == AccountType::Administrator &&
                account.privileged &&
                account.tier != Tier::Tier0 &&
                account.interactiveLogonAllowed
            ) {
                addFinding(
                    Severity::High,
                    "TIER_SEPARATION",
                    name,
                    "Administrative tier assignment requires review.",
                    "Separate administrative identities by security tier."
                );
            }

            if (
                policy.prohibitUnconstrainedDelegation &&
                account.delegation == Delegation::Unconstrained
            ) {
                addFinding(
                    Severity::Critical,
                    "UNCONSTRAINED_DELEGATION",
                    name,
                    "Unconstrained Kerberos delegation is enabled.",
                    "Remove unnecessary unconstrained delegation."
                );
            }

            if (account.trustedToAuthenticate) {
                addFinding(
                    Severity::High,
                    "PROTOCOL_TRANSITION",
                    name,
                    "Protocol transition is configured.",
                    "Review permitted delegation targets and necessity."
                );
            }

            bool service =
                account.type == AccountType::Service ||
                account.type == AccountType::ManagedService;

            if (
                service &&
                account.interactiveLogonAllowed
            ) {
                addFinding(
                    Severity::Medium,
                    "INTERACTIVE_SERVICE_LOGON",
                    name,
                    "Service identity allows interactive logon.",
                    "Restrict interactive logon where operationally possible."
                );
            }

            if (
                account.type == AccountType::Service &&
                policy.requireManagedServicePasswords &&
                !account.managedPassword
            ) {
                addFinding(
                    Severity::High,
                    "SERVICE_CREDENTIALS",
                    name,
                    "Service account does not use managed credentials.",
                    "Evaluate migration to a managed service identity."
                );
            }

            if (
                account.type == AccountType::Service &&
                account.spnCount > 0 &&
                account.passwordAgeDays >
                    policy.maximumServicePasswordAge
            ) {
                addFinding(
                    Severity::High,
                    "SERVICE_PASSWORD_AGE",
                    name,
                    "SPN-bearing service account has an old password.",
                    "Rotate or automatically manage service credentials."
                );
            }
        }
    }

    void auditTrusts() {
        for (const auto& [id, trust] : trusts) {
            if (!trust.enabled) {
                continue;
            }

            if (
                policy.requireTrustSIDFiltering &&
                !trust.sidFiltering
            ) {
                addFinding(
                    Severity::Critical,
                    "TRUST_SID_FILTERING",
                    id,
                    "Trust does not enforce SID filtering.",
                    "Enable appropriate SID filtering."
                );
            }

            if (
                policy.requireSelectiveAuthentication &&
                !trust.selectiveAuthentication
            ) {
                addFinding(
                    Severity::High,
                    "TRUST_SELECTIVE_AUTHENTICATION",
                    id,
                    "Selective authentication is disabled.",
                    "Restrict authentication to authorized resources."
                );
            }
        }
    }

    void audit() {
        findings.clear();
        findingCounter = 0;

        auditAccounts();
        auditTrusts();
    }

    /*
     * Breadth-first search identifies shortest documented paths.
     * Relationship edges must be validated independently before
     * treating a path as an actual security exposure.
     */
    vector<vector<string>> findShortestPaths(
        const string& start,
        const string& target,
        size_t maximumDepth = 8
    ) const {
        if (start == target) {
            return {{start}};
        }

        if (maximumDepth == 0) {
            return {};
        }

        unordered_map<string, vector<string>> graph;

        for (const auto& relation : relationships) {
            graph[relation.source].push_back(relation.target);
        }

        queue<vector<string>> pending;
        pending.push({start});

        unordered_map<string, size_t> bestDepth;
        bestDepth[start] = 0;

        vector<vector<string>> results;
        size_t shortest = maximumDepth + 1;

        while (!pending.empty()) {
            auto path = pending.front();
            pending.pop();

            size_t depth = path.size() - 1;

            if (depth >= maximumDepth || depth >= shortest) {
                continue;
            }

            string node = path.back();

            for (const auto& neighbor : graph[node]) {
                if (
                    find(path.begin(), path.end(), neighbor) != path.end()
                ) {
                    continue;
                }

                auto nextPath = path;
                nextPath.push_back(neighbor);

                size_t nextDepth = depth + 1;

                if (neighbor == target) {
                    shortest = nextDepth;
                    results.push_back(nextPath);
                    continue;
                }

                auto it = bestDepth.find(neighbor);

                if (
                    it == bestDepth.end() ||
                    nextDepth <= it->second
                ) {
                    bestDepth[neighbor] = nextDepth;
                    pending.push(move(nextPath));
                }
            }
        }

        results.erase(
            remove_if(
                results.begin(),
                results.end(),
                [&](const vector<string>& path) {
                    return path.size() - 1 != shortest;
                }
            ),
            results.end()
        );

        return results;
    }

    void resolveFinding(
        const string& findingId,
        FindingStatus status
    ) {
        auto it = find_if(
            findings.begin(),
            findings.end(),
            [&](const Finding& finding) {
                return finding.id == findingId;
            }
        );

        if (it == findings.end()) {
            throw invalid_argument("Finding not found");
        }

        it->status = status;
    }

    void printFindings() const {
        for (const auto& finding : findings) {
            cout << "\n[" << toString(finding.severity) << "] "
                 << finding.id << " | "
                 << finding.category << "\n";

            cout << "Subject: " << finding.subject << "\n";
            cout << "Issue: " << finding.description << "\n";
            cout << "Remediation: "
                 << finding.recommendation << "\n";

            cout << "Status: "
                 << toString(finding.status) << "\n";
        }
    }

    void printStatistics() const {
        map<Severity, int> counts;

        for (const auto& finding : findings) {
            counts[finding.severity]++;
        }

        cout << "\nSECURITY STATISTICS\n";

        for (Severity severity : {
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low
        }) {
            cout << toString(severity)
                 << ": " << counts[severity] << "\n";
        }

        cout << "Accounts: " << accounts.size() << "\n";
        cout << "Trusts: " << trusts.size() << "\n";
        cout << "Relationships: " << relationships.size() << "\n";
    }

    void exportReport(const string& filename) const {
        if (
            filename.empty() ||
            filename.find('/') != string::npos ||
            filename.find('\\') != string::npos ||
            filename.size() < 5 ||
            filename.substr(filename.size() - 5) != ".json"
        ) {
            throw invalid_argument("Invalid local JSON filename");
        }

        ofstream output(filename);

        if (!output) {
            throw runtime_error("Unable to create report");
        }

        output << "{\n";
        output << "  \"domain\": \"" << domain << "\",\n";
        output << "  \"account_count\": " << accounts.size() << ",\n";
        output << "  \"findings\": [\n";

        for (size_t i = 0; i < findings.size(); ++i) {
            const auto& finding = findings[i];

            output << "    {\n";
            output << "      \"id\": \"" << finding.id << "\",\n";
            output << "      \"category\": \"" << finding.category << "\",\n";
            output << "      \"subject\": \"" << finding.subject << "\",\n";
            output << "      \"severity\": \""
                   << toString(finding.severity) << "\",\n";
            output << "      \"status\": \""
                   << toString(finding.status) << "\"\n";
            output << "    }";

            if (i + 1 < findings.size()) {
                output << ",";
            }

            output << "\n";
        }

        output << "  ]\n";
        output << "}\n";

        if (!output.good()) {
            throw runtime_error("Report writing failed");
        }
    }
};

int main() {
    try {
        DirectoryGovernance directory("corp.example.com");

        directory.addAccount({
            "domain_admin",
            AccountType::Administrator,
            Tier::Tier0,
            true,
            true,
            true,
            false,
            false,
            false,
            false,
            Delegation::None,
            0,
            20
        });

        directory.addAccount({
            "helpdesk_admin",
            AccountType::Administrator,
            Tier::Tier2,
            true,
            true,
            false,
            true,
            true,
            false,
            false,
            Delegation::None,
            0,
            100
        });

        directory.addAccount({
            "sql_service",
            AccountType::Service,
            Tier::Tier1,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            Delegation::None,
            2,
            240
        });

        directory.addAccount({
            "legacy_web",
            AccountType::Service,
            Tier::Tier1,
            true,
            false,
            false,
            true,
            true,
            false,
            true,
            Delegation::Unconstrained,
            1,
            300
        });

        directory.addAccount({
            "web_gmsa",
            AccountType::ManagedService,
            Tier::Tier1,
            true,
            false,
            false,
            false,
            false,
            true,
            false,
            Delegation::None,
            1,
            5
        });

        directory.addTrust({
            "TRUST-001",
            "corp.example.com",
            "partner.example.net",
            TrustDirection::Bidirectional,
            true,
            false,
            false
        });

        directory.addRelationship({
            "employee01",
            "helpdesk_admin",
            "group_membership"
        });

        directory.addRelationship({
            "helpdesk_admin",
            "server01",
            "administrative_access"
        });

        directory.addRelationship({
            "server01",
            "legacy_web",
            "service_dependency"
        });

        directory.addRelationship({
            "legacy_web",
            "domain_admin",
            "delegation_exposure"
        });

        directory.addRelationship({
            "employee01",
            "server02",
            "remote_access"
        });

        directory.addRelationship({
            "server02",
            "domain_admin",
            "privileged_dependency"
        });

        cout << "ACTIVE DIRECTORY SECURITY GOVERNANCE\n";
        cout << "=====================================\n";

        directory.audit();
        directory.printFindings();
        directory.printStatistics();

        cout << "\nDEFENSIVE ATTACK-PATH ANALYSIS\n";

        auto paths = directory.findShortestPaths(
            "employee01",
            "domain_admin"
        );

        if (paths.empty()) {
            cout << "No documented path found.\n";
        } else {
            for (size_t i = 0; i < paths.size(); ++i) {
                cout << "Path " << i + 1 << ": ";

                for (size_t j = 0; j < paths[i].size(); ++j) {
                    if (j > 0) cout << " -> ";
                    cout << paths[i][j];
                }

                cout << "\n";
            }
        }

        directory.exportReport("ad_security_report.json");

        cout << "\nReport exported successfully.\n";

    } catch (const exception& error) {
        cerr << "Execution error: "
             << error.what() << "\n";

        return 1;
    }

    return 0;
}
