#include <algorithm>
#include <cctype>
#include <chrono>
#include <functional>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

class LDAPException : public runtime_error {
public:
    explicit LDAPException(const string& message)
        : runtime_error(message) {}
};

enum class AccountStatus {
    ACTIVE,
    LOCKED,
    DISABLED
};

enum class SearchScope {
    BASE,
    ONE,
    SUBTREE
};

enum class ReviewState {
    NONE,
    PENDING,
    APPROVED,
    REJECTED
};

struct DirectoryEntry {
    string dn;
    map<string, vector<string>> attributes;
    string credentialVerifier;
    AccountStatus status = AccountStatus::ACTIVE;
    int failedAttempts = 0;
};

struct SearchResult {
    string dn;
    map<string, vector<string>> attributes;
};

struct StatusCheck {
    string name;
    bool required;
    bool passed;
};

struct Review {
    string reviewer;
    ReviewState state;
    bool eligible;
    bool stale;
    string comment;
};

struct BranchProtection {
    int requiredApprovals = 2;
    bool requireChecks = true;
    bool requireResolvedConversations = true;
    bool prohibitDirectPush = true;
    bool prohibitForcePush = true;
    bool prohibitDeletion = true;
    bool requireLinearHistory = false;
    bool administratorBypass = false;
};

struct PullRequest {
    int id;
    string sourceBranch;
    string targetBranch;
    string author;
    vector<string> commits;
    vector<Review> reviews;
    vector<StatusCheck> checks;
    int unresolvedConversations = 0;
    bool draft = false;
    bool closed = false;
    bool mergeConflict = false;
    bool baseSynchronized = true;
    bool merged = false;
};

class FilterParser {
private:
    string expression;
    size_t position = 0;

    string parseNode() {
        if (position >= expression.size() ||
            expression[position++] != '(') {
            throw LDAPException("Expected opening parenthesis.");
        }

        if (position >= expression.size()) {
            throw LDAPException("Incomplete LDAP filter.");
        }

        char op = expression[position];

        if (op == '&' || op == '|') {
            position++;

            vector<string> children;

            while (position < expression.size() &&
                   expression[position] == '(') {
                children.push_back(parseNode());
            }

            if (children.empty()) {
                throw LDAPException("Empty logical filter.");
            }

            if (position >= expression.size() ||
                expression[position++] != ')') {
                throw LDAPException("Missing closing parenthesis.");
            }

            string result;
            result.push_back(op);
            result += "[";

            for (const auto& child : children) {
                result += child + ";";
            }

            result += "]";
            return result;
        }

        if (op == '!') {
            position++;
            string child = parseNode();

            if (position >= expression.size() ||
                expression[position++] != ')') {
                throw LDAPException("Invalid NOT filter.");
            }

            return "!" + child;
        }

        size_t start = position;

        while (position < expression.size() &&
               expression[position] != ')') {
            position++;
        }

        if (position >= expression.size()) {
            throw LDAPException("Unclosed equality filter.");
        }

        string value = expression.substr(start, position - start);
        position++;

        if (value.find('=') == string::npos) {
            throw LDAPException("Equality operator required.");
        }

        return "=" + value;
    }

    static bool equalIgnoreCase(string a, string b) {
        transform(a.begin(), a.end(), a.begin(),
                  [](unsigned char c) { return tolower(c); });

        transform(b.begin(), b.end(), b.begin(),
                  [](unsigned char c) { return tolower(c); });

        return a == b;
    }

    bool evaluate(const string& node,
                  const DirectoryEntry& entry) const {
        if (node.empty()) return false;

        if (node[0] == '&' || node[0] == '|') {
            size_t start = 2;
            bool isAnd = node[0] == '&';
            bool result = isAnd;

            while (start < node.size() - 1) {
                size_t end = start;
                int depth = 0;

                for (; end < node.size() - 1; ++end) {
                    if (node[end] == '[') depth++;
                    if (node[end] == ']') depth--;

                    if (node[end] == ';' && depth == 0) break;
                }

                if (end > start) {
                    string child = node.substr(start, end - start);
                    bool current = evaluate(child, entry);

                    if (isAnd && !current) return false;
                    if (!isAnd && current) return true;
                }

                start = end + 1;
            }

            return result;
        }

        if (node[0] == '!') {
            return !evaluate(node.substr(1), entry);
        }

        if (node[0] != '=') return false;

        string expression = node.substr(1);
        size_t separator = expression.find('=');

        if (separator == string::npos) return false;

        string attribute = expression.substr(0, separator);
        string expected = expression.substr(separator + 1);

        transform(attribute.begin(), attribute.end(), attribute.begin(),
                  [](unsigned char c) { return tolower(c); });

        auto found = entry.attributes.find(attribute);

        if (found == entry.attributes.end()) return false;

        if (expected == "*") return !found->second.empty();

        return any_of(
            found->second.begin(),
            found->second.end(),
            [&](const string& value) {
                return equalIgnoreCase(value, expected);
            }
        );
    }

public:
    explicit FilterParser(string input)
        : expression(move(input)) {}

    bool matches(const DirectoryEntry& entry) {
        position = 0;
        string ast = parseNode();

        if (position != expression.size()) {
            throw LDAPException("Unexpected filter characters.");
        }

        return evaluate(ast, entry);
    }
};

class Directory {
private:
    map<string, DirectoryEntry> entries;
    vector<string> audit;

    static string normalizeDN(const string& dn) {
        if (dn.empty()) {
            throw LDAPException("DN cannot be empty.");
        }

        string normalized;
        stringstream stream(dn);
        string component;

        while (getline(stream, component, ',')) {
            size_t equal = component.find('=');

            if (equal == string::npos) {
                throw LDAPException("Invalid RDN.");
            }

            string attribute = component.substr(0, equal);
            string value = component.substr(equal + 1);

            if (attribute.empty() || value.empty()) {
                throw LDAPException("Invalid RDN component.");
            }

            transform(
                attribute.begin(), attribute.end(),
                attribute.begin(),
                [](unsigned char c) { return tolower(c); }
            );

            transform(
                value.begin(), value.end(),
                value.begin(),
                [](unsigned char c) { return tolower(c); }
            );

            if (!normalized.empty()) normalized += ",";
            normalized += attribute + "=" + value;
        }

        return normalized;
    }

    static int depth(const string& dn) {
        return static_cast<int>(count(dn.begin(), dn.end(), ',')) + 1;
    }

    static bool within(const string& dn, const string& base) {
        return dn == base ||
               (dn.size() > base.size() &&
                dn.compare(dn.size() - base.size(), base.size(), base) == 0 &&
                dn[dn.size() - base.size() - 1] == ',');
    }

    void log(const string& message) {
        audit.push_back(message);
    }

public:
    void addEntry(DirectoryEntry entry) {
        entry.dn = normalizeDN(entry.dn);

        if (!entry.attributes.count("objectclass")) {
            throw LDAPException("objectClass is mandatory.");
        }

        if (entries.count(entry.dn)) {
            throw LDAPException("Duplicate DN.");
        }

        size_t separator = entry.dn.find(',');

        if (separator != string::npos) {
            string parent = entry.dn.substr(separator + 1);

            if (!entries.count(parent)) {
                throw LDAPException("Parent DN does not exist.");
            }
        }

        entries.emplace(entry.dn, move(entry));
        log("ADD " + entry.dn);
    }

    bool authenticate(
        const string& dn,
        const string& suppliedVerifier
    ) {
        string normalized = normalizeDN(dn);
        auto it = entries.find(normalized);

        if (it == entries.end()) {
            log("BIND REJECTED " + normalized);
            throw LDAPException("Invalid credentials.");
        }

        DirectoryEntry& entry = it->second;

        if (entry.status != AccountStatus::ACTIVE) {
            throw LDAPException("Account unavailable.");
        }

        // Demonstration verifier only. Production systems must use
        // a vetted password KDF and constant-time comparison.
        if (entry.credentialVerifier != suppliedVerifier) {
            entry.failedAttempts++;

            if (entry.failedAttempts >= 5) {
                entry.status = AccountStatus::LOCKED;
            }

            log("BIND REJECTED " + normalized);
            throw LDAPException("Invalid credentials.");
        }

        entry.failedAttempts = 0;
        log("BIND SUCCESS " + normalized);
        return true;
    }

    vector<SearchResult> search(
        const string& baseDN,
        const string& filter,
        SearchScope scope,
        const vector<string>& requestedAttributes,
        size_t limit = 100
    ) {
        string base = normalizeDN(baseDN);

        if (!entries.count(base)) {
            throw LDAPException("Search base does not exist.");
        }

        if (limit == 0 || limit > 1000) {
            throw LDAPException("Invalid search limit.");
        }

        FilterParser parser(filter);
        vector<SearchResult> results;

        for (const auto& [dn, entry] : entries) {
            bool inScope = false;

            if (scope == SearchScope::BASE) {
                inScope = dn == base;
            } else if (scope == SearchScope::ONE) {
                inScope = within(dn, base) &&
                          depth(dn) == depth(base) + 1;
            } else {
                inScope = within(dn, base);
            }

            if (!inScope || !parser.matches(entry)) continue;

            SearchResult result;
            result.dn = dn;

            for (const string& attribute : requestedAttributes) {
                auto found = entry.attributes.find(attribute);

                if (found != entry.attributes.end()) {
                    result.attributes[attribute] = found->second;
                }
            }

            results.push_back(move(result));

            if (results.size() >= limit) break;
        }

        log("SEARCH " + base + " RESULTS=" +
            to_string(results.size()));

        return results;
    }

    const vector<string>& getAudit() const {
        return audit;
    }
};

class GovernanceEngine {
private:
    BranchProtection policy;

public:
    explicit GovernanceEngine(BranchProtection protection)
        : policy(protection) {}

    vector<string> evaluate(const PullRequest& pr) const {
        vector<string> failures;

        if (pr.merged) {
            failures.push_back("Pull Request is already merged.");
            return failures;
        }

        if (pr.closed) {
            failures.push_back("Pull Request is closed.");
        }

        if (pr.draft) {
            failures.push_back("Draft Pull Requests cannot be merged.");
        }

        if (pr.sourceBranch == pr.targetBranch) {
            failures.push_back("Source and target branches must differ.");
        }

        if (pr.commits.empty()) {
            failures.push_back("No commits are proposed.");
        }

        if (pr.mergeConflict) {
            failures.push_back("Merge conflicts must be resolved.");
        }

        if (!pr.baseSynchronized) {
            failures.push_back("Source branch must synchronize with base.");
        }

        int approvals = 0;
        set<string> reviewers;

        for (const auto& review : pr.reviews) {
            if (!reviewers.insert(review.reviewer).second) {
                continue;
            }

            if (!review.eligible || review.stale) continue;

            if (review.state == ReviewState::REJECTED) {
                failures.push_back(
                    "An eligible reviewer requested changes: " +
                    review.reviewer
                );
            }

            if (review.state == ReviewState::APPROVED) {
                approvals++;
            }
        }

        if (approvals < policy.requiredApprovals) {
            failures.push_back(
                "Insufficient approvals: " +
                to_string(approvals) + "/" +
                to_string(policy.requiredApprovals)
            );
        }

        if (policy.requireChecks) {
            bool foundRequired = false;

            for (const auto& check : pr.checks) {
                if (!check.required) continue;

                foundRequired = true;

                if (!check.passed) {
                    failures.push_back(
                        "Required status check failed: " + check.name
                    );
                }
            }

            if (!foundRequired) {
                failures.push_back("Required status checks are missing.");
            }
        }

        if (policy.requireResolvedConversations &&
            pr.unresolvedConversations > 0) {
            failures.push_back(
                "Unresolved review conversations remain."
            );
        }

        return failures;
    }

    bool canMerge(const PullRequest& pr) const {
        return evaluate(pr).empty();
    }

    void merge(PullRequest& pr) const {
        if (!canMerge(pr)) {
            throw LDAPException("Merge eligibility conditions failed.");
        }

        pr.merged = true;
    }
};

int main() {
    try {
        cout << "LDAP DIRECTORY AND REPOSITORY GOVERNANCE\n";
        cout << "=========================================\n";

        Directory directory;

        directory.addEntry({
            "dc=example,dc=com",
            {
                {"objectclass", {"top", "domain"}},
                {"dc", {"example"}}
            }
        });

        directory.addEntry({
            "ou=people,dc=example,dc=com",
            {
                {"objectclass", {"top", "organizationalUnit"}},
                {"ou", {"people"}}
            }
        });

        directory.addEntry({
            "uid=alice,ou=people,dc=example,dc=com",
            {
                {"objectclass", {"top", "person", "inetOrgPerson"}},
                {"uid", {"alice"}},
                {"cn", {"Alice Sharma"}},
                {"department", {"Engineering"}},
                {"mail", {"alice@example.com"}}
            },
            "DEMO_VERIFIER_ALICE"
        });

        directory.addEntry({
            "uid=bob,ou=people,dc=example,dc=com",
            {
                {"objectclass", {"top", "person", "inetOrgPerson"}},
                {"uid", {"bob"}},
                {"cn", {"Bob Kumar"}},
                {"department", {"Security"}},
                {"mail", {"bob@example.com"}}
            },
            "DEMO_VERIFIER_BOB"
        });

        cout << "\n1. LDAP SEARCH\n";

        auto results = directory.search(
            "dc=example,dc=com",
            "(&(department=Engineering)(uid=*))",
            SearchScope::SUBTREE,
            {"uid", "cn", "department"}
        );

        for (const auto& result : results) {
            cout << result.dn << "\n";

            for (const auto& [key, values] : result.attributes) {
                cout << "  " << key << ": ";

                for (const auto& value : values) {
                    cout << value << " ";
                }

                cout << "\n";
            }
        }

        cout << "\n2. LDAP BIND\n";

        bool authenticated = directory.authenticate(
            "uid=alice,ou=people,dc=example,dc=com",
            "DEMO_VERIFIER_ALICE"
        );

        cout << "Authenticated: "
             << boolalpha << authenticated << "\n";

        cout << "\n3. INVALID BIND\n";

        try {
            directory.authenticate(
                "uid=alice,ou=people,dc=example,dc=com",
                "INVALID"
            );
        } catch (const exception& ex) {
            cout << "Rejected: " << ex.what() << "\n";
        }

        cout << "\n4. REPOSITORY MERGE ELIGIBILITY\n";

        BranchProtection policy;
        policy.requiredApprovals = 2;
        policy.requireChecks = true;
        policy.requireResolvedConversations = true;

        GovernanceEngine engine(policy);

        PullRequest pr{
            101,
            "feature/ldap-security",
            "main",
            "alice",
            {"a1b2c3", "d4e5f6"},
            {
                {"bob", ReviewState::APPROVED, true, false, "Approved"},
                {"carol", ReviewState::APPROVED, true, false, "Approved"}
            },
            {
                {"unit-tests", true, true},
                {"security-scan", true, true},
                {"integration-tests", true, true}
            },
            0,
            false,
            false,
            false,
            true,
            false
        };

        auto failures = engine.evaluate(pr);

        if (failures.empty()) {
            engine.merge(pr);
            cout << "Pull Request merged successfully.\n";
        } else {
            for (const auto& failure : failures) {
                cout << "BLOCKED: " << failure << "\n";
            }
        }

        cout << "\n5. POLICY FAILURE SCENARIO\n";

        PullRequest blocked = pr;
        blocked.id = 102;
        blocked.merged = false;
        blocked.draft = true;
        blocked.unresolvedConversations = 2;

        blocked.checks[1].passed = false;
        blocked.reviews[0].stale = true;

        for (const auto& failure : engine.evaluate(blocked)) {
            cout << "BLOCKED: " << failure << "\n";
        }

        cout << "\n6. AUDIT EVENTS\n";

        for (const auto& event : directory.getAudit()) {
            cout << event << "\n";
        }

    } catch (const exception& ex) {
        cerr << "Execution error: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
