#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * Case study: enterprise directory governance and service discovery.
 *
 * A multinational engineering company operates a corporate AD forest,
 * a child engineering domain, and a separate partner forest. The program
 * models domain membership, trust direction, DNS SRV discovery, and the
 * distinction between trust reachability and actual authorization.
 *
 * Build: g++ -std=c++17 -Wall -Wextra -pedantic ad_architecture.cpp -o ad_architecture
 */

namespace directory {

class ConfigurationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string lower(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(std::tolower(character));
        }
    );
    return value;
}

std::string normalizeDnsName(std::string name) {
    while (!name.empty() && name.back() == '.') {
        name.pop_back();
    }

    name = lower(name);

    if (name.empty() || name.size() > 253) {
        throw ConfigurationError("Invalid DNS name length.");
    }

    std::size_t start = 0;
    while (start < name.size()) {
        const std::size_t end = name.find('.', start);
        const std::size_t stop =
            end == std::string::npos ? name.size() : end;
        const std::string label = name.substr(start, stop - start);

        if (label.empty() || label.size() > 63 ||
            label.front() == '-' || label.back() == '-') {
            throw ConfigurationError("Invalid DNS label.");
        }

        for (unsigned char character : label) {
            if (!std::isalnum(character) && character != '-') {
                throw ConfigurationError("Invalid DNS character.");
            }
        }

        if (end == std::string::npos) break;
        start = end + 1;
    }

    return name;
}

struct DirectoryObject {
    std::string distinguishedName;
    std::string objectClass;
    std::map<std::string, std::string> attributes;
};

class Domain {
private:
    std::string name_;
    std::string forestRoot_;
    std::string parent_;
    std::map<std::string, DirectoryObject> objects_;

public:
    Domain(std::string name, std::string forestRoot, std::string parent = "")
        : name_(normalizeDnsName(std::move(name))),
          forestRoot_(normalizeDnsName(std::move(forestRoot))),
          parent_(parent.empty() ? "" : normalizeDnsName(std::move(parent))) {}

    const std::string& name() const { return name_; }
    const std::string& forestRoot() const { return forestRoot_; }
    const std::string& parent() const { return parent_; }

    std::string baseDn() const {
        std::string result;
        std::size_t start = 0;

        while (start < name_.size()) {
            const std::size_t end = name_.find('.', start);
            const std::size_t stop =
                end == std::string::npos ? name_.size() : end;

            if (!result.empty()) result += ",";
            result += "DC=" + name_.substr(start, stop - start);

            if (end == std::string::npos) break;
            start = end + 1;
        }

        return result;
    }

    void addObject(DirectoryObject object) {
        const std::string key = lower(object.distinguishedName);

        if (object.distinguishedName.empty() ||
            object.distinguishedName.find('=') == std::string::npos) {
            throw ConfigurationError("Invalid distinguished name.");
        }

        if (!objects_.emplace(key, std::move(object)).second) {
            throw ConfigurationError("Duplicate distinguished name.");
        }
    }

    std::vector<DirectoryObject> findUsersByDepartment(
        const std::string& department
    ) const {
        std::vector<DirectoryObject> matches;

        for (const auto& entry : objects_) {
            const DirectoryObject& object = entry.second;
            if (lower(object.objectClass) != "user") continue;

            const auto attribute = object.attributes.find("department");
            if (attribute != object.attributes.end() &&
                lower(attribute->second) == lower(department)) {
                matches.push_back(object);
            }
        }

        return matches;
    }
};

class Forest {
private:
    std::string rootDomain_;
    std::map<std::string, Domain> domains_;

public:
    explicit Forest(std::string root)
        : rootDomain_(normalizeDnsName(std::move(root))) {}

    const std::string& rootDomain() const { return rootDomain_; }

    void addDomain(Domain domain) {
        if (domain.forestRoot() != rootDomain_) {
            throw ConfigurationError("Domain belongs to another forest.");
        }

        if (domains_.empty()) {
            if (domain.name() != rootDomain() || !domain.parent().empty()) {
                throw ConfigurationError("Invalid forest root domain.");
            }
        } else {
            const auto parent = domains_.find(domain.parent());
            if (parent == domains_.end()) {
                throw ConfigurationError("Parent domain does not exist.");
            }

            const std::string suffix = "." + domain.parent();
            if (domain.name().size() <= suffix.size() ||
                domain.name().compare(
                    domain.name().size() - suffix.size(),
                    suffix.size(), suffix
                ) != 0) {
                throw ConfigurationError("Invalid child domain namespace.");
            }
        }

        const std::string key = domain.name();
        if (!domains_.emplace(key, std::move(domain)).second) {
            throw ConfigurationError("Duplicate domain.");
        }
    }

    const Domain& findDomain(const std::string& name) const {
        const auto found = domains_.find(normalizeDnsName(name));
        if (found == domains_.end()) {
            throw ConfigurationError("Domain not found.");
        }
        return found->second;
    }
};

enum class TrustDirection {
    Outbound,
    Inbound,
    Bidirectional
};

struct Trust {
    std::string sourceForest;
    std::string targetForest;
    TrustDirection direction;
    bool transitive;
    bool enabled;
};

class TrustGraph {
private:
    std::vector<Trust> trusts_;

public:
    void addTrust(Trust trust) {
        trust.sourceForest = normalizeDnsName(trust.sourceForest);
        trust.targetForest = normalizeDnsName(trust.targetForest);

        if (trust.sourceForest == trust.targetForest) {
            throw ConfigurationError("A forest cannot trust itself.");
        }

        for (const Trust& existing : trusts_) {
            if (existing.sourceForest == trust.sourceForest &&
                existing.targetForest == trust.targetForest) {
                throw ConfigurationError("Duplicate trust relationship.");
            }
        }

        trusts_.push_back(std::move(trust));
    }

    bool canReach(
        const std::string& sourceForest,
        const std::string& targetForest
    ) const {
        const std::string source = normalizeDnsName(sourceForest);
        const std::string target = normalizeDnsName(targetForest);

        if (source == target) return true;

        // A direct, non-transitive trust permits only its direct peer.
        // It must not be used as a bridge to a third forest.
        std::unordered_map<std::string, std::vector<std::string>> graph;

        for (const Trust& trust : trusts_) {
            if (!trust.enabled) continue;

            if (trust.direction == TrustDirection::Outbound ||
                trust.direction == TrustDirection::Bidirectional) {
                graph[trust.sourceForest].push_back(trust.targetForest);
            }

            if (trust.direction == TrustDirection::Inbound ||
                trust.direction == TrustDirection::Bidirectional) {
                graph[trust.targetForest].push_back(trust.sourceForest);
            }
        }

        std::queue<std::pair<std::string, bool>> pending;
        std::set<std::pair<std::string, bool>> visited;
        pending.push({source, true});
        visited.insert({source, true});

        while (!pending.empty()) {
            const auto current = pending.front();
            pending.pop();

            for (const std::string& next : graph[current.first]) {
                if (next == target) return true;

                // Crossing a non-transitive trust can satisfy a direct
                // request but must not enable onward traversal.
                bool mayContinue = current.second;
                for (const Trust& trust : trusts_) {
                    const bool sameEdge =
                        (trust.sourceForest == current.first &&
                         trust.targetForest == next) ||
                        (trust.sourceForest == next &&
                         trust.targetForest == current.first);
                    if (sameEdge && !trust.transitive) {
                        mayContinue = false;
                    }
                }

                if (mayContinue &&
                    visited.insert({next, true}).second) {
                    pending.push({next, true});
                }
            }
        }

        return false;
    }
};

struct SrvRecord {
    std::string queryName;
    std::string target;
    unsigned short port;
    unsigned short priority;
    unsigned short weight;
};

class DnsCatalog {
private:
    std::unordered_map<std::string, std::vector<SrvRecord>> records_;

public:
    void add(SrvRecord record) {
        record.queryName = normalizeDnsName(record.queryName);
        record.target = normalizeDnsName(record.target);

        if (record.port == 0) {
            throw ConfigurationError("SRV port cannot be zero.");
        }

        records_[record.queryName].push_back(std::move(record));
    }

    std::vector<SrvRecord> lookup(const std::string& name) const {
        const auto found = records_.find(normalizeDnsName(name));
        if (found == records_.end()) return {};

        auto result = found->second;
        std::stable_sort(
            result.begin(), result.end(),
            [](const SrvRecord& left, const SrvRecord& right) {
                if (left.priority != right.priority) {
                    return left.priority < right.priority;
                }
                return left.weight > right.weight;
            }
        );
        return result;
    }
};

class DirectoryService {
private:
    std::map<std::string, Forest> forests_;
    DnsCatalog dns_;
    TrustGraph trusts_;

public:
    void addForest(Forest forest) {
        const std::string key = forest.rootDomain();
        if (!forests_.emplace(key, std::move(forest)).second) {
            throw ConfigurationError("Duplicate forest.");
        }
    }

    DnsCatalog& dns() { return dns_; }
    TrustGraph& trusts() { return trusts_; }

    bool sameForest(
        const std::string& firstDomain,
        const std::string& secondDomain
    ) const {
        const std::string first = normalizeDnsName(firstDomain);
        const std::string second = normalizeDnsName(secondDomain);

        for (const auto& entry : forests_) {
            const Forest& forest = entry.second;
            try {
                forest.findDomain(first);
                forest.findDomain(second);
                return true;
            } catch (const ConfigurationError&) {
                // Continue until a forest containing both domains is found.
            }
        }

        return false;
    }

    bool canAttemptAuthentication(
        const std::string& sourceDomain,
        const std::string& targetDomain
    ) const {
        if (sameForest(sourceDomain, targetDomain)) return true;

        const std::string source = normalizeDnsName(sourceDomain);
        const std::string target = normalizeDnsName(targetDomain);
        std::string sourceForest;
        std::string targetForest;

        for (const auto& entry : forests_) {
            const Forest& forest = entry.second;
            try {
                forest.findDomain(source);
                sourceForest = entry.first;
            } catch (const ConfigurationError&) {
            }
            try {
                forest.findDomain(target);
                targetForest = entry.first;
            } catch (const ConfigurationError&) {
            }
        }

        if (sourceForest.empty() || targetForest.empty()) {
            throw ConfigurationError("Source or target domain is unknown.");
        }

        return trusts_.canReach(sourceForest, targetForest);
    }

    std::vector<SrvRecord> locateControllers(
        const std::string& domain
    ) const {
        const std::string query =
            "_ldap._tcp." + normalizeDnsName(domain);
        const auto controllers = dns_.lookup(query);

        if (controllers.empty()) {
            throw ConfigurationError(
                "DNS cannot locate a domain controller for " + query
            );
        }

        return controllers;
    }
};

}  // namespace directory

int main() {
    using namespace directory;

    try {
        DirectoryService service;

        Forest corporate("corp.example.com");
        corporate.addDomain(
            Domain("corp.example.com", "corp.example.com")
        );

        Domain engineering(
            "engineering.corp.example.com",
            "corp.example.com",
            "corp.example.com"
        );

        engineering.addObject({
            "CN=Riya Sharma,OU=Engineering,DC=engineering,"
            "DC=corp,DC=example,DC=com",
            "user",
            {
                {"cn", "Riya Sharma"},
                {"department", "Engineering"},
                {"sAMAccountName", "riya.sharma"}
            }
        });

        engineering.addObject({
            "CN=Build Host,OU=Computers,DC=engineering,"
            "DC=corp,DC=example,DC=com",
            "computer",
            {
                {"cn", "Build Host"},
                {"dNSHostName", "build01.engineering.corp.example.com"}
            }
        });

        corporate.addDomain(std::move(engineering));
        service.addForest(std::move(corporate));

        Forest partner("partner.example.net");
        partner.addDomain(
            Domain("partner.example.net", "partner.example.net")
        );
        service.addForest(std::move(partner));

        service.trusts().addTrust({
            "corp.example.com",
            "partner.example.net",
            TrustDirection::Bidirectional,
            true,
            true
        });

        service.dns().add({
            "_ldap._tcp.engineering.corp.example.com",
            "dc01.corp.example.com",
            389,
            0,
            100
        });

        service.dns().add({
            "_kerberos._tcp.engineering.corp.example.com",
            "dc01.corp.example.com",
            88,
            0,
            100
        });

        std::cout << "=== Domain Controller Discovery ===\n";
        for (const SrvRecord& record :
             service.locateControllers("engineering.corp.example.com")) {
            std::cout << record.target << ":" << record.port
                      << " priority=" << record.priority
                      << " weight=" << record.weight << '\n';
        }

        std::cout << "\n=== LDAP Domain Search ===\n";
        const Domain& engineeringDomain =
            [&service]() -> const Domain& {
                // Forest lookup remains explicit so a missing domain fails
                // before an incomplete search is presented as successful.
                return service.canAttemptAuthentication(
                    "engineering.corp.example.com",
                    "corp.example.com"
                )
                    ? throw ConfigurationError(
                        "Use the forest's domain lookup for LDAP searches."
                    )
                    : throw ConfigurationError("Unexpected domain state.");
            }();

        (void)engineeringDomain;
    } catch (const std::exception& error) {
        std::cerr << "Configuration error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
