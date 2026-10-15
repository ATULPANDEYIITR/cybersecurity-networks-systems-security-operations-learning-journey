#include <algorithm>
#include <cctype>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

/*
 * Case study: repository-independent directory governance for a distributed
 * engineering organization.
 *
 * The directory service supports domain identities, domain controllers,
 * OU hierarchy, nested security groups, policy inheritance, and resource
 * authorization. Ordered maps make reports deterministic for review.
 *
 * This is a C++17 model, not an AD DS protocol implementation.
 */

class DirectoryError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ValidationError : public DirectoryError {
public:
    using DirectoryError::DirectoryError;
};

class NotFoundError : public DirectoryError {
public:
    using DirectoryError::DirectoryError;
};

enum class GroupScope {
    Global,
    DomainLocal,
    Universal
};

enum class ObjectKind {
    User,
    Group,
    OrganizationalUnit,
    Computer
};

struct DomainController {
    std::string name;
    std::string site;
    std::set<std::string> operationsMasterRoles;
    bool writable = true;
    bool globalCatalog = true;
    bool reachable = true;
    unsigned long long observedRevision = 0;
};

struct DirectoryObject {
    std::string id;
    std::string name;
    ObjectKind kind;
    std::string distinguishedName;
    bool enabled = true;
};

struct User {
    DirectoryObject object;
    std::string samAccountName;
    std::string upn;
    std::string department;
    bool mfaRegistered = false;
    bool locked = false;
};

struct SecurityGroup {
    DirectoryObject object;
    GroupScope scope;
    std::set<std::string> members;
};

struct OrganizationalUnit {
    DirectoryObject object;
    std::string parentDn;
    bool protectedFromDeletion = true;
    std::set<std::string> children;
    bool blockInheritance = false;
};

struct GroupPolicy {
    std::string id;
    std::string name;
    std::map<std::string, std::string> settings;
    bool enabled = true;
    bool computerConfigurationEnabled = true;
};

struct PolicyLink {
    std::string policyId;
    std::string targetDn;
    int order = 1;
    bool enforced = false;
    bool disabled = false;
};

class DirectoryGovernance {
private:
    std::string dnsName_;
    std::string netbiosName_;
    std::string domainDn_;
    unsigned long long revision_ = 0;

    std::map<std::string, DirectoryController> unusedControllerTypeCheck_;
    std::map<std::string, DomainController> controllers_;
    std::map<std::string, DirectoryObject> objects_;
    std::map<std::string, User> users_;
    std::map<std::string, SecurityGroup> groups_;
    std::map<std::string, OrganizationalUnit> ous_;
    std::map<std::string, GroupPolicy> policies_;
    std::vector<PolicyLink> links_;
    std::vector<std::string> audit_;

    static std::string lower(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        return value;
    }

    static std::string upper(std::string value) {
        std::transform(value.begin(), value.end(), value.begin(),
            [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
        return value;
    }

    void record(const std::string& message) {
        ++revision_;
        audit_.push_back("revision=" + std::to_string(revision_) + " " + message);
    }

    void ensureUniqueDn(const std::string& dn) const {
        for (const auto& [id, object] : objects_) {
            if (lower(object.distinguishedName) == lower(dn)) {
                throw ValidationError("Duplicate distinguished name: " + dn);
            }
        }
    }

    bool containsGroup(
        const std::string& start,
        const std::string& target,
        std::set<std::string>& visited
    ) const {
        if (start == target) return true;
        if (!visited.insert(start).second) return false;

        auto it = groups_.find(start);
        if (it == groups_.end()) return false;

        for (const auto& member : it->second.members) {
            if (groups_.count(member) &&
                containsGroup(member, target, visited)) {
                return true;
            }
        }
        return false;
    }

public:
    DirectoryGovernance(std::string dnsName, std::string netbiosName)
        : dnsName_(lower(std::move(dnsName))),
          netbiosName_(upper(std::move(netbiosName))) {
        if (dnsName_.find('.') == std::string::npos) {
            throw ValidationError("Domain must be a multi-label DNS name.");
        }
        if (netbiosName_.empty() || netbiosName_.size() > 15) {
            throw ValidationError("Invalid NetBIOS name.");
        }

        std::stringstream labels(dnsName_);
        std::string label;
        while (std::getline(labels, label, '.')) {
            if (label.empty() || label.size() > 63 ||
                !std::isalnum(static_cast<unsigned char>(label.front())) ||
                !std::isalnum(static_cast<unsigned char>(label.back()))) {
                throw ValidationError("Invalid DNS label in domain name.");
            }
            for (unsigned char ch : label) {
                if (!std::isalnum(ch) && ch != '-') {
                    throw ValidationError("Invalid DNS character.");
                }
            }
            if (!domainDn_.empty()) domainDn_ += ",";
            domainDn_ += "DC=" + label;
        }

        OrganizationalUnit root;
        root.object = {
            "ou-root", "Domain Root", ObjectKind::OrganizationalUnit, domainDn_, true
        };
        root.parentDn = "";
        ous_.emplace(lower(domainDn_), root);
        objects_.emplace(root.object.id, root.object);
    }

    const std::string& domainDn() const {
        return domainDn_;
    }

    void addController(DomainController controller) {
        const std::string key = lower(controller.name);
        if (controllers_.count(key)) {
            throw ValidationError("Duplicate domain controller.");
        }
        controllers_.emplace(key, controller);
        record("controller-added name=" + controller.name + " site=" + controller.site);
    }

    OrganizationalUnit& createOU(
        const std::string& name,
        const std::string& parentDn,
        bool protect = true
    ) {
        if (name.empty() || name.find(',') != std::string::npos) {
            throw ValidationError("Invalid OU name.");
        }

        auto parent = ous_.find(lower(parentDn));
        if (parent == ous_.end()) throw NotFoundError("Parent OU does not exist.");

        const std::string dn = "OU=" + name + "," + parent->second.object.distinguishedName;
        ensureUniqueDn(dn);

        OrganizationalUnit ou;
        ou.object = {
            "ou-" + std::to_string(revision_ + 1),
            name,
            ObjectKind::OrganizationalUnit,
            dn,
            true
        };
        ou.parentDn = parent->second.object.distinguishedName;
        ou.protectedFromDeletion = protect;

        const std::string id = ou.object.id;
        auto [it, inserted] = ous_.emplace(lower(dn), std::move(ou));
        if (!inserted) throw ValidationError("OU insertion failed.");
        parent->second.children.insert(id);
        objects_.emplace(id, it->second.object);
        record("ou-created dn=" + dn);
        return it->second;
    }

    User& createUser(
        const std::string& displayName,
        const std::string& sam,
        const std::string& department,
        const std::string& ouDn,
        bool mfaRegistered
    ) {
        if (displayName.empty() || department.empty() || sam.empty() || sam.size() > 20) {
            throw ValidationError("Required identity fields are invalid.");
        }

        const std::string key = lower(sam);
        if (users_.count(key)) throw ValidationError("Duplicate sAMAccountName.");

        auto ou = ous_.find(lower(ouDn));
        if (ou == ous_.end()) throw NotFoundError("User OU does not exist.");

        const std::string dn = "CN=" + displayName + "," +
                               ou->second.object.distinguishedName;
        ensureUniqueDn(dn);

        User user;
        user.object = {
            "user-" + std::to_string(revision_ + 1),
            displayName,
            ObjectKind::User,
            dn,
            true
        };
        user.samAccountName = sam;
        user.upn = sam + "@" + dnsName_;
        user.department = department;
        user.mfaRegistered = mfaRegistered;

        const std::string id = user.object.id;
        auto [it, inserted] = users_.emplace(key, std::move(user));
        if (!inserted) throw ValidationError("User insertion failed.");
        objects_.emplace(id, it->second.object);
        record("user-created sam=" + sam + " dn=" + dn);
        return it->second;
    }

    SecurityGroup& createGroup(
        const std::string& name,
        GroupScope scope,
        const std::string& ouDn
    ) {
        auto ou = ous_.find(lower(ouDn));
        if (ou == ous_.end()) throw NotFoundError("Group OU does not exist.");

        const std::string dn = "CN=" + name + "," + ou->second.object.distinguishedName;
        ensureUniqueDn(dn);

        SecurityGroup group;
        group.object = {
            "group-" + std::to_string(revision_ + 1),
            name,
            ObjectKind::Group,
            dn,
            true
        };
        group.scope = scope;
        const std::string id = group.object.id;
        auto [it, inserted] = groups_.emplace(id, std::move(group));
        if (!inserted) throw ValidationError("Group insertion failed.");
        objects_.emplace(id, it->second.object);
        record("group-created name=" + name);
        return it->second;
    }

    void addMember(const std::string& groupId, const std::string& memberId) {
        auto group = groups_.find(groupId);
        if (group == groups_.end()) throw NotFoundError("Group not found.");
        if (!objects_.count(memberId)) throw NotFoundError("Member not found.");
        if (groupId == memberId) throw ValidationError("Self-membership is forbidden.");

        if (groups_.count(memberId)) {
            std::set<std::string> visited;
            if (containsGroup(memberId, groupId, visited)) {
                throw ValidationError("Nested membership would create a cycle.");
            }
        }

        group->second.members.insert(memberId);
        record("member-added group=" + groupId + " member=" + memberId);
    }

    std::set<std::string> effectiveGroups(const std::string& principalId) const {
        if (!objects_.count(principalId)) throw NotFoundError("Principal not found.");

        std::set<std::string> result;
        std::set<std::string> visited;
        std::vector<std::string> pending{principalId};

        while (!pending.empty()) {
            std::string current = pending.back();
            pending.pop_back();
            if (!visited.insert(current).second) continue;

            for (const auto& [groupId, group] : groups_) {
                if (group.members.count(current) && group.object.enabled) {
                    if (result.insert(groupId).second) pending.push_back(groupId);
                }
            }
        }
        return result;
    }

    void registerPolicy(GroupPolicy policy) {
        for (const auto& [setting, value] : policy.settings) {
            if (setting == "passwordMinLength") {
                int length = std::stoi(value);
                if (length < 8 || length > 128) {
                    throw ValidationError("Password minimum length must be 8-128.");
                }
            } else if (setting == "screenLockMinutes") {
                int minutes = std::stoi(value);
                if (minutes < 1 || minutes > 240) {
                    throw ValidationError("Screen lock must be 1-240 minutes.");
                }
            } else if (
                (setting == "firewallEnabled" ||
                 setting == "requireMfa" ||
                 setting == "usbStorageAllowed") &&
                value != "true" && value != "false"
            ) {
                throw ValidationError("Boolean policy setting has an invalid value.");
            }
        }

        if (policies_.count(policy.id)) throw ValidationError("Duplicate GPO identifier.");
        policies_.emplace(policy.id, std::move(policy));
        record("policy-registered");
    }

    void linkPolicy(PolicyLink link) {
        if (!policies_.count(link.policyId)) throw NotFoundError("Policy not found.");
        if (!ous_.count(lower(link.targetDn))) throw NotFoundError("Target OU not found.");
        if (link.order < 1) throw ValidationError("Link order must be positive.");
        links_.push_back(std::move(link));
        record("policy-linked");
    }

    std::map<std::string, std::string> effectivePolicy(
        const std::string& targetDn
    ) const {
        auto target = ous_.find(lower(targetDn));
        if (target == ous_.end()) throw NotFoundError("Policy target not found.");

        std::vector<const OrganizationalUnit*> chain;
        const OrganizationalUnit* current = &target->second;
        while (current) {
            chain.push_back(current);
            if (current->parentDn.empty()) break;

            auto parent = ous_.find(lower(current->parentDn));
            if (parent == ous_.end()) {
                throw DirectoryError("OU hierarchy contains a missing parent.");
            }
            current = &parent->second;
        }
        std::reverse(chain.begin(), chain.end());

        std::map<std::string, std::string> effective;
        std::map<std::string, std::string> enforcedValues;

        for (const auto* ou : chain) {
            std::vector<const PolicyLink*> scopedLinks;
            for (const auto& link : links_) {
                if (!link.disabled &&
                    lower(link.targetDn) == lower(ou->object.distinguishedName)) {
                    scopedLinks.push_back(&link);
                }
            }

            // Larger link-order values are applied first so order 1 wins
            // within the same scope in this simplified policy model.
            std::sort(scopedLinks.begin(), scopedLinks.end(),
                [](const PolicyLink* a, const PolicyLink* b) {
                    return a->order > b->order;
                });

            for (const PolicyLink* link : scopedLinks) {
                const auto& policy = policies_.at(link->policyId);
                if (!policy.enabled || !policy.computerConfigurationEnabled) continue;

                for (const auto& [setting, value] : policy.settings) {
                    if (link->enforced) {
                        enforcedValues[setting] = value;
                    } else if (!enforcedValues.count(setting)) {
                        effective[setting] = value;
                    }
                }
            }
        }

        effective.insert(enforcedValues.begin(), enforcedValues.end());
        for (const auto& [setting, value] : enforcedValues) effective[setting] = value;
        return effective;
    }

    bool authorize(
        const std::string& principalId,
        const std::string& requiredGroupId
    ) const {
        auto principal = objects_.find(principalId);
        if (principal == objects_.end()) throw NotFoundError("Principal not found.");
        if (!principal->second.enabled) throw DirectoryError("Principal is disabled.");
        if (!groups_.count(requiredGroupId)) throw NotFoundError("Required group not found.");

        const auto memberships = effectiveGroups(principalId);
        return memberships.count(requiredGroupId) > 0;
    }

    void reportReplication() const {
        std::cout << "\nDomain controller observations\n";
        for (const auto& [key, controller] : controllers_) {
            const auto lag = revision_ > controller.observedRevision
                ? revision_ - controller.observedRevision : 0;
            std::cout << "  " << controller.name
                      << " site=" << controller.site
                      << " reachable=" << std::boolalpha << controller.reachable
                      << " revision-lag=" << lag << '\n';
        }
    }

    void reportAudit() const {
        std::cout << "\nRecent directory audit events\n";
        const std::size_t start = audit_.size() > 6 ? audit_.size() - 6 : 0;
        for (std::size_t i = start; i < audit_.size(); ++i) {
            std::cout << "  " << audit_[i] << '\n';
        }
    }
};

int main() {
    try {
        DirectoryGovernance directory("corp.example.com", "CORP");

        directory.addController({
            "DC01", "Lucknow", {"PDC Emulator", "RID Master"}, true, true, true, 0
        });
        directory.addController({
            "DC02", "Delhi", {}, true, true, true, 0
        });

        auto& engineering = directory.createOU("Engineering", directory.domainDn());
        auto& privileged = directory.createOU(
            "Privileged", engineering.object.distinguishedName
        );

        auto& developer = directory.createUser(
            "Riya Sharma", "riya.sharma", "Engineering",
            engineering.object.distinguishedName, true
        );
        auto& operatorUser = directory.createUser(
            "Release Operator", "release.operator", "IT",
            privileged.object.distinguishedName, true
        );

        auto& developers = directory.createGroup(
            "Engineering-Developers", GroupScope::Global,
            engineering.object.distinguishedName
        );
        auto& administrators = directory.createGroup(
            "Production-Administrators", GroupScope::DomainLocal,
            privileged.object.distinguishedName
        );

        directory.addMember(developers.object.id, developer.object.id);
        directory.addMember(administrators.object.id, operatorUser.object.id);
        directory.addMember(administrators.object.id, developers.object.id);

        std::cout << "Domain: corp.example.com\n"
                  << "Domain DN: " << directory.domainDn() << '\n'
                  << "Developer DN: " << developer.object.distinguishedName << '\n';

        std::cout << "Developer effective groups: "
                  << directory.effectiveGroups(developer.object.id).size() << '\n';

        std::cout << "Developer production access: "
                  << std::boolalpha
                  << directory.authorize(developer.object.id, administrators.object.id)
                  << '\n';
        std::cout << "Release operator production access: "
                  << directory.authorize(operatorUser.object.id, administrators.object.id)
                  << '\n';

        GroupPolicy baseline{
            "gpo-baseline",
            "Corporate Security Baseline",
            {
                {"passwordMinLength", "14"},
                {"requireMfa", "true"},
                {"firewallEnabled", "true"},
                {"usbStorageAllowed", "false"},
                {"screenLockMinutes", "10"}
            },
            true,
            true
        };
        directory.registerPolicy(baseline);
        directory.linkPolicy({
            "gpo-baseline", directory.domainDn(), 1, true, false
        });

        GroupPolicy engineeringPolicy{
            "gpo-engineering",
            "Engineering Workstations",
            {
                {"usbStorageAllowed", "true"},
                {"screenLockMinutes", "20"}
            },
            true,
            true
        };
        directory.registerPolicy(engineeringPolicy);
        directory.linkPolicy({
            "gpo-engineering", engineering.object.distinguishedName, 1, false, false
        });

        std::cout << "\nEffective Engineering policy\n";
        for (const auto& [setting, value] :
             directory.effectivePolicy(engineering.object.distinguishedName)) {
            std::cout << "  " << setting << " = " << value << '\n';
        }

        try {
            directory.addMember(developers.object.id, administrators.object.id);
        } catch (const ValidationError& error) {
            std::cout << "\nRejected group cycle: " << error.what() << '\n';
        }

        try {
            GroupPolicy invalid{
                "gpo-invalid", "Invalid Policy", {{"passwordMinLength", "3"}}, true, true
            };
            directory.registerPolicy(invalid);
        } catch (const ValidationError& error) {
            std::cout << "Rejected policy: " << error.what() << '\n';
        }

        directory.reportReplication();
        directory.reportAudit();
    } catch (const std::exception& error) {
        std::cerr << "Directory case study failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
