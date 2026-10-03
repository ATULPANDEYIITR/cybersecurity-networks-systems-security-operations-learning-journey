#include <algorithm>
#include <bitset>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Linux Repository Governance Engine
 *
 * Case study:
 * A company operates a shared inventory repository on Linux. Developers,
 * auditors, and operations engineers need different access to deployment
 * files, reports, logs, and shared directories.
 *
 * The engine evaluates:
 *   - owner/group/other mode bits
 *   - named ACL users and ACL masks
 *   - directory traversal
 *   - ownership changes
 *   - sudo command policy
 *   - setgid and sticky-bit semantics
 *   - creation under a umask
 *   - audit findings
 *
 * It is a policy model rather than a wrapper around chmod/chown. No host
 * filesystem is modified, making the case study deterministic and safe.
 *
 * Build:
 *   g++ -std=c++17 -Wall -Wextra -pedantic linux_permissions.cpp -o permissions
 */

enum class Permission {
    Read,
    Write,
    Execute
};

using PermissionSet = std::set<Permission>;

std::string permissionText(const PermissionSet& permissions) {
    std::string result;
    if (permissions.count(Permission::Read)) result += 'r';
    if (permissions.count(Permission::Write)) result += 'w';
    if (permissions.count(Permission::Execute)) result += 'x';
    return result;
}

int permissionBits(const PermissionSet& permissions) {
    int bits = 0;
    if (permissions.count(Permission::Read)) bits |= 4;
    if (permissions.count(Permission::Write)) bits |= 2;
    if (permissions.count(Permission::Execute)) bits |= 1;
    return bits;
}

PermissionSet permissionsFromBits(int bits) {
    PermissionSet result;
    if (bits & 4) result.insert(Permission::Read);
    if (bits & 2) result.insert(Permission::Write);
    if (bits & 1) result.insert(Permission::Execute);
    return result;
}

PermissionSet intersect(
    const PermissionSet& left,
    const PermissionSet& right
) {
    PermissionSet result;
    std::set_intersection(
        left.begin(), left.end(),
        right.begin(), right.end(),
        std::inserter(result, result.begin())
    );
    return result;
}

bool containsAll(
    const PermissionSet& available,
    const PermissionSet& requested
) {
    return std::includes(
        available.begin(), available.end(),
        requested.begin(), requested.end()
    );
}

std::string modeText(uint16_t mode, bool directory) {
    std::string result = directory ? "d" : "-";

    const int shifts[] = {6, 3, 0};

    for (int shift : shifts) {
        const int bits = (mode >> shift) & 7;
        result += (bits & 4) ? 'r' : '-';
        result += (bits & 2) ? 'w' : '-';
        result += (bits & 1) ? 'x' : '-';
    }

    if (mode & 04000) {
        result[3] = (mode & 0100) ? 's' : 'S';
    }

    if (mode & 02000) {
        result[6] = (mode & 0010) ? 's' : 'S';
    }

    if (mode & 01000) {
        result[9] = (mode & 0001) ? 't' : 'T';
    }

    return result;
}

struct User {
    std::string name;
    int uid;
    std::set<std::string> groups;
    bool root{false};
};

struct ACL {
    std::map<std::string, PermissionSet> users;
    std::map<std::string, PermissionSet> groups;
    PermissionSet mask{
        Permission::Read,
        Permission::Write,
        Permission::Execute
    };
};

struct FileObject {
    std::string path;
    bool directory;
    std::string owner;
    std::string group;
    uint16_t mode;
    std::string parent;
    std::optional<ACL> acl;
};

struct Decision {
    bool allowed;
    std::string source;
    PermissionSet available;
    std::string reason;
};

class PolicyError : public std::runtime_error {
public:
    explicit PolicyError(const std::string& message)
        : std::runtime_error(message) {}
};

class RepositoryGovernance {
private:
    std::map<std::string, User> users;
    std::map<std::string, FileObject> objects;
    std::map<std::string, std::set<std::string>> sudoRules;
    uint16_t umask{0022};

    const User& user(const std::string& username) const {
        const auto iterator = users.find(username);
        if (iterator == users.end()) {
            throw PolicyError("unknown user: " + username);
        }
        return iterator->second;
    }

    FileObject& object(const std::string& path) {
        const auto iterator = objects.find(path);
        if (iterator == objects.end()) {
            throw PolicyError("unknown path: " + path);
        }
        return iterator->second;
    }

    const FileObject& object(const std::string& path) const {
        const auto iterator = objects.find(path);
        if (iterator == objects.end()) {
            throw PolicyError("unknown path: " + path);
        }
        return iterator->second;
    }

    bool memberOf(
        const User& principal,
        const std::string& group
    ) const {
        return principal.groups.count(group) != 0;
    }

    std::optional<std::pair<PermissionSet, std::string>> namedAcl(
        const FileObject& file,
        const User& principal
    ) const {
        if (!file.acl) {
            return std::nullopt;
        }

        const auto userEntry = file.acl->users.find(principal.name);
        if (userEntry != file.acl->users.end()) {
            return std::make_pair(
                intersect(userEntry->second, file.acl->mask),
                "named ACL user:" + principal.name
            );
        }

        for (const auto& group : principal.groups) {
            const auto groupEntry = file.acl->groups.find(group);
            if (groupEntry != file.acl->groups.end()) {
                return std::make_pair(
                    intersect(groupEntry->second, file.acl->mask),
                    "named ACL group:" + group
                );
            }
        }

        return std::nullopt;
    }

    void requireTraversal(
        const std::string& username,
        const std::string& path
    ) const {
        const User& principal = user(username);

        std::stringstream stream(path);
        std::string component;
        std::string current;

        std::vector<std::string> components;

        while (std::getline(stream, component, '/')) {
            if (!component.empty()) {
                components.push_back(component);
            }
        }

        /*
         * Every parent directory must grant execute/search permission.
         * This is separate from the final file's read permission.
         */
        for (std::size_t index = 0; index + 1 < components.size(); ++index) {
            current += "/" + components[index];

            const FileObject& parent = object(current);
            Decision decision = decide(
                principal.name,
                current,
                PermissionSet{Permission::Execute}
            );

            if (!decision.allowed) {
                throw PolicyError(
                    "directory traversal denied at " + parent.path
                );
            }
        }
    }

public:
    RepositoryGovernance() {
        addUser({
            "root",
            0,
            {"root"},
            true
        });

        addUser({
            "alice",
            1001,
            {"developers"},
            false
        });

        addUser({
            "bob",
            1002,
            {"developers"},
            false
        });

        addUser({
            "carol",
            1003,
            {"auditors"},
            false
        });

        addUser({
            "dave",
            1004,
            {"operations"},
            false
        });

        sudoRules["alice"] = {
            "systemctl restart inventory.service",
            "journalctl -u inventory.service"
        };

        sudoRules["dave"] = {
            "systemctl restart inventory.service",
            "chown"
        };

        objects["/srv"] = {
            "/srv",
            true,
            "root",
            "root",
            0755,
            "",
            std::nullopt
        };

        objects["/srv/inventory"] = {
            "/srv/inventory",
            true,
            "root",
            "operations",
            02775,
            "/srv",
            std::nullopt
        };

        objects["/srv/inventory/stock.csv"] = {
            "/srv/inventory/stock.csv",
            false,
            "alice",
            "developers",
            0664,
            "/srv/inventory",
            std::nullopt
        };

        objects["/srv/inventory/audit.log"] = {
            "/srv/inventory/audit.log",
            false,
            "root",
            "operations",
            0640,
            "/srv/inventory",
            std::nullopt
        };

        objects["/srv/inventory/deploy.sh"] = {
            "/srv/inventory/deploy.sh",
            false,
            "root",
            "operations",
            0750,
            "/srv/inventory",
            std::nullopt
        };

        ACL reportAcl;
        reportAcl.users["carol"] = {Permission::Read};
        reportAcl.mask = {Permission::Read};

        objects["/srv/inventory/shared-report.txt"] = {
            "/srv/inventory/shared-report.txt",
            false,
            "root",
            "operations",
            0640,
            "/srv/inventory",
            reportAcl
        };

        objects["/srv/inventory/drop"] = {
            "/srv/inventory/drop",
            true,
            "root",
            "operations",
            03770,
            "/srv/inventory",
            std::nullopt
        };
    }

    void addUser(const User& newUser) {
        users[newUser.name] = newUser;
    }

    Decision decide(
        const std::string& username,
        const std::string& path,
        const PermissionSet& requested
    ) const {
        const User& principal = user(username);
        const FileObject& file = object(path);

        if (principal.root) {
            return {
                true,
                "root",
                {Permission::Read, Permission::Write, Permission::Execute},
                "root bypasses ordinary discretionary access checks"
            };
        }

        PermissionSet available;
        std::string source;
        std::string reason;

        if (principal.name == file.owner) {
            available = permissionsFromBits((file.mode >> 6) & 7);
            source = "owner";
            reason = "owner mode bits";
        } else if (auto acl = namedAcl(file, principal)) {
            available = acl->first;
            source = "ACL";
            reason = acl->second;
        } else if (memberOf(principal, file.group)) {
            available = permissionsFromBits((file.mode >> 3) & 7);

            if (file.acl) {
                available = intersect(available, file.acl->mask);
                reason = "owning group bits limited by ACL mask";
            } else {
                reason = "owning group mode bits";
            }

            source = "group";
        } else {
            available = permissionsFromBits(file.mode & 7);
            source = "other";
            reason = "other mode bits";
        }

        if (!containsAll(available, requested)) {
            std::string missing;

            for (Permission permission : requested) {
                if (!available.count(permission)) {
                    missing += permission == Permission::Read
                        ? 'r'
                        : permission == Permission::Write
                            ? 'w'
                            : 'x';
                }
            }

            reason += "; missing " + missing;
            return {false, source, available, reason};
        }

        return {true, source, available, reason};
    }

    void printObject(const std::string& path) const {
        const FileObject& file = object(path);

        std::cout
            << modeText(file.mode, file.directory)
            << " "
            << std::oct
            << std::setw(4)
            << std::setfill('0')
            << file.mode
            << std::dec
            << std::setfill(' ')
            << " "
            << file.owner
            << ":"
            << file.group
            << " "
            << file.path
            << "\n";
    }

    void chmod(
        const std::string& actor,
        const std::string& path,
        uint16_t newMode
    ) {
        const User& principal = user(actor);
        FileObject& file = object(path);

        if (!principal.root && principal.name != file.owner) {
            throw PolicyError(
                "chmod denied: actor is neither owner nor privileged"
            );
        }

        if (newMode > 07777) {
            throw PolicyError("chmod mode exceeds 07777");
        }

        file.mode = newMode;
        std::cout
            << "chmod " << std::oct << newMode
            << std::dec << " " << path << "\n";
    }

    void chown(
        const std::string& actor,
        const std::string& path,
        const std::string& newOwner,
        const std::string& newGroup
    ) {
        const User& principal = user(actor);
        FileObject& file = object(path);

        if (!principal.root) {
            throw PolicyError(
                "chown denied: ownership changes require privilege"
            );
        }

        user(newOwner);

        file.owner = newOwner;
        file.group = newGroup;

        std::cout
            << "chown "
            << newOwner
            << ":"
            << newGroup
            << " "
            << path
            << "\n";
    }

    void setAclUser(
        const std::string& actor,
        const std::string& path,
        const std::string& targetUser,
        PermissionSet permissions
    ) {
        const User& principal = user(actor);
        FileObject& file = object(path);

        if (!principal.root && principal.name != file.owner) {
            throw PolicyError("setfacl denied: insufficient authority");
        }

        user(targetUser);

        if (!file.acl) {
            file.acl = ACL{};
        }

        file.acl->users[targetUser] = std::move(permissions);

        std::cout
            << "ACL user:"
            << targetUser
            << "="
            << permissionText(file.acl->users[targetUser])
            << " "
            << path
            << "\n";
    }

    void setAclMask(
        const std::string& actor,
        const std::string& path,
        PermissionSet permissions
    ) {
        const User& principal = user(actor);
        FileObject& file = object(path);

        if (!principal.root && principal.name != file.owner) {
            throw PolicyError("setfacl mask denied: insufficient authority");
        }

        if (!file.acl) {
            file.acl = ACL{};
        }

        file.acl->mask = std::move(permissions);

        std::cout
            << "ACL mask="
            << permissionText(file.acl->mask)
            << " "
            << path
            << "\n";
    }

    void read(
        const std::string& username,
        const std::string& path
    ) const {
        requireTraversal(username, path);

        const Decision decision = decide(
            username,
            path,
            {Permission::Read}
        );

        std::cout
            << "[read] "
            << username
            << " "
            << path
            << " -> "
            << (decision.allowed ? "ALLOW" : "DENY")
            << " ["
            << decision.source
            << "] "
            << decision.reason
            << "\n";

        if (!decision.allowed) {
            throw PolicyError("read operation denied");
        }
    }

    void write(
        const std::string& username,
        const std::string& path
    ) const {
        requireTraversal(username, path);

        const Decision decision = decide(
            username,
            path,
            {Permission::Write}
        );

        std::cout
            << "[write] "
            << username
            << " "
            << path
            << " -> "
            << (decision.allowed ? "ALLOW" : "DENY")
            << " ["
            << decision.source
            << "] "
            << decision.reason
            << "\n";

        if (!decision.allowed) {
            throw PolicyError("write operation denied");
        }
    }

    std::string createFile(
        const std::string& username,
        const std::string& directory,
        const std::string& filename
    ) {
        const FileObject& parent = object(directory);

        if (!parent.directory) {
            throw PolicyError("creation parent is not a directory");
        }

        const Decision decision = decide(
            username,
            directory,
            {Permission::Write, Permission::Execute}
        );

        if (!decision.allowed) {
            throw PolicyError(
                "creation denied: " + decision.reason
            );
        }

        const std::string path =
            directory + "/" + filename;

        if (objects.count(path)) {
            throw PolicyError("object already exists: " + path);
        }

        const User& principal = user(username);

        std::string inheritedGroup;

        if (parent.mode & 02000) {
            inheritedGroup = parent.group;
        } else if (!principal.groups.empty()) {
            inheritedGroup = *principal.groups.begin();
        } else {
            inheritedGroup = "users";
        }

        const uint16_t requestedMode = 0664;
        const uint16_t effectiveMode =
            requestedMode & static_cast<uint16_t>(~umask);

        objects[path] = {
            path,
            false,
            username,
            inheritedGroup,
            effectiveMode,
            directory,
            std::nullopt
        };

        std::cout
            << "[create] "
            << path
            << " owner="
            << username
            << " group="
            << inheritedGroup
            << " mode="
            << std::oct
            << effectiveMode
            << std::dec
            << "\n";

        return path;
    }

    void sudo(
        const std::string& username,
        const std::string& command
    ) const {
        const User& principal = user(username);

        if (principal.root) {
            std::cout
                << "[sudo] root directly executes "
                << command
                << "\n";
            return;
        }

        const auto iterator = sudoRules.find(username);
        const bool allowed =
            iterator != sudoRules.end() &&
            iterator->second.count(command) != 0;

        std::cout
            << "[sudo] "
            << username
            << " -> "
            << command
            << " : "
            << (allowed ? "ALLOW" : "DENY")
            << "\n";

        if (!allowed) {
            throw PolicyError("sudo rule does not permit command");
        }

        std::cout
            << "       effective administrative identity: root\n";
    }

    void setUmask(uint16_t newUmask) {
        if (newUmask > 0777) {
            throw PolicyError("umask must fit within 0777");
        }
        umask = newUmask;
    }

    std::vector<std::string> audit() const {
        std::vector<std::string> findings;

        for (const auto& [path, file] : objects) {
            if (file.mode & 0002) {
                findings.push_back(
                    "world-writable object: " + path
                );
            }

            if (file.mode & 04000) {
                findings.push_back(
                    "setuid object requires privileged review: " + path
                );
            }

            if (file.mode & 02000 && file.directory) {
                findings.push_back(
                    "setgid directory controls collaborative group inheritance: "
                    + path
                );
            }

            if (file.mode & 01000 && file.directory) {
                findings.push_back(
                    "sticky directory applies deletion/rename restrictions: "
                    + path
                );
            }

            if (file.acl) {
                for (const auto& [username, permissions] : file.acl->users) {
                    if (permissions.count(Permission::Write)) {
                        findings.push_back(
                            "named ACL grants write to "
                            + username
                            + ": "
                            + path
                        );
                    }
                }
            }
        }

        return findings;
    }

    void demonstrateAccessMatrix() const {
        struct Test {
            std::string user;
            std::string path;
            PermissionSet permissions;
        };

        const std::vector<Test> tests = {
            {
                "alice",
                "/srv/inventory/stock.csv",
                {Permission::Read, Permission::Write}
            },
            {
                "bob",
                "/srv/inventory/stock.csv",
                {Permission::Read, Permission::Write}
            },
            {
                "carol",
                "/srv/inventory/audit.log",
                {Permission::Read}
            },
            {
                "dave",
                "/srv/inventory/audit.log",
                {Permission::Read}
            },
            {
                "carol",
                "/srv/inventory/shared-report.txt",
                {Permission::Read}
            },
            {
                "bob",
                "/srv/inventory/deploy.sh",
                {Permission::Execute}
            }
        };

        std::cout << "\n=== Access matrix ===\n";

        for (const auto& test : tests) {
            const Decision decision =
                decide(test.user, test.path, test.permissions);

            std::cout
                << std::left
                << std::setw(7)
                << test.user
                << std::setw(4)
                << permissionText(test.permissions)
                << std::setw(38)
                << test.path
                << std::setw(7)
                << (decision.allowed ? "ALLOW" : "DENY")
                << "["
                << decision.source
                << "] "
                << decision.reason
                << "\n";
        }
    }

    void runCaseStudy() {
        std::cout << "Linux Repository Governance Engine\n";
        std::cout << "==================================\n";

        std::cout << "\n=== Initial repository objects ===\n";
        printObject("/srv");
        printObject("/srv/inventory");
        printObject("/srv/inventory/stock.csv");
        printObject("/srv/inventory/audit.log");
        printObject("/srv/inventory/deploy.sh");
        printObject("/srv/inventory/shared-report.txt");
        printObject("/srv/inventory/drop");

        std::cout << "\n=== Ownership boundary ===\n";

        try {
            chown(
                "alice",
                "/srv/inventory/stock.csv",
                "bob",
                "developers"
            );
        } catch (const PolicyError& error) {
            std::cout
                << "Expected denial: "
                << error.what()
                << "\n";
        }

        chown(
            "root",
            "/srv/inventory/stock.csv",
            "bob",
            "developers"
        );

        printObject("/srv/inventory/stock.csv");

        chown(
            "root",
            "/srv/inventory/stock.csv",
            "alice",
            "developers"
        );

        std::cout << "\n=== chmod boundary ===\n";

        try {
            chmod(
                "bob",
                "/srv/inventory/stock.csv",
                0600
            );
        } catch (const PolicyError& error) {
            std::cout
                << "Expected denial: "
                << error.what()
                << "\n";
        }

        chmod(
            "alice",
            "/srv/inventory/stock.csv",
            0660
        );

        printObject("/srv/inventory/stock.csv");

        chmod(
            "alice",
            "/srv/inventory/stock.csv",
            0664
        );

        std::cout << "\n=== ACL named-user access ===\n";

        const std::string report =
            "/srv/inventory/shared-report.txt";

        Decision before = decide(
            "carol",
            report,
            {Permission::Write}
        );

        std::cout
            << "carol write before ACL change: "
            << (before.allowed ? "ALLOW" : "DENY")
            << " ["
            << before.source
            << "] "
            << before.reason
            << "\n";

        setAclUser(
            "root",
            report,
            "carol",
            {Permission::Read, Permission::Write}
        );

        setAclMask(
            "root",
            report,
            {Permission::Read, Permission::Write}
        );

        Decision after = decide(
            "carol",
            report,
            {Permission::Write}
        );

        std::cout
            << "carol write after ACL change: "
            << (after.allowed ? "ALLOW" : "DENY")
            << " ["
            << after.source
            << "] "
            << after.reason
            << "\n";

        /*
         * The ACL mask is an upper bound for named ACL entries and the
         * owning group class. A permissive named entry can therefore still
         * fail when the mask is reduced.
         */
        setAclMask(
            "root",
            report,
            {Permission::Read}
        );

        Decision masked = decide(
            "carol",
            report,
            {Permission::Write}
        );

        std::cout
            << "carol write after mask reduction: "
            << (masked.allowed ? "ALLOW" : "DENY")
            << " ["
            << masked.source
            << "] "
            << masked.reason
            << "\n";

        std::cout << "\n=== Directory traversal boundary ===\n";

        FileObject& inventory = object("/srv/inventory");
        const uint16_t originalMode = inventory.mode;

        inventory.mode = 0770;

        try {
            read(
                "carol",
                "/srv/inventory/shared-report.txt"
            );
        } catch (const PolicyError& error) {
            std::cout
                << "Expected traversal denial: "
                << error.what()
                << "\n";
        }

        inventory.mode = originalMode;

        std::cout << "\n=== sudo policy ===\n";

        sudo(
            "alice",
            "systemctl restart inventory.service"
        );

        try {
            sudo(
                "alice",
                "chown"
            );
        } catch (const PolicyError& error) {
            std::cout
                << "Expected sudo denial: "
                << error.what()
                << "\n";
        }

        try {
            sudo(
                "bob",
                "systemctl restart inventory.service"
            );
        } catch (const PolicyError& error) {
            std::cout
                << "Expected sudo denial: "
                << error.what()
                << "\n";
        }

        std::cout << "\n=== umask and setgid collaboration ===\n";

        setUmask(0027);

        const std::string created =
            createFile(
                "alice",
                "/srv/inventory",
                "generated-report.csv"
            );

        printObject(created);

        std::cout
            << "The parent directory has setgid, so the new file uses "
               "the directory's operations group in this model.\n";

        std::cout << "\n=== Special-bit interpretation ===\n";

        std::cout
            << "/srv/inventory mode 02775 -> "
            << modeText(
                object("/srv/inventory").mode,
                true
            )
            << "\n";

        std::cout
            << "/srv/inventory/drop mode 03770 -> "
            << modeText(
                object("/srv/inventory/drop").mode,
                true
            )
            << "\n";

        std::cout
            << "A hypothetical root-owned helper with 04750 would have "
               "setuid semantics and therefore deserves strict code and "
               "ownership review.\n";

        demonstrateAccessMatrix();

        std::cout << "\n=== Audit findings ===\n";

        const std::vector<std::string> findings = audit();

        if (findings.empty()) {
            std::cout << "No findings.\n";
        } else {
            for (const auto& finding : findings) {
                std::cout << "- " << finding << "\n";
            }
        }

        std::cout << "\n=== Design observations ===\n";
        std::cout
            << "Mode bits answer the basic owner/group/other question.\n";
        std::cout
            << "ACLs add named principals while retaining a mask constraint.\n";
        std::cout
            << "sudo authorizes selected commands rather than changing "
               "ordinary file ownership permanently.\n";
        std::cout
            << "Directory execute permission controls traversal and is "
               "independent from reading a target file.\n";
        std::cout
            << "setgid and sticky bits alter directory collaboration rules, "
               "so numeric modes cannot be interpreted as only rwx flags.\n";
    }
};

int main() {
    try {
        RepositoryGovernance governance;
        governance.runCaseStudy();
        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal policy-model error: "
            << error.what()
            << "\n";
        return 1;
    }
}
