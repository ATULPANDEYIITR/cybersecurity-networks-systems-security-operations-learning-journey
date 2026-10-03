# Linux Permissions: chmod, chown, ACLs, sudo, Ownership, and Privilege Boundaries

## Scope

Linux permissions are a discretionary access-control mechanism built around identities, ownership, permission bits, ACLs, and privileged operations. The core question is not simply whether a file has `rwx` somewhere in its mode. The effective result depends on the requesting identity, the object's owner and group, the selected permission class, ACL entries when present, directory traversal permissions, and any privileged execution path.

This repository contains three complementary implementations:

- The Python program builds a safe permission laboratory with executable models for mode bits, ownership, ACLs, directory traversal, `umask`, special bits, sudo rules, and permission auditing.
- The JavaScript program models the same domain through an event-driven policy engine. Access decisions emit audit events, making the relationship between authorization and observability explicit.
- The C++ program presents a repository-governance case study in which a shared inventory service must separate developer, auditor, and operations access while evaluating ACLs, ownership, sudo rules, and directory policy.

The implementations model Linux behavior rather than modifying the host filesystem. This distinction makes experiments reproducible and avoids requiring root privileges.

---

## Permission model

A normal Unix file mode contains three primary permission classes:

| Class | Meaning | Mode position |
|---|---|---|
| Owner | Permissions for the file's owning user | First triplet |
| Group | Permissions associated with the owning group | Second triplet |
| Other | Permissions for identities that do not match the owner or applicable group/ACL entries | Third triplet |

For example, `0640` means:

- owner: `rw-`
- group: `r--`
- other: `---`

The numeric representation is based on bit values:

| Permission | Value |
|---|---:|
| Read | `4` |
| Write | `2` |
| Execute | `1` |

A class therefore has a three-bit value. `7` is `rwx`, `6` is `rw-`, `5` is `r-x`, `4` is `r--`, and `0` grants no permission.

The important point is that Linux does not independently combine the owner, group, and other classes. The identity is matched to an applicable class, and that class supplies the ordinary mode permissions. An object owned by `alice` therefore uses the owner class for `alice`, even if `alice` also belongs to the object's group.

---

## `chmod`: changing permission bits

`chmod` changes an object's mode. Numeric notation is useful when an exact complete mode is required.

A command such as `chmod 640 audit.log` expresses the desired ordinary permission bits directly. Symbolic notation can instead change selected classes, such as `chmod g-w file`, without replacing unrelated bits.

The Python laboratory models `chmod` through its `chmod()` method. It validates the mode and permits the simulated owner or root to change it. The JavaScript engine applies the same ownership boundary while emitting a policy event. The C++ case study demonstrates that `bob` cannot change `alice`'s file merely because both users belong to `developers`.

Permission changes should be treated as policy changes. A broad `chmod 777` can make a resource writable by every local identity, while an overly restrictive mode can break legitimate service operation. The correct mode depends on the required access path.

### File versus directory permissions

The meaning of execute permission changes significantly for directories.

For a regular file:

- `r` permits reading file contents.
- `w` permits modifying file contents.
- `x` permits execution when the file is executable and the program format permits execution.

For a directory:

- `r` permits reading directory entries.
- `w` permits creating, removing, or renaming entries subject to the applicable directory rules.
- `x` provides search/traversal permission.

A user can therefore have read permission on a file and still fail to access it if the user cannot traverse one of its parent directories.

The Python `check_parent_traversal()` method explicitly walks parent directories and requires execute permission. The JavaScript `traverse()` method performs the same operation before reading or writing a target. The C++ case study uses `requireTraversal()` to make this distinction visible.

---

## Ownership and `chown`

Every normal filesystem object has an owning user and an owning group. Ownership affects which mode class applies to an access request.

`chown` changes ownership. On a typical Linux system, changing an object's owner is a privileged operation. Group ownership changes are also subject to operating-system rules and the caller's authority.

The educational models deliberately enforce a strong boundary:

- `alice` owns `stock.csv` and can change its mode.
- `alice` cannot arbitrarily transfer ownership to `bob`.
- `root` can perform the simulated ownership transfer.
- The C++ implementation restores ownership after the demonstration so later tests remain deterministic.

Ownership and permissions are different concepts. A file can be owned by `alice` while its group grants access to a development team. Changing the owner does not mean the object should automatically become inaccessible to everyone else, and changing the mode does not transfer ownership.

---

## ACLs

Traditional mode bits are intentionally compact. They distinguish the owner, owning group, and other identities, but they cannot directly express every requirement.

An Access Control List can add named user and group entries. A typical ACL can therefore express a policy such as:

- `root` owns a report.
- `operations` is the owning group.
- `carol` is not in `operations`.
- `carol` still receives read access through a named ACL entry.

The models use an `ACL` structure with:

- named users
- named groups
- an ACL mask

### ACL mask

The ACL mask is important because a named ACL entry does not necessarily represent unrestricted effective access.

The implementations intentionally create a situation where `carol` receives `rw` in a named ACL entry, followed by a mask containing only `r`. The resulting effective write permission is denied.

This demonstrates a common ACL troubleshooting mistake: inspecting only the named user entry and ignoring the mask.

For ACL-bearing files, the owning-group class and named ACL classes can be constrained by the mask. The file owner remains governed by the owner entry rather than being reduced by the ACL mask.

On a real Linux system, `getfacl` is useful when diagnosing ACL-enabled files. An `ls -l` listing can display an ACL indicator, but it does not expose the complete policy.

---

## `sudo` and privilege boundaries

`sudo` is not simply another file permission bit. It is a controlled mechanism for executing an operation with elevated authority according to a policy.

A sudo policy can allow a user to perform a particular administrative command without making that user the owner of arbitrary system files.

The examples model:

- `alice` may restart `inventory.service`.
- `alice` may inspect its service journal.
- `alice` cannot use the modeled `chown` privilege.
- `bob` has no modeled sudo rule.
- `dave` has a narrower administrative set.

The distinction matters because a rule such as unrestricted execution of an interpreter can effectively become broad administrative access. Sudo policy should therefore constrain commands and arguments where practical, and privileged commands should not unnecessarily expose arbitrary command execution.

A privilege boundary should be analyzed as a complete execution path:

`user -> sudo policy -> executable -> arguments -> filesystem/resources`

A seemingly narrow sudo rule can still be dangerous if the permitted program can invoke a shell, load arbitrary configuration, write privileged files, or execute attacker-controlled hooks.

---

## Privileged identities and root

The models represent `root` as a privileged identity that bypasses ordinary discretionary permission checks.

This is a teaching abstraction rather than a complete model of every Linux kernel restriction. Real Linux systems also contain mechanisms such as capabilities, namespaces, MAC systems, service isolation, mount options, and container boundaries.

The important operational distinction is that root is not equivalent to "a user with mode `777`". Root's authority is associated with privileged kernel operations and the effective credentials of the process.

This is why giving users unnecessary administrative privilege is fundamentally different from granting ordinary file read or write permission.

---

## `umask`

`umask` influences the permissions assigned when a process creates a new filesystem object.

The creation request starts with a requested mode and the process's umask removes permission bits. The effective mode can be conceptualized as:

`effective_mode = requested_mode & ~umask`

The Python and JavaScript implementations use a requested file mode of `0664` and demonstrate a `0027` umask. This produces a more restrictive result than the original request.

`umask` is therefore a default-creation control rather than a replacement for later permission management. Applications may request their own modes, and directory defaults, ACLs, and application behavior can further affect the resulting policy.

---

## Special permission bits

Linux modes contain more than the ordinary nine `rwx` bits.

### Setuid

The setuid bit on an executable can cause the process to run with the executable owner's effective user identity. A root-owned setuid executable therefore creates a high-impact privilege boundary.

The implementations model a hypothetical root-owned helper with mode `04750`. They do not execute it.

Setuid programs require careful security review because bugs in argument handling, environment processing, file selection, path resolution, or unsafe library use can become privilege-escalation paths.

### Setgid

The setgid bit has different effects depending on object type.

For an executable, setgid can affect the process's effective group identity.

For a directory, setgid causes newly created files and directories to inherit the directory's group in the common collaborative-directory model. The case study uses `/srv/inventory` with mode `02775` and group `operations` to represent a shared operational workspace.

This is useful when multiple users need consistent group ownership without manually running `chown` after every file creation.

### Sticky bit

The sticky bit on a directory changes deletion and rename behavior in shared writable directories. A classic example is a shared temporary directory.

The C++ and Python models represent `/srv/inventory/drop` with the sticky bit. The purpose is to distinguish "can write to the directory" from "can arbitrarily remove another user's entry".

The sticky bit does not make the contents private. It addresses ownership of directory entries and deletion/rename operations.

---

## Permission evaluation workflow

A useful diagnostic workflow is to separate the access request into distinct questions.

A process requests an operation such as reading `/srv/inventory/audit.log`.

The kernel must establish the process identity and then evaluate the target object. The ordinary mode path can be conceptualized as:

`requesting identity -> owner/group/other class -> requested permission -> allow or deny`

When an ACL exists, named entries can provide more precise access. The directory path must also be searchable, so the request cannot be reduced to the target file's mode alone.

For a path such as `/srv/inventory/audit.log`, the relevant chain includes:

`/srv` -> `/srv/inventory` -> `audit.log`

A denial can therefore originate from:

- the target file
- a parent directory
- an ACL
- a missing group membership
- an incorrect owner
- an unexpected ACL mask
- a privileged operation policy
- an application using a different effective identity than expected

This separation is particularly important when debugging services because the interactive shell user's permissions may not match the service process's credentials.

---

## Python implementation

The Python file is a self-contained permission laboratory.

Its `PermissionSystem` stores users, groups, simulated filesystem objects, ACLs, and sudo rules. `LinuxObject` represents ownership, group ownership, mode, parent directory, and optional ACL information.

`permission_decision()` implements the central access-selection mechanism. It first handles the privileged root case, then distinguishes the owner, named ACL user/group, owning group, and other classes. When an ACL is active, the implementation applies its mask to named entries and the group path.

`check_parent_traversal()` deliberately performs a separate path traversal check. This prevents the educational model from incorrectly treating target-file read permission as sufficient for path access.

The script also demonstrates:

- changing modes through `chmod()`
- privileged ownership changes through `chown()`
- named ACL users and masks
- `umask` during file creation
- setgid group inheritance
- sticky-directory semantics
- setuid as a privileged execution concern
- sudo command allowlists
- access matrices
- permission-oriented audit findings
- host filesystem metadata observation without modifying the host

The command-line interface can inspect an individual simulated object, for example `python linux_permissions.py --user alice --path /srv/inventory/stock.csv --access rw`, or run the complete laboratory with `python linux_permissions.py --all`.

---

## JavaScript implementation

The JavaScript file models permissions as an event-driven system.

`PermissionEngine` extends Node.js's `EventEmitter`. Permission operations emit `access`, `sudo`, `policy`, and `filesystem` events. This makes logging part of the system architecture rather than an afterthought.

The implementation is intentionally not a line-by-line translation of the Python program. Its focus is the relationship between policy decisions and asynchronous-style event observation:

- `read()` and `write()` emit access audit records.
- `sudo()` emits administrative policy events.
- `chmod()` and `chown()` emit policy events.
- `createFile()` emits a filesystem creation event.
- listeners format those events as audit records.

The ACL implementation uses JavaScript `Map` and `Set` structures. `AccessControlEntry` stores named users, named groups, and the mask. The engine applies the mask when resolving named ACL permissions.

The script also uses Node's `fs.statSync()` only to observe metadata for the running script. The permission laboratory itself remains simulated, so the examples do not require root privileges and cannot accidentally change real files.

Run it with a Node.js runtime using `node linux_permissions.js`.

---

## C++ case study: repository governance

The C++ program models a shared inventory repository operated by three functional groups:

| Identity | Group | Operational purpose |
|---|---|---|
| `alice` | `developers` | Maintains inventory data |
| `bob` | `developers` | Development access |
| `carol` | `auditors` | Audits reports and records |
| `dave` | `operations` | Operational administration |
| `root` | `root` | Privileged administration |

The repository contains:

- `/srv/inventory` as a setgid operational directory
- `stock.csv` owned by `alice:developers`
- `audit.log` owned by `root:operations`
- `deploy.sh` owned by `root:operations`
- `shared-report.txt` with a named ACL for `carol`
- `drop` as a shared sticky directory

The C++ data model separates `User`, `ACL`, `FileObject`, and `Decision`. This mirrors an important security design principle: identity, resource metadata, policy entries, and the result of an authorization check should not be collapsed into one undifferentiated structure.

The access engine uses `std::set` for permission collections and explicit intersection for ACL masks. This makes the mask operation visible in the implementation and gives the permission comparison deterministic behavior.

The case study also demonstrates failure handling with `PolicyError`. Unauthorized `chmod`, unauthorized `chown`, forbidden sudo commands, denied ACL changes, and failed directory traversal are treated as policy failures rather than silently ignored.

---

## Ownership, ACLs, and mode bits are not interchangeable

These mechanisms solve different parts of the authorization problem.

| Mechanism | Primary responsibility |
|---|---|
| Mode bits | Compact owner/group/other access policy |
| Ownership | Establishes the identity and group associated with an object |
| ACL | Adds named-user/group exceptions beyond the basic mode classes |
| `chmod` | Changes the mode policy |
| `chown` | Changes ownership metadata |
| `sudo` | Controls selected privileged command execution |
| `umask` | Influences permissions of newly created objects |
| Setuid | Changes effective identity for specific executable execution |
| Setgid directory | Controls group inheritance for collaborative directories |
| Sticky bit | Restricts deletion/rename behavior in shared writable directories |

A policy can use several of these simultaneously. For example, `/srv/inventory` can use setgid to maintain group ownership while a file inside it can use an ACL to grant a specific auditor access.

Treating these mechanisms as synonyms causes configuration errors.

---

## Edge cases

### Readable file inside an inaccessible directory

A target file with `0644` does not guarantee that every user can read it through its pathname. The user must be able to search each required parent directory.

### Writable directory with non-writable files

Directory write permission controls operations on directory entries. A user may be able to create or remove entries without having write permission on the contents of an existing file.

The sticky bit can further constrain deletion and rename behavior.

### ACL entry appears permissive but access fails

Inspect the ACL mask. A named entry such as `user:carol:rwx` can have effective access limited by a mask such as `r--`.

### Group membership changes

Permission checks depend on the process's credentials and group membership. A user being added to a Unix group does not mean every already-running process automatically behaves as though its credentials have been refreshed.

### Root and special security mechanisms

The simplified root model does not capture every Linux security mechanism. Capabilities, SELinux, AppArmor, namespaces, mount restrictions, seccomp, and service managers can impose additional boundaries.

### Symbolic links

The examples intentionally avoid implementing symbolic-link resolution. Real permission debugging involving links must distinguish the link itself from the target and consider pathname resolution and directory traversal.

### ACL and mode representation

When an ACL is present, interpreting only the nine visible permission characters can be misleading. The complete ACL and its mask must be inspected.

---

## Common mistakes

### Using `chmod 777` as a troubleshooting shortcut

A broad mode can hide the actual ownership or group-policy problem while creating a permanent security weakness. Troubleshooting should identify which identity requires which operation and grant only that access.

### Assuming group membership overrides ownership

A user who owns a file uses the owner class. Membership in the owning group does not cause the group class to be combined with the owner class.

### Forgetting directory execute permission

Directory `x` means search/traversal. It is frequently the missing permission when a file appears readable but access through its path fails.

### Inspecting only `ls -l`

For ACL-enabled resources, `ls -l` is not a complete authorization report. The ACL entries and mask matter.

### Treating sudo as permanent ownership

Running one command through sudo does not make the invoking user the owner of every resource touched by that command. Sudo changes the execution context according to its policy.

### Granting broad sudo access to interpreters

Allowing unrestricted privileged execution of a shell, Python interpreter, editor, or similarly extensible program can provide much broader authority than the command name suggests.

### Ignoring special bits

The leading mode digit can contain setuid, setgid, and sticky-bit information. A mode such as `4750`, `2775`, or `3770` therefore contains semantics that cannot be understood by looking only at ordinary `rwx` permissions.

---

## Security considerations

Linux permissions form one layer of a defense-in-depth model.

Least privilege should determine both file access and administrative command access. A service should run under a dedicated identity rather than a broadly privileged account when its workload permits.

Privileged files deserve strict ownership controls. A root-owned executable that is writable by an unprivileged user creates an obvious privilege-escalation path. The same principle applies indirectly to configuration files, plugins, scripts, service units, and directories searched by privileged programs.

ACLs should be audited as complete policies. A named ACL that was introduced for a temporary exception can remain long after the original requirement disappears.

Sudo rules should be narrow enough that the allowed executable and its arguments do not accidentally create a generic administrative shell.

Shared directories should be evaluated as a combination of directory mode, group ownership, setgid behavior, sticky-bit behavior, and the permissions on their contents.

---

## Debugging methodology

When an access failure occurs, identify the exact operation first: read, write, execute, create, delete, rename, or administrative command execution.

Then establish the actual identity involved. For a service, this means checking the service's process credentials rather than assuming they match the interactive user.

Inspect the target object and every relevant parent directory. Check owner, group, mode, ACL presence, and special bits.

For ACL-enabled resources, inspect the complete ACL and its mask.

For privileged operations, inspect the sudo policy and the exact command being authorized.

Useful real-system commands include `ls -l`, `stat`, `namei`, `getfacl`, `id`, `groups`, and `sudo -l`. These commands are diagnostic tools; their output must still be interpreted in the context of the process identity and the path being accessed.

---

## Performance and design considerations

Ordinary Unix mode checks are compact and efficient because the kernel can evaluate a small amount of credential and inode metadata.

ACLs provide greater policy expressiveness but require more metadata and a more involved authorization decision. This is normally a reasonable trade-off when named exceptions are genuinely required.

Large-scale systems should avoid using filesystem permissions as the only authorization layer for application-level business rules. A filesystem can determine whether a process may read a file, but it does not inherently understand concepts such as which customer owns a record or which application role may approve a transaction.

The C++ implementation keeps authorization data separate from presentation and uses deterministic containers. This makes policy decisions testable and reduces accidental coupling between data storage and access evaluation.

---

## Production considerations

A production Linux permission design should establish clear ownership for application data, configuration, logs, sockets, deployment artifacts, and secrets.

Shared application directories should have explicit group ownership and deliberate setgid behavior when group collaboration is required.

Sensitive files should not rely on obscurity. Secrets should receive restrictive ownership and mode settings, and applications should avoid logging secret material.

Administrative operations should use tightly scoped privilege policies. Privileged execution should be auditable, and changes to ownership, ACLs, and special permission bits should be treated as security-sensitive configuration changes.

Permission audits should look for unexpected world-writable resources, writable files used by privileged programs, unexpected setuid/setgid binaries, stale ACL entries, excessive sudo rules, and shared directories whose policy does not match their intended collaboration model.

The most important production distinction is between **who owns a resource**, **who can access it**, and **who is allowed to perform an administrative operation**. Linux provides separate mechanisms for each of these questions, and secure configurations depend on keeping those responsibilities explicit.
