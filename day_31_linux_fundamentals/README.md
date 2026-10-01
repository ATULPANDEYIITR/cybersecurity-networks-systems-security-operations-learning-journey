# Linux Fundamentals: Filesystem, Processes, Users, Groups, Permissions, Packages, and Services

## Scope

This repository presents Linux fundamentals as an interconnected operating-system model rather than as isolated commands.

The implementations cover:

- The Linux filesystem hierarchy and filesystem metadata
- Unix users, groups, ownership, and permission classes
- Process identity, parent-child relationships, lifecycle, and `/proc`
- Package repositories and dependency resolution
- Long-running services and service supervision
- The relationship between filesystem access, runtime identity, installed software, and service operation
- Security, failure analysis, and operational design considerations

The Python program is an executable laboratory and simulator. The JavaScript program models the same domain through Node.js event-driven mechanisms. The C++ program turns the concepts into a coherent service-governance case study.

The implementations deliberately avoid destructive administration. They inspect available host information where appropriate and otherwise model privileged operations in memory.

---

## Linux as a System of Interacting Mechanisms

A Linux application does not operate independently of the operating system.

A simplified deployment relationship is:

`filesystem objects -> ownership and permissions -> user/group identity -> process -> package dependencies -> service supervision`

A service executable may be installed by a package manager, stored somewhere in the filesystem, owned by a particular account, started by a service manager, and executed under a restricted service identity. The running process then attempts to read configuration, access libraries, create files, open logs, communicate over the network, and consume system resources.

A failure at one layer can appear as a failure at another layer.

For example, a service may be correctly registered with a service manager but fail during startup because its runtime account cannot read its configuration file. In that situation, restarting the service does not fix the underlying filesystem authorization problem.

---

# Filesystem Fundamentals

Linux exposes a single hierarchical namespace rooted at `/`.

Common directories have different operational roles.

| Path | Typical role |
|---|---|
| `/` | Root of the filesystem hierarchy |
| `/etc` | System and application configuration |
| `/home` | Home directories for regular users |
| `/tmp` | Temporary files |
| `/var` | Variable data such as logs, caches, and queues |
| `/usr` | User-space programs, libraries, and shared data |
| `/proc` | Kernel-generated process and system information |
| `/sys` | Kernel device and subsystem information |
| `/dev` | Device nodes |

The exact contents vary by distribution and installation.

Linux filesystem entries have metadata associated with them. Important metadata includes the object type, owner UID, group GID, permission bits, size, timestamps, and, depending on the filesystem, additional attributes and security metadata.

The Python implementation uses `pathlib.Path.lstat()` to inspect an entry without automatically following a symbolic link. This distinction matters when the administrator needs to determine whether the link itself or its target is being examined.

The JavaScript implementation uses `fs.lstatSync()` for the same conceptual reason.

The implementations recognize regular files, directories, symbolic links, sockets, FIFOs, and other filesystem object types where the runtime exposes them.

## Files and directories have different permission semantics

For a regular file:

- `r` permits reading its contents.
- `w` permits modifying its contents, subject to other system controls.
- `x` permits execution.

For a directory:

- `r` permits listing directory entries.
- `w` permits creating, removing, or renaming entries when the required traversal permissions are also available.
- `x` permits traversal through the directory.

This distinction is important when debugging errors such as "permission denied." A user might be able to see a directory's name but still be unable to enter it because the directory lacks the required execute permission.

---

# Users, Groups, Ownership, and Permission Classes

Linux processes have credentials. A process normally has a user identity represented by a UID and group memberships represented through a primary group and supplementary groups.

Filesystem objects traditionally associate:

- An owner UID
- A group GID
- Permission bits divided into owner, group, and other classes

A mode such as `0750` can be read as:

`0 | 7 | 5 | 0`

The first position represents special mode information in the conventional four-digit representation. The remaining three digits correspond to owner, group, and other.

`7` means `rwx`, `5` means `r-x`, and `0` means `---`.

Therefore `0750` means:

`rwxr-x---`

The critical permission-selection rule demonstrated by all three implementations is that the traditional owner/group/other classes are not simply combined.

If the process user is the inode owner, the owner permission class is selected.

If the process is not the owner but belongs to the inode's group, the group class is selected.

Otherwise, the other class is selected.

This is why adding a user to a file's group does not automatically augment permissions that are already selected through the owner class.

---

# Special Permission Bits

Linux permission modes also contain special bits.

The implementations demonstrate the conceptual significance of:

- Setuid
- Setgid
- Sticky bit

A directory such as `02770` contains the setgid bit. On a directory, setgid commonly causes newly created files and directories to inherit the directory's group, supporting collaborative directory trees.

A directory such as `/tmp` commonly uses the sticky-bit concept. The sticky bit restricts which users can remove or rename entries in a shared writable directory.

These mechanisms should not be confused with ordinary read, write, and execute permissions.

---

# Umask

The Python implementation explicitly models `umask`.

When a process creates a file or directory, it requests a creation mode. The process umask removes selected permission bits from that requested mode.

For example:

`requested mode = 0666`

`umask = 0027`

The conceptual result is:

`0640`

For directories, a requested mode of `0777` with the same umask produces:

`0750`

The umask is therefore a restriction applied during object creation. It is not an additional permission grant.

The actual kernel behavior is more nuanced because creation APIs, filesystem behavior, default ACLs, and application choices can affect the final result, but the bit-removal rule is the foundation demonstrated by the Python program.

---

# Users and Groups in the Python Implementation

The Python program defines `LinuxUser` and `LinuxFile` data structures.

A user such as `alice` can have:

- A username
- A UID
- A primary group
- Supplementary groups

A file such as `deploy.sh` can have:

- A name
- An owner
- A group
- A mode

The `effective_permission()` function models selection of the owner, group, or other permission class before testing a particular bit.

The program also inspects the real execution identity when available through POSIX Python facilities such as `os.getuid()`, `os.getgid()`, `pwd`, and `grp`.

This creates a useful distinction between:

- A simulated identity used for controlled educational experiments
- The actual identity of the Python process executing the program

---

# Permissions and Security

Traditional Unix mode bits are powerful but are not the complete Linux authorization model.

A production system can also involve:

- POSIX ACLs
- SELinux or another Linux Security Module
- Capabilities
- Mount options
- Namespace isolation
- Container security policies
- Application-level authorization
- Filesystem-specific behavior

A successful mode-bit check therefore does not prove that an operation will succeed.

Conversely, a mode-bit denial may not be the only authorization barrier involved.

Security-sensitive files such as private keys, credential stores, and service configuration should generally avoid unnecessary world readability or writability.

A long-running service also commonly uses a dedicated account rather than running as root when its functionality does not require unrestricted privileges.

---

# Processes

A process is a running instance of a program.

A Linux process has substantially more state than an executable filename. Its operating-system context can include:

- PID
- Parent PID
- User and group credentials
- Address space
- Open file descriptors
- Environment
- Current working directory
- Signal state
- Scheduling state
- Resource limits
- Memory mappings
- Namespace membership
- Security credentials

The parent-child relationship is represented through process IDs.

The Python implementation reads `/proc/<pid>/status` on Linux. This demonstrates how `/proc` exposes kernel-maintained process information through a pseudo-filesystem.

The JavaScript implementation reads `/proc/<pid>/status` through Node's filesystem APIs.

The C++ implementation models a process table containing PID, PPID, executable, runtime user, lifecycle state, and exit code.

## `/proc` is not an ordinary persistent data directory

`/proc` is a pseudo-filesystem provided by the kernel. Its contents change as processes start and exit.

This creates an important race condition during process inspection:

A process can exist when a directory listing is performed and disappear before its status file is read.

The Python implementation therefore handles `FileNotFoundError` and related operating-system errors during inspection rather than assuming that a previously observed PID remains valid.

The same operational principle is represented in the JavaScript implementation.

---

# Safe Process Creation

The Python implementation uses `subprocess.run()` with an argument list rather than constructing a shell command.

The JavaScript implementation uses Node's `execFile()`.

This is an important security distinction.

When dynamic input is interpolated into a shell command, shell metacharacters can change the meaning of the command. Passing an executable and its arguments separately avoids unnecessary shell interpretation.

This does not make arbitrary process execution automatically safe. The executable itself, arguments, environment, working directory, privileges, and output handling still require validation.

---

# Process States and Failure Handling

The C++ case study models:

`created -> running -> stopped`

and a failure state:

`running -> failed`

A real Linux process has richer lifecycle behavior, including creation, scheduling, signals, termination, exit status, zombie state, and reaping by a parent or appropriate supervisor.

The simplified model is intended to isolate the relationship between process identity and service operation without pretending that the model is a complete kernel process implementation.

---

# Package Management

Linux distributions generally use package management systems to install, upgrade, remove, and track software.

Examples of package ecosystems include Debian-family packages and RPM-family packages. The exact commands and metadata formats depend on the distribution.

The educational implementations do not modify the host package database.

Instead, they model the most important structural concept: dependency resolution.

A package may require another package before it can operate.

For example:

`monitor-agent -> http-client -> libssl`

means the monitoring agent depends on the HTTP client, which in turn depends on a cryptographic library.

The dependency relationship can be represented as a directed graph.

A valid installation order is a topological ordering of that graph when the dependency graph is acyclic.

The implementations detect missing dependencies and dependency cycles rather than silently producing an invalid installation plan.

Real package managers perform many additional tasks, including package metadata management, version selection, conflict handling, file ownership tracking, upgrades, removal, repository interaction, and package verification according to the distribution's security model.

---

# Package Files and the Filesystem

Package management and filesystem administration are closely connected but should not be treated as the same mechanism.

A package describes software that should be installed and maintained.

The filesystem contains the actual paths occupied by that software.

For example, a package might install an executable under `/usr/bin` or another distribution-specific location, while configuration can reside under `/etc` and variable application data under `/var`.

If a package is installed but a service cannot execute correctly, administrators need to distinguish between:

- Missing package dependencies
- Missing executable files
- Incorrect filesystem permissions
- Incorrect ownership
- Invalid service configuration
- Runtime dependency failures
- Application-level errors

This distinction prevents unrelated fixes from being applied to the wrong layer.

---

# Services

A service is generally a long-running process or group of processes managed as an operational unit.

Modern Linux distributions frequently use systemd, although service-management technology varies across systems.

A service manager can provide functionality such as:

- Starting and stopping units
- Enabling units for boot-time activation
- Monitoring process state
- Restarting failed services
- Expressing dependencies
- Managing targets and ordering
- Collecting or integrating logs
- Applying resource and security controls

The Python `ServiceManagerSimulator` models service registration, starting, stopping, failure, and restart-on-failure behavior.

The JavaScript `ServiceSupervisor` uses Node's `EventEmitter` to represent service lifecycle events. This is intentionally JavaScript-specific: service state changes become events that other parts of the program can observe.

The C++ implementation models a service as part of a larger governance system rather than as an isolated state machine.

---

# Runtime Identity and Services

A service's runtime account is one of the most important connections between process management and filesystem permissions.

Consider:

`monitor-agent.service`

running as:

`monitor`

with configuration:

`/etc/monitor/monitor.conf`

and logs:

`/var/log/monitor`

The service may start successfully only if the `monitor` identity can read its configuration and write its required runtime directories.

The C++ case study deliberately gives the service:

- A dedicated `monitor` account
- Membership in the `webops` group
- Read access to a root-owned configuration file through group permissions
- Write and traversal access to the log directory
- A separately installed package dependency

The service does not need unrestricted root access for these operations.

---

# C++ Governance Case Study

The C++ program models a production monitoring deployment.

Its architecture contains several layers.

### Identity model

`Identity` represents the account under which a process operates. It stores the username, UID, primary group, and supplementary groups.

### Filesystem model

`Inode` represents a filesystem object with an owner, group, mode, and directory flag.

The `canAccess()` function determines which traditional permission class applies and tests the corresponding permission bit.

### Package graph

`PackageGraph` stores packages and their dependencies.

Its recursive resolver uses a depth-first traversal and tracks both visited and currently visiting nodes. The `visiting` set detects dependency cycles.

The resulting dependency order is suitable for the simplified installation model because dependencies appear before the packages that require them.

### Process table

`ProcessTable` stores process records indexed by PID.

Each process contains a parent PID and runtime identity, making the connection between process hierarchy and account privileges explicit.

### Service governance

`ServiceUnit` describes the service executable, runtime account, configuration path, log directory, package dependencies, and restart policy.

`GovernanceEngine::evaluateService()` verifies:

- The service exists
- Its runtime account exists
- Its configuration file exists
- The runtime account can read configuration
- The log path exists
- The log path is a directory
- The runtime account can write the log directory
- Required packages are installed
- An executable has been configured

The engine produces either an accepted result or specific failure reasons.

This is more useful than a single Boolean because operational debugging depends on identifying which prerequisite failed.

---

# The Deliberate Failure Scenario

The C++ program creates a second service configuration in which:

`/etc/monitor/monitor.conf`

is owned by `root:root` with mode `0600`.

The service still runs as `monitor`.

The `monitor` account therefore cannot read the configuration through the traditional owner/group/other mode bits.

The log directory remains correctly accessible.

The package dependency is installed.

The resulting failure isolates the configuration permission as the problem.

This is an important troubleshooting pattern:

`service failure -> inspect runtime identity -> inspect required paths -> inspect ownership/mode -> verify dependencies`

A service-management command alone does not provide enough information to distinguish all of these failure classes.

---

# Python Implementation

The Python file is designed as an executable laboratory.

It demonstrates:

- Linux filesystem hierarchy
- `pathlib` and `lstat()` metadata inspection
- POSIX UID and GID information
- User and group simulation
- Traditional Unix permission calculation
- Special permission bits
- `umask` behavior
- Linux `/proc` process inspection
- Safe subprocess creation
- Package dependency resolution
- Service lifecycle simulation
- Deployment artifact validation
- Security-oriented permission checks

The filesystem and process inspection portions interact with the host only for read-oriented inspection.

The package and service sections remain simulated, avoiding accidental modification of installed packages or running services.

The command-line interface supports:

`python linux_fundamentals.py`

to run the complete laboratory.

A specific filesystem path can be inspected with:

`python linux_fundamentals.py --path /etc`

A Linux process can be inspected with:

`python linux_fundamentals.py --pid 1`

The PID example is illustrative. The available process and access information depends on the host system and the privileges of the current user.

---

# JavaScript Implementation

The JavaScript file uses Node.js-specific mechanisms to provide a complementary perspective.

The filesystem portion uses `fs.lstatSync()` and metadata fields such as `uid`, `gid`, `mode`, and `size`.

The permission model is implemented through the `UnixInode` class and `Identity` class.

The process lifecycle is represented using `EventEmitter`. A `spawn` event is emitted when a process record is created, and an `exit` event is emitted when it terminates.

The package section models dependency resolution with JavaScript `Map` and `Set` collections.

The service supervisor uses events for `started`, `failed`, and `stopped` transitions. Its restart policy demonstrates how an event-driven supervisor can respond to failure.

The process inspection section reads `/proc/<pid>/status` directly on Linux.

The child-process demonstration uses `execFile()` instead of passing a constructed command string to a shell.

This gives the JavaScript implementation a different emphasis from the Python program: event-driven state propagation, Node.js process APIs, and asynchronous command execution.

---

# Relationship Between the Major Concepts

These areas are distinct but operationally connected.

| Mechanism | Primary responsibility | Example failure |
|---|---|---|
| Filesystem | Stores files, directories, devices, links, and other objects | Required configuration path does not exist |
| Users and groups | Represent process and ownership identities | Service runs under an unexpected account |
| Permissions | Control traditional filesystem access | Service account cannot read configuration |
| Processes | Represent executing program instances | Worker exits unexpectedly |
| Packages | Install and track software components and dependencies | Required library/package is missing |
| Services | Supervise long-running application processes | Service repeatedly fails or does not start |

A service manager does not replace filesystem permissions.

A package manager does not decide which users may read a secret configuration file.

A process inherits credentials and operating-system context that affect its ability to interact with filesystem resources.

A user being present in a group does not guarantee access if another authorization mechanism denies it or if the traditional owner permission class is the one selected.

---

# Common Administrative Mistakes

## Confusing file and directory permissions

A directory's execute bit is about traversal. Giving a user read access to a directory does not necessarily allow that user to enter it.

## Assuming group membership always adds permissions

Traditional mode-bit evaluation selects the applicable class. Owner status can cause owner permissions to be used even when the user also belongs to the file's group.

## Running every service as root

Root removes many traditional filesystem restrictions, but it also increases the impact of a compromised application. A dedicated service identity with narrowly scoped access is often more appropriate.

## Changing permissions without examining ownership

`chmod` changes mode bits. It does not replace the owner or group. An incorrect ownership model can remain incorrect after a permission change.

## Treating package installation as proof of successful operation

A package can be installed while configuration, permissions, environment, runtime dependencies, or service state remain incorrect.

## Assuming a PID remains valid

Processes terminate concurrently with administration tools. `/proc` inspection must tolerate processes disappearing during enumeration.

## Debugging only from the service manager

Service state tells part of the story. The administrator may also need to inspect the runtime user, configuration permissions, executable path, dependency availability, and application logs.

---

# Failure Analysis Workflow

A practical Linux service investigation should separate the layers instead of changing several things at once.

First establish which executable is supposed to run and which account should execute it.

Then verify that the executable and configuration paths exist.

Inspect ownership and permissions on every directory leading to the required files. A file can have suitable permissions while an ancestor directory prevents traversal.

Verify that the service's runtime account belongs to the intended groups.

Check package dependencies and executable availability.

Inspect the process state and parent relationship.

Finally, inspect application and service logs for failures that occur after the operating system has successfully started the process.

This workflow is represented directly by the C++ governance engine.

---

# Performance Considerations

Filesystem metadata inspection is generally inexpensive for individual paths, but recursively scanning large trees can become expensive because every directory entry and metadata lookup creates work.

Process enumeration through `/proc` is also inherently dynamic. Large systems may contain thousands of processes, and every process can disappear between enumeration and inspection.

Dependency resolution in the provided package models uses depth-first graph traversal. With appropriate hash-based lookup, dependency resolution is approximately linear in the number of reachable packages and dependency edges.

The C++ package graph uses `unordered_map` and `unordered_set` for efficient dependency lookup and cycle detection.

The JavaScript implementation uses `Map` and `Set` for the same structural purpose.

The simulations are intentionally smaller than real package databases or process tables, so their complexity should not be mistaken for a complete benchmark of Linux administration tools.

---

# Security Considerations

Linux security cannot be reduced to `chmod`.

Production systems may also use:

- POSIX ACLs
- SELinux
- AppArmor
- Linux capabilities
- Namespaces
- Containers
- Mount restrictions
- Resource controls
- Application-level authorization
- Network policy

The traditional owner/group/other model remains fundamental because many services still depend on it directly, but it is only one layer of the complete security architecture.

Sensitive service configuration should not be readable by unrelated accounts.

Service executables and configuration should not normally be writable by untrusted users.

Shared writable directories require careful consideration of ownership, setgid behavior, and sticky-bit semantics.

Service accounts should receive only the filesystem and operating-system access required for their function.

Subprocess execution should avoid unnecessary shell interpretation when command arguments can be supplied directly.

---

# Production Considerations

The simulators intentionally avoid actually running commands such as `chmod`, `chown`, package installation commands, or service-control operations.

Real administration introduces additional concerns:

- Root privileges or narrowly scoped privilege elevation
- Distribution-specific package tooling
- systemd unit semantics and dependency ordering
- Journal and application logs
- SELinux or AppArmor policy
- File ACLs
- Service sandboxing
- Resource limits
- Network connectivity
- Secrets management
- Atomic configuration deployment
- Backup and rollback procedures

A production implementation should therefore treat the models in these files as conceptual foundations rather than replacements for the operating system's actual security and service-management mechanisms.

---

# Technical Boundaries of the Models

The permission engines model traditional Unix mode bits and do not attempt to reproduce every Linux authorization layer.

The process models do not emulate kernel scheduling, virtual memory, signals, namespaces, cgroups, file-descriptor inheritance, or the complete process lifecycle.

The package graphs model dependency ordering but do not implement repository metadata, version constraints, package signatures, conflicts, transactions, or rollback.

The service models represent lifecycle and supervision concepts but are not replacements for systemd or another real service manager.

These boundaries are intentional. They keep the educational implementations small enough to inspect while preserving the relationships that matter for Linux fundamentals.

---

# Compilation and Execution

The Python program requires Python 3.

Run:

`python3 linux_fundamentals.py`

The JavaScript program requires Node.js.

Run:

`node linux_fundamentals.js`

The C++ case study requires C++17 or later.

Compile with a command such as:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic linux_fundamentals.cpp -o linux_fundamentals`

Then run:

`./linux_fundamentals`

The Python and JavaScript programs contain Linux-specific inspection paths but retain graceful behavior when executed on another operating system.

The C++ program is deliberately platform-independent because its Linux mechanisms are modeled in memory rather than implemented through Linux-specific system calls.

---

# Core Technical Distinctions

The most important distinction in this material is that each mechanism answers a different systems question.

**Filesystem:** Where does the object exist, and what metadata does it carry?

**User and group identity:** Which account and groups does the process have?

**Permissions:** Does the selected traditional permission class permit the requested filesystem operation?

**Process:** Which program instance is currently executing, under which identity and parent relationship?

**Package:** Which software components and dependencies are installed or required?

**Service:** How is a long-running process started, supervised, stopped, restarted, and observed?

A reliable Linux deployment works because these mechanisms cooperate correctly. A failure in one layer should be investigated at that layer before changing unrelated configuration.
