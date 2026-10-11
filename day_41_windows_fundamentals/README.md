# Windows Fundamentals: Architecture, Identity, Services, Registry, and Filesystem

## Scope

Windows administration depends on several connected operating-system mechanisms. Processor architecture determines which binaries can execute. User and group identities supply security principals. Services execute background workloads under configured identities. The registry stores machine-wide and per-user configuration. The filesystem organizes data and enforces access through security descriptors.

These mechanisms are related, but they are not interchangeable. A service can be running while its executable permissions are unsafe. A registry value can exist while the current user lacks permission to modify it. A file can be visible in a directory listing while an attempted write is denied. A process can belong to an administrator group without every operation necessarily receiving unrestricted access.

The accompanying implementations use different perspectives:

| Deliverable | Technical emphasis |
|---|---|
| Python | Read-only Windows inspection, identity discovery, service inventory, registry queries, filesystem operations, and audit reporting |
| JavaScript | Asynchronous command execution, concurrent metadata retrieval, process handling, and safe temporary-file workflows |
| C++ | Endpoint security policy evaluation, service exposure analysis, principal modeling, and simplified filesystem authorization |
| Java | Enterprise configuration inventory, immutable domain records, validation, service governance, and structured findings |
| PostgreSQL | Relational inventory, referential integrity, service-risk views, registry ownership reviews, filesystem ACL records, and persistent findings |

The Python and JavaScript programs can run on non-Windows systems to demonstrate their portable portions. Windows-specific commands are executed only on Windows. The C++ and Java programs are self-contained policy simulations. The SQL script stores an illustrative endpoint inventory rather than interrogating a live machine.

## Windows architecture

### User mode and kernel mode

Windows separates ordinary application execution from privileged operating-system functionality. User-mode processes normally interact with the operating system through supported APIs and system calls. The kernel and kernel-mode drivers execute with greater privilege and can affect system-wide behavior.

This boundary explains why a normal application cannot arbitrarily change kernel memory or directly perform every privileged operation. Administrative authorization, enabled privileges, operating-system interfaces, and object-specific permissions influence which operations succeed.

A process and its security identity are distinct concepts. A process has an associated access token, which contains the user SID, group SIDs, privileges, and other security information. An access check evaluates the requested operation against applicable authorization rules and the token's security context.

### Native architecture and process architecture

A 64-bit Windows installation can execute compatible 32-bit applications. Consequently, the architecture of the operating system and the architecture of a particular process must not be assumed to be identical.

The Python implementation reports the Python process architecture and attempts to determine whether the process is running under WOW64. The JavaScript implementation reports the architecture exposed by Node.js. These values describe the running process, not a complete hardware inventory.

Architecture also affects software deployment. Administrators must account for binary compatibility, application installation paths, registry views, and the availability of drivers. Kernel-mode drivers have stricter compatibility requirements than ordinary user-mode applications.

### Core operating-system components

- **Security Reference Monitor:** Enforces access checks for Windows securable objects. Security descriptors, access tokens, privileges, and requested access all influence authorization.
- **Service Control Manager:** Maintains service configuration and coordinates service startup, status, and control requests.
- **Configuration Manager:** Provides registry functionality, including key and value access subject to registry security descriptors.
- **NTFS filesystem:** Supports access-control lists, inherited permissions, file metadata, hard links, and reparse points.
- **Windows management interfaces:** CIM, PowerShell, and command-line utilities expose selected operating-system inventory and administrative operations.

An inventory tool should identify the source and limitations of each observation. A successful management query does not establish that every relevant component is healthy or correctly secured.

## Users, groups, and access tokens

### Security identifiers

Windows uses security identifiers, or SIDs, to identify users and groups. Display names can change and may not be globally unique. SIDs provide a more reliable identity reference for authorization records.

The sample implementations represent users and service identities with synthetic SIDs. These are training records, not actual identities on a Windows computer.

Local users, domain users, local groups, and domain groups have different administrative scopes. A local inventory command cannot replace a complete Active Directory inventory.

### Group membership and effective permissions

Groups simplify administration by allowing permissions to be assigned to a collection of principals. The resulting authorization decision depends on the user's access token and the security descriptor of the target object.

The presence of a group membership alone does not establish that a particular operation is permitted. Explicit deny entries, enabled privileges, inherited entries, mandatory integrity controls, and object-specific rules can affect the result.

The C++ program demonstrates a deliberately simplified authorization model. It aggregates matching allow and deny masks for a file object. This is useful for understanding policy evaluation, but it is not a faithful implementation of the Windows access-check algorithm.

The SQL schema stores group membership in `group_memberships`, with foreign keys to the corresponding principals. A production identity inventory would also need to model domain membership, nested groups, disabled identities, historical observations, and the source of each membership record.

### Administrative privileges and least privilege

Administrative accounts can perform operations unavailable to standard users, but routine work should not require unrestricted administrative access. A dedicated service identity should receive only the rights required by its workload.

The Java and C++ implementations flag services using administrative identities and service identities belonging to a modeled administrator group. Such findings are risk indicators. Actual remediation requires inspecting the effective token, service configuration, logon rights, and application dependencies.

## Windows services

### Configuration and lifecycle

A Windows service has a service name, display name, executable configuration, logon identity, startup configuration, and runtime state.

Runtime state and startup configuration are different properties. A service may be stopped while configured for automatic startup. A disabled service may still be represented in inventory even though normal service startup is prohibited.

The Service Control Manager is responsible for service lifecycle operations. Service dependencies, service-specific recovery configuration, trigger-based startup, account logon rights, and failure actions can affect operational behavior beyond the basic state displayed by an inventory query.

### Service inspection

The Python implementation uses `sc.exe` and CIM-backed PowerShell queries to retrieve selected service properties. The JavaScript implementation retrieves service information asynchronously and parses JSON returned by PowerShell.

Both implementations perform inspection only. They do not start, stop, delete, or reconfigure services.

The C++ case study models three different exposures:

- `InventoryAgent` runs as a dedicated identity, but standard users can modify its executable.
- `LegacyUpdater` runs under an administrative identity and has an executable path with spaces that is modeled as unquoted.
- `DisabledDiagnostic` is disabled while its startup configuration remains automatic.

These conditions illustrate why a service audit must consider configuration consistency, identity privilege, executable permissions, and executable path handling.

### Service security

A privileged service whose executable or parent directory is writable by ordinary users creates a serious privilege-escalation risk. The precise impact depends on the service's execution behavior and the executable-loading path.

Service configuration should be reviewed alongside executable and directory ACLs, the service logon identity, required privileges, dependencies, recovery behavior, and the ability of ordinary users to modify associated configuration files.

A service inventory should distinguish an observed fact from a derived risk assessment. For example, an unquoted path containing spaces is a configuration indicator that requires examination of the actual executable path and Windows command-line parsing behavior.

## Registry fundamentals

### Hives, keys, and values

The registry is a hierarchical configuration database. A key can contain subkeys and named values. Each value has a type and stored data.

Common root hives include:

| Hive | Purpose |
|---|---|
| `HKEY_LOCAL_MACHINE` | Machine-wide configuration |
| `HKEY_CURRENT_USER` | Configuration associated with the current user |
| `HKEY_USERS` | Loaded user-profile hives |
| `HKEY_CLASSES_ROOT` | Merged class-registration view |
| `HKEY_CURRENT_CONFIG` | Hardware-profile configuration view |

Registry data types include `REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, and `REG_MULTI_SZ`. A value's type matters because consumers interpret the stored data according to that type.

The Python implementation reads selected values with the Windows registry API. The JavaScript implementation uses `reg.exe query`. Neither implementation changes registry values.

### Security and architecture

Registry keys have security descriptors that govern access. Read permission does not imply write permission, and the existence of a key does not mean the current process can change it.

The registry can also present different views to 32-bit and 64-bit applications. The effective view depends on the operating system, process architecture, API, and registry location.

Machine-wide configuration usually requires controlled administrative ownership. Per-user settings should be scoped to the relevant user context. Applications should validate configuration types and handle absent, malformed, or outdated values without assuming that every key exists.

### Registry inventory in the relational model

The `registry_settings` table records the endpoint, hive, key path, value name, value type, captured data, recorded owner, and whether the setting is machine-wide.

Its unique constraint prevents duplicate records for the same endpoint, hive, key, and value name. The `registry_ownership_review` view identifies machine-wide settings attributed to ordinary user principals.

The recorded owner is inventory metadata, not proof of effective write access. A complete registry security audit must inspect the actual key security descriptor and account for inheritance, group membership, and applicable access rules.

## Windows filesystem fundamentals

### Files, directories, volumes, and metadata

Windows commonly uses NTFS for system and application volumes. A filesystem object has a path, metadata, an owner, and a security descriptor. Directories determine traversal and containment behavior, while files hold data and can have separate metadata and alternate data streams.

Standard installation locations have different purposes:

- `%SystemRoot%` contains core Windows operating-system files.
- `%ProgramFiles%` is a conventional location for installed applications.
- `%ProgramData%` holds machine-wide application data.
- `%USERPROFILE%` identifies the current user's profile directory.
- `%APPDATA%` and `%LOCALAPPDATA%` distinguish roaming and local application settings.

The actual paths depend on the installation and environment. Applications should use known-folder APIs or appropriate environment information rather than assuming that every installation uses the same drive or directory.

### ACLs, inheritance, and access

Filesystem access is controlled by security descriptors and access-control entries. Permissions can be inherited from parent directories, and explicit entries can interact with inherited entries.

The practical distinction between read, write, execute, delete, and permission-management rights matters when evaluating application exposure. Permission changes may permit a principal to grant itself or others additional access. Directory permissions can also influence whether an application can replace a file or create a new executable.

The Python implementation uses `stat` to inspect metadata and `icacls.exe` to display ACL information on Windows. Its metadata mode bits are not a replacement for native Windows ACL analysis.

The Java model represents allow and deny entries with explicit right sets. The SQL model stores ACL entries in `filesystem_acl_entries` and relates them to filesystem objects and principals.

Neither a compact rights model nor a flattened ACL table fully reproduces Windows authorization semantics. Inherited entries, ACE ordering, group expansion, privileges, mandatory integrity levels, ownership, and reparse points can change the effective result.

### Safe path handling

Filesystem paths may contain traversal components, symbolic links, junctions, or other reparse points. A string-prefix check is not sufficient to establish that a resolved path remains inside a trusted directory.

The Python and JavaScript filesystem demonstrations create files under a newly created temporary directory, resolve paths before checking containment, and remove the isolated test data when finished.

In production, a path check can still be vulnerable to time-of-check-to-time-of-use races if another process can modify relevant directories or reparse points between validation and use. Sensitive operations should rely on appropriate operating-system APIs, restrictive directory permissions, and carefully controlled handles.

## Python implementation

The Python program combines standard-library operating-system inspection with a practical filesystem exercise.

`windows_architecture()` separates process-level facts from Windows-specific information. `collect_identity()` obtains the current account context and, on Windows, queries the user SID and group membership. `inspect_local_accounts()` retrieves local user and group inventories through native command-line tools.

`inspect_services()` parses structured service inventory returned by PowerShell. `inspect_service()` retrieves an individual service's state and configuration. `inspect_registry_read_only()` reads selected registry values with `winreg`, preserving their registry types.

`describe_filesystem_paths()` reports standard directories and their existence. `filesystem_demo()` creates a temporary configuration file and audit log, reads them back, checks path containment, copies a backup, and verifies cleanup.

The optional `--security-audit` mode retrieves selected security posture information, including the current identity, firewall profile configuration, and common pending-reboot indicators. These checks are partial and should not be interpreted as a complete compliance certification.

Example commands:

- `python windows_fundamentals.py` performs the standard inspection and filesystem exercise.
- `python windows_fundamentals.py --inspect` collects operating-system and identity information.
- `python windows_fundamentals.py --filesystem-demo` runs only the isolated filesystem exercise.
- `python windows_fundamentals.py --service EventLog` inspects a named Windows service.
- `python windows_fundamentals.py --path "C:\ProgramData"` inspects a selected path.
- `python windows_fundamentals.py --security-audit` retrieves selected security configuration.

Windows-specific commands may fail when permissions, system configuration, or management components prevent access. The script reports those failures rather than treating missing data as proof of a secure configuration.

## JavaScript implementation

The Node.js implementation emphasizes asynchronous process execution and filesystem cleanup.

`runCommand()` wraps process execution in a promise-based interface and captures standard output and standard error. The command runner avoids shell interpretation and uses fixed executable names and argument arrays. This reduces shell-injection exposure when user-supplied strings are involved.

`inspectIdentity()` collects operating-system identity metadata and conditionally queries `whoami.exe`. `inspectService()` validates service names before passing them to `sc.exe`. `inspectServices()` retrieves a structured service inventory through a fixed PowerShell script.

`filesystemLaboratory()` uses asynchronous filesystem APIs to create a unique temporary workspace, write configuration and log files, read their contents, inspect metadata, and remove the workspace in a `finally` block.

The program also uses `Promise.all()` when creating independent directories. This is appropriate because those operations do not depend on one another. File creation occurs afterward, preserving the dependency between directory creation and writing files.

The timeout handling and process output limits are useful operational safeguards, although a production process runner should also terminate timed-out child processes explicitly and handle partial output and stream failures carefully. A production Windows integration would need additional tests for process termination, Unicode output, access-denied responses, and differences among Windows releases.

## C++ endpoint policy case study

The C++ program models a fictional managed endpoint where a policy engine evaluates service and filesystem configuration.

The domain types have distinct responsibilities:

- `Principal` represents an account identity, account classification, enabled state, and group memberships.
- `Service` records executable configuration, runtime state, startup behavior, and selected exposure indicators.
- `AccessRule` represents allow and deny rights associated with a principal.
- `FileObject` associates a path with an owner and a collection of access rules.
- `Finding` records the severity, affected resource, and explanation of a detected issue.
- `EndpointPolicy` owns the inventories, validates references, and performs policy evaluation.

The policy engine rejects duplicate principal SIDs, duplicate service names, unknown service identities, and invalid filesystem ownership references. These checks prevent an incomplete inventory from silently producing misleading results.

The audit evaluates service-specific conditions and orders findings by severity. A writable service executable is classified as critical, while administrative service identities and unquoted paths are treated as high-priority findings in the modeled policy.

The filesystem authorization method combines rights for a user and explicitly supplied token groups. Denied rights are removed from the aggregated allow mask. This method is a simplified teaching model, not a Windows-compatible access-check implementation.

The policy's computational cost is approximately linear in the number of services, filesystem objects, and ACL entries examined, apart from the ordered containers and final finding sort. The ordered maps provide predictable key lookup and traversal behavior, while the sets simplify group membership tests.

The program is suitable for reasoning about policy design and finding prioritization. A production endpoint assessment would obtain the inventory from trusted Windows APIs, preserve the provenance and timestamp of each observation, and evaluate actual security descriptors and service configurations.

## Java enterprise governance model

The Java implementation uses Java 17 records to represent immutable inventory observations and domain values.

`Identity` validates the presence of an SID and account name and copies group membership into an immutable set. `ServiceDefinition` requires a service name, executable path, and service identity. `RegistrySetting` validates its root hive and value name, and it checks that `REG_DWORD` values fall within the unsigned 32-bit range represented by a Java `long`.

`GovernanceRepository` acts as an in-memory inventory service. It rejects duplicate identities, duplicate service names, services referencing unknown identities, duplicate registry values, and ACL entries referencing unknown principals.

The `evaluate()` method applies explicit service and registry governance rules. Findings include a severity, resource identifier, description, and remediation statement. The result is sorted and returned as an immutable list, separating policy evaluation from reporting.

The registry model distinguishes machine-wide configuration from per-user configuration. The filesystem model represents individual allow and deny sets. Its `simplifiedEffectiveRights()` method computes a simplified set difference and must not be mistaken for native Windows authorization.

The sample inventory demonstrates how a service identity can be present in an administrative group, how a legacy updater can run under an administrator account, and how registry configuration ownership can be evaluated separately from filesystem permissions.

The model is intentionally in-memory. An enterprise deployment would persist observations, distinguish desired configuration from observed configuration, track inventory timestamps, and separate policy evaluation from remediation execution.

## PostgreSQL relational model

The SQL script represents the same broad administrative domain through relational tables, foreign keys, checks, indexes, views, and transactions.

### Endpoint and identity relationships

`endpoints` stores the machine name, Windows edition, build, architecture, and selected platform security observations.

`principals` stores users, groups, and service identities. SIDs are unique per endpoint, preventing duplicate identity records within one endpoint's inventory.

`group_memberships` represents the relationship between a member and a group. Foreign keys prevent memberships from referencing missing principals. A primary key prevents the same membership from being recorded twice.

### Service configuration

`services` stores the service name, executable path, logon identity, runtime state, startup type, and selected risk indicators.

Check constraints restrict runtime state and startup configuration to recognized values. A unique constraint prevents duplicate service names on the same endpoint. An index supports queries that filter services by endpoint, state, and startup type.

The `service_risk_inventory` view derives a risk category from recorded service properties. It prioritizes writable executables and services running as a built-in administrator, followed by modeled unquoted paths and inconsistent disabled-service configuration.

These categories are screening results, not a substitute for validating the actual service executable path, ACLs, identity token, and startup configuration.

### Registry and filesystem records

`registry_settings` captures registry hive, key path, value name, value type, data, owner, and machine-wide scope. Its uniqueness constraint prevents duplicate observations for the same registry value within an endpoint inventory.

`filesystem_objects` records file, directory, and reparse-point observations. `filesystem_acl_entries` relates an object to a principal and stores an access type, rights array, and inheritance indicator.

The ACL constraints restrict rights to a known vocabulary. They do not implement native Windows ACE evaluation or guarantee that the stored permissions reflect current effective access.

### Findings and queries

`audit_findings` persists risk observations with a severity, description, remediation, status, and timestamp. Optional foreign keys associate a finding with a service or filesystem object.

The partial index on open findings supports queries that prioritize unresolved security issues without indexing every historical finding in the same way.

The views and queries demonstrate how an administrator can identify service risks, inspect local group membership, review machine-wide registry ownership, and summarize filesystem permission observations.

The sample data uses `ON CONFLICT` clauses for repeatable insertion of baseline records. The schema setup and sample inserts are enclosed in a transaction so that database changes can be committed atomically.

## Security boundaries and implementation limitations

These implementations deliberately separate inventory collection from policy evaluation. A collected value can be missing because a command failed, the caller lacked permission, a component was unavailable, or the target configuration did not exist. Those outcomes should not automatically be classified as secure.

The examples do not change service configurations, create users, modify registry values, change ACLs, or elevate privileges. The simulated C++ and Java policy engines only assess the records supplied to them.

A live Windows assessment requires additional context, including:

- Effective token privileges and group memberships for the process performing the assessment.
- Service dependencies, recovery configuration, logon rights, executable ACLs, and parent-directory permissions.
- Registry security descriptors, 32-bit and 64-bit views, and the provenance of observed values.
- NTFS inheritance, ACE ordering, mandatory integrity controls, reparse points, and actual access-check results.
- Domain policy, local security policy, firewall configuration, update state, and relevant security events.

These distinctions are essential when converting a training inventory into an operational security assessment. Observed configuration, inferred risk, and verified exploitability are different levels of evidence.
