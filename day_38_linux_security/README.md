# Linux Security: SSH, sudo, Permissions, Secure Configuration, and Service Minimization

## Scope

This learning artifact models Linux host security as a set of related but distinct control layers:

- **SSH** controls remote authentication and the conditions under which an account may establish an administrative session.
- **sudo** controls privileged command execution after an account has already authenticated.
- **Permissions** control access to filesystem objects according to Unix ownership and permission bits.
- **Secure configuration** reduces dangerous host-wide behavior such as unrestricted firewall exposure, missing audit logging, uncontrolled kernel extensions, and unrestricted core dumps.
- **Service minimization** reduces attack surface by removing unnecessary daemons, startup services, and network listeners.

The implementations intentionally keep these boundaries separate. A user being able to authenticate over SSH does not imply root access. A sudo rule does not replace filesystem permissions. A correctly configured filesystem does not make an unnecessary network daemon safe. Host security depends on the interaction of these controls.

## Security Model

A Linux host has several authorization boundaries that operate at different stages.

A typical administrative path can be represented as:

`remote client -> SSH authentication -> account/session -> sudo authorization -> privileged process -> filesystem/network resources`

SSH is the entry boundary. Its job is to establish whether a remote account may connect and which authentication mechanisms are accepted.

sudo operates later. Once a user has an authenticated session, sudo determines whether that account can execute a particular command with elevated privileges. This is why an SSH user and a sudo administrator are not equivalent concepts.

Filesystem permissions apply to objects such as `/etc/ssh/sshd_config`, `/etc/shadow`, application directories, logs, and executables. Unix permissions select an owner, group, or other-user permission class and then evaluate read, write, and execute bits.

Secure configuration addresses controls that are broader than one account or one file. Firewall state, audit logging, time synchronization, patching, core-dump restrictions, kernel-module restrictions, file-integrity monitoring, and boot-chain controls belong to this layer.

Service minimization addresses the software that is actually running or listening. Every unnecessary daemon can introduce code, configuration, credentials, sockets, dependencies, and network exposure that must be maintained securely.

## SSH

SSH security is represented through `SSHConfig`, `SSHPolicy`, `SshPolicy`, and related request objects.

The implementations distinguish several SSH-specific controls:

- Direct root login is independently evaluated. Disabling root SSH access does not disable the root account itself.
- Password authentication can be disabled while public-key authentication remains enabled.
- Public-key access requires both an enabled authentication mechanism and a configured key for the account.
- `AllowUsers`-style restrictions limit the account population.
- Group restrictions provide a second authorization boundary for administrative accounts.
- `MaxAuthTries` limits repeated authentication attempts within the modeled policy.
- X11 forwarding, agent forwarding, and TCP forwarding are treated as separate capabilities because they create different forms of session functionality and exposure.

The Python program demonstrates successful public-key access for an administrative account, rejection of a legacy password login, rejection of direct root access, and rejection after excessive authentication attempts.

The JavaScript implementation treats login requests as events and evaluates them through an `SSHPolicy` object. This emphasizes the event-driven nature of authentication systems.

The C++ implementation uses a `User` structure and an `SSHPolicy` class to demonstrate policy evaluation as part of a host governance engine.

The Java implementation uses immutable records for user accounts and SSH requests. The `SshPolicy.evaluate` method provides an explicit policy boundary and returns an `EvaluationResult` rather than mixing authorization with output.

The SQL implementation stores SSH policy separately from users, groups, allowed users, and allowed groups. This allows database queries to determine whether a particular identity belongs to an allowed SSH population.

## SSH Hardening Decisions

A hardened SSH configuration normally favors:

`PermitRootLogin no`

and a controlled authentication policy using public keys or another explicitly approved authentication mechanism.

Password authentication should not be disabled blindly before verified key-based access exists. A production change must account for console access, recovery access, automation accounts, and the possibility of locking administrators out.

Forwarding options require their own threat analysis. Agent forwarding is particularly important because an SSH agent represents access credentials that may have consequences beyond the current server. TCP forwarding can turn an SSH account into a network tunneling mechanism. X11 forwarding introduces another session capability that may be unnecessary on server infrastructure.

Restricting users and groups is useful when only a defined administrative population should reach a host. It should be coordinated with identity lifecycle management so that departed or unauthorized accounts do not remain operationally permitted.

## sudo

sudo is modeled as a command authorization system rather than as a general synonym for administrator access.

A rule contains:

- the users to whom the rule applies,
- the commands that may be executed,
- whether a password is required,
- and whether `noexec` is requested in the model.

The important distinction is between an explicit command rule such as:

`/usr/bin/systemctl restart nginx`

and an unrestricted rule represented by `ALL`.

Least privilege favors the first form when the operational requirement is only to restart one service.

The programs deliberately include an unsafe unrestricted rule in their audit models so that the governance engine can identify it as a critical finding. This demonstrates why authorization scope matters more than simply asking whether sudo exists.

Passwordless sudo is treated separately from unrestricted command scope. A passwordless rule can be appropriate for tightly controlled automation, but it changes the consequences of account compromise and should therefore be deliberate.

`noexec` is represented as an additional policy property rather than as a universal security guarantee. Real-world sudo behavior depends on the command, operating system, libraries, executable behavior, and the exact sudo configuration. It should not be treated as a complete sandbox.

## Filesystem Permissions

Unix permissions are represented using the conventional three permission classes:

`owner | group | other`

Each class has:

`read = 4`

`write = 2`

`execute = 1`

For example, mode `0750` means:

- owner: read, write, execute
- group: read, execute
- other: no permissions

The programs model access selection by first determining whether the requesting identity is the owner. If not, membership in the owning group is considered. Otherwise, the `other` permission class applies.

This ordering is important. Unix permission evaluation does not simply combine all permissions from every group a user belongs to. The selected class determines the relevant basic permission bits.

Sensitive examples include `/etc/ssh/sshd_config` with mode `0600` and `/etc/shadow` with a restricted owner/group boundary.

The examples also include `/tmp/application-upload` with `0777` to demonstrate why world-writable objects deserve review. World-writable directories may be legitimate in tightly controlled temporary workflows, but their security consequences depend on sticky-bit usage, ownership, application behavior, and what is stored there.

The programs also identify setuid executables. A setuid executable can execute with the effective privileges of its owner, which is why privileged executables require careful trust and maintenance.

## Secure Configuration

Secure configuration is deliberately separated from account authorization and filesystem permissions.

The model evaluates:

- host firewall state,
- automatic security updates,
- audit logging,
- time synchronization,
- core-dump restrictions,
- kernel-module loading restrictions,
- file-integrity monitoring,
- and Secure Boot.

These controls address different failure modes.

A firewall reduces reachable network paths. It does not make an exposed service intrinsically safe.

Security updates reduce exposure to known vulnerabilities. They do not replace configuration review or application security.

Audit logging provides evidence for detection and investigation. It does not itself prevent an attack.

Time synchronization is important because authentication records, system logs, monitoring events, and incident timelines depend on meaningful timestamps.

Core dumps can contain process memory, so their handling matters on systems processing credentials, tokens, cryptographic material, or other sensitive data.

Kernel modules operate at a highly privileged layer. Restricting module loading can reduce the ability of unauthorized software to extend kernel functionality, although operational requirements must be considered.

File-integrity monitoring can detect unexpected changes to important configuration or executable paths. It complements access controls rather than replacing them.

Secure Boot provides boot-chain verification when supported and correctly configured. It is a platform-level control and therefore differs from SSH or Unix permissions.

## Service Minimization

Service minimization follows an attack-surface principle: software that is not required should not normally be running or listening.

The model distinguishes:

- whether a service starts at boot,
- whether it is running,
- whether it has network listeners,
- whether it is remotely reachable,
- and whether it has an identified business requirement.

The example contains `sshd` and `nginx` as required services and `telnet` and `cups` as unnecessary examples.

The telnet example is especially important because a legacy remote administration service creates a network entry point without providing a justified requirement in the modeled production host.

Stopping an unnecessary service is not equivalent to merely closing its firewall port. Removing the service or disabling it prevents the component from becoming active through another configuration path.

Service minimization should therefore be considered at several levels:

`installed software -> enabled services -> running services -> listening sockets -> reachable networks`

Each level represents a different operational state.

## Python Implementation

The Python program provides the broadest policy simulation.

`SSHSecurityModel` evaluates remote login requests against account state, authentication method, user restrictions, group restrictions, and authentication attempt limits.

`SudoPolicy` models explicit command authorization and detects unrestricted or passwordless rules.

`PermissionEngine` models owner, group, and other permission selection and evaluates read, write, and execute requests.

`ConfigurationAuditor` evaluates host-level security settings.

`ServiceMinimizer` identifies unnecessary enabled services and listeners.

`LinuxSecurityAssessment` combines these separate controls into a single report and applies severity penalties to produce a posture score.

The program also demonstrates edge cases including unknown accounts, missing filesystem paths, unauthorized sudo commands, direct root SSH access, and excessive authentication attempts.

The implementation does not call `sshd`, `sudo`, `chmod`, `systemctl`, or other privileged operating-system commands. This makes the example executable without requiring root access or risking changes to the host.

## JavaScript Implementation

The JavaScript program takes an event-driven approach.

`SSHPolicy.evaluate` consumes an authentication event rather than directly managing a connection. This models a common application architecture in which authentication requests are received as events and passed to policy evaluation.

`SudoPolicy`, `PermissionEngine`, `ConfigurationPolicy`, and `ServiceMinimizer` use JavaScript classes to keep policy state and decision logic together.

JavaScript `Set` objects are useful for group membership and allowed-user policies because membership testing is central to the model.

The program uses `Map` for account lookup so that an SSH event can resolve a username into an account object efficiently.

The JavaScript implementation is intentionally not a direct line-by-line translation of the Python version. It emphasizes event processing, object-oriented policy components, and Node.js execution.

## C++ Case Study

The C++ program presents a repository-independent enterprise Linux governance engine for a production application host.

The modeled host has:

- `sshd` for remote administration,
- `nginx` for application traffic,
- an intentionally unnecessary telnet service,
- an unnecessary CUPS listener,
- an administrative account,
- a developer account,
- a legacy account,
- sensitive configuration files,
- an application directory,
- and a privileged executable.

`SSHPolicy` performs remote-access decisions.

`SudoPolicy` evaluates explicit command rules.

`PermissionEngine` uses Unix permission bits to calculate access.

`ConfigurationAuditor` evaluates host-wide security controls.

`ServiceMinimizer` identifies unnecessary software and listeners.

`GovernanceEngine` combines their findings and calculates a weighted posture score.

The C++ implementation uses standard containers such as `std::set`, `std::map`, and `std::vector`. The policy classes separate decision logic from the reporting layer.

The permission lookup is linear across the modeled file vector. For a large production inventory, a hash-based map keyed by canonical path would provide expected constant-time lookup, subject to hashing and memory considerations.

The service and policy audits are similarly proportional to the number of configured records and rules. The example favors clarity over premature optimization because configuration inventories are usually much smaller than high-volume application datasets.

## Java Enterprise Model

The Java program models Linux security as explicit domain types.

Java records represent immutable concepts such as `UserAccount`, `SshRequest`, `SshPolicy`, `SudoRule`, `FileObject`, `Service`, and `HostConfiguration`.

The `EvaluationResult` type separates a security decision from the mechanism used to display it.

`SshPolicy`, `SudoPolicy`, `PermissionService`, `ConfigurationService`, and `ServiceMinimizationService` each own one security boundary. `GovernanceService` composes them into a host-level assessment.

This separation is important in enterprise systems because authentication, privilege authorization, filesystem controls, configuration compliance, and service inventory often originate from different operational systems.

Java's immutable records also prevent accidental mutation of policy definitions during evaluation. `Set.copyOf` and `List.copyOf` provide defensive immutable collections for policy objects.

The implementation uses standard Java 17 features and requires no external framework.

## SQL Data Model

The PostgreSQL schema separates identities, groups, SSH policies, sudo rules, filesystem objects, host configuration, services, and listeners.

The relationships are significant:

`users -> user_groups -> groups`

represents identity membership.

`ssh_policies -> ssh_allowed_users`

and

`ssh_policies -> ssh_allowed_groups`

represent separate SSH access restrictions.

`s​udo_rules -> sudo_rule_users`

and

`s​udo_rules -> sudo_rule_commands`

represent privilege authorization.

`filesystem_objects -> users`

and

`filesystem_objects -> groups`

represent Unix ownership.

`services -> service_listeners`

represents the network exposure created by running services.

The schema uses primary keys and foreign keys to preserve referential integrity. Unique constraints prevent duplicate usernames, group names, policy names, paths, and service identities.

Check constraints restrict invalid values such as impossible ports and invalid authentication retry counts.

Indexes are placed on relationship columns and common operational lookup fields such as service listener ports and sudo command paths.

## Database-Level Security Enforcement

The database contains deliberately insecure sample states so that audit queries can expose them.

The unrestricted sudo rule has both `all_users` and `all_commands` enabled. The audit query identifies this as a critical authorization problem.

The application upload directory uses mode `0777`, making it a world-writable object in the model.

The privileged helper uses the setuid bit, making it a high-priority object for trust and configuration review.

File-integrity monitoring is disabled for the example host, producing a configuration finding.

Telnet is modeled as an unnecessary enabled service with a network listener.

The final transaction disables the modeled telnet service and removes its listener records. This demonstrates relational state consistency. The SQL database transaction does not itself execute a systemd operation, because database state and operating-system state are separate control planes.

## Important Distinctions

| Area | Primary security question | Typical failure |
| --- | --- | --- |
| SSH | Who may establish a remote session, and how? | Password-based or unrestricted remote access |
| sudo | Which privileged commands may an authenticated user execute? | Broad `ALL` authorization |
| Permissions | Which identity can access a filesystem object? | World-writable or overly readable files |
| Secure configuration | Are host-wide defensive controls correctly configured? | Missing firewall, auditing, patching, or integrity controls |
| Service minimization | Which software and listeners are unnecessarily active? | Legacy daemons and unnecessary network exposure |

These controls should not be collapsed into one mechanism.

A hardened SSH configuration does not compensate for unrestricted sudo.

A restrictive sudo policy does not make a world-writable privileged file safe.

Good filesystem permissions do not compensate for an unnecessary network daemon.

A minimal service inventory does not replace patching and audit logging.

Host security comes from the combined reduction of unauthorized access, unauthorized privilege, unsafe resource access, insecure configuration, and unnecessary attack surface.

## Failure Modes and Edge Cases

Account lifecycle is an important SSH boundary. A user can possess a valid public key while still being inappropriate for access if the account is locked, disabled, outside the allowed group, or no longer operationally required.

A key-based authentication policy can still be undermined if private keys are poorly protected, shared between users, left on compromised endpoints, or not removed when access should terminate.

sudo rules can become dangerous through command scope. A command that appears narrow may provide indirect access to a shell or another privileged execution mechanism. Authorization should therefore consider the actual behavior of the permitted command, not only its filename.

Unix permission analysis becomes more complex with ACLs, capabilities, setuid, setgid, sticky directories, mount options, namespaces, containers, and service-specific privilege models. The implementations focus on traditional owner/group/other permission bits because those are the core mechanism being taught.

World-writable directories are not automatically vulnerabilities. Temporary directories and collaboration areas may legitimately require broader write access. Their security depends on ownership, sticky-bit behavior, application design, and the identities sharing the directory.

Service minimization also requires operational context. A service that appears unused from a local inventory may be required by monitoring, backup, printing, configuration management, or another infrastructure dependency.

## Performance Considerations

Security checks should be efficient enough to run regularly without becoming operationally disruptive.

The Python and JavaScript models use dictionaries or maps for direct account and path lookup where appropriate.

The C++ case study uses structured containers and separates policy evaluation from report generation.

The Java implementation uses immutable collections and streams where they make policy evaluation readable without hiding the authorization rules.

The PostgreSQL implementation uses indexes for foreign-key relationships and operational lookup fields. Query plans should still be reviewed on large inventories because an index is useful only when its access pattern matches the workload.

High-volume SSH event logging should be handled differently from static configuration data. Authentication events can grow rapidly and therefore benefit from timestamp indexes, retention policies, partitioning, or external log pipelines in production systems.

## Security and Production Considerations

The examples are policy models rather than complete host-hardening automation.

A production SSH configuration change should be tested through a second administrative session before the current session is closed. Otherwise, an incorrect configuration can create an administrative lockout.

Sudo policies should be reviewed whenever command paths, packages, service management procedures, or administrative responsibilities change.

Sensitive files should be protected according to their actual content. Configuration files containing credentials, private keys, tokens, database connection strings, or other secrets require stronger handling than ordinary configuration.

File permissions should be considered together with ownership, groups, ACLs, mount options, service accounts, and application behavior.

Services should be inventoried from the actual host state rather than from assumptions about a standard installation. Listening sockets are particularly useful because an installed package is not necessarily an exposed service.

Security logging must have appropriate permissions and retention. Logging sensitive authentication information can itself create a confidentiality problem if logs are broadly readable.

Time synchronization is a security dependency when incident investigation, authentication events, certificate validation, and distributed correlation depend on accurate timestamps.

Patch management should account for both kernel and user-space components. Applying updates is only one part of the security lifecycle; changes must also be validated against application compatibility and service availability.

The central design principle demonstrated across all six artifacts is separation of security responsibilities. Remote access, privilege escalation, resource permissions, host configuration, and service exposure are different control surfaces. Each requires its own policy, validation logic, monitoring, and operational ownership.
