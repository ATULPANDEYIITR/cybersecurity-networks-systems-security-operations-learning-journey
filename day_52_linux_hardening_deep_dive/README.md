# Linux Hardening Deep Dive

This project models Linux host hardening as a collection of enforceable security controls rather than as a list of configuration recommendations. The implementations focus on five connected areas: SSH access, sudo privilege delegation, filesystem permissions, kernel security controls, and auditing.

The central principle is that hardening reduces unnecessary authority and makes security-relevant behavior observable.

| Area | Primary security question | Main mechanism |
|---|---|---|
| SSH | Who can remotely authenticate and how? | `sshd_config` policy |
| sudo | Which authenticated users can obtain elevated privileges? | sudoers rules |
| Filesystem permissions | Which identities can read, modify, or execute sensitive resources? | Unix ownership and mode bits |
| Kernel controls | Which operating-system protections are active? | `/proc/sys` controls |
| Auditing | Can privileged or security-sensitive activity be reconstructed? | Linux audit subsystem |

The five areas interact, but they are not interchangeable. SSH controls remote entry. sudo controls privilege elevation after access has been established. Filesystem permissions control resource access. Kernel controls reduce classes of operating-system attacks. Auditing provides evidence about security-relevant activity.

## Security model

A useful hardening model is:

    Remote authentication
            |
            v
          SSH
            |
            v
    Authenticated identity
            |
            +------------------+
            |                  |
            v                  v
    Filesystem access       sudo policy
            |                  |
            |                  v
            |             Elevated identity
            |                  |
            +---------+--------+
                      |
                      v
              Kernel controls
                      |
                      v
          Security-relevant events
                      |
                      v
                  Auditing

The model deliberately separates prevention from observation. SSH, sudo, filesystem permissions, and kernel controls primarily prevent or restrict behavior. Auditing records evidence and supports investigation.

## Python implementation

The Python program is a read-only host auditor. It does not edit `sshd_config`, sudoers files, permissions, or kernel settings.

The `LinuxHardeningAuditor` class collects findings from five independent audit methods:

- `audit_ssh()` parses `/etc/ssh/sshd_config` and evaluates root login, password authentication, empty passwords, and X11 forwarding.
- `audit_sudo()` examines `/etc/sudoers` for passwordless elevation and broad administrative grants.
- `audit_filesystem()` evaluates the permissions of `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, and `/etc/sudoers`.
- `audit_kernel()` reads selected `/proc/sys` controls.
- `audit_auditing()` checks the Linux audit interface through `auditctl`.

Findings use a structured dataclass containing category, control, status, severity, evidence, and recommendation. This makes the result suitable for both terminal output and JSON export.

The script distinguishes `PASS`, `REVIEW`, `FAIL`, and `UNKNOWN`. `UNKNOWN` is important because inability to inspect a security control is not equivalent to a secure configuration.

The program returns a non-zero exit status when a `FAIL` finding exists, allowing it to participate in operational monitoring or CI-style checks without modifying the host.

Run it on Linux with:

`python3 linux_hardening_audit.py`

Machine-readable output is available with:

`python3 linux_hardening_audit.py --json`

The audit requires access to protected system files for complete results. Running without sufficient permissions can legitimately produce `UNKNOWN` findings.

## SSH hardening

SSH is the remote access boundary.

The Python and JavaScript implementations inspect four important directives:

| Directive | Security role |
|---|---|
| `PermitRootLogin` | Controls direct SSH authentication as root |
| `PasswordAuthentication` | Controls password-based SSH authentication |
| `PermitEmptyPasswords` | Prevents authentication using empty account passwords |
| `X11Forwarding` | Controls forwarding of X11 sessions |

`PermitRootLogin no` removes direct root login as an SSH authentication target. `prohibit-password` is weaker than `no` because it still permits certain non-password root authentication mechanisms. The appropriate setting depends on the administrative model.

Disabling `PasswordAuthentication` reduces exposure to password guessing and password reuse when strong key-based authentication is operationally available. It should not be applied blindly to a system where administrators have no alternative authentication path.

`PermitEmptyPasswords no` is a basic defensive control and should remain explicitly disabled.

X11 forwarding is not inherently unsafe, but it increases the functionality available through an SSH session. Systems that do not require graphical forwarding can reduce their attack surface by disabling it.

### SSH configuration parsing

The implementations intentionally parse configuration directives instead of performing blind text searches. Blank lines and comments are ignored, and directives are normalized for case-insensitive comparison.

A production-grade configuration evaluator must account for OpenSSH's complete configuration semantics, including included files, conditional blocks, command-line overrides, and the effective configuration generated by the installed OpenSSH version. Therefore, the simple parser is an audit baseline rather than a complete replacement for `sshd -T`.

### SSH failure conditions

A secure audit should distinguish these conditions:

- Explicitly secure directive: `PASS`
- Missing or ambiguous directive: `REVIEW`
- Explicitly weak directive: `FAIL`
- Configuration inaccessible: `UNKNOWN`

This avoids treating missing evidence as proof of security.

## sudo privilege control

sudo provides controlled privilege elevation. Its security value comes from restricting what an identity can execute as another identity.

A rule that permits a user to execute one administrative command is materially different from a rule that grants unrestricted root execution.

The SQL model represents:

- the subject receiving the privilege
- the target run-as identity
- the command pattern
- whether a password is required
- the source policy file
- whether the rule is enabled

The implementations specifically identify two policy conditions requiring review:

`NOPASSWD` rules can be legitimate for automation, but they remove password confirmation from the elevation path. They should therefore be narrowly scoped.

An `ALL` command grant creates a much broader privilege boundary and should be reviewed carefully.

Sudo security also depends on included configuration files. Examining only `/etc/sudoers` is insufficient for a complete host assessment because many Linux distributions load additional files from `/etc/sudoers.d`.

## Filesystem permissions

Linux discretionary access control commonly begins with the owner, group, and other permission classes.

For a file such as `/etc/shadow`, the security objective is to prevent unauthorized users from reading password-hash data or modifying authentication state.

The permission model can be represented as:

    Owner       Group       Other
     rwx         rwx         rwx
      |           |           |
      +-----------+-----------+
                  |
           9 permission bits

The Python, C++, and Java implementations inspect sensitive system files and detect excessive permissions.

The PostgreSQL model stores both an octal representation and explicit world-read/world-write/world-execute flags. The explicit flags make security queries easier without repeatedly decoding an octal string.

A permission such as `0644` means:

- owner: read and write
- group: read
- other: read

For sensitive resources, the important issue is not whether a particular octal value is universally correct. The correct value depends on the file's ownership model and service requirements. Hardening therefore compares observed state against a documented baseline rather than assuming that one permission value fits every Linux distribution.

Ownership is equally important. A restrictive mode on an attacker-controlled file owner does not create the same security boundary as a restrictive mode on a root-owned system file.

## Kernel security controls

The implementations inspect three controls:

| Control | Purpose |
|---|---|
| `kernel.randomize_va_space` | Controls address-space layout randomization behavior |
| `fs.protected_hardlinks` | Restricts unsafe hard-link creation |
| `fs.protected_symlinks` | Adds protections around symbolic-link following |

Address-space layout randomization makes memory locations less predictable and is an important mitigation against exploitation techniques that depend on fixed addresses.

Protected hardlinks and symlinks address classes of filesystem attacks involving users interacting with objects they do not own.

The audit compares an observed value with an expected baseline. It does not automatically write to `/proc/sys`. Automatic changes can create compatibility problems, fail to persist after reboot, or conflict with a distribution's configuration management.

Persistent kernel configuration belongs in the system's supported configuration mechanism, such as the distribution's sysctl configuration framework.

## Auditing

Hardening without visibility creates a weak operational model. A secure host needs evidence about important events.

The project treats auditing as a separate control from prevention.

The SQL model records:

- whether auditing is enabled
- whether persistent rules are loaded
- the audit log directory
- individual audit rules
- monitored paths
- syscall-oriented rules
- permission masks

The sample rules focus on identity files and privilege-sensitive operations.

A useful audit rule should answer a specific investigative question. Monitoring every possible event can create excessive volume, storage costs, and operational noise. Monitoring too little can make incident reconstruction impossible.

Audit records should also be protected from unauthorized modification. A local audit trail is valuable only when its integrity and retention properties are appropriate for the threat model.

## JavaScript event-driven model

The JavaScript implementation uses Node.js built-in modules and an `EventEmitter`.

The `HardeningAudit` class emits a `finding` event whenever a control has been evaluated. This separates evaluation from reporting.

The event flow is:

    Audit method
         |
         v
    Finding object
         |
         v
    EventEmitter
         |
         +--> terminal progress
         |
         +--> final JSON report

This structure is useful for operational integrations because another event listener could consume findings without changing the individual audit methods.

The program remains read-only and uses Node.js filesystem APIs rather than external packages.

The final JSON document contains host information, findings, timestamps, and status counts. This makes the result suitable for ingestion into a monitoring or reporting pipeline.

## C++ implementation

The C++ program approaches hardening as a compiled policy evaluation engine.

`Finding` is the central result type, while `GovernanceEngine` stores findings independently from the Linux-specific collection logic.

The Linux implementation uses:

- `std::optional` for unavailable files
- `std::array` for fixed control definitions
- `std::map` for parsed SSH directives
- POSIX `stat()` for filesystem metadata
- `/proc/sys` for kernel-control evidence
- structured status and severity values

The filesystem evaluator converts permission metadata into an explicit octal representation and checks sensitive resources against maximum permission baselines.

The design separates evidence collection from finding creation. This reduces the risk that an I/O failure is interpreted as a policy failure.

The program returns a failure exit status when at least one `FAIL` finding is produced.

## Java enterprise model

The Java implementation uses explicit domain types to model security policy.

`Finding` is a Java record, providing immutable result data. `Status` and `Severity` are enums, preventing arbitrary strings from representing policy state.

`Control` defines a common evaluation contract, while `KernelControl` implements it for `/proc/sys` controls.

`LinuxGovernanceService` coordinates SSH, sudo, filesystem, kernel, and auditing evaluation.

This structure reflects an enterprise governance pattern:

    Control
       |
       +--> SSH policy
       +--> sudo policy
       +--> filesystem policy
       +--> kernel policy
       +--> audit policy
              |
              v
           Finding

The Java implementation also uses POSIX file attributes rather than relying on shell commands. This provides type-safe access to Unix permission information from Java's standard library.

The `RepositoryPolicy` type demonstrates explicit policy state as immutable domain data. Although the Linux audit itself does not require a repository abstraction, the pattern is useful when hardening rules become part of a larger enterprise policy service.

## PostgreSQL relational model

The SQL implementation treats a hardening assessment as structured evidence.

The relational model contains separate tables for:

- hosts
- administrators
- SSH policies
- sudo rules
- filesystem objects
- kernel controls
- audit configuration
- audit rules
- generated hardening findings

The relationships preserve host-specific evidence. A policy from one machine cannot accidentally be interpreted as the policy for another host because each security record references a host through a foreign key.

Constraints provide database-level validation. For example, environments and administrator roles are restricted with `CHECK` constraints, filesystem paths are unique per host, and kernel control names are unique within a host.

Partial and ordinary indexes are used for operational queries such as finding world-writable objects and filtering findings by host and status.

## Database evaluation workflow

The `evaluate_host_hardening()` PostgreSQL function evaluates recorded evidence and inserts findings.

Its evaluation path is:

    Host
     |
     +--> SSH policy
     |
     +--> Filesystem state
     |
     +--> Kernel controls
     |
     +--> Audit configuration
     |
     +--> sudo rules
     |
     v
    Hardening findings
     |
     +--> PASS
     +--> REVIEW
     +--> FAIL
     +--> UNKNOWN

The function deliberately stores findings instead of returning only a boolean. Security assessment requires evidence, severity, and remediation context.

The `host_hardening_summary` view provides aggregate posture per host, while `failed_controls` provides a remediation-oriented view.

The sample data includes both compliant and intentionally weak states. For example, `app-staging-01` records a world-readable `/etc/shadow`, disabled kernel protections, and incomplete persistent audit configuration. These records demonstrate how the same schema handles different host postures.

## Transactional integrity

The SQL script evaluates hosts inside a transaction:

`BEGIN;`

Existing findings for the evaluated hosts are removed, the current evidence is evaluated, and the transaction is committed.

This prevents a partially refreshed assessment from becoming visible if an error interrupts the operation.

The final transaction demonstrates database-side rejection of an unsafe `/etc/shadow` state. The update attempts to create a world-readable condition, then a PL/pgSQL block detects the policy violation and raises an exception.

This illustrates an important distinction between application validation and database enforcement. Application code can detect policy violations before issuing a write, while database-side logic can prevent an unsafe state from being accepted even when another client performs the operation.

## Security boundaries and limitations

These implementations are deliberately conservative and should be treated as hardening assessment components rather than complete security scanners.

### SSH limitations

A complete OpenSSH assessment should evaluate effective configuration rather than only direct lines in `/etc/ssh/sshd_config`. Include files, conditional blocks, distribution defaults, authentication modules, host keys, cryptographic algorithms, access-control directives, and the effective daemon configuration can materially change the result.

### sudo limitations

The examples inspect selected sudoers evidence. Complete privilege analysis requires evaluating all included sudoers files, group membership, command-specific restrictions, environment controls, `secure_path`, shell escape possibilities, and the actual commands permitted by policy.

### Filesystem limitations

Unix mode bits are only one access-control layer. ACLs, extended attributes, mount options, SELinux, AppArmor, capabilities, namespaces, service-specific access controls, and filesystem ownership can change effective access.

### Kernel-control limitations

A small set of sysctl values cannot represent the complete kernel attack surface. Hardening also depends on kernel version, module policy, namespaces, capabilities, LSM configuration, container isolation, device access, and distribution-specific security defaults.

### Auditing limitations

Checking whether auditing is enabled does not establish that the audit policy is complete. Rule quality, persistence, event coverage, log integrity, retention, forwarding, storage capacity, and monitoring must be assessed separately.

## Failure-state interpretation

The project distinguishes security posture from evidence availability.

| Status | Meaning |
|---|---|
| `PASS` | The available evidence satisfies the selected baseline |
| `REVIEW` | The state may be legitimate but requires human policy evaluation |
| `FAIL` | The evidence violates the selected baseline |
| `UNKNOWN` | The control could not be reliably evaluated |

This distinction prevents a common auditing error: assuming that an inaccessible configuration is secure simply because no weakness could be observed.

## Production hardening considerations

A production hardening process should treat configuration as controlled infrastructure rather than ad hoc shell changes.

Important operational properties include:

- maintain an approved baseline for each Linux distribution and service role
- validate changes before restarting security-sensitive services
- preserve administrative recovery paths before disabling authentication methods
- avoid broad sudo permissions when command-level permissions are sufficient
- protect authentication databases and private keys with appropriate ownership and modes
- use persistent kernel configuration rather than temporary `/proc/sys` writes
- maintain audit rules across reboot
- monitor audit storage capacity
- protect audit logs against unauthorized alteration
- periodically reassess exceptions instead of allowing them to become permanent
- record evidence with timestamps and host identity
- test hardening changes in staging before production deployment

Hardening is strongest when every control has a defined baseline, an owner, observable evidence, and an explicit response to failure.
