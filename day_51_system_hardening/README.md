# System Hardening

This project models system hardening as a controlled reduction of security exposure rather than as a collection of isolated configuration changes. The five implementations represent the same operational domain from different technical perspectives:

| Implementation | Primary perspective |
|---|---|
| Python | Host baseline assessment, service minimization, attack-surface scoring, and patch prioritization |
| JavaScript | Event-oriented policy evaluation and mutable exposure-reduction workflow |
| C++17 | Low-level governance and merge-eligibility engine combined with host exposure analysis |
| Java 17 | Enterprise domain model with explicit policies, immutable records, state evaluation, and service boundaries |
| PostgreSQL | Persistent relational model for hosts, services, vulnerabilities, repositories, reviews, checks, and governance policies |

The central security principle is to establish an explicit desired state, compare real state against it, reduce unnecessary exposure, remediate known vulnerabilities, and verify that security conditions remain satisfied.

## Security model

System hardening in this project has four related but distinct control areas:

- **Secure baselines** define the minimum acceptable security configuration.
- **Attack-surface reduction** removes or restricts unnecessary exposure.
- **Service minimization** disables services that are not required for the system's intended function.
- **Patch management** addresses known vulnerabilities through fixed versions and controlled remediation states.

A simplified operational relationship is:

`Secure baseline → Detect deviations → Reduce exposure → Patch vulnerabilities → Reassess`

A secure baseline is not itself a patching mechanism. Likewise, installing patches does not compensate for unnecessary services, weak authentication configuration, or unrestricted administrative access.

## Secure baselines

A baseline is an explicit collection of security requirements against which a host can be evaluated.

The examples use requirements such as:

| Control | Example baseline |
|---|---|
| Password length | At least 14 characters |
| Password age | No more than 90 days |
| Host firewall | Required |
| Remote root login | Disabled |
| Audit logging | Required |
| Disk encryption | Required |

The Python implementation represents these requirements using `SecureBaseline`. A `Host` stores its observed state, while `HardeningEngine.assess_baseline()` produces findings when the observed state falls below the desired state.

The Java implementation makes the baseline an immutable `record`. `SecureBaseline` therefore represents policy data separately from the mutable host configuration. `Host.applyBaseline()` changes only configuration values represented by the model.

The SQL implementation stores baseline requirements in `secure_baselines` and host state in `hosts`. This separation permits multiple hosts to be evaluated against a common baseline without duplicating the policy definition.

A baseline should be versioned in a production environment. Changing the required password length or encryption requirement changes the expected security state and should therefore be auditable.

## Attack-surface reduction

Attack surface represents the collection of reachable functionality that an attacker could potentially interact with.

The implementations model attack surface through service properties:

- whether the service is required;
- whether it is externally reachable;
- whether its communication is encrypted.

The Python and JavaScript implementations calculate a simple prioritization score. The score is intentionally not presented as a vulnerability severity rating. It identifies exposure that deserves investigation.

An externally reachable unnecessary service receives a higher score than an internal required service. An externally reachable unencrypted service receives additional risk weight.

The C++ implementation uses the same conceptual dimensions but embeds them in a governance-oriented `Host` model. `GovernanceEngine::attackSurface()` calculates exposure while `minimizeServices()` removes external exposure from unnecessary services.

The PostgreSQL view `externally_exposed_services` makes the same analysis queryable across multiple hosts.

The model demonstrates an important distinction:

`Exposure ≠ Vulnerability`

A service can be correctly patched and still represent unnecessary attack surface. Conversely, an internal service can contain a serious vulnerability even though it is not directly exposed to the Internet.

## Service minimization

Service minimization follows the principle of enabling only functionality required by the system's role.

The example host contains:

- SSH for administration;
- HTTPS for the application;
- a metrics service that is not externally reachable;
- Telnet as an unnecessary exposed service;
- FTP as another unnecessary exposed service.

Telnet and FTP are particularly useful examples because their unnecessary exposure combines service minimization with transport-security concerns.

The implementations do not blindly remove every service. Each service contains a `required` property. A production hardening process must first establish dependencies because disabling a service without dependency analysis can interrupt legitimate operations.

The Python implementation restricts external exposure from unnecessary services. The JavaScript implementation performs the same action through `reduceExposure()`. The C++ implementation uses `minimizeServices()`. The SQL model records the service state and exposes it through reporting views rather than automatically modifying operational infrastructure.

This separation is intentional. A database reporting system should not silently disable operating-system services.

## Patch management

Patch management addresses known software weaknesses through a controlled lifecycle.

The model uses four states:

`required → scheduled → installed`

with `deferred` available when remediation cannot immediately occur.

Each vulnerability contains:

- vulnerability identifier;
- severity;
- affected service;
- fixed version;
- due date;
- remediation status.

The Python implementation prioritizes patches using severity and overdue duration.

The JavaScript implementation sorts outstanding vulnerabilities by severity and due date, providing a policy-evaluation result suitable for an event-driven service.

The Java implementation models patches as immutable records and separates patch prioritization from host configuration.

The SQL model separates vulnerability definitions from host-specific remediation state. `vulnerabilities` describes the vulnerability, while `host_vulnerabilities` describes how a particular host is affected and what fixed version is required.

A critical vulnerability receives immediate priority even if its nominal deadline has not passed. A lower-severity vulnerability whose deadline has passed becomes overdue and receives elevated attention.

Patch status must not be interpreted as proof that software is actually patched. In production, the state should be backed by package-manager results, endpoint inventory, configuration-management evidence, or another authoritative source.

## Python implementation

The Python file uses dataclasses to represent security policy and host state.

`SecureBaseline` contains the expected security configuration. `Service` describes individual network functionality. `Vulnerability` represents a patch-management item. `Host` combines the observed state.

`HardeningEngine` separates three assessment mechanisms:

- `assess_baseline()` checks configuration;
- `assess_services()` checks exposure and unnecessary functionality;
- `assess_patches()` evaluates outstanding vulnerabilities.

The separate methods prevent the different hardening controls from being treated as one generic finding category.

`apply_safe_hardening()` applies only deterministic changes represented safely by the model. It does not execute operating-system commands. This is important because real changes such as enabling encryption can require recovery-key handling, reboot planning, backups, and operational approval.

The script also demonstrates a post-change assessment. A hardening action is useful only when the resulting state can be checked again.

## JavaScript implementation

The JavaScript implementation uses classes and explicit policy objects to model a Node.js-oriented security evaluation service.

`SecureBaseline` stores the desired state. `Host`, `Service`, and `Vulnerability` represent operational data.

`HardeningPolicy` provides separate evaluation methods for:

- baseline compliance;
- service exposure;
- patch status;
- attack-surface calculation;
- exposure reduction;
- patch prioritization.

JavaScript-specific validation occurs in constructors. Invalid ports, malformed vulnerability identifiers, and missing service names produce immediate exceptions instead of silently entering the security model.

The implementation uses `reduce()`, filtering, sorting, and structured objects to represent the sort of event-processing operations commonly used by a policy service.

No external npm package is required.

## C++17 implementation

The C++ program uses a repository-governance scenario to connect system-hardening concepts with controlled software delivery.

The `Host` model contains hardening configuration, services, and patches. The same program also contains repository structures:

`Repository → BranchProtection → PullRequest → StatusCheck / approvals`

This permits merge eligibility to be evaluated as an explicit policy decision.

`GovernanceEngine::evaluateMerge()` checks:

- Pull Request state;
- draft status;
- required status checks;
- required approvals;
- unresolved conversations;
- protected-branch restrictions.

The program separately evaluates host hardening and attack surface.

The C++ design emphasizes explicit state and deterministic decision logic. `Decision` contains both the boolean eligibility result and individual blockers, which makes the result useful for debugging and operational reporting.

The example demonstrates an important security-engineering relationship: a security fix can exist as a proposed change while still being prevented from merging until required validation conditions are satisfied.

## Java 17 implementation

The Java implementation uses enterprise-oriented domain modeling.

Records represent immutable domain values such as:

- `Service`;
- `Patch`;
- `SecureBaseline`;
- `StatusCheck`;
- `Review`;
- `BranchPolicy`;
- `PullRequest`;
- `Repository`;
- `MergeDecision`.

`Host` remains mutable because it represents operational state that can be changed by a hardening workflow.

The model separates two services:

- `HardeningService` evaluates host configuration, exposure, and patches.
- `RepositoryGovernanceService` evaluates repository merge eligibility.

This separation prevents hardening policy from becoming a single undifferentiated rule engine.

Review eligibility and approval state are also distinct. An approval from an inactive or stale reviewer does not automatically satisfy a required-approval policy.

The Java implementation uses streams for filtering, counting, and sorting. It uses explicit exceptions for invalid domain data, such as malformed vulnerability identifiers or invalid ports.

## PostgreSQL model

The PostgreSQL implementation provides persistent state for the operational model.

The main relationships are:

`repositories → branches → branch_protection_policies`

and:

`repositories → pull_requests → commits`

with review and validation data attached through:

`pull_requests → reviews → review_comments`

and:

`pull_requests → status_checks`

The host-hardening side uses:

`hosts → host_services`

and:

`hosts → host_vulnerabilities → vulnerabilities`

This prevents vulnerability metadata from being duplicated for every affected host.

### Repository governance data

The database represents:

- repositories;
- branches;
- protected branches;
- branch-protection policies;
- users;
- Pull Requests;
- commits;
- review requests;
- reviews;
- review comments;
- status checks.

Branch protection is represented as policy data rather than inferred from individual reviews.

The `branch_protection_policies` table includes controls such as required reviews, approval counts, status checks, resolved conversations, direct-push restrictions, force-push restrictions, branch deletion restrictions, linear-history requirements, and administrator bypass behavior.

### Hardening data

The host model represents:

- operating-system version;
- password requirements;
- firewall state;
- remote-root configuration;
- audit logging;
- disk encryption;
- services;
- vulnerabilities;
- fixed versions;
- patch deadlines;
- patch states.

Database constraints prevent invalid values such as ports outside the TCP/UDP port range or negative approval requirements.

### Reporting views

`host_hardening_findings` identifies baseline deviations.

`externally_exposed_services` identifies reachable services and provides an exposure-prioritization score.

`patch_risk_report` combines vulnerability severity, affected service, due date, and patch status.

These views provide read-only security reporting rather than making operational changes to hosts.

## Merge eligibility and security validation

A secure software change should not become deployable merely because a Pull Request exists.

The database evaluates several independent conditions:

- Pull Request must be open;
- draft Pull Requests are not mergeable;
- required reviews must be satisfied;
- required status checks must pass;
- required review conversations must be resolved.

The relationship is:

`Pull Request → proposed change`

`Review → evaluation of the proposed change`

`Approval → reviewer decision`

`Branch protection → repository-level enforcement of merge conditions`

These mechanisms have different responsibilities. A Pull Request is a change-management workflow, while branch protection is an enforcement policy. A review is an evaluation activity, while an approval is a particular review decision.

## Transactional patch remediation

The SQL script includes a transaction around a critical vulnerability state transition.

The sequence is:

`BEGIN → update patch state → validate resulting state → COMMIT`

If the integrity check fails, the transaction raises an exception instead of committing an inconsistent remediation state.

Database transactions do not themselves patch an operating system. They provide atomicity for the security inventory's representation of a patch operation.

A production implementation should correlate this state with authoritative endpoint evidence.

## Failure modes

### Weak baseline

A host can satisfy operational requirements while violating a security baseline. For example, an application may function normally even when its firewall is disabled.

The model reports the configuration deviation independently from application availability.

### Excessive service exposure

An unnecessary service increases attack surface even when no current vulnerability is known.

The model therefore evaluates service necessity independently from vulnerability status.

### Unencrypted external service

A service can be required but still be incorrectly exposed without encryption. The required status of a service does not make an insecure protocol acceptable.

### Overdue patch

A patch that remains uninstalled after its due date is escalated during prioritization.

### Critical vulnerability

Critical severity takes precedence over normal scheduling because delaying remediation can expose the system to disproportionate risk.

### Stale or invalid review state

An approval should not automatically remain valid after the underlying change has materially changed or the reviewer is no longer eligible. The Java and SQL models provide explicit fields that allow these states to be evaluated rather than assuming that every historical approval is permanently valid.

### Unresolved review discussion

A branch policy can require conversations to be resolved before merging. The review-comment model therefore stores resolution state independently from approval state.

## Performance considerations

The in-memory implementations use linear scans for host services, vulnerabilities, and findings. For a single host this is appropriate and keeps the decision engine deterministic.

The PostgreSQL implementation uses indexes where repeated filtering benefits from indexed access:

- Pull Requests by target branch and status;
- reviews by Pull Request and review state;
- status checks by Pull Request and required/pass state;
- vulnerabilities by due date and patch status.

The database should not be indexed indiscriminately. Each index adds storage and write-maintenance cost.

For larger repositories, merge eligibility can be evaluated from materialized or cached policy state, but cached decisions must be invalidated whenever a status check, review, approval, conversation, branch policy, or Pull Request state changes.

## Security considerations

Hardening automation must distinguish between desired state and verified state.

A configuration system should not claim that encryption is active simply because a desired configuration field was changed. The Python and Java examples intentionally model this distinction rather than invoking destructive operating-system commands.

Patch inventory should similarly be tied to authoritative software inventory.

Sensitive operational information should be protected. Security findings can disclose vulnerable services, versions, hostnames, or configuration weaknesses. Production systems should enforce access control, audit access to findings, protect credentials and recovery keys, and avoid exposing vulnerability inventories through unauthenticated endpoints.

Hardening changes should be auditable. A production workflow should record who initiated a change, what policy required it, what state existed before the change, what evidence confirmed success, and whether rollback was possible.

## Practical hardening workflow

A defensible operational workflow can be represented as:

`Inventory → Baseline → Assess → Prioritize → Minimize → Patch → Verify → Monitor`

Inventory establishes what exists.

Baseline defines the acceptable configuration.

Assessment identifies deviations.

Prioritization orders remediation according to severity, exposure, and operational urgency.

Minimization removes unnecessary services and exposure.

Patching addresses known software weaknesses.

Verification checks that the intended state actually exists.

Monitoring detects regression as systems and software change.

The implementations deliberately keep these activities distinguishable because a system can be patched and still be insecure, or have a strong baseline and still contain an unpatched critical vulnerability.
