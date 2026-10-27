# Secure Configuration Management: Baselines, Drift, and Compliance

## Scope

This project models configuration management as a controlled engineering process rather than simple storage of configuration values.

The central relationship is:

`Configuration Source → Baseline → Observed Configuration → Drift Detection → Compliance Evaluation → Change Approval → Remediation → Audit`

The implementation separates four related concerns:

| Concern | Role |
|---|---|
| Configuration | The values used by an application, operating system, service, or infrastructure component |
| Baseline | The approved reference state against which observed configuration is evaluated |
| Drift | A difference between the approved baseline and the observed state |
| Compliance | Whether configuration satisfies explicit security and operational rules |

A baseline answers "what state is approved?" Drift detection answers "what changed?" Compliance evaluation answers "does the current state satisfy policy?" Remediation answers "how should an unacceptable state be restored?"

## Configuration Baselines

A configuration baseline is a versioned, integrity-protected representation of an approved configuration state.

The examples use settings such as:

| Configuration | Baseline expectation | Security purpose |
|---|---:|---|
| `ssh.root_login` | `false` | Prevent direct privileged remote login |
| `ssh.password_authentication` | `false` | Reduce password-based remote access |
| `firewall.enabled` | `true` | Maintain host network controls |
| `tls.minimum_version` | `TLS1.2` | Prevent obsolete protocol versions |
| `audit.enabled` | `true` | Preserve security-relevant activity records |
| `backup.retention_days` | `30` | Preserve recoverability |
| `service.https_port` | `443` | Define the approved service endpoint |

Each baseline is versioned. A checksum is calculated from canonicalized baseline metadata. Before drift evaluation, the implementation verifies that the baseline itself has not been modified unexpectedly.

This distinction is important: a comparison is only trustworthy when the reference state is trustworthy.

## Drift

Drift occurs when the observed configuration differs from the approved baseline.

The implementations recognize several forms:

- A required configuration key is missing.
- An existing value differs from the baseline.
- A secret value differs from its approved state.
- An unauthorized configuration key appears.
- A baseline fails its own integrity verification.

Drift is not automatically equivalent to a security violation. A changed value can be legitimate if it has passed the organization's change process. Compliance policies determine whether the resulting state is acceptable.

The Python implementation returns structured `Drift` objects. The JavaScript implementation produces structured drift records. The PostgreSQL implementation exposes drift through `configuration_drift`, allowing database queries to aggregate and report the state.

## Compliance

Compliance is represented separately from baseline comparison.

For example, a baseline may specify a particular backup retention period, while a compliance rule may only require a minimum retention period. A configuration can therefore differ from a baseline while still satisfying a policy, depending on the organization's control model.

The examples evaluate controls such as:

- root login disabled;
- password authentication disabled;
- firewall enabled;
- TLS 1.2 or newer;
- minimum backup retention.

The Python model uses `ComplianceRule` objects containing a key and predicate. JavaScript uses policy objects with executable checks. Java represents governance through explicit domain types and policy objects. PostgreSQL evaluates required approvals, status checks, and configuration state using relational queries and functions.

## Secure Handling of Secrets

Configuration management frequently contains sensitive material such as database passwords, API tokens, private keys, and credentials.

The implementations deliberately avoid exposing secret values in normal reporting.

Python marks secret configuration items with `secret=True` and replaces their values with `<REDACTED>` during export.

JavaScript applies the same principle through `ConfigItem.secret` and `redactedSnapshot()`.

The PostgreSQL model records secret configuration items using `is_secret`. Observed secret material is represented as `REDACTED` in the demonstration data rather than being stored as cleartext.

A production implementation should normally obtain secrets from a dedicated secret-management mechanism rather than placing them in source-controlled configuration files or audit records.

## Python Implementation

The Python program provides a complete configuration workflow.

The primary domain types are:

| Type | Purpose |
|---|---|
| `ConfigItem` | Defines a baseline configuration item |
| `ConfigurationBaseline` | Stores versioned approved state and integrity checksum |
| `Drift` | Represents a detected difference |
| `ComplianceRule` | Encapsulates a compliance condition |
| `AuditEvent` | Records configuration-management activity |
| `ConfigurationManager` | Coordinates loading, evaluation, remediation, approval, and application |

The workflow begins with a production Linux web baseline. A deliberately drifted current configuration contains a changed authentication setting, a changed secret, and an unauthorized debug setting.

The manager:

1. Verifies baseline integrity.
2. Loads the observed configuration.
3. Detects missing, changed, secret, and unauthorized values.
4. Evaluates compliance rules.
5. Produces a redacted configuration view.
6. Remediates drift.
7. Proposes a configuration change.
8. Requires approval before application.
9. Records audit events.
10. Writes the audit data to a temporary JSON file.

The implementation uses only Python standard-library functionality.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library features and an event-driven architecture.

`ConfigurationService` extends `EventEmitter`. Audit events are emitted whenever important configuration actions occur.

The model uses:

- `Map` for configuration state;
- classes for baseline and configuration services;
- `Set`-like collection behavior through map keys;
- Promises for asynchronous change operations;
- Node.js `crypto` for SHA-256 baseline integrity;
- Node.js filesystem APIs for protected audit-file output.

The service distinguishes proposal, approval, rejection, and application states. A configuration change cannot be applied until it has been approved and passes compliance evaluation.

The audit file is created with restrictive filesystem permissions where supported by the runtime. Secret configuration values are excluded from the exported snapshot.

## C++17 Governance Engine

The C++ program focuses on repository-level governance of configuration changes.

Its domain includes:

`Repository Governance → Pull Request → Reviews → Approvals → Status Checks → Branch Protection → Merge Eligibility`

The program evaluates a Pull Request against a protected `main` branch.

The branch policy requires:

- two eligible approvals;
- required status checks;
- resolved review conversations;
- linear history;
- restrictions against direct pushes, force pushes, and deletion;
- no administrator bypass.

The implementation deliberately distinguishes reviewer eligibility from reviewer activity. An approval from an ineligible reviewer does not satisfy the required approval count.

Duplicate approvals from the same reviewer also count only once because the engine uses a set of reviewer identities.

The program demonstrates three important failure cases:

1. A valid Pull Request becomes blocked when an approval is dismissed.
2. The Pull Request becomes eligible again when the required reviewer re-approves.
3. A failed required security check blocks the merge even when approvals are present.

This represents the repository-governance boundary: configuration changes can be technically correct while still being prohibited from entering a protected branch.

## Java 17 Enterprise Model

The Java implementation represents an enterprise repository-governance service with explicit domain modeling.

Important records include:

- `Commit`
- `Review`
- `ReviewComment`
- `StatusCheck`
- `BranchProtectionPolicy`
- `PullRequest`
- `MergeDecision`

The `MergeEligibilityService` evaluates a Pull Request against a branch-specific policy.

Approval eligibility requires all of the following:

- the reviewer is eligible;
- the reviewer is listed by the branch policy;
- the review decision is `APPROVED`;
- each reviewer contributes at most one effective approval.

The service also evaluates required status checks, merge conflicts, Pull Request state, unresolved comments, and linear-history requirements.

`ConfigurationChangeService` provides an explicit configuration-change state machine:

`PROPOSED → APPROVED → APPLIED`

A governance failure changes the proposed operation to `REJECTED` instead of allowing an uncontrolled application.

This separation is useful in enterprise environments because repository governance and configuration management are related control layers, but they are not the same operation.

## PostgreSQL Relational Model

The PostgreSQL implementation models configuration management and repository governance together through normalized relational structures.

The principal relationships are:

`Repository`
`→ Branch`
`→ Pull Request`
`→ Commit`
`→ Review`
`→ Review Comment`
`→ Status Check`
`→ Branch Protection Policy`
`→ Approval Requirement`

Configuration state is modeled separately:

`Configuration Baseline`
`→ Baseline Item`
`→ Configuration Snapshot`
`→ Configuration Value`

A configuration change can optionally reference the Pull Request that introduced it.

### Database Constraints

The schema uses:

- primary keys for entity identity;
- foreign keys for workflow relationships;
- unique constraints for branch names and baseline keys;
- check constraints for positive versions, line numbers, and approval counts;
- PostgreSQL enum types for controlled workflow states.

These constraints prevent invalid data from entering the database even if an application-level validation layer is bypassed.

### Indexing

Indexes target actual query patterns:

| Index | Purpose |
|---|---|
| `idx_pr_target_state` | Locate Pull Requests by protected target branch and state |
| `idx_reviews_pr_state` | Evaluate approvals efficiently |
| `idx_status_checks_pr` | Locate required checks for a Pull Request |
| `idx_config_values_key` | Search observed configuration keys |
| `idx_audit_entity` | Retrieve recent audit events for an entity |

The schema does not index every column because unnecessary indexes increase write cost and storage requirements.

### Drift Views

`configuration_drift` compares baseline items with observed configuration values.

It classifies records as:

- `compliant`;
- `drifted`;
- `missing`;
- `optional_missing`;
- `observed`.

`unauthorized_configuration_keys` identifies observed configuration keys that do not exist in the baseline.

These views make compliance reporting queryable without embedding all reporting logic in application code.

## Approval and Governance

Configuration changes should not be treated as automatically deployable merely because they match a desired technical state.

The repository workflow provides a control boundary:

`Configuration Change`
`→ Pull Request`
`→ Code Review`
`→ Eligible Approvals`
`→ Required Status Checks`
`→ Protected Branch Evaluation`
`→ Merge`
`→ Deployment`
`→ Observed Configuration`
`→ Drift and Compliance Evaluation`

An approval represents a review decision. It is not itself a complete merge authorization.

A branch-protection policy determines which approvals are valid, how many are required, which automated checks must pass, whether conversations must be resolved, and which merge behaviors are permitted.

## Failure Modes

The implementations intentionally cover realistic failures.

| Failure | Control |
|---|---|
| Baseline modified unexpectedly | Checksum verification |
| Required key missing | Drift detection |
| Unauthorized configuration key | Drift detection |
| Secret differs | Secret-aware drift detection |
| Configuration violates policy | Compliance evaluation |
| Reviewer is not eligible | Approval eligibility |
| Approval is dismissed | Approval count is recalculated |
| Required check fails | Merge eligibility |
| Merge conflict exists | Pull Request validation |
| Conversation remains unresolved | Branch protection |
| Protected branch lacks required approvals | Merge guard |
| Configuration change lacks approval | Explicit state transition |
| Administrator attempts bypass | Policy-controlled bypass behavior |

## State Management

Configuration state and repository state are separate state machines.

Configuration changes use:

`PROPOSED → APPROVED → APPLIED`

with rejection possible when governance conditions fail.

Pull Requests use:

`DRAFT → OPEN → CLOSED`
`              ↓`
`            MERGED`

Reviews use decisions such as:

`COMMENTED`
`APPROVED`
`CHANGES_REQUESTED`
`DISMISSED`

A review can therefore change without changing the Pull Request itself. Merge eligibility is recalculated from the current repository state rather than permanently trusting an earlier decision.

## Security Controls

The implementation applies several security principles:

- Treat the baseline as a security-sensitive reference.
- Verify baseline integrity before using it.
- Never expose secrets in normal reports.
- Distinguish eligible reviewers from arbitrary reviewers.
- Require explicit approval for controlled changes.
- Require required automated checks.
- Prevent unauthorized keys from silently becoming part of the approved state.
- Preserve audit records for important state transitions.
- Make administrator bypass an explicit policy decision rather than an implicit privilege.
- Use restrictive permissions for locally generated audit output where supported.
- Keep secret material outside source-controlled configuration whenever practical.

The examples do not claim that a checksum alone makes a configuration baseline trustworthy. A production system also needs controlled baseline ownership, access control, secure storage, key management, audit protection, and a defined change-management process.

## Performance Characteristics

Baseline comparison is approximately `O(B + C)` for `B` baseline items and `C` observed configuration items when dictionary or map lookups are used.

The Python implementation uses dictionaries for near-constant average key lookup.

The JavaScript implementation uses `Map`, providing efficient keyed access for configuration state.

The C++ governance engine uses hash-based containers for policy and reviewer evaluation while using sets to prevent duplicate approval counting.

The PostgreSQL implementation relies on indexed foreign-key and workflow columns for repeated Pull Request and configuration queries. Relational joins and aggregation allow compliance reports to be evaluated close to the data.

For very large environments, configuration snapshots should be partitioned or retained according to an explicit retention policy rather than allowing unbounded historical growth.

## Operational Workflow

A practical controlled configuration workflow is:

`Define Baseline`
`      ↓`
`Approve Baseline`
`      ↓`
`Observe Environment`
`      ↓`
`Compare With Baseline`
`      ↓`
`Detect Drift`
`      ↓`
`Evaluate Compliance`
`      ↓`
`Create Controlled Change`
`      ↓`
`Review Change`
`      ↓`
`Collect Eligible Approvals`
`      ↓`
`Run Required Checks`
`      ↓`
`Evaluate Protected Branch`
`      ↓`
`Merge`
`      ↓`
`Deploy`
`      ↓`
`Observe Again`

This workflow prevents repository governance, configuration state, and runtime compliance from being treated as one undifferentiated control.

## Practical Distinctions

### Baseline Versus Current Configuration

The baseline is the approved reference state. Current configuration is the observed state of a real environment.

### Drift Versus Non-Compliance

Drift is a difference. Non-compliance is a policy failure.

A configuration may drift because an approved operational change has not yet been incorporated into a new baseline. Conversely, a configuration can match a baseline while violating an external compliance requirement if the baseline itself is inadequate.

### Remediation Versus Change

Remediation restores a controlled state. A change intentionally modifies the controlled state.

Both require auditability. Remediation should not be used to conceal legitimate configuration changes.

### Approval Versus Merge Eligibility

An approval is one review decision. Merge eligibility is the result of evaluating all applicable repository conditions.

A Pull Request can have approvals and still be blocked by failed status checks, conflicts, unresolved discussions, or branch protection.

## Limitations

The examples are deliberately self-contained and do not implement an actual remote repository provider API, infrastructure-agent deployment system, operating-system configuration agent, or external secret manager.

The database stores demonstration observations rather than collecting them directly from hosts.

The baseline checksum protects against accidental or unauthorized alteration detectable through checksum comparison, but secure production deployments require protected storage for both baselines and their integrity mechanisms.

Compliance predicates in the Python and JavaScript examples are executable application rules. A production policy framework would normally require stronger policy versioning, authorization, evidence retention, exception handling, and independent audit controls.

The examples also assume that configuration keys can be represented as scalar values. Real systems may require structured documents, arrays, typed values, certificates, files, permissions, package versions, service states, and platform-specific controls.

## File Relationship

| File | Primary perspective | Main implementation |
|---|---|---|
| Python | Configuration lifecycle | Baseline, drift, compliance, remediation, approval, audit |
| JavaScript | Event-driven operations | Map-based state, policy evaluation, asynchronous changes, audit events |
| C++17 | Governance engine | Pull Request, approvals, status checks, branch protection, merge eligibility |
| Java 17 | Enterprise domain model | Records, policies, state transitions, eligibility service, audit service |
| PostgreSQL | Persistent relational workflow | Repository governance, configuration snapshots, drift views, constraints, functions, triggers, reporting |
| README | Technical model | Terminology, architecture, implementation decisions, failure handling, security and performance |

## Design Boundary

The project intentionally keeps the major concepts distinct:

`Configuration`
defines actual settings.

`Baseline`
defines the approved reference state.

`Drift`
identifies differences between observed and approved state.

`Compliance`
determines whether the observed state satisfies policy.

`Pull Request`
provides controlled proposal and integration workflow for repository changes.

`Code Review`
evaluates proposed changes and records reviewer decisions.

`Approval`
represents an eligible review decision that may satisfy a required-review policy.

`Branch Protection`
enforces repository-level conditions before integration into a protected branch.

`Merge Eligibility`
combines these independent conditions into a final authorization decision.

This separation prevents a configuration value, a review decision, an approval, and a repository policy from being treated as interchangeable controls.
