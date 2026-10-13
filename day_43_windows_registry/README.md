# Windows Registry: Structure, Configuration, and Security

## Purpose and scope

The Windows Registry is a hierarchical configuration database used by Windows and applications to store settings, hardware and software configuration, file associations, service parameters, user preferences, and security-relevant state.

The registry is not an ordinary folder tree. Its keys contain named values, each of which has a data type. Access is governed by Windows security descriptors and access-control lists. Some configuration is specific to a user, while other configuration affects the computer or system services.

This learning implementation models registry paths, typed values, configuration access, and permission enforcement in Python and JavaScript. The C++ and Java programs apply related governance principles to a repository-development scenario, where pull requests, code review, approvals, and branch protection are separate mechanisms. The PostgreSQL implementation provides a relational model of that repository-governance scenario.

The repository examples are not substitutes for registry security controls. The relationship is architectural: both systems require explicit configuration, access rules, validation, auditability, and enforcement at the appropriate boundary.

## Registry architecture

### Hives and their purposes

A hive is a top-level registry namespace. Common predefined root handles include:

| Abbreviation | Windows root | Typical purpose |
|---|---|---|
| `HKCU` | `HKEY_CURRENT_USER` | Settings associated with the current user |
| `HKLM` | `HKEY_LOCAL_MACHINE` | Machine-wide configuration |
| `HKCR` | `HKEY_CLASSES_ROOT` | Merged view of class registration and file associations |
| `HKU` | `HKEY_USERS` | Loaded user profiles |
| `HKCC` | `HKEY_CURRENT_CONFIG` | Current hardware profile configuration |

These abbreviations are commonly used in Registry Editor and Windows documentation. They identify root namespaces, not ordinary directories.

`HKEY_CURRENT_USER` represents the current user's loaded profile context. Services and applications running under different accounts can see different user-specific configuration. A process running as a service account should not assume that its `HKCU` corresponds to an interactive user's settings.

`HKEY_LOCAL_MACHINE` contains machine-level configuration. Access to particular keys depends on their security descriptors and the operation being attempted. A process does not gain unrestricted access merely because it can open the root hive.

`HKEY_CLASSES_ROOT` is a merged view involving machine-wide and per-user class-registration information. Applications that inspect file associations must account for the effective view rather than assuming that every displayed entry has a single underlying storage location.

### Keys and values

A registry key resembles a directory in that it can contain subkeys. It can also contain named values, which are closer to typed configuration entries than files.

For example:

- `HKCU\Software\ExampleCorp\ReleaseAgent` is a key path.
- `Channel` can be a string value containing `stable`.
- `MaxRetries` can be a DWORD value containing `4`.
- `InstallPath` can be an expandable string containing `%ProgramFiles%\ExampleCorp\Agent`.

The default registry value has an empty name. It is not the same thing as a key's default data type. A key can contain named values with different data types.

Registry path and value-name comparisons are generally case-insensitive. The simulators preserve displayed names while normalizing lookups for comparison. They intentionally implement only a subset of native Windows behavior.

### Registry value types

| Type | Representation | Typical use |
|---|---|---|
| `REG_SZ` | String | Application name, channel, or ordinary text setting |
| `REG_EXPAND_SZ` | String with environment-variable references | Installation paths containing `%ProgramFiles%` |
| `REG_DWORD` | 32-bit unsigned integer | Feature flags, retry limits, and small numeric settings |
| `REG_QWORD` | 64-bit unsigned integer | Larger numeric settings |
| `REG_BINARY` | Byte sequence | Opaque binary configuration |
| `REG_MULTI_SZ` | Sequence of strings | Multiple search paths or configured endpoints |

A numeric value should not be stored as a string merely because both can display digits. Consumers interpret the registry type as well as its data.

`REG_EXPAND_SZ` does not mean that every consumer automatically expands environment variables. Expansion depends on the API and how the application uses the returned value. The configuration simulator retains the literal string so that expansion is not confused with reading.

The Python implementation represents `REG_BINARY` as `bytes`. Its JSON export encodes those bytes as hexadecimal because JSON has no native byte-array type. The JavaScript implementation uses `Buffer` for binary data and `BigInt` for QWORD values to avoid JavaScript's numeric precision limitations.

## Python implementation

The Python program provides a self-contained registry simulator and an optional read-only Windows adapter.

### Path resolution and case-insensitive lookup

`RegistrySimulator.normalize()` validates the root hive and rejects empty, malformed, or traversal-like path components. `_locate()` walks the simulated key tree one component at a time. Missing keys are created only when the caller explicitly requests creation.

The simulator uses dictionaries for subkeys and values. It performs case-insensitive matching without discarding the original spelling. This is important because configuration code should not create duplicate logical entries merely because callers use different capitalization.

The implementation raises separate validation and permission exceptions. Invalid data, missing keys, and denied operations should not all be represented as the same failure because callers may need to handle them differently.

### Typed values and validation

`validate_value()` enforces the data type before a value is stored. A DWORD must be an integer in the unsigned 32-bit range. A QWORD must fit the unsigned 64-bit range. Python's `bool` is a subclass of `int`, so the implementation uses an exact type check to prevent `True` from silently becoming DWORD value `1`.

Binary data must be represented by bytes, while multi-string data must be a list of valid strings. These checks catch common configuration mistakes before data enters the model.

The simulator does not attempt to reproduce every Windows registry encoding detail. Its purpose is to make type and validation rules observable without requiring Windows or modifying a real registry.

### Access checks and audit events

`set_permissions()` associates an allowed-operation set with a simulated path. `_authorize()` checks the requested operation against applicable configured ancestors and records the outcome.

The model supports read, write, delete, and enumeration operations. It denies a write to a protected key when only reading and enumeration are allowed.

This is an educational access-control model, not an implementation of Windows access tokens, security descriptors, inheritance rules, privileges, or integrity levels. Real registry authorization is performed by Windows and must not be replaced by application-maintained dictionaries.

### Export and tests

`export_json()` recursively exports the selected key, its values, and its descendants. Binary values are converted to hexadecimal so that the result is serializable.

The built-in tests check case-insensitive lookup, DWORD boundaries, binary export, inherited simulated restrictions, and deletion of empty keys. These tests verify the simulator's own behavior rather than asserting that the real Windows registry follows every simulator-specific rule.

Run the demonstration and tests with:

`python windows_registry.py --test`

To inspect an existing key on Windows without modifying it, run:

`python windows_registry.py --inspect "HKCU\Software"`

The Windows adapter uses `winreg.OpenKey()` with read access and enumerates values using `winreg.EnumValue()`. Registry inspection can still fail because a key is absent, access is denied, or the process is using a different user or registry view.

## JavaScript implementation

The JavaScript file combines a registry configuration model with an event-driven repository-governance workflow. It runs under Node.js and requires no npm dependencies.

### Registry model

`RegistryModel` uses `Map` objects for hives, keys, values, permissions, and events. This makes key existence and updates explicit, while `RegistryKey` separates named values from child keys.

The `validateValue()` function enforces registry-specific types. It uses `Buffer` for binary data and `BigInt` for QWORD values. JavaScript's ordinary `Number` type represents integers exactly only within its safe-integer range, so using `BigInt` avoids silently corrupting large 64-bit registry values.

The model rejects unsupported value types and malformed values before updating a key. It also records denied operations, making the relationship between configuration access and audit events observable.

### Pull request lifecycle as an event-driven state model

The `PullRequest` class represents a proposed repository change. Its source branch identifies where the changes originate, while its target branch identifies where they are intended to be integrated.

The request can move from draft to open, from open to merged, or from open or draft to closed. A closed request can reopen. A merged request cannot be reopened through the provided transition methods.

Commits, reviews, status checks, and discussions are maintained separately. The model clears earlier reviews when the base branch advances, illustrating why an approval must be associated with the changeset it evaluated.

The `merge()` method evaluates approval count, required check results, discussion resolution, and merge strategy. It returns a list of blockers rather than pretending that an unsuccessful merge is a successful state transition.

This model is deliberately smaller than a hosted repository platform. It does not implement network synchronization, authentication, concurrent event delivery, repository webhooks, or server-side permissions. In a production service, event persistence and merge evaluation would need transactional consistency.

## C++ case study: repository governance engine

The C++ program models a software team proposing a registry-audit change to the protected `main` branch.

### Domain model

`PullRequest` owns the request state, source and target branch names, commit identifiers, reviewer decisions, status checks, discussions, and conflict state.

`ProtectionPolicy` describes conditions that apply to the target branch. It contains a minimum approval count, required status checks, discussion-resolution rules, linear-history requirements, and restrictions on direct pushes, force pushes, and deletion.

`ProtectedBranch` evaluates direct-write, force-push, and deletion requests separately from pull-request merge eligibility. This distinction matters because a repository can allow a reviewed merge while denying direct modification of the protected branch.

### Review validity

Each `Review` records the reviewer, review state, and commit identifier that was examined. The program rejects self-review and rejects a review that refers to an obsolete head commit.

When a new commit is added, earlier reviews are cleared. A reviewer who previously approved a change has not necessarily evaluated the updated code. Synchronizing the base branch also invalidates existing reviews in the model.

These rules illustrate stale-review handling. Hosted repository systems may support different approval-dismissal settings, so an actual deployment must use the provider's configured semantics.

### Merge eligibility

`mergeBlockers()` evaluates the request state, presence of commits, conflicts, review freshness, approval count, change requests, required checks, unresolved discussions, and permitted merge method.

The function returns all detected blockers. Collecting blockers in one evaluation is more useful than stopping at the first failure because maintainers can see the complete set of conditions preventing integration.

The demonstration first encounters an unresolved discussion. Once the discussion is marked resolved, the merge can proceed because the other configured conditions are satisfied.

The implementation uses ordered collections and maps to keep the state explicit. Review and check lookup is efficient on average, while evaluation is linear in the number of reviews and discussions plus the number of required checks. The case study does not attempt to reproduce Git's actual commit graph or calculate merge conflicts.

### Branch protection and bypass

The branch policy denies ordinary direct pushes, force pushes, and deletion. An explicit bypass can override the modeled restriction, and the administrator setting determines whether administrators must comply with the policy.

A bypass is a privileged exception, not evidence that a review or status check passed. Production governance should log the actor, affected branch, justification, and time of every bypass. Broad bypass permissions weaken the protection provided by the normal merge workflow.

Compile with a C++17-compatible compiler, for example:

`g++ -std=c++17 repository_governance.cpp -o repository_governance`

## Java implementation: enterprise repository policy

The Java program represents repository governance using explicit domain types and immutable policy configuration.

### Domain types and state transitions

The enums `RequestState`, `ReviewState`, `CheckState`, `MergeMethod`, and `Permission` prevent unrelated states from being represented as arbitrary strings.

The `Commit` and `Review` records validate their fields at construction time. `BranchProtection` copies its required-check set so that the policy cannot be changed by modifying the caller's original collection.

`PullRequest` maintains separate collections for commits, reviews, status checks, and review discussions. Methods such as `markReady()`, `addCommit()`, `submitReview()`, `close()`, and `reopen()` enforce allowed state transitions.

Invalid transitions raise exceptions rather than silently changing request state. The program also prevents authors from submitting their own approvals and rejects reviews that do not reference the current commit.

### Policy evaluation

`evaluateMerge()` computes the current blockers. Java Streams count valid approvals and detect change requests, while explicit iteration checks each required status check.

An approval alone does not authorize a merge. The request must also satisfy the target branch's configured requirements. A successful status check associated with an earlier head is not equivalent to a successful check for the current changeset; a production implementation should require checks to match the current head.

The policy treats unresolved discussions as blockers when configured. It also rejects merge commits when linear history is required. Squash and rebase are represented as distinct merge methods because they produce different commit-history outcomes.

### Access restrictions

`ProtectedBranch.permits()` distinguishes read, direct-write, deletion, and bypass decisions. Force-push permission is evaluated separately because force pushes can rewrite branch history even when ordinary writes are restricted.

The example models administrator exceptions and explicit bypass behavior, but it does not authenticate users or implement actual server-side authorization. A real service must derive identity from a trusted authentication system and enforce policy at the point where branch changes occur.

Compile and run using Java 17 or later:

`javac RepositoryGovernance.java`

`java RepositoryGovernance`

## SQL implementation: relational governance and audit

The PostgreSQL script stores repository governance data in a relational schema named `repository_governance`.

### Entity relationships

| Table | Responsibility |
|---|---|
| `repositories` | Repository identity and default branch |
| `repository_users` | Reviewer, author, and administrator identities |
| `branches` | Branch names, heads, revisions, and deletion state |
| `branch_protection` | Target-branch governance settings |
| `protected_required_checks` | Required check names for each protected branch |
| `pull_requests` | Request metadata, source and target, and lifecycle state |
| `commits` | Commit metadata associated with branches |
| `pull_request_commits` | Ordered commits included in a request |
| `reviews` | Review decisions and the commit each decision examined |
| `review_comments` | General and inline comments |
| `review_discussions` | Resolution state for review conversations |
| `status_checks` | Check results associated with a request and head |
| `merge_events` | Recorded integration events |
| `governance_audit` | Security-relevant policy decisions |

Primary keys identify individual records. Foreign keys preserve relationships between repositories, branches, users, reviews, checks, and requests. Unique constraints prevent duplicate branch names within a repository, duplicate reviewer-independent commit references within the same branch, and repeated sequence numbers for a request's changeset.

The schema intentionally keeps review comments and discussion-resolution state separate. A comment can remain available for audit purposes after its discussion has been resolved.

### Database constraints and triggers

Check constraints validate non-empty names, numeric bounds, commit-hash formats, and compatible timestamp states. A merged pull request must have a merge timestamp and a selected strategy.

The `prevent_self_review()` trigger prevents an author from reviewing their own pull request. This is a database-level integrity rule that protects against writes from any application path that uses the table.

The `resolve_discussion()` function updates an unresolved discussion and records the resolver and time. It raises an exception when the discussion does not exist or has already been resolved.

These mechanisms provide consistency checks, but they do not replace authentication, authorization, or a complete merge transaction. Production access should be restricted through database roles and service-level permissions.

### Approval semantics and stale reviews

The `current_approval_counts` view counts approvals that have not been dismissed and that reference the latest commit associated with a pull request. It also exposes whether a current review requests changes.

A dismissed approval is retained as historical data instead of being deleted. This preserves the decision history and its dismissal reason.

The example advances the target branch revision and dismisses old approvals. In a real repository service, stale-review rules depend on the actual provider policy and which changes invalidate approval. The schema demonstrates one explicit policy choice rather than claiming that all hosting platforms use identical behavior.

### Required status checks

`protected_required_checks` defines which checks a target branch requires. `status_checks` stores each check's result against a particular head commit.

The `merge_eligibility` view compares required checks with the latest commit in the request. A missing check, a pending check, or a failed check prevents eligibility.

The view reports eligibility before merge-strategy validation and does not perform the merge. The configured strategy, linear-history setting, actor permissions, bypass authorization, and concurrent updates must also be enforced by the merge service.

The indexes on target branch and request state, active reviews, status checks, unresolved discussions, and audit timestamps support common governance queries. Partial indexes reduce the number of indexed rows for queries that consistently filter dismissed reviews or resolved discussions.

### Transactions and production consistency

The script wraps schema creation and sample data insertion in a transaction. PostgreSQL can roll back those changes if an error aborts the transaction.

A production merge workflow should evaluate the request and protection policy within a transaction that locks the relevant request and branch rows. It should verify the current head, review decisions, check results, discussion states, and branch revision immediately before recording the merge. Otherwise, a check or approval may become stale between evaluation and integration.

The schema does not implement every provider feature. In particular, it does not reproduce Git's commit graph, distributed synchronization, native identity tokens, full access-control inheritance, or a hosting provider's exact bypass and review-dismissal rules. Those require additional integration and authorization logic.

## Configuration and security distinctions

Registry configuration and repository governance share the need for reliable state and enforceable rules, but their security mechanisms are not interchangeable.

Windows registry security is based on Windows access tokens, registry handles, security descriptors, access-control lists, and relevant privileges. Repository governance is based on repository identities, review decisions, status checks, branch policies, and merge authorization.

A registry value containing a security setting does not enforce that setting by itself. The consuming component must interpret it correctly, and the system must enforce the resulting policy. Similarly, a database row indicating that a pull request is eligible does not prevent another actor from modifying a protected branch. Enforcement must occur at the trusted integration boundary.

Configuration readers should use the least access required, validate data types and ranges, distinguish missing values from denied access, and avoid exposing secrets through diagnostic output. Applications should not assume that values under a particular path are trustworthy merely because the path has a familiar name.

Registry changes can affect application behavior, system configuration, file associations, or security controls. A production registry modification should identify the exact key and value, understand the scope of the change, confirm the required permissions, preserve a recovery path, and validate the result after modification.

The simulators in these files intentionally avoid modifying the real registry. Their access-control maps demonstrate policy concepts, while actual Windows registry operations must rely on the operating system's security mechanisms.
