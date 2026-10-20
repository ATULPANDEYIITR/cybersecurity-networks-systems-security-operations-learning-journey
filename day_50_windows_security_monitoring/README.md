# Windows Security Monitoring

## Scope

This project models Windows Security monitoring for four closely related activity domains:

- Process creation
- Logon activity
- Privilege changes
- Account activity

The implementations use normalized security events corresponding to common Windows Security event IDs. The focus is detection logic rather than raw Windows Event Viewer formatting.

| Activity | Representative Event IDs | Monitoring purpose |
|---|---|---|
| Logons | 4624, 4625, 4634, 4647 | Detect successful and failed authentication activity |
| Privilege changes | 4672 | Identify assignment of special privileges |
| Process creation | 4688 | Track executable creation and suspicious interpreters |
| Account activity | 4720, 4722, 4725, 4726, 4738, 4740 | Track account lifecycle and lockout activity |

The central relationship is temporal:

`Logon → Privilege assignment → Process creation`

and, independently:

`Account change → Account use → Subsequent activity`

A single event is often insufficient to establish risk. Correlation across event type, identity, computer, source address, and time produces stronger detections.

## Windows Security Event Model

The normalized event model used by the source files contains:

| Field | Meaning |
|---|---|
| `event_id` | Windows Security event identifier |
| `timestamp` | Event occurrence time |
| `computer` | Host that generated the event |
| `subject_user` | Security principal responsible for the action |
| `target_user` | Account affected by the action |
| `source_ip` | Remote origin when applicable |
| `process_name` | Created executable |
| `process_id` | Process identifier when available |
| `logon_type` | Windows logon mechanism |
| `privilege` | Special privilege assigned to a principal |

The distinction between subject and target is important. A service or administrator may perform an operation against another account. Treating every account field as the same identity can produce incorrect attribution.

## Logon Monitoring

Event 4624 represents a successful logon and event 4625 represents a failed logon.

The implementations pay particular attention to logon types 2, 10, and 11:

| Logon type | Interpretation |
|---|---|
| 2 | Interactive |
| 10 | RemoteInteractive, commonly associated with Remote Desktop |
| 11 | CachedInteractive |

A privileged interactive logon is elevated in the examples because privileged accounts provide greater control over the operating system.

Failed authentication is handled differently. Three failed logons for the same target account within five minutes trigger a burst detection. This is a threshold-based behavioral rule rather than a claim that every failed authentication represents an attack.

The Python implementation maintains grouped event windows. JavaScript maintains per-user event queues in an event-driven monitor. C++ performs an offline sliding-window analysis. Java encapsulates the behavior in a `DetectionRule`. PostgreSQL uses a window function with a five-minute temporal frame.

## Process Creation Monitoring

Event 4688 records process creation.

The examples treat the following executables as security-relevant script or administrative interpreters:

`powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, and `certutil.exe`.

The presence of one of these processes is not automatically proof of malicious activity. These programs have legitimate administrative uses. The implementations therefore represent the event as a detection signal rather than a final security verdict.

The stronger correlation is:

`4672 special privilege assignment`
  
`↓`
  
`4688 process creation`

When a privileged process appears shortly after a special-privilege event for the same user and computer, the detection severity is increased.

Process identifiers are retained as evidence but are not treated as permanent identities. Windows process IDs can be reused after a process terminates.

## Privilege Monitoring

Event 4672 is used to identify special privileges assigned to a logon session.

The examples distinguish privilege names rather than treating every privilege identically. `SeDebugPrivilege` receives a higher severity because it can provide powerful process-access capabilities.

Privilege assignment should be interpreted in context:

- Which account received the privilege?
- Which computer generated the event?
- When was the privilege assigned?
- Was a sensitive process created afterward?
- Is the account expected to possess administrative capabilities?

A monitoring system should not assume that a privilege assignment itself constitutes compromise.

## Account Activity

Account lifecycle events represent a different monitoring dimension from authentication and process execution.

The SQL model records:

- Account creation
- Account enablement
- Account disablement
- Account deletion
- Account changes
- Account lockouts

The trigger `record_account_activity` converts Windows event identifiers into a constrained relational activity vocabulary.

This separates raw telemetry from the operational interpretation of that telemetry.

For example:

`4720 → created`

`4722 → enabled`

`4725 → disabled`

`4726 → deleted`

`4738 → changed`

`4740 → locked`

Account creation and enablement are treated as higher-severity examples because a newly usable identity can immediately become an execution or persistence mechanism.

## Python Implementation

The Python program is an offline monitoring and analysis engine.

Its `SecurityEvent` dataclass provides a strongly structured representation of normalized telemetry. Validation occurs while events are parsed, including timestamp parsing, event-ID validation, and IPv4 validation.

The event pipeline is:

`CSV / sample data`

`↓`

`SecurityEvent`

`↓`

`Detection rules`

`↓`

`Alert`

`↓`

`Operational report`

The implementation contains independent detectors for:

- Failed-logon bursts
- Special-privilege assignments
- Script or administrative interpreter processes
- Account lifecycle changes
- Privileged interactive logons

The failed-logon detector groups events by account and uses a moving time window. This avoids repeatedly scanning the entire event collection for every event.

The script also creates SHA-256 fingerprints of normalized events. These fingerprints provide deterministic identifiers for the exact normalized representation used by the program. They are not substitutes for Windows event record identifiers or cryptographic evidence collection.

A CSV input can be supplied with `--csv`. Without an input file, a controlled sample dataset is used so the program remains executable without external services or dependencies.

## JavaScript Implementation

The JavaScript implementation uses Node.js event-driven processing rather than reproducing the Python architecture.

`SecurityEventStream` provides a publish-subscribe mechanism. Consumers subscribe to security events and process them as they arrive.

The flow is:

`SecurityEventStream`

`↓`

`SecurityMonitor`

`↓`

`Detection rules`

`↓`

`Alert collection`

This structure is appropriate for a monitoring process where events arrive continuously instead of being analyzed only after a complete batch has been collected.

The stream uses a bounded event history. This prevents an indefinitely running process from retaining every event in memory.

The JavaScript monitor also demonstrates temporal correlation by searching recent history for a special-privilege event immediately preceding a process creation event.

JSON Lines input is supported. Each line represents one normalized event, which allows the program to process large files incrementally instead of loading the complete file into a single JSON array.

## C++ Implementation

The C++ program implements a batch-oriented monitoring engine using explicit domain structures and standard-library containers.

The principal design is a `RepositoryGovernanceStyleMonitor`-like analysis engine that maintains:

- Ordered security events
- Detection alerts
- Grouped failed-logon windows
- Process interpreter classifications

The failed-logon detector groups pointers to relevant events by effective account and applies a sliding window. Its time complexity is approximately O(n) for the grouping and window traversal after sorting, with sorting contributing O(n log n).

The implementation separates:

- Event ingestion
- Validation
- Detection
- Alert construction
- Reporting

This makes the analysis rules independent of the presentation layer.

The program uses `std::optional` for fields that do not apply to every event. For example, a process creation event may have a process ID while a privilege assignment event does not.

## Java Implementation

The Java implementation uses explicit domain types and a rule-oriented enterprise model.

`SecurityEvent` is an immutable record. Its compact constructor validates event identifiers, required identity fields, logon types, and source addresses.

`EventType` converts numeric Windows event identifiers into a domain vocabulary.

`DetectionRule` provides a common policy interface:

`SecurityEvent collection → List<Alert>`

The concrete rules are:

- `FailedLogonRule`
- `PrivilegeRule`
- `AccountActivityRule`
- `PrivilegedLogonRule`

`SecurityMonitor` composes these rules without embedding every detection policy directly into the monitor itself.

This architecture makes it possible to add a new detection rule without changing the representation of existing security events.

The use of immutable records also prevents a security event from being silently modified after validation. That is important when an event is passed through multiple detection services.

## PostgreSQL Model

The PostgreSQL implementation represents security telemetry relationally.

The main entities are:

`computers`

`accounts`

`security_events`

`account_activity`

`status_checks`

`detection_rules`

`alerts`

Foreign keys maintain relationships between event records, computers, identities, detection rules, and alerts.

The database enforces rules that should not depend solely on application code. A trigger rejects:

- Logon events without target accounts
- Process creation events without process names
- Privilege events without privilege names

The account activity trigger converts relevant Windows event identifiers into the normalized `account_activity` table.

The database contains indexes for the most important operational access patterns:

- Recent events
- Event type plus time
- Target-account activity
- Source-IP activity
- Unresolved alerts

Partial indexes are used where only open alerts or non-null network sources are relevant.

## SQL Detection and Correlation

The failed-logon query uses a PostgreSQL window function:

`COUNT(*) OVER (...)`

with a five-minute temporal frame.

This permits each failed authentication event to be evaluated against preceding failures for the same target account.

Privilege-to-process correlation uses a temporal join:

`4672 privilege assignment`

followed by:

`4688 process creation`

within one minute for the same computer and subject account.

The database therefore evaluates both isolated activity and event relationships.

The final transactional operation inserts detected failed-logon alerts while checking for existing event-level alerts. The transaction keeps the detection write consistent if the operation is interrupted.

## Detection Severity

The examples use three levels:

| Severity | Example |
|---|---|
| Medium | Script interpreter process, ordinary special privilege assignment, account modification |
| High | Repeated failed logons, privileged interactive logon, `SeDebugPrivilege`, account creation |
| Low | Reserved for lower-confidence detections not used by the supplied sample rules |

Severity is a prioritization mechanism, not a statement of certainty.

A production implementation should normally combine these rules with asset criticality, identity risk, historical behavior, allowlists, authentication context, and other telemetry.

## Failure Conditions and Edge Cases

The implementations validate malformed or incomplete telemetry rather than silently accepting it.

Important cases include:

- Invalid timestamps
- Invalid IPv4 addresses
- Missing computer or subject identity
- Missing target accounts for authentication events
- Missing process names for process creation
- Missing privilege names for privilege events
- Non-positive event IDs
- Invalid process IDs
- Negative logon types
- Empty input datasets
- Repeated detections inside the same correlation window

Temporal boundaries also matter. An event exactly at the beginning of a five-minute monitoring window is treated as part of the window, while events older than that interval are removed from the active sliding window.

## Security and Operational Considerations

Windows Security logs should be protected against unauthorized modification and access. Monitoring software should run with the minimum permissions required to read the telemetry it processes.

Network addresses and usernames are security-sensitive telemetry. Reports should restrict access according to operational need.

A detection engine should preserve the distinction between:

`observed event`

and:

`security conclusion`

A PowerShell process, privileged account, or failed logon can be legitimate. Rules should therefore generate evidence-rich alerts for investigation rather than automatically declaring compromise.

Clock consistency is also important. Cross-host correlation depends on comparable timestamps. Centralized collection should account for clock skew and preserve the original event time separately from ingestion time.

Large-scale monitoring should avoid unbounded memory growth. The JavaScript stream demonstrates bounded history, while the batch-oriented implementations rely on sorting and grouped windows. Production systems commonly use time-partitioned storage, streaming pipelines, or database retention policies.

## Relationship Between the Four Monitoring Domains

The four domains answer different questions:

| Domain | Primary question |
|---|---|
| Logons | Who authenticated, where, how, and whether authentication failed? |
| Privilege changes | Which security privileges were assigned to the session? |
| Process creation | What executable was started by that security principal? |
| Account activity | Which identity was created, enabled, disabled, changed, deleted, or locked? |

Their relationship enables correlation without collapsing them into one category.

For example:

`4624 successful logon`

`↓`

`4672 special privilege`

`↓`

`4688 PowerShell process`

is stronger investigative evidence than any one of these events considered alone.

A separate account lifecycle sequence such as:

`4720 account created`

`↓`

`4722 account enabled`

can indicate that an identity has become usable and should be correlated with subsequent authentication and process activity.

## Practical Monitoring Workflow

A practical monitoring pipeline represented by these implementations is:

`Windows Security telemetry`

`↓`

`Normalization and validation`

`↓`

`Event classification`

`↓`

`Temporal and identity correlation`

`↓`

`Detection rule evaluation`

`↓`

`Evidence-rich alert`

`↓`

`Investigation and response`

The important architectural boundary is between collection and interpretation. Raw security events should remain available so that detection decisions can be reproduced and investigated later.

The source implementations deliberately keep detection rules explicit. This makes thresholds, event IDs, identities, time windows, and evidence visible and testable rather than hiding security decisions inside generic data-processing code.
