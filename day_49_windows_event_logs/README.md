# Windows Event Logs: Security, System, Application, PowerShell, and Authentication

## Scope

Windows Event Logs provide structured operating-system telemetry for security investigation, system administration, application troubleshooting, and PowerShell activity.

This implementation treats the major event-log areas as related but distinct evidence sources:

| Area | Primary purpose | Representative evidence |
|---|---|---|
| Security | Auditing security-sensitive activity | Logons, failed logons, privilege assignment, account changes, audit-log clearing |
| System | Operating-system and service behavior | Service installation, driver activity, boot-related events, system failures |
| Application | Software-level failures and application-generated events | Application crashes, application errors, application diagnostics |
| PowerShell | PowerShell engine and execution telemetry | Engine lifecycle, module logging, script-block logging |
| Authentication | Identity and access activity across relevant Security events | Successful and failed logons, Kerberos activity, NTLM authentication |

The distinction matters because an authentication failure is not the same type of evidence as a service installation, an application crash, or PowerShell script-block telemetry. The programs preserve those differences instead of treating all events as one undifferentiated stream.

## Windows Event Record Structure

A Windows event normally contains a System section with metadata such as the provider, event ID, level, timestamp, computer, and record identifier. Event-specific fields are commonly stored in EventData.

The Python implementation parses these structures from XML. It extracts fields such as `TargetUserName`, `SubjectUserName`, `IpAddress`, and `ClientAddress` when they are available.

A normalized event in the Python program contains:

- `record_id`, which identifies the event within its log.
- `log_name`, which identifies the originating channel.
- `provider`, which identifies the event source.
- `event_id`, which gives the event type its Windows-specific meaning.
- `timestamp`, stored as a timezone-aware value.
- `computer`, identifying the originating Windows host.
- `user` and `ip_address` when the event supplies identity or network context.
- `message`, containing normalized event-specific fields rather than relying exclusively on human-readable rendered text.

This separation is important for analysis because searching a rendered message is less reliable than querying structured event fields.

## Security Events

The Security log is the primary source for Windows auditing. The implementation gives particular treatment to authentication and audit-integrity events.

Event ID `4624` represents a successful logon. The Python and Java implementations use it as successful authentication evidence rather than treating the mere presence of a user name as proof of successful access.

Event ID `4625` represents a failed logon. The implementations associate failures with both an account and a source address where possible. This allows repeated failures from the same source against the same account to be distinguished from isolated authentication mistakes.

Event ID `4672` represents special privileges assigned to a new logon. It is modeled separately because privileged authentication context has different investigative significance from an ordinary successful logon.

Event ID `1102` is handled as an audit-integrity event. Clearing the Security log affects the availability of historical audit evidence, so the C++, Java, and SQL implementations treat it as materially different from an ordinary authentication failure.

Other security-sensitive IDs represented by the Python model include account creation and security-group membership changes.

## System Events

The System channel describes operating-system and service behavior rather than primarily representing identity decisions.

The examples use event ID `7045`, associated with service installation, because service creation can represent either legitimate administration or persistence activity.

The Python model identifies `7045` as a suspicious event candidate. The C++ and Java governance models elevate service installation to a critical finding because it represents a system-level change that deserves explicit investigation.

The classification is intentionally not equivalent to proof of compromise. A legitimate software deployment can install a service. The event becomes more meaningful when correlated with authentication, process, deployment, and administrative context.

## Application Events

Application events are kept separate from operating-system security events.

The SQL dataset includes application event ID `1001` for a representative application crash. It identifies the affected application through JSON event data while preserving the originating computer and service account.

This distinction prevents an application crash from being automatically interpreted as an authentication or operating-system security event. Application telemetry is often essential during incident investigation because a security event can precede an application failure, but the two observations represent different mechanisms.

The relational model therefore stores Application events in the same normalized event table while preserving `channel`, `provider`, `event_id`, and structured `event_data`.

## PowerShell Events

PowerShell produces operational telemetry that can provide valuable execution evidence.

The implementations distinguish PowerShell from ordinary Application and System events.

Important event IDs represented in the code include:

| Event ID | Meaning represented by the implementation |
|---|---|
| `400` | PowerShell engine started |
| `403` | PowerShell engine stopped |
| `4103` | Module logging |
| `4104` | Script-block logging |
| `4105` | Command started |
| `4106` | Command stopped |

Event ID `4104` receives particular attention because script-block logging can preserve the content of PowerShell script blocks.

The code deliberately does not classify every `4104` event as malicious. A recorded script block is telemetry. Its security meaning depends on the command, user, host, timing, privileges, surrounding authentication activity, and other evidence.

The JavaScript implementation exposes PowerShell telemetry through a dedicated reporting function. The SQL implementation stores PowerShell script-block data in `powershell_events`, allowing analysts to query execution evidence independently of unrelated event channels.

## Authentication Analysis

Authentication analysis combines multiple Security events rather than treating each event independently.

The Python implementation groups failed `4625` events by user and source IP. Its burst detector looks for a configurable number of failures within a configurable time window.

The JavaScript implementation uses the same evidence model but processes it through asynchronous Node.js collection and JavaScript `Map` and `Set` structures.

The C++ implementation models the detection engine using hash-based indexes. Authentication failures are grouped by the composite account/source key.

The Java implementation expresses authentication analysis as an `EventPolicy`. This makes the threshold an explicit domain rule rather than a hard-coded print statement.

The SQL implementation performs the grouping with a common table expression:

`GROUP BY username, source_ip`

This makes the database capable of identifying concentrated authentication failures without exporting every event to application code first.

The threshold is a detection policy, not a universal Windows security rule. A production environment must account for service accounts, scheduled tasks, shared NAT addresses, domain controllers, VPN gateways, and distributed authentication attacks.

## Relationship Between Authentication and Other Event Areas

Authentication evidence becomes substantially more useful when correlated with events from other channels.

A successful administrative logon can be followed by a service installation. A failed authentication burst can precede a successful logon. PowerShell script-block activity can appear after an interactive or remote logon. An application failure can occur after a system-level configuration change.

The implementation therefore preserves timestamps, computers, accounts, source addresses, channels, and event IDs.

The relationship is analytical rather than categorical:

`Authentication evidence → host activity → PowerShell activity → application/system consequences`

This does not mean that one event proves another event caused it. Temporal and contextual correlation provides investigative evidence that requires validation.

## Python Implementation

The Python program is the broadest operational implementation.

It uses `wevtutil.exe` on Windows to retrieve recent events in XML form. The command is invoked with `subprocess.run`, and the output is parsed using the standard-library XML parser.

The program can inspect the Security, System, Application, and PowerShell Operational channels. It can also process supplied event XML and provides deterministic sample records when live Windows access is unavailable.

The `EventRecord` dataclass provides a normalized representation. Properties such as `is_authentication`, `is_suspicious`, and `event_name` keep channel-specific interpretation close to the event model.

The authentication detector implements a sliding time-window calculation over failed logons. Validation checks identify missing authentication users, missing source addresses, invalid IDs, and timezone-free timestamps.

The JSON export preserves normalized event evidence without executing or interpreting event message content as commands.

A practical security decision in this implementation is to treat event data as evidence. Event messages and PowerShell script text are never executed by the Python program.

## JavaScript Implementation

The JavaScript program uses Node.js to demonstrate asynchronous Windows event collection.

Instead of translating the Python implementation line by line, it uses PowerShell's `Get-WinEvent` through `execFile`. `Promise.allSettled` allows Security, System, Application, and PowerShell collection to occur independently. If one channel cannot be accessed, the other successful collections remain available.

The JavaScript parser extracts XML fields into ordinary objects. `Map` and `Set` provide natural structures for authentication aggregation, unique source addresses, and event classification.

`powershellReport()` isolates PowerShell telemetry, while `detectBruteForce()` demonstrates time-window analysis using JavaScript `Date` values.

The use of `execFile` rather than constructing a shell command containing event data is deliberate. Event content must never become executable shell input.

## C++ Governance Case Study

The C++ program represents a security operations event-analysis engine.

`Event` is a strongly typed normalized record. `EventIndex` creates hash-based lookup structures by event ID, user, and source address.

`DetectionEngine` evaluates distinct rules:

- Repeated `4625` failures are grouped by account and source.
- `1102` is treated as critical because audit history was cleared.
- `7045` is treated as a critical system-change observation.
- `4104` is treated as informational PowerShell telemetry rather than automatic evidence of compromise.

`EventStore` performs input validation before an event becomes part of the evidence set. For example, a failed authentication without a source IP is rejected.

The indexes provide expected constant-time lookup for individual hash keys, while the primary detection pass remains linear in the number of normalized events.

This architecture separates storage, indexing, and policy evaluation. That separation is useful when additional event rules must be added without rewriting event ingestion.

## Java Enterprise Model

The Java implementation models Windows event analysis as an enterprise policy system.

`WindowsEvent` is an immutable record containing the core event attributes. Validation is performed in the record constructor, making invalid domain state difficult to create.

`Channel`, `Severity`, and `AuthenticationOutcome` are explicit enums. This is preferable to passing arbitrary strings through the policy engine because channel and authentication semantics become constrained domain values.

The `EventPolicy` interface defines a common policy boundary. Four concrete policies handle authentication concentration, audit-log integrity, service installation, and PowerShell script-block telemetry.

`GovernanceService` composes these policies and evaluates the same immutable event collection against each rule set.

This design is useful when enterprise environments have multiple independent detection policies. A policy can be added without changing the event representation or the existing policies.

## SQL Data Model

The PostgreSQL schema models the domain relationally.

`computers` stores Windows hosts and their environments. `users` stores normalized identities. `windows_events` is the central event table and retains the originating channel, provider, event ID, timestamp, source address, message, and JSONB event data.

`authentication_events` contains authentication-specific attributes such as outcome, logon type, authentication package, and status code.

`powershell_events` separates PowerShell-specific execution evidence from the general event table while retaining a foreign-key relationship to the original event.

`security_findings` records the result of analytical rules without replacing the original event evidence.

Foreign keys enforce relationships. Unique constraints prevent duplicate event records for the same computer, channel, and record ID. Check constraints enforce important data-quality rules.

The `4625` constraint requires a source address. Authentication events require an associated user. These rules move integrity enforcement into PostgreSQL instead of relying entirely on application code.

## Database Query Strategy

The SQL indexes reflect common investigative access patterns.

The timestamp index supports recent-event investigation. The `(channel, event_id, event_time)` index supports queries such as recent Security `4625` or System `7045` activity.

The partial authentication index focuses storage and lookup on authentication-related event IDs. The source-IP index supports investigation of repeated activity from the same network origin.

The SQL common table expression aggregates failed authentication events by account and source. The query then classifies concentrated activity as `Investigate`.

PowerShell script blocks are queried through their dedicated table so analysts can retrieve execution evidence without scanning unrelated Application or System records.

The cross-channel query reconstructs a chronological operational view across Security, System, Application, and PowerShell events.

## Integrity and Failure Conditions

Event data is evidence and should not be silently corrected.

The Python validator reports malformed records. The C++ store rejects invalid events through exceptions. The Java record constructor prevents invalid domain objects. PostgreSQL check constraints reject invalid database states.

Authentication failures without source addresses are particularly important because a source-less record weakens correlation. The SQL schema therefore rejects such records for event ID `4625`.

The SQL transaction demonstrates atomic finding creation. The original event remains preserved while a separate finding records the detection decision and supporting evidence.

A failed detection rule should not erase or rewrite the original event. Detection output is derived information and must remain distinguishable from source telemetry.

## Event Retention and Audit Integrity

Event retention directly affects investigation quality.

A cleared Security log is not merely another event in the timeline. It represents a change to the evidence available for historical investigation.

The implementation therefore identifies event ID `1102` separately and records it in the SQL finding table.

Production environments should also consider centralized collection because a local attacker who gains sufficient privileges may be able to affect local logs. Centralized forwarding, controlled retention, time synchronization, access control, and protected storage improve the reliability of historical event evidence.

The programs do not attempt to treat a local event log as an immutable security archive.

## Common Analytical Mistakes

Treating every Security event as malicious creates excessive false positives. Authentication failures can result from expired credentials, mapped drives, scheduled tasks, service configuration, or user mistakes.

Treating every PowerShell `4104` event as malicious is also incorrect. Script-block logging records execution telemetry; interpretation requires context.

Treating event IDs as sufficient evidence ignores the provider, timestamp, computer, account, source address, event data, and surrounding activity.

Searching only human-readable messages can lose structured fields such as `TargetUserName`, `IpAddress`, `LogonType`, and status values.

Combining Application, System, Security, and PowerShell events into one undifferentiated category removes important semantic distinctions.

## Performance Considerations

Large Windows logs require filtering as early as practical.

The Python live collector uses `wevtutil` count and XPath capabilities so the operating system can restrict collection before all available events are transferred into Python.

The Node.js implementation requests bounded event counts and performs independent collection per channel.

The C++ implementation builds hash indexes to make repeated lookups efficient.

The PostgreSQL schema indexes event time, channel and event ID, source IP, and authentication-related records.

For enterprise-scale telemetry, the central challenge is not merely parsing events. It is controlling ingestion volume, retention, indexing cost, query latency, storage growth, and the amount of raw event data retained for investigation.

## Security Considerations

Event content must be treated as untrusted data.

A message containing PowerShell or command-line text must never automatically be executed. The JavaScript implementation uses `execFile` for the collector and does not interpolate event content into executable commands.

Access to Security logs should be restricted because event records can contain sensitive account and host information.

Source addresses, usernames, script-block text, and application messages can contain sensitive operational data. Access control and retention policies should therefore apply to normalized event stores as well as the original Windows logs.

Detection findings should retain evidence references rather than replacing raw telemetry. This supports later investigation and reduces the risk that a detection rule obscures the underlying observation.

## Production Considerations

A production monitoring architecture should preserve the originating computer, provider, channel, event ID, record ID, timestamp, and structured event fields.

Time synchronization is essential for correlation. A difference between host clocks can make an otherwise correct sequence appear out of order.

Authentication analysis should distinguish user accounts, service accounts, machine accounts, domain controllers, VPN sources, and shared network addresses.

PowerShell analysis should consider script-block content together with account privileges, parent process context, command execution timing, and host role.

Application and System failures should be correlated with security activity without being automatically interpreted as security incidents.

The central design principle across the implementations is preservation of event semantics: Security records represent auditing evidence, System records represent operating-system behavior, Application records represent software behavior, PowerShell records provide execution telemetry, and authentication events represent identity-related activity that can be correlated across the broader Windows event stream.
