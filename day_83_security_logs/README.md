# Security Logs: Multi-Source Monitoring, Correlation and Threat Detection

## 1. Technical Scope

Security logs provide records of activities performed by users, systems, applications, and network infrastructure. They establish an observable history of authentication, authorization, process execution, network communication, resource access, and application behavior.

This project implements a multi-source security log analytics platform using Python, JavaScript, C++17, Java 17, and PostgreSQL.

The platform demonstrates how heterogeneous telemetry can be normalized, correlated, evaluated against detection rules, and converted into actionable security findings.

The supported telemetry categories are:

| Source | Principal information | Security purpose |
|---|---|---|
| Windows | Event IDs, account activity, process execution, privilege assignments | Endpoint security monitoring |
| Linux | SSH authentication, system activity, service messages | Server and account monitoring |
| Firewall | Source IP, destination IP, ports, protocols, allow and deny decisions | Network security monitoring |
| DNS | Domain queries, record types, requesting hosts | Domain abuse and tunneling detection |
| Proxy | URLs, HTTP requests, users, download activity | Web traffic inspection |
| Authentication | Login successes, failures, identity information | Account compromise detection |
| Application | Application errors, resource access, security events | Application-level threat monitoring |

The implementation uses structured telemetry records. It does not require access to an actual Windows Event Log service, Linux journal, firewall appliance, DNS resolver, or enterprise proxy.

The supplied examples simulate normalized telemetry from these systems.

## 2. Security Log Architecture

The platform follows a processing architecture that separates ingestion, normalization, storage, detection, correlation, and incident management.

    Windows Event Logs ─────┐
    Linux System Logs ──────┤
    Firewall Logs ─────────┤
    DNS Logs ──────────────┤
    Proxy Logs ────────────┼──> Event Ingestion
    Authentication Logs ──┤
    Application Logs ─────┘
                                  |
                                  v
                          Event Validation
                                  |
                                  v
                          Event Normalization
                                  |
                                  v
                         Structured Event Store
                                  |
                                  v
                         Detection Rule Engine
                                  |
                                  v
                         Cross-Source Correlation
                                  |
                                  v
                         Risk Classification
                                  |
                                  v
                          Security Findings
                                  |
                                  v
                          Incident Management
                                  |
                                  v
                         Security Reporting

### 2.1 Event ingestion

Ingestion receives records from different systems.

Each source can use a different event format, timestamp representation, field naming convention, and severity classification.

For example:

- Windows identifies authentication events using event identifiers.
- Linux SSH records describe authentication outcomes in textual messages.
- Firewalls record network decisions using connection and packet metadata.
- DNS servers record domain-resolution requests.
- Proxies record requested URLs, HTTP methods, and user identities.
- Applications produce application-specific audit and error events.

Ingestion must distinguish event time from ingestion time.

**Event time** represents when an activity occurred.

**Ingestion time** represents when the monitoring platform received the record.

The distinction is important because network delays, disconnected endpoints, buffered logs, and forwarding failures can cause events to arrive late.

### 2.2 Event normalization

Normalization converts different source formats into a consistent event structure.

The five implementations use a common conceptual representation:

| Field | Purpose |
|---|---|
| Event ID | Unique event identifier |
| Timestamp | Time of the original activity |
| Source | Originating telemetry category |
| Event type | Standardized activity classification |
| Source IP | Originating network address |
| Destination IP | Target network address |
| Username | Associated identity |
| Hostname | Originating or affected system |
| Destination port | Network service endpoint |
| Protocol | TCP, UDP, or another protocol |
| Resource | URL, file, or accessed resource |
| Attributes | Source-specific structured metadata |
| Message | Original event description |

Normalization should preserve source-specific evidence rather than discard it.

The `attributes` structure provides a mechanism for retaining information that does not fit the common event fields.

### 2.3 Event validation

Invalid records should not enter the detection pipeline.

The implementations validate:

- Required identifiers.
- Timestamp format.
- Timestamp timezone information where applicable.
- Source and event classifications.
- IP address syntax.
- Destination port ranges.
- Structured attribute types.
- Message and resource length.
- Duplicate event identifiers.

Rejected events should be recorded separately from valid security findings.

An invalid record is a data-quality problem. It is not automatically evidence of an attack.

## 3. Windows Security Logs

Windows security auditing records authentication, account management, privilege assignment, and process-related activities.

The Python implementation provides a Windows event normalizer using representative Windows Security Event IDs.

| Event ID | Activity | Security relevance |
|---|---|---|
| 4624 | Successful logon | Account access |
| 4625 | Failed logon | Authentication attacks |
| 4672 | Special privileges assigned | Privileged account activity |
| 4688 | New process created | Process execution monitoring |

### 3.1 Authentication monitoring

Event 4624 indicates successful authentication, while Event 4625 records failed authentication.

A successful authentication is not necessarily legitimate. An attacker using stolen credentials can generate a successful logon event.

A failed authentication is not necessarily malicious. Incorrect passwords, expired credentials, and misconfigured services can also produce failures.

Detection requires contextual correlation.

Relevant attributes include:

- Account name.
- Source address.
- Destination computer.
- Logon type.
- Authentication mechanism.
- Event timestamp.
- Historical account behavior.

### 3.2 Privileged activity

Event 4672 identifies assignments of special privileges to a new logon session.

Such events deserve attention because privileged accounts can access sensitive system resources.

Monitoring should establish whether:

- The account is expected to receive privileges.
- The activity occurred during an authorized administrative session.
- The source system is recognized.
- The activity is consistent with the account's normal behavior.

Event 4688 provides process creation information. Process monitoring becomes more useful when combined with command-line auditing, parent process information, file reputation, and endpoint telemetry.

The demonstration normalizer does not implement a complete Windows Event Log collector or all Windows event schemas.

## 4. Linux Security Logs

Linux security telemetry commonly comes from:

- SSH authentication messages.
- System authentication logs.
- Systemd journal records.
- Audit subsystem events.
- Kernel messages.
- Service logs.
- Application audit records.

### 4.1 SSH authentication

The Python implementation recognizes representative SSH messages.

| Message pattern | Normalized event |
|---|---|
| Failed password | `login_failure` |
| Authentication failure | `login_failure` |
| Accepted password | `login_success` |
| Accepted publickey | `login_success` |

A normalized event retains the username, source IP, hostname, service, and timestamp.

This makes Linux authentication events comparable with Windows authentication telemetry.

### 4.2 Linux audit activity

Authentication logs alone cannot provide complete endpoint visibility.

Additional audit records can reveal:

- User and group changes.
- Privilege escalation.
- File permission modifications.
- Sensitive file access.
- Process execution.
- Service modifications.
- Administrative command execution.

A production implementation should use structured journal or audit records where available rather than relying exclusively on regular-expression parsing of human-readable messages.

## 5. Firewall Security Logs

Firewall telemetry records network traffic decisions and connection activity.

The principal fields include:

- Source address.
- Destination address.
- Source and destination ports.
- Transport protocol.
- Allow or deny decision.
- Connection state.
- Interface.
- Rule identifier.
- Timestamp.

### 5.1 Allow and deny events

A firewall allow event indicates that a particular traffic decision was permitted.

A deny event indicates that a firewall rule prevented the corresponding traffic.

Neither event independently proves malicious activity.

For example, repeated denied connections may indicate:

- Port scanning.
- Misconfigured applications.
- Unauthorized service discovery.
- Internet background noise.
- A legitimate vulnerability assessment.

The detection engine correlates network connection records to identify unusual activity.

### 5.2 Port scanning

Port scanning involves probing multiple network ports to identify available services.

The implemented detection rule groups network connection events by source IP and evaluates the number of distinct destination ports within a configured time window.

The default policy is:

| Parameter | Value |
|---|---:|
| Observation window | 300 seconds |
| Unique destination port threshold | 10 |
| Severity | HIGH |
| Confidence | 0.90 |

A source contacting ten different destination ports within five minutes satisfies the demonstration rule.

The rule detects horizontal or vertical probing patterns depending on how destination hosts are grouped.

The supplied implementation primarily evaluates distinct destination ports per source. It does not implement complete multi-host scanning detection.

### 5.3 Firewall correlation

Firewall records become more valuable when correlated with:

- Authentication failures.
- Endpoint process execution.
- DNS queries.
- Proxy requests.
- Application errors.

A firewall connection following a suspicious process execution can provide stronger evidence than either event alone.

## 6. DNS Security Logs

DNS telemetry records domain-name resolution activity.

A DNS event commonly includes:

| Field | Description |
|---|---|
| Client address | Requesting device |
| Query name | Requested domain |
| Record type | A, AAAA, MX, TXT, and other record types |
| Response code | Resolution outcome |
| Resolver | DNS server |
| Response address | Resolved IP address |
| Timestamp | Query time |

### 6.1 DNS tunneling indicators

DNS tunneling can encode information within DNS query names or responses.

Suspicious indicators can include:

- Unusually long DNS labels.
- High-entropy subdomains.
- Large volumes of unique queries.
- Repeated TXT queries.
- Unusual query patterns.
- High-frequency requests to uncommon domains.

The implementations calculate Shannon entropy for DNS labels.

The mathematical expression is:

\[
H(X)=-\sum_{i=1}^{n}p(x_i)\log_2 p(x_i)
\]

Where:

- \(X\) represents the characters in a label.
- \(p(x_i)\) represents the frequency of character \(i\).
- \(H(X)\) represents the character-distribution entropy.

A high-entropy label can indicate encoded content, although legitimate tracking identifiers and generated application names can also exhibit high entropy.

The implemented rule identifies:

- Labels reaching the configured length threshold.
- Longer labels with sufficiently high character entropy.

This is an anomaly indicator rather than proof of DNS tunneling.

## 7. Proxy Security Logs

Proxy logs provide visibility into web requests made by users and systems.

Common fields include:

- Requesting IP.
- Username.
- Requested URL.
- HTTP method.
- HTTP response status.
- User agent.
- Request duration.
- Content type.
- Transferred bytes.
- Proxy decision.

### 7.1 Suspicious downloads

The implementations identify selected executable file extensions:

| Extension | File category |
|---|---|
| `.exe` | Windows executable |
| `.dll` | Dynamic-link library |
| `.ps1` | PowerShell script |
| `.bat` | Batch script |
| `.scr` | Windows screen saver executable |
| `.vbs` | Visual Basic script |

The rule detects requests whose URL paths end with these extensions.

It removes query-string information before extension evaluation.

A matching request is assigned a medium-severity finding.

This rule does not establish that a file is malicious. It identifies an activity that may require inspection.

A production proxy analytics engine should also inspect:

- Download hashes.
- MIME types.
- File sizes.
- Reputation intelligence.
- HTTP response codes.
- Redirect chains.
- Content disposition.
- User and device context.

## 8. Authentication Security and Brute-Force Detection

Authentication telemetry is central to identifying unauthorized account access.

A brute-force attack repeatedly attempts different credentials against an account or authentication endpoint.

A password-spraying attack attempts a small number of passwords across many accounts.

Credential stuffing uses previously compromised credentials against other services.

These attack patterns are related but should not be treated as identical.

### 8.1 Brute-force detection

The demonstration engine groups failed authentication events using:

\[
G=(SourceIP,Username)
\]

For each group, it evaluates the number of failures in a sliding time window.

The default policy is:

| Parameter | Value |
|---|---:|
| Failed attempts | 5 |
| Time window | 5 minutes |
| Severity | HIGH |
| Confidence | 0.95 |

The detection condition is:

\[
Count(Failures_{G,W}) \geq Threshold
\]

Where:

- \(G\) is the source and username group.
- \(W\) is the observation window.
- `Threshold` is the configured failure count.

The Python implementation uses timestamp-based filtering.

The JavaScript and Java implementations use sliding-window processing.

The C++ implementation uses sorted events and a two-pointer window.

The PostgreSQL implementation uses grouped aggregation over a configured time range.

### 8.2 Password spraying and distributed attacks

Grouping exclusively by source IP and username may miss distributed attacks.

For example, an attacker may use several IP addresses to target one account.

Another attacker may use one IP to target many accounts.

A more advanced detection system should evaluate:

- Failures per account.
- Failures per source IP.
- Unique accounts per source.
- Unique source addresses per account.
- Authentication failures followed by success.
- Unusual geographic or device context.
- Service-account authentication patterns.

## 9. Application Security Telemetry

Application telemetry provides visibility beyond operating-system and network activity.

Important application events include:

- Authentication and authorization failures.
- Administrative operations.
- Sensitive resource access.
- API request anomalies.
- Session creation and termination.
- Input-validation failures.
- Application exceptions.
- Configuration modifications.
- Unexpected service behavior.

### 9.1 Application errors

An application error may indicate a normal software failure, a configuration issue, or an attempted attack.

Examples include:

- Repeated authorization failures.
- Unexpected database errors.
- Unusual API request volumes.
- Access to restricted endpoints.
- Repeated invalid session tokens.

An application error should be correlated with the request identity, session, endpoint, and relevant infrastructure events.

### 9.2 Audit logging

Security audit records should capture meaningful activity without unnecessarily recording sensitive data.

Avoid storing:

- Passwords.
- Authentication tokens.
- Session secrets.
- Private keys.
- Full payment credentials.
- Unnecessary personal information.

Sensitive values should be removed, masked, or replaced with appropriately protected identifiers before ingestion.

## 10. Cross-Source Correlation

Individual events often provide incomplete evidence.

Correlation connects activities across different sources to identify broader security patterns.

Consider the following scenario:

| Time | Source | Event |
|---|---|---|
| 10:00 | Windows | Failed account authentication |
| 10:01 | Linux | Failed SSH authentication |
| 10:02 | Firewall | Multiple outbound connection attempts |
| 10:03 | DNS | Unusual domain query |
| 10:04 | Proxy | Executable download request |
| 10:05 | Application | Authorization failure |

The events may represent independent operational problems or a coordinated attack.

A correlation engine should evaluate:

1. Temporal proximity.
2. Shared source addresses.
3. Shared usernames.
4. Common destination systems.
5. Event sequence.
6. Historical activity.
7. Relevant detection-rule outcomes.

The PostgreSQL implementation demonstrates a CTE-based correlation query that combines authentication failures and network connection patterns.

The query classifies sources into:

- `HIGH_CORRELATION`
- `AUTHENTICATION_ANOMALY`
- `NETWORK_ANOMALY`
- `NORMAL`

These classifications are illustrative. A production system should use configurable correlation windows, event provenance, and stronger identity resolution.

## 11. Detection Rules and Risk Scoring

The detection engine separates security observations from their risk classification.

A detection rule defines:

- Rule identifier.
- Rule name.
- Description.
- Severity.
- Confidence.
- Threshold.
- Observation window.
- Enabled or disabled state.

### 11.1 Severity levels

| Severity | Weight | Interpretation |
|---|---:|---|
| INFO | 0 | Informational activity |
| LOW | 10 | Minor anomaly |
| MEDIUM | 25 | Activity requiring inspection |
| HIGH | 45 | Significant security concern |
| CRITICAL | 70 | Potentially severe security incident |

### 11.2 Risk calculation

The demonstration uses:

\[
Risk=\min(100,SeverityWeight\times Confidence)
\]

For example, a high-severity finding with confidence 0.95 receives:

\[
45 \times 0.95=42.75
\]

The rounded risk score is 43.

This is a demonstration scoring mechanism, not a standardized security-risk measurement.

A production model should account for asset criticality, exposure, exploitability, business impact, threat intelligence, and the possibility of false positives.

Severity, confidence, and risk are separate concepts.

- Severity describes the potential importance of a finding.
- Confidence describes the strength of the evidence supporting the detection.
- Risk score provides a simplified prioritization value.

## 12. Incident Management

A security finding is not automatically a confirmed incident.

A finding is the output of a detection rule.

An incident represents an investigation or response workflow associated with one or more findings.

The Java and PostgreSQL implementations model explicit incident states.

    OPEN
      |
      v
    INVESTIGATING
      |
      +------> CONTAINED
      |           |
      |           v
      |       RESOLVED
      |
      +------> RESOLVED
                  |
                  v
                CLOSED

The implemented transitions are:

| Current state | Permitted next states |
|---|---|
| OPEN | INVESTIGATING, CLOSED |
| INVESTIGATING | CONTAINED, RESOLVED |
| CONTAINED | INVESTIGATING, RESOLVED |
| RESOLVED | CLOSED, INVESTIGATING |
| CLOSED | None |

Invalid transitions are rejected.

The Java implementation maintains an in-memory transition history.

The PostgreSQL implementation records transition history through a database trigger.

A production incident-management workflow should also include:

- Assignment and ownership.
- Analyst notes.
- Evidence preservation.
- Investigation timestamps.
- Containment actions.
- Escalation records.
- Resolution justification.
- Closure authorization.
- Audit history.

## 13. Python Implementation

**File:** `security_logs.py`

The Python implementation provides a modular security analytics pipeline.

### 13.1 Domain model

The implementation uses:

- `LogSource` for telemetry source classification.
- `EventType` for activity classification.
- `Severity` for finding severity.
- `SecurityEvent` for normalized telemetry.
- `Finding` for detection results.

Dataclasses provide structured event representation.

Enums restrict classification values.

### 13.2 Normalization

`EventNormalizer` contains source-specific conversion methods.

The Windows normalizer maps representative event identifiers to standardized event types.

The Linux normalizer recognizes representative SSH authentication messages.

The general `normalize_event()` function performs common validation.

### 13.3 Detection

`DetectionEngine` implements:

- `detect_brute_force()`
- `detect_port_scanning()`
- `detect_dns_anomalies()`
- `detect_suspicious_proxy_activity()`
- `detect_privilege_changes()`

Each detector returns structured findings.

### 13.4 Reporting

`SecurityReport` generates JSON-compatible output containing:

- Processed event count.
- Finding count.
- Source distribution.
- Severity distribution.
- Individual findings.
- Risk scores.
- Evidence.

### 13.5 Execution

Run the demonstration:

`python security_logs.py`

Run built-in assertions:

`python security_logs.py --test`

Process an existing JSONL file:

`python security_logs.py --input events.jsonl --output security_report.json`

Each JSONL line must represent one normalized event.

Invalid records are rejected and logged.

The script uses only the Python standard library.

## 14. JavaScript Implementation

**File:** `security_logs.js`

The JavaScript implementation focuses on asynchronous event-driven telemetry processing.

### 14.1 Event-driven architecture

`SecurityTelemetryService` extends Node.js `EventEmitter`.

It publishes:

- `event` when telemetry is accepted.
- `alert` when a new finding is emitted.
- `rejected` when an event fails validation.

This structure separates event ingestion from downstream consumers.

A reporting service, notification service, or incident-management component can subscribe to these events.

### 14.2 Sliding windows

`SlidingWindow` retains events within a configured time range.

It supports:

- Event insertion.
- Expiration of old events.
- Predicate-based retrieval.
- Maximum event retention.

The bounded collection reduces memory growth in long-running processes.

### 14.3 Alert deduplication

`AlertDeduplicator` prevents repeated alerts for the same rule and entity during a cooldown period.

The deduplication key is:

`ruleId:entity`

This reduces repeated notifications without removing the original evidence.

### 14.4 Policy evaluation

`SecurityPolicy` independently evaluates authentication, network, DNS, proxy, and privilege-related activity.

`ingestBatch()` processes multiple records and isolates individual failures.

One invalid event does not prevent other records in the batch from being processed.

### 14.5 Execution

Run:

`node security_logs.js`

Run tests:

`node security_logs.js --test`

Process JSONL telemetry:

`node security_logs.js --input events.jsonl`

The implementation uses Node.js built-in modules and does not require npm dependencies.

## 15. C++17 Implementation

**File:** `security_logs.cpp`

The C++ implementation focuses on typed domain modeling, validation, efficient containers, and a deterministic detection engine.

### 15.1 Domain types

The program defines:

- `LogSource`
- `EventType`
- `Severity`
- `SecurityEvent`
- `DetectionPolicy`
- `SecurityFinding`

Strongly typed enums prevent arbitrary classification values.

### 15.2 Event repository

`EventRepository` stores events in a vector and tracks identifiers in an unordered set.

This provides:

- Sequential event storage.
- Duplicate detection.
- Efficient average-case identifier lookup.

The duplicate check has average-case constant-time complexity.

### 15.3 Detection algorithms

The brute-force and port-scan detectors group events and sort them by timestamp.

They then use a two-pointer sliding-window algorithm.

For \(n\) events:

- Sorting requires \(O(n\log n)\) time.
- Window traversal requires \(O(n)\) time after sorting.
- Grouping requires storage proportional to the number of events.

The DNS detector calculates character entropy using frequency maps.

### 15.4 Reporting

`SecurityReporter` produces:

- Source counts.
- Finding counts.
- Severity distribution.
- Entity information.
- Evidence.
- Risk scores.

### 15.5 Execution

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic security_logs.cpp -o security_logs`

Run:

`./security_logs`

Run assertions:

`./security_logs --test`

The implementation uses only the C++17 standard library.

The sample program uses deterministic timestamps and illustrative IPv4 addresses.

## 16. Java 17 Implementation

**File:** `SecurityLogs.java`

The Java implementation focuses on enterprise domain modeling and controlled state management.

### 16.1 Immutable domain types

Java records represent:

- `SecurityEvent`
- `DetectionRule`
- `SecurityFinding`
- `DetectionPolicy`

Immutable event structures prevent downstream processing components from modifying original telemetry accidentally.

### 16.2 Event storage

`EventStore` maintains a map indexed by event ID.

The synchronized insertion method prevents concurrent duplicate insertion through the same store instance.

The snapshot method returns an immutable collection view.

### 16.3 Detection service

`DetectionService` implements independent detection methods and a configurable policy.

The service separates detection rules from event persistence.

The detection methods produce immutable finding records.

### 16.4 Alert management

`AlertRegistry` maintains a cooldown period for each rule and entity combination.

This prevents repeated alert generation for an unchanged condition.

### 16.5 Incident state management

`Incident` enforces explicit state transitions.

Illegal transitions raise an `IllegalStateException`.

The transition history provides a basic audit trail.

### 16.6 Execution

Compile:

`javac SecurityLogs.java`

Run:

`java SecurityLogs`

Run tests:

`java SecurityLogs --test`

The implementation uses Java 17 standard-library features without third-party dependencies.

## 17. PostgreSQL Implementation

**File:** `security_logs.sql`

The PostgreSQL implementation models persistent security telemetry and its associated operational workflow.

### 17.1 Relational structure

The principal entities are:

| Table | Responsibility |
|---|---|
| `organizations` | Organizational ownership |
| `telemetry_sources` | Registered log-producing systems |
| `security_events` | Normalized security telemetry |
| `detection_rules` | Detection configuration |
| `security_findings` | Rule-generated findings |
| `finding_events` | Evidence-to-finding relationships |
| `security_incidents` | Investigation records |
| `incident_history` | Incident state transitions |

The main relationships are:

    organizations
        |
        +---- telemetry_sources
        |          |
        |          +---- security_events
        |                       |
        |                       +---- finding_events
        |                                  |
        +---- security_findings -----------+
                     |
                     +---- detection_rules
                     |
                     +---- security_incidents
                                  |
                                  +---- incident_history

### 17.2 Referential integrity

Foreign keys ensure that:

- Telemetry sources belong to existing organizations.
- Events reference valid telemetry sources.
- Findings reference valid detection rules.
- Findings reference valid organizations.
- Finding evidence references valid events.
- Incidents reference existing findings.
- Incident history references existing incidents.

Unique constraints prevent duplicate external event identifiers from the same telemetry source.

Check constraints enforce valid port ranges, confidence values, and risk scores.

### 17.3 JSONB

The `attributes` column uses PostgreSQL JSONB.

This is useful for source-specific telemetry that does not fit a universal relational schema.

Examples include:

- Windows event identifiers.
- Linux service names.
- DNS record types.
- Authentication methods.
- Proxy request metadata.
- Application-specific audit attributes.

A GIN index supports queries against JSONB data.

### 17.4 Detection functions

The database implements:

- `detect_brute_force()`
- `detect_port_scans()`
- `detect_dns_anomalies()`
- `calculate_risk_score()`

These functions evaluate stored events and return detection results.

### 17.5 Detection processing

`process_security_detections()` coordinates detection rules and creates findings.

It also establishes relationships between findings and supporting events where implemented.

The procedure uses the configured rules rather than embedding all thresholds in reporting queries.

### 17.6 Database triggers

Two important trigger mechanisms are included.

**Event validation trigger**

`validate_security_event()` verifies that the telemetry source exists, is active, and belongs to the event's organization.

It also updates the source's last-seen timestamp.

**Incident transition trigger**

`enforce_incident_transition()` restricts invalid incident state changes and records valid transitions in `incident_history`.

### 17.7 Indexing

The SQL script creates indexes for common investigation queries.

| Index | Query purpose |
|---|---|
| Organization and timestamp | Organizational event timelines |
| Event type and timestamp | Activity-specific searches |
| Source IP and timestamp | Network investigations |
| Username and timestamp | Identity investigations |
| Destination port and timestamp | Port scanning investigations |
| JSONB GIN | Structured attribute searches |
| Finding risk | Alert prioritization |
| Incident status | Operational incident reporting |

Indexes improve retrieval performance but introduce storage and write-maintenance overhead.

### 17.8 Reporting

The SQL script includes queries for:

- Telemetry source distribution.
- Authentication failures.
- Firewall activity.
- DNS query distribution.
- Suspicious proxy downloads.
- Findings by severity.
- High-risk entities.
- Incident status.
- Cross-source correlation.
- Organizational dashboards.
- Data ingestion delays.
- Retention eligibility.

The final retention query identifies records eligible for archival. It deliberately does not delete records.

## 18. Detection Rule Reference

The five implementations share the following principal detection concepts.

| Rule | Detection | Main evidence | Severity |
|---|---|---|---|
| AUTH-001 | Brute-force activity | Repeated failed authentication | HIGH |
| AUTH-002 | Privilege change | Elevated account privileges | MEDIUM |
| NET-001 | Port scanning | Distinct destination ports | HIGH |
| DNS-001 | DNS anomaly | Long or high-entropy labels | MEDIUM |
| PROXY-001 | Executable download | Suspicious URL extension | MEDIUM |

Thresholds are configurable in the respective implementations.

A finding is generated when the configured detection condition is satisfied.

The existence of a finding does not establish malicious intent.

## 19. Security and Reliability Considerations

### 19.1 Log integrity

Security logs are evidence.

A production system should protect them against unauthorized modification and deletion.

Recommended architectural controls include:

- Restricted write permissions.
- Separate ingestion and investigation privileges.
- Immutable archival storage.
- Cryptographic integrity verification.
- Trusted timestamping.
- Audited administrative operations.
- Protected backups.

### 19.2 Authentication and authorization

Access to telemetry should follow least-privilege principles.

Different roles should have separate permissions.

| Role | Typical responsibility |
|---|---|
| Ingestion service | Submit telemetry |
| Security analyst | Investigate findings |
| Security administrator | Manage detection policies |
| Auditor | Review access and evidence |
| Database administrator | Maintain database infrastructure |

The demonstration database models data ownership and integrity, not a complete production authorization system.

Production deployment should add appropriate PostgreSQL roles, grants, row-level security where required, and controlled service credentials.

### 19.3 Sensitive information

Log records can contain personal identifiers, IP addresses, authentication metadata, and sensitive resource names.

Security controls should include:

- Data minimization.
- Masking of sensitive values.
- Encryption in transit.
- Encryption at rest.
- Access auditing.
- Defined retention periods.
- Secure deletion and archival policies.

Credentials and authentication secrets must never be recorded in plaintext.

### 19.4 Timestamp reliability

Systems should use synchronized clocks.

Time-zone conversion should occur during normalization.

UTC provides a consistent representation for cross-system correlation.

Late-arriving events should not be discarded solely because they arrived after the event time.

### 19.5 Duplicate records

Duplicate ingestion can result from:

- Forwarder retries.
- Network interruptions.
- Replayed batches.
- Collector restarts.
- Overlapping collection windows.

The implementations use event identifiers to prevent duplicate processing.

Production collectors should also consider idempotent ingestion, source sequence numbers, and persistent checkpoints.

### 19.6 False positives

Detection rules are indicators rather than definitive attack classifications.

Potential false positives include:

- Password resets.
- Administrative port scans.
- Legitimate software downloads.
- Generated DNS labels.
- Automated service authentication.
- Authorized penetration testing.

Analysts should evaluate asset context, user behavior, historical activity, and supporting evidence.

### 19.7 Resource consumption

Security telemetry can grow rapidly.

Production systems should consider:

- Event batching.
- Asynchronous ingestion.
- Bounded memory.
- Backpressure.
- Partitioned database tables.
- Retention policies.
- Index maintenance.
- Query execution plans.
- Detection-rule scheduling.
- Archival storage.

The Python implementation stores events in memory.

The JavaScript implementation uses bounded event windows but retains event identifiers for the lifetime of the process.

The C++ implementation uses in-memory collections.

The Java implementation uses in-memory maps and lists.

PostgreSQL provides persistent relational storage.

None of the implementations should be interpreted as a complete distributed Security Information and Event Management platform.

## 20. Limitations and Engineering Trade-offs

| Area | Current implementation | Production consideration |
|---|---|---|
| Collection | Normalized sample records | Native collectors and secure forwarding |
| Parsing | Representative Windows and Linux normalization | Complete source-specific parsers |
| Detection | Threshold-based rules | Behavioral and contextual analytics |
| Correlation | IP, account, and timestamp relationships | Identity resolution and distributed correlation |
| DNS analysis | Length and entropy indicators | Query-volume and response analysis |
| Proxy analysis | Executable URL extensions | Content inspection and file reputation |
| Storage | In-memory collections and PostgreSQL | Partitioning and scalable event storage |
| Alerting | Console output and event emission | Durable alert queues and notifications |
| Incidents | Basic state transitions | Full investigation and response workflow |
| Security | Validation and data-model constraints | Production IAM, encryption, and audit controls |

The detection algorithms intentionally favor interpretability over complex statistical models.

The same detection concept is implemented differently across languages to demonstrate distinct engineering approaches.

Python emphasizes modular data processing.

JavaScript emphasizes event-driven execution and asynchronous integration.

C++ emphasizes typed structures and efficient in-memory processing.

Java emphasizes enterprise domain modeling and controlled state transitions.

PostgreSQL emphasizes relational integrity, persistent evidence, database-side processing, and reporting.

## 21. Execution and Verification Matrix

| Deliverable | Runtime | Execution | Validation |
|---|---|---|---|
| Python | Python 3.10+ | `python security_logs.py` | `python security_logs.py --test` |
| JavaScript | Node.js 18+ | `node security_logs.js` | `node security_logs.js --test` |
| C++17 | C++17 compiler | `./security_logs` | `./security_logs --test` |
| Java | Java 17 | `java SecurityLogs` | `java SecurityLogs --test` |
| PostgreSQL | PostgreSQL 15+ | `psql -U postgres -d security_database -f security_logs.sql` | Database validation block and reporting queries |

The PostgreSQL script creates the `security_logs` schema, its relational objects, sample telemetry, detection rules, findings, incidents, and reporting mechanisms.

It drops an existing schema with the same name before initialization. Existing data in that schema is therefore destroyed when the script is rerun.

## 22. Educational and Technical Outcomes

The implementations demonstrate the relationship between heterogeneous security telemetry and operational threat detection.

The principal technical concepts are:

1. Source-specific event normalization.
2. Structured security event modeling.
3. Input validation and duplicate prevention.
4. Timestamp-based event correlation.
5. Sliding-window detection algorithms.
6. Authentication abuse monitoring.
7. Firewall and network anomaly detection.
8. DNS entropy analysis.
9. Proxy download monitoring.
10. Application and endpoint telemetry.
11. Severity and confidence-based risk classification.
12. Alert deduplication.
13. Incident state management.
14. Relational database integrity.
15. Database triggers and reporting.
16. Security evidence preservation.
17. Operational monitoring and retention.

The resulting architecture establishes a foundation for understanding how Windows, Linux, firewall, DNS, proxy, authentication, and application logs can be integrated into a common security monitoring and investigation workflow.
