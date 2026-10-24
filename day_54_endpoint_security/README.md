# Endpoint Security: Detection, Telemetry, and Incident Response

## Purpose

This project models endpoint security as a sequence of evidence collection, detection, correlation, incident creation, and response decisions. It distinguishes four complementary mechanisms:

- **Antivirus:** identifies known or classified malicious files and records quarantine outcomes.
- **Endpoint Detection and Response (EDR):** collects endpoint activity and correlates process execution, credential access, and network behavior.
- **Host-based Intrusion Detection System (HIDS):** identifies suspicious changes to protected host resources.
- **Behavioral detection:** identifies activity patterns that are suspicious even when individual events are not conclusive.

The implementations use synthetic telemetry. They do not install endpoint agents, scan the operating system, communicate with security products, or isolate real devices.

## Security Architecture

The core workflow is:

    Endpoint activity
          |
          v
    Telemetry collection
          |
          v
    Event validation and deduplication
          |
          v
    Antivirus / EDR / HIDS / behavioral detection
          |
          v
    Event correlation and severity assessment
          |
          v
    Incident creation and evidence association
          |
          v
    Triage -> Containment -> Investigation -> Resolution
          |
          v
    Reporting and audit records

The workflow separates observations from conclusions. A telemetry event records something observed by a sensor. A detection rule interprets that observation. Correlation combines related observations. An incident groups evidence into a unit of investigation. A response action records a proposed or completed operational action.

An incident's severity is not the same as its state. A critical incident can be under investigation, while a low-severity incident can remain open because evidence is incomplete.

## Core Concepts

### Antivirus

Antivirus detection typically combines signatures, file reputation, heuristics, and other classification techniques. The model focuses on two explicit event types:

- `malware_detected` records a detection.
- `quarantine_failed` records a failed remediation attempt.

Detection and remediation are different outcomes. A detection does not establish that a malicious file executed, and a failed quarantine does not establish that the endpoint is compromised. Both warrant investigation according to the applicable response policy.

A trusted file hash is not a universal safety guarantee. Files can change, trust decisions can expire, and compromised software may have a previously trusted identity. The Python model therefore does not discard a detection simply because a hash is in its trusted-hash set.

### Endpoint Detection and Response

EDR focuses on endpoint activity and its relationships. Useful telemetry includes:

- Process creation and parent-child process relationships.
- Credential access attempts.
- File and configuration changes.
- Network connection metadata.
- Authentication events.
- Security control failures.

The correlation rule in the implementations looks for suspicious process execution or credential access followed by unusual outbound activity within five minutes. When the temporal relationship is satisfied, the incident is assigned critical severity.

This is a deliberately small rule, not a universal indicator of compromise. A production rule should also consider process ancestry, user context, endpoint role, destination reputation, event quality, and false-positive history. Temporal proximity alone cannot establish causation.

### Host-Based Intrusion Detection

HIDS monitors activity on an individual host. File-integrity monitoring is one common technique. A change to a protected configuration file can be legitimate maintenance, an unauthorized modification, or a consequence of malware.

The sample records a change to `/etc/ssh/sshd_config`. The detection establishes that a protected-file integrity event occurred, not that an attacker necessarily caused it. Investigation should compare the event with authorized change records, file ownership, modification time, and related authentication or process telemetry.

### Behavioral Detection

Behavioral detection evaluates patterns rather than relying exclusively on known malicious signatures. The sample detects five or more authentication failures followed by a successful authentication for the same account.

The implementation tracks failure counts in timestamp order. The rule is intentionally transparent, so its assumptions can be inspected. It is not a complete brute-force detector: a production implementation would define a rolling time window, distinguish source addresses, account for identity-provider behavior, and consider legitimate retries and lockout policies.

Behavioral thresholds are policy decisions. A low threshold may produce excessive alerts, while a high threshold may delay detection.

## Telemetry Model

Every event has an identifier, endpoint identifier, timestamp, sensor, event type, severity, process name, user, optional SHA-256 file hash, and structured details.

| Field | Purpose |
|---|---|
| Event ID | Provides stable identity for deduplication and evidence references. |
| Endpoint ID | Associates events with the device where they were observed. |
| Timestamp | Supports ordering and temporal correlation. |
| Sensor | Identifies the telemetry source. |
| Event type | Describes the observed activity. |
| Severity | Represents the source's initial assessment. |
| Process name | Identifies the process associated with the event. |
| User | Provides identity context. |
| File hash | Supports file identification where applicable. |
| Details | Stores bounded structured metadata. |

Timestamps include timezone information in Python and JavaScript. The C++ program uses integer timestamps for compact, deterministic comparisons. PostgreSQL uses `timestamptz`, allowing database operations to compare normalized instants.

The implementations validate identifiers, event fields, and file hashes. They reject conflicting records that reuse an existing event ID. Replaying an identical event is treated as an idempotent operation.

Idempotency is important because collectors and event transport systems can deliver the same message more than once. Without it, duplicate delivery can inflate alert counts and distort incident evidence.

## Detection, Correlation, and Incident State

The sample detection rules identify:

| Sensor | Event | Interpretation |
|---|---|---|
| Antivirus | `malware_detected` | A malware detection requires assessment. |
| Antivirus | `quarantine_failed` | A remediation attempt failed. |
| HIDS | `integrity_violation` | A protected resource changed unexpectedly. |
| EDR | `suspicious_process` | Process behavior warrants review. |
| EDR | `credential_access` | Credential-related behavior warrants review. |
| EDR | `unusual_outbound_connection` | Network activity may require correlation. |
| Behavioral | `authentication_success` after repeated failures | An authentication pattern warrants review. |

The correlation window is five minutes. Events outside the window do not satisfy that particular rule, although they may independently produce detections.

Incident state transitions are explicitly controlled:

    NEW
      |
      v
    TRIAGED
      | \
      |  \ 
      v   v
    CONTAINED  INVESTIGATING
      |          |        \
      v          v         v
    INVESTIGATING       RESOLVED
                   CONTAINED

The permitted transitions are narrower than this diagram might suggest: a new incident must first be triaged; a triaged incident can be contained or investigated; a contained incident can be investigated; an investigating incident can be contained again or resolved. A resolved incident cannot be reopened by the implemented transition functions.

A real incident-management system may support reopening through an explicit audited transition or create a linked follow-up incident. It should not silently overwrite historical resolution.

Containment changes the modeled endpoint state to `isolated`. Resolution changes it to `review_required`, rather than automatically declaring it healthy. In a real deployment, endpoint isolation must be performed by an authorized control plane, confirmed independently, and recorded with the actor, time, result, and reason.

## Python Implementation

The Python script uses dataclasses and enums to represent immutable telemetry and explicit incident states. `EndpointSecurityEngine` maintains event and incident dictionaries, groups events by endpoint, evaluates detection rules, correlates EDR activity, and produces a JSON-compatible report.

Important implementation decisions include:

- Frozen `TelemetryEvent` objects prevent accidental modification after ingestion.
- Dictionary-based event identity provides average constant-time duplicate lookup.
- Sets and ordered deduplication prevent repeated evidence from inflating an incident.
- The incident transition method rejects invalid state changes.
- Report export uses a temporary file followed by replacement to reduce the risk of leaving a partially written report.
- Unit tests cover detection, conflicting event identifiers, and invalid state transitions.

The simulator's event correlation and report generation are in memory. It is appropriate for a small, deterministic case study, not an unbounded production event stream. Memory usage grows with the number of retained events and incidents.

## JavaScript Implementation

The JavaScript implementation emphasizes event-driven processing and asynchronous report export. `TelemetryEvent` validates and freezes event objects. `EndpointSecurityEngine` uses `Map` for indexed event and incident storage and `Set` for unique evidence and reasons.

The state-transition map keeps valid transitions separate from the detection logic. Detection rules process events grouped by endpoint, and `exportReport` writes a temporary file before renaming it into place.

Node.js filesystem operations are asynchronous, so export errors propagate through a rejected promise and are handled by the main entry point. The export path is supplied by the program, and the temporary file is created with restrictive file permissions where supported by the operating system.

The implementation still uses an in-memory event store and synchronous correlation loops. A large deployment would need bounded processing batches, backpressure, durable storage, and explicit retention controls.

## C++17 Implementation

The C++ program presents the model as a compact governance engine with typed structures and STL containers.

- `Event` stores the validated telemetry record.
- `Incident` stores severity, state, evidence, and detection reasons.
- `GovernanceEngine` handles ingestion, correlation, transition validation, and reporting.
- `unordered_map` provides efficient event lookup.
- `map` provides deterministic ordering for incident and endpoint reports.
- `set` prevents duplicate evidence and makes output ordering stable.
- `vector` stores events associated with each endpoint during evaluation.

The implementation uses integer timestamps so time-window comparisons are explicit and inexpensive. Its identifier validation uses unsigned characters with character-classification functions to avoid undefined behavior for negative signed-character values.

For \(N\) events, ingestion is average \(O(1)\) per event with hash-based storage. Grouping requires \(O(N)\) expected time, followed by sorting each endpoint's events. If endpoint \(i\) has \(n_i\) events, the sorting cost is \(O(\sum_i n_i \log n_i)\). The straightforward correlation loop can require \(O(S \times O)\) comparisons per endpoint, where \(S\) and \(O\) represent suspicious and outbound events. A production implementation could use a time-indexed search to reduce repeated comparisons.

## Java 17 Implementation

The Java program models enterprise policy and domain behavior explicitly.

- Records represent validated telemetry and immutable views of incidents.
- Enums constrain sensor types, severity levels, and incident states.
- `DetectionRule` encapsulates sensor and event-type matching.
- `ResponsePolicy` defines the containment decision interface.
- `RiskBasedResponsePolicy` separates response thresholds from detection rules.
- `EndpointSecurityService` owns ingestion, correlation, transitions, and reporting.

The service applies a critical-severity containment threshold. A critical incident is moved through triage and containment, while less severe incidents remain available for investigation.

Immutable collections and record-based views reduce accidental modification by callers. The service's internal incident objects remain mutable because state transitions must be recorded. In a concurrent production service, those transitions would require transactional persistence or synchronization to prevent competing updates from producing invalid outcomes.

The program requires Java 17 or later. Its record, stream, and immutable-collection usage is designed for that runtime.

## PostgreSQL Implementation

The SQL script models the same domain relationally. It creates the `endpoint_security` schema and defines enum types for sensors, severities, incident states, and endpoint states.

### Relational entities

| Table | Responsibility |
|---|---|
| `endpoints` | Device identity, operating system, environment, and response state. |
| `telemetry_events` | Normalized endpoint observations and structured metadata. |
| `detection_rules` | Configurable event-matching rules. |
| `incidents` | Incident severity, workflow state, and lifecycle timestamps. |
| `incident_evidence` | Links incidents to supporting telemetry. |
| `response_actions` | Records proposed or completed response actions. |
| `detection_exceptions` | Time-bounded file-hash exceptions with justification. |
| `endpoint_policy` | Endpoint security and containment policy settings. |
| `approval_requirements` | Minimum approvals for designated response actions. |
| `security_approvals` | Reviewer decisions for incident-related actions. |
| `status_check_runs` | Sensor or control check execution state. |

Primary keys preserve record identity, foreign keys maintain relationships, and check constraints restrict allowed values. Indexes support endpoint/time retrieval, common sensor/event queries, open-incident reporting, and pending-action review.

### Database enforcement

`ingest_event` provides idempotent ingestion. It returns `false` for an identical replay and raises an exception when an existing identifier is reused with different event data.

`enforce_incident_transition` prevents invalid workflow changes and manages resolution timestamps. `validate_response_action` checks action state against incident state and records completion timestamps when an action reaches a terminal status.

The `evaluate_endpoint_security` function evaluates an endpoint's stored events, correlates EDR activity, identifies qualifying authentication patterns, creates an incident, and links evidence records. The dashboard and coverage views provide operational reporting without requiring every consumer to reconstruct the joins.

The script includes a nested exception block to demonstrate rejection of an invalid transition without aborting the surrounding transaction.

The approval query calculates eligibility from configured minimum approvals and recorded decisions. Approval eligibility is a distinct policy result; it does not mean that a response action has executed or that an endpoint has been successfully isolated.

### Transactional considerations

The script creates its schema objects and sample data inside a transaction. This allows the setup to commit as a unit if all statements succeed. In production, schema migration management, least-privilege roles, transaction isolation, audit retention, and controlled policy updates would need explicit design.

The demonstration's incident evaluator is intentionally compact. It should not be treated as a complete detection engine. In particular, production implementations need durable event ingestion, explicit rolling-window definitions, concurrency-safe incident deduplication, policy versioning, and auditable evidence provenance.

## Operational Security and Limitations

A production endpoint security platform needs controls beyond those modeled here:

- **Sensor integrity:** authenticate collectors, validate event sources, and detect missing or tampered telemetry.
- **Transport security:** protect telemetry in transit and restrict ingestion credentials.
- **Access control:** separate analyst, responder, policy administrator, and audit roles.
- **Data minimization:** limit collected process arguments, identity details, and other potentially sensitive data.
- **Retention:** apply defined storage and deletion periods to raw events and incident evidence.
- **Time quality:** monitor clock drift and preserve event time separately from ingestion time.
- **Detection quality:** test rule behavior against representative benign and malicious scenarios.
- **Response safety:** require authorization for disruptive actions and verify the result of containment.
- **Auditability:** preserve rule versions, response decisions, policy changes, and incident transitions.
- **Failure handling:** distinguish missing telemetry, sensor failure, ingestion failure, detection failure, and successful execution with no findings.

The examples use a simple severity ordering and a limited collection of detection rules. Real endpoint risk depends on context, confidence, asset criticality, attack progression, and the quality of supporting evidence. A high-severity alert is a reason to investigate, not proof of compromise.

## Execution and Verification

The Python script uses only the standard library and runs its built-in unit tests when executed. It prints a report and exercises invalid-input and transition handling.

The JavaScript file requires Node.js 18 or later. Run it normally for a report or pass `--export` to write a JSON report to the current directory.

The C++ program requires a compiler with C++17 support. It prints the incident report and verifies that an invalid identifier is rejected.

The Java program requires Java 17 or later. Compile `EndpointSecurity.java` and run the `EndpointSecurity` class.

The PostgreSQL script targets PostgreSQL 15 or later. Execute the complete script in a database where the executing role can create schemas, types, tables, functions, and triggers. The script uses a dedicated schema and commits the sample model as one transaction.

All output records are synthetic. The examples demonstrate data modeling and security workflow decisions, not measured detection accuracy or verified operational endpoint protection.
