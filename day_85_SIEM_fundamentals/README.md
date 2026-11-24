# SIEM Fundamentals: Events, Fields, Indexes, Searches, Correlation and Alerts

## 1. Security Information and Event Management

Security Information and Event Management (SIEM) is a security monitoring architecture that collects, normalizes, stores, searches, correlates and analyzes security events from multiple infrastructure components.

A SIEM system brings together information from:

- Authentication servers
- Firewalls
- Network devices
- DNS servers
- Operating systems
- Endpoint Detection and Response (EDR) platforms
- Applications
- Cloud infrastructure
- Identity and access management systems

Its purpose is to provide a centralized view of security activity and identify patterns that individual devices might not recognize independently.

A typical SIEM processing architecture is:

Event Sources
    |
    v
Collection and Ingestion
    |
    v
Parsing and Normalization
    |
    v
Structured Event Storage
    |
    v
Indexing
    |
    v
Search and Investigation
    |
    v
Correlation and Detection Rules
    |
    v
Alerts
    |
    v
SOC Investigation and Response

The five implementations demonstrate different engineering approaches to this processing architecture.

## 2. Security Events

An event is a recorded occurrence within an information system that may have security relevance.

Examples include:

| Event | Source | Security significance |
|---|---|---|
| Successful login | Authentication server | Records account access |
| Failed login | Authentication server | May indicate password guessing |
| Blocked connection | Firewall | Records an enforced network restriction |
| Suspicious process | EDR | May indicate endpoint compromise |
| DNS query | DNS server | Provides domain-resolution activity |
| Privilege escalation | Operating system | May indicate unauthorized privilege use |
| Application error | Application | May indicate malfunction or exploitation |

An individual event does not necessarily represent an attack.

For example, one failed login may be caused by an incorrectly entered password. Hundreds of failed attempts from the same address within a short period provide stronger evidence of automated password guessing.

The distinction between an individual occurrence and a correlated security pattern is fundamental to SIEM operation.

### 2.1 Event structure

A normalized event contains identifiable metadata and structured attributes.

| Field | Purpose | Example |
|---|---|---|
| event_id | Unique event identifier | AUTH-001 |
| timestamp | Time of occurrence | 2026-11-24T06:00:05Z |
| source | Originating system | linux-auth-01 |
| category | Event classification | authentication |
| event_type | Specific occurrence | failed_login |
| severity | Initial importance | MEDIUM |
| src_ip | Originating address | 203.0.113.45 |
| username | Associated account | admin |
| hostname | Associated device | server-01 |
| result | Observed outcome | FAILURE |

A timestamp should include timezone information. UTC is commonly used to simplify event correlation across geographically distributed infrastructure.

An important distinction exists between:

- Event time: When the security activity occurred.
- Ingestion time: When the SIEM received and stored the event.

These timestamps can differ because of network delays, buffering, disconnected devices and collection failures.

The PostgreSQL implementation stores both `event_timestamp` and `ingested_at`.

## 3. Event Collection and Ingestion

Ingestion is the process of accepting events from their originating systems and making them available for security analysis.

The ingestion process must handle:

1. Source identification.
2. Payload validation.
3. Timestamp interpretation.
4. Event classification.
5. Field extraction.
6. Normalization.
7. Duplicate detection.
8. Storage.
9. Index maintenance.

### 3.1 Source identification

A SIEM must identify which system produced an event.

The implementations distinguish the source identifier from the event identifier.

For example:

- `linux-auth-01` identifies the originating authentication system.
- `AUTH-001` identifies one particular occurrence.

The PostgreSQL `data_sources` table maintains source registration, source type, operational status and last-seen information.

This makes it possible to distinguish between an event source that is producing no security events and an event source that has stopped communicating.

### 3.2 Duplicate detection

Security events may be delivered more than once because of:

- Message queue retries.
- Network interruptions.
- Collector restarts.
- Delivery acknowledgements being lost.
- Repeated API requests.

The implementations use unique event identifiers to prevent duplicate storage.

The Python and JavaScript implementations use in-memory maps. C++ uses an unordered map. Java uses a concurrent map. PostgreSQL enforces uniqueness using a database constraint on `external_event_id`.

This is an important ingestion property because duplicate events can inflate detection counts and produce incorrect alerts.

Deduplication by identifier assumes that the upstream system supplies a stable event identifier. Production ingestion pipelines may also require source-specific deduplication keys and retention windows.

## 4. Event Fields and Normalization

Fields represent the individual attributes associated with an event.

For example, a failed SSH authentication event may contain:

- `src_ip`
- `username`
- `hostname`
- `protocol`
- `result`

Normalization makes data from different sources consistent enough to search and correlate.

Consider two source-specific representations:

| Original source | Original value | Normalized representation |
|---|---|---|
| Linux authentication | SSH login failure | failed_login |
| Windows authentication | Failed account logon | failed_login |

The normalized event type allows a common detection rule to examine both sources.

Normalization should preserve the original event or an auditable representation of its original payload. It should not silently remove meaningful source-specific information.

The Python and JavaScript implementations retain structured event fields. The C++ implementation uses typed event properties and string-valued field maps. Java uses immutable event records. PostgreSQL combines relational columns with a JSONB field structure.

### 4.1 Common field types

| Field type | Example | Application |
|---|---|---|
| String | username | Account investigation |
| Integer | destination_port | Network analysis |
| Boolean | privileged | Access evaluation |
| Timestamp | event_timestamp | Time-based searches |
| IP address | src_ip | Network correlation |
| JSON object | fields | Flexible event attributes |

PostgreSQL uses the `INET` type for network addresses. This supports address validation and network-specific operations.

JSONB provides flexible storage for attributes that are not part of every event category.

## 5. SIEM Indexes

An index is a data structure that helps a search engine locate matching records without examining every stored event.

Without an index, searching a large event collection may require a sequential scan.

With an equality index, the system can identify candidate event identifiers associated with a particular field value.

### 5.1 Example

Suppose the SIEM contains one million events.

An analyst searches for:

`src_ip = 203.0.113.45`

A sequential search evaluates the source IP field for every event.

An indexed search first retrieves the identifiers associated with that address and evaluates only the resulting candidates.

The Python, JavaScript, C++ and Java implementations use equality indexes with the following conceptual structure:

Field
    |
    v
Normalized Value
    |
    v
Set of Event Identifiers

For example:

`src_ip`

- `203.0.113.45` → AUTH-001, AUTH-002, AUTH-003
- `198.51.100.20` → AUTH-004, AUTH-005

This structure supports candidate selection and reduces unnecessary event inspection.

### 5.2 Index trade-offs

Indexes improve read performance but introduce additional costs.

| Consideration | Effect |
|---|---|
| Search performance | Generally improves |
| Storage requirements | Increase |
| Ingestion performance | Additional index maintenance |
| Memory consumption | Increases for in-memory indexes |
| High-cardinality fields | Can produce large indexes |
| Frequently updated fields | Require maintenance |

Not every field should be indexed.

Fields frequently used in investigations, such as event type, source IP, username and timestamp, are stronger indexing candidates than arbitrary descriptive text.

### 5.3 PostgreSQL indexing

The SQL implementation uses:

- B-tree indexes for timestamps and frequently filtered relational fields.
- Composite indexes for category, severity and time combinations.
- Partial indexes for fields that are frequently non-null.
- GIN indexes for JSONB containment searches.

The index on `fields` supports searches involving flexible event attributes.

Index selection should be based on actual query patterns and execution plans. Additional indexes should not be created indiscriminately because they increase write and storage costs.

## 6. SIEM Search

Search enables security analysts to retrieve relevant events using structured conditions.

Common search dimensions include:

- Event type
- Source system
- Severity
- Source IP
- Destination IP
- Username
- Hostname
- Time range
- Structured JSON fields

An example investigation is:

Find all failed authentication attempts from a particular address during a five-minute period.

Conceptually:

`event_type = failed_login`

`src_ip = 203.0.113.45`

`timestamp >= investigation_start`

`timestamp <= investigation_end`

The search process follows:

Query Validation
    |
    v
Index Candidate Selection
    |
    v
Candidate Retrieval
    |
    v
Additional Filtering
    |
    v
Time Ordering
    |
    v
Result Limiting

### 6.1 Search operations

The implementations support equality searches, category filtering, severity filtering and time boundaries.

The SQL implementation additionally provides a reusable `search_events` function.

Search limits prevent unnecessarily large result sets from being returned to applications.

The Python implementation measures execution time using `time.perf_counter()`. JavaScript uses `process.hrtime.bigint()`. C++ uses `std::chrono::steady_clock`. Java uses `System.nanoTime()`.

These measurements are useful for local comparisons, although production search performance also depends on storage, cache behavior, concurrent workloads, network latency and query planning.

### 6.2 Search limitations

An equality index does not automatically provide efficient:

- Arbitrary substring searches.
- Complex regular-expression matching.
- Full-text search.
- Multi-dimensional statistical analysis.
- Distributed searches across separate storage nodes.

These require appropriate additional indexing, query processing and distributed search mechanisms.

## 7. Event Correlation

Event correlation identifies relationships between multiple events.

A correlation rule evaluates event attributes and determines whether their combined pattern represents suspicious activity.

Consider this scenario:

- An external address attempts to authenticate using the administrator account.
- Each attempt fails.
- The attempts originate from the same source IP.
- At least five attempts occur within five minutes.

An individual failed login may be ordinary activity.

Five failures from the same address within the specified time window satisfy the example detection rule.

### 7.1 Correlation rule components

| Component | Example | Purpose |
|---|---|---|
| Rule identifier | RULE-001 | Identifies the rule |
| Event type | failed_login | Selects relevant events |
| Group field | src_ip | Groups related events |
| Time window | 300 seconds | Defines observation period |
| Threshold | 5 | Defines minimum occurrences |
| Severity | CRITICAL | Assigns detection importance |

The general evaluation condition is:

\[
\operatorname{count}(E_g,W)\geq T
\]

Where:

- \(E_g\) represents events belonging to group \(g\).
- \(W\) represents the observation window.
- \(T\) represents the required threshold.

The correlation workflow is:

Retrieve Relevant Events
    |
    v
Apply Time Window
    |
    v
Group by Source IP
    |
    v
Count Events
    |
    v
Compare with Threshold
    |
    v
Generate Alert

### 7.2 Time-window behavior

A time window limits the period considered during correlation.

A five-minute window is not equivalent to counting all failed logins since the beginning of the day.

The example implementations use a bounded observation interval and evaluate event timestamps against its boundaries.

The examples also use time buckets to prevent repeated evaluations from generating duplicate alerts for the same rule and grouping key within a bucket.

This is a simplified correlation strategy.

Production systems may use:

- Sliding windows.
- Tumbling windows.
- Session windows.
- Event-time processing.
- Watermarks.
- Late-event handling.
- Distributed state management.

The choice depends on event volume, acceptable detection latency and the importance of late-arriving records.

### 7.3 Correlation is not causation

A correlation rule identifies a pattern that satisfies predefined conditions.

It does not independently establish that an attack has occurred.

For example, multiple failed logins can result from:

- Password guessing.
- A misconfigured application.
- An outdated service credential.
- A legitimate user repeatedly entering an incorrect password.

The resulting alert requires investigation and contextual validation.

## 8. Alerts

An alert is a structured security finding generated when a detection rule or other monitoring mechanism identifies activity requiring attention.

An alert contains:

- Alert identifier.
- Detection rule.
- Title.
- Severity.
- Creation timestamp.
- Related event identifiers.
- Description.
- Investigation status.
- Assigned analyst.

The distinction between an event and an alert is important.

| Event | Alert |
|---|---|
| Records an occurrence | Records a security finding |
| Originates from an event source | Generated by a detection mechanism |
| May be informational | Requires an operational interpretation |
| Can exist independently | Usually references supporting events |
| Does not require an investigation | May enter an investigation workflow |

Multiple events can contribute to one alert.

The `alert_events` table models this many-to-many relationship.

This allows an analyst to inspect all events associated with a particular detection without duplicating their original records.

## 9. Alert Lifecycle

Alerts require controlled state transitions to support investigation and reporting.

The implementations use the following lifecycle:

NEW
  |
  v
ACKNOWLEDGED
  |
  v
INVESTIGATING
  |
  +-----------> RESOLVED
  |
  +-----------> FALSE_POSITIVE

A new alert can also be classified as a false positive after an initial assessment.

### 9.1 Alert states

| State | Meaning |
|---|---|
| NEW | Alert has been generated |
| ACKNOWLEDGED | An analyst has accepted responsibility |
| INVESTIGATING | Investigation is underway |
| RESOLVED | Investigation has been completed |
| FALSE_POSITIVE | The detected pattern does not represent a relevant security incident |

Resolved and false-positive alerts are terminal states in the example implementations.

Invalid transitions are rejected.

For example, an alert that has reached `RESOLVED` cannot return to `NEW` through the normal transition mechanism.

The Python, JavaScript, C++ and Java implementations enforce these transitions in application logic.

PostgreSQL enforces them through the `validate_alert_transition` trigger.

The SQL implementation also records status changes in `alert_history`.

A production implementation should preserve the identity of the analyst performing each transition. The SQL workflow function records an analyst identifier, while the application implementations maintain analyst assignment.

## 10. Alert Prioritization

Severity expresses the initial importance assigned to an event or alert.

The example system uses five levels.

| Severity | Interpretation |
|---|---|
| INFO | Routine informational activity |
| LOW | Limited security significance |
| MEDIUM | Activity requiring contextual assessment |
| HIGH | Significant suspicious activity |
| CRITICAL | Activity requiring urgent investigation |

Severity should not be confused with confidence.

An alert can be classified as critical while still requiring validation.

Similarly, a high-severity event may not represent a confirmed incident.

Production prioritization can consider:

- Asset criticality.
- Account privilege.
- Threat intelligence.
- Network exposure.
- Detection confidence.
- Business impact.
- Historical activity.
- Existing incident context.

## 11. Implementation Perspectives

The five source implementations model the same security monitoring domain through different engineering approaches.

### 11.1 Python: SIEM workflow simulation

The Python implementation uses dataclasses, enumerations, dictionaries, sets and explicit domain validation.

Its main components are:

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Represents a normalized security event |
| `CorrelationRule` | Defines a detection condition |
| `SIEMEngine` | Handles ingestion, indexing and search |
| `Alert` | Represents a detection finding |
| `SearchResult` | Returns search results and timing information |

The `SIEMEngine` maintains an event dictionary and equality indexes.

The `correlate()` method groups matching events by a configured field and generates alerts when a threshold is satisfied.

The alert transition mechanism prevents invalid lifecycle operations.

The sample tests validate duplicate detection, event searching, threshold detection, correlation idempotency and alert state transitions.

### 11.2 JavaScript: Event-driven SIEM

The JavaScript implementation uses Node.js capabilities and event-driven processing.

Its main components are:

| Component | Responsibility |
|---|---|
| `SIEM` | Coordinates the monitoring pipeline |
| `EventIndex` | Maintains equality indexes |
| `validateEvent()` | Validates and normalizes input |
| `ingestBatch()` | Processes bounded asynchronous batches |
| `correlate()` | Evaluates registered detection rules |
| `transitionAlert()` | Manages alert state changes |

The `EventEmitter` publishes:

- `event:ingested`
- `alert:created`
- `alert:updated`

These events allow other application components to respond to ingestion and detection activity.

The batch ingestion method uses `Promise.allSettled()` to retain successful processing results even when individual events fail.

Concurrency is bounded to prevent unrestricted simultaneous processing.

The implementation uses private class fields to prevent direct external modification of internal event and alert collections.

### 11.3 C++17: SIEM detection engine

The C++ implementation emphasizes explicit domain modeling and efficient container usage.

Its primary components are:

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Typed event representation |
| `SearchQuery` | Search conditions |
| `SearchResult` | Matching events and execution time |
| `CorrelationRule` | Threshold-based detection configuration |
| `Alert` | Security finding |
| `SIEMEngine` | Indexing, searching and correlation |

The implementation uses:

- `std::unordered_map` for event lookup.
- `std::unordered_set` for indexed identifiers.
- `std::map` for deterministic correlation groups.
- `std::vector` for result collections.
- `std::chrono` for execution measurements.
- `std::set` for processed correlation fingerprints.

The implementation uses a deterministic non-cryptographic hash for demonstration alert identifiers. Production identifiers should use a cryptographic hash or a properly generated unique identifier.

### 11.4 Java 17: Enterprise SIEM model

The Java implementation emphasizes immutable domain data, explicit service responsibilities and concurrent collections.

Its principal components are:

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Immutable event record |
| `SearchCriteria` | Validated search conditions |
| `SearchResult` | Search response |
| `CorrelationRule` | Immutable detection configuration |
| `EventRepository` | Event storage and indexes |
| `CorrelationService` | Detection and alert generation |
| `Alert` | Controlled alert state |
| `SIEMApplication` | Coordinates the workflow |

Java records provide compact immutable representations of events and search criteria.

`ConcurrentHashMap` and concurrent sets support safe collection access.

`LongAdder` maintains ingestion metrics under concurrent updates.

The alert class synchronizes state transitions to protect its lifecycle.

The example uses concurrent collections but does not implement a complete distributed transaction across event storage, index updates and correlation state. A production implementation would require transactional persistence and recovery mechanisms.

### 11.5 PostgreSQL: Relational SIEM data model

The PostgreSQL implementation represents the operational data relationships in a relational database.

Its primary tables are:

| Table | Purpose |
|---|---|
| `data_sources` | Registered event sources |
| `security_events` | Normalized security events |
| `event_field_definitions` | Field metadata |
| `analysts` | SOC personnel and roles |
| `correlation_rules` | Detection configurations |
| `correlation_runs` | Rule execution history |
| `alerts` | Generated security findings |
| `alert_events` | Supporting event relationships |
| `alert_history` | Alert lifecycle audit |
| `status_checks` | Operational health checks |

The database uses foreign keys to maintain relationships and check constraints to enforce valid data.

The `ingest_event()` function validates source registration and prevents duplicate external identifiers.

The `evaluate_rule()` function retrieves matching events, groups them by a configured field and generates alerts when thresholds are satisfied.

The `search_events()` function provides a reusable parameterized search interface.

The reporting views expose event summaries, alert summaries and source health.

The script includes sample data and executable workflow statements.

## 12. Relational Data Model

The main relationships are:

Data Sources
    |
    v
Security Events
    |
    +----------------------+
    |                      |
    v                      v
Event Field Definitions   Correlation Rules
                           |
                           v
                    Correlation Runs
                           |
                           v
                         Alerts
                           |
              +------------+------------+
              |                         |
              v                         v
         Alert Events              Alert History
              |                         |
              v                         v
       Security Events                Analysts
              |
              v
        SOC Investigation

The model separates event storage, detection configuration, detection execution and investigation records.

This separation prevents a detected security pattern from being confused with the original events.

## 13. Search, Correlation and Detection Distinctions

These mechanisms serve different operational purposes.

| Mechanism | Primary question | Output |
|---|---|---|
| Event ingestion | What happened? | Stored event |
| Field normalization | How should the occurrence be represented? | Standardized event |
| Indexing | Where are matching records? | Candidate identifiers |
| Search | Which events match the conditions? | Matching event records |
| Correlation | Which combinations satisfy detection rules? | Detection findings |
| Alert generation | Which findings require attention? | Security alert |
| Investigation | What does the activity represent? | Analyst assessment |

A search retrieves information based on supplied conditions.

A correlation rule evaluates relationships between events.

An alert communicates a finding generated by a detection mechanism.

These operations should not be treated as interchangeable.

## 14. Detection Quality and False Positives

Detection quality depends on the quality of collected data, normalization and detection conditions.

A threshold that is too low can generate excessive alerts.

A threshold that is too high can miss suspicious activity.

For example:

| Rule threshold | Possible operational effect |
|---|---|
| 2 failed logins | High alert volume |
| 5 failed logins | More selective detection |
| 20 failed logins | May miss slower attempts |

These values are illustrative and must be calibrated against actual operational conditions.

Other factors include:

- Shared network addresses.
- Corporate VPN gateways.
- Service accounts.
- Scheduled automation.
- Time synchronization problems.
- Missing events.
- Inconsistent source identifiers.
- Late-arriving events.

Detection engineering requires continuous validation against legitimate activity and known malicious patterns.

## 15. Performance Considerations

The implementations use in-memory equality indexes for educational purposes.

Let:

- \(N\) represent the number of stored events.
- \(K\) represent the number of candidate events returned by an index.
- \(M\) represent the number of matching results.

| Operation | Approximate behavior |
|---|---|
| Event insertion | Average constant-time hash lookup, plus index updates |
| Duplicate detection | Average O(1) |
| Equality index lookup | Average O(1) |
| Candidate filtering | O(K) |
| Sorting results | O(M log M) |
| Grouping events | Average O(K) with hash-based grouping |
| Alert lookup | Average O(1) |

These estimates describe the in-memory data structures, not end-to-end production SIEM performance.

Actual costs depend on the number of indexed fields, memory allocation, hashing, event serialization and concurrent activity.

### Production scaling considerations

A production SIEM commonly requires:

- Persistent event storage.
- Time-based partitioning.
- Distributed ingestion.
- Message buffering.
- Backpressure.
- Retention management.
- Search pagination.
- Distributed correlation state.
- Query optimization.
- Monitoring of collection failures.
- High-availability architecture.

The sample implementations retain their event data in memory. Restarting a process therefore loses its stored events and correlation state.

PostgreSQL provides persistent relational storage, but the example schema is not a complete distributed SIEM deployment.

## 16. Security Considerations

A SIEM handles potentially sensitive operational information.

Event records may contain:

- Usernames.
- Internal IP addresses.
- Hostnames.
- Authentication metadata.
- Process information.
- Network activity.
- Application details.

Appropriate security controls include:

### Access control

Separate permissions should exist for ingestion, investigation, administration and auditing.

An ingestion service should not automatically receive administrative database permissions.

### Data protection

Sensitive event fields should be protected through appropriate encryption, restricted access and controlled retention.

### Input validation

Event payloads should be checked for valid structures, timestamps, field types and reasonable sizes.

### Auditability

Analyst actions, alert assignments and investigation status changes should be recorded.

### Integrity

Event identifiers and database constraints should prevent unintended duplication and inconsistent relationships.

### Operational resilience

The production pipeline should handle:

- Source disconnections.
- Collector failures.
- Storage failures.
- Message retries.
- Delayed events.
- Partial processing.
- Database outages.

### Detection security

Detection rules should be protected against unauthorized changes. Their modifications should be versioned and audited.

## 17. Testing and Validation Scenarios

The sample programs implement a scenario involving repeated failed SSH authentication attempts.

The principal expected behavior is:

| Test | Expected result |
|---|---|
| Ingest a valid authentication event | Event accepted |
| Ingest an existing event identifier | Duplicate rejected |
| Search by source IP | Matching events returned |
| Filter by authentication category | Only authentication events returned |
| Register a valid correlation rule | Rule accepted |
| Evaluate fewer events than the threshold | No alert |
| Evaluate five or more matching events | Alert generated |
| Evaluate the same correlation bucket again | No duplicate alert |
| Acknowledge a new alert | State updated |
| Begin investigation | State updated |
| Reopen a terminal alert through a normal transition | Operation rejected |
| Search with an invalid time range | Validation error |

The Python implementation includes explicit assertions.

The JavaScript implementation uses runtime assertions and error handling.

The C++ implementation checks expected behavior and throws exceptions for invalid operations.

The Java implementation uses validated records, service-level checks and controlled state transitions.

The PostgreSQL implementation uses constraints, triggers, functions and transaction boundaries.

## 18. Practical SOC Investigation Workflow

The example scenario represents a simplified Security Operations Center workflow.

1. The authentication server generates failed login events.
2. The SIEM ingestion process receives the records.
3. Each event is validated and normalized.
4. The SIEM indexes relevant fields.
5. An analyst searches for failed logins from a particular address.
6. A correlation rule groups matching events.
7. The threshold condition is satisfied.
8. The SIEM generates a critical alert.
9. The alert is assigned to an analyst.
10. The analyst acknowledges the finding.
11. The analyst investigates the associated events.
12. The alert is resolved or classified as a false positive.
13. The system retains the relevant alert history.

This workflow demonstrates how event collection, structured storage, search, correlation and alert management work together.

## 19. Technical Limitations

The five implementations are deliberately bounded SIEM models rather than complete commercial monitoring platforms.

| Capability | Implementation status |
|---|---|
| Structured event ingestion | Implemented |
| Basic normalization | Implemented |
| Duplicate prevention | Implemented |
| Equality indexes | Implemented |
| Time-bounded searches | Implemented |
| Severity and category filtering | Implemented |
| Threshold-based correlation | Implemented |
| Group-based detection | Implemented |
| Alert generation | Implemented |
| Alert lifecycle validation | Implemented |
| Basic reporting | Implemented |
| Persistent storage | PostgreSQL implementation |
| Distributed event ingestion | Not implemented |
| Full-text search | Not implemented |
| Threat intelligence enrichment | Not implemented |
| Machine-learning detection | Not implemented |
| Distributed stream processing | Not implemented |
| Automated incident containment | Not implemented |
| Production-grade identity integration | Not implemented |

The correlation examples use bounded in-memory event collections and simplified time buckets. They do not implement a complete streaming event-time engine.

The PostgreSQL correlation function uses exact execution windows and unique execution constraints. A production scheduler must define appropriate window boundaries and execution frequency.

The database example also requires deployment-specific role creation, permissions, retention policies, backup procedures and operational monitoring.

The central technical distinction remains consistent throughout the implementations: events record activity, fields describe that activity, indexes accelerate retrieval, searches locate relevant records, correlation identifies relationships, and alerts communicate findings requiring security attention.
