# SIEM Querying: Filtering, Aggregation, Timelines and Field Analysis

## 1. Project Overview

This project implements a Security Information and Event Management (SIEM) querying and analytics workflow using Python, JavaScript, C++17, Java 17, and PostgreSQL.

A SIEM system collects security telemetry from different infrastructure components, normalizes events, and supports investigation through structured queries and analytical operations.

The project concentrates on four important SIEM querying capabilities:

1. **Filtering:** Selecting security events that satisfy specified conditions.
2. **Aggregation:** Summarizing events by fields such as severity, source IP, username, and event type.
3. **Timeline analysis:** Examining event frequency and distribution across time intervals.
4. **Field analysis:** Understanding the frequency, uniqueness, and distribution of event attributes.

A failed-authentication detection scenario connects these capabilities to a practical security investigation.

## 2. Technical Architecture

The implementations use a common security-event model while demonstrating different engineering approaches.

| Component | Responsibility |
|---|---|
| Event ingestion | Receives and validates security events |
| Event repository | Maintains event collections and field indexes |
| Query engine | Applies filtering and time conditions |
| Aggregation engine | Calculates event distributions |
| Timeline engine | Groups events into time buckets |
| Field analyzer | Examines event attributes |
| Detection engine | Identifies suspicious authentication patterns |
| Reporting engine | Produces investigation summaries |
| PostgreSQL database | Provides persistent relational storage and analytical queries |

### Event processing architecture

    Security Event Sources
            |
            v
    Event Ingestion
            |
            v
    Validation and Normalization
            |
            v
    Event Repository / Database
            |
            v
    SIEM Query Engine
            |
            +------ Filtering
            |
            +------ Aggregation
            |
            +------ Timeline Analysis
            |
            +------ Field Analysis
            |
            v
    Detection Rules
            |
            v
    Security Alerts and Reports

The architecture distinguishes event collection from event investigation. Ingestion establishes the available security evidence. Queries determine which evidence is relevant to an investigation.

## 3. Security Event Data Model

A security event represents an observable occurrence in an information system.

The implementations use the following principal attributes:

| Field | Meaning |
|---|---|
| `event_id` | Unique event identifier |
| `timestamp` | Time at which the event occurred |
| `source_ip` | Originating IP address |
| `destination_ip` | Destination IP address |
| `username` | Associated account |
| `event_type` | Classification of the event |
| `severity` | Security importance |
| `action` | Observed or recorded operation |
| `source` | Originating security telemetry system |
| `fields` | Additional structured event attributes |

### Severity classification

| Severity | Interpretation |
|---|---|
| INFO | Informational activity |
| LOW | Low-priority security observation |
| MEDIUM | Activity requiring attention |
| HIGH | Significant security concern |
| CRITICAL | Activity requiring urgent investigation |

Severity is a classification attribute. It does not independently establish whether an event represents a confirmed attack.

For example, a HIGH-severity authentication failure is evidence of a potentially suspicious activity. It is not proof of account compromise.

### Event normalization

Different security products can report the same underlying activity using different field names and formats.

Normalization converts these records into a consistent representation.

The implementations validate mandatory fields, timestamp formats, severity values, and event identifiers.

The PostgreSQL implementation additionally uses `INET` for IP addresses, `TIMESTAMPTZ` for timestamps, `JSONB` for additional attributes, and an event-source registry.

## 4. SIEM Querying Fundamentals

A SIEM query selects and analyzes security events using conditions applied to their attributes.

A query generally contains:

- Fields to inspect.
- Comparison operators.
- Values or thresholds.
- Optional time boundaries.
- Aggregation requirements.
- Sorting and result limits.

### Filtering operators

| Operator | Meaning | Example |
|---|---|---|
| `=` | Exact match | `severity = 'HIGH'` |
| `!=` | Exclusion | `action != 'success'` |
| `>` | Greater than | Event count greater than a threshold |
| `>=` | Greater than or equal | Severity score at least HIGH |
| `<` | Less than | Event timestamp before a boundary |
| `<=` | Less than or equal | Event timestamp within a limit |
| `IN` | Membership | `severity IN ('HIGH', 'CRITICAL')` |
| `CONTAINS` | Substring match | Username contains a specified value |

The Python and JavaScript implementations provide composable filtering operations. C++ and Java demonstrate domain-specific filtering methods. PostgreSQL expresses these operations through SQL predicates.

Filtering reduces the dataset before more expensive analytical operations are performed.

### Compound filtering

Multiple conditions can be combined.

For example, an investigation may select:

- Authentication events.
- Failed actions.
- HIGH or CRITICAL severity.
- Events originating from a particular source IP.
- Events occurring during a defined investigation window.

The result is the intersection of all applicable conditions.

### Time-range filtering

Time filtering is particularly important in incident investigation.

A query may use a closed time interval:

`start_timestamp <= event_timestamp <= end_timestamp`

PostgreSQL examples also demonstrate half-open intervals, which are useful for partitioned datasets and adjacent reporting periods.

Timestamps should be stored and compared using consistent timezone-aware representations. UTC is used throughout the examples.

## 5. Aggregation

Aggregation transforms individual event records into summarized measurements.

Instead of inspecting every event, analysts can identify patterns across a large collection.

### Common aggregation operations

| Operation | Security application |
|---|---|
| COUNT | Number of recorded events |
| COUNT DISTINCT | Number of unique entities |
| GROUP BY | Event distribution by attribute |
| MIN | Earliest observed event |
| MAX | Latest observed event |
| AVG | Average numerical measurement |
| HAVING | Filtering aggregated groups |

### Severity aggregation

Severity aggregation determines the number of events in each classification.

It can identify whether a dataset contains a concentration of HIGH and CRITICAL events.

### Source IP aggregation

Grouping by source IP identifies the most active originating addresses.

This can support investigations involving:

- Repeated authentication failures.
- Network scanning.
- Unusual connection frequency.
- Multiple targeted systems.
- Suspicious traffic concentration.

High event frequency alone is not sufficient to establish malicious activity. Infrastructure roles, normal operating patterns, and event context must also be considered.

### Username aggregation

Grouping by username helps identify accounts associated with unusual activity.

For example, one account generating repeated authentication failures may warrant investigation.

Aggregation can also reveal accounts associated with multiple source addresses.

### Multi-dimensional aggregation

Grouping by both `event_type` and `action` provides more contextual information than either field independently.

A result can distinguish authentication failures, successful authentications, blocked network connections, and process execution events.

## 6. Timeline Analysis

Timeline analysis examines how event frequency changes over time.

A SIEM system groups events into defined intervals called time buckets.

For example, a five-minute timeline creates intervals such as:

    02:30 - 02:35 | 5 events
    02:35 - 02:40 | 3 events
    02:40 - 02:45 | 2 events

The example dataset contains ten events distributed across a thirteen-minute observation period.

### Time-bucket calculation

For an interval of duration `T`, a timestamp is assigned to the bucket:

`bucket = floor(timestamp / T) * T`

This ensures that events occurring in the same interval contribute to the same bucket.

The C++ implementation uses epoch timestamps. Python and JavaScript use timezone-aware timestamp representations. Java uses `Instant`, while PostgreSQL uses `date_bin()`.

### Timeline applications

Timeline analysis supports:

- Detecting sudden increases in authentication failures.
- Identifying concentrated network activity.
- Correlating events across security sources.
- Examining activity before and after an incident.
- Measuring event rates.
- Comparing normal and abnormal operating periods.

### Bucket-size tradeoffs

| Interval | Advantage | Limitation |
|---|---|---|
| 1 minute | High temporal detail | More buckets |
| 5 minutes | Useful operational resolution | Can conceal short bursts |
| 15 minutes | Reduced reporting volume | Less temporal precision |
| 1 hour | Useful for broad trends | Can obscure attack sequences |

The correct interval depends on event volume, detection requirements, and investigation objectives.

A five-minute aggregation is not equivalent to a five-minute detection window. Timeline aggregation summarizes activity by time bucket, while detection windows evaluate event relationships over a specified duration.

## 7. Field Analysis

Field analysis examines the characteristics and distribution of event attributes.

It helps determine which fields are useful for filtering, correlation, and detection.

### Important measurements

| Measurement | Purpose |
|---|---|
| Unique values | Measures field diversity |
| Frequency distribution | Identifies common values |
| Top values | Identifies dominant entities |
| Null count | Evaluates missing information |
| Distinct entity count | Measures source or account diversity |
| Field presence | Determines whether optional attributes exist |

### Example

Consider the following source IP distribution:

| Source IP | Events |
|---|---:|
| 192.168.1.10 | 6 |
| 10.10.1.20 | 2 |
| 172.16.0.25 | 1 |
| 192.168.1.15 | 1 |

The address `192.168.1.10` accounts for six events.

Further investigation reveals five failed authentication attempts followed by one successful authentication.

This is more informative than examining the source IP count independently.

### Cardinality

Cardinality refers to the number of distinct values in a field.

Examples:

- A severity field usually has low cardinality.
- A username field may have medium cardinality.
- An event identifier field normally has very high cardinality.

Cardinality affects aggregation efficiency, indexing decisions, storage requirements, and dashboard design.

High-cardinality fields should not automatically be used as grouping dimensions in every query because they can generate large result sets.

## 8. Practical Detection: Repeated Failed Authentication

The implementations include a brute-force detection example.

The detection rule identifies repeated failed authentication attempts from the same source IP against the same username.

### Detection policy

| Parameter | Value |
|---|---|
| Event type | authentication |
| Action | failure |
| Threshold | 5 attempts |
| Observation window | 10 minutes |
| Alert severity | HIGH |

The sample events contain five failed attempts against the `admin` account from `192.168.1.10`.

The failures occur within four minutes.

The detection engine therefore produces a HIGH-severity alert.

### Detection workflow

    Authentication Events
             |
             v
    Filter Failed Attempts
             |
             v
    Group by Source IP and Username
             |
             v
    Sort by Timestamp
             |
             v
    Evaluate Sliding Time Window
             |
             v
    Compare Against Threshold
             |
             v
    Generate Alert

### Sliding-window algorithm

For each source-IP and username combination:

1. Sort failed authentication events by timestamp.
2. Maintain a left boundary and a right boundary.
3. Move the right boundary through the event sequence.
4. Remove events outside the configured observation window.
5. Count the events remaining inside the window.
6. Generate a detection result when the threshold is reached.

For a group containing `n` events, sorting requires O(n log n) time. The subsequent sliding-window scan requires O(n) time.

The algorithm avoids repeatedly examining every possible event combination.

### Detection limitations

The sample rule is deliberately narrow.

It does not independently identify:

- Distributed attacks involving multiple source addresses.
- Password spraying across many usernames.
- Credential stuffing.
- Successful authentication followed by suspicious activity.
- Attacks spread across multiple observation windows.
- Attempts obscured by shared proxy infrastructure.

A production detection strategy should correlate multiple signals and evaluate false-positive behavior.

## 9. Python Implementation

The Python implementation provides a simulation-oriented SIEM engine.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Immutable event representation |
| `Severity` | Severity classification |
| `EventStore` | Event storage and indexes |
| `SIEMQuery` | Filtering and time-range operations |
| `SIEMAnalytics` | Aggregation and field analysis |
| `load_events()` | NDJSON event ingestion |
| `DetectionEngine` equivalent | Failed-login detection |
| `export_report()` | JSON report persistence |

The query engine uses chained methods to construct filtering operations.

The event store maintains dictionaries indexed by frequently queried fields.

This provides efficient equality lookup without scanning the complete dataset.

The report contains severity distributions, source-IP distributions, timelines, field statistics, and detection results.

### Execution

Run the demonstration:

`python siem_query.py`

Run validation tests:

`python siem_query.py --test`

Load an NDJSON event file:

`python siem_query.py --input security_events.jsonl --output report.json`

Each line in the input file must contain one JSON event with the required event attributes.

The loader validates timestamps and severity classifications before accepting events.

## 10. JavaScript Implementation

The JavaScript implementation emphasizes asynchronous ingestion and event-driven processing.

### Main components

| Component | Responsibility |
|---|---|
| `EventRepository` | Stores events and maintains indexes |
| `EventBus` | Publishes ingestion events |
| `QueryBuilder` | Composes filtering predicates |
| `SIEMAnalytics` | Performs analytical operations |
| `SIEMEngine` | Coordinates ingestion and querying |
| `validateEvent()` | Validates event structure |

### Event-driven processing

The `EventBus` provides a publish-subscribe mechanism.

When an event is ingested, the engine publishes an `event:ingested` notification.

A registered listener examines severity and emits an alert notification for HIGH and CRITICAL events.

This separates ingestion from downstream notification behavior.

The event repository also supports asynchronous batch ingestion.

Batch validation occurs before state mutation, preventing malformed records and duplicate identifiers from causing partial ingestion.

### Execution

`node siem_query.js`

The program generates `siem_report.json` and runs validation tests.

The implementation uses Node.js standard-library modules and does not require npm dependencies.

## 11. C++17 Implementation

The C++ implementation emphasizes efficient in-memory processing and explicit domain modeling.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Event structure |
| `EventRepository` | Event storage and indexes |
| `QueryEngine` | Filtering operations |
| `SIEMAnalytics` | Aggregation and timelines |
| `DetectionEngine` | Sliding-window detection |
| `DetectionAlert` | Structured detection result |

The repository uses STL containers, including:

- `vector` for event storage.
- `set` for identifier uniqueness.
- `unordered_map` for indexed lookups.
- `map` for ordered analytical results.

The query engine uses STL algorithms to remove records that do not satisfy the specified conditions.

The detection engine groups events using a composite key consisting of source IP and username.

### Execution

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic siem_query.cpp -o siem_query`

Execute:

`./siem_query`

The implementation requires no external libraries.

## 12. Java 17 Implementation

The Java implementation provides an enterprise-oriented service structure.

### Main components

| Component | Responsibility |
|---|---|
| `SecurityEvent` | Immutable event record |
| `EventRepository` | Synchronized event ingestion and indexing |
| `Query` | Composable query predicates |
| `AnalyticsService` | Aggregation and field analysis |
| `DetectionService` | Detection-rule execution |
| `ReportingService` | Consolidated report creation |
| `QueryReport` | Immutable reporting structure |

Java records provide concise immutable domain types.

The repository uses synchronized methods for coordinated in-process access.

The query service uses predicates to combine conditions before execution.

The analytics service uses streams and collectors for grouped event calculations.

The reporting service combines query results, distributions, timelines, and detection alerts.

### Execution

Compile:

`javac SIEMQueryEngine.java`

Run:

`java SIEMQueryEngine`

The implementation uses only Java 17 standard-library capabilities.

## 13. PostgreSQL Implementation

The PostgreSQL implementation provides persistent SIEM storage and database-side analytics.

### Relational model

| Table | Purpose |
|---|---|
| `event_sources` | Registers security telemetry sources |
| `security_events` | Stores normalized security events |
| `detection_rules` | Stores detection configuration |
| `security_alerts` | Maintains generated security alerts |

### Database relationships

    event_sources
         |
         | 1:N
         |
    security_events

    detection_rules
         |
         | 1:N
         |
    security_alerts

The event-source registry separates source metadata from individual event records.

The event table references its originating source through a foreign key.

The alert table references its detection rule.

### Data integrity

The schema uses:

- Primary keys for record identity.
- Foreign keys for relational integrity.
- Unique constraints for external event identifiers.
- Check constraints for field validation.
- Enumerated types for severity and alert status.
- Triggers for event-source and timestamp validation.

The ingestion function provides a structured database insertion interface.

### Indexing

Indexes support frequently used investigation patterns.

| Index | Query pattern |
|---|---|
| Timestamp | Time-range retrieval |
| Severity and timestamp | Serious-event investigations |
| Source IP and timestamp | Origin-based investigations |
| Username and timestamp | Account-based investigations |
| Event type and timestamp | Event-category retrieval |
| JSONB GIN | Structured attribute searches |
| Partial authentication index | Failed-login investigation |

Indexes improve selected query patterns but consume storage and increase write costs.

The PostgreSQL optimizer determines whether an index is appropriate for a particular query.

`EXPLAIN (ANALYZE, BUFFERS)` provides execution information for performance investigation.

### SQL analytics

The script demonstrates:

- Conditional filtering.
- Multi-column grouping.
- Distinct-value analysis.
- Five-minute timelines using `date_bin()`.
- JSONB field analysis.
- Window-function-based detection.
- Alert generation.
- Investigation reporting views.
- Transactional alert processing.

### Transaction handling

Alert processing is executed inside a transaction.

This provides a consistent boundary for generating and updating alert records.

The transaction can be rolled back if an operation fails before commit.

## 14. Important Technical Distinctions

Several SIEM concepts are related but should not be treated as interchangeable.

| Concept | Main question answered |
|---|---|
| Filtering | Which events satisfy the conditions? |
| Aggregation | How many events belong to each group? |
| Timeline analysis | When did the events occur? |
| Field analysis | What values and characteristics appear in the data? |
| Correlation | Which events are related? |
| Detection | Does observed activity satisfy a security rule? |
| Alerting | Which detected conditions require investigation? |

A query can return suspicious events without producing an alert.

A detection rule can evaluate a pattern and produce an alert without establishing that an attack has been confirmed.

An alert is an investigation object, not a definitive security conclusion.

## 15. Performance and Scalability

SIEM workloads can involve millions or billions of events. Performance depends on data volume, field cardinality, query selectivity, time-range width, and storage architecture.

### Computational considerations

| Operation | Typical complexity |
|---|---|
| Full event scan | O(n) |
| Indexed equality lookup | Approximately O(1) average index lookup plus matching results |
| Hash-based aggregation | O(n) average |
| Ordered aggregation | O(n log k), where k is the number of distinct groups |
| Timeline bucketing | O(n) average with hash-based buckets |
| Event sorting | O(n log n) |
| Sliding-window detection after sorting | O(n) |

These estimates describe the in-memory algorithms. Actual performance depends on memory allocation, index structures, data distribution, and implementation details.

### Production considerations

- Partition event tables by timestamp when retention and query volume justify it.
- Avoid unnecessarily broad historical queries.
- Use indexed predicates where appropriate.
- Limit high-cardinality grouping operations.
- Prefer columnar or analytical storage for suitable large-scale workloads.
- Use asynchronous ingestion and bounded processing queues.
- Monitor ingestion lag and dropped events.
- Maintain consistent timestamps and event schemas.
- Apply retention and archival policies.
- Measure actual query plans instead of assuming indexes are always beneficial.

The supplied implementations are educational engines rather than distributed SIEM platforms. Their in-memory repositories are not substitutes for persistent, horizontally scalable event storage.

## 16. Security and Data Governance

Security telemetry may contain usernames, internal addresses, system information, and potentially sensitive operational details.

A production implementation should enforce:

1. Authentication and authorization for ingestion and investigation interfaces.
2. Role-based access to security events.
3. Encryption in transit and appropriate encryption at rest.
4. Input validation and controlled query construction.
5. Protection against SQL injection.
6. Restricted access to raw event attributes.
7. Retention and deletion policies.
8. Audit logging for analyst activities.
9. Detection-rule change management.
10. Protection against event duplication and ingestion abuse.

Queries should use parameterized statements rather than constructing SQL from untrusted input.

The Python, JavaScript, C++, and Java implementations use predefined field allowlists to restrict supported query fields.

The PostgreSQL implementation demonstrates relational integrity but does not independently configure production authentication, role permissions, row-level security, or deployment-specific network controls.

## 17. Limitations and Interpretation

The project uses a small deterministic event dataset to demonstrate query and detection mechanisms.

The dataset is not a representative measurement of real enterprise security traffic.

The implementations also have different persistence and concurrency characteristics:

| Implementation | Storage | Processing model |
|---|---|---|
| Python | In-memory | Sequential |
| JavaScript | In-memory | Event-driven and asynchronous interfaces |
| C++17 | In-memory | STL-based processing |
| Java 17 | In-memory | Service-oriented and synchronized repository |
| PostgreSQL | Persistent relational storage | Database-managed transactions and queries |

The in-memory implementations do not provide distributed event collection, durable message delivery, cross-node correlation, or production-grade incident management.

The brute-force rule is intentionally simple. Real deployments require tuning for legitimate authentication patterns, distributed attempts, account context, and false-positive reduction.

The implementations demonstrate the analytical foundations needed to understand SIEM querying without claiming the functionality of a complete commercial SIEM platform.

## 18. Validation Scenarios

The supplied programs include tests for important operational conditions.

| Test case | Expected behavior |
|---|---|
| Ten valid sample events | Successful ingestion |
| Five failed authentication events | Five matching records |
| HIGH and CRITICAL filtering | Six matching records |
| Repeated failures within ten minutes | One detection result |
| Unsupported query field | Validation error |
| Unsupported query operator | Validation error |
| Duplicate event identifier | Rejected event |
| Invalid time interval | Query validation error |
| Empty timeline dataset | Empty analytical result |
| Invalid detection threshold | Configuration error |

The PostgreSQL schema additionally enforces source references, event identifiers, valid severity values, and event-source availability.

These scenarios provide a baseline for checking correctness before extending the implementations to larger event datasets or more advanced detection rules.
