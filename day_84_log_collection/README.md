# Distributed Log Collection and Processing Platform

## 1. System Architecture

Log collection is the process of acquiring operational and security events from distributed infrastructure and making them available in a consistent, searchable, and manageable format.

Applications, operating systems, databases, network devices, cloud services, and security appliances produce logs independently. Their output differs in structure, timestamp representation, severity terminology, transport mechanisms, and delivery reliability.

A centralized collection architecture addresses these differences through collection agents, forwarding components, normalization services, storage destinations, and retention policies.

The implementations in this repository model these components through Python, JavaScript, C++17, Java 17, and PostgreSQL.

### Architecture

```text
+---------------------------+
| Applications              |
| Operating Systems         |
| Databases                 |
| Network Devices           |
| Security Appliances       |
+-------------+-------------+
              |
              v
+---------------------------+
| Collection Agents         |
| Source Adapters           |
| Local Collection          |
| Buffering                 |
+-------------+-------------+
              |
              v
+---------------------------+
| Collection and Ingestion  |
| Raw Event Validation      |
| Source Identification     |
| Duplicate Detection       |
+-------------+-------------+
              |
              v
+---------------------------+
| Normalization             |
| Timestamp Conversion      |
| Severity Mapping          |
| Field Standardization     |
| Sensitive Data Redaction  |
+-------------+-------------+
              |
              v
+---------------------------+
| Forwarding Layer          |
| Queues                    |
| Batching                  |
| Retries                   |
| Backpressure              |
| Dead-Letter Processing    |
+-------------+-------------+
              |
              v
+---------------------------+
| Central Log Destination   |
| Hot Storage               |
| Archive Storage           |
| Search and Reporting      |
+-------------+-------------+
              |
              v
+---------------------------+
| Retention and Monitoring  |
| Expiration                |
| Archival                  |
| Metrics                   |
| Operational Reporting     |
+---------------------------+
```

The principal processing sequence is:

**Collection → Validation → Parsing → Normalization → Deduplication → Forwarding → Storage → Retention**

Each stage has a separate responsibility. A successfully collected event is not necessarily normalized, delivered, or permanently stored.

## 2. Log Collection Fundamentals

### 2.1 Log events

A log event is a record describing an occurrence within a system.

Examples include:

- Successful authentication.
- Failed database connections.
- Application exceptions.
- High CPU utilization.
- Network connection failures.
- Firewall policy violations.
- Configuration changes.
- Privilege escalation attempts.

A useful normalized event contains:

| Field | Purpose |
|---|---|
| Event ID | Identifies an individual event |
| Agent ID | Identifies the collection agent |
| Hostname | Identifies the originating host |
| Environment | Identifies production, development, or another environment |
| Source | Identifies the original log format |
| Event timestamp | Identifies when the occurrence happened |
| Received timestamp | Identifies when the collector received it |
| Severity | Represents event importance |
| Message | Contains the event description |
| Attributes | Contains additional structured information |
| Fingerprint | Supports duplicate detection |
| State | Represents processing progress |

The distinction between event time and received time is important.

A device may generate an event at 10:00 but remain disconnected until 10:15. Its event timestamp remains 10:00, while its received timestamp is 10:15.

Replacing the event timestamp with the collection timestamp destroys information about the original occurrence.

### 2.2 Collection agents

A collection agent is a software component operating near the system that generates logs.

Its responsibilities can include:

- Reading application log files.
- Receiving operating-system events.
- Collecting structured application output.
- Monitoring file changes.
- Maintaining local buffers.
- Sending events to central collectors.
- Reporting agent health.
- Managing connection failures.

An agent may operate as a service, daemon, container, or embedded component.

A production agent should support persistent checkpoints so that restarting the process does not cause previously collected data to be silently skipped.

For file-based collection, checkpoints should normally track file identity and byte offset rather than filename alone. Log rotation can replace a file while preserving its original name.

Important collection conditions include:

- File truncation.
- Log rotation.
- Temporary disconnection.
- Permission failures.
- Agent restarts.
- Duplicate file reads.
- Oversized records.
- Missing source files.

Agent health should be monitored independently of event volume. An agent that sends no events may be idle, disconnected, disabled, or malfunctioning.

### 2.3 Collection versus forwarding

Collection and forwarding are separate operations.

Collection acquires an event from its original source. Forwarding transports an accepted event to a downstream destination.

A collector can successfully acquire an event while forwarding fails because the destination is unavailable.

This distinction justifies separate processing states, metrics, and error handling.

## 3. Log Formats and Parsing

### 3.1 Structured JSON logs

JSON logs represent events as key-value objects.

A representative event contains:

| Field | Example |
|---|---|
| timestamp | `2026-11-23T04:00:00Z` |
| severity | `ERROR` |
| message | `Database connection failed` |
| service | `payments` |
| environment | `production` |

Advantages include:

- Explicit field names.
- Structured attributes.
- Easier schema validation.
- Better filtering.
- Compatibility with database JSON columns.
- Reduced dependence on message-text parsing.

JSON parsing should reject malformed input, unsupported structures, and missing required fields.

A production implementation should use a complete standards-compliant parser, enforce maximum nesting depth, and reject duplicate object keys where ambiguity could affect security or processing.

### 3.2 Syslog

Syslog is a widely used logging mechanism for network devices, operating systems, and infrastructure components.

The RFC 5424 message structure includes:

- Priority.
- Version.
- Timestamp.
- Hostname.
- Application name.
- Process identifier.
- Message identifier.
- Structured data.
- Message content.

The priority field combines facility and severity.

The relationship is:

`Priority = Facility × 8 + Severity`

Therefore:

`Facility = Priority / 8`

`Severity = Priority % 8`

The severity values are:

| Syslog value | Meaning |
|---|---|
| 0 | Emergency |
| 1 | Alert |
| 2 | Critical |
| 3 | Error |
| 4 | Warning |
| 5 | Notice |
| 6 | Informational |
| 7 | Debug |

The implementations demonstrate simplified RFC 5424-style parsing. Full production support must also handle structured data, escaping, transport framing, and protocol-specific constraints.

### 3.3 Parsing failures

Parsing should be treated as a distinct processing stage.

Common failures include:

- Malformed JSON.
- Invalid Syslog priority.
- Missing timestamp.
- Unknown severity.
- Invalid character encoding.
- Oversized messages.
- Unsupported source format.

Invalid events should be recorded in a rejection or quarantine mechanism with sufficient metadata for investigation.

They should not be silently converted into valid-looking records.

## 4. Timestamp Normalization

Distributed systems frequently operate in different time zones.

A database server may produce UTC timestamps, an application may use Indian Standard Time, and a network device may use another regional timezone.

Without normalization, chronological analysis becomes unreliable.

### 4.1 UTC normalization

UTC provides a common reference for distributed event ordering.

For example:

| Original timestamp | UTC timestamp |
|---|---|
| `2026-11-23T09:30:00+05:30` | `2026-11-23T04:00:00Z` |
| `2026-11-23T05:00:00+01:00` | `2026-11-23T04:00:00Z` |
| `2026-11-23T04:00:00Z` | `2026-11-23T04:00:00Z` |

The three timestamps represent the same instant.

The Python implementation uses timezone-aware `datetime` objects.

The JavaScript implementation converts timestamps into ISO-formatted UTC strings.

The C++ implementation converts explicit ISO-8601 offsets into UTC.

The Java implementation uses `Instant` and `OffsetDateTime`.

PostgreSQL stores normalized timestamps using `TIMESTAMPTZ`.

### 4.2 Event time and ingestion time

Two timestamps should normally be maintained:

- **Event time:** When the originating system generated the event.
- **Ingestion time:** When the collection platform received it.

Their difference represents ingestion delay:

`Ingestion Delay = Ingestion Time - Event Time`

This measurement helps identify network congestion, agent buffering, delayed forwarding, and clock problems.

### 4.3 Clock synchronization

UTC normalization does not automatically guarantee accurate event ordering.

The source system may have an incorrect clock.

Production infrastructure should use reliable clock synchronization and monitor clock drift.

Events with future timestamps should be investigated rather than automatically discarded. Delayed events and clock errors require different handling.

A naive timestamp without a timezone also introduces ambiguity. The Python demonstration interprets such timestamps as UTC by policy, while the Java implementation requires an explicit timezone.

For strict production deployments, rejecting timezone-free timestamps is generally safer.

## 5. Severity Normalization

Applications use different terminology for event importance.

One application may use `WARN`, another may use `WARNING`, and another may use numeric severity values.

Severity normalization converts these source-specific values into a common classification.

| Normalized level | Priority | Typical interpretation |
|---|---:|---|
| DEBUG | 10 | Diagnostic information |
| INFO | 20 | Normal operational activity |
| WARNING | 30 | Unexpected but potentially recoverable condition |
| ERROR | 40 | Failed operation |
| CRITICAL | 50 | Severe operational or security condition |

Normalization supports consistent filtering, reporting, alerting, and operational analysis.

Severity must not be confused with certainty or business impact.

A source may label an event as critical even when its actual operational impact is limited. A centralized platform should preserve original severity information where required and avoid assuming that every source uses identical classification policies.

## 6. Field Normalization and Sensitive Data Protection

### 6.1 Standardized fields

Normalization converts different source structures into a common event representation.

For example, source-specific host fields may be represented as:

- `host`
- `hostname`
- `server`
- `machine`

The normalized representation uses one canonical field: `hostname`.

Source-specific fields can remain in the attributes object.

This approach separates standardized platform fields from application-specific information.

### 6.2 Structured attributes

Attributes contain additional event information without requiring every application to follow an identical schema.

Examples include:

- Service name.
- Process identifier.
- Network address.
- Request identifier.
- Database operation.
- Deployment version.

PostgreSQL uses `JSONB` to store structured attributes and provides a GIN index for efficient containment queries.

### 6.3 Redaction

Logs can accidentally contain:

- Passwords.
- Authentication tokens.
- API keys.
- Email addresses.
- Payment card numbers.
- Personal information.

The implementations demonstrate basic credential and personal-data redaction.

Redaction should happen before data reaches an unrestricted central destination.

Pattern-based redaction is not a complete data-loss-prevention system. It can miss encoded secrets, nested credentials, unusual formats, and sensitive information embedded in arbitrary messages.

Production systems should combine field-level allowlists, structured secret detection, access controls, encryption, and audit logging.

Redaction rules should also be tested against legitimate operational messages to prevent excessive removal of useful diagnostic information.

## 7. Log Forwarding

Forwarding transports normalized events from collectors to centralized storage or analytical destinations.

A forwarding system must handle variable event volume, network interruptions, destination failures, and delivery delays.

### 7.1 Forwarding architecture

The typical workflow is:

1. The collector accepts a normalized event.
2. The event enters a bounded queue.
3. The forwarding service groups events into batches.
4. A batch is sent to a destination.
5. Successful delivery is acknowledged.
6. Failed deliveries are retried.
7. Events exceeding the retry policy enter a dead-letter mechanism.

### 7.2 Batching

Batching combines multiple events into a single delivery operation.

If a destination receives 1,000 individual requests, the transport and connection overhead can become significant.

Batching reduces this overhead.

The trade-off is that larger batches require more memory and may increase delivery latency.

A production forwarding configuration should consider:

- Maximum batch size.
- Maximum batch bytes.
- Maximum batch waiting time.
- Destination timeout.
- Maximum queue size.
- Retry limits.
- Destination throughput.

The implementations use configurable record-count batch sizes.

A production implementation should also enforce byte-based limits because ten large events can consume substantially more memory than ten small events.

### 7.3 Asynchronous forwarding

The JavaScript and Java implementations use asynchronous execution.

This separates event acquisition from downstream delivery.

Asynchronous forwarding can improve throughput when destination operations involve network waiting.

It also introduces concurrency concerns.

A production system must control:

- Concurrent batch operations.
- Queue access.
- Delivery ordering.
- Shutdown behavior.
- Memory pressure.
- Duplicate delivery.

The C++ implementation uses a bounded in-memory queue and a synchronous destination interface to emphasize resource management and deterministic state transitions.

### 7.4 Retry mechanisms

Temporary failures include:

- Network interruptions.
- Destination timeouts.
- Temporary server unavailability.
- Connection resets.
- Rate limiting.

Exponential backoff increases the delay between repeated attempts.

A common strategy is:

`Delay = min(Initial Delay × 2^Attempt, Maximum Delay)`

Jitter should be added in distributed production systems to prevent many agents from retrying simultaneously.

Retries should distinguish temporary failures from permanent failures.

For example, a temporary service outage may justify another attempt, while an invalid destination configuration requires administrative correction.

### 7.5 At-least-once and exactly-once delivery

These concepts describe delivery guarantees.

**At-most-once delivery**

An event is transmitted zero or one times. Failures may cause data loss.

**At-least-once delivery**

An event is retried until acknowledgement or an operational limit is reached. Duplicate delivery is possible.

**Exactly-once effects**

The receiving system ensures that repeated delivery attempts do not produce repeated logical records.

This is commonly implemented through idempotent writes and stable event identifiers.

A network acknowledgement can be lost after the destination has already stored an event. The sender may then retry a successfully processed event.

The destination must therefore support deduplication.

The Python, JavaScript, and Java implementations use deterministic fingerprints to demonstrate idempotent destination insertion.

The C++ implementation uses a deterministic FNV-1a fingerprint for demonstration and explicitly distinguishes it from a production cryptographic hash.

A hash-based deduplication mechanism should use a stable identity definition and a collision-resistant hash when security or data integrity requires it.

An in-memory deduplication set does not provide durable deduplication across restarts.

## 8. Backpressure and Queue Management

Backpressure occurs when events arrive faster than the forwarding destination can process them.

Without queue limits, a continuously unavailable destination can cause unbounded memory consumption.

A bounded queue establishes an explicit capacity.

When capacity is reached, the collection platform must apply a defined policy.

Possible strategies include:

- Pause collection where the source supports it.
- Persist events locally.
- Apply source-level rate limiting.
- Reject lower-priority events under an approved policy.
- Increase forwarding capacity.
- Generate an operational alert.

Dropping security events without recording the loss is particularly dangerous.

The implementations reject additional events when their in-memory forwarding queues are full.

Production deployments should use durable disk-backed buffering when loss prevention is required.

A bounded in-memory queue protects memory but does not guarantee event survival after a process crash.

## 9. Dead-Letter Processing

A dead-letter queue stores events that cannot be delivered after the configured retry policy.

Its purpose is to preserve failed records for investigation and controlled replay.

Typical failure categories include:

- Destination unavailable.
- Invalid destination configuration.
- Repeated transport failures.
- Rejected payload.
- Destination-side validation failure.

Dead-letter records should preserve:

- Original event identity.
- Destination identity.
- Failure reason.
- Attempt count.
- Last attempted time.
- Replay history.

Replay must preserve idempotency.

The JavaScript, Python, C++, and Java implementations demonstrate dead-letter storage and replay behavior.

The PostgreSQL implementation stores dead-letter metadata separately from normalized events.

Production replay systems should also provide operator authorization, replay limits, audit records, and protection against infinite retry loops.

## 10. Retention and Archival

Log retention determines how long collected records remain available in a particular storage tier.

Retention is influenced by:

- Operational requirements.
- Security monitoring.
- Investigation requirements.
- Storage capacity.
- Data protection obligations.
- Organizational policy.

### 10.1 Hot retention

Hot storage contains relatively recent records optimized for frequent retrieval and investigation.

Example: 30 days.

### 10.2 Archive retention

Archived records are maintained for longer periods, generally with lower retrieval frequency.

Example: 90 days or 365 days.

### 10.3 Expiration

Events older than the configured archive period are removed according to the applicable retention policy.

The processing model is:

| Event age | Action |
|---|---|
| Within hot retention | Keep in active storage |
| Beyond hot retention | Move to archive |
| Beyond archive retention | Delete |
| Future-dated event | Retain for investigation |

The distinction between archival and deletion is essential.

Moving a record to archive does not mean that its retention obligation has ended.

### 10.4 Retention policy evaluation

The Python and JavaScript implementations use configurable hot and archive periods.

The C++ implementation uses duration-based policy objects.

The Java implementation models retention as an immutable policy record.

PostgreSQL stores policies in `retention_policies` and processes events through a stored procedure.

Different environments can have different retention requirements.

For example:

| Environment | Hot retention | Archive retention |
|---|---:|---:|
| Development | 7 days | 30 days |
| Production | 30 days | 365 days |
| Security | 90 days | 730 days |

These are demonstration policies rather than universal compliance requirements.

### 10.5 Database retention considerations

Large log tables require special attention.

Deleting millions of rows in one transaction can cause:

- Long-running locks.
- Excessive WAL generation.
- Increased replication lag.
- Table bloat.
- Storage pressure.

A production PostgreSQL design should consider time-based partitioning.

Partitions can be detached, archived, or dropped when their retention periods expire.

Partitioning also helps limit query scans when timestamp predicates align with partition boundaries.

Retention execution should be monitored and audited.

## 11. Python Implementation

### File

`log_collection.py`

### Design

The Python implementation models the entire collection lifecycle through separate classes.

| Component | Responsibility |
|---|---|
| `AgentConfig` | Agent configuration and validation |
| `LogRecord` | Structured event representation |
| `TimestampNormalizer` | UTC timestamp conversion |
| `SeverityNormalizer` | Severity classification |
| `LogParser` | JSON and Syslog parsing |
| `SensitiveDataRedactor` | Basic sensitive-data removal |
| `LogNormalizer` | Canonical event creation |
| `MemoryLogSink` | Idempotent demonstration destination |
| `ForwardingAgent` | Bounded queue and retry |
| `RetentionManager` | Archival and expiration |
| `LogCollectionPipeline` | End-to-end orchestration |

### Important implementation decisions

**Dataclasses**

Dataclasses provide structured event and agent representations without requiring manually implemented constructors.

**Enums**

Severity and processing states use enums to prevent inconsistent string values.

**Protocol**

`LogSink` defines a destination interface. Different destination implementations can follow the same contract.

**Deque**

The forwarding queue uses `collections.deque` for efficient insertion and removal from opposite ends.

**Counter**

Operational metrics are maintained separately from event data.

**SHA-256**

The event fingerprint provides deterministic duplicate identification.

**Assertions**

The demonstration validates collection counts, destination delivery, duplicate detection, dead-letter handling, and retention.

### Execution

Run the script using Python 3.10 or later:

`python log_collection.py`

No third-party packages are required.

### Important limitation

The demonstration destination is in-memory. A production deployment should implement a durable destination and persistent queue.

## 12. JavaScript Implementation

### File

`log_collection.js`

### Design

The JavaScript implementation emphasizes event-driven processing and asynchronous delivery.

| Component | Responsibility |
|---|---|
| `AgentRegistry` | Agent lifecycle |
| `TimestampService` | Timestamp conversion |
| `LogParser` | Source-specific parsing |
| `NormalizationService` | Event normalization |
| `RedactionService` | Sensitive-data handling |
| `Metrics` | Operational counters |
| `MemoryDestination` | Idempotent destination |
| `ForwardingService` | Asynchronous batch delivery |
| `RetentionService` | Time-based lifecycle |
| `LogCollectionSystem` | Pipeline coordination |

### JavaScript-specific mechanisms

**EventEmitter**

The forwarding service emits events such as:

- `queued`
- `delivered`
- `deliveryError`

The collection system also emits collection and rejection events.

This allows monitoring components to subscribe without directly modifying the collection logic.

**Promises**

Destination operations return promises.

The forwarding service awaits delivery and retry completion.

**Private class fields**

The agent registry and destination maintain private internal state.

This prevents external code from modifying their internal maps directly.

**Maps and Sets**

Maps maintain agent and destination records. Sets maintain fingerprints for duplicate detection.

**Async processing**

The `flush()` method handles asynchronous delivery while preventing overlapping flush operations.

### Execution

Run using Node.js 18 or later:

`node log_collection.js`

No npm dependencies are required.

### Important limitation

The event queue and destination are memory-based.

A production implementation requires durable buffering, controlled concurrency, network timeouts, and a persistent destination.

## 13. C++17 Implementation

### File

`log_collection.cpp`

### Design

The C++ implementation emphasizes explicit domain modeling, resource limits, deterministic processing, and strongly typed state.

| Component | Responsibility |
|---|---|
| `Agent` | Collection configuration |
| `LogEvent` | Event representation |
| `TimestampNormalizer` | UTC conversion |
| `SeverityNormalizer` | Severity mapping |
| `LogParser` | JSON-style and Syslog parsing |
| `LogDestination` | Destination abstraction |
| `MemoryDestination` | Idempotent storage |
| `ForwardingEngine` | Queue, batches, and retries |
| `RetentionEngine` | Event archival and expiration |
| `LogCollectionSystem` | Pipeline orchestration |

### C++17-specific mechanisms

**Strongly typed enums**

Processing states and severity levels are represented using enums.

This avoids accidental assignment of unrelated string values.

**STL containers**

- `vector` stores event collections and batches.
- `unordered_map` maintains agents and destination records.
- `unordered_set` maintains event fingerprints.
- `map` maintains ordered reporting output.

**Smart pointers**

`shared_ptr` manages destination lifetime without manual memory management.

**Virtual interfaces**

`LogDestination` defines an interchangeable destination contract.

**Exception handling**

Validation and delivery failures are represented through specific exception classes.

### Compilation

Using GCC:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic log_collection.cpp -o log_collection`

Execute:

`./log_collection`

### Important implementation limitations

The JSON parser is deliberately restricted to the demonstration input structure. It is not a complete JSON implementation.

The fingerprint uses FNV-1a to demonstrate deterministic identity generation. It is not a cryptographic integrity mechanism.

The timestamp conversion uses the platform C runtime and should be replaced with a timezone-database-aware implementation for broader production requirements.

The in-memory forwarding queue is not crash durable.

## 14. Java 17 Implementation

### File

`Main.java`

### Design

The Java implementation uses an enterprise-oriented domain and service architecture.

| Component | Responsibility |
|---|---|
| `Agent` | Immutable agent configuration |
| `ParsedLog` | Parsed source record |
| `LogRecord` | Immutable normalized event |
| `TimestampPolicy` | Timestamp validation |
| `SeverityPolicy` | Severity normalization |
| `RedactionPolicy` | Sensitive-data handling |
| `JsonAdapter` | JSON-style input |
| `SyslogAdapter` | Syslog input |
| `AgentRegistry` | Agent lifecycle |
| `NormalizationService` | Canonical event generation |
| `FingerprintService` | Deterministic event identity |
| `ForwardingPolicy` | Queue and retry configuration |
| `ForwardingService` | Asynchronous forwarding |
| `RetentionPolicy` | Immutable retention configuration |
| `RetentionService` | Retention evaluation |
| `CollectionService` | End-to-end orchestration |

### Enterprise engineering decisions

**Records**

Java records represent immutable domain objects and policy configurations.

**Interfaces**

`CollectionAdapter` supports separate input formats without requiring changes to the normalization service.

`LogDestination` abstracts the downstream destination.

**CompletableFuture**

Asynchronous destination delivery is represented through `CompletableFuture`.

**ExecutorService**

A bounded thread pool controls forwarding execution.

**ConcurrentHashMap**

The demonstration destination uses concurrent storage.

**Immutable collections**

Normalized attributes and exposed collections are protected from accidental modification.

**Custom exceptions**

Collection, validation, and forwarding failures are represented using separate exception types.

### Execution

Compile:

`javac Main.java`

Run:

`java Main`

Requires Java 17.

### Important limitation

The JSON adapter is intentionally restricted to flat demonstration objects. Enterprise ingestion should use a complete JSON parser and explicit schema validation.

The destination is an in-memory implementation, not a persistent distributed storage system.

## 15. PostgreSQL Database Design

### File

`log_collection.sql`

### Relational architecture

The database models the relationships between agents, collection batches, raw events, normalized events, destinations, delivery attempts, dead-letter records, retention policies, and archived events.

| Table | Purpose |
|---|---|
| `collection_agents` | Registered collection agents |
| `collection_batches` | Agent-level ingestion batches |
| `log_destinations` | Configured downstream destinations |
| `raw_log_events` | Original collected payloads |
| `normalized_log_events` | Standardized events |
| `retention_policies` | Environment-specific retention rules |
| `archived_log_events` | Historical event records |
| `delivery_attempts` | Forwarding history |
| `dead_letter_events` | Permanently failed deliveries |
| `collection_metrics` | Operational measurements |

### Relationship model

```text
COLLECTION_AGENTS
       |
       +----------------------+
       |                      |
       v                      v
COLLECTION_BATCHES      RAW_LOG_EVENTS
                              |
                              v
                      NORMALIZED_LOG_EVENTS
                              |
                   +-----------+-----------+
                   |                       |
                   v                       v
           DELIVERY_ATTEMPTS       ARCHIVED_LOG_EVENTS
                  |
                  v
           LOG_DESTINATIONS
                  |
                  v
           DEAD_LETTER_EVENTS

RETENTION_POLICIES
       |
       v
ENVIRONMENT-SPECIFIC EVENT LIFECYCLE
```

### Constraints

The database uses:

- Primary keys for entity identity.
- Foreign keys for referential integrity.
- Unique constraints for agent names and event fingerprints.
- Check constraints for valid counts and retention periods.
- JSONB validation for structured attributes.
- Enumerated types for lifecycle states.

These constraints prevent invalid records from entering the relational model.

### Indexing strategy

The implementation includes indexes for:

- Agent status.
- Environment.
- Event timestamps.
- Agent and timestamp combinations.
- Severity and timestamp combinations.
- Forwarding queues.
- Pending delivery attempts.
- JSONB attributes.
- Full-text message searches.

Index selection should be based on actual query patterns.

Indexes improve retrieval but increase storage requirements and write overhead.

### Functions

The SQL functions implement:

- Timestamp normalization.
- Severity normalization.
- Sensitive-data redaction.
- Normalized-event insertion.
- Forwarding eligibility.

### Procedures

The procedures implement:

- Delivery-attempt processing.
- Dead-letter creation.
- Retention execution.

### Triggers

Triggers enforce event validation and update batch counters.

### Transactions

The sample SQL demonstrates transaction boundaries.

The retention demonstration uses a savepoint and rollback so that the sample data remains available after testing the procedure.

The forwarding workflow records delivery attempts and updates event state within database transactions.

A real distributed destination cannot participate in an ordinary PostgreSQL transaction unless a distributed transaction protocol is explicitly implemented. Database state changes and remote delivery therefore require an outbox, acknowledgement, and idempotency strategy.

### PostgreSQL extensions

The script uses:

- `pgcrypto` for SHA-256 fingerprint generation.
- PostgreSQL JSONB operations.
- Full-text search.
- Identity columns.
- Stored procedures.
- Triggers.

The `pgcrypto` extension must be available and installed before executing the sample ingestion section.

## 16. Collection State Management

An event passes through several processing states.

| State | Meaning |
|---|---|
| COLLECTED | Acquired from the source |
| NORMALIZED | Parsed and standardized |
| QUEUED | Accepted for forwarding |
| FORWARDED | Destination acknowledged delivery |
| FAILED | Delivery exhausted its retry policy |
| ARCHIVED | Moved out of active storage |

The state transition model is:

```text
COLLECTED
    |
    v
NORMALIZED
    |
    v
QUEUED
    |
    +--------------------+
    |                    |
    v                    v
FORWARDED              RETRYING
                         |
                         v
                       FAILED
                         |
                         v
                     DEAD LETTER

FORWARDED
    |
    v
RETENTION EVALUATION
    |
    +-------------------+
    |                   |
    v                   v
ACTIVE STORAGE       ARCHIVED
                        |
                        v
                      EXPIRED
                        |
                        v
                      DELETED
```

A processing state describes the operational progress of an event.

It does not independently prove that the event exists in durable storage.

For example, a forwarding service may mark an event as delivered after receiving an acknowledgement, but the destination may still require replication or archival before the record meets a separate durability requirement.

## 17. Reliability and Failure Analysis

| Failure | Potential impact | Appropriate control |
|---|---|---|
| Agent unavailable | Missing events | Heartbeats and health monitoring |
| Source file rotation | Lost or repeated records | File identity and offset checkpoints |
| Malformed event | Normalization failure | Validation and quarantine |
| Invalid timestamp | Incorrect chronology | Strict timestamp validation |
| Clock drift | Misordered events | Clock synchronization and drift monitoring |
| Network outage | Delivery delay | Durable buffering and retry |
| Destination outage | Queue growth | Backpressure and capacity monitoring |
| Queue overflow | Event loss risk | Persistent buffering and controlled admission |
| Duplicate delivery | Repeated records | Idempotency and deduplication |
| Permanent destination rejection | Undelivered events | Dead-letter processing |
| Excessive retention | Storage exhaustion | Automated retention enforcement |
| Incorrect redaction | Sensitive-data exposure | Security testing and structured redaction |
| Excessive indexing | Increased write overhead | Query-driven index selection |

### Reliability measurements

A production platform should track:

**Collection rate**

`Accepted Events / Unit of Time`

**Forwarding success rate**

`Successful Deliveries / Total Delivery Attempts × 100`

**Ingestion delay**

`Received Timestamp - Event Timestamp`

**Queue depth**

Number of events waiting for delivery.

**Dead-letter rate**

`Dead-Lettered Events / Total Forwarding Events × 100`

**Agent availability**

Percentage of monitored time during which the agent reports a healthy state.

These measurements help distinguish source problems, collection bottlenecks, network failures, and destination performance issues.

## 18. Security Considerations

Log collection systems can become high-value targets because they aggregate information from multiple infrastructure components.

Important security controls include:

- Mutual TLS for agent-to-collector communication.
- Authentication of collection agents.
- Authorization for destination access.
- Encryption at rest.
- Secure storage of destination credentials.
- Credential redaction.
- Restricted access to archived logs.
- Audit records for administrative actions.
- Protection against oversized or malformed events.
- Network segmentation.
- Agent identity and certificate lifecycle management.
- Rate limiting.
- Integrity verification.

Log messages must be treated as untrusted input.

An attacker may attempt to inject fake timestamps, manipulate structured fields, generate excessively large events, or insert terminal control characters into messages.

Collection systems should sanitize data at display boundaries and use parameterized database operations.

Raw payloads should have controlled access because normalization and redaction may not remove every sensitive value.

Retention and deletion must also account for replicas, backups, exports, and downstream copies.

## 19. Performance and Scalability

A distributed log platform must support event volume that can vary significantly over time.

### Collection performance

Agents should minimize unnecessary parsing, memory allocation, and repeated file reads.

File-based collectors should maintain reliable checkpoints and use efficient incremental reading.

### Forwarding performance

Batching reduces transport overhead.

Bounded queues control memory consumption.

Concurrent forwarding improves throughput when the destination supports parallel ingestion.

### Storage performance

Time-based indexes and partitioning support chronological retrieval.

JSONB indexes help with structured attribute queries.

Full-text indexes support message searches.

High-volume systems should evaluate partition pruning, write amplification, index maintenance, and archival throughput.

### Horizontal scaling

Collection and forwarding components can be distributed across multiple workers.

A scalable architecture should consider:

- Agent assignment.
- Collector load balancing.
- Destination partitioning.
- Stable event identity.
- Delivery ordering requirements.
- Shared deduplication.
- Persistent buffering.
- Backpressure propagation.

An in-memory deduplication set is insufficient when multiple independent collectors process the same event.

Distributed deduplication requires shared state or destination-side idempotency.

## 20. Cross-Language Implementation Comparison

| Engineering concern | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Domain modeling | Dataclasses | Classes and objects | Structs and classes | Records and classes | Relational tables |
| Source parsing | Parser class | Adapter logic | Parsing functions | Adapter interface | SQL validation |
| Timestamp handling | `datetime` | `Date` | `chrono` and runtime conversion | `Instant` | `TIMESTAMPTZ` |
| State management | Enums | String states | Enums | Enums | Enum types |
| Deduplication | Set | Set | Unordered set | Hash set | Unique index |
| Forwarding | Bounded deque | Async queue | Vector-based queue | ArrayDeque | Delivery tables |
| Retry | Bounded attempts | Promise-based retry | Bounded retry | CompletableFuture | Delivery procedure |
| Failure handling | Exceptions | Rejected promises | Exceptions | Custom exceptions | Transactions |
| Retention | Timedelta | Milliseconds | Duration | Duration | Stored procedure |
| Reporting | Counter | Metrics map | STL maps | Collections | Views and aggregates |

The implementations use different engineering approaches while representing the same fundamental processing lifecycle.

## 21. Limitations and Production Boundaries

The source files are executable demonstrations of a distributed collection pipeline. They are not complete replacements for production-grade log infrastructure.

The principal limitations are:

1. Collection agents do not continuously monitor operating-system files or native event APIs.
2. The forwarding destinations are in-memory demonstration implementations.
3. Persistent local buffering is not implemented.
4. The JSON parsers in C++17 and Java 17 support restricted demonstration formats.
5. The C++ timestamp implementation has platform-specific timezone limitations.
6. The demonstration redaction rules do not guarantee complete sensitive-data detection.
7. The SQL delivery procedure models database-side delivery state, not an actual network transport.
8. Durable distributed deduplication requires shared persistent state.
9. Retention execution in a high-volume production database requires partition-aware processing.
10. Exactly-once delivery cannot be guaranteed by retries alone.

The most important architectural distinction is between acquiring an event, transforming it, transporting it, and retaining it.

Each operation has different failure conditions and must be monitored independently.
```
