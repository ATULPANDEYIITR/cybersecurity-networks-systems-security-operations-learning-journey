# IOC Investigation and Threat Intelligence Analysis

## 1. Domain Overview

An Indicator of Compromise (IOC) is an observable artifact associated with potentially malicious activity. Security teams use IOCs to identify suspicious infrastructure, malicious files, unauthorized persistence mechanisms, and other evidence of compromise.

IOC investigation involves collecting indicators, validating their structure, recording their intelligence provenance, correlating them with observed security events, assessing their reliability, and managing resulting investigations.

An IOC match is evidence of a relationship between an observed artifact and a known indicator. It is not, by itself, proof that a system has been compromised.

This project implements a threat intelligence correlation and investigation workflow across Python, JavaScript, C++17, Java 17, and PostgreSQL.

## 2. IOC Categories

Six indicator categories are implemented.

| Category | Description | Example |
|---|---|---|
| IP address | IPv4 or IPv6 network endpoint | `203.0.113.45` |
| Domain | Fully qualified domain name | `malware.example` |
| Hash | Cryptographic file fingerprint | SHA-256 hexadecimal digest |
| URL | HTTP or HTTPS resource identifier | `https://malware.example/payload` |
| Filename | File artifact observed on an endpoint | `suspicious.exe` |
| Registry indicator | Windows registry location associated with suspicious behavior | `HKLM\Software\BadActor\Persistence` |

The examples use documentation IP ranges and reserved example domains. They are illustrative indicators, not operational threat infrastructure.

### 2.1 IP Addresses

IP indicators identify network endpoints involved in suspicious communications.

IPv4 addresses contain four decimal octets. Each octet must be within the range 0 to 255.

IPv6 addresses use hexadecimal groups and support compressed representations.

An IP match may indicate communication with a suspicious endpoint. Context such as destination port, connection direction, timestamp, and network policy is necessary to determine its significance.

An IP address may be shared by legitimate and malicious services, particularly when cloud hosting and content delivery networks are involved.

### 2.2 Domains

Domain indicators identify suspicious DNS names.

Normalization converts domain names to lowercase, removes a trailing root dot, and validates domain-label structure.

A domain match can identify DNS queries, proxy requests, or other observations involving a known suspicious domain.

Domain indicators should not automatically be treated as equivalent to all their subdomains. Exact matching and suffix matching are different detection policies.

### 2.3 Cryptographic Hashes

Hashes identify file content through a fixed-length digest.

| Algorithm | Digest length | Hexadecimal characters |
|---|---:|---:|
| MD5 | 128 bits | 32 |
| SHA-1 | 160 bits | 40 |
| SHA-256 | 256 bits | 64 |

The implementations validate supported hexadecimal lengths.

Python and JavaScript also demonstrate streaming file hashing. Streaming avoids loading an entire file into memory.

MD5 and SHA-1 are retained for compatibility with existing intelligence feeds. SHA-256 is preferred for stronger file identification.

A hash match identifies identical content under the selected algorithm. It does not establish the execution status or behavior of a file.

### 2.4 URLs

URL indicators identify suspicious web resources.

Normalization considers:

- URL scheme
- Hostname
- Port
- Path
- Query string
- Fragment

Only HTTP and HTTPS schemes are accepted.

Credential-bearing URLs are rejected to prevent sensitive information from entering the indicator database.

URL matching requires an explicit normalization policy. Matching an entire URL is different from matching only its hostname or path.

Fragments are removed because they are generally not transmitted in HTTP requests.

### 2.5 Filenames

Filename indicators identify suspicious file artifacts.

A filename alone has limited evidentiary value because different files can share the same name.

A stronger investigation combines filename observations with:

- Cryptographic hashes
- File paths
- Digital signatures
- File creation timestamps
- Endpoint identity
- Process execution evidence

The implementations normalize filename case and reject path separators.

### 2.6 Registry Indicators

Registry indicators identify Windows registry keys associated with suspicious configuration or persistence.

Common registry roots include:

| Long registry root | Normalized root |
|---|---|
| `HKEY_LOCAL_MACHINE` | `HKLM` |
| `HKEY_CURRENT_USER` | `HKCU` |
| `HKEY_CLASSES_ROOT` | `HKCR` |
| `HKEY_USERS` | `HKU` |

Registry locations can provide evidence of persistence, configuration modification, or unauthorized system changes.

A registry-key match does not establish that a malicious value exists or that the associated mechanism executed successfully. Value names, data, modification timestamps, and process context may be required.

## 3. IOC Normalization and Validation

Normalization ensures that equivalent indicator representations can be compared consistently.

Examples:

| Original value | Normalized value |
|---|---|
| `MALWARE.EXAMPLE.` | `malware.example` |
| Uppercase SHA-256 | Lowercase SHA-256 |
| `HKEY_LOCAL_MACHINE\Software\Test` | `hklm\software\test` |
| Uppercase filename | Lowercase filename |

Validation rejects malformed indicators before registration or event correlation.

The implementations enforce:

- Supported IOC categories
- Maximum input lengths
- Valid hash lengths and hexadecimal characters
- IP address structure
- Domain-label boundaries
- Permitted URL schemes
- Filename restrictions
- Supported Windows registry roots
- Valid confidence ranges
- Valid timestamps

Normalization must be consistent between intelligence ingestion and event ingestion.

A mismatch between the two processes can cause false negatives even when the underlying indicator is correct.

The implementations use different validation mechanisms according to their programming environments. Python uses the `ipaddress` module, JavaScript uses Node.js networking capabilities, C++ uses standard-library validation, and Java uses standard networking and domain-name utilities.

The PostgreSQL implementation centralizes normalization in a database function used by generated columns.

## 4. Threat Intelligence Provenance

An IOC should retain its origin rather than being stored as an isolated string.

The project models threat intelligence provenance through:

- Source organization
- Threat intelligence feed
- Feed reference
- Reliability score
- Confidence score
- Severity
- Tags
- Description
- Registration timestamp
- Expiration timestamp

### 4.1 Source Reliability

Source reliability describes the historical trustworthiness of an intelligence provider.

It is distinct from IOC confidence.

### 4.2 Confidence

Confidence represents the assessed likelihood that an indicator correctly identifies suspicious activity.

The project uses a scale from 0 to 100.

| Confidence | Interpretation |
|---|---|
| 0–39 | Low confidence |
| 40–69 | Moderate confidence |
| 70–89 | High confidence |
| 90–100 | Very high confidence |

These ranges provide an illustrative classification rather than a universal threat intelligence standard.

### 4.3 Severity

Severity represents the potential significance of an indicator match.

| Severity | Interpretation |
|---|---|
| Low | Limited investigative significance |
| Medium | Requires contextual examination |
| High | Significant suspicious activity |
| Critical | Potentially severe security impact |

Confidence and severity must remain separate.

A high-severity indicator with low confidence requires different handling from a high-confidence critical indicator.

### 4.4 Expiration

Indicators can expire because threat infrastructure changes, malicious domains are decommissioned, and intelligence becomes outdated.

An indicator is considered usable only when:

- Its active state is true.
- Its expiration timestamp has not passed.
- It satisfies the applicable confidence policy.

Expiration should be evaluated at detection time rather than relying exclusively on periodic cleanup.

## 5. IOC Investigation Workflow

The implemented workflow follows this sequence:

    Intelligence Sources
           |
           v
    IOC Collection
           |
           v
    Type Identification
           |
           v
    Validation and Normalization
           |
           v
    Provenance and Confidence Assessment
           |
           v
    IOC Repository
           |
           v
    Security Event Ingestion
           |
           v
    IOC Correlation
           |
           v
    Allowlist and Expiration Evaluation
           |
           v
    Match Generation
           |
           v
    Risk Prioritization
           |
           v
    Investigation Case
           |
           v
    Analyst Review and Containment

The workflow separates intelligence registration from event matching.

Registering an IOC does not establish that it has been observed in an environment.

Likewise, receiving a security event does not establish that the event is malicious.

A match is produced only when an active indicator and an observed event have compatible types and normalized values, subject to the applicable exclusion and policy rules.

## 6. Security Event Correlation

A security event represents an observation collected from a monitoring source.

The implementations model events with:

- Event identifier
- Event source
- IOC category
- Observed value
- Timestamp
- Asset identifier
- Associated metadata where applicable

Supported event sources include:

| Source | Typical observations |
|---|---|
| Firewall | Network connections and destination IP addresses |
| DNS | Domain queries and DNS responses |
| Endpoint | File hashes and process artifacts |
| Proxy | Requested URLs |
| Filesystem | File creation and filename observations |
| Registry | Windows registry modifications |

### 6.1 Exact Matching

The primary correlation mechanism uses the composite key:

`IOC Type + Normalized IOC Value`

This avoids treating identical strings from different IOC categories as interchangeable.

For example, a filename and a domain may contain similar text but represent different types of evidence.

The Python and JavaScript implementations use hash-based indexes.

C++ uses an unordered map.

Java uses a typed map keyed by an immutable record.

PostgreSQL uses a composite uniqueness constraint and indexed generated columns.

### 6.2 Match Generation

A successful match contains:

- Event identifier
- Indicator identifier
- Matched value
- Asset
- Confidence
- Severity
- Match timestamp

The system prevents duplicate event-to-indicator relationships.

This allows repeated ingestion to avoid creating duplicate match records.

### 6.3 Exact Matching Versus Contextual Matching

Exact matching is appropriate for normalized hashes, filenames, registry paths, and explicitly registered URLs.

Other detection requirements may need additional policies:

- Domain suffix matching
- IP subnet matching
- URL hostname matching
- URL path-prefix matching
- Filename and hash combinations
- Temporal correlation
- Multiple-event correlation

These are different matching mechanisms and should not be silently substituted for exact equality.

The implementations deliberately use exact matching to maintain predictable behavior.

## 7. Allowlisting and False Positives

Allowlisting identifies indicators or observations that should be excluded from ordinary alert generation under an approved policy.

Examples include:

- Approved test infrastructure
- Authorized security scanners
- Known internal monitoring endpoints
- Documented business services
- Validated operational exceptions

An allowlist entry includes:

- IOC type
- Normalized value
- Justification
- Approving identity
- Creation timestamp
- Optional expiration
- Active state

The detection workflow checks allowlisting after identifying a candidate indicator and before generating a match.

Allowlisting must be governed carefully.

An excessively broad exception can suppress genuine malicious activity.

For production deployments, exceptions should be scoped, time-limited where appropriate, reviewed periodically, and recorded in an audit trail.

## 8. Threat Prioritization

The implementations use a weighted confidence-and-severity calculation.

The severity weights are:

| Severity | Weight |
|---|---:|
| Low | 1 |
| Medium | 2 |
| High | 3 |
| Critical | 4 |

The score for an individual match is:

`Match Score = Confidence × Severity Weight / 4`

The investigation priority is the maximum score among the associated matches.

The resulting value is bounded between 0 and 100.

Using the maximum score prevents a large number of low-severity observations from automatically overwhelming a critical indicator.

This is a simple prioritization model. It does not represent a calibrated probability of compromise.

Production scoring can incorporate:

- Asset criticality
- Event frequency
- Intelligence source reliability
- Indicator age
- Detection confidence
- Network direction
- User identity
- Process behavior
- Business impact
- Correlated evidence

## 9. Investigation Case Management

A match becomes operationally useful when it is associated with an investigation.

The project models an investigation case with:

- Unique case identifier
- Case reference
- Title
- Status
- Priority
- Assigned analyst
- Associated matches
- Investigation notes
- Creation timestamp
- Update timestamp
- Closure timestamp

### 9.1 Case State Machine

The permitted state transitions are:

    OPEN
      |
      +------> INVESTIGATING
      |              |
      |              +------> CONTAINED
      |              |            |
      |              |            +----> INVESTIGATING
      |              |            |
      |              +------------+----> CLOSED
      |
      +------> CLOSED

A closed investigation cannot be reopened through the implemented transition rules.

Invalid transitions raise errors or database exceptions.

This prevents arbitrary state changes and preserves a predictable investigation lifecycle.

### 9.2 Analyst Responsibilities

The analyst reviews the evidence rather than treating a match as an automatic incident verdict.

Relevant activities include:

- Confirming the observation
- Examining affected assets
- Reviewing timestamps
- Checking source reliability
- Correlating related events
- Investigating endpoint artifacts
- Recording findings
- Assessing potential impact
- Recommending containment
- Documenting closure

The Java implementation includes analyst assignment and tenant validation.

The SQL implementation models analyst identities, case assignments, investigation notes, and case actions.

## 10. Python Implementation

**File:** `ioc_investigation.py`

The Python implementation models a complete investigation workflow using standard-library capabilities.

### Main components

| Component | Responsibility |
|---|---|
| `IOCType` | Defines supported indicator categories |
| `Severity` | Defines threat severity |
| `SecurityEvent` | Models observed security activity |
| `IOC` | Stores validated threat intelligence |
| `IOCRepository` | Maintains indexed indicators |
| `IOCInvestigationEngine` | Performs event correlation |
| `InvestigationCase` | Controls case state |
| `Match` | Represents a successful correlation |
| `calculate_priority()` | Computes investigation priority |
| `calculate_file_hash()` | Streams file content into a digest |

### Important implementation decisions

The `dataclass` mechanism provides structured domain objects without excessive boilerplate.

The repository maintains two structures:

- A dictionary indexed by indicator identifier.
- A composite-key dictionary indexed by indicator type and normalized value.

This supports efficient exact lookups.

The investigation engine records matching and allowlisting events in an audit collection.

File hashing uses chunked reads to avoid unnecessary memory consumption.

The built-in `unittest` framework validates normalization, duplicate registration, allowlisting, registry handling, and case transitions.

The implementation uses in-memory storage. Data is not retained after process termination.

## 11. JavaScript Implementation

**File:** `ioc_investigation.js`

The JavaScript implementation uses Node.js and an event-driven architecture.

### Main components

| Component | Responsibility |
|---|---|
| `Indicator` | Validates and stores an IOC |
| `IndicatorStore` | Maintains indexed intelligence |
| `ThreatDetectionService` | Processes events and publishes results |
| `InvestigationCase` | Manages investigation state |
| `ThreatPolicy` | Evaluates threat priority |
| `normalizeIOC()` | Applies category-specific normalization |
| `hashFile()` | Calculates file digests |
| `exportIndicators()` | Exports indicator records |

### Event-driven processing

The detection service extends Node.js `EventEmitter`.

Its important events are:

- `security-event`
- `ioc-match`
- `processing-error`

This separates event ingestion from the components that consume detection results.

The batch processor uses bounded concurrency.

This avoids launching an unlimited number of concurrent operations when processing large event collections.

The implementation also uses private class fields to prevent direct modification of repository internals.

Indicator objects and match records use controlled access to reduce accidental state changes.

The file export function creates a new file rather than silently overwriting an existing destination.

## 12. C++17 Implementation

**File:** `ioc_investigation.cpp`

The C++ implementation emphasizes a deterministic, strongly typed threat correlation engine.

### Main components

| Component | Responsibility |
|---|---|
| `IOC` | Validated indicator model |
| `SecurityEvent` | Security telemetry representation |
| `IOCRepository` | Indexed IOC storage |
| `ThreatEngine` | Event correlation |
| `ThreatPolicy` | Priority evaluation |
| `InvestigationCase` | Investigation state management |
| `Match` | Correlation result |

### Engineering decisions

The repository uses `std::unordered_map` for average constant-time indicator lookup.

`std::set` provides uniqueness for allowlist entries.

`std::optional` represents the absence of a match without requiring an artificial indicator object.

Enums provide explicit domain categories and prevent arbitrary status strings.

The program uses exceptions to report invalid indicators, duplicate registrations, and illegal state transitions.

The implementation uses standard-library validation and does not require external dependencies.

Its IPv6 validation accepts structurally valid textual forms but does not implement complete canonical IPv6 compression.

For production-grade address processing, canonicalization and binary address comparison should be provided by a dedicated IP-address library or a fully tested implementation.

## 13. Java 17 Implementation

**File:** `IOCInvestigation.java`

The Java implementation models an enterprise investigation service with explicit domain boundaries.

### Main components

| Component | Responsibility |
|---|---|
| `Indicator` | Immutable core indicator attributes |
| `ThreatSource` | Intelligence provenance |
| `SecurityEvent` | Tenant-associated telemetry |
| `IOCRepository` | Indicator persistence abstraction |
| `DetectionService` | Detection and correlation |
| `Policy` | Confidence requirements |
| `Investigation` | Case management |
| `RiskScoringService` | Risk evaluation |
| `AuditRecord` | Immutable audit entry |

### Enterprise considerations

Java records represent immutable data structures such as security events, audit records, and correlation results.

The repository maintains an indicator map and an allowlist.

The detection service evaluates normalized values against repository policy.

The investigation model supports:

- Analyst assignment
- Match association
- Tenant isolation
- Investigation notes
- Controlled status transitions

Cross-tenant matches are rejected.

The design distinguishes indicator registration, detection, case assignment, and investigation management rather than combining them into one service.

The implementation uses in-memory persistence. A production deployment would require a durable repository, authenticated user identity, transaction management, and explicit authorization checks.

## 14. PostgreSQL Database Architecture

**File:** `ioc_investigation.sql`

The PostgreSQL implementation provides a relational data model for threat intelligence and investigation management.

### 14.1 Entity Relationships

    organizations
         |
         v
    threat_feeds
         |
         v
    indicators
         |
         +--------------------+
         |                    |
         v                    v
    event_indicator_matches  indicator_allowlist
         |
         |
    security_events
         |
         v
    investigation_cases
         |
         +--------------------+
         |                    |
         v                    v
    investigation_notes   case_actions
         |
         v
    analysts

The actual schema includes additional relationships for event provenance, analyst assignments, tenant boundaries, and audit records.

### 14.2 Database Objects

| Database object | Purpose |
|---|---|
| `organizations` | Intelligence provider organizations |
| `threat_feeds` | Registered intelligence feeds |
| `analysts` | Investigation personnel |
| `indicators` | Validated IOC inventory |
| `indicator_allowlist` | Approved detection exclusions |
| `security_events` | Observed security telemetry |
| `event_indicator_matches` | Correlation results |
| `investigation_cases` | Investigation records |
| `investigation_notes` | Analyst documentation |
| `case_actions` | Case workflow history |
| `audit_log` | Database activity records |

### 14.3 Constraints

The database uses:

- Primary keys
- Foreign keys
- Unique constraints
- Check constraints
- Generated columns
- Enum types
- Timestamp constraints

Generated normalized values ensure that indexed matching uses the database normalization function.

The uniqueness constraint on indicator type and normalized value prevents duplicate indicators.

The uniqueness constraint on event and indicator identifiers prevents duplicate correlation records.

### 14.4 Indexing

Indexes support common investigative operations.

The implementation includes indexes for:

- IOC type and normalized value
- Indicator severity and confidence
- Active indicator expiration
- Security event timestamps
- Asset-level investigation
- Tenant-level retrieval
- Case assignment
- Case status and priority
- Match-to-case relationships
- Investigation notes
- Audit retrieval

A GIN index supports tag and JSONB searches.

Index selection should be reviewed against actual event volume and query plans. Excessive indexes increase storage and write costs.

### 14.5 Functions and Procedures

`normalize_ioc()` centralizes category-specific IOC validation.

`evaluate_case_priority()` calculates a case priority from its associated matches.

`correlate_event()` identifies eligible indicators and creates event-to-indicator relationships.

`create_investigation_case()` validates analyst assignment and creates a case.

These functions and procedures separate database operations from application-level orchestration.

### 14.6 Triggers

The indicator audit trigger records changes to the IOC inventory.

The case transition trigger validates status changes and maintains update and closure timestamps.

Database-level enforcement is important because application-only validation can be bypassed by other database clients.

### 14.7 Transactions

Event correlation and case updates are executed within a transaction.

This ensures that the workflow does not leave partially committed correlation results when a database operation fails.

The closure example demonstrates transactional state management and action recording.

## 15. IOC Matching and Investigation Distinctions

Several concepts must remain separate.

| Concept | Meaning |
|---|---|
| IOC | A known observable indicator |
| Security event | An observed system or network activity |
| IOC match | A relationship between an event and an indicator |
| Confidence | Assessment of indicator reliability |
| Severity | Potential significance of the finding |
| Allowlist | An approved detection exclusion |
| Investigation | A managed examination of security evidence |
| Containment | An operational response to reduce exposure |
| Audit record | A record of an action or state change |

A match should initiate contextual investigation when warranted by policy. It should not automatically authorize destructive remediation.

## 16. Performance Considerations

The implementations use data structures appropriate to their execution environments.

| Implementation | Lookup structure | Expected lookup complexity |
|---|---|---|
| Python | Dictionary | Average O(1) |
| JavaScript | Map | Average sublinear lookup |
| C++17 | Unordered map | Average O(1) |
| Java 17 | HashMap | Average O(1) |
| PostgreSQL | B-tree indexes | O(log n) |

Here, `n` represents the number of registered indicators or indexed records.

Batch processing reduces repeated orchestration overhead.

Streaming hash calculation controls memory consumption.

Database indexes accelerate selective queries but increase insertion, update, and storage costs.

For large-scale IOC processing, further architectural concerns include:

- Event deduplication
- Partitioning by event timestamp
- Bulk ingestion
- Indicator expiration jobs
- Feed update scheduling
- Backpressure
- Queue-based ingestion
- Distributed correlation
- Retention policies
- Historical indicator versioning

The supplied implementations demonstrate the core correlation mechanism rather than a distributed processing infrastructure.

## 17. Security Considerations

IOC investigation systems process potentially sensitive security information.

Important controls include:

**Input validation:** Reject malformed or excessively large values before storage or comparison.

**SQL safety:** Use parameterized queries when accepting application-provided values. Do not concatenate untrusted strings into SQL statements.

**URL safety:** Validate schemes and reject embedded credentials. Do not automatically fetch submitted URLs during IOC ingestion.

**File safety:** Calculate hashes without executing or opening files through unsafe application workflows.

**Access control:** Restrict IOC registration, allowlist approval, investigation assignment, and case closure according to organizational roles.

**Auditability:** Record indicator modifications, analyst actions, and important investigation transitions.

**Tenant isolation:** Restrict security events and investigation records to authorized organizational boundaries.

**Expiration:** Prevent stale indicators from generating matches indefinitely.

**Data protection:** Secure threat intelligence, endpoint identifiers, investigation notes, and operational metadata.

**False-positive management:** Require contextual validation before containment or remediation.

The SQL sample provides relational constraints and audit mechanisms. It is not a complete production authorization system. Production deployment also requires database roles, restricted grants, appropriate row-level security, secure credentials, encrypted transport, and protected backup procedures.

## 18. Edge Cases and Failure Conditions

| Condition | Expected behavior |
|---|---|
| Invalid IP address | Reject during normalization |
| Invalid hash length | Reject registration or ingestion |
| Uppercase domain | Normalize to lowercase |
| Trailing domain dot | Remove before comparison |
| Duplicate IOC | Reject duplicate registration |
| Expired indicator | Exclude from detection |
| Inactive indicator | Exclude from detection |
| Allowlisted indicator | Do not create an ordinary match |
| Unsupported URL scheme | Reject |
| Credential-bearing URL | Reject |
| Invalid registry root | Reject |
| Missing event | Report correlation failure |
| Duplicate event match | Preserve one relationship |
| Closed investigation | Reject further modifications |
| Invalid case transition | Reject state change |
| Cross-tenant match | Reject association |

## 19. Testing and Execution

### Python

Runtime requirement: Python 3.10 or later.

Run:

`python ioc_investigation.py`

The program executes the demonstration and built-in unit tests.

### JavaScript

Runtime requirement: Node.js 18 or later.

Run:

`node ioc_investigation.js`

The program executes asynchronous correlation and assertion-based validation tests.

### C++17

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic ioc_investigation.cpp -o ioc_investigation`

Run:

`./ioc_investigation`

On Windows, execute `ioc_investigation.exe`.

### Java 17

Compile:

`javac IOCInvestigation.java`

Run:

`java IOCInvestigation`

### PostgreSQL

Execute the SQL file against a PostgreSQL 15 or later database using an account authorized to create the schema, extension, tables, functions, and triggers.

The script creates the `threat_intel` schema, registers demonstration data, correlates security events, and executes reporting queries.

The `pgcrypto` extension provides UUID generation.

The sample uses a dedicated schema and should be executed in an appropriate development database.

## 20. Implementation Limitations

The five implementations demonstrate different engineering perspectives but do not claim identical production capabilities.

| Area | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| IOC validation | Yes | Yes | Yes | Yes | Yes |
| Indexed lookup | Yes | Yes | Yes | Yes | Yes |
| Event correlation | Yes | Yes | Yes | Yes | Yes |
| Allowlisting | Yes | Yes | Yes | Yes | Yes |
| Expiration | Yes | Yes | Yes | Yes | Yes |
| Case lifecycle | Yes | Yes | Yes | Yes | Yes |
| Audit records | In-memory | In-memory | In-memory | In-memory | Relational |
| Durable storage | No | No | No | No | Yes |
| Multi-tenant case checks | No | No | No | Yes | Yes |

Additional production engineering would be required for:

- Complete IPv6 canonicalization in every implementation
- Comprehensive internationalized domain handling
- URL canonicalization across all equivalent encodings
- Domain suffix and subnet matching policies
- Threat feed synchronization
- External reputation enrichment
- Durable application repositories
- Distributed event processing
- Identity and access management
- Formal incident response authorization
- Evidence retention and chain-of-custody controls
- Operational monitoring and alerting

The core distinction remains essential: an IOC is intelligence, a security event is an observation, a match is a correlation result, and an investigation is the controlled process used to determine what that evidence means.
