# Linux Logging: syslog, journald, Authentication Logs, Kernel Logs, and Application Logs

## Scope

Linux logging is not a single file or service. It is a collection of mechanisms that record events at different layers of the operating system and applications.

This implementation set treats five closely connected areas as distinct:

| Area | Primary purpose | Typical evidence |
|---|---|---|
| syslog | Standardized classification and transport model | Facility, severity, message |
| journald | Structured event collection on systemd systems | Journal fields, units, priorities, boot metadata |
| authentication logs | Identity and access activity | SSH success, failed authentication, invalid users |
| kernel logs | Host and kernel activity | Memory pressure, storage errors, hardware and network events |
| application logs | Service-specific behavior | Requests, failures, application state, business context |

The relationship is important. syslog defines a classification model, journald provides a structured collection mechanism, authentication logs describe access activity, kernel logs describe operating-system behavior, and application logs describe software running above the operating system.

The six deliverables implement these distinctions rather than treating every log as an interchangeable text line.

## Syslog Model

Syslog uses two major classification dimensions: **facility** and **severity**.

A facility identifies the subsystem that generated an event. Examples include `kern` for kernel messages, `authpriv` for security-sensitive authentication activity, `daemon` for system daemons, and `local0` through `local7` for locally assigned application or infrastructure purposes.

Severity represents urgency:

| Severity | Meaning |
|---|---|
| `emerg` | The system is unusable or facing an extreme emergency |
| `alert` | Immediate action is required |
| `crit` | Critical condition |
| `err` | Error condition |
| `warning` | Warning condition |
| `notice` | Significant normal condition |
| `info` | Informational event |
| `debug` | Diagnostic detail |

The traditional numeric priority is calculated as:

`facility_code * 8 + severity_code`

The Python, C++, Java, and SQL implementations calculate this value explicitly. This is useful when understanding syslog filtering and configuration because the numeric value represents both the origin category and urgency.

A syslog message is therefore more informative than a simple severity label. `kern/err` and `authpriv/err` have the same urgency but different operational meaning.

## Python Implementation

The Python program provides a complete log-analysis laboratory using only the standard library.

`LogRecord` acts as a normalized representation of an event regardless of whether the original evidence came from a text log, journald, authentication source, kernel source, or application.

`LogParser` handles two important formats:

- traditional syslog-style text lines
- structured JSON application records

The syslog parser recognizes timestamps, hostname, service name, process ID, and message text. Authentication-specific information such as a username and source IP is extracted when an SSH event contains that information.

`JournalReader` demonstrates a different mechanism. Instead of treating journald as another text file, it invokes `journalctl -o json`. This preserves structured journal fields such as systemd unit, process ID, priority, and hostname.

`AuthenticationAnalyzer` focuses specifically on SSH activity. It counts failed attempts by source address and successful sessions by account. Repeated failures are surfaced as suspicious evidence, but the program deliberately does not claim that repeated failures prove an intrusion.

`KernelAnalyzer` separates kernel messages into operational categories such as memory, storage, network, hardware, and security.

`LogCorrelator` demonstrates why multiple log sources are useful together. An authentication failure and an application event from the same IP address within a short time window may deserve investigation even though neither record alone provides the complete operational context.

`ApplicationLogger` demonstrates rotating application files. The use of `RotatingFileHandler` limits individual file size and retains bounded backups.

The program also demonstrates gzip compression of rotated content. Compression is operationally useful because historical logs can be substantially larger than their active counterparts.

The program is executable without privileged access because it includes realistic simulated events. `--real-logs` attempts to read conventional Linux files when they are accessible, while `--journal` queries journald through `journalctl`.

## JavaScript Implementation

The Node.js implementation approaches Linux logging through event-driven processing.

`LogRecord` represents normalized events, while `SyslogParser` parses traditional syslog-style messages. JavaScript's regular-expression and object facilities make it suitable for transforming text-oriented records into structured objects.

`JournalReader` uses Node's `child_process` capability to invoke `journalctl`. This is intentionally different from treating `/run/log/journal` as an ordinary application data file. The journal has its own query interface and structured metadata.

`LogEventBus` demonstrates an important Node.js pattern for operational logging. A single incoming record can produce different events:

- `authentication` for SSH-related activity
- `kernel` for kernel events
- `error-level` for error and critical records
- `log` for all records

This separates ingestion from downstream processing. A production service could connect these events to alerting, metrics, persistence, or centralized collection without embedding every action in the parser.

The application logger emits newline-delimited JSON. Each record contains fields such as timestamp, service, request ID, process ID, and source address.

The implementation deliberately does not log passwords, tokens, or credentials. Logging an authentication event is useful; logging the secret used to authenticate is a security failure.

## Journald

`systemd-journald` is a logging service commonly present on systemd-based Linux systems.

A traditional text log often looks like:

`Oct  7 16:30:22 server01 sshd[7124]: Failed password for root from 203.0.113.42`

A journal entry can contain many separate fields instead of encoding everything into one message string. Fields can include hostname, systemd unit, process ID, syslog identifier, priority, boot identifier, and the message itself.

The practical distinction is significant:

- text-log analysis often requires parsing strings
- journald queries can operate on structured metadata
- `journalctl` provides filtering and presentation
- journal data can represent events from different sources in a common collection system

The Python and JavaScript programs use `journalctl` rather than attempting to read journal storage directly.

A useful operational query is conceptually represented by the program as a recent JSON journal query. Real systems commonly use filters for units, priorities, boots, time ranges, identifiers, or other journal fields.

Journal persistence also varies with configuration. A system may use volatile storage, persistent storage, or a combination governed by journald configuration and available directories.

## Authentication Logs

Authentication logging answers questions about identity and access rather than general application behavior.

Typical Linux authentication evidence includes:

- successful SSH authentication
- failed passwords
- invalid usernames
- public-key authentication
- session activity
- privilege-related events from mechanisms such as `sudo`

Traditional locations vary by distribution. Common examples include `/var/log/auth.log` on Debian-family systems and `/var/log/secure` on many Red Hat-family systems.

The Python `LinuxLogLocator` checks these conventional locations without assuming that any particular distribution uses them.

The SQL model represents authentication activity separately through `authentication_events`. This makes fields such as username, source IP, authentication method, result, and SSH port queryable without parsing message text repeatedly.

The sample data distinguishes:

`invalid_user`

from:

`failure`

and:

`success`

That distinction matters during security analysis. An invalid username indicates that the requested account was not recognized, while a failed password may involve a valid or invalid account depending on the source message.

Repeated authentication failures are useful detection evidence. They should still be correlated with source ownership, expected administrative activity, identity systems, network telemetry, and other evidence before an incident is declared.

## Kernel Logs

Kernel logging describes activity close to the operating system.

The examples use three particularly useful operational categories:

### Memory

An out-of-memory event can indicate that available memory was exhausted and that the kernel selected a process for termination.

The sample event:

`Out of memory: Kill process 8121 (postgres)`

is not merely an application error. It indicates a host-level resource condition. The application may be affected, but the kernel is reporting the resource enforcement action.

### Storage

An event such as:

`nvme0: I/O error, aborting command`

belongs to host storage diagnostics.

Repeated storage errors may require investigation of the device, filesystem, controller, firmware, or underlying infrastructure.

The SQL model therefore classifies the event as `storage` rather than simply calling it an application error.

### Security

Kernel-adjacent security logging can expose enforcement activity from mechanisms such as Linux Security Modules, AppArmor, SELinux, and audit infrastructure.

A denial message may represent intended policy enforcement rather than an attack. Interpretation requires the affected process, policy, context, and expected behavior.

## Application Logs

Application logs describe behavior that the operating system alone cannot explain.

Useful application fields include:

- service name
- timestamp
- request ID
- HTTP method
- route
- HTTP status
- process ID
- application error code
- selected business or operational attributes

Structured JSON is preferable to embedding every field in an arbitrary sentence because downstream systems can query fields directly.

The SQL `application_events` table demonstrates this by storing request ID, route, HTTP method, HTTP status, and application error code separately from the original log message.

The `structured_data` JSONB field also allows application-specific attributes without forcing every optional attribute into a permanent relational column.

Application logs should not become a dumping ground for secrets. Passwords, authentication tokens, private keys, session cookies, and unnecessary personal information should not be logged.

## C++ Case Study

The C++ program models a host containing authentication, kernel, and application activity.

`RepositoryGovernanceLogEngine` is deliberately a logging analysis engine rather than a generic C++ tutorial. It stores normalized records, validates required fields, calculates severity distributions, counts service activity, isolates SSH authentication failures, and classifies kernel events.

The data structure is a `std::vector<LogRecord>` because the case study processes a finite event stream and needs to preserve record order.

`std::optional` is used for fields that legitimately do not exist in every log record, such as a process ID or source IP. A kernel storage event does not necessarily have an IP address, so forcing every event to contain one would misrepresent the data.

The kernel classifier maps messages to memory, storage, network, hardware, and security categories. This demonstrates why classification logic must be specific to the semantics of the source.

The validation method rejects records without a service, message, or source. This prevents obviously malformed records from entering the analysis pipeline.

The program also demonstrates conventional log-file discovery. It checks paths such as `/var/log/syslog`, `/var/log/messages`, `/var/log/auth.log`, `/var/log/secure`, and `/var/log/kern.log` without assuming that all of them exist.

## Java Enterprise Model

The Java program models logging as a domain service.

`LogEvent` is an immutable record with explicit fields for timestamp, host, service, facility, severity, message, source, process ID, user, IP address, and event domain.

`EventDomain` prevents three different meanings from being collapsed into one category:

- `AUTHENTICATION`
- `KERNEL`
- `APPLICATION`

This allows domain policies to remain separate.

`AuthenticationPolicy` detects repeated authentication failures by source address. It does not classify kernel memory pressure as an authentication event or attempt to use application HTTP errors as identity evidence.

`KernelPolicy` analyzes host-level faults and distinguishes storage problems from memory pressure.

`LogGovernanceService` provides ingestion, severity aggregation, domain aggregation, and policy evaluation.

This structure reflects an enterprise design where the event model is shared but domain rules remain specialized.

## SQL Data Model

The PostgreSQL implementation uses a normalized relational design.

`hosts` represents machines.

`services` identifies services operating on each host.

`log_events` stores the common event envelope. It contains:

- timestamp
- host relationship
- service relationship
- source type
- syslog facility
- severity
- process ID
- message
- source file
- journal cursor
- structured JSON data

Specialized tables then represent source-specific semantics.

`authentication_events` contains username, source IP, authentication result, method, and SSH port.

`kernel_events` contains subsystem and operational category.

`application_events` contains request ID, route, HTTP method, HTTP status, and application error code.

This design avoids putting every possible source-specific field into one oversized log table.

### Constraints

Foreign keys ensure that specialized events cannot reference nonexistent base events.

The process ID check prevents non-positive process identifiers.

The HTTP status check prevents impossible status values outside the standard 100 through 599 range.

The authentication SSH port check constrains ports to 1 through 65535.

The uniqueness of `journal_cursor` prevents the same journal cursor from being inserted twice when that cursor is available.

### Indexes

The timestamp index supports recent-log queries.

The source/severity index supports filtering by logging source and urgency.

The service/time index supports service-specific operational investigations.

The source-IP authentication index supports repeated-login analysis.

The JSONB GIN index supports queries against structured application attributes.

Indexes should be selected according to actual workload. Every index consumes storage and adds write overhead.

### Views

`authentication_log_view` provides a focused representation of identity activity.

`kernel_log_view` isolates host-level events.

`application_log_view` exposes service and request information.

These views keep repeated analytical queries readable without duplicating the underlying records.

## Cross-Source Correlation

Linux logging becomes substantially more useful when sources can be correlated.

A failed SSH authentication and a later application error from the same IP address may be operationally related. The relationship is not proof of malicious activity, but it provides an investigation path.

The Python implementation performs this correlation in memory.

The SQL implementation performs temporal correlation using:

`e.occurred_at BETWEEN a.occurred_at AND a.occurred_at + INTERVAL '5 minutes'`

The JavaScript implementation performs the same conceptual operation with timestamp arithmetic.

The implementations intentionally do not assert causality merely because two events are close in time.

## Log Rotation and Retention

Logs grow continuously. Without rotation or retention controls, an application can consume available disk space.

The Python implementation uses `RotatingFileHandler`, which limits individual file size and maintains bounded backups.

Compression can reduce the storage cost of historical files. The Python demonstration creates a gzip archive for a rotated log.

Rotation and retention are different controls:

- rotation determines when active files are replaced or archived
- retention determines how long historical evidence remains available

Retention should be based on operational requirements, incident-investigation needs, contractual obligations, privacy considerations, and applicable policies.

Deleting logs merely because they are old can destroy evidence. Keeping everything indefinitely can create storage, privacy, and security problems.

## Security Considerations

Log systems themselves are security-sensitive.

Authentication logs can reveal usernames, source addresses, administrative behavior, and access patterns. Kernel logs can reveal system architecture, device information, processes, and security enforcement details. Application logs can contain identifiers, request metadata, and business information.

Important controls include:

- restricting read access to sensitive logs
- preventing credentials and tokens from entering log messages
- protecting log transport from unauthorized modification
- synchronizing system clocks
- controlling retention
- monitoring log collection failures
- preventing unbounded disk consumption
- validating structured input
- separating operational and security access where appropriate
- preserving sufficient context for investigations

A log should not be considered trustworthy merely because it exists on the local host. Attackers with sufficient privileges may attempt to delete, modify, suppress, or flood logs.

Centralized collection can improve resilience because an event copied to a protected remote destination may remain available even if the originating host is compromised.

## Debugging and Failure Modes

A missing log does not necessarily mean that the event never occurred.

Possible causes include:

- the service was not configured to emit the event
- the event was filtered
- journald was unavailable or configured for volatile storage
- a traditional text log is stored at a different distribution-specific path
- permissions prevented reading the file
- the application failed before its logging subsystem initialized
- disk pressure prevented normal logging
- timestamps differ between systems
- the collector itself is unhealthy

The Python program catches permission and operating-system errors when reading conventional files.

The JavaScript journal reader handles the absence of `journalctl`.

The C++ and Java programs validate event structures before analysis.

The SQL schema prevents malformed relational states through constraints.

These controls address different failure layers and should not be treated as substitutes for one another.

## Performance Considerations

Large log volumes require more than simple sequential text parsing.

Useful design considerations include:

- indexing timestamps for recent-event queries
- indexing authentication source addresses for security analysis
- using structured fields instead of repeatedly parsing the same message
- limiting expensive regular expressions
- batching database writes
- partitioning very large event tables by time when operational volume justifies it
- retaining only the fields required for a given analytical purpose
- compressing historical data
- separating hot operational data from long-term archival data

The SQL implementation includes indexes that support common access patterns. It does not create indexes indiscriminately.

The Python and JavaScript examples process records in memory because their datasets are deliberately small. A production-scale collector would normally stream records and avoid retaining an unlimited event history in application memory.

## Important Distinctions

**syslog is not the same thing as journald.** Syslog provides a classification and message-handling model. Journald is a systemd logging service and data store with structured metadata and a query interface.

**Authentication logs are not generic security logs.** They primarily expose identity and access activity. Kernel security messages may describe policy enforcement at a different layer.

**Kernel logs are not application logs.** A kernel out-of-memory event describes host-level resource enforcement. An application exception describes behavior within a user-space service.

**Application logging is not merely printing errors.** Good application records provide enough structured context to connect an event to a service, request, process, and operational condition.

**A high-severity event is not automatically a security incident.** Severity describes urgency or importance. Security classification requires context and correlation.

## Practical Workflow

A practical Linux logging investigation can begin by identifying the relevant layer.

For an SSH problem, inspect authentication records and determine whether the activity represents successful access, failed authentication, an invalid account, or another session event.

For a server stability problem, inspect kernel records for memory, storage, hardware, and network conditions.

For a failed API request, inspect application logs and correlate the request with service state, host events, and authentication activity when appropriate.

On systemd systems, journald can provide a common structured collection point across these layers. Traditional text logs may still exist depending on distribution and configuration.

The important architectural principle is to preserve source-specific meaning while making cross-source correlation possible.

## Production Considerations

A production Linux logging architecture should account for the entire path from event creation to retention.

Applications should emit structured, useful records without exposing secrets.

System services should have appropriate logging levels so that important failures remain visible without overwhelming operators with unnecessary debug traffic.

Authentication logging should be protected because it contains security-sensitive evidence.

Kernel logging should be monitored for recurring resource and hardware failures.

Journald or another collection layer should be monitored so that logging failures are themselves detectable.

Storage and retention policies should prevent both premature evidence destruction and uncontrolled disk growth.

Centralized collection should be considered when local-host compromise, operational availability, or cross-host correlation makes local-only logs insufficient.

The implementations in this set keep these layers distinct while demonstrating how they can be analyzed together.
