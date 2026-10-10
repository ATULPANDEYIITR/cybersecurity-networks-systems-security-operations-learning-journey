# Linux Security Monitoring

## Scope

This project models security monitoring on Linux systems through four complementary telemetry categories: process execution, network connections, authentication activity, and persistence mechanisms. Each category exposes different evidence. Combining them can reveal suspicious activity that individual events might not establish.

The implementations use synthetic events by default. The Python implementation also provides an optional read-only host collection mode. The JavaScript, C++, Java, and PostgreSQL implementations model the detection and reporting logic without modifying system settings.

A security finding is an investigative lead, not a definitive statement that a host has been compromised. A process running from a temporary directory, a wildcard-bound listener, or a successful login after authentication failures may have a legitimate operational explanation.

## Monitoring architecture

The monitoring workflow separates collection, normalization, analysis, and reporting.

- **Collection** obtains process metadata, socket information, authentication records, and persistence configuration from their respective operating-system interfaces.
- **Normalization** converts different source formats into structured records with stable fields such as PID, UID, local address, source address, event time, and outcome.
- **Analysis** applies category-specific rules to identify behavior requiring investigation.
- **Correlation** links observations across time and categories, such as repeated SSH failures followed by a successful login.
- **Reporting** preserves the supporting evidence, severity, and recommended investigative action.

Process metadata and network connections are snapshots. Authentication events are temporal records. Persistence artifacts describe configuration that may influence future execution. These different lifecycles must be retained when designing a production monitoring system.

## Process monitoring

Linux represents process information through the `/proc` virtual filesystem. A process directory commonly contains `stat`, `status`, `cmdline`, and an `exe` symbolic link.

The `stat` file contains many positional fields. Its command-name field is enclosed in parentheses and can contain spaces, so splitting the complete line on whitespace produces incorrect field positions. The Python implementation locates the opening and closing parentheses before parsing the remaining fields.

The `status` file provides readable attributes such as process ID, parent process ID, real and effective credentials, thread count, memory usage, and effective capability masks.

### Process indicators

An executable path under `/tmp` or `/dev/shm` can deserve investigation because writable temporary locations may be used to stage executable content. It is not automatically malicious: administrators and applications can legitimately execute files from temporary directories.

A privileged process invoking a network utility may warrant inspection of its parent process, executable provenance, destination, and command history. The command text alone does not prove that a network transfer occurred.

Effective Linux capabilities provide a more precise privilege signal than UID alone. A process running as a non-root user can still possess powerful capabilities. The hexadecimal `CapEff` value should be interpreted according to Linux capability definitions and the service's expected privilege requirements.

Parent process ID 1 is a contextual clue, not a standalone detection rule. A process can be reparented after its original parent exits, and service managers legitimately supervise many long-running processes.

### Python implementation

The Python script implements `parse_proc_stat()` and `parse_proc_status()` to normalize Linux process metadata. `collect_processes()` enumerates numeric directories under `/proc`, reads available metadata, and tolerates processes that exit during collection.

The collector is deliberately read-only. It does not terminate processes, alter capabilities, or execute a process's command line. Access restrictions and process races can cause individual records to be skipped.

`analyze_processes()` evaluates executable locations, privileged command patterns, and effective capability masks. These checks are heuristic and should be supplemented with executable hashes, package ownership, process ancestry, audit records, and approved deployment information.

## Network connection monitoring

A Linux host can have listening sockets, established sessions, and other connection states. A listener indicates that a process or kernel subsystem is accepting connections on a local endpoint. It does not prove that a remote system can reach the endpoint.

The Python collector prefers `ss -H -lntup`, which can report TCP and UDP socket information and, where permissions allow, process ownership. It falls back to `/proc/net/tcp` and `/proc/net/tcp6` when `ss` is unavailable. The fallback has less attribution information and does not provide equivalent UDP coverage.

### Bind addresses and exposure

| Bind address | Interpretation |
|---|---|
| `127.0.0.1` | IPv4 loopback; ordinarily reachable only within the host's network namespace |
| `0.0.0.0` | All local IPv4 interfaces |
| `::1` | IPv6 loopback |
| `::` | IPv6 wildcard address; dual-stack behavior depends on socket configuration and system settings |

A wildcard bind requires an exposure review because the service may accept connections on multiple interfaces. Actual reachability also depends on firewall rules, routing, container networking, namespaces, and the service's authentication controls.

Port numbers provide context, not proof. A listener on TCP port 2375 deserves careful review because the Docker API may expose privileged container-management operations when configured without appropriate transport protection and authorization. Database ports such as 5432, 3306, 6379, and 27017 should be evaluated against the intended network architecture.

### JavaScript implementation

The JavaScript file models listener analysis using `parseEndpoint()` and `analyzeListener()`. The parser distinguishes bracketed IPv6 endpoints from ordinary address-and-port strings and rejects malformed input.

`EventProcessor` maintains a set of event identities to prevent duplicate ingestion from inflating event counts. Its private fields keep the deduplication set and alert collection encapsulated. The processor returns sorted alerts without exposing its mutable internal collection.

A production event identity should normally use a source-generated event ID or a stable hash of canonicalized fields. The demonstration uses a deterministic composite identity, which is adequate for its synthetic events but is not a universal deduplication strategy.

## Authentication event monitoring

Authentication records help distinguish isolated mistakes from repeated failures and potentially suspicious successful sessions. Relevant fields include event time, account name, source address, service, authentication method, and outcome.

The sample implementations evaluate repeated failures by source and by account. They also identify a successful login associated with a supplied count of preceding failures.

These two aggregation dimensions have different meanings:

- Repeated failures from one source may indicate brute-force activity, password spraying, a shared NAT address, or a misconfigured client.
- Repeated failures against one account may indicate a targeted account attack, a stale service credential, or a user entering an incorrect password.
- A successful login after repeated failures increases the value of investigating the session, but it does not establish that the successful login was unauthorized.

### Temporal correlation

Authentication analysis must define an observation window. Counting failures across an unlimited period can combine unrelated events and exaggerate risk. A rolling window, such as 15 minutes, is often more useful for identifying concentrated activity.

Event ordering also matters. Systems can deliver logs late or out of order, and distributed sources can have clock skew. A production pipeline should preserve event time separately from ingestion time, account for late arrivals, and use stable source identifiers.

The Python script reads recent SSH messages from `journalctl` when that command is available. Its regular expressions cover common SSH log formats rather than every possible distribution or logging configuration. Journald permissions, service naming, log retention, and alternative authentication services can limit coverage.

The Java implementation uses immutable `AuthenticationEvent` records and sorts a copy by timestamp before evaluation. The C++ case study assumes events are already ordered within an observation window. These approaches illustrate different choices: normalize and sort at the analysis boundary, or enforce ordering in the ingestion pipeline.

The PostgreSQL script groups failures by source address and account, and demonstrates a window-based query for successful events occurring alongside repeated failures. Its temporal query uses a 15-minute range and can be adapted to additional identity-provider and MFA records.

## Persistence monitoring

Persistence mechanisms allow a process or access path to survive a reboot, logout, or service restart. Linux persistence can be implemented through systemd units, cron entries, SSH authorized keys, desktop autostart entries, and legacy initialization scripts.

A useful inventory records the mechanism type, path, owner, permissions, enabled state, content hash, and command or target. Historical snapshots help identify changes that a single filesystem inspection cannot reveal.

### What to investigate

**Systemd units:** Inspect unit files, enablement relationships, executable paths, environment directives, service identities, and recent modifications. An unexpected service referencing a temporary executable is more informative when correlated with process execution and file metadata.

**Cron entries:** Review system-wide cron directories and user crontabs. Consider ownership, write permissions, command destinations, execution frequency, and whether the entry matches an approved maintenance task.

**SSH authorized keys:** Compare key fingerprints and account ownership against an approved inventory. A newly added key can represent routine administration or unauthorized access; its significance depends on the account, change history, and access context.

**Desktop autostart and initialization entries:** Review entries that launch programs automatically and identify unexpected commands, executable locations, and changes in ownership or permissions.

### Persistence implementation

The Python collector examines selected system cron and systemd directories, along with authorized-key files under `/home`. It inspects metadata without executing artifact contents. It does not represent a complete inventory of all persistence mechanisms: user crontabs, systemd user units, timers, shell startup files, all home directories, container configuration, and other locations may require separate collectors.

The Java implementation models persistence artifacts with the `PersistenceArtifact` record and distinguishes systemd units, cron entries, authorized keys, and autostart entries through an enum. Its analysis rules prioritize world-writable artifacts and entries referencing temporary locations.

The PostgreSQL schema stores persistence observations as timestamped records rather than overwriting the previous observation. This supports change analysis and historical investigations.

## C++ case study: endpoint investigation

The C++ program models an endpoint where several independent indicators appear together: a privileged process invokes a network utility from a temporary executable, a Docker API listener is bound to all IPv4 interfaces, and an account successfully authenticates after multiple failures.

Its `ProcessRecord`, `Connection`, and `AuthenticationEvent` structures represent normalized telemetry. `SecurityMonitor` applies separate analysis methods to each record category and stores the resulting findings in a common collection.

The process analyzer validates positive PIDs and rejects duplicate PIDs within the supplied snapshot. It checks executable paths, effective capabilities, and privileged network-utility invocations.

The network analyzer considers socket state, port, bind address, and process attribution. It does not treat established connections as listeners and raises the severity of some wildcard-bound endpoints.

The authentication analyzer counts failures by source and account, then checks whether a successful event follows repeated failures. Because its input model does not contain a complete time-window engine, the sample assumes the events have already been ordered and belong to the same observation window.

The report is sorted by severity before display. This gives analysts a prioritized view while retaining the evidence and recommended action for each finding. The implementation uses ordered maps for deterministic aggregate reporting and a set for PID uniqueness checks.

The case study illustrates correlation across independent telemetry sources. A temporary executable becomes more significant if a process uses it, a service configuration references it, and related network or authentication events appear in the same period. A production system should link these observations through host identity, process identity, event time, and artifact metadata instead of assuming that similar names alone prove a relationship.

## Java enterprise model

The Java implementation uses immutable records for process snapshots, network listeners, authentication events, persistence artifacts, and findings. Constructor validation prevents malformed domain objects from entering the monitoring service through the normal creation path.

`ReviewPolicy` makes the authentication threshold and selected inspection rules explicit. `MonitoringService` evaluates each telemetry category independently, while the caller combines findings for reporting.

The use of enums for severity, authentication outcome, and persistence kind limits accidental variation in categorical values. `Map.copyOf()` prevents callers from modifying evidence through a finding after construction.

The monitoring service checks duplicate process IDs within a snapshot, validates port ranges, and sorts authentication events by timestamp. Severity ordering is represented through enum order for report sorting; production systems may prefer an explicit severity mapping so that changes to declaration order cannot alter operational priority.

The model separates detection rules from host collection. This allows a collector to be replaced or expanded without requiring all policy logic to be rewritten. A production service would also need authorization controls, durable event ingestion, audit logging, policy versioning, bounded memory, and automated tests for event-time boundaries.

## PostgreSQL data model

The SQL script stores telemetry in related tables rather than flattening all observations into a single unstructured event record.

| Table | Purpose |
|---|---|
| `monitored_hosts` | Identifies each monitored endpoint and its environment |
| `processes` | Stores timestamped process identity, command, executable path, UID, and capabilities |
| `network_connections` | Stores protocol, state, local and remote endpoints, and optional process attribution |
| `authentication_events` | Stores account, source address, service, outcome, and event time |
| `persistence_artifacts` | Stores persistence type, path, ownership, permissions, enabled state, and observation time |
| `security_findings` | Stores categorized alerts, evidence, recommendations, status, and occurrence counts |

Foreign keys preserve relationships between hosts and observations. Check constraints restrict environment, state-like categories, severity, valid port ranges, nonnegative identity fields, and finding status. The unique constraints prevent duplicate host names and repeated observations with the same defined identity.

The schema uses PostgreSQL `INET` for IP addresses, `JSONB` for structured finding evidence, and partial indexes for common operational queries. The GIN index supports searches against evidence JSON, while indexes on host, timestamp, source address, and listener state support time-bounded investigations.

The seed statements use synthetic telemetry and idempotent checks to reduce duplication when the script is rerun. The script wraps its schema and data operations in a transaction so that the demonstration changes are committed together.

### Database queries and integrity

The authentication queries aggregate repeated failures by source within the previous day and demonstrate event-time correlation over a 15-minute window. The persistence query highlights enabled artifacts with world-writable permissions or paths in selected temporary locations. The unresolved-findings view exposes open and investigating findings for triage.

The SQL schema validates data shape, but it does not prove that telemetry is truthful. A database constraint can reject an invalid port or category; it cannot establish that a process executable is malicious or that a source address belongs to an attacker.

The demonstration's timestamped records are intentionally retained as observations. In a larger deployment, repeated detections should be deduplicated or aggregated according to a defined finding identity, while raw telemetry remains available for forensic review. The current seed data avoids duplicate inserts for its known sample identities, but a full ingestion service should define explicit idempotency keys and transaction boundaries.

## Severity, evidence, and false positives

Severity indicates investigation priority rather than certainty. A useful finding preserves the observable facts that triggered the rule, the host and event context, and a concrete investigative action.

A high-severity finding can still be a false positive. For example, a Docker API endpoint may be intentionally isolated in a controlled network, and a temporary executable may belong to a legitimate installer. Analysts should validate configuration, ownership, package provenance, expected network paths, and change records before making disruptive changes.

Detection rules should be calibrated to the environment. A development host, a production database, and a container worker have different expected process trees, listeners, authentication patterns, and persistence configurations.

## Operational limitations and production considerations

The sample collectors do not constitute a complete endpoint detection and response system.

- **Collection coverage:** `/proc`, `ss`, and journald expose different information and may be restricted by permissions, container namespaces, process exit races, or logging configuration.
- **Process attribution:** A network socket may lack an associated PID when collection permissions are insufficient. PID reuse and short-lived processes complicate correlation.
- **Authentication parsing:** SSH log messages vary by distribution and configuration. Structured journald fields or normalized authentication events are preferable to relying exclusively on regular expressions.
- **Persistence coverage:** Selected directories do not cover every system-wide and per-user startup mechanism.
- **Temporal accuracy:** Distributed logs can arrive late or have inconsistent clocks. Detection rules need explicit event-time windows, time-zone handling, and duplicate-event handling.
- **Network interpretation:** A listening socket is not equivalent to a remotely reachable service. Firewalls, routing, namespaces, and service-level controls must be considered.
- **Response safety:** The scripts report findings but do not kill processes, disable services, edit firewall rules, delete keys, or block addresses. Such actions require authorization, evidence preservation, change control, and a rollback procedure.
- **Data protection:** Process command lines and authentication records can contain sensitive information. Collection, retention, access control, redaction, and audit trails should follow organizational requirements.

## Running the implementations

Python uses the standard library. Run the synthetic demonstration with `python linux_security_monitor.py`. On Linux, `python linux_security_monitor.py --live` enables read-only collection, and `python linux_security_monitor.py --live --output report.json` writes the report to a JSON file as well as standard output. Some observations require elevated permissions, and missing collectors are reported as errors.

JavaScript runs under Node.js with `node linux-security-monitor.js`. It processes synthetic events and prints a JSON report.

C++ requires a C++17-compatible compiler. Compile with `g++ -std=c++17 -O2 -Wall -Wextra -pedantic linux_security_monitor.cpp -o linux-security-monitor`, then execute `./linux-security-monitor`.

Java requires Java 17 or later. Compile with `javac LinuxSecurityMonitor.java`, then execute `java LinuxSecurityMonitor`.

PostgreSQL requires a database role permitted to create the `linux_security` schema and its objects. Execute the SQL script in a PostgreSQL session. The transaction commits the demonstration schema, sample telemetry, findings, and reporting view.
