# Windows Processes: Processes, Threads, Services, and Parent-Child Relationships

## Scope

Windows process diagnostics require more than a list of executable names. A useful inventory distinguishes process identity, execution threads, service configuration, parent-child relationships, observation completeness, and the limitations of a point-in-time snapshot.

This project models those concerns through five complementary implementations:

- Python provides a process inventory, hierarchy traversal, diagnostic reporting, PowerShell-based collection, and JSON export.
- JavaScript provides an event-friendly process graph, asynchronous PowerShell integration, and atomic report generation.
- C++ implements a diagnostic case study using explicit graph validation, iterative traversal, and service correlation.
- Java defines an enterprise-oriented domain model with immutable records, typed states, validation, and service-correlation services.
- PostgreSQL stores snapshots and their relationships with relational constraints, recursive queries, indexes, and diagnostic findings.

The sample data is synthetic. Live collection is read-only and does not terminate processes, change service states, or modify Windows configuration.

## Windows execution model

### Processes and threads

A **process** is an instance of a running program with its own virtual address space, security context, handles, loaded modules, and associated operating-system resources. A process provides an isolation boundary for its code and data, although access to another process depends on Windows security rules and granted permissions.

A **thread** is an execution unit scheduled by the operating system. Threads within the same process generally share its address space and process-level resources while maintaining individual execution contexts, stacks, scheduling state, and thread-local storage.

A process can own many threads. Thread count is useful for diagnosing workload structure, concurrency, and possible resource pressure, but it is not a direct measure of CPU utilization. CPU usage requires time-based measurements of execution time or performance counters.

The project reports thread counts as observed metadata rather than interpreting them as a performance score.

### Parent-child relationships

Windows process records expose a parent process identifier through process metadata. This supports an approximate creation ancestry graph:

`System → services.exe → svchost.exe`

and, in a desktop session:

`explorer.exe → powershell.exe → python.exe`

These relationships are useful for understanding how a process may have been launched. They do not prove that the parent is still running, that the parent originally launched the process under the current observation, or that a process is safe.

A process can exit before its child. The parent PID may consequently be absent from a later snapshot. Windows can also reuse PIDs. For reliable historical correlation, record process creation time alongside the PID and use appropriate operating-system identifiers when available.

The implementations therefore treat parent-child relationships as observations that require validation, not as unquestionable facts.

### Windows services

A Windows service is a managed background component registered with the Service Control Manager. Service configuration includes its name, display name, startup mode, execution account, and current state.

Services and processes are related but are not equivalent:

- A service is a managed operating-system component.
- A process is a running execution container.
- A service may be stopped and have no active process.
- Multiple services can share a service-host process, such as an `svchost.exe` instance.
- A process may host no Windows services at all.

The service examples correlate service process IDs with a process snapshot. A missing match does not automatically imply failure because the process may have exited, the snapshot may be incomplete, or the service may not currently have an assigned process.

### Process identifiers and snapshots

A PID identifies a process instance only during the relevant lifetime of that identifier. It is not a permanent identifier for an executable, user, or application.

A process snapshot is also not a perfectly simultaneous view of the operating system. Processes can start and exit while enumeration is underway. A diagnostic system should therefore record collection time, collector identity, collection completeness, and errors encountered while obtaining metadata.

The database uses a snapshot identifier to scope process identity. The application implementations similarly build a graph from one collected set of process records.

## Architecture and data flow

The implementations follow this diagnostic pipeline:

`Collection → Validation → Relationship reconstruction → Analysis → Service correlation → Report`

Collection retrieves process and service metadata. Validation checks the shape and consistency of the records. Relationship reconstruction builds direct parent-child links. Analysis traverses the graph, counts reported threads, and identifies missing parents. Service correlation associates a service's process ID with the snapshot. Reporting presents the findings without making changes to the operating system.

The separation matters because a collector can return incomplete metadata even when the graph-processing logic is correct. A reliable report must preserve that uncertainty rather than silently converting it into a definitive conclusion.

## Python implementation

The Python script is designed as a self-contained diagnostic application using the standard library.

### Inventory model

`ProcessInfo` stores the PID, image name, parent PID, thread count, executable path, command line, observation status, and reconstructed child identifiers. `ServiceInfo` stores service configuration and runtime information separately.

`ProcessInventory` validates process identifiers and rejects duplicate PIDs. It then reconstructs child relationships by indexing the records by PID. Each child list is sorted to make the printed hierarchy deterministic.

This structure avoids repeatedly scanning the entire process collection for every parent lookup. Once the PID index is built, direct relationship lookups are efficient.

### Hierarchy analysis

The `descendants()` method uses breadth-first traversal. A queue processes children before deeper descendants, while a visited set prevents repeated traversal if the graph is malformed.

The `depth()` method follows the parent chain and detects cycles. The tree renderer is iterative, which avoids relying on Python's recursion limit for unusually deep or malformed input.

The summary reports the number of observed processes, the sum of reported thread counts, the number of roots, and processes whose parents are absent from the snapshot.

### Live Windows collection

`collect_live_processes()` queries the `Win32_Process` CIM class through PowerShell. It retrieves process IDs, parent IDs, image names, thread counts, executable paths, and command lines when available.

`collect_live_services()` queries `Win32_Service` for service states, startup modes, service process IDs, and service accounts.

Both collectors handle PowerShell errors and malformed records. Metadata access can be restricted by permissions, and command lines can contain sensitive information. JSON reports should therefore be stored in an access-controlled location and shared only when appropriate.

The script uses simulated data when explicitly requested with `--sample`. On a non-Windows host, it uses that sample rather than attempting an unsupported live Windows query.

### Report generation

The `write_json_report()` function writes a structured document to a temporary file and replaces the destination after writing completes. This reduces the risk of a consumer reading a partially written report.

The report includes the collection timestamp, host platform, summary, process records, parent anomalies, and service correlations.

Example commands:

- `python windows_processes.py --sample --tree` displays the example hierarchy.
- `python windows_processes.py --live --tree` collects live process data on Windows.
- `python windows_processes.py --live --pid 1200` reports descendants of a selected PID.
- `python windows_processes.py --live --services` includes Windows service information.
- `python windows_processes.py --live --services --json process_report.json` exports a JSON report.

The PID in a command must exist in the selected snapshot.

## JavaScript implementation

The JavaScript file complements the Python collector with asynchronous process execution and a graph-oriented model.

### Process graph

`ProcessRecord` validates each record at construction. `ProcessGraph` stores records in a `Map` keyed by PID and reconstructs each parent's child list.

The `Map` provides direct PID lookup without repeated linear searches. The descendant query uses an indexed queue instead of repeatedly removing the first array element, avoiding the unnecessary shifting cost associated with repeated array `shift()` calls.

The tree renderer is iterative and includes a fallback for disconnected or cyclic components.

### Asynchronous collection

`runPowerShellJson()` wraps the child-process API in a Promise. Standard output and standard error are collected separately. A timeout limits how long the collector waits, and an output-size limit prevents unexpectedly large output from consuming unbounded memory.

PowerShell is invoked without loading the user's profile and without interactive prompts. The command performs a read-only CIM query and serializes the resulting records as JSON.

A production collector should also consider cancellation semantics, bounded diagnostic logging, executable discovery, and the possibility that terminating a collector process does not instantly cancel every operation it initiated.

### Report consistency

The JavaScript report writer creates a temporary file and renames it to the destination after writing succeeds. The temporary file is placed in the same directory to support an atomic rename on ordinary local filesystems.

Atomic replacement is not a substitute for access control, encryption, retention policies, or safe handling of command-line data. A production inventory service should define these policies explicitly.

Example commands:

- `node windows-processes.js --tree`
- `node windows-processes.js --live --tree`
- `node windows-processes.js --live --services`
- `node windows-processes.js --live --pid 1200 --json report.json`

The file uses `Array.prototype.toSorted()`, which is available in modern JavaScript runtimes. Use a current Node.js release that supports this method.

## C++ diagnostic case study

The C++ program models a process inventory used by a diagnostic agent. Its emphasis is structural correctness, predictable traversal, and explicit failure reporting.

### Data structures

`ProcessRecord` contains a PID, an optional parent PID, an image name, and a thread count. `ProcessSnapshot` stores records in an ordered map and stores child relationships in a separate adjacency index.

The ordered map makes output deterministic and provides logarithmic lookup. The adjacency index supports efficient traversal of direct descendants without scanning every process for each step.

`ServiceRecord` is intentionally separate from `ProcessRecord`. This preserves the distinction between a Windows service and the process currently associated with that service.

### Validation and failure handling

The constructor rejects PID zero, empty process names, and duplicate process identifiers. `validate()` identifies missing parents and detects cycles in parent chains.

Missing parents are reported as informational findings because an incomplete snapshot is not necessarily corrupt. A cycle is a structural error because it violates the expected ancestry model.

The program does not treat a missing service process as proof that the service is malfunctioning. It reports whether the PID is present in the supplied snapshot.

### Algorithmic behavior

Let \(V\) represent the number of observed processes and \(E\) represent the number of parent-child links.

Building the adjacency index requires \(O(V + E)\) expected work with a hash-based child index, plus the costs associated with ordered storage and sorting child lists. Breadth-first descendant traversal takes \(O(V_r + E_r)\) for the reachable subgraph, where \(V_r\) and \(E_r\) are its vertices and edges.

Iterative traversal avoids recursive stack growth. The visited set prevents infinite traversal if malformed relationships create cycles.

The example includes a process whose recorded parent PID is absent. This is intentional: a realistic diagnostic system must expose incomplete ancestry rather than fabricating a parent.

Compile with a C++17-compatible compiler. The implementation uses only the standard library.

## Java enterprise model

The Java implementation separates process metadata, service metadata, diagnostic findings, and report behavior into domain-oriented types.

### Immutable records and explicit states

`ProcessIdentity` associates a PID with an observation timestamp. `ProcessRecord` represents the observed process and its metadata. `ServiceRecord` describes the corresponding service state and configuration.

Enums constrain process observation states, service runtime states, and diagnostic severity to known values. Constructor validation prevents invalid PIDs, negative thread counts, blank image names, and self-parenting records.

Immutable records reduce accidental changes after an inventory has been constructed. They do not make the underlying operating-system observation immutable; they simply prevent application code from silently changing the stored record.

### Service correlation

`ServiceCorrelationService` receives a validated `ProcessInventory` and evaluates each service independently.

A service with process ID zero is reported as having no currently assigned process. A nonzero PID that is absent from the inventory is reported as unobserved. A matching PID is associated with its image name.

This design keeps service policy and process storage separate. A future enterprise collector can add additional service metadata without changing the process graph's identity rules.

### Diagnostic reporting

`DiagnosticReport` aggregates thread counts, ranks processes by reported thread count, renders the hierarchy, and displays structural findings.

The diagnostic model distinguishes an informational missing-parent finding from an error-level cycle. This is important in operational monitoring because observations can be incomplete even when the collector is functioning correctly.

Compile and execute with Java 17 or later:

- `javac WindowsProcessGovernance.java`
- `java WindowsProcessGovernance`

The example uses no third-party dependencies and does not require elevated permissions.

## PostgreSQL relational model

The SQL script represents multiple observations of one or more Windows hosts. It uses PostgreSQL-specific identity columns, enumerated types, composite foreign keys, recursive common table expressions, and transactional data loading.

### Core entities and relationships

| Table | Purpose |
|---|---|
| `hosts` | Identifies monitored Windows machines. |
| `process_snapshots` | Records when and how an inventory was collected. |
| `processes` | Stores PID, parent PID, image name, thread count, and observation state within a snapshot. |
| `windows_services` | Stores service configuration, runtime state, and associated process ID. |
| `process_threads` | Stores selected thread-level observations. |
| `diagnostic_findings` | Preserves structural findings and their severity. |

The snapshot is central to identity. A PID can be reused across time, so the process primary key is `(snapshot_id, pid)` rather than PID alone.

The composite parent foreign key ensures that a parent, when recorded, belongs to the same snapshot. The service foreign key similarly ensures that a non-null service PID refers to a process in that snapshot.

### Integrity constraints

The schema uses `CHECK` constraints to prohibit invalid PIDs, negative thread counts, self-parenting, blank process names, unsupported service states, and invalid thread states.

The deferred self-referencing foreign key permits parent and child records to be inserted in any order within a transaction. It is checked when the transaction commits.

The demonstration includes a process with parent PID 9999, which is absent from the inventory. Such a record is useful for diagnostics but conflicts with strict referential integrity. The script therefore highlights an important modeling decision: if missing parents must be retained, use a separate unresolved-parent observation field or stage incomplete data before inserting it into the normalized table. Do not weaken referential integrity without deciding how incomplete data will be represented.

### Queries and performance

The SQL includes queries for direct ancestry, recursive descendants, missing parents, aggregate thread counts, service correlation, and sampled thread details.

The recursive query carries a path array and avoids revisiting a PID along the same path. This protects the traversal from looping indefinitely if malformed ancestry is present.

Indexes support parent lookup, process ranking by thread count, service-state filtering, and diagnostic retrieval. Their value depends on actual query volume and table size. For small snapshots, indexes may cost more to maintain than they save in query time.

The script uses a transaction so the sample inventory is loaded as one unit. A production ingestion service should also define snapshot retention, idempotent imports, concurrent collection behavior, and the treatment of incomplete or failed collection runs.

## Diagnostic interpretation and operational limits

### Thread counts are not CPU measurements

A process with many threads may be waiting on I/O, waiting on synchronization objects, or performing computation. Thread counts describe observed concurrency structure, not the amount of processor time consumed.

CPU diagnosis requires repeated measurements over a time interval. Memory diagnosis likewise requires specific metrics such as working set, private bytes, or commit usage rather than process count alone.

### Missing ancestry requires context

A missing parent can indicate that the parent exited before the snapshot, that collection was incomplete, or that the observed PID no longer refers to the original process instance.

Investigations should compare timestamps, creation times, image paths, service state, and other available telemetry. A process name or parent PID by itself is not a reliable basis for declaring an incident.

### Access and privacy

Process metadata may require additional privileges. Failure to retrieve an executable path or command line should be represented as unavailable metadata rather than an empty claim that the value does not exist.

Command lines and service accounts can disclose usernames, file paths, authentication parameters, or other sensitive operational details. Reports should minimize collection, restrict access, and apply appropriate retention policies.

### Live observation versus historical evidence

A live process query captures a changing system. A database snapshot records what the collector observed at a particular time, not an authoritative record of every process that existed during that interval.

Reliable historical analysis benefits from creation timestamps, collection timestamps, explicit observation states, and records of collector failures. These fields help distinguish a real process relationship from a stale PID reference or an incomplete inventory.

## Design distinctions

A process is an execution container, a thread is an execution unit within that container, and a Windows service is a managed background component. Parent-child links describe process ancestry, not service ownership or security trust.

The Python and JavaScript implementations focus on collection, graph reconstruction, and report generation. The C++ implementation emphasizes graph integrity and algorithmic behavior. The Java implementation models explicit domain states and service-level responsibilities. PostgreSQL provides durable snapshot identity and relational integrity.

These distinctions are necessary for building diagnostics that remain useful when processes exit during collection, metadata is inaccessible, services share host processes, or parent identifiers cannot be resolved.
