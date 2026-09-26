# Nmap Fundamentals: TCP Scans, UDP Scans, Port States, Service Detection, and OS Detection

## Topic Introduction

Nmap is a network exploration and security auditing tool used to discover hosts, identify accessible network ports, detect services and versions, and, when sufficient evidence is available, infer operating-system characteristics.

The central idea is that a scanner does not directly inspect another machine's internal configuration. It observes network behavior and interprets responses.

This distinction is important:

- A TCP connection succeeding is evidence that something is accepting TCP connections.
- A TCP connection being refused usually indicates that the host is reachable but no service is listening on that port.
- A lack of response does not always prove that a port is closed.
- A UDP timeout is particularly ambiguous because UDP applications frequently do not respond to unexpected probes.
- A port number suggests a possible service but does not prove which application is running.
- OS detection is fingerprinting and therefore an inference rather than a guaranteed identification.

The Python, JavaScript, and C++ implementations in this project demonstrate these principles with standard language facilities. They intentionally default to `127.0.0.1`.

Network scanning should only be performed against systems and networks for which explicit authorization exists.

---

## Fundamental Concepts

### Network Address

An IP address identifies a network interface or endpoint.

Examples include:

- IPv4: `127.0.0.1`
- IPv4 private address: `192.168.1.10`
- IPv6 loopback: `::1`

`127.0.0.1` represents the IPv4 loopback interface. Traffic directed there remains on the local machine.

### Port

A transport-layer port is a number from `1` through `65535`.

Ports allow multiple network applications to coexist on the same IP address.

For example, a host could have:

- TCP port `22` used by SSH
- TCP port `80` used by HTTP
- TCP port `443` used by HTTPS
- UDP port `53` used by DNS

The port number is only an association or convention. An administrator can configure an application to use a different port.

### Socket

A socket is an operating-system interface for network communication.

The implementations use sockets to:

1. create a network endpoint,
2. specify a destination,
3. send or receive data,
4. interpret network errors,
5. close the endpoint.

Python uses the `socket` module, JavaScript uses Node.js `net` and `dgram`, and C++ uses operating-system socket APIs.

---

## TCP Fundamentals

TCP is connection-oriented.

A normal TCP connection begins with a handshake involving:

1. SYN
2. SYN-ACK
3. ACK

A TCP connect scan asks the operating system to establish a normal TCP connection.

The Python implementation performs this with `socket.create_connection()`.

The JavaScript implementation uses Node.js `net.Socket`.

The C++ implementation uses a TCP socket and a controlled `connect()` operation.

### TCP Connect Scan

Conceptually:

1. Create a TCP socket.
2. Attempt to connect to the target port.
3. Wait for the result.
4. Classify the observation.
5. Close the socket.

A successful connection provides strong evidence that the port is open.

A connection refusal generally indicates that the host is reachable but there is no listener on that TCP port.

A timeout may indicate filtering, packet loss, routing problems, or another condition that prevents a definite conclusion.

---

## TCP Connect Scan Versus SYN Scan

These are different scanning mechanisms.

### TCP Connect Scan

A TCP connect scan uses the operating system's normal connection mechanism.

Nmap syntax:

`nmap -sT -p 22,80,443 127.0.0.1`

Advantages:

- Does not require the same low-level packet access as a SYN scan.
- Straightforward to implement using ordinary socket APIs.
- Works well as an educational demonstration.
- Produces a clear connection result.

Limitations:

- It completes the TCP connection.
- It does not provide the same packet-level behavior as a SYN scan.
- Application-level activity may occur after connection establishment.
- It can generate more visible connection activity in logs.

### SYN Scan

Nmap's SYN scan uses TCP SYN packets and analyzes responses without completing the normal application connection in the same way as a TCP connect scan.

Nmap syntax:

`nmap -sS -p 22,80,443 127.0.0.1`

A SYN scan is a lower-level technique and generally requires additional privileges or packet capabilities.

The implementations in this project deliberately use ordinary TCP connections rather than attempting to reproduce Nmap's packet-level SYN scanner.

---

## Port States

Nmap's state terminology describes what the scanner can infer from network behavior.

### Open

An open port has an application accepting traffic.

For TCP, a successful connection is strong evidence of an open port.

For UDP, an application-level response is useful evidence that the service is reachable.

### Closed

A closed port is reachable, but no application is listening there.

A TCP connection refusal is a common indication.

Closed does not mean the host is unreachable.

### Filtered

A filtered state means that filtering prevents the scanner from determining whether an application is listening.

A firewall may silently discard packets.

The scanner may therefore experience a timeout.

### Open|Filtered

This state is especially important for UDP.

If a UDP probe receives no response, two possibilities can remain:

1. the port is open but the application did not answer the probe;
2. a filtering device prevented the response.

Silence alone cannot always distinguish those cases.

The Python and C++ implementations explicitly report `open|filtered` for UDP timeouts rather than incorrectly claiming that every timeout represents an open port.

### Closed|Filtered

In some scanning circumstances, the available evidence does not clearly distinguish a closed port from a filtered one.

The exact states Nmap reports depend on the scan type and the evidence obtained.

---

## Why UDP Scanning Is Different

UDP has no TCP-style three-way handshake.

A scanner can send a UDP datagram, but the absence of a response does not establish that the application is absent.

This creates a fundamental asymmetry:

**TCP**

Connection attempt -> response/refusal/timeout -> comparatively direct interpretation.

**UDP**

Probe -> application response or ICMP response or silence -> potentially ambiguous interpretation.

The Python implementation's `udp_probe()` function illustrates this distinction.

The JavaScript implementation uses Node.js `dgram`.

The C++ implementation creates an `SOCK_DGRAM` socket and waits for a response.

---

## UDP Application Probes

A good UDP scanner does more than blindly send arbitrary bytes.

Different services understand different protocols.

The Python, JavaScript, and C++ examples provide a small DNS-specific probe for UDP port `53`.

This is useful because DNS can return an application-level response.

For other UDP ports, the examples use an intentionally minimal probe and preserve uncertainty when there is no response.

A production-grade scanner uses protocol-aware probes and a large collection of carefully designed probes.

---

## Common Services and Port Numbers

The implementations include a small educational service map.

| Port | Common Service | Typical Protocol |
|---:|---|---|
| 21 | FTP | TCP |
| 22 | SSH | TCP |
| 23 | Telnet | TCP |
| 25 | SMTP | TCP |
| 53 | DNS | TCP/UDP |
| 80 | HTTP | TCP |
| 110 | POP3 | TCP |
| 123 | NTP | UDP |
| 143 | IMAP | TCP |
| 161 | SNMP | UDP |
| 389 | LDAP | TCP/UDP |
| 443 | HTTPS | TCP |
| 445 | SMB | TCP |
| 3306 | MySQL | TCP |
| 3389 | RDP | TCP |
| 5432 | PostgreSQL | TCP |
| 6379 | Redis | TCP |
| 8080 | Alternate HTTP | TCP |

These values are conventions, not guarantees.

An HTTP server can operate on `8080`, `8000`, `443`, or another configured port.

Likewise, a completely unrelated application can listen on port `80`.

---

## Service Detection

Port discovery answers a transport-level question:

> Is something reachable at this port?

Service detection asks a more detailed question:

> What application appears to be operating there?

These are different tasks.

Nmap uses the `-sV` option for service and version detection.

Example:

`nmap -sT -sV -p 22,80,443 127.0.0.1`

The implementations provide simplified service detection.

### Python

The Python script:

- recognizes common port conventions,
- sends an HTTP `HEAD` request to likely HTTP ports,
- reads immediately available banners from services such as SSH,
- records application-level observations.

### JavaScript

The JavaScript file performs similar HTTP and banner probing using Node.js sockets.

The asynchronous event-driven model makes JavaScript particularly suitable for demonstrating concurrent network I/O.

### C++

The C++ case study performs HTTP detection on ports `80` and `8080`.

It uses `select()` to place a bounded wait around network operations.

---

## Why Port-Based Identification Is Insufficient

Consider port `8080`.

A port-number database may associate it with HTTP, but the following are possible:

- an HTTP server,
- a development server,
- a proxy,
- a custom TCP application,
- a completely unrelated service.

Therefore:

`port number -> possible service`

is weaker than:

`port number + protocol response -> stronger service evidence`

Nmap's service detection goes considerably further by comparing responses against known service fingerprints and protocol behaviors.

---

## Nmap Service Detection

The principal option is:

`-sV`

Example:

`nmap -sV -p 22,80,443 127.0.0.1`

Service detection can examine:

- protocol responses,
- banners,
- application behavior,
- protocol-specific responses,
- service fingerprints,
- version information.

The exact level of identification depends on the service and scan conditions.

A service may intentionally suppress version information.

A proxy may hide the real backend.

A custom service may not match a known fingerprint.

---

## OS Detection

Nmap's OS detection uses network fingerprinting.

The `-O` option requests operating-system detection.

Example:

`nmap -O 127.0.0.1`

The implementation of OS fingerprinting can involve observations such as:

- TCP options,
- TCP window characteristics,
- TCP sequencing behavior,
- IP-level characteristics,
- ICMP responses,
- responses to selected probes,
- timing-related behavior.

The important principle is that the scanner observes behavior and compares that behavior with known fingerprints.

It does not need to log into the remote operating system.

### OS Detection Is an Inference

An OS detection result should not automatically be interpreted as absolute truth.

Possible reasons for uncertainty include:

- network address translation,
- firewalls,
- packet filtering,
- virtualization,
- unusual TCP/IP stacks,
- proxies,
- middleboxes,
- insufficient responses,
- customized operating systems.

The Python implementation uses `platform.system()` only to show the local operating system. It explicitly distinguishes that from remote OS fingerprinting.

The JavaScript implementation similarly reports `process.platform` and `os.type()` for the local Node.js runtime.

These local values are not equivalent to Nmap's remote OS detection.

---

## Host Discovery and Port Scanning

Host discovery and port scanning answer different questions.

### Host Discovery

Question:

> Which hosts appear to be reachable?

### Port Scanning

Question:

> Which transport-layer ports on this host appear accessible?

Nmap can perform host discovery before scanning ports.

The implementations here focus on port scanning and therefore do not reproduce Nmap's complete host-discovery subsystem.

---

## Python Implementation

The Python file is a standalone educational scanner using the standard library.

### Main Components

`validate_target()`

Validates a supplied target and resolves hostnames when appropriate.

`parse_ports()`

Accepts individual ports, comma-separated lists, and ranges.

Examples:

- `22`
- `22,80,443`
- `20-25`
- `22,80,8000-8010`

`tcp_connect_scan()`

Performs an individual TCP connect probe.

`scan_tcp_ports()`

Runs TCP probes concurrently using `ThreadPoolExecutor`.

`udp_probe()`

Demonstrates UDP probing and the `open|filtered` ambiguity.

`scan_udp_ports()`

Runs UDP probes concurrently.

`detect_http_service()`

Sends a minimal HTTP request and examines the response.

`detect_banner()`

Attempts to read an immediately available service banner.

`perform_service_detection()`

Applies lightweight service detection to open TCP ports.

`build_nmap_commands()`

Constructs Nmap commands for study without automatically executing arbitrary scans.

`run_local_nmap()`

Can execute a limited Nmap service-detection command only when the target resolves to loopback.

---

## Running the Python Implementation

A basic local scan is:

`python nmap_fundamentals.py`

TCP only:

`python nmap_fundamentals.py --mode tcp`

UDP only:

`python nmap_fundamentals.py --mode udp`

Selected ports:

`python nmap_fundamentals.py --target 127.0.0.1 --ports 22,80,443`

Port range:

`python nmap_fundamentals.py --target 127.0.0.1 --ports 1-100`

Service detection:

`python nmap_fundamentals.py --mode tcp --service-detection`

JSON output:

`python nmap_fundamentals.py --mode tcp --json results.json`

Nmap reference mode:

`python nmap_fundamentals.py --mode reference`

The default configuration uses localhost and a small collection of common ports.

---

## Python Concurrency

The Python implementation uses `ThreadPoolExecutor`.

Network scanning is primarily I/O-bound. While one socket waits for a network response, another probe can make progress.

This can make controlled concurrency substantially faster than strictly sequential scanning.

The trade-off is that more concurrency consumes:

- file descriptors,
- memory,
- threads,
- network capacity,
- target-side resources.

Concurrency should therefore be bounded.

The `--workers` option controls the number of concurrent operations.

---

## JavaScript Implementation

The JavaScript implementation is designed for Node.js.

It uses:

- `net` for TCP,
- `dgram` for UDP,
- Promises for asynchronous operations,
- event listeners for socket events,
- a custom concurrency controller.

### TCP

`tcpConnectScan()` creates a `net.Socket`.

Important events include:

- `connect`
- `timeout`
- `error`

The implementation maps these events into port states.

### UDP

`udpProbe()` uses `dgram.createSocket("udp4")`.

The function demonstrates the event-driven nature of UDP communication.

A received datagram is evidence of an application response.

A timeout is reported as `open|filtered`.

### Service Detection

`detectHttpService()` sends:

`HEAD / HTTP/1.0`

and reads the status line and available headers.

The code intentionally limits the response size because service detection should not require unrestricted application data collection.

---

## Running the JavaScript Implementation

Basic execution:

`node nmap_fundamentals.js`

TCP scan:

`node nmap_fundamentals.js --mode tcp`

UDP scan:

`node nmap_fundamentals.js --mode udp`

Specific ports:

`node nmap_fundamentals.js --target 127.0.0.1 --ports 22,80,443`

Service detection:

`node nmap_fundamentals.js --mode tcp --service-detection`

Change concurrency:

`node nmap_fundamentals.js --mode tcp --concurrency 4`

Change timeout:

`node nmap_fundamentals.js --mode tcp --timeout 1000`

---

## JavaScript Event-Driven Design

Node.js is useful for illustrating network I/O because its socket APIs are naturally asynchronous.

The implementation does not need to create one blocking thread per network operation.

Instead:

1. a socket operation starts,
2. Node.js waits for an event,
3. another operation can proceed,
4. the result is handled by a callback or Promise,
5. the Promise resolves,
6. the controlled scheduler launches more work.

This model is particularly useful when many network operations are waiting for responses.

---

## C++ Case Study

The C++ program models an internal security inventory utility.

The scenario is:

> An authorized security operations team wants to examine selected common ports on a controlled host, classify their observed states, perform a basic application probe, and generate a structured terminal report.

The program starts with localhost by default.

### Architecture

The case study is divided into several layers:

1. Platform socket management
2. Address resolution
3. TCP scanning
4. UDP scanning
5. Service identification
6. HTTP application probing
7. Concurrent orchestration
8. Result classification
9. Reporting
10. Nmap command reference

This structure demonstrates how a small network-scanning utility can evolve from a single socket operation into a modular system.

---

## C++ Data Structures

The program defines:

`enum class PortState`

This provides strongly typed port-state values.

Possible values include:

- `Open`
- `Closed`
- `Filtered`
- `OpenOrFiltered`
- `Error`

`struct ScanResult`

Stores:

- port,
- protocol,
- state,
- service,
- observation,
- latency.

A structured result is preferable to returning a single string because later reporting, logging, testing, and analysis can use individual fields.

---

## C++ TCP Algorithm

The TCP scanner follows this process:

1. Resolve the target to IPv4.
2. Create a `SOCK_STREAM` socket.
3. Configure non-blocking behavior.
4. Call `connect()`.
5. Use `select()` to enforce a timeout.
6. Check the resulting socket error.
7. Classify the port.
8. Measure latency.
9. Close the socket.

The use of non-blocking I/O and `select()` prevents a filtered port from causing an uncontrolled blocking wait.

---

## C++ UDP Algorithm

The UDP scanner:

1. Resolves the target.
2. Creates a `SOCK_DGRAM` socket.
3. Constructs a DNS query for port `53`.
4. Sends the probe.
5. Waits for a response.
6. Classifies the response.
7. Treats silence conservatively as `open|filtered`.
8. Records latency.
9. Closes the socket.

This demonstrates why UDP scanning requires different reasoning from TCP scanning.

---

## C++ Concurrency

The C++ implementation uses `std::async` with `std::launch::async`.

Each selected port can be probed independently.

For a small educational port set, this is straightforward.

A production scanner would generally require more explicit concurrency management, especially when scanning thousands of ports or many hosts.

Possible production concerns include:

- maximum socket count,
- worker pools,
- retry queues,
- rate limiting,
- connection lifecycle management,
- cancellation,
- memory usage,
- result ordering,
- timeout scheduling.

---

## Complexity Considerations

Suppose there are `N` selected ports.

A sequential scanner performs approximately `N` probe operations.

The amount of work is therefore approximately:

`O(N)`

Concurrency does not remove the total amount of network work. It reduces wall-clock waiting when operations can proceed independently.

For a timeout-bound scan, an approximate sequential worst-case duration can approach:

`N × timeout`

A concurrent implementation can reduce wall-clock time, but the actual improvement depends on:

- concurrency,
- latency,
- packet loss,
- target behavior,
- operating-system limits,
- network capacity.

Increasing concurrency indefinitely is not a valid optimization strategy.

---

## Latency Measurement

All three implementations record approximate probe latency.

Latency can help distinguish:

- immediate connection refusal,
- rapid successful connection,
- delayed responses,
- timeout behavior.

Latency should not be interpreted as a definitive security or OS characteristic.

Network paths, load, routing, congestion, filtering, and virtualization can all affect timing.

---

## Important Distinctions

### Port State Versus Service

Port state answers whether the transport endpoint appears reachable.

Service detection attempts to identify the application.

They are related but separate observations.

### Service Detection Versus OS Detection

Service detection focuses on the application protocol.

OS detection focuses on characteristics of the network stack.

### TCP Versus UDP

TCP provides connection-oriented behavior.

UDP provides datagram-oriented behavior.

This difference has major consequences for scanning.

### Connect Scan Versus SYN Scan

A connect scan uses a normal OS-level connection.

A SYN scan analyzes lower-level TCP behavior without requiring the same completed connection model.

### Local OS Identification Versus Remote OS Fingerprinting

Calling Python's `platform.system()` or Node's `os.type()` tells the local process about its own operating system.

Nmap's `-O` option attempts to infer a remote host's operating-system family from network responses.

These are fundamentally different operations.

---

## Common Mistakes

### Mistake 1: Treating a Port Number as Proof

Port `22` commonly means SSH, but the number alone does not prove that SSH is running.

Use application-level evidence when service identification matters.

### Mistake 2: Treating UDP Silence as Open

UDP silence can correspond to `open|filtered`.

A scanner should preserve uncertainty.

### Mistake 3: Assuming Closed Means Unreachable

A closed TCP port can still demonstrate that the host itself is reachable.

The connection refusal is evidence about the port.

### Mistake 4: Assuming Every Timeout Means Filtering

Timeouts can result from:

- firewalls,
- packet loss,
- routing issues,
- overloaded hosts,
- short timeout values,
- network congestion.

### Mistake 5: Using Excessive Concurrency

More concurrent probes can increase speed but can also:

- exhaust local resources,
- increase packet load,
- overwhelm services,
- make observations less reliable.

### Mistake 6: Assuming Service Detection Is Always Correct

Custom services, proxies, modified software, and incomplete responses can make service identification uncertain.

### Mistake 7: Treating OS Detection as Guaranteed

OS fingerprinting is an inference from observed behavior.

Middleboxes, virtualization, filtering, and unusual configurations can affect the fingerprint.

### Mistake 8: Ignoring IPv6

A hostname can resolve to both IPv4 and IPv6 addresses.

An IPv4-only scanner may therefore provide an incomplete picture.

---

## Edge Cases

### Port 0

Port `0` is not treated as a normal application port in these implementations.

The valid scanning range is `1` through `65535`.

### Empty Port List

The parsers reject an empty port specification.

This prevents accidental execution with an undefined scan scope.

### Reversed Range

A range such as `100-90` is normalized to `90-100` in the Python and JavaScript implementations.

### Duplicate Ports

A set-based representation removes duplicate port numbers before scanning.

### Hostname Resolution Failure

The Python and C++ implementations detect address-resolution failures before attempting the scan.

### Filtered TCP Port

The TCP implementations use bounded timeouts.

A timeout is classified conservatively rather than being reported as a successful connection.

### UDP No Response

UDP timeout results are explicitly represented as `open|filtered`.

### Service Without a Banner

Some services do not immediately send a banner.

Absence of a banner does not prove that a service is absent.

---

## Error Handling

Network programs must expect errors.

Common conditions include:

- invalid hostname,
- DNS resolution failure,
- connection refusal,
- connection timeout,
- socket creation failure,
- permission errors,
- network interruption,
- unavailable local resources.

The Python implementation uses exception handling.

The JavaScript implementation uses socket error events and Promise resolution.

The C++ implementation checks socket return values and translates failures into structured scan results.

---

## Performance Considerations

A scanner's performance depends on more than CPU speed.

Important variables include:

- number of ports,
- number of hosts,
- timeout,
- retry count,
- concurrency,
- packet rate,
- network latency,
- packet loss,
- firewall behavior,
- target responsiveness.

### Timeout Trade-Off

A very short timeout can cause false uncertainty.

A very long timeout can make a scan unnecessarily slow.

The appropriate value depends on the network environment.

### Concurrency Trade-Off

Low concurrency:

- lower resource consumption,
- lower network load,
- potentially slower scans.

Higher concurrency:

- better utilization of waiting time,
- potentially faster scans,
- greater resource and network demands.

A production scanner should use controlled concurrency rather than unbounded parallelism.

---

## Security Considerations

Network scanning is a dual-use capability.

The same techniques can support legitimate:

- asset inventory,
- security auditing,
- troubleshooting,
- service discovery,
- configuration validation,
- authorized penetration testing.

They can also be used improperly against systems without authorization.

The examples therefore default to `127.0.0.1`.

The Python script's optional automatic Nmap execution is restricted to a loopback target.

The educational examples avoid automatic broad network discovery and do not implement an unrestricted host-range scanner.

### Least Scope

When conducting an authorized scan, use the smallest target and port scope necessary for the task.

A focused scan is easier to interpret and reduces unnecessary network activity.

### Logging

Production security tooling should preserve:

- timestamp,
- target,
- protocol,
- port,
- state,
- probe type,
- observed service,
- latency,
- error condition.

This creates an auditable record of what was observed.

---

## Nmap Command Mapping

The concepts demonstrated by the code correspond to common Nmap options.

### TCP Connect Scan

`nmap -sT -p 22,80,443 127.0.0.1`

### UDP Scan

`nmap -sU -p 53,161 127.0.0.1`

### Service Detection

`nmap -sV -p 22,80,443 127.0.0.1`

### OS Detection

`nmap -O 127.0.0.1`

### Combined Example

`nmap -sT -sV -O -p 22,80,443 127.0.0.1`

These commands are references to the corresponding Nmap mechanisms. The custom implementations do not reproduce Nmap's complete internal scanner architecture.

---

## What the Python Implementation Demonstrates

The Python script emphasizes:

- beginner-friendly socket programming,
- input validation,
- TCP connection scanning,
- UDP behavior,
- port-state classification,
- concurrent I/O,
- lightweight service detection,
- structured results,
- JSON export,
- Nmap command construction,
- local Nmap integration,
- operating-system detection concepts.

Python's standard library makes it practical to construct a readable network-scanning study implementation without third-party packages.

---

## What the JavaScript Implementation Demonstrates

The JavaScript file emphasizes:

- Node.js networking,
- TCP sockets,
- UDP datagrams,
- asynchronous programming,
- Promises,
- event-driven error handling,
- controlled concurrency,
- HTTP application probing,
- service identification,
- network timeout management.

JavaScript is particularly useful here because Node.js exposes network operations through an event-driven programming model.

---

## What the C++ Implementation Demonstrates

The C++ case study emphasizes:

- low-level socket APIs,
- explicit resource management,
- strong data modeling,
- `select()`-based timeout control,
- TCP and UDP socket differences,
- asynchronous task execution,
- platform abstraction,
- structured scan results,
- application-level HTTP probing,
- complexity and resource considerations.

C++ makes the operating-system interaction more explicit than the higher-level Python and Node.js examples.

---

## Practical Applications

The concepts in this project are relevant to:

- internal asset inventory,
- authorized security assessments,
- network troubleshooting,
- firewall validation,
- service exposure reviews,
- infrastructure monitoring,
- network architecture analysis,
- incident investigation,
- configuration verification.

A port scan can reveal the externally observable attack surface of a system, but it does not by itself establish that a discovered service is vulnerable.

Port discovery is one observation in a larger security assessment process.

---

## Implementation Limitations

These implementations are educational and intentionally smaller than Nmap.

They do not reproduce the full Nmap feature set.

Important omissions include:

- complete host discovery,
- SYN scanning,
- FIN/NULL/Xmas scanning,
- SCTP scanning,
- comprehensive IPv6 behavior,
- Nmap's full service-probe database,
- Nmap's complete OS fingerprint database,
- packet-level retransmission logic,
- sophisticated packet-rate control,
- evasion techniques,
- NSE scripting,
- complete version matching,
- advanced firewall detection,
- traceroute integration,
- comprehensive XML/Grepable output,
- large-scale distributed scanning.

These omissions are deliberate because the goal is to demonstrate the underlying concepts rather than reproduce the entire Nmap codebase.

---

## Production Considerations

A production-grade scanner requires stronger engineering around:

### Scope Management

Targets should be explicitly configured and validated.

### Rate Control

Scanning should be bounded to avoid unnecessary network load.

### Retries

Transient packet loss should not automatically become a definitive state.

### Fingerprinting

Service and OS identification require carefully designed probe databases.

### IPv4 and IPv6

Both address families may need independent handling.

### Resource Management

Large scans require explicit control of:

- sockets,
- descriptors,
- worker counts,
- memory,
- queues,
- timers.

### Observability

Structured logs and machine-readable output are important for integration with security operations systems.

### Result Confidence

Scanner results should distinguish between strong evidence and uncertain inference.

---

## Example Interpretation

Suppose a TCP probe to port `80` succeeds.

A reasonable interpretation is:

> The target accepted the TCP connection on port 80.

If the port is conventionally associated with HTTP, it is reasonable to perform an HTTP probe.

If the response begins with an HTTP status line, there is stronger evidence that an HTTP-speaking service is present.

The correct chain of reasoning is therefore:

`TCP connection succeeded`

then:

`Application response observed`

then:

`Response resembles HTTP`

rather than:

`Port 80 automatically proves HTTP`.

The same reasoning applies to OS detection.

A fingerprint is evidence about network-stack behavior, not direct access to the remote machine's operating-system metadata.

---

## Educational Architecture

The three implementations intentionally approach the same topic from different technical levels.

| Implementation | Main Emphasis |
|---|---|
| Python | Readability, sockets, validation, concurrency, structured scanning |
| JavaScript | Event-driven network I/O, Promises, asynchronous sockets |
| C++ | Operating-system socket APIs, explicit resource handling, system-level design |

The conceptual model remains the same:

`Target -> Transport Probe -> Response -> State -> Application Evidence -> Interpretation`

The programming model changes according to the language.

---

## Key Technical Principles

1. A port is a transport endpoint, not a guaranteed service identity.
2. TCP and UDP require different scanning logic.
3. TCP connection success is strong evidence of an accessible listener.
4. TCP refusal commonly indicates a reachable host with no listener.
5. A timeout does not automatically prove a port is closed or open.
6. UDP silence commonly creates `open|filtered` ambiguity.
7. Service detection operates above basic port-state discovery.
8. OS detection uses network fingerprints rather than direct remote OS queries.
9. Timeouts and concurrency affect both performance and reliability.
10. Scanner results represent observations and inferences, not absolute knowledge.
11. Network scanning should be explicitly authorized.
12. Production scanners need careful resource, rate, scope, and result-confidence management.
