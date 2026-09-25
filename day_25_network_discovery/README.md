# Network Discovery: Host Discovery, Service Discovery, Banners, and Network Mapping

## Topic

Network discovery is the process of identifying networked systems, reachable endpoints, exposed services, and useful identifying information about those services.

This implementation set examines network discovery through three programming environments:

- Python for a readable, modular discovery and inventory tool
- JavaScript with Node.js for event-driven socket operations and asynchronous processing
- C++ for a lower-level technical case study involving POSIX sockets, timeouts, concurrency, and structured reporting

The examples focus on TCP-based discovery and passive banner collection. They do not implement stealth, evasion, exploitation, credential attacks, or vulnerability exploitation.

All active discovery should be performed only against systems and networks for which explicit authorization exists.

---

# 1. Fundamental Concepts

## 1.1 What is network discovery?

Network discovery answers questions such as:

- Which addresses appear reachable?
- Which TCP ports accept connections?
- Which services appear to be listening?
- Does a service expose a banner?
- What hostname is associated with an IP address?
- What systems and services belong to an authorized network inventory?

Discovery is different from exploitation.

A discovery operation gathers information. An exploitation operation attempts to take advantage of a weakness.

A network inventory system should normally maintain a clear boundary between these activities.

---

# 2. Core Terminology

## Host

A host is a networked endpoint that can communicate using one or more network protocols.

Examples include:

- workstation
- server
- router
- printer
- virtual machine
- container
- network appliance
- IoT device

A host is commonly represented by an IP address.

## IP address

An IPv4 address contains 32 bits and is normally written as four decimal octets.

Example:

`192.168.1.20`

IPv6 uses 128 bits and has a substantially different textual representation.

The implementations in this study primarily demonstrate IPv4.

## Port

A port identifies a transport-layer endpoint.

TCP and UDP each have their own port namespace.

TCP port `22` and UDP port `22` are not the same endpoint.

Port numbers range from `1` through `65535` for the normal TCP and UDP port spaces.

Port ranges are conventionally divided into:

- well-known ports
- registered ports
- dynamic/private ports

The number alone does not guarantee which application is running.

For example, TCP port `8080` is commonly associated with HTTP alternatives, but an arbitrary application can listen there.

---

# 3. TCP and UDP

## TCP

TCP is connection-oriented.

A typical TCP connection involves:

1. Client attempts a connection.
2. TCP connection establishment occurs.
3. The server accepts or rejects the connection.
4. Application-layer communication can occur.

A successful TCP connection to a port is strong evidence that something is listening at that endpoint.

It does not prove exactly which application is operating there.

## UDP

UDP is connectionless.

There is no TCP-style connection establishment.

This makes UDP discovery fundamentally different from TCP discovery.

A UDP service may:

- respond to a valid request
- respond with an ICMP error
- remain silent
- be filtered by a firewall
- require application-specific protocol data before responding

The Python, JavaScript, and C++ implementations intentionally concentrate on TCP so that the mechanics of sockets, connection state, service discovery, and banners can be studied clearly.

---

# 4. Host Discovery

Host discovery attempts to determine whether an address appears reachable.

Possible techniques include:

- ICMP Echo
- TCP connection attempts
- UDP probes
- ARP on local Ethernet networks
- protocol-specific discovery mechanisms

Different techniques provide different evidence.

A host can be online while refusing all TCP connections used by a particular discovery method.

Therefore:

> "No response" is not equivalent to "the host does not exist."

A firewall may silently discard traffic.

---

# 5. TCP-Based Host Discovery

The Python implementation uses `socket.connect_ex()`.

The basic logic is:

1. Create a TCP socket.
2. Set a timeout.
3. Attempt a connection to a selected port.
4. Interpret the result.
5. Close the socket.
6. Repeat for selected ports when necessary.

If a connection succeeds, the host has demonstrated that a TCP endpoint is reachable.

The implementation deliberately uses a small explicit port list instead of automatically scanning every TCP port.

This makes the educational behavior easier to understand and keeps the traffic controlled.

---

# 6. Port States

The implementations use several simplified states.

## Open

A TCP connection was accepted.

This provides evidence that an application is listening.

## Closed

The target responded but rejected the connection.

This can still be useful evidence because the response demonstrates that the address is reachable at the network level.

## Filtered or timeout

The program could not determine whether the port was open because traffic may have been filtered, silently discarded, routed incorrectly, or delayed beyond the timeout.

## Error

The operating system reported another condition that prevented reliable classification.

Real network scanners can have considerably more nuanced state models.

---

# 7. Service Discovery

Port discovery answers:

> Which ports appear accessible?

Service discovery asks:

> What service appears to be associated with an accessible port?

A simple service inventory may map conventional port numbers to conventional names.

For example:

- TCP/22 → SSH
- TCP/25 → SMTP
- TCP/80 → HTTP
- TCP/443 → HTTPS
- TCP/3306 → MySQL
- TCP/5432 → PostgreSQL
- TCP/3389 → RDP

These are conventions, not guarantees.

A program can deliberately listen on an unconventional port.

Therefore:

`port number -> service guess`

is weaker evidence than:

`port behavior + protocol response -> service identification`

This distinction is important when interpreting scanner output.

---

# 8. Banner Discovery

A banner is information exposed by a network service that can help identify the service or its configuration.

Examples include:

- SSH identification strings
- SMTP greetings
- HTTP response headers
- FTP greetings
- application-specific protocol information

A banner can potentially reveal:

- product name
- protocol
- software family
- version
- hostname
- configuration information

The absence of a banner does not mean that the service is unidentified or unavailable.

Some applications wait for the client to send a valid protocol request before responding.

The implementations in this study use passive banner collection. They connect and read information that the service sends without sending arbitrary application-layer probe payloads.

---

# 9. Banner Data Is Untrusted

Network responses must be treated as untrusted input.

A banner can contain:

- unexpected characters
- very long data
- misleading information
- terminal control characters
- protocol-specific encoding
- malformed data

The implementations therefore:

- limit banner size
- decode safely
- remove problematic control characters
- avoid assuming that the banner is authoritative

A production inventory system should also escape data correctly when placing it into HTML, SQL, logs, JSON, or other formats.

---

# 10. Reverse DNS

Reverse DNS attempts to map an IP address back to a hostname.

For example:

`192.168.1.20 -> workstation.example.internal`

The mapping is normally provided through a PTR record.

Reverse DNS can fail for legitimate reasons:

- no PTR record exists
- DNS is unavailable
- the target does not publish reverse records
- a firewall or network configuration interferes
- the name is not meaningful to the operator

Therefore:

> A missing hostname is not evidence that a host is invalid or unavailable.

The implementations treat reverse DNS as supplementary metadata rather than as a requirement for discovery.

---

# 11. Network Mapping

A network map converts individual observations into structured information.

A useful inventory record can contain:

- IP address
- hostname
- reachability state
- latency
- open ports
- protocol
- service guess
- banner
- timestamp
- error information

The Python `NetworkMap`, JavaScript object structure, and C++ `NetworkMap` all follow this general model.

Structured data is more useful than terminal-only output because it can later be:

- stored
- searched
- compared
- visualized
- exported
- processed by another system

---

# 12. CIDR and Subnets

CIDR notation describes an address range.

Example:

`192.168.1.0/24`

The `/24` indicates that the first 24 bits represent the network prefix.

A conventional IPv4 `/24` contains:

`256`

total addresses.

For a normal subnet interpretation:

- one address represents the network
- one represents the broadcast address
- the remaining addresses are normally usable host addresses

The exact behavior of special-purpose ranges and modern network configurations requires additional context.

The Python implementation uses the standard `ipaddress` module to inspect networks instead of manipulating IP addresses as strings.

---

# 13. Why Address Parsing Matters

Naive string-based subnet processing can produce incorrect results.

For example, an implementation that simply increments the final decimal octet can fail at:

`192.168.1.255`

It also fails to correctly model different prefix lengths.

Python's `ipaddress` module provides:

- address parsing
- network parsing
- prefix information
- network and broadcast addresses
- host iteration
- address counts

For production systems, validated network libraries should be preferred over handwritten string arithmetic.

---

# 14. Python Implementation

The Python program is designed as a complete educational inventory tool.

Its major components are:

- `PortResult`
- `HostResult`
- `NetworkMap`
- `reverse_dns()`
- `tcp_host_discovery()`
- `tcp_connect()`
- `scan_tcp_ports()`
- `grab_tcp_banner()`
- `discover_services()`
- `inspect_host()`
- `parallel_inventory()`
- `save_json()`

These components separate discovery, classification, reporting, and persistence.

---

# 15. Python Port Testing

The function `tcp_connect()` demonstrates a fundamental network-programming operation.

The sequence is:

1. Create a socket.
2. Set a timeout.
3. Connect to an IPv4 address and TCP port.
4. Measure elapsed time.
5. Interpret the result.
6. Close the socket.

`connect_ex()` is useful for an inventory utility because it returns an error code rather than requiring every unsuccessful connection to be handled as an exception.

The code still handles timeouts and operating-system failures explicitly.

---

# 16. Python Banner Handling

The Python function `grab_tcp_banner()` establishes a connection and waits for the service to send data.

It does not send arbitrary protocol probes.

This demonstrates an important distinction:

- Passive banner collection reads unsolicited server information.
- Active service probing sends protocol-specific data to identify a service.

Professional scanners may implement much more sophisticated active service detection.

---

# 17. Python Concurrency

Network I/O often spends time waiting for operating-system and remote-host responses.

The Python implementation uses `ThreadPoolExecutor` for host-level concurrency.

Concurrency can significantly reduce elapsed time when many independent network operations are waiting.

The trade-off is increased network traffic.

Too much concurrency can cause:

- network congestion
- excessive socket creation
- resource exhaustion
- inaccurate results
- increased load on monitored systems
- operational alerts

The correct concurrency level depends on the authorized environment.

---

# 18. Python JSON Reporting

The Python inventory can be exported to JSON.

A record conceptually contains information similar to:

`ip`

`reachable`

`reverse_dns`

`latency_ms`

`ports`

Each port record contains:

`port`

`protocol`

`state`

`service_guess`

`banner`

`error`

This is a useful architecture because presentation is separated from collected data.

---

# 19. JavaScript Implementation

The JavaScript implementation uses Node.js networking APIs.

The major APIs are:

- `net`
- `dns`
- `os`
- `fs/promises`

The `net.Socket` class provides TCP networking.

The asynchronous model demonstrates how JavaScript can perform network operations without blocking the entire event loop.

---

# 20. JavaScript Event-Driven Networking

The JavaScript implementation registers handlers such as:

- `connect`
- `data`
- `timeout`
- `error`
- `close`

This is an event-driven model.

Instead of repeatedly blocking on a socket operation, the program registers behavior that executes when an event occurs.

This model is particularly natural for network applications.

---

# 21. JavaScript Promises

The `tcpConnect()` function returns a Promise.

This allows the calling code to use:

`await tcpConnect(...)`

instead of manually managing callback chains.

The implementation also explicitly prevents multiple completion paths from resolving the same operation using a `settled` flag.

This is important because networking can generate several events during the lifetime of a socket.

---

# 22. Bounded Concurrency

The JavaScript program includes `boundedMap()`.

A naive implementation could launch every network operation simultaneously with a large `Promise.all()` call.

That can become problematic for a large inventory.

Bounded concurrency allows a fixed number of workers to operate at the same time.

This provides better control over:

- memory consumption
- open sockets
- network traffic
- remote system load
- overall resource usage

The same principle applies to Python thread pools and C++ worker designs.

---

# 23. JavaScript Reverse DNS

Node.js provides asynchronous DNS functionality.

The implementation uses:

`dns.promises.reverse()`

The result is optional.

A failed reverse lookup does not cause host discovery to fail.

This is an example of separating primary evidence from enrichment data.

---

# 24. JavaScript JSON Reporting

JavaScript objects map naturally to JSON.

The inventory can therefore be serialized using:

`JSON.stringify(networkMap, null, 2)`

The second argument controls formatting indentation.

The result can be stored in a file using the promise-based filesystem API.

---

# 25. C++ Case Study

The C++ implementation models a small internal asset-inventory component.

The scenario is:

> An authorized organization wants to verify whether selected hosts expose selected TCP services and record useful metadata.

The system pipeline is:

1. Validate target address.
2. Attempt TCP host discovery.
3. Examine selected ports.
4. Classify conventional service names.
5. Attempt passive banner collection.
6. Perform reverse DNS.
7. Store results in structured objects.
8. Generate terminal output.
9. Optionally write a JSON report.

This is closer to the architecture of a small systems-level inventory component than a collection of isolated syntax examples.

---

# 26. C++ Socket Architecture

The C++ program uses POSIX socket APIs.

Important operations include:

- `socket()`
- `connect()`
- `select()`
- `getsockopt()`
- `recv()`
- `close()`

The `TcpSocket` class provides RAII-style resource ownership.

Its destructor closes an open descriptor automatically.

This is an important C++ design principle:

> Resources should have clearly defined ownership and cleanup behavior.

Sockets are operating-system resources, so failing to close them can eventually exhaust process resources.

---

# 27. C++ Non-Blocking Connect

The C++ case study uses a non-blocking socket during connection establishment.

This allows the program to use `select()` to wait for completion with an explicit timeout.

The high-level sequence is:

1. Create socket.
2. Change it to non-blocking mode.
3. Call `connect()`.
4. If connection is in progress, wait using `select()`.
5. Check `SO_ERROR`.
6. Classify the result.

This illustrates a lower-level implementation detail that higher-level Python and Node.js abstractions largely hide.

---

# 28. Why Explicit Timeouts Matter

Without an explicit timeout, a network operation can wait much longer than the application expects.

Timeouts are important for:

- predictable execution
- user experience
- batch inventories
- concurrency control
- failure recovery

A timeout does not automatically mean the port is closed.

The timeout means that the program did not obtain sufficient evidence within the configured period.

---

# 29. Service Identification Limitations

A port-to-service lookup is only a guess.

For example:

`TCP/80 -> HTTP`

is a convention.

A different application can listen on TCP/80.

A more sophisticated service-identification engine may examine:

- protocol responses
- protocol negotiation
- response structure
- application signatures
- version strings
- multiple probes

Nmap's `-sV` feature is designed for service/version detection.

The educational programs here intentionally use a simpler mechanism.

---

# 30. Nmap Concepts

Nmap is a network exploration and security auditing tool.

Several commonly encountered options illustrate different discovery layers.

`nmap 192.168.1.10`

Performs a normal scan of the specified target using Nmap's default behavior.

`nmap -sn 192.168.1.0/24`

Requests host discovery without a normal port scan.

`nmap -p 22,80,443 192.168.1.10`

Limits the port set to selected ports.

`nmap -sV 192.168.1.10`

Attempts service/version detection.

`nmap -O 192.168.1.10`

Attempts operating-system detection.

`nmap -A 192.168.1.10`

Enables a combination of advanced detection features and can generate substantially more probing traffic.

Exact behavior depends on the target, privileges, protocol, firewall behavior, Nmap version, and selected options.

---

# 31. Nmap State Interpretation

Nmap can report states such as:

- `open`
- `closed`
- `filtered`
- `unfiltered`
- `open|filtered`
- `closed|filtered`

The meanings depend on the scan type and protocol.

The key concept is that scanner states represent evidence gathered from probes.

They should not be interpreted as absolute statements about the entire network.

For example:

`filtered`

does not necessarily mean:

> no service exists.

It means the scanner could not reliably establish the required state because filtering interfered with the test.

---

# 32. Host Discovery and Port Discovery Are Different

Host discovery asks:

> Is there evidence that this address is reachable?

Port discovery asks:

> What transport endpoints respond?

A host can be discovered even when all examined ports are closed.

A host can also fail one discovery mechanism while still being accessible through another.

This is why network scanners commonly provide multiple discovery mechanisms.

---

# 33. TCP Versus ICMP Discovery

ICMP Echo is often called "ping," but host discovery does not have to use ICMP.

TCP-based discovery can be useful when ICMP is filtered.

ICMP-based discovery can be useful when TCP application ports are not suitable.

Local Ethernet discovery may use ARP because ARP operates below IP.

Each mechanism answers a slightly different question.

---

# 34. UDP Discovery

UDP discovery requires separate reasoning.

Because UDP has no TCP-style handshake, the absence of a response is ambiguous.

A UDP port may be:

- open
- closed
- filtered
- open but silent

Application-specific requests can produce useful responses, but the request must conform to the protocol being tested.

A TCP-only scanner therefore cannot claim to provide a complete inventory of all network services.

---

# 35. Banners and Version Information

A banner may contain a version string such as:

`SSH-2.0-example-server`

This can help identify a product family.

There are important limitations:

- banners can be disabled
- banners can be customized
- version strings can be misleading
- reverse proxies can hide the backend
- multiple services can share infrastructure
- a version string alone does not prove vulnerability

Discovery information should therefore be treated as evidence requiring appropriate interpretation.

---

# 36. Edge Cases

## Host is online but all ports are filtered

The scanner may report no confirmed reachable service.

This does not establish that the host is offline.

## Host is online but all selected ports are closed

A TCP discovery method may still classify the host differently from a method that requires an open application port.

## Service does not provide a banner

The port can still be open.

## Reverse DNS fails

The IP address can still be completely valid.

## Service uses a non-standard port

A port-number lookup may provide an incorrect service guess.

## Firewall silently drops traffic

The scanner may reach its timeout.

## Connection is refused

This can be valuable evidence that the host responded but the requested service was not accepting connections.

## Network route is unavailable

The error may resemble filtering from the application's perspective.

---

# 37. Common Mistakes

## Mistake 1: Treating an open port as proof of software identity

An open port only proves that something accepted the connection.

## Mistake 2: Treating no response as proof of an offline host

Firewalls and routing can prevent responses.

## Mistake 3: Scanning enormous networks without scope controls

Large address ranges can produce substantial traffic and operational impact.

## Mistake 4: Using unlimited concurrency

Too many simultaneous connections can exhaust local resources and overload remote systems.

## Mistake 5: Trusting banners

Network data is untrusted and may be incorrect or intentionally misleading.

## Mistake 6: Ignoring UDP

A TCP-only inventory is incomplete for environments containing UDP services.

## Mistake 7: Ignoring timestamps

Network inventories become difficult to interpret if observations cannot be associated with a time.

## Mistake 8: Mixing discovery and exploitation

An inventory tool should have clearly defined boundaries.

---

# 38. Performance Considerations

Network discovery is usually dominated by I/O rather than CPU computation.

For `H` hosts and `P` ports, a simple sequential model can require approximately:

`O(H × P)`

connection attempts.

The exact elapsed time depends on:

- latency
- timeout duration
- number of responsive services
- firewall behavior
- DNS latency
- concurrency
- operating-system socket limits

Concurrency can reduce wall-clock time, but it does not eliminate the underlying network work.

---

# 39. Timeout Trade-Off

A short timeout can improve performance but increase false negatives.

A long timeout can improve the chance of receiving slow responses but make the scan much slower.

Therefore timeout configuration is an operational trade-off.

Factors include:

- local network latency
- WAN links
- VPNs
- packet loss
- firewall behavior
- expected service response time

A single timeout value is not optimal for every network.

---

# 40. Concurrency Trade-Off

More workers can increase throughput.

Too many workers can increase:

- CPU overhead
- memory usage
- socket usage
- network traffic
- remote-system load

A bounded concurrency design is therefore preferable to unlimited parallelism.

The Python implementation uses `ThreadPoolExecutor`.

The JavaScript implementation implements bounded asynchronous workers.

The C++ case study uses asynchronous tasks for the deliberately small case study and documents why a bounded thread pool would be preferable at larger scale.

---

# 41. Security Considerations

Network discovery itself can have security implications.

Important controls include:

- explicit authorization
- strict target scope
- rate limits
- bounded concurrency
- logging
- timestamps
- safe handling of response data
- controlled storage
- access control for scan results

Discovery results can reveal infrastructure information and should be protected accordingly.

An inventory database may contain:

- internal IP addresses
- hostnames
- exposed services
- software information
- organizational topology

Such data can be sensitive even when no credentials or personal information are collected.

---

# 42. Input Validation

The implementations validate:

- port ranges
- target IPv4 syntax
- timeouts
- concurrency values
- address counts where applicable

Input validation prevents simple configuration errors from becoming unexpected runtime behavior.

Production tools should also validate authorization scope before any active network operation.

---

# 43. Error Handling

Network failures are normal.

Examples include:

- timeout
- connection refused
- DNS failure
- invalid address
- unavailable route
- socket creation failure
- permission failure

A robust inventory system should record these states rather than crashing after the first unsuccessful operation.

This is why the implementations distinguish between:

- open
- closed
- timeout/filtering
- error

instead of treating every failure as the same condition.

---

# 44. Python, JavaScript, and C++ Comparison

## Python

Python emphasizes readability and rapid implementation.

The standard `socket` module provides direct access to network operations while the rest of the language makes data modeling and reporting straightforward.

Python is particularly useful for:

- security automation
- inventory scripts
- data processing
- reporting
- orchestration

## JavaScript with Node.js

Node.js emphasizes asynchronous and event-driven networking.

The `net.Socket` API demonstrates:

- callbacks
- events
- promises
- asynchronous DNS
- non-blocking application design

This is useful for understanding how network applications can process many I/O operations without blocking a single main execution path.

## C++

C++ exposes more operating-system details.

The case study demonstrates:

- POSIX sockets
- file descriptors
- non-blocking mode
- `select()`
- socket error inspection
- RAII
- explicit memory/resource management
- concurrency using standard-library facilities

C++ is particularly useful when understanding lower-level network programming and operating-system interactions.

---

# 45. Architectural Separation

A maintainable discovery application can be separated into layers.

## Target layer

Responsible for:

- scope
- addresses
- authorization boundaries
- network ranges

## Transport layer

Responsible for:

- sockets
- connection attempts
- timeouts
- protocol transport

## Discovery layer

Responsible for:

- host state
- port state
- service observations
- banners

## Enrichment layer

Responsible for:

- reverse DNS
- service-name mappings
- asset metadata

## Storage layer

Responsible for:

- JSON
- database records
- timestamps
- historical observations

## Presentation layer

Responsible for:

- terminal output
- dashboards
- reports

This separation prevents reporting logic from becoming tightly coupled to network transport code.

---

# 46. Production Considerations

A production network inventory platform would normally require capabilities beyond these educational implementations.

Potential areas include:

- IPv6 support
- UDP discovery
- ARP-based local discovery
- ICMP discovery
- configurable probe sets
- retry policies
- rate limiting
- persistent databases
- historical comparison
- change detection
- authentication
- role-based access
- audit logs
- centralized scheduling
- distributed scanning
- asset ownership
- service fingerprints
- duplicate-address handling
- network segmentation
- proxy-aware operation
- monitoring integration

These are architectural concerns rather than merely additional socket calls.

---

# 47. Data Quality

A useful network inventory should distinguish between:

- observed facts
- inferred classifications
- unresolved states

For example:

`TCP/8080 accepted a connection`

is an observation.

`HTTP service`

may be an inference.

`Apache HTTP Server 2.x`

is a stronger identification only if supported by additional evidence.

This distinction improves the quality of security and infrastructure reporting.

---

# 48. Why Historical Data Matters

A single scan provides a snapshot.

Repeated inventories can reveal changes such as:

- new hosts
- removed hosts
- newly open ports
- closed ports
- changed banners
- changed DNS records

For example:

| Observation | Previous | Current |
|---|---|---|
| Host | present | present |
| TCP/22 | open | open |
| TCP/443 | closed | open |
| Banner | none | changed |

This kind of comparison is useful for asset management and configuration monitoring.

---

# 49. Limitations of the Three Implementations

These programs are educational rather than full-featured replacements for mature network scanners.

They do not attempt to provide:

- complete Nmap-compatible probing
- comprehensive UDP detection
- full IPv6 scanning
- operating-system fingerprinting
- extensive protocol fingerprints
- packet-capture analysis
- vulnerability assessment
- exploitation
- stealth scanning
- evasion mechanisms

Their purpose is to make the core mechanisms understandable and executable.

---

# 50. Important Conceptual Distinctions

## Discovery versus identification

Discovery determines whether an endpoint responds.

Identification attempts to determine what the endpoint represents.

## Identification versus vulnerability assessment

Identifying a service does not prove that it is vulnerable.

## Open versus secure

An open port is not inherently insecure.

Many legitimate services must be reachable.

Security depends on factors such as:

- authorization
- authentication
- encryption
- configuration
- patching
- network exposure
- application behavior

## Banner versus truth

A banner is evidence, not an absolute authority.

---

# 51. Practical Applications

Network discovery is used in legitimate contexts such as:

- asset inventory
- infrastructure management
- network troubleshooting
- service monitoring
- configuration verification
- security auditing
- incident investigation
- change detection
- cloud inventory
- internal documentation

The same technical mechanisms can produce very different operational outcomes depending on authorization and scope.

---

# 52. Running the Python Implementation

The Python file can be executed without external packages.

A basic demonstration runs against localhost.

The command-line interface also accepts:

- `--target`
- `--ports`
- `--timeout`
- `--workers`
- `--output`
- `--no-banners`

For example, the program can inspect an explicitly authorized host using a small selected port list.

The implementation also includes a safety-oriented target-size limit when processing CIDR networks.

---

# 53. Running the JavaScript Implementation

The JavaScript implementation requires Node.js.

The default demonstration uses:

`127.0.0.1`

It supports command-line parameters for:

- target
- selected ports
- timeout
- concurrency
- JSON output
- banner collection

The implementation intentionally accepts a single explicit IPv4 target in its inventory mode rather than automatically expanding an arbitrary CIDR range.

This makes the scope explicit.

---

# 54. Running the C++ Implementation

The C++ case study targets:

`127.0.0.1`

by default.

A different explicit IPv4 address can be supplied as an argument.

The program uses:

`-std=c++17`

or a later C++ standard.

The code is written around POSIX networking APIs and therefore requires adaptation for native Windows socket handling.

The architecture itself remains applicable across operating systems.

---

# 55. Case Study Data Flow

The C++ case study can be viewed as the following pipeline:

`Target`

→ `IPv4 validation`

→ `TCP connection attempts`

→ `HostResult`

→ `PortResult`

→ `Service classification`

→ `Passive banner`

→ `Reverse DNS`

→ `NetworkMap`

→ `Terminal report`

→ `Optional JSON`

Each stage has a specific responsibility.

This makes the implementation easier to test and extend than a single monolithic scanning function.

---

# 56. Example Interpretation

Suppose an authorized host produces:

`TCP/22 open`

and a banner beginning with an SSH identification string.

The correct interpretation is:

1. The host accepted a TCP connection on port 22.
2. The endpoint exposed SSH-like identification information.
3. The banner provides evidence about the service.
4. The banner should not automatically be treated as proof of a specific vulnerable version.
5. Additional service identification may be required for stronger conclusions.

This evidence-based reasoning is more reliable than simply mapping port numbers to application names.

---

# 57. Operational Discipline

A responsible discovery process should define:

- target scope
- authorized time window
- permitted protocols
- maximum concurrency
- timeout policy
- logging requirements
- data-retention requirements
- notification procedures
- acceptable traffic levels

These are engineering controls, not merely scanner settings.

---

# 58. Relationship to Nmap

Nmap provides a much larger discovery and fingerprinting system than the implementations in this study.

The Python, JavaScript, and C++ programs demonstrate the underlying concepts at a smaller scale:

- address selection
- socket connection
- port state
- service inference
- banner collection
- DNS enrichment
- structured results
- concurrency
- reporting

Understanding these primitives makes Nmap output easier to interpret because the user can distinguish the underlying network evidence from the higher-level classification performed by the scanner.

---

# 59. Key Technical Lessons

Network discovery is not a single operation.

It is a collection of related observations:

`Host Discovery`

determines whether there is evidence of a reachable endpoint.

`Port Discovery`

determines which transport endpoints respond.

`Service Discovery`

attempts to identify the application associated with an endpoint.

`Banner Discovery`

collects information voluntarily exposed by a service.

`Network Mapping`

organizes those observations into an understandable representation of the environment.

The three implementations demonstrate these concepts at different abstraction levels while maintaining the same core model: collect evidence, represent uncertainty, and avoid treating assumptions as facts.
