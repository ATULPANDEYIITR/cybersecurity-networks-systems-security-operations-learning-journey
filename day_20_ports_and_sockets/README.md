<!-- File: README.md -->

# Ports, Sockets, and Service Identification

## Project purpose

This repository is a practical study and implementation project for understanding TCP and UDP ports, ephemeral ports, sockets, listening services, and basic service identification on a local computer.

The project combines:

- Python for socket inspection, port-state observation, service identification, and a local HTTP API.
- JavaScript for browser-based visualization and Node.js socket demonstrations.
- C++17 for low-level TCP socket programming and endpoint inspection.
- PowerShell examples for Windows networking inspection.
- `netstat` and `ss` examples for operating-system-level socket inspection.
- Automated Python tests.
- GitHub Actions for repeatable validation.

The implementations intentionally operate on the local machine. They do not provide a remote port-scanning facility.

## Topic introduction

A network connection is identified by endpoint information. For TCP and UDP, an endpoint normally contains an IP address and a port number.

A port is a logical number associated with a transport-layer endpoint. TCP and UDP use 16-bit port numbers, giving a numerical range from `0` through `65535`.

Port numbers are commonly discussed in three ranges:

- `0-1023`: well-known ports.
- `1024-49151`: registered ports.
- `49152-65535`: dynamic/private ports commonly used for temporary client-side connections.

The exact ephemeral-port range is operating-system dependent. The `49152-65535` range is a common IANA classification for dynamic/private ports, not a universal statement that every operating system uses that exact ephemeral range.

A server normally binds a socket to an address and port and listens for incoming TCP connections. A client normally receives an ephemeral local port when it creates an outbound connection.

A TCP connection can therefore be represented using a four-part combination:

`local IP + local port + remote IP + remote port`

This is often called the TCP four-tuple.

## Terminology

### Port

A numeric transport-layer identifier used by TCP or UDP.

### Socket

An operating-system communication endpoint. A socket is associated with an address family, transport protocol, local endpoint, and, for connected sockets, a remote endpoint.

### Socket address

A combination of an IP address and port.

### Listening socket

A TCP socket that has been bound to a local endpoint and placed into a listening state.

### Established connection

A TCP connection for which both endpoints have completed the connection establishment process.

### Ephemeral port

A temporary local port generally allocated by the operating system for an outbound connection or temporary service endpoint.

### Bind

Associating a socket with a local IP address and port.

### Listen

Putting a TCP socket into a state where it can accept incoming connections.

### Accept

Creating a connected socket from an incoming TCP connection on a listening socket.

### Connect

Requesting a connection to a remote TCP endpoint.

### Service identification

Determining which local application or process is associated with a socket. Port numbers alone are not sufficient to prove which application is responsible for a service.

## Port numbers

Port `0` is reserved and has special meaning in APIs. Applications normally bind services to non-zero ports.

Ports below `1024` traditionally require elevated privileges on many Unix-like systems. Modern operating systems can apply additional policies.

Examples of commonly encountered ports include:

- `22`: SSH
- `25`: SMTP
- `53`: DNS
- `80`: HTTP
- `443`: HTTPS
- `3306`: MySQL
- `5432`: PostgreSQL
- `6379`: Redis
- `8080`: frequently used for development HTTP services

A port number is not a guarantee of a service. An HTTP server can listen on port `9000`, and an arbitrary application can listen on port `443` if the operating system permits it.

## TCP and UDP

TCP is connection-oriented and provides reliable, ordered byte-stream delivery.

UDP is connectionless at the transport-protocol level and provides datagrams without TCP's reliability and ordering guarantees.

A TCP server commonly follows this sequence:

1. Create socket.
2. Bind local address and port.
3. Listen.
4. Accept connections.
5. Receive and send data.
6. Close the connection.

A TCP client commonly follows:

1. Create socket.
2. Connect to server.
3. Send and receive data.
4. Close socket.

A UDP application commonly:

1. Creates a datagram socket.
2. Binds a local endpoint if it needs a specific receiving port.
3. Sends or receives datagrams.
4. Closes the socket.

## Repository structure

The repository contains the following main components:

- `src/port_inspector/inspector.py`: cross-platform Python socket inspection.
- `src/port_inspector/service.py`: local FastAPI service.
- `src/port_inspector/models.py`: typed data models.
- `src/port_inspector/cli.py`: command-line interface.
- `src/port_inspector/__main__.py`: module entry point.
- `tests/`: automated Python tests.
- `web/index.html`: browser interface.
- `web/app.js`: browser behavior.
- `web/styles.css`: browser styling.
- `node/socket-demo.js`: Node.js TCP socket demonstration.
- `cpp/socket_demo.cpp`: C++ TCP socket demonstration.
- `cpp/CMakeLists.txt`: C++ build configuration.
- `scripts/windows-network.ps1`: PowerShell inspection commands.
- `scripts/linux-network.sh`: Linux `ss` and `netstat` inspection commands.
- `.github/workflows/ci.yml`: automated validation.

## Prerequisites

### Python

Python 3.11 or newer is recommended.

### Node.js

Node.js 20 or newer is recommended for the Node.js demonstration.

### C++

A C++17-compatible compiler is required for the C++ demonstration.

On Windows, Visual Studio 2022 or a compatible MinGW environment can be used.

On Linux, GCC or Clang can be used.

### Operating-system tools

Windows:

- PowerShell
- `netstat`
- `Get-NetTCPConnection`
- `Get-NetUDPEndpoint`

Linux:

- `ss`
- `netstat` if the `net-tools` package is installed

## Python installation

Create a virtual environment:

`python -m venv .venv`

Windows PowerShell:

`.venv\Scripts\Activate.ps1`

Linux:

`source .venv/bin/activate`

Install the project:

`python -m pip install --upgrade pip`

`pip install -e ".[dev]"`

## Running the Python CLI

List local TCP and UDP endpoints:

`python -m port_inspector`

Inspect only TCP endpoints:

`python -m port_inspector --protocol tcp`

Inspect only listening TCP services:

`python -m port_inspector --listening`

Inspect a specific local port:

`python -m port_inspector --port 8000`

Use JSON output:

`python -m port_inspector --json`

The CLI uses operating-system facilities where available and falls back to a Python socket-based view when process-level information is unavailable.

## Python API

Start the local API:

`uvicorn port_inspector.service:app --host 127.0.0.1 --port 8000`

The API is intentionally bound to `127.0.0.1` by default so the educational inspection service is not exposed to a network interface unintentionally.

Useful endpoints:

- `GET /health`
- `GET /api/endpoints`
- `GET /api/endpoints/listening`
- `GET /api/endpoints/{port}`

Example:

`http://127.0.0.1:8000/api/endpoints/listening`

## API behavior

`GET /api/endpoints` returns a JSON array containing locally observed endpoints.

Each endpoint contains:

- protocol
- local address
- local port
- remote address
- remote port
- state
- process information when the operating system exposes it
- service classification when a common port mapping exists

Process information may be unavailable without elevated operating-system permissions.

The API reports missing process information as `null` instead of pretending that the service has been identified.

## Browser interface

Start the API:

`uvicorn port_inspector.service:app --host 127.0.0.1 --port 8000`

Open `web/index.html` in a browser.

The interface requests `/api/endpoints`, displays the observed endpoints, and separates listening endpoints from active connections.

If a browser blocks local-file requests in a particular environment, serve the `web` directory with a small local HTTP server:

`python -m http.server 8080 --directory web`

The browser then needs the API running at `http://127.0.0.1:8000`.

## Service identification

The project uses two forms of service identification.

First, it performs conservative port-number classification. For example, TCP port `443` is commonly associated with HTTPS.

Second, the operating system may provide process information such as a process ID or process name.

These are different concepts.

Port `443` does not prove that HTTPS is running.

A process name does not necessarily prove what application protocol the process is implementing.

Reliable application-level identification may require protocol negotiation, banner inspection, executable metadata, service-manager information, or other operating-system-specific evidence.

This repository deliberately avoids active remote banner scanning.

## netstat

On Windows:

`netstat -ano`

The `-a` option includes listening and active connections.

The `-n` option displays numerical addresses and ports.

The `-o` option includes process IDs.

To inspect listening TCP ports:

`netstat -ano | findstr LISTENING`

To identify the process behind a PID:

`Get-Process -Id <PID>`

On Linux:

`netstat -tulpen`

Option meanings vary between implementations, so use `netstat --help` when necessary.

## ss

`ss` is commonly available on modern Linux systems.

Show TCP and UDP sockets:

`ss -tuln`

Show listening sockets with process information:

`ss -tulpn`

Show established TCP connections:

`ss -tn state established`

The `-p` option may require elevated privileges to display process information.

## PowerShell

Windows provides structured networking commands that are often easier to process programmatically than parsing `netstat`.

Show TCP connections:

`Get-NetTCPConnection`

Show listening TCP connections:

`Get-NetTCPConnection -State Listen`

Show UDP endpoints:

`Get-NetUDPEndpoint`

Filter a port:

`Get-NetTCPConnection -LocalPort 8000`

Display process information:

`Get-Process -Id 1234`

The supplied PowerShell script contains safe examples that can be run without changing system configuration.

## Node.js demonstration

Run:

`node node/socket-demo.js`

The program starts a TCP server on an automatically selected local port, connects to it using a client socket, exchanges a small message, and closes both sockets.

The demonstration shows the distinction between:

- a listening server socket
- a client socket
- a connected socket
- local and remote ports
- operating-system-assigned ephemeral ports

## C++ demonstration

Configure and build:

`cmake -S cpp -B cpp/build`

`cmake --build cpp/build --config Release`

On Linux, the executable can normally be run with:

`./cpp/build/port_socket_demo`

On multi-configuration generators such as Visual Studio:

`cpp\build\Release\port_socket_demo.exe`

The C++ program creates a TCP server, obtains an operating-system-assigned port, connects a client to that server, exchanges data, and closes the sockets.

## Testing

Run:

`pytest`

The tests cover:

- port validation
- protocol validation
- service-name classification
- endpoint serialization
- local TCP server behavior
- API health behavior
- invalid API input

Run the test suite with:

`python -m pytest`

## Formatting and linting

Run Ruff:

`ruff check .`

The project uses Ruff for Python linting.

The configuration is stored in `pyproject.toml`.

## GitHub Actions

The CI workflow:

- installs Python
- installs development dependencies
- runs Ruff
- runs pytest
- verifies that the CLI can start and produce structured output
- verifies that the C++ project can configure and build on its supported runner environment

No deployment credentials are required.

## Error handling

Socket inspection can fail partially.

Typical reasons include:

- insufficient permissions
- unavailable operating-system APIs
- a socket disappearing while it is being inspected
- platform-specific differences
- processes terminating during inspection

The Python implementation treats endpoint collection as a snapshot. A network endpoint can disappear immediately after it is observed.

The API therefore does not claim that its result is an immutable representation of the machine.

## Edge cases

Important edge cases include:

- IPv4 versus IPv6 addresses.
- IPv6 wildcard addresses such as `::`.
- UDP endpoints without a remote connection.
- TCP listening sockets without a remote endpoint.
- IPv4-mapped IPv6 addresses.
- ephemeral client ports.
- processes that terminate during inspection.
- ports that cannot be mapped to known service names.
- privileged process information that is unavailable.
- multiple applications using different address families.
- wildcard listeners covering multiple local interfaces.

## Common mistakes

### Assuming every port number identifies a service

Port numbers are conventions, not cryptographic identities.

### Treating a listening port as an established connection

A listener is waiting for incoming connections. It does not mean that an active client connection currently exists.

### Treating a TCP port and UDP port as identical

TCP and UDP maintain separate transport namespaces. A TCP service can use port `53` while a UDP service also uses port `53`.

### Assuming ephemeral ports always come from one universal range

The actual allocation policy and range depend on the operating system.

### Assuming `netstat` output is identical everywhere

Command syntax and columns vary between operating systems and implementations.

### Parsing human-readable output unnecessarily

Structured PowerShell commands such as `Get-NetTCPConnection` are preferable on Windows when automation is required.

### Assuming a PID always identifies a single service

A process can own multiple sockets, and a service can consist of multiple processes.

## Performance considerations

The local inspection operation is primarily an operating-system query rather than a network-intensive operation.

The implementation:

- collects a snapshot rather than continuously polling;
- avoids remote scanning;
- performs service-name classification with a static mapping;
- uses typed objects for predictable serialization;
- keeps the HTTP API local by default.

Repeated polling should be controlled by the caller. A production monitoring system would normally use an appropriate sampling interval rather than continuously invoking expensive operating-system queries.

## Security considerations

The project is intentionally local.

The API defaults to loopback binding:

`127.0.0.1`

This prevents accidental exposure through a normal network interface.

The project does not store credentials.

The project does not perform remote port scanning.

The API does not execute shell commands supplied by HTTP clients.

The service-name mapping is static data and is not derived from untrusted command execution.

When running operating-system inspection commands manually, process information may require administrator or root privileges. Elevated privileges should be used only when necessary.

## Production considerations

A production network inventory system would need stronger controls around:

- authentication
- authorization
- audit logging
- process identity
- IPv6 handling
- operating-system differences
- data retention
- polling frequency
- privilege management
- telemetry collection
- alerting
- access control
- encrypted transport for remote administration

Those requirements are intentionally outside this local educational service.

## Architecture

The Python architecture separates:

`CLI -> Inspector -> Endpoint models`

and:

`HTTP API -> Inspector -> Endpoint models`

The browser communicates only with the local HTTP API.

The Node.js and C++ demonstrations are independent executable demonstrations of socket lifecycle behavior.

The PowerShell and shell scripts demonstrate native operating-system inspection tools rather than replacing them.

## Complexity

The Python inspector processes the endpoint records returned by the operating system.

If `n` endpoints are returned, formatting and classification require approximately `O(n)` application-level processing.

The actual operating-system cost is platform-specific and depends on the API or command used.

Memory usage is approximately `O(n)` for the endpoint snapshot.

## Real-world applications

Port and socket inspection is useful for:

- troubleshooting applications that fail to bind;
- identifying unexpected local listeners;
- diagnosing port conflicts;
- validating server deployments;
- understanding client ephemeral ports;
- investigating connection states;
- monitoring development environments;
- debugging microservices;
- verifying container port mappings;
- understanding firewall behavior;
- supporting incident investigation.

## License

This project is provided as an educational software repository. See `LICENSE` for the repository license.
