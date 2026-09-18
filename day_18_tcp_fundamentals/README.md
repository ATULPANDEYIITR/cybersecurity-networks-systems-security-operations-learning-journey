# TCP fundamentals

## Introduction

Transmission Control Protocol (TCP) is a transport-layer protocol designed to provide a reliable, ordered, connection-oriented byte stream between two endpoints.

TCP is widely used by application protocols such as HTTP, HTTPS, SSH, SMTP, IMAP, and many database and service protocols. The application normally does not need to implement packet numbering, acknowledgments, retransmission, or receiver flow control itself because these functions are handled by the TCP stack.

The implementations in this repository model TCP mechanics without creating a real network connection. The Python implementation provides a broad protocol study and simulation environment. The JavaScript implementation emphasizes object-oriented modeling, typed byte arrays, event-driven behavior, and asynchronous timers. The C++ implementation develops an industry-style telemetry transport case study using classes, queues, maps, validation, state modeling, and protocol algorithms.

## What TCP provides

TCP provides several important transport-layer properties:

- Reliable delivery
- Ordered delivery
- Duplicate suppression
- Retransmission of lost data
- Cumulative acknowledgments
- Receiver flow control
- Full-duplex communication
- Connection establishment
- Graceful connection termination
- Byte-stream abstraction

TCP does not inherently provide:

- Encryption
- Application-level authentication
- Guaranteed latency
- Guaranteed bandwidth
- Application message boundaries
- Protection against every form of denial-of-service attack

Encryption and authenticated communication are commonly provided by TLS above TCP.

## TCP as a byte stream

One of the most important TCP concepts is that TCP is a byte-stream protocol.

Suppose an application writes:

`HELLO`

and later writes:

`WORLD`

TCP does not preserve these two writes as separate network messages. The receiving application may obtain:

`HELLOWORLD`

or portions of the data in different reads, depending on buffering, scheduling, and the application interface.

The Python and JavaScript implementations explicitly model this behavior. The JavaScript `ByteStreamAssembler` combines incoming byte sequences into one continuous buffer.

Applications that require message boundaries must implement their own framing protocol. Common approaches include:

- Fixed-length records
- Length-prefixed messages
- Delimiter-based messages
- Self-describing serialization formats

## Fundamental TCP terminology

### Segment

A TCP segment is the transport-layer data unit carried by IP.

A simplified TCP segment contains information such as:

- Source port
- Destination port
- Sequence number
- Acknowledgment number
- Control flags
- Receive window
- Checksum
- Optional TCP fields
- Application payload

The educational implementations model only the fields needed to demonstrate TCP fundamentals.

### Sequence number

A sequence number identifies a position in the TCP byte stream.

If a segment starts at sequence number `1000` and contains 500 bytes, its payload occupies the byte positions:

`1000` through `1499`

The next byte is:

`1500`

Therefore the receiver can acknowledge `1500`.

TCP sequence numbers are not packet identifiers. They describe byte positions.

### Acknowledgment number

An ACK number normally identifies the next byte the receiver expects.

For example:

`ACK = 5000`

means that the receiver has cumulatively received the required byte sequence before byte `5000` and is expecting byte `5000` next.

This is why an acknowledgment number often looks like:

`received starting sequence + received byte count`

### Initial sequence number

When a TCP connection is established, each endpoint selects an initial sequence number (ISN).

Suppose:

- Client ISN = 1000
- Server ISN = 5000

The client SYN uses sequence number `1000`.

The server's SYN-ACK acknowledges `1001`.

The client's final ACK acknowledges `5001`.

The reason for the increment is that SYN consumes one sequence-number position.

### Receive window

The receive window communicates how much additional data the receiver can accept.

A simplified relationship is:

`advertised window = receive buffer capacity - currently buffered data`

A receiver with a 10,000-byte buffer that currently contains 4,000 bytes can advertise approximately 6,000 bytes of remaining capacity.

This is a flow-control mechanism.

### Congestion window

The congestion window, commonly called `cwnd`, is associated with congestion control.

It limits the amount of data a sender may have in flight based on perceived network conditions.

The receive window and congestion window solve different problems:

| Mechanism | Main concern | Protects |
|---|---|---|
| Receive window | Receiver capacity | Receiver |
| Congestion window | Network congestion | Network |
| Retransmission | Packet loss | Reliability |
| ACK | Receiver progress | Sender feedback |

A simplified conceptual relationship is:

`effective sending window = min(receive window, congestion window)`

Actual TCP congestion control is substantially more sophisticated than this formula.

## TCP three-way handshake

TCP uses a three-way handshake to establish the initial connection state.

A simplified handshake is:

`Client -> Server: SYN`

`Server -> Client: SYN + ACK`

`Client -> Server: ACK`

### Step 1: SYN

The client sends a SYN segment.

For example:

`SEQ=1000, SYN`

The client is communicating its initial sequence-number state.

The client normally moves from:

`CLOSED -> SYN-SENT`

### Step 2: SYN-ACK

The server responds with:

`SEQ=5000, ACK=1001, SYN+ACK`

The server communicates its own ISN and acknowledges the client's SYN.

The server can move through:

`LISTEN -> SYN-RECEIVED`

### Step 3: ACK

The client sends:

`SEQ=1001, ACK=5001, ACK`

This confirms receipt of the server's SYN.

The connection can then enter:

`ESTABLISHED`

Both endpoints now have the sequence-number state required for normal data transfer.

## Why SYN consumes sequence space

SYN consumes one sequence-number position even though it does not contain application data.

If the client sends:

`SYN SEQ=1000`

then the first normal data byte begins at:

`1001`

This is demonstrated in all three implementations.

## TCP flags

The implementations model the principal TCP flags.

| Flag | Purpose |
|---|---|
| SYN | Synchronize sequence numbers and initiate connection establishment |
| ACK | Indicates a valid acknowledgment field |
| FIN | Gracefully close one direction of the stream |
| RST | Reset a connection |
| PSH | Request prompt delivery of buffered data |
| URG | Indicates urgent-data semantics |
| ECE | Used in Explicit Congestion Notification |
| CWR | Indicates congestion-window reduction in ECN operation |

The Python implementation uses an enumeration. The JavaScript implementation represents flags as bit masks. The C++ implementation uses an enum class combined into a bit mask.

Bit masks are useful because several flags can be represented simultaneously.

For example:

`SYN + ACK`

can be represented by combining the SYN and ACK flag values.

## TCP data transfer

After the handshake, an endpoint can transmit application data.

Suppose the sender's first data sequence number is `1001`.

A 500-byte segment can contain:

`SEQ=1001`

with:

`PAYLOAD=500`

The next byte is:

`1501`

The receiver can acknowledge:

`ACK=1501`

The ACK is cumulative.

## Cumulative acknowledgments

TCP acknowledgments normally provide cumulative information.

Consider these ranges:

- Segment 1: bytes `1000-1499`
- Segment 2: bytes `1500-1999`
- Segment 3: bytes `2000-2499`

If all three arrive in order, the receiver can acknowledge:

`ACK=2500`

The ACK indicates that byte `2500` is the next expected byte.

## Out-of-order data

Networks can deliver packets in a different order from the order in which they were transmitted.

Suppose:

- Segment A contains bytes `1000-1499`
- Segment B contains bytes `1500-1999`
- Segment C contains bytes `2000-2499`

If A arrives first, the receiver can acknowledge:

`1500`

If C arrives next while B is missing, the receiver still needs byte `1500`.

It can continue acknowledging:

`1500`

while retaining C as out-of-order data.

When B finally arrives, B and the already buffered C form a contiguous range. The receiver can then advance its cumulative ACK to:

`2500`

The Python `TCPReceiver`, JavaScript `OrderedTCPReceiver`, and C++ `TCPReceiver` all model this principle.

## Selective acknowledgment

Cumulative ACKs do not fully describe which later ranges have arrived.

Modern TCP can use Selective Acknowledgment (SACK) when negotiated. SACK allows a receiver to provide more detailed information about received blocks.

For example, a receiver may effectively communicate:

`I am still waiting for 1500-1999, but I already have 2000-2499.`

This allows a sender to avoid unnecessarily retransmitting data that has already arrived.

The implementations focus on cumulative acknowledgments and mention SACK as an advanced mechanism rather than implementing the complete SACK option format.

## Sliding-window operation

TCP can have multiple segments outstanding before receiving an acknowledgment for each individual segment.

This is essential for efficient network utilization.

Suppose the effective sending window is 3,000 bytes.

The sender can have approximately 3,000 bytes outstanding before it must wait for additional acknowledgment or window capacity.

The sender tracks at least two important sequence positions conceptually:

- Oldest unacknowledged byte
- Next byte available for transmission

The difference between them represents data in flight.

The Python `TCPSender`, JavaScript `SlidingWindowSender`, and C++ `TCPSender` implement this model.

## Flow control

Flow control prevents a sender from overwhelming the receiver.

Consider a receiver with:

`capacity = 10,000 bytes`

If 7,000 bytes are buffered, the remaining advertised capacity is:

`3,000 bytes`

The sender must respect this advertised receive window.

If the receiver later consumes 5,000 bytes through its application, its available capacity increases.

The receive window is therefore dynamic.

## Zero-window condition

A receiver can eventually advertise a zero window if its buffer is full.

Conceptually:

`advertised window = 0`

The sender must not continue sending normal data beyond the permitted receive capacity.

TCP has mechanisms for discovering when the receiver's window opens again, including zero-window probing behavior.

The simplified implementations model the window constraint but do not attempt to implement every timer and probe rule of a production TCP stack.

## Flow control versus congestion control

These concepts are frequently confused.

### Flow control

Flow control addresses:

`Can the receiver handle more data?`

The receiver communicates this through the advertised receive window.

### Congestion control

Congestion control addresses:

`Can the network handle more traffic?`

The sender adapts its transmission behavior based on congestion signals and loss/delay observations.

The congestion window is a central component of TCP congestion control.

A sender can therefore be constrained by either:

- Receiver capacity
- Network congestion

or both.

## Retransmission

TCP provides reliability by detecting missing data and retransmitting it.

A sender normally retains enough information about outstanding data to retransmit it if necessary.

Loss can be detected through mechanisms such as:

- Retransmission timeout
- Duplicate ACK patterns
- Selective acknowledgment information
- Other loss-recovery mechanisms in modern TCP implementations

The Python `ReliableSender` models timeout-based retransmission.

The JavaScript implementation demonstrates asynchronous timer behavior.

The C++ case study shows how outstanding segments can be retained by a sender.

## Retransmission timeout

A fixed universal timeout would perform poorly because network conditions change.

TCP estimates round-trip time (RTT).

A simplified model uses:

`RTO = SRTT + 4 × RTTVAR`

where:

- `SRTT` is the smoothed round-trip time
- `RTTVAR` represents RTT variation
- `RTO` is the retransmission timeout

The Python, JavaScript, and C++ implementations use exponential smoothing to demonstrate this concept.

A production TCP implementation contains additional timer rules, bounds, retransmission backoff, and measurement constraints.

## RTT

Round-trip time is the elapsed time between transmission of a packet and the receipt of appropriate feedback.

For example:

`Request sent at 1.000 s`

`ACK observed at 1.080 s`

gives an RTT sample of approximately:

`0.080 s`

RTT can change because of:

- Queueing
- Routing
- Physical distance
- Network congestion
- Wireless conditions
- Server processing
- Operating-system scheduling

One RTT sample should not automatically be treated as a permanent network property.

## Duplicate ACKs

Suppose a receiver is expecting byte `4000`.

A later segment arrives before the missing segment.

The receiver may continue sending:

`ACK=4000`

When the sender receives repeated ACKs for the same sequence point, this can indicate that a segment is missing while later data is reaching the receiver.

The classic fast-retransmit mechanism uses three duplicate ACKs as an important trigger.

The Python `DuplicateAckDetector`, JavaScript `DuplicateAckDetector`, and C++ `DuplicateACKDetector` model this educationally.

Actual modern loss-recovery behavior depends on the TCP implementation and congestion-control algorithm.

## Fast retransmission

A timeout is not the only mechanism for detecting loss.

Duplicate ACKs can allow a sender to react before the retransmission timer expires.

Conceptually:

`Missing segment`

`-> later segment arrives`

`-> receiver sends duplicate ACK`

`-> repeated duplicate ACKs`

`-> sender detects likely loss`

`-> sender retransmits`

This reduces recovery latency in many loss scenarios.

## Retransmission backoff

When a retransmission timeout occurs, repeatedly using the same timeout can create excessive traffic under persistent network problems.

TCP implementations therefore use retransmission timer backoff mechanisms.

A retransmission does not necessarily mean the application data was permanently lost. It means the sender has insufficient evidence that the required data was successfully acknowledged within the applicable recovery conditions.

## TCP connection termination

TCP is full-duplex.

Each direction of the byte stream can be closed independently.

A typical graceful shutdown involves:

`FIN`

`ACK`

`FIN`

`ACK`

For example:

Client:

`FIN SEQ=7000`

Server:

`ACK=7001`

Server:

`FIN SEQ=9000`

Client:

`ACK=9001`

The exact packet count can differ because ACKs and FINs can sometimes be combined.

## Why FIN consumes sequence space

Like SYN, FIN consumes one sequence-number position.

If:

`FIN SEQ=7000`

then the corresponding acknowledgment advances to:

`ACK=7001`

This is an important sequence-number rule.

## TCP states

TCP maintains connection state.

Important states include:

- `CLOSED`
- `LISTEN`
- `SYN-SENT`
- `SYN-RECEIVED`
- `ESTABLISHED`
- `FIN-WAIT-1`
- `FIN-WAIT-2`
- `CLOSE-WAIT`
- `LAST-ACK`
- `CLOSING`
- `TIME-WAIT`

The state machine is necessary because the same packet can have different meanings depending on the connection's current state.

For example, a SYN received while listening is part of connection establishment, while a FIN received during an established connection contributes to connection termination.

## TIME-WAIT

`TIME-WAIT` is an important TCP state after active connection termination.

It provides protection against old duplicate segments from a previous connection interfering with a later connection using the same endpoint tuple.

It also gives the final ACK an opportunity to be retransmitted if the peer retransmits its FIN.

The duration and exact operational behavior depend on implementation and protocol rules.

## RST

RST means reset.

A reset can terminate or reject a connection immediately rather than performing a graceful FIN-based shutdown.

A RST can appear when:

- A connection does not exist
- A port is unavailable
- An endpoint rejects a connection
- A protocol error requires reset
- An existing connection is aborted

Unexpected RST packets are useful indicators when diagnosing connection failures.

## MSS

Maximum Segment Size (MSS) represents the maximum amount of TCP payload that a segment can carry under the negotiated conditions.

It is different from total packet size.

A simplified relationship is:

`IP packet size = IP header + TCP header + TCP payload`

The Python, JavaScript, and C++ implementations use an educational MSS value to divide application data into multiple TCP segments.

For example, if a 35-byte application payload is transmitted using an MSS of 8 bytes, it requires five data segments:

- 8 bytes
- 8 bytes
- 8 bytes
- 8 bytes
- 3 bytes

Actual MSS selection interacts with path MTU and TCP options.

## Sequence-number wrap-around

Classic TCP sequence numbers use a 32-bit sequence space.

The number of possible sequence values is:

`2^32 = 4,294,967,296`

After the maximum value, sequence numbers wrap back to zero.

This means sequence numbers form a circular space rather than an infinitely increasing integer.

Consequently, TCP implementations need specialized serial-number comparison logic.

Ordinary numerical comparisons can be incorrect around the wrap point.

TCP timestamps and other mechanisms also help implementations distinguish current traffic from sufficiently old duplicate traffic.

## Security considerations

TCP does not provide encryption.

A TCP payload can be observed by an attacker who has sufficient access to the network path.

TCP also does not inherently provide cryptographic peer authentication.

Important security concerns include:

### SYN floods

A SYN flood attempts to create many incomplete connection-establishment states.

The target can consume resources maintaining partially established connections.

Operating systems and network devices use defensive mechanisms such as SYN cookies, connection limits, filtering, and rate controls.

### TCP spoofing

An attacker may attempt to forge packets with a source address belonging to another endpoint.

Modern sequence-number generation makes certain attacks more difficult, but TCP is not a cryptographic authentication protocol.

### RST injection

An attacker able to construct sufficiently convincing packets may attempt to inject reset packets into an active connection.

### Encryption

TLS is commonly used above TCP when confidentiality, integrity, and peer authentication are required.

HTTPS is a major example.

The important distinction is:

`TCP provides transport reliability`

while:

`TLS provides cryptographic security properties`

## Python implementation

The Python implementation is a comprehensive protocol study.

### TCP flags

`TCPFlag` uses an enumeration for concepts such as:

- SYN
- ACK
- FIN
- RST
- PSH
- URG
- ECE
- CWR

### Segment model

`TCPSegment` models:

- Source
- Destination
- Sequence number
- Acknowledgment number
- Flags
- Payload
- Advertised receive window

The `sequence_space_consumed` property demonstrates the special behavior of SYN and FIN.

### Handshake

`simulate_three_way_handshake()` generates the three packets required for the educational handshake model.

### Receive window

`ReceiveWindow` demonstrates receiver-side flow control.

### Sender

`TCPSender` tracks:

- Oldest unacknowledged sequence
- Next sequence number
- Receive window
- Congestion window
- Bytes in flight
- Outstanding payloads

### Receiver

`TCPReceiver` buffers out-of-order segments and advances the cumulative acknowledgment point only when the byte stream becomes contiguous.

### RTT estimator

`RTTTracker` demonstrates smoothed RTT and RTT variation.

### Retransmission

`ReliableSender` retains outstanding data and retransmits it when a simplified timeout expires.

### Duplicate ACK detection

`DuplicateAckDetector` demonstrates the classic three-duplicate-ACK trigger.

### Segmentation

`segment_application_data()` demonstrates MSS-based splitting of an application byte stream.

### Self-tests

The Python file includes assertions covering:

- Handshake sequence numbers
- SYN sequence consumption
- FIN sequence consumption
- Payload sequence consumption
- Sequence wrap-around

## JavaScript implementation

The JavaScript implementation focuses on language features that are particularly useful for protocol simulation.

### Typed byte arrays

TCP carries bytes rather than JavaScript strings.

The implementation uses `Uint8Array` to represent payloads.

This makes the model closer to actual network data.

`TextEncoder` converts strings to bytes and `TextDecoder` converts byte sequences back into text.

### Bit-mask flags

JavaScript represents flags as hexadecimal bit values.

For example, the ACK flag is represented by a bit mask, and SYN plus ACK is created with a bitwise OR operation.

This reflects how protocol flags can be packed into a compact field.

### Object-oriented modeling

Classes include:

- `TCPSegment`
- `ReceiveWindow`
- `SlidingWindowSender`
- `OrderedTCPReceiver`
- `RTTEstimator`
- `DuplicateAckDetector`
- `NetworkSimulator`
- `ByteStreamAssembler`

Each class isolates one major responsibility.

### Event-driven network simulation

`EventEmitter` provides a small event system.

`NetworkSimulator` emits:

- `packetLost`
- `packetDelivered`

This demonstrates how JavaScript's event-driven programming model can represent asynchronous network events.

### Asynchronous timeout

`demonstrateRetransmissionTimer()` uses a JavaScript timer and `Promise`-based waiting to model a retransmission timer.

The example distinguishes:

`ACK arrives before timeout`

from:

`timer expires before ACK`

### Byte-stream assembly

`ByteStreamAssembler` demonstrates why application reads do not necessarily correspond to application writes.

The receiver consumes a stream of bytes rather than independent TCP message objects.

## C++ case study

The C++ implementation models an industrial telemetry gateway communicating with an analytics server.

The scenario contains:

`Industrial gateway -> TCP transport -> network -> analytics server`

The gateway sends telemetry such as:

`TEMP=27.5;PRESSURE=101.3;STATUS=OK`

The case study intentionally uses a small MSS so that segmentation and sequence numbers remain visible.

### Architecture

The major components are:

| Component | Responsibility |
|---|---|
| `TCPSegment` | Represents a TCP segment |
| `ReceiveWindow` | Models receiver-side flow control |
| `TCPReceiver` | Reassembles ordered data |
| `RTTEstimator` | Tracks RTT and derives RTO |
| `TCPSender` | Tracks outstanding data and window capacity |
| `DuplicateACKDetector` | Detects repeated ACKs |
| `TelemetryTransport` | Coordinates the TCP connection |
| `LossyNetwork` | Simulates packet loss |

### Connection establishment

`TelemetryTransport::establishConnection()` models:

`SYN -> SYN-ACK -> ACK`

The gateway and server each maintain their own initial sequence number.

The final ACK confirms the server's sequence state.

### Segmentation

`createTelemetrySegments()` divides telemetry into MSS-sized chunks.

Each segment receives a sequence number corresponding to the byte position of its payload.

### Out-of-order processing

The C++ receiver stores future segments in a `std::map`.

The map key is the segment's sequence number.

When the missing segment arrives, buffered contiguous segments can be delivered in sequence.

This demonstrates why ordered reassembly requires both:

- Sequence tracking
- Temporary storage

### Sender outstanding queue

`TCPSender` uses a `std::deque` for outstanding segments.

The sender retains data until it receives an appropriate acknowledgment.

This models the fundamental requirement that TCP must be able to retransmit data that has not yet been acknowledged.

### RTT estimation

`RTTEstimator` uses:

`SRTT`

and:

`RTTVAR`

to calculate:

`RTO = SRTT + 4 × RTTVAR`

The implementation is intentionally educational and does not attempt to reproduce every detail of a production kernel TCP timer implementation.

### Packet loss

`LossyNetwork` uses a pseudo-random generator to simulate packet loss.

If a segment is lost, the model reports the loss.

A real TCP stack would retain the outstanding segment and use its loss-recovery mechanisms to decide when and how to retransmit it.

### Duplicate ACK detection

`DuplicateACKDetector` tracks repeated acknowledgments.

Three or more duplicate ACKs can trigger the classic fast-retransmit condition represented by the model.

### Graceful shutdown

`gracefulClose()` demonstrates the typical FIN/ACK sequence.

The case study transitions the gateway through:

`ESTABLISHED -> FIN-WAIT-1 -> FIN-WAIT-2 -> TIME-WAIT`

The server transitions toward closed state.

## Sequence-number calculations

For ordinary data:

`next sequence = current sequence + payload length`

For SYN:

`next sequence = current sequence + 1`

For FIN:

`next sequence = current sequence + 1`

For SYN with payload in a conceptual calculation:

`sequence-space consumption = 1 + payload length`

The actual legal use of payload with SYN depends on protocol rules and extensions, so the educational model primarily treats SYN as a control segment.

## Example packet progression

A simplified connection can be visualized as:

`Client -> Server: SYN SEQ=1000`

`Server -> Client: SYN-ACK SEQ=5000 ACK=1001`

`Client -> Server: ACK SEQ=1001 ACK=5001`

Then data:

`Client -> Server: ACK SEQ=1001 PAYLOAD=500`

Receiver:

`Server -> Client: ACK=1501`

The next segment can begin at:

`SEQ=1501`

If that segment is lost, the receiver may continue acknowledging the next missing byte.

## Important distinction: packet versus byte

TCP sequence numbers operate on bytes.

If three segments contain:

- 500 bytes
- 500 bytes
- 500 bytes

and the first sequence number is `1000`, their payload sequence ranges are:

- `1000-1499`
- `1500-1999`
- `2000-2499`

The corresponding cumulative ACK after all three are received is:

`2500`

The number of packets is not what determines the ACK value.

The amount of contiguous byte data is.

## Important distinction: ACK versus confirmation of an application operation

A TCP acknowledgment confirms receipt of sequence space according to TCP's reliability semantics.

It does not necessarily mean:

- The application has processed the data
- A database transaction has committed
- A file has been permanently stored
- A business operation has succeeded

For example, an HTTP request may be successfully received by TCP while the server application later returns an HTTP error.

Transport-level acknowledgment and application-level success are different concepts.

## Important distinction: reliability versus security

TCP reliability means that the protocol attempts to provide an ordered byte stream despite packet loss and reordering.

Reliability does not mean security.

TCP does not inherently provide:

- Confidentiality
- Cryptographic authentication
- Application authorization
- Protection from every network attacker

TLS can be layered above TCP to provide cryptographic protection.

## Important distinction: flow control versus congestion control

Flow control responds primarily to receiver capacity.

Congestion control responds primarily to network capacity and congestion signals.

A receiver can have plenty of available memory while the network path is congested.

A network can have available capacity while a particular receiver has a full buffer.

These are independent constraints.

## Edge cases

### Empty payload

Control segments such as ACKs can contain no application payload.

An empty data payload does not advance the payload sequence number.

### SYN

SYN consumes one sequence position.

### FIN

FIN consumes one sequence position.

### Duplicate data

A segment that has already been received may be duplicated.

The receiver must avoid delivering the same bytes to the application twice.

### Out-of-order data

A future segment may need to be buffered.

### Invalid ACK

An ACK that acknowledges data the sender has not transmitted should not be accepted as ordinary valid progress.

The educational implementations validate this condition.

### Zero receive window

A receiver may advertise no available capacity.

The sender must respect the receive window.

### Sequence wrap-around

32-bit TCP sequence numbers eventually wrap around.

Protocol implementations need serial-number arithmetic rather than naïve integer comparison.

### Packet loss

A lost segment can require retransmission.

The receiver may expose the loss through duplicate ACK behavior.

### Duplicate ACKs

Repeated ACKs can indicate a missing segment.

They do not automatically prove that a specific packet was lost in every possible network condition.

## Common mistakes

### Treating ACK as a packet number

Incorrect:

`ACK=5 means packet 5 arrived.`

Correct interpretation:

`ACK=5 identifies the next byte expected in the cumulative acknowledgment model.`

### Forgetting that SYN consumes sequence space

Incorrect:

`SYN SEQ=1000` followed by data `SEQ=1000`

Correct:

`SYN SEQ=1000` followed by the first normal data byte at `SEQ=1001`.

### Forgetting that FIN consumes sequence space

A FIN advances sequence space by one.

### Assuming TCP preserves application messages

TCP provides a byte stream, not a message protocol.

### Assuming TCP encrypts traffic

TCP does not provide encryption.

### Confusing MSS and MTU

MSS concerns TCP payload.

MTU concerns the maximum size of an IP packet on a network link.

### Confusing receive window and congestion window

The receive window represents receiver capacity.

The congestion window represents sender-side congestion-control limitations.

### Assuming every packet loss immediately causes a timeout

Loss can also be detected through duplicate ACKs and other recovery mechanisms.

### Assuming retransmission means application-level failure

A TCP retransmission is a transport-level recovery event.

The application may never observe it.

## Performance considerations

TCP performance depends on several interacting factors.

### RTT

A high RTT increases feedback delay.

### Window size

A sender may need a sufficiently large effective window to keep a high-bandwidth path fully utilized.

### Packet loss

Loss can cause retransmission and congestion-control reactions.

### MSS and MTU

Appropriate packet sizing reduces unnecessary fragmentation and protocol overhead.

### Receiver processing

If an application consumes data slowly, the receive buffer can fill and the advertised window can shrink.

### Congestion control

Increasing the sending rate without considering congestion can cause queues to grow and packet loss to increase.

## Bandwidth-delay product

Bandwidth-delay product estimates the amount of data that can be present in transit on a path.

The simplified equation is:

`BDP = bandwidth × RTT`

For a 100 Mbps path with a 100 ms RTT:

`100,000,000 bits/s × 0.1 s = 10,000,000 bits`

Converting to bytes:

`10,000,000 / 8 = 1,250,000 bytes`

A sender with an effective window much smaller than the bandwidth-delay product may be unable to keep the path fully utilized.

## Production implementation considerations

A real operating-system TCP stack must handle substantially more complexity than these educational implementations.

Production concerns include:

- TCP options
- Window scaling
- Timestamps
- Selective acknowledgment
- Congestion-control algorithms
- Retransmission backoff
- Fast recovery
- Duplicate and overlapping segments
- Sequence-number wrap-around
- Receive-buffer management
- Send-buffer management
- Connection state transitions
- Simultaneous open
- Simultaneous close
- Half-closed connections
- Delayed acknowledgments
- Keepalive behavior
- Path MTU discovery
- ECN
- Security hardening
- Resource exhaustion
- Timer management
- High-throughput performance
- Kernel memory management
- Socket API behavior

The code in this repository intentionally isolates fundamental concepts rather than reproducing a complete TCP stack.

## Debugging TCP behavior

When examining a packet capture, a useful process is:

1. Identify the two endpoints.
2. Locate the initial SYN.
3. Record the client's initial sequence number.
4. Locate the SYN-ACK.
5. Verify its acknowledgment of the client's SYN.
6. Record the server's initial sequence number.
7. Locate the final ACK.
8. Track sequence numbers in each direction independently.
9. Track cumulative acknowledgment numbers.
10. Inspect advertised receive windows.
11. Identify repeated sequence ranges.
12. Identify duplicate ACKs.
13. Look for retransmitted segments.
14. Compare packet timestamps to estimate RTT.
15. Inspect FIN and RST packets when the connection closes.

A sequence-number table is often useful during manual analysis:

| Direction | SEQ | ACK | Payload | Interpretation |
|---|---:|---:|---:|---|
| Client → Server | 1000 | — | 0 | SYN |
| Server → Client | 5000 | 1001 | 0 | SYN-ACK |
| Client → Server | 1001 | 5001 | 0 | Final ACK |
| Client → Server | 1001 | 5001 | 500 | First data |
| Server → Client | 5001 | 1501 | 0 | Cumulative ACK |

## Python, JavaScript, and C++ comparison

| Language | Main demonstration |
|---|---|
| Python | Broad protocol concepts, simulations, validation, calculations, and readable models |
| JavaScript | Typed byte arrays, bit flags, event-driven simulation, asynchronous timers, and stream assembly |
| C++ | Structured systems modeling, classes, queues, maps, state management, validation, and performance-oriented design |

### Why Python is useful

Python makes protocol algorithms easy to inspect.

Classes such as `TCPSender` and `TCPReceiver` expose the state directly, making it suitable for studying:

- Sequence calculations
- ACK behavior
- Window calculations
- RTT estimation
- Retransmission
- Simulations

### Why JavaScript is useful

JavaScript is particularly suitable for event-driven demonstrations.

Its asynchronous execution model naturally represents:

- Network events
- Timers
- Packet delivery
- Packet loss
- Application stream consumption

`Uint8Array` also provides a more accurate representation of raw network bytes than ordinary JavaScript strings.

### Why C++ is useful

C++ is appropriate for modeling systems software where memory layout, data structures, deterministic behavior, and performance matter.

The C++ case study uses:

- `std::deque` for outstanding transmission state
- `std::map` for out-of-order segments
- `std::optional` for fields that may be absent
- `std::vector` for payloads
- `std::mt19937` for deterministic loss simulation
- Classes to separate protocol responsibilities

These are representative of the kinds of structures that are useful when designing systems-level protocol software.

## Design principles demonstrated

### Separate protocol state from packet representation

`TCPSegment` represents transmitted information.

Sender and receiver classes maintain state about what has been transmitted, acknowledged, buffered, or expected.

### Make sequence calculations explicit

Sequence-number advancement is implemented as an explicit operation instead of being hidden inside unrelated logic.

### Validate protocol assumptions

The implementations reject invalid conditions such as:

- Negative sequence values
- Invalid MSS
- Invalid RTT
- ACKs beyond transmitted data
- Receive-window overflow

### Retain unacknowledged data

A reliable sender must retain enough information to retransmit data that has not been successfully acknowledged.

### Treat each direction independently

TCP is full-duplex.

The sequence number of one direction and the sequence number of the reverse direction are separate.

## Limitations of the educational models

These implementations are deliberately simplified.

They do not constitute a production TCP stack.

They do not implement the complete:

- TCP header format
- TCP checksum algorithm
- IP layer
- Socket API
- TCP option negotiation
- SACK option processing
- Window scaling
- Full congestion-control algorithms
- Full retransmission-control algorithms
- Simultaneous-open behavior
- Every TCP state transition
- Production sequence-number comparison rules
- Kernel-level timer implementation
- NIC interaction
- Real packet transmission

The goal is to make core TCP mechanics observable and executable.

## Real-world relevance

The concepts demonstrated by these implementations appear directly in real network troubleshooting and systems engineering.

When an application experiences poor network behavior, understanding TCP helps distinguish among:

- Packet loss
- Receiver limitations
- Network congestion
- High latency
- Out-of-order delivery
- Retransmission
- Connection resets
- Connection-establishment problems
- Connection-termination problems

For example, a packet capture showing repeated ACK values and a retransmitted sequence range can reveal a loss-recovery event that would otherwise appear to the application simply as increased latency.

Similarly, a shrinking advertised receive window can indicate receiver-side backpressure rather than network congestion.

TCP therefore provides an important foundation for understanding web performance, distributed systems, cloud networking, database connections, service-to-service communication, and network troubleshooting.
