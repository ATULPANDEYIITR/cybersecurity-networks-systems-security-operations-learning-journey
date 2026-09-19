#!/usr/bin/env python3
"""
UDP Fundamentals: from beginner concepts to advanced practical networking.

This standalone study script demonstrates:
- UDP terminology and packet structure
- Connectionless communication
- Datagram semantics
- Client/server communication
- Binding, ports, addresses, and sockets
- Timeouts and error handling
- DNS-style request/response design
- Broadcasting and multicast concepts
- Streaming and telemetry patterns
- Reliability techniques layered over UDP
- Message framing and serialization
- Checksums and integrity concepts
- Security considerations
- Performance measurements
- Concurrency with threads
- A small reliable-message protocol
- A simulated lossy network for testing

All network examples use localhost by default where practical.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import random
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# 1. FUNDAMENTAL TERMINOLOGY
# ---------------------------------------------------------------------------

def explain_fundamentals() -> None:
    """Print the core UDP vocabulary."""
    print("=" * 78)
    print("UDP FUNDAMENTALS")
    print("=" * 78)
    print(
        """
UDP stands for User Datagram Protocol.

UDP is a transport-layer protocol. Applications normally access it through
operating-system sockets.

Important characteristics:

1. Connectionless
   UDP does not establish a transport connection before sending data.

2. Datagram-oriented
   Each send operation produces a separate datagram. Message boundaries are
   preserved at the UDP layer.

3. Best effort
   UDP does not guarantee delivery, ordering, duplicate suppression, or
   retransmission.

4. Low protocol overhead
   The UDP header is only 8 bytes.

5. Application-controlled reliability
   An application can add sequence numbers, acknowledgements, retries,
   integrity checks, or other mechanisms when its requirements justify them.

6. No congestion-control mechanism equivalent to TCP's built-in behavior
   is provided by UDP itself. Applications sending substantial traffic need
   to consider network conditions and congestion.

A useful mental model:

    Application
        |
        | message
        v
    UDP socket
        |
        | datagram
        v
    IP network
        |
        v
    Destination UDP socket
        |
        v
    Application
"""
    )


# ---------------------------------------------------------------------------
# 2. UDP HEADER AND DATAGRAM STRUCTURE
# ---------------------------------------------------------------------------

def explain_udp_header() -> None:
    """Explain the four UDP header fields."""
    print("\n" + "=" * 78)
    print("UDP HEADER")
    print("=" * 78)

    fields = [
        ("Source port", "16 bits", "Port associated with the sender."),
        ("Destination port", "16 bits", "Port associated with the receiver."),
        ("Length", "16 bits", "UDP header plus UDP payload length."),
        ("Checksum", "16 bits", "Integrity mechanism over the UDP datagram and pseudo-header."),
    ]

    for name, size, meaning in fields:
        print(f"{name:18} {size:8} {meaning}")

    print(
        """
The UDP header is 8 bytes.

UDP does not contain fields for:
- connection establishment
- sequence numbers
- acknowledgement numbers
- retransmission counters
- receive windows
- stream offsets

Those omissions are deliberate. Applications that require such behavior
must obtain it elsewhere, such as TCP, QUIC, or an application protocol.
"""
    )


# ---------------------------------------------------------------------------
# 3. BASIC UDP CLIENT/SERVER
# ---------------------------------------------------------------------------

HOST = "127.0.0.1"


def run_udp_server(
    host: str = HOST,
    port: int = 0,
    stop_after: int = 3,
) -> tuple[int, threading.Thread]:
    """
    Start a small UDP echo server in a background thread.

    port=0 asks the operating system to select an available ephemeral port.
    This avoids hard-coding a port and reduces conflicts.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    actual_port = server_socket.getsockname()[1]

    def server_loop() -> None:
        received_count = 0
        server_socket.settimeout(5.0)

        try:
            while received_count < stop_after:
                try:
                    data, client_address = server_socket.recvfrom(4096)
                except socket.timeout:
                    break

                received_count += 1

                # UDP preserves datagram boundaries: one recvfrom() receives
                # one UDP datagram, subject to the buffer size supplied.
                response = b"echo:" + data
                server_socket.sendto(response, client_address)
        finally:
            server_socket.close()

    thread = threading.Thread(target=server_loop, daemon=True)
    thread.start()
    return actual_port, thread


def udp_echo_client(host: str, port: int, messages: list[str]) -> None:
    """Send independent UDP datagrams and print responses."""
    print("\nUDP echo demonstration:")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
        client_socket.settimeout(2.0)

        for message in messages:
            payload = message.encode("utf-8")

            # sendto() sends one datagram to a destination address.
            client_socket.sendto(payload, (host, port))

            try:
                response, server_address = client_socket.recvfrom(4096)
                print(
                    f"sent={message!r}, received={response.decode()!r}, "
                    f"server={server_address}"
                )
            except socket.timeout:
                print(f"timeout waiting for response to {message!r}")


def demonstrate_basic_udp() -> None:
    """Run the local UDP client/server example."""
    port, server_thread = run_udp_server(stop_after=3)
    udp_echo_client(
        HOST,
        port,
        ["hello", "UDP preserves datagram boundaries", "third message"],
    )
    server_thread.join(timeout=2)


# ---------------------------------------------------------------------------
# 4. DATAGRAM BOUNDARIES
# ---------------------------------------------------------------------------

def demonstrate_datagram_boundaries() -> None:
    """
    Show an important distinction between UDP and byte-stream protocols.

    TCP exposes a byte stream. UDP exposes individual datagrams.
    """
    print("\n" + "=" * 78)
    print("DATAGRAM BOUNDARIES")
    print("=" * 78)

    port, server_thread = run_udp_server(stop_after=2)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)

        client.sendto(b"first datagram", (HOST, port))
        client.sendto(b"second datagram", (HOST, port))

        first, _ = client.recvfrom(4096)
        second, _ = client.recvfrom(4096)

        print("First response :", first)
        print("Second response:", second)

    server_thread.join(timeout=2)

    print(
        """
Each recvfrom() corresponds to a received UDP datagram rather than an
arbitrary fragment of a continuous byte stream.

The receive buffer matters. If a datagram is larger than the buffer supplied
to recvfrom(), excess data can be discarded by the operating system rather
than returned through a second recvfrom() call.

Therefore application protocols should establish maximum message sizes.
"""
    )


# ---------------------------------------------------------------------------
# 5. ADDRESSING, PORTS, AND BINDING
# ---------------------------------------------------------------------------

def demonstrate_addressing() -> None:
    """Demonstrate IPv4 address and port concepts."""
    print("\n" + "=" * 78)
    print("ADDRESSING AND PORTS")
    print("=" * 78)

    addresses = ["127.0.0.1", "192.0.2.10", "239.255.0.1"]

    for address in addresses:
        parsed = ipaddress.ip_address(address)
        print(
            f"{address:15} version={parsed.version}, "
            f"loopback={parsed.is_loopback}, multicast={parsed.is_multicast}"
        )

    print(
        """
An endpoint is commonly represented as:

    IP address + UDP port

Examples:
    127.0.0.1:5353
    192.0.2.10:9000

A server normally binds to a local address and port. A client may allow the
operating system to select its source port automatically.

Ports distinguish application endpoints within the same host.
"""
    )


# ---------------------------------------------------------------------------
# 6. TIMEOUTS AND FAILURE MODES
# ---------------------------------------------------------------------------

def demonstrate_timeout() -> None:
    """Show why applications need explicit timeout behavior."""
    print("\n" + "=" * 78)
    print("TIMEOUTS AND FAILURE HANDLING")
    print("=" * 78)

    unused_port = 65500

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.25)
        started = time.perf_counter()

        client.sendto(b"request to a probably unused port", (HOST, unused_port))

        try:
            client.recvfrom(1024)
        except socket.timeout:
            elapsed = time.perf_counter() - started
            print(f"No application response after approximately {elapsed:.3f}s.")

    print(
        """
A UDP send operation can succeed locally even when the destination
application does not receive or process the datagram.

Possible failures include:
- packet loss
- destination host unavailable
- destination process unavailable
- firewall filtering
- network congestion
- receive-buffer overflow
- malformed application data
- application timeout

The absence of a response is not automatically proof of one particular cause.
"""
    )


# ---------------------------------------------------------------------------
# 7. SERIALIZATION AND MESSAGE FRAMING
# ---------------------------------------------------------------------------

@dataclass
class SensorReading:
    sensor_id: str
    sequence: int
    temperature_c: float
    timestamp: float

    def to_bytes(self) -> bytes:
        """Serialize a reading as UTF-8 JSON."""
        document = {
            "sensor_id": self.sensor_id,
            "sequence": self.sequence,
            "temperature_c": self.temperature_c,
            "timestamp": self.timestamp,
        }
        return json.dumps(document, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, payload: bytes) -> "SensorReading":
        """Validate and deserialize a reading."""
        document = json.loads(payload.decode("utf-8"))

        if not isinstance(document, dict):
            raise ValueError("message must contain a JSON object")

        required = {
            "sensor_id",
            "sequence",
            "temperature_c",
            "timestamp",
        }

        missing = required - document.keys()
        if missing:
            raise ValueError(f"missing fields: {sorted(missing)}")

        if not isinstance(document["sensor_id"], str):
            raise ValueError("sensor_id must be a string")

        if not isinstance(document["sequence"], int):
            raise ValueError("sequence must be an integer")

        if not isinstance(document["temperature_c"], (int, float)):
            raise ValueError("temperature_c must be numeric")

        return cls(
            sensor_id=document["sensor_id"],
            sequence=document["sequence"],
            temperature_c=float(document["temperature_c"]),
            timestamp=float(document["timestamp"]),
        )


def demonstrate_serialization() -> None:
    """Show an application-level UDP message format."""
    print("\n" + "=" * 78)
    print("APPLICATION MESSAGE SERIALIZATION")
    print("=" * 78)

    reading = SensorReading(
        sensor_id="warehouse-17",
        sequence=42,
        temperature_c=21.75,
        timestamp=time.time(),
    )

    encoded = reading.to_bytes()
    decoded = SensorReading.from_bytes(encoded)

    print("Encoded:", encoded.decode())
    print("Decoded:", decoded)


# ---------------------------------------------------------------------------
# 8. APPLICATION-LEVEL SEQUENCING
# ---------------------------------------------------------------------------

@dataclass
class SequencedPacket:
    sequence: int
    payload: bytes

    def encode(self) -> bytes:
        """
        Encode:
            8-byte unsigned sequence number
            followed by application payload
        """
        return struct.pack("!Q", self.sequence) + self.payload

    @staticmethod
    def decode(data: bytes) -> "SequencedPacket":
        if len(data) < 8:
            raise ValueError("packet is too short to contain a sequence number")

        sequence = struct.unpack("!Q", data[:8])[0]
        return SequencedPacket(sequence=sequence, payload=data[8:])


class SequenceTracker:
    """Detect gaps and duplicates in an ordered sequence of packets."""

    def __init__(self) -> None:
        self.last_sequence: Optional[int] = None
        self.missing_packets = 0
        self.duplicates = 0

    def observe(self, sequence: int) -> None:
        if self.last_sequence is None:
            self.last_sequence = sequence
            return

        if sequence > self.last_sequence + 1:
            self.missing_packets += sequence - self.last_sequence - 1
            self.last_sequence = sequence
        elif sequence == self.last_sequence + 1:
            self.last_sequence = sequence
        elif sequence <= self.last_sequence:
            self.duplicates += 1


def demonstrate_sequence_tracking() -> None:
    """Demonstrate one way to detect loss and duplication."""
    print("\n" + "=" * 78)
    print("SEQUENCE NUMBERS")
    print("=" * 78)

    tracker = SequenceTracker()

    observed = [1, 2, 4, 5, 5, 7]
    for sequence in observed:
        tracker.observe(sequence)

    print("Observed:", observed)
    print("Estimated missing packets:", tracker.missing_packets)
    print("Duplicates/out-of-order observations:", tracker.duplicates)

    print(
        """
Sequence numbers do not magically make UDP reliable. They provide information
that an application can use to detect ordering problems, loss, or duplicates.

A protocol must define what to do after detection:
- ignore late packets
- request retransmission
- interpolate missing data
- use the latest state
- terminate the session
- continue without recovery
"""
    )


# ---------------------------------------------------------------------------
# 9. SIMPLE ACKNOWLEDGEMENT PROTOCOL
# ---------------------------------------------------------------------------

@dataclass
class ReliableMessage:
    sequence: int
    payload: bytes

    def encode(self) -> bytes:
        """
        Header:
            1 byte version
            1 byte message type
            8 bytes sequence number
            payload
        """
        version = 1
        message_type = 1
        return struct.pack("!BBQ", version, message_type, self.sequence) + self.payload

    @staticmethod
    def decode(data: bytes) -> "ReliableMessage":
        if len(data) < 10:
            raise ValueError("reliable message header is incomplete")

        version, message_type, sequence = struct.unpack("!BBQ", data[:10])

        if version != 1:
            raise ValueError(f"unsupported protocol version: {version}")

        if message_type != 1:
            raise ValueError(f"unexpected message type: {message_type}")

        return ReliableMessage(sequence, data[10:])


def ack_packet(sequence: int) -> bytes:
    """Create an application-level acknowledgement."""
    return struct.pack("!BBQ", 1, 2, sequence)


def decode_ack(data: bytes) -> int:
    """Validate and decode an acknowledgement."""
    if len(data) != 10:
        raise ValueError("invalid acknowledgement length")

    version, message_type, sequence = struct.unpack("!BBQ", data)

    if version != 1 or message_type != 2:
        raise ValueError("invalid acknowledgement")

    return sequence


def run_ack_server(
    host: str = HOST,
    port: int = 0,
    expected_messages: int = 3,
) -> tuple[int, threading.Thread]:
    """Run a local UDP server implementing application-level ACKs."""
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((host, port))
    actual_port = server.getsockname()[1]

    def loop() -> None:
        processed = 0
        server.settimeout(5)

        try:
            while processed < expected_messages:
                try:
                    data, address = server.recvfrom(4096)
                except socket.timeout:
                    break

                try:
                    message = ReliableMessage.decode(data)
                    print(
                        f"  server received sequence={message.sequence}, "
                        f"payload={message.payload!r}"
                    )
                    server.sendto(ack_packet(message.sequence), address)
                    processed += 1
                except ValueError as error:
                    print("  server rejected packet:", error)
        finally:
            server.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return actual_port, thread


def reliable_send(
    client: socket.socket,
    destination: tuple[str, int],
    sequence: int,
    payload: bytes,
    retries: int = 3,
    timeout: float = 0.3,
) -> bool:
    """
    Implement stop-and-wait reliability above UDP.

    This is educational rather than production-grade. Real protocols may use
    sliding windows, congestion control, authentication, encryption, and
    more sophisticated acknowledgement semantics.
    """
    packet = ReliableMessage(sequence, payload).encode()

    for attempt in range(1, retries + 1):
        client.sendto(packet, destination)

        try:
            data, _ = client.recvfrom(1024)
            acknowledged = decode_ack(data)

            if acknowledged == sequence:
                print(f"  sequence={sequence} acknowledged on attempt {attempt}")
                return True

        except socket.timeout:
            print(f"  sequence={sequence} timeout on attempt {attempt}")

    return False


def demonstrate_reliability_layer() -> None:
    """Demonstrate adding acknowledgement and retry logic above UDP."""
    print("\n" + "=" * 78)
    print("APPLICATION-LEVEL RELIABILITY")
    print("=" * 78)

    port, server_thread = run_ack_server(expected_messages=3)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.3)

        for sequence in range(1, 4):
            success = reliable_send(
                client,
                (HOST, port),
                sequence,
                f"payload-{sequence}".encode(),
            )

            if not success:
                print(f"  sequence={sequence} failed after retries")

    server_thread.join(timeout=2)


# ---------------------------------------------------------------------------
# 10. DNS-STYLE REQUEST/RESPONSE
# ---------------------------------------------------------------------------

class MiniDnsServer:
    """
    A deliberately small DNS-like service.

    Real DNS has a much richer binary protocol, resource records, caching,
    recursion, authoritative servers, negative answers, EDNS, DNSSEC, and
    many other mechanisms. This example focuses on UDP request/response.
    """

    def __init__(self, records: dict[str, str]) -> None:
        self.records = records

    def handle(self, request: bytes) -> bytes:
        """Parse a simple name query and produce a structured response."""
        try:
            query = json.loads(request.decode("utf-8"))
            name = query["name"].lower().rstrip(".")
        except (ValueError, KeyError, UnicodeDecodeError) as error:
            return json.dumps(
                {"status": "FORMERR", "error": str(error)}
            ).encode("utf-8")

        address = self.records.get(name)

        if address is None:
            response = {
                "status": "NXDOMAIN",
                "name": name,
            }
        else:
            response = {
                "status": "NOERROR",
                "name": name,
                "address": address,
            }

        return json.dumps(response, separators=(",", ":")).encode("utf-8")


def run_mini_dns_server(
    records: dict[str, str],
) -> tuple[int, threading.Thread]:
    """Start the mini DNS-like service."""
    service = MiniDnsServer(records)

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, 0))
    port = server.getsockname()[1]

    def loop() -> None:
        server.settimeout(5)

        try:
            while True:
                try:
                    request, address = server.recvfrom(2048)
                except socket.timeout:
                    break

                if request == b"__STOP__":
                    break

                response = service.handle(request)
                server.sendto(response, address)
        finally:
            server.close()

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()

    return port, thread


def mini_dns_query(
    host: str,
    port: int,
    name: str,
) -> dict:
    """Send one DNS-like query."""
    request = json.dumps({"name": name}).encode("utf-8")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(request, (host, port))
        response, _ = client.recvfrom(2048)

    return json.loads(response.decode("utf-8"))


def demonstrate_dns_style() -> None:
    """Demonstrate why DNS is a classic UDP-oriented application."""
    print("\n" + "=" * 78)
    print("DNS-STYLE UDP REQUEST/RESPONSE")
    print("=" * 78)

    records = {
        "example.local": "192.0.2.20",
        "api.local": "192.0.2.30",
    }

    port, server_thread = run_mini_dns_server(records)

    try:
        for name in ["example.local", "missing.local", "api.local"]:
            print(name, "->", mini_dns_query(HOST, port, name))
    finally:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stopper:
            stopper.sendto(b"__STOP__", (HOST, port))

    server_thread.join(timeout=2)

    print(
        """
DNS is not simply "UDP". Modern DNS can use different transports depending
on circumstances. Traditional DNS queries commonly use UDP because a small
request and response can be exchanged efficiently without maintaining a
transport connection.

Large responses, truncation, transport requirements, or privacy/security
requirements can cause DNS traffic to use other mechanisms.
"""
    )


# ---------------------------------------------------------------------------
# 11. STREAMING AND TELEMETRY
# ---------------------------------------------------------------------------

class TelemetryReceiver:
    """Keep the latest state from an unordered UDP telemetry stream."""

    def __init__(self) -> None:
        self.latest_sequence = -1
        self.latest_value: Optional[float] = None
        self.accepted = 0
        self.discarded = 0

    def receive(self, sequence: int, value: float) -> None:
        # For telemetry where only current state matters, a late packet can
        # be discarded instead of retransmitted.
        if sequence <= self.latest_sequence:
            self.discarded += 1
            return

        self.latest_sequence = sequence
        self.latest_value = value
        self.accepted += 1


def demonstrate_streaming_pattern() -> None:
    """Demonstrate a common real-time telemetry policy."""
    print("\n" + "=" * 78)
    print("STREAMING / REAL-TIME TELEMETRY")
    print("=" * 78)

    receiver = TelemetryReceiver()

    samples = [
        (100, 20.1),
        (101, 20.2),
        (103, 20.4),
        (102, 20.3),
        (104, 20.5),
    ]

    for sequence, value in samples:
        receiver.receive(sequence, value)

    print("Latest sequence:", receiver.latest_sequence)
    print("Latest value:", receiver.latest_value)
    print("Accepted:", receiver.accepted)
    print("Discarded late/duplicate:", receiver.discarded)

    print(
        """
For live audio, video, games, telemetry, and control systems, retransmitting
every lost packet can sometimes be worse than skipping it because old data
may become useless by the time it arrives.

The appropriate policy depends on the application:
- real-time media may tolerate some loss
- financial transaction state generally requires reliable delivery
- telemetry may prefer newest-state semantics
- industrial control requires carefully bounded latency and strong safety
  engineering
"""
    )


# ---------------------------------------------------------------------------
# 12. BROADCAST AND MULTICAST CONCEPTS
# ---------------------------------------------------------------------------

def demonstrate_multicast_configuration() -> None:
    """
    Show how multicast configuration is represented without joining a live
    multicast group.

    239.0.0.0/8 is commonly used for administratively scoped IPv4 multicast.
    """
    print("\n" + "=" * 78)
    print("MULTICAST CONFIGURATION")
    print("=" * 78)

    multicast_address = "239.255.0.1"
    group = ipaddress.ip_address(multicast_address)

    print("Address:", multicast_address)
    print("IPv4 multicast:", group.is_multicast)

    ttl = 2
    print("Example multicast TTL:", ttl)

    print(
        """
Multicast allows one sender to address a multicast group rather than sending
a separate application datagram to every receiver.

Typical conceptual flow:

sender -> multicast group -> multiple receivers

Receivers join the group through socket and network-interface mechanisms.

Broadcast and multicast behavior depends on the operating system, interface,
routing configuration, firewalls, and network topology.
"""
    )


# ---------------------------------------------------------------------------
# 13. INTEGRITY CHECKS
# ---------------------------------------------------------------------------

def payload_digest(payload: bytes) -> str:
    """Create a SHA-256 digest for application-level integrity checking."""
    return hashlib.sha256(payload).hexdigest()


def demonstrate_integrity() -> None:
    """Show how an application can detect unintended payload modification."""
    print("\n" + "=" * 78)
    print("PAYLOAD INTEGRITY")
    print("=" * 78)

    payload = b"important application data"
    digest = payload_digest(payload)

    print("Payload:", payload)
    print("SHA-256:", digest)

    modified = payload + b"!"
    print("Modified payload digest:", payload_digest(modified))
    print("Digests match:", digest == payload_digest(modified))

    print(
        """
A cryptographic hash can detect changes when the expected digest is trusted,
but a plain hash does not authenticate the sender.

For hostile networks, authentication requires a mechanism such as a
cryptographic MAC or digital signature. Confidentiality requires encryption.

UDP's checksum and an application-level cryptographic integrity mechanism
serve different purposes and should not be treated as interchangeable.
"""
    )


# ---------------------------------------------------------------------------
# 14. SECURITY VALIDATION
# ---------------------------------------------------------------------------

MAX_MESSAGE_SIZE = 1200


def validate_udp_application_message(payload: bytes) -> dict:
    """
    Example defensive parser.

    Validation is essential because UDP exposes an application to arbitrary
    datagrams if the socket is reachable.
    """
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError("message exceeds configured application limit")

    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid UTF-8 JSON") from error

    if not isinstance(document, dict):
        raise ValueError("top-level value must be an object")

    message_type = document.get("type")

    if message_type not in {"telemetry", "heartbeat"}:
        raise ValueError("unsupported message type")

    return document


def demonstrate_security_validation() -> None:
    """Demonstrate input validation for UDP datagrams."""
    print("\n" + "=" * 78)
    print("SECURITY AND INPUT VALIDATION")
    print("=" * 78)

    valid = b'{"type":"heartbeat","device":"sensor-7"}'
    invalid = b'{"type":"unexpected","device":"sensor-7"}'

    print("Valid message:", validate_udp_application_message(valid))

    try:
        validate_udp_application_message(invalid)
    except ValueError as error:
        print("Rejected invalid message:", error)

    print(
        """
UDP security concerns include:

- spoofed source addresses
- reflection/amplification attacks
- malformed datagrams
- resource exhaustion
- packet floods
- replay attacks
- missing confidentiality
- missing application authentication
- fragmented or oversized traffic
- state exhaustion when applications track senders

Defensive design includes:
- strict input validation
- bounded datagram sizes
- rate limiting
- authentication where appropriate
- replay protection
- carefully bounded server state
- amplification controls
- least-privilege deployment
- monitoring and logging
- appropriate firewall policy

A UDP socket does not inherently authenticate its sender.
"""
    )


# ---------------------------------------------------------------------------
# 15. BASE64 IS NOT ENCRYPTION
# ---------------------------------------------------------------------------

def demonstrate_encoding_vs_encryption() -> None:
    """Illustrate the difference between encoding and encryption."""
    print("\n" + "=" * 78)
    print("ENCODING IS NOT ENCRYPTION")
    print("=" * 78)

    secret = b"confidential UDP payload"
    encoded = base64.b64encode(secret)

    print("Original:", secret)
    print("Base64:", encoded)
    print("Decoded:", base64.b64decode(encoded))

    print(
        """
Base64 only represents binary data as printable characters. Anyone who can
read the packet can decode it.

When confidentiality is required, use an authenticated encryption protocol
or a secure higher-level protocol rather than inventing cryptography around
UDP.
"""
    )


# ---------------------------------------------------------------------------
# 16. PERFORMANCE MEASUREMENT
# ---------------------------------------------------------------------------

def benchmark_local_udp(iterations: int = 100) -> None:
    """
    Measure local request/response latency.

    This is not an Internet benchmark. Loopback performance is affected by
    the local operating system, Python runtime, scheduling, CPU load, and
    socket implementation.
    """
    print("\n" + "=" * 78)
    print("LOCAL UDP LATENCY BENCHMARK")
    print("=" * 78)

    port, server_thread = run_udp_server(stop_after=iterations)

    latencies: list[float] = []

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)

        for index in range(iterations):
            payload = f"benchmark-{index}".encode("ascii")

            started = time.perf_counter()
            client.sendto(payload, (HOST, port))
            client.recvfrom(4096)
            elapsed = time.perf_counter() - started

            latencies.append(elapsed)

    server_thread.join(timeout=2)

    if latencies:
        minimum = min(latencies)
        maximum = max(latencies)
        average = sum(latencies) / len(latencies)

        print(f"iterations: {len(latencies)}")
        print(f"minimum:   {minimum * 1000:.3f} ms")
        print(f"average:   {average * 1000:.3f} ms")
        print(f"maximum:   {maximum * 1000:.3f} ms")


# ---------------------------------------------------------------------------
# 17. SIMULATED LOSSY NETWORK
# ---------------------------------------------------------------------------

class LossyChannel:
    """
    Simulate packet loss and duplication without manipulating a real network.

    This is useful for testing application behavior safely.
    """

    def __init__(
        self,
        loss_probability: float = 0.15,
        duplicate_probability: float = 0.05,
        random_seed: int = 7,
    ) -> None:
        if not 0 <= loss_probability <= 1:
            raise ValueError("loss probability must be between 0 and 1")
        if not 0 <= duplicate_probability <= 1:
            raise ValueError("duplicate probability must be between 0 and 1")

        self.loss_probability = loss_probability
        self.duplicate_probability = duplicate_probability
        self.random = random.Random(random_seed)

    def transmit(self, packet: bytes) -> list[bytes]:
        if self.random.random() < self.loss_probability:
            return []

        output = [packet]

        if self.random.random() < self.duplicate_probability:
            output.append(packet)

        return output


def demonstrate_loss_simulation() -> None:
    """Show how an application can be tested under controlled loss."""
    print("\n" + "=" * 78)
    print("SIMULATED LOSS AND DUPLICATION")
    print("=" * 78)

    channel = LossyChannel(
        loss_probability=0.20,
        duplicate_probability=0.10,
        random_seed=42,
    )

    delivered = 0
    duplicated = 0

    for sequence in range(1, 21):
        packet = SequencedPacket(sequence, b"data").encode()
        outputs = channel.transmit(packet)

        delivered += len(outputs)

        if len(outputs) == 2:
            duplicated += 1

    print("Original packets:", 20)
    print("Delivered copies:", delivered)
    print("Duplicate events:", duplicated)

    print(
        """
A simulation makes it possible to test:
- retry policies
- sequence tracking
- duplicate handling
- timeout behavior
- application-level recovery

without intentionally disrupting a real network.
"""
    )


# ---------------------------------------------------------------------------
# 18. SOCKET OPTIONS
# ---------------------------------------------------------------------------

def demonstrate_socket_options() -> None:
    """Show selected UDP socket options."""
    print("\n" + "=" * 78)
    print("SOCKET OPTIONS")
    print("=" * 78)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        receive_buffer = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        send_buffer = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

        print("Operating-system receive buffer:", receive_buffer)
        print("Operating-system send buffer:", send_buffer)

    print(
        """
Socket buffer values are operating-system managed and may not correspond
directly to the exact application payload capacity.

For high-rate UDP systems, socket buffers, packet rate, CPU scheduling,
network-interface capacity, receive processing, and application backpressure
can all matter.
"""
    )


# ---------------------------------------------------------------------------
# 19. UDP SIZE AND MTU CONSIDERATIONS
# ---------------------------------------------------------------------------

def explain_size_limits() -> None:
    """Explain why applications should avoid blindly maximizing datagrams."""
    print("\n" + "=" * 78)
    print("DATAGRAM SIZE AND MTU")
    print("=" * 78)

    print(
        """
UDP has a 16-bit Length field, so the protocol field can represent a UDP
datagram up to 65,535 bytes including its 8-byte UDP header.

That does not mean that sending a 65,535-byte UDP payload is a good design.

IP networks have MTUs. If a packet exceeds an available path MTU, IP
fragmentation or other behavior may occur depending on protocol version,
configuration, and network conditions.

Large fragmented UDP messages can have undesirable loss characteristics:
if one fragment is lost, the complete higher-level datagram may become
unusable.

Applications often choose conservative payload sizes, especially for
Internet-facing protocols. Some protocols deliberately target payloads
around or below common path MTU constraints.
"""
    )


# ---------------------------------------------------------------------------
# 20. UDP VS TCP COMPARISON
# ---------------------------------------------------------------------------

def compare_udp_tcp() -> None:
    """Print a factual comparison."""
    print("\n" + "=" * 78)
    print("UDP VS TCP")
    print("=" * 78)

    rows = [
        ("Transport model", "Datagram", "Byte stream"),
        ("Connection setup", "None at transport layer", "Three-way handshake"),
        ("Ordering", "Not guaranteed", "Guaranteed byte-stream ordering"),
        ("Retransmission", "Not provided by UDP", "Built into TCP"),
        ("Duplicate suppression", "Not provided", "TCP presents ordered stream semantics"),
        ("Message boundaries", "Preserved", "Not preserved"),
        ("Congestion control", "Not provided by UDP", "Provided by TCP"),
        ("Broadcast/multicast", "Can support relevant IP mechanisms", "Not used as a TCP feature"),
        ("Typical uses", "DNS, media, games, telemetry", "Web, file transfer, many APIs"),
    ]

    print(f"{'Property':25} {'UDP':32} {'TCP':35}")
    print("-" * 94)

    for property_name, udp, tcp in rows:
        print(f"{property_name:25} {udp:32} {tcp:35}")


# ---------------------------------------------------------------------------
# 21. PRODUCTION DESIGN CHECKLIST
# ---------------------------------------------------------------------------

def production_checklist() -> None:
    """Print a practical checklist for designing UDP applications."""
    print("\n" + "=" * 78)
    print("PRODUCTION UDP DESIGN CHECKLIST")
    print("=" * 78)

    checklist = [
        "Define whether loss is acceptable.",
        "Define whether ordering is required.",
        "Define whether duplicate packets are possible.",
        "Set explicit receive and processing limits.",
        "Define timeouts and retry behavior.",
        "Use sequence numbers where ordering/loss detection matters.",
        "Use message types and protocol versions.",
        "Validate every received field.",
        "Avoid unbounded per-client state.",
        "Consider rate limiting and abuse resistance.",
        "Use authentication when the sender must be trusted.",
        "Use encryption when confidentiality is required.",
        "Plan for packet reordering.",
        "Plan for network changes and endpoint disappearance.",
        "Measure latency, loss, jitter, throughput, and CPU usage.",
        "Test under loss, duplication, delay, and malformed input.",
        "Avoid assuming loopback performance represents Internet performance.",
        "Document maximum supported datagram size.",
    ]

    for item in checklist:
        print("[ ]", item)


# ---------------------------------------------------------------------------
# 22. ADVANCED CONCEPTS
# ---------------------------------------------------------------------------

def explain_advanced_concepts() -> None:
    """Explain advanced mechanisms without requiring external infrastructure."""
    print("\n" + "=" * 78)
    print("ADVANCED UDP CONCEPTS")
    print("=" * 78)

    print(
        """
1. Jitter
   Variation in packet arrival time. Real-time media systems often need
   buffering or timing strategies to smooth jitter.

2. Loss rate
   Fraction of transmitted datagrams that fail to arrive or are discarded.

3. Reordering
   Datagram B may arrive before datagram A even if A was sent first.

4. Application-level acknowledgement
   The receiver explicitly confirms receipt.

5. Selective retransmission
   Only missing data is retransmitted instead of resending everything.

6. Sliding windows
   Multiple packets may be in flight simultaneously. This can greatly
   improve throughput compared with stop-and-wait.

7. Forward error correction
   Redundant information can allow recovery from some losses without
   retransmission.

8. Congestion control
   A responsible UDP-based protocol can implement its own congestion-control
   strategy. This is important for Internet-scale traffic.

9. NAT traversal
   UDP is frequently used in systems that need to communicate through
   Network Address Translation. Techniques such as STUN and TURN are used
   by some real-time communication architectures.

10. QUIC
    QUIC is an encrypted transport protocol implemented over UDP. It adds
    connection management, reliability mechanisms, streams, congestion
    control, and cryptographic protection at a higher protocol layer.

11. DTLS
    Datagram Transport Layer Security provides TLS-like security semantics
    for datagram-oriented communication.

12. DNSSEC
    DNSSEC adds cryptographic authentication of DNS data. It addresses data
    authenticity, not general confidentiality.

UDP therefore should not be understood as "unsafe TCP" or "TCP without a
handshake". It is a minimal transport service on which many different
application designs can be constructed.
"""
    )


# ---------------------------------------------------------------------------
# 23. TESTS
# ---------------------------------------------------------------------------

def run_self_tests() -> None:
    """Run deterministic unit-style checks."""
    print("\n" + "=" * 78)
    print("SELF TESTS")
    print("=" * 78)

    packet = SequencedPacket(123, b"hello")
    decoded = SequencedPacket.decode(packet.encode())

    assert decoded.sequence == 123
    assert decoded.payload == b"hello"

    reading = SensorReading("sensor-a", 9, 22.5, 1234.5)
    decoded_reading = SensorReading.from_bytes(reading.to_bytes())

    assert decoded_reading.sensor_id == "sensor-a"
    assert decoded_reading.sequence == 9
    assert decoded_reading.temperature_c == 22.5

    reliable = ReliableMessage(77, b"message")
    decoded_reliable = ReliableMessage.decode(reliable.encode())

    assert decoded_reliable.sequence == 77
    assert decoded_reliable.payload == b"message"

    ack = ack_packet(77)
    assert decode_ack(ack) == 77

    try:
        SequencedPacket.decode(b"short")
    except ValueError:
        pass
    else:
        raise AssertionError("short sequence packet was not rejected")

    try:
        validate_udp_application_message(b"[]")
    except ValueError:
        pass
    else:
        raise AssertionError("non-object message was not rejected")

    print("All deterministic self-tests passed.")


# ---------------------------------------------------------------------------
# 24. MAIN PROGRAM
# ---------------------------------------------------------------------------

def main() -> None:
    explain_fundamentals()
    explain_udp_header()
    demonstrate_addressing()
    demonstrate_basic_udp()
    demonstrate_datagram_boundaries()
    demonstrate_timeout()
    demonstrate_serialization()
    demonstrate_sequence_tracking()
    demonstrate_reliability_layer()
    demonstrate_dns_style()
    demonstrate_streaming_pattern()
    demonstrate_multicast_configuration()
    demonstrate_integrity()
    demonstrate_security_validation()
    demonstrate_encoding_vs_encryption()
    demonstrate_socket_options()
    explain_size_limits()
    compare_udp_tcp()
    demonstrate_loss_simulation()
    benchmark_local_udp(iterations=50)
    explain_advanced_concepts()
    production_checklist()
    run_self_tests()

    print("\n" + "=" * 78)
    print("END OF UDP STUDY PROGRAM")
    print("=" * 78)


if __name__ == "__main__":
    main()
