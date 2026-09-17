#!/usr/bin/env python3
"""
ICMP: Echo Request/Reply, Unreachable Messages, Traceroute, and Security
==========================================================================

This standalone study script progresses from the basic Internet Control
Message Protocol (ICMP) concepts to packet construction, checksum
calculation, parsing, simulated traceroute, unreachable-message analysis,
security considerations, and an optional live ICMP Echo test.

Important:
    ICMP is an IP-layer control protocol. It does not use TCP or UDP ports
    for its own transport. ICMP messages are carried directly inside IP.

The live ICMP example may require administrator/root privileges because raw
sockets are commonly restricted by operating systems.
"""

from __future__ import annotations

import ipaddress
import platform
import random
import socket
import struct
import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# 1. Fundamental terminology
# ---------------------------------------------------------------------------

def print_intro() -> None:
    print("=" * 78)
    print("ICMP STUDY: ECHO, UNREACHABLE, TRACEROUTE, AND SECURITY")
    print("=" * 78)
    print(
        """
ICMP stands for Internet Control Message Protocol.

ICMPv4 is defined primarily by RFC 792 and later updated by several RFCs.
ICMPv6 is a different protocol with a different message architecture.

ICMP is used by IP networks to communicate control and error information.
Examples include:

    Type 0  - Echo Reply
    Type 3  - Destination Unreachable
    Type 5  - Redirect
    Type 8  - Echo Request
    Type 11 - Time Exceeded
    Type 12 - Parameter Problem

A typical IPv4 ICMP packet has:

    IP header
        |
        +-- ICMP header
              |
              +-- ICMP-specific fields
              |
              +-- ICMP payload

The ICMP checksum covers the ICMP message, not the entire IPv4 packet.

Traceroute relies on TTL expiration. A packet is sent with a deliberately
small TTL. Each router decrements TTL. When TTL reaches zero, a router
normally discards the packet and sends ICMP Time Exceeded (Type 11).
"""
    )


# ---------------------------------------------------------------------------
# 2. ICMP message types
# ---------------------------------------------------------------------------

class ICMPType(IntEnum):
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT = 5
    ECHO_REQUEST = 8
    TIME_EXCEEDED = 11
    PARAMETER_PROBLEM = 12


class UnreachableCode(IntEnum):
    NETWORK_UNREACHABLE = 0
    HOST_UNREACHABLE = 1
    PROTOCOL_UNREACHABLE = 2
    PORT_UNREACHABLE = 3
    FRAGMENTATION_NEEDED = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    NETWORK_ADMIN_PROHIBITED = 9
    HOST_ADMIN_PROHIBITED = 10
    NETWORK_UNREACHABLE_TOS = 11
    HOST_UNREACHABLE_TOS = 12


ICMP_TYPE_NAMES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}


UNREACHABLE_CODE_NAMES = {
    0: "Network unreachable",
    1: "Host unreachable",
    2: "Protocol unreachable",
    3: "Port unreachable",
    4: "Fragmentation needed",
    5: "Source route failed",
    6: "Destination network unknown",
    7: "Destination host unknown",
    8: "Source host isolated",
    9: "Network administratively prohibited",
    10: "Host administratively prohibited",
    11: "Network unreachable for requested TOS",
    12: "Host unreachable for requested TOS",
}


def describe_type(message_type: int) -> str:
    return ICMP_TYPE_NAMES.get(message_type, f"Unknown ICMP type {message_type}")


def describe_unreachable_code(code: int) -> str:
    return UNREACHABLE_CODE_NAMES.get(code, f"Unknown unreachable code {code}")


# ---------------------------------------------------------------------------
# 3. Internet checksum
# ---------------------------------------------------------------------------

def internet_checksum(data: bytes) -> int:
    """
    Calculate the standard one's-complement Internet checksum.

    Algorithm:
        1. Treat the message as 16-bit words.
        2. Add the words using one's-complement arithmetic.
        3. Fold carries back into the low 16 bits.
        4. Complement the result.

    An odd number of bytes is padded with one zero byte for calculation.
    """
    if len(data) % 2:
        data += b"\x00"

    total = 0

    for offset in range(0, len(data), 2):
        word = (data[offset] << 8) | data[offset + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def demonstrate_checksum() -> None:
    print("\n--- Internet checksum ---")

    sample = b"ICMP checksum demonstration"
    checksum = internet_checksum(sample)

    print(f"Data: {sample!r}")
    print(f"Checksum: 0x{checksum:04x}")

    # A useful property of a valid one's-complement checksum is that
    # recomputing it over the data plus the checksum gives the expected
    # one's-complement validation result.
    packet = sample + struct.pack("!H", checksum)
    validation = internet_checksum(packet)
    print(f"Validation checksum: 0x{validation:04x}")


# ---------------------------------------------------------------------------
# 4. ICMP Echo Request and Echo Reply
# ---------------------------------------------------------------------------

@dataclass
class ICMPEcho:
    identifier: int
    sequence: int
    payload: bytes


def build_echo_request(identifier: int, sequence: int, payload: bytes) -> bytes:
    """
    Build an IPv4 ICMP Echo Request.

    ICMP Echo format:

        Type       1 byte
        Code       1 byte
        Checksum   2 bytes
        Identifier 2 bytes
        Sequence   2 bytes
        Data       variable

    For Echo Request:
        Type = 8
        Code = 0
    """
    if not 0 <= identifier <= 0xFFFF:
        raise ValueError("identifier must fit in 16 bits")

    if not 0 <= sequence <= 0xFFFF:
        raise ValueError("sequence must fit in 16 bits")

    header_without_checksum = struct.pack(
        "!BBHHH",
        ICMPType.ECHO_REQUEST,
        0,
        0,
        identifier,
        sequence,
    )

    checksum = internet_checksum(header_without_checksum + payload)

    header = struct.pack(
        "!BBHHH",
        ICMPType.ECHO_REQUEST,
        0,
        checksum,
        identifier,
        sequence,
    )

    return header + payload


def build_echo_reply(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build an ICMP Echo Reply using the same identifier and sequence."""
    header_without_checksum = struct.pack(
        "!BBHHH",
        ICMPType.ECHO_REPLY,
        0,
        0,
        identifier,
        sequence,
    )

    checksum = internet_checksum(header_without_checksum + payload)

    return struct.pack(
        "!BBHHH",
        ICMPType.ECHO_REPLY,
        0,
        checksum,
        identifier,
        sequence,
    ) + payload


def parse_echo_message(packet: bytes) -> ICMPEcho:
    """Parse either an Echo Request or Echo Reply ICMP message."""
    if len(packet) < 8:
        raise ValueError("ICMP packet is shorter than the 8-byte ICMP header")

    message_type, code, received_checksum, identifier, sequence = struct.unpack(
        "!BBHHH", packet[:8]
    )

    if message_type not in (
        ICMPType.ECHO_REQUEST,
        ICMPType.ECHO_REPLY,
    ):
        raise ValueError("packet is not an ICMP Echo message")

    if code != 0:
        raise ValueError("Echo Request/Reply must use ICMP code 0")

    payload = packet[8:]

    # Recalculate the checksum after replacing the checksum field with zero.
    zeroed = struct.pack(
        "!BBHHH",
        message_type,
        code,
        0,
        identifier,
        sequence,
    ) + payload

    calculated_checksum = internet_checksum(zeroed)

    if calculated_checksum != received_checksum:
        raise ValueError(
            f"invalid checksum: received 0x{received_checksum:04x}, "
            f"calculated 0x{calculated_checksum:04x}"
        )

    return ICMPEcho(identifier, sequence, payload)


def demonstrate_echo() -> None:
    print("\n--- ICMP Echo Request/Reply ---")

    payload = b"ICMP educational payload"
    request = build_echo_request(
        identifier=0x1234,
        sequence=1,
        payload=payload,
    )

    print(f"Echo Request length: {len(request)} bytes")
    print(f"Echo Request hex: {request.hex()}")

    parsed = parse_echo_message(request)
    print(f"Identifier: {parsed.identifier}")
    print(f"Sequence:   {parsed.sequence}")
    print(f"Payload:    {parsed.payload!r}")

    reply = build_echo_reply(
        identifier=parsed.identifier,
        sequence=parsed.sequence,
        payload=parsed.payload,
    )

    parsed_reply = parse_echo_message(reply)
    print(f"Echo Reply length: {len(reply)} bytes")
    print(f"Reply payload: {parsed_reply.payload!r}")


# ---------------------------------------------------------------------------
# 5. Edge cases in packet validation
# ---------------------------------------------------------------------------

def demonstrate_validation_edge_cases() -> None:
    print("\n--- Validation and edge cases ---")

    cases = [
        b"",
        b"\x08\x00",
        b"\x08\x00\x00\x00\x12\x34\x00\x01",
    ]

    for index, packet in enumerate(cases, start=1):
        try:
            parse_echo_message(packet)
            print(f"Case {index}: accepted")
        except ValueError as exc:
            print(f"Case {index}: rejected safely -> {exc}")

    valid = build_echo_request(1, 1, b"test")
    corrupted = bytearray(valid)
    corrupted[-1] ^= 0xFF

    try:
        parse_echo_message(bytes(corrupted))
    except ValueError as exc:
        print(f"Corrupted packet rejected -> {exc}")


# ---------------------------------------------------------------------------
# 6. Destination Unreachable messages
# ---------------------------------------------------------------------------

@dataclass
class DestinationUnreachable:
    code: int
    next_hop_mtu: int
    original_ip_data: bytes


def build_destination_unreachable(
    code: int,
    original_ip_data: bytes,
    next_hop_mtu: int = 0,
) -> bytes:
    """
    Build the IPv4 Destination Unreachable ICMP message.

    RFC-era IPv4 implementations commonly include:
        Type
        Code
        Checksum
        Unused / Next-Hop MTU
        Original IP header + initial transport bytes

    Code 4 uses the low 16 bits as Next-Hop MTU in the classic format.
    """
    if not 0 <= code <= 255:
        raise ValueError("ICMP code must fit in one byte")

    if not 0 <= next_hop_mtu <= 0xFFFF:
        raise ValueError("MTU must fit in 16 bits")

    if code != UnreachableCode.FRAGMENTATION_NEEDED:
        next_hop_mtu = 0

    fixed = struct.pack(
        "!BBHH",
        ICMPType.DESTINATION_UNREACHABLE,
        code,
        0,
        next_hop_mtu,
    )

    checksum = internet_checksum(fixed + original_ip_data)

    return struct.pack(
        "!BBHH",
        ICMPType.DESTINATION_UNREACHABLE,
        code,
        checksum,
        next_hop_mtu,
    ) + original_ip_data


def parse_destination_unreachable(packet: bytes) -> DestinationUnreachable:
    if len(packet) < 8:
        raise ValueError("Destination Unreachable packet is too short")

    message_type, code, received_checksum, _, next_hop_mtu = struct.unpack(
        "!BBHHH", packet[:8]
    )

    if message_type != ICMPType.DESTINATION_UNREACHABLE:
        raise ValueError("not an ICMP Destination Unreachable message")

    zeroed = struct.pack(
        "!BBHHH",
        message_type,
        code,
        0,
        0,
        next_hop_mtu,
    ) + packet[8:]

    if internet_checksum(zeroed) != received_checksum:
        raise ValueError("invalid Destination Unreachable checksum")

    return DestinationUnreachable(
        code=code,
        next_hop_mtu=next_hop_mtu,
        original_ip_data=packet[8:],
    )


def demonstrate_unreachable() -> None:
    print("\n--- Destination Unreachable ---")

    # In real traffic, the embedded data identifies the packet that
    # triggered the error. It is useful to transport-layer diagnostics.
    original_packet_context = (
        b"\x45\x00\x00\x3c"
        b"\x12\x34\x00\x00"
        b"\x40\x11\x00\x00"
        b"\xc0\xa8\x01\x64"
        b"\x08\x08\x08\x08"
        b"\x12\x34\x00\x35"
    )

    packet = build_destination_unreachable(
        code=UnreachableCode.PORT_UNREACHABLE,
        original_ip_data=original_packet_context,
    )

    parsed = parse_destination_unreachable(packet)

    print(f"Type: {ICMPType.DESTINATION_UNREACHABLE} "
          f"({describe_type(ICMPType.DESTINATION_UNREACHABLE)})")
    print(f"Code: {parsed.code} ({describe_unreachable_code(parsed.code)})")
    print(f"Embedded original data: {len(parsed.original_ip_data)} bytes")

    fragmentation_needed = build_destination_unreachable(
        code=UnreachableCode.FRAGMENTATION_NEEDED,
        original_ip_data=original_packet_context,
        next_hop_mtu=1400,
    )

    parsed_mtu = parse_destination_unreachable(fragmentation_needed)
    print(f"Fragmentation-needed Next-Hop MTU: {parsed_mtu.next_hop_mtu}")


# ---------------------------------------------------------------------------
# 7. ICMP Time Exceeded and traceroute
# ---------------------------------------------------------------------------

class ProbeResultType(IntEnum):
    TIME_EXCEEDED = 1
    ECHO_REPLY = 2
    DESTINATION_UNREACHABLE = 3
    TIMEOUT = 4


@dataclass
class TraceHop:
    ttl: int
    address: Optional[str]
    result: ProbeResultType
    rtt_ms: Optional[float]


def simulate_router_path() -> list[str]:
    """
    Produce a deterministic teaching path.

    A real Internet path changes with routing, load balancing, failures,
    policy, VPNs, and asymmetric routes. A deterministic simulation makes
    the educational output repeatable.
    """
    return [
        "192.168.1.1",
        "10.10.0.1",
        "172.16.4.1",
        "203.0.113.9",
        "198.51.100.20",
    ]


def simulate_traceroute(
    destination: str,
    path: Iterable[str],
    maximum_hops: int = 30,
) -> list[TraceHop]:
    """
    Model the core traceroute algorithm.

    Conceptually:

        TTL = 1 -> first router expires the packet
        TTL = 2 -> second router expires the packet
        TTL = 3 -> third router expires the packet
        ...
        TTL = N -> destination responds

    Real traceroute implementations vary:
        - classic UDP traceroute
        - ICMP Echo traceroute
        - TCP traceroute
        - platform-specific variants

    The response that identifies each hop is generally ICMP Time Exceeded.
    """
    if maximum_hops <= 0:
        raise ValueError("maximum_hops must be positive")

    ipaddress.ip_address(destination)
    path = list(path)

    results: list[TraceHop] = []

    for ttl in range(1, min(maximum_hops, len(path)) + 1):
        # Deterministic values make this a teaching model rather than
        # pretending these are measurements from the Internet.
        simulated_rtt = 1.5 + ttl * 2.25

        if ttl < len(path):
            results.append(
                TraceHop(
                    ttl=ttl,
                    address=path[ttl - 1],
                    result=ProbeResultType.TIME_EXCEEDED,
                    rtt_ms=simulated_rtt,
                )
            )
        else:
            results.append(
                TraceHop(
                    ttl=ttl,
                    address=destination,
                    result=ProbeResultType.ECHO_REPLY,
                    rtt_ms=simulated_rtt,
                )
            )
            break

    return results


def print_traceroute(results: list[TraceHop]) -> None:
    print("\n--- Simulated traceroute ---")

    for hop in results:
        if hop.address is None:
            address = "*"
        else:
            address = hop.address

        if hop.rtt_ms is None:
            rtt = "*"
        else:
            rtt = f"{hop.rtt_ms:.2f} ms"

        print(f"{hop.ttl:2d}  {address:15s}  {rtt:>10s}  "
              f"{hop.result.name}")


def explain_traceroute() -> None:
    print(
        """
Traceroute is not a separate network protocol.

It is a diagnostic technique that exploits the IPv4 TTL field.

Example:

    Probe 1: TTL=1
        Router A decrements TTL to zero.
        Router A discards the packet.
        Router A sends ICMP Time Exceeded.

    Probe 2: TTL=2
        Router A decrements TTL.
        Router B decrements TTL to zero.
        Router B sends ICMP Time Exceeded.

    Probe 3: TTL=3
        Router C may generate Time Exceeded.

When the destination is finally reached, its response identifies that the
probe reached the destination.

Asterisks in real traceroute output do not necessarily mean that a router
is broken. Firewalls, ACLs, rate limiting, control-plane policing, routing
behavior, and ICMP filtering can suppress responses.
"""
    )


# ---------------------------------------------------------------------------
# 8. Simulating packet filtering and security policy
# ---------------------------------------------------------------------------

@dataclass
class ICMPPolicy:
    allow_echo_request: bool = True
    allow_echo_reply: bool = True
    allow_time_exceeded: bool = True
    allow_destination_unreachable: bool = True
    rate_limit_per_second: int = 10


class ICMPSecurityPolicy:
    """
    A small policy engine showing how an enterprise firewall or host policy
    can distinguish message types.

    This does not modify the operating system firewall.
    """

    def __init__(self, policy: ICMPPolicy):
        self.policy = policy
        self._window_start = time.monotonic()
        self._window_count = 0

    def _rate_limit_allows(self) -> bool:
        now = time.monotonic()

        if now - self._window_start >= 1.0:
            self._window_start = now
            self._window_count = 0

        if self._window_count >= self.policy.rate_limit_per_second:
            return False

        self._window_count += 1
        return True

    def allows(self, message_type: int) -> bool:
        if not self._rate_limit_allows():
            return False

        if message_type == ICMPType.ECHO_REQUEST:
            return self.policy.allow_echo_request

        if message_type == ICMPType.ECHO_REPLY:
            return self.policy.allow_echo_reply

        if message_type == ICMPType.TIME_EXCEEDED:
            return self.policy.allow_time_exceeded

        if message_type == ICMPType.DESTINATION_UNREACHABLE:
            return self.policy.allow_destination_unreachable

        # Unknown or unsupported control messages are denied by this
        # deliberately conservative example policy.
        return False


def demonstrate_security_policy() -> None:
    print("\n--- ICMP security policy ---")

    policy = ICMPSecurityPolicy(
        ICMPPolicy(
            allow_echo_request=True,
            allow_echo_reply=True,
            allow_time_exceeded=True,
            allow_destination_unreachable=True,
            rate_limit_per_second=3,
        )
    )

    message_types = [
        ICMPType.ECHO_REQUEST,
        ICMPType.ECHO_REPLY,
        ICMPType.TIME_EXCEEDED,
        ICMPType.DESTINATION_UNREACHABLE,
    ]

    for message_type in message_types:
        print(
            f"{describe_type(message_type):32s} -> "
            f"{'allowed' if policy.allows(message_type) else 'blocked'}"
        )

    print(
        """
Security principle:

    "Allow all ICMP" and "block all ICMP" are both crude policies.

Operationally useful ICMP messages can support:
    - diagnostics
    - path discovery
    - routing troubleshooting
    - error reporting
    - IPv4 Path MTU Discovery

Blindly blocking all ICMP can cause legitimate networking failures.

Blindly permitting all ICMP traffic can increase exposure to:
    - reconnaissance
    - excessive control traffic
    - reflection/amplification scenarios involving applicable protocols
    - information leakage
    - denial-of-service attempts

A security policy should be based on message type, direction, context,
rate, source, destination, and the role of the system.
"""
    )


# ---------------------------------------------------------------------------
# 9. IP address and input validation
# ---------------------------------------------------------------------------

def validate_destination(value: str) -> str:
    """Validate a destination as an IPv4 or IPv6 literal."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value}") from exc

    return str(address)


def demonstrate_address_validation() -> None:
    print("\n--- Address validation ---")

    values = [
        "192.0.2.10",
        "2001:db8::10",
        "999.1.1.1",
        "not-an-address",
    ]

    for value in values:
        try:
            print(f"{value:20s} -> {validate_destination(value)}")
        except ValueError as exc:
            print(f"{value:20s} -> rejected ({exc})")


# ---------------------------------------------------------------------------
# 10. Optional live ICMP Echo
# ---------------------------------------------------------------------------

def live_icmp_echo(
    destination: str,
    timeout_seconds: float = 2.0,
    sequence: int = 1,
) -> Optional[float]:
    """
    Send one IPv4 ICMP Echo Request.

    Caveats:
        - Raw sockets may require administrator/root privileges.
        - Some operating systems provide special ping sockets.
        - Network firewalls may block Echo Request or Reply.
        - A successful packet exchange does not prove an application service
          is healthy.
        - This function intentionally performs only one controlled probe.

    The received IP packet normally contains an IPv4 header followed by
    the ICMP message, so the parser skips the IPv4 header according to its
    IHL field.
    """
    destination = validate_destination(destination)

    parsed_destination = ipaddress.ip_address(destination)
    if parsed_destination.version != 4:
        raise ValueError("this live demonstration supports IPv4 only")

    identifier = random.randint(0, 0xFFFF)
    payload = struct.pack("!d", time.time()) + b"ICMP-study"

    packet = build_echo_request(
        identifier=identifier,
        sequence=sequence,
        payload=payload,
    )

    protocol_icmp = socket.getprotobyname("icmp")

    start = time.perf_counter()

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            protocol_icmp,
        ) as sock:
            sock.settimeout(timeout_seconds)
            sock.sendto(packet, (destination, 0))

            while True:
                received, sender = sock.recvfrom(65535)

                if len(received) < 20:
                    continue

                version_and_ihl = received[0]
                version = version_and_ihl >> 4
                ihl_words = version_and_ihl & 0x0F

                if version != 4 or ihl_words < 5:
                    continue

                ip_header_length = ihl_words * 4

                if len(received) < ip_header_length + 8:
                    continue

                icmp_message = received[ip_header_length:]

                try:
                    parsed = parse_echo_message(icmp_message)
                except ValueError:
                    continue

                if parsed.identifier != identifier:
                    # The raw socket may receive unrelated ICMP traffic.
                    continue

                if parsed.sequence != sequence:
                    continue

                elapsed_ms = (time.perf_counter() - start) * 1000
                print(
                    f"ICMP Echo Reply from {sender[0]}: "
                    f"{elapsed_ms:.2f} ms"
                )
                return elapsed_ms

    except PermissionError:
        print(
            "Live ICMP test requires privileges that are not available "
            "to this process."
        )
    except OSError as exc:
        print(f"Live ICMP test failed at the socket layer: {exc}")

    return None


def explain_live_testing() -> None:
    print(
        """
Live test example:

    live_icmp_echo("192.0.2.1")

The address 192.0.2.0/24 is reserved for documentation and should not be
expected to provide a real Internet Echo Reply.

For a real controlled test, use a destination you are authorized to probe.

Do not interpret a timeout as proof that the destination is offline.
ICMP may be filtered while TCP or application traffic remains available.
"""
    )


# ---------------------------------------------------------------------------
# 11. ICMP error-message relationships
# ---------------------------------------------------------------------------

def demonstrate_error_relationships() -> None:
    print("\n--- ICMP error-message relationships ---")

    relationships = {
        "Echo Request": "The sender asks whether an IP endpoint can return an Echo Reply.",
        "Echo Reply": "The endpoint responds to a valid Echo Request.",
        "Destination Unreachable": "A router or host reports that delivery cannot proceed.",
        "Time Exceeded": "A router reports TTL expiration or another hop-limit-related condition.",
        "Redirect": "A router can advise a host about a more appropriate next hop in applicable IPv4 scenarios.",
        "Parameter Problem": "A receiver reports a problem interpreting an IP header field.",
    }

    for name, explanation in relationships.items():
        print(f"{name:28s}: {explanation}")


# ---------------------------------------------------------------------------
# 12. Advanced concepts
# ---------------------------------------------------------------------------

def advanced_concepts() -> None:
    print(
        """
--- Advanced ICMP concepts ---

1. ICMP is not reliable transport
   ICMP does not provide TCP-like delivery guarantees, ordering,
   retransmission, congestion control, or byte-stream semantics.

2. ICMP error messages quote the triggering packet
   IPv4 ICMP error messages include the original IP header and enough of the
   original packet to identify the flow in classic specifications.

3. Rate limiting matters
   Routers and hosts may rate-limit ICMP errors. Diagnostic output therefore
   represents observable behavior, not necessarily the complete routing state.

4. Asymmetric routing
   The forward path and return path may differ. An ICMP response source does
   not automatically describe every router on the reverse path.

5. Load balancing
   Per-flow or per-packet load balancing can produce apparently different
   traceroute paths.

6. Firewalls and ACLs
   A firewall may permit application traffic while suppressing ICMP, or
   permit selected ICMP types while denying others.

7. Path MTU Discovery
   IPv4 Path MTU Discovery historically depends on ICMP Destination
   Unreachable with Code 4 when fragmentation is needed and DF is set.
   Modern operational designs must account for filtering and PMTUD behavior.

8. IPv6 distinction
   IPv6 uses ICMPv6 rather than ICMPv4. ICMPv6 is integral to IPv6 operation
   and includes Neighbor Discovery and other functions. IPv6 also replaces
   the IPv4 TTL concept with Hop Limit.

9. Spoofing
   Source addresses in IP packets can be forged. An ICMP response should be
   interpreted in context and should not automatically be trusted as proof
   of identity.

10. Control-plane protection
    Network devices commonly protect their CPU/control plane from excessive
    ICMP and other control traffic using policing and filtering.

11. Application availability versus host reachability
    An Echo Reply demonstrates a response to ICMP. It does not demonstrate
    that HTTP, SSH, DNS, or another application is available.

12. Information exposure
    ICMP errors can reveal network topology, addressing information, or
    implementation behavior. This is one reason security architectures
    carefully control which messages are exposed externally.
"""
    )


# ---------------------------------------------------------------------------
# 13. Complexity and engineering considerations
# ---------------------------------------------------------------------------

def engineering_considerations() -> None:
    print(
        """
--- Engineering considerations ---

Packet construction:
    O(n) where n is the packet length because the checksum processes the
    packet bytes.

Packet parsing:
    O(n) in the worst case for checksum verification.

Traceroute:
    If H is the maximum TTL and P is the number of probes per hop,
    approximately O(H * P) probes are generated.

Memory:
    Packet parsing can be implemented with bounded buffers. Production
    network tools should never assume that received packets are well formed.

Reliability:
    Use timeouts, correlation identifiers, sequence numbers, and bounded
    retries.

Observability:
    Record timestamps, source addresses, ICMP type/code, interface context,
    and probe identity where appropriate.

Security:
    Validate packet lengths before unpacking fields.
    Never trust sender-provided lengths without bounds checking.
    Avoid unbounded retry loops.
    Rate-limit active probing.
    Restrict raw-socket privileges.
"""
    )


# ---------------------------------------------------------------------------
# 14. Small testing framework
# ---------------------------------------------------------------------------

def assert_equal(actual, expected, description: str) -> None:
    if actual != expected:
        raise AssertionError(
            f"{description}: expected {expected!r}, got {actual!r}"
        )


def run_tests() -> None:
    print("\n--- Self-tests ---")

    payload = b"hello"
    request = build_echo_request(10, 20, payload)
    parsed = parse_echo_message(request)

    assert_equal(parsed.identifier, 10, "Echo identifier")
    assert_equal(parsed.sequence, 20, "Echo sequence")
    assert_equal(parsed.payload, payload, "Echo payload")

    reply = build_echo_reply(10, 20, payload)
    parsed_reply = parse_echo_message(reply)
    assert_equal(parsed_reply.payload, payload, "Echo Reply payload")

    original = b"\x45\x00\x00\x20" + b"\x00" * 20

    unreachable = build_destination_unreachable(
        UnreachableCode.PORT_UNREACHABLE,
        original,
    )

    parsed_unreachable = parse_destination_unreachable(unreachable)
    assert_equal(
        parsed_unreachable.code,
        UnreachableCode.PORT_UNREACHABLE,
        "Unreachable code",
    )

    path = simulate_router_path()
    trace = simulate_traceroute("198.51.100.50", path)
    assert_equal(trace[-1].result, ProbeResultType.ECHO_REPLY, "Trace endpoint")

    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# 15. Main study flow
# ---------------------------------------------------------------------------

def main() -> None:
    print_intro()
    demonstrate_checksum()
    demonstrate_echo()
    demonstrate_validation_edge_cases()
    demonstrate_unreachable()
    explain_traceroute()

    path = simulate_router_path()
    results = simulate_traceroute(
        destination="198.51.100.50",
        path=path,
        maximum_hops=30,
    )
    print_traceroute(results)

    demonstrate_security_policy()
    demonstrate_address_validation()
    demonstrate_error_relationships()
    advanced_concepts()
    engineering_considerations()
    explain_live_testing()
    run_tests()

    print("\nStudy completed.")
    print(
        f"Python version: {platform.python_version()} | "
        f"Platform: {platform.system()}"
    )


if __name__ == "__main__":
    main()
