"""
TCP Fundamentals Study and Simulation
======================================

Topics covered:
- TCP purpose and transport-layer role
- TCP connections and reliable byte streams
- TCP three-way handshake
- TCP flags
- Sequence numbers
- Acknowledgment numbers
- Sliding windows
- Flow control
- Retransmission
- Timeouts and duplicate ACKs
- Cumulative acknowledgments
- Out-of-order data
- Duplicate segments
- Connection termination
- FIN/ACK behavior
- TCP state-machine concepts
- RTT and retransmission timeout
- Congestion-control distinction
- Security considerations
- Practical packet-level simulation

This file intentionally models TCP behavior without opening real sockets.
The goal is to make protocol mechanics visible and reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
import math
import random
import statistics
from typing import Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Fundamental terminology
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


print_section("1. TCP fundamentals")

print(
    """
TCP (Transmission Control Protocol) is a connection-oriented transport
protocol. It provides a reliable, ordered byte stream between two endpoints.

Important properties:
- Connection-oriented: endpoints establish state before normal data transfer.
- Reliable: lost data is detected and retransmitted.
- Ordered: the receiving application sees bytes in sequence.
- Byte-oriented: TCP sequence numbers identify byte positions, not packets.
- Full-duplex: both endpoints can send independently.
- Flow-controlled: a receiver advertises how much data it can accept.
- Stream-based: TCP does not preserve application message boundaries.

TCP itself does not guarantee:
- a fixed latency,
- delivery within a particular time,
- preservation of application message boundaries,
- immunity from congestion,
- encryption or confidentiality.

TLS is commonly layered above TCP when encryption and authentication are
required, as in HTTPS.
"""
)


# ---------------------------------------------------------------------------
# 2. TCP flags
# ---------------------------------------------------------------------------

class TCPFlag(Enum):
    FIN = auto()
    SYN = auto()
    RST = auto()
    PSH = auto()
    ACK = auto()
    URG = auto()
    ECE = auto()
    CWR = auto()
    NS = auto()


def format_flags(flags: Iterable[TCPFlag]) -> str:
    names = [flag.name for flag in flags]
    return ",".join(names) if names else "NONE"


print_section("2. TCP flags")

flag_meanings = {
    TCPFlag.SYN: "Synchronize sequence numbers and initiate a connection.",
    TCPFlag.ACK: "Indicate that the acknowledgment field is valid.",
    TCPFlag.FIN: "Request graceful termination of a byte stream.",
    TCPFlag.RST: "Immediately reset or reject a connection.",
    TCPFlag.PSH: "Request prompt delivery of buffered data to the application.",
    TCPFlag.URG: "Indicate urgent-pointer semantics.",
    TCPFlag.ECE: "Used with Explicit Congestion Notification.",
    TCPFlag.CWR: "Indicate congestion-window reduction in ECN operation.",
    TCPFlag.NS: "Historical/extended ECN-related flag semantics.",
}

for flag, meaning in flag_meanings.items():
    print(f"{flag.name:4} -> {meaning}")


# ---------------------------------------------------------------------------
# 3. TCP segments
# ---------------------------------------------------------------------------

@dataclass
class TCPSegment:
    source: str
    destination: str
    sequence_number: int
    acknowledgment_number: Optional[int] = None
    flags: Tuple[TCPFlag, ...] = ()
    payload: bytes = b""
    advertised_window: int = 65535

    @property
    def payload_length(self) -> int:
        return len(self.payload)

    @property
    def sequence_space_consumed(self) -> int:
        """
        SYN and FIN each consume one sequence-number position.
        Payload consumes one position per byte.
        ACK itself does not consume sequence-number space.
        """
        consumed = len(self.payload)
        if TCPFlag.SYN in self.flags:
            consumed += 1
        if TCPFlag.FIN in self.flags:
            consumed += 1
        return consumed

    def describe(self) -> str:
        ack = (
            str(self.acknowledgment_number)
            if self.acknowledgment_number is not None
            else "-"
        )
        return (
            f"{self.source} -> {self.destination} | "
            f"SEQ={self.sequence_number} ACK={ack} "
            f"FLAGS={format_flags(self.flags)} "
            f"PAYLOAD={self.payload_length} "
            f"WINDOW={self.advertised_window}"
        )


# ---------------------------------------------------------------------------
# 4. Three-way handshake
# ---------------------------------------------------------------------------

@dataclass
class TCPConnectionState:
    client_isn: int
    server_isn: int
    client_next_sequence: int = 0
    server_next_sequence: int = 0


def simulate_three_way_handshake(
    client_isn: int = 1000,
    server_isn: int = 5000,
) -> List[TCPSegment]:
    """
    Demonstrate the classic TCP three-way handshake.

    Step 1:
        Client -> Server: SYN, SEQ=client_isn

    Step 2:
        Server -> Client: SYN+ACK, SEQ=server_isn, ACK=client_isn+1

    Step 3:
        Client -> Server: ACK, SEQ=client_isn+1, ACK=server_isn+1

    SYN consumes one sequence-number position.
    """

    client = "CLIENT"
    server = "SERVER"

    syn = TCPSegment(
        source=client,
        destination=server,
        sequence_number=client_isn,
        flags=(TCPFlag.SYN,),
    )

    syn_ack = TCPSegment(
        source=server,
        destination=client,
        sequence_number=server_isn,
        acknowledgment_number=client_isn + 1,
        flags=(TCPFlag.SYN, TCPFlag.ACK),
    )

    ack = TCPSegment(
        source=client,
        destination=server,
        sequence_number=client_isn + 1,
        acknowledgment_number=server_isn + 1,
        flags=(TCPFlag.ACK,),
    )

    return [syn, syn_ack, ack]


print_section("3. TCP three-way handshake")

for number, segment in enumerate(simulate_three_way_handshake(), start=1):
    print(f"Step {number}: {segment.describe()}")

print(
    """
Why three messages?

The endpoints need to establish sequence-number state in both directions.
The server must learn the client's initial sequence number, while the client
must learn the server's initial sequence number.

The third ACK confirms that the client received the server's SYN.

A simplified state progression is:

Client:
CLOSED -> SYN-SENT -> ESTABLISHED

Server:
LISTEN -> SYN-RECEIVED -> ESTABLISHED
"""
)


# ---------------------------------------------------------------------------
# 5. Sequence numbers
# ---------------------------------------------------------------------------

print_section("4. Sequence numbers")

print(
    """
TCP sequence numbers identify positions in a byte stream.

Suppose the first usable data byte has sequence number 1001.
A segment carrying 500 bytes occupies:

1001 through 1500

The next byte expected is:

1501

Therefore an acknowledgment of 1501 means:

"I have received every byte through 1500 and I am waiting for byte 1501."

This is a cumulative acknowledgment model.
"""
)

first_data_sequence = 1001
payload = b"A" * 500
next_byte = first_data_sequence + len(payload)

print(f"First data byte: {first_data_sequence}")
print(f"Payload length:  {len(payload)}")
print(f"Next byte:       {next_byte}")
print(f"Cumulative ACK:  {next_byte}")


# ---------------------------------------------------------------------------
# 6. Acknowledgment calculations
# ---------------------------------------------------------------------------

def acknowledgment_after_segment(segment: TCPSegment) -> int:
    """
    Return the next sequence number expected after a segment.

    This is useful for understanding why SYN and FIN advance sequence space.
    """
    return segment.sequence_number + segment.sequence_space_consumed


print_section("5. ACK calculation")

examples = [
    TCPSegment(
        "A",
        "B",
        sequence_number=100,
        flags=(TCPFlag.SYN,),
    ),
    TCPSegment(
        "A",
        "B",
        sequence_number=101,
        acknowledgment_number=900,
        flags=(TCPFlag.ACK,),
        payload=b"hello",
    ),
    TCPSegment(
        "A",
        "B",
        sequence_number=106,
        acknowledgment_number=900,
        flags=(TCPFlag.FIN, TCPFlag.ACK),
    ),
]

for segment in examples:
    print(segment.describe())
    print("Next sequence position:", acknowledgment_after_segment(segment))


# ---------------------------------------------------------------------------
# 7. Sliding window and flow control
# ---------------------------------------------------------------------------

@dataclass
class ReceiveWindow:
    capacity: int
    buffered: int = 0

    @property
    def advertised_window(self) -> int:
        return max(0, self.capacity - self.buffered)

    def receive(self, byte_count: int) -> bool:
        if byte_count < 0:
            raise ValueError("byte_count cannot be negative")

        if byte_count > self.advertised_window:
            return False

        self.buffered += byte_count
        return True

    def application_consumes(self, byte_count: int) -> None:
        if byte_count < 0:
            raise ValueError("byte_count cannot be negative")

        self.buffered = max(0, self.buffered - byte_count)


print_section("6. Receive window and flow control")

receiver = ReceiveWindow(capacity=10_000)

print("Initial advertised window:", receiver.advertised_window)

for amount in (2_000, 3_000, 4_000):
    accepted = receiver.receive(amount)
    print(
        f"Received {amount:>5} bytes | "
        f"accepted={accepted} | "
        f"window={receiver.advertised_window}"
    )

receiver.application_consumes(5_000)
print("Application consumed 5,000 bytes.")
print("Advertised window:", receiver.advertised_window)

accepted = receiver.receive(7_000)
print("Attempt to receive 7,000 bytes:", accepted)
print("Advertised window:", receiver.advertised_window)

print(
    """
Flow control prevents a fast sender from overwhelming a slower receiver.

The receive window is different from the congestion window.

Receive window:
    Protects the receiver.

Congestion window:
    Controls how much data the sender puts into the network based on
    congestion-control behavior.

The effective amount a sender can have outstanding is constrained by both.
A simplified conceptual expression is:

    usable_send_window = min(receive_window, congestion_window)
"""
)


# ---------------------------------------------------------------------------
# 8. Sender-side outstanding data
# ---------------------------------------------------------------------------

@dataclass
class TCPSender:
    initial_sequence: int
    next_sequence: int
    oldest_unacknowledged: int
    receive_window: int
    congestion_window: int
    unacknowledged: Dict[int, bytes] = field(default_factory=dict)

    @property
    def effective_window(self) -> int:
        return min(self.receive_window, self.congestion_window)

    @property
    def bytes_in_flight(self) -> int:
        return self.next_sequence - self.oldest_unacknowledged

    @property
    def available_send_capacity(self) -> int:
        return max(0, self.effective_window - self.bytes_in_flight)

    def send(self, payload: bytes) -> TCPSegment:
        if not payload:
            raise ValueError("TCP data segment cannot be empty in this simulation")

        allowed = self.available_send_capacity

        if allowed <= 0:
            raise BufferError("Send window is full")

        actual_payload = payload[:allowed]

        segment = TCPSegment(
            source="SENDER",
            destination="RECEIVER",
            sequence_number=self.next_sequence,
            acknowledgment_number=None,
            flags=(TCPFlag.ACK,),
            payload=actual_payload,
            advertised_window=self.receive_window,
        )

        self.unacknowledged[self.next_sequence] = actual_payload
        self.next_sequence += len(actual_payload)

        return segment

    def acknowledge(self, acknowledgment_number: int) -> int:
        """
        Apply a cumulative ACK.

        Returns the number of newly acknowledged bytes.
        """
        if acknowledgment_number < self.oldest_unacknowledged:
            return 0

        if acknowledgment_number > self.next_sequence:
            raise ValueError(
                "ACK cannot acknowledge bytes that the sender has not sent"
            )

        old = self.oldest_unacknowledged
        self.oldest_unacknowledged = acknowledgment_number

        acknowledged_keys = [
            sequence
            for sequence, payload in self.unacknowledged.items()
            if sequence + len(payload) <= acknowledgment_number
        ]

        for sequence in acknowledged_keys:
            del self.unacknowledged[sequence]

        return acknowledgment_number - old


print_section("7. Sliding-window sender")

sender = TCPSender(
    initial_sequence=10_000,
    next_sequence=10_000,
    oldest_unacknowledged=10_000,
    receive_window=4_000,
    congestion_window=3_000,
)

print("Effective window:", sender.effective_window)

segment1 = sender.send(b"A" * 2_000)
print(segment1.describe())
print("Bytes in flight:", sender.bytes_in_flight)
print("Available capacity:", sender.available_send_capacity)

segment2 = sender.send(b"B" * 1_000)
print(segment2.describe())
print("Bytes in flight:", sender.bytes_in_flight)
print("Available capacity:", sender.available_send_capacity)

acknowledged = sender.acknowledge(13_000)
print("ACK 13000 acknowledged bytes:", acknowledged)
print("Bytes in flight:", sender.bytes_in_flight)


# ---------------------------------------------------------------------------
# 9. Out-of-order segments
# ---------------------------------------------------------------------------

@dataclass
class TCPReceiver:
    next_expected: int
    receive_buffer: Dict[int, bytes] = field(default_factory=dict)

    def receive_segment(self, segment: TCPSegment) -> int:
        """
        Process a segment and return the cumulative ACK number.

        This model buffers future data but does not implement every detail
        of a production TCP stack.
        """
        if segment.payload_length == 0:
            return self.next_expected

        sequence = segment.sequence_number

        if sequence == self.next_expected:
            self.next_expected += len(segment.payload)

            # Deliver contiguous buffered segments.
            while self.next_expected in self.receive_buffer:
                buffered_payload = self.receive_buffer.pop(self.next_expected)
                self.next_expected += len(buffered_payload)

        elif sequence > self.next_expected:
            # Future data is out of order.
            self.receive_buffer.setdefault(sequence, segment.payload)

        else:
            # Segment begins before the current ACK point.
            # This may be a duplicate or partially overlapping segment.
            pass

        return self.next_expected


print_section("8. Out-of-order delivery")

receiver = TCPReceiver(next_expected=1_000)

segment_a = TCPSegment(
    "SENDER",
    "RECEIVER",
    sequence_number=1_000,
    flags=(TCPFlag.ACK,),
    payload=b"A" * 500,
)

segment_b = TCPSegment(
    "SENDER",
    "RECEIVER",
    sequence_number=2_000,
    flags=(TCPFlag.ACK,),
    payload=b"C" * 500,
)

segment_c = TCPSegment(
    "SENDER",
    "RECEIVER",
    sequence_number=1_500,
    flags=(TCPFlag.ACK,),
    payload=b"B" * 500,
)

print("ACK after segment A:", receiver.receive_segment(segment_a))
print("ACK after segment C:", receiver.receive_segment(segment_c))
print("ACK after segment B:", receiver.receive_segment(segment_b))

print(
    """
When a segment arrives beyond the next expected byte, the receiver may retain
it while waiting for the missing bytes.

Example:

Expected: 1000
Received: 1000-1499 -> ACK 1500
Received: 2000-2499 -> still ACK 1500
Received: 1500-1999 -> ACK can advance to 2500

The exact behavior of modern TCP implementations includes additional mechanisms
such as selective acknowledgments (SACK), which allow the sender to learn more
precisely which ranges have already arrived.
"""
)


# ---------------------------------------------------------------------------
# 10. Retransmission timeout
# ---------------------------------------------------------------------------

@dataclass
class RTTTracker:
    smoothed_rtt: Optional[float] = None
    rtt_variation: Optional[float] = None
    retransmission_timeout: Optional[float] = None

    def update(self, measured_rtt: float) -> None:
        if measured_rtt <= 0:
            raise ValueError("RTT must be positive")

        # These constants illustrate the standard exponential-smoothing idea.
        alpha = 1 / 8
        beta = 1 / 4

        if self.smoothed_rtt is None:
            self.smoothed_rtt = measured_rtt
            self.rtt_variation = measured_rtt / 2
        else:
            assert self.rtt_variation is not None

            self.rtt_variation = (
                (1 - beta) * self.rtt_variation
                + beta * abs(self.smoothed_rtt - measured_rtt)
            )

            self.smoothed_rtt = (
                (1 - alpha) * self.smoothed_rtt
                + alpha * measured_rtt
            )

        assert self.rtt_variation is not None
        self.retransmission_timeout = (
            self.smoothed_rtt + 4 * self.rtt_variation
        )


print_section("9. RTT and retransmission timeout")

rtt_tracker = RTTTracker()

for measured in [0.080, 0.095, 0.090, 0.110, 0.085]:
    rtt_tracker.update(measured)
    print(
        f"Measured RTT={measured:.3f}s | "
        f"SRTT={rtt_tracker.smoothed_rtt:.3f}s | "
        f"RTTVAR={rtt_tracker.rtt_variation:.3f}s | "
        f"RTO={rtt_tracker.retransmission_timeout:.3f}s"
    )

print(
    """
A retransmission timeout cannot simply be fixed to one universal value.

Network delay changes because of:
- distance,
- routing,
- queueing,
- congestion,
- wireless conditions,
- server load,
- operating-system scheduling.

TCP estimates RTT and uses it to derive a retransmission timeout.

A simplified conceptual relationship is:

    RTO = SRTT + 4 * RTTVAR

Real TCP implementations apply additional rules, bounds, and timer behavior.
"""
)


# ---------------------------------------------------------------------------
# 11. Retransmission simulation
# ---------------------------------------------------------------------------

@dataclass
class ReliableSender:
    next_sequence: int
    outstanding: Dict[int, Tuple[bytes, float]] = field(default_factory=dict)
    retransmissions: int = 0

    def transmit(self, payload: bytes, current_time: float) -> TCPSegment:
        sequence = self.next_sequence
        self.next_sequence += len(payload)

        self.outstanding[sequence] = (payload, current_time)

        return TCPSegment(
            source="SENDER",
            destination="RECEIVER",
            sequence_number=sequence,
            flags=(TCPFlag.ACK,),
            payload=payload,
        )

    def check_timeout(
        self,
        current_time: float,
        rto: float,
    ) -> List[TCPSegment]:
        retransmitted = []

        for sequence, (payload, sent_time) in list(self.outstanding.items()):
            if current_time - sent_time >= rto:
                self.retransmissions += 1
                self.outstanding[sequence] = (payload, current_time)

                retransmitted.append(
                    TCPSegment(
                        source="SENDER",
                        destination="RECEIVER",
                        sequence_number=sequence,
                        flags=(TCPFlag.ACK,),
                        payload=payload,
                    )
                )

        return retransmitted

    def acknowledge(self, acknowledgment_number: int) -> None:
        completed = [
            sequence
            for sequence, (payload, _) in self.outstanding.items()
            if sequence + len(payload) <= acknowledgment_number
        ]

        for sequence in completed:
            del self.outstanding[sequence]


print_section("10. Retransmission after timeout")

reliable_sender = ReliableSender(next_sequence=5_000)
first = reliable_sender.transmit(b"important-data", current_time=0.0)

print("Original:", first.describe())

rto = 0.200
retransmissions = reliable_sender.check_timeout(0.250, rto)

for segment in retransmissions:
    print("Retransmitted:", segment.describe())

print("Retransmission count:", reliable_sender.retransmissions)

reliable_sender.acknowledge(5_000 + len(b"important-data"))
print("Outstanding data:", reliable_sender.outstanding)


# ---------------------------------------------------------------------------
# 12. Duplicate ACKs and fast retransmission
# ---------------------------------------------------------------------------

@dataclass
class DuplicateAckDetector:
    last_ack: Optional[int] = None
    duplicate_count: int = 0

    def observe_ack(self, acknowledgment_number: int) -> bool:
        """
        Return True after three duplicate ACKs for the same ACK number.

        This illustrates the classic fast-retransmit trigger.
        Modern TCP congestion-control behavior is more sophisticated.
        """
        if self.last_ack is None:
            self.last_ack = acknowledgment_number
            self.duplicate_count = 0
            return False

        if acknowledgment_number == self.last_ack:
            self.duplicate_count += 1
        elif acknowledgment_number > self.last_ack:
            self.last_ack = acknowledgment_number
            self.duplicate_count = 0
        else:
            # Older ACKs are ignored by this simplified detector.
            return False

        return self.duplicate_count >= 3


print_section("11. Duplicate ACKs and fast retransmission")

detector = DuplicateAckDetector()

for ack_number in [4_000, 4_000, 4_000, 4_000, 4_500]:
    fast_retransmit = detector.observe_ack(ack_number)
    print(
        f"ACK={ack_number} | duplicate_count={detector.duplicate_count} | "
        f"fast_retransmit={fast_retransmit}"
    )

print(
    """
Duplicate ACKs can provide evidence that a segment is missing while later
data is arriving.

A classic mechanism is:

    missing segment
          |
          v
    later segments arrive
          |
          v
    receiver repeatedly acknowledges missing byte
          |
          v
    sender sees repeated duplicate ACKs
          |
          v
    fast retransmission

This can detect loss sooner than waiting for the retransmission timer.

The exact algorithms used by modern TCP stacks depend on the selected
congestion-control and loss-recovery mechanisms.
"""
)


# ---------------------------------------------------------------------------
# 13. Congestion-control distinction
# ---------------------------------------------------------------------------

print_section("12. Flow control versus congestion control")

comparison = [
    ("Flow control", "Receiver", "Prevent receiver buffer overflow"),
    ("Congestion control", "Network", "Reduce overload and adapt sending rate"),
    ("Retransmission", "Sender/reliability", "Recover from detected loss"),
    ("Acknowledgment", "Receiver feedback", "Report received byte position"),
]

for mechanism, target, purpose in comparison:
    print(f"{mechanism:20} | {target:20} | {purpose}")


# ---------------------------------------------------------------------------
# 14. TCP connection termination
# ---------------------------------------------------------------------------

def simulate_four_step_close(
    client_sequence: int = 7_000,
    server_sequence: int = 9_000,
) -> List[TCPSegment]:
    """
    Illustrate the common four-segment graceful shutdown.

    FIN consumes one sequence-number position.
    """
    return [
        TCPSegment(
            "CLIENT",
            "SERVER",
            sequence_number=client_sequence,
            acknowledgment_number=server_sequence,
            flags=(TCPFlag.FIN, TCPFlag.ACK),
        ),
        TCPSegment(
            "SERVER",
            "CLIENT",
            sequence_number=server_sequence,
            acknowledgment_number=client_sequence + 1,
            flags=(TCPFlag.ACK,),
        ),
        TCPSegment(
            "SERVER",
            "CLIENT",
            sequence_number=server_sequence,
            acknowledgment_number=client_sequence + 1,
            flags=(TCPFlag.FIN, TCPFlag.ACK),
        ),
        TCPSegment(
            "CLIENT",
            "SERVER",
            sequence_number=client_sequence + 1,
            acknowledgment_number=server_sequence + 1,
            flags=(TCPFlag.ACK,),
        ),
    ]


print_section("13. Graceful connection termination")

for number, segment in enumerate(simulate_four_step_close(), start=1):
    print(f"Step {number}: {segment.describe()}")

print(
    """
TCP is full-duplex, so each direction has an independent byte stream.

A FIN says that an endpoint has no more data to send in that direction.
The peer can acknowledge the FIN and may still send data before sending its
own FIN.

This is why graceful shutdown commonly takes four segments.
Some packets can be combined, so real traces may look different.
"""
)


# ---------------------------------------------------------------------------
# 15. Simplified TCP state machine
# ---------------------------------------------------------------------------

class TCPState(Enum):
    CLOSED = auto()
    LISTEN = auto()
    SYN_SENT = auto()
    SYN_RECEIVED = auto()
    ESTABLISHED = auto()
    FIN_WAIT_1 = auto()
    FIN_WAIT_2 = auto()
    CLOSE_WAIT = auto()
    LAST_ACK = auto()
    CLOSING = auto()
    TIME_WAIT = auto()


print_section("14. TCP connection states")

state_transitions = {
    "active open + SYN": (TCPState.CLOSED, TCPState.SYN_SENT),
    "SYN received": (TCPState.LISTEN, TCPState.SYN_RECEIVED),
    "handshake completed": (TCPState.SYN_SENT, TCPState.ESTABLISHED),
    "application closes local send side": (
        TCPState.ESTABLISHED,
        TCPState.FIN_WAIT_1,
    ),
    "FIN acknowledged": (
        TCPState.FIN_WAIT_1,
        TCPState.FIN_WAIT_2,
    ),
    "peer FIN received": (
        TCPState.FIN_WAIT_2,
        TCPState.TIME_WAIT,
    ),
}

for event, (old, new) in state_transitions.items():
    print(f"{old.name:15} -- {event} --> {new.name}")


# ---------------------------------------------------------------------------
# 16. MSS and segmentation
# ---------------------------------------------------------------------------

print_section("15. MSS and segmentation")

def segment_application_data(
    data: bytes,
    initial_sequence: int,
    mss: int,
) -> List[TCPSegment]:
    if mss <= 0:
        raise ValueError("MSS must be positive")

    segments = []

    for offset in range(0, len(data), mss):
        chunk = data[offset:offset + mss]
        segments.append(
            TCPSegment(
                source="SENDER",
                destination="RECEIVER",
                sequence_number=initial_sequence + offset,
                flags=(TCPFlag.ACK,),
                payload=chunk,
            )
        )

    return segments


application_data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
segments = segment_application_data(
    application_data,
    initial_sequence=20_000,
    mss=8,
)

for segment in segments:
    print(segment.describe())

print(
    """
MSS means Maximum Segment Size and refers to the amount of TCP payload that
can be carried in one segment under the negotiated conditions.

MSS is not the same thing as the IP packet's total size.

A simplified relationship is:

    IP packet size = IP headers + TCP headers + TCP payload

The exact maximum packet size also depends on path MTU and other mechanisms.
"""
)


# ---------------------------------------------------------------------------
# 17. Sequence wrap-around
# ---------------------------------------------------------------------------

print_section("16. Sequence-number wrap-around")

MAX_SEQUENCE_SPACE = 2 ** 32


def add_sequence_number(sequence: int, amount: int) -> int:
    return (sequence + amount) % MAX_SEQUENCE_SPACE


near_end = MAX_SEQUENCE_SPACE - 3

for amount in range(5):
    print(
        f"SEQ={near_end + amount if amount < 3 else 'wrapped'} "
        f"-> {add_sequence_number(near_end, amount)}"
    )

print(
    """
Classic TCP sequence numbers use a 32-bit sequence space.

Therefore:

    2^32 = 4,294,967,296

After reaching the end of the sequence space, numbering wraps around.

TCP sequence-number comparisons cannot always be implemented as ordinary
integer comparisons because the sequence space is circular.

Production implementations use serial-number arithmetic rules and also use
mechanisms such as timestamps to make old duplicate segments easier to
distinguish from current traffic.
"""
)


# ---------------------------------------------------------------------------
# 18. Three-way handshake with random ISNs
# ---------------------------------------------------------------------------

print_section("17. Randomized initial sequence numbers")

random_generator = random.Random(42)

client_isn = random_generator.randrange(0, MAX_SEQUENCE_SPACE)
server_isn = random_generator.randrange(0, MAX_SEQUENCE_SPACE)

for segment in simulate_three_way_handshake(client_isn, server_isn):
    print(segment.describe())

print(
    """
Modern TCP implementations select initial sequence numbers using mechanisms
intended to make them difficult to predict.

Predictable sequence numbers can make certain spoofing attacks easier.

Randomization alone does not authenticate a TCP peer.
TCP by itself does not provide cryptographic identity verification.
"""
)


# ---------------------------------------------------------------------------
# 19. Edge cases
# ---------------------------------------------------------------------------

print_section("18. Edge cases and validation")

edge_cases = [
    ("Empty payload", b""),
    ("One byte", b"X"),
    ("Large payload", b"X" * 10_000),
]

for name, data in edge_cases:
    result = segment_application_data(
        data,
        initial_sequence=30_000,
        mss=1_024,
    )
    print(f"{name:20} -> {len(result)} TCP data segments")

try:
    segment_application_data(b"data", 100, 0)
except ValueError as error:
    print("Invalid MSS:", error)

try:
    sender.acknowledge(sender.next_sequence + 1)
except ValueError as error:
    print("Invalid ACK:", error)

try:
    receiver.receive_segment(
        TCPSegment(
            "SENDER",
            "RECEIVER",
            sequence_number=1,
            payload=b"",
        )
    )
    print("Zero-length data segment handled safely.")
except Exception as error:
    print("Unexpected error:", error)


# ---------------------------------------------------------------------------
# 20. Packet-loss simulation
# ---------------------------------------------------------------------------

@dataclass
class TransmissionResult:
    delivered: int
    lost: int
    retransmitted: int
    total_attempts: int


def simulate_lossy_network(
    packet_count: int,
    loss_probability: float,
    seed: int = 123,
) -> TransmissionResult:
    if packet_count < 0:
        raise ValueError("packet_count cannot be negative")

    if not 0 <= loss_probability <= 1:
        raise ValueError("loss_probability must be between 0 and 1")

    rng = random.Random(seed)

    delivered = 0
    lost = 0
    retransmitted = 0

    for _ in range(packet_count):
        if rng.random() < loss_probability:
            lost += 1

            # Simplified recovery: retransmit once.
            retransmitted += 1

            if rng.random() >= loss_probability:
                delivered += 1
        else:
            delivered += 1

    return TransmissionResult(
        delivered=delivered,
        lost=lost,
        retransmitted=retransmitted,
        total_attempts=packet_count + retransmitted,
    )


print_section("19. Packet-loss simulation")

result = simulate_lossy_network(
    packet_count=1_000,
    loss_probability=0.05,
)

print(result)

print(
    """
This simulation intentionally simplifies real TCP.

Real TCP does not simply retransmit every packet once after random loss.
It combines:
- retransmission timers,
- duplicate ACK behavior,
- selective acknowledgments where negotiated,
- congestion control,
- retransmission backoff,
- sequence-number tracking,
- receive buffering,
- sender state.

The simulation is useful because it isolates the reliability concept.
"""
)


# ---------------------------------------------------------------------------
# 21. RTT statistics
# ---------------------------------------------------------------------------

print_section("20. RTT statistics")

rtt_samples = [82, 90, 87, 95, 91, 110, 85, 88]

print("Samples in milliseconds:", rtt_samples)
print("Minimum:", min(rtt_samples))
print("Maximum:", max(rtt_samples))
print("Mean:", round(statistics.mean(rtt_samples), 2))
print("Median:", statistics.median(rtt_samples))
print("Population standard deviation:", round(statistics.pstdev(rtt_samples), 2))

print(
    """
RTT measurements vary over time. A TCP implementation therefore benefits from
smoothing rather than treating one sample as a permanent network property.

A sudden high RTT can indicate queueing or congestion, but RTT alone does not
prove that packets were lost.
"""
)


# ---------------------------------------------------------------------------
# 22. A compact end-to-end TCP transfer simulation
# ---------------------------------------------------------------------------

@dataclass
class TCPTransferSimulation:
    sender_sequence: int
    receiver_sequence: int
    mss: int
    receive_window: int
    delivered_data: bytearray = field(default_factory=bytearray)
    pending: Dict[int, bytes] = field(default_factory=dict)

    def make_segments(self, data: bytes) -> List[TCPSegment]:
        return segment_application_data(
            data,
            self.sender_sequence,
            self.mss,
        )

    def process(self, segment: TCPSegment) -> int:
        if segment.sequence_number == self.receiver_sequence:
            self.delivered_data.extend(segment.payload)
            self.receiver_sequence += len(segment.payload)

            while self.receiver_sequence in self.pending:
                payload = self.pending.pop(self.receiver_sequence)
                self.delivered_data.extend(payload)
                self.receiver_sequence += len(payload)

        elif segment.sequence_number > self.receiver_sequence:
            self.pending.setdefault(
                segment.sequence_number,
                segment.payload,
            )

        return self.receiver_sequence


print_section("21. End-to-end ordered byte-stream simulation")

transfer = TCPTransferSimulation(
    sender_sequence=40_000,
    receiver_sequence=40_000,
    mss=5,
    receive_window=20,
)

data = b"TCP reliability"
segments = transfer.make_segments(data)

# Deliberately deliver the middle segment first when possible.
delivery_order = list(segments)

if len(delivery_order) >= 3:
    delivery_order[1], delivery_order[2] = (
        delivery_order[2],
        delivery_order[1],
    )

for segment in delivery_order:
    ack = transfer.process(segment)
    print(
        f"Received SEQ={segment.sequence_number:<5} "
        f"length={segment.payload_length:<2} "
        f"cumulative ACK={ack}"
    )

print("Delivered bytes:", bytes(transfer.delivered_data))
print("Expected bytes: ", data)


# ---------------------------------------------------------------------------
# 23. Security considerations
# ---------------------------------------------------------------------------

print_section("22. Security considerations")

security_points = [
    "TCP does not encrypt payloads.",
    "TCP does not inherently authenticate the application peer.",
    "RST injection can disrupt connections if an attacker can construct valid-looking traffic.",
    "SYN floods exploit server resources consumed by incomplete connection establishment.",
    "IP spoofing can make source addresses unreliable as an identity mechanism.",
    "Sequence-number unpredictability reduces some spoofing risks but is not authentication.",
    "TLS should be used when confidentiality and authenticated communication are required.",
    "Firewalls and operating systems can enforce connection and rate limits.",
]

for point in security_points:
    print("-", point)


# ---------------------------------------------------------------------------
# 24. Debugging methodology
# ---------------------------------------------------------------------------

print_section("23. Packet-level debugging checklist")

debugging_checklist = [
    "Identify the client and server addresses and ports.",
    "Find the initial SYN.",
    "Verify the SYN-ACK acknowledges client ISN + 1.",
    "Verify the final ACK acknowledges server ISN + 1.",
    "Track SEQ and ACK values separately in both directions.",
    "Check advertised receive-window changes.",
    "Identify retransmissions by repeated sequence ranges.",
    "Look for duplicate ACKs.",
    "Check whether segments arrive out of order.",
    "Measure RTT from suitable packet pairs.",
    "Distinguish receiver-window limitation from congestion behavior.",
    "Inspect FIN/RST packets when a connection closes unexpectedly.",
]

for index, item in enumerate(debugging_checklist, start=1):
    print(f"{index:2}. {item}")


# ---------------------------------------------------------------------------
# 25. Common mistakes
# ---------------------------------------------------------------------------

print_section("24. Common conceptual mistakes")

mistakes = {
    "ACK means the packet was received": (
        "TCP ACK numbers describe the next byte expected cumulatively; "
        "they are not simply packet IDs."
    ),
    "TCP sequence numbers identify packets": (
        "They identify byte positions in the TCP stream."
    ),
    "SYN consumes no sequence number": (
        "SYN consumes one sequence-number position."
    ),
    "FIN consumes no sequence number": (
        "FIN also consumes one sequence-number position."
    ),
    "TCP guarantees low latency": (
        "TCP provides reliability and ordering, not a latency guarantee."
    ),
    "TCP encryption is built in": (
        "TCP does not provide application-level confidentiality."
    ),
    "Receive window equals congestion window": (
        "The receive window protects the receiver; congestion control responds "
        "to network conditions."
    ),
    "One TCP segment equals one application message": (
        "TCP is a byte stream and does not preserve message boundaries."
    ),
}

for misconception, correction in mistakes.items():
    print(f"\nMisconception: {misconception}")
    print(f"Correction:    {correction}")


# ---------------------------------------------------------------------------
# 26. Performance considerations
# ---------------------------------------------------------------------------

print_section("25. Performance considerations")

print(
    """
TCP performance is affected by:

1. RTT
   A larger round-trip time increases feedback delay.

2. Window size
   A small window can limit throughput on high-bandwidth/high-latency paths.

3. Packet loss
   Loss can cause retransmissions and can trigger congestion-control responses.

4. MSS and MTU
   Poorly chosen packet sizes can cause fragmentation or inefficient use of
   network capacity.

5. Receiver processing
   Applications that consume data slowly can reduce the advertised window.

6. Congestion control
   Sending faster is not always better because network queues and links have
   finite capacity.

A rough bandwidth-delay relationship is:

    bandwidth-delay product = bandwidth * RTT

For example, a 100 Mbps path with a 100 ms RTT has:

    100,000,000 bits/s * 0.1 s
    = 10,000,000 bits
    = 1,250,000 bytes

A sender may need a sufficiently large effective window to keep such a path
fully utilized.
"""
)

bandwidth_bits_per_second = 100_000_000
rtt_seconds = 0.1
bdp_bytes = bandwidth_bits_per_second * rtt_seconds / 8

print("Example BDP in bytes:", int(bdp_bytes))


# ---------------------------------------------------------------------------
# 27. Final executable self-test
# ---------------------------------------------------------------------------

print_section("26. Self-test")

handshake = simulate_three_way_handshake(100, 500)

assert handshake[0].sequence_number == 100
assert handshake[0].flags == (TCPFlag.SYN,)

assert handshake[1].sequence_number == 500
assert handshake[1].acknowledgment_number == 101
assert set(handshake[1].flags) == {TCPFlag.SYN, TCPFlag.ACK}

assert handshake[2].sequence_number == 101
assert handshake[2].acknowledgment_number == 501
assert handshake[2].flags == (TCPFlag.ACK,)

syn = TCPSegment("A", "B", 10, flags=(TCPFlag.SYN,))
assert syn.sequence_space_consumed == 1

fin = TCPSegment("A", "B", 10, flags=(TCPFlag.FIN,))
assert fin.sequence_space_consumed == 1

data_segment = TCPSegment(
    "A",
    "B",
    10,
    flags=(TCPFlag.ACK,),
    payload=b"abc",
)
assert data_segment.sequence_space_consumed == 3

assert add_sequence_number(MAX_SEQUENCE_SPACE - 1, 2) == 1

print("All assertions passed.")
print(
    """
TCP fundamentals demonstrated successfully:
- handshake
- flags
- sequence numbers
- acknowledgments
- receive windows
- sliding-window sending
- out-of-order buffering
- retransmission
- duplicate ACK detection
- connection termination
- RTT estimation
- segmentation
- sequence-number wrap-around
- performance reasoning
- security considerations
"""
)
