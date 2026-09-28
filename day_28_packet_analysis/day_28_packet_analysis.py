#!/usr/bin/env python3
"""
Packet Analysis Study Script
============================

A self-contained educational implementation of packet-capture analysis concepts.

Topics demonstrated:
    - Packet captures and Ethernet frames
    - IPv4 parsing
    - TCP and UDP parsing
    - Protocol identification
    - BPF/Wireshark-style filter concepts
    - TCP stream reconstruction
    - DNS and HTTP analysis
    - Packet statistics
    - Suspicious-traffic indicators
    - Validation and malformed-packet handling
    - Performance considerations
    - Safe offline analysis

The script deliberately analyzes offline packet bytes supplied to it or a
small generated capture. It does not intercept live traffic, collect
credentials, or perform active network actions.

Usage:
    python packet_analysis.py
    python packet_analysis.py --pcap capture.pcap
    python packet_analysis.py --pcap capture.pcap --filter "tcp port 80"
    python packet_analysis.py --pcap capture.pcap --filter "ip.addr == 10.0.0.5"
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional


# ---------------------------------------------------------------------------
# Fundamental packet structures
# ---------------------------------------------------------------------------

@dataclass
class EthernetFrame:
    timestamp: float
    source_mac: str
    destination_mac: str
    ethertype: int
    payload: bytes
    original_length: int


@dataclass
class IPv4Packet:
    timestamp: float
    source: str
    destination: str
    protocol: int
    ttl: int
    identification: int
    flags: int
    fragment_offset: int
    payload: bytes
    total_length: int


@dataclass
class TCPSegment:
    timestamp: float
    source: str
    destination: str
    source_port: int
    destination_port: int
    sequence: int
    acknowledgment: int
    flags: int
    window: int
    payload: bytes

    @property
    def syn(self) -> bool:
        return bool(self.flags & 0x002)

    @property
    def ack(self) -> bool:
        return bool(self.flags & 0x010)

    @property
    def fin(self) -> bool:
        return bool(self.flags & 0x001)

    @property
    def rst(self) -> bool:
        return bool(self.flags & 0x004)

    @property
    def psh(self) -> bool:
        return bool(self.flags & 0x008)

    @property
    def urg(self) -> bool:
        return bool(self.flags & 0x020)


@dataclass
class UDPSegment:
    timestamp: float
    source: str
    destination: str
    source_port: int
    destination_port: int
    payload: bytes


@dataclass
class PacketRecord:
    number: int
    timestamp: float
    length: int
    ethernet: Optional[EthernetFrame] = None
    ipv4: Optional[IPv4Packet] = None
    tcp: Optional[TCPSegment] = None
    udp: Optional[UDPSegment] = None
    protocol: str = "UNKNOWN"

    @property
    def source(self) -> Optional[str]:
        if self.ipv4:
            return self.ipv4.source
        return None

    @property
    def destination(self) -> Optional[str]:
        if self.ipv4:
            return self.ipv4.destination
        return None

    @property
    def source_port(self) -> Optional[int]:
        if self.tcp:
            return self.tcp.source_port
        if self.udp:
            return self.udp.source_port
        return None

    @property
    def destination_port(self) -> Optional[int]:
        if self.tcp:
            return self.tcp.destination_port
        if self.udp:
            return self.udp.destination_port
        return None


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def mac_address(raw: bytes) -> str:
    """Convert six binary MAC bytes to conventional hexadecimal notation."""
    return ":".join(f"{byte:02x}" for byte in raw)


def safe_ascii(data: bytes, limit: int = 256) -> str:
    """Display printable bytes while preventing binary payloads from flooding output."""
    text = data[:limit].decode("utf-8", errors="replace")
    return "".join(character if character.isprintable() or character in "\r\n\t"
                   else "." for character in text)


def ipv4_checksum(header: bytes) -> int:
    """Calculate the Internet checksum used by IPv4 headers."""
    if len(header) % 2:
        header += b"\x00"

    total = 0
    for index in range(0, len(header), 2):
        total += (header[index] << 8) | header[index + 1]

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def is_private_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------

class PcapReader:
    """
    Minimal classic-PCAP reader.

    Supported:
        - PCAP little-endian
        - PCAP big-endian
        - microsecond timestamps
        - nanosecond timestamps

    This intentionally does not attempt to implement every capture format.
    PCAP-NG is a different container format and requires different parsing.
    """

    MAGIC_MICRO_LE = b"\xd4\xc3\xb2\xa1"
    MAGIC_MICRO_BE = b"\xa1\xb2\xc3\xd4"
    MAGIC_NANO_LE = b"\x4d\x3c\xb2\xa1"
    MAGIC_NANO_BE = b"\xa1\xb2\x3c\x4d"

    def __init__(self, filename: str):
        self.filename = filename
        self.endian = "<"
        self.timestamp_divisor = 1_000_000
        self.link_type = 1  # Ethernet

    def packets(self) -> Iterable[tuple[float, bytes, int]]:
        with open(self.filename, "rb") as capture:
            header = capture.read(24)

            if len(header) != 24:
                raise ValueError("The file is too small to be a valid PCAP.")

            magic = header[:4]

            if magic == self.MAGIC_MICRO_LE:
                self.endian = "<"
                self.timestamp_divisor = 1_000_000
            elif magic == self.MAGIC_MICRO_BE:
                self.endian = ">"
                self.timestamp_divisor = 1_000_000
            elif magic == self.MAGIC_NANO_LE:
                self.endian = "<"
                self.timestamp_divisor = 1_000_000_000
            elif magic == self.MAGIC_NANO_BE:
                self.endian = ">"
                self.timestamp_divisor = 1_000_000_000
            else:
                raise ValueError("Unsupported or invalid PCAP magic number.")

            _, _, _, _, _, _, network = struct.unpack(
                self.endian + "HHIIII",
                header[4:24],
            )
            self.link_type = network

            if self.link_type != 1:
                raise ValueError(
                    f"Unsupported link-layer type {self.link_type}. "
                    "This educational parser expects Ethernet captures."
                )

            while True:
                packet_header = capture.read(16)

                if not packet_header:
                    break

                if len(packet_header) != 16:
                    raise ValueError("Truncated PCAP packet header.")

                seconds, fraction, included_length, original_length = struct.unpack(
                    self.endian + "IIII",
                    packet_header,
                )

                payload = capture.read(included_length)

                if len(payload) != included_length:
                    raise ValueError("Truncated packet data.")

                timestamp = seconds + fraction / self.timestamp_divisor
                yield timestamp, payload, original_length


# ---------------------------------------------------------------------------
# Packet decoders
# ---------------------------------------------------------------------------

def parse_ethernet(
    timestamp: float,
    raw: bytes,
    original_length: int,
) -> EthernetFrame:
    if len(raw) < 14:
        raise ValueError("Ethernet frame is shorter than 14 bytes.")

    destination = mac_address(raw[0:6])
    source = mac_address(raw[6:12])
    ethertype = struct.unpack("!H", raw[12:14])[0]

    # VLAN-tagged Ethernet places the actual EtherType after a 4-byte tag.
    if ethertype in (0x8100, 0x88A8) and len(raw) >= 18:
        ethertype = struct.unpack("!H", raw[16:18])[0]
        payload = raw[18:]
    else:
        payload = raw[14:]

    return EthernetFrame(
        timestamp=timestamp,
        source_mac=source,
        destination_mac=destination,
        ethertype=ethertype,
        payload=payload,
        original_length=original_length,
    )


def parse_ipv4(frame: EthernetFrame) -> Optional[IPv4Packet]:
    if frame.ethertype != 0x0800:
        return None

    data = frame.payload

    if len(data) < 20:
        raise ValueError("IPv4 packet is shorter than the minimum header.")

    version = data[0] >> 4
    ihl_words = data[0] & 0x0F

    if version != 4:
        raise ValueError("Ethernet EtherType indicates IPv4 but version is not 4.")

    header_length = ihl_words * 4

    if header_length < 20 or len(data) < header_length:
        raise ValueError("Invalid IPv4 header length.")

    (
        _,
        _,
        total_length,
        identification,
        fragment_info,
        ttl,
        protocol,
        checksum,
        source_raw,
        destination_raw,
    ) = struct.unpack("!BBHHHBBH4s4s", data[:20])

    if total_length < header_length or total_length > len(data):
        raise ValueError("Invalid IPv4 total length.")

    # A checksum of zero is not valid for ordinary IPv4 headers.
    calculated = ipv4_checksum(data[:header_length])
    if calculated != 0:
        # We record the packet rather than rejecting it. Captures can contain
        # packets whose checksum is intentionally offloaded by the NIC.
        pass

    flags = fragment_info >> 13
    fragment_offset = fragment_info & 0x1FFF

    return IPv4Packet(
        timestamp=frame.timestamp,
        source=str(ipaddress.ip_address(source_raw)),
        destination=str(ipaddress.ip_address(destination_raw)),
        protocol=protocol,
        ttl=ttl,
        identification=identification,
        flags=flags,
        fragment_offset=fragment_offset,
        payload=data[header_length:total_length],
        total_length=total_length,
    )


def parse_tcp(packet: IPv4Packet) -> Optional[TCPSegment]:
    if packet.protocol != 6:
        return None

    data = packet.payload

    if len(data) < 20:
        raise ValueError("TCP segment is shorter than the minimum header.")

    (
        source_port,
        destination_port,
        sequence,
        acknowledgment,
        offset_flags,
        window,
        checksum,
        urgent_pointer,
    ) = struct.unpack("!HHIIHHHH", data[:20])

    header_length = ((offset_flags >> 12) & 0xF) * 4

    if header_length < 20 or header_length > len(data):
        raise ValueError("Invalid TCP header length.")

    flags = offset_flags & 0x01FF

    return TCPSegment(
        timestamp=packet.timestamp,
        source=packet.source,
        destination=packet.destination,
        source_port=source_port,
        destination_port=destination_port,
        sequence=sequence,
        acknowledgment=acknowledgment,
        flags=flags,
        window=window,
        payload=data[header_length:],
    )


def parse_udp(packet: IPv4Packet) -> Optional[UDPSegment]:
    if packet.protocol != 17:
        return None

    data = packet.payload

    if len(data) < 8:
        raise ValueError("UDP datagram is shorter than 8 bytes.")

    source_port, destination_port, length, checksum = struct.unpack(
        "!HHHH",
        data[:8],
    )

    if length < 8 or length > len(data):
        raise ValueError("Invalid UDP length.")

    return UDPSegment(
        timestamp=packet.timestamp,
        source=packet.source,
        destination=packet.destination,
        source_port=source_port,
        destination_port=destination_port,
        payload=data[8:length],
    )


def decode_capture(filename: str) -> list[PacketRecord]:
    records: list[PacketRecord] = []
    reader = PcapReader(filename)

    for number, (timestamp, raw, original_length) in enumerate(
        reader.packets(), start=1
    ):
        record = PacketRecord(
            number=number,
            timestamp=timestamp,
            length=len(raw),
        )

        try:
            ethernet = parse_ethernet(timestamp, raw, original_length)
            record.ethernet = ethernet

            ipv4 = parse_ipv4(ethernet)
            record.ipv4 = ipv4

            if ipv4 is not None:
                tcp = parse_tcp(ipv4)
                udp = parse_udp(ipv4)

                record.tcp = tcp
                record.udp = udp

                if tcp:
                    record.protocol = identify_application_protocol(
                        tcp.source_port,
                        tcp.destination_port,
                        tcp.payload,
                    )
                elif udp:
                    record.protocol = identify_application_protocol(
                        udp.source_port,
                        udp.destination_port,
                        udp.payload,
                    )
                else:
                    record.protocol = protocol_number_name(ipv4.protocol)

            records.append(record)

        except ValueError as error:
            # Malformed packets should not crash analysis of the whole capture.
            record.protocol = f"MALFORMED: {error}"
            records.append(record)

    return records


# ---------------------------------------------------------------------------
# Protocol identification
# ---------------------------------------------------------------------------

PROTOCOL_NUMBERS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}


def protocol_number_name(number: int) -> str:
    return PROTOCOL_NUMBERS.get(number, f"IP/{number}")


def identify_application_protocol(
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> str:
    ports = {source_port, destination_port}

    if 53 in ports:
        return "DNS"

    if 80 in ports:
        return "HTTP"

    if 443 in ports:
        return "HTTPS/TLS"

    if 22 in ports:
        return "SSH"

    if 25 in ports or 587 in ports:
        return "SMTP"

    if 123 in ports:
        return "NTP"

    if 67 in ports or 68 in ports:
        return "DHCP"

    # Lightweight protocol signatures can complement port-based identification.
    if payload.startswith(b"GET ") or payload.startswith(b"POST "):
        return "HTTP"

    if payload.startswith(b"\x16\x03"):
        return "TLS"

    return "TCP" if len(payload) >= 0 else "UNKNOWN"


# ---------------------------------------------------------------------------
# Wireshark-style filter engine
# ---------------------------------------------------------------------------

class PacketFilter:
    """
    Small educational filter language.

    Supported examples:

        tcp
        udp
        dns
        http
        tcp port 443
        tcp.port == 443
        ip.addr == 192.168.1.10
        ip.src == 192.168.1.10
        ip.dst == 8.8.8.8
        tcp.flags.syn == 1
        tcp.flags.rst == 1
        frame.len > 1000
        tcp && ip.addr == 10.0.0.5

    This is intentionally not a complete Wireshark display-filter parser.
    """

    def __init__(self, expression: str):
        self.expression = expression.strip()

    def matches(self, packet: PacketRecord) -> bool:
        expression = self.expression

        if not expression:
            return True

        # Parenthesized expressions are intentionally supported only when the
        # outer pair encloses the complete expression.
        if expression.startswith("(") and expression.endswith(")"):
            expression = expression[1:-1].strip()

        # Basic logical AND.
        and_parts = re.split(r"\s+(?:&&|and)\s+", expression, flags=re.I)
        if len(and_parts) > 1:
            return all(PacketFilter(part).matches(packet) for part in and_parts)

        # Basic logical OR.
        or_parts = re.split(r"\s+(?:\|\||or)\s+", expression, flags=re.I)
        if len(or_parts) > 1:
            return any(PacketFilter(part).matches(packet) for part in or_parts)

        return self._match_atom(expression)

    def _match_atom(self, expression: str) -> bool:
        expression = expression.strip().lower()

        if expression == "tcp":
            return packet_has_tcp(self.current_packet)

        if expression == "udp":
            return self.current_packet.udp is not None

        if expression == "dns":
            return self.current_packet.protocol == "DNS"

        if expression == "http":
            return self.current_packet.protocol == "HTTP"

        if expression in {"tls", "ssl", "https"}:
            return self.current_packet.protocol in {"TLS", "HTTPS/TLS"}

        if expression == "icmp":
            return (
                self.current_packet.ipv4 is not None
                and self.current_packet.ipv4.protocol == 1
            )

        match = re.fullmatch(r"(?:tcp\.)?port\s*(?:==|=)?\s*(\d+)", expression)
        if match:
            port = int(match.group(1))
            return (
                self.current_packet.source_port == port
                or self.current_packet.destination_port == port
            )

        match = re.fullmatch(r"tcp\.port\s*==\s*(\d+)", expression)
        if match:
            if self.current_packet.tcp is None:
                return False
            port = int(match.group(1))
            return (
                self.current_packet.tcp.source_port == port
                or self.current_packet.tcp.destination_port == port
            )

        match = re.fullmatch(r"ip\.addr\s*==\s*([\d.]+)", expression)
        if match:
            address = match.group(1)
            return (
                self.current_packet.source == address
                or self.current_packet.destination == address
            )

        match = re.fullmatch(r"ip\.src\s*==\s*([\d.]+)", expression)
        if match:
            return self.current_packet.source == match.group(1)

        match = re.fullmatch(r"ip\.dst\s*==\s*([\d.]+)", expression)
        if match:
            return self.current_packet.destination == match.group(1)

        match = re.fullmatch(r"frame\.len\s*(==|>=|<=|>|<)\s*(\d+)", expression)
        if match:
            operator, number = match.groups()
            number = int(number)
            return compare(self.current_packet.length, operator, number)

        match = re.fullmatch(r"tcp\.flags\.(syn|ack|fin|rst|psh|urg)\s*==\s*([01])", expression)
        if match:
            flag, expected = match.groups()
            if self.current_packet.tcp is None:
                return False

            actual = int(getattr(self.current_packet.tcp, flag))
            return actual == int(expected)

        raise ValueError(f"Unsupported filter expression: {expression}")

    def filter(self, packets: Iterable[PacketRecord]) -> list[PacketRecord]:
        result = []

        for packet in packets:
            self.current_packet = packet
            if self.matches(packet):
                result.append(packet)

        return result


def packet_has_tcp(packet: PacketRecord) -> bool:
    return packet.tcp is not None


def compare(left: int, operator: str, right: int) -> bool:
    if operator == "==":
        return left == right
    if operator == ">":
        return left > right
    if operator == "<":
        return left < right
    if operator == ">=":
        return left >= right
    if operator == "<=":
        return left <= right
    return False


# ---------------------------------------------------------------------------
# TCP stream reconstruction
# ---------------------------------------------------------------------------

@dataclass
class TCPStream:
    key: tuple[str, int, str, int]
    segments: list[TCPSegment] = field(default_factory=list)

    def add(self, segment: TCPSegment) -> None:
        self.segments.append(segment)

    def ordered_segments(self) -> list[TCPSegment]:
        return sorted(
            self.segments,
            key=lambda segment: (segment.source, segment.destination, segment.sequence),
        )

    def reconstruct_direction(
        self,
        source: str,
        source_port: int,
    ) -> bytes:
        segments = [
            segment
            for segment in self.segments
            if segment.source == source and segment.source_port == source_port
        ]

        segments.sort(key=lambda segment: segment.sequence)

        output = bytearray()
        next_sequence: Optional[int] = None

        for segment in segments:
            if not segment.payload:
                continue

            start = segment.sequence

            if next_sequence is None:
                output.extend(segment.payload)
                next_sequence = start + len(segment.payload)
                continue

            if start >= next_sequence:
                output.extend(segment.payload)
                next_sequence = start + len(segment.payload)
            else:
                # Overlapping/retransmitted bytes are trimmed rather than
                # duplicated. Real TCP reassembly must handle many more cases.
                overlap = next_sequence - start
                if overlap < len(segment.payload):
                    output.extend(segment.payload[overlap:])
                    next_sequence += len(segment.payload) - overlap

        return bytes(output)

    def summary(self) -> str:
        if not self.segments:
            return "empty TCP stream"

        first = self.segments[0]
        forward = self.reconstruct_direction(first.source, first.source_port)

        reverse_candidates = [
            segment
            for segment in self.segments
            if segment.source != first.source
            or segment.source_port != first.source_port
        ]

        if reverse_candidates:
            reverse = self.reconstruct_direction(
                reverse_candidates[0].source,
                reverse_candidates[0].source_port,
            )
        else:
            reverse = b""

        return (
            f"segments={len(self.segments)}, "
            f"forward_bytes={len(forward)}, "
            f"reverse_bytes={len(reverse)}"
        )


def build_tcp_streams(packets: Iterable[PacketRecord]) -> dict[tuple, TCPStream]:
    streams: dict[tuple, TCPStream] = {}

    for packet in packets:
        segment = packet.tcp
        if segment is None:
            continue

        endpoint_a = (segment.source, segment.source_port)
        endpoint_b = (segment.destination, segment.destination_port)

        # Canonical ordering makes both directions belong to one stream.
        if endpoint_a <= endpoint_b:
            key = (*endpoint_a, *endpoint_b)
        else:
            key = (*endpoint_b, *endpoint_a)

        streams.setdefault(key, TCPStream(key)).add(segment)

    return streams


# ---------------------------------------------------------------------------
# DNS parsing
# ---------------------------------------------------------------------------

def parse_dns_header(payload: bytes) -> Optional[dict]:
    if len(payload) < 12:
        return None

    transaction_id, flags, questions, answers, authorities, additional = struct.unpack(
        "!HHHHHH",
        payload[:12],
    )

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "is_response": bool(flags & 0x8000),
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additional": additional,
        "rcode": flags & 0x000F,
    }


def read_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decode a DNS QNAME.

    Compression pointers are supported sufficiently for educational packet
    inspection. A visited-pointer set prevents malicious loops.
    """
    labels = []
    original_offset = offset
    jumped = False
    visited: set[int] = set()

    while True:
        if offset >= len(data):
            raise ValueError("DNS name extends beyond packet.")

        length = data[offset]

        if length == 0:
            offset += 1
            break

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated DNS compression pointer.")

            pointer = ((length & 0x3F) << 8) | data[offset + 1]

            if pointer in visited:
                raise ValueError("DNS compression loop detected.")

            visited.add(pointer)

            if not jumped:
                original_offset = offset + 2
                jumped = True

            offset = pointer
            continue

        if length > 63:
            raise ValueError("Invalid DNS label length.")

        start = offset + 1
        end = start + length

        if end > len(data):
            raise ValueError("Truncated DNS label.")

        labels.append(data[start:end].decode("ascii", errors="replace"))
        offset = end

    return ".".join(labels), original_offset if jumped else offset


def parse_dns_questions(payload: bytes) -> list[dict]:
    header = parse_dns_header(payload)
    if header is None:
        return []

    offset = 12
    questions = []

    for _ in range(min(header["questions"], 100)):
        name, offset = read_dns_name(payload, offset)

        if offset + 4 > len(payload):
            break

        qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
        offset += 4

        questions.append({
            "name": name,
            "type": qtype,
            "class": qclass,
        })

    return questions


# ---------------------------------------------------------------------------
# HTTP analysis
# ---------------------------------------------------------------------------

HTTP_REQUEST_PATTERN = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)"
)

HTTP_HOST_PATTERN = re.compile(rb"\r?\nHost:\s*([^\r\n]+)", re.I)


def analyze_http_payload(payload: bytes) -> Optional[dict]:
    match = HTTP_REQUEST_PATTERN.search(payload)

    if not match:
        return None

    method = match.group(1).decode("ascii", errors="replace")
    path = match.group(2).decode("ascii", errors="replace")
    version = match.group(3).decode("ascii", errors="replace")

    host_match = HTTP_HOST_PATTERN.search(payload)
    host = (
        host_match.group(1).decode("utf-8", errors="replace").strip()
        if host_match
        else ""
    )

    return {
        "method": method,
        "path": path,
        "version": version,
        "host": host,
    }


# ---------------------------------------------------------------------------
# Suspicious-traffic indicators
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    severity: str
    packet_number: int
    title: str
    evidence: str


SUSPICIOUS_PORTS = {
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}


def detect_suspicious_traffic(packets: Iterable[PacketRecord]) -> list[Finding]:
    findings: list[Finding] = []
    syn_counts: Counter[tuple[str, str, int]] = Counter()
    unique_destinations: defaultdict[str, set[str]] = defaultdict(set)

    for packet in packets:
        if packet.tcp:
            tcp = packet.tcp

            if tcp.syn and not tcp.ack:
                key = (tcp.source, tcp.destination, tcp.destination_port)
                syn_counts[key] += 1

            if tcp.destination_port in SUSPICIOUS_PORTS:
                service = SUSPICIOUS_PORTS[tcp.destination_port]
                findings.append(
                    Finding(
                        severity="MEDIUM",
                        packet_number=packet.number,
                        title=f"Traffic to {service} port",
                        evidence=(
                            f"{tcp.source}:{tcp.source_port} -> "
                            f"{tcp.destination}:{tcp.destination_port}"
                        ),
                    )
                )

            if tcp.rst:
                findings.append(
                    Finding(
                        severity="LOW",
                        packet_number=packet.number,
                        title="TCP reset observed",
                        evidence=(
                            f"{tcp.source}:{tcp.source_port} -> "
                            f"{tcp.destination}:{tcp.destination_port}"
                        ),
                    )
                )

        if packet.destination:
            unique_destinations[packet.source or "unknown"].add(packet.destination)

    # A high SYN count is an indicator, not proof, of scanning or connectivity
    # problems. Thresholds are deliberately conservative for demonstration.
    for (source, destination, port), count in syn_counts.items():
        if count >= 10:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    packet_number=0,
                    title="Repeated TCP SYN attempts",
                    evidence=(
                        f"{source} sent {count} SYN packets toward "
                        f"{destination}:{port}. This can indicate scanning, "
                        f"retries, or a broken application."
                    ),
                )
            )

    # Large fan-out can be interesting in malware analysis, but legitimate
    # clients such as browsers and DNS resolvers can also contact many hosts.
    for source, destinations in unique_destinations.items():
        if len(destinations) >= 50:
            findings.append(
                Finding(
                    severity="LOW",
                    packet_number=0,
                    title="High destination fan-out",
                    evidence=(
                        f"{source} contacted {len(destinations)} unique "
                        "destination addresses in the capture."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def capture_statistics(packets: list[PacketRecord]) -> dict:
    protocols = Counter(packet.protocol for packet in packets)
    sources = Counter(packet.source for packet in packets if packet.source)
    destinations = Counter(
        packet.destination for packet in packets if packet.destination
    )

    tcp_bytes = sum(len(packet.tcp.payload) for packet in packets if packet.tcp)
    udp_bytes = sum(len(packet.udp.payload) for packet in packets if packet.udp)

    return {
        "packet_count": len(packets),
        "total_bytes": sum(packet.length for packet in packets),
        "protocols": protocols,
        "top_sources": sources.most_common(10),
        "top_destinations": destinations.most_common(10),
        "tcp_payload_bytes": tcp_bytes,
        "udp_payload_bytes": udp_bytes,
    }


def print_statistics(packets: list[PacketRecord]) -> None:
    statistics = capture_statistics(packets)

    print("\n=== CAPTURE STATISTICS ===")
    print(f"Packets:       {statistics['packet_count']}")
    print(f"Captured bytes:{statistics['total_bytes']}")
    print(f"TCP payload:   {statistics['tcp_payload_bytes']}")
    print(f"UDP payload:   {statistics['udp_payload_bytes']}")

    print("\nProtocols:")
    for protocol, count in statistics["protocols"].most_common():
        print(f"  {protocol:<15} {count}")

    print("\nTop source addresses:")
    for address, count in statistics["top_sources"]:
        print(f"  {address:<20} {count}")

    print("\nTop destination addresses:")
    for address, count in statistics["top_destinations"]:
        print(f"  {address:<20} {count}")


# ---------------------------------------------------------------------------
# Educational packet generation
# ---------------------------------------------------------------------------

def build_ipv4_header(
    source: str,
    destination: str,
    protocol: int,
    payload_length: int,
    identification: int = 1,
) -> bytes:
    source_bytes = ipaddress.ip_address(source).packed
    destination_bytes = ipaddress.ip_address(destination).packed

    version_ihl = (4 << 4) | 5
    total_length = 20 + payload_length

    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        0,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )

    checksum = ipv4_checksum(header_without_checksum)

    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        0,
        64,
        protocol,
        checksum,
        source_bytes,
        destination_bytes,
    )


def build_tcp_segment(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    sequence: int,
    flags: int,
    payload: bytes,
) -> bytes:
    offset_flags = (5 << 12) | flags

    header = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        sequence,
        0,
        offset_flags,
        64240,
        0,
        0,
    )

    return build_ipv4_header(
        source,
        destination,
        6,
        len(header) + len(payload),
    ) + header + payload


def build_udp_segment(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    payload: bytes,
) -> bytes:
    length = 8 + len(payload)

    header = struct.pack(
        "!HHHH",
        source_port,
        destination_port,
        length,
        0,
    )

    return build_ipv4_header(
        source,
        destination,
        17,
        len(header) + len(payload),
    ) + header + payload


def build_ethernet_frame(
    source_mac: bytes,
    destination_mac: bytes,
    ip_payload: bytes,
) -> bytes:
    return destination_mac + source_mac + struct.pack("!H", 0x0800) + ip_payload


def write_demo_pcap(filename: str) -> None:
    """
    Create a small valid Ethernet PCAP without external libraries.

    The packets contain harmless synthetic HTTP and DNS data for studying
    decoding, filtering, stream reconstruction, and protocol analysis.
    """
    source_mac = bytes.fromhex("001122334455")
    destination_mac = bytes.fromhex("aabbccddeeff")

    http_request = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.test\r\n"
        b"User-Agent: PacketStudy/1.0\r\n"
        b"\r\n"
    )

    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 12\r\n"
        b"\r\n"
        b"hello world\n"
    )

    dns_payload = (
        b"\x12\x34"
        b"\x01\x00"
        b"\x00\x01"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x07example"
        b"\x04test"
        b"\x00"
        b"\x00\x01"
        b"\x00\x01"
    )

    packets = [
        build_ethernet_frame(
            source_mac,
            destination_mac,
            build_tcp_segment(
                "192.168.1.10",
                "192.168.1.20",
                50000,
                80,
                1000,
                0x002,
                b"",
            ),
        ),
        build_ethernet_frame(
            destination_mac,
            source_mac,
            build_tcp_segment(
                "192.168.1.20",
                "192.168.1.10",
                80,
                50000,
                2000,
                0x012,
                b"",
            ),
        ),
        build_ethernet_frame(
            source_mac,
            destination_mac,
            build_tcp_segment(
                "192.168.1.10",
                "192.168.1.20",
                50000,
                80,
                1001,
                0x018,
                http_request[:45],
            ),
        ),
        build_ethernet_frame(
            source_mac,
            destination_mac,
            build_tcp_segment(
                "192.168.1.10",
                "192.168.1.20",
                50000,
                80,
                1046,
                0x018,
                http_request[45:],
            ),
        ),
        build_ethernet_frame(
            destination_mac,
            source_mac,
            build_tcp_segment(
                "192.168.1.20",
                "192.168.1.10",
                80,
                50000,
                2001,
                0x018,
                http_response,
            ),
        ),
        build_ethernet_frame(
            source_mac,
            destination_mac,
            build_udp_segment(
                "192.168.1.10",
                "8.8.8.8",
                53000,
                53,
                dns_payload,
            ),
        ),
    ]

    with open(filename, "wb") as capture:
        # Classic PCAP global header, little-endian, Ethernet.
        capture.write(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,
                2,
                4,
                0,
                0,
                65535,
                1,
            )
        )

        base_time = int(datetime.now(tz=timezone.utc).timestamp())

        for index, packet in enumerate(packets):
            capture.write(
                struct.pack(
                    "<IIII",
                    base_time,
                    index * 1000,
                    len(packet),
                    len(packet),
                )
            )
            capture.write(packet)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_packet_table(packets: Iterable[PacketRecord], limit: int = 30) -> None:
    print("\n=== PACKET LIST ===")
    print(
        f"{'No.':>4} {'Source':<18} {'Destination':<18} "
        f"{'Proto':<14} {'Length':>7}"
    )
    print("-" * 72)

    for packet in list(packets)[:limit]:
        print(
            f"{packet.number:>4} "
            f"{(packet.source or '-'): <18} "
            f"{(packet.destination or '-'): <18} "
            f"{packet.protocol:<14} "
            f"{packet.length:>7}"
        )


def print_tcp_streams(packets: list[PacketRecord]) -> None:
    streams = build_tcp_streams(packets)

    print("\n=== TCP STREAMS ===")

    if not streams:
        print("No TCP streams found.")
        return

    for index, stream in enumerate(streams.values(), start=1):
        print(f"\nStream {index}: {stream.key}")
        print(f"  {stream.summary()}")

        first = stream.segments[0]
        forward = stream.reconstruct_direction(
            first.source,
            first.source_port,
        )

        http = analyze_http_payload(forward)

        if http:
            print("  HTTP request:")
            print(f"    Method: {http['method']}")
            print(f"    Host:   {http['host'] or '(not present)'}")
            print(f"    Path:   {http['path']}")

        print(f"  Payload preview: {safe_ascii(forward, 180)!r}")


def print_dns_analysis(packets: list[PacketRecord]) -> None:
    print("\n=== DNS ANALYSIS ===")

    found = False

    for packet in packets:
        if packet.protocol != "DNS":
            continue

        payload = (
            packet.udp.payload
            if packet.udp
            else b""
        )

        header = parse_dns_header(payload)
        questions = parse_dns_questions(payload)

        if not header:
            continue

        found = True

        print(
            f"Packet {packet.number}: "
            f"{'response' if header['is_response'] else 'query'}, "
            f"rcode={header['rcode']}"
        )

        for question in questions:
            print(
                f"  QNAME={question['name']}, "
                f"QTYPE={question['type']}, "
                f"QCLASS={question['class']}"
            )

    if not found:
        print("No decodable DNS packets found.")


def print_findings(packets: list[PacketRecord]) -> None:
    findings = detect_suspicious_traffic(packets)

    print("\n=== TRAFFIC INDICATORS ===")

    if not findings:
        print("No configured indicators were observed.")
        return

    for finding in findings:
        location = (
            f"packet {finding.packet_number}"
            if finding.packet_number
            else "capture-level"
        )
        print(f"[{finding.severity}] {location}: {finding.title}")
        print(f"  {finding.evidence}")


# ---------------------------------------------------------------------------
# Demonstration mode
# ---------------------------------------------------------------------------

def run_demo() -> None:
    filename = "packet_analysis_demo.pcap"

    print("Creating a synthetic offline PCAP...")
    write_demo_pcap(filename)

    packets = decode_capture(filename)

    print_packet_table(packets)
    print_statistics(packets)

    print("\n=== FILTER DEMONSTRATION ===")

    filters = [
        "tcp",
        "udp",
        "http",
        "tcp port 80",
        "ip.addr == 192.168.1.10",
        "tcp.flags.syn == 1",
        "frame.len > 60",
    ]

    for expression in filters:
        matched = PacketFilter(expression).filter(packets)
        print(f"{expression:<30} -> {len(matched)} packet(s)")

    print_tcp_streams(packets)
    print_dns_analysis(packets)
    print_findings(packets)

    print(
        f"\nDemo capture written to {filename!r}. "
        "It contains synthetic traffic only."
    )


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline educational PCAP packet-analysis tool."
    )

    parser.add_argument(
        "--pcap",
        help="Path to a classic PCAP file containing Ethernet frames.",
    )

    parser.add_argument(
        "--filter",
        default="",
        help="Educational display filter, for example: tcp port 443",
    )

    parser.add_argument(
        "--show-packets",
        action="store_true",
        help="Display a packet table.",
    )

    parser.add_argument(
        "--streams",
        action="store_true",
        help="Reconstruct and inspect TCP streams.",
    )

    parser.add_argument(
        "--dns",
        action="store_true",
        help="Inspect DNS queries.",
    )

    parser.add_argument(
        "--findings",
        action="store_true",
        help="Display configured suspicious-traffic indicators.",
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate and analyze a synthetic PCAP.",
    )

    return parser


def main() -> int:
    parser = build_argument_parser()
    arguments = parser.parse_args()

    try:
        if arguments.demo or not arguments.pcap:
            run_demo()
            return 0

        packets = decode_capture(arguments.pcap)

        if arguments.filter:
            packets = PacketFilter(arguments.filter).filter(packets)

        print_statistics(packets)

        if arguments.show_packets:
            print_packet_table(packets)

        if arguments.streams:
            print_tcp_streams(packets)

        if arguments.dns:
            print_dns_analysis(packets)

        if arguments.findings:
            print_findings(packets)

        if not any(
            (
                arguments.show_packets,
                arguments.streams,
                arguments.dns,
                arguments.findings,
            )
        ):
            print_packet_table(packets)

        return 0

    except FileNotFoundError:
        print(f"Error: PCAP file not found: {arguments.pcap}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
