#!/usr/bin/env python3
"""
DNS: Resolution Process, Recursive Queries, Authoritative Servers, Records, and Caching

This standalone study program teaches DNS from fundamental concepts through a
small, working DNS-resolution simulator and DNS wire-format demonstrations.

The program intentionally uses only the Python standard library. It does not
require Internet access and therefore remains useful in restricted environments.

Topics demonstrated:
    - DNS names and hierarchy
    - Root, TLD, and authoritative servers
    - Recursive and iterative resolution
    - DNS records
    - TTL and caching
    - Positive and negative caching
    - CNAME chains
    - DNS message structure
    - DNS name encoding
    - UDP transport concepts
    - DNS response-code concepts
    - Cache expiration
    - Resolver validation
    - dig/nslookup-style observations
    - Wireshark-style packet interpretation
    - Operational and security considerations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import struct
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# SECTION 1: FUNDAMENTAL TERMINOLOGY
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def print_subsection(title: str) -> None:
    print("\n" + "-" * 78)
    print(title)
    print("-" * 78)


def explain_fundamentals() -> None:
    print_section("1. DNS FUNDAMENTALS")

    concepts = {
        "DNS": (
            "The Domain Name System maps names such as www.example.com to "
            "information such as IPv4 addresses, IPv6 addresses, mail servers, "
            "aliases, and other metadata."
        ),
        "Domain name": (
            "A hierarchical name made from labels separated by dots. "
            "www.example.com contains the labels www, example, and com."
        ),
        "Root": (
            "The DNS hierarchy begins at the root, represented textually by "
            "a final dot: '.'."
        ),
        "TLD": (
            "A top-level domain such as .com, .org, .net, or a country-code "
            "TLD such as .in."
        ),
        "Authoritative server": (
            "A DNS server that holds authoritative data for one or more DNS "
            "zones."
        ),
        "Recursive resolver": (
            "A server that obtains an answer for a client, potentially "
            "querying other DNS servers and caching the result."
        ),
        "TTL": (
            "Time To Live. It specifies how long a cached DNS record may be "
            "used before it needs to be refreshed."
        ),
        "Zone": (
            "An administrative portion of the DNS namespace served by "
            "authoritative DNS servers."
        ),
    }

    for name, explanation in concepts.items():
        print(f"{name:22}: {explanation}")

    print("\nExample name hierarchy:")
    print("root")
    print("  └── com")
    print("       └── example")
    print("            └── www")


# ---------------------------------------------------------------------------
# SECTION 2: DNS RECORD TYPES
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: int = 300

    def normalized_name(self) -> str:
        return normalize_domain(self.name)

    def __str__(self) -> str:
        return f"{self.name:<28} {self.ttl:<5} IN {self.record_type:<6} {self.value}"


def demonstrate_record_types() -> None:
    print_section("2. COMMON DNS RECORD TYPES")

    records = [
        DNSRecord("example.com", "A", "93.184.216.34", 300),
        DNSRecord("example.com", "AAAA", "2001:db8::10", 300),
        DNSRecord("www.example.com", "CNAME", "example.com.", 300),
        DNSRecord("example.com", "MX", "10 mail.example.com.", 3600),
        DNSRecord("example.com", "NS", "ns1.example.com.", 86400),
        DNSRecord("example.com", "TXT", "v=spf1 -all", 3600),
        DNSRecord("example.com", "SOA", "ns1.example.com. hostmaster.example.com.", 3600),
    ]

    print(f"{'NAME':<28} {'TTL':<5} {'CLASS':<5} {'TYPE':<6} VALUE")
    print("-" * 78)

    for record in records:
        print(record)

    print("\nImportant distinctions:")
    print("A     -> IPv4 address")
    print("AAAA  -> IPv6 address")
    print("CNAME -> Canonical-name alias")
    print("MX    -> Mail-exchange information")
    print("NS    -> Authoritative name server")
    print("TXT   -> Arbitrary text used by many protocols and services")
    print("SOA   -> Start of Authority information for a DNS zone")
    print("PTR   -> Reverse DNS mapping from address to name")


# ---------------------------------------------------------------------------
# SECTION 3: DOMAIN NORMALIZATION
# ---------------------------------------------------------------------------

def normalize_domain(name: str) -> str:
    """
    DNS names are case-insensitive.

    A fully qualified DNS name may end with a root label represented by a
    trailing dot. Removing that dot gives a convenient canonical comparison
    form for this educational simulator.
    """
    normalized = name.strip().lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    return normalized


def domain_labels(name: str) -> List[str]:
    normalized = normalize_domain(name)
    return [] if not normalized else normalized.split(".")


def is_valid_hostname(name: str) -> bool:
    """
    This is intentionally a practical validation function rather than a
    complete implementation of every possible internationalized DNS rule.
    """
    normalized = normalize_domain(name)

    if not normalized or len(normalized) > 253:
        return False

    for label in normalized.split("."):
        if not 1 <= len(label) <= 63:
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if any(
            not (character.isalnum() or character == "-")
            for character in label
        ):
            return False

    return True


def demonstrate_domain_structure() -> None:
    print_section("3. DOMAIN NAMES AND HIERARCHY")

    examples = [
        "www.example.com",
        "WWW.Example.COM.",
        "mail.example.org",
        "api.service.example.net",
    ]

    for name in examples:
        print(f"\nOriginal:    {name}")
        print(f"Normalized:  {normalize_domain(name)}")
        print(f"Labels:      {domain_labels(name)}")
        print(f"Valid basic hostname syntax: {is_valid_hostname(name)}")

    print("\nDNS comparison is case-insensitive:")
    print(
        normalize_domain("WWW.Example.COM.")
        == normalize_domain("www.example.com")
    )


# ---------------------------------------------------------------------------
# SECTION 4: DNS SERVERS AND AUTHORITY
# ---------------------------------------------------------------------------

@dataclass
class DNSZone:
    name: str
    records: Dict[Tuple[str, str], List[DNSRecord]] = field(default_factory=dict)

    def add_record(self, record: DNSRecord) -> None:
        key = (normalize_domain(record.name), record.record_type.upper())
        self.records.setdefault(key, []).append(record)

    def lookup(self, name: str, record_type: str) -> List[DNSRecord]:
        key = (normalize_domain(name), record_type.upper())
        return list(self.records.get(key, []))


class SimulatedServer:
    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return f"SimulatedServer({self.name!r})"


class AuthoritativeServer(SimulatedServer):
    def __init__(self, name: str, zones: Optional[Iterable[DNSZone]] = None):
        super().__init__(name)
        self.zones: Dict[str, DNSZone] = {}

        for zone in zones or []:
            self.add_zone(zone)

    def add_zone(self, zone: DNSZone) -> None:
        self.zones[normalize_domain(zone.name)] = zone

    def authoritative_zone_for(self, name: str) -> Optional[DNSZone]:
        """
        Choose the longest matching zone suffix.

        This models the important DNS idea that a server can be authoritative
        for a specific zone and potentially more-specific delegated zones.
        """
        normalized = normalize_domain(name)
        candidates = [
            (zone_name, zone)
            for zone_name, zone in self.zones.items()
            if normalized == zone_name or normalized.endswith("." + zone_name)
        ]

        if not candidates:
            return None

        candidates.sort(key=lambda item: len(item[0]), reverse=True)
        return candidates[0][1]

    def query(self, name: str, record_type: str) -> List[DNSRecord]:
        zone = self.authoritative_zone_for(name)

        if zone is None:
            return []

        return zone.lookup(name, record_type)


def build_demo_dns_infrastructure() -> Tuple[
    AuthoritativeServer,
    AuthoritativeServer,
    AuthoritativeServer,
]:
    """
    Build a small hierarchy:

        root
          |
          +-- .com
                |
                +-- example.com

    Real DNS contains many more servers and delegation relationships.
    """
    root_zone = DNSZone(".")

    # A root server normally does not provide the final A record for a
    # normal domain. It can refer a resolver toward the appropriate TLD.
    root_zone.add_record(
        DNSRecord("com", "NS", "a.gtld-servers.net.", 172800)
    )

    tld_zone = DNSZone("com")
    tld_zone.add_record(
        DNSRecord("example.com", "NS", "ns1.example.com.", 86400)
    )

    example_zone = DNSZone("example.com")
    example_zone.add_record(
        DNSRecord("example.com", "A", "93.184.216.34", 300)
    )
    example_zone.add_record(
        DNSRecord("example.com", "AAAA", "2001:db8::10", 300)
    )
    example_zone.add_record(
        DNSRecord("www.example.com", "CNAME", "example.com.", 300)
    )
    example_zone.add_record(
        DNSRecord("mail.example.com", "A", "192.0.2.25", 300)
    )

    root_server = AuthoritativeServer("Root Server", [root_zone])
    tld_server = AuthoritativeServer("COM TLD Server", [tld_zone])
    authoritative_server = AuthoritativeServer(
        "ns1.example.com",
        [example_zone],
    )

    return root_server, tld_server, authoritative_server


# ---------------------------------------------------------------------------
# SECTION 5: CACHE
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    records: List[DNSRecord]
    expires_at: float

    def is_expired(self, now: Optional[float] = None) -> bool:
        current_time = time.monotonic() if now is None else now
        return current_time >= self.expires_at

    def remaining_ttl(self, now: Optional[float] = None) -> int:
        current_time = time.monotonic() if now is None else now
        return max(0, int(self.expires_at - current_time))


class DNSCache:
    """
    A simple TTL-aware cache.

    Real recursive resolvers have more sophisticated cache structures,
    negative caching, DNSSEC-related state, prefetching, serve-stale
    behavior, eviction strategies, and policy controls.
    """

    def __init__(self, capacity: int = 1000):
        if capacity <= 0:
            raise ValueError("Cache capacity must be positive.")

        self.capacity = capacity
        self.entries: Dict[Tuple[str, str], CacheEntry] = {}
        self.hits = 0
        self.misses = 0

    def get(
        self,
        name: str,
        record_type: str,
        now: Optional[float] = None,
    ) -> Optional[List[DNSRecord]]:
        key = (normalize_domain(name), record_type.upper())
        entry = self.entries.get(key)

        if entry is None:
            self.misses += 1
            return None

        if entry.is_expired(now):
            del self.entries[key]
            self.misses += 1
            return None

        self.hits += 1
        return list(entry.records)

    def put(
        self,
        name: str,
        record_type: str,
        records: Sequence[DNSRecord],
        now: Optional[float] = None,
    ) -> None:
        current_time = time.monotonic() if now is None else now
        key = (normalize_domain(name), record_type.upper())

        if len(self.entries) >= self.capacity and key not in self.entries:
            oldest_key = min(
                self.entries,
                key=lambda cache_key: self.entries[cache_key].expires_at,
            )
            del self.entries[oldest_key]

        if records:
            ttl = min(max(0, record.ttl) for record in records)
            self.entries[key] = CacheEntry(
                records=list(records),
                expires_at=current_time + ttl,
            )

    def clear(self) -> None:
        self.entries.clear()

    def statistics(self) -> Dict[str, float]:
        total = self.hits + self.misses
        hit_rate = self.hits / total if total else 0.0

        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "entries": len(self.entries),
        }


# ---------------------------------------------------------------------------
# SECTION 6: RESOLUTION RESULT
# ---------------------------------------------------------------------------

class ResolutionStatus(Enum):
    ANSWER = "ANSWER"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"


@dataclass
class ResolutionResult:
    status: ResolutionStatus
    name: str
    record_type: str
    records: List[DNSRecord]
    path: List[str]
    cache_hit: bool = False
    explanation: str = ""


# ---------------------------------------------------------------------------
# SECTION 7: RECURSIVE RESOLVER SIMULATION
# ---------------------------------------------------------------------------

class RecursiveResolver:
    """
    A simplified recursive resolver.

    Client -> recursive resolver -> root -> TLD -> authoritative server

    The recursive resolver performs the work for the client and caches the
    final result. This is a conceptual model, not a replacement for a real
    DNS implementation such as BIND, Unbound, or a managed resolver.
    """

    def __init__(
        self,
        root_server: AuthoritativeServer,
        tld_server: AuthoritativeServer,
        authoritative_server: AuthoritativeServer,
        cache_capacity: int = 100,
    ):
        self.root_server = root_server
        self.tld_server = tld_server
        self.authoritative_server = authoritative_server
        self.cache = DNSCache(cache_capacity)

    def resolve(
        self,
        name: str,
        record_type: str = "A",
        now: Optional[float] = None,
    ) -> ResolutionResult:
        normalized_name = normalize_domain(name)
        normalized_type = record_type.upper()

        cached = self.cache.get(normalized_name, normalized_type, now)

        if cached is not None:
            return ResolutionResult(
                status=ResolutionStatus.ANSWER,
                name=normalized_name,
                record_type=normalized_type,
                records=cached,
                path=["Client", "Recursive Resolver", "Cache"],
                cache_hit=True,
                explanation="Answer served from the recursive resolver cache.",
            )

        path = [
            "Client",
            "Recursive Resolver",
            "Root Server",
            "COM TLD Server",
            "Authoritative Server",
        ]

        # Root step: in a real resolver this produces a referral toward the
        # authoritative infrastructure for the requested TLD.
        root_records = self.root_server.query("com", "NS")

        if not root_records:
            return ResolutionResult(
                ResolutionStatus.SERVFAIL,
                normalized_name,
                normalized_type,
                [],
                path,
                explanation="Root referral was unavailable.",
            )

        # TLD step: identify the authoritative server for example.com.
        tld_records = self.tld_server.query("example.com", "NS")

        if not tld_records:
            return ResolutionResult(
                ResolutionStatus.SERVFAIL,
                normalized_name,
                normalized_type,
                [],
                path,
                explanation="TLD referral was unavailable.",
            )

        # Authoritative step: ask the server holding the zone data.
        records = self.authoritative_server.query(
            normalized_name,
            normalized_type,
        )

        # CNAME processing is important because a DNS query may return an
        # alias instead of the final A/AAAA record.
        if not records and normalized_type in {"A", "AAAA"}:
            cname_records = self.authoritative_server.query(
                normalized_name,
                "CNAME",
            )

            if cname_records:
                target = normalize_domain(cname_records[0].value)
                target_records = self.authoritative_server.query(
                    target,
                    normalized_type,
                )

                if target_records:
                    records = target_records

        if not records:
            return ResolutionResult(
                ResolutionStatus.NXDOMAIN,
                normalized_name,
                normalized_type,
                [],
                path,
                explanation=(
                    "No matching record was found in the simulated "
                    "authoritative zone."
                ),
            )

        self.cache.put(normalized_name, normalized_type, records, now)

        return ResolutionResult(
            status=ResolutionStatus.ANSWER,
            name=normalized_name,
            record_type=normalized_type,
            records=records,
            path=path,
            cache_hit=False,
            explanation="Answer obtained through simulated recursive resolution.",
        )


def demonstrate_resolution() -> None:
    print_section("4. RECURSIVE DNS RESOLUTION")

    root, tld, authoritative = build_demo_dns_infrastructure()
    resolver = RecursiveResolver(root, tld, authoritative)

    result = resolver.resolve("example.com", "A")

    print("Query: example.com A")
    print(f"Status: {result.status.value}")
    print(f"Cache hit: {result.cache_hit}")
    print("Resolution path:")
    for step in result.path:
        print(f"  -> {step}")

    print("\nAnswer:")
    for record in result.records:
        print(f"  {record}")

    print("\nSecond query:")
    second_result = resolver.resolve("example.com", "A")
    print(f"Status: {second_result.status.value}")
    print(f"Cache hit: {second_result.cache_hit}")
    print(f"Answer: {[record.value for record in second_result.records]}")


# ---------------------------------------------------------------------------
# SECTION 8: ITERATIVE VS RECURSIVE RESOLUTION
# ---------------------------------------------------------------------------

def demonstrate_recursive_vs_iterative() -> None:
    print_section("5. RECURSIVE VS ITERATIVE DNS QUERIES")

    print(
        """
Recursive model:
    Client -> Recursive Resolver
    Client expects the resolver to obtain the final answer.

Iterative model:
    Resolver asks one DNS server.
    That server provides the best information it has, often a referral.
    Resolver then asks the next appropriate server.

Typical iterative chain:
    Root
      -> TLD
          -> Authoritative

A stub client usually does not need to understand the entire DNS hierarchy.
It normally sends a query to a configured recursive resolver.
"""
    )

    print("Key distinction:")
    print(
        "Recursion describes who performs the work of following referrals; "
        "iteration describes the resolver's step-by-step querying behavior."
    )


# ---------------------------------------------------------------------------
# SECTION 9: TTL AND CACHE EXPIRATION
# ---------------------------------------------------------------------------

def demonstrate_ttl() -> None:
    print_section("6. TTL AND CACHE EXPIRATION")

    cache = DNSCache(capacity=10)
    simulated_time = 1000.0

    record = DNSRecord(
        "short.example",
        "A",
        "192.0.2.10",
        ttl=30,
    )

    cache.put(
        "short.example",
        "A",
        [record],
        now=simulated_time,
    )

    print("Record inserted at simulated time:", simulated_time)

    for elapsed in (0, 10, 29, 30, 31):
        current = simulated_time + elapsed
        result = cache.get("short.example", "A", now=current)

        if result:
            print(
                f"At +{elapsed:2d}s: cache HIT, "
                f"remaining TTL={cache.entries[('short.example', 'a')].remaining_ttl(current)}s"
            )
        else:
            print(f"At +{elapsed:2d}s: cache MISS / expired")

    print(
        "\nA low TTL can make changes propagate sooner but can increase "
        "query traffic. A high TTL can reduce traffic but preserve stale "
        "information for longer after changes."
    )


# ---------------------------------------------------------------------------
# SECTION 10: NEGATIVE RESULTS
# ---------------------------------------------------------------------------

@dataclass
class NegativeCacheEntry:
    expires_at: float
    reason: str


class NegativeDNSCache:
    """
    Simplified negative cache for NXDOMAIN-like results.

    Real negative caching behavior is governed by DNS specifications and
    information supplied by the authoritative response, including SOA data.
    """

    def __init__(self):
        self.entries: Dict[Tuple[str, str], NegativeCacheEntry] = {}

    def put(
        self,
        name: str,
        record_type: str,
        ttl: int,
        reason: str,
        now: float,
    ) -> None:
        key = (normalize_domain(name), record_type.upper())
        self.entries[key] = NegativeCacheEntry(
            expires_at=now + max(0, ttl),
            reason=reason,
        )

    def get(
        self,
        name: str,
        record_type: str,
        now: float,
    ) -> Optional[str]:
        key = (normalize_domain(name), record_type.upper())
        entry = self.entries.get(key)

        if entry is None:
            return None

        if now >= entry.expires_at:
            del self.entries[key]
            return None

        return entry.reason


def demonstrate_negative_caching() -> None:
    print_section("7. NEGATIVE CACHING")

    negative_cache = NegativeDNSCache()
    now = 5000.0

    negative_cache.put(
        "missing.example.com",
        "A",
        ttl=60,
        reason="NXDOMAIN",
        now=now,
    )

    for elapsed in (0, 30, 60, 61):
        reason = negative_cache.get(
            "missing.example.com",
            "A",
            now + elapsed,
        )

        print(
            f"At +{elapsed:2d}s: "
            f"{reason if reason else 'not negatively cached'}"
        )


# ---------------------------------------------------------------------------
# SECTION 11: CNAME CHAINS
# ---------------------------------------------------------------------------

def resolve_cname_chain(
    records: Sequence[DNSRecord],
    start_name: str,
    max_depth: int = 10,
) -> List[str]:
    """
    Resolve a CNAME chain represented entirely by a supplied record set.

    The maximum depth prevents an accidental or malicious cycle from causing
    an infinite loop.
    """
    mapping = {
        normalize_domain(record.name): normalize_domain(record.value)
        for record in records
        if record.record_type.upper() == "CNAME"
    }

    current = normalize_domain(start_name)
    chain = [current]
    visited = {current}

    for _ in range(max_depth):
        target = mapping.get(current)

        if target is None:
            return chain

        if target in visited:
            raise ValueError(
                "CNAME loop detected: " + " -> ".join(chain + [target])
            )

        chain.append(target)
        visited.add(target)
        current = target

    raise ValueError("CNAME chain exceeded maximum depth.")


def demonstrate_cname() -> None:
    print_section("8. CNAME RECORDS AND ALIAS CHAINS")

    records = [
        DNSRecord("app.example.com", "CNAME", "edge.example.net."),
        DNSRecord("edge.example.net", "CNAME", "origin.example.net."),
    ]

    chain = resolve_cname_chain(records, "app.example.com")

    print("CNAME chain:")
    print(" -> ".join(chain))

    print(
        "\nA CNAME is an alias and does not directly contain the final address. "
        "A resolver may need to follow the alias before obtaining an A or "
        "AAAA record."
    )

    print(
        "\nImportant DNS rule: a CNAME generally cannot coexist with other "
        "ordinary data at the same owner name, with DNS protocol rules "
        "defining important exceptions such as DNSSEC-related records."
    )


# ---------------------------------------------------------------------------
# SECTION 12: DNS WIRE FORMAT
# ---------------------------------------------------------------------------

DNS_TYPE_CODES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}

DNS_CLASS_CODES = {
    "IN": 1,
}


def encode_dns_name(name: str) -> bytes:
    """
    Encode a domain name in DNS wire format.

    Example:
        example.com
    becomes conceptually:
        07 example 03 com 00
    """
    normalized = normalize_domain(name)

    if not normalized:
        return b"\x00"

    result = bytearray()

    for label in normalized.split("."):
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise ValueError("A DNS label cannot exceed 63 octets.")

        result.append(len(label_bytes))
        result.extend(label_bytes)

    result.append(0)
    return bytes(result)


def decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """
    Decode an uncompressed DNS name.

    DNS packets can also use compression pointers. This function intentionally
    handles the simple non-compressed representation so the wire-format idea
    remains visible.
    """
    labels: List[str] = []
    position = offset

    while True:
        if position >= len(data):
            raise ValueError("DNS name extends beyond packet.")

        length = data[position]
        position += 1

        if length == 0:
            break

        if length & 0xC0:
            raise ValueError(
                "Compressed DNS names require pointer-aware decoding."
            )

        if position + length > len(data):
            raise ValueError("DNS label extends beyond packet.")

        label = data[position:position + length].decode("ascii")
        labels.append(label)
        position += length

    return ".".join(labels), position


def build_dns_query(
    transaction_id: int,
    name: str,
    record_type: str = "A",
) -> bytes:
    """
    Build a minimal DNS query packet.

    Header:
        ID
        Flags
        QDCOUNT
        ANCOUNT
        NSCOUNT
        ARCOUNT

    This packet uses RD=1, meaning recursion is desired.
    """
    normalized_type = record_type.upper()

    if normalized_type not in DNS_TYPE_CODES:
        raise ValueError(f"Unsupported demonstration type: {record_type}")

    if not 0 <= transaction_id <= 0xFFFF:
        raise ValueError("Transaction ID must fit in 16 bits.")

    flags = 0x0100  # RD = Recursion Desired

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        1,  # one question
        0,
        0,
        0,
    )

    question = (
        encode_dns_name(name)
        + struct.pack(
            "!HH",
            DNS_TYPE_CODES[normalized_type],
            DNS_CLASS_CODES["IN"],
        )
    )

    return header + question


def parse_dns_header(packet: bytes) -> Dict[str, int]:
    if len(packet) < 12:
        raise ValueError("A DNS packet header requires at least 12 bytes.")

    (
        transaction_id,
        flags,
        question_count,
        answer_count,
        authority_count,
        additional_count,
    ) = struct.unpack("!HHHHHH", packet[:12])

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "question_count": question_count,
        "answer_count": answer_count,
        "authority_count": authority_count,
        "additional_count": additional_count,
    }


def demonstrate_dns_wire_format() -> None:
    print_section("9. DNS WIRE FORMAT")

    packet = build_dns_query(
        transaction_id=0x1234,
        name="example.com",
        record_type="A",
    )

    print("Minimal DNS query packet:")
    print(packet.hex())

    header = parse_dns_header(packet)
    print("\nParsed header:")
    for key, value in header.items():
        print(f"  {key:<18}: {value}")

    encoded_name = encode_dns_name("example.com")
    decoded_name, next_offset = decode_dns_name(encoded_name, 0)

    print("\nDNS name encoding:")
    print(f"Encoded bytes: {encoded_name.hex()}")
    print(f"Decoded name:  {decoded_name}")
    print(f"Next offset:   {next_offset}")

    print(
        "\nDNS uses a binary wire format. A packet normally contains a header, "
        "question section, answer section, authority section, and additional "
        "section."
    )


# ---------------------------------------------------------------------------
# SECTION 13: DNS HEADER FLAGS
# ---------------------------------------------------------------------------

def decode_dns_flags(flags: int) -> Dict[str, int]:
    """
    Interpret the major DNS header flags.

    Bit positions:
        QR = bit 15
        AA = bit 10
        TC = bit 9
        RD = bit 8
        RA = bit 7
        RCODE = low four bits
    """
    return {
        "QR": (flags >> 15) & 1,
        "AA": (flags >> 10) & 1,
        "TC": (flags >> 9) & 1,
        "RD": (flags >> 8) & 1,
        "RA": (flags >> 7) & 1,
        "RCODE": flags & 0xF,
    }


def demonstrate_flags() -> None:
    print_section("10. DNS HEADER FLAGS")

    example_response_flags = 0x8580
    decoded = decode_dns_flags(example_response_flags)

    print(f"Flags: 0x{example_response_flags:04x}")

    for name, value in decoded.items():
        print(f"  {name:<5}: {value}")

    print("\nCommon meanings:")
    print("QR=1   -> response")
    print("AA=1   -> authoritative answer")
    print("TC=1   -> response was truncated")
    print("RD=1   -> recursion desired")
    print("RA=1   -> recursion available")
    print("RCODE=0 -> NOERROR")
    print("RCODE=3 -> NXDOMAIN")


# ---------------------------------------------------------------------------
# SECTION 14: UDP AND TCP
# ---------------------------------------------------------------------------

def explain_dns_transport() -> None:
    print_section("11. DNS TRANSPORT: UDP AND TCP")

    print(
        """
Traditional DNS queries commonly use UDP port 53 because UDP has low
overhead and is suitable for short request/response exchanges.

TCP port 53 is also part of DNS and is important when:
    - a response is too large for the selected UDP behavior,
    - a response is truncated and the client retries using TCP,
    - zone transfers are performed,
    - reliable stream transport is required.

Modern DNS also has encrypted transports:
    - DNS over TLS (DoT)
    - DNS over HTTPS (DoH)

These change the transport path and privacy characteristics but still rely
on DNS semantics such as names, records, TTLs, and response codes.
"""
    )


# ---------------------------------------------------------------------------
# SECTION 15: dig / nslookup CONCEPTS
# ---------------------------------------------------------------------------

def explain_dig_and_nslookup() -> None:
    print_section("12. DIG AND NSLOOKUP")

    print(
        """
dig is a detailed DNS diagnostic utility. A typical command such as:

    dig example.com A

asks for an A record and displays sections of the DNS response.

Useful forms include:
    dig example.com
    dig example.com A
    dig example.com AAAA
    dig example.com MX
    dig example.com NS
    dig +trace example.com
    dig @1.1.1.1 example.com
    dig +short example.com

nslookup is another DNS diagnostic utility. Typical usage includes:

    nslookup example.com
    nslookup -type=MX example.com
    nslookup example.com 1.1.1.1

The exact output depends on the operating system and resolver configuration.
"""
    )


# ---------------------------------------------------------------------------
# SECTION 16: WIRESHARK INTERPRETATION
# ---------------------------------------------------------------------------

def explain_wireshark() -> None:
    print_section("13. WIRESHARK DNS PACKET ANALYSIS")

    print(
        """
A packet capture can reveal the actual DNS exchange rather than only the
final answer shown by an application.

A useful Wireshark display filter is:

    dns

Other useful filters include:

    dns.flags.response == 0
    dns.flags.response == 1
    dns.qry.name == "example.com"
    dns.qry.type == 1

When examining a DNS packet, inspect:

    1. Transaction ID
    2. Query/response flag
    3. Recursion Desired (RD)
    4. Recursion Available (RA)
    5. Authoritative Answer (AA)
    6. Response code
    7. Question section
    8. Answer section
    9. Authority section
   10. Additional section
   11. Record TTL
   12. UDP/TCP transport and ports

A client query often has source port >1023 and destination port 53.
The response reverses the direction.

Encrypted DNS changes what a passive packet observer can see. With DoT or
DoH, DNS contents are protected by the corresponding encrypted transport,
although metadata such as endpoint addresses may still be observable.
"""
    )


# ---------------------------------------------------------------------------
# SECTION 17: VALIDATION AND EDGE CASES
# ---------------------------------------------------------------------------

def demonstrate_validation_and_edge_cases() -> None:
    print_section("14. VALIDATION AND EDGE CASES")

    test_names = [
        "",
        "example.com",
        "example.com.",
        "EXAMPLE.COM",
        "-bad.example.com",
        "bad-.example.com",
        "a" * 64 + ".example.com",
        "example..com",
        "localhost",
    ]

    for name in test_names:
        print(f"{name!r:<72} -> {is_valid_hostname(name)}")

    print("\nImportant edge cases:")
    print("- DNS names are case-insensitive.")
    print("- The root is represented by a single dot in presentation format.")
    print("- A label is limited to 63 octets in ordinary DNS wire representation.")
    print("- A complete DNS name is normally limited to 255 octets on the wire.")
    print("- IPv4 and IPv6 addresses use different record types.")
    print("- NXDOMAIN means the queried domain name does not exist.")
    print("- NOERROR with an empty answer section can mean the name exists but")
    print("  the requested record type does not exist, depending on the response.")


# ---------------------------------------------------------------------------
# SECTION 18: PERFORMANCE
# ---------------------------------------------------------------------------

def demonstrate_cache_performance() -> None:
    print_section("15. CACHE PERFORMANCE")

    root, tld, authoritative = build_demo_dns_infrastructure()
    resolver = RecursiveResolver(root, tld, authoritative)

    queries = [
        ("example.com", "A"),
        ("example.com", "A"),
        ("example.com", "AAAA"),
        ("example.com", "A"),
        ("example.com", "AAAA"),
        ("missing.example.com", "A"),
    ]

    for name, record_type in queries:
        result = resolver.resolve(name, record_type)
        print(
            f"{name:<25} {record_type:<5} "
            f"{result.status.value:<8} cache_hit={result.cache_hit}"
        )

    stats = resolver.cache.statistics()

    print("\nCache statistics:")
    print(f"Hits:     {stats['hits']}")
    print(f"Misses:   {stats['misses']}")
    print(f"Hit rate: {stats['hit_rate']:.1%}")
    print(f"Entries:  {stats['entries']}")

    print(
        "\nCaching reduces repeated upstream resolution work and network "
        "traffic. The trade-off is that cached information can remain in use "
        "until its TTL expires."
    )


# ---------------------------------------------------------------------------
# SECTION 19: SECURITY
# ---------------------------------------------------------------------------

def explain_security() -> None:
    print_section("16. DNS SECURITY CONSIDERATIONS")

    security_topics = [
        (
            "DNS cache poisoning",
            "An attacker attempts to cause a resolver to cache false DNS data."
        ),
        (
            "DNS spoofing",
            "Forged DNS responses may attempt to impersonate legitimate answers."
        ),
        (
            "DNSSEC",
            "Adds cryptographic signatures that allow validating resolvers to "
            "authenticate DNS data and its chain of trust."
        ),
        (
            "DoT / DoH",
            "Encrypt DNS transport between the client and the selected DNS "
            "resolver, reducing exposure of query contents on the network."
        ),
        (
            "DNS amplification",
            "Open or abused resolvers can participate in reflected traffic "
            "attacks when attackers exploit asymmetric request/response sizes."
        ),
        (
            "Split-horizon DNS",
            "Different answers can be provided to different client networks, "
            "which is useful for internal versus public services."
        ),
        (
            "DNS rebinding",
            "Attackers can manipulate DNS answers over time to change the "
            "destination associated with a hostname."
        ),
    ]

    for topic, explanation in security_topics:
        print(f"\n{topic}:")
        print(f"  {explanation}")


# ---------------------------------------------------------------------------
# SECTION 20: PRODUCTION DESIGN
# ---------------------------------------------------------------------------

def explain_production_design() -> None:
    print_section("17. PRODUCTION DNS DESIGN CONSIDERATIONS")

    print(
        """
A production recursive resolver may need to handle:

- Concurrent clients
- UDP and TCP
- IPv4 and IPv6
- DNS message compression
- EDNS(0)
- DNSSEC validation
- Negative caching
- Cache eviction
- Query rate limiting
- Timeouts and retries
- Multiple upstream servers
- Referral processing
- CNAME chains
- Delegation changes
- Malformed packets
- Oversized responses
- Monitoring and logging
- Access-control policies
- Privacy requirements
- Failure isolation

A production authoritative service additionally needs accurate zone
management, serial-number handling for SOA records, redundancy, delegation
correctness, and operational monitoring.

A real resolver should not be implemented by simply copying this educational
simulator. DNS has a large standards surface and many protocol details.
"""
    )


# ---------------------------------------------------------------------------
# SECTION 21: PRACTICAL DNS DIAGNOSTIC WORKFLOW
# ---------------------------------------------------------------------------

def diagnostic_workflow() -> None:
    print_section("18. PRACTICAL DNS TROUBLESHOOTING WORKFLOW")

    steps = [
        "Confirm the hostname is spelled correctly.",
        "Query A and AAAA separately.",
        "Inspect the resolver being used.",
        "Compare answers from multiple resolvers.",
        "Inspect TTL values.",
        "Check whether the answer is authoritative.",
        "Inspect CNAME chains.",
        "Check NS records for delegation.",
        "Use +trace when delegation behavior must be investigated.",
        "Capture packets when the application result and DNS behavior disagree.",
        "Distinguish NXDOMAIN from NOERROR with an empty answer.",
        "Check whether local caching is masking a recent DNS change.",
    ]

    for index, step in enumerate(steps, start=1):
        print(f"{index:2}. {step}")


# ---------------------------------------------------------------------------
# SECTION 22: TESTS
# ---------------------------------------------------------------------------

def run_tests() -> None:
    print_section("19. BUILT-IN VALIDATION TESTS")

    assert normalize_domain("Example.COM.") == "example.com"
    assert domain_labels("www.example.com") == ["www", "example", "com"]

    assert is_valid_hostname("example.com")
    assert is_valid_hostname("example.com.")
    assert not is_valid_hostname("-example.com")
    assert not is_valid_hostname("example-.com")

    encoded = encode_dns_name("example.com")
    decoded, end = decode_dns_name(encoded, 0)

    assert decoded == "example.com"
    assert end == len(encoded)

    packet = build_dns_query(0xABCD, "example.com", "A")
    header = parse_dns_header(packet)

    assert header["transaction_id"] == 0xABCD
    assert header["question_count"] == 1

    root, tld, authoritative = build_demo_dns_infrastructure()
    resolver = RecursiveResolver(root, tld, authoritative)

    result = resolver.resolve("example.com", "A")
    assert result.status == ResolutionStatus.ANSWER
    assert result.records[0].value == "93.184.216.34"

    cached_result = resolver.resolve("example.com", "A")
    assert cached_result.cache_hit is True

    missing = resolver.resolve("does-not-exist.example.com", "A")
    assert missing.status == ResolutionStatus.NXDOMAIN

    cname_records = [
        DNSRecord("a.example", "CNAME", "b.example"),
        DNSRecord("b.example", "CNAME", "c.example"),
    ]
    assert resolve_cname_chain(cname_records, "a.example") == [
        "a.example",
        "b.example",
        "c.example",
    ]

    cycle_records = [
        DNSRecord("a.example", "CNAME", "b.example"),
        DNSRecord("b.example", "CNAME", "a.example"),
    ]

    try:
        resolve_cname_chain(cycle_records, "a.example")
    except ValueError:
        pass
    else:
        raise AssertionError("CNAME cycle should have been detected.")

    print("All built-in tests passed.")


# ---------------------------------------------------------------------------
# SECTION 23: MINI STUDY EXERCISES
# ---------------------------------------------------------------------------

def print_exercises() -> None:
    print_section("20. STUDY EXERCISES")

    exercises = [
        "Change the simulated A record and observe cache behavior.",
        "Give a record a very short TTL and observe expiration.",
        "Add an MX record and query it through the simulated authoritative zone.",
        "Create a three-level CNAME chain.",
        "Create a CNAME loop and inspect the validation failure.",
        "Modify the DNS query transaction ID and inspect the binary packet.",
        "Change RD in the DNS header and observe the flag difference.",
        "Add a second TLD and extend the simulated hierarchy.",
        "Implement an LRU cache instead of the expiration-based capacity policy.",
        "Extend the wire-format parser to support DNS compression pointers.",
        "Add support for parsing an A record from a real DNS response.",
        "Add support for IPv6 AAAA RDATA parsing.",
    ]

    for index, exercise in enumerate(exercises, start=1):
        print(f"{index:2}. {exercise}")


# ---------------------------------------------------------------------------
# SECTION 24: MAIN PROGRAM
# ---------------------------------------------------------------------------

def main() -> None:
    print(
        """
DNS STUDY PROGRAM
=================
This program demonstrates DNS concepts from basic terminology to resolver
simulation, caching, wire-format construction, diagnostics, and security.
"""
    )

    explain_fundamentals()
    demonstrate_record_types()
    demonstrate_domain_structure()
    demonstrate_resolution()
    demonstrate_recursive_vs_iterative()
    demonstrate_ttl()
    demonstrate_negative_caching()
    demonstrate_cname()
    demonstrate_dns_wire_format()
    demonstrate_flags()
    explain_dns_transport()
    explain_dig_and_nslookup()
    explain_wireshark()
    demonstrate_validation_and_edge_cases()
    demonstrate_cache_performance()
    explain_security()
    explain_production_design()
    diagnostic_workflow()
    run_tests()
    print_exercises()

    print_section("END OF DNS STUDY PROGRAM")
    print("The program completed successfully.")


if __name__ == "__main__":
    main()
