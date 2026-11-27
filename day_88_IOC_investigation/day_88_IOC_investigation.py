#!/usr/bin/env python3
"""
IOC Investigation and Threat Intelligence Analysis Engine

Supports:
- IPv4 and IPv6 indicators
- Domains and subdomains
- SHA-256, SHA-1, and MD5 hashes
- URLs
- Filenames
- Windows registry indicators
- Indicator normalization and validation
- Threat intelligence enrichment
- Confidence and severity scoring
- IOC matching against endpoint and network events
- Allowlisting and expiration
- Investigation case management
- JSON import and export
- Audit logging

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
import unittest

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    FILENAME = "filename"
    REGISTRY = "registry"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    CLOSED = "closed"


class EventSource(str, Enum):
    FIREWALL = "firewall"
    DNS = "dns"
    ENDPOINT = "endpoint"
    PROXY = "proxy"
    REGISTRY = "registry"
    FILESYSTEM = "filesystem"


class IOCValidationError(ValueError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_domain(value: str) -> str:
    value = value.strip().rstrip(".").lower()

    if not value or len(value) > 253:
        raise IOCValidationError("Invalid domain length")

    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise IOCValidationError("Invalid international domain") from exc

    labels = value.split(".")

    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise IOCValidationError("Invalid domain label")

    if len(labels) < 2:
        raise IOCValidationError("A fully qualified domain is required")

    return value


def normalize_hash(value: str) -> str:
    value = value.strip().lower()

    if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
        raise IOCValidationError("Expected MD5, SHA-1 or SHA-256")

    return value


def normalize_url(value: str) -> str:
    value = value.strip()

    if len(value) > 4096:
        raise IOCValidationError("URL exceeds maximum length")

    try:
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise IOCValidationError("Only HTTP and HTTPS URLs are supported")

        if not parsed.hostname or parsed.username or parsed.password:
            raise IOCValidationError("Invalid or credential-bearing URL")

        host = parsed.hostname

        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            host = normalize_domain(host)

        port = parsed.port

        if port is not None and not 1 <= port <= 65535:
            raise IOCValidationError("Invalid URL port")

        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        netloc = host if port is None else f"{host}:{port}"

        return urlunsplit((
            parsed.scheme.lower(),
            netloc,
            parsed.path or "/",
            parsed.query,
            parsed.fragment
        ))

    except ValueError as exc:
        raise IOCValidationError("Malformed URL") from exc


def normalize_filename(value: str) -> str:
    value = value.strip()

    if not value or len(value) > 255:
        raise IOCValidationError("Invalid filename length")

    if any(char in value for char in ("\x00", "/", "\\", "\n", "\r")):
        raise IOCValidationError("Filename must not contain path separators")

    return value.casefold()


def normalize_registry(value: str) -> str:
    value = value.strip()

    if len(value) > 1024 or not value:
        raise IOCValidationError("Invalid registry indicator")

    value = re.sub(r"^HKEY_LOCAL_MACHINE", "HKLM", value, flags=re.I)
    value = re.sub(r"^HKEY_CURRENT_USER", "HKCU", value, flags=re.I)
    value = re.sub(r"^HKEY_CLASSES_ROOT", "HKCR", value, flags=re.I)
    value = re.sub(r"^HKEY_USERS", "HKU", value, flags=re.I)

    if not re.match(r"^HK(?:LM|CU|CR|U)\\", value, re.I):
        raise IOCValidationError("Unsupported registry root")

    if "\x00" in value:
        raise IOCValidationError("Invalid registry characters")

    return value.casefold()


def normalize_ioc(ioc_type: IOCType, value: str) -> str:
    if not isinstance(value, str):
        raise IOCValidationError("IOC value must be text")

    if ioc_type == IOCType.IP:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError as exc:
            raise IOCValidationError("Invalid IP address") from exc

    if ioc_type == IOCType.DOMAIN:
        return normalize_domain(value)

    if ioc_type == IOCType.HASH:
        return normalize_hash(value)

    if ioc_type == IOCType.URL:
        return normalize_url(value)

    if ioc_type == IOCType.FILENAME:
        return normalize_filename(value)

    if ioc_type == IOCType.REGISTRY:
        return normalize_registry(value)

    raise IOCValidationError("Unsupported IOC type")


@dataclass
class IOC:
    indicator_type: IOCType
    value: str
    source: str
    confidence: int = 50
    severity: Severity = Severity.MEDIUM
    tags: set[str] = field(default_factory=set)
    description: str = ""
    expires_at: datetime | None = None
    active: bool = True
    created_at: datetime = field(default_factory=utc_now)
    identifier: str = field(default_factory=lambda: "")

    def __post_init__(self) -> None:
        self.value = normalize_ioc(self.indicator_type, self.value)

        if not 0 <= self.confidence <= 100:
            raise IOCValidationError("Confidence must be between 0 and 100")

        if not self.source.strip():
            raise IOCValidationError("Threat intelligence source is required")

        self.tags = {tag.strip().lower() for tag in self.tags if tag.strip()}

        if not self.identifier:
            raw = f"{self.indicator_type.value}:{self.value}"
            self.identifier = hashlib.sha256(raw.encode()).hexdigest()

        if self.expires_at and self.expires_at.tzinfo is None:
            raise IOCValidationError("Expiration timestamp must be timezone-aware")

    def is_active(self) -> bool:
        return (
            self.active
            and (self.expires_at is None or self.expires_at > utc_now())
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["indicator_type"] = self.indicator_type.value
        data["severity"] = self.severity.value
        data["tags"] = sorted(self.tags)
        data["created_at"] = self.created_at.isoformat()
        data["expires_at"] = (
            self.expires_at.isoformat() if self.expires_at else None
        )
        return data


@dataclass
class SecurityEvent:
    event_id: str
    source: EventSource
    indicator_type: IOCType
    observed_value: str
    timestamp: datetime
    asset: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.observed_value = normalize_ioc(
            self.indicator_type, self.observed_value
        )

        if not self.event_id or not self.asset:
            raise ValueError("Event ID and asset are required")

        if self.timestamp.tzinfo is None:
            raise ValueError("Event timestamp must be timezone-aware")


@dataclass
class Match:
    event_id: str
    ioc_id: str
    confidence: int
    severity: Severity
    matched_value: str
    matched_at: datetime = field(default_factory=utc_now)


@dataclass
class InvestigationCase:
    case_id: str
    title: str
    status: CaseStatus = CaseStatus.OPEN
    matches: list[Match] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=utc_now)

    def add_match(self, match: Match) -> None:
        if self.status == CaseStatus.CLOSED:
            raise ValueError("Cannot modify a closed investigation")

        if not any(m.event_id == match.event_id and m.ioc_id == match.ioc_id
                   for m in self.matches):
            self.matches.append(match)

    def transition(self, new_status: CaseStatus) -> None:
        allowed = {
            CaseStatus.OPEN: {CaseStatus.INVESTIGATING, CaseStatus.CLOSED},
            CaseStatus.INVESTIGATING: {
                CaseStatus.CONTAINED, CaseStatus.CLOSED
            },
            CaseStatus.CONTAINED: {
                CaseStatus.INVESTIGATING, CaseStatus.CLOSED
            },
            CaseStatus.CLOSED: set()
        }

        if new_status not in allowed[self.status]:
            raise ValueError(
                f"Invalid transition: {self.status.value} "
                f"to {new_status.value}"
            )

        self.status = new_status


class IOCRepository:
    """In-memory repository with indexed indicator lookup."""

    def __init__(self) -> None:
        self._indicators: dict[str, IOC] = {}
        self._index: dict[tuple[IOCType, str], str] = {}
        self._allowlist: set[tuple[IOCType, str]] = set()

    def add(self, ioc: IOC) -> None:
        key = (ioc.indicator_type, ioc.value)

        if key in self._index:
            raise ValueError("Duplicate IOC")

        self._indicators[ioc.identifier] = ioc
        self._index[key] = ioc.identifier

    def get(self, indicator_type: IOCType, value: str) -> IOC | None:
        normalized = normalize_ioc(indicator_type, value)
        identifier = self._index.get((indicator_type, normalized))

        return self._indicators.get(identifier) if identifier else None

    def all(self) -> list[IOC]:
        return list(self._indicators.values())

    def allow(self, indicator_type: IOCType, value: str) -> None:
        normalized = normalize_ioc(indicator_type, value)
        self._allowlist.add((indicator_type, normalized))

    def is_allowed(self, indicator_type: IOCType, value: str) -> bool:
        return (indicator_type, value) in self._allowlist

    def active_indicators(self) -> list[IOC]:
        return [ioc for ioc in self.all() if ioc.is_active()]


class IOCInvestigationEngine:
    def __init__(self, repository: IOCRepository) -> None:
        self.repository = repository
        self.audit_log: list[dict[str, Any]] = []

    def investigate(self, event: SecurityEvent) -> Match | None:
        ioc = self.repository.get(
            event.indicator_type,
            event.observed_value
        )

        if not ioc or not ioc.is_active():
            return None

        if self.repository.is_allowed(
            event.indicator_type, event.observed_value
        ):
            self._audit("allowlisted", event.event_id, ioc.identifier)
            return None

        match = Match(
            event_id=event.event_id,
            ioc_id=ioc.identifier,
            confidence=ioc.confidence,
            severity=ioc.severity,
            matched_value=ioc.value
        )

        self._audit("ioc_match", event.event_id, ioc.identifier)

        return match

    def investigate_batch(
        self, events: list[SecurityEvent]
    ) -> list[Match]:
        matches = []

        for event in events:
            match = self.investigate(event)

            if match:
                matches.append(match)

        return matches

    def _audit(
        self, action: str, event_id: str, ioc_id: str
    ) -> None:
        self.audit_log.append({
            "action": action,
            "event_id": event_id,
            "ioc_id": ioc_id,
            "timestamp": utc_now().isoformat()
        })


def calculate_priority(matches: list[Match]) -> int:
    """Weighted investigation priority, bounded to 0-100."""

    if not matches:
        return 0

    weights = {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4
    }

    score = max(
        match.confidence * weights[match.severity] / 4
        for match in matches
    )

    return min(100, round(score))


def calculate_file_hash(
    file_path: str | Path, algorithm: str = "sha256"
) -> str:
    """Stream file contents to avoid loading large files into memory."""

    if algorithm not in {"md5", "sha1", "sha256"}:
        raise ValueError("Unsupported hash algorithm")

    digest = hashlib.new(algorithm)

    with Path(file_path).open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def export_intelligence(
    repository: IOCRepository,
    destination: str | Path
) -> None:
    data = [ioc.to_dict() for ioc in repository.all()]

    # Restrict export to a caller-controlled destination.
    Path(destination).write_text(
        json.dumps(data, indent=2),
        encoding="utf-8"
    )


def build_demo() -> tuple[
    IOCRepository, IOCInvestigationEngine, list[SecurityEvent]
]:
    repository = IOCRepository()

    repository.add(IOC(
        IOCType.IP,
        "203.0.113.45",
        "Internal Threat Intelligence",
        confidence=95,
        severity=Severity.CRITICAL,
        tags={"c2", "network"}
    ))

    repository.add(IOC(
        IOCType.DOMAIN,
        "malware.example",
        "DNS Threat Feed",
        confidence=90,
        severity=Severity.HIGH,
        tags={"phishing", "dns"}
    ))

    repository.add(IOC(
        IOCType.HASH,
        "a" * 64,
        "Endpoint Threat Feed",
        confidence=99,
        severity=Severity.CRITICAL,
        tags={"malware", "sha256"}
    ))

    repository.add(IOC(
        IOCType.URL,
        "https://malware.example/payload",
        "URL Intelligence Feed",
        confidence=92,
        severity=Severity.HIGH
    ))

    repository.add(IOC(
        IOCType.FILENAME,
        "suspicious.exe",
        "Endpoint Investigation",
        confidence=80,
        severity=Severity.MEDIUM
    ))

    repository.add(IOC(
        IOCType.REGISTRY,
        r"HKEY_LOCAL_MACHINE\Software\BadActor\Persistence",
        "Endpoint Registry Analysis",
        confidence=90,
        severity=Severity.HIGH
    ))

    repository.allow(IOCType.IP, "192.0.2.10")

    events = [
        SecurityEvent(
            "EVT-001", EventSource.FIREWALL, IOCType.IP,
            "203.0.113.45", utc_now(), "WORKSTATION-01"
        ),
        SecurityEvent(
            "EVT-002", EventSource.DNS, IOCType.DOMAIN,
            "MALWARE.EXAMPLE.", utc_now(), "WORKSTATION-02"
        ),
        SecurityEvent(
            "EVT-003", EventSource.ENDPOINT, IOCType.HASH,
            "a" * 64, utc_now(), "SERVER-01"
        ),
        SecurityEvent(
            "EVT-004", EventSource.PROXY, IOCType.URL,
            "https://malware.example/payload", utc_now(),
            "WORKSTATION-03"
        ),
        SecurityEvent(
            "EVT-005", EventSource.FILESYSTEM, IOCType.FILENAME,
            "suspicious.exe", utc_now(), "WORKSTATION-04"
        ),
        SecurityEvent(
            "EVT-006", EventSource.REGISTRY, IOCType.REGISTRY,
            r"HKLM\Software\BadActor\Persistence",
            utc_now(), "WORKSTATION-05"
        )
    ]

    return repository, IOCInvestigationEngine(repository), events


class IOCSystemTests(unittest.TestCase):

    def test_ip_normalization(self):
        self.assertEqual(
            normalize_ioc(IOCType.IP, "203.0.113.45"),
            "203.0.113.45"
        )

    def test_invalid_ip(self):
        with self.assertRaises(IOCValidationError):
            normalize_ioc(IOCType.IP, "999.999.999.999")

    def test_hash_validation(self):
        self.assertEqual(len(normalize_hash("A" * 64)), 64)

    def test_invalid_hash(self):
        with self.assertRaises(IOCValidationError):
            normalize_hash("12345")

    def test_duplicate_detection(self):
        repo = IOCRepository()
        repo.add(IOC(IOCType.IP, "203.0.113.1", "test"))

        with self.assertRaises(ValueError):
            repo.add(IOC(IOCType.IP, "203.0.113.1", "another"))

    def test_allowlisting(self):
        repo = IOCRepository()
        repo.add(IOC(IOCType.IP, "203.0.113.1", "test"))
        repo.allow(IOCType.IP, "203.0.113.1")

        engine = IOCInvestigationEngine(repo)

        event = SecurityEvent(
            "T1", EventSource.FIREWALL, IOCType.IP,
            "203.0.113.1", utc_now(), "HOST-01"
        )

        self.assertIsNone(engine.investigate(event))

    def test_registry_normalization(self):
        value = normalize_registry(
            r"HKEY_LOCAL_MACHINE\Software\Test"
        )
        self.assertTrue(value.startswith("hklm\\"))

    def test_case_transition(self):
        case = InvestigationCase("C1", "Test")
        case.transition(CaseStatus.INVESTIGATING)
        self.assertEqual(case.status, CaseStatus.INVESTIGATING)

        with self.assertRaises(ValueError):
            case.transition(CaseStatus.OPEN)


def main() -> None:
    repository, engine, events = build_demo()

    matches = engine.investigate_batch(events)

    case = InvestigationCase(
        "CASE-2026-001",
        "Suspicious endpoint and network activity"
    )

    for match in matches:
        case.add_match(match)

    if matches:
        case.transition(CaseStatus.INVESTIGATING)

    print("\nIOC INVESTIGATION REPORT")
    print("=" * 65)

    print(f"Indicators registered: {len(repository.all())}")
    print(f"Events analyzed: {len(events)}")
    print(f"Confirmed matches: {len(matches)}")
    print(f"Investigation priority: {calculate_priority(matches)}/100")

    for match in matches:
        print(
            f"\nEvent: {match.event_id}"
            f"\nIOC: {match.matched_value}"
            f"\nSeverity: {match.severity.value}"
            f"\nConfidence: {match.confidence}%"
        )

    print(f"\nCase: {case.case_id}")
    print(f"Case status: {case.status.value}")
    print(f"Audit records: {len(engine.audit_log)}")

    print("\nRunning validation tests...")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        IOCSystemTests
    )
    result = unittest.TextTestRunner(verbosity=1).run(suite)

    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == "__main__":
    main()
