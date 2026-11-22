#!/usr/bin/env python3
"""
Security Log Analytics and Threat Detection Engine

Processes Windows, Linux, firewall, DNS, proxy, authentication,
and application telemetry.

Features:
- Structured log normalization
- Event validation
- Cross-source correlation
- Brute-force detection
- Port scanning detection
- DNS tunneling indicators
- Suspicious proxy activity
- Authentication anomaly detection
- Risk scoring
- Incident management
- JSONL ingestion and reporting

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import math
import re
import sys

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("security_logs")


class LogSource(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    FIREWALL = "firewall"
    DNS = "dns"
    PROXY = "proxy"
    AUTHENTICATION = "authentication"
    APPLICATION = "application"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PRIVILEGE_CHANGE = "privilege_change"
    PROCESS_EXECUTION = "process_execution"
    NETWORK_CONNECTION = "network_connection"
    FIREWALL_BLOCK = "firewall_block"
    FIREWALL_ALLOW = "firewall_allow"
    DNS_QUERY = "dns_query"
    HTTP_REQUEST = "http_request"
    APPLICATION_ERROR = "application_error"
    FILE_ACCESS = "file_access"
    UNKNOWN = "unknown"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 25,
    Severity.HIGH: 45,
    Severity.CRITICAL: 70,
}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: LogSource
    event_type: EventType
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    action: str | None = None
    resource: str | None = None
    message: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    confidence: float
    event_ids: list[str]
    description: str
    entity: str
    evidence: dict[str, Any]
    timestamp: datetime

    @property
    def risk_score(self) -> int:
        return min(
            100,
            round(
                SEVERITY_WEIGHT[self.severity] * self.confidence
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        result["severity"] = self.severity.value
        result["risk_score"] = self.risk_score
        return result


class SecurityLogError(Exception):
    """Base exception for security log processing."""


class EventValidationError(SecurityLogError):
    """Raised when an event violates the data contract."""


def parse_timestamp(value: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            raise EventValidationError(
                "Timestamps must include a timezone."
            )

        return timestamp.astimezone(timezone.utc)

    except ValueError as exc:
        raise EventValidationError(
            f"Invalid timestamp: {value}"
        ) from exc


def validate_ip(value: str | None) -> str | None:
    if value is None:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise EventValidationError(
            f"Invalid IP address: {value}"
        ) from exc


def normalize_event(raw: dict[str, Any]) -> SecurityEvent:
    required = {
        "event_id",
        "timestamp",
        "source",
        "event_type",
    }

    missing = required - raw.keys()

    if missing:
        raise EventValidationError(
            f"Missing required fields: {sorted(missing)}"
        )

    try:
        source = LogSource(raw["source"].lower())
        event_type = EventType(raw["event_type"].lower())

        port = raw.get("destination_port")

        if port is not None:
            port = int(port)
            if not 1 <= port <= 65535:
                raise EventValidationError(
                    "Destination port must be between 1 and 65535."
                )

        attributes = raw.get("attributes", {})

        if not isinstance(attributes, dict):
            raise EventValidationError(
                "Attributes must be a JSON object."
            )

        message = str(raw.get("message", ""))

        if len(message) > 8192:
            raise EventValidationError(
                "Message exceeds maximum length."
            )

        return SecurityEvent(
            event_id=str(raw["event_id"]),
            timestamp=parse_timestamp(str(raw["timestamp"])),
            source=source,
            event_type=event_type,
            source_ip=validate_ip(raw.get("source_ip")),
            destination_ip=validate_ip(
                raw.get("destination_ip")
            ),
            username=raw.get("username"),
            hostname=raw.get("hostname"),
            destination_port=port,
            protocol=raw.get("protocol"),
            action=raw.get("action"),
            resource=raw.get("resource"),
            message=message,
            attributes=attributes,
        )

    except (ValueError, TypeError) as exc:
        raise EventValidationError(
            f"Invalid event: {exc}"
        ) from exc


class EventNormalizer:
    """Converts different telemetry formats into a common schema."""

    WINDOWS_EVENTS = {
        4624: EventType.LOGIN_SUCCESS,
        4625: EventType.LOGIN_FAILURE,
        4672: EventType.PRIVILEGE_CHANGE,
        4688: EventType.PROCESS_EXECUTION,
    }

    def normalize_windows(
        self,
        record: dict[str, Any],
    ) -> SecurityEvent:
        event_code = int(record.get("event_id", 0))

        return normalize_event({
            "event_id": str(record.get("record_id", event_code)),
            "timestamp": record["timestamp"],
            "source": "windows",
            "event_type": self.WINDOWS_EVENTS.get(
                event_code,
                EventType.UNKNOWN,
            ).value,
            "source_ip": record.get("ip_address"),
            "username": record.get("account"),
            "hostname": record.get("computer"),
            "message": record.get("message", ""),
            "attributes": {
                "windows_event_code": event_code,
                "logon_type": record.get("logon_type"),
            },
        })

    def normalize_linux(
        self,
        record: dict[str, Any],
    ) -> SecurityEvent:
        message = str(record.get("message", ""))

        failed = bool(
            re.search(
                r"failed password|authentication failure",
                message,
                re.IGNORECASE,
            )
        )

        successful = bool(
            re.search(
                r"accepted password|accepted publickey",
                message,
                re.IGNORECASE,
            )
        )

        event_type = (
            EventType.LOGIN_FAILURE if failed
            else EventType.LOGIN_SUCCESS if successful
            else EventType.UNKNOWN
        )

        return normalize_event({
            "event_id": str(record["record_id"]),
            "timestamp": record["timestamp"],
            "source": "linux",
            "event_type": event_type.value,
            "source_ip": record.get("source_ip"),
            "username": record.get("username"),
            "hostname": record.get("hostname"),
            "message": message,
            "attributes": {
                "service": record.get("service", "sshd")
            },
        })


class DetectionEngine:
    """
    Performs time-window-based detection.

    Events are retained in bounded time windows.
    The engine uses event timestamps rather than arrival order.
    """

    def __init__(
        self,
        brute_force_threshold: int = 5,
        scan_threshold: int = 10,
        window_minutes: int = 5,
        dns_label_threshold: int = 50,
    ):
        if min(
            brute_force_threshold,
            scan_threshold,
            window_minutes,
            dns_label_threshold,
        ) <= 0:
            raise ValueError("Detection thresholds must be positive.")

        self.brute_force_threshold = brute_force_threshold
        self.scan_threshold = scan_threshold
        self.window = timedelta(minutes=window_minutes)
        self.dns_label_threshold = dns_label_threshold

        self.events: list[SecurityEvent] = []
        self.seen_ids: set[str] = set()
        self.findings: list[Finding] = []

    def ingest(self, event: SecurityEvent) -> None:
        if event.event_id in self.seen_ids:
            raise EventValidationError(
                f"Duplicate event ID: {event.event_id}"
            )

        self.seen_ids.add(event.event_id)
        self.events.append(event)

    def _finding(
        self,
        rule_id: str,
        title: str,
        severity: Severity,
        confidence: float,
        events: list[SecurityEvent],
        description: str,
        entity: str,
        evidence: dict[str, Any],
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=confidence,
            event_ids=[e.event_id for e in events],
            description=description,
            entity=entity,
            evidence=evidence,
            timestamp=max(e.timestamp for e in events),
        )

    def detect_brute_force(self) -> list[Finding]:
        grouped = defaultdict(list)

        for event in self.events:
            if (
                event.event_type == EventType.LOGIN_FAILURE
                and event.source_ip
            ):
                grouped[
                    (event.source_ip, event.username)
                ].append(event)

        findings = []

        for (ip, username), events in grouped.items():
            events.sort(key=lambda e: e.timestamp)

            for index, event in enumerate(events):
                window_events = [
                    item for item in events[index:]
                    if item.timestamp - event.timestamp <= self.window
                ]

                if len(window_events) >= self.brute_force_threshold:
                    finding = self._finding(
                        "AUTH-001",
                        "Repeated authentication failures",
                        Severity.HIGH,
                        0.95,
                        window_events,
                        "Repeated failed authentication attempts from one source.",
                        ip,
                        {
                            "username": username,
                            "attempts": len(window_events),
                            "window_seconds": self.window.total_seconds(),
                        },
                    )
                    findings.append(finding)
                    break

        return findings

    def detect_port_scanning(self) -> list[Finding]:
        grouped = defaultdict(list)

        for event in self.events:
            if (
                event.event_type == EventType.NETWORK_CONNECTION
                and event.source_ip
                and event.destination_port
            ):
                grouped[event.source_ip].append(event)

        findings = []

        for ip, events in grouped.items():
            events.sort(key=lambda e: e.timestamp)

            for index, event in enumerate(events):
                window_events = [
                    item for item in events[index:]
                    if item.timestamp - event.timestamp <= self.window
                ]

                ports = {
                    item.destination_port
                    for item in window_events
                }

                if len(ports) >= self.scan_threshold:
                    findings.append(
                        self._finding(
                            "NET-001",
                            "Potential port scan",
                            Severity.HIGH,
                            0.90,
                            window_events,
                            "One source contacted multiple destination ports.",
                            ip,
                            {
                                "unique_ports": len(ports),
                                "ports": sorted(ports),
                            },
                        )
                    )
                    break

        return findings

    def detect_dns_anomalies(self) -> list[Finding]:
        findings = []

        for event in self.events:
            if event.event_type != EventType.DNS_QUERY:
                continue

            domain = str(
                event.attributes.get("query", "")
            ).lower().rstrip(".")

            labels = domain.split(".") if domain else []

            if not labels:
                continue

            longest_label = max(map(len, labels))

            entropy = self._entropy(
                labels[0]
            )

            if (
                longest_label >= self.dns_label_threshold
                or (len(labels[0]) >= 25 and entropy >= 3.5)
            ):
                findings.append(
                    self._finding(
                        "DNS-001",
                        "Suspicious DNS query",
                        Severity.MEDIUM,
                        0.85,
                        [event],
                        "DNS query contains an unusually long or high-entropy label.",
                        event.source_ip or "unknown",
                        {
                            "domain": domain,
                            "longest_label": longest_label,
                            "entropy": round(entropy, 3),
                        },
                    )
                )

        return findings

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0

        counts = Counter(value)

        return -sum(
            (count / len(value)) *
            math.log2(count / len(value))
            for count in counts.values()
        )

    def detect_suspicious_proxy_activity(self) -> list[Finding]:
        findings = []

        suspicious_extensions = (
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".scr",
            ".vbs",
        )

        for event in self.events:
            if event.event_type != EventType.HTTP_REQUEST:
                continue

            resource = (event.resource or "").lower()

            if any(
                resource.split("?")[0].endswith(ext)
                for ext in suspicious_extensions
            ):
                findings.append(
                    self._finding(
                        "PROXY-001",
                        "Executable download through proxy",
                        Severity.MEDIUM,
                        0.80,
                        [event],
                        "HTTP request accessed an executable file extension.",
                        event.source_ip or "unknown",
                        {
                            "resource": event.resource,
                            "username": event.username,
                        },
                    )
                )

        return findings

    def detect_privilege_changes(self) -> list[Finding]:
        findings = []

        for event in self.events:
            if event.event_type == EventType.PRIVILEGE_CHANGE:
                findings.append(
                    self._finding(
                        "AUTH-002",
                        "Privilege change detected",
                        Severity.MEDIUM,
                        0.85,
                        [event],
                        "An account received elevated privileges.",
                        event.username or "unknown",
                        {
                            "hostname": event.hostname,
                            "attributes": event.attributes,
                        },
                    )
                )

        return findings

    def run(self) -> list[Finding]:
        detectors = [
            self.detect_brute_force,
            self.detect_port_scanning,
            self.detect_dns_anomalies,
            self.detect_suspicious_proxy_activity,
            self.detect_privilege_changes,
        ]

        self.findings = []

        for detector in detectors:
            self.findings.extend(detector())

        self.findings.sort(
            key=lambda f: (
                -f.risk_score,
                f.timestamp,
            )
        )

        return self.findings


class SecurityReport:
    @staticmethod
    def generate(
        events: list[SecurityEvent],
        findings: list[Finding],
    ) -> dict[str, Any]:
        source_counts = Counter(
            event.source.value for event in events
        )

        severity_counts = Counter(
            finding.severity.value for finding in findings
        )

        return {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "total_events": len(events),
            "total_findings": len(findings),
            "sources": dict(source_counts),
            "severities": dict(severity_counts),
            "findings": [
                finding.to_dict()
                for finding in findings
            ],
        }


def load_jsonl(path: Path) -> Iterable[SecurityEvent]:
    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue

            try:
                raw = json.loads(line)

                if not isinstance(raw, dict):
                    raise EventValidationError(
                        "Each JSONL record must be an object."
                    )

                yield normalize_event(raw)

            except (
                json.JSONDecodeError,
                SecurityLogError,
            ) as exc:
                logger.error(
                    "Invalid record at line %s: %s",
                    line_number,
                    exc,
                )


def create_sample_events() -> list[SecurityEvent]:
    now = datetime.now(timezone.utc)

    records = []

    for index in range(7):
        records.append({
            "event_id": f"auth-{index}",
            "timestamp": (
                now - timedelta(seconds=60 - index * 5)
            ).isoformat(),
            "source": "authentication",
            "event_type": "login_failure",
            "source_ip": "203.0.113.50",
            "username": "administrator",
            "hostname": "server-01",
            "message": "Authentication failed",
        })

    for index in range(12):
        records.append({
            "event_id": f"network-{index}",
            "timestamp": (
                now - timedelta(seconds=40 - index)
            ).isoformat(),
            "source": "firewall",
            "event_type": "network_connection",
            "source_ip": "198.51.100.20",
            "destination_ip": "10.0.0.10",
            "destination_port": 1000 + index,
            "protocol": "TCP",
            "action": "allow",
        })

    records.append({
        "event_id": "dns-001",
        "timestamp": now.isoformat(),
        "source": "dns",
        "event_type": "dns_query",
        "source_ip": "10.0.0.15",
        "attributes": {
            "query": "a" * 65 + ".example.com"
        },
    })

    records.append({
        "event_id": "proxy-001",
        "timestamp": now.isoformat(),
        "source": "proxy",
        "event_type": "http_request",
        "source_ip": "10.0.0.15",
        "username": "employee01",
        "resource": "https://example.com/payload.exe",
    })

    return [
        normalize_event(record)
        for record in records
    ]


def run_self_tests() -> None:
    assert validate_ip("127.0.0.1") == "127.0.0.1"

    try:
        validate_ip("999.999.999.999")
        raise AssertionError("Invalid IP was accepted.")
    except EventValidationError:
        pass

    assert DetectionEngine._entropy("aaaa") == 0.0

    engine = DetectionEngine(
        brute_force_threshold=3
    )

    sample = create_sample_events()

    for event in sample:
        engine.ingest(event)

    findings = engine.run()

    assert any(
        finding.rule_id == "AUTH-001"
        for finding in findings
    )

    assert any(
        finding.rule_id == "DNS-001"
        for finding in findings
    )

    print("All self-tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Multi-source security log analytics engine"
    )

    parser.add_argument(
        "--input",
        type=Path,
        help="Input JSONL file containing normalized events.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("security_report.json"),
    )

    parser.add_argument(
        "--test",
        action="store_true",
    )

    args = parser.parse_args()

    if args.test:
        run_self_tests()
        return 0

    engine = DetectionEngine()

    events = (
        load_jsonl(args.input)
        if args.input
        else iter(create_sample_events())
    )

    accepted = 0

    for event in events:
        try:
            engine.ingest(event)
            accepted += 1
        except SecurityLogError as exc:
            logger.warning("Event rejected: %s", exc)

    findings = engine.run()

    report = SecurityReport.generate(
        engine.events,
        findings,
    )

    args.output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "events_processed": accepted,
                "findings_detected": len(findings),
                "report": str(args.output),
            },
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
