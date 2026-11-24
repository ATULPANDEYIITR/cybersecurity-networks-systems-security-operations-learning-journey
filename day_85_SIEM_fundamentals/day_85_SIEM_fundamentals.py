#!/usr/bin/env python3
"""
SIEM FUNDAMENTALS
Events, Fields, Indexes, Searches, Correlation, and Alerts

A self-contained Security Information and Event Management simulator.
Python 3.10+
Uses only the Python standard library.
"""

from __future__ import annotations

import json
import re
import hashlib
import logging
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable, Optional


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("siem")


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    FIREWALL = "firewall"
    DNS = "dns"


class AlertStatus(str, Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: str
    category: EventCategory
    event_type: str
    severity: Severity
    fields: dict[str, Any]

    def __post_init__(self):
        if not self.event_id or len(self.event_id) > 128:
            raise ValueError("Invalid event ID")

        if self.timestamp.tzinfo is None:
            raise ValueError("Timestamp must include timezone")

        if not self.source.strip():
            raise ValueError("Event source cannot be empty")

        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", self.event_type):
            raise ValueError("Invalid event type")

        if not isinstance(self.fields, dict):
            raise ValueError("Event fields must be a dictionary")

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "category": self.category.value,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "fields": self.fields,
        }


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    title: str
    severity: Severity
    created_at: datetime
    event_ids: list[str]
    description: str
    status: AlertStatus = AlertStatus.NEW
    assigned_to: Optional[str] = None

    def transition(self, new_status: AlertStatus):
        transitions = {
            AlertStatus.NEW: {
                AlertStatus.ACKNOWLEDGED,
                AlertStatus.FALSE_POSITIVE,
            },
            AlertStatus.ACKNOWLEDGED: {
                AlertStatus.INVESTIGATING,
                AlertStatus.RESOLVED,
                AlertStatus.FALSE_POSITIVE,
            },
            AlertStatus.INVESTIGATING: {
                AlertStatus.RESOLVED,
                AlertStatus.FALSE_POSITIVE,
            },
            AlertStatus.RESOLVED: set(),
            AlertStatus.FALSE_POSITIVE: set(),
        }

        if new_status not in transitions[self.status]:
            raise ValueError(
                f"Invalid alert transition: {self.status} -> {new_status}"
            )

        self.status = new_status


@dataclass(frozen=True)
class SearchResult:
    events: tuple[SecurityEvent, ...]
    total: int
    execution_ms: float


@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    window_seconds: int
    threshold: int
    severity: Severity
    event_type: str
    group_field: str

    def __post_init__(self):
        if self.window_seconds <= 0 or self.threshold <= 0:
            raise ValueError("Window and threshold must be positive")


class SIEMEngine:
    """
    In-memory SIEM engine.

    Event ingestion:
        Validate -> Normalize -> Deduplicate -> Store -> Index.

    Search:
        Candidate selection using indexes -> Filtering -> Results.

    Correlation:
        Group related events -> Evaluate threshold -> Generate alert.
    """

    def __init__(self):
        self.events: dict[str, SecurityEvent] = {}

        # Equality indexes support fast candidate selection.
        self.indexes: dict[str, dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )

        self.alerts: dict[str, Alert] = {}
        self.rules: dict[str, CorrelationRule] = {}
        self.processed_rule_windows: set[tuple] = set()

        self.ingestion_count = 0
        self.duplicate_count = 0

    @staticmethod
    def normalize_field(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            return json.dumps(value, sort_keys=True)
        return str(value).strip().lower()

    def ingest(self, event: SecurityEvent) -> bool:
        """Ingest an event once, preserving its original identifier."""

        if event.event_id in self.events:
            self.duplicate_count += 1
            return False

        # Reject excessively large or deeply nested event payloads.
        serialized = json.dumps(event.to_dict(), default=str)
        if len(serialized.encode("utf-8")) > 65536:
            raise ValueError("Event exceeds 64 KB ingestion limit")

        self.events[event.event_id] = event

        searchable = {
            "source": event.source,
            "category": event.category.value,
            "event_type": event.event_type,
            "severity": event.severity.value,
            **event.fields,
        }

        for field_name, value in searchable.items():
            normalized = self.normalize_field(value)
            self.indexes[field_name][normalized].add(event.event_id)

        self.ingestion_count += 1
        return True

    def ingest_json(self, raw: str) -> bool:
        """Parse and validate a JSON security event."""

        if len(raw.encode("utf-8")) > 65536:
            raise ValueError("Input exceeds ingestion size limit")

        try:
            data = json.loads(raw)

            if not isinstance(data, dict):
                raise ValueError("Event must be a JSON object")

            required = {
                "event_id",
                "timestamp",
                "source",
                "category",
                "event_type",
                "severity",
                "fields",
            }

            if not required.issubset(data):
                raise ValueError("Missing required event properties")

            event = SecurityEvent(
                event_id=str(data["event_id"]),
                timestamp=datetime.fromisoformat(
                    data["timestamp"].replace("Z", "+00:00")
                ),
                source=str(data["source"]),
                category=EventCategory(data["category"]),
                event_type=str(data["event_type"]),
                severity=Severity(data["severity"]),
                fields=data["fields"],
            )

            return self.ingest(event)

        except (json.JSONDecodeError, TypeError, KeyError) as exc:
            raise ValueError(f"Invalid event JSON: {exc}") from exc

    def search(
        self,
        field_name: Optional[str] = None,
        value: Optional[Any] = None,
        category: Optional[EventCategory] = None,
        severity: Optional[Severity] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> SearchResult:
        """
        Search using an equality index when available.

        The final filtering stage guarantees that index candidates
        satisfy all supplied conditions.
        """

        if not 1 <= limit <= 10000:
            raise ValueError("Search limit must be between 1 and 10000")

        if start_time and end_time and start_time > end_time:
            raise ValueError("Start time cannot exceed end time")

        import time
        started = time.perf_counter()

        candidates: Optional[set[str]] = None

        if field_name is not None and value is not None:
            key = self.normalize_field(value)
            candidates = set(
                self.indexes.get(field_name, {}).get(key, set())
            )

        if category is not None:
            ids = set(
                self.indexes["category"].get(category.value, set())
            )
            candidates = ids if candidates is None else candidates & ids

        if severity is not None:
            ids = set(
                self.indexes["severity"].get(severity.value, set())
            )
            candidates = ids if candidates is None else candidates & ids

        if candidates is None:
            candidates = set(self.events)

        matching = []

        for event_id in candidates:
            event = self.events[event_id]

            if start_time and event.timestamp < start_time:
                continue

            if end_time and event.timestamp > end_time:
                continue

            if field_name is not None:
                actual = (
                    getattr(event, field_name)
                    if hasattr(event, field_name)
                    else event.fields.get(field_name)
                )

                if actual is None:
                    continue

                if self.normalize_field(actual) != self.normalize_field(value):
                    continue

            matching.append(event)

        matching.sort(
            key=lambda item: (item.timestamp, item.event_id),
            reverse=True,
        )

        elapsed = (time.perf_counter() - started) * 1000

        return SearchResult(
            events=tuple(matching[:limit]),
            total=len(matching),
            execution_ms=elapsed,
        )

    def add_rule(self, rule: CorrelationRule):
        if rule.rule_id in self.rules:
            raise ValueError("Correlation rule already exists")

        self.rules[rule.rule_id] = rule

    def correlate(self, now: Optional[datetime] = None) -> list[Alert]:
        """
        Detect threshold-based activity within rolling time windows.

        Events are grouped by the configured field, such as source IP.
        A deterministic alert ID prevents duplicate alert creation
        for the same rule, grouping key and time window.
        """

        now = now or datetime.now(timezone.utc)

        if now.tzinfo is None:
            raise ValueError("Correlation time must be timezone-aware")

        generated = []

        for rule in self.rules.values():
            start = now - timedelta(seconds=rule.window_seconds)

            candidates = self.search(
                field_name="event_type",
                value=rule.event_type,
                start_time=start,
                end_time=now,
                limit=10000,
            )

            groups: dict[str, list[SecurityEvent]] = defaultdict(list)

            for event in candidates.events:
                group_value = event.fields.get(rule.group_field)

                if group_value is None:
                    continue

                groups[self.normalize_field(group_value)].append(event)

            for group_key, events in groups.items():
                if len(events) < rule.threshold:
                    continue

                bucket = int(now.timestamp()) // rule.window_seconds
                fingerprint = (
                    rule.rule_id,
                    group_key,
                    bucket,
                )

                if fingerprint in self.processed_rule_windows:
                    continue

                event_ids = sorted(e.event_id for e in events)

                raw_id = "|".join([
                    rule.rule_id,
                    group_key,
                    str(bucket),
                ])

                alert_id = hashlib.sha256(
                    raw_id.encode("utf-8")
                ).hexdigest()[:24]

                alert = Alert(
                    alert_id=alert_id,
                    rule_id=rule.rule_id,
                    title=rule.name,
                    severity=rule.severity,
                    created_at=now,
                    event_ids=event_ids,
                    description=(
                        f"{len(events)} events of type "
                        f"{rule.event_type} observed for "
                        f"{rule.group_field}={group_key} "
                        f"within {rule.window_seconds} seconds."
                    ),
                )

                self.alerts[alert_id] = alert
                self.processed_rule_windows.add(fingerprint)
                generated.append(alert)

        return generated

    def update_alert(
        self,
        alert_id: str,
        status: AlertStatus,
        analyst: Optional[str] = None,
    ):
        alert = self.alerts.get(alert_id)

        if alert is None:
            raise KeyError("Alert does not exist")

        if analyst is not None:
            if not analyst.strip() or len(analyst) > 100:
                raise ValueError("Invalid analyst identity")
            alert.assigned_to = analyst

        alert.transition(status)

    def statistics(self) -> dict:
        severity_counts = Counter(
            event.severity.value for event in self.events.values()
        )

        category_counts = Counter(
            event.category.value for event in self.events.values()
        )

        return {
            "total_events": len(self.events),
            "total_alerts": len(self.alerts),
            "ingestion_count": self.ingestion_count,
            "duplicate_count": self.duplicate_count,
            "severity_distribution": dict(severity_counts),
            "category_distribution": dict(category_counts),
            "alert_status_distribution": dict(
                Counter(a.status.value for a in self.alerts.values())
            ),
        }

    def export_alerts(self, filename: str):
        """Export alerts without exposing credentials or secrets."""

        output = []

        for alert in self.alerts.values():
            output.append({
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "title": alert.title,
                "severity": alert.severity.value,
                "created_at": alert.created_at.isoformat(),
                "event_ids": alert.event_ids,
                "description": alert.description,
                "status": alert.status.value,
                "assigned_to": alert.assigned_to,
            })

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(output, file, indent=2)


def create_sample_engine() -> SIEMEngine:
    engine = SIEMEngine()

    base = datetime(2026, 11, 24, 6, 0, tzinfo=timezone.utc)

    sample_events = [
        SecurityEvent(
            event_id=f"AUTH-{i}",
            timestamp=base + timedelta(seconds=i * 5),
            source="linux-auth-01",
            category=EventCategory.AUTHENTICATION,
            event_type="failed_login",
            severity=Severity.MEDIUM,
            fields={
                "src_ip": "203.0.113.45",
                "username": "admin",
                "host": "server-01",
                "result": "failure",
                "protocol": "ssh",
            },
        )
        for i in range(1, 7)
    ]

    sample_events.extend([
        SecurityEvent(
            event_id="FW-001",
            timestamp=base + timedelta(seconds=10),
            source="firewall-01",
            category=EventCategory.FIREWALL,
            event_type="blocked_connection",
            severity=Severity.HIGH,
            fields={
                "src_ip": "203.0.113.45",
                "dst_ip": "10.0.0.10",
                "dst_port": 22,
                "action": "blocked",
            },
        ),
        SecurityEvent(
            event_id="DNS-001",
            timestamp=base + timedelta(seconds=20),
            source="dns-01",
            category=EventCategory.DNS,
            event_type="dns_query",
            severity=Severity.INFO,
            fields={
                "src_ip": "10.0.0.15",
                "domain": "example.internal",
                "query_type": "A",
            },
        ),
        SecurityEvent(
            event_id="END-001",
            timestamp=base + timedelta(seconds=30),
            source="edr-01",
            category=EventCategory.ENDPOINT,
            event_type="suspicious_process",
            severity=Severity.HIGH,
            fields={
                "host": "workstation-04",
                "username": "employee01",
                "process": "powershell.exe",
                "action": "suspicious_execution",
            },
        ),
    ])

    for event in sample_events:
        engine.ingest(event)

    engine.add_rule(CorrelationRule(
        rule_id="RULE-001",
        name="SSH Brute Force Detection",
        description="Multiple failed SSH authentication attempts.",
        window_seconds=300,
        threshold=5,
        severity=Severity.CRITICAL,
        event_type="failed_login",
        group_field="src_ip",
    ))

    return engine


def run_tests(engine: SIEMEngine):
    assert len(engine.events) == 9

    duplicate = next(iter(engine.events.values()))
    assert engine.ingest(duplicate) is False

    results = engine.search(
        field_name="src_ip",
        value="203.0.113.45",
        category=EventCategory.AUTHENTICATION,
    )

    assert results.total == 6

    assert engine.search(
        severity=Severity.CRITICAL
    ).total == 0

    alerts = engine.correlate(
        datetime(2026, 11, 24, 6, 1, tzinfo=timezone.utc)
    )

    assert len(alerts) == 1
    assert alerts[0].severity == Severity.CRITICAL

    # Repeated evaluation in the same window must not duplicate alerts.
    assert engine.correlate(
        datetime(2026, 11, 24, 6, 1, tzinfo=timezone.utc)
    ) == []

    alert = alerts[0]
    engine.update_alert(
        alert.alert_id,
        AlertStatus.ACKNOWLEDGED,
        analyst="soc-analyst-01",
    )
    engine.update_alert(
        alert.alert_id,
        AlertStatus.INVESTIGATING,
    )

    assert alert.status == AlertStatus.INVESTIGATING

    try:
        alert.transition(AlertStatus.NEW)
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid alert transition was accepted")

    print("All SIEM validation tests passed.")


def main():
    engine = create_sample_engine()

    run_tests(engine)

    print("\n=== SIEM EVENT SEARCH ===")

    result = engine.search(
        field_name="event_type",
        value="failed_login",
        limit=20,
    )

    for event in result.events:
        print(
            event.event_id,
            event.timestamp.isoformat(),
            event.fields.get("src_ip"),
            event.fields.get("username"),
        )

    print(f"\nMatching events: {result.total}")
    print(f"Search execution: {result.execution_ms:.3f} ms")

    print("\n=== CORRELATION ALERTS ===")

    for alert in engine.alerts.values():
        print(json.dumps({
            "alert_id": alert.alert_id,
            "title": alert.title,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "events": alert.event_ids,
            "description": alert.description,
        }, indent=2))

    print("\n=== SIEM STATISTICS ===")
    print(json.dumps(engine.statistics(), indent=2))


if __name__ == "__main__":
    main()
