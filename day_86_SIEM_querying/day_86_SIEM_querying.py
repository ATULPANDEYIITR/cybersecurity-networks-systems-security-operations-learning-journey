#!/usr/bin/env python3
"""
SIEM Querying Engine
Filtering, aggregation, timelines, field analysis, and security detection.

Python 3.10+
Standard-library only.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("siem")


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    username: str
    event_type: str
    severity: Severity
    action: str
    source: str
    fields: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.event_id.strip():
            raise ValueError("Event ID cannot be empty")

        if self.timestamp.tzinfo is None:
            raise ValueError("Timestamp must include timezone information")

        if self.timestamp.utcoffset() is None:
            raise ValueError("Invalid timestamp timezone")

        if not self.source_ip or not self.destination_ip:
            raise ValueError("Source and destination IP are required")

        if not self.event_type.strip():
            raise ValueError("Event type cannot be empty")

        if not self.username.strip():
            raise ValueError("Username cannot be empty")


def parse_timestamp(value: str) -> datetime:
    """Parse ISO-8601 timestamps and normalize them to UTC."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("Timezone information is required")
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid timestamp: {value}") from exc


class QueryError(Exception):
    """Raised when a SIEM query is invalid."""


class EventStore:
    """In-memory event store with indexed field access."""

    def __init__(self):
        self.events: list[SecurityEvent] = []
        self.ids: set[str] = set()
        self.indexes: dict[str, dict[Any, list[SecurityEvent]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add(self, event: SecurityEvent) -> None:
        if event.event_id in self.ids:
            raise ValueError(f"Duplicate event ID: {event.event_id}")

        self.events.append(event)
        self.ids.add(event.event_id)

        for field_name in (
            "source_ip",
            "destination_ip",
            "username",
            "event_type",
            "severity",
            "action",
            "source",
        ):
            value = getattr(event, field_name)
            self.indexes[field_name][value].append(event)

    def extend(self, events: Iterable[SecurityEvent]) -> None:
        for event in events:
            self.add(event)

    def get_by_field(self, name: str, value: Any) -> list[SecurityEvent]:
        if name not in self.indexes:
            raise QueryError(f"Field is not indexed: {name}")
        return list(self.indexes[name].get(value, []))

    def all(self) -> list[SecurityEvent]:
        return list(self.events)


class SIEMQuery:
    """Composable query engine supporting filtering and time boundaries."""

    ALLOWED_FIELDS = {
        "event_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "username",
        "event_type",
        "severity",
        "action",
        "source",
    }

    OPERATORS = {
        "eq",
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "contains",
        "in",
        "regex",
    }

    def __init__(self, events: Iterable[SecurityEvent]):
        self.events = list(events)

    def where(
        self,
        field_name: str,
        operator: str,
        value: Any
    ) -> SIEMQuery:
        if field_name not in self.ALLOWED_FIELDS:
            raise QueryError(f"Unsupported field: {field_name}")

        if operator not in self.OPERATORS:
            raise QueryError(f"Unsupported operator: {operator}")

        if operator == "regex":
            if not isinstance(value, str) or len(value) > 200:
                raise QueryError("Invalid regular expression")
            try:
                pattern = re.compile(value)
            except re.error as exc:
                raise QueryError("Malformed regular expression") from exc

        def matches(event: SecurityEvent) -> bool:
            actual = getattr(event, field_name)

            if isinstance(actual, Enum):
                actual = actual.value

            expected = value.value if isinstance(value, Enum) else value

            if operator == "eq":
                return actual == expected
            if operator == "ne":
                return actual != expected
            if operator == "gt":
                return actual > expected
            if operator == "gte":
                return actual >= expected
            if operator == "lt":
                return actual < expected
            if operator == "lte":
                return actual <= expected
            if operator == "contains":
                return str(expected).lower() in str(actual).lower()
            if operator == "in":
                return actual in expected
            if operator == "regex":
                return bool(pattern.search(str(actual)))

            return False

        self.events = [event for event in self.events if matches(event)]
        return self

    def time_range(
        self,
        start: datetime,
        end: datetime
    ) -> SIEMQuery:
        if start.tzinfo is None or end.tzinfo is None:
            raise QueryError("Time boundaries must be timezone-aware")

        if start > end:
            raise QueryError("Start time must precede end time")

        self.events = [
            event for event in self.events
            if start <= event.timestamp <= end
        ]
        return self

    def results(self) -> list[SecurityEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)

    def count(self) -> int:
        return len(self.events)


class SIEMAnalytics:
    """Aggregation, timeline, and field analysis."""

    @staticmethod
    def aggregate(
        events: Iterable[SecurityEvent],
        field_name: str
    ) -> dict[str, int]:
        if field_name not in SIEMQuery.ALLOWED_FIELDS:
            raise QueryError(f"Unsupported aggregation field: {field_name}")

        counts = Counter()
        for event in events:
            value = getattr(event, field_name)
            if isinstance(value, Enum):
                value = value.value
            counts[str(value)] += 1

        return dict(counts.most_common())

    @staticmethod
    def timeline(
        events: Iterable[SecurityEvent],
        interval_minutes: int = 5
    ) -> dict[str, int]:
        if not 1 <= interval_minutes <= 1440:
            raise ValueError("Interval must be between 1 and 1440 minutes")

        buckets = Counter()

        for event in events:
            timestamp = event.timestamp.astimezone(timezone.utc)
            minute = (
                timestamp.minute // interval_minutes
            ) * interval_minutes

            bucket = timestamp.replace(
                minute=minute,
                second=0,
                microsecond=0
            )
            buckets[bucket.isoformat()] += 1

        return dict(sorted(buckets.items()))

    @staticmethod
    def field_analysis(
        events: Iterable[SecurityEvent]
    ) -> dict[str, Any]:
        records = list(events)

        fields = [
            "source_ip",
            "destination_ip",
            "username",
            "event_type",
            "severity",
            "action",
            "source",
        ]

        analysis = {}

        for field_name in fields:
            values = [
                str(getattr(event, field_name).value)
                if isinstance(getattr(event, field_name), Enum)
                else str(getattr(event, field_name))
                for event in records
            ]

            frequencies = Counter(values)

            analysis[field_name] = {
                "unique_values": len(frequencies),
                "most_common": frequencies.most_common(5),
                "null_values": 0,
            }

        return analysis

    @staticmethod
    def severity_summary(
        events: Iterable[SecurityEvent]
    ) -> dict[str, int]:
        counts = Counter(event.severity.value for event in events)

        return {
            severity.value: counts.get(severity.value, 0)
            for severity in Severity
        }

    @staticmethod
    def failed_login_detection(
        events: Iterable[SecurityEvent],
        threshold: int = 5,
        window_minutes: int = 10,
    ) -> list[dict[str, Any]]:
        """
        Detect repeated failed authentication attempts.
        Uses a sliding window per source IP and username.
        """
        if threshold < 1 or window_minutes < 1:
            raise ValueError("Threshold and window must be positive")

        failed = sorted(
            [
                event for event in events
                if event.event_type == "authentication"
                and event.action == "failure"
            ],
            key=lambda event: event.timestamp
        )

        groups = defaultdict(list)

        for event in failed:
            groups[(event.source_ip, event.username)].append(event)

        alerts = []
        window = timedelta(minutes=window_minutes)

        for (source_ip, username), records in groups.items():
            left = 0

            for right, current in enumerate(records):
                while (
                    current.timestamp - records[left].timestamp > window
                ):
                    left += 1

                count = right - left + 1

                if count == threshold:
                    alerts.append({
                        "source_ip": source_ip,
                        "username": username,
                        "attempts": count,
                        "window_minutes": window_minutes,
                        "first_seen": records[left].timestamp.isoformat(),
                        "last_seen": current.timestamp.isoformat(),
                        "severity": "HIGH",
                    })

        return alerts


def load_events(path: Path) -> list[SecurityEvent]:
    """Load newline-delimited JSON events with strict validation."""
    events = []

    if not path.is_file():
        raise FileNotFoundError(path)

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)

                event = SecurityEvent(
                    event_id=str(record["event_id"]),
                    timestamp=parse_timestamp(record["timestamp"]),
                    source_ip=str(record["source_ip"]),
                    destination_ip=str(record["destination_ip"]),
                    username=str(record["username"]),
                    event_type=str(record["event_type"]),
                    severity=Severity(record["severity"].upper()),
                    action=str(record["action"]),
                    source=str(record["source"]),
                    fields=record.get("fields", {}),
                )

                events.append(event)

            except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Invalid event at line {line_number}: {exc}"
                ) from exc

    return events


def sample_events() -> list[SecurityEvent]:
    base = datetime(2026, 11, 25, 2, 30, tzinfo=timezone.utc)

    records = [
        ("E001", 0, "192.168.1.10", "10.0.0.5", "admin",
         "authentication", Severity.HIGH, "failure", "firewall"),
        ("E002", 1, "192.168.1.10", "10.0.0.5", "admin",
         "authentication", Severity.HIGH, "failure", "firewall"),
        ("E003", 2, "192.168.1.10", "10.0.0.5", "admin",
         "authentication", Severity.HIGH, "failure", "firewall"),
        ("E004", 3, "192.168.1.10", "10.0.0.5", "admin",
         "authentication", Severity.HIGH, "failure", "firewall"),
        ("E005", 4, "192.168.1.10", "10.0.0.5", "admin",
         "authentication", Severity.HIGH, "failure", "firewall"),
        ("E006", 5, "192.168.1.10", "10.0.0.5", "admin",
         "authentication", Severity.INFO, "success", "firewall"),
        ("E007", 6, "10.10.1.20", "10.0.0.8", "analyst",
         "network", Severity.MEDIUM, "blocked", "ids"),
        ("E008", 7, "10.10.1.20", "10.0.0.8", "analyst",
         "network", Severity.CRITICAL, "blocked", "ids"),
        ("E009", 8, "172.16.0.25", "10.0.0.9", "service_account",
         "process", Severity.LOW, "executed", "endpoint"),
        ("E010", 12, "192.168.1.15", "10.0.0.5", "user01",
         "authentication", Severity.INFO, "success", "firewall"),
    ]

    return [
        SecurityEvent(
            event_id=event_id,
            timestamp=base + timedelta(minutes=minute),
            source_ip=source,
            destination_ip=destination,
            username=username,
            event_type=event_type,
            severity=severity,
            action=action,
            source=origin,
        )
        for (
            event_id, minute, source, destination, username,
            event_type, severity, action, origin
        ) in records
    ]


def export_report(report: dict[str, Any], output: Path) -> None:
    """Write a JSON report without exposing credentials or raw secrets."""
    output.parent.mkdir(parents=True, exist_ok=True)

    temporary = output.with_suffix(output.suffix + ".tmp")

    try:
        temporary.write_text(
            json.dumps(report, indent=2, default=str),
            encoding="utf-8"
        )
        temporary.replace(output)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def run_demo(events: list[SecurityEvent]) -> dict[str, Any]:
    store = EventStore()
    store.extend(events)

    query = SIEMQuery(store.all())

    suspicious = (
        query
        .where("severity", "in", ["HIGH", "CRITICAL"])
        .results()
    )

    analytics = SIEMAnalytics()

    report = {
        "total_events": len(events),
        "high_severity_events": len(suspicious),
        "severity_distribution": analytics.severity_summary(events),
        "event_type_distribution": analytics.aggregate(
            events, "event_type"
        ),
        "source_ip_distribution": analytics.aggregate(
            events, "source_ip"
        ),
        "timeline": analytics.timeline(events, 5),
        "field_analysis": analytics.field_analysis(events),
        "failed_login_alerts": analytics.failed_login_detection(
            events, threshold=5, window_minutes=10
        ),
    }

    print("\n=== SIEM QUERY REPORT ===")
    print(json.dumps(report, indent=2))

    return report


def run_tests() -> None:
    events = sample_events()

    assert len(events) == 10

    high = SIEMQuery(events).where(
        "severity", "in", ["HIGH", "CRITICAL"]
    ).results()

    assert len(high) == 6

    failed = SIEMQuery(events).where(
        "action", "eq", "failure"
    ).count()

    assert failed == 5

    alerts = SIEMAnalytics.failed_login_detection(events)
    assert len(alerts) == 1
    assert alerts[0]["attempts"] == 5

    assert len(SIEMAnalytics.timeline(events, 5)) > 0

    try:
        SIEMQuery(events).where("password", "eq", "secret")
        raise AssertionError("Invalid field was accepted")
    except QueryError:
        pass

    try:
        SIEMQuery(events).where("severity", "unknown", "HIGH")
        raise AssertionError("Invalid operator was accepted")
    except QueryError:
        pass

    try:
        EventStore().add(events[0])
        store = EventStore()
        store.add(events[0])
        store.add(events[0])
        raise AssertionError("Duplicate event was accepted")
    except ValueError:
        pass

    print("All tests passed.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SIEM filtering, aggregation, and threat analysis"
    )

    parser.add_argument(
        "--input",
        type=Path,
        help="Path to newline-delimited JSON security events"
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("siem_report.json"),
        help="JSON report output path"
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="Execute built-in validation tests"
    )

    args = parser.parse_args()

    try:
        if args.test:
            run_tests()
            return

        events = load_events(args.input) if args.input else sample_events()

        report = run_demo(events)
        export_report(report, args.output)

        logger.info("Report saved to %s", args.output)

    except (ValueError, OSError, QueryError) as exc:
        logger.error("SIEM execution failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
