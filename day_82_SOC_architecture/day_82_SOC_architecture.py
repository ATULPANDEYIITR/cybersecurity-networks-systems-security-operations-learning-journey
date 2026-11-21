#!/usr/bin/env python3
"""
SOC Architecture: Data Sources, Collectors, Parsers, Storage,
Correlation, and Dashboards.

A self-contained Security Operations Center event-processing simulation.
Compatible with Python 3.10+.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Iterable, Optional


# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("soc")


# ------------------------------------------------------------
# Domain types
# ------------------------------------------------------------

class EventSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK = "NETWORK"
    ENDPOINT = "ENDPOINT"
    APPLICATION = "APPLICATION"
    CLOUD = "CLOUD"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"


class CollectorStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class DataSource:
    source_id: str
    name: str
    source_type: str
    environment: str
    enabled: bool = True


@dataclass
class RawEvent:
    source_id: str
    payload: str
    received_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass
class SecurityEvent:
    event_id: str
    source_id: str
    timestamp: datetime
    category: EventCategory
    severity: EventSeverity
    event_type: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    hostname: Optional[str]
    message: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAlert:
    alert_id: str
    title: str
    severity: EventSeverity
    event_ids: list[str]
    description: str
    created_at: datetime
    status: AlertStatus = AlertStatus.OPEN


# ------------------------------------------------------------
# Data source registry
# ------------------------------------------------------------

class DataSourceRegistry:

    def __init__(self) -> None:
        self._sources: dict[str, DataSource] = {}

    def register(self, source: DataSource) -> None:
        if not source.source_id.strip():
            raise ValueError("Source ID cannot be empty")

        if source.source_id in self._sources:
            raise ValueError("Data source already registered")

        self._sources[source.source_id] = source

    def get(self, source_id: str) -> DataSource:
        try:
            return self._sources[source_id]
        except KeyError:
            raise ValueError(f"Unknown data source: {source_id}") from None

    def enabled_sources(self) -> list[DataSource]:
        return [s for s in self._sources.values() if s.enabled]


# ------------------------------------------------------------
# Collectors
# ------------------------------------------------------------

class EventCollector:

    def __init__(self, registry: DataSourceRegistry) -> None:
        self.registry = registry
        self.status: dict[str, CollectorStatus] = {}
        self.buffer: deque[RawEvent] = deque(maxlen=10000)
        self.dropped_events = 0

    def collect(self, source_id: str, payload: str) -> bool:
        source = self.registry.get(source_id)

        if not source.enabled:
            self.dropped_events += 1
            return False

        if not isinstance(payload, str) or not payload.strip():
            raise ValueError("Empty event payload")

        if len(payload.encode("utf-8")) > 65536:
            self.dropped_events += 1
            raise ValueError("Event exceeds maximum payload size")

        if len(self.buffer) == self.buffer.maxlen:
            self.dropped_events += 1
            self.status[source_id] = CollectorStatus.DEGRADED
            return False

        self.buffer.append(RawEvent(source_id, payload))
        self.status[source_id] = CollectorStatus.ACTIVE
        return True

    def batch(self, limit: int = 100) -> list[RawEvent]:
        if limit <= 0:
            raise ValueError("Batch limit must be positive")

        return [self.buffer.popleft() for _ in range(min(limit, len(self.buffer)))]


# ------------------------------------------------------------
# Parsers
# ------------------------------------------------------------

class EventParser:

    IP_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
    )

    @staticmethod
    def _optional_ip(value: Any) -> Optional[str]:
        if value is None:
            return None

        if not isinstance(value, str) or not EventParser.IP_PATTERN.fullmatch(value):
            raise ValueError("Invalid IPv4 address")

        return value

    @staticmethod
    def _timestamp(value: str) -> datetime:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))

        if result.tzinfo is None:
            raise ValueError("Timestamp must include timezone information")

        return result.astimezone(timezone.utc)

    def parse(self, raw: RawEvent) -> SecurityEvent:
        try:
            data = json.loads(raw.payload)

            if not isinstance(data, dict):
                raise ValueError("Event must be a JSON object")

            required = {"timestamp", "category", "severity", "event_type"}

            if not required.issubset(data):
                raise ValueError("Missing required event fields")

            category = EventCategory(data["category"].upper())
            severity = EventSeverity(data["severity"].upper())

            event_type = data["event_type"]

            if not isinstance(event_type, str) or not event_type.strip():
                raise ValueError("Invalid event type")

            message = data.get("message", "")

            if not isinstance(message, str):
                raise ValueError("Message must be a string")

            username = data.get("username")
            hostname = data.get("hostname")

            for value, name in ((username, "username"), (hostname, "hostname")):
                if value is not None and (
                    not isinstance(value, str) or len(value) > 255
                ):
                    raise ValueError(f"Invalid {name}")

            event_hash = hashlib.sha256(
                f"{raw.source_id}|{raw.payload}".encode("utf-8")
            ).hexdigest()[:24]

            reserved = {
                "timestamp", "category", "severity", "event_type",
                "source_ip", "destination_ip", "username",
                "hostname", "message",
            }

            attributes = {
                key: value
                for key, value in data.items()
                if key not in reserved
            }

            return SecurityEvent(
                event_id=event_hash,
                source_id=raw.source_id,
                timestamp=self._timestamp(data["timestamp"]),
                category=category,
                severity=severity,
                event_type=event_type,
                source_ip=self._optional_ip(data.get("source_ip")),
                destination_ip=self._optional_ip(data.get("destination_ip")),
                username=username,
                hostname=hostname,
                message=message,
                attributes=attributes,
            )

        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"Event parsing failed: {exc}") from exc


# ------------------------------------------------------------
# Storage
# ------------------------------------------------------------

class EventStorage:

    def __init__(self, maximum_events: int = 50000) -> None:
        if maximum_events <= 0:
            raise ValueError("Storage capacity must be positive")

        self.maximum_events = maximum_events
        self.events: dict[str, SecurityEvent] = {}
        self.by_source: dict[str, list[str]] = defaultdict(list)
        self.by_username: dict[str, list[str]] = defaultdict(list)
        self.duplicates = 0

    def save(self, event: SecurityEvent) -> bool:
        if event.event_id in self.events:
            self.duplicates += 1
            return False

        if len(self.events) >= self.maximum_events:
            raise OverflowError("Event storage capacity reached")

        self.events[event.event_id] = event
        self.by_source[event.source_id].append(event.event_id)

        if event.username:
            self.by_username[event.username].append(event.event_id)

        return True

    def query(
        self,
        category: Optional[EventCategory] = None,
        severity: Optional[EventSeverity] = None,
        username: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[SecurityEvent]:

        results = self.events.values()

        if username is not None:
            results = (
                self.events[event_id]
                for event_id in self.by_username.get(username, [])
            )

        return sorted(
            (
                event for event in results
                if (category is None or event.category == category)
                and (severity is None or event.severity == severity)
                and (since is None or event.timestamp >= since)
            ),
            key=lambda event: event.timestamp,
        )


# ------------------------------------------------------------
# Correlation engine
# ------------------------------------------------------------

class CorrelationEngine:

    def __init__(
        self,
        storage: EventStorage,
        failure_threshold: int = 5,
        window_minutes: int = 5,
    ) -> None:
        if failure_threshold < 2 or window_minutes <= 0:
            raise ValueError("Invalid correlation configuration")

        self.storage = storage
        self.failure_threshold = failure_threshold
        self.window = timedelta(minutes=window_minutes)
        self.alerts: dict[str, SecurityAlert] = {}

    def detect_brute_force(
        self,
        events: Iterable[SecurityEvent],
    ) -> list[SecurityAlert]:

        groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if (
                event.category == EventCategory.AUTHENTICATION
                and event.event_type == "LOGIN_FAILURE"
                and event.source_ip
                and event.username
            ):
                groups[(event.source_ip, event.username)].append(event)

        generated = []

        for (source_ip, username), group in groups.items():
            group.sort(key=lambda event: event.timestamp)

            left = 0

            for right, current in enumerate(group):
                while (
                    group[left].timestamp < current.timestamp - self.window
                ):
                    left += 1

                matching = group[left:right + 1]

                if len(matching) >= self.failure_threshold:
                    event_ids = sorted(e.event_id for e in matching)

                    alert_id = hashlib.sha256(
                        "|".join(event_ids).encode()
                    ).hexdigest()[:20]

                    if alert_id not in self.alerts:
                        alert = SecurityAlert(
                            alert_id=alert_id,
                            title="Possible brute-force attack",
                            severity=EventSeverity.HIGH,
                            event_ids=event_ids,
                            description=(
                                f"{len(matching)} failed login attempts "
                                f"against {username} from {source_ip}"
                            ),
                            created_at=datetime.now(timezone.utc),
                        )

                        self.alerts[alert_id] = alert
                        generated.append(alert)

                    break

        return generated

    def detect_critical_events(
        self,
        events: Iterable[SecurityEvent],
    ) -> list[SecurityAlert]:

        generated = []

        for event in events:
            if event.severity != EventSeverity.CRITICAL:
                continue

            alert_id = f"critical-{event.event_id}"

            if alert_id not in self.alerts:
                alert = SecurityAlert(
                    alert_id=alert_id,
                    title="Critical security event",
                    severity=EventSeverity.CRITICAL,
                    event_ids=[event.event_id],
                    description=event.message or event.event_type,
                    created_at=datetime.now(timezone.utc),
                )

                self.alerts[alert_id] = alert
                generated.append(alert)

        return generated


# ------------------------------------------------------------
# Dashboard and reporting
# ------------------------------------------------------------

class SOCDashboard:

    def __init__(
        self,
        storage: EventStorage,
        correlation: CorrelationEngine,
    ) -> None:
        self.storage = storage
        self.correlation = correlation

    def metrics(self) -> dict[str, Any]:
        events = list(self.storage.events.values())
        alerts = list(self.correlation.alerts.values())

        return {
            "total_events": len(events),
            "total_alerts": len(alerts),
            "open_alerts": sum(
                a.status == AlertStatus.OPEN for a in alerts
            ),
            "severity_distribution": dict(
                Counter(e.severity.value for e in events)
            ),
            "category_distribution": dict(
                Counter(e.category.value for e in events)
            ),
            "source_distribution": dict(
                Counter(e.source_id for e in events)
            ),
            "duplicate_events": self.storage.duplicates,
        }

    def report(self) -> str:
        return json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "metrics": self.metrics(),
                "alerts": [
                    {
                        "alert_id": a.alert_id,
                        "title": a.title,
                        "severity": a.severity.value,
                        "description": a.description,
                        "status": a.status.value,
                        "event_count": len(a.event_ids),
                    }
                    for a in self.correlation.alerts.values()
                ],
            },
            indent=2,
        )


# ------------------------------------------------------------
# SOC processing pipeline
# ------------------------------------------------------------

class SOCPipeline:

    def __init__(self) -> None:
        self.registry = DataSourceRegistry()
        self.collector = EventCollector(self.registry)
        self.parser = EventParser()
        self.storage = EventStorage()
        self.correlation = CorrelationEngine(self.storage)
        self.dashboard = SOCDashboard(
            self.storage,
            self.correlation,
        )
        self.invalid_events = 0

    def process_batch(self, limit: int = 100) -> int:
        processed = 0

        for raw in self.collector.batch(limit):
            try:
                event = self.parser.parse(raw)
                if self.storage.save(event):
                    processed += 1
            except ValueError as exc:
                self.invalid_events += 1
                logger.warning("%s", exc)

        return processed

    def analyze(self) -> list[SecurityAlert]:
        events = list(self.storage.events.values())

        alerts = self.correlation.detect_brute_force(events)
        alerts.extend(self.correlation.detect_critical_events(events))

        return alerts

    def run(self) -> dict[str, Any]:
        self.process_batch()
        self.analyze()
        return self.dashboard.metrics()


# ------------------------------------------------------------
# Demonstration and verification
# ------------------------------------------------------------

def create_sample_events() -> list[dict[str, Any]]:
    base = datetime.now(timezone.utc) - timedelta(minutes=3)

    records = []

    for index in range(6):
        records.append({
            "timestamp": (base + timedelta(seconds=index * 20)).isoformat(),
            "category": "AUTHENTICATION",
            "severity": "MEDIUM",
            "event_type": "LOGIN_FAILURE",
            "source_ip": "203.0.113.45",
            "username": "admin",
            "hostname": "identity-server-01",
            "message": "Authentication failed",
        })

    records.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": "ENDPOINT",
        "severity": "CRITICAL",
        "event_type": "MALWARE_DETECTED",
        "source_ip": "192.0.2.10",
        "username": "analyst",
        "hostname": "workstation-01",
        "message": "Suspicious executable detected",
    })

    records.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": "NETWORK",
        "severity": "LOW",
        "event_type": "CONNECTION_ALLOWED",
        "source_ip": "192.0.2.20",
        "destination_ip": "198.51.100.10",
        "message": "Permitted network connection",
    })

    return records


def main() -> None:
    soc = SOCPipeline()

    soc.registry.register(
        DataSource(
            source_id="firewall-01",
            name="Enterprise Firewall",
            source_type="NETWORK",
            environment="PRODUCTION",
        )
    )

    soc.registry.register(
        DataSource(
            source_id="edr-01",
            name="Endpoint Detection",
            source_type="ENDPOINT",
            environment="PRODUCTION",
        )
    )

    records = create_sample_events()

    for index, record in enumerate(records):
        source_id = "edr-01" if index == 6 else "firewall-01"
        soc.collector.collect(source_id, json.dumps(record))

    processed = soc.process_batch()
    alerts = soc.analyze()

    assert processed == len(records)
    assert len(alerts) >= 2

    # Duplicate event detection.
    duplicate_payload = json.dumps(records[0])
    soc.collector.collect("firewall-01", duplicate_payload)
    soc.process_batch()

    assert soc.storage.duplicates == 1

    # Invalid source and invalid event validation.
    try:
        soc.collector.collect("unknown-source", "{}")
    except ValueError:
        logger.info("Unknown source correctly rejected")

    soc.collector.collect("firewall-01", '{"invalid": true}')
    soc.process_batch()

    assert soc.invalid_events == 1

    # Dashboard output.
    report = soc.dashboard.report()
    print("\nSOC DASHBOARD")
    print(report)

    print("\nGenerated alerts:")

    for alert in alerts:
        print(
            f"{alert.severity.value}: {alert.title} "
            f"| {alert.description}"
        )

    print("\nSOC pipeline verification passed.")


if __name__ == "__main__":
    main()
