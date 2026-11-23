#!/usr/bin/env python3
"""
Distributed Log Collection Pipeline

Implements:
- Log agents and source collection
- Structured JSON and Syslog parsing
- Timestamp normalization to UTC
- Field normalization and severity mapping
- Sensitive-data redaction
- Bounded asynchronous forwarding
- Batch delivery and retry handling
- Duplicate detection
- Retention and archival
- Validation, monitoring, and reporting

Python 3.10+
Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import time
import uuid

from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional, Protocol


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)

LOGGER = logging.getLogger("log_collection")


class Severity(Enum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50


class LogState(Enum):
    COLLECTED = "collected"
    NORMALIZED = "normalized"
    QUEUED = "queued"
    FORWARDED = "forwarded"
    FAILED = "failed"
    ARCHIVED = "archived"


class LogValidationError(ValueError):
    pass


class ForwardingError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentConfig:
    agent_id: str
    hostname: str
    environment: str
    source_type: str
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.agent_id.strip():
            raise LogValidationError("Agent ID cannot be empty")
        if not self.hostname.strip():
            raise LogValidationError("Hostname cannot be empty")
        if not self.environment.strip():
            raise LogValidationError("Environment cannot be empty")


@dataclass
class LogRecord:
    event_id: str
    agent_id: str
    hostname: str
    source: str
    timestamp: datetime
    severity: Severity
    message: str
    attributes: dict[str, Any] = field(default_factory=dict)
    state: LogState = LogState.COLLECTED
    received_at: Optional[datetime] = None
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.name,
            "message": self.message,
            "attributes": self.attributes,
            "state": self.state.value,
            "received_at": (
                self.received_at.isoformat()
                if self.received_at else None
            ),
            "fingerprint": self.fingerprint,
        }


class TimestampNormalizer:
    """Convert supported timestamps into timezone-aware UTC values."""

    @staticmethod
    def normalize(value: Any) -> datetime:
        if isinstance(value, datetime):
            result = value

        elif isinstance(value, (int, float)):
            try:
                result = datetime.fromtimestamp(
                    value,
                    tz=timezone.utc
                )
            except (OverflowError, OSError, ValueError) as exc:
                raise LogValidationError(
                    "Invalid Unix timestamp"
                ) from exc

        elif isinstance(value, str):
            try:
                result = datetime.fromisoformat(
                    value.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise LogValidationError(
                    f"Invalid timestamp: {value}"
                ) from exc

        else:
            raise LogValidationError(
                "Unsupported timestamp format"
            )

        # Naive timestamps are interpreted as UTC by policy.
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)


class SeverityNormalizer:
    MAPPING = {
        "trace": Severity.DEBUG,
        "debug": Severity.DEBUG,
        "info": Severity.INFO,
        "notice": Severity.INFO,
        "warn": Severity.WARNING,
        "warning": Severity.WARNING,
        "error": Severity.ERROR,
        "err": Severity.ERROR,
        "critical": Severity.CRITICAL,
        "fatal": Severity.CRITICAL,
        "emergency": Severity.CRITICAL,
    }

    @classmethod
    def normalize(cls, value: Any) -> Severity:
        if isinstance(value, Severity):
            return value

        if isinstance(value, int):
            for severity in Severity:
                if severity.value == value:
                    return severity

        if isinstance(value, str):
            normalized = cls.MAPPING.get(value.strip().lower())
            if normalized:
                return normalized

        raise LogValidationError(
            f"Unsupported severity: {value}"
        )


class LogParser:
    """Parse JSON and simplified RFC 5424-style Syslog messages."""

    SYSLOG_PATTERN = re.compile(
        r"^<(?P<priority>\d{1,3})>"
        r"(?P<version>\d+)\s+"
        r"(?P<timestamp>\S+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<app>\S+)\s+"
        r"(?P<procid>\S+)\s+"
        r"(?P<msgid>\S+)\s+"
        r"(?P<message>.*)$"
    )

    SYSLOG_SEVERITIES = {
        0: Severity.CRITICAL,
        1: Severity.CRITICAL,
        2: Severity.CRITICAL,
        3: Severity.ERROR,
        4: Severity.WARNING,
        5: Severity.INFO,
        6: Severity.INFO,
        7: Severity.DEBUG,
    }

    @classmethod
    def parse(cls, raw: str, source_type: str) -> dict[str, Any]:
        if not isinstance(raw, str) or not raw.strip():
            raise LogValidationError("Empty log message")

        if len(raw.encode("utf-8")) > 1024 * 1024:
            raise LogValidationError("Log exceeds 1 MB limit")

        if source_type.lower() == "json":
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise LogValidationError(
                    "Malformed JSON log"
                ) from exc

            if not isinstance(data, dict):
                raise LogValidationError(
                    "JSON log must contain an object"
                )

            required = {"timestamp", "severity", "message"}
            missing = required.difference(data)

            if missing:
                raise LogValidationError(
                    f"Missing fields: {sorted(missing)}"
                )

            return data

        if source_type.lower() == "syslog":
            match = cls.SYSLOG_PATTERN.match(raw)

            if not match:
                raise LogValidationError(
                    "Unsupported Syslog format"
                )

            groups = match.groupdict()
            priority = int(groups["priority"])

            if priority > 191:
                raise LogValidationError(
                    "Invalid Syslog priority"
                )

            facility = priority // 8
            severity_code = priority % 8

            return {
                "timestamp": groups["timestamp"],
                "severity": cls.SYSLOG_SEVERITIES[severity_code],
                "message": groups["message"],
                "hostname": groups["hostname"],
                "application": groups["app"],
                "process_id": groups["procid"],
                "message_id": groups["msgid"],
                "facility": facility,
            }

        raise LogValidationError(
            f"Unsupported source type: {source_type}"
        )


class SensitiveDataRedactor:
    """Redact common credentials and personal identifiers."""

    PATTERNS = [
        (
            re.compile(
                r"(?i)(password|passwd|token|secret|api_key)"
                r"\s*[=:]\s*['\"]?[^,\s'\"]+"
            ),
            r"\1=[REDACTED]",
        ),
        (
            re.compile(
                r"\b[A-Za-z0-9._%+-]+@"
                r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
            ),
            "[EMAIL_REDACTED]",
        ),
        (
            re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
            "[CARD_REDACTED]",
        ),
    ]

    @classmethod
    def redact(cls, text: str) -> str:
        for pattern, replacement in cls.PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class LogNormalizer:
    def __init__(self) -> None:
        self.redactor = SensitiveDataRedactor()

    def normalize(
        self,
        raw: str,
        agent: AgentConfig,
    ) -> LogRecord:

        data = LogParser.parse(raw, agent.source_type)

        timestamp = TimestampNormalizer.normalize(
            data["timestamp"]
        )

        severity = SeverityNormalizer.normalize(
            data["severity"]
        )

        message = self.redactor.redact(
            str(data["message"])
        )

        attributes = {
            key: value
            for key, value in data.items()
            if key not in {"timestamp", "severity", "message"}
        }

        if len(message) > 10000:
            message = message[:10000]

        # Limit arbitrary attributes to avoid oversized records.
        if len(attributes) > 100:
            raise LogValidationError(
                "Too many log attributes"
            )

        record = LogRecord(
            event_id=str(uuid.uuid4()),
            agent_id=agent.agent_id,
            hostname=str(
                attributes.pop("hostname", agent.hostname)
            ),
            source=agent.source_type,
            timestamp=timestamp,
            severity=severity,
            message=message,
            attributes=attributes,
            state=LogState.NORMALIZED,
            received_at=datetime.now(timezone.utc),
        )

        fingerprint_data = (
            f"{record.agent_id}|{record.hostname}|"
            f"{record.timestamp.isoformat()}|"
            f"{record.severity.name}|{record.message}"
        )

        record.fingerprint = hashlib.sha256(
            fingerprint_data.encode("utf-8")
        ).hexdigest()

        return record


class LogSink(Protocol):
    def send(self, batch: list[LogRecord]) -> None:
        ...


class MemoryLogSink:
    """Demonstration destination with idempotent ingestion."""

    def __init__(self) -> None:
        self.records: dict[str, LogRecord] = {}
        self.fail_next = False

    def send(self, batch: list[LogRecord]) -> None:
        if self.fail_next:
            self.fail_next = False
            raise ForwardingError(
                "Simulated destination outage"
            )

        for record in batch:
            self.records.setdefault(
                record.fingerprint,
                record
            )


class ForwardingAgent:
    """Bounded queue with batching and bounded retry attempts."""

    def __init__(
        self,
        sink: LogSink,
        batch_size: int = 10,
        max_retries: int = 3,
        queue_capacity: int = 1000,
    ) -> None:

        if batch_size <= 0 or max_retries < 0:
            raise ValueError("Invalid forwarding configuration")

        if queue_capacity <= 0:
            raise ValueError("Queue capacity must be positive")

        self.sink = sink
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.queue: deque[LogRecord] = deque(
            maxlen=queue_capacity
        )

        self.dead_letter_queue: list[LogRecord] = []
        self.metrics = Counter()

    def enqueue(self, record: LogRecord) -> None:
        if len(self.queue) == self.queue.maxlen:
            self.metrics["queue_overflow"] += 1
            raise ForwardingError("Forwarding queue is full")

        record.state = LogState.QUEUED
        self.queue.append(record)
        self.metrics["enqueued"] += 1

    def flush(self) -> int:
        delivered = 0

        while self.queue:
            batch = [
                self.queue.popleft()
                for _ in range(
                    min(self.batch_size, len(self.queue))
                )
            ]

            successful = False

            for attempt in range(self.max_retries + 1):
                try:
                    self.sink.send(batch)
                    successful = True
                    break

                except Exception as exc:
                    self.metrics["forwarding_errors"] += 1

                    if attempt < self.max_retries:
                        delay = min(0.05 * (2 ** attempt), 1.0)
                        LOGGER.warning(
                            "Forwarding attempt %s failed: %s",
                            attempt + 1,
                            exc,
                        )
                        time.sleep(delay)

            if successful:
                for record in batch:
                    record.state = LogState.FORWARDED

                delivered += len(batch)
                self.metrics["forwarded"] += len(batch)

            else:
                for record in batch:
                    record.state = LogState.FAILED
                    self.dead_letter_queue.append(record)

                self.metrics["dead_lettered"] += len(batch)

        return delivered


class RetentionManager:
    """Time-based retention using event timestamps."""

    def __init__(
        self,
        retention_days: int = 30,
        archive_days: int = 90,
    ) -> None:

        if retention_days <= 0:
            raise ValueError("Retention must be positive")

        if archive_days <= retention_days:
            raise ValueError(
                "Archive period must exceed retention period"
            )

        self.retention_period = timedelta(
            days=retention_days
        )

        self.archive_period = timedelta(
            days=archive_days
        )

        self.archived: list[LogRecord] = []

    def apply(
        self,
        records: list[LogRecord],
        now: Optional[datetime] = None,
    ) -> dict[str, int]:

        current = TimestampNormalizer.normalize(
            now or datetime.now(timezone.utc)
        )

        retained = []
        archived = 0
        deleted = 0

        for record in records:
            age = current - record.timestamp

            if age < timedelta(0):
                retained.append(record)
                continue

            if age >= self.archive_period:
                deleted += 1
                continue

            if age >= self.retention_period:
                record.state = LogState.ARCHIVED
                self.archived.append(record)
                archived += 1
                continue

            retained.append(record)

        records[:] = retained

        return {
            "retained": len(records),
            "archived": archived,
            "deleted": deleted,
        }


class LogCollectionPipeline:
    def __init__(
        self,
        agents: list[AgentConfig],
        sink: LogSink,
    ) -> None:

        self.agents = {
            agent.agent_id: agent
            for agent in agents
        }

        if len(self.agents) != len(agents):
            raise ValueError("Duplicate agent IDs")

        self.normalizer = LogNormalizer()
        self.forwarder = ForwardingAgent(sink)
        self.retention = RetentionManager()
        self.records: list[LogRecord] = []
        self.fingerprints: set[str] = set()
        self.metrics = Counter()

    def collect(
        self,
        agent_id: str,
        raw_message: str,
    ) -> Optional[LogRecord]:

        agent = self.agents.get(agent_id)

        if agent is None:
            raise LogValidationError("Unknown collection agent")

        if not agent.enabled:
            self.metrics["disabled_agent_events"] += 1
            return None

        try:
            record = self.normalizer.normalize(
                raw_message,
                agent,
            )

            if record.fingerprint in self.fingerprints:
                self.metrics["duplicates"] += 1
                return None

            self.fingerprints.add(record.fingerprint)

            self.records.append(record)
            self.forwarder.enqueue(record)

            self.metrics["collected"] += 1
            return record

        except LogValidationError:
            self.metrics["invalid_events"] += 1
            LOGGER.exception("Log normalization failed")
            raise

        except ForwardingError:
            self.metrics["queue_failures"] += 1
            raise

    def flush(self) -> int:
        return self.forwarder.flush()

    def report(self) -> dict[str, Any]:
        return {
            "collection_metrics": dict(self.metrics),
            "forwarding_metrics": dict(
                self.forwarder.metrics
            ),
            "records_by_severity": dict(
                Counter(
                    record.severity.name
                    for record in self.records
                )
            ),
            "queued_records": len(
                self.forwarder.queue
            ),
            "dead_letter_records": len(
                self.forwarder.dead_letter_queue
            ),
            "destination_records": len(
                self.forwarder.sink.records
            ) if isinstance(
                self.forwarder.sink,
                MemoryLogSink
            ) else None,
        }


def run_demo() -> None:
    print("\n=== DISTRIBUTED LOG COLLECTION ===")

    agents = [
        AgentConfig(
            "agent-web-01",
            "web-server-01",
            "production",
            "json",
        ),
        AgentConfig(
            "agent-db-01",
            "database-01",
            "production",
            "syslog",
        ),
    ]

    sink = MemoryLogSink()

    pipeline = LogCollectionPipeline(
        agents,
        sink,
    )

    events = [
        (
            "agent-web-01",
            json.dumps({
                "timestamp": "2026-11-23T04:00:00Z",
                "severity": "INFO",
                "message": "User login successful",
                "user": "employee01",
                "service": "authentication",
            }),
        ),
        (
            "agent-web-01",
            json.dumps({
                "timestamp": "2026-11-23T04:01:00+05:30",
                "severity": "ERROR",
                "message": "Database connection failed",
                "password": "example-secret",
                "service": "payment",
            }),
        ),
        (
            "agent-db-01",
            "<34>1 2026-11-23T04:02:00Z "
            "database-01 postgres 1234 ID47 "
            "Database connection restored",
        ),
        (
            "agent-web-01",
            json.dumps({
                "timestamp": "2026-11-23T04:03:00Z",
                "severity": "WARNING",
                "message": "High CPU utilization",
                "cpu_usage": 92.5,
            }),
        ),
    ]

    for agent_id, raw in events:
        try:
            pipeline.collect(agent_id, raw)
        except LogValidationError as exc:
            LOGGER.error("Rejected event: %s", exc)

    # Demonstrate duplicate detection.
    pipeline.collect(
        "agent-web-01",
        events[0][1],
    )

    print("\nForwarding logs...")
    print("Successfully forwarded:", pipeline.flush())

    print("\nNormalized records:")

    for record in pipeline.records:
        print(
            json.dumps(
                record.to_dict(),
                indent=2,
            )
        )

    # Test destination failure and dead-letter handling.
    failure_sink = MemoryLogSink()
    failure_sink.fail_next = True

    failure_forwarder = ForwardingAgent(
        failure_sink,
        batch_size=2,
        max_retries=0,
    )

    failed_record = LogRecord(
        event_id="failure-example",
        agent_id="agent-web-01",
        hostname="web-server-01",
        source="json",
        timestamp=datetime.now(timezone.utc),
        severity=Severity.ERROR,
        message="Forwarding failure test",
    )

    failure_forwarder.enqueue(failed_record)
    failure_forwarder.flush()

    print(
        "\nDead-letter test:",
        len(failure_forwarder.dead_letter_queue),
    )

    # Test retention independently with historical records.
    historical = [
        LogRecord(
            event_id="old-001",
            agent_id="agent-web-01",
            hostname="web-server-01",
            source="json",
            timestamp=datetime.now(timezone.utc)
            - timedelta(days=45),
            severity=Severity.INFO,
            message="Historical event",
        ),
        LogRecord(
            event_id="old-002",
            agent_id="agent-web-01",
            hostname="web-server-01",
            source="json",
            timestamp=datetime.now(timezone.utc)
            - timedelta(days=120),
            severity=Severity.ERROR,
            message="Expired event",
        ),
    ]

    print(
        "\nRetention results:",
        pipeline.retention.apply(historical),
    )

    print("\nPipeline metrics:")
    print(
        json.dumps(
            pipeline.report(),
            indent=2,
        )
    )

    assert len(sink.records) == 3
    assert len(pipeline.records) == 3
    assert pipeline.metrics["duplicates"] == 1
    assert len(failure_forwarder.dead_letter_queue) == 1
    assert len(pipeline.retention.archived) == 1
    assert not historical

    print("\nAll demonstration assertions passed.")


if __name__ == "__main__":
    run_demo()
