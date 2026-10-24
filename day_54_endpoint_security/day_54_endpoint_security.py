#!/usr/bin/env python3
"""Endpoint security workflow simulator using Python's standard library.

Models antivirus findings, EDR telemetry, HIDS alerts, behavioral detection,
incident states, containment decisions, and endpoint security reporting.

This is a deterministic educational simulator, not an operating-system sensor.
"""

from __future__ import annotations

import json
import logging
import re
import unittest
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOGGER = logging.getLogger("endpoint_security")


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SensorType(str, Enum):
    ANTIVIRUS = "antivirus"
    EDR = "edr"
    HIDS = "hids"
    BEHAVIORAL = "behavioral"


class IncidentState(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    endpoint_id: str
    timestamp: datetime
    sensor: SensorType
    event_type: str
    severity: Severity
    process_name: str
    file_hash: str | None = None
    user_name: str = "unknown"
    details: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id.strip() or not self.endpoint_id.strip():
            raise ValueError("Event and endpoint identifiers are required")
        if self.timestamp.tzinfo is None:
            raise ValueError("Timestamps must include a timezone")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.process_name):
            raise ValueError("Invalid process name")
        if self.file_hash and not re.fullmatch(r"[a-fA-F0-9]{64}", self.file_hash):
            raise ValueError("File hashes must be SHA-256 hexadecimal strings")
        if len(self.details) > 30:
            raise ValueError("Too many telemetry detail fields")
        if any(len(k) > 100 or len(v) > 500 for k, v in self.details.items()):
            raise ValueError("Telemetry detail exceeds permitted length")


@dataclass
class Incident:
    incident_id: str
    endpoint_id: str
    severity: Severity
    event_ids: list[str]
    reasons: list[str]
    state: IncidentState = IncidentState.NEW
    assigned_to: str | None = None


class EndpointSecurityEngine:
    """Correlates telemetry and applies explicit response rules."""

    def __init__(self, trusted_hashes: set[str] | None = None) -> None:
        self.trusted_hashes = {h.lower() for h in (trusted_hashes or set())}
        self.events: dict[str, TelemetryEvent] = {}
        self.incidents: dict[str, Incident] = {}
        self.endpoint_states: dict[str, str] = {}
        self._sequence = 0

    def ingest(self, event: TelemetryEvent) -> None:
        if event.event_id in self.events:
            existing = self.events[event.event_id]
            if existing != event:
                raise ValueError("Conflicting duplicate event identifier")
            return

        if event.file_hash and event.file_hash.lower() in self.trusted_hashes:
            if event.sensor == SensorType.ANTIVIRUS:
                LOGGER.info("Trusted hash observed; antivirus finding retained for review")

        self.events[event.event_id] = event

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[severity]

    def detect(self, events: Iterable[TelemetryEvent]) -> list[Incident]:
        grouped: dict[str, list[TelemetryEvent]] = defaultdict(list)
        for event in events:
            grouped[event.endpoint_id].append(event)

        created: list[Incident] = []

        for endpoint_id, endpoint_events in grouped.items():
            endpoint_events.sort(key=lambda e: e.timestamp)
            reasons: list[str] = []
            evidence_ids: list[str] = []
            severity = Severity.LOW

            def record(event: TelemetryEvent, reason: str, level: Severity) -> None:
                nonlocal severity
                evidence_ids.append(event.event_id)
                reasons.append(reason)
                if self._severity_rank(level) > self._severity_rank(severity):
                    severity = level

            # Antivirus: a malware signature or quarantine failure.
            for event in endpoint_events:
                if event.sensor == SensorType.ANTIVIRUS:
                    if event.event_type == "malware_detected":
                        record(event, "Antivirus malware detection", event.severity)
                    elif event.event_type == "quarantine_failed":
                        record(event, "Antivirus quarantine failed", Severity.HIGH)

            # HIDS: integrity monitoring detects an unexpected protected-file change.
            for event in endpoint_events:
                if event.sensor == SensorType.HIDS and event.event_type == "integrity_violation":
                    record(event, "Protected-file integrity violation", event.severity)

            # EDR: correlate suspicious process execution and outbound connections.
            suspicious_processes = {
                e.event_id: e for e in endpoint_events
                if e.sensor == SensorType.EDR
                and e.event_type in {"suspicious_process", "credential_access"}
            }
            outbound_events = [
                e for e in endpoint_events
                if e.sensor == SensorType.EDR and e.event_type == "unusual_outbound_connection"
            ]

            for event in suspicious_processes.values():
                record(event, f"EDR event: {event.event_type}", event.severity)

            if suspicious_processes and outbound_events:
                first_suspicious = min(
                    e.timestamp for e in suspicious_processes.values()
                )
                for event in outbound_events:
                    if 0 <= (event.timestamp - first_suspicious).total_seconds() <= 300:
                        record(
                            event,
                            "Suspicious execution correlated with outbound activity",
                            Severity.CRITICAL,
                        )

            # Behavioral detection: repeated authentication failures followed by success.
            auth_events = [
                e for e in endpoint_events
                if e.sensor == SensorType.BEHAVIORAL
                and e.event_type in {"authentication_failure", "authentication_success"}
            ]
            failures_by_user: Counter[str] = Counter()

            for event in auth_events:
                if event.event_type == "authentication_failure":
                    failures_by_user[event.user_name] += 1
                elif (
                    event.event_type == "authentication_success"
                    and failures_by_user[event.user_name] >= 5
                ):
                    record(
                        event,
                        f"Repeated authentication failures followed by success for {event.user_name}",
                        Severity.HIGH,
                    )

            if not evidence_ids:
                continue

            self._sequence += 1
            incident_id = f"INC-{self._sequence:05d}"
            incident = Incident(
                incident_id=incident_id,
                endpoint_id=endpoint_id,
                severity=severity,
                event_ids=list(dict.fromkeys(evidence_ids)),
                reasons=list(dict.fromkeys(reasons)),
            )
            self.incidents[incident_id] = incident
            created.append(incident)

        return created

    def transition(self, incident_id: str, new_state: IncidentState) -> None:
        incident = self.incidents.get(incident_id)
        if incident is None:
            raise KeyError(f"Unknown incident: {incident_id}")

        allowed = {
            IncidentState.NEW: {IncidentState.TRIAGED},
            IncidentState.TRIAGED: {
                IncidentState.CONTAINED,
                IncidentState.INVESTIGATING,
            },
            IncidentState.CONTAINED: {IncidentState.INVESTIGATING},
            IncidentState.INVESTIGATING: {
                IncidentState.CONTAINED,
                IncidentState.RESOLVED,
            },
            IncidentState.RESOLVED: set(),
        }

        if new_state not in allowed[incident.state]:
            raise ValueError(
                f"Invalid transition: {incident.state.value} -> {new_state.value}"
            )

        incident.state = new_state
        if new_state == IncidentState.CONTAINED:
            self.endpoint_states[incident.endpoint_id] = "isolated"
        elif new_state == IncidentState.RESOLVED:
            self.endpoint_states[incident.endpoint_id] = "review_required"

    def report(self) -> dict[str, object]:
        severity_counts = Counter(i.severity.value for i in self.incidents.values())
        state_counts = Counter(i.state.value for i in self.incidents.values())
        sensor_counts = Counter(e.sensor.value for e in self.events.values())

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "telemetry_events": len(self.events),
            "incidents": len(self.incidents),
            "incidents_by_severity": dict(sorted(severity_counts.items())),
            "incidents_by_state": dict(sorted(state_counts.items())),
            "events_by_sensor": dict(sorted(sensor_counts.items())),
            "endpoint_response_states": dict(sorted(self.endpoint_states.items())),
        }

    def export_json(self, path: Path) -> None:
        """Write a report using a temporary file to avoid partial final output."""
        payload = {
            "report": self.report(),
            "incidents": [
                {
                    **asdict(incident),
                    "severity": incident.severity.value,
                    "state": incident.state.value,
                }
                for incident in self.incidents.values()
            ],
        }
        temporary = path.with_suffix(path.suffix + ".tmp")
        try:
            temporary.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            temporary.replace(path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise


def sample_events() -> list[TelemetryEvent]:
    now = datetime.now(timezone.utc)
    return [
        TelemetryEvent(
            "EV-001", "WS-101", now, SensorType.ANTIVIRUS,
            "malware_detected", Severity.HIGH, "invoice.exe",
            "a" * 64, "analyst",
        ),
        TelemetryEvent(
            "EV-002", "WS-202", now, SensorType.HIDS,
            "integrity_violation", Severity.HIGH, "systemd",
            user_name="root",
            details={"path": "/etc/ssh/sshd_config"},
        ),
        TelemetryEvent(
            "EV-003", "WS-303", now, SensorType.EDR,
            "suspicious_process", Severity.HIGH, "powershell.exe",
            user_name="employee",
        ),
        TelemetryEvent(
            "EV-004", "WS-303", now.replace(microsecond=0),
            SensorType.EDR, "unusual_outbound_connection",
            Severity.MEDIUM, "powershell.exe", user_name="employee",
        ),
        *[
            TelemetryEvent(
                f"EV-AUTH-{i}", "WS-404",
                now.replace(microsecond=0),
                SensorType.BEHAVIORAL,
                "authentication_failure", Severity.MEDIUM,
                "login_service", user_name="svc-backup",
            )
            for i in range(1, 6)
        ],
        TelemetryEvent(
            "EV-AUTH-6", "WS-404", now,
            SensorType.BEHAVIORAL, "authentication_success",
            Severity.MEDIUM, "login_service", user_name="svc-backup",
        ),
        TelemetryEvent(
            "EV-005", "WS-505", now, SensorType.EDR,
            "process_started", Severity.LOW, "notepad.exe",
        ),
    ]


class EndpointSecurityTests(unittest.TestCase):
    def test_detection_and_response(self) -> None:
        engine = EndpointSecurityEngine()
        events = sample_events()
        for event in events:
            engine.ingest(event)

        incidents = engine.detect(engine.events.values())
        self.assertEqual(len(incidents), 4)
        self.assertTrue(any(i.severity == Severity.CRITICAL for i in incidents))

        incident = next(i for i in incidents if i.endpoint_id == "WS-303")
        engine.transition(incident.incident_id, IncidentState.TRIAGED)
        engine.transition(incident.incident_id, IncidentState.CONTAINED)
        self.assertEqual(engine.endpoint_states["WS-303"], "isolated")

    def test_conflicting_duplicate(self) -> None:
        engine = EndpointSecurityEngine()
        event = sample_events()[0]
        engine.ingest(event)
        altered = TelemetryEvent(
            event.event_id, event.endpoint_id, event.timestamp,
            event.sensor, "benign", event.severity, event.process_name,
            event.file_hash, event.user_name,
        )
        with self.assertRaises(ValueError):
            engine.ingest(altered)

    def test_invalid_state_transition(self) -> None:
        engine = EndpointSecurityEngine()
        incident = Incident("INC-X", "WS-X", Severity.HIGH, [], [])
        engine.incidents[incident.incident_id] = incident
        with self.assertRaises(ValueError):
            engine.transition("INC-X", IncidentState.RESOLVED)


def main() -> None:
    engine = EndpointSecurityEngine()
    for event in sample_events():
        engine.ingest(event)

    incidents = engine.detect(engine.events.values())
    for incident in incidents:
        LOGGER.info(
            "%s endpoint=%s severity=%s evidence=%d reasons=%s",
            incident.incident_id,
            incident.endpoint_id,
            incident.severity.value,
            len(incident.event_ids),
            "; ".join(incident.reasons),
        )

    print(json.dumps(engine.report(), indent=2))
    unittest.main(argv=["endpoint_security.py"], exit=False)


if __name__ == "__main__":
    main()
