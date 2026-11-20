"""
SECURITY OPERATIONS FUNDAMENTALS
SOC mission, SOC tiers, monitoring, alerting, escalation, and incident lifecycle.

Runtime: Python 3.10+
Dependencies: Python standard library only.
"""

from __future__ import annotations

import json
import logging
import re
import unittest
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import Optional
from uuid import uuid4


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
logger = logging.getLogger("soc")


# ---------------------------------------------------------
# 1. Domain definitions
# ---------------------------------------------------------

class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertStatus(Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class IncidentType(Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    NETWORK_INTRUSION = "network_intrusion"


class SOCTier(IntEnum):
    TIER_1 = 1
    TIER_2 = 2
    TIER_3 = 3


class Decision(Enum):
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    FALSE_POSITIVE = "false_positive"


# ---------------------------------------------------------
# 2. Data models
# ---------------------------------------------------------

@dataclass(frozen=True)
class SecurityEvent:
    source: str
    event_type: str
    source_ip: str
    destination: str
    description: str
    timestamp: datetime
    failed_attempts: int = 0
    affected_users: int = 1

    def validate(self) -> None:
        if not self.source.strip():
            raise ValueError("Event source is required")

        if not re.fullmatch(
            r"(?:\d{1,3}\.){3}\d{1,3}", self.source_ip
        ):
            raise ValueError("Invalid IPv4 address format")

        import ipaddress
        ipaddress.ip_address(self.source_ip)

        if self.failed_attempts < 0:
            raise ValueError("Failed attempts cannot be negative")

        if self.affected_users < 1:
            raise ValueError("Affected users must be positive")

        if self.timestamp.tzinfo is None:
            raise ValueError("Timestamp must include timezone")


@dataclass
class Alert:
    alert_id: str
    event: SecurityEvent
    incident_type: IncidentType
    severity: Severity
    status: AlertStatus = AlertStatus.NEW
    assigned_tier: SOCTier = SOCTier.TIER_1
    assigned_analyst: Optional[str] = None
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)

    def record(self, action: str, details: str = "") -> None:
        self.history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details
        })


@dataclass(frozen=True)
class Analyst:
    analyst_id: str
    name: str
    tier: SOCTier
    skills: frozenset[str]
    active: bool = True


# ---------------------------------------------------------
# 3. SOC monitoring and detection
# ---------------------------------------------------------

class DetectionEngine:
    """Rule-based event detection with transparent thresholds."""

    RULES = {
        "brute_force": 10,
        "data_exfiltration": 500,
        "critical_failed_attempts": 25
    }

    def analyze(self, event: SecurityEvent) -> Optional[Alert]:
        event.validate()

        incident_type = None
        severity = Severity.LOW
        confidence = 0.0
        evidence = []

        if event.failed_attempts >= self.RULES["critical_failed_attempts"]:
            incident_type = IncidentType.BRUTE_FORCE
            severity = Severity.CRITICAL
            confidence = 0.98
            evidence.append("Critical authentication failure threshold exceeded")

        elif event.failed_attempts >= self.RULES["brute_force"]:
            incident_type = IncidentType.BRUTE_FORCE
            severity = Severity.HIGH
            confidence = 0.90
            evidence.append("Repeated authentication failures detected")

        elif (
            event.event_type == "outbound_transfer"
            and event.affected_users >= self.RULES["data_exfiltration"]
        ):
            incident_type = IncidentType.DATA_EXFILTRATION
            severity = Severity.CRITICAL
            confidence = 0.95
            evidence.append("Unusually large outbound transfer")

        elif event.event_type == "malware_detected":
            incident_type = IncidentType.MALWARE
            severity = Severity.HIGH
            confidence = 0.95
            evidence.append("Endpoint malware detection reported")

        elif event.event_type == "phishing_report":
            incident_type = IncidentType.PHISHING
            severity = Severity.MEDIUM
            confidence = 0.85
            evidence.append("User-reported suspicious email")

        elif event.event_type == "unauthorized_access":
            incident_type = IncidentType.UNAUTHORIZED_ACCESS
            severity = Severity.HIGH
            confidence = 0.90
            evidence.append("Unauthorized access indicator detected")

        if incident_type is None:
            return None

        alert = Alert(
            alert_id=str(uuid4()),
            event=event,
            incident_type=incident_type,
            severity=severity,
            confidence=confidence,
            evidence=evidence
        )

        alert.record("DETECTED", f"{incident_type.value}: {severity.name}")
        return alert


# ---------------------------------------------------------
# 4. SOC analyst management
# ---------------------------------------------------------

class AnalystRegistry:

    def __init__(self):
        self.analysts: dict[str, Analyst] = {}

    def register(self, analyst: Analyst) -> None:
        if analyst.analyst_id in self.analysts:
            raise ValueError("Analyst already registered")

        if not analyst.name.strip():
            raise ValueError("Analyst name is required")

        self.analysts[analyst.analyst_id] = analyst

    def find_available(
        self,
        tier: SOCTier,
        skill: str
    ) -> Optional[Analyst]:
        candidates = [
            analyst for analyst in self.analysts.values()
            if analyst.active
            and analyst.tier == tier
            and skill in analyst.skills
        ]

        return sorted(candidates, key=lambda a: a.analyst_id)[0] \
            if candidates else None


# ---------------------------------------------------------
# 5. Escalation management
# ---------------------------------------------------------

class EscalationEngine:

    SEVERITY_TIERS = {
        Severity.LOW: SOCTier.TIER_1,
        Severity.MEDIUM: SOCTier.TIER_1,
        Severity.HIGH: SOCTier.TIER_2,
        Severity.CRITICAL: SOCTier.TIER_3
    }

    def assign(
        self,
        alert: Alert,
        registry: AnalystRegistry
    ) -> Alert:

        tier = self.SEVERITY_TIERS[alert.severity]

        analyst = registry.find_available(
            tier,
            alert.incident_type.value
        )

        # Escalate to the next available tier if a specialist
        # at the preferred tier is unavailable.
        if analyst is None:
            for candidate_tier in range(int(tier), 4):
                analyst = registry.find_available(
                    SOCTier(candidate_tier),
                    alert.incident_type.value
                )
                if analyst:
                    tier = SOCTier(candidate_tier)
                    break

        if analyst is None:
            alert.status = AlertStatus.ESCALATED
            alert.record(
                "ASSIGNMENT_FAILED",
                "No available qualified analyst"
            )
            return alert

        alert.assigned_tier = tier
        alert.assigned_analyst = analyst.analyst_id
        alert.status = AlertStatus.TRIAGED

        alert.record(
            "ASSIGNED",
            f"{analyst.name}, Tier {tier.value}"
        )

        return alert


# ---------------------------------------------------------
# 6. Incident lifecycle
# ---------------------------------------------------------

class IncidentManager:

    TRANSITIONS = {
        AlertStatus.NEW: {
            AlertStatus.TRIAGED,
            AlertStatus.FALSE_POSITIVE,
            AlertStatus.ESCALATED
        },
        AlertStatus.TRIAGED: {
            AlertStatus.INVESTIGATING,
            AlertStatus.ESCALATED,
            AlertStatus.FALSE_POSITIVE
        },
        AlertStatus.INVESTIGATING: {
            AlertStatus.ESCALATED,
            AlertStatus.CONTAINED,
            AlertStatus.FALSE_POSITIVE
        },
        AlertStatus.ESCALATED: {
            AlertStatus.INVESTIGATING,
            AlertStatus.CONTAINED
        },
        AlertStatus.CONTAINED: {
            AlertStatus.RESOLVED
        },
        AlertStatus.RESOLVED: {
            AlertStatus.CLOSED
        },
        AlertStatus.FALSE_POSITIVE: {
            AlertStatus.CLOSED
        },
        AlertStatus.CLOSED: set()
    }

    def transition(
        self,
        alert: Alert,
        new_status: AlertStatus,
        actor: str,
        reason: str
    ) -> None:

        if new_status not in self.TRANSITIONS[alert.status]:
            raise ValueError(
                f"Invalid transition: {alert.status.value} "
                f"-> {new_status.value}"
            )

        if not actor.strip() or not reason.strip():
            raise ValueError("Actor and reason are required")

        if (
            new_status == AlertStatus.CONTAINED
            and not alert.evidence
        ):
            raise ValueError("Containment requires recorded evidence")

        alert.status = new_status
        alert.record(
            new_status.value.upper(),
            f"{actor}: {reason}"
        )


# ---------------------------------------------------------
# 7. SOC operational reporting
# ---------------------------------------------------------

class SOCReporter:

    @staticmethod
    def generate(alerts: list[Alert]) -> dict:
        severity_counts = Counter(
            alert.severity.name for alert in alerts
        )

        status_counts = Counter(
            alert.status.value for alert in alerts
        )

        tier_counts = Counter(
            alert.assigned_tier.name for alert in alerts
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_alerts": len(alerts),
            "severity_distribution": dict(severity_counts),
            "status_distribution": dict(status_counts),
            "tier_distribution": dict(tier_counts),
            "confirmed_incidents": sum(
                alert.status not in {
                    AlertStatus.FALSE_POSITIVE,
                    AlertStatus.CLOSED
                }
                for alert in alerts
            )
        }


# ---------------------------------------------------------
# 8. Secure audit export
# ---------------------------------------------------------

def export_report(report: dict, destination: str) -> None:
    path = Path(destination).resolve()

    if path.suffix.lower() != ".json":
        raise ValueError("Report must use JSON format")

    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_suffix(".tmp")

    try:
        temporary.write_text(
            json.dumps(report, indent=2),
            encoding="utf-8"
        )
        temporary.replace(path)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------
# 9. Operational tests
# ---------------------------------------------------------

class SOCTests(unittest.TestCase):

    def setUp(self):
        self.event = SecurityEvent(
            source="Firewall",
            event_type="authentication_failure",
            source_ip="203.0.113.45",
            destination="vpn-gateway",
            description="Repeated failed VPN authentication",
            timestamp=datetime.now(timezone.utc),
            failed_attempts=30
        )

    def test_detection(self):
        alert = DetectionEngine().analyze(self.event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, Severity.CRITICAL)

    def test_invalid_ip(self):
        event = SecurityEvent(
            "Firewall", "login", "999.999.999.999",
            "VPN", "Invalid IP",
            datetime.now(timezone.utc)
        )

        with self.assertRaises(ValueError):
            DetectionEngine().analyze(event)

    def test_lifecycle(self):
        alert = DetectionEngine().analyze(self.event)
        manager = IncidentManager()

        registry = AnalystRegistry()
        registry.register(Analyst(
            "A003", "Senior Analyst", SOCTier.TIER_3,
            frozenset({"brute_force"})
        ))

        EscalationEngine().assign(alert, registry)

        manager.transition(
            alert,
            AlertStatus.INVESTIGATING,
            "A003",
            "Investigation started"
        )

        manager.transition(
            alert,
            AlertStatus.CONTAINED,
            "A003",
            "Suspicious source blocked"
        )

        manager.transition(
            alert,
            AlertStatus.RESOLVED,
            "A003",
            "Access restored securely"
        )

        manager.transition(
            alert,
            AlertStatus.CLOSED,
            "A003",
            "Evidence and documentation completed"
        )

        self.assertEqual(alert.status, AlertStatus.CLOSED)

    def test_invalid_transition(self):
        alert = DetectionEngine().analyze(self.event)

        with self.assertRaises(ValueError):
            IncidentManager().transition(
                alert,
                AlertStatus.CLOSED,
                "A001",
                "Invalid direct closure"
            )


# ---------------------------------------------------------
# 10. End-to-end SOC simulation
# ---------------------------------------------------------

def main():
    registry = AnalystRegistry()

    registry.register(Analyst(
        "A001", "SOC Operator", SOCTier.TIER_1,
        frozenset({"brute_force", "phishing"})
    ))

    registry.register(Analyst(
        "A002", "Incident Responder", SOCTier.TIER_2,
        frozenset({"malware", "unauthorized_access"})
    ))

    registry.register(Analyst(
        "A003", "Threat Hunter", SOCTier.TIER_3,
        frozenset({
            "brute_force",
            "data_exfiltration",
            "network_intrusion"
        })
    ))

    events = [
        SecurityEvent(
            "Firewall", "authentication_failure",
            "203.0.113.45", "VPN Gateway",
            "Repeated failed login attempts",
            datetime.now(timezone.utc), 30
        ),
        SecurityEvent(
            "EDR", "malware_detected",
            "198.51.100.20", "Workstation-17",
            "Malware execution detected",
            datetime.now(timezone.utc)
        ),
        SecurityEvent(
            "Email Gateway", "phishing_report",
            "192.0.2.15", "Mail Server",
            "Suspicious attachment reported",
            datetime.now(timezone.utc)
        ),
        SecurityEvent(
            "Firewall", "normal_traffic",
            "192.0.2.40", "Internal Server",
            "Routine traffic",
            datetime.now(timezone.utc)
        )
    ]

    detector = DetectionEngine()
    escalation = EscalationEngine()
    incident_manager = IncidentManager()

    alerts = []

    for event in events:
        try:
            alert = detector.analyze(event)

            if alert is None:
                logger.info("No alert generated for %s", event.source)
                continue

            escalation.assign(alert, registry)

            if alert.assigned_analyst:
                incident_manager.transition(
                    alert,
                    AlertStatus.INVESTIGATING,
                    alert.assigned_analyst,
                    "Initial investigation commenced"
                )

            alerts.append(alert)

            logger.info(
                "Alert %s | Severity=%s | Tier=%s | Status=%s",
                alert.alert_id[:8],
                alert.severity.name,
                alert.assigned_tier.name,
                alert.status.value
            )

        except (ValueError, OSError) as exc:
            logger.error("Event processing failed: %s", exc)

    report = SOCReporter.generate(alerts)

    print("\nSOC OPERATIONAL REPORT")
    print(json.dumps(report, indent=2))

    export_report(report, "soc_report.json")

    print("\nINDIVIDUAL ALERTS")

    for alert in alerts:
        print(json.dumps({
            "alert_id": alert.alert_id,
            "type": alert.incident_type.value,
            "severity": alert.severity.name,
            "status": alert.status.value,
            "assigned_analyst": alert.assigned_analyst,
            "history": alert.history
        }, indent=2))

    print("\nRUNNING VALIDATION TESTS")
    unittest.main(argv=["soc"], exit=False)


if __name__ == "__main__":
    main()
