"""
ALERT TRIAGE ENGINE
Severity, confidence, false positives, enrichment, and investigation workflow.

Runtime: Python 3.10+
Dependencies: Python standard library only.

The program simulates a security operations alert-triage workflow:
1. Alert ingestion and validation.
2. Severity and confidence assessment.
3. Context enrichment.
4. False-positive evaluation.
5. Risk-based prioritization.
6. Analyst assignment.
7. Investigation and evidence collection.
8. Escalation and resolution.
9. Audit logging and reporting.
"""

from __future__ import annotations

import json
import logging
import statistics
import uuid

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Optional, Any


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

logger = logging.getLogger("alert_triage")


# ============================================================
# DOMAIN ENUMERATIONS
# ============================================================

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertStatus(Enum):
    NEW = "new"
    ENRICHING = "enriching"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Verdict(Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    UNDETERMINED = "undetermined"


class AnalystRole(Enum):
    L1 = "tier_1"
    L2 = "tier_2"
    L3 = "tier_3"


# ============================================================
# VALIDATION UTILITIES
# ============================================================

def validate_probability(value: float, field_name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field_name} must be numeric")

    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} must be between 0 and 1")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ============================================================
# DOMAIN MODELS
# ============================================================

@dataclass
class Evidence:
    evidence_type: str
    description: str
    reliability: float
    source: str
    observed_at: datetime = field(default_factory=utc_now)

    def __post_init__(self):
        validate_probability(self.reliability, "Evidence reliability")

        if not self.evidence_type.strip():
            raise ValueError("Evidence type cannot be empty")

        if not self.source.strip():
            raise ValueError("Evidence source cannot be empty")


@dataclass
class EnrichmentData:
    asset_criticality: float = 0.5
    threat_intelligence: float = 0.0
    known_malicious_indicator: bool = False
    asset_owner: str = "Unknown"
    business_context: str = "Unclassified"
    historical_alert_count: int = 0
    privileged_asset: bool = False

    def __post_init__(self):
        validate_probability(
            self.asset_criticality,
            "Asset criticality"
        )

        validate_probability(
            self.threat_intelligence,
            "Threat intelligence"
        )

        if self.historical_alert_count < 0:
            raise ValueError("Historical alert count cannot be negative")


@dataclass
class Analyst:
    analyst_id: str
    name: str
    role: AnalystRole
    max_active_cases: int = 5
    active_cases: int = 0
    specialties: set[str] = field(default_factory=set)

    def __post_init__(self):
        if self.max_active_cases < 1:
            raise ValueError("Maximum active cases must be positive")

        if not 0 <= self.active_cases <= self.max_active_cases:
            raise ValueError("Invalid active case count")

    @property
    def available(self) -> bool:
        return self.active_cases < self.max_active_cases


@dataclass
class AuditEvent:
    timestamp: datetime
    action: str
    actor: str
    details: dict[str, Any]


@dataclass
class SecurityAlert:
    alert_id: str
    title: str
    description: str
    source: str
    category: str
    asset_id: str
    severity: Severity
    confidence: float
    observed_at: datetime

    status: AlertStatus = AlertStatus.NEW
    verdict: Verdict = Verdict.UNDETERMINED
    enrichment: EnrichmentData = field(
        default_factory=EnrichmentData
    )
    evidence: list[Evidence] = field(default_factory=list)
    assigned_analyst: Optional[str] = None
    risk_score: float = 0.0
    investigation_notes: list[str] = field(default_factory=list)
    audit_log: list[AuditEvent] = field(default_factory=list)

    def __post_init__(self):
        validate_probability(self.confidence, "Confidence")

        if not self.alert_id.strip():
            raise ValueError("Alert ID cannot be empty")

        if not self.title.strip():
            raise ValueError("Alert title cannot be empty")

        if not self.asset_id.strip():
            raise ValueError("Asset ID cannot be empty")

        if self.observed_at.tzinfo is None:
            raise ValueError("Alert timestamp must include timezone")

    def record(self, action: str, actor: str, **details):
        self.audit_log.append(
            AuditEvent(
                timestamp=utc_now(),
                action=action,
                actor=actor,
                details=details
            )
        )


# ============================================================
# RISK SCORING
# ============================================================

class RiskScorer:
    """
    Calculates operational risk independently from detector confidence.

    Confidence describes confidence in the detection.
    Severity describes the potential impact.
    Enrichment contributes contextual risk.
    """

    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 1.00,
        Severity.HIGH: 0.80,
        Severity.MEDIUM: 0.55,
        Severity.LOW: 0.30,
        Severity.INFORMATIONAL: 0.10,
    }

    @staticmethod
    def calculate(alert: SecurityAlert) -> float:
        enrichment = alert.enrichment

        severity_score = RiskScorer.SEVERITY_WEIGHTS[
            alert.severity
        ]

        confidence_score = alert.confidence

        threat_score = enrichment.threat_intelligence

        asset_score = enrichment.asset_criticality

        privileged_bonus = (
            0.10 if enrichment.privileged_asset else 0.0
        )

        malicious_bonus = (
            0.15 if enrichment.known_malicious_indicator else 0.0
        )

        historical_bonus = min(
            enrichment.historical_alert_count * 0.01,
            0.10
        )

        weighted_score = (
            0.30 * severity_score
            + 0.25 * confidence_score
            + 0.20 * threat_score
            + 0.25 * asset_score
            + privileged_bonus
            + malicious_bonus
            + historical_bonus
        )

        alert.risk_score = min(
            round(weighted_score, 4),
            1.0
        )

        return alert.risk_score


# ============================================================
# FALSE-POSITIVE EVALUATION
# ============================================================

class FalsePositiveEvaluator:
    """
    False-positive decisions require contextual evidence.

    A low confidence score alone does not establish a
    false positive.
    """

    @staticmethod
    def evaluate(alert: SecurityAlert) -> Verdict:

        malicious_evidence = any(
            evidence.evidence_type in {
                "malware_detection",
                "confirmed_c2",
                "credential_theft",
                "unauthorized_access"
            }
            and evidence.reliability >= 0.70
            for evidence in alert.evidence
        )

        benign_evidence = any(
            evidence.evidence_type in {
                "approved_activity",
                "authorized_scanner",
                "maintenance_window",
                "verified_business_process"
            }
            and evidence.reliability >= 0.90
            for evidence in alert.evidence
        )

        if malicious_evidence:
            return Verdict.TRUE_POSITIVE

        if benign_evidence:
            return Verdict.FALSE_POSITIVE

        if (
            alert.confidence >= 0.90
            and alert.enrichment.known_malicious_indicator
        ):
            return Verdict.TRUE_POSITIVE

        return Verdict.UNDETERMINED


# ============================================================
# ALERT TRIAGE SERVICE
# ============================================================

class AlertTriageService:

    TRANSITIONS = {
        AlertStatus.NEW: {
            AlertStatus.ENRICHING,
            AlertStatus.CLOSED
        },
        AlertStatus.ENRICHING: {
            AlertStatus.TRIAGED,
            AlertStatus.ESCALATED
        },
        AlertStatus.TRIAGED: {
            AlertStatus.ASSIGNED,
            AlertStatus.ESCALATED,
            AlertStatus.CLOSED
        },
        AlertStatus.ASSIGNED: {
            AlertStatus.INVESTIGATING,
            AlertStatus.ESCALATED
        },
        AlertStatus.INVESTIGATING: {
            AlertStatus.ESCALATED,
            AlertStatus.RESOLVED
        },
        AlertStatus.ESCALATED: {
            AlertStatus.INVESTIGATING,
            AlertStatus.RESOLVED
        },
        AlertStatus.RESOLVED: {
            AlertStatus.CLOSED
        },
        AlertStatus.CLOSED: set()
    }

    def transition(
        self,
        alert: SecurityAlert,
        new_status: AlertStatus,
        actor: str
    ):
        allowed = self.TRANSITIONS[alert.status]

        if new_status not in allowed:
            raise ValueError(
                f"Invalid transition: {alert.status.value} "
                f"-> {new_status.value}"
            )

        previous = alert.status
        alert.status = new_status

        alert.record(
            "status_transition",
            actor,
            previous=previous.value,
            current=new_status.value
        )

    def ingest(self, alert: SecurityAlert):
        if alert.status != AlertStatus.NEW:
            raise ValueError("Only new alerts can be ingested")

        alert.record(
            "alert_ingested",
            "system",
            source=alert.source
        )

        logger.info("Ingested alert %s", alert.alert_id)

    def enrich(
        self,
        alert: SecurityAlert,
        enrichment: EnrichmentData
    ):
        self.transition(
            alert,
            AlertStatus.ENRICHING,
            "enrichment_service"
        )

        alert.enrichment = enrichment

        alert.record(
            "alert_enriched",
            "enrichment_service",
            asset_owner=enrichment.asset_owner,
            threat_score=enrichment.threat_intelligence
        )

        return enrichment

    def triage(self, alert: SecurityAlert):
        if alert.status != AlertStatus.ENRICHING:
            raise ValueError("Alert must be enriched before triage")

        verdict = FalsePositiveEvaluator.evaluate(alert)

        risk = RiskScorer.calculate(alert)

        alert.verdict = verdict

        alert.record(
            "triage_completed",
            "triage_engine",
            verdict=verdict.value,
            risk_score=risk
        )

        self.transition(
            alert,
            AlertStatus.TRIAGED,
            "triage_engine"
        )

        if verdict == Verdict.FALSE_POSITIVE:
            alert.investigation_notes.append(
                "Benign activity supported by reliable evidence."
            )

        return {
            "alert_id": alert.alert_id,
            "verdict": verdict.value,
            "risk_score": risk,
            "priority": self.priority(alert)
        }

    @staticmethod
    def priority(alert: SecurityAlert) -> str:
        if alert.risk_score >= 0.85:
            return "P1"

        if alert.risk_score >= 0.70:
            return "P2"

        if alert.risk_score >= 0.45:
            return "P3"

        return "P4"

    def assign(
        self,
        alert: SecurityAlert,
        analyst: Analyst
    ):
        if alert.status != AlertStatus.TRIAGED:
            raise ValueError("Only triaged alerts can be assigned")

        if alert.verdict == Verdict.FALSE_POSITIVE:
            raise ValueError("False positives do not require investigation")

        if not analyst.available:
            raise ValueError("Analyst capacity exhausted")

        required_role = (
            AnalystRole.L3
            if alert.risk_score >= 0.85
            else AnalystRole.L2
            if alert.risk_score >= 0.65
            else AnalystRole.L1
        )

        role_order = {
            AnalystRole.L1: 1,
            AnalystRole.L2: 2,
            AnalystRole.L3: 3
        }

        if role_order[analyst.role] < role_order[required_role]:
            raise ValueError("Analyst does not meet required tier")

        analyst.active_cases += 1
        alert.assigned_analyst = analyst.analyst_id

        self.transition(
            alert,
            AlertStatus.ASSIGNED,
            "assignment_service"
        )

        alert.record(
            "analyst_assigned",
            "assignment_service",
            analyst_id=analyst.analyst_id
        )

    def investigate(
        self,
        alert: SecurityAlert,
        analyst: Analyst,
        findings: str,
        evidence: Optional[Evidence] = None
    ):
        if alert.assigned_analyst != analyst.analyst_id:
            raise PermissionError("Analyst is not assigned to this alert")

        if alert.status not in {
            AlertStatus.ASSIGNED,
            AlertStatus.INVESTIGATING
        }:
            raise ValueError("Alert cannot enter investigation")

        if alert.status == AlertStatus.ASSIGNED:
            self.transition(
                alert,
                AlertStatus.INVESTIGATING,
                analyst.analyst_id
            )

        if not findings.strip():
            raise ValueError("Investigation findings cannot be empty")

        alert.investigation_notes.append(findings)

        if evidence:
            alert.evidence.append(evidence)

        alert.verdict = FalsePositiveEvaluator.evaluate(alert)

        alert.record(
            "investigation_update",
            analyst.analyst_id,
            findings=findings,
            verdict=alert.verdict.value
        )

    def escalate(self, alert: SecurityAlert, actor: str, reason: str):
        if not reason.strip():
            raise ValueError("Escalation reason is required")

        self.transition(
            alert,
            AlertStatus.ESCALATED,
            actor
        )

        alert.record(
            "alert_escalated",
            actor,
            reason=reason
        )

    def resolve(
        self,
        alert: SecurityAlert,
        actor: str,
        verdict: Verdict,
        findings: str
    ):
        if alert.status not in {
            AlertStatus.INVESTIGATING,
            AlertStatus.ESCALATED
        }:
            raise ValueError("Alert must be under investigation")

        if verdict == Verdict.UNDETERMINED:
            raise ValueError("Cannot resolve with undetermined verdict")

        if not findings.strip():
            raise ValueError("Resolution findings are required")

        alert.verdict = verdict

        self.transition(
            alert,
            AlertStatus.RESOLVED,
            actor
        )

        alert.investigation_notes.append(findings)

        alert.record(
            "alert_resolved",
            actor,
            verdict=verdict.value
        )

        return True

    def close(self, alert: SecurityAlert, actor: str):
        if alert.status != AlertStatus.RESOLVED:
            raise ValueError("Only resolved alerts can be closed")

        self.transition(
            alert,
            AlertStatus.CLOSED,
            actor
        )

        alert.record("alert_closed", actor)


# ============================================================
# PRIORITY QUEUE
# ============================================================

class AlertQueue:
    """
    Heap-based priority queue.
    Higher risk scores are processed first.
    """

    def __init__(self):
        import heapq
        self._heapq = heapq
        self._items = []
        self._sequence = 0

    def add(self, alert: SecurityAlert):
        self._sequence += 1

        self._heapq.heappush(
            self._items,
            (
                -alert.risk_score,
                self._sequence,
                alert
            )
        )

    def pop(self) -> Optional[SecurityAlert]:
        if not self._items:
            return None

        return self._heapq.heappop(self._items)[2]

    def __len__(self):
        return len(self._items)


# ============================================================
# REPORTING
# ============================================================

class AlertReporter:

    @staticmethod
    def generate(alerts: list[SecurityAlert]) -> dict:

        status_counts = Counter(
            alert.status.value for alert in alerts
        )

        verdict_counts = Counter(
            alert.verdict.value for alert in alerts
        )

        severity_counts = Counter(
            alert.severity.value for alert in alerts
        )

        average_confidence = (
            statistics.mean(
                alert.confidence for alert in alerts
            )
            if alerts else 0.0
        )

        average_risk = (
            statistics.mean(
                alert.risk_score for alert in alerts
            )
            if alerts else 0.0
        )

        false_positive_rate = (
            verdict_counts[Verdict.FALSE_POSITIVE.value]
            / len(alerts)
            if alerts else 0.0
        )

        return {
            "total_alerts": len(alerts),
            "status_distribution": dict(status_counts),
            "severity_distribution": dict(severity_counts),
            "verdict_distribution": dict(verdict_counts),
            "average_confidence": round(average_confidence, 4),
            "average_risk": round(average_risk, 4),
            "false_positive_rate": round(false_positive_rate, 4)
        }


# ============================================================
# SAMPLE SECURITY OPERATIONS SCENARIO
# ============================================================

def build_sample_alerts() -> list[SecurityAlert]:

    now = utc_now()

    return [
        SecurityAlert(
            alert_id="ALT-1001",
            title="Suspicious privileged login",
            description="Privileged account login from unusual location",
            source="SIEM",
            category="identity",
            asset_id="SRV-001",
            severity=Severity.CRITICAL,
            confidence=0.96,
            observed_at=now - timedelta(minutes=8),
            evidence=[
                Evidence(
                    "unauthorized_access",
                    "Unusual privileged login confirmed",
                    0.95,
                    "Identity monitoring"
                )
            ]
        ),
        SecurityAlert(
            alert_id="ALT-1002",
            title="Repeated failed authentication",
            description="Multiple failed login attempts",
            source="SIEM",
            category="authentication",
            asset_id="WS-102",
            severity=Severity.MEDIUM,
            confidence=0.75,
            observed_at=now - timedelta(minutes=20)
        ),
        SecurityAlert(
            alert_id="ALT-1003",
            title="Authorized vulnerability scan",
            description="Scheduled internal vulnerability scan",
            source="EDR",
            category="network",
            asset_id="SRV-003",
            severity=Severity.HIGH,
            confidence=0.92,
            observed_at=now - timedelta(minutes=35),
            evidence=[
                Evidence(
                    "authorized_scanner",
                    "Approved scanning window confirmed",
                    0.98,
                    "Change management"
                )
            ]
        )
    ]


def main():

    service = AlertTriageService()

    alerts = build_sample_alerts()

    analysts = [
        Analyst("AN-01", "Analyst One", AnalystRole.L1, 4),
        Analyst("AN-02", "Analyst Two", AnalystRole.L2, 5),
        Analyst("AN-03", "Analyst Three", AnalystRole.L3, 5)
    ]

    enrichment_records = {
        "ALT-1001": EnrichmentData(
            asset_criticality=0.98,
            threat_intelligence=0.95,
            known_malicious_indicator=True,
            asset_owner="Infrastructure Security",
            business_context="Production identity server",
            privileged_asset=True
        ),
        "ALT-1002": EnrichmentData(
            asset_criticality=0.45,
            threat_intelligence=0.35,
            asset_owner="End User Computing",
            business_context="Employee workstation",
            historical_alert_count=3
        ),
        "ALT-1003": EnrichmentData(
            asset_criticality=0.70,
            threat_intelligence=0.05,
            asset_owner="Security Engineering",
            business_context="Scanning infrastructure"
        )
    }

    queue = AlertQueue()

    for alert in alerts:

        service.ingest(alert)

        service.enrich(
            alert,
            enrichment_records[alert.alert_id]
        )

        result = service.triage(alert)

        print("\nTRIAGE RESULT")
        print(json.dumps(result, indent=2))

        if alert.verdict != Verdict.FALSE_POSITIVE:
            queue.add(alert)

    analyst_lookup = {
        AnalystRole.L1: analysts[0],
        AnalystRole.L2: analysts[1],
        AnalystRole.L3: analysts[2]
    }

    print("\nINVESTIGATION QUEUE")

    while len(queue):

        alert = queue.pop()

        required_role = (
            AnalystRole.L3
            if alert.risk_score >= 0.85
            else AnalystRole.L2
            if alert.risk_score >= 0.65
            else AnalystRole.L1
        )

        analyst = analyst_lookup[required_role]

        try:
            service.assign(alert, analyst)

            service.investigate(
                alert,
                analyst,
                "Reviewed authentication records and endpoint telemetry."
            )

            final_verdict = (
                Verdict.TRUE_POSITIVE
                if alert.alert_id == "ALT-1001"
                else Verdict.UNDETERMINED
            )

            if final_verdict != Verdict.UNDETERMINED:
                service.resolve(
                    alert,
                    analyst.analyst_id,
                    final_verdict,
                    "Incident evidence validated."
                )

                service.close(alert, analyst.analyst_id)

                analyst.active_cases -= 1

            else:
                service.escalate(
                    alert,
                    analyst.analyst_id,
                    "Additional investigation required."
                )

        except (ValueError, PermissionError) as exc:
            logger.error(
                "Processing failed for %s: %s",
                alert.alert_id,
                exc
            )

    report = AlertReporter.generate(alerts)

    print("\nSECURITY OPERATIONS REPORT")
    print(json.dumps(report, indent=2))

    print("\nAUDIT LOG COUNTS")

    for alert in alerts:
        print(
            alert.alert_id,
            len(alert.audit_log),
            alert.status.value,
            alert.verdict.value
        )

    # Core invariants.
    assert len(alerts) == 3
    assert alerts[2].verdict == Verdict.FALSE_POSITIVE
    assert alerts[0].status == AlertStatus.CLOSED
    assert report["total_alerts"] == 3

    print("\nAll validation assertions passed.")


if __name__ == "__main__":
    main()
