"""
Security Terminology: IOC, IOA, TTP, Exploit, Payload, Vulnerability,
Breach, Incident, Event, Alert, and Detection

This is a self-contained educational script designed to demonstrate how
these security terms relate to one another and how they are used in practical
cybersecurity operations.

The examples use simulated data only. No real systems are scanned, attacked,
exploited, or modified.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from collections import Counter, defaultdict
from typing import Any, Iterable, Optional
import hashlib
import ipaddress
import re
import statistics


# ============================================================================
# 1. FUNDAMENTAL TERMINOLOGY
# ============================================================================

print("=" * 80)
print("SECURITY TERMINOLOGY")
print("=" * 80)

print(
    """
The central distinction in security operations is:

Event       -> Something happened.
Alert       -> A security control believes an event deserves attention.
Detection   -> The logic/process used to identify suspicious or malicious
               behavior.
Incident    -> A confirmed or suspected security event requiring response.
Breach      -> Unauthorized access, disclosure, acquisition, or compromise
               of protected information or systems, depending on the
               applicable legal and organizational definition.

Vulnerability -> A weakness that can be exploited.
Exploit       -> The method, technique, or code used to take advantage of
                 a vulnerability.
Payload       -> The action, data, or content delivered/executed after or
                 during exploitation.

IOC -> Evidence that may indicate compromise.
IOA -> Evidence describing suspicious or malicious behavior.
TTP -> Tactics, techniques, and procedures used by an adversary.

A useful conceptual chain is:

Vulnerability
      |
      v
    Exploit
      |
      v
   Payload
      |
      v
  Adversary behavior
      |
      +----> IOA / TTP observations
      |
      +----> IOC artifacts
      |
      v
     Event
      |
      v
   Detection
      |
      v
     Alert
      |
      v
 Investigation
      |
      v
   Incident
      |
      v
 Possible breach
"""
)


# ============================================================================
# 2. ENUMERATIONS
# ============================================================================

class Severity(Enum):
    """Common operational severity categories."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(Enum):
    """Types of simulated security-relevant events."""

    LOGIN = "login"
    PROCESS_START = "process_start"
    NETWORK_CONNECTION = "network_connection"
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    DNS_QUERY = "dns_query"
    AUTHENTICATION_FAILURE = "authentication_failure"
    PRIVILEGE_CHANGE = "privilege_change"
    DATA_TRANSFER = "data_transfer"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CONFIGURATION_CHANGE = "configuration_change"


class IndicatorType(Enum):
    """Common IOC categories."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_NAME = "file_name"
    FILE_PATH = "file_path"
    EMAIL_ADDRESS = "email_address"
    REGISTRY_KEY = "registry_key"


class AlertStatus(Enum):
    """Lifecycle state of an alert."""

    NEW = "new"
    INVESTIGATING = "investigating"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


# ============================================================================
# 3. BASIC DATA MODELS
# ============================================================================

@dataclass
class Vulnerability:
    """
    Represents a weakness in software, hardware, configuration, or process.

    A vulnerability is not itself an exploit.
    It is a condition that may permit an attacker to cause an unintended
    security impact.
    """

    vulnerability_id: str
    description: str
    affected_asset: str
    severity: Severity
    remotely_exploitable: bool
    patched: bool = False


@dataclass
class Exploit:
    """
    Represents a method for taking advantage of a vulnerability.

    This simulation intentionally stores only descriptive metadata rather
    than operational exploit code.
    """

    exploit_id: str
    vulnerability_id: str
    description: str
    publicly_known: bool
    requires_authentication: bool


@dataclass
class Payload:
    """
    Represents content or an action delivered through an attack mechanism.

    A payload may be malicious code, a command, a file, or another action.
    """

    payload_id: str
    description: str
    delivery_method: str
    expected_effect: str


@dataclass
class IOC:
    """
    Indicator of Compromise.

    IOCs are observable artifacts that can provide evidence associated with
    malicious activity or compromise.
    """

    indicator_type: IndicatorType
    value: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    malicious: bool = True
    context: str = ""

    def normalized_value(self) -> str:
        """Normalize the IOC so matching is less sensitive to formatting."""

        value = self.value.strip()

        if self.indicator_type in {
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.EMAIL_ADDRESS,
        }:
            return value.lower()

        if self.indicator_type == IndicatorType.IP_ADDRESS:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                return value

        return value


@dataclass
class TTP:
    """
    Tactics, Techniques, and Procedures.

    Tactics represent goals.
    Techniques describe methods used to achieve those goals.
    Procedures describe concrete implementations or variations.
    """

    tactic: str
    technique_id: str
    technique_name: str
    procedure: str
    description: str


@dataclass
class SecurityEvent:
    """
    An event is an observable occurrence.

    Most events are not malicious. Security monitoring begins with large
    quantities of events and attempts to identify meaningful patterns.
    """

    event_id: str
    timestamp: datetime
    event_type: EventType
    source: str
    user: Optional[str]
    host: str
    description: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class Detection:
    """
    A detection is logic that identifies potentially interesting activity.

    A detection may be signature-based, IOC-based, behavior-based,
    correlation-based, anomaly-based, or a combination.
    """

    detection_id: str
    name: str
    description: str
    severity: Severity
    detection_type: str


@dataclass
class Alert:
    """
    An alert is the operational output of a detection or security control.

    An alert is not automatically a confirmed incident.
    """

    alert_id: str
    detection_id: str
    event_id: str
    timestamp: datetime
    title: str
    severity: Severity
    status: AlertStatus = AlertStatus.NEW
    confidence: float = 0.0
    analyst_notes: list[str] = field(default_factory=list)


@dataclass
class Incident:
    """
    An incident represents a security situation requiring investigation or
    response according to organizational criteria.
    """

    incident_id: str
    title: str
    severity: Severity
    related_alerts: list[str]
    confirmed: bool
    description: str
    created_at: datetime


@dataclass
class Breach:
    """
    Represents a simulated confirmed compromise involving protected assets
    or information.

    A security incident does not necessarily become a breach.
    """

    breach_id: str
    incident_id: str
    affected_assets: list[str]
    data_involved: list[str]
    confirmed_at: datetime
    notification_required: Optional[bool] = None


# ============================================================================
# 4. VULNERABILITY
# ============================================================================

print("\n" + "=" * 80)
print("VULNERABILITY")
print("=" * 80)

vulnerability = Vulnerability(
    vulnerability_id="VULN-2026-001",
    description="A server application contains an input-validation weakness.",
    affected_asset="application-server-01",
    severity=Severity.HIGH,
    remotely_exploitable=True,
)

print(vulnerability)

print(
    """
A vulnerability can exist without being exploited.

Important distinction:

Vulnerability:
    A weakness exists.

Exploit:
    Someone uses a technique or mechanism to take advantage of that weakness.

Compromise:
    The attack succeeds in gaining unauthorized capability, access, or
    control.

This distinction matters because vulnerability management and incident
response solve different problems.
"""
)


# ============================================================================
# 5. EXPLOIT
# ============================================================================

print("\n" + "=" * 80)
print("EXPLOIT")
print("=" * 80)

exploit = Exploit(
    exploit_id="EXP-001",
    vulnerability_id=vulnerability.vulnerability_id,
    description="A simulated technique that abuses the vulnerable input path.",
    publicly_known=True,
    requires_authentication=False,
)

print(exploit)

print(
    """
An exploit is not necessarily malware.

An exploit can be:

- A sequence of specially constructed requests.
- A malicious document triggering a software flaw.
- A local privilege-escalation technique.
- A memory-corruption technique.
- Abuse of a misconfiguration when the organization treats that weakness
  as a vulnerability.

The word "exploit" describes exploitation of a weakness, not necessarily
the final malicious action.
"""
)


# ============================================================================
# 6. PAYLOAD
# ============================================================================

print("\n" + "=" * 80)
print("PAYLOAD")
print("=" * 80)

payload = Payload(
    payload_id="PAY-001",
    description="Simulated post-exploitation action.",
    delivery_method="application request",
    expected_effect="Create unauthorized process execution.",
)

print(payload)

print(
    """
Exploit and payload are related but different.

Exploit:
    How a weakness is taken advantage of.

Payload:
    What is delivered or what action is performed as part of the attack.

For example, conceptually:

weakness -> exploitation mechanism -> payload -> resulting behavior

An exploit can succeed while a payload fails.
A payload can also be delivered through mechanisms that do not depend on
a traditional software vulnerability.
"""
)


# ============================================================================
# 7. IOC
# ============================================================================

print("\n" + "=" * 80)
print("IOC: INDICATOR OF COMPROMISE")
print("=" * 80)

base_time = datetime(2026, 9, 4, 9, 0, 0)

iocs = [
    IOC(
        indicator_type=IndicatorType.IP_ADDRESS,
        value="203.0.113.50",
        confidence=0.97,
        source="threat_intelligence_feed",
        first_seen=base_time,
        last_seen=base_time + timedelta(hours=3),
        context="Simulated command-and-control infrastructure",
    ),
    IOC(
        indicator_type=IndicatorType.DOMAIN,
        value="malicious-example.test",
        confidence=0.91,
        source="internal_investigation",
        first_seen=base_time,
        last_seen=base_time + timedelta(hours=1),
        context="Observed during simulated investigation",
    ),
    IOC(
        indicator_type=IndicatorType.FILE_HASH,
        value="a" * 64,
        confidence=0.99,
        source="malware_analysis",
        first_seen=base_time,
        last_seen=base_time + timedelta(hours=4),
        context="Simulated SHA-256 artifact",
    ),
]

for indicator in iocs:
    print(
        indicator.indicator_type.value,
        indicator.normalized_value(),
        f"confidence={indicator.confidence:.0%}",
    )

print(
    """
Common IOC categories include:

- IP addresses
- Domains
- URLs
- File hashes
- File names
- File paths
- Email addresses
- Registry locations
- Certificates
- Malware-specific artifacts

An IOC is generally an artifact, not a complete description of attacker
behavior.

For example:

IOC:
    A suspicious IP address was contacted.

IOA:
    A process launched an unusual interpreter and immediately made an
    outbound connection.

The second observation describes behavior rather than simply an artifact.
"""
)


# ============================================================================
# 8. IOC NORMALIZATION
# ============================================================================

print("\n" + "=" * 80)
print("IOC NORMALIZATION")
print("=" * 80)

ioc_examples = [
    IOC(
        indicator_type=IndicatorType.DOMAIN,
        value="  MALICIOUS-EXAMPLE.TEST ",
        confidence=0.9,
        source="feed",
        first_seen=base_time,
        last_seen=base_time,
    ),
    IOC(
        indicator_type=IndicatorType.IP_ADDRESS,
        value="203.0.113.50",
        confidence=0.9,
        source="feed",
        first_seen=base_time,
        last_seen=base_time,
    ),
]

for indicator in ioc_examples:
    print(f"Original:   {indicator.value!r}")
    print(f"Normalized: {indicator.normalized_value()!r}")

print(
    """
Normalization reduces false negatives caused by formatting differences.

Real security systems may normalize:

- Domain case.
- URL encoding.
- IP representation.
- Hash formatting.
- File-path separators.
- Email address casing where appropriate.

Normalization must be performed carefully because aggressive normalization
can also cause distinct values to become incorrectly equivalent.
"""
)


# ============================================================================
# 9. IOA: INDICATOR OF ATTACK
# ============================================================================

print("\n" + "=" * 80)
print("IOA: INDICATOR OF ATTACK")
print("=" * 80)

ioa_examples = [
    {
        "behavior": "Repeated authentication failures followed by success",
        "why_interesting": "May indicate password guessing or credential abuse",
    },
    {
        "behavior": "Unusual interpreter execution by a server process",
        "why_interesting": "May indicate command execution through application abuse",
    },
    {
        "behavior": "A user account accesses systems it never previously accessed",
        "why_interesting": "May indicate lateral movement or compromised credentials",
    },
]

for item in ioa_examples:
    print(f"- {item['behavior']}")
    print(f"  Reason: {item['why_interesting']}")

print(
    """
IOAs focus on activity patterns.

An IOC often answers:
    "What artifact should I look for?"

An IOA often answers:
    "What suspicious behavior should I look for?"

IOA-oriented detection can be more resilient to IOC changes because attackers
can change domains, IP addresses, filenames, and hashes while retaining
similar behavior.
"""
)


# ============================================================================
# 10. TTP
# ============================================================================

print("\n" + "=" * 80)
print("TTP: TACTICS, TECHNIQUES, AND PROCEDURES")
print("=" * 80)

ttps = [
    TTP(
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        procedure="Attempt to obtain credential material from an operating system.",
        description="Technique-level behavior used to obtain credentials.",
    ),
    TTP(
        tactic="Execution",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        procedure="Use a command interpreter or scripting environment.",
        description="Execution technique that may be legitimate or malicious.",
    ),
    TTP(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        procedure="Use remote services to access another system.",
        description="Technique associated with movement between systems.",
    ),
]

for ttp in ttps:
    print(f"{ttp.tactic} | {ttp.technique_id} | {ttp.technique_name}")
    print(f"  Procedure: {ttp.procedure}")

print(
    """
TTP is a broader behavioral concept than IOC.

Tactics:
    The adversary's goal or stage.

Techniques:
    The method used to achieve the goal.

Procedures:
    Concrete ways a technique may be implemented.

A useful abstraction is:

Tactic
  |
  +-- Technique
        |
        +-- Procedure

TTP-based defense is valuable because adversaries may change individual
artifacts while continuing to use similar operational methods.
"""
)


# ============================================================================
# 11. IOC VS IOA VS TTP
# ============================================================================

print("\n" + "=" * 80)
print("IOC VS IOA VS TTP")
print("=" * 80)

comparison = [
    ("IOC", "Observable artifact", "IP address, hash, domain", "Often narrower"),
    ("IOA", "Suspicious behavior", "Unusual process/network sequence", "Behavior-oriented"),
    ("TTP", "Adversary method", "Technique used to execute or move", "Broad behavioral context"),
]

print(f"{'Concept':<10} {'Primary focus':<25} {'Example':<40} {'Nature':<25}")
print("-" * 105)

for row in comparison:
    print(f"{row[0]:<10} {row[1]:<25} {row[2]:<40} {row[3]:<25}")

print(
    """
The concepts can overlap.

For example:

An attacker uses a remote service.

TTP:
    Remote Services is the technique.

IOA:
    An account suddenly starts making unusual remote connections.

IOC:
    A specific suspicious source address is repeatedly observed.

Detection:
    A rule correlates the remote connection behavior with identity and
    asset context.

Alert:
    The rule generates an alert.

Incident:
    Analysts determine the activity is unauthorized and part of an attack.

Breach:
    Investigation confirms protected data was accessed or acquired,
    depending on the organization's and jurisdiction's definition.
"""
)


# ============================================================================
# 12. SECURITY EVENTS
# ============================================================================

print("\n" + "=" * 80)
print("EVENT")
print("=" * 80)

events = [
    SecurityEvent(
        event_id="EVT-001",
        timestamp=base_time,
        event_type=EventType.LOGIN,
        source="identity_provider",
        user="alice",
        host="workstation-01",
        description="Successful login",
        attributes={"source_ip": "198.51.100.10"},
    ),
    SecurityEvent(
        event_id="EVT-002",
        timestamp=base_time + timedelta(minutes=1),
        event_type=EventType.AUTHENTICATION_FAILURE,
        source="identity_provider",
        user="admin",
        host="server-01",
        description="Failed authentication",
        attributes={"source_ip": "203.0.113.90"},
    ),
    SecurityEvent(
        event_id="EVT-003",
        timestamp=base_time + timedelta(minutes=2),
        event_type=EventType.PROCESS_START,
        source="endpoint",
        user="admin",
        host="server-01",
        description="New process started",
        attributes={"process": "script-interpreter"},
    ),
]

for event in events:
    print(
        f"{event.event_id} | {event.timestamp.isoformat()} | "
        f"{event.event_type.value} | {event.host} | {event.description}"
    )

print(
    """
An event is not automatically malicious.

Examples of legitimate events:

- Successful login.
- Process creation.
- DNS query.
- File creation.
- Network connection.
- Configuration change.

Security monitoring must distinguish ordinary activity from activity that
is suspicious in context.
"""
)


# ============================================================================
# 13. EVENT VS ALERT
# ============================================================================

print("\n" + "=" * 80)
print("EVENT VS ALERT")
print("=" * 80)

print(
    """
Suppose a firewall records:

    Connection from 203.0.113.50 to server-01.

That is an event.

If a detection system knows that 203.0.113.50 is a high-confidence malicious
indicator and produces:

    HIGH: Server contacted known malicious infrastructure.

That is an alert.

The alert is an interpretation of one or more events.
"""
)


# ============================================================================
# 14. DETECTION
# ============================================================================

print("\n" + "=" * 80)
print("DETECTION")
print("=" * 80)

detections = [
    Detection(
        detection_id="DET-IOC-001",
        name="Known Malicious IP",
        description="Detect communication with a high-confidence IOC.",
        severity=Severity.HIGH,
        detection_type="IOC-based",
    ),
    Detection(
        detection_id="DET-BEH-001",
        name="Authentication Burst",
        description="Detect repeated failures followed by successful login.",
        severity=Severity.MEDIUM,
        detection_type="Behavior-based",
    ),
    Detection(
        detection_id="DET-COR-001",
        name="Suspicious Execution Chain",
        description="Correlate unusual process execution with network activity.",
        severity=Severity.HIGH,
        detection_type="Correlation-based",
    ),
]

for detection in detections:
    print(
        f"{detection.detection_id} | "
        f"{detection.detection_type} | "
        f"{detection.name}"
    )

print(
    """
Detection is the logic or capability used to identify activity of interest.

Common detection approaches:

1. Signature-based
   Looks for known patterns.

2. IOC-based
   Matches known artifacts.

3. Rule-based
   Uses explicit conditions.

4. Behavior-based
   Identifies suspicious activity patterns.

5. Anomaly-based
   Looks for deviations from a baseline.

6. Correlation-based
   Combines multiple events or signals.

7. Statistical or machine-learning-assisted
   Uses statistical patterns or learned models.

No single method is sufficient for every environment.
"""
)


# ============================================================================
# 15. SIMPLE IOC DETECTION
# ============================================================================

print("\n" + "=" * 80)
print("IOC-BASED DETECTION")
print("=" * 80)


def build_ioc_index(indicators: Iterable[IOC]) -> dict[str, set[str]]:
    """Build a lookup index grouped by indicator type."""

    index: dict[str, set[str]] = defaultdict(set)

    for indicator in indicators:
        index[indicator.indicator_type.value].add(
            indicator.normalized_value()
        )

    return dict(index)


def detect_ioc_match(
    event: SecurityEvent,
    ioc_index: dict[str, set[str]],
) -> list[str]:
    """
    Match event attributes against known IOCs.

    This is a deliberately simple demonstration. Production systems require
    richer parsing, normalization, context, expiration, confidence, and
    allowlisting.
    """

    matches: list[str] = []

    source_ip = event.attributes.get("source_ip")
    destination_ip = event.attributes.get("destination_ip")
    domain = event.attributes.get("domain")

    ip_values = {
        value
        for value in (source_ip, destination_ip)
        if isinstance(value, str)
    }

    for ip_value in ip_values:
        if ip_value in ioc_index.get(IndicatorType.IP_ADDRESS.value, set()):
            matches.append(f"malicious_ip:{ip_value}")

    if isinstance(domain, str):
        if domain.lower() in ioc_index.get(
            IndicatorType.DOMAIN.value, set()
        ):
            matches.append(f"malicious_domain:{domain.lower()}")

    return matches


ioc_index = build_ioc_index(iocs)

network_event = SecurityEvent(
    event_id="EVT-IOC-001",
    timestamp=base_time + timedelta(minutes=5),
    event_type=EventType.NETWORK_CONNECTION,
    source="firewall",
    user=None,
    host="server-01",
    description="Outbound network connection",
    attributes={
        "destination_ip": "203.0.113.50",
        "destination_port": 443,
    },
)

matches = detect_ioc_match(network_event, ioc_index)

print("IOC index:", ioc_index)
print("Matches:", matches)


# ============================================================================
# 16. BEHAVIOR-BASED DETECTION
# ============================================================================

print("\n" + "=" * 80)
print("BEHAVIOR-BASED DETECTION")
print("=" * 80)


def detect_authentication_burst(
    events: Iterable[SecurityEvent],
    failure_threshold: int = 5,
    window_minutes: int = 10,
) -> list[dict[str, Any]]:
    """
    Identify users with repeated authentication failures within a time window.

    This is a simplified behavioral detector.

    Important:
    Repeated failures do not prove an attack. They may be caused by:
    - Forgotten passwords.
    - Misconfigured applications.
    - Expired credentials.
    - Automated jobs.
    - Password guessing.
    """

    authentication_events = sorted(
        (
            event
            for event in events
            if event.event_type == EventType.AUTHENTICATION_FAILURE
            and event.user
        ),
        key=lambda event: event.timestamp,
    )

    findings: list[dict[str, Any]] = []

    for index, event in enumerate(authentication_events):
        window_end = event.timestamp + timedelta(minutes=window_minutes)

        count = sum(
            1
            for candidate in authentication_events[index:]
            if candidate.user == event.user
            and candidate.timestamp <= window_end
        )

        if count >= failure_threshold:
            findings.append(
                {
                    "user": event.user,
                    "start": event.timestamp,
                    "failures": count,
                }
            )

    return findings


auth_events = [
    SecurityEvent(
        event_id=f"AUTH-{number}",
        timestamp=base_time + timedelta(minutes=number),
        event_type=EventType.AUTHENTICATION_FAILURE,
        source="identity_provider",
        user="admin",
        host="identity-server",
        description="Failed authentication",
        attributes={"source_ip": "198.51.100.25"},
    )
    for number in range(6)
]

auth_findings = detect_authentication_burst(auth_events)

for finding in auth_findings:
    print(finding)


# ============================================================================
# 17. CORRELATION
# ============================================================================

print("\n" + "=" * 80)
print("CORRELATION-BASED DETECTION")
print("=" * 80)


def correlate_suspicious_sequence(
    events: Iterable[SecurityEvent],
) -> list[dict[str, Any]]:
    """
    Look for a simplified sequence:

        authentication failures
              |
              v
        successful login
              |
              v
        process execution
              |
              v
        network connection

    Real detection engineering requires careful time windows, identity
    context, asset criticality, baselines, exclusions, and validation.
    """

    sorted_events = sorted(events, key=lambda event: event.timestamp)
    findings: list[dict[str, Any]] = []

    for index, event in enumerate(sorted_events):
        if event.event_type != EventType.LOGIN:
            continue

        user = event.user

        preceding_failures = [
            candidate
            for candidate in sorted_events[max(0, index - 10):index]
            if candidate.user == user
            and candidate.event_type == EventType.AUTHENTICATION_FAILURE
        ]

        following_process = next(
            (
                candidate
                for candidate in sorted_events[index + 1:index + 10]
                if candidate.user == user
                and candidate.event_type == EventType.PROCESS_START
            ),
            None,
        )

        following_network = next(
            (
                candidate
                for candidate in sorted_events[index + 1:index + 15]
                if candidate.event_type == EventType.NETWORK_CONNECTION
                and candidate.host == event.host
            ),
            None,
        )

        if preceding_failures and following_process and following_network:
            findings.append(
                {
                    "user": user,
                    "failed_authentication_count": len(preceding_failures),
                    "process_event": following_process.event_id,
                    "network_event": following_network.event_id,
                }
            )

    return findings


sequence_events = [
    SecurityEvent(
        event_id="SEQ-001",
        timestamp=base_time,
        event_type=EventType.AUTHENTICATION_FAILURE,
        source="identity",
        user="bob",
        host="server-02",
        description="Authentication failure",
    ),
    SecurityEvent(
        event_id="SEQ-002",
        timestamp=base_time + timedelta(minutes=1),
        event_type=EventType.AUTHENTICATION_FAILURE,
        source="identity",
        user="bob",
        host="server-02",
        description="Authentication failure",
    ),
    SecurityEvent(
        event_id="SEQ-003",
        timestamp=base_time + timedelta(minutes=2),
        event_type=EventType.LOGIN,
        source="identity",
        user="bob",
        host="server-02",
        description="Successful login",
    ),
    SecurityEvent(
        event_id="SEQ-004",
        timestamp=base_time + timedelta(minutes=3),
        event_type=EventType.PROCESS_START,
        source="endpoint",
        user="bob",
        host="server-02",
        description="Process started",
    ),
    SecurityEvent(
        event_id="SEQ-005",
        timestamp=base_time + timedelta(minutes=4),
        event_type=EventType.NETWORK_CONNECTION,
        source="endpoint",
        user="bob",
        host="server-02",
        description="Outbound connection",
    ),
]

for finding in correlate_suspicious_sequence(sequence_events):
    print(finding)


# ============================================================================
# 18. ALERT CREATION
# ============================================================================

print("\n" + "=" * 80)
print("ALERT")
print("=" * 80)


def create_alert(
    detection: Detection,
    event: SecurityEvent,
    confidence: float,
    title: str,
) -> Alert:
    """Create an operational alert from a detection result."""

    return Alert(
        alert_id=f"ALT-{event.event_id}",
        detection_id=detection.detection_id,
        event_id=event.event_id,
        timestamp=event.timestamp,
        title=title,
        severity=detection.severity,
        confidence=max(0.0, min(1.0, confidence)),
    )


ioc_detection = detections[0]

alert = create_alert(
    detection=ioc_detection,
    event=network_event,
    confidence=0.97,
    title="Connection to known suspicious infrastructure",
)

print(alert)


# ============================================================================
# 19. ALERT IS NOT INCIDENT
# ============================================================================

print("\n" + "=" * 80)
print("ALERT IS NOT AUTOMATICALLY AN INCIDENT")
print("=" * 80)

print(
    """
A detection can be correct while the alert does not represent a security
incident.

Example:

Detection:
    Login from an unusual country.

Alert:
    Generated.

Investigation:
    The employee is confirmed to be traveling.

Result:
    False positive from the perspective of malicious activity.

Another example:

Detection:
    Endpoint contacted a suspicious IP.

Investigation:
    The IP is actually shared infrastructure used by a legitimate service.

Result:
    Benign or false positive.

A third example:

Detection:
    Known malicious file hash detected.

Investigation:
    File is confirmed malicious and executed on a production server.

Result:
    Likely security incident.
"""
)


# ============================================================================
# 20. ALERT LIFECYCLE
# ============================================================================

print("\n" + "=" * 80)
print("ALERT LIFECYCLE")
print("=" * 80)


def update_alert_status(
    alert: Alert,
    status: AlertStatus,
    note: str,
) -> None:
    """Update alert state and record analyst reasoning."""

    alert.status = status
    alert.analyst_notes.append(note)


update_alert_status(
    alert,
    AlertStatus.INVESTIGATING,
    "Analyst is validating the destination infrastructure.",
)

update_alert_status(
    alert,
    AlertStatus.TRUE_POSITIVE,
    "Activity confirmed as unauthorized in this simulation.",
)

print("Status:", alert.status.value)
print("Notes:")

for note in alert.analyst_notes:
    print(" -", note)


# ============================================================================
# 21. INCIDENT
# ============================================================================

print("\n" + "=" * 80)
print("INCIDENT")
print("=" * 80)

incident = Incident(
    incident_id="INC-2026-001",
    title="Unauthorized server activity",
    severity=Severity.HIGH,
    related_alerts=[alert.alert_id],
    confirmed=True,
    description=(
        "Investigation determined that the alert represented unauthorized "
        "activity against a production asset."
    ),
    created_at=base_time + timedelta(minutes=10),
)

print(incident)

print(
    """
An incident is a security event or set of events that meets an
organization's incident criteria.

Incident criteria vary.

A failed login may be an event.
Thousands of failed logins may generate an alert.
A confirmed credential attack may become an incident.
A confirmed compromise may become a high-severity incident.
A confirmed compromise involving protected information may constitute a
breach under the applicable definition.
"""
)


# ============================================================================
# 22. BREACH
# ============================================================================

print("\n" + "=" * 80)
print("BREACH")
print("=" * 80)

breach = Breach(
    breach_id="BR-2026-001",
    incident_id=incident.incident_id,
    affected_assets=["application-server-01"],
    data_involved=["customer-records"],
    confirmed_at=base_time + timedelta(hours=2),
    notification_required=None,
)

print(breach)

print(
    """
The relationship is not:

    event = incident = breach

Instead:

    Events
       |
       v
    Detection
       |
       v
     Alerts
       |
       v
   Investigation
       |
       v
    Incident
       |
       +----> May remain an incident without a breach
       |
       v
      Breach
       |
       v
Potential legal, regulatory, contractual, and organizational obligations

The exact legal definition of "breach" depends on jurisdiction, sector,
contractual obligations, and the type of information involved.
"""
)


# ============================================================================
# 23. EVENT -> DETECTION -> ALERT -> INCIDENT -> BREACH
# ============================================================================

print("\n" + "=" * 80)
print("SECURITY OPERATIONS CHAIN")
print("=" * 80)

chain = [
    ("1", "Event", "A system records an observable occurrence."),
    ("2", "Detection", "Security logic evaluates the occurrence."),
    ("3", "Alert", "The detection produces a security signal for review."),
    ("4", "Investigation", "An analyst evaluates context and evidence."),
    ("5", "Incident", "The activity meets incident criteria."),
    ("6", "Breach", "The situation meets the applicable breach definition."),
]

for number, name, explanation in chain:
    print(f"{number}. {name}: {explanation}")


# ============================================================================
# 24. DETECTION TYPES
# ============================================================================

print("\n" + "=" * 80)
print("DETECTION TYPES")
print("=" * 80)

detection_types = {
    "Signature-based": "Matches known patterns.",
    "IOC-based": "Matches known malicious or suspicious artifacts.",
    "Behavior-based": "Identifies suspicious actions or sequences.",
    "Anomaly-based": "Identifies deviations from expected behavior.",
    "Correlation-based": "Combines multiple signals into a higher-confidence finding.",
    "Rule-based": "Applies explicit conditions to telemetry.",
    "Threshold-based": "Triggers when activity exceeds a defined quantity.",
    "Context-aware": "Uses identity, asset, time, geography, or business context.",
}

for name, description in detection_types.items():
    print(f"{name}: {description}")


# ============================================================================
# 25. FALSE POSITIVES AND FALSE NEGATIVES
# ============================================================================

print("\n" + "=" * 80)
print("FALSE POSITIVES AND FALSE NEGATIVES")
print("=" * 80)

print(
    """
False positive:
    A detection reports suspicious activity that is actually benign.

False negative:
    Malicious activity occurs but the detection fails to identify it.

Security detection engineering attempts to balance:

    Detection coverage
          versus
    Alert quality
          versus
    Analyst workload
          versus
    Operational performance

A detection with extremely broad conditions may generate many false
positives.

A detection with extremely strict conditions may miss real attacks.
"""
)


@dataclass
class DetectionMetrics:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else 0.0

    @property
    def specificity(self) -> float:
        denominator = self.true_negative + self.false_positive
        return self.true_negative / denominator if denominator else 0.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall

        if p + r == 0:
            return 0.0

        return 2 * p * r / (p + r)


metrics = DetectionMetrics(
    true_positive=80,
    false_positive=20,
    true_negative=880,
    false_negative=20,
)

print(f"Precision:    {metrics.precision:.2%}")
print(f"Recall:       {metrics.recall:.2%}")
print(f"Specificity:  {metrics.specificity:.2%}")
print(f"F1 score:     {metrics.f1_score:.2%}")

print(
    """
Precision answers approximately:

    Of everything the detector flagged, how much was actually positive?

Recall answers approximately:

    Of everything that was actually positive, how much did the detector
    identify?

A SOC often needs to consider both metrics rather than optimizing one in
isolation.
"""
)


# ============================================================================
# 26. IOC QUALITY AND CONFIDENCE
# ============================================================================

print("\n" + "=" * 80)
print("IOC QUALITY")
print("=" * 80)


def classify_ioc_confidence(confidence: float) -> str:
    """Convert numerical confidence into an operational category."""

    if confidence >= 0.90:
        return "high"
    if confidence >= 0.70:
        return "medium"
    if confidence >= 0.40:
        return "low"
    return "very_low"


for confidence in [0.25, 0.55, 0.75, 0.95]:
    print(
        confidence,
        "->",
        classify_ioc_confidence(confidence),
    )

print(
    """
IOC quality depends on context.

Important properties include:

- Confidence.
- Source reliability.
- First-seen time.
- Last-seen time.
- Freshness.
- Specificity.
- Relationship to observed activity.
- Whether the indicator is shared infrastructure.
- Whether it has known legitimate uses.
- Whether the indicator is stale.

An old malicious IP address can become benign or reassigned.
A hash can be highly precise but may fail when malware changes.
A domain can be useful but may be shared or dynamically generated.

IOC feeds should therefore not be treated as unquestionable truth.
"""
)


# ============================================================================
# 27. IOC EXPIRATION
# ============================================================================

print("\n" + "=" * 80)
print("IOC FRESHNESS")
print("=" * 80)


def is_ioc_fresh(
    indicator: IOC,
    now: datetime,
    maximum_age: timedelta,
) -> bool:
    """Determine whether an IOC is within its configured freshness window."""

    return now - indicator.last_seen <= maximum_age


now = base_time + timedelta(days=2)

freshness_window = timedelta(days=7)

for indicator in iocs:
    print(
        indicator.normalized_value(),
        "fresh=",
        is_ioc_fresh(indicator, now, freshness_window),
    )


# ============================================================================
# 28. IOC LIFECYCLE
# ============================================================================

print("\n" + "=" * 80)
print("IOC LIFECYCLE")
print("=" * 80)

print(
    """
A practical IOC lifecycle can include:

1. Collection
2. Validation
3. Normalization
4. Enrichment
5. Scoring
6. Distribution
7. Detection
8. Investigation
9. Expiration or review
10. Removal or archival

The goal is not simply to collect the largest possible IOC database.

A massive low-quality indicator set can increase:

- Storage requirements.
- Processing cost.
- False positives.
- Analyst workload.
- Investigation complexity.

High-quality contextual intelligence is generally more useful than raw
indicator volume.
"""
)


# ============================================================================
# 29. HASHING AND FILE IOCs
# ============================================================================

print("\n" + "=" * 80)
print("FILE HASHES AS IOCs")
print("=" * 80)


def sha256_text(content: str) -> str:
    """Generate a SHA-256 digest for demonstration purposes."""

    return hashlib.sha256(content.encode("utf-8")).hexdigest()


sample_file_content = "simulated file content"

sample_hash = sha256_text(sample_file_content)

print("SHA-256:", sample_hash)
print("Length:", len(sample_hash))

print(
    """
A cryptographic hash can act as a file IOC.

Advantages:
    - Exact and compact.
    - Easy to search.
    - Useful for known malicious files.

Limitations:
    - Any meaningful file modification changes the hash.
    - Polymorphic or frequently changing malware reduces hash usefulness.
    - A hash alone does not explain attacker behavior.

Therefore:

Hash -> useful artifact

but:

Hash != complete detection strategy
"""
)


# ============================================================================
# 30. IP ADDRESS VALIDATION
# ============================================================================

print("\n" + "=" * 80)
print("IP IOC VALIDATION")
print("=" * 80)


def validate_ip(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


for value in [
    "203.0.113.50",
    "192.168.1.10",
    "not-an-ip",
    "::1",
]:
    print(value, "valid=", validate_ip(value))


# ============================================================================
# 31. DOMAIN VALIDATION
# ============================================================================

print("\n" + "=" * 80)
print("DOMAIN VALIDATION")
print("=" * 80)


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}"
    r"[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def looks_like_domain(value: str) -> bool:
    """
    Perform a lightweight domain-format check.

    This does not prove that a domain exists or is malicious.
    """

    return bool(DOMAIN_PATTERN.fullmatch(value.strip()))


for domain in [
    "example.com",
    "malicious-example.test",
    "not a domain",
    "-invalid.com",
]:
    print(domain, "format_valid=", looks_like_domain(domain))


# ============================================================================
# 32. IOC MATCHING WITH CONFIDENCE
# ============================================================================

print("\n" + "=" * 80)
print("CONFIDENCE-AWARE IOC MATCHING")
print("=" * 80)


def match_high_confidence_iocs(
    event: SecurityEvent,
    indicators: Iterable[IOC],
    minimum_confidence: float = 0.90,
) -> list[IOC]:
    """Return matching IOCs above a confidence threshold."""

    event_values = set()

    for value in event.attributes.values():
        if isinstance(value, str):
            event_values.add(value.strip().lower())

    matches = []

    for indicator in indicators:
        if indicator.confidence < minimum_confidence:
            continue

        if indicator.normalized_value().lower() in event_values:
            matches.append(indicator)

    return matches


high_confidence_matches = match_high_confidence_iocs(
    network_event,
    iocs,
)

for match in high_confidence_matches:
    print(
        match.indicator_type.value,
        match.normalized_value(),
        match.confidence,
    )


# ============================================================================
# 33. CONTEXT MATTERS
# ============================================================================

print("\n" + "=" * 80)
print("SECURITY CONTEXT")
print("=" * 80)


@dataclass
class AssetContext:
    """Context about an asset used to improve alert prioritization."""

    hostname: str
    criticality: Severity
    internet_exposed: bool
    owner: str
    environment: str


asset = AssetContext(
    hostname="application-server-01",
    criticality=Severity.CRITICAL,
    internet_exposed=True,
    owner="payments-team",
    environment="production",
)

print(asset)

print(
    """
The same event can have different risk depending on context.

Example:

    Suspicious login on a disposable test machine
    versus
    Suspicious login on a production payment server

The raw event may be similar.

The risk is not necessarily similar.

Useful enrichment can include:

- Asset criticality.
- User role.
- Network segment.
- Business function.
- Internet exposure.
- Geographic context.
- Known maintenance windows.
- Approved administrative activity.
- Threat intelligence.
"""
)


# ============================================================================
# 34. ALERT RISK SCORING
# ============================================================================

print("\n" + "=" * 80)
print("ALERT RISK SCORING")
print("=" * 80)


def calculate_risk_score(
    severity_weight: float,
    confidence: float,
    asset_criticality: float,
    exposure: float,
) -> float:
    """
    Produce a simple normalized risk score.

    This is an educational model, not a universal security formula.
    """

    values = [
        max(0.0, min(1.0, severity_weight)),
        max(0.0, min(1.0, confidence)),
        max(0.0, min(1.0, asset_criticality)),
        max(0.0, min(1.0, exposure)),
    ]

    return statistics.fmean(values)


risk = calculate_risk_score(
    severity_weight=1.0,
    confidence=0.97,
    asset_criticality=1.0,
    exposure=1.0,
)

print(f"Risk score: {risk:.2%}")

print(
    """
Risk scoring should be explainable.

A production organization should document:

- Which inputs are used.
- Their ranges.
- Their weights.
- How missing values are handled.
- How scores map to priorities.
- How analysts can override scores.
- How the model is validated.

A score is a decision-support mechanism, not proof of malicious activity.
"""
)


# ============================================================================
# 35. TTP-BASED THINKING
# ============================================================================

print("\n" + "=" * 80)
print("TTP-BASED DETECTION")
print("=" * 80)


def describe_ttp_detection(ttp: TTP) -> str:
    """Describe what a defender might monitor for a TTP."""

    return (
        f"Monitor behavior associated with {ttp.technique_id} "
        f"({ttp.technique_name}), focusing on: {ttp.procedure}"
    )


for ttp in ttps:
    print(describe_ttp_detection(ttp))


print(
    """
TTP-based detection asks:

    What is the adversary doing?

rather than only:

    Which artifact did the adversary use?

This distinction helps address indicator churn.

An attacker can change:

    IP address
    domain
    filename
    hash
    email address

while continuing to use:

    similar execution
    similar credential access
    similar persistence
    similar lateral movement
    similar command-and-control behavior

TTP detection is therefore often more durable than a static IOC list.
"""
)


# ============================================================================
# 36. DETECTION COVERAGE
# ============================================================================

print("\n" + "=" * 80)
print("DETECTION COVERAGE")
print("=" * 80)

coverage_matrix = {
    "Known malicious IP": ["IOC"],
    "Known malicious hash": ["IOC"],
    "Unusual process chain": ["IOA", "TTP"],
    "Credential dumping behavior": ["IOA", "TTP"],
    "Unauthorized remote access": ["IOA", "TTP"],
    "Known vulnerable software": ["Vulnerability"],
    "Attempted exploitation": ["Exploit", "IOA"],
}

for behavior, concepts in coverage_matrix.items():
    print(f"{behavior:<35} -> {', '.join(concepts)}")


# ============================================================================
# 37. VULNERABILITY VS EXPLOIT VS PAYLOAD
# ============================================================================

print("\n" + "=" * 80)
print("VULNERABILITY VS EXPLOIT VS PAYLOAD")
print("=" * 80)

print(
    """
Vulnerability:
    Weakness or flaw.

Exploit:
    Method used to take advantage of the weakness.

Payload:
    Action/content delivered or executed through the attack.

Example:

    Vulnerability:
        Application fails to safely process a particular input.

    Exploit:
        An attacker crafts input that causes unintended behavior.

    Payload:
        The resulting action intended to execute unauthorized activity.

Important:
    A vulnerability may exist for years without being exploited.
    An exploit may exist without successfully compromising a target.
    A successful exploit does not guarantee that the intended payload succeeds.
"""
)


# ============================================================================
# 38. INCIDENT SEVERITY
# ============================================================================

print("\n" + "=" * 80)
print("INCIDENT SEVERITY")
print("=" * 80)


def estimate_incident_severity(
    asset_criticality: Severity,
    confirmed_compromise: bool,
    data_exposure: bool,
) -> Severity:
    """
    Demonstrate basic severity reasoning.

    Production severity frameworks should be organization-specific.
    """

    if data_exposure and confirmed_compromise:
        return Severity.CRITICAL

    if confirmed_compromise and asset_criticality in {
        Severity.HIGH,
        Severity.CRITICAL,
    }:
        return Severity.HIGH

    if confirmed_compromise:
        return Severity.MEDIUM

    return Severity.LOW


print(
    estimate_incident_severity(
        asset_criticality=Severity.CRITICAL,
        confirmed_compromise=True,
        data_exposure=True,
    ).value
)


# ============================================================================
# 39. COMMON SECURITY TERMINOLOGY CONFUSIONS
# ============================================================================

print("\n" + "=" * 80)
print("COMMON CONFUSIONS")
print("=" * 80)

confusions = {
    "IOC vs IOA": (
        "IOC focuses on an observable artifact; IOA focuses on suspicious "
        "behavior or activity."
    ),
    "IOA vs TTP": (
        "IOA is an observed indication; TTP describes adversary behavior "
        "at a broader tactical and technical level."
    ),
    "Event vs Alert": (
        "An event is an occurrence; an alert is a security signal generated "
        "after detection logic identifies something noteworthy."
    ),
    "Alert vs Incident": (
        "An alert requires investigation; an incident is activity that meets "
        "the organization's incident criteria."
    ),
    "Incident vs Breach": (
        "An incident does not automatically involve a breach of protected "
        "information or systems."
    ),
    "Vulnerability vs Exploit": (
        "A vulnerability is a weakness; an exploit is a method of abusing it."
    ),
    "Exploit vs Payload": (
        "The exploit enables or performs exploitation; the payload represents "
        "the delivered action or content."
    ),
}

for distinction, explanation in confusions.items():
    print(f"{distinction}: {explanation}")


# ============================================================================
# 40. COMMON MISTAKES
# ============================================================================

print("\n" + "=" * 80)
print("COMMON MISTAKES")
print("=" * 80)

mistakes = [
    "Treating every alert as a confirmed incident.",
    "Treating every IOC match as proof of compromise.",
    "Using stale IOC feeds without expiration.",
    "Ignoring legitimate uses of shared infrastructure.",
    "Using only hash-based detection.",
    "Ignoring behavioral evidence.",
    "Ignoring asset and identity context.",
    "Creating detections without measuring false positives.",
    "Assuming a vulnerability means exploitation has occurred.",
    "Confusing an exploit with a payload.",
    "Using unexplained risk scores.",
    "Failing to preserve evidence during investigations.",
]

for number, mistake in enumerate(mistakes, start=1):
    print(f"{number:02d}. {mistake}")


# ============================================================================
# 41. DETECTION ENGINEERING BEST PRACTICES
# ============================================================================

print("\n" + "=" * 80)
print("DETECTION ENGINEERING BEST PRACTICES")
print("=" * 80)

best_practices = [
    "Define the threat behavior the detection is intended to identify.",
    "Document the data sources required by the detection.",
    "Use stable identifiers and normalized fields.",
    "Include context such as identity, asset criticality, and time.",
    "Prefer explainable logic when possible.",
    "Test detections against known benign behavior.",
    "Measure false-positive and false-negative behavior.",
    "Version-control detection logic.",
    "Document assumptions and exclusions.",
    "Review detections when attacker behavior changes.",
    "Monitor telemetry quality and ingestion failures.",
    "Use layered detections rather than relying on one signal.",
]

for practice in best_practices:
    print("-", practice)


# ============================================================================
# 42. PERFORMANCE CONSIDERATIONS
# ============================================================================

print("\n" + "=" * 80)
print("PERFORMANCE CONSIDERATIONS")
print("=" * 80)


def naive_ioc_lookup(
    value: str,
    indicators: list[IOC],
) -> Optional[IOC]:
    """O(n) lookup through a list."""

    normalized = value.strip().lower()

    for indicator in indicators:
        if indicator.normalized_value().lower() == normalized:
            return indicator

    return None


def indexed_ioc_lookup(
    value: str,
    index: dict[str, IOC],
) -> Optional[IOC]:
    """Average O(1) dictionary lookup."""

    return index.get(value.strip().lower())


ioc_lookup_index = {
    indicator.normalized_value().lower(): indicator
    for indicator in iocs
}

print(
    "Indexed lookup:",
    indexed_ioc_lookup("203.0.113.50", ioc_lookup_index),
)

print(
    """
For small IOC collections, a linear search may be adequate.

For large collections, indexed structures are usually preferable.

Conceptually:

List search:
    O(n)

Dictionary/hash lookup:
    Average O(1)

Production systems must also consider:

- Memory consumption.
- Distributed indexing.
- Update frequency.
- Duplicate indicators.
- Indicator expiration.
- Query volume.
- Concurrent ingestion.
- Storage architecture.
"""
)


# ============================================================================
# 43. SECURITY OF DETECTION SYSTEMS
# ============================================================================

print("\n" + "=" * 80)
print("SECURITY CONSIDERATIONS")
print("=" * 80)

security_considerations = [
    "Protect security logs from unauthorized modification.",
    "Restrict access to detection rules and sensitive telemetry.",
    "Use least privilege for security tooling.",
    "Protect API credentials and integration secrets.",
    "Audit changes to detection logic.",
    "Protect threat-intelligence ingestion pipelines.",
    "Validate external indicator data before use.",
    "Avoid trusting unverified indicators blindly.",
    "Preserve timestamps and source metadata.",
    "Protect incident evidence from tampering.",
    "Control who can close or suppress alerts.",
]

for consideration in security_considerations:
    print("-", consideration)


# ============================================================================
# 44. LOG INTEGRITY
# ============================================================================

print("\n" + "=" * 80)
print("LOG INTEGRITY")
print("=" * 80)


def event_fingerprint(event: SecurityEvent) -> str:
    """
    Create a deterministic fingerprint for an event.

    A fingerprint can help identify duplicates, although it is not by itself
    a tamper-proof integrity mechanism.
    """

    raw = "|".join(
        [
            event.event_id,
            event.timestamp.isoformat(),
            event.event_type.value,
            event.source,
            event.host,
            event.description,
        ]
    )

    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


for event in events:
    print(event.event_id, event_fingerprint(event))


print(
    """
Hashing can help detect changes when the trusted original hash is preserved.

A hash does not automatically provide:

- Authenticity.
- Confidentiality.
- Proof that the original input was trustworthy.

Production log integrity may require additional controls such as:

- Access control.
- Immutable storage.
- Cryptographic signing.
- Write-once retention mechanisms.
- Centralized logging.
- Audit trails.
"""
)


# ============================================================================
# 45. ALERT DEDUPLICATION
# ============================================================================

print("\n" + "=" * 80)
print("ALERT DEDUPLICATION")
print("=" * 80)


def deduplicate_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """
    Keep one alert per detection/event combination.

    Production deduplication may use more sophisticated keys and time windows.
    """

    seen: set[tuple[str, str]] = set()
    unique: list[Alert] = []

    for alert in alerts:
        key = (alert.detection_id, alert.event_id)

        if key not in seen:
            seen.add(key)
            unique.append(alert)

    return unique


duplicate_alert = create_alert(
    detection=ioc_detection,
    event=network_event,
    confidence=0.97,
    title="Duplicate alert example",
)

deduplicated = deduplicate_alerts([alert, duplicate_alert])

print("Original alerts:", 2)
print("After deduplication:", len(deduplicated))


# ============================================================================
# 46. ALERT PRIORITIZATION
# ============================================================================

print("\n" + "=" * 80)
print("ALERT PRIORITIZATION")
print("=" * 80)


def severity_rank(severity: Severity) -> int:
    """Map severity to a sortable numeric rank."""

    return {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[severity]


def prioritize_alerts(alerts: Iterable[Alert]) -> list[Alert]:
    """Sort alerts by severity and confidence."""

    return sorted(
        alerts,
        key=lambda item: (
            severity_rank(item.severity),
            item.confidence,
        ),
        reverse=True,
    )


alerts = [
    alert,
    Alert(
        alert_id="ALT-LOW",
        detection_id="DET-LOW",
        event_id="EVT-LOW",
        timestamp=base_time,
        title="Low severity event",
        severity=Severity.LOW,
        confidence=0.99,
    ),
    Alert(
        alert_id="ALT-CRITICAL",
        detection_id="DET-CRITICAL",
        event_id="EVT-CRITICAL",
        timestamp=base_time,
        title="Critical alert",
        severity=Severity.CRITICAL,
        confidence=0.85,
    ),
]

for prioritized in prioritize_alerts(alerts):
    print(
        prioritized.alert_id,
        prioritized.severity.value,
        prioritized.confidence,
    )


# ============================================================================
# 47. SIMPLE SECURITY PIPELINE
# ============================================================================

print("\n" + "=" * 80)
print("SIMULATED SECURITY MONITORING PIPELINE")
print("=" * 80)


class SecurityMonitoringPipeline:
    """
    Simplified end-to-end monitoring pipeline.

    Flow:

        Events
          |
          +--> normalization
          |
          +--> IOC matching
          |
          +--> behavioral analysis
          |
          +--> alert generation
          |
          +--> analyst investigation
    """

    def __init__(self, indicators: Iterable[IOC]):
        self.indicators = list(indicators)
        self.ioc_index = build_ioc_index(self.indicators)
        self.alerts: list[Alert] = []

    def process_event(self, event: SecurityEvent) -> list[Alert]:
        """Process one event through the simplified detection pipeline."""

        generated_alerts: list[Alert] = []

        ioc_matches = detect_ioc_match(event, self.ioc_index)

        if ioc_matches:
            detection = next(
                detection
                for detection in detections
                if detection.detection_id == "DET-IOC-001"
            )

            generated_alerts.append(
                create_alert(
                    detection=detection,
                    event=event,
                    confidence=0.95,
                    title=(
                        "IOC match detected: "
                        + ", ".join(ioc_matches)
                    ),
                )
            )

        self.alerts.extend(generated_alerts)

        return generated_alerts


pipeline = SecurityMonitoringPipeline(iocs)

pipeline_alerts = pipeline.process_event(network_event)

for generated_alert in pipeline_alerts:
    print(generated_alert)


# ============================================================================
# 48. DETECTION TESTING
# ============================================================================

print("\n" + "=" * 80)
print("DETECTION TESTING")
print("=" * 80)


def test_ip_ioc_detection() -> None:
    """Basic unit test for IOC detection."""

    test_event = SecurityEvent(
        event_id="TEST-001",
        timestamp=base_time,
        event_type=EventType.NETWORK_CONNECTION,
        source="firewall",
        user=None,
        host="test-host",
        description="Test connection",
        attributes={"destination_ip": "203.0.113.50"},
    )

    matches = detect_ioc_match(test_event, ioc_index)

    assert matches, "Expected an IOC match."
    assert "malicious_ip:203.0.113.50" in matches


def test_benign_ip_does_not_match() -> None:
    """Ensure a known benign test value does not match the IOC index."""

    test_event = SecurityEvent(
        event_id="TEST-002",
        timestamp=base_time,
        event_type=EventType.NETWORK_CONNECTION,
        source="firewall",
        user=None,
        host="test-host",
        description="Benign connection",
        attributes={"destination_ip": "192.0.2.10"},
    )

    matches = detect_ioc_match(test_event, ioc_index)

    assert not matches


test_ip_ioc_detection()
test_benign_ip_does_not_match()

print("Detection unit tests passed.")


# ============================================================================
# 49. EDGE CASES
# ============================================================================

print("\n" + "=" * 80)
print("EDGE CASES")
print("=" * 80)


edge_cases = [
    ("Empty IOC value", ""),
    ("Whitespace", "   "),
    ("Uppercase domain", "MALICIOUS-EXAMPLE.TEST"),
    ("Invalid IP", "999.999.999.999"),
    ("IPv6", "::1"),
    ("Missing event user", None),
]

for description, value in edge_cases:
    print(f"{description}: {value!r}")

print(
    """
Important edge cases in security telemetry include:

- Missing fields.
- Incorrect timestamps.
- Duplicate events.
- Out-of-order events.
- Malformed IP addresses.
- IPv4 and IPv6.
- Case differences.
- Encoded URLs.
- Unicode or internationalized domains.
- Shared hosting.
- Dynamic IP addresses.
- NAT.
- Proxies.
- Cloud infrastructure.
- Service accounts.
- Automated jobs.
- Legitimate administrative activity.
- Clock drift.

Detection logic that ignores these cases can produce misleading results.
"""
)


# ============================================================================
# 50. TIME WINDOWS
# ============================================================================

print("\n" + "=" * 80)
print("TIME WINDOWS")
print("=" * 80)


def events_within_window(
    events: Iterable[SecurityEvent],
    start: datetime,
    end: datetime,
) -> list[SecurityEvent]:
    """Return events whose timestamps fall inside an inclusive interval."""

    return [
        event
        for event in events
        if start <= event.timestamp <= end
    ]


window_events = events_within_window(
    events,
    base_time,
    base_time + timedelta(minutes=2),
)

for event in window_events:
    print(event.event_id, event.timestamp.isoformat())


print(
    """
Time windows are essential for behavioral detections.

For example:

    20 failed logins in 30 seconds

can be very different from:

    20 failed logins over 30 days.

A detector must define:

- Window size.
- Whether boundaries are inclusive.
- Event ordering behavior.
- Clock skew tolerance.
- Late-arriving events.
- Time zone handling.
"""
)


# ============================================================================
# 51. BASELINE AND ANOMALY CONCEPT
# ============================================================================

print("\n" + "=" * 80)
print("BASELINE AND ANOMALY")
print("=" * 80)


def calculate_mean(values: list[float]) -> float:
    """Return the arithmetic mean."""

    return statistics.fmean(values)


def calculate_standard_deviation(values: list[float]) -> float:
    """Return population standard deviation."""

    return statistics.pstdev(values)


login_counts = [8, 9, 7, 10, 8, 9, 11, 8, 10, 50]

mean = calculate_mean(login_counts)
stddev = calculate_standard_deviation(login_counts)

print("Mean:", mean)
print("Standard deviation:", stddev)

if stddev:
    latest_z_score = (login_counts[-1] - mean) / stddev
    print("Latest z-score:", latest_z_score)


print(
    """
Anomaly detection attempts to identify activity that differs from an
expected baseline.

But unusual does not mean malicious.

A legitimate event can be anomalous because:

- A user changed roles.
- A company launched a new system.
- A maintenance operation occurred.
- A business event increased traffic.
- A backup job ran.

Anomaly detection therefore requires context and investigation.
"""
)


# ============================================================================
# 52. SECURITY TELEMETRY QUALITY
# ============================================================================

print("\n" + "=" * 80)
print("TELEMETRY QUALITY")
print("=" * 80)

telemetry_requirements = [
    "Accurate timestamps",
    "Reliable source identification",
    "Stable host identifiers",
    "User identity where appropriate",
    "Process information where available",
    "Network metadata where appropriate",
    "Consistent field names",
    "Retention appropriate to investigation needs",
    "Integrity protection",
    "Monitoring for ingestion failures",
]

for requirement in telemetry_requirements:
    print("-", requirement)

print(
    """
A detection is only as reliable as the telemetry supporting it.

If endpoint logs stop arriving, a detection may appear quiet because there
is no activity or because visibility has disappeared.

This creates an important distinction:

No detection result

does not necessarily mean:

No malicious activity.
"""
)


# ============================================================================
# 53. IOC FEED POISONING AND VALIDATION
# ============================================================================

print("\n" + "=" * 80)
print("THREAT INTELLIGENCE VALIDATION")
print("=" * 80)


def validate_ioc_for_ingestion(indicator: IOC) -> tuple[bool, list[str]]:
    """Perform basic quality checks before an IOC enters a detection system."""

    problems: list[str] = []

    if not indicator.value.strip():
        problems.append("empty value")

    if not 0.0 <= indicator.confidence <= 1.0:
        problems.append("confidence outside valid range")

    if indicator.first_seen > indicator.last_seen:
        problems.append("first_seen is later than last_seen")

    if indicator.indicator_type == IndicatorType.IP_ADDRESS:
        if not validate_ip(indicator.value):
            problems.append("invalid IP address")

    return not problems, problems


for indicator in iocs:
    valid, problems = validate_ioc_for_ingestion(indicator)
    print(indicator.value, "valid=", valid, "problems=", problems)


# ============================================================================
# 54. INCIDENT INVESTIGATION EVIDENCE
# ============================================================================

print("\n" + "=" * 80)
print("INCIDENT INVESTIGATION")
print("=" * 80)

investigation_questions = [
    "What happened?",
    "When did it happen?",
    "Which assets were involved?",
    "Which identities were involved?",
    "What evidence supports the finding?",
    "Which IOCs were observed?",
    "Which IOAs were observed?",
    "Which TTPs are consistent with the behavior?",
    "Was exploitation attempted?",
    "Was exploitation successful?",
    "Was a payload executed?",
    "Was persistence established?",
    "Was lateral movement observed?",
    "Was data accessed or transferred?",
    "What remains uncertain?",
]

for question in investigation_questions:
    print("-", question)


# ============================================================================
# 55. ROOT CAUSE REASONING
# ============================================================================

print("\n" + "=" * 80)
print("ROOT CAUSE REASONING")
print("=" * 80)

print(
    """
Consider this simplified investigation:

1. An event records a suspicious network connection.
2. IOC matching identifies a known suspicious destination.
3. Endpoint telemetry shows an unusual process.
4. Authentication logs show unusual account activity.
5. Analysts correlate the events.
6. The behavior is determined to be unauthorized.
7. The activity meets incident criteria.
8. Investigation determines a vulnerable application was involved.
9. The exploit path is reconstructed.
10. The delivered action is identified as the payload.
11. Data access is confirmed.

Notice how the terminology describes different parts of the same case.

The terms are not competing definitions.
They describe different layers of security analysis.
"""
)


# ============================================================================
# 56. DEFENSIVE MAPPING
# ============================================================================

print("\n" + "=" * 80)
print("DEFENSIVE USE OF EACH CONCEPT")
print("=" * 80)

defensive_mapping = {
    "Vulnerability": "Prioritize remediation and reduce attack surface.",
    "Exploit": "Understand how weaknesses can be abused and detect exploitation.",
    "Payload": "Identify resulting malicious actions and containment requirements.",
    "IOC": "Search historical and current telemetry for known artifacts.",
    "IOA": "Detect suspicious behavior and attack activity.",
    "TTP": "Understand adversary methods and design durable behavioral detections.",
    "Event": "Provide raw observable telemetry.",
    "Detection": "Convert telemetry into meaningful security signals.",
    "Alert": "Prioritize activity for analyst investigation.",
    "Incident": "Coordinate response to confirmed or suspected security events.",
    "Breach": "Determine impact and applicable organizational/legal obligations.",
}

for concept, use in defensive_mapping.items():
    print(f"{concept:<15} -> {use}")


# ============================================================================
# 57. PRACTICAL SCENARIO
# ============================================================================

print("\n" + "=" * 80)
print("END-TO-END SCENARIO")
print("=" * 80)

scenario = [
    ("Vulnerability", "A production application contains a known weakness."),
    ("Exploit", "An attacker attempts to abuse the weakness."),
    ("Payload", "An unauthorized action is delivered through the attack."),
    ("TTP", "The behavior aligns with a known execution technique."),
    ("IOA", "The process and network sequence is suspicious."),
    ("IOC", "The system contacts known suspicious infrastructure."),
    ("Event", "Endpoint and network systems record the activity."),
    ("Detection", "IOC and behavioral rules identify the pattern."),
    ("Alert", "The SOC receives a high-confidence signal."),
    ("Incident", "Investigation confirms unauthorized activity."),
    ("Breach", "Protected data access is confirmed, meeting the applicable definition."),
]

for number, (concept, description) in enumerate(scenario, start=1):
    print(f"{number:02d}. {concept:<15} {description}")


# ============================================================================
# 58. PRACTICAL SECURITY OPERATIONS DECISION TREE
# ============================================================================

print("\n" + "=" * 80)
print("DECISION TREE")
print("=" * 80)


def classify_security_signal(
    event_exists: bool,
    detection_triggered: bool,
    malicious_activity_confirmed: bool,
    incident_criteria_met: bool,
    breach_criteria_met: bool,
) -> str:
    """
    Illustrate the conceptual progression from event to breach.

    This is not a legal or organizational decision engine.
    """

    if not event_exists:
        return "No observed event"

    if not detection_triggered:
        return "Event observed; no detection triggered"

    if not malicious_activity_confirmed:
        return "Alert requiring investigation"

    if not incident_criteria_met:
        return "Confirmed suspicious/malicious activity below incident threshold"

    if not breach_criteria_met:
        return "Security incident; breach not established"

    return "Security incident meeting breach criteria"


states = [
    (True, False, False, False, False),
    (True, True, False, False, False),
    (True, True, True, True, False),
    (True, True, True, True, True),
]

for state in states:
    print(state, "->", classify_security_signal(*state))


# ============================================================================
# 59. SECURITY TERMINOLOGY QUIZ
# ============================================================================

print("\n" + "=" * 80)
print("KNOWLEDGE CHECK")
print("=" * 80)

quiz = [
    (
        "A known malicious SHA-256 value is found on an endpoint.",
        "IOC",
    ),
    (
        "A user performs an unusual sequence of privileged operations.",
        "IOA",
    ),
    (
        "A weakness exists in an application.",
        "Vulnerability",
    ),
    (
        "A technique is used to abuse that weakness.",
        "Exploit",
    ),
    (
        "Content delivered to perform the intended malicious action.",
        "Payload",
    ),
    (
        "A security system records a DNS request.",
        "Event",
    ),
    (
        "A rule determines that the DNS request is suspicious.",
        "Detection",
    ),
    (
        "The SOC receives a notification generated by the rule.",
        "Alert",
    ),
    (
        "Investigation confirms activity meets organizational response criteria.",
        "Incident",
    ),
]

for number, (question, answer) in enumerate(quiz, start=1):
    print(f"{number}. {question}")
    print(f"   Answer: {answer}")


# ============================================================================
# 60. ADVANCED CONCEPT: SIGNAL FUSION
# ============================================================================

print("\n" + "=" * 80)
print("ADVANCED CONCEPT: SIGNAL FUSION")
print("=" * 80)


def combine_security_signals(
    ioc_match: bool,
    suspicious_behavior: bool,
    high_risk_asset: bool,
    unusual_identity_activity: bool,
) -> float:
    """
    Combine multiple signals into a simple confidence score.

    This illustrates signal fusion rather than providing a universal
    production scoring formula.
    """

    weights = {
        "ioc": 0.30,
        "behavior": 0.30,
        "asset": 0.20,
        "identity": 0.20,
    }

    score = 0.0

    if ioc_match:
        score += weights["ioc"]

    if suspicious_behavior:
        score += weights["behavior"]

    if high_risk_asset:
        score += weights["asset"]

    if unusual_identity_activity:
        score += weights["identity"]

    return score


signal_score = combine_security_signals(
    ioc_match=True,
    suspicious_behavior=True,
    high_risk_asset=True,
    unusual_identity_activity=True,
)

print(f"Combined signal score: {signal_score:.2%}")

print(
    """
Multiple weak signals can become meaningful when correlated.

Example:

    IOC match
      +
    unusual process
      +
    unusual identity activity
      +
    critical asset
      =
    much stronger investigative priority

Correlation must be designed carefully because correlated inputs can create
false confidence if they all originate from the same underlying noisy signal.
"""
)


# ============================================================================
# 61. ADVANCED CONCEPT: DETECTION DRIFT
# ============================================================================

print("\n" + "=" * 80)
print("ADVANCED CONCEPT: DETECTION DRIFT")
print("=" * 80)

print(
    """
Detection drift occurs when a detection's assumptions stop matching the
environment.

Examples:

- A company adopts a new cloud platform.
- User behavior changes after a merger.
- Infrastructure is migrated.
- A legitimate administration tool becomes widely used.
- Attackers change their behavior.
- A threat-intelligence indicator becomes stale.

A detection should therefore have:

- An owner.
- A purpose.
- Required telemetry.
- Test cases.
- Version history.
- Known limitations.
- Review criteria.
- Performance metrics.
"""
)


# ============================================================================
# 62. ADVANCED CONCEPT: LAYERED DETECTION
# ============================================================================

print("\n" + "=" * 80)
print("ADVANCED CONCEPT: LAYERED DETECTION")
print("=" * 80)

layers = [
    "Layer 1: Known IOC detection",
    "Layer 2: Suspicious behavior detection",
    "Layer 3: TTP-oriented detection",
    "Layer 4: Cross-source correlation",
    "Layer 5: Asset and identity context",
    "Layer 6: Human investigation",
]

for layer in layers:
    print(layer)

print(
    """
Layered detection reduces dependence on one defensive mechanism.

If an attacker changes an IP address:

    IOC detection may fail.

Behavior detection may still work.

If the behavior changes:

    TTP-oriented detection may still identify related activity.

If individual signals remain weak:

    Correlation and contextual enrichment may increase confidence.

Defense should therefore be designed as a system rather than as a single
list of signatures.
"""
)


# ============================================================================
# 63. ADVANCED CONCEPT: DETECTION DEPENDENCIES
# ============================================================================

print("\n" + "=" * 80)
print("ADVANCED CONCEPT: DETECTION DEPENDENCIES")
print("=" * 80)

detection_dependencies = {
    "Known IP IOC detection": [
        "network telemetry",
        "normalized destination IP",
        "IOC repository",
    ],
    "Suspicious process detection": [
        "endpoint process telemetry",
        "process ancestry",
        "user identity",
    ],
    "Credential attack detection": [
        "authentication logs",
        "source identity",
        "time-series aggregation",
    ],
}

for detection_name, dependencies in detection_dependencies.items():
    print(detection_name)
    for dependency in dependencies:
        print("  -", dependency)


# ============================================================================
# 64. ADVANCED CONCEPT: VISIBILITY GAP
# ============================================================================

print("\n" + "=" * 80)
print("ADVANCED CONCEPT: VISIBILITY GAP")
print("=" * 80)

print(
    """
A visibility gap exists when the organization lacks telemetry necessary to
observe relevant activity.

Examples:

    No endpoint telemetry
    No authentication logs
    Missing cloud audit logs
    Incomplete DNS visibility
    Unmonitored network segments
    Incorrect timestamp synchronization

A detection cannot reliably identify information that the telemetry does
not contain.

Therefore:

    Detection engineering
            depends on
    telemetry engineering
            which depends on
    visibility architecture.
"""
)


# ============================================================================
# 65. ADVANCED CONCEPT: ATTACK SURFACE VS VULNERABILITY
# ============================================================================

print("\n" + "=" * 80)
print("ATTACK SURFACE VS VULNERABILITY")
print("=" * 80)

print(
    """
Attack surface:
    The collection of exposed systems, interfaces, services, identities,
    applications, dependencies, and other entry points that may be targeted.

Vulnerability:
    A specific weakness that may be present within an asset or component.

An organization can reduce attack surface without fixing every vulnerability
by disabling unnecessary services, reducing exposure, enforcing access
controls, and removing unused components.

Conversely, a highly exposed asset with an unpatched vulnerability may have
significantly elevated risk.
"""
)


# ============================================================================
# 66. ADVANCED CONCEPT: EXPLOITABILITY VS IMPACT
# ============================================================================

print("\n" + "=" * 80)
print("EXPLOITABILITY VS IMPACT")
print("=" * 80)


@dataclass
class RiskFactors:
    exploitability: float
    asset_criticality: float
    exposure: float
    data_sensitivity: float

    def score(self) -> float:
        values = [
            self.exploitability,
            self.asset_criticality,
            self.exposure,
            self.data_sensitivity,
        ]

        return statistics.fmean(values)


risk_factors = RiskFactors(
    exploitability=0.9,
    asset_criticality=1.0,
    exposure=1.0,
    data_sensitivity=0.9,
)

print(f"Illustrative risk score: {risk_factors.score():.2%}")

print(
    """
A vulnerability's technical severity is not the only factor in operational
risk.

Risk assessment may also consider:

- Exploitability.
- Internet exposure.
- Asset criticality.
- Data sensitivity.
- Existing compensating controls.
- Attack likelihood.
- Business impact.
- Availability of an exploit.
- Required attacker privileges.

The numerical model used here is illustrative.
Organizations should use their own documented risk methodology.
"""
)


# ============================================================================
# 67. ADVANCED CONCEPT: INDICATOR CHURN
# ============================================================================

print("\n" + "=" * 80)
print("ADVANCED CONCEPT: INDICATOR CHURN")
print("=" * 80)

print(
    """
Indicator churn describes the rate at which observable indicators change.

Attackers can frequently change:

    IP addresses
    domains
    file hashes
    filenames
    infrastructure

Behavioral characteristics may change more slowly.

This creates an important defensive principle:

    IOCs are valuable evidence,
    but IOCs alone are not sufficient for durable detection.

A mature detection program combines:

    IOC intelligence
        +
    behavioral detection
        +
    TTP understanding
        +
    contextual enrichment
        +
    investigation
"""
)


# ============================================================================
# 68. FINAL TERMINOLOGY MAP
# ============================================================================

print("\n" + "=" * 80)
print("FINAL TERMINOLOGY MAP")
print("=" * 80)

terminology_map = {
    "Vulnerability": "Weakness",
    "Exploit": "Method of abusing a weakness",
    "Payload": "Delivered action/content",
    "IOC": "Observable compromise artifact",
    "IOA": "Observable suspicious attack behavior",
    "TTP": "Adversary tactics, techniques, procedures",
    "Event": "Recorded occurrence",
    "Detection": "Logic/process identifying relevant activity",
    "Alert": "Security signal requiring attention",
    "Incident": "Security situation meeting response criteria",
    "Breach": "Compromise meeting the applicable breach definition",
}

for term, meaning in terminology_map.items():
    print(f"{term:<15} : {meaning}")


# ============================================================================
# 69. SELF-CHECK ASSERTIONS
# ============================================================================

print("\n" + "=" * 80)
print("SELF-CHECK")
print("=" * 80)

assert vulnerability.vulnerability_id == exploit.vulnerability_id
assert 0.0 <= alert.confidence <= 1.0
assert metrics.precision >= 0.0
assert metrics.precision <= 1.0
assert metrics.recall >= 0.0
assert metrics.recall <= 1.0
assert metrics.f1_score >= 0.0
assert metrics.f1_score <= 1.0
assert validate_ip("203.0.113.50")
assert not validate_ip("not-an-ip")
assert looks_like_domain("example.com")
assert not looks_like_domain("not a domain")
assert len(sample_hash) == 64
assert risk >= 0.0
assert risk <= 1.0

print("All self-check assertions passed.")


# ============================================================================
# 70. END OF SCRIPT
# ============================================================================

print("\n" + "=" * 80)
print("SECURITY TERMINOLOGY STUDY SCRIPT COMPLETED")
print("=" * 80)

print(
    """
The script demonstrated the relationships among:

    Vulnerability
        -> Exploit
        -> Payload

    IOC
    IOA
    TTP

    Event
        -> Detection
        -> Alert
        -> Investigation
        -> Incident
        -> Possible Breach

It also demonstrated normalization, IOC matching, behavioral detection,
correlation, confidence scoring, false-positive/false-negative concepts,
performance considerations, detection testing, telemetry quality, and
security operations reasoning.
"""
)
