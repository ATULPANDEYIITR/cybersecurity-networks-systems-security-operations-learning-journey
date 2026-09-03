"""
===============================================================================
THREAT LANDSCAPE, THREAT ACTORS, CYBERCRIME, NATION-STATE THREATS,
INSIDERS, HACKTIVISTS, SCRIPT KIDDIES, CYBER ESPIONAGE AND MITRE ATT&CK
===============================================================================

PURPOSE
-------
This is a comprehensive, defensive-learning Python script explaining and
demonstrating the concept of the cybersecurity threat landscape.

The script progresses from basic concepts to more advanced concepts:

1. What is a cybersecurity threat?
2. Threat vs vulnerability vs risk vs attack
3. What is the threat landscape?
4. Threat actors
5. Cybercriminals
6. Nation-state actors
7. Insider threats
8. Hacktivists
9. Script kiddies
10. Cyber espionage
11. Advanced Persistent Threats (APTs)
12. Motivations and capabilities
13. Attack surfaces
14. Threat intelligence
15. Indicators of compromise
16. Tactics, techniques and procedures
17. MITRE ATT&CK
18. ATT&CK tactics
19. ATT&CK techniques and sub-techniques
20. Mapping observed behaviors to ATT&CK
21. Threat modeling
22. Risk scoring
23. Detection engineering
24. Security telemetry
25. Incident investigation
26. Threat actor profiling
27. Defensive prioritization
28. Attack-path reasoning
29. Purple-team concepts
30. Security operations concepts
31. Advanced threat-landscape analysis
32. A complete simulated defensive case study

IMPORTANT SAFETY NOTE
---------------------
This script does NOT perform real exploitation, credential theft, malware
deployment, persistence, evasion, destructive actions, or unauthorized
access.

All examples are simulated data structures designed for defensive learning.

MITRE ATT&CK NOTE
-----------------
MITRE ATT&CK is a knowledge base describing adversary tactics and techniques.
Technique identifiers and descriptions can evolve as ATT&CK is updated.

For production security engineering, always verify current technique IDs,
names, versions and platform applicability against the current MITRE ATT&CK
knowledge base.

===============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from collections import Counter, defaultdict
from typing import Dict, List, Set, Tuple, Optional
import math
import statistics
import json


# =============================================================================
# SECTION 1 — BASIC CYBERSECURITY CONCEPTS
# =============================================================================

print("=" * 80)
print("THREAT LANDSCAPE AND MITRE ATT&CK — DEFENSIVE LEARNING GUIDE")
print("=" * 80)


def explain_basic_concepts() -> None:
    """
    Explain the foundational vocabulary used in threat analysis.
    """

    concepts = {
        "Asset":
            "Something valuable that needs protection: data, systems, users, "
            "applications, devices, credentials, services or business processes.",

        "Threat":
            "A potential cause of harm to an asset.",

        "Threat actor":
            "An individual, group or organization capable of intentionally "
            "causing or attempting to cause security harm.",

        "Vulnerability":
            "A weakness that could be exploited or otherwise abused.",

        "Attack":
            "A deliberate attempt to compromise confidentiality, integrity, "
            "availability or another security objective.",

        "Risk":
            "The possibility that a threat will exploit a vulnerability and "
            "cause an undesirable impact.",

        "Control":
            "A safeguard designed to prevent, detect, respond to or recover "
            "from security problems.",

        "Incident":
            "A security event or series of events that requires investigation "
            "or response according to an organization's security policy.",

        "Threat intelligence":
            "Analyzed information about threats, threat actors, behaviors, "
            "capabilities, intentions and indicators that supports decisions.",

        "Attack surface":
            "The collection of exposed assets, interfaces, identities, "
            "applications, networks and services that could become relevant "
            "to security risk.",
    }

    for name, definition in concepts.items():
        print(f"\n{name}")
        print("-" * len(name))
        print(definition)


# =============================================================================
# SECTION 2 — THREAT VS VULNERABILITY VS RISK
# =============================================================================

def demonstrate_threat_vulnerability_risk() -> None:
    """
    Demonstrates the relationship between threat, vulnerability and risk.

    Simplified conceptual relationship:

        Threat
           |
           v
    Exploitable weakness
           |
           v
         Impact
           |
           v
          Risk

    A vulnerability does not automatically mean a major risk.
    Context matters.

    Example:
        Asset value = high
        Threat likelihood = high
        Vulnerability exposure = high
        Impact = high

    These together can produce significant risk.
    """

    asset_value = 5
    threat_likelihood = 4
    vulnerability_exposure = 4
    impact = 5

    simplified_risk = (
        asset_value
        * threat_likelihood
        * vulnerability_exposure
        * impact
    )

    print("\n" + "=" * 80)
    print("THREAT / VULNERABILITY / RISK")
    print("=" * 80)

    print(f"Asset value: {asset_value}/5")
    print(f"Threat likelihood: {threat_likelihood}/5")
    print(f"Vulnerability exposure: {vulnerability_exposure}/5")
    print(f"Potential impact: {impact}/5")
    print(f"Simplified risk score: {simplified_risk}")


# =============================================================================
# SECTION 3 — WHAT IS THE THREAT LANDSCAPE?
# =============================================================================

def explain_threat_landscape() -> None:
    """
    The threat landscape represents the collection of security threats
    relevant to an organization, sector, geography or technology environment.

    It is dynamic because:

    - technology changes
    - business models change
    - geopolitical conditions change
    - criminal economics change
    - vulnerabilities appear
    - cloud adoption changes architecture
    - identities become increasingly important
    - attackers adapt
    - defensive controls improve
    """

    dimensions = [
        "Threat actors",
        "Motivations",
        "Capabilities",
        "Target sectors",
        "Geographic scope",
        "Attack surfaces",
        "Vulnerabilities",
        "Adversary behaviors",
        "Malware and tooling",
        "Social engineering",
        "Cloud threats",
        "Identity threats",
        "Supply-chain threats",
        "Insider threats",
        "Cyber espionage",
        "Cybercrime",
        "Hacktivism",
        "Nation-state activity",
    ]

    print("\n" + "=" * 80)
    print("THREAT LANDSCAPE")
    print("=" * 80)

    for index, dimension in enumerate(dimensions, start=1):
        print(f"{index:02d}. {dimension}")


# =============================================================================
# SECTION 4 — THREAT ACTORS
# =============================================================================

class ThreatActorType(Enum):
    """
    High-level categories of threat actors.

    These categories are analytical labels rather than perfect real-world
    classifications. A single actor may fit more than one category.
    """

    CYBERCRIMINAL = "Cybercriminal"
    NATION_STATE = "Nation-state"
    INSIDER = "Insider"
    HACKTIVIST = "Hacktivist"
    SCRIPT_KIDDIE = "Script kiddie"
    ESPIONAGE_GROUP = "Cyber espionage group"
    APT = "Advanced Persistent Threat"
    COMPETITOR = "Competitor / industrial threat actor"


@dataclass
class ThreatActor:
    """
    Represents a hypothetical threat actor for defensive analysis.
    """

    name: str
    actor_type: ThreatActorType
    motivation: List[str]
    capability: int
    persistence: int
    sophistication: int
    target_preferences: List[str]
    typical_behavior: List[str]

    def profile(self) -> Dict:
        return {
            "name": self.name,
            "type": self.actor_type.value,
            "motivation": self.motivation,
            "capability": self.capability,
            "persistence": self.persistence,
            "sophistication": self.sophistication,
            "target_preferences": self.target_preferences,
            "typical_behavior": self.typical_behavior,
        }


# =============================================================================
# SECTION 5 — COMMON THREAT ACTOR CATEGORIES
# =============================================================================

def create_threat_actor_catalog() -> List[ThreatActor]:
    """
    Create hypothetical profiles for common threat actor categories.
    """

    return [

        ThreatActor(
            name="Financially Motivated Criminal Group",
            actor_type=ThreatActorType.CYBERCRIMINAL,
            motivation=[
                "Financial gain",
                "Extortion",
                "Fraud",
                "Credential monetization"
            ],
            capability=4,
            persistence=4,
            sophistication=4,
            target_preferences=[
                "Financial organizations",
                "Retail",
                "Healthcare",
                "Technology companies"
            ],
            typical_behavior=[
                "Credential abuse",
                "Social engineering",
                "Malware delivery",
                "Data theft",
                "Extortion"
            ]
        ),

        ThreatActor(
            name="Hypothetical State Intelligence Unit",
            actor_type=ThreatActorType.NATION_STATE,
            motivation=[
                "Strategic intelligence",
                "Geopolitical advantage",
                "Military intelligence",
                "Political objectives"
            ],
            capability=5,
            persistence=5,
            sophistication=5,
            target_preferences=[
                "Government",
                "Defense",
                "Critical infrastructure",
                "Research institutions"
            ],
            typical_behavior=[
                "Long-term access",
                "Targeted intrusion",
                "Credential abuse",
                "Information collection",
                "Covert operations"
            ]
        ),

        ThreatActor(
            name="Disgruntled Internal User",
            actor_type=ThreatActorType.INSIDER,
            motivation=[
                "Revenge",
                "Financial gain",
                "Personal grievance"
            ],
            capability=3,
            persistence=3,
            sophistication=2,
            target_preferences=[
                "Internal systems",
                "Sensitive documents",
                "Business applications"
            ],
            typical_behavior=[
                "Unauthorized access",
                "Data misuse",
                "Policy violations",
                "Abuse of legitimate privileges"
            ]
        ),

        ThreatActor(
            name="Ideological Online Collective",
            actor_type=ThreatActorType.HACKTIVIST,
            motivation=[
                "Political expression",
                "Ideological goals",
                "Publicity"
            ],
            capability=3,
            persistence=2,
            sophistication=2,
            target_preferences=[
                "Government websites",
                "Organizations associated with a cause",
                "Public-facing services"
            ],
            typical_behavior=[
                "Website disruption",
                "Public campaigns",
                "Data exposure",
                "Online propaganda"
            ]
        ),

        ThreatActor(
            name="Inexperienced Tool User",
            actor_type=ThreatActorType.SCRIPT_KIDDIE,
            motivation=[
                "Curiosity",
                "Entertainment",
                "Recognition",
                "Experimentation"
            ],
            capability=1,
            persistence=1,
            sophistication=1,
            target_preferences=[
                "Poorly secured public systems",
                "Visible services",
                "Easy targets"
            ],
            typical_behavior=[
                "Use of publicly available tools",
                "Low customization",
                "Opportunistic activity"
            ]
        ),

        ThreatActor(
            name="Strategic Intelligence Collector",
            actor_type=ThreatActorType.ESPIONAGE_GROUP,
            motivation=[
                "Intelligence collection",
                "Strategic advantage",
                "Economic information"
            ],
            capability=5,
            persistence=5,
            sophistication=5,
            target_preferences=[
                "Government",
                "Technology",
                "Research",
                "Defense",
                "Telecommunications"
            ],
            typical_behavior=[
                "Targeted collection",
                "Long dwell time",
                "Credential abuse",
                "Information discovery"
            ]
        ),
    ]


def display_actor_profiles(actors: List[ThreatActor]) -> None:

    print("\n" + "=" * 80)
    print("THREAT ACTOR PROFILES")
    print("=" * 80)

    for actor in actors:

        print(f"\nActor: {actor.name}")
        print(f"Type: {actor.actor_type.value}")
        print(f"Capability: {actor.capability}/5")
        print(f"Persistence: {actor.persistence}/5")
        print(f"Sophistication: {actor.sophistication}/5")

        print("Motivations:")
        for item in actor.motivation:
            print(f"  - {item}")

        print("Preferred targets:")
        for item in actor.target_preferences:
            print(f"  - {item}")

        print("Typical behavior:")
        for item in actor.typical_behavior:
            print(f"  - {item}")


# =============================================================================
# SECTION 6 — CYBERCRIME
# =============================================================================

def explain_cybercrime() -> None:
    """
    Cybercrime is criminal activity involving computers, networks,
    digital systems or data.

    Common economic motivations include:

    - fraud
    - extortion
    - theft
    - account compromise
    - financial manipulation
    - ransomware
    - data monetization
    - identity abuse

    Defensive lesson:
        Organizations should protect both technology and business processes.
    """

    cybercrime_categories = {
        "Financial fraud":
            "Unauthorized manipulation intended to obtain money or economic benefit.",

        "Credential theft":
            "Obtaining authentication information for unauthorized access.",

        "Data theft":
            "Unauthorized acquisition of valuable or sensitive information.",

        "Extortion":
            "Threatening harm, disclosure or disruption to pressure a victim.",

        "Ransomware":
            "Malicious activity involving unauthorized encryption, disruption "
            "or extortion associated with data or systems.",

        "Account takeover":
            "Unauthorized control of a legitimate user account.",

        "Business email compromise":
            "Fraudulent abuse of business communications and identities.",

        "Fraud-as-a-service":
            "Criminal ecosystems that provide capabilities or services to "
            "other criminals."
    }

    print("\n" + "=" * 80)
    print("CYBERCRIME")
    print("=" * 80)

    for category, explanation in cybercrime_categories.items():
        print(f"\n{category}")
        print(explanation)


# =============================================================================
# SECTION 7 — NATION-STATE THREATS
# =============================================================================

def explain_nation_state_threats() -> None:
    """
    Nation-state cyber activity may support geopolitical, military,
    intelligence, economic or strategic objectives.

    Important analytical dimensions:

    1. Strategic objective
    2. Target selection
    3. Resources
    4. Persistence
    5. Operational security
    6. Intelligence value
    7. Geopolitical context
    """

    dimensions = [
        ("Strategic objective", "What information or capability is valuable?"),
        ("Target selection", "Which sectors or organizations are strategically important?"),
        ("Resources", "What level of funding, personnel and infrastructure is available?"),
        ("Persistence", "How important is long-term access?"),
        ("Operational security", "How carefully does the actor attempt to avoid detection?"),
        ("Intelligence value", "How valuable is the collected information?"),
        ("Geopolitical context", "What external political factors influence targeting?"),
    ]

    print("\n" + "=" * 80)
    print("NATION-STATE THREATS")
    print("=" * 80)

    for dimension, explanation in dimensions:
        print(f"\n{dimension}:")
        print(explanation)


# =============================================================================
# SECTION 8 — INSIDER THREATS
# =============================================================================

class InsiderType(Enum):
    MALICIOUS = "Malicious insider"
    NEGLIGENT = "Negligent insider"
    COMPROMISED = "Compromised insider"


@dataclass
class InsiderRisk:
    name: str
    insider_type: InsiderType
    access_level: int
    data_sensitivity: int
    anomaly_level: int

    def risk_score(self) -> float:
        """
        Simplified educational score.

        Real organizations use much more sophisticated models and should
        avoid treating a mathematical score as proof of malicious behavior.
        """

        return (
            self.access_level
            * self.data_sensitivity
            * self.anomaly_level
        )


def demonstrate_insider_risk() -> None:

    examples = [
        InsiderRisk(
            "Privileged administrator",
            InsiderType.COMPROMISED,
            5,
            5,
            4
        ),
        InsiderRisk(
            "Employee accidentally sharing data",
            InsiderType.NEGLIGENT,
            3,
            4,
            2
        ),
        InsiderRisk(
            "Disgruntled employee",
            InsiderType.MALICIOUS,
            4,
            5,
            4
        ),
    ]

    print("\n" + "=" * 80)
    print("INSIDER THREAT ANALYSIS")
    print("=" * 80)

    for example in examples:
        print(
            f"{example.name:40} | "
            f"{example.insider_type.value:25} | "
            f"Score={example.risk_score()}"
        )


# =============================================================================
# SECTION 9 — HACKTIVISTS
# =============================================================================

def explain_hacktivism() -> None:

    print("\n" + "=" * 80)
    print("HACKTIVISM")
    print("=" * 80)

    characteristics = [
        "Ideological or political motivation",
        "Public visibility may be important",
        "Targets may be selected because of perceived symbolic value",
        "Operations can be opportunistic",
        "Disruption and publicity can be objectives",
        "Attribution may be difficult",
        "Groups may be decentralized",
        "Capability can vary dramatically",
    ]

    for characteristic in characteristics:
        print(f"- {characteristic}")


# =============================================================================
# SECTION 10 — SCRIPT KIDDIES
# =============================================================================

def explain_script_kiddies() -> None:

    print("\n" + "=" * 80)
    print("SCRIPT KIDDIES")
    print("=" * 80)

    print(
        """
A script kiddie is a commonly used informal term for an inexperienced
individual who relies heavily on existing tools, scripts or publicly
available techniques without necessarily understanding their internals.

Important defensive lesson:

Low sophistication does NOT mean zero risk.

Automated tools can still create:

- scanning noise
- account lockouts
- service disruption
- opportunistic compromise
- exposure of poorly protected systems
"""
    )


# =============================================================================
# SECTION 11 — CYBER ESPIONAGE
# =============================================================================

def explain_cyber_espionage() -> None:

    print("\n" + "=" * 80)
    print("CYBER ESPIONAGE")
    print("=" * 80)

    objectives = [
        "Political intelligence",
        "Military intelligence",
        "Diplomatic intelligence",
        "Industrial information",
        "Research and development information",
        "Strategic business information",
        "Technology information",
    ]

    print("Potential objectives:")
    for objective in objectives:
        print(f"- {objective}")

    print(
        """
Cyber espionage is often characterized by the value of information rather
than immediate financial gain.

The defender should therefore ask:

    What information would an adversary value?

rather than only:

    What system could an adversary attack?
"""
    )


# =============================================================================
# SECTION 12 — ADVANCED PERSISTENT THREATS
# =============================================================================

def explain_apt() -> None:

    print("\n" + "=" * 80)
    print("ADVANCED PERSISTENT THREAT (APT)")
    print("=" * 80)

    print(
        """
APT is generally used to describe a capable adversary or campaign that
maintains a sustained and strategically motivated presence.

The important concepts are:

ADVANCED
    The actor may possess substantial capability.

PERSISTENT
    The actor may maintain long-term interest or access.

THREAT
    The activity presents a meaningful security risk.

An APT is therefore not simply "a very advanced hacker."

The term is most useful when analyzing:

- capability
- persistence
- objectives
- targeting
- operational behavior
- intelligence requirements
"""
    )


# =============================================================================
# SECTION 13 — MOTIVATION VS CAPABILITY
# =============================================================================

def actor_risk_profile(actor: ThreatActor) -> float:
    """
    Calculate a simplified actor profile.

    This is NOT a real-world threat score.
    It is only an educational analytical model.
    """

    return (
        actor.capability
        * actor.persistence
        * actor.sophistication
    )


def rank_actors(actors: List[ThreatActor]) -> None:

    ranked = sorted(
        actors,
        key=actor_risk_profile,
        reverse=True
    )

    print("\n" + "=" * 80)
    print("SIMPLIFIED ACTOR RANKING")
    print("=" * 80)

    for position, actor in enumerate(ranked, start=1):
        print(
            f"{position}. "
            f"{actor.name} -> "
            f"{actor_risk_profile(actor)}"
        )


# =============================================================================
# SECTION 14 — MITRE ATT&CK FUNDAMENTALS
# =============================================================================

def explain_mitre_attack() -> None:
    """
    MITRE ATT&CK is a knowledge base for understanding adversary behavior.

    ATT&CK organizes behavior into:

        Tactics
            ↓
        Techniques
            ↓
        Sub-techniques

    It can support:

    - threat intelligence
    - detection engineering
    - SOC analysis
    - incident response
    - threat hunting
    - adversary emulation
    - purple teaming
    - security control assessment
    """

    print("\n" + "=" * 80)
    print("MITRE ATT&CK")
    print("=" * 80)

    print(
        """
MITRE ATT&CK helps answer:

    "What behavior might an adversary use to achieve an objective?"

It is behavior-oriented rather than merely malware-oriented.

A malware family is not itself the complete threat model.

Two different malware families can exhibit similar behaviors.

Two actors can use different tools to accomplish similar objectives.

Therefore:

    Tools change frequently.
    Techniques can remain conceptually useful for longer.
"""
    )


# =============================================================================
# SECTION 15 — ATT&CK TACTICS
# =============================================================================

ATTACK_TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def display_attack_tactics() -> None:

    print("\n" + "=" * 80)
    print("ATT&CK TACTIC CONCEPTS")
    print("=" * 80)

    for index, tactic in enumerate(ATTACK_TACTICS, start=1):
        print(f"{index:02d}. {tactic}")


# =============================================================================
# SECTION 16 — TACTIC VS TECHNIQUE VS PROCEDURE
# =============================================================================

def explain_attack_hierarchy() -> None:

    print("\n" + "=" * 80)
    print("TACTIC VS TECHNIQUE VS PROCEDURE")
    print("=" * 80)

    print(
        """
TACTIC
------
Represents the adversary's objective.

Example:
    Credential Access

TECHNIQUE
---------
Represents a general method used to achieve the objective.

Example:
    OS Credential Dumping

SUB-TECHNIQUE
-------------
Provides a more specific behavior where the ATT&CK knowledge base defines one.

PROCEDURE
---------
Represents a concrete example of how a particular actor or software has
used a technique.

Mental model:

    WHY?
      ↓
    TACTIC

    HOW?
      ↓
    TECHNIQUE

    HOW EXACTLY?
      ↓
    PROCEDURE / OBSERVED IMPLEMENTATION
"""
    )


# =============================================================================
# SECTION 17 — SIMULATED ATT&CK TECHNIQUES
# =============================================================================

@dataclass
class Technique:
    """
    Simplified local representation of ATT&CK-style technique information.

    IDs below are examples used to teach the structure of ATT&CK.
    Always verify current IDs and names against the official ATT&CK knowledge
    base before using them operationally.
    """

    technique_id: str
    name: str
    tactic: str
    description: str


SIMULATED_TECHNIQUES = [

    Technique(
        "T1566",
        "Phishing",
        "Initial Access",
        "Social engineering through deceptive communication."
    ),

    Technique(
        "T1059",
        "Command and Scripting Interpreter",
        "Execution",
        "Execution through command or scripting interpreters."
    ),

    Technique(
        "T1078",
        "Valid Accounts",
        "Initial Access",
        "Abuse of legitimate account credentials or sessions."
    ),

    Technique(
        "T1087",
        "Account Discovery",
        "Discovery",
        "Discovery of accounts in an environment."
    ),

    Technique(
        "T1083",
        "File and Directory Discovery",
        "Discovery",
        "Discovery of files and directories."
    ),

    Technique(
        "T1005",
        "Data from Local System",
        "Collection",
        "Collection of data from local systems."
    ),

    Technique(
        "T1041",
        "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Exfiltration through an established command-and-control channel."
    ),

    Technique(
        "T1486",
        "Data Encrypted for Impact",
        "Impact",
        "Use of encryption to affect availability or operational access."
    ),

]


def display_techniques() -> None:

    print("\n" + "=" * 80)
    print("SIMULATED ATT&CK TECHNIQUE CATALOG")
    print("=" * 80)

    for technique in SIMULATED_TECHNIQUES:
        print(
            f"{technique.technique_id:<8} | "
            f"{technique.name:<40} | "
            f"{technique.tactic}"
        )


# =============================================================================
# SECTION 18 — OBSERVED BEHAVIOR
# =============================================================================

@dataclass
class Observation:
    """
    Represents a defensive observation.

    Examples:

    - unusual authentication activity
    - suspicious process execution
    - unusual discovery behavior
    - unexpected access to sensitive data
    """

    event_id: str
    host: str
    user: str
    behavior: str
    source: str
    severity: int
    timestamp: str
    tags: List[str] = field(default_factory=list)


SIMULATED_OBSERVATIONS = [

    Observation(
        "E001",
        "WS-001",
        "employee01",
        "Suspicious email link interaction",
        "Email Security",
        3,
        "2026-09-03T09:15:00",
        ["phishing", "initial-access"]
    ),

    Observation(
        "E002",
        "WS-001",
        "employee01",
        "Unexpected command interpreter activity",
        "Endpoint Telemetry",
        4,
        "2026-09-03T09:18:00",
        ["execution"]
    ),

    Observation(
        "E003",
        "WS-001",
        "employee01",
        "Unusual account discovery behavior",
        "Endpoint Telemetry",
        3,
        "2026-09-03T09:20:00",
        ["discovery"]
    ),

    Observation(
        "E004",
        "FS-002",
        "employee01",
        "Unexpected access to sensitive project directory",
        "File Monitoring",
        4,
        "2026-09-03T09:25:00",
        ["collection"]
    ),

    Observation(
        "E005",
        "FS-002",
        "employee01",
        "Large outbound data transfer anomaly",
        "Network Monitoring",
        5,
        "2026-09-03T09:35:00",
        ["possible-exfiltration"]
    ),
]


# =============================================================================
# SECTION 19 — MAPPING BEHAVIOR TO ATT&CK
# =============================================================================

BEHAVIOR_TO_TECHNIQUE = {
    "Suspicious email link interaction": "T1566",
    "Unexpected command interpreter activity": "T1059",
    "Unusual account discovery behavior": "T1087",
    "Unexpected access to sensitive project directory": "T1005",
    "Large outbound data transfer anomaly": "T1041",
}


def map_observations_to_attack(
    observations: List[Observation],
    techniques: List[Technique]
) -> List[Dict]:

    technique_lookup = {
        technique.technique_id: technique
        for technique in techniques
    }

    mapped = []

    for observation in observations:

        technique_id = BEHAVIOR_TO_TECHNIQUE.get(
            observation.behavior
        )

        if technique_id is None:
            continue

        technique = technique_lookup.get(technique_id)

        if technique is None:
            continue

        mapped.append({
            "event_id": observation.event_id,
            "behavior": observation.behavior,
            "technique_id": technique.technique_id,
            "technique": technique.name,
            "tactic": technique.tactic,
            "severity": observation.severity,
        })

    return mapped


def display_mapping(mapped: List[Dict]) -> None:

    print("\n" + "=" * 80)
    print("OBSERVED BEHAVIOR → ATT&CK MAPPING")
    print("=" * 80)

    for item in mapped:
        print(
            f"{item['event_id']} | "
            f"{item['behavior']} | "
            f"{item['technique_id']} | "
            f"{item['technique']} | "
            f"{item['tactic']}"
        )


# =============================================================================
# SECTION 20 — ATT&CK COVERAGE
# =============================================================================

def calculate_tactic_coverage(mapped: List[Dict]) -> Dict[str, int]:

    coverage = Counter(
        item["tactic"]
        for item in mapped
    )

    return dict(coverage)


def display_tactic_coverage(mapped: List[Dict]) -> None:

    coverage = calculate_tactic_coverage(mapped)

    print("\n" + "=" * 80)
    print("TACTIC COVERAGE")
    print("=" * 80)

    for tactic in ATTACK_TACTICS:

        count = coverage.get(tactic, 0)

        if count:
            print(f"{tactic:<25} -> {count} observation(s)")


# =============================================================================
# SECTION 21 — THREAT MODEL
# =============================================================================

@dataclass
class Asset:
    name: str
    criticality: int
    sensitivity: int
    exposure: int


@dataclass
class ThreatScenario:
    name: str
    actor: ThreatActor
    likelihood: int
    impact: int
    affected_assets: List[str]


def calculate_scenario_risk(
    scenario: ThreatScenario,
    assets: Dict[str, Asset]
) -> float:

    if not scenario.affected_assets:
        asset_factor = 1
    else:
        factors = []

        for asset_name in scenario.affected_assets:

            asset = assets.get(asset_name)

            if asset:
                factors.append(
                    (
                        asset.criticality
                        + asset.sensitivity
                        + asset.exposure
                    ) / 3
                )

        asset_factor = statistics.mean(factors) if factors else 1

    return (
        scenario.likelihood
        * scenario.impact
        * asset_factor
    )


def demonstrate_threat_modeling() -> None:

    assets = {
        "Customer Database": Asset(
            "Customer Database",
            criticality=5,
            sensitivity=5,
            exposure=3
        ),

        "Public Website": Asset(
            "Public Website",
            criticality=3,
            sensitivity=1,
            exposure=5
        ),

        "Research Repository": Asset(
            "Research Repository",
            criticality=5,
            sensitivity=5,
            exposure=2
        ),

        "Employee Identity Platform": Asset(
            "Employee Identity Platform",
            criticality=5,
            sensitivity=5,
            exposure=4
        ),
    }

    actors = create_threat_actor_catalog()

    scenarios = [

        ThreatScenario(
            "Financially motivated account compromise",
            actors[0],
            likelihood=4,
            impact=4,
            affected_assets=[
                "Customer Database",
                "Employee Identity Platform"
            ]
        ),

        ThreatScenario(
            "Strategic cyber espionage",
            actors[1],
            likelihood=3,
            impact=5,
            affected_assets=[
                "Research Repository"
            ]
        ),

        ThreatScenario(
            "Opportunistic disruption",
            actors[4],
            likelihood=4,
            impact=2,
            affected_assets=[
                "Public Website"
            ]
        ),
    ]

    print("\n" + "=" * 80)
    print("THREAT MODELING")
    print("=" * 80)

    for scenario in scenarios:

        risk = calculate_scenario_risk(
            scenario,
            assets
        )

        print(
            f"{scenario.name:<40} "
            f"Risk={risk:.2f}"
        )


# =============================================================================
# SECTION 22 — RISK CATEGORIZATION
# =============================================================================

def risk_category(score: float) -> str:

    if score < 20:
        return "Low"

    if score < 40:
        return "Moderate"

    if score < 60:
        return "High"

    return "Critical"


def demonstrate_risk_categories() -> None:

    print("\n" + "=" * 80)
    print("RISK CATEGORIES")
    print("=" * 80)

    scores = [8, 22, 45, 72]

    for score in scores:
        print(
            f"Score={score:>3} -> "
            f"{risk_category(score)}"
        )


# =============================================================================
# SECTION 23 — DETECTION ENGINEERING
# =============================================================================

@dataclass
class DetectionRule:
    name: str
    description: str
    severity: int
    data_sources: List[str]
    attack_technique: Optional[str]


DETECTION_RULES = [

    DetectionRule(
        name="Suspicious Authentication Pattern",
        description=(
            "Detect unusual authentication behavior using contextual "
            "identity and device telemetry."
        ),
        severity=4,
        data_sources=[
            "Identity provider",
            "Authentication logs",
            "Device telemetry"
        ],
        attack_technique="T1078"
    ),

    DetectionRule(
        name="Unusual Discovery Activity",
        description=(
            "Identify unusual account or resource discovery behavior "
            "relative to a user's baseline."
        ),
        severity=3,
        data_sources=[
            "Endpoint telemetry",
            "Process telemetry",
            "Audit logs"
        ],
        attack_technique="T1087"
    ),

    DetectionRule(
        name="Sensitive Data Access Anomaly",
        description=(
            "Identify unusual access patterns to sensitive repositories."
        ),
        severity=4,
        data_sources=[
            "File access logs",
            "DLP telemetry",
            "Identity logs"
        ],
        attack_technique="T1005"
    ),

    DetectionRule(
        name="Outbound Transfer Anomaly",
        description=(
            "Identify unusually large or unusual outbound data transfers."
        ),
        severity=5,
        data_sources=[
            "Network flow",
            "Proxy",
            "DLP",
            "Cloud telemetry"
        ],
        attack_technique="T1041"
    ),
]


def display_detection_rules() -> None:

    print("\n" + "=" * 80)
    print("DETECTION ENGINEERING")
    print("=" * 80)

    for rule in DETECTION_RULES:

        print(f"\nRule: {rule.name}")
        print(f"Severity: {rule.severity}")
        print(f"ATT&CK technique: {rule.attack_technique}")
        print("Data sources:")

        for source in rule.data_sources:
            print(f"  - {source}")

        print(f"Description: {rule.description}")


# =============================================================================
# SECTION 24 — SECURITY TELEMETRY
# =============================================================================

def explain_security_telemetry() -> None:

    telemetry = {
        "Identity logs":
            "Authentication, authorization and account activity.",

        "Endpoint telemetry":
            "Process, application, device and system behavior.",

        "Network telemetry":
            "Connections, flows, DNS, proxy and traffic metadata.",

        "Cloud audit logs":
            "Administrative and resource activity in cloud environments.",

        "Application logs":
            "Business application events and errors.",

        "Email security telemetry":
            "Messages, filtering decisions and suspicious email events.",

        "DLP telemetry":
            "Potentially sensitive data movement or policy violations.",

        "EDR telemetry":
            "Endpoint behavior used for investigation and detection.",
    }

    print("\n" + "=" * 80)
    print("SECURITY TELEMETRY")
    print("=" * 80)

    for source, description in telemetry.items():
        print(f"\n{source}:")
        print(description)


# =============================================================================
# SECTION 25 — INDICATORS OF COMPROMISE VS BEHAVIOR
# =============================================================================

def explain_ioc_vs_behavior() -> None:

    print("\n" + "=" * 80)
    print("IOC VS BEHAVIOR")
    print("=" * 80)

    print(
        """
INDICATOR OF COMPROMISE (IOC)
-----------------------------
An observable artifact associated with potentially malicious activity.

Examples:
    - suspicious domain
    - malicious file hash
    - suspicious IP address
    - unusual email sender
    - unexpected executable

BEHAVIOR
--------
What the system or user actually does.

Examples:
    - unusual authentication
    - abnormal data access
    - unexpected administrative behavior
    - unusual discovery activity

Why behavior matters:

Attackers can change infrastructure.

They can change:

    IP addresses
    domains
    filenames
    malware hashes
    hosting providers

Behavior-based detection can remain useful even when artifacts change.

ATT&CK is particularly useful for thinking about adversary behavior.
"""
    )


# =============================================================================
# SECTION 26 — TACTICS, TECHNIQUES AND PROCEDURES
# =============================================================================

@dataclass
class TTP:
    tactic: str
    technique: str
    procedure_example: str


SIMULATED_TTPS = [

    TTP(
        "Initial Access",
        "Phishing",
        "A hypothetical user receives a suspicious message."
    ),

    TTP(
        "Execution",
        "Command and Scripting Interpreter",
        "A suspicious process invokes an interpreter."
    ),

    TTP(
        "Discovery",
        "Account Discovery",
        "A system generates unusual account enumeration telemetry."
    ),

    TTP(
        "Collection",
        "Data from Local System",
        "Sensitive files are accessed unexpectedly."
    ),

    TTP(
        "Exfiltration",
        "Exfiltration Over C2 Channel",
        "Network telemetry shows an unusual outbound transfer."
    ),
]


def display_ttps() -> None:

    print("\n" + "=" * 80)
    print("TTP ANALYSIS")
    print("=" * 80)

    for item in SIMULATED_TTPS:

        print(
            f"Tactic={item.tactic} | "
            f"Technique={item.technique} | "
            f"Procedure={item.procedure_example}"
        )


# =============================================================================
# SECTION 27 — THREAT ACTOR COMPARISON
# =============================================================================

def compare_actor_types(actors: List[ThreatActor]) -> None:

    print("\n" + "=" * 80)
    print("THREAT ACTOR COMPARISON")
    print("=" * 80)

    header = (
        f"{'Actor':35} "
        f"{'Type':22} "
        f"{'Capability':10} "
        f"{'Persistence':12}"
    )

    print(header)
    print("-" * len(header))

    for actor in actors:

        print(
            f"{actor.name[:34]:35} "
            f"{actor.actor_type.value[:21]:22} "
            f"{actor.capability:<10} "
            f"{actor.persistence:<12}"
        )


# =============================================================================
# SECTION 28 — ATT&CK HEATMAP-STYLE ANALYSIS
# =============================================================================

def build_attack_matrix(
    mapped: List[Dict]
) -> Dict[str, Set[str]]:

    matrix = defaultdict(set)

    for item in mapped:

        matrix[item["tactic"]].add(
            item["technique_id"]
        )

    return dict(matrix)


def display_attack_matrix(mapped: List[Dict]) -> None:

    matrix = build_attack_matrix(mapped)

    print("\n" + "=" * 80)
    print("ATT&CK-STYLE COVERAGE MATRIX")
    print("=" * 80)

    for tactic in ATTACK_TACTICS:

        techniques = matrix.get(tactic, set())

        if techniques:

            print(
                f"{tactic:<25} -> "
                f"{', '.join(sorted(techniques))}"
            )


# =============================================================================
# SECTION 29 — DETECTION COVERAGE
# =============================================================================

def calculate_detection_coverage(
    techniques: List[Technique],
    detection_rules: List[DetectionRule]
) -> Dict[str, bool]:

    covered_techniques = {
        rule.attack_technique
        for rule in detection_rules
        if rule.attack_technique
    }

    return {
        technique.technique_id:
            technique.technique_id in covered_techniques
        for technique in techniques
    }


def display_detection_coverage() -> None:

    coverage = calculate_detection_coverage(
        SIMULATED_TECHNIQUES,
        DETECTION_RULES
    )

    print("\n" + "=" * 80)
    print("DETECTION COVERAGE")
    print("=" * 80)

    for technique_id, covered in coverage.items():

        status = "COVERED" if covered else "GAP"

        print(
            f"{technique_id:<8} -> {status}"
        )


# =============================================================================
# SECTION 30 — ATT&CK COVERAGE SCORE
# =============================================================================

def attack_coverage_score(
    techniques: List[Technique],
    detection_rules: List[DetectionRule]
) -> float:

    if not techniques:
        return 0.0

    covered = calculate_detection_coverage(
        techniques,
        detection_rules
    )

    count_covered = sum(
        1 for value in covered.values()
        if value
    )

    return (
        count_covered
        / len(techniques)
        * 100
    )


def display_coverage_score() -> None:

    score = attack_coverage_score(
        SIMULATED_TECHNIQUES,
        DETECTION_RULES
    )

    print("\n" + "=" * 80)
    print("OVERALL SIMULATED ATT&CK DETECTION COVERAGE")
    print("=" * 80)

    print(f"Coverage: {score:.1f}%")


# =============================================================================
# SECTION 31 — THREAT HUNTING
# =============================================================================

def explain_threat_hunting() -> None:

    print("\n" + "=" * 80)
    print("THREAT HUNTING")
    print("=" * 80)

    print(
        """
Threat hunting is a proactive security activity in which analysts search
for evidence of potentially malicious behavior that may not have generated
a high-confidence alert.

A simplified hunting process:

1. Form a hypothesis.
2. Identify relevant ATT&CK behaviors.
3. Identify telemetry.
4. Search for anomalies.
5. Investigate context.
6. Validate or reject the hypothesis.
7. Create or improve detections.
8. Document findings.
9. Feed intelligence back into defenses.

Example hypothesis:

    "An attacker may be abusing legitimate identities."

Possible telemetry:

    - authentication logs
    - device identity
    - location context
    - access patterns
    - privilege changes
    - application activity
"""
    )


# =============================================================================
# SECTION 32 — INCIDENT RESPONSE
# =============================================================================

def incident_response_lifecycle() -> List[str]:

    return [
        "Preparation",
        "Detection and Analysis",
        "Containment",
        "Eradication",
        "Recovery",
        "Post-Incident Activity",
    ]


def display_incident_response() -> None:

    print("\n" + "=" * 80)
    print("INCIDENT RESPONSE")
    print("=" * 80)

    for number, phase in enumerate(
        incident_response_lifecycle(),
        start=1
    ):
        print(f"{number}. {phase}")


# =============================================================================
# SECTION 33 — SIMULATED INCIDENT
# =============================================================================

@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    observations: List[Observation]
    suspected_actor_type: ThreatActorType
    mapped_techniques: List[str]


def create_simulated_incident() -> Incident:

    observations = SIMULATED_OBSERVATIONS

    mapped = map_observations_to_attack(
        observations,
        SIMULATED_TECHNIQUES
    )

    return Incident(
        incident_id="INC-2026-001",
        title="Simulated Suspicious Data Access Scenario",
        severity="High",
        observations=observations,
        suspected_actor_type=ThreatActorType.ESPIONAGE_GROUP,
        mapped_techniques=[
            item["technique_id"]
            for item in mapped
        ]
    )


def investigate_incident(
    incident: Incident
) -> None:

    print("\n" + "=" * 80)
    print("SIMULATED INCIDENT INVESTIGATION")
    print("=" * 80)

    print(f"Incident ID: {incident.incident_id}")
    print(f"Title: {incident.title}")
    print(f"Severity: {incident.severity}")
    print(
        f"Analytical hypothesis: "
        f"{incident.suspected_actor_type.value}"
    )

    print("\nObserved events:")

    for observation in incident.observations:

        print(
            f"{observation.event_id}: "
            f"{observation.behavior} | "
            f"Severity={observation.severity}"
        )

    print("\nMapped techniques:")

    for technique in incident.mapped_techniques:
        print(f"- {technique}")


# =============================================================================
# SECTION 34 — ATTACK CHAIN REASONING
# =============================================================================

def explain_attack_chain_reasoning() -> None:

    print("\n" + "=" * 80)
    print("ATTACK CHAIN REASONING")
    print("=" * 80)

    print(
        """
Security analysts should not always investigate alerts as isolated events.

Instead, they can ask:

    What happened before this?
    What happened after this?
    Does this behavior connect to another behavior?
    Does the sequence make sense?
    Is there a plausible adversary objective?

Example conceptual chain:

    Initial Access
          ↓
    Execution
          ↓
    Discovery
          ↓
    Collection
          ↓
    Exfiltration

The value of ATT&CK is that it provides a common vocabulary for describing
the behaviors in this chain.
"""
    )


# =============================================================================
# SECTION 35 — KILL CHAIN VS ATT&CK
# =============================================================================

def compare_kill_chain_and_attack() -> None:

    print("\n" + "=" * 80)
    print("KILL CHAIN VS MITRE ATT&CK")
    print("=" * 80)

    comparison = {
        "Cyber Kill Chain":
            "High-level staged model of an intrusion.",
        "MITRE ATT&CK":
            "Detailed knowledge base of adversary tactics and techniques.",
        "Best use of Kill Chain":
            "Communicating broad attack progression.",
        "Best use of ATT&CK":
            "Behavior mapping, detection, threat hunting and adversary analysis.",
    }

    for key, value in comparison.items():
        print(f"{key}: {value}")


# =============================================================================
# SECTION 36 — THREAT INTELLIGENCE LEVELS
# =============================================================================

def explain_threat_intelligence_levels() -> None:

    print("\n" + "=" * 80)
    print("THREAT INTELLIGENCE LEVELS")
    print("=" * 80)

    levels = {
        "Strategic":
            "Executive-level understanding of major threats and business impact.",

        "Operational":
            "Understanding campaigns, actors, intentions and operational activity.",

        "Tactical":
            "Understanding techniques, procedures and defensive behaviors.",

        "Technical":
            "Machine-oriented indicators and technical artifacts.",
    }

    for level, explanation in levels.items():
        print(f"\n{level}")
        print(explanation)


# =============================================================================
# SECTION 37 — ATT&CK FOR DIFFERENT SECURITY TEAMS
# =============================================================================

def explain_attack_organizational_use() -> None:

    print("\n" + "=" * 80)
    print("HOW DIFFERENT TEAMS USE ATT&CK")
    print("=" * 80)

    teams = {
        "SOC":
            "Classify alerts and investigate adversary behavior.",

        "Threat Intelligence":
            "Describe actor behaviors and campaigns.",

        "Threat Hunting":
            "Build behavioral hunting hypotheses.",

        "Incident Response":
            "Describe observed behaviors during investigations.",

        "Detection Engineering":
            "Identify telemetry and detection opportunities.",

        "Purple Team":
            "Compare offensive behavior simulations with defensive coverage.",

        "Security Architecture":
            "Identify control gaps across attack behaviors.",

        "Management":
            "Communicate security capability and detection coverage.",
    }

    for team, usage in teams.items():
        print(f"\n{team}:")
        print(usage)


# =============================================================================
# SECTION 38 — ZERO TRUST CONNECTION
# =============================================================================

def explain_zero_trust_connection() -> None:

    print("\n" + "=" * 80)
    print("THREAT LANDSCAPE AND ZERO TRUST")
    print("=" * 80)

    principles = [
        "Verify explicitly",
        "Use least privilege",
        "Assume breach",
        "Continuously evaluate risk",
        "Segment sensitive resources",
        "Monitor identities and devices",
        "Reduce implicit trust",
    ]

    for principle in principles:
        print(f"- {principle}")

    print(
        """
Threat actors increasingly target identities, applications, cloud resources
and legitimate access pathways.

Therefore, defensive architecture cannot rely exclusively on a network
perimeter.
"""
    )


# =============================================================================
# SECTION 39 — CLOUD THREAT LANDSCAPE
# =============================================================================

def explain_cloud_threats() -> None:

    print("\n" + "=" * 80)
    print("CLOUD THREAT LANDSCAPE")
    print("=" * 80)

    cloud_risks = [
        "Misconfigured storage",
        "Excessive permissions",
        "Compromised identities",
        "Exposed secrets",
        "Insecure APIs",
        "Weak workload isolation",
        "Insufficient logging",
        "Supply-chain risk",
        "Cloud control-plane abuse",
    ]

    for risk in cloud_risks:
        print(f"- {risk}")


# =============================================================================
# SECTION 40 — SUPPLY CHAIN THREATS
# =============================================================================

def explain_supply_chain_threats() -> None:

    print("\n" + "=" * 80)
    print("SUPPLY-CHAIN THREATS")
    print("=" * 80)

    stages = [
        "Software dependency",
        "Developer environment",
        "Build pipeline",
        "Artifact repository",
        "Third-party service",
        "Cloud infrastructure",
        "Deployment environment",
        "End user",
    ]

    for index, stage in enumerate(stages, start=1):
        print(f"{index}. {stage}")

    print(
        """
A supply-chain threat matters because an organization may trust software,
vendors or services that become an indirect pathway to risk.
"""
    )


# =============================================================================
# SECTION 41 — HUMAN FACTOR
# =============================================================================

def explain_human_factor() -> None:

    print("\n" + "=" * 80)
    print("HUMAN FACTOR IN THE THREAT LANDSCAPE")
    print("=" * 80)

    factors = [
        "Security awareness",
        "Identity management",
        "Privilege management",
        "Phishing resistance",
        "Insider-risk management",
        "Secure operational procedures",
        "Incident reporting",
        "Training",
    ]

    for factor in factors:
        print(f"- {factor}")


# =============================================================================
# SECTION 42 — DEFENSE IN DEPTH
# =============================================================================

def explain_defense_in_depth() -> None:

    print("\n" + "=" * 80)
    print("DEFENSE IN DEPTH")
    print("=" * 80)

    layers = [
        "Governance",
        "Security architecture",
        "Identity security",
        "Endpoint security",
        "Network security",
        "Application security",
        "Data security",
        "Monitoring",
        "Detection",
        "Incident response",
        "Backup and recovery",
        "Security awareness",
    ]

    for layer in layers:
        print(f"- {layer}")


# =============================================================================
# SECTION 43 — RISK PRIORITIZATION
# =============================================================================

def prioritize_controls(
    scenarios: List[ThreatScenario],
    assets: Dict[str, Asset]
) -> List[Tuple[str, float, str]]:

    results = []

    for scenario in scenarios:

        score = calculate_scenario_risk(
            scenario,
            assets
        )

        results.append(
            (
                scenario.name,
                score,
                risk_category(score)
            )
        )

    return sorted(
        results,
        key=lambda item: item[1],
        reverse=True
    )


# =============================================================================
# SECTION 44 — SIMPLE STATISTICS
# =============================================================================

def calculate_observation_statistics(
    observations: List[Observation]
) -> None:

    severities = [
        observation.severity
        for observation in observations
    ]

    print("\n" + "=" * 80)
    print("OBSERVATION STATISTICS")
    print("=" * 80)

    print(f"Number of observations: {len(observations)}")
    print(f"Average severity: {statistics.mean(severities):.2f}")
    print(f"Maximum severity: {max(severities)}")
    print(f"Minimum severity: {min(severities)}")


# =============================================================================
# SECTION 45 — BASIC ANOMALY SCORE
# =============================================================================

def anomaly_score(
    baseline: float,
    observed: float
) -> float:

    if baseline <= 0:
        return 0.0

    ratio = observed / baseline

    return min(
        ratio * 20,
        100
    )


def demonstrate_anomaly_detection() -> None:

    print("\n" + "=" * 80)
    print("SIMULATED ANOMALY DETECTION")
    print("=" * 80)

    baseline = 10
    observations = [8, 12, 20, 35, 50]

    for value in observations:

        score = anomaly_score(
            baseline,
            value
        )

        print(
            f"Baseline={baseline:>3} | "
            f"Observed={value:>3} | "
            f"Anomaly score={score:>6.2f}"
        )


# =============================================================================
# SECTION 46 — ATT&CK NAVIGATION MENTAL MODEL
# =============================================================================

def attack_navigation_model() -> None:

    print("\n" + "=" * 80)
    print("ATT&CK NAVIGATION MENTAL MODEL")
    print("=" * 80)

    questions = [
        "What is the adversary trying to achieve?",
        "Which ATT&CK tactic represents that objective?",
        "Which technique describes the observed behavior?",
        "Is there a relevant sub-technique?",
        "What telemetry would expose this behavior?",
        "Do we have a detection?",
        "How reliable is the detection?",
        "What control could prevent the behavior?",
        "What evidence would confirm or reject the hypothesis?",
    ]

    for number, question in enumerate(
        questions,
        start=1
    ):
        print(f"{number}. {question}")


# =============================================================================
# SECTION 47 — FALSE POSITIVES AND DETECTION QUALITY
# =============================================================================

@dataclass
class DetectionQuality:
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int

    def precision(self) -> float:

        denominator = (
            self.true_positives
            + self.false_positives
        )

        if denominator == 0:
            return 0.0

        return (
            self.true_positives
            / denominator
        )

    def recall(self) -> float:

        denominator = (
            self.true_positives
            + self.false_negatives
        )

        if denominator == 0:
            return 0.0

        return (
            self.true_positives
            / denominator
        )


def demonstrate_detection_metrics() -> None:

    quality = DetectionQuality(
        true_positives=80,
        false_positives=20,
        false_negatives=10,
        true_negatives=890
    )

    print("\n" + "=" * 80)
    print("DETECTION QUALITY")
    print("=" * 80)

    print(
        f"Precision: {quality.precision():.2%}"
    )

    print(
        f"Recall: {quality.recall():.2%}"
    )

    print(
        """
Precision asks:

    Of the alerts we generated, how many were actually relevant?

Recall asks:

    Of the relevant events that existed, how many did we detect?

A mature SOC balances both.
"""
    )


# =============================================================================
# SECTION 48 — RISK REGISTER
# =============================================================================

@dataclass
class RiskRegisterEntry:
    risk_id: str
    threat_actor: str
    scenario: str
    likelihood: int
    impact: int
    current_controls: List[str]
    recommended_controls: List[str]

    @property
    def inherent_risk(self) -> int:
        return self.likelihood * self.impact


def create_risk_register() -> List[RiskRegisterEntry]:

    return [

        RiskRegisterEntry(
            "R001",
            "Cybercriminal",
            "Account compromise",
            4,
            5,
            [
                "MFA",
                "Identity monitoring"
            ],
            [
                "Phishing-resistant authentication",
                "Conditional access",
                "Behavior analytics"
            ]
        ),

        RiskRegisterEntry(
            "R002",
            "Nation-state",
            "Strategic information collection",
            3,
            5,
            [
                "EDR",
                "Network monitoring"
            ],
            [
                "Threat hunting",
                "Data access monitoring",
                "Segmentation"
            ]
        ),

        RiskRegisterEntry(
            "R003",
            "Insider",
            "Unauthorized sensitive data access",
            3,
            5,
            [
                "DLP",
                "Access controls"
            ],
            [
                "Least privilege",
                "UEBA",
                "Privileged access management"
            ]
        ),
    ]


def display_risk_register() -> None:

    print("\n" + "=" * 80)
    print("RISK REGISTER")
    print("=" * 80)

    register = create_risk_register()

    for item in register:

        print(
            f"{item.risk_id} | "
            f"{item.threat_actor} | "
            f"{item.scenario} | "
            f"Inherent Risk={item.inherent_risk}"
        )


# =============================================================================
# SECTION 49 — EXECUTIVE THREAT SUMMARY
# =============================================================================

def executive_summary(
    actors: List[ThreatActor],
    observations: List[Observation]
) -> Dict:

    actor_types = Counter(
        actor.actor_type.value
        for actor in actors
    )

    observation_severity = statistics.mean(
        observation.severity
        for observation in observations
    )

    return {
        "actor_categories": dict(actor_types),
        "observation_count": len(observations),
        "average_observation_severity": round(
            observation_severity,
            2
        ),
        "primary_security_focus": [
            "Identity security",
            "Endpoint monitoring",
            "Sensitive data monitoring",
            "Threat hunting",
            "Detection engineering",
        ],
    }


def display_executive_summary() -> None:

    actors = create_threat_actor_catalog()

    summary = executive_summary(
        actors,
        SIMULATED_OBSERVATIONS
    )

    print("\n" + "=" * 80)
    print("EXECUTIVE THREAT SUMMARY")
    print("=" * 80)

    print(
        json.dumps(
            summary,
            indent=4
        )
    )


# =============================================================================
# SECTION 50 — ADVANCED THREAT-LANDSCAPE ANALYSIS
# =============================================================================

def advanced_threat_landscape_analysis() -> None:

    print("\n" + "=" * 80)
    print("ADVANCED THREAT-LANDSCAPE ANALYSIS")
    print("=" * 80)

    principles = [

        "1. Threat landscape is contextual.",
        "2. Actor capability does not equal actor intent.",
        "3. Intent does not guarantee successful capability.",
        "4. Risk depends on assets and business impact.",
        "5. Vulnerability severity is not the same as organizational risk.",
        "6. Detection should focus on behavior as well as artifacts.",
        "7. ATT&CK provides a common language for adversary behavior.",
        "8. ATT&CK mapping does not prove attribution.",
        "9. Multiple observations can provide stronger context than one alert.",
        "10. Security controls should be aligned with actual threat scenarios.",
        "11. Threat intelligence must be converted into decisions.",
        "12. Detection coverage should be continuously measured.",
        "13. Identity is a critical part of the modern attack surface.",
        "14. Cloud environments introduce new control-plane risks.",
        "15. Supply-chain dependencies expand the trust boundary.",
        "16. Insider risk requires behavioral and contextual analysis.",
        "17. Threat hunting complements automated detection.",
        "18. Incident response converts detection into containment and recovery.",
        "19. Security maturity requires feedback loops.",
        "20. No framework replaces security judgment.",
    ]

    for principle in principles:
        print(principle)


# =============================================================================
# SECTION 51 — DEFENSIVE FEEDBACK LOOP
# =============================================================================

def defensive_feedback_loop() -> None:

    print("\n" + "=" * 80)
    print("DEFENSIVE FEEDBACK LOOP")
    print("=" * 80)

    loop = [
        "Threat intelligence",
        "Threat modeling",
        "ATT&CK mapping",
        "Telemetry collection",
        "Detection engineering",
        "Alert investigation",
        "Threat hunting",
        "Incident response",
        "Lessons learned",
        "Control improvement",
        "Updated threat intelligence",
    ]

    for index, step in enumerate(
        loop,
        start=1
    ):
        next_step = (
            loop[index]
            if index < len(loop)
            else loop[0]
        )

        print(
            f"{index:02d}. {step:<30} "
            f"→ {next_step}"
        )


# =============================================================================
# SECTION 52 — COMPLETE DEFENSIVE WORKFLOW
# =============================================================================

def complete_defensive_workflow() -> None:

    print("\n" + "=" * 80)
    print("COMPLETE DEFENSIVE THREAT ANALYSIS WORKFLOW")
    print("=" * 80)

    workflow = [

        "Define business context",
        "Identify critical assets",
        "Identify relevant threat actors",
        "Understand motivations",
        "Estimate actor capability",
        "Identify attack surfaces",
        "Identify vulnerabilities",
        "Develop threat scenarios",
        "Estimate likelihood",
        "Estimate business impact",
        "Prioritize risks",
        "Map behaviors to ATT&CK",
        "Identify required telemetry",
        "Build detections",
        "Measure detection coverage",
        "Conduct threat hunting",
        "Investigate incidents",
        "Contain and remediate",
        "Measure residual risk",
        "Improve controls",
        "Repeat continuously",
    ]

    for number, step in enumerate(
        workflow,
        start=1
    ):
        print(f"{number:02d}. {step}")


# =============================================================================
# SECTION 53 — LEARNING CHECKLIST
# =============================================================================

def learning_checklist() -> None:

    checklist = {

        "Fundamentals": [
            "Threat",
            "Threat actor",
            "Vulnerability",
            "Risk",
            "Attack surface",
            "Security control",
            "Incident",
        ],

        "Threat actors": [
            "Cybercriminals",
            "Nation-state actors",
            "Insiders",
            "Hacktivists",
            "Script kiddies",
            "Cyber espionage actors",
            "APTs",
        ],

        "ATT&CK": [
            "Tactics",
            "Techniques",
            "Sub-techniques",
            "Procedures",
            "Behavior mapping",
            "Detection coverage",
        ],

        "Defensive operations": [
            "Threat intelligence",
            "Threat hunting",
            "Detection engineering",
            "Incident response",
            "Risk management",
            "Security monitoring",
            "Purple teaming",
        ],
    }

    print("\n" + "=" * 80)
    print("LEARNING CHECKLIST")
    print("=" * 80)

    for category, topics in checklist.items():

        print(f"\n{category}")

        for topic in topics:
            print(f"  [x] {topic}")


# =============================================================================
# SECTION 54 — MINI QUIZ
# =============================================================================

def mini_quiz() -> None:

    questions = [
        (
            "1. What represents an adversary's objective in ATT&CK?",
            "Tactic"
        ),
        (
            "2. What represents an adversary behavior or method?",
            "Technique"
        ),
        (
            "3. Which actor category is generally associated with financial gain?",
            "Cybercriminal"
        ),
        (
            "4. Which actor category may pursue strategic intelligence?",
            "Nation-state / espionage actor"
        ),
        (
            "5. Can an insider threat be accidental?",
            "Yes"
        ),
        (
            "6. Does ATT&CK itself prove attribution?",
            "No"
        ),
        (
            "7. What is a vulnerability?",
            "A weakness that may be abused or exploited"
        ),
        (
            "8. What is risk?",
            "Potential for threat-related harm considering likelihood and impact"
        ),
        (
            "9. Why is behavior-based detection useful?",
            "Behavior can remain relevant even when tools and indicators change."
        ),
        (
            "10. What is threat hunting?",
            "Proactive investigation for suspicious or malicious behavior."
        ),
    ]

    print("\n" + "=" * 80)
    print("MINI QUIZ")
    print("=" * 80)

    for question, answer in questions:

        print(f"\nQuestion: {question}")
        print(f"Answer:   {answer}")


# =============================================================================
# SECTION 55 — MAIN PROGRAM
# =============================================================================

def main() -> None:

    explain_basic_concepts()

    demonstrate_threat_vulnerability_risk()

    explain_threat_landscape()

    actors = create_threat_actor_catalog()

    display_actor_profiles(actors)

    explain_cybercrime()

    explain_nation_state_threats()

    demonstrate_insider_risk()

    explain_hacktivism()

    explain_script_kiddies()

    explain_cyber_espionage()

    explain_apt()

    rank_actors(actors)

    explain_mitre_attack()

    display_attack_tactics()

    explain_attack_hierarchy()

    display_techniques()

    mapped = map_observations_to_attack(
        SIMULATED_OBSERVATIONS,
        SIMULATED_TECHNIQUES
    )

    display_mapping(mapped)

    display_tactic_coverage(mapped)

    demonstrate_threat_modeling()

    demonstrate_risk_categories()

    display_detection_rules()

    explain_security_telemetry()

    explain_ioc_vs_behavior()

    display_ttps()

    compare_actor_types(actors)

    display_attack_matrix(mapped)

    display_detection_coverage()

    display_coverage_score()

    explain_threat_hunting()

    display_incident_response()

    incident = create_simulated_incident()

    investigate_incident(incident)

    explain_attack_chain_reasoning()

    compare_kill_chain_and_attack()

    explain_threat_intelligence_levels()

    explain_attack_organizational_use()

    explain_zero_trust_connection()

    explain_cloud_threats()

    explain_supply_chain_threats()

    explain_human_factor()

    explain_defense_in_depth()

    calculate_observation_statistics(
        SIMULATED_OBSERVATIONS
    )

    demonstrate_anomaly_detection()

    attack_navigation_model()

    demonstrate_detection_metrics()

    display_risk_register()

    display_executive_summary()

    advanced_threat_landscape_analysis()

    defensive_feedback_loop()

    complete_defensive_workflow()

    learning_checklist()

    mini_quiz()

    print("\n" + "=" * 80)
    print("END OF DEFENSIVE THREAT LANDSCAPE GUIDE")
    print("=" * 80)


if __name__ == "__main__":
    main()
