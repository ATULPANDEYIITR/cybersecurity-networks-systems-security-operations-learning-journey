"""
RISK MANAGEMENT: FROM FUNDAMENTALS TO ADVANCED PRACTICE

This standalone study script teaches risk management through executable Python
examples. The focus is on asset identification, threat modeling, likelihood,
impact, risk scoring, risk treatment, NIST Cybersecurity Framework concepts,
spreadsheet-style risk registers, prioritization, residual risk, simulations,
and practical governance.

No external packages are required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from math import ceil, exp, log
from random import Random
from statistics import mean, median, quantiles
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# =============================================================================
# 1. FUNDAMENTAL TERMINOLOGY
# =============================================================================

print("=" * 80)
print("RISK MANAGEMENT: FUNDAMENTALS TO ADVANCED")
print("=" * 80)


def print_section(title: str) -> None:
    """Print a consistent section heading."""
    print(f"\n{'-' * 80}\n{title}\n{'-' * 80}")


print_section("1.1 Core Definitions")

print(
    """
Asset:
    Something valuable that an organization needs to protect.

Threat:
    A potential cause of an unwanted event.

Vulnerability:
    A weakness that can be exploited by a threat.

Risk:
    The possibility that a threat exploits a vulnerability and causes harm.

Likelihood:
    An estimate of how probable a harmful event is.

Impact:
    The magnitude of harm if the event occurs.

Inherent risk:
    Risk before considering controls.

Control:
    A safeguard that reduces likelihood, impact, or both.

Residual risk:
    Risk remaining after controls are applied.

Risk owner:
    The person accountable for managing a particular risk.

Risk treatment:
    The decision and actions used to modify risk.

Risk appetite:
    The amount and type of risk an organization is willing to accept.

Risk tolerance:
    The acceptable variation around a risk objective or appetite.

Risk register:
    A structured record of identified risks, assessments, owners,
    treatments, controls, and status.
"""
)


# =============================================================================
# 2. BASIC RISK MODEL
# =============================================================================

print_section("2. Basic Risk Scoring")

print(
    """
A simple qualitative model is:

    Risk Score = Likelihood × Impact

For a 1-to-5 scale:

    1 = Very Low
    2 = Low
    3 = Moderate
    4 = High
    5 = Very High

The resulting score ranges from 1 to 25.
"""
)


def basic_risk_score(likelihood: int, impact: int) -> int:
    """Calculate a basic likelihood-times-impact score."""
    if not 1 <= likelihood <= 5:
        raise ValueError("Likelihood must be between 1 and 5.")
    if not 1 <= impact <= 5:
        raise ValueError("Impact must be between 1 and 5.")
    return likelihood * impact


def classify_basic_risk(score: int) -> str:
    """Classify a 1-to-25 risk score."""
    if not 1 <= score <= 25:
        raise ValueError("Risk score must be between 1 and 25.")

    if score <= 4:
        return "Low"
    if score <= 9:
        return "Moderate"
    if score <= 16:
        return "High"
    return "Critical"


examples = [
    ("Weak password policy", 4, 4),
    ("Temporary service outage", 3, 2),
    ("Major customer-data exposure", 4, 5),
    ("Minor office equipment loss", 1, 2),
]

for name, likelihood, impact in examples:
    score = basic_risk_score(likelihood, impact)
    print(f"{name:35} score={score:2} classification={classify_basic_risk(score)}")


# =============================================================================
# 3. RISK SCALES AND THEIR LIMITATIONS
# =============================================================================

print_section("3. Risk Matrices")

print(
    """
A risk matrix maps likelihood against impact.

Important limitation:
    A matrix is a decision aid, not a mathematical law.

For example:

    Likelihood = 5, Impact = 2 -> score 10
    Likelihood = 2, Impact = 5 -> score 10

The arithmetic treats them equally even though the two risks may require
different treatment. Direction, uncertainty, velocity, detectability,
regulatory consequences, and concentration can change the decision.

A mature assessment therefore records the underlying reasoning instead of
storing only the final score.
"""
)


def display_risk_matrix() -> None:
    """Display a simple 5x5 risk matrix."""
    print("\nImpact →       1      2      3      4      5")
    print("Likelihood ↓")

    for likelihood in range(5, 0, -1):
        values = []
        for impact in range(1, 6):
            score = likelihood * impact
            values.append(f"{score:>6}")
        print(f"{likelihood}              " + "".join(values))


display_risk_matrix()


# =============================================================================
# 4. ASSET IDENTIFICATION
# =============================================================================

print_section("4. Asset Identification")

print(
    """
Asset identification begins with determining what needs protection.

Common asset classes include:

    Information assets
    Software
    Hardware
    Cloud resources
    Networks
    People
    Business processes
    Facilities
    Intellectual property
    Financial resources
    Third-party services
    Reputation

The CIA triad is commonly used for information-security impact analysis:

    Confidentiality
        Preventing unauthorized disclosure.

    Integrity
        Preventing unauthorized modification or destruction.

    Availability
        Ensuring authorized users can access systems and information.

An asset can have high confidentiality requirements but moderate availability
requirements, or the reverse.
"""
)


class AssetCategory(Enum):
    INFORMATION = "Information"
    SOFTWARE = "Software"
    HARDWARE = "Hardware"
    PEOPLE = "People"
    PROCESS = "Business Process"
    THIRD_PARTY = "Third Party"
    FACILITY = "Facility"


@dataclass
class Asset:
    asset_id: str
    name: str
    category: AssetCategory
    owner: str
    confidentiality: int
    integrity: int
    availability: int
    business_value: int

    def __post_init__(self) -> None:
        for value_name, value in (
            ("confidentiality", self.confidentiality),
            ("integrity", self.integrity),
            ("availability", self.availability),
            ("business_value", self.business_value),
        ):
            if not 1 <= value <= 5:
                raise ValueError(f"{value_name} must be between 1 and 5.")

    @property
    def criticality(self) -> float:
        """Average CIA requirement weighted equally."""
        return mean(
            [self.confidentiality, self.integrity, self.availability]
        )

    def description(self) -> str:
        return (
            f"{self.asset_id}: {self.name} | "
            f"{self.category.value} | owner={self.owner} | "
            f"C={self.confidentiality}, I={self.integrity}, "
            f"A={self.availability} | value={self.business_value}"
        )


assets = [
    Asset(
        "A001",
        "Customer Database",
        AssetCategory.INFORMATION,
        "Data Team",
        5,
        5,
        4,
        5,
    ),
    Asset(
        "A002",
        "Payment API",
        AssetCategory.SOFTWARE,
        "Engineering",
        4,
        5,
        5,
        5,
    ),
    Asset(
        "A003",
        "Employee Laptops",
        AssetCategory.HARDWARE,
        "IT",
        4,
        3,
        3,
        3,
    ),
    Asset(
        "A004",
        "Cloud Backup Provider",
        AssetCategory.THIRD_PARTY,
        "Infrastructure",
        4,
        4,
        5,
        4,
    ),
]

for asset in assets:
    print(asset.description())
    print(f"  Criticality: {asset.criticality:.2f}")


# =============================================================================
# 5. THREAT MODELING
# =============================================================================

print_section("5. Threat Modeling")

print(
    """
Threat modeling systematically asks:

    1. What are we protecting?
    2. Who or what could cause harm?
    3. How could the event occur?
    4. What weakness enables it?
    5. What would happen?
    6. What controls already exist?
    7. What additional treatment is appropriate?

Threat categories can include:

    Human error
    Malicious insider
    External attacker
    Malware
    Phishing
    Credential theft
    Supply-chain compromise
    Software vulnerability
    Misconfiguration
    Hardware failure
    Natural disaster
    Utility failure
    Third-party outage
    Fraud
    Regulatory failure

A useful threat model connects:

    Asset → Threat → Vulnerability → Event → Consequence → Control
"""
)


@dataclass
class Threat:
    threat_id: str
    name: str
    category: str
    description: str


@dataclass
class Vulnerability:
    vulnerability_id: str
    name: str
    description: str
    exploitability: int


threats = [
    Threat(
        "T001",
        "Credential Theft",
        "Cyber",
        "An attacker obtains valid user credentials.",
    ),
    Threat(
        "T002",
        "Ransomware",
        "Cyber",
        "Malicious software encrypts business data.",
    ),
    Threat(
        "T003",
        "Cloud Provider Outage",
        "Operational",
        "A critical external service becomes unavailable.",
    ),
    Threat(
        "T004",
        "Human Error",
        "Operational",
        "An employee accidentally exposes or changes information.",
    ),
]

vulnerabilities = [
    Vulnerability(
        "V001",
        "Weak Authentication",
        "Accounts do not consistently use strong authentication.",
        4,
    ),
    Vulnerability(
        "V002",
        "Insufficient Backup Isolation",
        "Backups can be affected by the same compromise as production.",
        4,
    ),
    Vulnerability(
        "V003",
        "Third-Party Dependency",
        "A critical business process relies on an external provider.",
        3,
    ),
    Vulnerability(
        "V004",
        "Excessive Permissions",
        "Users have more access than their business roles require.",
        3,
    ),
]

for threat in threats:
    print(f"{threat.threat_id}: {threat.name} [{threat.category}]")

for vulnerability in vulnerabilities:
    print(
        f"{vulnerability.vulnerability_id}: {vulnerability.name} "
        f"exploitability={vulnerability.exploitability}"
    )


# =============================================================================
# 6. RISK EVENTS
# =============================================================================

print_section("6. From Threats to Risk Events")

print(
    """
A threat by itself is not necessarily a risk.

Example:

    Threat:
        Credential theft.

    Vulnerability:
        Weak authentication.

    Risk event:
        An attacker uses stolen credentials to access the customer database.

    Consequence:
        Unauthorized disclosure of customer information.

The risk statement should be specific enough to support a treatment decision.
"""
)


@dataclass
class RiskEvent:
    risk_id: str
    title: str
    asset_id: str
    threat_id: str
    vulnerability_id: str
    consequence: str
    likelihood: int
    impact: int

    @property
    def inherent_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def inherent_rating(self) -> str:
        return classify_basic_risk(self.inherent_score)


risk_events = [
    RiskEvent(
        "R001",
        "Unauthorized customer database access",
        "A001",
        "T001",
        "V001",
        "Customer information is disclosed.",
        4,
        5,
    ),
    RiskEvent(
        "R002",
        "Production data encrypted by ransomware",
        "A001",
        "T002",
        "V002",
        "Critical information becomes unavailable.",
        3,
        5,
    ),
    RiskEvent(
        "R003",
        "Payment API outage",
        "A002",
        "T003",
        "V003",
        "Customers cannot complete payments.",
        3,
        5,
    ),
    RiskEvent(
        "R004",
        "Accidental sensitive-data disclosure",
        "A001",
        "T004",
        "V004",
        "Sensitive information is shared with an unauthorized party.",
        3,
        4,
    ),
]

for risk in risk_events:
    print(
        f"{risk.risk_id}: {risk.title} | "
        f"inherent={risk.inherent_score} ({risk.inherent_rating})"
    )


# =============================================================================
# 7. QUALITATIVE AND QUANTITATIVE ANALYSIS
# =============================================================================

print_section("7. Qualitative vs Quantitative Risk Analysis")

print(
    """
Qualitative analysis:
    Uses categories such as Low, Moderate, High, and Critical.

Advantages:
    - Fast
    - Easy to communicate
    - Useful when numerical data is limited

Limitations:
    - Subjective
    - Different assessors may interpret scales differently
    - A score can conceal uncertainty

Quantitative analysis:
    Attempts to express loss using numerical estimates.

A simplified expected-loss model is:

    Expected Annual Loss = Probability × Loss

For example:

    Annual probability = 0.10
    Estimated loss = $500,000

    Expected annual loss = 0.10 × $500,000
                         = $50,000

Quantitative estimates are still uncertain. A precise-looking number does not
automatically mean the estimate is accurate.
"""
)


def expected_annual_loss(probability: float, loss: float) -> float:
    if not 0 <= probability <= 1:
        raise ValueError("Probability must be between 0 and 1.")
    if loss < 0:
        raise ValueError("Loss cannot be negative.")
    return probability * loss


probability = 0.10
loss = 500_000
print(
    f"Expected annual loss: "
    f"${expected_annual_loss(probability, loss):,.2f}"
)


# =============================================================================
# 8. CONTROL TYPES
# =============================================================================

print_section("8. Security and Risk Controls")

print(
    """
Controls can be classified in several ways.

By purpose:

    Preventive
        Attempt to stop an unwanted event.

    Detective
        Identify an event that has occurred or is occurring.

    Corrective
        Restore or repair after an event.

    Deterrent
        Discourage unwanted behavior.

    Compensating
        Provide an alternative safeguard when the preferred control cannot
        be implemented.

Examples:

    Multi-factor authentication       -> Preventive
    Intrusion detection                -> Detective
    Backup restoration                 -> Corrective
    Security policy and sanctions     -> Deterrent
    Manual review when automation fails -> Compensating

Controls may also be:

    Administrative
    Technical
    Physical

A single control rarely eliminates all risk.
"""
)


@dataclass
class Control:
    control_id: str
    name: str
    control_type: str
    effectiveness: float
    cost: float
    reduces_likelihood: bool
    reduces_impact: bool

    def __post_init__(self) -> None:
        if not 0 <= self.effectiveness <= 1:
            raise ValueError("Effectiveness must be between 0 and 1.")
        if self.cost < 0:
            raise ValueError("Cost cannot be negative.")


controls = [
    Control(
        "C001",
        "Multi-Factor Authentication",
        "Preventive / Technical",
        0.70,
        25_000,
        True,
        False,
    ),
    Control(
        "C002",
        "Immutable Backups",
        "Corrective / Technical",
        0.80,
        40_000,
        False,
        True,
    ),
    Control(
        "C003",
        "Continuous Monitoring",
        "Detective / Technical",
        0.60,
        30_000,
        True,
        True,
    ),
    Control(
        "C004",
        "Security Awareness Training",
        "Preventive / Administrative",
        0.40,
        15_000,
        True,
        False,
    ),
]

for control in controls:
    print(
        f"{control.control_id}: {control.name} | "
        f"type={control.control_type} | "
        f"effectiveness={control.effectiveness:.0%}"
    )


# =============================================================================
# 9. INHERENT AND RESIDUAL RISK
# =============================================================================

print_section("9. Residual Risk")

print(
    """
Inherent risk:
    Risk before controls.

Residual risk:
    Risk after controls.

A simple teaching model can reduce likelihood or impact according to control
effectiveness. Real organizations should define a consistent methodology
rather than blindly applying percentages.

For example:

    Inherent likelihood = 4
    Control effectiveness = 50%

    Adjusted likelihood = 4 × (1 - 0.50) = 2

Because likelihood scales are ordinal in many risk matrices, rounding and
interpretation require governance.
"""
)


def residual_value(
    inherent_likelihood: int,
    inherent_impact: int,
    control_effectiveness: float,
    reduces_likelihood: bool = True,
    reduces_impact: bool = False,
) -> Tuple[int, int, int]:
    """
    Teaching model for deriving residual risk.

    This is intentionally transparent rather than pretending that risk
    reduction is scientifically exact.
    """
    if not 1 <= inherent_likelihood <= 5:
        raise ValueError("Likelihood must be 1..5.")
    if not 1 <= inherent_impact <= 5:
        raise ValueError("Impact must be 1..5.")
    if not 0 <= control_effectiveness <= 1:
        raise ValueError("Effectiveness must be 0..1.")

    likelihood = inherent_likelihood
    impact = inherent_impact

    if reduces_likelihood:
        likelihood = max(
            1,
            round(inherent_likelihood * (1 - control_effectiveness)),
        )

    if reduces_impact:
        impact = max(
            1,
            round(inherent_impact * (1 - control_effectiveness)),
        )

    score = likelihood * impact
    return likelihood, impact, score


for control in controls:
    likelihood, impact, score = residual_value(
        4,
        5,
        control.effectiveness,
        control.reduces_likelihood,
        control.reduces_impact,
    )

    print(
        f"{control.name:30} -> "
        f"L={likelihood}, I={impact}, "
        f"residual score={score}, "
        f"rating={classify_basic_risk(score)}"
    )


# =============================================================================
# 10. RISK TREATMENT OPTIONS
# =============================================================================

print_section("10. Risk Treatment")

print(
    """
Four classic risk treatment strategies are:

    Avoid
        Stop the activity that creates the risk.

    Reduce / Mitigate
        Implement controls to lower likelihood or impact.

    Transfer / Share
        Shift some financial or operational consequences to another party,
        such as through insurance or contractual arrangements.

    Accept
        Consciously retain the risk within defined tolerance.

Risk treatment should be based on the organization's risk appetite, legal and
regulatory obligations, cost, feasibility, strategic objectives, and residual
risk.

Acceptance should be explicit rather than accidental.
"""
)


class TreatmentStrategy(Enum):
    AVOID = "Avoid"
    REDUCE = "Reduce"
    TRANSFER = "Transfer"
    ACCEPT = "Accept"


@dataclass
class TreatmentPlan:
    strategy: TreatmentStrategy
    description: str
    implementation_cost: float
    expected_reduction: float
    owner: str

    def cost_effectiveness(self) -> float:
        if self.implementation_cost == 0:
            return float("inf")
        return self.expected_reduction / self.implementation_cost


treatment_plans = [
    TreatmentPlan(
        TreatmentStrategy.REDUCE,
        "Deploy MFA for privileged and remote access.",
        25_000,
        0.70,
        "Security Manager",
    ),
    TreatmentPlan(
        TreatmentStrategy.REDUCE,
        "Implement immutable offline backups.",
        40_000,
        0.80,
        "Infrastructure Manager",
    ),
    TreatmentPlan(
        TreatmentStrategy.TRANSFER,
        "Use contractual SLA and cyber insurance mechanisms.",
        20_000,
        0.30,
        "Risk Manager",
    ),
    TreatmentPlan(
        TreatmentStrategy.ACCEPT,
        "Accept low-value residual operational risk.",
        0,
        0,
        "Business Owner",
    ),
]

for plan in treatment_plans:
    print(
        f"{plan.strategy.value:8} | "
        f"cost=${plan.implementation_cost:,.0f} | "
        f"reduction={plan.expected_reduction:.0%} | "
        f"owner={plan.owner}"
    )


# =============================================================================
# 11. RISK APPETITE AND TOLERANCE
# =============================================================================

print_section("11. Risk Appetite and Risk Tolerance")

print(
    """
Risk appetite:
    Broad amount and type of risk an organization is willing to pursue or
    retain while achieving its objectives.

Risk tolerance:
    More specific acceptable boundary for variation or exposure.

Example:

    Strategic appetite:
        Moderate technology risk may be accepted to enable innovation.

    Tolerance:
        A critical production service may have a maximum tolerable outage of
        two hours.

A risk can be strategically acceptable while a particular exposure exceeds
its operational tolerance.
"""
)


@dataclass
class RiskThreshold:
    name: str
    maximum_score: int
    description: str

    def is_within_tolerance(self, score: int) -> bool:
        return score <= self.maximum_score


threshold = RiskThreshold(
    "Standard technology risk",
    9,
    "Scores above 9 require additional management attention.",
)

for risk in risk_events:
    status = (
        "Within tolerance"
        if threshold.is_within_tolerance(risk.inherent_score)
        else "Outside tolerance"
    )
    print(f"{risk.risk_id}: {risk.inherent_score:2} -> {status}")


# =============================================================================
# 12. RISK REGISTER
# =============================================================================

print_section("12. Spreadsheet-Style Risk Register")

print(
    """
A risk register commonly contains fields such as:

    Risk ID
    Risk statement
    Asset
    Threat
    Vulnerability
    Owner
    Likelihood
    Impact
    Inherent score
    Existing controls
    Treatment
    Residual likelihood
    Residual impact
    Residual score
    Status
    Review date

The same structure can be represented in a spreadsheet, database, or Python
data model.
"""
)


@dataclass
class RiskRegisterEntry:
    risk: RiskEvent
    owner: str
    controls: List[str] = field(default_factory=list)
    treatment: TreatmentStrategy = TreatmentStrategy.REDUCE
    residual_likelihood: Optional[int] = None
    residual_impact: Optional[int] = None
    status: str = "Open"

    @property
    def residual_score(self) -> Optional[int]:
        if self.residual_likelihood is None or self.residual_impact is None:
            return None
        return self.residual_likelihood * self.residual_impact

    def to_row(self) -> Dict[str, object]:
        return {
            "Risk ID": self.risk.risk_id,
            "Risk": self.risk.title,
            "Owner": self.owner,
            "Likelihood": self.risk.likelihood,
            "Impact": self.risk.impact,
            "Inherent Score": self.risk.inherent_score,
            "Inherent Rating": self.risk.inherent_rating,
            "Controls": ", ".join(self.controls),
            "Treatment": self.treatment.value,
            "Residual Likelihood": self.residual_likelihood,
            "Residual Impact": self.residual_impact,
            "Residual Score": self.residual_score,
            "Status": self.status,
        }


register = [
    RiskRegisterEntry(
        risk_events[0],
        "Chief Information Security Officer",
        ["C001", "C003"],
        TreatmentStrategy.REDUCE,
        2,
        5,
        "Treatment in progress",
    ),
    RiskRegisterEntry(
        risk_events[1],
        "Infrastructure Manager",
        ["C002", "C003"],
        TreatmentStrategy.REDUCE,
        2,
        3,
        "Open",
    ),
    RiskRegisterEntry(
        risk_events[2],
        "Technology Director",
        ["C003"],
        TreatmentStrategy.TRANSFER,
        2,
        5,
        "Open",
    ),
    RiskRegisterEntry(
        risk_events[3],
        "Data Protection Owner",
        ["C004"],
        TreatmentStrategy.REDUCE,
        2,
        4,
        "Open",
    ),
]

headers = [
    "Risk ID",
    "Inherent",
    "Residual",
    "Owner",
    "Treatment",
    "Status",
]

print(
    f"{headers[0]:8} | {headers[1]:9} | {headers[2]:9} | "
    f"{headers[3]:28} | {headers[4]:9} | {headers[5]}"
)

for entry in register:
    residual = (
        str(entry.residual_score)
        if entry.residual_score is not None
        else "N/A"
    )
    print(
        f"{entry.risk.risk_id:8} | "
        f"{entry.risk.inherent_score:9} | "
        f"{residual:9} | "
        f"{entry.owner:28} | "
        f"{entry.treatment.value:9} | "
        f"{entry.status}"
    )


# =============================================================================
# 13. RISK PRIORITIZATION
# =============================================================================

print_section("13. Prioritizing Multiple Risks")

print(
    """
When many risks exist, organizations need a repeatable prioritization method.

A basic method is descending risk score.

A stronger prioritization model may include:

    Risk score
    Asset criticality
    Regulatory impact
    Financial exposure
    Customer impact
    Risk velocity
    Control maturity
    Strategic importance
    Uncertainty
"""
)


def priority_score(entry: RiskRegisterEntry) -> float:
    """Example multi-factor prioritization model."""
    asset = next(
        asset for asset in assets if asset.asset_id == entry.risk.asset_id
    )

    regulatory_factor = 1.20 if entry.risk.asset_id == "A001" else 1.00
    criticality_factor = 0.80 + asset.business_value / 5 * 0.40

    return (
        entry.risk.inherent_score
        * regulatory_factor
        * criticality_factor
    )


ranked_register = sorted(register, key=priority_score, reverse=True)

for rank, entry in enumerate(ranked_register, start=1):
    print(
        f"{rank}. {entry.risk.risk_id} | "
        f"priority={priority_score(entry):.2f} | "
        f"{entry.risk.title}"
    )


# =============================================================================
# 14. RISK VELOCITY
# =============================================================================

print_section("14. Risk Velocity")

print(
    """
Risk velocity describes how quickly an event can create consequences.

Two risks with the same score may deserve different treatment:

    Risk A:
        Likelihood 4, impact 4, consequence develops over months.

    Risk B:
        Likelihood 4, impact 4, consequence develops within minutes.

Risk B may require stronger preventive and detective controls because response
time is limited.
"""
)


@dataclass
class VelocityProfile:
    detection_time_hours: float
    impact_time_hours: float

    @property
    def velocity_factor(self) -> float:
        if self.impact_time_hours <= 0:
            raise ValueError("Impact time must be positive.")

        ratio = self.detection_time_hours / self.impact_time_hours
        return max(0.5, min(2.0, 1 + ratio))


velocity_examples = [
    ("Credential theft", VelocityProfile(12, 24)),
    ("Ransomware", VelocityProfile(2, 1)),
    ("Long-term supplier deterioration", VelocityProfile(720, 2160)),
]

for name, profile in velocity_examples:
    print(
        f"{name:35} velocity factor={profile.velocity_factor:.2f}"
    )


# =============================================================================
# 15. RISK INTERDEPENDENCY
# =============================================================================

print_section("15. Risk Interdependencies")

print(
    """
Risks are often correlated.

Example:

    Cloud outage
        ↓
    Payment API unavailable
        ↓
    Revenue interruption
        ↓
    Customer dissatisfaction
        ↓
    Reputational damage

Treating each risk as independent can underestimate systemic exposure.

A dependency graph can be represented using an adjacency dictionary.
"""
)


risk_dependencies: Dict[str, List[str]] = {
    "R003": ["R005", "R006"],
    "R005": ["R007"],
    "R006": ["R007"],
    "R001": ["R008"],
}


def show_dependencies(graph: Dict[str, List[str]]) -> None:
    for risk_id, dependencies in graph.items():
        print(f"{risk_id} -> {', '.join(dependencies)}")


show_dependencies(risk_dependencies)


# =============================================================================
# 16. NIST CYBERSECURITY FRAMEWORK
# =============================================================================

print_section("16. NIST Cybersecurity Framework")

print(
    """
The NIST Cybersecurity Framework 2.0 organizes cybersecurity outcomes into
six Functions:

    GOVERN
        Establish and monitor cybersecurity risk management strategy,
        expectations, policies, roles, and oversight.

    IDENTIFY
        Understand assets, risks, threats, vulnerabilities, and dependencies.

    PROTECT
        Implement safeguards to reduce cybersecurity risk.

    DETECT
        Identify possible cybersecurity attacks and compromises.

    RESPOND
        Take action regarding detected cybersecurity incidents.

    RECOVER
        Restore assets and operations affected by cybersecurity incidents.

Risk management connects strongly with all six Functions.

Example:

    Asset inventory       -> IDENTIFY
    MFA                   -> PROTECT
    Monitoring            -> DETECT
    Incident playbook     -> RESPOND
    Backup restoration    -> RECOVER
    Governance policy     -> GOVERN
"""
)


class NISTFunction(Enum):
    GOVERN = "Govern"
    IDENTIFY = "Identify"
    PROTECT = "Protect"
    DETECT = "Detect"
    RESPOND = "Respond"
    RECOVER = "Recover"


nist_examples = {
    NISTFunction.GOVERN: "Define cybersecurity risk governance and accountability.",
    NISTFunction.IDENTIFY: "Maintain asset and risk inventories.",
    NISTFunction.PROTECT: "Implement access control and protective safeguards.",
    NISTFunction.DETECT: "Monitor systems and identify suspicious activity.",
    NISTFunction.RESPOND: "Contain and communicate during incidents.",
    NISTFunction.RECOVER: "Restore affected services and improve resilience.",
}

for function, example in nist_examples.items():
    print(f"{function.value:8} -> {example}")


# =============================================================================
# 17. RISK ASSESSMENT WORKFLOW
# =============================================================================

print_section("17. Complete Risk Assessment Workflow")

print(
    """
A practical workflow is:

    1. Establish context.
    2. Identify assets.
    3. Identify threats.
    4. Identify vulnerabilities.
    5. Describe risk events.
    6. Estimate likelihood.
    7. Estimate impact.
    8. Determine inherent risk.
    9. Identify existing controls.
    10. Estimate control effectiveness.
    11. Determine residual risk.
    12. Compare with appetite and tolerance.
    13. Select treatment.
    14. Assign ownership.
    15. Define deadlines and measures.
    16. Monitor and review.
    17. Reassess when conditions change.

Risk management is therefore a continuous process rather than a one-time
worksheet exercise.
"""
)


def assess_risk(
    likelihood: int,
    impact: int,
    control_effectiveness: float,
) -> Dict[str, object]:
    inherent = likelihood * impact

    residual_likelihood = max(
        1,
        round(likelihood * (1 - control_effectiveness)),
    )
    residual = residual_likelihood * impact

    return {
        "inherent_score": inherent,
        "inherent_rating": classify_basic_risk(inherent),
        "residual_likelihood": residual_likelihood,
        "residual_impact": impact,
        "residual_score": residual,
        "residual_rating": classify_basic_risk(residual),
    }


assessment = assess_risk(4, 5, 0.60)
for key, value in assessment.items():
    print(f"{key:22}: {value}")


# =============================================================================
# 18. CONTROL EFFECTIVENESS AND MATURITY
# =============================================================================

print_section("18. Control Effectiveness")

print(
    """
A control should not be considered effective merely because a policy exists.

Useful dimensions include:

    Design effectiveness:
        Is the control designed to address the intended risk?

    Operating effectiveness:
        Does the control actually operate as intended?

    Coverage:
        How much of the relevant population is protected?

    Consistency:
        Does it operate reliably over time?

    Evidence:
        Can operation be demonstrated?

Example:

    A password policy may exist.
    Yet if privileged accounts are exempt, enforcement may be incomplete.

Control maturity can be represented as:

    1 = Ad hoc
    2 = Developing
    3 = Defined
    4 = Managed
    5 = Optimized

Maturity and effectiveness are related but are not identical concepts.
"""
)


@dataclass
class ControlAssessment:
    control: Control
    design_effectiveness: float
    operating_effectiveness: float
    coverage: float

    @property
    def effective_strength(self) -> float:
        return (
            self.design_effectiveness
            * self.operating_effectiveness
            * self.coverage
        )


control_assessments = [
    ControlAssessment(controls[0], 0.90, 0.85, 0.95),
    ControlAssessment(controls[1], 0.95, 0.90, 0.90),
    ControlAssessment(controls[2], 0.85, 0.70, 0.90),
]

for assessment_item in control_assessments:
    print(
        f"{assessment_item.control.name:30} "
        f"effective strength={assessment_item.effective_strength:.2%}"
    )


# =============================================================================
# 19. KEY RISK INDICATORS
# =============================================================================

print_section("19. Key Risk Indicators")

print(
    """
A Key Risk Indicator (KRI) is a measurable signal associated with increasing
or decreasing risk exposure.

Examples:

    Number of critical vulnerabilities
    Percentage of systems without MFA
    Failed backup jobs
    Security incidents
    Third-party service outages
    Privileged accounts
    Employee turnover in critical roles
    Policy exceptions
    Mean time to detect
    Mean time to respond

A KRI becomes useful when thresholds trigger defined management action.
"""
)


@dataclass
class KRI:
    name: str
    current_value: float
    threshold: float
    direction: str = "higher_is_worse"

    def status(self) -> str:
        if self.direction == "higher_is_worse":
            return "RED" if self.current_value > self.threshold else "GREEN"

        if self.direction == "lower_is_worse":
            return "RED" if self.current_value < self.threshold else "GREEN"

        raise ValueError("Unsupported direction.")


kris = [
    KRI("Critical vulnerabilities", 12, 10),
    KRI("Systems without MFA (%)", 4, 5, "higher_is_worse"),
    KRI("Failed backup jobs (%)", 1, 2, "higher_is_worse"),
    KRI("Mean time to detect (hours)", 3, 4, "higher_is_worse"),
]

for kri in kris:
    print(
        f"{kri.name:32} "
        f"value={kri.current_value:>5} "
        f"threshold={kri.threshold:>5} "
        f"status={kri.status()}"
    )


# =============================================================================
# 20. SCENARIO ANALYSIS
# =============================================================================

print_section("20. Scenario Analysis")

print(
    """
Scenario analysis evaluates plausible situations rather than relying on a
single expected outcome.

Example scenarios:

    Best case
    Expected case
    Severe case
    Extreme but plausible case

A scenario can combine:

    Probability
    Operational duration
    Financial loss
    Customer impact
    Regulatory exposure
    Recovery time
"""
)


@dataclass
class Scenario:
    name: str
    probability: float
    financial_loss: float
    downtime_hours: float

    @property
    def expected_loss(self) -> float:
        return self.probability * self.financial_loss


scenarios = [
    Scenario("Minor incident", 0.40, 20_000, 2),
    Scenario("Material incident", 0.15, 150_000, 12),
    Scenario("Severe incident", 0.05, 1_000_000, 72),
]

for scenario in scenarios:
    print(
        f"{scenario.name:20} "
        f"expected loss=${scenario.expected_loss:,.0f} "
        f"downtime={scenario.downtime_hours:g}h"
    )


# =============================================================================
# 21. MONTE CARLO SIMULATION
# =============================================================================

print_section("21. Monte Carlo Risk Simulation")

print(
    """
A deterministic estimate might say:

    Probability = 10%
    Loss = $500,000
    Expected loss = $50,000

A real loss may vary greatly.

Monte Carlo simulation repeatedly samples possible outcomes from assumed
distributions. It can estimate:

    Mean loss
    Median loss
    Percentiles
    Probability of exceeding a threshold

This is useful when uncertainty is material.

The simulation below uses a triangular distribution because it can represent
minimum, most-likely, and maximum loss assumptions without external packages.
"""
)


def triangular_sample(
    rng: Random,
    minimum: float,
    mode: float,
    maximum: float,
) -> float:
    """Sample from a triangular distribution."""
    if not minimum <= mode <= maximum:
        raise ValueError("Require minimum <= mode <= maximum.")

    if minimum == maximum:
        return minimum

    u = rng.random()
    split = (mode - minimum) / (maximum - minimum)

    if u < split:
        return minimum + (
            ((u * (maximum - minimum) * (mode - minimum)) ** 0.5)
        )

    return maximum - (
        (((1 - u) * (maximum - minimum) * (maximum - mode)) ** 0.5)
    )


def monte_carlo_loss(
    simulations: int,
    probability_of_event: float,
    minimum_loss: float,
    most_likely_loss: float,
    maximum_loss: float,
    seed: int = 42,
) -> List[float]:
    if simulations <= 0:
        raise ValueError("Simulations must be positive.")

    if not 0 <= probability_of_event <= 1:
        raise ValueError("Probability must be between 0 and 1.")

    rng = Random(seed)
    results = []

    for _ in range(simulations):
        if rng.random() < probability_of_event:
            loss_value = triangular_sample(
                rng,
                minimum_loss,
                most_likely_loss,
                maximum_loss,
            )
            results.append(loss_value)
        else:
            results.append(0.0)

    return results


losses = monte_carlo_loss(
    simulations=10_000,
    probability_of_event=0.10,
    minimum_loss=50_000,
    most_likely_loss=300_000,
    maximum_loss=1_500_000,
)

loss_percentiles = quantiles(losses, n=100)

print(f"Mean simulated annual loss: ${mean(losses):,.2f}")
print(f"Median simulated annual loss: ${median(losses):,.2f}")
print(f"95th percentile loss: ${loss_percentiles[94]:,.2f}")
print(f"99th percentile loss: ${loss_percentiles[98]:,.2f}")


# =============================================================================
# 22. RISK CAPACITY AND COST-BENEFIT ANALYSIS
# =============================================================================

print_section("22. Treatment Cost-Benefit Analysis")

print(
    """
Risk treatment has a cost.

A treatment decision can compare:

    Cost of control
        versus
    Expected reduction in loss

Suppose:

    Expected annual loss before treatment = $200,000
    Expected annual loss after treatment  = $80,000
    Treatment cost                       = $50,000

Expected annual benefit:

    $200,000 - $80,000 = $120,000

Simple net benefit:

    $120,000 - $50,000 = $70,000

This is not sufficient by itself. Compliance requirements, safety obligations,
reputation, contractual obligations, and catastrophic downside can justify
controls even when simple financial return is unattractive.
"""
)


def treatment_net_benefit(
    expected_loss_before: float,
    expected_loss_after: float,
    treatment_cost: float,
) -> float:
    if min(
        expected_loss_before,
        expected_loss_after,
        treatment_cost,
    ) < 0:
        raise ValueError("Financial values cannot be negative.")

    return (
        expected_loss_before
        - expected_loss_after
        - treatment_cost
    )


net_benefit = treatment_net_benefit(200_000, 80_000, 50_000)
print(f"Estimated treatment net benefit: ${net_benefit:,.2f}")


# =============================================================================
# 23. RISK ACCEPTANCE
# =============================================================================

print_section("23. Risk Acceptance")

print(
    """
Risk acceptance should answer:

    What risk is being accepted?
    What is the residual exposure?
    Who has authority to accept it?
    Why is acceptance reasonable?
    How long is acceptance valid?
    What conditions invalidate acceptance?
    When will the risk be reviewed?

A useful distinction:

    Unmanaged risk:
        Nobody consciously owns or evaluates it.

    Accepted risk:
        An authorized decision-maker knowingly accepts the exposure.

These are not equivalent.
"""
)


@dataclass
class RiskAcceptance:
    risk_id: str
    residual_score: int
    accepted_by: str
    rationale: str
    expiry_days: int

    def is_valid(self) -> bool:
        return self.expiry_days > 0


acceptance = RiskAcceptance(
    "R004",
    8,
    "Business Owner",
    "Residual exposure is within approved tolerance while remediation is planned.",
    90,
)

print(
    f"Risk {acceptance.risk_id} accepted by {acceptance.accepted_by}; "
    f"valid={acceptance.is_valid()}"
)


# =============================================================================
# 24. THIRD-PARTY AND SUPPLY-CHAIN RISK
# =============================================================================

print_section("24. Third-Party Risk")

print(
    """
Third-party risk occurs when another organization can affect your assets,
services, customers, compliance obligations, or reputation.

Assessment areas can include:

    Criticality of supplier
    Data access
    System connectivity
    Geographic concentration
    Financial stability
    Security controls
    Incident notification
    Recovery capability
    Contractual obligations
    Subcontractors
    Exit strategy

A supplier's risk should be connected to the business service it supports.
"""
)


@dataclass
class ThirdParty:
    name: str
    service: str
    criticality: int
    data_access: int
    dependency: int
    control_maturity: int

    @property
    def exposure_score(self) -> float:
        return (
            self.criticality
            * self.data_access
            * self.dependency
            / self.control_maturity
        )


third_parties = [
    ThirdParty("Cloud Provider", "Production Hosting", 5, 5, 5, 4),
    ThirdParty("Email Provider", "Corporate Email", 4, 4, 4, 4),
    ThirdParty("Office Supplier", "Office Supplies", 1, 1, 1, 3),
]

for supplier in third_parties:
    print(
        f"{supplier.name:20} exposure={supplier.exposure_score:.2f}"
    )


# =============================================================================
# 25. BUSINESS CONTINUITY AND RESILIENCE
# =============================================================================

print_section("25. Business Continuity and Resilience")

print(
    """
Risk management connects directly with business continuity.

Important terms:

    Business Impact Analysis (BIA):
        Identifies consequences of disruption and recovery requirements.

    Recovery Time Objective (RTO):
        Target maximum time to restore a service.

    Recovery Point Objective (RPO):
        Target maximum amount of data loss measured in time.

Example:

    RTO = 4 hours
    RPO = 15 minutes

This means the service should be restored within four hours and data recovery
should target a point no more than approximately fifteen minutes behind the
disruption, subject to the organization's actual architecture and procedures.
"""
)


@dataclass
class RecoveryRequirement:
    service: str
    rto_hours: float
    rpo_minutes: float

    def validate(self) -> None:
        if self.rto_hours <= 0:
            raise ValueError("RTO must be positive.")
        if self.rpo_minutes < 0:
            raise ValueError("RPO cannot be negative.")


recovery_requirements = [
    RecoveryRequirement("Payment Processing", 2, 5),
    RecoveryRequirement("Customer Portal", 4, 30),
    RecoveryRequirement("Internal Reporting", 24, 240),
]

for requirement in recovery_requirements:
    requirement.validate()
    print(
        f"{requirement.service:25} "
        f"RTO={requirement.rto_hours:g}h "
        f"RPO={requirement.rpo_minutes:g}m"
    )


# =============================================================================
# 26. INCIDENT RISK VS CHRONIC RISK
# =============================================================================

print_section("26. Different Risk Patterns")

print(
    """
Acute risk:
    A relatively sudden event such as ransomware or a major outage.

Chronic risk:
    Persistent exposure such as excessive privilege, technical debt, or
    recurring control exceptions.

Both require management, but the treatment may differ.

Acute risks often emphasize:

    Detection
    Response
    Containment
    Recovery

Chronic risks often emphasize:

    Governance
    Root-cause correction
    Process redesign
    Architecture improvement
    Continuous monitoring
"""
)


# =============================================================================
# 27. ROOT-CAUSE THINKING
# =============================================================================

print_section("27. Root Cause Analysis")

print(
    """
Treating symptoms can leave the underlying risk unchanged.

Example:

    Incident:
        Sensitive file was publicly accessible.

    Immediate cause:
        Incorrect cloud storage permission.

    Contributing cause:
        No automated configuration scanning.

    Root organizational cause:
        Infrastructure changes lacked a consistent security review process.

Treatment should address causes at an appropriate level.
"""
)


def five_whys(problem: str, causes: Sequence[str]) -> None:
    print(f"Problem: {problem}")
    for index, cause in enumerate(causes, start=1):
        print(f"Why {index}: {cause}")


five_whys(
    "Sensitive cloud data became publicly accessible.",
    [
        "The storage permission was configured incorrectly.",
        "The configuration was not automatically validated.",
        "Security checks were not integrated into deployment.",
        "Ownership for cloud security validation was unclear.",
        "Governance did not define a mandatory control gate.",
    ],
)


# =============================================================================
# 28. RISK SCORING EDGE CASES
# =============================================================================

print_section("28. Edge Cases and Common Scoring Problems")

print(
    """
Important edge cases include:

    1. Zero likelihood:
       Some methodologies permit zero; others use a minimum value of one.
       The scale must define this explicitly.

    2. Unknown likelihood:
       Unknown is not the same as zero.

    3. Unknown impact:
       Missing information should not automatically produce a low score.

    4. Catastrophic low-probability events:
       A multiplication model can understate the management importance of
       extreme scenarios.

    5. Correlated risks:
       Adding individual scores may double-count or undercount exposure.

    6. Control optimism:
       Claimed controls may not actually operate effectively.

    7. Changing conditions:
       Risk assessments become stale when systems, suppliers, regulations,
       threats, or business processes change.
"""
)


def validate_risk_inputs(
    likelihood: Optional[int],
    impact: Optional[int],
) -> None:
    if likelihood is None:
        raise ValueError("Unknown likelihood requires explicit handling.")

    if impact is None:
        raise ValueError("Unknown impact requires explicit handling.")

    if not 1 <= likelihood <= 5:
        raise ValueError("Likelihood must be 1..5.")

    if not 1 <= impact <= 5:
        raise ValueError("Impact must be 1..5.")


try:
    validate_risk_inputs(None, 5)
except ValueError as error:
    print(f"Handled edge case: {error}")


# =============================================================================
# 29. DATA VALIDATION
# =============================================================================

print_section("29. Validation and Data Quality")

print(
    """
A risk register is only as useful as its data.

Validation should check:

    Required fields
    Valid scales
    Valid ownership
    Consistent ratings
    Duplicate IDs
    Missing treatment plans
    Missing review dates
    Invalid residual scores
    Inconsistent control references
"""
)


def validate_register(entries: Sequence[RiskRegisterEntry]) -> List[str]:
    errors: List[str] = []
    seen_ids = set()

    for entry in entries:
        risk_id = entry.risk.risk_id

        if risk_id in seen_ids:
            errors.append(f"Duplicate risk ID: {risk_id}")
        seen_ids.add(risk_id)

        if not entry.owner.strip():
            errors.append(f"{risk_id}: missing owner")

        if not entry.controls and entry.treatment == TreatmentStrategy.REDUCE:
            errors.append(f"{risk_id}: mitigation selected without controls")

        if entry.residual_likelihood is not None:
            if not 1 <= entry.residual_likelihood <= 5:
                errors.append(f"{risk_id}: invalid residual likelihood")

        if entry.residual_impact is not None:
            if not 1 <= entry.residual_impact <= 5:
                errors.append(f"{risk_id}: invalid residual impact")

    return errors


validation_errors = validate_register(register)

if validation_errors:
    for error in validation_errors:
        print("ERROR:", error)
else:
    print("Risk register validation passed.")


# =============================================================================
# 30. TESTING RISK FUNCTIONS
# =============================================================================

print_section("30. Basic Testing")

print(
    """
Risk-management software should itself be tested.

Tests should include:

    Valid inputs
    Boundary values
    Invalid values
    Missing values
    Duplicate identifiers
    Control calculations
    Classification logic
    Sorting and prioritization
    Exported records

The assertions below provide lightweight executable tests.
"""
)


def run_tests() -> None:
    assert basic_risk_score(1, 1) == 1
    assert basic_risk_score(5, 5) == 25

    assert classify_basic_risk(1) == "Low"
    assert classify_basic_risk(4) == "Low"
    assert classify_basic_risk(5) == "Moderate"
    assert classify_basic_risk(9) == "Moderate"
    assert classify_basic_risk(10) == "High"
    assert classify_basic_risk(16) == "High"
    assert classify_basic_risk(17) == "Critical"
    assert classify_basic_risk(25) == "Critical"

    try:
        basic_risk_score(0, 3)
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid likelihood should fail.")

    try:
        basic_risk_score(3, 6)
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid impact should fail.")

    assert expected_annual_loss(0.1, 100_000) == 10_000

    print("All built-in tests passed.")


run_tests()


# =============================================================================
# 31. SECURITY CONSIDERATIONS FOR RISK REGISTER SOFTWARE
# =============================================================================

print_section("31. Security Considerations")

print(
    """
A risk register can itself contain sensitive information.

It may reveal:

    Critical assets
    Vulnerabilities
    Security weaknesses
    Incident information
    Supplier weaknesses
    Regulatory concerns
    Business continuity gaps

Therefore, risk-management systems should consider:

    Access control
    Least privilege
    Authentication
    Encryption
    Audit logging
    Secure backups
    Data retention
    Change control
    Segregation of duties
    Secure exports
    Protection against unauthorized modification

A spreadsheet is not automatically insecure, but spreadsheet-based risk
management requires deliberate access and version-control practices.
"""
)


# =============================================================================
# 32. LEAST PRIVILEGE EXAMPLE
# =============================================================================

print_section("32. Least Privilege Example")

print(
    """
Least privilege means giving a person or system only the access required for
their legitimate responsibilities.

The example models permissions as sets and calculates excessive permissions.
"""
)


role_permissions = {
    "Analyst": {"read_reports", "read_customer_data"},
    "Developer": {"read_code", "write_code", "read_logs"},
    "Administrator": {
        "read_code",
        "write_code",
        "read_logs",
        "modify_identity",
        "modify_security_policy",
    },
}

required_permissions = {
    "Analyst": {"read_reports"},
    "Developer": {"read_code", "write_code", "read_logs"},
    "Administrator": {
        "read_code",
        "write_code",
        "read_logs",
        "modify_identity",
    },
}

for role, assigned in role_permissions.items():
    required = required_permissions[role]
    excessive = assigned - required

    print(
        f"{role:15} excessive permissions: "
        f"{sorted(excessive) if excessive else 'None'}"
    )


# =============================================================================
# 33. RISK GOVERNANCE
# =============================================================================

print_section("33. Governance and Accountability")

print(
    """
Risk governance establishes who makes decisions and who is accountable.

Typical responsibilities may include:

    Board / governing body:
        Oversight and strategic risk direction.

    Executive leadership:
        Risk appetite, resources, accountability.

    Risk function:
        Methodology, aggregation, reporting, challenge.

    Security function:
        Cybersecurity risk identification and treatment.

    Business owner:
        Ownership of business consequences and acceptance decisions.

    Control owner:
        Operation and evidence of specific controls.

    Internal audit:
        Independent assurance.

A critical distinction is between:

    Control ownership
        Who operates the control?

and

    Risk ownership
        Who is accountable for the risk?
"""
)


@dataclass
class Responsibility:
    role: str
    responsibility: str


responsibilities = [
    Responsibility("Risk Owner", "Owns the risk decision and residual exposure."),
    Responsibility("Control Owner", "Ensures a specific control operates."),
    Responsibility("Risk Function", "Maintains methodology and challenges assessments."),
    Responsibility("Internal Audit", "Provides independent assurance."),
]

for responsibility in responsibilities:
    print(
        f"{responsibility.role:18} -> {responsibility.responsibility}"
    )


# =============================================================================
# 34. RISK AGGREGATION
# =============================================================================

print_section("34. Risk Aggregation")

print(
    """
Organizations often need an enterprise view.

Naively summing risk scores can be misleading because:

    Scores may be ordinal.
    Risks may overlap.
    Risks may be correlated.
    Different business units may use inconsistent scales.

A useful aggregation process considers:

    Common categories
    Shared assets
    Shared controls
    Correlation
    Concentration
    Scenario impacts
    Dependencies
"""
)


risk_scores_by_domain = {
    "Cybersecurity": [20, 15, 12, 8],
    "Operational": [16, 10, 9],
    "Third Party": [18, 12, 6],
    "Compliance": [15, 8, 7],
}

for domain, scores in risk_scores_by_domain.items():
    print(
        f"{domain:15} highest={max(scores):2} "
        f"average={mean(scores):.2f} "
        f"count={len(scores)}"
    )


# =============================================================================
# 35. RISK HEAT MAP DATA
# =============================================================================

print_section("35. Heat Map Data Representation")

print(
    """
A heat map can be generated from structured data. The example keeps the data
representation separate from presentation so the same information can be
used in a spreadsheet, dashboard, database, or report.
"""
)


heat_map = [
    {"likelihood": 1, "impact": 5, "count": 2},
    {"likelihood": 2, "impact": 4, "count": 3},
    {"likelihood": 3, "impact": 4, "count": 5},
    {"likelihood": 4, "impact": 4, "count": 4},
    {"likelihood": 4, "impact": 5, "count": 3},
    {"likelihood": 5, "impact": 5, "count": 1},
]

for cell in heat_map:
    score = cell["likelihood"] * cell["impact"]
    print(
        f"L={cell['likelihood']} I={cell['impact']} "
        f"score={score:2} risks={cell['count']}"
    )


# =============================================================================
# 36. PERFORMANCE CONSIDERATIONS
# =============================================================================

print_section("36. Performance Considerations")

print(
    """
For small risk registers, ordinary Python lists and dictionaries are enough.

For larger systems:

    Use indexed identifiers.
    Avoid repeatedly scanning large collections.
    Normalize data where appropriate.
    Cache frequently used reference data.
    Validate data at ingestion.
    Batch processing operations.
    Use database indexes for large persistent registers.

The demonstration below compares direct dictionary lookup with a repeated
linear search conceptually.
"""
)


asset_by_id = {asset.asset_id: asset for asset in assets}

for risk in risk_events:
    asset = asset_by_id.get(risk.asset_id)

    if asset is None:
        print(f"{risk.risk_id}: asset not found")
    else:
        print(
            f"{risk.risk_id}: asset lookup -> "
            f"{asset.name}"
        )


# =============================================================================
# 37. AUDIT TRAIL
# =============================================================================

print_section("37. Auditability and Change History")

print(
    """
Risk assessments change.

An audit trail should capture:

    What changed?
    Who changed it?
    When did it change?
    Why did it change?
    What was the previous value?
    What is the new value?

This is important for accountability, governance, compliance, and investigation.
"""
)


@dataclass
class AuditEvent:
    timestamp: str
    user: str
    object_id: str
    field: str
    old_value: str
    new_value: str
    reason: str


audit_events = [
    AuditEvent(
        "2026-09-05T10:00:00",
        "risk.manager",
        "R001",
        "likelihood",
        "4",
        "3",
        "MFA deployment completed.",
    ),
    AuditEvent(
        "2026-09-05T10:05:00",
        "risk.manager",
        "R001",
        "status",
        "Open",
        "Treatment in progress",
        "Control implementation started.",
    ),
]

for event in audit_events:
    print(
        f"{event.timestamp} | {event.user} | {event.object_id} | "
        f"{event.field}: {event.old_value} -> {event.new_value} | "
        f"{event.reason}"
    )


# =============================================================================
# 38. COMMON MISTAKES
# =============================================================================

print_section("38. Common Risk Management Mistakes")

print(
    """
1. Treating every risk score as objective fact.
2. Confusing threats with vulnerabilities.
3. Listing vulnerabilities without identifying business consequences.
4. Assigning risks without clear owners.
5. Assuming a policy equals an effective control.
6. Ignoring residual risk.
7. Accepting risk without authorization.
8. Using stale assessments.
9. Ignoring third-party dependencies.
10. Ignoring correlated risks.
11. Focusing only on cybersecurity while ignoring operational risk.
12. Optimizing controls solely for financial return.
13. Using overly precise numerical estimates without reliable evidence.
14. Failing to document assumptions.
15. Treating the risk register as a static spreadsheet rather than a
    management process.
"""
)


# =============================================================================
# 39. INTEGRATED CASE STUDY
# =============================================================================

print_section("39. Integrated Case Study")

print(
    """
Scenario:

A company operates an online payment platform. Its customer database is
highly sensitive, the payment API is business-critical, and several services
are hosted by a cloud provider.

Assessment:

    Asset:
        Customer Database

    Threat:
        Credential Theft

    Vulnerability:
        Weak Authentication

    Risk:
        Stolen credentials enable unauthorized access.

    Consequence:
        Confidentiality breach and regulatory exposure.

    Existing controls:
        MFA and monitoring

    Treatment:
        Reduce risk through stronger authentication, privileged-access
        controls, monitoring, and periodic access reviews.

The code below turns this narrative into a structured assessment.
"""
)


case_asset = assets[0]
case_threat = threats[0]
case_vulnerability = vulnerabilities[0]

case_likelihood = 4
case_impact = case_asset.business_value
case_control_effectiveness = 0.70

case_result = assess_risk(
    case_likelihood,
    case_impact,
    case_control_effectiveness,
)

print(f"Asset: {case_asset.name}")
print(f"Threat: {case_threat.name}")
print(f"Vulnerability: {case_vulnerability.name}")

for key, value in case_result.items():
    print(f"{key:22}: {value}")


# =============================================================================
# 40. ADVANCED RISK SCORING WITH WEIGHTS
# =============================================================================

print_section("40. Weighted Risk Model")

print(
    """
Some organizations use additional dimensions.

For teaching purposes:

    Weighted Score =
        Likelihood ×
        (Financial Weight + Regulatory Weight + Operational Weight)

Weights must be governed carefully. Adding many arbitrary factors can make a
model look sophisticated while reducing transparency.

The safest practice is to document:

    Scale definitions
    Weight definitions
    Data sources
    Assumptions
    Review frequency
"""
)


@dataclass
class WeightedRisk:
    likelihood: float
    financial_impact: float
    regulatory_impact: float
    operational_impact: float

    def score(
        self,
        financial_weight: float,
        regulatory_weight: float,
        operational_weight: float,
    ) -> float:
        return self.likelihood * (
            self.financial_impact * financial_weight
            + self.regulatory_impact * regulatory_weight
            + self.operational_impact * operational_weight
        )


weighted_risk = WeightedRisk(4, 5, 5, 4)

weighted_score = weighted_risk.score(
    financial_weight=0.40,
    regulatory_weight=0.35,
    operational_weight=0.25,
)

print(f"Weighted risk score: {weighted_score:.2f}")


# =============================================================================
# 41. DECISION TREE FOR TREATMENT
# =============================================================================

print_section("41. Treatment Decision Logic")

print(
    """
A basic decision framework:

    Is the risk above tolerance?
        |
        +-- No --> Monitor or accept if authorized.
        |
        +-- Yes
             |
             +-- Can the activity be stopped?
             |      |
             |      +-- Yes --> Consider Avoidance.
             |
             +-- No
                  |
                  +-- Can likelihood or impact be reduced?
                  |      |
                  |      +-- Yes --> Mitigate.
                  |
                  +-- Can exposure be shared?
                         |
                         +-- Yes --> Transfer/share.
                         |
                         +-- No --> Escalate or seek explicit acceptance.
"""
)


def recommend_treatment(
    score: int,
    tolerance: int,
    activity_avoidable: bool,
    mitigatable: bool,
    transferable: bool,
) -> TreatmentStrategy:
    if score <= tolerance:
        return TreatmentStrategy.ACCEPT

    if activity_avoidable:
        return TreatmentStrategy.AVOID

    if mitigatable:
        return TreatmentStrategy.REDUCE

    if transferable:
        return TreatmentStrategy.TRANSFER

    return TreatmentStrategy.ACCEPT


recommendation = recommend_treatment(
    score=20,
    tolerance=9,
    activity_avoidable=False,
    mitigatable=True,
    transferable=True,
)

print(f"Recommended treatment: {recommendation.value}")


# =============================================================================
# 42. RISK COMMUNICATION
# =============================================================================

print_section("42. Risk Communication")

print(
    """
Risk communication should be understandable to its audience.

Technical audience:
    May need vulnerability identifiers, control evidence, attack paths, and
    technical remediation details.

Executive audience:
    Needs business impact, exposure, trend, decision required, cost,
    ownership, and whether appetite or tolerance is exceeded.

Board-level reporting:
    Should emphasize material enterprise exposures, strategic implications,
    concentrations, emerging risks, and management response.

The same underlying risk should not be distorted merely because the audience
changes. The presentation changes; the evidence should remain consistent.
"""
)


def executive_risk_statement(entry: RiskRegisterEntry) -> str:
    residual = entry.residual_score
    residual_text = str(residual) if residual is not None else "not assessed"

    return (
        f"{entry.risk.title} has an inherent risk score of "
        f"{entry.risk.inherent_score} and a residual score of "
        f"{residual_text}. The accountable owner is {entry.owner}. "
        f"Current treatment is {entry.treatment.value}."
    )


for entry in register:
    print(executive_risk_statement(entry))


# =============================================================================
# 43. EMERGING RISK
# =============================================================================

print_section("43. Emerging Risk")

print(
    """
Emerging risks are uncertain risks whose characteristics, probability, or
impact may be changing.

Examples include:

    New technologies
    New attack techniques
    Regulatory changes
    Geopolitical disruptions
    New suppliers
    Business-model changes
    Rapid market changes
    New dependencies

Emerging risk management emphasizes:

    Weak signals
    Scenario analysis
    Monitoring
    Expert judgment
    Assumption tracking
    Trigger conditions
"""
)


@dataclass
class EmergingRisk:
    name: str
    signal_strength: int
    uncertainty: int
    potential_impact: int

    @property
    def attention_score(self) -> int:
        return (
            self.signal_strength
            * self.uncertainty
            * self.potential_impact
        )


emerging_risks = [
    EmergingRisk("New supplier dependency", 3, 4, 5),
    EmergingRisk("New regulatory requirement", 4, 3, 4),
    EmergingRisk("New attack technique", 2, 5, 5),
]

for emerging in emerging_risks:
    print(
        f"{emerging.name:30} "
        f"attention={emerging.attention_score}"
    )


# =============================================================================
# 44. RISK REGISTER EXPORT FORMAT
# =============================================================================

print_section("44. Spreadsheet-Oriented Output")

print(
    """
A spreadsheet-oriented row can be produced as a dictionary. This makes it
straightforward to write the data into CSV or spreadsheet software later.

A real implementation should also preserve:

    Unique identifiers
    Dates
    Version information
    Data validation rules
    Ownership
    Evidence references
    Change history
"""
)


for entry in register:
    row = entry.to_row()

    print(
        " | ".join(
            f"{key}={value}"
            for key, value in row.items()
        )
    )


# =============================================================================
# 45. FINAL INTEGRATED DASHBOARD
# =============================================================================

print_section("45. Risk Dashboard Metrics")

total_risks = len(register)
critical_risks = sum(
    1 for entry in register
    if entry.risk.inherent_rating == "Critical"
)
high_or_above = sum(
    1 for entry in register
    if entry.risk.inherent_score >= 10
)
open_risks = sum(
    1 for entry in register
    if entry.status != "Closed"
)
accepted_risks = sum(
    1 for entry in register
    if entry.treatment == TreatmentStrategy.ACCEPT
)

print(f"Total risks:              {total_risks}")
print(f"Critical inherent risks:  {critical_risks}")
print(f"High or critical risks:   {high_or_above}")
print(f"Open risks:               {open_risks}")
print(f"Accepted-risk entries:    {accepted_risks}")

print(
    """
The dashboard demonstrates an important principle:

Risk management is not just the calculation of a number.

A useful system connects:

    Assets
        ↓
    Threats
        ↓
    Vulnerabilities
        ↓
    Risk events
        ↓
    Likelihood and impact
        ↓
    Inherent risk
        ↓
    Controls
        ↓
    Residual risk
        ↓
    Appetite and tolerance
        ↓
    Treatment decisions
        ↓
    Ownership
        ↓
    Monitoring
        ↓
    Review and reassessment
"""
)


# =============================================================================
# 46. STUDY CHECKLIST
# =============================================================================

print_section("46. Executable Knowledge Checklist")

knowledge_checklist = {
    "Asset identification": True,
    "Threat modeling": True,
    "Vulnerability analysis": True,
    "Likelihood assessment": True,
    "Impact assessment": True,
    "Risk scoring": True,
    "Risk matrices": True,
    "Inherent risk": True,
    "Residual risk": True,
    "Control classification": True,
    "Risk treatment": True,
    "Risk appetite": True,
    "Risk tolerance": True,
    "Risk register": True,
    "NIST CSF Functions": True,
    "Key Risk Indicators": True,
    "Scenario analysis": True,
    "Monte Carlo simulation": True,
    "Third-party risk": True,
    "Business continuity": True,
    "Audit trails": True,
    "Security considerations": True,
    "Validation and testing": True,
}

completed = sum(knowledge_checklist.values())
print(
    f"Covered concepts: {completed}/{len(knowledge_checklist)}"
)


# =============================================================================
# 47. PROGRAM ENTRY POINT
# =============================================================================

def main() -> None:
    """
    The educational examples above execute when the file is run directly.

    Keeping a main function is a useful production practice because it makes
    code easier to import and test without automatically executing the entire
    demonstration.
    """
    print_section("47. Program Execution Complete")
    print(
        "The risk-management study script completed successfully. "
        "All core demonstrations and built-in tests were executed."
    )


if __name__ == "__main__":
    main()
