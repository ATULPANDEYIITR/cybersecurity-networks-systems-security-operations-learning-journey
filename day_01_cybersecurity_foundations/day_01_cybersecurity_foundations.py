"""
CYBERSECURITY FOUNDATIONS
=========================

Topic:
    CIA Triad, Authenticity, Accountability, Non-Repudiation,
    Security Principles, Threat vs Vulnerability vs Risk,
    Attack Surface

Environment:
    Python 3.x
    Kali Linux / Windows
    VS Code

Purpose:
    This program is an interactive cybersecurity foundations course.
    It explains concepts from beginner to advanced level and provides
    safe simulations for understanding security principles.

IMPORTANT:
    This program does NOT perform real attacks, exploitation,
    credential attacks, scanning of external systems, or destructive
    security operations.

Run:
    python cybersecurity_foundations.py
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional
import hashlib
import hmac
import secrets
import time
import textwrap


# ============================================================
# SECTION 1: BASIC UTILITIES
# ============================================================

def title(text: str):
    """Print a formatted section title."""
    print("\n" + "=" * 80)
    print(text.upper())
    print("=" * 80)


def subsection(text: str):
    """Print a formatted subsection."""
    print("\n" + "-" * 70)
    print(text)
    print("-" * 70)


def explain(text: str):
    """Print wrapped explanatory text."""
    print(textwrap.fill(text, width=78))


def pause():
    """Pause between lessons."""
    input("\nPress ENTER to continue...")


# ============================================================
# SECTION 2: SECURITY DEFINITIONS
# ============================================================

def lesson_cybersecurity_basics():
    title("1. What Is Cybersecurity?")

    explain("""
    Cybersecurity is the discipline of protecting information,
    systems, applications, networks, devices, identities, and digital
    services against unauthorized access, modification, destruction,
    disruption, disclosure, and misuse.

    A useful way to think about cybersecurity is:

        Assets
           |
           v
        Threats
           |
           v
    Vulnerabilities
           |
           v
         Risk
           |
           v
       Controls
           |
           v
    Reduced Risk

    Cybersecurity is therefore not simply "using antivirus software."

    It involves:

    - Security architecture
    - Identity and access management
    - Network security
    - Application security
    - Endpoint security
    - Data security
    - Cryptography
    - Security monitoring
    - Incident response
    - Governance
    - Risk management
    - Business continuity
    - Privacy
    - Physical security

    The objective is not to make risk equal to zero.

    The objective is to understand, reduce, transfer, accept, or avoid
    risk according to the organization's requirements.
    """)

    subsection("Core security vocabulary")

    definitions = {
        "Asset":
            "Something valuable that requires protection.",
        "Threat":
            "A potential cause of harm to an asset.",
        "Vulnerability":
            "A weakness that can potentially be exploited.",
        "Risk":
            "The possibility of loss or harm arising from threats exploiting vulnerabilities.",
        "Control":
            "A safeguard designed to prevent, detect, deter, or reduce security risk.",
        "Attack":
            "A deliberate attempt to compromise security.",
        "Incident":
            "A security event or series of events that threatens security.",
        "Exposure":
            "The condition of being susceptible to a threat or loss.",
    }

    for key, value in definitions.items():
        print(f"\n{key}:")
        explain(value)


# ============================================================
# SECTION 3: CIA TRIAD
# ============================================================

def lesson_cia_triad():
    title("2. The CIA Triad")

    explain("""
    The CIA Triad is one of the foundational models of information
    security.

    CIA means:

        C = Confidentiality
        I = Integrity
        A = Availability

    These three properties describe what cybersecurity controls are
    generally trying to preserve.
    """)

    subsection("2.1 Confidentiality")

    explain("""
    Confidentiality means preventing information from being disclosed
    to unauthorized individuals, systems, or processes.

    Example:

        Employee salary information should be accessible only to
        authorized personnel.

    Common confidentiality controls:

        - Authentication
        - Authorization
        - Encryption
        - Access control
        - Data classification
        - Network segmentation
        - Data loss prevention
        - Least privilege

    Confidentiality failure:

        An unauthorized person reads confidential customer records.

    Confidentiality does NOT necessarily mean encryption.

    Encryption is one mechanism for achieving confidentiality.
    """)

    subsection("2.2 Integrity")

    explain("""
    Integrity means ensuring that information remains accurate,
    complete, trustworthy, and protected against unauthorized
    modification.

    Example:

        A bank transaction recorded as:

            Transfer = Rs. 10,000

        should not silently become:

            Transfer = Rs. 1,00,000

    Integrity mechanisms include:

        - Hashes
        - HMACs
        - Digital signatures
        - Database constraints
        - Version control
        - Access controls
        - File permissions
        - Audit logs

    Important distinction:

        A cryptographic hash can help detect modification.

        A hash alone does NOT prove who created the data.
    """)

    subsection("2.3 Availability")

    explain("""
    Availability means authorized users should be able to access
    systems and information when required.

    Examples of availability controls:

        - Redundancy
        - Backups
        - Disaster recovery
        - Failover
        - Load balancing
        - Capacity planning
        - Monitoring
        - DDoS protection
        - Power redundancy

    Availability failure examples:

        - Server outage
        - Ransomware making files inaccessible
        - Hardware failure
        - Network outage
        - Resource exhaustion
    """)

    subsection("CIA trade-offs")

    explain("""
    Security properties can sometimes conflict.

    Example:

        Extremely strict access controls may improve confidentiality
        but reduce availability or usability.

        Extremely aggressive encryption and key management may improve
        confidentiality but increase operational complexity.

    Security engineering is therefore about balancing:

        Security
        Availability
        Usability
        Performance
        Cost
        Compliance
        Business requirements
    """)


# ============================================================
# SECTION 4: CIA SCENARIO ENGINE
# ============================================================

def cia_scenario_engine():
    title("3. CIA Scenario Classification")

    scenarios = [
        (
            "An unauthorized employee reads confidential HR records.",
            "Confidentiality"
        ),
        (
            "An attacker modifies a database record.",
            "Integrity"
        ),
        (
            "A production server becomes unavailable.",
            "Availability"
        ),
        (
            "A backup file is silently modified.",
            "Integrity"
        ),
        (
            "A private API key is leaked publicly.",
            "Confidentiality"
        ),
        (
            "A website is unavailable during business hours.",
            "Availability"
        ),
    ]

    for i, (scenario, answer) in enumerate(scenarios, 1):
        print(f"\nScenario {i}: {scenario}")
        print(f"Primary CIA property affected: {answer}")


# ============================================================
# SECTION 5: AUTHENTICITY
# ============================================================

def lesson_authenticity():
    title("4. Authenticity")

    explain("""
    Authenticity answers a question such as:

        "Is this entity really who or what it claims to be?"

    Authenticity is different from authorization.

    Authentication:
        "Who are you?"

    Authorization:
        "What are you allowed to do?"

    Example:

        Alice logs into a banking application.

        Authentication:
            Is Alice really Alice?

        Authorization:
            Can Alice transfer Rs. 5 lakh?

    A system can correctly authenticate a person and still deny the
    requested action because the person lacks authorization.
    """)

    subsection("Authentication factors")

    factors = [
        "Something you know: password, PIN",
        "Something you have: hardware token, phone",
        "Something you are: biometric",
        "Somewhere you are: location",
        "Something you do: behavioral characteristics"
    ]

    for factor in factors:
        print(" -", factor)

    subsection("Multi-factor authentication")

    explain("""
    Multi-factor authentication combines independent authentication
    factors.

    Example:

        Password + hardware security key

    This is stronger than:

        Password + another password

    because two passwords are still the same factor category.
    """)


# ============================================================
# SECTION 6: ACCOUNTABILITY
# ============================================================

def lesson_accountability():
    title("5. Accountability")

    explain("""
    Accountability means being able to associate actions with the
    responsible identities, systems, or processes.

    A mature security environment should be able to answer:

        Who performed the action?
        What action occurred?
        When did it happen?
        Which system was involved?
        What was the result?
        Was the action authorized?
        What evidence remains?

    Common mechanisms:

        - User identities
        - Audit logs
        - Authentication logs
        - Access logs
        - Database audit trails
        - Endpoint telemetry
        - SIEM systems
        - Change-management records
        - Privileged access management
    """)

    subsection("Accountability example")

    log = {
        "timestamp": "2026-09-01T20:30:00",
        "user": "alice",
        "action": "READ",
        "resource": "customer_database",
        "result": "SUCCESS",
        "source": "application-server-01"
    }

    for key, value in log.items():
        print(f"{key:15}: {value}")

    explain("""
    Notice that the log does not merely say:

        "Someone accessed the database."

    It attempts to associate the action with an identity,
    resource, time, source, action, and result.

    Logs themselves must be protected.

    Otherwise an attacker could modify or delete evidence.
    """)


# ============================================================
# SECTION 7: NON-REPUDIATION
# ============================================================

def lesson_non_repudiation():
    title("6. Non-Repudiation")

    explain("""
    Non-repudiation is the ability to provide evidence supporting the
    origin, integrity, or occurrence of an action or communication,
    making it difficult for a party to credibly deny that action.

    Digital signatures are an important technical mechanism.

    Conceptually:

        Sender
           |
           | private key
           v
       Signature
           |
           v
        Message
           |
           v
        Receiver
           |
           | public key
           v
      Verification

    Important distinction:

        Authentication asks:
            "Who are you?"

        Accountability asks:
            "Can we associate an action with you?"

        Non-repudiation asks:
            "What evidence supports that this action or message
             originated from you?"

    Real-world non-repudiation can also depend on:

        - Key management
        - Certificate infrastructure
        - Secure signing processes
        - Legal frameworks
        - Audit trails
        - Trusted timestamps
        - Organizational controls
    """)


# ============================================================
# SECTION 8: SECURITY PRINCIPLES
# ============================================================

def lesson_security_principles():
    title("7. Core Security Principles")

    principles = {
        "Least Privilege":
            "Give users and processes only the permissions they need.",
        "Need to Know":
            "Provide access to information only when it is necessary.",
        "Defense in Depth":
            "Use multiple independent layers of security.",
        "Fail Secure":
            "When something fails, default to a secure state where practical.",
        "Secure by Design":
            "Build security into architecture rather than adding it later.",
        "Secure by Default":
            "Default configurations should minimize unnecessary exposure.",
        "Separation of Duties":
            "Split sensitive responsibilities across different people or roles.",
        "Complete Mediation":
            "Check authorization whenever access to a protected resource occurs.",
        "Economy of Mechanism":
            "Prefer simple security mechanisms that are easier to understand and verify.",
        "Open Design":
            "Security should not depend on secrecy of the design.",
        "Psychological Acceptability":
            "Security controls should be usable enough that people can follow them.",
        "Zero Trust":
            "Do not automatically trust an entity merely because of its network location.",
        "Minimize Attack Surface":
            "Reduce unnecessary exposed functionality and interfaces.",
    }

    for principle, explanation in principles.items():
        print(f"\n{principle}")
        explain(explanation)


# ============================================================
# SECTION 9: LEAST PRIVILEGE SIMULATION
# ============================================================

@dataclass
class User:
    name: str
    roles: List[str] = field(default_factory=list)


ROLE_PERMISSIONS = {
    "employee": {"read_profile"},
    "manager": {"read_profile", "read_team_reports"},
    "security_admin": {
        "read_profile",
        "read_team_reports",
        "manage_security_logs"
    },
    "database_admin": {
        "read_database",
        "write_database"
    }
}


def get_permissions(user: User):
    permissions = set()

    for role in user.roles:
        permissions.update(ROLE_PERMISSIONS.get(role, set()))

    return permissions


def lesson_least_privilege_simulation():
    title("8. Least Privilege Simulation")

    users = [
        User("Alice", ["employee"]),
        User("Bob", ["manager"]),
        User("Charlie", ["security_admin"]),
        User("David", ["database_admin"])
    ]

    for user in users:
        permissions = get_permissions(user)

        print(f"\nUser: {user.name}")
        print(f"Roles: {user.roles}")
        print("Permissions:")

        for permission in sorted(permissions):
            print("  -", permission)

    explain("""
    The important lesson is that permissions should be derived from
    legitimate business responsibilities.

    Giving every user administrator access is convenient but creates
    enormous security risk.

    Least privilege reduces the potential impact of:

        - Credential theft
        - Malware
        - Insider threats
        - Accidental changes
        - Compromised applications
    """)


# ============================================================
# SECTION 10: THREAT VS VULNERABILITY VS RISK
# ============================================================

def lesson_threat_vulnerability_risk():
    title("9. Threat vs Vulnerability vs Risk")

    explain("""
    These three concepts are frequently confused.

    THREAT
        Something capable of causing harm.

    VULNERABILITY
        A weakness that can be exploited or contribute to harm.

    RISK
        The potential impact arising from a threat interacting with
        a vulnerability.

    Example:

        Threat:
            Attacker

        Vulnerability:
            Weak password

        Asset:
            Corporate email account

        Potential impact:
            Unauthorized access to confidential messages

        Risk:
            Possibility that the weak password is exploited and the
            organization suffers unauthorized access.
    """)

    subsection("A practical model")

    explain("""
    A simplified conceptual model is:

        Risk ≈ Likelihood × Impact

    This is not a universal mathematical law.

    Real risk analysis can involve:

        - Threat likelihood
        - Vulnerability exploitability
        - Asset value
        - Business impact
        - Existing controls
        - Exposure
        - Detection capability
        - Recovery capability
        - Uncertainty

    Therefore, two vulnerabilities with identical technical severity
    can have very different business risks.
    """)


# ============================================================
# SECTION 11: RISK CALCULATION SIMULATOR
# ============================================================

class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def calculate_risk(likelihood: int, impact: int) -> int:
    """
    Simplified educational risk score.

    likelihood: 1-5
    impact: 1-5
    """
    if not (1 <= likelihood <= 5):
        raise ValueError("Likelihood must be between 1 and 5.")

    if not (1 <= impact <= 5):
        raise ValueError("Impact must be between 1 and 5.")

    return likelihood * impact


def risk_level(score: int) -> RiskLevel:
    if score <= 4:
        return RiskLevel.LOW
    elif score <= 9:
        return RiskLevel.MEDIUM
    elif score <= 16:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def lesson_risk_matrix():
    title("10. Educational Risk Matrix")

    print("\nRisk Matrix: Likelihood × Impact\n")

    print("Impact ->       1       2       3       4       5")
    print("Likelihood")

    for likelihood in range(1, 6):
        row = []

        for impact in range(1, 6):
            score = calculate_risk(likelihood, impact)
            row.append(f"{score:2}")

        print(f"{likelihood:^10}   " + "      ".join(row))

    explain("""
    Example:

        Likelihood = 4
        Impact = 5

        Risk score = 4 × 5 = 20

        Educational classification = CRITICAL

    In professional environments, organizations often use more
    sophisticated methodologies and calibrated scoring systems.
    """)


# ============================================================
# SECTION 12: ASSET-THREAT-VULNERABILITY-RISK MODEL
# ============================================================

@dataclass
class SecurityScenario:
    asset: str
    threat: str
    vulnerability: str
    likelihood: int
    impact: int

    @property
    def risk_score(self):
        return calculate_risk(self.likelihood, self.impact)

    @property
    def risk_classification(self):
        return risk_level(self.risk_score).value


def lesson_scenario_model():
    title("11. Complete Risk Scenario")

    scenario = SecurityScenario(
        asset="Customer database",
        threat="Unauthorized user",
        vulnerability="Excessive database permissions",
        likelihood=4,
        impact=5
    )

    print(f"Asset:          {scenario.asset}")
    print(f"Threat:         {scenario.threat}")
    print(f"Vulnerability:  {scenario.vulnerability}")
    print(f"Likelihood:     {scenario.likelihood}")
    print(f"Impact:         {scenario.impact}")
    print(f"Risk score:     {scenario.risk_score}")
    print(f"Risk level:     {scenario.risk_classification}")

    explain("""
    A security team could reduce this risk through controls such as:

        - Least privilege
        - Role-based access control
        - Strong authentication
        - Privileged access management
        - Database activity monitoring
        - Access reviews
        - Logging
        - Network segmentation

    The objective is not simply "fix the vulnerability."

    The organization must reduce the relevant business risk.
    """)


# ============================================================
# SECTION 13: ATTACK SURFACE
# ============================================================

def lesson_attack_surface():
    title("12. Attack Surface")

    explain("""
    Attack surface refers to the collection of exposed points through
    which an unauthorized party could potentially interact with or
    influence a system.

    Attack surface can include:

        Network interfaces
        Open services
        APIs
        Web applications
        Mobile applications
        Cloud resources
        User accounts
        Administrative interfaces
        Remote access services
        Third-party integrations
        Software dependencies
        Endpoints
        Physical interfaces
        Human processes
        Supply-chain relationships

    Attack surface is broader than "open ports."

    Modern organizations have:

        - Internet-facing infrastructure
        - SaaS applications
        - Cloud APIs
        - Employee endpoints
        - Mobile devices
        - Identity providers
        - CI/CD pipelines
        - Third-party services
        - AI systems
        - Data stores
    """)


# ============================================================
# SECTION 14: ATTACK SURFACE INVENTORY
# ============================================================

@dataclass
class AttackSurfaceItem:
    name: str
    category: str
    exposure: str
    security_owner: str
    risk_notes: str


def lesson_attack_surface_inventory():
    title("13. Attack Surface Inventory")

    assets = [
        AttackSurfaceItem(
            name="Public Web Application",
            category="Application",
            exposure="Internet-facing",
            security_owner="Application Security",
            risk_notes="Authentication, authorization, input validation"
        ),
        AttackSurfaceItem(
            name="Employee Laptop",
            category="Endpoint",
            exposure="External network",
            security_owner="Endpoint Security",
            risk_notes="Patch status, credentials, malware"
        ),
        AttackSurfaceItem(
            name="Cloud Storage",
            category="Cloud",
            exposure="Internet/API",
            security_owner="Cloud Security",
            risk_notes="IAM, encryption, access policies"
        ),
        AttackSurfaceItem(
            name="Third-party API",
            category="Integration",
            exposure="External dependency",
            security_owner="Platform Team",
            risk_notes="Authentication, data exchange, availability"
        ),
    ]

    for asset in assets:
        print(f"\nName:          {asset.name}")
        print(f"Category:      {asset.category}")
        print(f"Exposure:      {asset.exposure}")
        print(f"Owner:         {asset.security_owner}")
        print(f"Risk notes:    {asset.risk_notes}")

    explain("""
    A strong security program maintains an accurate asset inventory.

    You cannot reliably protect what you do not know exists.

    This is why asset management and attack-surface management are
    closely related.
    """)


# ============================================================
# SECTION 15: ATTACK SURFACE REDUCTION
# ============================================================

def lesson_attack_surface_reduction():
    title("14. Reducing Attack Surface")

    controls = [
        "Remove unnecessary services",
        "Disable unused accounts",
        "Close unnecessary interfaces",
        "Restrict administrative access",
        "Use network segmentation",
        "Patch vulnerable software",
        "Remove unsupported software",
        "Enforce strong authentication",
        "Reduce unnecessary permissions",
        "Secure APIs",
        "Protect cloud configurations",
        "Monitor exposed assets",
        "Control third-party integrations",
        "Apply secure configuration baselines",
    ]

    for control in controls:
        print(" -", control)

    explain("""
    Attack surface reduction is a continuous process.

    An organization can reduce its attack surface today and accidentally
    increase it tomorrow by deploying:

        - A new API
        - A new cloud service
        - A new employee application
        - A new remote access system
        - A new third-party integration

    Security therefore needs continuous visibility.
    """)


# ============================================================
# SECTION 16: WINDOWS SECURITY FOUNDATION
# ============================================================

def lesson_windows_security():
    title("15. Windows Security Foundations")

    explain("""
    On Windows, foundational security concepts include:

        - User accounts
        - Local administrators
        - Windows Defender
        - Windows Firewall
        - User Account Control
        - NTFS permissions
        - Security Event Logs
        - PowerShell
        - Windows Update
        - Group Policy
        - Credential protection
        - BitLocker
        - Microsoft security controls

    Useful defensive commands and interfaces include:

        whoami
        hostname
        ipconfig
        net user
        net localgroup
        systeminfo
        tasklist
        Get-Process
        Get-Service
        Get-WinEvent

    These commands are useful for understanding the local security
    state of a Windows machine.
    """)


# ============================================================
# SECTION 17: KALI LINUX SECURITY FOUNDATION
# ============================================================

def lesson_kali_linux():
    title("16. Kali Linux Foundations")

    explain("""
    Kali Linux is a Debian-based Linux distribution designed for
    security testing, digital forensics, research, and related work.

    It contains many security-oriented tools.

    For cybersecurity foundations, focus first on Linux itself.

    Important concepts:

        - Filesystem
        - Users
        - Groups
        - Permissions
        - Processes
        - Services
        - Networking
        - Logs
        - Package management
        - Shell
        - Environment variables
        - SSH
        - sudo

    Useful commands for defensive learning:

        whoami
        id
        pwd
        ls
        ps
        ss
        ip
        systemctl
        journalctl
        chmod
        chown

    The goal is not to memorize hundreds of Kali tools.

    First understand the operating system, networking, permissions,
    processes, and security model.
    """)


# ============================================================
# SECTION 18: HASHING AND INTEGRITY
# ============================================================

def sha256_hash(data: str) -> str:
    """Generate SHA-256 hash."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def lesson_hashing():
    title("17. Cryptographic Hashing and Integrity")

    original = "Cybersecurity Foundations"
    modified = "Cybersecurity Foundation"

    hash_original = sha256_hash(original)
    hash_modified = sha256_hash(modified)

    print("Original data:")
    print(original)

    print("\nOriginal SHA-256:")
    print(hash_original)

    print("\nModified data:")
    print(modified)

    print("\nModified SHA-256:")
    print(hash_modified)

    print("\nHashes equal:", hash_original == hash_modified)

    explain("""
    A cryptographic hash maps input data to a fixed-size digest.

    Important properties include:

        - Deterministic output
        - Efficient computation
        - Avalanche effect
        - Resistance to practical collision attacks for suitable
          modern algorithms
        - One-way behavior as a practical design goal

    Hashes can support integrity checking.

    They do not automatically provide:

        - Confidentiality
        - Authentication
        - Authorization
        - Non-repudiation
    """)


# ============================================================
# SECTION 19: HMAC AUTHENTICITY + INTEGRITY
# ============================================================

def create_hmac(message: str, secret: bytes) -> str:
    return hmac.new(
        secret,
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def lesson_hmac():
    title("18. HMAC: Integrity + Authenticity")

    message = "Transfer amount=1000"
    secret = secrets.token_bytes(32)

    signature = create_hmac(message, secret)

    print("Message:")
    print(message)

    print("\nHMAC:")
    print(signature)

    modified_message = "Transfer amount=9000"

    verification = hmac.compare_digest(
        signature,
        create_hmac(modified_message, secret)
    )

    print("\nModified message:")
    print(modified_message)

    print("\nVerification result:", verification)

    explain("""
    HMAC combines a cryptographic hash function with a secret key.

    It can provide:

        - Message integrity
        - Authentication of a message to parties sharing the secret

    HMAC does NOT provide non-repudiation because both parties know
    the same secret key.

    A digital signature is different because signing and verification
    use asymmetric cryptography.
    """)


# ============================================================
# SECTION 20: AUTHENTICATION VS AUTHORIZATION
# ============================================================

def lesson_authentication_authorization():
    title("19. Authentication vs Authorization")

    examples = [
        ("Authentication", "Verifying a username and password"),
        ("Authorization", "Checking whether the user may access payroll"),
        ("Authentication", "Validating a hardware security key"),
        ("Authorization", "Allowing an administrator to change firewall rules"),
    ]

    for concept, example in examples:
        print(f"{concept:18}: {example}")

    explain("""
    A useful sequence is:

        Identification
             |
             v
        Authentication
             |
             v
        Authorization
             |
             v
        Accounting / Auditing

    Identification:
        "I am Alice."

    Authentication:
        "Prove you are Alice."

    Authorization:
        "What may Alice do?"

    Accounting:
        "What did Alice actually do?"
    """)


# ============================================================
# SECTION 21: DEFENSE IN DEPTH
# ============================================================

def lesson_defense_in_depth():
    title("20. Defense in Depth")

    explain("""
    Defense in depth means using multiple layers of security.

    Example architecture:

        Layer 1: Physical security
        Layer 2: Network segmentation
        Layer 3: Firewall
        Layer 4: Identity controls
        Layer 5: Endpoint security
        Layer 6: Application security
        Layer 7: Data protection
        Layer 8: Monitoring
        Layer 9: Incident response
        Layer 10: Backup and recovery

    Why?

    Because no single control is perfect.

    If one control fails, another may still prevent or detect the attack.

    Example:

        Stolen password
             |
             v
        MFA blocks login
             |
             v
        If MFA fails:
             |
             v
        Conditional access
             |
             v
        If bypassed:
             |
             v
        Endpoint detection
             |
             v
        Suspicious behavior detected
             |
             v
        Security team investigates
    """)


# ============================================================
# SECTION 22: ZERO TRUST
# ============================================================

def lesson_zero_trust():
    title("21. Zero Trust")

    explain("""
    Zero Trust is a security approach based on the idea that trust
    should not be granted automatically based solely on network
    location or previous access.

    Common principles include:

        - Verify explicitly
        - Use least privilege
        - Assume breach

    Example:

        Being connected to a corporate network should not automatically
        mean a user can access every internal application.

    Access decisions can consider:

        - Identity
        - Device posture
        - Application
        - Resource
        - Location
        - Risk signals
        - Authentication strength
        - Time
        - Policy
    """)


# ============================================================
# SECTION 23: SECURITY CONTROL TYPES
# ============================================================

def lesson_security_controls():
    title("22. Security Controls")

    categories = {
        "Preventive":
            "Designed to prevent unwanted events.",
        "Detective":
            "Designed to detect events after or while they occur.",
        "Corrective":
            "Designed to restore or correct systems after an event.",
        "Deterrent":
            "Designed to discourage unwanted behavior.",
        "Compensating":
            "Alternative controls used when the preferred control is not feasible.",
        "Recovery":
            "Designed to restore operations after disruption.",
    }

    for category, explanation in categories.items():
        print(f"\n{category}")
        explain(explanation)

    examples = [
        ("Firewall", "Preventive"),
        ("Security monitoring", "Detective"),
        ("Backup restoration", "Recovery"),
        ("Account lockout", "Preventive"),
        ("Audit logging", "Detective"),
        ("Incident remediation", "Corrective"),
    ]

    subsection("Examples")

    for control, category in examples:
        print(f"{control:25} -> {category}")


# ============================================================
# SECTION 24: SECURITY EVENTS VS INCIDENTS
# ============================================================

def lesson_events_incidents():
    title("23. Security Events vs Incidents")

    explain("""
    A security event is an observable occurrence relevant to security.

    Examples:

        - Successful login
        - Failed login
        - File access
        - Firewall block
        - Password change

    Not every security event is an incident.

    An incident involves a security-related situation requiring
    investigation or response according to organizational policy.

    Example:

        Event:
            1 failed login

        Event:
            100 failed logins from an unusual source

        Potential incident:
            Evidence suggesting a credential attack
    """)


# ============================================================
# SECTION 25: SECURITY LOGGING
# ============================================================

def lesson_logging():
    title("24. Security Logging")

    logs = [
        {
            "timestamp": "2026-09-01 09:00:01",
            "user": "alice",
            "event": "LOGIN",
            "result": "SUCCESS"
        },
        {
            "timestamp": "2026-09-01 09:02:31",
            "user": "bob",
            "event": "LOGIN",
            "result": "FAILURE"
        },
        {
            "timestamp": "2026-09-01 09:02:32",
            "user": "bob",
            "event": "LOGIN",
            "result": "FAILURE"
        }
    ]

    for event in logs:
        print(event)

    explain("""
    Good security logs should generally support:

        - Accurate timestamps
        - Identity
        - Source
        - Action
        - Target
        - Outcome
        - Relevant context

    Logs should also be:

        - Protected against unauthorized modification
        - Retained according to policy
        - Monitored
        - Searchable
        - Correlated where appropriate
        - Time synchronized

    This supports accountability and incident response.
    """)


# ============================================================
# SECTION 26: THREAT MODELING
# ============================================================

def lesson_threat_modeling():
    title("25. Threat Modeling")

    explain("""
    Threat modeling is a structured approach for identifying potential
    security problems before or during system design.

    A simplified workflow:

        1. Identify assets
        2. Identify trust boundaries
        3. Understand data flows
        4. Identify threats
        5. Analyze vulnerabilities
        6. Estimate risk
        7. Design controls
        8. Validate controls
        9. Reassess

    Questions:

        What are we protecting?
        Who might attack it?
        How could they reach it?
        What could go wrong?
        What would the impact be?
        Which controls reduce the risk?
    """)

    subsection("STRIDE overview")

    stride = {
        "S": "Spoofing",
        "T": "Tampering",
        "R": "Repudiation",
        "I": "Information Disclosure",
        "D": "Denial of Service",
        "E": "Elevation of Privilege"
    }

    for letter, meaning in stride.items():
        print(f"{letter} -> {meaning}")

    explain("""
    STRIDE is a threat-modeling mnemonic.

    It should be treated as a structured thinking aid rather than a
    complete security methodology.
    """)


# ============================================================
# SECTION 27: SECURITY ASSUMPTIONS
# ============================================================

def lesson_security_assumptions():
    title("26. Security Assumptions")

    explain("""
    Security systems often fail because assumptions are incorrect.

    Dangerous assumptions include:

        "The internal network is trusted."

        "Nobody knows this URL."

        "Only administrators can make mistakes."

        "Our application is too small to attack."

        "The firewall solves everything."

        "Encryption means the system is secure."

        "The logs are automatically trustworthy."

        "A vulnerability with a low technical score is always low risk."

    Security engineering requires continuously challenging assumptions.
    """)


# ============================================================
# SECTION 28: SECURITY VS OBSCURITY
# ============================================================

def lesson_security_through_obscurity():
    title("27. Security Through Obscurity")

    explain("""
    Hiding implementation details should not be the primary security
    mechanism.

    Example:

        Renaming an administrative endpoint may reduce casual discovery,
        but it does not replace authentication and authorization.

    Good security assumes that an attacker may learn significant
    information about the system.

    This connects to the principle of open design:

        Security should depend on strong mechanisms and protected
        secrets, not on the assumption that nobody knows how the
        system works.
    """)


# ============================================================
# SECTION 29: FAILURE MODES
# ============================================================

def lesson_failure_modes():
    title("28. Secure Failure Modes")

    explain("""
    When a system fails, the failure behavior itself can create risk.

    Example:

        Access-control service unavailable.

    Unsafe approach:

        "Allow access because authorization cannot be checked."

    Safer approach in many sensitive contexts:

        "Deny access until authorization can be established."

    This is the concept of fail-secure.

    The correct behavior depends on the system.

    For example, a safety-critical physical system may require
    availability-oriented fail-safe behavior.

    Security engineering therefore requires understanding context.
    """)


# ============================================================
# SECTION 30: BUSINESS RISK VS TECHNICAL RISK
# ============================================================

def lesson_business_risk():
    title("29. Technical Risk vs Business Risk")

    explain("""
    Security professionals must translate technical weaknesses into
    business consequences.

    Technical statement:

        "An application has excessive permissions."

    Business translation:

        "A compromised application identity could modify financial
        records, causing financial loss and regulatory consequences."

    Business impacts can include:

        - Financial loss
        - Operational disruption
        - Legal consequences
        - Regulatory penalties
        - Privacy impact
        - Reputation damage
        - Customer loss
        - Safety consequences
        - Strategic damage

    This is why cybersecurity is a business discipline as well as
    a technical discipline.
    """)


# ============================================================
# SECTION 31: RISK TREATMENT
# ============================================================

def lesson_risk_treatment():
    title("30. Risk Treatment")

    treatments = {
        "Avoid":
            "Stop the activity that creates unacceptable risk.",
        "Mitigate":
            "Implement controls to reduce likelihood or impact.",
        "Transfer":
            "Shift some financial or contractual consequences to another party.",
        "Accept":
            "Consciously retain the risk within approved limits."
    }

    for treatment, meaning in treatments.items():
        print(f"\n{treatment}")
        explain(meaning)

    explain("""
    Example:

        Risk:
            Critical business service depends on a single server.

        Mitigation:
            Add redundancy.

        Avoidance:
            Retire the service.

        Transfer:
            Contractual arrangement or insurance may shift some
            consequences.

        Acceptance:
            Management may knowingly accept the residual risk if the
            cost of mitigation is disproportionate and policy allows it.
    """)


# ============================================================
# SECTION 32: RESIDUAL RISK
# ============================================================

def lesson_residual_risk():
    title("31. Residual Risk")

    explain("""
    Residual risk is the risk remaining after controls are implemented.

    Example:

        Initial risk = HIGH

        Controls:
            MFA
            Network segmentation
            Monitoring
            Least privilege

        Remaining risk = MEDIUM

    Controls rarely eliminate every possible risk.

    Security management therefore asks:

        "Is the remaining risk acceptable?"
    """)


# ============================================================
# SECTION 33: SECURITY ARCHITECTURE
# ============================================================

def lesson_security_architecture():
    title("32. Security Architecture")

    explain("""
    Security architecture is the design of security controls across
    an organization's technology environment.

    A simplified architecture might look like:

                  USERS
                    |
                    v
             Identity Layer
                    |
                    v
             Access Policies
                    |
                    v
          Application Layer
                    |
                    v
             API Gateway
                    |
                    v
          Service / Network
                    |
                    v
             Data Layer
                    |
                    v
              Backups

    Across every layer:

        Logging
        Monitoring
        Authentication
        Authorization
        Encryption
        Configuration management
        Incident response
    """)


# ============================================================
# SECTION 34: SECURITY PROPERTIES MAPPING
# ============================================================

def lesson_security_mapping():
    title("33. Mapping Security Goals to Controls")

    mapping = {
        "Confidentiality": [
            "Encryption",
            "Access control",
            "Least privilege",
            "Data classification"
        ],
        "Integrity": [
            "Hashing",
            "Digital signatures",
            "HMAC",
            "Change control"
        ],
        "Availability": [
            "Redundancy",
            "Backups",
            "Failover",
            "Monitoring"
        ],
        "Authenticity": [
            "Authentication",
            "Certificates",
            "Digital signatures",
            "MFA"
        ],
        "Accountability": [
            "Logging",
            "Audit trails",
            "Identity management",
            "Monitoring"
        ],
        "Non-repudiation": [
            "Digital signatures",
            "Trusted timestamps",
            "Audit evidence",
            "Key management"
        ]
    }

    for property_name, controls in mapping.items():
        print(f"\n{property_name}:")
        for control in controls:
            print("   -", control)


# ============================================================
# SECTION 35: SECURITY DESIGN CHECKLIST
# ============================================================

def security_design_checklist():
    title("34. Security Design Checklist")

    checklist = [
        "What assets require protection?",
        "What is the business impact if each asset is compromised?",
        "Who should have access?",
        "How are identities authenticated?",
        "How is authorization enforced?",
        "What data requires confidentiality?",
        "How is data integrity protected?",
        "How is availability maintained?",
        "How are actions logged?",
        "Can logs be modified by attackers?",
        "How is time synchronized?",
        "What are the trust boundaries?",
        "What is the attack surface?",
        "Which services are unnecessarily exposed?",
        "What happens if a control fails?",
        "How are backups protected?",
        "How is residual risk evaluated?",
        "Who owns each risk?",
        "How are incidents detected?",
        "How is recovery performed?"
    ]

    for number, question in enumerate(checklist, 1):
        print(f"{number:2}. {question}")


# ============================================================
# SECTION 36: MINI CASE STUDY
# ============================================================

def lesson_case_study():
    title("35. End-to-End Cybersecurity Case Study")

    explain("""
    Imagine an online banking application.

    Assets:

        - Customer identities
        - Account balances
        - Transaction records
        - Authentication credentials
        - Banking APIs
        - Audit logs

    Threats:

        - Cybercriminals
        - Malicious insiders
        - Compromised devices
        - Third-party compromise
        - Accidental administrative changes

    Vulnerabilities:

        - Weak authentication
        - Excessive permissions
        - Poor input validation
        - Misconfigured cloud storage
        - Unprotected administrative interfaces

    CIA analysis:

        Confidentiality:
            Customer information must not be exposed.

        Integrity:
            Transaction records must not be manipulated.

        Availability:
            Customers must be able to access banking services.

    Authenticity:

        Users must be verified.

    Accountability:

        Sensitive actions should be attributable to identities.

    Non-repudiation:

        Appropriate transactions may require strong evidence
        regarding their origin and integrity.

    Attack surface:

        - Web application
        - Mobile application
        - APIs
        - Employee endpoints
        - Cloud infrastructure
        - Third-party integrations

    Security architecture:

        MFA
        Least privilege
        Network segmentation
        Encryption
        Secure APIs
        Logging
        Monitoring
        Fraud detection
        Backups
        Incident response
    """)


# ============================================================
# SECTION 37: KNOWLEDGE CHECK
# ============================================================

def knowledge_check():
    title("36. Knowledge Check")

    questions = [
        (
            "What does CIA stand for?",
            "Confidentiality, Integrity, Availability"
        ),
        (
            "What is the difference between authentication and authorization?",
            "Authentication verifies identity; authorization determines permitted actions."
        ),
        (
            "What is a vulnerability?",
            "A weakness that may contribute to compromise or harm."
        ),
        (
            "What is a threat?",
            "A potential cause of harm."
        ),
        (
            "What is risk?",
            "Potential loss or harm arising from threats interacting with weaknesses."
        ),
        (
            "What is least privilege?",
            "Giving only the permissions necessary for a role or task."
        ),
        (
            "What is defense in depth?",
            "Using multiple layers of security controls."
        ),
        (
            "What is attack surface?",
            "The exposed points through which a system could potentially be interacted with or influenced."
        ),
        (
            "What does accountability provide?",
            "Association of actions with identities or responsible entities."
        ),
        (
            "Why is a hash not automatically non-repudiation?",
            "A hash detects changes but does not establish who created the data."
        ),
    ]

    score = 0

    for i, (question, answer) in enumerate(questions, 1):
        print(f"\nQ{i}. {question}")
        user_answer = input("Your answer: ").strip()

        print(f"Reference answer: {answer}")

        if user_answer:
            score += 1

    print(f"\nYou attempted {score}/{len(questions)} questions.")

    explain("""
    This score is only a participation metric.

    Cybersecurity mastery comes from being able to apply the concepts
    to unfamiliar systems rather than memorizing definitions.
    """)


# ============================================================
# SECTION 38: ADVANCED CONCEPT CONNECTIONS
# ============================================================

def lesson_advanced_connections():
    title("37. Advanced Connections")

    explain("""
    The concepts learned in this lesson are connected.

    CIA Triad
        |
        +-- Confidentiality
        |      |
        |      +-- Access control
        |      +-- Encryption
        |
        +-- Integrity
        |      |
        |      +-- Hashing
        |      +-- HMAC
        |      +-- Digital signatures
        |
        +-- Availability
               |
               +-- Redundancy
               +-- Recovery
               +-- Resilience

    Identity concepts
        |
        +-- Identification
        +-- Authentication
        +-- Authorization
        +-- Accountability
        +-- Non-repudiation

    Risk concepts
        |
        +-- Asset
        +-- Threat
        +-- Vulnerability
        +-- Likelihood
        +-- Impact
        +-- Risk
        +-- Control
        +-- Residual risk

    Architecture concepts
        |
        +-- Attack surface
        +-- Trust boundaries
        +-- Least privilege
        +-- Defense in depth
        +-- Zero Trust
        +-- Secure defaults
        +-- Fail secure

    This is the foundation for advanced domains such as:

        - Network security
        - Security operations
        - Penetration testing
        - Cloud security
        - Application security
        - Identity security
        - Digital forensics
        - Governance, risk and compliance
        - Security architecture
        - Incident response
    """)


# ============================================================
# SECTION 39: SAFE LOCAL LAB
# ============================================================

def lesson_safe_lab():
    title("38. Safe Cybersecurity Lab")

    explain("""
    Recommended learning environment:

        Host operating system:
            Windows

        Virtual machine:
            Kali Linux

        Editor:
            VS Code

        Programming:
            Python

    Keep your laboratory isolated and use intentionally vulnerable
    practice systems designed for education.

    Suggested foundation exercises:

        1. Learn Linux permissions.
        2. Learn Windows users and groups.
        3. Inspect local logs.
        4. Study firewall concepts.
        5. Build a local Python web application.
        6. Add authentication.
        7. Add authorization.
        8. Implement audit logging.
        9. Calculate simulated risk.
        10. Draw the application's attack surface.
        11. Identify trust boundaries.
        12. Design defense-in-depth controls.

    Never test systems you do not own or have explicit authorization
    to assess.
    """)


# ============================================================
# SECTION 40: FINAL SUMMARY
# ============================================================

def final_summary():
    title("39. Final Summary")

    summary = """
    You have studied the foundational vocabulary and reasoning model
    used throughout cybersecurity.

    The most important concepts are:

    1. Confidentiality
       Prevent unauthorized disclosure.

    2. Integrity
       Protect information from unauthorized or improper modification.

    3. Availability
       Keep authorized services and information accessible.

    4. Authenticity
       Establish that an entity or message is genuine.

    5. Accountability
       Associate actions with responsible identities or systems.

    6. Non-repudiation
       Preserve evidence supporting the origin or occurrence of an action.

    7. Threat
       Potential source of harm.

    8. Vulnerability
       Weakness that can contribute to compromise.

    9. Risk
       Potential consequence of threats interacting with weaknesses.

    10. Attack surface
        The exposed points through which systems may potentially be
        attacked or influenced.

    11. Least privilege
        Give only necessary permissions.

    12. Defense in depth
        Use multiple security layers.

    13. Zero Trust
        Continuously verify rather than blindly trust.

    14. Secure by default
        Start from a restrictive and safer configuration.

    15. Security is continuous
        Systems, threats, vulnerabilities, and business requirements
        constantly change.
    """

    explain(summary)


# ============================================================
# SECTION 41: MAIN COURSE
# ============================================================

def run_course():
    title("CYBERSECURITY FOUNDATIONS")
    print("""
    A Python-based interactive course.

    Difficulty:
        Beginner -> Intermediate -> Advanced Foundations

    Topics:
        CIA Triad
        Authenticity
        Accountability
        Non-repudiation
        Security Principles
        Threats
        Vulnerabilities
        Risk
        Attack Surface
        Security Controls
        Windows
        Kali Linux
        Cryptographic Integrity
        Threat Modeling
        Defense in Depth
        Zero Trust
    """)

    lessons = [
        lesson_cybersecurity_basics,
        lesson_cia_triad,
        cia_scenario_engine,
        lesson_authenticity,
        lesson_accountability,
        lesson_non_repudiation,
        lesson_security_principles,
        lesson_least_privilege_simulation,
        lesson_threat_vulnerability_risk,
        lesson_risk_matrix,
        lesson_scenario_model,
        lesson_attack_surface,
        lesson_attack_surface_inventory,
        lesson_attack_surface_reduction,
        lesson_windows_security,
        lesson_kali_linux,
        lesson_hashing,
        lesson_hmac,
        lesson_authentication_authorization,
        lesson_defense_in_depth,
        lesson_zero_trust,
        lesson_security_controls,
        lesson_events_incidents,
        lesson_logging,
        lesson_threat_modeling,
        lesson_security_assumptions,
        lesson_security_through_obscurity,
        lesson_failure_modes,
        lesson_business_risk,
        lesson_risk_treatment,
        lesson_residual_risk,
        lesson_security_architecture,
        lesson_security_mapping,
        security_design_checklist,
        lesson_case_study,
        lesson_advanced_connections,
        lesson_safe_lab,
        final_summary
    ]

    for lesson in lessons:
        lesson()

        # Optional pause.
        # Uncomment the following line for interactive learning:
        #
        # pause()

    print("\nCourse completed.")
    print("Recommended next step: Network Security Foundations.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    run_course()
