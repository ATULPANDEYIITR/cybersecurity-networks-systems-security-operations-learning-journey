```python
"""
CYBERSECURITY DOMAINS
=====================

Topics covered:
1. Network Security
2. Endpoint Security
3. Application Security
4. Cloud Security
5. Identity Security
6. Data Security
7. Security Operations
8. Kali Linux and Windows in cybersecurity
9. Security architecture and domain relationships
10. Defensive security concepts, monitoring, hardening and incident response

This program is written as a study-oriented Python script.
It does not perform attacks against real systems.

The purpose is to explain cybersecurity concepts through:
- structured notes
- terminology
- examples
- simple calculations
- defensive demonstrations
- configuration concepts
- log analysis
- security controls
- practical thinking

Run this file with Python 3.
"""


# ============================================================
# 1. BASIC PYTHON UTILITIES
# ============================================================

def title(text):
    print("\n" + "=" * 78)
    print(text)
    print("=" * 78)


def section(text):
    print("\n" + "-" * 78)
    print(text)
    print("-" * 78)


def explain(term, meaning):
    print(f"\n{term}")
    print(f"  {meaning}")


def show(items):
    for item in items:
        print(f"  • {item}")


# ============================================================
# 2. INTRODUCTION TO CYBERSECURITY
# ============================================================

title("CYBERSECURITY DOMAINS: FROM FUNDAMENTALS TO ADVANCED CONCEPTS")

section("What is cybersecurity?")

print("""
Cybersecurity is the discipline of protecting information systems,
networks, applications, devices, identities and data from unauthorized
access, misuse, disruption, alteration and destruction.

A modern organization does not have one single security boundary.

A typical environment may contain:

    Users
       |
       v
    Identity Provider
       |
       +----------------------+
       |                      |
       v                      v
    Endpoints              Cloud Services
       |                      |
       v                      v
    Network  ------------> Applications
       |                      |
       +----------+-----------+
                  |
                  v
                Data
                  |
                  v
            Security Operations

Each component creates a different security problem.

This is why cybersecurity is divided into specialized domains.
""")

section("The CIA Triad")

explain(
    "Confidentiality",
    "Information should only be accessible to authorized people, systems or processes."
)

explain(
    "Integrity",
    "Information should remain accurate, trustworthy and protected from unauthorized modification."
)

explain(
    "Availability",
    "Systems and information should be available when legitimate users need them."
)

print("""
Example:

A banking application stores account information.

Confidentiality:
    An unauthorized person must not read the account information.

Integrity:
    An unauthorized person must not change the account balance.

Availability:
    Customers should be able to access the service when required.

A security control can improve one property while affecting another.

For example, very strict security controls may increase confidentiality
but can sometimes reduce usability or availability.

Cybersecurity therefore involves balancing security, business requirements,
risk, performance and usability.
""")


# ============================================================
# 3. CYBERSECURITY DOMAINS
# ============================================================

title("THE SEVEN MAJOR CYBERSECURITY DOMAINS")

domains = {
    "Network Security":
        "Protects communication networks, traffic flows, network devices and network boundaries.",

    "Endpoint Security":
        "Protects laptops, desktops, servers, mobile devices and other computing endpoints.",

    "Application Security":
        "Protects software applications throughout design, development, deployment and operation.",

    "Cloud Security":
        "Protects cloud infrastructure, workloads, identities, services, configurations and data.",

    "Identity Security":
        "Controls who can access resources, what they can access and under which conditions.",

    "Data Security":
        "Protects data throughout its lifecycle, including storage, processing and transmission.",

    "Security Operations":
        "Continuously monitors, detects, investigates, responds to and improves security posture."
}

for domain, description in domains.items():
    explain(domain, description)


# ============================================================
# 4. NETWORK SECURITY
# ============================================================

title("DOMAIN 1: NETWORK SECURITY")

section("Definition")

print("""
Network security protects the communication infrastructure through which
systems exchange information.

It includes:

    • Network architecture
    • Firewalls
    • Network segmentation
    • Routing security
    • Secure protocols
    • Intrusion detection
    • Intrusion prevention
    • VPNs
    • Wireless security
    • DNS security
    • Network access control
    • Traffic monitoring
    • Zero Trust network principles
""")

section("Basic network concepts")

network_concepts = [
    ("IP address", "Logical address used to identify a device or interface on a network."),
    ("MAC address", "Link-layer hardware address associated with a network interface."),
    ("Port", "Logical communication endpoint used by network services."),
    ("Protocol", "Rules defining how systems communicate."),
    ("TCP", "Connection-oriented transport protocol providing reliable delivery."),
    ("UDP", "Connectionless transport protocol with lower overhead."),
    ("DNS", "System that translates domain names into network addresses."),
    ("DHCP", "Protocol commonly used to automatically provide network configuration."),
    ("Router", "Device that forwards traffic between networks."),
    ("Switch", "Device that connects systems within a local network."),
    ("Firewall", "Control that permits or blocks traffic according to defined rules."),
]

for name, meaning in network_concepts:
    explain(name, meaning)


section("Network layers")

print("""
A practical security engineer should understand several representations
of network communication.

OSI model:

    7  Application
    6  Presentation
    5  Session
    4  Transport
    3  Network
    2  Data Link
    1  Physical

Examples:

Application:
    HTTP, HTTPS, DNS, SMTP

Transport:
    TCP, UDP

Network:
    IPv4, IPv6

Data Link:
    Ethernet, Wi-Fi

Security controls operate at different layers.

A firewall may make decisions using IP addresses, ports and protocols.

An application security control may inspect HTTP requests.

An endpoint security product may inspect the process generating network traffic.
""")


section("Ports and services")

common_ports = {
    20: "FTP data",
    21: "FTP control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "Remote Desktop Protocol"
}

for port, service in common_ports.items():
    print(f"Port {port:4} -> {service}")

print("""
A port number does not automatically prove what application is actually
running. Administrators can configure services to listen on non-standard
ports.

Therefore:

    Port number != guaranteed service identity

Security monitoring should consider:

    IP address
    port
    protocol
    process
    hostname
    certificate
    application behavior
    historical activity
""")


section("Firewall principles")

print("""
A firewall policy normally evaluates traffic using attributes such as:

    source
    destination
    protocol
    port
    direction
    interface
    connection state
    application identity
    user identity

A simplified policy might look like:

    ALLOW internal-web -> application-server:443
    ALLOW application-server -> database-server:5432
    DENY everything else

The principle of least privilege is important.

A system should not be able to communicate with every other system
unless there is a legitimate requirement.
""")


section("Network segmentation")

print("""
Segmentation divides a network into security zones.

Example:

    Internet
       |
       v
    Firewall
       |
       v
    DMZ
       |
       v
    Application Network
       |
       v
    Database Network
       |
       v
    Restricted Management Network

The purpose is to limit lateral movement and reduce the blast radius
of a security incident.

A compromised web server should not automatically provide unrestricted
access to database systems, employee endpoints or administrative systems.
""")


section("Zero Trust")

print("""
Zero Trust does not mean trusting nobody in an absolute sense.

It is an architectural approach based on continuously evaluating:

    identity
    device state
    resource
    context
    policy
    risk

A traditional model might think:

    "The user is inside the corporate network, therefore trust them."

A Zero Trust model asks:

    "Who is the user?"
    "Which device are they using?"
    "What resource are they requesting?"
    "Is this access appropriate?"
    "What is the current security context?"

Network location alone is not sufficient evidence of trust.
""")


# ============================================================
# 5. ENDPOINT SECURITY
# ============================================================

title("DOMAIN 2: ENDPOINT SECURITY")

section("Definition")

print("""
An endpoint is a computing device that participates in an environment.

Examples:

    Windows workstation
    Linux server
    laptop
    desktop
    mobile device
    virtual machine
    server
    workstation used by an administrator

Endpoint security protects these systems against:

    unauthorized access
    malicious software
    insecure configuration
    privilege abuse
    persistence
    data theft
    unauthorized software
    exploitation of vulnerable software
""")


section("Windows security architecture")

print("""
Important Windows security concepts include:

    Windows Security
    Microsoft Defender
    Windows Firewall
    User Account Control
    Windows Event Log
    Security Event Logs
    PowerShell
    Active Directory
    Group Policy
    NTFS permissions
    BitLocker
    Credential protection
    Windows services
    Scheduled tasks
    Application control

Windows is commonly deployed in enterprise environments, so security
engineers frequently investigate Windows authentication events,
processes, services, network connections and endpoint telemetry.
""")


section("Windows Event Logs")

windows_events = {
    "4624": "Successful logon",
    "4625": "Failed logon",
    "4688": "Process creation when process auditing is enabled",
    "4720": "User account created",
    "4728": "Member added to a global security-enabled group",
    "4732": "Member added to a local security-enabled group",
    "7045": "Service installed"
}

for event_id, meaning in windows_events.items():
    print(f"Event ID {event_id}: {meaning}")

print("""
Event IDs should not be interpreted in isolation.

For example, one failed login may be normal.

Thousands of failed logins against one account from an unusual source
may deserve investigation.

Security analysis depends on:

    frequency
    time
    source
    destination
    account
    device
    process
    historical baseline
    surrounding events
""")


section("Endpoint hardening")

hardening = [
    "Apply security updates and patches.",
    "Remove unnecessary software.",
    "Disable unnecessary services.",
    "Use strong authentication.",
    "Use least privilege.",
    "Enable endpoint protection.",
    "Configure host firewalls.",
    "Encrypt sensitive storage.",
    "Restrict administrative access.",
    "Enable appropriate security logging.",
    "Control removable media where required.",
    "Use application allowlisting where appropriate.",
]

show(hardening)


section("Linux endpoint security")

print("""
Linux security involves concepts such as:

    users
    groups
    file permissions
    sudo
    processes
    systemd
    SSH
    logs
    package management
    kernel security
    firewall configuration
    mandatory access controls

Typical permission representation:

    rwxr-xr--

This can be interpreted as:

    owner:       rwx
    group:       r-x
    others:      r--

The principle is that access should be granted only when necessary.
""")


# ============================================================
# 6. KALI LINUX
# ============================================================

title("KALI LINUX IN CYBERSECURITY")

print("""
Kali Linux is a Debian-based Linux distribution designed for security
testing, digital forensics, security research and related professional
work.

It is not a magical hacking operating system.

Its importance comes from its collection of security-oriented tools and
its usefulness in controlled security laboratories.

A security professional can use Kali for:

    network analysis
    vulnerability assessment
    web security testing
    digital forensics
    password auditing
    wireless security assessment
    reconnaissance in authorized environments
    incident investigation
    security research
""")


section("Important Kali tool categories")

kali_categories = {
    "Wireshark":
        "Graphical network protocol analyzer used to inspect captured traffic.",

    "Nmap":
        "Network discovery and security auditing tool.",

    "Burp Suite":
        "Web application security testing platform.",

    "Nikto":
        "Web server assessment tool.",

    "John the Ripper":
        "Password security auditing software.",

    "Hydra":
        "Authentication testing tool used in authorized environments.",

    "Metasploit":
        "Security testing framework used for vulnerability research and validation.",

    "Autopsy":
        "Digital forensics platform.",

    "tcpdump":
        "Command-line packet capture and analysis utility."
}

for tool, purpose in kali_categories.items():
    explain(tool, purpose)


section("Defensive interpretation of Kali")

print("""
A security professional should not judge a tool only by its ability
to perform an action.

The important question is:

    What security property does this tool help evaluate?

For example:

Nmap:
    Can help identify exposed services.

Wireshark:
    Can help understand network behavior.

Burp Suite:
    Can help inspect application requests and responses.

Autopsy:
    Can help investigate digital evidence.

Metasploit:
    Can help validate whether a known vulnerability exists in an
    authorized test environment.

The same technical knowledge can be used by attackers and defenders.
Authorization and controlled scope determine whether an activity is legitimate.
""")


# ============================================================
# 7. APPLICATION SECURITY
# ============================================================

title("DOMAIN 3: APPLICATION SECURITY")

section("Definition")

print("""
Application security protects software from vulnerabilities throughout
its lifecycle.

The lifecycle includes:

    requirements
        |
        v
    architecture
        |
        v
    design
        |
        v
    development
        |
        v
    testing
        |
        v
    deployment
        |
        v
    monitoring
        |
        v
    maintenance

Security should not be added only after software has been completed.
""")


section("Common application security weaknesses")

application_risks = [
    "Broken access control",
    "Authentication weaknesses",
    "Injection vulnerabilities",
    "Cross-site scripting",
    "Security misconfiguration",
    "Cryptographic failures",
    "Insecure deserialization",
    "Server-side request forgery",
    "Sensitive information exposure",
    "Improper input validation",
    "Insecure file handling",
    "Dependency vulnerabilities",
    "Insufficient logging and monitoring"
]

show(application_risks)


section("Input validation")

print("""
Applications receive input from users and other systems.

Examples:

    username
    email
    search query
    uploaded file
    JSON request
    URL parameter
    HTTP header

Never assume input is trustworthy.

Validation can include:

    type checking
    length restrictions
    format validation
    range validation
    allowlists
    encoding handling
    context-aware output encoding

Input validation is only one part of application security.

Security must also be enforced through:

    authorization
    secure database access
    safe cryptographic practices
    session management
    secure configuration
""")


section("Authentication versus authorization")

explain(
    "Authentication",
    "Determines who a user or system is."
)

explain(
    "Authorization",
    "Determines what an authenticated identity is permitted to do."
)

print("""
Example:

A user successfully logs into a banking application.

Authentication:
    The system establishes that the user is Alice.

Authorization:
    The system determines whether Alice may view account X,
    transfer money, change account settings, or administer users.

Successful authentication does not imply unlimited authorization.
""")


section("Secure software design")

print("""
Important design principles include:

    Least privilege
    Defense in depth
    Fail securely
    Secure defaults
    Separation of duties
    Complete mediation
    Minimize attack surface
    Avoid unnecessary complexity

Defense in depth means that security does not depend on a single control.

For example:

    Authentication
        +
    Authorization
        +
    Input validation
        +
    Database permissions
        +
    Encryption
        +
    Logging
        +
    Monitoring

A failure in one layer does not automatically result in total compromise.
""")


# ============================================================
# 8. CLOUD SECURITY
# ============================================================

title("DOMAIN 4: CLOUD SECURITY")

section("Definition")

print("""
Cloud security protects cloud-hosted infrastructure, applications,
identities, configurations and data.

Major cloud service models include:

    IaaS
    PaaS
    SaaS

IaaS:
    Infrastructure is provided as a service.

PaaS:
    The provider manages more of the underlying infrastructure and
    provides a platform for applications.

SaaS:
    The provider delivers the application as a service.
""")


section("Shared responsibility model")

print("""
Cloud security is based heavily on shared responsibility.

The cloud provider is responsible for certain parts of the infrastructure.

The customer is responsible for other parts depending on the service.

For example, the customer may remain responsible for:

    identity configuration
    permissions
    data
    application configuration
    secrets
    network rules
    virtual machines in some service models

A common security failure is assuming:

    "The cloud provider secures everything."

The correct security model depends on the service being used.
""")


section("Cloud security controls")

cloud_controls = [
    "Identity and access management",
    "Multi-factor authentication",
    "Least-privilege permissions",
    "Network segmentation",
    "Security groups",
    "Encryption",
    "Key management",
    "Secrets management",
    "Logging",
    "Configuration monitoring",
    "Vulnerability management",
    "Backup and recovery",
    "Security posture management",
]

show(cloud_controls)


section("Cloud misconfiguration")

print("""
A cloud environment can be technically secure but incorrectly configured.

Examples of dangerous configuration patterns include:

    excessive permissions
    publicly exposed storage
    unrestricted management interfaces
    missing logging
    weak authentication
    exposed credentials
    insecure network rules
    outdated workloads

Cloud security therefore requires continuous configuration assessment.

Security is not a one-time installation process.
""")


# ============================================================
# 9. IDENTITY SECURITY
# ============================================================

title("DOMAIN 5: IDENTITY SECURITY")

section("Definition")

print("""
Identity security protects accounts, credentials, authentication systems,
authorization mechanisms and privileged access.

Identity has become one of the most important security boundaries because
users access applications from many different networks and devices.
""")


section("Identity concepts")

identity_concepts = [
    ("Identity", "A representation of a person, service, device or system."),
    ("Authentication", "Verification of an identity."),
    ("Authorization", "Determination of permitted actions."),
    ("Account", "Record representing an identity in a system."),
    ("Credential", "Information used to authenticate."),
    ("Role", "Collection of permissions associated with a responsibility."),
    ("Privilege", "Specific authority granted to an identity."),
    ("MFA", "Authentication requiring multiple independent factors."),
    ("SSO", "Single sign-on allowing access to multiple services through a common identity system."),
]

for name, meaning in identity_concepts:
    explain(name, meaning)


section("Authentication factors")

print("""
Authentication factors are commonly divided into:

    Something you know
        password
        PIN

    Something you have
        security key
        authenticator device

    Something you are
        biometric characteristic

The security value of multi-factor authentication comes from requiring
independent factors rather than simply requiring two pieces of information
from the same category.
""")


section("Least privilege")

print("""
Suppose an employee only needs to read financial reports.

Granting:

    read reports

is preferable to granting:

    system administrator

Least privilege reduces the damage caused by:

    compromised accounts
    mistakes
    insider misuse
    malware
    credential theft
""")


section("Privileged Access Management")

print("""
Privileged accounts deserve stronger controls.

Examples:

    domain administrators
    cloud administrators
    database administrators
    security administrators
    infrastructure administrators

Controls may include:

    just-in-time access
    approval workflows
    session monitoring
    separate administrative accounts
    MFA
    privileged credential rotation
    detailed logging
""")


# ============================================================
# 10. DATA SECURITY
# ============================================================

title("DOMAIN 6: DATA SECURITY")

section("Definition")

print("""
Data security protects information from unauthorized access,
modification, destruction or disclosure.

Data exists in different states:

    Data at rest
    Data in transit
    Data in use
""")


section("Data at rest")

print("""
Data at rest includes information stored in:

    databases
    hard drives
    SSDs
    cloud storage
    backups
    archives

Security controls include:

    encryption
    access controls
    file permissions
    database permissions
    key management
    backup protection
""")


section("Data in transit")

print("""
Data in transit moves between systems.

Examples:

    browser -> web server
    application -> database
    employee -> corporate service

Transport encryption helps protect against interception.

HTTPS uses TLS to protect HTTP communication.

A secure protocol does not automatically make an entire application secure.

For example:

    HTTPS
        protects transport

but:

    authorization
        protects access decisions

These solve different problems.
""")


section("Data classification")

classification = {
    "Public":
        "Information intended for public distribution.",

    "Internal":
        "Information intended primarily for organizational use.",

    "Confidential":
        "Information whose unauthorized disclosure could cause harm.",

    "Restricted":
        "Highly sensitive information requiring strict controls."
}

for category, meaning in classification.items():
    print(f"{category}: {meaning}")


section("Data lifecycle")

print("""
A useful model is:

    Create
      |
      v
    Store
      |
      v
    Use
      |
      v
    Share
      |
      v
    Archive
      |
      v
    Destroy

Security controls should exist throughout the lifecycle.

Data should not remain accessible indefinitely simply because it
was once useful.
""")


# ============================================================
# 11. CRYPTOGRAPHY
# ============================================================

title("CRYPTOGRAPHY AS A CROSS-DOMAIN SECURITY CONTROL")

section("Encryption")

print("""
Encryption transforms readable information into a protected representation
using a cryptographic algorithm and key.

Symmetric encryption:

    plaintext + secret key
             |
             v
        ciphertext

The same secret key is generally used for encryption and decryption.

Asymmetric cryptography uses a key pair:

    public key
    private key

The private key must be protected.

Cryptography supports:

    confidentiality
    integrity
    authentication
    non-repudiation in appropriate systems
""")


section("Hashing")

print("""
A cryptographic hash function maps input data to a fixed-size digest.

Example concept:

    data
      |
      v
    SHA-256
      |
      v
    digest

Hashing is not the same as encryption.

Encryption is designed to be reversible with the appropriate key.

Cryptographic hashing is designed to be computationally difficult
to reverse to the original input.

Passwords should not normally be stored as simple unsalted hashes.
Password storage uses specialized password hashing functions and
appropriate parameters.
""")


# ============================================================
# 12. SECURITY OPERATIONS
# ============================================================

title("DOMAIN 7: SECURITY OPERATIONS")

section("Definition")

print("""
Security Operations, commonly called SecOps, is the continuous practice
of monitoring and protecting an organization's technology environment.

Typical activities include:

    monitoring
    detection
    triage
    investigation
    threat analysis
    incident response
    vulnerability management
    threat intelligence
    security engineering
    reporting
""")


section("SOC")

print("""
A Security Operations Center may contain analysts with different roles.

Tier 1:
    Alert monitoring and initial triage

Tier 2:
    Deeper investigation and incident analysis

Tier 3:
    Advanced investigation, detection engineering and specialized analysis

Other functions may include:

    incident response
    threat hunting
    malware analysis
    digital forensics
    detection engineering
    security automation
""")


section("SIEM")

print("""
A SIEM, or Security Information and Event Management platform,
collects and correlates security-relevant logs.

Possible sources:

    Windows Event Logs
    Linux logs
    firewall logs
    VPN logs
    identity provider logs
    cloud logs
    application logs
    endpoint security telemetry
    DNS logs

A SIEM can help answer questions such as:

    Which account logged in?
    From where?
    At what time?
    Which device was used?
    What happened immediately before the event?
    What happened immediately afterward?
""")


# ============================================================
# 13. LOG ANALYSIS WITH PYTHON
# ============================================================

title("DEFENSIVE LOG ANALYSIS USING PYTHON")

section("Example authentication log")

sample_logs = [
    "2026-09-03 08:11:02 user=alice source=10.0.0.10 status=SUCCESS",
    "2026-09-03 08:14:11 user=bob source=10.0.0.20 status=SUCCESS",
    "2026-09-03 08:20:17 user=admin source=10.0.0.30 status=FAILURE",
    "2026-09-03 08:20:18 user=admin source=10.0.0.30 status=FAILURE",
    "2026-09-03 08:20:20 user=admin source=10.0.0.30 status=FAILURE",
    "2026-09-03 08:20:22 user=admin source=10.0.0.30 status=FAILURE",
    "2026-09-03 08:21:05 user=admin source=10.0.0.30 status=SUCCESS",
]

show(sample_logs)


def count_failed_logins(logs):
    count = 0

    for line in logs:
        if "status=FAILURE" in line:
            count += 1

    return count


failed = count_failed_logins(sample_logs)

print(f"\nFailed login events detected: {failed}")

print("""
The script is not claiming that the account was compromised.

It only identifies a pattern.

Security investigation requires context.

Questions include:

    Was the source address expected?
    Is the source an administrator's workstation?
    Was the successful login expected?
    Was MFA completed?
    Was the login during normal working hours?
    Were other accounts targeted?
    What happened after the successful login?
""")


# ============================================================
# 14. SIMPLE SECURITY RISK CALCULATION
# ============================================================

title("RISK MANAGEMENT")

print("""
Risk can be conceptualized using:

    Risk = Likelihood × Impact

This is a simplified model.

Example:

    Likelihood = 4
    Impact     = 5

    Risk = 4 × 5
         = 20
""")

likelihood = 4
impact = 5
risk = likelihood * impact

print(f"Calculated example risk: {risk}")


section("Risk treatment")

print("""
Organizations commonly respond to risk by:

    Avoiding the risk
    Reducing the risk
    Transferring the risk
    Accepting the risk

Risk management is not the same as eliminating every possible risk.

Security decisions are made using:

    business value
    probability
    impact
    cost
    regulatory requirements
    operational requirements
    threat environment
""")


# ============================================================
# 15. VULNERABILITY MANAGEMENT
# ============================================================

title("VULNERABILITY MANAGEMENT")

print("""
A vulnerability is a weakness that can potentially be used to
compromise confidentiality, integrity or availability.

Vulnerability management normally involves:

    Asset discovery
        |
        v
    Vulnerability identification
        |
        v
    Risk assessment
        |
        v
    Prioritization
        |
        v
    Remediation
        |
        v
    Validation
        |
        v
    Continuous monitoring
""")


section("Severity versus risk")

print("""
A vulnerability can have a high technical severity but relatively low
business risk if the affected system is isolated and contains no
important information.

Conversely, a moderate vulnerability may become a serious business risk
if it affects an internet-facing system containing sensitive information.

Therefore:

    Vulnerability severity != complete business risk

Context matters.
""")


# ============================================================
# 16. INCIDENT RESPONSE
# ============================================================

title("INCIDENT RESPONSE")

section("Incident response lifecycle")

print("""
A commonly used conceptual lifecycle is:

    Preparation
        |
        v
    Detection and Analysis
        |
        v
    Containment
        |
        v
    Eradication
        |
        v
    Recovery
        |
        v
    Lessons and Improvement

Preparation includes:

    policies
    tools
    access
    backups
    logging
    playbooks
    communication procedures
""")


section("Detection and analysis")

print("""
During analysis, investigators establish:

    What happened?
    When did it happen?
    Which systems were affected?
    Which identities were involved?
    What data was affected?
    What was the initial entry point?
    Is the activity still occurring?
    What evidence exists?

Evidence should be handled carefully.

Security investigation requires preserving evidence while minimizing
unnecessary changes to affected systems.
""")


section("Containment")

print("""
Containment attempts to stop an incident from expanding.

Examples:

    isolate an endpoint
    disable a compromised account
    block malicious communication
    restrict access to affected resources
    isolate a network segment

Containment must be balanced against business continuity.

Disconnecting an important production system can itself cause a major
availability incident.
""")


# ============================================================
# 17. THREAT MODELING
# ============================================================

title("THREAT MODELING")

print("""
Threat modeling identifies security problems before or during system design.

A simple process is:

    1. Identify assets
    2. Identify trust boundaries
    3. Identify entry points
    4. Identify threats
    5. Estimate risk
    6. Design controls
    7. Validate controls
""")


section("Example threat model")

print("""
Consider an online shopping application.

Assets:

    customer accounts
    payment information
    order information
    business data

Entry points:

    web application
    mobile application
    APIs
    administrative interfaces

Trust boundaries:

    customer -> application
    application -> database
    application -> payment provider

Security questions:

    Can one customer access another customer's order?
    Can unauthorized users access administrative functions?
    Are API permissions correctly enforced?
    Are secrets protected?
    Are sensitive records encrypted?
    Are important actions logged?
""")


# ============================================================
# 18. DEFENSE IN DEPTH
# ============================================================

title("DEFENSE IN DEPTH")

print("""
A mature environment does not depend on one security control.

Example:

                    INTERNET
                       |
                  [Firewall]
                       |
                [Network Controls]
                       |
                 [Application]
                       |
              [Authentication]
                       |
               [Authorization]
                       |
                [Database]
                       |
                 [Encryption]
                       |
                   [Logging]
                       |
                    [SOC]

If one layer fails, additional controls can reduce the impact.

This is the principle of defense in depth.
""")


# ============================================================
# 19. SECURITY ARCHITECTURE
# ============================================================

title("HOW THE CYBERSECURITY DOMAINS CONNECT")

print("""
The domains are not independent silos.

Example:

A user logs into a cloud application.

Identity Security:
    verifies the user's identity.

Endpoint Security:
    evaluates the device.

Network Security:
    protects communication paths.

Application Security:
    protects the application.

Cloud Security:
    protects cloud infrastructure and services.

Data Security:
    protects the information being processed.

Security Operations:
    monitors the entire activity and investigates anomalies.

This creates a security chain:

    Identity
       |
    Endpoint
       |
    Network
       |
    Application
       |
    Cloud
       |
    Data
       |
    Operations

A weakness in one layer can affect the others.
""")


# ============================================================
# 20. WINDOWS + KALI COMPARISON
# ============================================================

title("KALI LINUX AND WINDOWS IN CYBERSECURITY")

comparison = {
    "Primary role":
        "Windows is widely used as an enterprise endpoint/server platform; Kali is specialized for security testing, research and forensics.",

    "Typical security use":
        "Windows is commonly defended and monitored; Kali is commonly used to assess security in authorized environments.",

    "Command line":
        "Windows commonly uses PowerShell and Command Prompt; Kali heavily uses Linux shell utilities.",

    "Logging":
        "Windows uses Event Viewer and Windows Event Logs; Linux systems commonly use journaling and log files.",

    "Security testing":
        "Windows can be assessed directly as an endpoint; Kali provides many specialized security assessment tools.",

    "Administration":
        "Windows commonly uses GUI administration, PowerShell, Group Policy and enterprise management systems; Kali uses standard Linux administration tools."
}

for category, meaning in comparison.items():
    explain(category, meaning)


# ============================================================
# 21. WINDOWS POWERSHELL CONCEPTS
# ============================================================

title("WINDOWS POWERSHELL FOR DEFENSIVE SECURITY")

print("""
PowerShell is a powerful Windows automation and administration environment.

Security professionals use it for tasks such as:

    collecting system information
    reviewing services
    examining processes
    querying event logs
    checking configuration
    automating administrative tasks
    responding to incidents

The important security principle is that powerful administration tools
must themselves be monitored and controlled.

PowerShell can be used for legitimate administration and can also be
abused by malicious actors.

Therefore security teams monitor:

    who used PowerShell
    when it was used
    from which device
    which commands or scripts were executed
    what processes were created
    what network activity followed
""")


# ============================================================
# 22. LINUX SECURITY COMMAND CONCEPTS
# ============================================================

title("LINUX SECURITY COMMAND CONCEPTS")

linux_commands = {
    "whoami":
        "Shows the current user identity.",

    "id":
        "Shows user and group identity information.",

    "ps":
        "Displays running processes.",

    "ss":
        "Displays socket and network connection information.",

    "ip":
        "Displays or manages network configuration.",

    "journalctl":
        "Reads systemd journal logs.",

    "systemctl":
        "Controls and examines systemd services.",

    "ls -l":
        "Displays files with permission and ownership information.",

    "chmod":
        "Changes file permissions.",

    "chown":
        "Changes file ownership."
}

for command, purpose in linux_commands.items():
    explain(command, purpose)


# ============================================================
# 23. SECURITY MONITORING METRICS
# ============================================================

title("SECURITY MONITORING METRICS")

metrics = {
    "MTTD":
        "Mean Time to Detect. Average time required to detect an incident.",

    "MTTR":
        "Mean Time to Respond or Recover, depending on organizational definition.",

    "False Positive Rate":
        "Proportion of alerts incorrectly classified as security incidents.",

    "Alert Volume":
        "Number of alerts generated by monitoring systems.",

    "Patch Compliance":
        "Percentage of relevant systems meeting defined patch requirements.",

    "MFA Coverage":
        "Percentage of relevant identities protected by multi-factor authentication."
}

for metric, meaning in metrics.items():
    explain(metric, meaning)


# ============================================================
# 24. SECURITY AUTOMATION
# ============================================================

title("SECURITY AUTOMATION")

print("""
Security automation reduces repetitive manual work.

Examples:

    collecting logs
    enriching alerts
    checking IP reputation
    disabling compromised accounts
    creating tickets
    notifying analysts
    checking asset configuration
    generating reports

Automation should be carefully designed.

A dangerous automation system can amplify an incorrect decision.

Example:

    Detection incorrectly identifies an administrator as malicious
        |
        v
    Automation disables account
        |
        v
    Production outage

Therefore automated actions should consider:

    confidence
    authorization
    impact
    approval requirements
    rollback
    auditability
""")


# ============================================================
# 25. SECURITY INFORMATION CORRELATION
# ============================================================

title("EVENT CORRELATION")

print("""
One event may be harmless.

Several related events can create a meaningful security signal.

Example:

    09:00  Failed login
    09:01  Failed login
    09:02  Successful login
    09:03  Privileged group change
    09:04  Unusual network connection

Each event alone may not prove malicious activity.

Together they may justify investigation.

This is why security operations relies heavily on correlation.
""")


def classify_login_pattern(failed_attempts, successful_login):
    if failed_attempts >= 3 and successful_login:
        return "HIGHER PRIORITY FOR INVESTIGATION"
    elif failed_attempts >= 3:
        return "REVIEW AUTHENTICATION ACTIVITY"
    else:
        return "NO IMMEDIATE SIGNAL FROM THIS SIMPLE RULE"


print(
    "\nExample detection result:",
    classify_login_pattern(4, True)
)


# ============================================================
# 26. ZERO TRUST ARCHITECTURE
# ============================================================

title("ZERO TRUST ARCHITECTURE")

print("""
Zero Trust can be understood through several principles:

    Verify explicitly
    Use least privilege
    Assume breach
    Continuously evaluate access

Identity becomes an important control plane.

Instead of:

    Network location -> Trust

the architecture considers:

    Identity
    Device
    Application
    Data
    Context
    Policy
    Risk

Example:

A user may be allowed to access a business application from a managed
device using MFA but denied from an unmanaged device.

Access decisions can therefore become contextual.
""")


# ============================================================
# 27. SECURITY CONFIGURATION
# ============================================================

title("SECURE CONFIGURATION")

print("""
Security configuration means setting systems so that unnecessary
exposure is reduced.

A secure configuration commonly considers:

    unnecessary services
    unnecessary accounts
    permissions
    firewall rules
    encryption
    authentication
    logging
    software versions
    security policies
    administrative interfaces

Configuration drift occurs when systems gradually move away from
their approved security configuration.

Continuous monitoring helps detect configuration drift.
""")


# ============================================================
# 28. BACKUP AND RECOVERY
# ============================================================

title("BACKUP, RESILIENCE AND RECOVERY")

print("""
Data security is incomplete without recovery.

A backup strategy considers:

    what is backed up
    how often
    where backups are stored
    how backups are protected
    how long they are retained
    who can access them
    whether recovery has been tested

A backup that cannot be restored is not a reliable recovery mechanism.

Security-sensitive backups should also be protected against unauthorized
access and destructive actions.
""")


# ============================================================
# 29. SECURITY POLICIES
# ============================================================

title("SECURITY GOVERNANCE")

print("""
Technical security controls operate within organizational governance.

Important policy areas include:

    access control
    password and authentication
    acceptable use
    data classification
    encryption
    vulnerability management
    incident response
    backup
    vendor security
    cloud security
    endpoint security
    security awareness

Governance defines expectations.

Technical controls enforce those expectations.
""")


# ============================================================
# 30. SECURITY FRAMEWORK THINKING
# ============================================================

title("SECURITY FRAMEWORK THINKING")

print("""
Security frameworks provide structured ways to organize security activities.

A common conceptual lifecycle is:

    Identify
        understand assets, risks and dependencies

    Protect
        implement safeguards

    Detect
        identify suspicious activity

    Respond
        contain and manage incidents

    Recover
        restore operations and improve resilience

Frameworks are useful because cybersecurity is too broad to manage
through isolated technical controls.
""")


# ============================================================
# 31. ATTACK SURFACE
# ============================================================

title("ATTACK SURFACE")

print("""
An attack surface is the collection of exposed points through which
an unauthorized party could potentially interact with a system.

Examples:

    internet-facing applications
    open network services
    user accounts
    APIs
    cloud resources
    remote administration interfaces
    third-party integrations
    endpoints
    software dependencies

Attack surface management attempts to:

    discover assets
    understand exposure
    identify weaknesses
    reduce unnecessary exposure
    continuously monitor changes
""")


# ============================================================
# 32. ASSET INVENTORY
# ============================================================

title("ASSET MANAGEMENT")

print("""
You cannot reliably protect assets that you do not know exist.

An asset inventory may contain:

    hostname
    IP address
    operating system
    owner
    business function
    location
    software
    criticality
    data classification
    security status

Asset management supports:

    vulnerability management
    incident response
    access control
    patch management
    risk assessment
""")


# ============================================================
# 33. SECURITY BASELINES
# ============================================================

title("SECURITY BASELINES")

print("""
A security baseline is an approved minimum configuration standard.

Example baseline for a workstation:

    supported operating system
    current security updates
    host firewall enabled
    endpoint protection enabled
    disk encryption enabled
    standard users without unnecessary administrator privileges
    logging enabled
    screen lock configured
    unnecessary services disabled

Baselines make security measurable.

Without a baseline, organizations may not have a clear definition
of what "secure configuration" means.
""")


# ============================================================
# 34. SECURITY TESTING
# ============================================================

title("SECURITY TESTING")

print("""
Security testing validates whether controls work as intended.

Methods include:

    vulnerability scanning
    configuration assessment
    code review
    penetration testing
    security testing
    architecture review
    threat modeling
    log review
    tabletop exercises
    disaster recovery testing

Testing should have:

    defined scope
    authorization
    objectives
    boundaries
    evidence collection
    reporting
    remediation tracking
""")


# ============================================================
# 35. ETHICS AND AUTHORIZATION
# ============================================================

title("AUTHORIZATION AND PROFESSIONAL ETHICS")

print("""
Cybersecurity tools can interact deeply with systems.

A professional must distinguish between:

    authorized security testing

and:

    unauthorized access

Before testing a system, security professionals should understand:

    who authorized the activity
    which systems are in scope
    which techniques are permitted
    testing dates
    operational restrictions
    data handling requirements
    reporting requirements

A technically successful action can still be professionally and
legally unacceptable if it was performed without authorization.
""")


# ============================================================
# 36. CROSS-DOMAIN SECURITY SCENARIO
# ============================================================

title("INTEGRATED SECURITY SCENARIO")

print("""
Consider a company with:

    Windows employee laptops
    Linux servers
    cloud applications
    web APIs
    PostgreSQL databases
    corporate identity provider
    firewall
    VPN
    security monitoring platform

A user reports suspicious activity.

Network Security asks:

    What network connections occurred?

Endpoint Security asks:

    What processes ran on the laptop?

Identity Security asks:

    Which account was involved?
    Was MFA used?

Application Security asks:

    Which application endpoint was accessed?

Cloud Security asks:

    Which cloud resource was accessed?

Data Security asks:

    Which data was exposed or modified?

Security Operations asks:

    When did the incident begin?
    What other systems were affected?
    What evidence exists?
    What containment actions are required?

This illustrates why cybersecurity domains work together.
""")


# ============================================================
# 37. PYTHON SECURITY DATA STRUCTURE
# ============================================================

title("MODELING SECURITY ASSETS WITH PYTHON")

assets = [
    {
        "name": "Employee-Laptop-01",
        "type": "Windows Endpoint",
        "criticality": "Medium",
        "encryption": True,
        "mfa": True
    },
    {
        "name": "Web-Server-01",
        "type": "Linux Server",
        "criticality": "High",
        "encryption": True,
        "mfa": True
    },
    {
        "name": "Database-01",
        "type": "Database",
        "criticality": "Critical",
        "encryption": True,
        "mfa": True
    }
]

for asset in assets:
    print(
        f"{asset['name']} | "
        f"{asset['type']} | "
        f"Criticality={asset['criticality']} | "
        f"Encryption={asset['encryption']} | "
        f"MFA={asset['mfa']}"
    )


# ============================================================
# 38. SECURITY CONTROL MAPPING
# ============================================================

title("MAPPING CONTROLS TO DOMAINS")

control_map = {
    "Firewall": ["Network Security"],
    "EDR": ["Endpoint Security", "Security Operations"],
    "MFA": ["Identity Security", "Endpoint Security", "Cloud Security"],
    "TLS": ["Data Security", "Network Security", "Application Security"],
    "WAF": ["Network Security", "Application Security"],
    "SIEM": ["Security Operations"],
    "Encryption": ["Data Security", "Cloud Security"],
    "IAM": ["Identity Security", "Cloud Security"],
    "Secure SDLC": ["Application Security"],
    "Network Segmentation": ["Network Security", "Cloud Security"],
    "Backups": ["Data Security", "Security Operations"],
}

for control, domains_supported in control_map.items():
    print(f"\n{control}")
    for domain in domains_supported:
        print(f"    -> {domain}")


# ============================================================
# 39. SECURITY MATURITY
# ============================================================

title("SECURITY MATURITY")

print("""
Security maturity can be viewed as a progression.

Level 1:
    Security is mostly reactive.

Level 2:
    Basic controls exist.

Level 3:
    Security processes are documented and measured.

Level 4:
    Controls are continuously monitored and improved.

Level 5:
    Security is highly integrated, automated and risk-driven.

Maturity is not simply about owning more security products.

An organization can own many tools and still have poor security if:

    logs are ignored
    vulnerabilities remain unresolved
    permissions are excessive
    assets are unknown
    incident response is weak
    controls are not tested
""")


# ============================================================
# 40. SECURITY PRINCIPLES
# ============================================================

title("CORE SECURITY PRINCIPLES")

principles = [
    "Least privilege",
    "Defense in depth",
    "Separation of duties",
    "Secure by design",
    "Secure defaults",
    "Minimize attack surface",
    "Continuous monitoring",
    "Assume breach",
    "Strong authentication",
    "Explicit authorization",
    "Data minimization",
    "Accountability",
    "Resilience",
    "Recovery",
    "Continuous improvement"
]

show(principles)


# ============================================================
# 41. ADVANCED SECURITY CONCEPTS
# ============================================================

title("ADVANCED CONCEPTS")

advanced = [
    "Zero Trust Architecture",
    "Security Information and Event Management",
    "Endpoint Detection and Response",
    "Extended Detection and Response",
    "Identity Threat Detection and Response",
    "Cloud Security Posture Management",
    "Cloud Workload Protection",
    "Data Loss Prevention",
    "Privileged Access Management",
    "Security Orchestration and Automation",
    "Threat Intelligence",
    "Threat Hunting",
    "Detection Engineering",
    "Digital Forensics",
    "Attack Surface Management",
    "Security Architecture",
    "Supply Chain Security",
    "Software Bill of Materials",
    "DevSecOps",
    "Continuous Control Monitoring"
]

show(advanced)


# ============================================================
# 42. DEVSECOPS
# ============================================================

title("DEVSECOPS")

print("""
DevSecOps integrates security into software development and operations.

Traditional model:

    Development -> Operations -> Security review

A DevSecOps model attempts to make security continuous:

    Plan
      |
    Code
      |
    Build
      |
    Test
      |
    Deploy
      |
    Operate
      |
    Monitor
      |
    Feedback

Security activities can include:

    dependency scanning
    secret detection
    static analysis
    dynamic testing
    container scanning
    infrastructure-as-code scanning
    code review
    security testing
    runtime monitoring
""")


# ============================================================
# 43. SUPPLY CHAIN SECURITY
# ============================================================

title("SOFTWARE SUPPLY CHAIN SECURITY")

print("""
Modern applications depend on:

    libraries
    packages
    operating systems
    containers
    cloud services
    build systems
    third-party APIs

A vulnerability in a dependency can affect applications that use it.

Supply chain security therefore considers:

    dependency inventory
    package provenance
    software integrity
    build security
    signing
    dependency vulnerability monitoring
    vendor risk
    secure CI/CD pipelines
""")


# ============================================================
# 44. SECURITY TELEMETRY
# ============================================================

title("SECURITY TELEMETRY")

print("""
Telemetry is information collected about system behavior.

Examples:

Endpoint telemetry:
    process creation
    file activity
    registry changes
    network connections

Network telemetry:
    DNS queries
    connection metadata
    firewall events
    proxy events

Identity telemetry:
    logins
    MFA events
    privilege changes
    password changes

Cloud telemetry:
    API calls
    resource changes
    authentication events

Application telemetry:
    requests
    errors
    authentication
    authorization decisions

Good detection depends on useful telemetry.
""")


# ============================================================
# 45. THREAT HUNTING
# ============================================================

title("THREAT HUNTING")

print("""
Threat hunting is a proactive search for suspicious activity that may
not have generated a high-confidence alert.

A hunt may begin with a hypothesis.

Example:

    "Could an unusual administrative login pattern exist?"

The analyst may examine:

    authentication logs
    endpoint activity
    network connections
    privilege changes
    cloud activity

Threat hunting is different from simply waiting for alerts.
""")


# ============================================================
# 46. DETECTION ENGINEERING
# ============================================================

title("DETECTION ENGINEERING")

print("""
Detection engineering converts security knowledge into repeatable
detections.

A good detection should consider:

    signal
    data source
    logic
    expected behavior
    false positives
    severity
    response
    testing
    maintenance

Example conceptual rule:

    IF
        multiple authentication failures
        followed by a successful login
        from an unusual source
    THEN
        create an investigation alert

This is a simplified example.

Real environments require baselines and contextual enrichment.
""")


# ============================================================
# 47. FALSE POSITIVES
# ============================================================

title("FALSE POSITIVES AND FALSE NEGATIVES")

print("""
False positive:

    The security system reports malicious activity,
    but the activity is actually legitimate.

False negative:

    Malicious activity occurs,
    but the security system fails to detect it.

Security operations attempts to balance both.

Too many false positives:

    analysts become overwhelmed
    important alerts may be missed

Too many false negatives:

    malicious activity can remain undetected
""")


# ============================================================
# 48. SECURITY INCIDENT PRIORITIZATION
# ============================================================

title("INCIDENT PRIORITIZATION")

print("""
Incident priority can consider:

    asset criticality
    affected identities
    data sensitivity
    attack confidence
    business impact
    spread
    persistence
    regulatory implications
    availability impact

Example:

A suspicious event on a test workstation may have lower business impact
than the same event on a production database server.

Security operations therefore uses context rather than treating every
alert equally.
""")


# ============================================================
# 49. BUSINESS CONTINUITY
# ============================================================

title("BUSINESS CONTINUITY AND CYBER RESILIENCE")

print("""
Cybersecurity includes maintaining business operations during disruption.

Important concepts:

    Business Continuity
        ability to continue important functions

    Disaster Recovery
        ability to restore systems after disruption

    Recovery Point Objective
        acceptable amount of data loss measured in time

    Recovery Time Objective
        acceptable amount of downtime

Security incidents can affect:

    confidentiality
    integrity
    availability

Availability and recovery are therefore core security concerns.
""")


# ============================================================
# 50. PRACTICAL DOMAIN MAP
# ============================================================

title("PRACTICAL CYBERSECURITY DOMAIN MAP")

domain_map = {
    "Network Security":
        "Firewalls, segmentation, VPN, IDS/IPS, DNS, network monitoring",

    "Endpoint Security":
        "Windows Defender, EDR, host firewall, patching, hardening",

    "Application Security":
        "Secure coding, authentication, authorization, testing, WAF",

    "Cloud Security":
        "IAM, cloud logging, security groups, encryption, posture management",

    "Identity Security":
        "MFA, IAM, PAM, SSO, least privilege, access reviews",

    "Data Security":
        "Encryption, classification, DLP, backups, access control",

    "Security Operations":
        "SIEM, SOC, detection, threat hunting, incident response",

    "Kali Linux":
        "Authorized security testing, assessment, research and forensics",

    "Windows":
        "Enterprise endpoints, servers, Active Directory, PowerShell and security monitoring"
}

for domain, technologies in domain_map.items():
    print(f"\n{domain}")
    print(f"    {technologies}")


# ============================================================
# 51. FINAL INTEGRATED MODEL
# ============================================================

title("INTEGRATED CYBERSECURITY MODEL")

print("""
A mature cybersecurity environment can be visualized as:

                         USERS
                           |
                           v
                    IDENTITY SECURITY
                           |
                           v
                    ENDPOINT SECURITY
                           |
                           v
                     NETWORK SECURITY
                           |
                           v
                   APPLICATION SECURITY
                           |
                           v
                      CLOUD SECURITY
                           |
                           v
                       DATA SECURITY
                           |
                           v
                  SECURITY OPERATIONS
                           |
            +--------------+--------------+
            |                             |
            v                             v
      INCIDENT RESPONSE            CONTINUOUS MONITORING
            |                             |
            +--------------+--------------+
                           |
                           v
                    RISK MANAGEMENT

Kali Linux can support authorized assessment, testing, research and
forensics across several of these layers.

Windows is commonly one of the systems being protected and monitored
within enterprise environments.

The domains are interconnected.

A compromised identity can affect endpoints.

A compromised endpoint can affect networks.

A vulnerable application can expose data.

A cloud misconfiguration can expose identities and storage.

A logging failure can prevent security operations from detecting the event.

Security therefore has to be treated as a system rather than as a collection
of unrelated tools.
""")


# ============================================================
# 52. END
# ============================================================

print("\n" + "=" * 78)
print("END OF CYBERSECURITY DOMAINS STUDY PROGRAM")
print("=" * 78)
```

